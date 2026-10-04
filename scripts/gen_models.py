"""Generate the per-model settings files from the cached vendor thing models.

For each model in the cache (``<cache>/<PN>/{td.json, <PN>Handle.mix.js}``), run the
vendor handler through ``scripts/gen_models_driver.js`` with setProperty over every
writable property's domain, in a station-child and a standalone context, infer the write
codecs (``scripts/gen_models_codec.py``), feed each written recipe's parameter dump back
to getProperty for the read codec, join the app's labels and settings layout
(``scripts/gen_models_join.py``) with the app's setting titles, units and variant pairs,
and write ``<out>/<PN>.json``, then ``<out>/INDEX.json``,
the sorted list of every ``<PN>.json`` in ``<out>``.

Every model is checked before it is written: each codec must render back every swept
recipe, and every row of the frozen v1 reference (``tests/fixtures/models_v1_reference.json``)
must render to its recorded cmd/subCmd/params unless ``RELEASE_ACCEPTED`` names it. A model
that fails is not written and the run exits 1. ``--check`` regenerates into a temporary
directory and compares byte for byte with ``--out``.

Runs on a maintainer host only (needs Node and the private cache); nothing at runtime
executes vendor code. See docs/reference/models-schema.md.

    gen_models.py [PN ...] [--check] [--cache DIR] [--out DIR] [--jobs N]
                  [--labels FILE] [--trees FILE] [--titles FILE] [--app-version V]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "scripts" / "gen_models_driver.js"
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
INDEX = "INDEX.json"  # {"schema_version", "codes"}: the bundled product codes, sorted
DEFAULT_LABELS = ROOT / ".work" / "tools" / "data" / "app_choice_labels.json"
DEFAULT_TREES = ROOT / ".work" / "tools" / "data" / "settings_trees.json"
DEFAULT_TITLES = ROOT / ".work" / "tools" / "data" / "app_setting_titles.json"
REFERENCE = ROOT / "tests" / "fixtures" / "models_v1_reference.json"
DEFAULT_APP_VERSION = "6.1.10"  # the app build the label and tree data come from
NODE_TIMEOUT_S = 600
SIGNAL_RETRIES = 2
SCHEMA_VERSION = 2
IDENTIFIER = re.compile(r"[a-z0-9_]+")


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
joiner = _load("gen_models_join")
controls = _load("gen_models_controls")
GeneratorError = codec.GeneratorError
RECIPE_FIELDS = ("cmd", "subCmd", "params")

# v1 reference rows whose render may differ, keyed (PN, identifier), with the reason.
RELEASE_ACCEPTED: dict[tuple[str, str], str] = {}


class CheckError(GeneratorError):
    """A generated codec does not reproduce a swept recipe or a v1 reference row."""


def _canon(x: Any) -> str:
    """JSON text that tells ``1``, ``1.0`` and ``true`` apart."""
    return json.dumps(x, sort_keys=True)


def _render_or_error(setting: dict[str, Any], value: Any, context: str, channel: int) -> Any:
    try:
        return codec.render(setting, value, context=context, channel=channel)
    except ValueError as err:
        return f"render error: {err}"


def sweep_mismatches(
    settings: dict[str, Any],
    samples: dict[str, dict[str, list[tuple[Any, Any]]]],
    standalone_failed: set[str],
) -> list[tuple[str, str]]:
    """``(identifier, detail)`` for every swept recipe its rw codec does not render back."""
    out = []
    for ident, entry in settings.items():
        if entry["access"] != "rw":
            continue
        for ctx in codec.CONTEXTS:
            if ctx is codec.STANDALONE and ident in standalone_failed:
                continue
            for value, recipe in samples[ident][ctx.name]:
                got = _render_or_error(entry, value, ctx.name, ctx.channel)
                if _canon(got) != _canon(recipe):
                    out.append((ident, f"{ctx.name} payload {value!r}: {got!r} != {recipe!r}"))
    return out


def reference_key(settings: dict[str, Any], ident: str) -> str | None:
    """The key a reference row of ``ident`` renders through: ``ident`` itself, else the key
    that absorbed it as a same-codec variant, else None."""
    return ident if ident in settings else controls.absorbed_by(ident, settings)


def reference_setting(settings: dict[str, Any], ident: str) -> dict[str, Any] | None:
    key = reference_key(settings, ident)
    return None if key is None else settings[key]


def reference_mismatches(
    settings: dict[str, Any], rows: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """``(identifier, detail)`` for every v1 reference row the model does not reproduce.

    Each row is rendered in its recorded context and channel; cmd, subCmd and params are
    compared (presence and JSON type included). A row of a key dropped as a same-codec
    variant renders through the key that absorbed it (``reference_setting``).
    """
    out = []
    for row in rows:
        ident, payload = row["identifier"], row["payload"]
        where = f"{row['context']} ch {row['channel']} payload {payload!r}"
        entry = reference_setting(settings, ident)
        if entry is None:
            out.append((ident, f"{where}: setting missing"))
            continue
        try:
            value = controls.reference_value(entry, row)
            if entry.get("kind") != "flags" and entry.get("bit") is None:
                value = codec.coerce(entry, value)
        except ValueError as err:
            out.append((ident, f"{where}: {err}"))
            continue
        got = _render_or_error(entry, value, row["context"], row["channel"])
        if isinstance(got, dict):
            got = {k: got[k] for k in RECIPE_FIELDS if k in got}
        want = {k: row["recipe"][k] for k in RECIPE_FIELDS if k in row["recipe"]}
        if _canon(got) != _canon(want):
            out.append((ident, f"{where}: {got!r} != {want!r}"))
    return out


def load_reference(path: Path = REFERENCE) -> dict[str, list[dict[str, Any]]]:
    """The v1 reference rows per product code (empty when the fixture is absent)."""
    if not path.is_file():
        return {}
    rows: dict[str, list[dict[str, Any]]] = {}
    for row in _read_json(path)["rows"]:
        rows.setdefault(row["product_code"], []).append(row)
    return rows


def run_driver(product_code: str, handler: Path, requests: list[dict[str, Any]]) -> list[Any]:
    """One node batch: a reply per request, in order."""
    job = json.dumps({"handler": str(handler), "requests": requests})
    for _ in range(SIGNAL_RETRIES + 1):
        res = subprocess.run(
            ["node", str(DRIVER)],
            input=job,
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT_S,
            check=False,
        )
        # Node occasionally aborts under heavy parallel load; the job is deterministic,
        # so a run killed by a signal is repeated as is.
        if res.returncode >= 0:
            break
        print(f"{product_code}: driver killed by signal {-res.returncode}, rerun", file=sys.stderr)
    if res.returncode:
        raise GeneratorError(f"{product_code}: driver exit {res.returncode}: {res.stderr[-400:]}")
    try:
        replies = json.loads(res.stdout)
    except json.JSONDecodeError as err:
        raise GeneratorError(f"{product_code}: driver output is not JSON: {err}") from err
    if not isinstance(replies, list) or len(replies) != len(requests):
        raise GeneratorError(f"{product_code}: driver returned {len(replies)} replies")
    return replies


def p2p(reply: Any) -> dict[str, Any] | None:
    """The recipe of a handler reply: ``data.p2p`` when it is a dict without ``error``."""
    data = reply.get("data") if isinstance(reply, dict) else None
    recipe = data.get("p2p") if isinstance(data, dict) else None
    if isinstance(recipe, dict) and recipe and not recipe.get("error"):
        return recipe
    return None


def _is_error(reply: Any) -> bool:
    """A reply whose handler threw or whose recipe carries ``error``."""
    if not isinstance(reply, dict):
        return False
    data = reply.get("data")
    recipe = data.get("p2p") if isinstance(data, dict) else None
    return "error" in reply or (isinstance(recipe, dict) and bool(recipe.get("error")))


def td_fields(
    product_code: str, prop: dict[str, Any], kind: str, values: list[Any]
) -> dict[str, Any]:
    """``min``/``max``/``step``/``unit``/``default``/``values`` from the TD where present.

    The unit is normalised (``gen_models_join.normalise_unit``); raises GeneratorError for
    a unit without a mapping.
    """
    specs = codec.specs_of(prop)
    out: dict[str, Any] = {}
    if kind == "range":
        lo, hi, step = codec.range_spec(prop)
        out.update(min=codec.intify(lo), max=codec.intify(hi), step=codec.intify(step))
    if kind == "enum":
        out["values"] = values
    unit = specs.get("unit")
    if isinstance(unit, str) and unit.strip():
        normal = joiner.normalise_unit(
            product_code, prop["identifier"], unit.strip(), out.get("min"), out.get("max")
        )
        if normal is not None:
            out["unit"] = normal
    default = codec.td_default(prop, kind)
    if default is not None:
        out["default"] = default
    return out


def _param_dump(recipe: dict[str, Any] | None) -> list[dict[str, Any]]:
    """``[{param_type, param_value}]`` from a recipe's ``update`` and ``extUpdates`` items."""
    if recipe is None:
        return []
    update = recipe.get("update")
    if not isinstance(update, dict):
        return []
    if not isinstance(update.get("cmd"), int) or update.get("paramValue") is None:
        return []
    dump = [{"param_type": update["cmd"], "param_value": update["paramValue"]}]
    ext = recipe.get("extUpdates")
    dump.extend(
        {"param_type": item["cmd"], "param_value": item.get("paramValue")}
        for item in (ext if isinstance(ext, list) else [])
        if isinstance(item, dict) and isinstance(item.get("cmd"), int)
    )
    return dump


def read_samples(
    product_code: str, handler: Path, raw: dict[str, list[tuple[Any, dict[str, Any] | None]]]
) -> dict[str, list[Any]]:
    """getProperty over each child-context recipe's own parameter dump, per identifier.

    An identifier gets samples only when at least one written value yields a dump; a value
    without one is a sample with no ``cmd`` (its round trip fails).
    """
    requests: list[dict[str, Any]] = []
    index: list[tuple[str, int]] = []
    for ident, rows in raw.items():
        for i, (_, recipe) in enumerate(rows):
            dump = _param_dump(recipe)
            if not dump:
                continue
            device = codec.CHILD.device(product_code)
            device["params"] = dump
            requests.append(
                {"kind": "get", "cmds": [p["param_type"] for p in dump], "device": device}
            )
            index.append((ident, i))
    replies = run_driver(product_code, handler, requests) if requests else []
    decoded: dict[tuple[str, int], Any] = {}
    for (ident, i), reply in zip(index, replies, strict=True):
        values = p2p(reply) or {}
        decoded[(ident, i)] = values.get(ident, codec.MISSING)
    out: dict[str, list[Any]] = {}
    for ident, rows in raw.items():
        if not any((ident, i) in decoded for i in range(len(rows))):
            continue
        samples = []
        for i, (v, recipe) in enumerate(rows):
            update = (recipe or {}).get("update")
            got = decoded.get((ident, i), codec.MISSING)
            if (ident, i) in decoded and isinstance(update, dict):
                samples.append(codec.ReadSample(v, update["cmd"], update["paramValue"], got))
            else:
                samples.append(codec.ReadSample(v, None, None, codec.MISSING))
        out[ident] = samples
    return out


def generate(
    product_code: str,
    cache: Path,
    app_labels: dict[str, Any] | None = None,
    tree: dict[str, Any] | None = None,
    app_version: str = DEFAULT_APP_VERSION,
    *,
    reference: list[dict[str, Any]] | None = None,
    titles: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    """The settings-file object of one model and its counters.

    ``app_labels`` / ``tree`` are the model's entries of the label and settings-tree
    files (None: TD labels only / no UI placement); ``reference`` its v1 reference rows;
    ``titles`` the app setting-title file (None: no names, app units or variants).
    Raises CheckError when a codec does not reproduce a swept recipe or an unaccepted
    reference row.
    """
    folder = cache / product_code
    td = json.loads((folder / "td.json").read_text(encoding="utf-8"))
    handler = folder / f"{product_code}Handle.mix.js"
    props = [p for p in td.get("properties", []) if isinstance(p, dict)]
    counts: dict[str, int] = {}
    valid = []
    for prop in props:
        ident = prop.get("identifier")
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident):
            counts["skipped"] = counts.get("skipped", 0) + 1
            continue
        valid.append(prop)
    requests: list[dict[str, Any]] = []
    index: list[tuple[str, str, Any]] = []
    for prop in valid:
        if "W" not in (prop.get("access_mode") or ""):
            continue
        _, values = codec.domain(prop)
        for ctx in codec.CONTEXTS:
            for v in values:
                requests.append(
                    {
                        "kind": "set",
                        "identifier": prop["identifier"],
                        "payload": v,
                        "device": ctx.device(product_code),
                    }
                )
                index.append((prop["identifier"], ctx.name, v))
    replies = run_driver(product_code, handler, requests) if requests else []
    samples: dict[str, dict[str, list[tuple[Any, Any]]]] = {}
    raw: dict[str, list[tuple[Any, dict[str, Any] | None]]] = {}
    contexts = {c.name: c for c in codec.CONTEXTS}
    rejected: set[str] = set()
    standalone_failed: set[str] = set()
    for (ident, ctx_name, v), reply in zip(index, replies, strict=True):
        recipe = p2p(reply)
        if recipe is None and _is_error(reply):
            rejected.add(ident)
        slotted = codec.slot(recipe, contexts[ctx_name]) if recipe is not None else None
        samples.setdefault(ident, {}).setdefault(ctx_name, []).append((v, slotted))
        if ctx_name == codec.CHILD.name:
            raw.setdefault(ident, []).append((v, recipe))
    reads = read_samples(product_code, handler, raw)
    settings: dict[str, Any] = {}
    for prop in valid:
        ident = prop["identifier"]
        kind, values = codec.domain(prop)
        entry: dict[str, Any] = {
            "kind": kind,
            **td_fields(product_code, prop, kind, values),
            "access": "ro",
            "read": None,
        }
        if "W" in (prop.get("access_mode") or ""):
            _count(counts, "writable")
            result = codec.infer_write(kind, samples[ident]["child"], samples[ident]["standalone"])
            if result.note == "no handler write path" and ident in rejected:
                result.note = "handler rejects the probed values"
            entry.update(codec.codec_fields(result))
            read, read_note = None, None
            if result.access == "rw":
                read, read_note = codec.infer_read(kind, reads.get(ident, []))
                _count(counts, "read:codec" if read else "read:null")
                if read is not None:
                    _count(counts, "read:identity" if read["map"] is None else "read:map")
                elif read_note:
                    _count(counts, f"read:{read_note}")
            entry["read"] = read
            if read_note:
                entry["note"] = f"{entry['note']}; {read_note}" if "note" in entry else read_note
            if result.access == "rw":
                _count(counts, f"rw:{result.form}")
                if "write_standalone" in entry or "write_table_standalone" in entry:
                    _count(counts, "standalone_variant")
                if "standalone_note" in result.extra:
                    standalone_failed.add(ident)
                    _count(counts, f"standalone:{result.extra['standalone_note']}")
            else:
                _count(counts, f"ro:{result.note}")
        settings[ident] = entry
    try:
        joined = joiner.join(product_code, settings, td, app_labels, tree, titles=titles)
        source = joiner.source_block(td, app_version)
    except GeneratorError as err:
        raise GeneratorError(f"{product_code}: {err}") from err
    for key, n in joined.items():
        _count(counts, key, n)
    found = sweep_mismatches(settings, samples, standalone_failed)
    found += reference_mismatches(settings, reference or [])
    failed = [(i, d) for i, d in found if (product_code, i) not in RELEASE_ACCEPTED]
    if failed:
        lines = "\n".join(f"  {product_code} {i}: {d}" for i, d in failed)
        raise CheckError(f"{product_code}: {len(failed)} codec mismatches\n{lines}")
    if reference:
        _count(counts, "reference_rows", len(reference))
    shape_controls(product_code, handler, settings, counts)
    shaped = reference_mismatches(settings, reference or [])
    failed = [(i, d) for i, d in shaped if (product_code, i) not in RELEASE_ACCEPTED]
    if failed:
        lines = "\n".join(f"  {product_code} {i}: {d}" for i, d in failed)
        raise CheckError(f"{product_code}: {len(failed)} shaped settings differ\n{lines}")
    doc = {
        "schema_version": SCHEMA_VERSION,
        "product_code": product_code,
        "source": source,
        "settings": settings,
    }
    return doc, counts


def shape_controls(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    counts: dict[str, int],
) -> None:
    """Bit switches, flags, scales, same-write variants, controls and the drop of
    same-codec variants (``scripts/gen_models_controls.py``), probing the handler once
    more for the first two."""

    def device(params: dict[int, str]) -> dict[str, Any]:
        dev = codec.CHILD.device(product_code)
        dev["params"] = [{"param_type": k, "param_value": v} for k, v in params.items()]
        return dev

    gates = {e["applies_when"][0] for e in settings.values() if e.get("applies_when")}
    bits = controls.bit_candidates(settings)
    flags = controls.flag_candidates(settings, gates)
    bit_reqs = controls.bit_requests(bits, device)
    # Members are probed as text, the form the app's multi-choice screens send.
    flag_reqs = [
        (
            ident,
            payload,
            {
                "kind": "set",
                "identifier": ident,
                "payload": payload,
                "device": codec.CHILD.device(product_code),
            },
        )
        for ident, values in flags.items()
        for payload in [codec.value_key(v) for v in values] + controls.flag_payloads(values)
    ]
    requests = [r for *_, r in bit_reqs] + [r for *_, r in flag_reqs]
    replies = run_driver(product_code, handler, requests) if requests else []

    def slotted(reply: Any) -> Any:
        recipe = p2p(reply)
        return None if recipe is None else codec.slot(recipe, codec.CHILD)

    bit_replies = {
        (ident, value): slotted(rep)
        for (ident, value, _), rep in zip(bit_reqs, replies, strict=False)
    }
    flag_replies = {
        (ident, payload): slotted(rep)
        for (ident, payload, _), rep in zip(flag_reqs, replies[len(bit_reqs) :], strict=True)
    }
    controls.apply_bits(settings, bits, bit_replies, counts)
    singles = {
        ident: [(v, flag_replies.get((ident, codec.value_key(v)))) for v in values]
        for ident, values in flags.items()
    }
    controls.apply_flags(settings, flags, singles, flag_replies, counts)
    controls.apply_scales(settings, gates, counts)
    controls.apply_duplicate_variants(settings, counts)
    controls.apply_domains(settings, counts)
    controls.apply_controls(settings, counts)
    controls.drop_same_codec_variants(settings, counts)


def _count(counts: dict[str, int], key: str, n: int = 1) -> None:
    counts[key] = counts.get(key, 0) + n


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise GeneratorError(f"{path.name}: not a JSON object")
    return data


def _summary(counts: dict[str, int]) -> str:
    """The per-model log line: headline counters first, then every counter."""
    head = {
        "rw": sum(n for k, n in counts.items() if k.startswith("rw:")),
        "read": counts.get("read:codec", 0),
        "read_null": counts.get("read:null", 0),
        "labels_app": counts.get("label:app", 0),
        "labels_td": counts.get("label:td", 0),
        "applies_when": counts.get("applies_when", 0),
        "group": counts.get("group", 0),
        "names_app": counts.get("name:app", 0),
        "units_app": counts.get("unit:app", 0),
        "variants": counts.get("variant_of", 0),
        "bits": counts.get("bit", 0),
        "flags": counts.get("flags", 0),
        "scales": counts.get("scale", 0),
    }
    return (
        " ".join(f"{k}={v}" for k, v in head.items())
        + " "
        + json.dumps(counts, sort_keys=True, ensure_ascii=False)
    )


def _missing_inputs(cache: Path, pns: list[str]) -> str | None:
    """Why a run cannot start (no node, no cache, a model not in the cache), or None."""
    if shutil.which("node") is None:
        return "node is not on PATH"
    if not cache.is_dir():
        return f"no thing-model cache at {cache}"
    absent = [pn for pn in pns if not (cache / pn / "td.json").is_file()]
    return f"not in the cache: {' '.join(absent)}" if absent else None


def index_text(codes: list[str]) -> str:
    """The text of ``INDEX.json`` listing ``codes``."""
    return codec.dump({"schema_version": SCHEMA_VERSION, "codes": sorted(codes)})


def write_index(out: Path) -> None:
    """Write ``out/INDEX.json`` from the ``<PN>.json`` files in ``out``."""
    codes = [p.stem for p in out.glob("*.json") if p.name != INDEX]
    (out / INDEX).write_text(index_text(codes), encoding="utf-8")


def compare(fresh: Path, committed: Path, pns: list[str] | None) -> list[str]:
    """Names of the files that differ (or exist on one side only, for a full run)."""
    if pns:
        names = {f"{pn}.json" for pn in pns}
    else:
        names = {p.name for p in fresh.glob("*.json")} | {p.name for p in committed.glob("*.json")}
    return sorted(
        name
        for name in names
        if not (fresh / name).is_file()
        or not (committed / name).is_file()
        or (fresh / name).read_bytes() != (committed / name).read_bytes()
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate models/<PN>.json from the vendor thing-model cache."
    )
    parser.add_argument("product_codes", nargs="*", metavar="PN")
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate into a temporary directory and compare with --out byte for byte",
    )
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--trees", type=Path, default=DEFAULT_TREES)
    parser.add_argument("--titles", type=Path, default=DEFAULT_TITLES)
    parser.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    args = parser.parse_args(argv)
    cache: Path = args.cache
    missing = _missing_inputs(cache, args.product_codes)
    if missing is None and not all(p.is_file() for p in (args.labels, args.trees, args.titles)):
        missing = "label, settings-tree or title data not found"
    if missing is not None:
        print(f"gen_models: {missing}", file=sys.stderr)
        return 2
    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            rc = _generate_all(args, cache, Path(tmp), quiet=True)
            if rc:
                return rc
            differ = compare(Path(tmp), args.out, args.product_codes)
        for name in differ:
            print(f"differs: {name}")
        print(f"check: {len(differ)} files differ")
        return 1 if differ else 0
    return _generate_all(args, cache, args.out, quiet=False)


def _generate_all(args: argparse.Namespace, cache: Path, out: Path, *, quiet: bool) -> int:
    """Generate the requested models into ``out``; 1 when any model failed its check."""
    labels = _read_json(args.labels)
    trees = _read_json(args.trees)
    titles = _read_json(args.titles)
    reference = load_reference()
    pns = args.product_codes or sorted(d.name for d in cache.iterdir() if d.is_dir())
    out.mkdir(parents=True, exist_ok=True)

    def build(pn: str) -> tuple[str, str | None, dict[str, int]]:
        try:
            doc, counts = generate(
                pn,
                cache,
                labels.get(pn),
                trees.get(pn),
                args.app_version,
                reference=reference.get(pn),
                titles=titles,
            )
        except CheckError as err:
            print(err, file=sys.stderr)
            return pn, None, {}
        return pn, codec.dump(doc), counts

    total: dict[str, int] = {}
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        # map() yields in input order, so output and log do not depend on --jobs.
        for pn, text, counts in pool.map(build, pns):
            if text is None:
                failed.append(pn)
                continue
            (out / f"{pn}.json").write_text(text, encoding="utf-8")
            if not quiet:
                print(pn, _summary(counts))
            for key, n in counts.items():
                total[key] = total.get(key, 0) + n
    write_index(out)
    if not quiet:
        print(f"total {len(pns)} models", _summary(total))
    if failed:
        print(f"check failed, not written: {' '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
