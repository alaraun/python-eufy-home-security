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
import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from eufy_home_security.devices.settings import DUAL_VIEW, VIEW_MODE_PARAM

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
SCHEMA_VERSION = 3
BASE = "SINGLE"  # the base context: a station child whose parent is no station kind
STANDALONE = "standalone"
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
type LeafPath = tuple[str | int, ...]

# v1 reference rows whose render may differ, keyed (PN, identifier), with the reason.
RELEASE_ACCEPTED: dict[tuple[str, str], str] = {}


class CheckError(GeneratorError):
    """A generated codec does not reproduce a swept recipe or a v1 reference row."""


def _canon(x: Any) -> str:
    """JSON text that tells ``1``, ``1.0`` and ``true`` apart."""
    return json.dumps(x, sort_keys=True)


def _render_or_error(setting: dict[str, Any], value: Any, channel: int) -> Any:
    try:
        return codec.render(setting, value, channel=channel)
    except ValueError as err:
        return f"render error: {err}"


def sweep_mismatches(
    settings: dict[str, Any], samples: dict[str, Sweep], context: codec.Context
) -> list[tuple[str, str]]:
    """``(identifier, detail)`` for every recipe swept in ``context`` (on both of its
    channels) that its rw codec does not render back."""
    out = []
    alt = codec.alt_channel(context)
    for ident, entry in settings.items():
        if entry["access"] != "rw":
            continue
        for ctx, rows in ((context, samples[ident].main), (alt, samples[ident].alt)):
            for value, recipe in rows:
                got = _render_or_error(entry, value, ctx.channel)
                if _canon(got) != _canon(recipe):
                    out.append(
                        (ident, f"ch {ctx.channel} payload {value!r}: {got!r} != {recipe!r}")
                    )
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
        got = _render_or_error(entry, value, row["channel"])
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
    """``[{param_type, param_value}]`` from a recipe's ``update`` and ``extUpdates`` items
    (``update`` first)."""
    if recipe is None:
        return []
    dump = []
    update = recipe.get("update")
    if (
        isinstance(update, dict)
        and isinstance(update.get("cmd"), int)
        and update.get("paramValue") is not None
    ):
        dump.append({"param_type": update["cmd"], "param_value": update["paramValue"]})
    ext = recipe.get("extUpdates")
    dump.extend(
        {"param_type": item["cmd"], "param_value": item.get("paramValue")}
        for item in (ext if isinstance(ext, list) else [])
        if isinstance(item, dict) and isinstance(item.get("cmd"), int)
    )
    return dump


@dataclass
class Sweep:
    """One identifier's setProperty replies in one context, on both of its channels:
    slotted ``(value, recipe or None)`` rows, plus the unslotted ``raw`` rows of the
    main channel whose ``update`` items the read inference feeds back."""

    main: list[tuple[Any, Any]] = field(default_factory=list)
    alt: list[tuple[Any, Any]] = field(default_factory=list)
    raw: list[tuple[Any, dict[str, Any] | None]] = field(default_factory=list)
    rejected: bool = False


def contexts_of(product_code: str) -> dict[str, codec.Context]:
    """Every context a model is generated for, by name: the base (``SINGLE``, a parent of
    no station kind), ``standalone`` and each station connect type."""
    out = {BASE: codec.CHILD, STANDALONE: codec.standalone_context(product_code)}
    for name in sorted(codec.CONNECT_PARENTS):
        out[name] = codec.child_context(name)
    return out


def sweep(
    product_code: str,
    handler: Path,
    props: list[dict[str, Any]],
    contexts: dict[str, codec.Context],
) -> dict[str, dict[str, Sweep]]:
    """setProperty over every writable property's domain in every context, on both of
    each context's channels: ``{context: {identifier: Sweep}}``.

    Each context and channel runs in its own driver process: a handler can keep state
    between requests, so one sweep must not see another's.
    """
    out: dict[str, dict[str, Sweep]] = {name: {} for name in contexts}
    writable = [p for p in props if "W" in (p.get("access_mode") or "")]
    for name, ctx in contexts.items():
        for alt, c in ((False, ctx), (True, codec.alt_channel(ctx))):
            requests: list[dict[str, Any]] = []
            index: list[tuple[str, Any]] = []
            for prop in writable:
                _, values = codec.domain(prop)
                for v in values:
                    requests.append(
                        {
                            "kind": "set",
                            "identifier": prop["identifier"],
                            "payload": v,
                            "device": c.device(product_code),
                        }
                    )
                    index.append((prop["identifier"], v))
            replies = run_driver(product_code, handler, requests) if requests else []
            for (ident, v), reply in zip(index, replies, strict=True):
                recipe = p2p(reply)
                row = out[name].setdefault(ident, Sweep())
                if recipe is None and _is_error(reply):
                    row.rejected = True
                slotted = codec.slot(recipe, ctx) if recipe is not None else None
                (row.alt if alt else row.main).append((v, slotted))
                if not alt:
                    row.raw.append((v, recipe))
    return out


def read_samples(
    product_code: str,
    handler: Path,
    raw: dict[str, list[tuple[Any, dict[str, Any] | None]]],
    context: codec.Context,
    counts: dict[str, int],
    *,
    background: Mapping[int, Any] | None = None,
) -> dict[str, list[Any]]:
    """getProperty over each recipe's own parameter dump in ``context``, per identifier,
    the way the app asks: ``commandId`` = every parameter of the device.

    ``background`` (param -> value) are further parameters the device is given ahead of
    the dump, as a real block reports them beside the written ones. An identifier gets
    samples only when at least one written value yields a dump; a value without one is
    a sample with no ``cmd`` (its round trip fails). When the dump holds several
    parameters and the decode depends on exactly one of them on every sample (leaving it
    out loses the value, leaving out any other does not), that parameter is the sample's
    ``cmd`` instead of the ``update`` one.
    """
    requests: list[dict[str, Any]] = []
    index: list[tuple[str, int, int | None]] = []

    def ask(dump: list[dict[str, Any]], ident: str, i: int, left_out: int | None) -> None:
        own = {p["param_type"] for p in dump}
        rest = [
            {"param_type": k, "param_value": v}
            for k, v in (background or {}).items()
            if k not in own
        ]
        device = context.device(product_code)
        device["params"] = rest + dump
        requests.append(
            {"kind": "get", "cmds": [p["param_type"] for p in device["params"]], "device": device}
        )
        index.append((ident, i, left_out))

    for ident, rows in raw.items():
        for i, (_, recipe) in enumerate(rows):
            dump = _param_dump(recipe)
            if not dump:
                continue
            ask(dump, ident, i, None)
            if len({p["param_type"] for p in dump}) > 1:
                for p in dump:
                    ask([q for q in dump if q is not p], ident, i, p["param_type"])
    replies = run_driver(product_code, handler, requests) if requests else []
    decoded: dict[tuple[str, int, int | None], Any] = {}
    for key, reply in zip(index, replies, strict=True):
        values = p2p(reply) or {}
        decoded[key] = values.get(key[0], codec.MISSING)
    out: dict[str, list[Any]] = {}
    for ident, rows in raw.items():
        if not any((ident, i, None) in decoded for i in range(len(rows))):
            continue
        samples = []
        needed: set[tuple[int, ...]] = set()
        for i, (v, recipe) in enumerate(rows):
            got = decoded.get((ident, i, None), codec.MISSING)
            if (ident, i, None) in decoded:
                first = _param_dump(recipe)[0]
                samples.append(codec.ReadSample(v, first["param_type"], first["param_value"], got))
                needed.add(
                    tuple(
                        p
                        for (d_ident, d_i, p), d in decoded.items()
                        if d_ident == ident and d_i == i and p is not None
                        if not codec.decodes_to(d, v)
                    )
                )
            else:
                samples.append(codec.ReadSample(v, None, None, codec.MISSING))
        if len(needed) == 1 and len(only := next(iter(needed))) == 1:
            (param,) = only
            dumps = [{p["param_type"]: p["param_value"] for p in _param_dump(r)} for _, r in rows]
            if any(s.cmd != param for s in samples) and all(param in d for d in dumps):
                samples = [
                    codec.ReadSample(s.value, param, d[param], s.decoded)
                    for s, d in zip(samples, dumps, strict=True)
                ]
                _count(counts, "read:param from the decode")
        out[ident] = samples
    return out


def param_slots(
    product_code: str,
    handler: Path,
    context: codec.Context,
    rows: dict[str, Sweep],
    seen: Mapping[int, list[str]],
    *,
    counts: dict[str, int],
) -> dict[str, dict[LeafPath, str]]:
    """``{identifier: {path: "$param:<id>:<form>"}}`` for each write leaf the handler takes
    from a device parameter: null in every swept recipe (the parameter is absent there)
    and, with the parameter set to two of the values the model's writes give it, that
    value each time (as int or as the string).

    ``seen`` holds those values per parameter. A leaf two parameters explain stays null.
    """
    asks: list[tuple[str, int, str]] = []
    requests: list[dict[str, Any]] = []
    for ident, row in rows.items():
        recipes = [r for _, r in row.main if r is not None]
        if not recipes:
            continue
        nulls = set.intersection(*({p for p, x in codec.leaves(r) if x is None} for r in recipes))
        for param, values in seen.items():
            for raw in values[:2] if len(values) > 1 and nulls else ():
                device = context.device(product_code)
                device["params"] = [{"param_type": param, "param_value": raw}]
                requests.append(
                    {
                        "kind": "set",
                        "identifier": ident,
                        "payload": row.main[0][0],
                        "device": device,
                    }
                )
                asks.append((ident, param, raw))
    replies = run_driver(product_code, handler, requests) if requests else []
    leaves: dict[tuple[str, int], list[tuple[str, dict[LeafPath, Any]]]] = {}
    for (ident, param, raw), reply in zip(asks, replies, strict=True):
        recipe = p2p(reply)
        flat = dict(codec.leaves(codec.slot(recipe, context))) if recipe is not None else {}
        leaves.setdefault((ident, param), []).append((raw, flat))
    out: dict[str, dict[LeafPath, str]] = {}
    for ident, row in rows.items():
        recipes = [r for _, r in row.main if r is not None]
        if not recipes:
            continue
        nulls = set.intersection(*({p for p, x in codec.leaves(r) if x is None} for r in recipes))
        for path in sorted(nulls, key=str):
            found = set()
            for param in seen:
                probes = leaves.get((ident, param), [])
                for form in ("int", "str"):
                    got = [flat.get(path, codec.MISSING) for _, flat in probes]
                    want = [codec.param_leaf(raw, form) for raw, _ in probes]
                    if len(probes) == 2 and want[0] != want[1] and got == want:
                        found.add(codec.param_slot(param, form))
                        break
            if len(found) == 1:
                out.setdefault(ident, {})[path] = found.pop()
                _count(counts, "write:param slot")
    return out


def _set_leaf(recipe: dict[str, Any], path: LeafPath, value: Any) -> None:
    node: Any = recipe
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def view_reads(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    context: codec.Context,
    counts: dict[str, int],
) -> None:
    """Add a per-view read to each enum whose write sends a ``quality`` per value and
    whose handler decodes a per-view report of that quality parameter.

    A multi-view camera reports such a parameter as base64 JSON
    ``{"mode_0": {"quality": q}, "mode_1": {…}, "cur_mode": m}``. Each value's quality is
    put in one view and another value's in the other, and getProperty is asked three
    times; the view rule whose picks match every answer is kept (``read.view``): ``by``
    the view-mode parameter (12 selects ``mode_1``), ``cur_mode`` (0 or 1 selects
    ``mode_0``) or null (always ``mode_0``). Read-map keys that are such reports are
    dropped, since the view read decodes them.
    """
    view, dual = VIEW_MODE_PARAM, DUAL_VIEW
    # Per rule and probe, whose quality getProperty returns: 0 the value's, 1 the other's.
    rules: dict[str | int | None, tuple[int, int, int]] = {
        view: (0, 0, 1),
        "cur_mode": (0, 1, 0),
        None: (0, 1, 1),
    }
    asks: list[tuple[str, int, Any, Any]] = []
    requests: list[dict[str, Any]] = []
    for ident, entry in settings.items():
        write, read = entry.get("write"), entry.get("read")
        params = write.get("params") if isinstance(write, dict) else None
        quality = params.get("quality") if isinstance(params, dict) else None
        if entry["kind"] != "enum" or not isinstance(quality, dict) or "$map" not in quality:
            continue
        param = (write.get("update") or {}).get("cmd") or write.get("subCmd")
        if not isinstance(param, int) or (read is not None and read["param"] != param):
            continue
        wire = {k: q for k, q in quality["$map"].items() if isinstance(q, int)}
        values = [v for v in entry.get("values") or () if codec.value_key(v) in wire]
        if len(values) < 2 or len(set(wire.values())) != len(wire):
            continue
        for i, v in enumerate(values):
            q, other = wire[codec.value_key(v)], values[(i + 1) % len(values)]
            q2 = wire[codec.value_key(other)]
            probes = ((q, q2, 0, 0), (q2, q, 0, dual), (q2, q, 2, 0))
            for n, (m0, m1, cur, mode) in enumerate(probes):
                report = {"mode_0": {"quality": m0}, "mode_1": {"quality": m1}, "cur_mode": cur}
                device = context.device(product_code)
                device["params"] = [
                    {"param_type": param, "param_value": _b64_json(report)},
                    {"param_type": view, "param_value": str(mode)},
                ]
                requests.append({"kind": "get", "cmds": [param, view], "device": device})
                asks.append((ident, n, v, other))
    replies = run_driver(product_code, handler, requests) if requests else []
    picks: dict[str, list[tuple[int, int | None]]] = {}
    for (ident, n, v, other), reply in zip(asks, replies, strict=True):
        got = (p2p(reply) or {}).get(ident, codec.MISSING)
        pick = 0 if codec.decodes_to(got, v) else 1 if codec.decodes_to(got, other) else None
        picks.setdefault(ident, []).append((n, pick))
    for ident, rows in picks.items():
        matching = [by for by, want in rules.items() if all(p == want[n] for n, p in rows)]
        if len(matching) != 1:
            continue
        entry = settings[ident]
        quality = entry["write"]["params"]["quality"]["$map"]
        values = {codec.value_key(v): v for v in entry["values"]}
        qmap = {str(q): values[k] for k, q in quality.items() if k in values}
        read = entry["read"] or {"param": param_of(entry), "map": {}}
        if read["map"] is not None:
            read["map"] = {k: v for k, v in read["map"].items() if not _is_view_report(k)}
        read["view"] = {"by": matching[0], "map": dict(sorted(qmap.items()))}
        entry["read"] = read
        note = entry.get("note")
        if note is not None:
            parts = [p for p in note.split("; ") if p != codec.ROUND_TRIP_NOTE]
            if parts:
                entry["note"] = "; ".join(parts)
            else:
                del entry["note"]
        _count(counts, "read:per view")


def param_of(entry: Mapping[str, Any]) -> int:
    write = entry["write"]
    cmd = (write.get("update") or {}).get("cmd") or write.get("subCmd")
    return int(cmd)


def _b64_json(obj: Any) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def _is_view_report(raw: str) -> bool:
    """``raw`` is base64 of a JSON object with a ``mode_0`` key."""
    try:
        obj = json.loads(base64.b64decode(raw, validate=True))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(obj, dict) and "mode_0" in obj


ABSENT_PRIOR = frozenset({"{}", _b64_json({})})
"""An update value the handler builds by changing a parameter the device does not hold:
the encoding of an empty JSON object."""


def _absent_prior(item: Mapping[str, Any]) -> bool:
    value = item.get("paramValue")
    return isinstance(value, str) and value in ABSENT_PRIOR


def drop_absent_prior_updates(settings: dict[str, Any], counts: dict[str, int]) -> None:
    """Leave out each ``update`` / ``extUpdates`` item whose value is :data:`ABSENT_PRIOR`.

    Such a value is the handler's read-modify-write of a parameter that was absent in the
    sweep; written to the local cache it would replace the device's real value with an
    empty object. The next parameter dump carries the new value.
    """
    for entry in settings.values():
        templates = [entry.get("write"), *(entry.get("write_table") or {}).values()]
        for template in templates:
            if not isinstance(template, dict):
                continue
            update = template.get("update")
            if isinstance(update, dict) and _absent_prior(update):
                del template["update"]
                _count(counts, "write:absent-prior update dropped")
            ext = template.get("extUpdates")
            if isinstance(ext, list):
                kept = [i for i in ext if not (isinstance(i, dict) and _absent_prior(i))]
                if len(kept) != len(ext):
                    _count(counts, "write:absent-prior update dropped", len(ext) - len(kept))
                    if kept:
                        template["extUpdates"] = kept
                    else:
                        del template["extUpdates"]


def empty_value_reads(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    context: codec.Context,
    counts: dict[str, int],
) -> None:
    """Add the empty parameter value to the read map of each readable enum or bool
    whose handler decodes ``""`` to one of its values (a dump can report the parameter
    empty)."""
    asks: list[tuple[str, list[Any]]] = []
    requests: list[dict[str, Any]] = []
    for ident, entry in settings.items():
        read = entry.get("read")
        if not isinstance(read, dict) or entry.get("bit") is not None:
            continue
        if entry["kind"] == "bool":
            values: list[Any] = [False, True]
        elif entry["kind"] == "enum":
            values = list(entry.get("values") or ())
        else:
            continue
        rmap = read.get("map")
        if rmap is not None and "" in rmap:
            continue
        device = context.device(product_code)
        device["params"] = [{"param_type": read["param"], "param_value": ""}]
        requests.append({"kind": "get", "cmds": [read["param"]], "device": device})
        asks.append((ident, values))
    replies = run_driver(product_code, handler, requests) if requests else []
    for (ident, values), reply in zip(asks, replies, strict=True):
        got = (p2p(reply) or {}).get(ident, codec.MISSING)
        hits = [v for v in values if codec.decodes_to(got, v)]
        if len(hits) != 1:
            continue
        read = settings[ident]["read"]
        rmap = read["map"]
        if rmap is None:
            rmap = {codec.str_form(v): v for v in values}
        read["map"] = {**rmap, "": hits[0]}
        _count(counts, "read:empty value")


def build_context(
    product_code: str,
    handler: Path,
    td: dict[str, Any],
    props: list[dict[str, Any]],
    *,
    context: codec.Context,
    swept: dict[str, Sweep],
    app_labels: dict[str, Any] | None,
    tree: dict[str, Any] | None,
    titles: dict[str, Any] | None,
    reference: list[dict[str, Any]],
    background: Mapping[int, Any],
    seen: Mapping[int, list[str]],
) -> tuple[dict[str, Any], dict[str, int]]:
    """The settings of one model in one context and its counters. ``background``: every
    parameter the model's writes set in any context, with one value each; ``seen``: the
    distinct values they set per parameter.

    Raises CheckError when a codec does not reproduce a swept recipe or an unaccepted
    reference row of this context.
    """
    counts: dict[str, int] = {}
    alt = codec.alt_channel(context)
    raw = {i: s.raw for i, s in swept.items()}
    reads = read_samples(product_code, handler, raw, context, counts)
    kinds = {p["identifier"]: codec.domain(p)[0] for p in props}
    # A handler keeps state between the requests of one driver run, so a read can fail
    # only for what the batch asked before it: ask each failed one again on its own.
    failed = {i for i, rows in reads.items() if codec.infer_read(kinds[i], rows)[0] is None}
    for ident in sorted(failed):
        alone = read_samples(product_code, handler, {ident: raw[ident]}, context, {})
        if ident in alone and codec.infer_read(kinds[ident], alone[ident])[0] is not None:
            reads[ident] = alone[ident]
            _count(counts, "read:asked alone")
    # A parser can need a parameter the write does not set (a trigger, a mode): ask once
    # more with every parameter the model's writes set, for the reads that failed.
    failed = {i for i, rows in reads.items() if codec.infer_read(kinds[i], rows)[0] is None}
    if failed and background:
        retry = read_samples(
            product_code,
            handler,
            {i: raw[i] for i in failed},
            context,
            counts,
            background=background,
        )
        for ident, rows in retry.items():
            if codec.infer_read(kinds[ident], rows)[0] is not None:
                reads[ident] = rows
                _count(counts, "read:with the other parameters")
    slots = param_slots(product_code, handler, context, swept, seen, counts=counts)
    settings: dict[str, Any] = {}
    for prop in props:
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
            row = swept[ident]
            result = codec.infer_write(kind, row.main, row.alt, context.channel, alt.channel)
            if result.note == "no handler write path" and row.rejected:
                result.note = "handler rejects the probed values"
            entry.update(copy.deepcopy(codec.codec_fields(result)))
            for template in [entry.get("write"), *(entry.get("write_table") or {}).values()]:
                for path, slot_name in slots.get(ident, {}).items() if template else ():
                    _set_leaf(template, path, slot_name)
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
            else:
                _count(counts, f"ro:{result.note}")
        settings[ident] = entry
    try:
        joined = joiner.join(product_code, settings, td, app_labels, tree, titles=titles)
    except GeneratorError as err:
        raise GeneratorError(f"{product_code}: {err}") from err
    for key, n in joined.items():
        _count(counts, key, n)
    found = sweep_mismatches(settings, swept, context)
    found += reference_mismatches(settings, reference)
    _raise_unaccepted(product_code, context, found, "codec mismatches")
    if reference:
        _count(counts, "reference_rows", len(reference))
    shape_controls(product_code, handler, settings, counts, context)
    view_reads(product_code, handler, settings, context, counts)
    drop_absent_prior_updates(settings, counts)
    empty_value_reads(product_code, handler, settings, context, counts)
    return settings, counts


def _raise_unaccepted(
    product_code: str, context: codec.Context, found: list[tuple[str, str]], what: str
) -> None:
    failed = [(i, d) for i, d in found if (product_code, i) not in RELEASE_ACCEPTED]
    if failed:
        lines = "\n".join(f"  {product_code} {i}: {d}" for i, d in failed)
        raise CheckError(f"{product_code} ({context_name(context)}): {len(failed)} {what}\n{lines}")


def context_name(context: codec.Context) -> str:
    if context.name == codec.STANDALONE.name:
        return STANDALONE
    return next((n for n, sn in codec.CONNECT_PARENTS.items() if sn == context.station_sn), BASE)


def merge_contexts(per_context: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The base context's settings, each carrying under ``contexts`` the fields every
    other context changes: ``[{"names": [...], "entry": {field: value or null}}]``, one
    item per distinct change, ``null`` for a field the context lacks.

    Raises GeneratorError when the contexts do not list the same settings.
    """
    base = per_context[BASE]
    for name, settings in per_context.items():
        if set(settings) != set(base):
            missing = sorted(set(base) ^ set(settings))
            raise GeneratorError(f"context {name} lists other settings: {missing}")
    out: dict[str, Any] = {}
    for key, entry in base.items():
        groups: dict[str, tuple[dict[str, Any], list[str]]] = {}
        for name in sorted(n for n in per_context if n != BASE):
            other = per_context[name][key]
            diff = {
                k: other.get(k)
                for k in sorted(set(entry) | set(other))
                if _canon(entry.get(k)) != _canon(other.get(k))
            }
            if diff:
                groups.setdefault(_canon(diff), (diff, []))[1].append(name)
        merged = dict(entry)
        if groups:
            merged["contexts"] = [
                {"names": names, "entry": diff}
                for diff, names in sorted(groups.values(), key=lambda g: g[1])
            ]
        out[key] = merged
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
    """The settings-file object of one model and its counters (the base context's).

    ``app_labels`` / ``tree`` are the model's entries of the label and settings-tree
    files (None: TD labels only / no UI placement); ``reference`` its v1 reference rows
    (``child`` rows check the base context, ``standalone`` rows the standalone one);
    ``titles`` the app setting-title file (None: no names, app units or variants).
    Raises CheckError when a codec does not reproduce a swept recipe or an unaccepted
    reference row.
    """
    folder = cache / product_code
    td = json.loads((folder / "td.json").read_text(encoding="utf-8"))
    handler = folder / f"{product_code}Handle.mix.js"
    props = []
    skipped = 0
    for prop in td.get("properties", []):
        if not isinstance(prop, dict):
            continue
        ident = prop.get("identifier")
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident):
            skipped += 1
            continue
        props.append(prop)
    contexts = contexts_of(product_code)
    swept = sweep(product_code, handler, props, contexts)
    background: dict[int, Any] = {}
    seen: dict[int, list[str]] = {}
    for rows in swept.values():
        for row in rows.values():
            for _, recipe in row.raw:
                for p in _param_dump(recipe):
                    background.setdefault(p["param_type"], p["param_value"])
                    if isinstance(p["param_value"], str):
                        found = seen.setdefault(p["param_type"], [])
                        if p["param_value"] not in found:
                            found.append(p["param_value"])
    rows = reference or []
    per_context: dict[str, dict[str, Any]] = {}
    references: dict[str, list[dict[str, Any]]] = {}
    counts: dict[str, int] = {}
    for name, ctx in contexts.items():
        wanted = {BASE: "child", STANDALONE: "standalone"}.get(name)
        references[name] = [r for r in rows if r["context"] == wanted]
        settings, ctx_counts = build_context(
            product_code,
            handler,
            td,
            props,
            context=ctx,
            swept=swept[name],
            app_labels=app_labels,
            tree=tree,
            titles=titles,
            reference=references[name],
            background=background,
            seen=seen,
        )
        per_context[name] = settings
        if name == BASE:
            counts = ctx_counts
    # A variant is dropped only where it duplicates its primary in every context.
    drop = set.intersection(*(set(controls.same_codec_variants(s)) for s in per_context.values()))
    for name, settings in per_context.items():
        controls.drop_same_codec_variants(settings, counts if name == BASE else {}, only=drop)
        shaped = reference_mismatches(settings, references[name])
        _raise_unaccepted(product_code, contexts[name], shaped, "shaped settings differ")
    if skipped:
        counts["skipped"] = skipped
    merged = merge_contexts(per_context)
    for entry in merged.values():
        for item in entry.get("contexts", ()):
            for name in item["names"]:
                _count(counts, f"context:{name}")
    doc = {
        "schema_version": SCHEMA_VERSION,
        "product_code": product_code,
        "source": joiner.source_block(td, app_version),
        "settings": merged,
    }
    return doc, counts


def shape_controls(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    counts: dict[str, int],
    context: codec.Context,
) -> None:
    """Bit switches, flags, scales, same-write variants and controls
    (``scripts/gen_models_controls.py``), probing the handler once more in ``context``
    for the first two. Same-codec variants are dropped across contexts (``generate``)."""

    def device(params: dict[int, str]) -> dict[str, Any]:
        dev = context.device(product_code)
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
                "device": context.device(product_code),
            },
        )
        for ident, values in flags.items()
        for payload in [codec.value_key(v) for v in values] + controls.flag_payloads(values)
    ]
    requests = [r for *_, r in bit_reqs] + [r for *_, r in flag_reqs]
    replies = run_driver(product_code, handler, requests) if requests else []

    def slotted(reply: Any) -> Any:
        recipe = p2p(reply)
        return None if recipe is None else codec.slot(recipe, context)

    bit_replies = {
        (ident, value): slotted(rep)
        for (ident, value, _), rep in zip(bit_reqs, replies, strict=False)
    }
    flag_replies = {
        (ident, payload): slotted(rep)
        for (ident, payload, _), rep in zip(flag_reqs, replies[len(bit_reqs) :], strict=True)
    }
    controls.apply_bits(settings, bits, bit_replies, counts, channel=context.channel)
    singles = {
        ident: [(v, flag_replies.get((ident, codec.value_key(v)))) for v in values]
        for ident, values in flags.items()
    }
    controls.apply_flags(settings, flags, singles, flag_replies, counts, channel=context.channel)
    controls.apply_scales(settings, gates, counts)
    controls.apply_duplicate_variants(settings, counts)
    controls.apply_domains(settings, counts)
    controls.apply_controls(settings, counts)


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
