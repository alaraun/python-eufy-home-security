"""Control shaping for ``scripts/gen_models.py``: bit switches, flags, scales, controls.

Runs after the codecs, labels and checks of a model are final. Each transform rewrites a
setting only when the vendor handler's own recipes prove the new form renders the same
wire values (the probe replies are passed in; this module does no I/O):

- **bit**: a bool written as one bit of a parameter other settings share. The handler
  read-modifies-writes it (with the parameter at ``other`` it sends ``other | bit`` and
  ``other``), so the setting gets ``bit`` and a ``$v:int`` template the library fills with
  the whole current mask.
- **flags**: an enum whose comma-joined payload renders the OR of its members' values;
  it becomes ``kind: flags`` with ``flags: {member: bits}`` and a mask template.
- **scale**: an enum whose labels are the numbers ``1..N`` (or ``0..N``) in order becomes
  a ``range`` of those numbers.
- **variant**: a setting whose write codec equals that of a shorter key it extends
  (``detection_sensitivity_test_mode``) is ``variant_of`` that key; when only the longer
  one reads, and it reads the parameter the shared write updates, the shorter one takes
  that read.

Then every ``rw`` setting gets ``control`` (see ``control_of``), and an ``rw`` variant
whose whole codec equals its primary's is dropped (``drop_same_codec_variants``).
See docs/reference/models-schema.md.
"""

from __future__ import annotations

import copy
import itertools
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import gen_models_codec as codec

type Settings = dict[str, dict[str, Any]]
type Recipe = dict[str, Any]

SLIDER_MAX_STEPS = 200  # the library's SLIDER_MAX_STEPS
CONTROL_BY_KIND = {"bool": "switch", "enum": "select", "flags": "toggles", "string": "text"}
_OTHER_BITS = 0x5A5  # bits set in the shared parameter while probing a bit switch


def _count(counts: dict[str, int], key: str, n: int = 1) -> None:
    counts[key] = counts.get(key, 0) + n


def _as_int(x: Any) -> int | None:
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str) and x.lstrip("-").isdigit():
        return int(x)
    return None


def _maps(x: Any) -> list[dict[str, Any]]:
    """Every ``{"$map": ...}`` argument in a template."""
    if isinstance(x, dict):
        if set(x) == {"$map"} and isinstance(x["$map"], dict):
            return [x["$map"]]
        return [m for v in x.values() for m in _maps(v)]
    if isinstance(x, list):
        return [m for v in x for m in _maps(v)]
    return []


def _swap_maps(x: Any, slot_of: Callable[[dict[str, Any]], Any | None]) -> Any:
    """``x`` with each ``$map`` replaced by ``slot_of(map)`` when that is not None."""
    if isinstance(x, dict):
        if set(x) == {"$map"} and isinstance(x["$map"], dict):
            new = slot_of(x["$map"])
            return x if new is None else new
        return {k: _swap_maps(v, slot_of) for k, v in x.items()}
    if isinstance(x, list):
        return [_swap_maps(v, slot_of) for v in x]
    return x


def _plain_write(entry: Mapping[str, Any]) -> bool:
    """An rw setting with one template (no value table) the transforms can rewrite."""
    return entry.get("access") == "rw" and "write" in entry and "write_table" not in entry


def _templates(entry: Mapping[str, Any]) -> list[str]:
    return [k for k in ("write", "write_standalone") if k in entry]


def _param_of(entry: Mapping[str, Any]) -> int | None:
    """The parameter a write updates (``update.cmd``, else the one ``extUpdates`` item),
    else the read parameter."""
    write = entry.get("write", {})
    update = write.get("update")
    if isinstance(update, dict) and isinstance(update.get("cmd"), int):
        return int(update["cmd"])
    ext = [u.get("cmd") for u in write.get("extUpdates") or [] if isinstance(u, dict)]
    if len(ext) == 1 and isinstance(ext[0], int):
        return int(ext[0])
    read = entry.get("read")
    return read["param"] if isinstance(read, dict) else None


def _params(recipe: Recipe | None) -> Any:
    return None if recipe is None else recipe.get("params")


# ── bit switches ────────────────────────────────────────────────────────────


def bit_candidates(settings: Settings) -> dict[str, tuple[int, int]]:
    """``{ident: (bit, param)}``: rw bools writing ``0`` / one power of two to a param."""
    out: dict[str, tuple[int, int]] = {}
    for ident, entry in settings.items():
        if entry.get("kind") != "bool" or not _plain_write(entry):
            continue
        param = _param_of(entry)
        bits = {
            _as_int(m.get("true"))
            for m in _maps(entry["write"])
            if _as_int(m.get("false")) == 0 and set(m) == {"false", "true"}
        }
        if param is None or len(bits) != 1:
            continue
        (bit,) = bits
        if bit is not None and bit > 0 and bit & (bit - 1) == 0:
            out[ident] = (bit, param)
    return out


def bit_requests(
    candidates: Mapping[str, tuple[int, int]], device: Callable[[dict[int, str]], dict[str, Any]]
) -> list[tuple[str, bool, dict[str, Any]]]:
    """``(ident, value, set request)``: true with the param at ``other``, false at ``other|bit``."""
    out = []
    for ident, (bit, param) in candidates.items():
        other = _OTHER_BITS & ~bit
        for value, current in ((True, other), (False, other | bit)):
            out.append(
                (
                    ident,
                    value,
                    {
                        "kind": "set",
                        "identifier": ident,
                        "payload": value,
                        "device": device({param: str(current)}),
                    },
                )
            )
    return out


def _mask_slot(bits: set[int]) -> Callable[[dict[str, Any]], Any | None]:
    """A ``$map`` whose values are exactly ``bits`` (ints or digit strings) -> mask slot."""

    def slot(m: dict[str, Any]) -> Any | None:
        values = list(m.values())
        ints = {_as_int(v) for v in values}
        if not values or None in ints or not ints <= bits:
            return None
        return "$v:str" if all(isinstance(v, str) for v in values) else "$v:int"

    return slot


def apply_bits(
    settings: Settings,
    candidates: Mapping[str, tuple[int, int]],
    replies: Mapping[tuple[str, bool], Recipe | None],
    counts: dict[str, int],
) -> None:
    """Give each candidate the handler read-modify-writes a ``bit`` and a mask template."""
    for ident, (bit, param) in candidates.items():
        other = _OTHER_BITS & ~bit
        on, off = replies.get((ident, True)), replies.get((ident, False))
        entry = settings[ident]
        new = copy.deepcopy(entry)
        for key in _templates(new):
            new[key] = _swap_maps(new[key], _mask_slot({0, bit}))
        ctx = codec.CHILD
        try:
            good = (
                on is not None
                and off is not None
                and _params(codec.render(new, other | bit, context=ctx.name, channel=ctx.channel))
                == _params(on)
                and _params(codec.render(new, other, context=ctx.name, channel=ctx.channel))
                == _params(off)
            )
        except ValueError:
            good = False
        if not good:
            _count(counts, "bit:handler writes blind")
            continue
        new["bit"] = bit
        new["read"] = {"param": param, "map": None}
        if new.get("note") == codec.ROUND_TRIP_NOTE:
            new.pop("note")
        settings[ident] = new
        _count(counts, "bit")


# ── flags ───────────────────────────────────────────────────────────────────


def flag_candidates(settings: Settings, gates: set[str]) -> dict[str, list[Any]]:
    """``{ident: values}``: rw enums of two or more values that gate nothing."""
    return {
        ident: list(entry["values"])
        for ident, entry in settings.items()
        if entry.get("kind") == "enum"
        and _plain_write(entry)
        and len(entry.get("values", ())) >= 2
        and ident not in gates
    }


def flag_payloads(values: Sequence[Any]) -> list[str]:
    """The joined payloads probed: every neighbouring pair, then all values."""
    keys = [codec.value_key(v) for v in values]
    pairs = [f"{a},{b}" for a, b in itertools.pairwise(keys)]
    return [*pairs, ",".join(keys)]


def _numeric_leaves(recipe: Recipe | None) -> dict[codec.Path, int]:
    out = {}
    for path, leaf in codec.leaves({"params": _params(recipe)}):
        n = _as_int(leaf)
        if n is not None:
            out[path] = n
    return out


def apply_flags(
    settings: Settings,
    candidates: Mapping[str, list[Any]],
    singles: Mapping[str, Sequence[tuple[Any, Recipe | None]]],
    joined: Mapping[tuple[str, str], Recipe | None],
    counts: dict[str, int],
) -> None:
    """Turn each candidate whose joined payloads render the OR of its members into flags."""
    for ident, values in candidates.items():
        by_value = {codec.value_key(v): r for v, r in singles.get(ident, ())}
        leaves = {k: _numeric_leaves(r) for k, r in by_value.items()}
        if len(leaves) != len(values) or any(r is None for r in by_value.values()):
            continue
        paths = {p for lv in leaves.values() for p in lv}
        varying = [p for p in paths if len({lv.get(p) for lv in leaves.values()}) > 1]
        if len(varying) != 1:
            continue
        (path,) = varying
        bits = {k: lv.get(path) for k, lv in leaves.items()}
        if any(b is None or b < 0 for b in bits.values()):
            continue
        members = {k: int(b) for k, b in bits.items() if b}  # a 0 member sets no bit
        if len(members) < 2:
            continue
        keys = [codec.value_key(v) for v in values]
        ok = True
        for payload in flag_payloads(values):
            want = 0
            parts = payload.split(",")
            for part in parts:
                want |= bits[part] or 0
            got = _numeric_leaves(joined.get((ident, payload))).get(path)
            overlap = any(
                members.get(a, 0) & members.get(b, 0)
                for i, a in enumerate(parts)
                for b in parts[i + 1 :]
            )
            if got != want or overlap:
                ok = False
                break
        if not ok:
            continue
        entry = settings[ident]
        new = copy.deepcopy(entry)
        for key in _templates(new):
            new[key] = _swap_maps(
                new[key], _mask_slot({int(b) for b in bits.values() if b is not None})
            )
        if any(_maps(new[key]) for key in _templates(new)):
            _count(counts, "flags:another field is keyed by the value")
            continue
        read = entry.get("read")
        rmap = read.get("map") if isinstance(read, dict) else None
        if rmap is not None and any(
            _as_int(raw) != bits.get(codec.value_key(v)) for raw, v in rmap.items()
        ):
            _count(counts, "flags:read is not the member's bits")
            continue
        all_bits = 0
        for b in members.values():
            all_bits |= b
        ctx = codec.CHILD
        try:
            rendered = codec.render(new, all_bits, context=ctx.name, channel=ctx.channel)
            same = _numeric_leaves(rendered) == _numeric_leaves(joined.get((ident, ",".join(keys))))
        except ValueError:
            same = False
        if not same:
            _count(counts, "flags:template does not render the joined recipe")
            continue
        new["kind"] = "flags"
        new["flags"] = members
        new["labels"] = {k: v for k, v in entry.get("labels", {}).items() if k in members}
        for key in ("values", "default"):
            new.pop(key, None)
        param = _param_of(entry)
        if param is None:
            _count(counts, "flags:no parameter holds the mask")
            continue
        new["read"] = {"param": param, "map": None}
        if new.get("note") == codec.ROUND_TRIP_NOTE:
            new.pop("note")
        settings[ident] = new
        _count(counts, "flags")
        if len(members) < len(values):
            _count(counts, "flags:member without a bit dropped", len(values) - len(members))


# ── numbered scales ─────────────────────────────────────────────────────────


def _scale(entry: Mapping[str, Any]) -> list[int] | None:
    """The numbers an enum's labels show, in value order, when they count up by one."""
    labels = entry.get("labels") or {}
    shown = [_as_int(labels.get(codec.value_key(v))) for v in entry.get("values", ())]
    if len(shown) < 3 or None in shown:
        return None
    numbers = [n for n in shown if n is not None]
    if numbers != list(range(numbers[0], numbers[0] + len(numbers))):
        return None
    return numbers


def apply_scales(settings: Settings, gates: set[str], counts: dict[str, int]) -> None:
    """Turn rw enums labelled ``1..N`` into a range of those numbers, when the write and
    read codecs can be restated for them (a slot or an affine map)."""
    for ident, entry in list(settings.items()):
        if entry.get("kind") != "enum" or not _plain_write(entry) or ident in gates:
            continue
        shown = _scale(entry)
        if shown is None:
            continue
        values = list(entry["values"])
        by_key = {codec.value_key(v): n for v, n in zip(values, shown, strict=True)}
        failed = False

        def restate(m: dict[str, Any], *, by_key: dict[str, int] = by_key) -> Any:
            nonlocal failed
            column = [m.get(k) for k in by_key]
            numbers = list(by_key.values())
            form = codec._value_slot(column, numbers)
            if form is not None:
                return form
            coeffs = codec._affine(column, numbers)
            if coeffs is None:
                failed = True
                return None
            return {"$affine": coeffs}

        new = copy.deepcopy(entry)
        for key in _templates(new):
            if _uses_value_directly(new[key]):
                failed = True
            new[key] = _swap_maps(new[key], restate)
        read = entry.get("read")
        if isinstance(read, dict):
            rmap = read.get("map")
            raw_map = {codec.value_key(v): v for v in values} if rmap is None else dict(rmap)
            mapped = {raw: by_key.get(codec.value_key(v)) for raw, v in raw_map.items()}
            if None in mapped.values():
                failed = True
            identity = all(raw == str(n) for raw, n in mapped.items())
            new["read"] = {"param": read["param"], "map": None if identity else mapped}
        if failed or not _renders_alike(entry, new, values, shown):
            _count(counts, "scale:codec not restatable")
            continue
        new["kind"] = "range"
        new["min"], new["max"], new["step"] = shown[0], shown[-1], 1
        if "default" in entry:
            new["default"] = by_key.get(codec.value_key(entry["default"]))
        for key in ("values", "labels"):
            new.pop(key, None)
        settings[ident] = new
        _count(counts, "scale")


def _uses_value_directly(template: Any) -> bool:
    """Whether a template places the public value itself (a slot outside any ``$map``)."""
    return any(
        isinstance(leaf, str) and leaf in ("$v", "$v:str", "$v:int")
        for _, leaf in codec.leaves(template)
    )


def _renders_alike(
    old: Mapping[str, Any], new: Mapping[str, Any], values: Sequence[Any], shown: Sequence[int]
) -> bool:
    for ctx in codec.CONTEXTS:
        for v, n in zip(values, shown, strict=True):
            try:
                a = codec.render(old, v, context=ctx.name, channel=ctx.channel)
                b = codec.render(new, n, context=ctx.name, channel=ctx.channel)
            except ValueError:
                return False
            if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
                return False
    return True


# ── duplicate codecs ────────────────────────────────────────────────────────

_WRITE_KEYS = ("kind", "write", "write_standalone", "write_table", "values", "min", "max")


def _write_sig(entry: Mapping[str, Any]) -> str:
    return json.dumps({k: entry.get(k) for k in _WRITE_KEYS}, sort_keys=True)


def apply_duplicate_variants(settings: Settings, counts: dict[str, int]) -> None:
    """``variant_of`` for an rw setting whose write equals a shorter key it extends."""
    for ident, entry in settings.items():
        if entry.get("access") != "rw" or "variant_of" in entry:
            continue
        for base, other in settings.items():
            if (
                base == ident
                or not ident.startswith(f"{base}_")
                or other.get("access") != "rw"
                or "variant_of" in other
                or _write_sig(other) != _write_sig(entry)
            ):
                continue
            read, base_read = entry.get("read"), other.get("read")
            if base_read is None and isinstance(read, dict) and read["param"] == _param_of(entry):
                other["read"] = copy.deepcopy(read)
                if other.get("note") == codec.ROUND_TRIP_NOTE:
                    other.pop("note")
                _count(counts, "read:from the same write")
            elif base_read != read:
                continue
            entry["variant_of"] = base
            _count(counts, "variant_of:same write")
            break


# Keys a variant may lack or carry differently and still be dropped for its primary.
_PLACEMENT_KEYS = ("page", "group", "order")


def absorbed_by(ident: str, settings: Mapping[str, Any]) -> str | None:
    """The setting a key dropped as a duplicate is checked through: the longest other key
    of ``settings`` that ``ident`` extends (``<key>_…``), or None."""
    bases = [k for k in settings if k != ident and ident.startswith(f"{k}_")]
    return max(bases, key=len) if bases else None


def drop_same_codec_variants(settings: Settings, counts: dict[str, int]) -> None:
    """Remove an rw variant whose codec, labels and control equal its primary's.

    Kept: a variant that differs in anything but placement, one whose placement the
    primary lacks, one another setting's ``applies_when`` names, and one whose key does
    not extend its primary's (``absorbed_by`` must find the primary from the file alone).
    """
    gates = {e["applies_when"][0] for e in settings.values() if e.get("applies_when")}
    for ident in list(settings):
        entry = settings[ident]
        primary = entry.get("variant_of")
        if primary is None or entry.get("access") != "rw" or ident in gates:
            continue
        rest = {k: v for k, v in settings.items() if k != ident}
        if absorbed_by(ident, rest) != primary:
            continue
        base = settings[primary]
        if any(k in entry and entry[k] != base.get(k) for k in _PLACEMENT_KEYS):
            continue
        skip = {"variant_of", *_PLACEMENT_KEYS}
        mine = {k: v for k, v in entry.items() if k not in skip}
        theirs = {k: v for k, v in base.items() if k not in skip}
        if json.dumps(mine, sort_keys=True) != json.dumps(theirs, sort_keys=True):
            continue
        del settings[ident]
        _count(counts, "dropped:same codec variant")


# ── reference payloads ──────────────────────────────────────────────────────


def reference_value(entry: Mapping[str, Any], row: Mapping[str, Any]) -> Any:
    """A v1 reference row's payload in the public form of a shaped entry.

    The rows were recorded on the unshaped settings. A flags member becomes its bits, a
    bit switch's bool its mask with only that bit, and a range payload that does not
    reproduce the row's recipe the one value in the range that does (a numbered scale's
    enum index -> the shown number). Raises ValueError when no single value fits.
    """
    payload = row["payload"]
    if entry.get("kind") == "flags":
        return entry["flags"].get(codec.value_key(payload), 0)
    if entry.get("bit") is not None:
        return entry["bit"] if codec.coerce({"kind": "bool"}, payload) else 0
    if entry.get("kind") != "range":
        return payload
    want = _params(row["recipe"])

    def renders(value: Any) -> bool:
        try:
            got = codec.render(entry, value, context=row["context"], channel=row["channel"])
        except ValueError:
            return False
        return _params(got) == want

    if renders(payload):
        return payload
    lo, hi, step = entry["min"], entry["max"], entry.get("step") or 1
    hits = [
        v
        for i in range(round((hi - lo) / step) + 1)
        if renders(v := codec.intify(round(lo + i * step, 9)))
    ]
    if len(hits) != 1:
        raise ValueError(f"{len(hits)} range values reproduce the reference recipe")
    return hits[0]


# ── controls ────────────────────────────────────────────────────────────────


def control_of(entry: Mapping[str, Any]) -> str | None:
    """The UI control of an rw setting: switch, select, toggles, text, or for a range a
    slider of at most ``SLIDER_MAX_STEPS`` steps, else a box; None for ``other``. A string
    with a ``domain`` (a fixed list the library supplies) is a select."""
    kind = entry.get("kind")
    if kind == "range":
        lo, hi, step = entry.get("min"), entry.get("max"), entry.get("step") or 1
        if lo is None or hi is None:
            return "box"
        return "slider" if (hi - lo) / step <= SLIDER_MAX_STEPS else "box"
    if kind == "string" and entry.get("domain") is not None:
        return "select"
    return CONTROL_BY_KIND.get(str(kind))


# Command ids whose string value is one row of a library table (the app's own list), and
# the table's domain name: 1215 is the device time zone (the app's zone table).
DOMAIN_BY_CMD = {1215: "timezone"}


def apply_domains(settings: Settings, counts: dict[str, int]) -> None:
    """Mark an rw string setting whose write is a ``DOMAIN_BY_CMD`` command (no sub-command)
    with that ``domain``."""
    for entry in settings.values():
        entry.pop("domain", None)
        write = entry.get("write")
        if entry.get("access") != "rw" or entry.get("kind") != "string":
            continue
        if not isinstance(write, dict) or "subCmd" in write:
            continue
        domain = DOMAIN_BY_CMD.get(write.get("cmd"))  # type: ignore[arg-type]
        if domain is not None:
            entry["domain"] = domain
            _count(counts, f"domain:{domain}")


def apply_controls(settings: Settings, counts: dict[str, int]) -> None:
    for entry in settings.values():
        entry.pop("control", None)
        if entry.get("access") == "rw" and (control := control_of(entry)) is not None:
            entry["control"] = control
            _count(counts, f"control:{control}")
