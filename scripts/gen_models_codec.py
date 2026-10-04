"""Pure write-codec inference for ``scripts/gen_models.py`` (no I/O).

Turns a model's thing-description property and the handler's setProperty recipes for each
value of its domain into a write codec: the recipe with value positions replaced by slots.
See docs/reference/models-schema.md.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# The TD readers live in the library; the generator reaches them through this module.
from eufy_home_security.devices.td import (  # noqa: F401 - re-exported
    intify,
    kind_of,
    public_value,
    range_spec,
    specs_of,
    td_default,
)

type Value = bool | int | float | str
type Recipe = dict[str, Any]
type Path = tuple[str | int, ...]

VOLATILE_KEYS = frozenset({"transaction", "buildTimestamp"})
RANGE_FULL_POINTS = 41
FIXED_CLOCK_MS = 1700000000000  # the driver's Date.now()
# Two probes for open domains, so a leaf that only happens to equal one probe is no slot.
STRING_PROBES = ("probe", "probe2")
OTHER_PROBES = (0, 1)


@dataclass(frozen=True)
class Context:
    """A synthetic device context the handler is run in."""

    name: str
    device_sn: str
    station_sn: str
    channel: int

    def device(self, product_code: str) -> dict[str, Any]:
        """The ``device`` object of a setProperty/getProperty message."""
        return {
            "device_sn": self.device_sn,
            "parent_sn": self.station_sn,
            "station_sn": self.station_sn,
            "device_pn": product_code,
            "device_channel": self.channel,
            "channel": self.channel,
            "main_sw_version": "9.9.9.9",
            "params": [],
        }


CHILD = Context("child", "T0000CHILDSN0001", "T0000STATION0001", 3)
STANDALONE = Context("standalone", "T0000ALONESN0001", "T0000ALONESN0001", 0)
CONTEXTS = (CHILD, STANDALONE)


class GeneratorError(Exception):
    """A model could not be generated."""


@dataclass
class WriteCodec:
    """The inferred write side of one setting."""

    access: str = "ro"
    write: Recipe | None = None
    write_standalone: Recipe | None = None
    write_table: dict[str, Recipe] | None = None
    note: str | None = None
    form: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _snap(x: float, lo: float, step: float) -> float:
    return lo + round((x - lo) / step) * step


def domain(prop: Mapping[str, Any]) -> tuple[str, list[Value]]:
    """The kind and the public values swept for a property."""
    kind = kind_of(prop)
    if kind == "enum":
        return kind, [public_value(e.get("value")) for e in specs_of(prop)["eunmList"]]
    if kind == "bool":
        return kind, [False, True]
    if kind == "range":
        lo, hi, step = range_spec(prop)
        n = round((hi - lo) / step) + 1
        if n <= RANGE_FULL_POINTS:
            points = {lo + i * step for i in range(n)}
        else:
            points = {lo, lo + step, _snap((lo + hi) / 2, lo, step), hi - step, hi}
            points |= {_snap(lo + (hi - lo) * i / 6, lo, step) for i in range(1, 6)}
        return kind, [intify(round(p, 9)) for p in sorted(points)]
    if kind == "string":
        return kind, list(STRING_PROBES)
    return kind, list(OTHER_PROBES)


def value_key(value: Value) -> str:
    """The JSON-object key form of a public value (``"3"``, ``"true"``)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def slot(recipe: Any, context: Context) -> Any:
    """Drop volatile keys at any depth and replace the context's serials by slots."""
    if isinstance(recipe, dict):
        return {k: slot(v, context) for k, v in recipe.items() if k not in VOLATILE_KEYS}
    if isinstance(recipe, list):
        return [slot(v, context) for v in recipe]
    if isinstance(recipe, str):
        if recipe == context.device_sn:
            return "$device_sn"
        if recipe == context.station_sn:
            return "$station_sn"
    return recipe


def leaves(x: Any, path: Path = ()) -> Iterator[tuple[Path, Any]]:
    """Every scalar leaf of a recipe with its path, in document order."""
    if isinstance(x, dict):
        for k, v in x.items():
            yield from leaves(v, (*path, k))
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from leaves(v, (*path, i))
    else:
        yield path, x


def _replace(x: Any, subst: Mapping[Path, Any], path: Path = ()) -> Any:
    if path in subst:
        return subst[path]
    if isinstance(x, dict):
        return {k: _replace(v, subst, (*path, k)) for k, v in x.items()}
    if isinstance(x, list):
        return [_replace(v, subst, (*path, i)) for i, v in enumerate(x)]
    return x


def _same(a: Any, b: Any) -> bool:
    """Equality that keeps bools apart from numbers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    return type(a) is type(b) and bool(a == b)


type Samples = Sequence[tuple[Value, Recipe | None]]

FAKE_SERIALS = tuple(sorted({s for c in CONTEXTS for s in (c.device_sn, c.station_sn)}))
SINGLE_PROBE_KINDS = frozenset({"string", "other"})  # open domains, probed only


def _str_form(value: Value) -> str:
    """The string the handler writes for a value (bools as ``"0"``/``"1"``)."""
    if isinstance(value, bool):
        return str(int(value))
    return str(value)


def _int_form(value: Value) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _value_slot(column: Sequence[Any], values: Sequence[Value]) -> str | None:
    """``$v`` / ``$v:str`` / ``$v:int`` when the column holds the value on every sample."""
    pairs = list(zip(column, values, strict=True))
    if all(_same(leaf, v) for leaf, v in pairs):
        return "$v"
    if all(isinstance(leaf, str) and leaf == _str_form(v) for leaf, v in pairs):
        return "$v:str"
    if all(
        isinstance(leaf, int) and not isinstance(leaf, bool) and leaf == _int_form(v)
        for leaf, v in pairs
    ):
        return "$v:int"
    return None


def _affine(column: Sequence[Any], values: Sequence[Value]) -> list[int | float] | None:
    """``[a, b]`` with ``leaf == a*v + b`` on every sample, or None."""
    if not all(isinstance(x, int | float) and not isinstance(x, bool) for x in (*column, *values)):
        return None
    xs = [float(v) for v in values]
    ys = [float(leaf) for leaf in column]
    if len(set(xs)) < 2:
        return None
    i, j = 0, next(k for k, x in enumerate(xs) if x != xs[0])
    a = (ys[j] - ys[i]) / (xs[j] - xs[i])
    b = ys[i] - a * xs[i]
    if not all(abs(a * x + b - y) <= 1e-9 * max(1.0, abs(y)) for x, y in zip(xs, ys, strict=True)):
        return None
    return [intify(round(a, 9)), intify(round(b, 9))]


def _channel_paths(child: Samples, standalone: Samples) -> dict[str, set[Path]]:
    """Per value key: leaf paths that are the context channel (3 as child, 0 standalone)."""
    alone = {value_key(v): r for v, r in standalone}
    out: dict[str, set[Path]] = {}
    for v, rc in child:
        rs = alone.get(value_key(v))
        if rc is None or rs is None:
            continue
        flat = dict(leaves(rs))
        out[value_key(v)] = {
            p
            for p, leaf in leaves(rc)
            if _same(leaf, CHILD.channel) and _same(flat.get(p), STANDALONE.channel)
        }
    return out


def _has_embedded_serial(samples: Samples) -> bool:
    return any(
        isinstance(leaf, str) and any(sn in leaf for sn in FAKE_SERIALS)
        for _, r in samples
        if r is not None
        for _, leaf in leaves(r)
    )


@dataclass(frozen=True)
class _Fit:
    """The codec of one context: a template, a table, or a read-only reason."""

    form: str | None
    write: Recipe | None = None
    table: dict[str, Recipe] | None = None
    note: str | None = None


def _fit(kind: str, samples: Samples, channel: Mapping[str, set[Path]]) -> _Fit:
    """Infer one context's codec from samples whose channel leaves are ``channel``."""
    present = [r for _, r in samples]
    if not any(present):
        return _Fit(None, note="no handler write path")
    if any(r is None for r in present):
        return _Fit(None, note="handler rejects some values")
    values = [v for v, _ in samples]
    recipes = [
        _replace(r, dict.fromkeys(channel.get(value_key(v), ()), "$channel")) for v, r in samples
    ]
    shapes = {json.dumps([p for p, _ in leaves(r)]) for r in recipes}
    if len(shapes) > 1:
        if kind in SINGLE_PROBE_KINDS:
            return _Fit(None, note="handler expects a structured value")
        return _Fit("table", table={value_key(v): r for v, r in zip(values, recipes, strict=True)})
    first = recipes[0]
    if len(values) == 1 and kind == "enum":
        # The only value there is: the recipe as it stands is the write.
        return _Fit("fixed", write=first)
    flats = [dict(leaves(r)) for r in recipes]
    subst: dict[Path, Any] = {}
    forms: set[str] = set()
    for path, _ in leaves(first):
        column = [f[path] for f in flats]
        if len(values) > 1 and all(_same(leaf, column[0]) for leaf in column):
            continue
        form = _value_slot(column, values)
        if form is not None:
            subst[path], _ = form, forms.add("slot")
            continue
        if len(values) == 1:
            continue
        if kind in SINGLE_PROBE_KINDS:
            return _Fit(None, note="handler transforms the value")
        if kind in ("enum", "bool"):
            m = {value_key(v): leaf for v, leaf in zip(values, column, strict=True)}
            subst[path], _ = {"$map": m}, forms.add("map")
            continue
        coeffs = _affine(column, values)
        if coeffs is None:
            return _Fit(None, note="non-linear range")
        subst[path], _ = {"$affine": coeffs}, forms.add("affine")
    if not subst:
        return _Fit(None, note="handler ignores the value")
    form = "affine" if "affine" in forms else "map" if "map" in forms else "slot"
    return _Fit(form, write=_replace(first, subst))


def infer_write(kind: str, child: Samples, standalone: Samples) -> WriteCodec:
    """Write codec from slotted samples ``[(value, recipe or None)]`` of both contexts.

    The child context's codec is ``write`` (or ``write_table``); the standalone codec is
    kept as ``write_standalone`` only when it differs. A setting without a codec in the
    child context is read-only with a note naming why.
    """
    if _has_embedded_serial(child) or _has_embedded_serial(standalone):
        return WriteCodec(note="serial embedded in a string")
    channel = _channel_paths(child, standalone)
    main = _fit(kind, child, channel)
    if main.form is None:
        return WriteCodec(note=main.note)
    alone = _fit(kind, standalone, channel)
    result = WriteCodec(access="rw", form=main.form, write=main.write, write_table=main.table)
    if alone.form is None:
        result.extra["standalone_note"] = alone.note
    elif main.table is not None:
        if alone.table != main.table:
            result.extra["write_table_standalone"] = alone.table or {}
            result.extra["standalone_form"] = alone.form
    elif alone.write != main.write:
        if alone.table is not None:
            result.extra["write_table_standalone"] = alone.table
        else:
            result.write_standalone = alone.write
    return result


MISSING: Any = object()  # no getProperty reply for a written value
ROUND_TRIP_NOTE = "round trip does not return the written value"
RANGE_READ_NOTE = "range read is not the identity"


@dataclass(frozen=True)
class ReadSample:
    """One written value, its recipe's ``update`` and what getProperty decoded from it."""

    value: Value
    cmd: Any
    param_value: Any
    decoded: Any


def _decodes_to(decoded: Any, value: Value) -> bool:
    """getProperty returned the written value (string compare; bools also as 0/1)."""
    if decoded is None or decoded is MISSING:
        return False
    if str(decoded) == str(value):
        return True
    if isinstance(value, bool):
        return str(decoded).lower() in (str(value).lower(), str(int(value)))
    return False


def infer_read(
    kind: str, samples: Sequence[ReadSample]
) -> tuple[dict[str, Any] | None, str | None]:
    """Read codec ``{"param", "map"}`` and a note from the round trip of every written value.

    ``map`` is null when the parameter value is the value's string form on every sample,
    else ``{"<param value>": public value}``. Without samples there is no parameter id.
    """
    if not samples:
        return None, None
    cmds = {s.cmd for s in samples}
    if len(cmds) != 1 or not all(isinstance(s.cmd, int) for s in samples):
        return None, ROUND_TRIP_NOTE
    if not all(_decodes_to(s.decoded, s.value) for s in samples):
        return None, ROUND_TRIP_NOTE
    (cmd,) = cmds
    if all(str(s.param_value) == _str_form(s.value) for s in samples):
        return {"param": cmd, "map": None}, None
    if kind == "range":
        return None, RANGE_READ_NOTE
    mapping: dict[str, Value] = {}
    for s in samples:
        key = str(s.param_value)
        if key in mapping and not _same(mapping[key], s.value):
            return None, ROUND_TRIP_NOTE
        mapping[key] = s.value
    return {"param": cmd, "map": mapping}, None


SN_SLOTS = frozenset({"$device_sn", "$station_sn"})
SCALAR_SLOTS = frozenset({"$v", "$v:str", "$v:int", "$channel", *SN_SLOTS})
OBJECT_SLOTS = frozenset({"$map", "$affine"})


def coerce(setting: Mapping[str, Any], payload: Any) -> Value:
    """A handler payload as the setting's public value (bool settings take 0/1 too)."""
    if setting.get("kind") == "bool" and not isinstance(payload, bool):
        if payload in (0, 1, "0", "1"):
            return bool(int(payload))
        raise ValueError(f"not a bool payload: {payload!r}")
    if isinstance(payload, bool | int | float | str):
        return payload
    raise ValueError(f"not a scalar payload: {payload!r}")


def write_template(setting: Mapping[str, Any], value: Value, context: str) -> Recipe:
    """The write template of a setting for one value in a context (``child``/``standalone``)."""
    if setting.get("access") != "rw":
        raise ValueError("setting is read-only")
    key = value_key(value)
    alone = context == STANDALONE.name
    tables = [setting.get("write_table_standalone")] if alone else []
    tables.append(setting.get("write_table"))
    for table in tables:
        if isinstance(table, dict):
            if key not in table:
                raise ValueError(f"value {key} not in the write table")
            recipe: Recipe = table[key]
            return recipe
    if alone and isinstance(setting.get("write_standalone"), dict):
        return setting["write_standalone"]  # type: ignore[no-any-return]
    if isinstance(setting.get("write"), dict):
        return setting["write"]  # type: ignore[no-any-return]
    raise ValueError("setting has no write codec")


def render(
    setting: Mapping[str, Any],
    value: Value,
    *,
    context: str,
    channel: int,
    device_sn: str = "$device_sn",
    station_sn: str = "$station_sn",
) -> Recipe:
    """The recipe a setting's write codec gives for a public value in a device context.

    Raises ValueError for an unknown placeholder, an unmapped value or a read-only setting.
    """
    serials = {"$device_sn": device_sn, "$station_sn": station_sn}

    def fill(x: Any) -> Any:
        if isinstance(x, dict):
            if any(isinstance(k, str) and k.startswith("$") for k in x):
                return form(x)
            return {k: fill(v) for k, v in x.items()}
        if isinstance(x, list):
            return [fill(v) for v in x]
        if isinstance(x, str) and x.startswith("$"):
            return scalar(x)
        return x

    def scalar(slot_name: str) -> Any:
        if slot_name == "$v":
            return value
        if slot_name == "$v:str":
            return _str_form(value)
        if slot_name == "$v:int":
            if isinstance(value, float) and not value.is_integer():
                raise ValueError(f"$v:int of a fraction: {value!r}")
            return int(value)
        if slot_name == "$channel":
            return channel
        if slot_name in SN_SLOTS:
            return serials[slot_name]
        raise ValueError(f"unknown placeholder {slot_name!r}")

    def form(x: dict[str, Any]) -> Any:
        if len(x) != 1:
            raise ValueError(f"unknown placeholder object {sorted(x)}")
        ((name, arg),) = x.items()
        if name == "$map" and isinstance(arg, dict):
            key = value_key(value)
            if key not in arg:
                raise ValueError(f"value {key} not in $map")
            return arg[key]
        if name == "$affine" and isinstance(arg, list) and len(arg) == 2:
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError(f"$affine of a non-number: {value!r}")
            a, b = arg
            return intify(round(a * value + b, 9))
        raise ValueError(f"unknown placeholder object {name!r}")

    return fill(write_template(setting, value, context))  # type: ignore[no-any-return]


def codec_fields(result: WriteCodec) -> dict[str, Any]:
    """The setting-entry keys of a write codec (``access`` plus what is present)."""
    out: dict[str, Any] = {"access": result.access}
    for key in ("write", "write_standalone", "write_table", "note"):
        value = getattr(result, key)
        if value is not None:
            out[key] = value
    if "write_table_standalone" in result.extra:
        out["write_table_standalone"] = result.extra["write_table_standalone"]
    if result.access == "rw" and "standalone_note" in result.extra:
        out["note"] = f"standalone: {result.extra['standalone_note']}"
    return out


def dump(obj: Any) -> str:
    """Stable JSON text: keys sorted, except inside recipe objects (handler order kept)."""
    return json.dumps(_sorted(obj), indent=1, ensure_ascii=False) + "\n"


RECIPE_KEYS = frozenset({"write", "write_standalone"})
TABLE_KEYS = frozenset({"write_table", "write_table_standalone"})


def _sorted(obj: Any, *, keep: bool = False) -> Any:
    if isinstance(obj, dict):
        items = obj.items() if keep else sorted(obj.items())
        out: dict[str, Any] = {}
        for k, v in items:
            if keep or k in RECIPE_KEYS:
                out[k] = _sorted(v, keep=True)
            elif k in TABLE_KEYS and isinstance(v, dict):
                out[k] = {tk: _sorted(tv, keep=True) for tk, tv in sorted(v.items())}
            else:
                out[k] = _sorted(v)
        return out
    if isinstance(obj, list):
        return [_sorted(v, keep=keep) for v in obj]
    return obj
