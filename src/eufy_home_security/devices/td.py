"""Pure readers of a vendor thing description (TD), shared with the model generator.

A TD is the per-product JSON the cloud's ``app/things/get_things_list`` returns:
``{"profile": {"product_code": ...}, "properties": [...], "large_version": int, ...}``.
:func:`parse_thing_description` turns one into read-only :class:`Setting` entries for a
model without a bundled file: domain, labels, unit and default, never a codec. No I/O.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from .labels import choice_label, setting_name
from .model_settings import IDENTIFIER, Setting, SettingKind, Value
from .settings import SettingUnit

__all__ = [
    "LISTED_NOTE",
    "UNITS",
    "VOLUME_UNIT",
    "enum_label",
    "intify",
    "kind_of",
    "normalise_unit",
    "parse_thing_description",
    "public_value",
    "range_spec",
    "specs_of",
    "td_default",
    "td_version",
]

_LOGGER = logging.getLogger(__name__)

#: The note of every setting listed from a cloud TD.
LISTED_NOTE: Final = "not in bundled data"

#: TD unit -> setting unit; None drops the unit (a count or no unit).
UNITS: Final[Mapping[str, SettingUnit | None]] = MappingProxyType(
    {
        "s": SettingUnit.SECONDS,
        "秒": SettingUnit.SECONDS,
        "毫秒": SettingUnit.MILLISECONDS,
        "day": SettingUnit.DAYS,
        "天": SettingUnit.DAYS,
        "无": None,
        "个": None,
    }
)
#: "音量" (volume) is a percentage only on a 0..100 or 1..100 scale.
VOLUME_UNIT: Final = "音量"

_ENUM_TYPES: Final = frozenset({"enum", "ienum", "tenum"})


def normalise_unit(raw: str, minimum: float | None, maximum: float | None) -> SettingUnit | None:
    """The setting unit of TD unit ``raw`` (None for none); ValueError when unmapped."""
    if raw in UNITS:
        return UNITS[raw]
    if raw == VOLUME_UNIT and minimum in (0, 1) and maximum == 100:
        return SettingUnit.PERCENT
    raise ValueError(f"unit {raw!r} has no mapping")


def _num(raw: Any) -> float | None:
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return None


def intify(x: float) -> int | float:
    """``x`` as int when integral."""
    return int(x) if float(x).is_integer() else x


def public_value(raw: Any) -> Value:
    """A TD value as public value: int when int-able, else the string."""
    try:
        return int(raw)
    except (TypeError, ValueError):
        return str(raw)


def specs_of(prop: Mapping[str, Any]) -> dict[str, Any]:
    """The property's ``data_type.specs`` object (empty when absent)."""
    specs = (prop.get("data_type") or {}).get("specs")
    return specs if isinstance(specs, dict) else {}


def kind_of(prop: Mapping[str, Any]) -> str:
    """``enum`` / ``bool`` / ``range`` / ``string`` / ``other`` for a TD property."""
    dtype = (prop.get("data_type") or {}).get("type")
    specs = specs_of(prop)
    if dtype in _ENUM_TYPES:
        return "enum" if specs.get("eunmList") else "other"  # vendor spelling
    if dtype == "bool":
        return "bool"
    numeric = _num(specs.get("min")) is not None and _num(specs.get("max")) is not None
    if dtype in ("int", "float", "string", "text") and numeric:
        # A few string-typed properties carry a numeric min/max: the handler takes a number.
        return "range"
    if dtype in ("string", "text"):
        return "string"
    return "other"


def range_spec(prop: Mapping[str, Any]) -> tuple[float, float, float]:
    """``(min, max, step)`` of a range property; a missing or zero step counts as 1."""
    specs = specs_of(prop)
    lo, hi = _num(specs.get("min")), _num(specs.get("max"))
    if lo is None or hi is None:
        raise ValueError("not a range property")
    step = _num(specs.get("step"))
    return lo, hi, step or 1.0


def _number(raw: Any) -> int | float | None:
    x = _num(raw)
    return intify(x) if x is not None else None


def td_default(prop: Mapping[str, Any], kind: str) -> Any:
    """The TD default of a property: ``defaultValue`` (a number for enum and range, a bool
    for bool), else an enum's one ``isDefault`` row; None without one."""
    specs = specs_of(prop)
    default = specs.get("defaultValue")
    if default not in (None, ""):
        if kind == "bool":
            text = str(default).lower()
            if text in ("true", "1", "false", "0"):
                return text in ("true", "1")
        elif kind in ("range", "enum"):
            num = _number(default)
            return num if num is not None else default
        else:
            return default
    if kind == "enum":
        rows = specs.get("eunmList") or []
        defaults = [r.get("value") for r in rows if str(r.get("isDefault")) == "1"]
        if len(defaults) == 1:
            return public_value(defaults[0])
    return None


def enum_label(identifier: str, value: Value, desc: str) -> tuple[str, bool]:
    """The display label of a TD enum value and whether the TD supplied it.

    ``False`` means a fallback: ``"Value <n>"`` for an int value, else the raw desc or
    the value itself.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        label = choice_label(identifier, value, desc)
        return label, label != f"Value {value}"
    label = choice_label(identifier, -1, desc)
    if label == "Value -1":
        return desc.strip() or str(value), False
    return label, True


def td_version(td: Mapping[str, Any]) -> int | None:
    """The TD's ``large_version``, or None."""
    version = td.get("large_version")
    return version if isinstance(version, int) and not isinstance(version, bool) else None


def _listed_setting(code: str, prop: Mapping[str, Any]) -> Setting:
    ident: str = prop["identifier"]
    kind = SettingKind(kind_of(prop))
    values: tuple[Value, ...] = ()
    labels: dict[Value, str] = {}
    minimum = maximum = step = None
    if kind is SettingKind.ENUM:
        rows = [r for r in specs_of(prop)["eunmList"] if isinstance(r, dict)]
        values = tuple(public_value(r.get("value")) for r in rows)
        for row, value in zip(rows, values, strict=True):
            labels[value] = enum_label(ident, value, str(row.get("desc") or ""))[0]
    elif kind is SettingKind.RANGE:
        lo, hi, st = range_spec(prop)
        minimum, maximum, step = intify(lo), intify(hi), intify(st)
    unit = None
    raw_unit = specs_of(prop).get("unit")
    if isinstance(raw_unit, str) and raw_unit.strip():
        try:
            unit = normalise_unit(raw_unit.strip(), minimum, maximum)
        except ValueError:
            _LOGGER.debug("%s %s: unit %r has no mapping, dropped", code, ident, raw_unit)
    default = td_default(prop, kind.value)
    if default is not None and not isinstance(default, bool | int | float | str):
        default = None
    return Setting(
        key=ident,
        product_code=code,
        name=setting_name(ident),
        kind=kind,
        values=values,
        minimum=minimum,
        maximum=maximum,
        step=step,
        unit=unit,
        default=default,
        labels=MappingProxyType(labels),
        writable=False,
        readable=False,
        note=LISTED_NOTE,
    )


def parse_thing_description(code: str, td: Mapping[str, Any]) -> Mapping[str, Setting]:
    """Read-only settings of ``code`` from its TD, keyed by identifier.

    One setting per property whose identifier matches ``[a-z0-9_]+``; malformed
    property entries are skipped. Every setting has ``writable`` and ``readable``
    False and the note :data:`LISTED_NOTE`. Raises ValueError when ``td`` has no
    ``properties`` list.
    """
    props = td.get("properties")
    if not isinstance(props, list):
        raise ValueError(f"{code}: thing description has no properties list")
    out: dict[str, Setting] = {}
    for prop in props:
        if not isinstance(prop, dict):
            continue
        ident = prop.get("identifier")
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident) or ident in out:
            continue
        try:
            out[ident] = _listed_setting(code, prop)
        except (AttributeError, KeyError, TypeError, ValueError):
            _LOGGER.debug("%s %s: malformed property skipped", code, ident)
    return MappingProxyType(out)
