"""Thing-description conditions and ``__v`` variants, evaluated as the eufy app evaluates them.

A thing-description property can carry ``available_conditions`` and ``read_conditions``:
a list of groups, each a list of conditions. The list passes when it is empty or any
group passes; a group passes when every condition passes. The app reads a property
through its ``__v`` variants: of the properties whose identifier is the base followed by
``__v`` (any case), those with non-empty read conditions that pass compete, the one with
the most conditions (summed over its groups) wins, the first in thing-description order
among equals, and none passing leaves the base. **[declared: eufy app]**; see
docs/protocol/media.md, *WebRTC or P2P*, and docs/reference/models-schema.md, *Variants*.

Conditions evaluate to True, False or None (the input is unknown to the client). A group
with a failing condition fails and one with only passing conditions passes; otherwise the
result is None, and a list follows the same rule. Callers decide what the app does with a
missing input (a missing firmware is ``""``, which compares as below every version) and
pass None only for what the client cannot know. Pure functions: no I/O.
"""

from __future__ import annotations

import functools
import itertools
import re
from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from .versions import version_bigger_than, version_equals

__all__ = [
    "Condition",
    "ConditionUnit",
    "Groups",
    "choices",
    "evaluate",
    "groups_of",
    "passes",
    "td_conditions",
]

THING_SDK_VERSION: Final = "2.3.1.2"
"""The app's thing-SDK version that ``sdk_version`` conditions compare: that of the app
build the generated data comes from (see docs/how-to/regenerate-models.md)."""
VARIANT_SEPARATOR: Final = "__v"
"""What follows a base identifier in a variant's identifier (compared ignoring case)."""
ASSOCIATED_TYPES: Final = frozenset({"associated_field", "parent_associated_field"})
"""Condition types that compare another property's value."""

_MAX_PATTERN: Final = 512
_MAX_VALUE: Final = 2048
_INLINE_FLAGS: Final = re.compile(r"\(\?([imsx]+)\)")
_FLAGS: Final = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}
_MAX_UNKNOWN: Final = 8  # candidates with an unknown result enumerated by choices()


@dataclass(frozen=True, slots=True, kw_only=True)
class Condition:
    """One condition: ``kind`` (the thing description's ``type``), ``qualifier`` and
    ``value``.

    An associated condition (:data:`ASSOCIATED_TYPES`) compares the property ``prop``
    (None: the condition names none, which reads as ``""``). Its value is read from the
    device parameter ``param`` (None: no read is known, the value is unknown), through
    ``read_map`` (raw value -> property value; None: as reported); a device without the
    parameter has the property's ``default``.
    """

    kind: str
    qualifier: str
    value: str
    prop: str | None = None
    param: int | None = None
    read_map: Mapping[str, str] | None = None
    default: str = ""


type Groups = tuple[tuple[Condition, ...], ...]
"""A condition list: any group passes when all its conditions do."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ConditionUnit:
    """One device as the conditions read it; None marks an input the client lacks."""

    serial: str
    parent_serial: str
    """Its station's serial; its own when it stands alone or is a station."""
    firmware: str | None
    """Its main firmware version (``""`` when the cloud lists none, as the app reads it)."""
    parent_firmware: str | None
    """The parent's main firmware (its own when it is its own parent; ``""`` when the
    parent is not listed)."""
    params: Mapping[int, str] | None = None
    """The device's parameters as the client holds them (P2P and cloud)."""
    parent_listed: bool = True
    """Whether the parent is in the account's device list."""
    country: str | None = None
    """The country the account logs in with."""
    sdk_version: str = THING_SDK_VERSION
    """The app thing-SDK version ``sdk_version`` conditions compare."""


@functools.lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str] | None:
    """``pattern`` compiled with its inline flags (``(?i)`` anywhere) applied to all of
    it; None when it does not compile."""
    flags = 0

    def take(match: re.Match[str]) -> str:
        nonlocal flags
        for letter in match.group(1):
            flags |= _FLAGS[letter]
        return ""

    try:
        return re.compile(_INLINE_FLAGS.sub(take, pattern), flags)
    except re.error:
        return None


def regex(pattern: str, value: str) -> bool:
    """A pattern condition: an empty pattern or value passes; a match anywhere passes."""
    if not pattern or not value:
        return True
    if len(pattern) > _MAX_PATTERN or len(value) > _MAX_VALUE:
        return False
    compiled = _compiled(pattern)
    return compiled is not None and compiled.search(value) is not None


def version(current: str, qualifier: str, bound: str) -> bool:
    """A version condition: ``current`` against ``bound`` (:mod:`.versions`)."""
    match qualifier:
        case ">":
            return version_bigger_than(current, bound)
        case "<":
            return version_bigger_than(bound, current)
        case "=":
            return version_equals(current, bound)
        case "!=":
            return not version_equals(current, bound)
        case ">=":
            return version_bigger_than(current, bound) or version_equals(current, bound)
        case "<=":
            return version_bigger_than(bound, current) or version_equals(current, bound)
        case "RE":
            return regex(bound, current)
    return False


def operator(qualifier: str, current: str, target: str) -> bool:
    """A property comparison: equality, or text order for ``<``, ``<=``, ``>``, ``>=``."""
    match qualifier:
        case "=":
            return current == target
        case "!=":
            return current != target
        case "<":
            return current < target
        case "<=":
            return current <= target
        case ">":
            return current > target
        case ">=":
            return current >= target
    return False


def _property_value(condition: Condition, params: Mapping[int, str] | None) -> str | None:
    if not condition.prop:
        return ""
    if condition.param is None or params is None:
        return None
    raw = params.get(condition.param)
    if raw is None:
        return condition.default
    if condition.read_map is None:
        return raw
    return condition.read_map.get(raw)


def evaluate(condition: Condition, unit: ConditionUnit) -> bool | None:
    """Whether ``condition`` passes for ``unit``; None when an input it needs is unknown.
    A type the app does not know fails."""
    qualifier, value = condition.qualifier, condition.value
    match condition.kind:
        case "device_version":
            return None if unit.firmware is None else version(unit.firmware, qualifier, value)
        case "parent_version":
            if not value or not qualifier:
                return True
            if unit.parent_firmware is None:
                return None
            return version(unit.parent_firmware, qualifier, value)
        case "sdk_version":
            return version(unit.sdk_version, qualifier, value)
        case "device_sn":
            return regex(value, unit.serial)
        case "parent_sn":
            return regex(value, unit.parent_serial)
        case "user_country":
            return None if unit.country is None else regex(value, unit.country)
        case "associated_field":
            current = _property_value(condition, unit.params)
            if current is None:
                return None
            return (
                regex(value, current) if qualifier == "RE" else operator(qualifier, current, value)
            )
        case "parent_associated_field":
            return True if not unit.parent_listed else None
    return False


def passes(groups: Groups, unit: ConditionUnit) -> bool | None:
    """Whether the list ``groups`` passes for ``unit`` (an empty list does); None when
    the unknown inputs decide it."""
    if not groups:
        return True
    unknown = False
    for group in groups:
        results = [evaluate(c, unit) for c in group]
        if False in results:
            continue
        if None in results:
            unknown = True
            continue
        return True
    return None if unknown else False


def condition_count(groups: Groups) -> int:
    """How many conditions ``groups`` holds, summed over its groups."""
    return sum(len(group) for group in groups)


def choices[T: Hashable](
    candidates: Sequence[tuple[T, Groups]], unit: ConditionUnit
) -> frozenset[T | None]:
    """Every variant the app may read for ``unit``: of ``candidates`` (a tag and its read
    conditions, in thing-description order), the one whose non-empty conditions pass with
    the most conditions, the first among equals; None stands for the base (no candidate
    passes). One element when the known inputs decide it; with unknown inputs, every
    outcome they allow. Candidates beyond :data:`_MAX_UNKNOWN` unknown ones read as
    failing."""
    known: list[tuple[int, T, int]] = []
    unknown: list[tuple[int, T, int]] = []
    for index, (tag, groups) in enumerate(candidates):
        if not groups:
            continue
        result = passes(groups, unit)
        if result is True:
            known.append((index, tag, condition_count(groups)))
        elif result is None:
            unknown.append((index, tag, condition_count(groups)))
    outcomes: set[T | None] = set()
    for chosen in itertools.product((False, True), repeat=min(len(unknown), _MAX_UNKNOWN)):
        passing = sorted(known + [u for u, take in zip(unknown, chosen, strict=False) if take])
        best: T | None = None
        most = -1
        for _, tag, count in passing:
            if count > most:
                best, most = tag, count
        outcomes.add(best)
    return frozenset(outcomes)


def variant_rest(identifier: str, base: str) -> str | None:
    """What follows ``base`` in ``identifier`` when ``identifier`` is one of its ``__v``
    variants, else None."""
    if not identifier.startswith(base) or len(identifier) <= len(base):
        return None
    rest = identifier[len(base) :]
    return rest if rest.lower().startswith(VARIANT_SEPARATOR) else None


def td_conditions(conditions: Any) -> list[list[dict[str, str]]]:
    """A thing description's condition list (``{"condition_list": [{"conditions":
    [...]}]}``) as plain groups: ``type``, ``qualifier``, ``value`` and, for an
    associated condition, ``prop`` (the ``prop_id``, left out when empty)."""
    out: list[list[dict[str, str]]] = []
    for group in (conditions or {}).get("condition_list") or []:
        items: list[dict[str, str]] = []
        for raw in group.get("conditions") or []:
            item = {k: str(raw.get(k) or "") for k in ("type", "qualifier", "value")}
            if item["type"] in ASSOCIATED_TYPES and raw.get("prop_id"):
                item["prop"] = str(raw["prop_id"])
            items.append(item)
        out.append(items)
    return out


def _condition(raw: Any) -> Condition:
    if not isinstance(raw, dict):
        raise TypeError("a condition is not an object")
    texts = {k: raw.get(k) for k in ("type", "qualifier", "value")}
    if not all(isinstance(v, str) for v in texts.values()):
        raise TypeError(f"condition {raw!r}: type, qualifier and value are not strings")
    prop, param, read_map, default = (raw.get(k) for k in ("prop", "param", "map", "default"))
    if prop is not None and not isinstance(prop, str):
        raise TypeError(f"condition {raw!r}: prop is not a string")
    if param is not None and (isinstance(param, bool) or not isinstance(param, int)):
        raise TypeError(f"condition {raw!r}: param is not an int")
    if read_map is not None and not (
        isinstance(read_map, dict) and all(isinstance(v, str) for v in read_map.values())
    ):
        raise TypeError(f"condition {raw!r}: map is not an object of strings")
    if default is not None and not isinstance(default, str):
        raise TypeError(f"condition {raw!r}: default is not a string")
    return Condition(
        kind=str(texts["type"]),
        qualifier=str(texts["qualifier"]),
        value=str(texts["value"]),
        prop=prop,
        param=param,
        read_map=None if read_map is None else MappingProxyType(dict(read_map)),
        default=default or "",
    )


def groups_of(raw: Any) -> Groups:
    """Plain groups (:func:`td_conditions`, plus an associated condition's ``param``,
    ``map`` and ``default``) as :data:`Groups`; raises TypeError when malformed."""
    if not isinstance(raw, list) or not all(isinstance(g, list) for g in raw):
        raise TypeError("conditions are not a list of lists")
    return tuple(tuple(_condition(item) for item in group) for group in raw)
