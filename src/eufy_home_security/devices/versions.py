"""Firmware version comparison as the eufy app's thing-description conditions do it.

A version is split on ``.``; each side's leading run of numeric parts (a part counts when
it is an integer after dropping trailing ASCII letters, ``"9h"`` -> 9) is compared field by
field as 32-bit integers, a missing or non-numeric field counting as 0. Equal so far, the
parts after the longer run decide: a side with parts left over is bigger than one without;
both with parts, the last integer part of each is compared when the parts before it are
equal. A missing version (``""``) compares as 0 everywhere. **[declared: eufy app]**
Pure functions: no I/O.
"""

from __future__ import annotations

import re
from typing import Final

_TRAILING_LETTERS: Final = re.compile(r"[a-zA-Z]+$")
_INTEGER: Final = re.compile(r"[+-]?\d+")
_INT_MIN: Final = -(2**31)
_INT_MAX: Final = 2**31 - 1


def _int_or_none(part: str) -> int | None:
    """``part`` as a 32-bit integer (optional sign, digits only), or None."""
    if not _INTEGER.fullmatch(part):
        return None
    value = int(part)
    return value if _INT_MIN <= value <= _INT_MAX else None


def _field(part: str) -> int | None:
    return _int_or_none(_TRAILING_LETTERS.sub("", part))


def _numeric_run(parts: list[str]) -> int:
    for i, part in enumerate(parts):
        if _field(part) is None:
            return i
    return len(parts)


def _fields(a: str, b: str) -> tuple[list[str], list[str], int]:
    left, right = a.split("."), b.split(".")
    return left, right, max(_numeric_run(left), _numeric_run(right))


def _at(parts: list[str], i: int) -> int:
    return _field(parts[i] if i < len(parts) else "0") or 0


def _last_int(parts: list[str]) -> int:
    """Index of the last part that is an integer as written, or -1."""
    for i in range(len(parts) - 1, -1, -1):
        if _int_or_none(parts[i]) is not None:
            return i
    return -1


def version_bigger_than(a: str, b: str) -> bool:
    """Whether version ``a`` is strictly bigger than ``b``."""
    left, right, run = _fields(a, b)
    for i in range(run):
        diff = (_at(left, i) - _at(right, i) - _INT_MIN) % 2**32 + _INT_MIN  # int32 wrap
        if diff:
            return diff > 0
    rest_a, rest_b = left[run:], right[run:]
    if not rest_a or not rest_b:
        return bool(rest_a)
    i, j = _last_int(rest_a), _last_int(rest_b)
    if (rest_a[:i] if i >= 0 else rest_a) != (rest_b[:j] if j >= 0 else rest_b):
        return False
    return (int(rest_a[i]) if i >= 0 else 0) > (int(rest_b[j]) if j >= 0 else 0)


def version_equals(a: str, b: str) -> bool:
    """Whether versions ``a`` and ``b`` are equal."""
    left, right, run = _fields(a, b)
    if any(_at(left, i) != _at(right, i) for i in range(run)):
        return False
    return left[run:] == right[run:]


def version_between(version: str, low: str, high: str) -> bool:
    """Whether ``low <= version <= high``, both bounds inclusive."""
    at_least = version_bigger_than(version, low) or version_equals(version, low)
    at_most = version_bigger_than(high, version) or version_equals(version, high)
    return at_least and at_most
