"""Strict JSON helpers shared by the P2P decoders.

Kept free of the crypto stack so light modules (parameter dumps, the CLI renderer)
can use them without importing ``cryptography``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..exceptions import ProtocolError

_DECIMAL = re.compile(r"-?[0-9]{1,18}")


def json_int(value: object) -> int | None:
    """An int from a JSON int or an ASCII decimal string; None for anything else.

    The station writes ids and codes both ways (``1224`` and ``"1224"``). Floats
    (``1.9``), booleans and non-decimal strings are rejected, never truncated.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _DECIMAL.fullmatch(value):
        return int(value)
    return None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON number {name}")


#: Strict JSON: NaN/Infinity are rejected instead of becoming floats.
_JSON = json.JSONDecoder(parse_constant=_reject_constant)

#: Deepest array/object nesting accepted. Station payloads nest a few levels; the
#: interpreter's own recursion limit depends on the build and the C stack, so a
#: deeper document is refused before parsing.
MAX_JSON_DEPTH = 64
_NESTING = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')


def _too_deep(text: str) -> bool:
    """Whether ``text`` nests arrays/objects deeper than :data:`MAX_JSON_DEPTH` (strings skipped)."""
    depth = 0
    for match in _NESTING.finditer(text):
        char = match.group()
        if char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif char in "]}":
            depth -= 1
    return False


def raw_decode_json(text: str) -> tuple[Any, int]:
    """:meth:`json.JSONDecoder.raw_decode`, strict, with the nesting limit.

    Raises :class:`ValueError` for invalid JSON, NaN/Infinity or nesting deeper than
    :data:`MAX_JSON_DEPTH`.
    """
    if _too_deep(text):
        raise ValueError(f"JSON nested deeper than {MAX_JSON_DEPTH}")
    try:
        return _JSON.raw_decode(text)
    except RecursionError:
        raise ValueError("JSON nested too deep to parse") from None


def loads_json(text: str | bytes) -> Any:
    """Parse one JSON document strictly; any failure raises :class:`ProtocolError`.

    Rejects NaN/Infinity and nesting deeper than :data:`MAX_JSON_DEPTH`, so a decoder
    built on it can only raise :class:`ProtocolError`.
    """
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        obj, end = raw_decode_json(text.strip())
        if end != len(text.strip()):
            raise ValueError("trailing data after the JSON document")
    except ValueError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from None
    return obj
