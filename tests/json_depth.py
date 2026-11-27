"""JSON texts one nesting level past the parser's depth bound (``p2p._json.MAX_JSON_DEPTH``).

Every interpreter parses such a text with ``json.loads``; a parse with the bound refuses it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from eufy_home_security.p2p._json import MAX_JSON_DEPTH


def nested_lists(depth: int) -> list[Any]:
    """An empty list inside ``depth - 1`` more lists: a value ``depth`` levels deep."""
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


def past_the_bound(document: Mapping[str, Any]) -> str:
    """``document`` as JSON text plus a field that nests it one level past the bound."""
    return json.dumps({**document, "nested": nested_lists(MAX_JSON_DEPTH)})
