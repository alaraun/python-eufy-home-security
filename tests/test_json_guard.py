"""Every JSON text from a device, the cloud or a broker is parsed with the depth bound.

``json.loads`` raises :class:`RecursionError` on deep enough nesting, which escapes the
``except ValueError`` of every caller; ``p2p._json.parse_json`` refuses it as a
:class:`ValueError`. This scan fails on a direct parse anywhere else in ``src``.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src" / "eufy_home_security"

#: Direct parses that read only trusted text, by (file, enclosing function): the count of each.
_ALLOWED: dict[tuple[str, str], int] = {
    ("p2p/_json.py", "<module>"): 1,  # the bounded parser's own decoder
    ("storage.py", "MemoryStore.async_load"): 1,  # a copy of in-memory data
    ("storage.py", "MemoryStore.async_save"): 1,
    ("devices/timezones.py", "_table"): 1,  # bundled package data
    ("devices/model_settings.py", "bundled_codes"): 1,
    ("devices/model_settings.py", "_load"): 1,
    ("testing/station.py", "_stored_report"): 1,  # fakes reading what the client sends
    ("testing/mqtt.py", "FakeMqttLock._read"): 3,
    ("testing/locks.py", "FakeLock._on_1961"): 1,
}

_PARSERS = {"loads", "load", "JSONDecoder"}


class _Finder(ast.NodeVisitor):
    """Collects the enclosing function of every direct JSON parse in one module."""

    def __init__(self) -> None:
        self.scope: list[str] = []
        self.found: list[tuple[str, int]] = []

    def _nested(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._nested(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._nested(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._nested(node)

    def _note(self, node: ast.AST) -> None:
        self.found.append((".".join(self.scope) or "<module>", getattr(node, "lineno", 0)))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "json" and any(alias.name in _PARSERS for alias in node.names):
            self._note(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _PARSERS
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        ):
            self._note(node)
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        # aiohttp's ``await response.json()`` parses without the bound.
        call = node.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "json"
        ):
            self._note(node)
        self.generic_visit(node)


def _direct_parses(source: str) -> list[tuple[str, int]]:
    finder = _Finder()
    finder.visit(ast.parse(source))
    return finder.found


def _scan() -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()
        for scope, line in _direct_parses(path.read_text(encoding="utf-8")):
            found.setdefault((rel, scope), []).append(line)
    return found


def test_json_text_is_parsed_only_through_the_bounded_parser() -> None:
    found = _scan()
    unexpected = {
        f"{rel}:{lines} in {scope}"
        for (rel, scope), lines in found.items()
        if len(lines) > _ALLOWED.get((rel, scope), 0)
    }
    assert not unexpected, f"parse with p2p._json.parse_json instead: {sorted(unexpected)}"


def test_every_allowed_direct_parse_still_exists() -> None:
    counts = Counter({key: len(lines) for key, lines in _scan().items()})
    assert {key: counts[key] for key in _ALLOWED} == _ALLOWED


@pytest.mark.parametrize(
    ("source", "scope"),
    [
        ("import json\njson.loads(text)\n", "<module>"),
        ("import json\ndef f(fh):\n    return json.load(fh)\n", "f"),
        ("from json import loads\n", "<module>"),
        ("import json\nclass C:\n    D = json.JSONDecoder()\n", "C"),
        ("class C:\n    async def f(self, resp):\n        return await resp.json()\n", "C.f"),
    ],
    ids=["loads", "load", "imported", "decoder", "aiohttp"],
)
def test_the_scan_finds_each_form_of_direct_parse(source: str, scope: str) -> None:
    assert [found for found, _line in _direct_parses(source)] == [scope]


def test_the_scan_leaves_other_calls_alone() -> None:
    source = "import json\nfrom json import dumps\njson.dumps(x)\nframe.json()\nparse_json(t)\n"
    assert _direct_parses(source) == []
