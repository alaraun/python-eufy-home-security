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
    ("rtc/diagnostics.py", "RtcStationReport.secrets_dict"): 1,  # a JSON copy of own data
    ("devices/timezones.py", "_table"): 1,  # bundled package data
    ("devices/model_settings.py", "bundled_codes"): 1,
    ("devices/model_settings.py", "_load"): 1,
    ("testing/station.py", "_stored_report"): 1,  # fakes reading what the client sends
    ("testing/mqtt.py", "FakeMqttLock._read"): 3,
    ("testing/locks.py", "FakeLock._on_1961"): 1,
}

#: Names of the ``json`` module that parse, or lead to a parser.
_PARSERS = frozenset({"loads", "load", "JSONDecoder", "decoder", "scanner"})
#: Third-party JSON parsers, none bounded.
_OTHER_PARSERS = frozenset({"orjson", "ujson", "simplejson"})


class _Finder(ast.NodeVisitor):
    """Collects the enclosing function of every direct JSON parse in one module: a use of a
    parser of the ``json`` module (by any alias, called or not, through ``getattr``), an
    import of one, an import of another JSON library, or aiohttp's ``response.json()``."""

    def __init__(self) -> None:
        self.scope: list[str] = []
        self.found: list[tuple[str, int]] = []
        self.json_names = {"json"}  # names bound to the json module

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

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.partition(".")[0]
            if top in _OTHER_PARSERS or (top == "json" and alias.name != "json"):
                self._note(node)  # another library, or json.decoder / json.scanner
            elif alias.name == "json":
                self.json_names.add(alias.asname or "json")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        top = (node.module or "").partition(".")[0] if node.level == 0 else ""
        if (
            top in _OTHER_PARSERS
            or (top == "json" and node.module != "json")
            or (node.module == "json" and top and any(a.name in _PARSERS for a in node.names))
        ):
            self._note(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        value = node.value
        if isinstance(value, ast.Name) and value.id in self.json_names and node.attr in _PARSERS:
            self._note(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func, args = node.func, node.args
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(args) >= 2
            and isinstance(args[0], ast.Name)
            and args[0].id in self.json_names
            and not (isinstance(args[1], ast.Constant) and args[1].value not in _PARSERS)
        ):
            self._note(node)
        # aiohttp's ``response.json()`` handed on as a coroutine (a task, a gather).
        for arg in (*args, *(keyword.value for keyword in node.keywords)):
            if _is_json_method_call(arg):
                self._note(arg)
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        # aiohttp's ``await response.json()`` parses without the bound.
        if _is_json_method_call(node.value):
            self._note(node)
        self.generic_visit(node)


def _is_json_method_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "json"
    )


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
        ("import json as j\nj.loads(t)\n", "<module>"),
        ("import json\nrows = list(map(json.loads, texts))\n", "<module>"),
        ("import json\nparse = json.loads\n", "<module>"),
        ("import json\ngetattr(json, 'loads')(t)\n", "<module>"),
        ("import json\ngetattr(json, name)(t)\n", "<module>"),
        ("import json\njson.decoder.JSONDecoder().decode(t)\n", "<module>"),
        ("from json import decoder\n", "<module>"),
        ("from json.decoder import JSONDecoder\n", "<module>"),
        ("import json.decoder as d\n", "<module>"),
        ("import json\nclass D(json.JSONDecoder):\n    pass\n", "D"),
        ("async def f(resp):\n    return await resp.json(loads=json.loads)\n", "f"),
        ("import asyncio\nasyncio.ensure_future(resp.json())\n", "<module>"),
        ("import orjson\n", "<module>"),
        ("import ujson as u\n", "<module>"),
        ("from simplejson import loads\n", "<module>"),
    ],
    ids=[
        "loads",
        "load",
        "imported",
        "decoder",
        "aiohttp",
        "alias",
        "reference",
        "bound-name",
        "getattr",
        "getattr-name",
        "decoder-module",
        "from-json-decoder-module",
        "from-decoder-module",
        "import-decoder-module",
        "subclass",
        "aiohttp-loads-argument",
        "aiohttp-task",
        "orjson",
        "ujson",
        "simplejson",
    ],
)
def test_the_scan_finds_each_form_of_direct_parse(source: str, scope: str) -> None:
    assert {found for found, _line in _direct_parses(source)} == {scope}


def test_the_scan_leaves_other_calls_alone() -> None:
    source = (
        "import json\n"
        "from json import dumps\n"
        "from ._json import loads_json\n"
        "from .p2p import json_frames\n"
        "import jsonschema\n"
        "json.dumps(x)\n"
        "getattr(json, 'dumps')(x)\n"
        "obj = frame.json()\n"
        "parse_json(t)\n"
    )
    assert _direct_parses(source) == []
