"""Generate ``devices/_model_names_data.py``: the product names, per product and unit.

Every product handler of the eufy app carries one name table (a JS object literal):
product prefix → display name, plus ``specialRules`` that name single units by characters
of their serial. The table's lookup: the first rule for the serial's 5-character prefix
whose characters all match, else the prefix's entry when it is not blank, else nothing.
Six-character keys are never looked up. Tables differ between handler builds.

A handler answers the thing property ``device_model`` in one of three shapes: the
lookup's result (``""`` on a miss); the lookup's result, else the cloud record's
``device_model`` field (the product code); or that field alone, without the table. A
product whose thing description declares no ``device_model`` has no such answer, so the
app shows no name from the table for it.

Per product code (every cached product, and every prefix any table names) the module
records the base name and the serial rules of one table, in three steps:

1. the product's own handler table, when it names the product's prefix (base or rule):
   the name the eufy app shows for a unit of that product;
2. else, as the library's choice, the newest handler table (by the handler's publication
   date, then code) that names the prefix: the app shows no name from a table there;
3. else no row: the library names the product from the app's model constant.

Products that declare no ``device_model`` are named by the same steps. The library never
uses the cloud record's product code as the name: where no table names a unit it keeps
its own fallback (step 2, else 3).

The tables are parsed as data (no vendor code runs for that). The parse is then checked
against the handlers themselves (``scripts/thing_models.py`` harness, Node): for every
product whose thing description declares ``device_model``, its handler answers a base
serial, the base serial with each single character changed and one serial per known rule
of its prefix, the probe device carrying the product code as its ``device_model``; each
answer must equal what the parsed table gives, or on a miss be ``""`` or that code. Runs
on a maintainer host only; nothing at runtime executes vendor code. The table is a Python
module, so reading it is an import.

    gen_model_names.py [--cache DIR] [--out FILE] [--check]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "_model_names_data.py"
PREFIX_LEN = 5
SERIAL_LEN = 16
#: A table has at least this many product-code keys with string values.
MIN_TABLE_KEYS = 10
PROPERTY = "device_model"
RULES_KEY = "specialRules"
_TABLE_START = re.compile(r"\{T[0-9A-Z]{4,6}:\"")
_CODE = re.compile(r"T[0-9][0-9A-Z]{3,4}")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
#: Serial characters tried for the positions no rule fixes, first fit wins.
_FILLERS = "ZYXWVU"
#: The characters a probe serial tries at each position after the prefix.
_SWEEP = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

Condition = tuple[int, str]
"""``(position, text)``: the serial holds ``text`` from ``position`` on."""
Rule = tuple[tuple[Condition, ...], str]
"""The conditions that must all hold, and the unit's name."""


class TableError(ValueError):
    """A handler's name table is ambiguous or malformed."""


# ── the JS literal ────────────────────────────────────────────────────────────


class _Literal:
    """A parser for the JSON-like subset of a JS object literal the tables use: objects
    with bare or quoted keys, arrays, double-quoted strings, integers, ``!0``/``!1``."""

    def __init__(self, text: str, pos: int) -> None:
        self.text = text
        self.pos = pos

    def _peek(self) -> str:
        return self.text[self.pos : self.pos + 1]

    def _expect(self, char: str) -> None:
        if self._peek() != char:
            raise ValueError(f"expected {char!r} at {self.pos}")
        self.pos += 1

    def value(self) -> Any:
        char = self._peek()
        if char == "{":
            return self._object()
        if char == "[":
            return self._array()
        if char == '"':
            return self._string()
        if self.text.startswith(("!0", "!1"), self.pos):
            self.pos += 2
            return self.text[self.pos - 1] == "0"
        match = _NUMBER.match(self.text, self.pos)
        if match is None:
            raise ValueError(f"unsupported value at {self.pos}")
        self.pos = match.end()
        return json.loads(match.group())

    def _string(self) -> str:
        end = self.pos + 1
        while True:
            end = self.text.find('"', end)
            if end < 0:
                raise ValueError("unterminated string")
            escape = end
            while self.text[escape - 1] == "\\":
                escape -= 1
            if (end - escape) % 2 == 0:
                break
            end += 1
        raw = self.text[self.pos : end + 1]
        self.pos = end + 1
        return str(json.loads(raw))

    def _key(self) -> str:
        if self._peek() == '"':
            return self._string()
        match = _IDENT.match(self.text, self.pos)
        if match is None:
            raise ValueError(f"unsupported key at {self.pos}")
        self.pos = match.end()
        return match.group()

    def _object(self) -> dict[str, Any]:
        self._expect("{")
        out: dict[str, Any] = {}
        while self._peek() != "}":
            key = self._key()
            self._expect(":")
            out[key] = self.value()
            if self._peek() == ",":
                self.pos += 1
        self._expect("}")
        return out

    def _array(self) -> list[Any]:
        self._expect("[")
        out: list[Any] = []
        while self._peek() != "]":
            out.append(self.value())
            if self._peek() == ",":
                self.pos += 1
        self._expect("]")
        return out


def _is_table(candidate: Mapping[str, Any]) -> bool:
    names = [k for k, v in candidate.items() if _CODE.fullmatch(k) and isinstance(v, str)]
    others = [k for k in candidate if k != RULES_KEY and k not in names]
    return len(names) >= MIN_TABLE_KEYS and not others


def name_table(js: str) -> dict[str, Any] | None:
    """The handler's name table, or None when it carries none. A literal that does not
    parse is not a table; two different tables raise :class:`TableError`."""
    found: list[dict[str, Any]] = []
    for match in _TABLE_START.finditer(js):
        try:
            candidate = _Literal(js, match.start()).value()
        except ValueError:
            continue
        if _is_table(candidate) and candidate not in found:
            found.append(candidate)
    if len(found) > 1:
        raise TableError(f"{len(found)} different name tables")
    return found[0] if found else None


# ── rules ─────────────────────────────────────────────────────────────────────


def _position(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TableError(f"{what} is not a serial position: {value!r}")
    return value


def rule_of(raw: Mapping[str, Any]) -> Rule | None:
    """A table rule as conditions and a name; None for a rule that never matches (no
    ``pos``, a ``posN`` without its ``valueN``, a value that is not one character).

    A rule with ``substringPos`` and ``substringValue`` tests only that substring; any
    other tests ``pos``/``value`` and each ``pos2``..``pos4`` it defines."""
    name = raw.get("model")
    if not isinstance(name, str) or not name.strip():
        raise TableError(f"rule without a name: {raw!r}")
    if "substringPos" in raw and "substringValue" in raw:
        text = raw["substringValue"]
        if not isinstance(text, str):
            raise TableError(f"substring rule without a text: {raw!r}")
        return ((_position(raw["substringPos"], "substringPos"), text),), name
    conditions: list[Condition] = []
    for suffix in ("", "2", "3", "4"):
        key = f"pos{suffix}"
        if key not in raw:
            if suffix == "":
                return None
            continue
        value = raw.get(f"value{suffix}")
        if not isinstance(value, str) or len(value) != 1:
            return None
        conditions.append((_position(raw[key], key), value))
    return tuple(conditions), name


def matches(serial: str, conditions: Iterable[Condition]) -> bool:
    """Whether ``serial`` holds every condition's text at its position."""
    return all(serial[pos : pos + len(text)] == text for pos, text in conditions)


@dataclass(frozen=True)
class Row:
    """One product's names: the base name (None where the table has none for its
    prefix), its serial rules in table order, and the product whose table gave them."""

    base: str | None
    rules: tuple[Rule, ...]
    source: str

    def name_for(self, serial: str) -> str:
        """The name the table gives ``serial`` (``""`` for none), as the handler does."""
        for conditions, name in self.rules:
            if matches(serial, conditions):
                return name
        return self.base or ""


def row_of(table: Mapping[str, Any], prefix: str, source: str) -> Row | None:
    """``table``'s names for ``prefix``; None when it names the prefix nowhere."""
    base = table.get(prefix)
    if not isinstance(base, str) or not base.strip():
        base = None
    raw_rules = table.get(RULES_KEY) or []
    if not isinstance(raw_rules, list):
        raise TableError(f"{RULES_KEY} is not a list")
    rules: list[Rule] = []
    for raw in raw_rules:
        if not isinstance(raw, Mapping):
            raise TableError(f"rule is not an object: {raw!r}")
        if raw.get("prefix") != prefix:
            continue
        rule = rule_of(raw)
        if rule is not None:
            rules.append(rule)
    if base is None and not rules:
        return None
    return Row(base, tuple(rules), source)


def all_rules(tables: Iterable[Mapping[str, Any] | None], prefix: str) -> list[Rule]:
    """Every table's rules for ``prefix``, in table order."""
    found: list[Rule] = []
    for table in tables:
        row = row_of(table, prefix, "") if table is not None else None
        found += row.rules if row is not None else ()
    return found


def table_prefixes(table: Mapping[str, Any]) -> set[str]:
    """Every 5-character prefix ``table`` names, by entry or rule."""
    named = {k for k in table if k != RULES_KEY and len(k) == PREFIX_LEN}
    for raw in table.get(RULES_KEY) or []:
        if isinstance(raw, Mapping) and isinstance(raw.get("prefix"), str):
            named.add(raw["prefix"])
    return named


def choose_rows(
    tables: Mapping[str, Mapping[str, Any] | None], newest_first: Sequence[str]
) -> dict[str, Row]:
    """The row per product code: its own table when that names its prefix, else the
    first table of ``newest_first`` that does. ``tables`` holds every cached product
    (None for a handler without a table); the rows cover those and every prefix any
    table names."""
    codes = set(tables)
    for table in tables.values():
        if table is not None:
            codes |= table_prefixes(table)
    rows: dict[str, Row] = {}
    for code in sorted(codes):
        prefix = code[:PREFIX_LEN]
        own = tables.get(code)
        row = row_of(own, prefix, code) if own is not None else None
        for other in newest_first:
            if row is not None:
                break
            table = tables.get(other)
            if table is not None:
                row = row_of(table, prefix, other)
        if row is not None:
            rows[code] = row
    return rows


# ── the check against the handlers ────────────────────────────────────────────


def base_serial(prefix: str, rules: Iterable[Rule]) -> str:
    """A serial of ``prefix`` that no rule's text touches: each free position takes the
    first filler character no condition places there."""
    taken: dict[int, set[str]] = {}
    for conditions, _ in rules:
        for pos, text in conditions:
            for i, char in enumerate(text):
                taken.setdefault(pos + i, set()).add(char)
    tail = [
        next(c for c in _FILLERS if c not in taken.get(pos, set()))
        for pos in range(PREFIX_LEN, SERIAL_LEN)
    ]
    return prefix + "".join(tail)


def rule_serial(base: str, conditions: Iterable[Condition]) -> str:
    """``base`` with each condition's text written at its position."""
    chars = list(base)
    for pos, text in conditions:
        chars[pos : pos + len(text)] = text
    return "".join(chars)


def probe_serials(prefix: str, rules: Iterable[Rule]) -> list[str]:
    """The serials a handler is checked on: a base serial no rule touches, that serial
    with each single character of :data:`_SWEEP` at each position after the prefix, and
    one serial per rule (every table's rules for the prefix, so a rule the parse missed
    shows), without repeats."""
    rules = list(rules)
    base = base_serial(prefix, rules)
    serials = [base]
    serials += [
        base[:pos] + char + base[pos + 1 :]
        for pos in range(PREFIX_LEN, SERIAL_LEN)
        for char in _SWEEP
    ]
    serials += [rule_serial(base, conditions) for conditions, _ in rules]
    return list(dict.fromkeys(serials))


def check_handler(
    tm: ModuleType,
    cache: Path,
    code: str,
    table: Mapping[str, Any] | None,
    known_rules: Iterable[Rule] = (),
) -> list[str]:
    """Where the handler of ``code`` answers ``device_model`` otherwise than its own
    parsed table gives (one line per serial); empty when they agree. The probe device
    carries ``code`` as the cloud record's ``device_model``, which a handler may answer
    where its table names nothing. ``known_rules`` adds probe serials (rules other tables
    hold for the prefix)."""
    prefix = code[:PREFIX_LEN]
    row = row_of(table, prefix, code) if table is not None else None
    own_rules = row.rules if row is not None else ()
    serials = probe_serials(prefix, [*own_rules, *known_rules])
    requests = [
        {
            "kind": "get",
            "cmds": "",
            "props": [PROPERTY],
            "device": {"device_sn": sn, "station_sn": sn, PROPERTY: code, "params": []},
        }
        for sn in serials
    ]
    replies = tm.run_driver(tm.handler_file(cache, code), requests)
    problems = []
    for serial, reply in zip(serials, replies, strict=True):
        data = reply.get("data") if isinstance(reply, Mapping) else None
        found = data.get("p2p") if isinstance(data, Mapping) else None
        answer = found.get(PROPERTY, "") if isinstance(found, Mapping) else None
        expected = row.name_for(serial) if row is not None else ""
        if answer != expected and not (expected == "" and answer == code):
            problems.append(
                f"{code}: serial tail {serial[PREFIX_LEN:]!r}: {answer!r} != {expected!r}"
            )
    return problems


# ── generation ────────────────────────────────────────────────────────────────


def _harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "thing_models", ROOT / "scripts" / "thing_models.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("scripts/thing_models.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["thing_models"] = module
    spec.loader.exec_module(module)
    return module


def generate(tm: ModuleType, cache: Path) -> tuple[dict[str, Row], list[str]]:
    """The rows, and every disagreement between a handler and its parsed table."""
    tables: dict[str, Mapping[str, Any] | None] = {}
    dated: list[tuple[str, str]] = []
    declares: list[str] = []
    for code in tm.cached_product_codes(cache):
        td = tm.load_td(cache, code)
        js = tm.handler_file(cache, code).read_text(encoding="utf-8")
        try:
            tables[code] = name_table(js)
        except TableError as err:
            raise TableError(f"{code}: {err}") from None
        plugin_path = str((td.get("profile") or {}).get("plugin_path", ""))
        dated.append((tm.plugin_path_date(plugin_path) or "", code))
        if PROPERTY in tm.identifiers(td, "properties"):
            declares.append(code)
    newest_first = [code for _, code in sorted(dated, reverse=True)]
    rows = choose_rows(tables, newest_first)
    problems = [
        line
        for code in declares
        for line in check_handler(
            tm, cache, code, tables[code], all_rules(tables.values(), code[:PREFIX_LEN])
        )
    ]
    return rows, problems


def _tuple(items: Sequence[str]) -> str:
    return "(" + ", ".join(items) + ("," if len(items) == 1 else "") + ")"


def _rule_literal(rule: Rule) -> str:
    conditions, name = rule
    pairs = _tuple([f"({pos}, {json.dumps(text)})" for pos, text in conditions])
    return f"({pairs}, {json.dumps(name, ensure_ascii=False)})"


def render(rows: Mapping[str, Row]) -> str:
    """The module text: one line per product code, sorted."""
    lines = [
        '"""Generated by scripts/gen_model_names.py from the eufy app\'s product handlers; do',
        "not edit. Per product code: the base name of one handler table (None where it names",
        "only single units), that table's rules that name single units by their serial (each",
        "``(position, text)`` pair must hold; the first rule that matches wins), and the",
        "product code whose handler table gave them: the product's own (the name the eufy app",
        "shows) or, as the library's choice, the newest table naming the prefix (see the",
        'generator)."""',
        "",
        "from typing import Final",
        "",
        "# fmt: off",
        "MODEL_NAMES: Final[",
        "    dict[str, tuple[str | None, tuple[tuple[tuple[tuple[int, str], ...], str], ...], str]]",
        "] = {",
    ]
    for code, row in sorted(rows.items()):
        base = "None" if row.base is None else json.dumps(row.base, ensure_ascii=False)
        rules = _tuple([_rule_literal(rule) for rule in row.rules])
        lines.append(f"    {json.dumps(code)}: ({base}, {rules}, {json.dumps(row.source)}),")
    lines += ["}", "# fmt: on", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_model_names_data.py.")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="compare with --out, write nothing")
    args = parser.parse_args(argv)
    if not args.cache.is_dir():
        print(f"no thing-model cache at {args.cache}", file=sys.stderr)
        return 2
    tm = _harness()
    if (refused := tm.node.node_refusal("gen_model_names")) is not None:
        return int(refused)
    try:
        rows, problems = generate(tm, args.cache)
    except TableError as err:
        print(f"name table: {err}; nothing written", file=sys.stderr)
        return 1
    if problems:
        for line in problems:
            print(f"handler disagrees: {line}", file=sys.stderr)
        print("nothing written", file=sys.stderr)
        return 1
    if not rows:
        print("no names in the cache; nothing written", file=sys.stderr)
        return 1
    text = render(rows)
    if args.check:
        same = args.out.is_file() and args.out.read_text(encoding="utf-8") == text
        print("up to date" if same else f"{args.out} differs")
        return 0 if same else 1
    args.out.write_text(text, encoding="utf-8")
    print(f"{len(rows)} product names written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
