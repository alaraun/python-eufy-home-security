"""The product-name generator: the handlers' name tables, the choice of table, the check."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from eufy_home_security.devices._model_names_data import MODEL_NAMES

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"

# A synthetic name table in the handlers' shape, with other literals around it.
_NAMES = {f"T90{i:02d}": f"Thing {i}" for i in range(10)}
_RULES = (
    '[{prefix:"T9001",pos:6,value:"5",model:"Thing 1 Max"},'
    '{prefix:"T9002",substringPos:8,substringValue:"2609",model:"Thing 2 Mini"},'
    '{prefix:"T9002",pos:7,value:"A",model:"Thing 2 OEM"}]'
)


def _table_js(names: Mapping[str, str] = _NAMES, rules: str = _RULES) -> str:
    entries = ",".join(f"{code}:{json.dumps(name)}" for code, name in names.items())
    return "{" + entries + f",specialRules:{rules}" + "}"


def _bundle(*tables: str) -> str:
    modules = ",".join(f"{100 + i}:function(e){{e.exports={t}}}" for i, t in enumerate(tables))
    return (
        'var a={T9000:"one",T9001:"two"},b={x:!0,y:[1,2]};'
        f"var m={{{modules}}};"
        'function f(e){return{T9009:"not a table"}}'
    )


@pytest.fixture
def gen(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """``scripts/gen_model_names.py``, registered in ``sys.modules`` for this test only."""
    spec = importlib.util.spec_from_file_location(
        "gen_model_names", ROOT / "scripts" / "gen_model_names.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


# ── the table ─────────────────────────────────────────────────────────────────


def test_the_name_table_is_found_among_other_literals(gen: ModuleType) -> None:
    table = gen.name_table(_bundle(_table_js(), _table_js()))
    assert table is not None
    assert {k: v for k, v in table.items() if k != "specialRules"} == _NAMES
    assert table["specialRules"][1] == {
        "prefix": "T9002",
        "substringPos": 8,
        "substringValue": "2609",
        "model": "Thing 2 Mini",
    }


def test_two_different_tables_are_refused(gen: ModuleType) -> None:
    other = _table_js({**_NAMES, "T9000": "Renamed"})
    with pytest.raises(gen.TableError, match="2 different name tables"):
        gen.name_table(_bundle(_table_js(), other))


@pytest.mark.parametrize(
    "js",
    [
        _bundle(),
        _bundle(_table_js(dict(list(_NAMES.items())[:9]))),  # too few names
        _bundle(_table_js(rules="[]").replace(",specialRules", ",other:1,specialRules")),
    ],
)
def test_a_handler_without_a_table_has_none(gen: ModuleType, js: str) -> None:
    assert gen.name_table(js) is None


def test_the_literal_reads_quoted_keys_escapes_and_booleans(gen: ModuleType) -> None:
    literal = '{"T9000":"Cam \\"Pro\\" \\\\ 2",T9001:"x",flags:[!0,!1,-3]}'
    assert gen._Literal(literal, 0).value() == {
        "T9000": 'Cam "Pro" \\ 2',
        "T9001": "x",
        "flags": [True, False, -3],
    }


# ── rules ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "rule"),
    [
        ({"pos": 6, "value": "5", "model": "A"}, (((6, "5"),), "A")),
        (
            {
                "pos": 5,
                "value": "5",
                "pos2": 6,
                "value2": "3",
                "pos4": 11,
                "value4": "7",
                "model": "B",
            },
            (((5, "5"), (6, "3"), (11, "7")), "B"),
        ),
        (  # a substring rule tests only its substring
            {"substringPos": 8, "substringValue": "2609", "pos": 1, "value": "x", "model": "C"},
            (((8, "2609"),), "C"),
        ),
        ({"substringPos": 8, "pos": 7, "value": "A", "model": "D"}, (((7, "A"),), "D")),
        ({"value": "5", "model": "E"}, None),  # no position: never matches
        ({"pos": 6, "value": "5", "pos2": 7, "model": "F"}, None),  # pos2 without value2
        ({"pos": 6, "value": "55", "model": "G"}, None),  # one character never equals two
    ],
)
def test_a_rule_reads_as_its_conditions(
    gen: ModuleType, raw: dict[str, Any], rule: tuple[Any, str] | None
) -> None:
    assert gen.rule_of(raw) == rule


@pytest.mark.parametrize(
    "raw",
    [
        {"pos": -1, "value": "5", "model": "A"},
        {"pos": True, "value": "5", "model": "A"},
        {"substringPos": 1, "substringValue": 5, "model": "A"},
        {"pos": 6, "value": "5", "model": " "},
        {"pos": 6, "value": "5"},
    ],
)
def test_a_malformed_rule_is_refused(gen: ModuleType, raw: dict[str, Any]) -> None:
    with pytest.raises(gen.TableError):
        gen.rule_of(raw)


def test_a_row_takes_its_prefixs_base_and_rules(gen: ModuleType) -> None:
    table = gen.name_table(_bundle(_table_js()))
    row = gen.row_of(table, "T9002", "T9003")
    assert row == gen.Row(
        "Thing 2",
        (((((8, "2609"),), "Thing 2 Mini")), (((7, "A"),), "Thing 2 OEM")),
        "T9003",
    )
    assert row.name_for("T9002ZZZZZZZZZZZ") == "Thing 2"
    assert row.name_for("T9002ZZA2609ZZZZ") == "Thing 2 Mini"  # the first match wins
    assert row.name_for("T9002ZZAZZZZZZZZ") == "Thing 2 OEM"
    assert gen.row_of(table, "T9999", "T9003") is None


def test_a_blank_base_name_is_none(gen: ModuleType) -> None:
    table = {**{f"T80{i:02d}": "x" for i in range(10)}, "T9001": " ", "specialRules": []}
    assert gen.row_of(table, "T9001", "T9001") is None
    rules = [{"prefix": "T9001", "pos": 6, "value": "5", "model": "Y"}]
    row = gen.row_of({**table, "specialRules": rules}, "T9001", "T9001")
    assert (row.base, row.name_for("T9001ZZZZZZZZZZZ")) == (None, "")


# ── the choice of table ───────────────────────────────────────────────────────


def test_a_product_takes_its_own_table_else_the_newest_naming_it(gen: ModuleType) -> None:
    own = {"T9001": "Own name", "specialRules": []}
    old = {"T9001": "Old name", "T9002": "Old two", "T9003": "Old three", "specialRules": []}
    new = {"T9002": "New two", "T9004": "New four", "specialRules": []}
    tables = {"T9001": own, "T9002": None, "T9005": old, "T9006": new, "T9007": {}}
    rows = gen.choose_rows(tables, ["T9006", "T9005", "T9001", "T9007", "T9002"])
    assert {code: (row.base, row.source) for code, row in rows.items()} == {
        "T9001": ("Own name", "T9001"),  # its own table, though older ones name it too
        "T9002": ("New two", "T9006"),  # no own table: the newest naming it
        "T9003": ("Old three", "T9005"),  # named only by an older table
        "T9004": ("New four", "T9006"),  # not cached: named by a table
    }


def test_a_six_character_code_reads_its_tables_entry_for_the_prefix(gen: ModuleType) -> None:
    own = {"T9001": "Prefix name", "T9001R": "Never looked up", "specialRules": []}
    rows = gen.choose_rows({"T9001R": own}, ["T9001R"])
    assert (rows["T9001R"].base, rows["T9001"].base) == ("Prefix name", "Prefix name")


# ── the check against the handlers ────────────────────────────────────────────


def test_the_probe_serials_reach_every_rule_and_a_base_no_rule_touches(gen: ModuleType) -> None:
    table = gen.name_table(_bundle(_table_js()))
    row = gen.row_of(table, "T9002", "T9002")
    serials = gen.probe_serials("T9002", row.rules)
    base = serials[0]
    assert len(base) == gen.SERIAL_LEN
    assert row.name_for(base) == "Thing 2"
    names = {row.name_for(sn) for sn in serials}
    assert names == {"Thing 2", "Thing 2 Mini", "Thing 2 OEM"}
    assert len(serials) == len(set(serials))


def test_the_base_serial_avoids_every_rules_characters(gen: ModuleType) -> None:
    rules = [(((9, "Z"),), "Zed"), (((10, "ZY"),), "Zed Y")]
    base = gen.base_serial("T9002", rules)
    assert (base[:5], base[9], base[10], base[11]) == ("T9002", "Y", "Y", "Z")
    assert all(base[pos] == "Z" for pos in (5, 6, 7, 8, 12, 13, 14, 15))


def _fake_tm(
    answers: Mapping[str, Callable[[str], str]],
    dates: Mapping[str, str],
    or_cloud: Collection[str] = (),
) -> Any:
    """A harness whose handler of ``code`` answers ``answers[code](serial)`` (default: none);
    a handler in ``or_cloud`` answers the probe device's ``device_model`` instead of none."""

    def nothing(serial: str) -> str:
        return ""

    def run_driver(handler: Path, requests: Sequence[Mapping[str, Any]]) -> list[Any]:
        code = handler.parent.name
        answer = answers.get(code, nothing)
        replies = []
        for r in requests:
            value = answer(r["device"]["device_sn"])
            if code in or_cloud:
                value = value or r["device"].get("device_model")
            replies.append({"code": 0, "data": {"p2p": {"device_model": value}}})
        return replies

    return SimpleNamespace(
        run_driver=run_driver,
        handler_file=lambda cache, code: cache / code / f"{code}Handle.mix.js",
        cached_product_codes=lambda cache: sorted(p.parent.name for p in cache.glob("*/td.json")),
        load_td=lambda cache, code: json.loads((cache / code / "td.json").read_text()),
        plugin_path_date=dates.get,
        identifiers=lambda td, kind: [e["identifier"] for e in td.get(kind, [])],
    )


def _cache(tmp_path: Path, products: Mapping[str, tuple[str, bool]]) -> Path:
    """A cache of ``code -> (handler js, declares device_model)``."""
    for code, (js, declares) in products.items():
        folder = tmp_path / code
        folder.mkdir()
        props = [{"identifier": "device_model"}] if declares else []
        td = {"profile": {"plugin_path": code}, "properties": props}
        (folder / "td.json").write_text(json.dumps(td))
        (folder / f"{code}Handle.mix.js").write_text(js)
    return tmp_path


def test_a_handler_agreeing_with_its_table_passes(gen: ModuleType, tmp_path: Path) -> None:
    js = _bundle(_table_js())
    cache = _cache(tmp_path, {"T9002": (js, True)})
    row = gen.row_of(gen.name_table(js), "T9002", "T9002")
    rows, problems = gen.generate(_fake_tm({"T9002": row.name_for}, {}), cache)
    assert problems == []
    assert rows["T9002"] == row


def test_a_handler_naming_a_unit_its_parsed_table_does_not_is_reported(
    gen: ModuleType, tmp_path: Path
) -> None:
    """A rule the parse missed shows: the probes include every table's rules."""
    without_rules = _bundle(_table_js(rules="[]"))
    with_rules = _bundle(_table_js())
    cache = _cache(tmp_path, {"T9002": (without_rules, True), "T9008": (with_rules, False)})
    truth = gen.row_of(gen.name_table(with_rules), "T9002", "T9002")
    _rows, problems = gen.generate(_fake_tm({"T9002": truth.name_for}, {}), cache)
    assert sorted(problems) == [
        "T9002: serial tail 'ZZAZZZZZZZZ': 'Thing 2 OEM' != 'Thing 2'",
        "T9002: serial tail 'ZZZ2609ZZZZ': 'Thing 2 Mini' != 'Thing 2'",
    ]


def test_a_handler_naming_a_unit_no_table_knows_is_reported(
    gen: ModuleType, tmp_path: Path
) -> None:
    """Each single serial character is tried, so a rule no table holds shows too."""
    js = _bundle(_table_js())
    cache = _cache(tmp_path, {"T9003": (js, True)})

    def handler(serial: str) -> str:
        return "Thing 3 Q" if serial[13] == "Q" else "Thing 3"

    _rows, problems = gen.generate(_fake_tm({"T9003": handler}, {}), cache)
    assert problems == ["T9003: serial tail 'ZZZZZZZZQZZ': 'Thing 3 Q' != 'Thing 3'"]


def test_a_handler_answering_the_cloud_records_code_on_a_miss_passes(
    gen: ModuleType, tmp_path: Path
) -> None:
    """The ``table || device.device_model`` shape: the probe device carries the code."""
    js = _bundle(_table_js())
    cache = _cache(tmp_path, {"T9002": (js, True), "T9050": (js, True)})
    row = gen.row_of(gen.name_table(js), "T9002", "T9002")
    answers = {"T9002": row.name_for}
    _rows, problems = gen.generate(_fake_tm(answers, {}, or_cloud={"T9002", "T9050"}), cache)
    assert problems == []


@pytest.mark.parametrize(
    ("code", "answer", "first"),
    [
        ("T9002", "T9002", "T9002: serial tail 'ZZZZZZZZZZZ': 'T9002' != 'Thing 2'"),
        ("T9050", "Other", "T9050: serial tail 'ZZZZZZZZZZZ': 'Other' != ''"),
    ],
)
def test_a_handler_answering_otherwise_than_its_table_or_the_code_is_reported(
    gen: ModuleType, tmp_path: Path, code: str, answer: str, first: str
) -> None:
    """The code is accepted only on a miss; any other text never."""
    cache = _cache(tmp_path, {code: (_bundle(_table_js()), True)})
    _rows, problems = gen.generate(_fake_tm({code: lambda serial: answer}, {}), cache)
    assert problems[0] == first


def test_only_a_product_declaring_the_property_is_checked(gen: ModuleType, tmp_path: Path) -> None:
    cache = _cache(tmp_path, {"T9002": (_bundle(_table_js()), False)})
    _rows, problems = gen.generate(_fake_tm({}, {}), cache)  # every answer would be ""
    assert problems == []


def test_the_newest_handler_by_date_wins(gen: ModuleType, tmp_path: Path) -> None:
    older = _bundle(_table_js({**_NAMES, "T9005": "Older"}))
    newer = _bundle(_table_js({**_NAMES, "T9005": "Newer"}))
    cache = _cache(tmp_path, {"T9101": (newer, False), "T9102": (older, False)})
    dates = {"T9101": "2026/09/01", "T9102": "2026/01/01"}
    rows, _ = gen.generate(_fake_tm({}, dates), cache)
    assert (rows["T9005"].base, rows["T9005"].source) == ("Newer", "T9101")


def test_a_handler_with_two_tables_names_the_product(gen: ModuleType, tmp_path: Path) -> None:
    js = _bundle(_table_js(), _table_js({**_NAMES, "T9000": "Renamed"}))
    cache = _cache(tmp_path, {"T9002": (js, False)})
    with pytest.raises(gen.TableError, match=r"^T9002: 2 different name tables"):
        gen.generate(_fake_tm({}, {}), cache)


# ── the module ────────────────────────────────────────────────────────────────


def test_the_rendered_module_holds_the_rows(gen: ModuleType) -> None:
    rows = {
        "T9001": gen.Row(
            'Thing "1"', ((((6, "5"),), "One"), (((5, "5"), (6, "3")), "Two")), "T9001"
        ),
        "T9002": gen.Row(None, ((((8, "2609"),), "Mini"),), "T9008"),
        "T9003": gen.Row("Three", (), "T9003"),
    }
    namespace: dict[str, Any] = {}
    exec(gen.render(rows), namespace)  # noqa: S102 - the generator's own output
    assert namespace["MODEL_NAMES"] == {
        code: (row.base, row.rules, row.source) for code, row in rows.items()
    }


def test_the_committed_module_has_the_shape_the_library_reads() -> None:
    for code, (base, rules, source) in MODEL_NAMES.items():
        assert base is None or base.strip()
        assert rules or base is not None, code
        assert source[:1] == "T"
        for conditions, name in rules:
            assert name.strip()
            assert all(pos >= 0 and text for pos, text in conditions)


def test_without_a_cache_the_generator_exits_2(gen: ModuleType, tmp_path: Path) -> None:
    assert gen.main(["--cache", str(tmp_path / "none"), "--check"]) == 2


@pytest.mark.parametrize(
    ("result", "exit_code", "message"),
    [
        ((None, ["T9002: serial tail 'x': 'a' != 'b'"]), 1, "handler disagrees"),
        ((None, None), 1, "name table: bad"),
        (({}, []), 1, "no names in the cache"),
    ],
)
def test_a_failed_run_writes_nothing(
    gen: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    result: tuple[Any, Any],
    exit_code: int,
    message: str,
) -> None:
    def generate(tm: Any, cache: Path) -> tuple[Any, Any]:
        if result == (None, None):
            raise gen.TableError("bad")
        return result

    harness = SimpleNamespace(node=SimpleNamespace(node_refusal=lambda prog: None))
    monkeypatch.setattr(gen, "_harness", lambda: harness)
    monkeypatch.setattr(gen, "generate", generate)
    out = tmp_path / "out.py"
    assert gen.main(["--cache", str(tmp_path), "--out", str(out)]) == exit_code
    assert message in capsys.readouterr().err
    assert not out.exists()


def test_check_compares_and_a_run_writes(
    gen: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = {"T9003": gen.Row("Three", (), "T9003")}
    harness = SimpleNamespace(node=SimpleNamespace(node_refusal=lambda prog: None))
    monkeypatch.setattr(gen, "_harness", lambda: harness)
    monkeypatch.setattr(gen, "generate", lambda tm, cache: (rows, []))
    out = tmp_path / "out.py"
    argv = ["--cache", str(tmp_path), "--out", str(out)]
    assert gen.main([*argv, "--check"]) == 1
    assert gen.main(argv) == 0
    assert out.read_text(encoding="utf-8") == gen.render(rows)
    assert gen.main([*argv, "--check"]) == 0



@pytest.mark.needs_node
@pytest.mark.skipif(not CACHE.is_dir(), reason="needs the private thing-model cache")
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_model_names.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
