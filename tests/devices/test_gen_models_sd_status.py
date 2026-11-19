"""The settings generator writes how a model's handler groups an ``SDINFO_EX`` status
(scripts/gen_models.py, ``sd_status_groups``).

Runs synthetic handlers through the real driver, so it needs Node.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
gen_models = _load("gen_models")

PN = "T9ZZ7"  # a product code named nowhere in the library
STATUS_PARAM = 1135

pytestmark = [pytest.mark.needs_node, pytest.mark.timeout(120)]

# A handler of the same shape as a product's: controlDevice answers the parse action of
# an SDINFO_EX answer ({ivalue1: total, ivalue2: free, ivalue3: status}) with the status
# group, deviceStatus fills the status property from the status parameter. ``%(parse)s``
# is the body of ``function parse_status(r, o, m)`` (r: the answer's status, o: the
# device's status parameter, m: the message), ``%(table)s`` the grouping.
HANDLER = """
const TABLE = %(table)s;
function group(v) {
  const n = /^\\s*-?\\d+\\s*$/.test(String(v)) ? parseInt(v, 10) : NaN;
  for (const g in TABLE) if (TABLE[g].includes(n)) return parseInt(g, 10);
  return 1;
}
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function parse_status(r, o, m) { %(parse)s }
module.exports.controlDevice = function (s) {
  const m = parse(s);
  if (m.action !== "get_storage_info_parse_payload") return JSON.stringify({ data: {} });
  const { ivalue1: t = 0, ivalue2: a = 0, ivalue3: r = 0 } = m.input;
  const o = (m.device.params || []).find((p) => p.param_type === 1135)?.param_value;
  const status = parse_status(r, o, m);
  if (status === undefined) return JSON.stringify({ data: { p2p: {} } });
  const mapOf = { totalSpace: t, freeSpace: a, status: { status, buttonList: [6] } };
  return JSON.stringify({ data: { p2p: { mapOf } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const out = {};
  for (const p of m.device.params || []) {
    if (p.param_type === 1135 && %(property)s)
      out.get_storage_status = JSON.stringify({ status: group(p.param_value), buttonList: [] });
  }
  return JSON.stringify({ data: { p2p: out } });
};
const ids = [1101, 1135, 6001];
"""
TABLE = "{0: [0, 25], 2: [4, 31], 18: [29], 22: [33], 3: [-5], 40: [4000]}"
CODES = {"-5": 3, "0": 0, "25": 0, "29": 18, "31": 2, "33": 22, "4": 2, "4000": 40}
READS = "return group(r);"
PREFERS = "return group(o || r);"
IGNORES = "return group(r.status);"  # the answer's status is a number: no group read


def _handler(
    tmp_path: Path, parse: str = READS, *, table: str = TABLE, prop: bool | str = True
) -> Path:
    """A synthetic handler; ``prop``: whether it fills the status property, or the JS
    condition (on ``m``, the message) under which it does."""
    path = tmp_path / f"{PN}Handle.mix.js"
    cond = prop if isinstance(prop, str) else "true" if prop else "false"
    text = HANDLER % {"table": table, "parse": parse, "property": cond}
    path.write_text(text, "utf-8")
    return path


def _groups(
    tmp_path: Path,
    parse: str = READS,
    *,
    prop: bool | str = True,
    located: bool = True,
    **kwargs: Any,
) -> tuple[dict[str, Any] | None, dict[str, int]]:
    """``sd_status_groups`` of a synthetic handler; ``located``: the status property is
    among the located thing-description properties (else the generator looks for it)."""
    counts: dict[str, int] = {}
    where = {"get_storage_status": gen_models.Located(STATUS_PARAM, True)}
    handler = _handler(tmp_path, parse, prop=prop, **kwargs)
    found = gen_models.sd_status_groups(
        PN, handler, gen_models.contexts_of(PN), where if located else {}, counts
    )
    return found, counts


def test_the_parse_of_the_answer_gives_each_code_its_group(tmp_path: Path) -> None:
    """Codes beyond the sample range are found through the handler's number literals."""
    assert _groups(tmp_path) == ({"codes": CODES, "default": 1}, {"sd status:answer": 1})


def test_the_default_group_is_the_one_of_an_unlisted_code(tmp_path: Path) -> None:
    found, _ = _groups(tmp_path, "const g = group(r); return g === 1 ? 7 : g;")
    assert found == {"codes": CODES, "default": 7}


def test_a_parse_that_prefers_the_status_parameter_names_it(tmp_path: Path) -> None:
    found, _ = _groups(tmp_path, PREFERS)
    assert found == {"codes": CODES, "default": 1, "param": STATUS_PARAM}


@pytest.mark.parametrize(
    "parse",
    [
        "return group(o === undefined ? r : o);",  # an empty parameter wins too
        "return o ? group(o) + 1 : group(r);",  # the parameter's group is not its table's
    ],
)
def test_a_preference_other_than_the_set_parameter_fails(tmp_path: Path, parse: str) -> None:
    with pytest.raises(gen_models.GeneratorError, match="status parameter"):
        _groups(tmp_path, parse)


@pytest.mark.parametrize(
    "parse",
    [
        "return group(o ? Number(o) : r);",  # "+4", "4.0", "0x4" read as 4, "  " as 0
        "return group(o ? parseInt(o, 10) : r);",  # "+4", "4.0" read as 4
    ],
)
def test_a_status_parameter_read_otherwise_than_a_decimal_code_fails(
    tmp_path: Path, parse: str
) -> None:
    """Every code and an empty value read alike; only a value no code names tells."""
    with pytest.raises(gen_models.GeneratorError, match="otherwise than"):
        _groups(tmp_path, parse)


def test_a_parse_that_reads_no_status_takes_the_status_property(tmp_path: Path) -> None:
    found, counts = _groups(tmp_path, IGNORES)
    assert (found, counts) == ({"codes": CODES, "default": 1}, {"sd status:param": 1})


def test_a_parse_that_reads_only_the_status_parameter_names_no_parameter(
    tmp_path: Path,
) -> None:
    """Without the answer's status the table comes from the status property, alone."""
    found, counts = _groups(tmp_path, "return group(o);")
    assert (found, counts) == ({"codes": CODES, "default": 1}, {"sd status:param": 1})


def test_a_parse_that_prefers_two_parameters_fails(tmp_path: Path) -> None:
    parse = (
        "const p = (m.device.params || []).find((x) => x.param_type === 6001)?.param_value;"
        " return group(o || p || r);"
    )
    with pytest.raises(gen_models.GeneratorError, match=r"reads parameters \[1135, 6001\]"):
        _groups(tmp_path, parse)


def test_no_parse_at_all_takes_the_status_property(tmp_path: Path) -> None:
    found, counts = _groups(tmp_path, "return undefined;")
    assert (found, counts) == ({"codes": CODES, "default": 1}, {"sd status:param": 1})


def test_a_status_property_the_description_lacks_is_looked_for(tmp_path: Path) -> None:
    found, counts = _groups(tmp_path, IGNORES, located=False)
    assert (found, counts) == ({"codes": CODES, "default": 1}, {"sd status:param": 1})


@pytest.mark.parametrize("parse", [IGNORES, "return undefined;"])
def test_no_grouping_without_a_parse_or_a_status_property(tmp_path: Path, parse: str) -> None:
    assert _groups(tmp_path, parse, prop=False, located=False) == (None, {})


def test_a_status_property_that_reads_no_status_gives_no_grouping(tmp_path: Path) -> None:
    assert _groups(tmp_path, IGNORES, table="{}") == (None, {})


STANDALONE = "m.device.device_sn === m.device.parent_sn"  # true in the standalone context


@pytest.mark.parametrize(
    ("parse", "prop", "what"),
    [
        (f"return {STANDALONE} ? group(r) : 1 + group(r);", True, "grouping"),
        (f"return group({STANDALONE} && o ? o : r);", True, "status parameter"),
        (IGNORES, STANDALONE, "status property's grouping"),
        (IGNORES, f"!({STANDALONE}) || p.param_value !== '4'", "status property's grouping"),
    ],
    ids=["answer", "parameter", "property", "property-code"],
)
def test_a_grouping_that_differs_between_contexts_fails(
    tmp_path: Path, parse: str, prop: str | bool, what: str
) -> None:
    with pytest.raises(gen_models.GeneratorError, match=rf"SDINFO_EX {what} differs between"):
        _groups(tmp_path, parse, prop=prop)


def _td(tmp_path: Path, props: list[str], parse: str, *, prop: bool = True) -> Path:
    folder = tmp_path / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {"identifier": p, "access_mode": "R", "data_type": {"type": "text"}} for p in props
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    _handler(folder, parse, prop=prop)
    return tmp_path


@pytest.mark.parametrize(
    ("props", "parse", "prop", "groups"),
    [
        (["label"], READS, True, {"codes": CODES, "default": 1}),
        (["get_storage_status"], IGNORES, True, {"codes": CODES, "default": 1}),
        (["label"], IGNORES, False, None),  # nothing to read the table from
    ],
)
def test_the_settings_file_carries_the_grouping(
    tmp_path: Path, props: list[str], parse: str, prop: bool, groups: dict[str, Any] | None
) -> None:
    doc, _ = gen_models.generate(PN, _td(tmp_path, props, parse, prop=prop))
    found = doc.get("sd_status_groups")
    assert ("sd_status_groups" in doc, found) == (groups is not None, groups)
