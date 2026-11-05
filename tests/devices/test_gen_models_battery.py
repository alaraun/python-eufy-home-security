"""The settings generator writes the parameters a model's battery level is read from
(scripts/gen_models.py, ``battery_reads``).

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

PN = "T9ZZ8"  # a product code named nowhere in the library

pytestmark = [pytest.mark.needs_node, pytest.mark.timeout(120)]

# Each handler fills battery_value from the parameters named in commandId, one listed
# parameter after the other; ``read`` is the body of ``function read(id, v, out)``.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function read(id, v, out) { %s }
module.exports.controlDevice = function () { return JSON.stringify({ data: {} }); };
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const cmds = m.input.commandId || [];
  const out = {};
  for (const p of m.device.params || []) {
    if (cmds.indexOf(p.param_type) >= 0) read(p.param_type, p.param_value, out);
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""

# 1101: 0 and 255 are no level (-1), 200 reads as 100, 1 as 0; 6001 as is; the one listed
# last wins.
LAST_LISTED = """
  const n = parseInt(v, 10);
  if (id === 1101) out.battery_value = n === 0 || n === 255 ? -1 : n === 200 ? 100 : n === 1 ? 0 : n;
  if (id === 6001) out.battery_value = n;
"""
LAST_LISTED_READS = [
    {"param": 1101, "levels": {"0": None, "1": 0, "255": None, "200": 100}},
    {"param": 6001},
]
# 6001 wins over 1101 in either order; 1101 is read as text, "0" as the text "-1".
FIXED = """
  if (id === 1101 && out.from6001 === undefined) out.battery_value = v === "0" ? "-1" : v;
  if (id === 6001) { out.battery_value = parseInt(v, 10); out.from6001 = 1; }
"""
# The one listed first wins.
FIRST_LISTED = """
  if ((id === 1101 || id === 6001) && out.battery_value === undefined)
    out.battery_value = parseInt(v, 10);
"""
# 1101 reads every value as another level, 6001 as is.
SHIFTED = """
  if (id === 1101) out.battery_value = parseInt(v, 10) + 1;
  if (id === 6001) out.battery_value = parseInt(v, 10);
"""
NONE = "if (id === 1101) out.other = v;"


def _handler(tmp_path: Path, body: str) -> Path:
    path = tmp_path / f"{PN}Handle.mix.js"
    path.write_text(HANDLER % body + "\nconst ids = [1101, 1102, 6001, 7000];\n", "utf-8")
    return path


def _reads(tmp_path: Path, body: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    counts: dict[str, int] = {}
    reads = gen_models.battery_reads(PN, _handler(tmp_path, body), codec.CHILD, counts)
    return reads, counts


def test_every_parameter_that_fills_the_battery_is_found(tmp_path: Path) -> None:
    handler = _handler(tmp_path, LAST_LISTED)
    assert gen_models.battery_sources(PN, handler, codec.CHILD) == [1101, 6001]


def test_levels_name_the_raw_values_read_as_another_level(tmp_path: Path) -> None:
    # the device's list order decides between them: ascending ids
    assert _reads(tmp_path, LAST_LISTED) == (LAST_LISTED_READS, {"battery": 2})


def test_a_parameter_that_wins_in_both_orders_comes_first(tmp_path: Path) -> None:
    reads, _ = _reads(tmp_path, FIXED)
    assert reads == [{"param": 6001}, {"param": 1101, "levels": {"0": None}}]


def test_the_one_listed_first_winning_gives_ascending_ids(tmp_path: Path) -> None:
    reads, _ = _reads(tmp_path, FIRST_LISTED)
    assert reads == [{"param": 1101}, {"param": 6001}]


def test_sources_with_no_two_shared_plain_levels_fail(tmp_path: Path) -> None:
    with pytest.raises(gen_models.GeneratorError, match="no two battery levels"):
        _reads(tmp_path, SHIFTED)


def test_one_source_needs_no_plain_level(tmp_path: Path) -> None:
    (read,), _ = _reads(tmp_path, "if (id === 1101) out.battery_value = parseInt(v, 10) + 1;")
    assert (read["param"], len(read["levels"]), read["levels"]["255"]) == (1101, 256, 256)


@pytest.mark.parametrize("answer", ['"full"', "true"])
def test_no_read_when_a_value_is_no_level(tmp_path: Path, answer: str) -> None:
    body = f'if (id === 1101) out.battery_value = v === "100" ? {answer} : v;'
    assert _reads(tmp_path, body) == ([], {"battery:not a level": 1})


def test_no_read_when_nothing_fills_the_battery(tmp_path: Path) -> None:
    assert _reads(tmp_path, NONE) == ([], {})


def _td(tmp_path: Path, props: list[str], body: str) -> Path:
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
    _handler(folder, body)
    return tmp_path


@pytest.mark.parametrize(
    ("props", "body", "battery"),
    [
        (["battery_value", "label"], LAST_LISTED, LAST_LISTED_READS),
        (["label"], LAST_LISTED, None),  # no battery property: no battery read is looked for
        (["battery_value"], NONE, None),  # nothing fills it: no empty list either
    ],
)
def test_the_settings_file_carries_the_battery_reads(
    tmp_path: Path, props: list[str], body: str, battery: list[dict[str, Any]] | None
) -> None:
    doc, _ = gen_models.generate(PN, _td(tmp_path, props, body))
    assert ("battery" in doc, doc.get("battery")) == (battery is not None, battery)
