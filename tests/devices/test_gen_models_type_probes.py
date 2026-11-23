"""The settings generator writes an open number as an int where the handler converts the
value (scripts/gen_models.py ``sweep``, scripts/gen_models_codec.py ``int_slots``).

Runs a synthetic handler through the real driver, so it needs Node.
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


gen_models = _load("gen_models")

PN = "T9ZZ8"  # a product code named nowhere in the library

# converted: the handler writes parseInt of the value; passed: the value as given;
# ranged: a range the handler converts too (its values are numbers already).
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function recipe(cmd, params, stored) {
  return JSON.stringify({ data: { p2p: {
    cmd, params, update: { needUpdate: true, cmd, paramValue: stored } } } });
}
module.exports.controlDevice = function (s) {
  const m = parse(s);
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  const ident = Object.keys(m.input)[0];
  const v = JSON.parse(m.input[ident])["payload-value"];
  if (ident === "converted") return recipe(1282, { d: parseInt(v, 10) }, String(v));
  if (ident === "passed") return recipe(1283, { d: v }, String(v));
  if (ident === "ranged") return recipe(1284, { d: parseInt(v, 10) }, String(v));
  return JSON.stringify({ data: {} });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const cmds = m.input.commandId || [];
  const names = { 1282: "converted", 1283: "passed", 1284: "ranged" };
  const out = {};
  for (const p of m.device.params || []) {
    if (cmds.indexOf(p.param_type) >= 0 && names[p.param_type]) {
      out[names[p.param_type]] = p.param_value;
    }
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""

PROPS = [
    {"identifier": "converted", "access_mode": "RW", "data_type": {"type": "int"}},
    {"identifier": "passed", "access_mode": "RW", "data_type": {"type": "int"}},
    {
        "identifier": "ranged",
        "access_mode": "RW",
        "data_type": {"type": "int", "specs": {"min": "0", "max": "3", "step": "1"}},
    },
]

pytestmark = pytest.mark.needs_node


@pytest.fixture(scope="module")
def settings(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    cache = tmp_path_factory.mktemp("cache")
    folder = cache / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": PROPS,
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(HANDLER, encoding="utf-8")
    out: dict[str, Any] = gen_models.generate(PN, cache)[0]["settings"]
    return out


def _write(entry: dict[str, Any]) -> dict[str, Any]:
    assert entry["access"] == "rw"
    assert "contexts" not in entry
    write: dict[str, Any] = entry["write"]
    return write


@pytest.mark.timeout(120)
def test_an_open_number_the_handler_converts_is_written_as_an_int(
    settings: dict[str, Any],
) -> None:
    """The handler turns a digit string into its number: the client sends an int."""
    entry = settings["converted"]
    assert entry["kind"] == "other"
    assert _write(entry) == {
        "cmd": 1282,
        "params": {"d": "$v:int"},
        "update": {"needUpdate": True, "cmd": 1282, "paramValue": "$v:str"},
    }
    assert entry["read"] == {"param": 1282, "map": None}


@pytest.mark.timeout(120)
def test_an_open_number_the_handler_passes_through_keeps_the_value(
    settings: dict[str, Any],
) -> None:
    assert _write(settings["passed"])["params"] == {"d": "$v"}
    assert settings["passed"]["read"] == {"param": 1283, "map": None}


@pytest.mark.timeout(120)
def test_only_an_open_number_is_type_probed(settings: dict[str, Any]) -> None:
    """A range's values are numbers already: its slot stays ``$v``."""
    assert settings["ranged"]["kind"] == "range"
    assert _write(settings["ranged"])["params"] == {"d": "$v"}
