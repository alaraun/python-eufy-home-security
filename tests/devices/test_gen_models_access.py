"""The settings generator probes every property's write, whatever the thing description's
``access_mode`` declares (scripts/gen_models.py, ``sweep`` / ``build_context``).

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


codec = _load("gen_models_codec")
gen_models = _load("gen_models")

PN = "T9ZZ7"  # a product code named nowhere in the library

# lamp: written to 1408 and read from it; blind, declared_blind: the value reaches only the
# stored update (1500, 1501) while the read takes another parameter (1510, 1511);
# status_flag, declared_none: no write, status_flag read from 1600.
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
  if (ident === "lamp") return recipe(1408, { on: v }, v ? "1" : "0");
  if (ident === "blind") return recipe(1500, { open: null }, String(v));
  if (ident === "declared_blind") return recipe(1501, { open: null }, String(v));
  return JSON.stringify({ data: {} });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const cmds = m.input.commandId || [];
  const out = {};
  for (const p of m.device.params || []) {
    if (cmds.indexOf(p.param_type) < 0) continue;
    const on = p.param_value === "1";
    if (p.param_type === 1408) out.lamp = on;
    if (p.param_type === 1510) out.blind = on;
    if (p.param_type === 1511) out.declared_blind = on;
    if (p.param_type === 1600) out.status_flag = on;
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""

PROPS = [
    {"identifier": "lamp", "access_mode": "", "data_type": {"type": "bool"}},
    {"identifier": "blind", "access_mode": "", "data_type": {"type": "bool"}},
    {"identifier": "status_flag", "access_mode": "R", "data_type": {"type": "bool"}},
    {"identifier": "declared_blind", "access_mode": "RW", "data_type": {"type": "bool"}},
    {"identifier": "declared_none", "access_mode": "RW", "data_type": {"type": "bool"}},
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


@pytest.mark.timeout(120)
def test_an_undeclared_property_with_a_proven_write_is_writable(settings: dict[str, Any]) -> None:
    """No ``W`` in its ``access_mode``, but the handler writes it and reads it back."""
    entry = settings["lamp"]
    assert entry["access"] == "rw"
    assert entry["write"] == {
        "cmd": 1408,
        "params": {"on": "$v"},
        "update": {"needUpdate": True, "cmd": 1408, "paramValue": "$v:str"},
    }
    assert entry["read"]["param"] == 1408
    assert "note" not in entry
    assert entry["role"] == "setting"


@pytest.mark.timeout(120)
def test_a_property_without_a_handler_write_stays_read_only(settings: dict[str, Any]) -> None:
    """Declared read-only and never written: ro without a note, read where the handler
    fills it from, and no setting role."""
    entry = settings["status_flag"]
    assert entry["access"] == "ro"
    assert "write" not in entry
    assert "note" not in entry
    assert entry["read"] == {
        "param": 1600,
        "map": {"": False, "0": False, "1": True},
        "no_default": True,
    }
    assert entry["role"] == "diagnostic"


@pytest.mark.timeout(120)
def test_an_undeclared_write_that_does_not_read_back_stays_read_only(
    settings: dict[str, Any],
) -> None:
    """The handler writes it, but getProperty does not return the written value: the read
    the handler fills from its own parameter is kept, no write and no note."""
    entry = settings["blind"]
    assert entry["access"] == "ro"
    assert "write" not in entry
    assert "note" not in entry
    assert entry["read"] == {
        "param": 1510,
        "map": {"": False, "0": False, "1": True},
        "no_default": True,
    }
    assert entry["role"] == "diagnostic"


@pytest.mark.timeout(120)
def test_a_declared_property_keeps_its_write_and_notes(settings: dict[str, Any]) -> None:
    """Declared writable: written without a read back, or read-only with the reason, and
    the app's control either way."""
    blind = settings["declared_blind"]
    assert (blind["access"], blind["read"], blind["note"]) == ("rw", None, codec.ROUND_TRIP_NOTE)
    assert blind["role"] == "setting"
    none = settings["declared_none"]
    assert (none["access"], none["note"]) == ("ro", "no handler write path")
    assert "write" not in none
    assert none["role"] == "setting"
