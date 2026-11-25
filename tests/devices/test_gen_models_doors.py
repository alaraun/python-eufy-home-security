"""The settings generator writes a lock's state parameter per context (``lock``) and a
garage camera's door parameters and command (``garage``) (scripts/gen_models.py).

Runs synthetic handlers through the real driver, so it needs Node.
"""

from __future__ import annotations

import importlib.util
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

PN = "T9ZZ6"  # a product code named nowhere in the library

pytestmark = [pytest.mark.needs_node, pytest.mark.timeout(120)]

COMMON = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function toInt(v, d) { const n = parseInt(v, 10); return isNaN(n) ? d : n; }
const ids = [1101, 1912, 6000, 7500, 7501, 7502];
"""

# The lock-state read of every lock handler: behind a station 1912, as its own station
# 6000, whichever of the two the device lists. ``%(read)s`` turns the raw value ``a``
# into the property, ``%(solo)s`` is the standalone test.
LOCK = (
    COMMON
    + """
module.exports.controlDevice = function () { return JSON.stringify({ data: {} }); };
module.exports.deviceStatus = function (s) {
  const t = parse(s).device;
  const out = {};
  const solo = %(solo)s;
  for (const e of t.params || []) {
    if (e.param_type !== 1912 && e.param_type !== 6000) continue;
    const other = t.params.find((x) => x.param_type === (e.param_type === 1912 ? 6000 : 1912));
    const mine = (e.param_type === 6000) === solo;
    const a = mine ? e.param_value : other?.param_value;
    out.smart_lock_onoff_status = %(read)s;
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""
)
SOLO = "t.device_sn === t.parent_sn"
TO_INT = "toInt(a, 0)"

GARAGE = (
    COMMON
    + """
function doorState(e) {
  %(state)s
}
function bind(e) {
  const a = !(1 & ~e), n = !(2 & ~e);
  return { door_1: a ? 1 : 0, door_2: n ? 1 : 0 };
}
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const value = m.input && m.input.garage_door_on_off;
  if (m.action !== "setProperty" || value === undefined) return JSON.stringify({ data: {} });
  const payload = JSON.parse(value)["payload-value"];
  return JSON.stringify({ data: { p2p: { cmd: 1700, subCmd: 7500, params: %(params)s } } });
};
module.exports.deviceStatus = function (s) {
  const t = parse(s).device;
  const out = {};
  for (const e of t.params || []) {
    const v = parseInt(e.param_value, 10);
    if (e.param_type === 7500) out.garage_door_on_off = JSON.stringify(doorState(v));
    if (e.param_type === 7501)
      out.garage_door_binding_status = JSON.stringify({ ...bind(v), type: v });
    if (e.param_type === 7502) out.garage_sensor_binding_status = JSON.stringify(bind(v));
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""
)
# The handler's parse: a door's unknown bit first, then open, then closed.
HANDLER_STATE = """
  let t = 0, _ = 0;
  e >> 4 & 1 ? t = 0 : 1 & e ? t = 1 : e >> 1 & 1 && (t = 2);
  e >> 5 & 1 ? _ = 0 : e >> 2 & 1 ? _ = 1 : e >> 3 & 1 && (_ = 2);
  return { door_1: t, door_2: _ };
"""
# Door 2 open on bit 1, as the app's home card reads the parameter.
CARD_STATE = HANDLER_STATE.replace("e >> 2 & 1 ? _ = 1", "e >> 1 & 1 ? _ = 1")
# Open before the unknown bit.
OPEN_FIRST = HANDLER_STATE.replace(
    "e >> 4 & 1 ? t = 0 : 1 & e ? t = 1", "1 & e ? t = 1 : e >> 4 & 1 ? t = 0"
)
GARAGE_PROPS = [
    {"identifier": "garage_door_on_off"},
    {"identifier": "garage_door_binding_status"},
    {"identifier": "garage_sensor_binding_status"},
]
GARAGE_FILE = {
    "garage": {
        "state": 7500,
        "motors": 7501,
        "sensors": 7502,
        "control": {"cmd": 1700, "subCmd": 7500},
    }
}


def _handler(tmp_path: Path, text: str) -> Path:
    path = tmp_path / f"{PN}Handle.mix.js"
    path.write_text(text, "utf-8")
    return path


def _lock(
    tmp_path: Path, read: str = TO_INT, solo: str = SOLO, props: list[str] | None = None
) -> tuple[dict[str, Any], dict[str, int]]:
    counts: dict[str, int] = {}
    handler = _handler(tmp_path, LOCK % {"read": read, "solo": solo})
    declared = [{"identifier": i} for i in (props or ["smart_lock_onoff_status"])]
    found = gen_models.lock_block(PN, handler, declared, gen_models.contexts_of(PN), counts)
    return found, counts


def _garage(
    tmp_path: Path,
    state: str = HANDLER_STATE,
    params: str = "payload",
    props: list[dict[str, str]] = GARAGE_PROPS,
) -> tuple[dict[str, Any], dict[str, int]]:
    counts: dict[str, int] = {}
    handler = _handler(tmp_path, GARAGE % {"state": state, "params": params})
    found = gen_models.garage_block(PN, handler, props, gen_models.contexts_of(PN), counts)
    return found, counts


def test_a_lock_reads_6000_as_its_own_station_and_1912_behind_one(tmp_path: Path) -> None:
    assert _lock(tmp_path) == (
        {"lock": {"param": 1912, "contexts": {"standalone": 6000}}},
        {"lock": 1},
    )


def test_a_lock_reading_one_param_everywhere_names_no_context(tmp_path: Path) -> None:
    found, _ = _lock(tmp_path, solo="false")
    assert found == {"lock": {"param": 1912, "contexts": {}}}


def test_a_model_without_the_lock_property_gets_no_block(tmp_path: Path) -> None:
    assert _lock(tmp_path, props=["battery_value"]) == ({}, {})


def test_a_lock_read_that_maps_a_code_fails_the_model(tmp_path: Path) -> None:
    with pytest.raises(gen_models.GeneratorError, match="reads 5 as 9"):
        _lock(tmp_path, read="toInt(a, 0) === 5 ? 9 : toInt(a, 0)")


def test_a_lock_read_in_some_contexts_only_fails_the_model(tmp_path: Path) -> None:
    with pytest.raises(gen_models.GeneratorError, match=r"no read in \['standalone'\]"):
        _lock(tmp_path, read=f"({SOLO}) ? undefined : toInt(a, 0)")


def test_a_lock_read_from_no_param_gets_no_block(tmp_path: Path) -> None:
    assert _lock(tmp_path, read="undefined") == ({}, {"lock:no read": 1})


def test_a_garage_names_its_params_and_door_command(tmp_path: Path) -> None:
    assert _garage(tmp_path) == (GARAGE_FILE, {"garage": 1})


@pytest.mark.parametrize(
    ("state", "message"),
    [(CARD_STATE, r"reads 2 as .*door_2\":1"), (OPEN_FIRST, "reads 17 as")],
)
def test_a_door_state_read_other_than_the_librarys_fails_the_model(
    tmp_path: Path, state: str, message: str
) -> None:
    with pytest.raises(gen_models.GeneratorError, match=message):
        _garage(tmp_path, state)


def test_contexts_reading_the_doors_from_other_params_fail_the_model(tmp_path: Path) -> None:
    handler = _handler(
        tmp_path,
        GARAGE.replace(
            "if (e.param_type === 7500) out.garage_door_on_off",
            "if (e.param_type === (t.device_sn === t.parent_sn ? 1101 : 7500))"
            " out.garage_door_on_off",
        )
        % {"state": HANDLER_STATE, "params": "payload"},
    )
    with pytest.raises(gen_models.GeneratorError, match="differ between contexts"):
        gen_models.garage_block(PN, handler, GARAGE_PROPS, gen_models.contexts_of(PN), {})


def test_a_write_that_does_not_send_the_body_as_is_gets_no_block(tmp_path: Path) -> None:
    found, counts = _garage(tmp_path, params="{ door: payload }")
    assert (found, counts) == ({}, {"garage:no read or write": 1})


def test_a_model_without_every_door_property_gets_no_block(tmp_path: Path) -> None:
    assert _garage(tmp_path, props=GARAGE_PROPS[:2]) == ({}, {"garage:incomplete": 1})
    assert _garage(tmp_path, props=[{"identifier": "battery_value"}]) == ({}, {})
