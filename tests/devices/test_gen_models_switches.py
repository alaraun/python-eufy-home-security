"""The settings generator types a string property the app shows as an on/off switch as a
bool, sweeping it with the text the app writes (scripts/gen_models.py, ``switches``), and a
bare value the app's screen writes from a switch the same way (``switch_writes``).

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
join = _load("gen_models_join")
gen_models = _load("gen_models")

PN = "T9ZZ9"  # a product code named nowhere in the library
TITLES = {"switches": {"camera_on_off": {"on": "1", "off": "0", "models": {}, "source": "-"}}}

# A handler that reads the app's text ("1" on), as the eufyCam handlers do: a JS true is
# not "1", so a bool payload would read as off. POLARITY: "inverted" sends switch false
# for on (and reports param 1035 "0"), "direct" sends switch true.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const POLARITY = "@POLARITY@";
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty" || ident !== "camera_on_off") return JSON.stringify({ data: {} });
  const on = JSON.parse(m.input[ident])["payload-value"] === "1";
  const sw = POLARITY === "inverted" ? !on : on;
  return JSON.stringify({ data: { p2p: {
    cmd: 1035, params: { switch: sw },
    update: { needUpdate: true, cmd: 1035, paramValue: sw ? "1" : "0" } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 1035);
  if (!p) return JSON.stringify({ data: { p2p: {} } });
  const sw = p.param_value === "1";
  const on = POLARITY === "inverted" ? !sw : sw;
  return JSON.stringify({ data: { p2p: { camera_on_off: on ? "1" : "0" } } });
};
"""

pytestmark = pytest.mark.needs_node


def _cache(tmp_path: Path, polarity: str, data_type: dict[str, Any]) -> Path:
    folder = tmp_path / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {"identifier": "camera_on_off", "access_mode": "RW", "data_type": data_type}
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(
        HANDLER.replace("@POLARITY@", polarity), encoding="utf-8"
    )
    return tmp_path


STRING_TD = {"type": "string", "specs": {"defaultValue": "1"}}


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    ("polarity", "switch", "read"),
    [
        ("inverted", {"$map": {"false": True, "true": False}}, {"0": True, "1": False}),
        ("direct", "$v", {"0": False, "1": True}),
    ],
)
def test_a_string_switch_is_a_bool_written_as_its_handler_does(
    tmp_path: Path, polarity: str, switch: Any, read: dict[str, bool]
) -> None:
    """The write and read polarity come from the handler; the app's text drives it."""
    doc, _ = gen_models.generate(PN, _cache(tmp_path, polarity, STRING_TD), titles=TITLES)
    entry = doc["settings"]["camera_on_off"]
    assert (entry["kind"], entry["access"], entry["default"]) == ("bool", "rw", True)
    assert entry["control"] == "switch"
    assert entry["write"]["cmd"] == 1035
    assert entry["write"]["params"] == {"switch": switch}
    assert entry["read"]["param"] == 1035
    assert {k: v for k, v in entry["read"]["map"].items() if k} == read


@pytest.mark.timeout(120)
def test_a_switch_whose_on_text_is_zero_reads_back_through_the_texts(tmp_path: Path) -> None:
    """With "0" for on, the handler's "0" reads as on: the read decodes the app's text."""
    titles = {"switches": {"camera_on_off": {"on": "0", "off": "1", "models": {}}}}
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "direct", STRING_TD), titles=titles)
    entry = doc["settings"]["camera_on_off"]
    assert (entry["kind"], entry["access"], entry["default"]) == ("bool", "rw", False)
    assert entry["write"]["params"] == {"switch": {"$map": {"false": True, "true": False}}}
    assert {k: v for k, v in entry["read"]["map"].items() if k} == {"0": True, "1": False}


@pytest.mark.timeout(120)
def test_without_the_apps_switch_data_the_string_stays_read_only(tmp_path: Path) -> None:
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "inverted", STRING_TD), titles={})
    entry = doc["settings"]["camera_on_off"]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert entry["note"] == "handler ignores the value"


@pytest.mark.timeout(120)
def test_a_bool_typed_switch_is_also_written_with_the_apps_text(tmp_path: Path) -> None:
    """A thing description typing it bool keeps the kind; the sweep still sends "1"/"0"."""
    bool_td = {"type": "bool", "specs": {"defaultValue": "1"}}
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "inverted", bool_td), titles=TITLES)
    entry = doc["settings"]["camera_on_off"]
    assert (entry["kind"], entry["access"]) == ("bool", "rw")
    assert entry["write"]["params"] == {"switch": {"$map": {"false": True, "true": False}}}


# A handler that turns the light on only for a JSON true, as the app's switch sends it:
# every text, an open-string probe among them, reads as off.
BOOL_HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty" || ident !== "spotlight_switch") return JSON.stringify({ data: {} });
  const on = JSON.parse(m.input[ident])["payload-value"] === true ? 1 : 0;
  return JSON.stringify({ data: { p2p: {
    cmd: 1700, subCmd: 1400, params: { value: on },
    update: { needUpdate: true, cmd: 1400, paramValue: String(on) } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 1400);
  if (!p) return JSON.stringify({ data: { p2p: {} } });
  return JSON.stringify({ data: { p2p: { spotlight_switch: p.param_value === "1" } } });
};
"""
BOOL_TITLES = {"bool_switches": {"spotlight_switch": {"source": "-"}}}


def _bool_cache(tmp_path: Path) -> Path:
    folder = tmp_path / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {
                "identifier": "spotlight_switch",
                "access_mode": "RW",
                "data_type": {"type": "string", "specs": {}},
            }
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(BOOL_HANDLER, encoding="utf-8")
    return tmp_path


@pytest.mark.timeout(120)
def test_a_string_switch_the_app_writes_as_a_json_bool_is_writable(tmp_path: Path) -> None:
    """A switch whose app value is the JSON bool itself is swept with true/false."""
    doc, _ = gen_models.generate(PN, _bool_cache(tmp_path), titles=BOOL_TITLES)
    entry = doc["settings"]["spotlight_switch"]
    assert (entry["kind"], entry["access"], entry["control"]) == ("bool", "rw", "switch")
    assert (entry["write"]["cmd"], entry["write"]["subCmd"]) == (1700, 1400)
    assert entry["write"]["params"] == {"value": "$v:int"}
    assert entry["write"]["update"]["paramValue"] == "$v:str"
    assert entry["read"]["param"] == 1400
    assert {k: v for k, v in entry["read"]["map"].items() if k} == {"0": False, "1": True}


@pytest.mark.timeout(120)
def test_a_json_bool_switch_without_the_apps_data_stays_read_only(tmp_path: Path) -> None:
    """The open-string probes read as off both times: no write is inferred."""
    doc, _ = gen_models.generate(PN, _bool_cache(tmp_path), titles={})
    entry = doc["settings"]["spotlight_switch"]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert entry["note"] == "handler ignores the value"


def test_a_bool_switch_writes_the_json_bool_for_each_state() -> None:
    assert join.switches(PN, BOOL_TITLES) == {"spotlight_switch": {True: True, False: False}}


@pytest.mark.parametrize(("on", "off"), [(True, False), (1, 0)], ids=str)
def test_switch_texts_must_be_strings(on: Any, off: Any) -> None:
    with pytest.raises(join.GeneratorError, match="two distinct"):
        join.switches(PN, {"switches": {"spotlight_switch": {"on": on, "off": off}}})


@pytest.mark.parametrize(
    "rules",
    [
        ["spotlight_switch"],
        {"spotlight_switch": "-"},
        {"spotlight_switch": {}},
        {"spotlight_switch": {"source": 1}},
    ],
    ids=["list", "text-entry", "no-source", "non-text-source"],
)
def test_a_bool_switch_entry_needs_a_source(rules: Any) -> None:
    with pytest.raises(join.GeneratorError, match="bool switch"):
        join.switches(PN, {"bool_switches": rules})


@pytest.mark.parametrize(
    ("default", "values", "expected"),
    [
        ("true", {True: True, False: False}, "true"),
        ("false", {True: True, False: False}, "false"),
        ("0", {True: "1", False: "0"}, "false"),
        ("1", {True: "0", False: "1"}, "false"),
    ],
)
def test_a_switchs_td_default_becomes_its_state(
    default: str, values: dict[bool, Any], expected: str
) -> None:
    prop = {"identifier": "x", "data_type": {"type": "string", "specs": {"defaultValue": default}}}
    assert codec.as_switch(prop, values)["data_type"] == {
        "type": "bool",
        "specs": {"defaultValue": expected},
    }


@pytest.mark.parametrize(
    ("default", "values"),
    [(None, {True: True, False: False}), ("on", {True: True, False: False})],
)
def test_a_switch_default_matching_no_state_is_dropped(
    default: Any, values: dict[bool, Any]
) -> None:
    specs = {} if default is None else {"defaultValue": default}
    prop = {"identifier": "x", "data_type": {"type": "string", "specs": specs}}
    assert codec.as_switch(prop, values)["data_type"] == {"type": "bool", "specs": {}}


def test_a_switch_listed_with_texts_and_as_a_bool_raises() -> None:
    titles = {**BOOL_TITLES, "switches": {"spotlight_switch": {"on": "1", "off": "0"}}}
    with pytest.raises(join.GeneratorError, match="with texts and as a bool"):
        join.switches(PN, titles)


def test_switch_texts_take_a_models_own_pair() -> None:
    titles = {
        "switches": {
            "device_on_off": {"on": "1", "off": "0", "models": {PN: {"on": "0", "off": "1"}}}
        }
    }
    assert join.switches(PN, titles) == {"device_on_off": {True: "0", False: "1"}}
    assert join.switches("T0001", titles) == {"device_on_off": {True: "1", False: "0"}}


def test_switch_with_one_text_for_both_states_raises() -> None:
    with pytest.raises(join.GeneratorError, match="two distinct"):
        join.switches(PN, {"switches": {"camera_on_off": {"on": "1", "off": "1"}}})


# A handler that writes and reads a number, as a station's alarm-delay handler does: the
# app's screen switch sends 1 / 0 (``switch_writes``); the TD declares a bare int.
INT_HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty" || ident !== "alarm_delay") return JSON.stringify({ data: {} });
  const v = parseInt(JSON.parse(m.input[ident])["payload-value"], 10) || 0;
  return JSON.stringify({ data: { p2p: {
    cmd: 1350, subCmd: 1282, params: { notify_alarm_delay: v },
    update: { needUpdate: true, cmd: 1282, paramValue: String(v) } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 1282);
  if (!p) return JSON.stringify({ data: { p2p: {} } });
  return JSON.stringify({ data: { p2p: { alarm_delay: parseInt(p.param_value, 10) } } });
};
"""
INT_SWITCH = {"type": "Int", "on": 1, "off": 0, "sources": ["-"]}


def _int_cache(tmp_path: Path, data_type: dict[str, Any], access: str = "R") -> Path:
    folder = tmp_path / PN
    folder.mkdir(parents=True)
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {"identifier": "alarm_delay", "access_mode": access, "data_type": data_type}
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(INT_HANDLER, encoding="utf-8")
    return tmp_path


BARE_INT_TD = {"type": "int", "specs": {"defaultValue": "1"}}


@pytest.mark.timeout(120)
def test_a_bare_int_the_apps_screen_switches_is_a_switch(tmp_path: Path) -> None:
    """The screen's two values drive the handler; the TD's bare int becomes the bool shown."""
    titles = {"switch_writes": {"alarm_delay": INT_SWITCH}}
    doc, _ = gen_models.generate(
        PN, _int_cache(tmp_path, BARE_INT_TD), titles=titles, shown={"alarm_delay": "page"}
    )
    entry = doc["settings"]["alarm_delay"]
    assert (entry["kind"], entry["access"], entry["control"]) == ("bool", "rw", "switch")
    assert (entry["default"], entry["role"], entry["shown"]) == (True, "setting", "page")
    assert (entry["write"]["cmd"], entry["write"]["subCmd"]) == (1350, 1282)
    assert entry["write"]["params"] == {"notify_alarm_delay": "$v:int"}
    assert entry["read"] == {"param": 1282, "map": None}  # "1" / "0" read as the bool


@pytest.mark.timeout(120)
def test_without_the_screens_switch_a_bare_int_keeps_no_control(tmp_path: Path) -> None:
    """The write is still proven, but no control: the role is the one a read gives it."""
    doc, _ = gen_models.generate(
        PN, _int_cache(tmp_path, BARE_INT_TD), titles={}, shown={"alarm_delay": "page"}
    )
    entry = doc["settings"]["alarm_delay"]
    assert (entry["kind"], entry["access"]) == ("other", "rw")
    assert "control" not in entry
    assert entry["role"] == "status"


ENUM_TD = {
    "type": "enum",
    "specs": {"eunmList": [{"value": "0", "desc": "Off"}, {"value": "1", "desc": "On"}]},
}


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    "data_type", [ENUM_TD, {"type": "bool", "specs": {}}], ids=["enum", "bool"]
)
def test_a_screen_switch_leaves_a_domain_the_td_declares(
    tmp_path: Path, data_type: dict[str, Any]
) -> None:
    """A TD that declares a domain is generated as without the rule: it fills only a bare
    value (the bool is swept with its own true/false, which this handler ignores)."""
    titles = {"switch_writes": {"alarm_delay": INT_SWITCH}}
    doc, _ = gen_models.generate(PN, _int_cache(tmp_path / "a", data_type, "RW"), titles=titles)
    plain, _ = gen_models.generate(PN, _int_cache(tmp_path / "b", data_type, "RW"), titles={})
    assert doc["settings"]["alarm_delay"] == plain["settings"]["alarm_delay"]
    assert doc["settings"]["alarm_delay"]["kind"] == data_type["type"]


@pytest.mark.parametrize(
    ("rule", "values"),
    [
        (INT_SWITCH, {True: 1, False: 0}),
        ({"type": "Bool", "on": True, "off": False, "sources": ["-"]}, {True: True, False: False}),
        ({"type": "String", "on": "0", "off": "1", "sources": ["-"]}, {True: "0", False: "1"}),
    ],
    ids=["int", "bool", "text"],
)
def test_a_screen_switch_writes_its_two_values(rule: dict[str, Any], values: Any) -> None:
    assert join.screen_switches(PN, {"switch_writes": {"x": rule}}) == {"x": values}


@pytest.mark.parametrize(
    "rules",
    [
        ["x"],
        {"x": "-"},
        {"x": {**INT_SWITCH, "sources": []}},
        {"x": {**INT_SWITCH, "sources": "-"}},
        {"x": {**INT_SWITCH, "type": "Float"}},
        {"x": {**INT_SWITCH, "on": 0}},
        {"x": {**INT_SWITCH, "on": "1"}},
        {"x": {**INT_SWITCH, "off": None}},
        {"x": {**INT_SWITCH, "type": "Bool"}},
    ],
    ids=["list", "text", "no-source", "text-sources", "type", "same", "int-text", "none", "bool"],
)
def test_a_screen_switch_entry_needs_two_values_of_its_type(rules: Any) -> None:
    with pytest.raises(join.GeneratorError, match="screen switch"):
        join.screen_switches(PN, {"switch_writes": rules})


@pytest.mark.parametrize(
    ("raw", "fields"), [("degree", {"meaning": "temperature"}), ("s", {"unit": "s"})]
)
def test_td_fields_carry_the_meaning_of_a_unit_without_a_setting_unit(
    raw: str, fields: dict[str, str]
) -> None:
    prop = {
        "identifier": "temp_max",
        "data_type": {"type": "int", "specs": {"min": "50", "max": "100", "unit": raw}},
    }
    out = gen_models.td_fields(PN, prop, "range", [])
    assert {k: out[k] for k in ("unit", "meaning") if k in out} == fields
