"""The settings generator reads a setting without a write from the parameter the handler
fills it from (scripts/gen_models.py, ``locate_params`` / ``located_reads``).

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

from eufy_home_security.devices import model_settings

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

PN = "T9ZZ9"  # a product code named nowhere in the library

# A handler shaped like the vendor's: a property table read for the asked properties,
# and command parsers that fill a property only from a parameter named in commandId.
# door_open: bool from command 61016 (above the four-digit ids), "1" open, as a device
# reports it; door_open_count: an int from command 1550, as is; label: a string from
# parameter 1105 in the property table; either_open: true when 1201 or 1202 says "1" (no
# single parameter decides it); status_text: no parameter at all; doubled: 1300 read as
# twice its value; low_power: commands 1552 and 1601 both fill it, the one met last wins;
# bypass: 1560 as false / true for "0" / "1", else its number (seconds); ring: a bool
# the handler fills with the number of 1561; power_mode: 1700 parsed as
# JSON (its field "source", else the number), its write stores that JSON; ability /
# enc_type: 1103 as is / its JSON field "enc", else its number; mode_num: 1151 parsed as
# an int (1 when it is none); ai_level: 1299 parsed as JSON; raw_level: 1298 a number,
# a JSON object read as its field "items" (a list); nick: 1106 as is, its write stores another form; volume: written to
# 1400, read from 1401; both_open: true when 1203 and 1204 say "1"; digits: 1320 when
# it is digits, else null.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function asBoolean(v) { return v === true || v === 1 || v === "true" || v === "1"; }
function json(v) { try { return JSON.parse(v); } catch (e) { return undefined; } }
function recipe(cmd, value) {
  return { data: { p2p: { cmd: 1350, payload: { value }, update: { cmd, paramValue: value } } } };
}
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const value = (ident) => JSON.parse(m.input[ident])["payload-value"];
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  if (m.input.power_mode !== undefined)
    return JSON.stringify(recipe(1700, JSON.stringify({ source: value("power_mode") })));
  if (m.input.nick !== undefined) return JSON.stringify(recipe(1106, "N:" + value("nick")));
  if (m.input.volume !== undefined) return JSON.stringify(recipe(1400, String(value("volume"))));
  return JSON.stringify({ data: {} });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const params = m.device.params || [];
  const cmds = m.input.commandId || [];
  const out = {};
  for (const p of params) {
    if (cmds.indexOf(p.param_type) < 0) continue;
    const v = p.param_value;
    if (p.param_type === 61016) out.door_open = v === "1";
    if (p.param_type === 1550) out.door_open_count = parseInt(v, 10);
    switch (p.param_type) {
      case 1552:
      case 1601:
        out.low_power = asBoolean(v);
    }
    if (p.param_type === 1560) out.bypass = v === "0" ? false : v === "1" ? true : parseInt(v, 10);
    if (p.param_type === 1561) out.ring = parseInt(v, 10);
    if (p.param_type === 1700) {
      const o = json(v);
      out.power_mode = o !== null && typeof o === "object" ? o.source : o === undefined ? v : o;
    }
  }
  const find = (id) => (params.find((p) => p.param_type === id) || {}).param_value;
  for (const prop of m.input.property || []) {
    if (prop === "label") out.label = find(1105) || "";
    if (prop === "either_open") out.either_open = asBoolean(find(1201)) || asBoolean(find(1202));
    if (prop === "status_text") out.status_text = "fixed";
    if (prop === "doubled") out.doubled = 2 * parseInt(find(1300), 10);
    if (prop === "ability") out.ability = find(1103) || "";
    if (prop === "enc_type") {
      const o = json(find(1103));
      out.enc_type = o !== null && typeof o === "object" ? o.enc : parseInt(find(1103), 10);
    }
    if (prop === "mode_num") {
      const n = parseInt(find(1151), 10);
      out.mode_num = isNaN(n) ? 1 : n;
    }
    if (prop === "ai_level") {
      const o = json(find(1299));
      out.ai_level = o === undefined ? 0 : o;
    }
    if (prop === "raw_level") {
      const o = json(find(1298));
      out.raw_level = o !== null && typeof o === "object" ? o.items || [] : o;
    }
    if (prop === "nick") out.nick = find(1106) || "";
    if (prop === "both_open") out.both_open = asBoolean(find(1203)) && asBoolean(find(1204));
    if (prop === "digits") out.digits = /^[0-9]+$/.test(find(1320)) ? find(1320) : null;
    if (prop === "volume") out.volume = parseInt(find(1401), 10);
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""

RANGE_0_3 = {"type": "int", "specs": {"min": "0", "max": "3", "step": "1"}}


def _prop(ident: str, data_type: dict[str, Any], access: str = "R") -> dict[str, Any]:
    return {"identifier": ident, "access_mode": access, "data_type": data_type}


PROPS: list[dict[str, Any]] = [
    _prop("door_open", {"type": "bool"}),
    _prop("door_open_count", RANGE_0_3),
    _prop("label", {"type": "text"}),
    _prop("either_open", {"type": "bool"}),
    _prop("status_text", {"type": "text"}),
    _prop("doubled", RANGE_0_3),
    _prop("low_power", {"type": "bool"}),
    _prop("bypass", {"type": "bool"}),
    _prop("ring", {"type": "bool"}),
    _prop("power_mode", {"type": "int"}, "RW"),
    _prop("ability", {"type": "text"}),
    _prop("enc_type", {"type": "int"}),
    _prop("mode_num", {"type": "int"}),
    _prop("ai_level", {"type": "int"}),
    _prop("raw_level", {"type": "int"}),
    _prop("nick", {"type": "text"}, "RW"),
    _prop("volume", RANGE_0_3, "RW"),
    _prop("both_open", {"type": "bool"}),
    _prop("digits", {"type": "int"}),
]

SHOWN = frozenset({"door_open", "label", "mode_num"})  # what the app's card and pages read
TREE = {"positions": {"setting_model_config": {"AboutDevice": ["ability#A#1"]}}}
TITLES: dict[str, Any] = {"read_only": {"nick": {}}}  # a status the app only reads

pytestmark = pytest.mark.needs_node


def _cache(tmp_path: Path) -> Path:
    folder = tmp_path / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": PROPS,
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(HANDLER, encoding="utf-8")
    return tmp_path


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    doc: dict[str, Any] = gen_models.generate(
        PN, _cache(tmp_path_factory.mktemp("cache")), tree=TREE, titles=TITLES, shown=SHOWN
    )[0]
    return doc


def _handler(tmp_path: Path) -> Path:
    return _cache(tmp_path) / PN / f"{PN}Handle.mix.js"


def test_the_candidate_ids_are_the_number_literals_of_the_handler(tmp_path: Path) -> None:
    source = tmp_path / "h.js"
    source.write_text(
        "a=7e3;b=0x60f;c=[61016,1550];d=999;e=70000;f=x1234;g=$2345;h=1.5000;i=1E3;", "utf-8"
    )
    assert gen_models.handler_param_ids(source) == [1000, 1550, 1551, 7000, 61016]


@pytest.mark.timeout(120)
def test_each_property_is_placed_on_the_parameter_its_handler_reads(tmp_path: Path) -> None:
    counts: dict[str, int] = {}
    located = gen_models.locate_params(
        PN, _handler(tmp_path), codec.CHILD, [p["identifier"] for p in PROPS], counts
    )
    by_property = {"label": 1105, "doubled": 1300, "ability": 1103, "enc_type": 1103}
    by_property |= {"mode_num": 1151, "ai_level": 1299, "raw_level": 1298}
    by_property |= {"nick": 1106, "volume": 1401, "digits": 1320}
    by_command = {"door_open": 61016, "door_open_count": 1550, "bypass": 1560, "ring": 1561}
    by_command |= {"power_mode": 1700}
    assert located == {
        **{i: gen_models.Located(p, as_command=False) for i, p in by_property.items()},
        **{i: gen_models.Located(p, as_command=True) for i, p in by_command.items()},
    }
    # either_open, both_open: two parameters turn them; low_power: two fill it, the last
    # one met wins.
    assert counts == {"locate:property": 10, "locate:command": 5}


@pytest.mark.timeout(120)
def test_reported_param_takes_the_located_parameter_when_it_reads_as_is(tmp_path: Path) -> None:
    handler = _handler(tmp_path)
    located = gen_models.locate_params(
        PN, handler, codec.CHILD, [p["identifier"] for p in PROPS], {}
    )
    kinds = {p["identifier"]: codec.kind_of(p) for p in PROPS}

    def reported(ident: str, values: list[str]) -> int | None:
        found: int | None = gen_models.reported_param(
            PN, handler, codec.CHILD, ident, values, located=located, kind=kinds[ident]
        )
        return found

    assert reported("label", ["a", "b"]) == 1105
    assert reported("ability", ["a", "b"]) == 1103
    assert reported("mode_num", ["1", "2"]) == 1151  # a numeric parse
    assert reported("doubled", ["1", "2"]) is None  # read back as twice the value
    assert reported("status_text", ["fixed"]) is None  # no parameter
    assert reported("nick", ["a", "b"]) is None  # its write stores another form
    assert reported("power_mode", ["1", "2"]) is None  # a JSON field
    assert reported("enc_type", ["1", "2"]) is None  # another property reads its parameter
    assert reported("ai_level", ["1", "2"]) == 1299  # a JSON parse of the whole value
    assert reported("raw_level", ["1", "2"]) is None  # a JSON value read as a field


@pytest.mark.timeout(120)
def test_a_read_only_bool_reads_its_command_parameter(generated: dict[str, Any]) -> None:
    entry = generated["settings"]["door_open"]
    assert (entry["kind"], entry["access"]) == ("bool", "ro")
    assert entry["read"] == {
        "param": 61016,
        "map": {"": False, "0": False, "1": True},
        "no_default": True,
    }
    assert "contexts" not in entry


@pytest.mark.timeout(120)
def test_read_only_values_read_as_is_from_their_parameter(generated: dict[str, Any]) -> None:
    settings = generated["settings"]
    as_is = {"door_open_count": 1550, "label": 1105, "ability": 1103, "mode_num": 1151}
    as_is |= {"ai_level": 1299, "nick": 1106}
    for ident, param in as_is.items():
        assert settings[ident]["read"] == {"param": param, "map": None, "no_default": True}


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    "ident",
    [
        "either_open",  # two parameters decide it
        "both_open",  # it needs two parameters
        "status_text",  # no parameter does
        "doubled",  # its parameter's value is not the value read
        "low_power",  # two parameters fill it
        "bypass",  # a bool for 0 and 1, a number (seconds) above
        "ring",  # a bool the handler fills with a number
        "power_mode",  # a JSON field; its write stores the JSON
        "enc_type",  # a JSON field of a parameter another property reads as is
        "raw_level",  # a number, but a JSON value reads as one of its fields
        "digits",  # neither as is nor a number
    ],
)
def test_a_property_no_parameter_reports_as_is_stays_unreadable(
    generated: dict[str, Any], ident: str
) -> None:
    entry = generated["settings"][ident]
    assert entry["access"] == "ro"
    assert entry["read"] is None


@pytest.mark.timeout(120)
def test_a_writable_setting_keeps_its_write_round_trip(generated: dict[str, Any]) -> None:
    """A located parameter does not give a read to a setting with a write."""
    entry = generated["settings"]["volume"]
    assert (entry["access"], entry["read"]) == ("rw", None)


@pytest.mark.timeout(120)
def test_every_setting_gets_its_role(generated: dict[str, Any]) -> None:
    got = {k: e["role"] for k, e in generated["settings"].items()}
    named = {
        "door_open": "status",  # shown, read-only
        "label": "status",
        "ability": "status",  # placed in the app's layout
        "mode_num": "diagnostic",  # shown, but it reads the active mode, a device state field
        "volume": "setting",  # written
        "power_mode": "setting",  # writable in the thing description, no library write
        "nick": "status",  # writable in the thing description, the app only reads it
    }
    assert {k: got[k] for k in named} == named
    # The rest are read-only and shown nowhere.
    assert {r for k, r in got.items() if k not in named} == {"diagnostic"}


@pytest.mark.timeout(120)
def test_the_generated_file_reads_through_the_library(generated: dict[str, Any]) -> None:
    """The file loads as the package loads a bundled one; the read-only bool decodes the
    parameter's values and is not writable."""
    data = json.loads(json.dumps(generated))
    settings = model_settings._parse(PN, model_settings._entries(PN, data), None)
    door = settings["door_open"]
    assert (door.readable, door.writable, door.control, door.read_param) == (
        True,
        False,
        None,
        61016,
    )
    assert [door.decode(raw) for raw in ("1", "0", "")] == [True, False, False]
    assert settings["door_open_count"].decode("3") == 3
    assert door._no_default
    assert door.role is model_settings.SettingRole.STATUS
    assert settings["volume"].role is model_settings.SettingRole.SETTING
    assert settings["door_open_count"].role is model_settings.SettingRole.DIAGNOSTIC
    assert not settings["status_text"].readable
    assert settings["status_text"].decode("1") is None
