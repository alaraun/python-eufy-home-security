"""An object write whose members the handler spreads over several parameters: the generator
fits text and switch slots to the recipe (scripts/gen_models_codec.py ``fit_members``) and
reads the object back member by member (scripts/gen_models.py ``member_reads``).

The generator tests run a synthetic handler through the real driver, so they need Node.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.devices.model_settings import WriteContext
from eufy_home_security.devices.model_settings import _build as build_setting

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
IDENT = "sun_cfg"
APP_OBJECTS = [
    {"enable": 1, "lat": "1.5", "lng": "2.5"},
    {"enable": 0, "lat": "1.5", "lng": "2.5"},
    {"enable": True, "lat": 3.25, "lng": -4},
    {"enable": "0", "lat": "-5", "lng": "6"},
]
TITLES = {"object_writes": {IDENT: {"source": "-", "payloads": APP_OBJECTS}}}
CHILD = WriteContext(
    standalone=False, channel=3, device_sn="T0000CHILDSN0001", station_sn="T0000STATION0001"
)

# The handler sends the switch as a number and the place as JSON text, stores the switch's
# text in 7001 and the place (with the device's serial) as JSON text in 7002, and reads the
# property back from both, with "rise"/"set" members only the device fills. MODE "lost":
# the read drops the place.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const MODE = "@MODE@";
const flag = (v) => (v === true || v === 1 || v === "1" || v === "true" ? 1 : 0);
module.exports.controlDevice = function (s) {
  const m = parse(s);
  if (m.action !== "setProperty" || !(IDENT in m.input)) return JSON.stringify({ data: {} });
  const p = JSON.parse(m.input[IDENT])["payload-value"] || {};
  const lat = String(p.lat), lng = String(p.lng), on = flag(p.enable);
  const recipe = { cmd: 7001, params: { value: JSON.stringify({ lat, lng }), mValue3: on },
    update: { needUpdate: true, cmd: 7001, paramValue: String(on) },
    extUpdates: [{ cmd: 7002, paramValue: JSON.stringify({ sn: m.device.device_sn, lat, lng }) }] };
  return JSON.stringify({ data: { p2p: recipe } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const get = (id) => (m.device.params || []).find((x) => x.param_type === id);
  const a = get(7001), b = get(7002);
  if (!a) return JSON.stringify({ data: { p2p: {} } });
  let place = {};
  try { place = JSON.parse(b ? b.param_value : "{}"); } catch (e) { place = {}; }
  const out = { enable: flag(a.param_value), lat: place.lat || "", lng: place.lng || "",
                rise: place.rise || "", set: place.set || "" };
  if (MODE === "lost") { out.lat = ""; }
  return JSON.stringify({ data: { p2p: { [IDENT]: JSON.stringify(out) } } });
};
""".replace("IDENT", json.dumps(IDENT))


def _cache(tmp_path: Path, mode: str) -> Path:
    folder = tmp_path / PN
    folder.mkdir(parents=True)
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {
                "identifier": IDENT,
                "access_mode": "",
                "data_type": {"type": "text", "specs": {"defaultValue": None}},
            }
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(HANDLER.replace("@MODE@", mode), encoding="utf-8")
    return tmp_path


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_an_object_spread_over_parameters_is_written_and_read_member_by_member(
    tmp_path: Path,
) -> None:
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "full"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"], entry["control"]) == ("object", "rw", "object")
    place = {"lat": "$v.lat:str", "lng": "$v.lng:str"}
    assert entry["write"] == {
        "cmd": 7001,
        "params": {"value": {"$jsontext": place}, "mValue3": "$v.enable:flag"},
        "update": {"needUpdate": True, "cmd": 7001, "paramValue": {"$format": ["%s", "$v.enable:flag"]}},
        "extUpdates": [{"cmd": 7002, "paramValue": {"$jsontext": {"sn": "$device_sn", **place}}}],
    }  # fmt: skip
    assert entry["read"] == {
        "param": 7001,
        "map": None,
        "members": {
            "enable": {"param": 7001, "as": "flag"},
            "lat": {"param": 7002, "member": "lat"},
            "lng": {"param": 7002, "member": "lng"},
            "rise": {"param": 7002, "member": "rise"},
            "set": {"param": 7002, "member": "set"},
        },
    }
    assert counts["object:read"] == 1
    setting = build_setting(PN, IDENT, {k: v for k, v in entry.items() if k != "contexts"})
    assert not setting.writable  # 7001 has no frame form: the library refuses the write
    recipe = setting._render_recipe({"enable": True, "lat": 9.5, "lng": "8"}, CHILD)
    block = {7001: "1", 7002: '{"sn":"T0000CHILDSN0001","lat":"9.5","lng":"8"}'}
    assert recipe["update"]["paramValue"] == block[7001]
    assert recipe["extUpdates"][0]["paramValue"] == block[7002]
    assert setting.decode(block[7001], block) == {
        "enable": 1, "lat": "9.5", "lng": "8", "rise": "", "set": ""
    }  # fmt: skip


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_member_the_read_does_not_follow_is_no_read(tmp_path: Path) -> None:
    """The undeclared property keeps its entry: no read, so no write either."""
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "lost"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert "object:read" not in counts


# ── the pure fit ────────────────────────────────────────────────────────────


def test_a_varying_leaf_gets_the_first_member_slot_that_gives_every_sample() -> None:
    values = [{"on": 1, "t": "a"}, {"on": True, "t": 2}, {"on": "0", "t": "c"}]
    recipes = [
        {"n": 1, "s": "1", "x": "a", "k": 5, "j": '{"t":"a"}'},
        {"n": 1, "s": "1", "x": "2", "k": 5, "j": '{"t":"2"}'},
        {"n": 0, "s": "0", "x": "c", "k": 5, "j": '{"t":"c"}'},
    ]
    fitted = codec.fit_members(recipes[0], recipes, values)
    assert fitted == {
        "n": "$v.on:flag",
        "s": {"$format": ["%s", "$v.on:flag"]},
        "x": "$v.t:str",
        "k": 5,  # the same in every sample: no slot
        "j": {"$jsontext": {"t": "$v.t:str"}},
    }


def test_a_write_that_slots_some_members_only_is_no_object_write() -> None:
    """Sending one member of a larger value would drop the others."""
    values = [{"on": 1, "level": 5}, {"on": 0, "level": 5}]
    rows = [(v, {"cmd": 1350, "subCmd": 1, "params": {"on": v["on"]}}) for v in values]
    fit = codec.infer_object_write(rows, rows, 3, 3)
    assert (fit.write, fit.note) == (None, codec.OBJECT_UNMATCHED_NOTE)
    whole = [(v, {"cmd": 1350, "subCmd": 1, "params": {"on": v["on"], "l": 5}}) for v in values]
    assert codec.infer_object_write(whole, whole, 3, 3).note == codec.OBJECT_UNMATCHED_NOTE
    both = [
        ({"on": 1, "level": 5}, {"cmd": 1350, "subCmd": 1, "params": {"o": 1, "l": "5"}}),
        ({"on": 0, "level": 7}, {"cmd": 1350, "subCmd": 1, "params": {"o": 0, "l": "7"}}),
    ]
    fit = codec.infer_object_write(both, both, 3, 3)
    assert fit.write == {
        "cmd": 1350,
        "subCmd": 1,
        "params": {"o": "$v.on:json", "l": "$v.level:str"},
    }


def test_a_leaf_no_member_gives_stays_as_it_is() -> None:
    values = [{"on": 1}, {"on": 0}]
    recipes = [{"n": 7, "j": '{"a": 1}'}, {"n": 9, "j": '{"a": 2}'}]  # spaced text
    assert codec.fit_members(recipes[0], recipes, values) == recipes[0]


def test_a_stored_text_object_is_the_value_only_when_it_holds_the_apps_members() -> None:
    payload = {"enable": 1, "lat": "1"}
    partial = {"update": {"cmd": 1, "paramValue": '{"sn":"x","lat":"1"}'}}
    whole = {"update": {"cmd": 1, "paramValue": '{"enable":1,"lat":"1","sn":"x"}'}}
    based = {"update": {"cmd": 1, "paramValue": codec.object_slot("$v:b64json", {"s": {}})}}
    assert codec.object_value(partial, payload) == payload
    assert codec.object_value(whole, payload) == {"enable": 1, "lat": "1", "sn": "x"}
    assert codec.object_value(based, payload) == {"s": {}}


def test_slotting_texts_replaces_a_serial_inside_a_json_object_text() -> None:
    ctx = codec.CONTEXTS[0]
    text = json.dumps({"sn": ctx.device_sn, "x": ctx.station_sn}, separators=(",", ":"))
    recipe: dict[str, Any] = {"a": text, "b": f"not json {ctx.device_sn}"}
    assert codec.slot(recipe, ctx) == recipe
    assert codec.slot(recipe, ctx, texts=True) == {
        "a": '{"sn":"$device_sn","x":"$station_sn"}'
        if ctx.device_sn != ctx.station_sn
        else '{"sn":"$device_sn","x":"$device_sn"}',
        "b": recipe["b"],
    }
