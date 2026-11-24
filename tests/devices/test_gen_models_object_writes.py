"""The settings generator writes a property whose app screens write a JSON object as an
``object`` setting where an object form reproduces the handler's recipes
(scripts/gen_models.py ``object_writes``, scripts/gen_models_codec.py
``infer_object_write``).

The generator tests run a synthetic handler through the real driver, so they need Node.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.devices.model_settings import (
    SettingControl,
    SettingKind,
    WriteContext,
    WritePath,
)
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
join = _load("gen_models_join")
gen_models = _load("gen_models")

PN = "T9ZZ9"  # a product code named nowhere in the library
IDENT = "light_cfg"
APP_OBJECTS = [
    {"enable": 1, "time": 30, "loop": [{"start_h": 9, "week": [0, 1]}]},
    {"enable": 0, "time": 60, "loop": [{"start_h": 18, "week": [1, 3]}]},
    {"enable": 1, "time": 60, "loop": []},
]
TITLES = {"object_writes": {IDENT: {"source": "-", "payloads": APP_OBJECTS}}}
CHILD = WriteContext(
    standalone=False, channel=3, device_sn="T0000CHILDSN0001", station_sn="T0000STATION0001"
)

# MODE "base64": the handler reshapes the app's object (days to a bitmask), sends it as the
# body and stores its base64, and reads the property from that parameter. "text": it stores
# the JSON text instead. "member": the body wraps it next to a fixed field, the stored
# base64 is of {schedules}, and nothing reads it back. "constant": as "base64", but the
# property reads one fixed value whatever the parameter holds. "alone": as "base64", but the
# property reads from the parameter only on a standalone device.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const MODE = "@MODE@";
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
module.exports.controlDevice = function (s) {
  const m = parse(s);
  if (m.action !== "setProperty" || !(IDENT in m.input)) return JSON.stringify({ data: {} });
  const p = JSON.parse(m.input[IDENT])["payload-value"] || {};
  const n = {
    enable: p.enable ? 1 : 0,
    time: p.time ?? 30,
    schedule: (p.loop || []).map((e) => ({ ...e, week: e.week.reduce((a, d) => a | (1 << d), 0) })),
  };
  let recipe;
  if (MODE === "member") {
    recipe = { cmd: 1700, subCmd: 6085, params: { account_id: "acct", schedules: n },
               update: { needUpdate: true, cmd: 6085, paramValue: b64({ schedules: n }) } };
  } else {
    const stored = MODE === "text" ? JSON.stringify(n) : b64(n);
    recipe = { cmd: 1350, subCmd: 1422, params: n,
               update: { needUpdate: true, cmd: 1422, paramValue: stored } };
  }
  return JSON.stringify({ data: { p2p: recipe } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 1422);
  const alone = m.device.device_sn === m.device.station_sn;
  if (!p || MODE === "member" || (MODE === "alone" && !alone)) {
    return JSON.stringify({ data: { p2p: {} } });
  }
  if (MODE === "constant") return JSON.stringify({ data: { p2p: { [IDENT]: "{}" } } });
  const raw = p.param_value.startsWith("{") ? p.param_value
    : Buffer.from(p.param_value, "base64").toString();
  return JSON.stringify({ data: { p2p: { [IDENT]: raw } } });
};
""".replace("IDENT", json.dumps(IDENT))


def _cache(tmp_path: Path, mode: str, access: str = "RW") -> Path:
    folder = tmp_path / PN
    folder.mkdir(parents=True)
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [
            {
                "identifier": IDENT,
                "access_mode": access,
                "data_type": {"type": "text", "specs": {"defaultValue": None}},
            }
        ],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(HANDLER.replace("@MODE@", mode), encoding="utf-8")
    return tmp_path


def _stored(obj: Any) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_handler_that_stores_the_objects_base64_gets_an_object_write(tmp_path: Path) -> None:
    """The value is the object the handler stores; it is sent whole and read back."""
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "base64"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"], entry["control"]) == ("object", "rw", "object")
    assert entry["structured"] is True
    assert "note" not in entry
    assert entry["write"] == {
        "cmd": 1350,
        "subCmd": 1422,
        "params": "$v:json",
        "update": {"needUpdate": True, "cmd": 1422, "paramValue": "$v:b64json"},
    }
    assert entry["read"] == {"param": 1422, "map": None}
    assert counts["object:write"] == 1
    setting = build_setting(PN, IDENT, {k: v for k, v in entry.items() if k != "contexts"})
    assert (setting.kind, setting.control) == (SettingKind.OBJECT, SettingControl.OBJECT)
    value = {"enable": 1, "time": 30, "schedule": [{"start_h": 9, "week": 3}]}
    wire = setting.encode(value, CHILD)
    assert (wire.path, wire.cmd, wire.params) == (WritePath.SUB_1350, 1422, value)
    assert wire.updates == ((1422, _stored(value)),)
    assert setting.decode(wire.updates[0][1]) == value


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_handler_that_stores_json_text_keeps_the_setting_read_only(tmp_path: Path) -> None:
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "text"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert entry["note"].endswith(codec.OBJECT_UNMATCHED_NOTE)
    assert "write" not in entry
    assert counts[f"object:{codec.OBJECT_UNMATCHED_NOTE}"] == 1


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_member_of_the_stored_object_fills_its_place_in_the_body(tmp_path: Path) -> None:
    """A body that wraps the stored object's member beside a fixed field slots the member;
    a handler that reads nothing back leaves the setting without a read."""
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "member"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("object", "rw")
    assert entry["write"]["params"] == {"account_id": "acct", "schedules": "$v.schedules:json"}
    assert entry["write"]["update"]["paramValue"] == "$v:b64json"
    assert entry["read"] is None
    assert counts["object:no read"] == 1


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_read_that_does_not_follow_the_stored_value_is_no_read(tmp_path: Path) -> None:
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "constant"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"], entry["read"]) == ("object", "rw", None)
    assert counts["object:no read"] == 1


@pytest.mark.needs_node
@pytest.mark.timeout(120)
@pytest.mark.parametrize("access", ["", "R"])
def test_an_undeclared_object_written_and_read_back_is_writable(
    tmp_path: Path, access: str
) -> None:
    """No ``W`` in its ``access_mode``: the object write is kept where it is proven and the
    handler reads the property from the stored value."""
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "base64", access=access), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"], entry["control"]) == ("object", "rw", "object")
    assert entry["write"]["params"] == "$v:json"
    assert entry["read"] == {"param": 1422, "map": None}
    assert "contexts" not in entry
    assert counts["object:write"] == 1


@pytest.mark.needs_node
@pytest.mark.timeout(120)
@pytest.mark.parametrize("mode", ["member", "constant"])
def test_an_undeclared_object_written_without_a_read_stays_read_only(
    tmp_path: Path, mode: str
) -> None:
    """The handler writes the app's objects, but nothing reads the stored value back: the
    entry stays as without the app's objects, without a note."""
    doc, counts = gen_models.generate(PN, _cache(tmp_path, mode, access=""), titles=TITLES)
    plain, _ = gen_models.generate(PN, _cache(tmp_path / "plain", mode, access=""), titles={})
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert "write" not in entry
    assert "note" not in entry
    assert entry == plain["settings"][IDENT]
    assert not any(key.startswith("object:") for key in counts)


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_an_undeclared_object_without_an_object_form_gets_no_note(tmp_path: Path) -> None:
    doc, counts = gen_models.generate(PN, _cache(tmp_path, "text", access=""), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert "note" not in entry
    assert not any(key.startswith("object:") for key in counts)


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_an_undeclared_object_read_back_in_one_context_is_written_there_only(
    tmp_path: Path,
) -> None:
    """Read back only on a standalone device: the base context stays read-only, the
    standalone context carries the object write and its read."""
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "alone", access=""), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert "write" not in entry
    assert [group["names"] for group in entry["contexts"]] == [["standalone"]]
    alone = entry["contexts"][0]["entry"]
    assert (alone["kind"], alone["access"], alone["control"]) == ("object", "rw", "object")
    assert alone["structured"] is True
    assert alone["read"] == {"param": 1422, "map": None}
    assert alone["write"]["update"]["paramValue"] == "$v:b64json"


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_a_declared_object_read_back_in_one_context_is_written_in_every_context(
    tmp_path: Path,
) -> None:
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "alone"), titles=TITLES)
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"], entry["read"]) == ("object", "rw", None)
    assert entry["contexts"] == [
        {"names": ["standalone"], "entry": {"read": {"param": 1422, "map": None}}}
    ]


@pytest.mark.needs_node
@pytest.mark.timeout(120)
def test_without_the_apps_objects_the_setting_is_left_as_it_was(tmp_path: Path) -> None:
    doc, _ = gen_models.generate(PN, _cache(tmp_path, "base64"), titles={})
    entry = doc["settings"][IDENT]
    assert (entry["kind"], entry["access"]) == ("string", "ro")
    assert codec.OBJECT_UNMATCHED_NOTE not in entry.get("note", "")


# ── the pure inference ──────────────────────────────────────────────────────


def _recipe(value: dict[str, Any], channel: int = 3) -> dict[str, Any]:
    return {
        "cmd": 1350,
        "subCmd": 1422,
        "params": {"value": value, "channel": channel},
        "update": {"needUpdate": True, "cmd": 1422, "paramValue": _stored(value)},
    }


_VALUES = [{"enable": 1, "week": 3}, {"enable": 0, "week": 10}]


def test_an_object_write_slots_the_channel_beside_the_value() -> None:
    main = [(v, _recipe(v)) for v in _VALUES]
    alt = [(v, _recipe(v, 5)) for v in _VALUES]
    fit = codec.infer_object_write(main, alt, 3, 5)
    assert fit.note is None
    assert fit.stored == 1422
    assert fit.values == tuple(_VALUES)
    assert fit.write == {
        "cmd": 1350,
        "subCmd": 1422,
        "params": {"value": "$v:json", "channel": "$channel"},
        "update": {"needUpdate": True, "cmd": 1422, "paramValue": "$v:b64json"},
    }


def test_an_object_write_needs_two_distinct_values() -> None:
    same = [(_VALUES[0], _recipe(_VALUES[0]))] * 2
    fit = codec.infer_object_write(same, same, 3, 3)
    assert (fit.write, fit.note) == (None, codec.OBJECT_UNMATCHED_NOTE)


def test_an_object_write_with_a_rejected_object_names_the_rejection() -> None:
    main = [(_VALUES[0], _recipe(_VALUES[0])), (_VALUES[1], None)]
    fit = codec.infer_object_write(main, main, 3, 5)
    assert (fit.write, fit.note) == (None, codec.OBJECT_REJECTED_NOTE)


def test_no_recipe_for_any_object_is_no_object_write_and_no_note() -> None:
    rows = [(v, None) for v in _VALUES]
    assert codec.infer_object_write(rows, rows, 3, 5) == codec.ObjectFit()


def test_a_body_in_another_member_order_than_the_stored_value_is_no_match() -> None:
    """Member order counts: the body is compared with the stored value as written."""
    main = []
    for v in _VALUES:
        recipe = _recipe(v)
        recipe["params"]["value"] = dict(reversed(list(v.items())))
        main.append((v, recipe))
    fit = codec.infer_object_write(main, main, 3, 3)
    assert (fit.write, fit.note) == (None, codec.OBJECT_UNMATCHED_NOTE)


@pytest.mark.parametrize(
    "rule",
    [
        {"payloads": APP_OBJECTS},
        {"source": "-", "payloads": [APP_OBJECTS[0]]},
        {"source": "-", "payloads": [APP_OBJECTS[0], APP_OBJECTS[0]]},
        {"source": "-", "payloads": [APP_OBJECTS[0], "text"]},
        {"source": "-"},
    ],
    ids=["no-source", "one-object", "same-objects", "not-an-object", "no-payloads"],
)
def test_an_object_write_input_needs_a_source_and_two_distinct_objects(
    rule: dict[str, Any],
) -> None:
    with pytest.raises(codec.GeneratorError, match=f"object write {IDENT}"):
        join.object_writes(PN, {"object_writes": {IDENT: rule}})


def test_the_object_write_input_is_read_per_identifier() -> None:
    assert join.object_writes(PN, TITLES) == {IDENT: APP_OBJECTS}
    assert join.object_writes(PN, None) == {}
