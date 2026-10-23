"""The settings generator types a string property the app shows as an on/off switch as a
bool, sweeping it with the text the app writes (scripts/gen_models.py, ``switches``).

Runs a synthetic handler through the real driver, so it needs Node.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
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


_load("gen_models_codec")
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

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


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
