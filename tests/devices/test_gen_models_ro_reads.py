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
# reports it; door_open_count: an int
# from command 1550, as is; label: a string from parameter 1105 in the property table;
# either_open: true when 1201 or 1202 says "1" (no single parameter decides it);
# status_text: no parameter at all; doubled: 1300 read as twice its value.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function asBoolean(v) { return v === true || v === 1 || v === "true" || v === "1"; }
module.exports.controlDevice = function () { return JSON.stringify({ data: {} }); };
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const params = m.device.params || [];
  const cmds = m.input.commandId || [];
  const out = {};
  for (const p of params) {
    if (cmds.indexOf(p.param_type) < 0) continue;
    if (p.param_type === 61016) out.door_open = p.param_value === "1";
    if (p.param_type === 1550) out.door_open_count = parseInt(p.param_value, 10);
  }
  const find = (id) => params.find((p) => p.param_type === id);
  for (const prop of m.input.property || []) {
    if (prop === "label") out.label = (find(1105) || {}).param_value || "";
    if (prop === "either_open") out.either_open =
      asBoolean((find(1201) || {}).param_value) || asBoolean((find(1202) || {}).param_value);
    if (prop === "status_text") out.status_text = "fixed";
    if (prop === "doubled") out.doubled = 2 * parseInt((find(1300) || {}).param_value, 10);
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""

PROPS: list[dict[str, Any]] = [
    {"identifier": "door_open", "access_mode": "R", "data_type": {"type": "bool"}},
    {
        "identifier": "door_open_count",
        "access_mode": "R",
        "data_type": {"type": "int", "specs": {"min": "0", "max": "3", "step": "1"}},
    },
    {"identifier": "label", "access_mode": "R", "data_type": {"type": "text"}},
    {"identifier": "either_open", "access_mode": "R", "data_type": {"type": "bool"}},
    {"identifier": "status_text", "access_mode": "R", "data_type": {"type": "text"}},
    {
        "identifier": "doubled",
        "access_mode": "R",
        "data_type": {"type": "int", "specs": {"min": "0", "max": "3", "step": "1"}},
    },
]

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
        PN, _cache(tmp_path_factory.mktemp("cache")), titles={}
    )[0]
    return doc


def _handler(tmp_path: Path) -> Path:
    return _cache(tmp_path) / PN / f"{PN}Handle.mix.js"


@pytest.mark.timeout(120)
def test_each_property_is_placed_on_the_parameter_its_handler_reads(tmp_path: Path) -> None:
    counts: dict[str, int] = {}
    located = gen_models.locate_params(
        PN, _handler(tmp_path), codec.CHILD, [p["identifier"] for p in PROPS], counts
    )
    assert located == {
        "door_open": gen_models.Located(61016, as_command=True),
        "door_open_count": gen_models.Located(1550, as_command=True),
        "label": gen_models.Located(1105, as_command=False),
        "doubled": gen_models.Located(1300, as_command=False),
    }
    assert counts == {"locate:property": 2, "locate:command": 2}


@pytest.mark.timeout(120)
def test_reported_param_takes_the_located_parameter_when_it_reads_as_is(tmp_path: Path) -> None:
    handler = _handler(tmp_path)
    located = gen_models.locate_params(
        PN, handler, codec.CHILD, [p["identifier"] for p in PROPS], {}
    )

    def reported(ident: str, values: list[str]) -> int | None:
        found: int | None = gen_models.reported_param(
            PN, handler, codec.CHILD, ident, values, located=located
        )
        return found

    assert reported("label", ["a", "b"]) == 1105
    assert reported("doubled", ["1", "2"]) is None  # read back as twice the value
    assert reported("status_text", ["fixed"]) is None  # no parameter


@pytest.mark.timeout(120)
def test_a_read_only_bool_reads_its_command_parameter(generated: dict[str, Any]) -> None:
    entry = generated["settings"]["door_open"]
    assert (entry["kind"], entry["access"]) == ("bool", "ro")
    assert entry["read"] == {"param": 61016, "map": {"": False, "0": False, "1": True}}
    assert "contexts" not in entry


@pytest.mark.timeout(120)
def test_read_only_values_read_as_is_from_their_parameter(generated: dict[str, Any]) -> None:
    settings = generated["settings"]
    assert settings["door_open_count"]["read"] == {"param": 1550, "map": None}
    assert settings["label"]["read"] == {"param": 1105, "map": None}


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    "ident",
    [
        "either_open",  # two parameters decide it
        "status_text",  # no parameter does
        "doubled",  # its parameter's value is not the value read
    ],
)
def test_a_property_no_parameter_reports_as_is_stays_unreadable(
    generated: dict[str, Any], ident: str
) -> None:
    entry = generated["settings"][ident]
    assert entry["access"] == "ro"
    assert entry["read"] is None
    assert "note" not in entry


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
    assert not settings["status_text"].readable
    assert settings["status_text"].decode("1") is None
