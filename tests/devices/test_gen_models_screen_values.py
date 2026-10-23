"""The settings generator drives a handler with the values the app's screens write
(scripts/gen_models.py, ``screen_values``), and reads an enum whose handler read does not
return the written value through the inverse of a bijective write.

Runs synthetic handlers through the real driver, so it needs Node.
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


codec = _load("gen_models_codec")
join = _load("gen_models_join")
gen_models = _load("gen_models")

PN = "T9ZZ8"  # a product code named nowhere in the library
IDENT = "device_continuous_recording_time"
SCREEN = {"default:00": 0, "default:0": 0, "1": 1}
TITLES = {"screen_values": {IDENT: {"values": SCREEN, "models": {}, "source": "-"}}}

# As the app's handlers: the value is taken as an int (NaN for a text that is none).
RECORDING_HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  const t = parseInt(JSON.parse(m.input[ident])["payload-value"], 10);
  return JSON.stringify({ data: { p2p: {
    cmd: 1700, subCmd: 6011, params: { type: t },
    update: { needUpdate: true, cmd: 6011, paramValue: String(t) } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 6011);
  if (!p) return JSON.stringify({ data: { p2p: {} } });
  return JSON.stringify({ data: { p2p: { @IDENT@: parseInt(p.param_value, 10) } } });
};
"""

# A write that maps each value to another wire value (F), and a read through R, by
# default the same map again instead of back: the handler's read never returns the
# written value.
MAPPED_HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const F = @MAP@;
const R = @READ@;
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  const w = F[String(JSON.parse(m.input[ident])["payload-value"])];
  return JSON.stringify({ data: { p2p: {
    cmd: 1214, params: { value: w },
    update: { needUpdate: true, cmd: 1214, paramValue: String(w) }, extUpdates: @EXT@ } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 1214);
  if (!p) return JSON.stringify({ data: { p2p: {} } });
  return JSON.stringify({ data: { p2p: { @IDENT@: R[p.param_value] } } });
};
"""

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _cache(tmp_path: Path, handler: str, ident: str, data_type: dict[str, Any]) -> Path:
    folder = tmp_path / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": [{"identifier": ident, "access_mode": "RW", "data_type": data_type}],
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(handler.replace("@IDENT@", ident), encoding="utf-8")
    return tmp_path


def _enum(*values: str) -> dict[str, Any]:
    return {"type": "ienum", "specs": {"eunmList": [{"value": v} for v in values]}}


RECORDING_TD = _enum("default:00", "1")


def _recording(tmp_path: Path, titles: dict[str, Any], td: dict[str, Any]) -> dict[str, Any]:
    doc, _ = gen_models.generate(PN, _cache(tmp_path, RECORDING_HANDLER, IDENT, td), titles=titles)
    entry: dict[str, Any] = doc["settings"][IDENT]
    return entry


@pytest.mark.timeout(120)
def test_an_enum_is_written_with_the_value_its_screen_writes(tmp_path: Path) -> None:
    """The thing description's ``default:00`` is sent as the screen's 0: the write
    carries 0, not the null an int conversion of the text gives, and reads back."""
    entry = _recording(tmp_path, TITLES, RECORDING_TD)
    assert entry["access"] == "rw"
    assert entry["write"]["params"] == {"type": {"$map": {"default:00": 0, "1": 1}}}
    assert entry["write"]["update"]["paramValue"] == {"$map": {"default:00": "0", "1": "1"}}
    assert entry["read"] == {"param": 6011, "map": {"0": "default:00", "1": 1}}
    assert "note" not in entry


@pytest.mark.timeout(120)
def test_a_single_choice_enum_takes_its_screen_value(tmp_path: Path) -> None:
    entry = _recording(tmp_path, TITLES, _enum("default:0"))
    assert entry["write"]["params"] == {"type": 0}
    assert entry["read"] == {"param": 6011, "map": {"0": "default:0"}}


@pytest.mark.timeout(120)
def test_without_screen_values_the_failed_conversion_stays_write_only(tmp_path: Path) -> None:
    """Probed with the description's own text, the handler writes null ("NaN" stored):
    no value the device reports, so no read is inverted from it."""
    entry = _recording(tmp_path, {}, RECORDING_TD)
    assert entry["write"]["params"] == {"type": {"$map": {"default:00": None, "1": 1}}}
    assert entry["read"] is None
    assert entry["note"] == codec.ROUND_TRIP_NOTE


def test_a_screen_value_two_choices_share_is_not_decoded() -> None:
    wire = {IDENT: (("default:0", 0), ("default:00", 0), (1, "1"))}
    shared = {"data": {"p2p": {IDENT: 0}}}
    assert codec.from_wire({"kind": "get"}, shared, wire) == shared
    one = codec.from_wire({"kind": "get"}, {"data": {"p2p": {IDENT: 1}}}, wire)
    assert one["data"]["p2p"][IDENT] == 1


@pytest.mark.parametrize("cmd", [None, 1214], ids=["no update", "no parameter value"])
def test_a_write_that_stores_no_parameter_value_is_not_read(cmd: int | None) -> None:
    sample = codec.ReadSample(0, cmd, None, codec.MISSING)
    assert codec.inverse_read("enum", [sample]) is None


def test_screen_values_take_a_models_own_values() -> None:
    titles = {
        "screen_values": {
            IDENT: {"values": {"default:0": 0}, "models": {PN: {"default:0": 5}}, "source": "-"}
        }
    }
    assert join.screen_values(PN, titles) == {IDENT: {"default:0": 5}}
    assert join.screen_values("T0001", titles) == {IDENT: {"default:0": 0}}


def test_screen_values_must_be_scalars() -> None:
    titles = {"screen_values": {IDENT: {"values": {"1": [1]}, "models": {}}}}
    with pytest.raises(join.GeneratorError, match="scalar"):
        join.screen_values(PN, titles)


def _mapped(
    tmp_path: Path,
    mapping: dict[str, int],
    data_type: dict[str, Any],
    ext: str = "[]",
    read: dict[str, int] | None = None,
) -> dict[str, Any]:
    handler = (
        MAPPED_HANDLER.replace("@MAP@", json.dumps(mapping))
        .replace("@READ@", json.dumps(mapping if read is None else read))
        .replace("@EXT@", ext)
    )
    doc, _ = gen_models.generate(
        PN, _cache(tmp_path, handler, "watermark_set", data_type), titles={}
    )
    entry: dict[str, Any] = doc["settings"]["watermark_set"]
    return entry


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    "read",
    [
        {"0": 0, "1": 0, "2": 0},
        None,
        {"0": 2, "1": 0, "2": 1, "": 0},
        {"2": 1, "0": 2},
        {"0": 2, "1": 2, "2": 1},
        {"0": 0, "1": 0, "2": 0, "": 1},
    ],
    ids=[
        "one-value-for-all",
        "another-value-each",
        "another-value-each-and-empty",
        "no-value-for-one",
        "one-value-twice",
        "one-value-for-all-and-empty",
    ],
)
def test_a_bijective_write_is_read_by_its_inverse(
    tmp_path: Path, read: dict[str, int] | None
) -> None:
    """Where the handler's read does not return the written value (whatever it decodes,
    the empty parameter included), the read maps each written parameter value back to the
    value that wrote it; the write stays the handler's."""
    entry = _mapped(tmp_path, {"0": 2, "1": 0, "2": 1}, _enum("0", "1", "2"), read=read)
    assert entry["write"]["params"] == {"value": {"$map": {"0": 2, "1": 0, "2": 1}}}
    assert entry["read"] == {"param": 1214, "map": {"0": 1, "1": 2, "2": 0}}
    assert "note" not in entry
    for value in (0, 1, 2):  # write -> read
        rendered = codec.render(entry, value, channel=0)
        assert entry["read"]["map"][str(rendered["update"]["paramValue"])] == value
    for raw, value in entry["read"]["map"].items():  # read -> write
        assert codec.render(entry, value, channel=0)["params"]["value"] == int(raw)


@pytest.mark.timeout(120)
def test_a_write_that_stores_the_value_itself_reads_it_as_is(tmp_path: Path) -> None:
    entry = _mapped(tmp_path, {"0": 0, "1": 1, "2": 2}, _enum("0", "1", "2"), read={})
    assert entry["read"] == {"param": 1214, "map": None}


@pytest.mark.timeout(120)
def test_a_write_two_values_share_stays_write_only(tmp_path: Path) -> None:
    entry = _mapped(tmp_path, {"0": 2, "1": 2, "2": 1}, _enum("0", "1", "2"))
    assert entry["access"] == "rw"
    assert entry["read"] is None
    assert entry["note"] == codec.ROUND_TRIP_NOTE


@pytest.mark.timeout(120)
def test_a_write_that_also_stores_a_failed_conversion_stays_write_only(tmp_path: Path) -> None:
    ext = '[{ cmd: 2003, paramValue: String(parseInt("x", 10)) }]'
    entry = _mapped(tmp_path, {"0": 2, "1": 0, "2": 1}, _enum("0", "1", "2"), ext)
    assert entry["read"] is None
    assert entry["note"] == codec.ROUND_TRIP_NOTE


@pytest.mark.timeout(120)
def test_a_bool_is_not_read_by_the_inverse_of_its_write(tmp_path: Path) -> None:
    entry = _mapped(tmp_path, {"false": 1, "true": 0}, {"type": "bool", "specs": {}})
    assert (entry["kind"], entry["access"]) == ("bool", "rw")
    assert entry["read"] is None


# A write that stores each value's quality base64-encoded, and a read that decodes only
# a per-view report (the view-mode-0 quality), not the value the write stored.
VIEW_HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const Q = { "0": 3, "1": 5, "2": 7 };
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  const q = Q[String(JSON.parse(m.input[ident])["payload-value"])];
  return JSON.stringify({ data: { p2p: {
    cmd: 1350, subCmd: 2730, params: { quality: q },
    update: { needUpdate: true, cmd: 2730, paramValue: Buffer.from(String(q)).toString("base64") } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const p = (m.device.params || []).find((x) => x.param_type === 2730);
  let report = null;
  try { report = JSON.parse(Buffer.from(p.param_value, "base64").toString()); } catch (e) {}
  if (!report || !report.mode_0) return JSON.stringify({ data: { p2p: {} } });
  const v = Object.keys(Q).find((k) => Q[k] === report.mode_0.quality);
  return JSON.stringify({ data: { p2p: { @IDENT@: Number(v) } } });
};
"""


@pytest.mark.timeout(120)
def test_a_per_view_read_takes_precedence_over_the_inverse_of_the_write(tmp_path: Path) -> None:
    """A quality the handler reads per view is read through the view, not by the
    inverse of the write's stored value."""
    cache = _cache(tmp_path, VIEW_HANDLER, "live_streaming_resolution", _enum("0", "1", "2"))
    doc, _ = gen_models.generate(PN, cache, titles={})
    entry = doc["settings"]["live_streaming_resolution"]
    assert entry["read"] == {
        "param": 2730,
        "map": {},
        "view": {"by": None, "map": {"3": 0, "5": 1, "7": 2}},
    }
