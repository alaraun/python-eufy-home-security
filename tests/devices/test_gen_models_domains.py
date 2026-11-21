"""The settings generator applies the app's domains and structured marks inside
``generate`` (scripts/gen_models.py, title file ``domains`` / ``structured``).

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

# Each property writes its number to its own command and reads it back from there; a
# text that is no number (an open-string probe) writes null.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const CMDS = { rec_type: 6010, delay: 6011, fmt: 6012, mode: 6013 };
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  const cmd = CMDS[ident];
  if (m.action !== "setProperty" || !cmd) return JSON.stringify({ data: {} });
  const v = Number(JSON.parse(m.input[ident])["payload-value"]);
  return JSON.stringify({ data: { p2p: {
    cmd: 1700, subCmd: cmd, params: { value: Number.isNaN(v) ? null : v },
    update: { needUpdate: true, cmd: cmd, paramValue: String(v) } } } });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const out = {};
  for (const [ident, cmd] of Object.entries(CMDS)) {
    const p = (m.device.params || []).find((x) => x.param_type === cmd);
    if (p) out[ident] = Number(p.param_value);
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""


def _prop(ident: str, dtype: str, specs: dict[str, Any]) -> dict[str, Any]:
    return {"identifier": ident, "access_mode": "RW", "data_type": {"type": dtype, "specs": specs}}


PROPS = [
    _prop("rec_type", "int", {"defaultValue": "0"}),
    _prop("delay", "int", {}),
    _prop("fmt", "string", {}),
    _prop(
        "mode",
        "enum",
        {"eunmList": [{"value": "0", "desc": "a"}, {"value": "1", "desc": "b", "isDefault": 1}]},
    ),
    _prop("sched", "string", {}),
]
TITLES = {
    "domains": {
        "rec_type": {
            "kind": "enum",
            "labels": {"2": "Event-based", "3": "Continuous"},
            "td": "replace",
            "fallback": 3,
            "source": "-",
        },
        "delay": {"kind": "enum", "labels": {"0": "0s", "5": "5s"}, "td": "replace", "source": "-"},
        "fmt": {
            "kind": "enum",
            "labels": {"0": "12-hour", "1": "24-hour"},
            "td": "fill",
            "source": "-",
        },
        "mode": {
            "kind": "enum",
            "labels": {"0": "A", "1": "B", "2": "C"},
            "td": "replace",
            "source": "-",
        },
    },
    "structured": {"sched": {"source": "-"}},
}

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
    doc, _ = gen_models.generate(PN, cache, titles=TITLES)
    return dict(doc["settings"])


@pytest.mark.timeout(120)
def test_a_replace_domain_with_a_fallback_gives_the_default_and_the_read(
    settings: dict[str, Any],
) -> None:
    """The TD default 0 lies outside the screen's values: the default and the read of any
    other value are the screen's fallback."""
    entry = settings["rec_type"]
    assert (entry["kind"], entry["access"], entry["control"]) == ("enum", "rw", "select")
    assert (entry["values"], entry["default"]) == ([2, 3], 3)
    assert entry["read"] == {"param": 6010, "map": None, "fallback": 3}
    assert entry["write"]["subCmd"] == 6010


@pytest.mark.timeout(120)
def test_an_enum_domain_keeps_the_screens_label_texts(settings: dict[str, Any]) -> None:
    entry = settings["delay"]
    assert entry["labels"] == {"0": "0s", "5": "5s"}
    assert "default" not in entry
    assert "fallback" not in entry["read"]


@pytest.mark.timeout(120)
def test_a_fill_domain_makes_an_open_string_a_writable_enum(settings: dict[str, Any]) -> None:
    entry = settings["fmt"]
    assert (entry["kind"], entry["access"], entry["values"]) == ("enum", "rw", [0, 1])
    assert entry["labels"] == {"0": "12-hour", "1": "24-hour"}


@pytest.mark.timeout(120)
def test_a_replace_domain_keeps_the_tds_one_marked_default(settings: dict[str, Any]) -> None:
    """Rows the TD did not mark stay unmarked: the one marked row is the default."""
    entry = settings["mode"]
    assert (entry["values"], entry["default"]) == ([0, 1, 2], 1)


@pytest.mark.timeout(120)
def test_a_structured_rule_marks_the_generated_setting(settings: dict[str, Any]) -> None:
    assert settings["sched"]["structured"] is True
