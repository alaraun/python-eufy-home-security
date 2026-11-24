"""The settings generator's routing steps over a whole model (scripts/gen_models.py
``generate``): the owner's id in a JSON-text frame, the span read of a timed value, and
the native-screen decision from the settings tree.

Runs a synthetic handler through the real driver, so it needs Node.
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

from eufy_home_security.devices import model_settings

from .routing_input import library_routing

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
routing = _load("gen_models_routing")

PN = "T9ZZ7"  # a product code named nowhere in the library

# snooze: 1271 with the owner id from the message's user_id; its read takes a stored
# {snooze_time: end, startTime: start} as the duration end - start. chirp: a scalar that
# only a native screen sends (1408, no request case). ring: 1013 with the owner id, a frame
# that carries none. doze (1961) reads its stored end against the clock, so the read depends
# on the absolute start; nap (1962) reads no 30 min choice from its stored span. glow: 1963,
# which only a native screen sends, in its own form, though the handler's params name the
# owner id.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
const DUR = { "0": 1800, "1": 3600, "-1": 0 };
const b64 = (t) => Buffer.from(t).toString("base64");
module.exports.controlDevice = function (s) {
  const m = parse(s);
  const ident = Object.keys(m.input)[0];
  if (m.action !== "setProperty") return JSON.stringify({ data: {} });
  const v = JSON.parse(m.input[ident])["payload-value"];
  let p2p = null;
  if (ident === "snooze") {
    const d = DUR[String(v)];
    p2p = { cmd: 1271, params: { account_id: m.user_id, snooze_time: d },
            update: { needUpdate: true, cmd: 1271, paramValue: b64('{"snooze_time":' + d + "}") } };
  } else if (ident === "pause") {
    const d = DUR[String(v)];
    p2p = { cmd: 1272, params: { pause_time: d },
            update: { needUpdate: true, cmd: 1272, paramValue: b64('{"pause_time":' + d + "}") } };
  } else if (ident === "doze" || ident === "nap") {
    const cmd = ident === "doze" ? 1961 : 1962;
    const d = DUR[String(v)], name = ident + "_time";
    p2p = { cmd, params: { [name]: d },
            update: { needUpdate: true, cmd, paramValue: b64('{"' + name + '":' + d + "}") } };
  } else if (ident === "glow") {
    p2p = { cmd: 1963, params: { on: v ? 1 : 0, user_id: m.user_id },
            update: { needUpdate: true, cmd: 1963, paramValue: v ? "1" : "0" } };
  } else if (ident === "chirp") {
    p2p = { cmd: 1408, params: { on: v ? 1 : 0 },
            update: { needUpdate: true, cmd: 1408, paramValue: v ? "1" : "0" } };
  } else if (ident === "ring") {
    p2p = { cmd: 1013, params: { value: Number(v), user: m.user_id },
            update: { needUpdate: true, cmd: 1013, paramValue: String(v) } };
  }
  return JSON.stringify({ data: p2p ? { p2p } : {} });
};
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const out = {};
  for (const p of m.device.params || []) {
    if (p.param_type === 1271) {
      if (!p.param_value) { out.snooze = -1; continue; }
      try {
        const t = JSON.parse(Buffer.from(p.param_value, "base64").toString());
        let a = t.snooze_time;
        if (String(a).length >= 10 && t.startTime) a = a - t.startTime;
        const k = Object.keys(DUR).find((x) => DUR[x] === a);
        out.snooze = k !== undefined ? Number(k) : a;
      } catch (e) { out.snooze = -1; }
    }
    if (p.param_type === 1272) {
      try {
        const a = JSON.parse(Buffer.from(p.param_value, "base64").toString()).pause_time;
        const k = String(a).length >= 10 ? "0" : Object.keys(DUR).find((x) => DUR[x] === a);
        out.pause = k !== undefined ? Number(k) : -1;
      } catch (e) { out.pause = -1; }
    }
    if (p.param_type === 1961 || p.param_type === 1962) {
      const doze = p.param_type === 1961;
      const name = doze ? "doze" : "nap";
      try {
        const t = JSON.parse(Buffer.from(p.param_value, "base64").toString());
        const a = t[name + "_time"] - (doze ? Math.floor(Date.now() / 1000) : t.startTime);
        const table = doze ? DUR : { "1": 3600, "-1": 0 };
        const k = Object.keys(table).find((x) => table[x] === a);
        out[name] = k !== undefined ? Number(k) : -1;
      } catch (e) { out[name] = -1; }
    }
    if (p.param_type === 1963) out.glow = p.param_value === "1";
    if (p.param_type === 1408) out.chirp = p.param_value === "1";
    if (p.param_type === 1013) out.ring = Number(p.param_value);
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""


def _duration_enum(ident: str) -> dict[str, Any]:
    choices = [
        {"value": "0", "desc": "30min"},
        {"value": "1", "desc": "1hour"},
        {"value": "-1", "desc": "close", "isDefault": 1},
    ]
    return {
        "identifier": ident,
        "access_mode": "RW",
        "data_type": {"type": "enum", "specs": {"eunmList": choices}},
    }


PROPS = [
    *(_duration_enum(ident) for ident in ("snooze", "pause", "doze", "nap")),
    {"identifier": "chirp", "access_mode": "RW", "data_type": {"type": "bool"}},
    {"identifier": "glow", "access_mode": "RW", "data_type": {"type": "bool"}},
    {
        "identifier": "ring",
        "access_mode": "RW",
        "data_type": {"type": "int", "specs": {"min": "0", "max": "2", "step": "1"}},
    },
]


GLOW_SCREEN = {"state": "$v:flag", "account_id": "$account_id"}


def _routes() -> Any:
    doc = library_routing()
    doc["executor"]["cases"] |= {
        "1271": {"msgType": 6, "reader": "json"},
        "1013": {"msgType": 10, "reader": "int", "field": "value"},
        "1961": {"msgType": 6, "reader": "json"},
        "1962": {"msgType": 6, "reader": "json"},
    }
    doc["native"]["forms"]["json_text"]["cmds"] += [1961, 1962, 1963]
    doc["screens"]["forms"] = {"1963": {"form": "json_text", "params": GLOW_SCREEN}}
    doc["screens"]["senders"] = {"1408": [{"msgType": 10}]}
    return routing.parse(doc)


@pytest.fixture(scope="module")
def cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
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
    return cache


def _settings(cache: Path, settings_ui: str) -> dict[str, Any]:
    doc, _ = gen_models.generate(PN, cache, tree={"settings_ui": settings_ui}, routes=_routes())
    return dict(doc["settings"])


pytestmark = pytest.mark.needs_node


@pytest.fixture(scope="module")
def native(cache: Path) -> dict[str, Any]:
    return _settings(cache, "native")


def test_a_json_text_frame_carries_the_owner_id_the_handler_sets(native: dict[str, Any]) -> None:
    """The handler's member that takes the app's user id becomes the owner-id slot, in the
    handler's member order; the frame form that carries no body members keeps none."""
    write = native["snooze"]["write"]
    assert list(write["params"]) == ["account_id", "snooze_time"]
    assert write["params"]["account_id"] == model_settings.ACCOUNT_SLOT
    assert "user" not in json.dumps(native["ring"]["write"])


def test_a_screen_s_json_text_form_keeps_its_own_members(native: dict[str, Any]) -> None:
    """A write the native screen sends in its own JSON-text form keeps that form's members
    and order, even when the handler's params name the owner id elsewhere."""
    assert native["glow"]["access"] == "rw"
    assert list(native["glow"]["write"]["params"].items()) == list(GLOW_SCREEN.items())


def _stored(end: int, start: int) -> str:
    text = json.dumps({"snooze_time": end, "startTime": start})
    return base64.b64encode(text.encode()).decode()


def test_a_timed_value_stored_as_end_and_start_reads_as_its_duration(
    native: dict[str, Any], tmp_path: Path
) -> None:
    """The stored end and start epochs read as the choice whose duration is end - start,
    as the handler reads them; a span no choice has reads unknown."""
    assert native["snooze"]["read"]["span"] == {
        "member": "snooze_time",
        "start": "startTime",
        "map": {"0": -1, "1800": 0, "3600": 1},
    }
    assert "span" not in native["pause"]["read"]  # reads one choice for any stored end
    setting = model_settings._build(PN, "snooze", native["snooze"])
    start = 1795510759
    assert setting.decode(_stored(start + 1800, start)) == 0
    assert setting.decode(_stored(start + 3600, start)) == 1
    assert setting.decode(_stored(start, start)) == -1
    assert setting.decode(_stored(start + 1234, start)) is None
    assert setting.decode("") == -1


@pytest.mark.parametrize("ident", ["doze", "nap"])
def test_a_span_read_only_where_every_probe_reads_back(native: dict[str, Any], ident: str) -> None:
    """A handler that reads a stored span against the clock (doze: right only at one
    start) or reads one choice's span as another (nap: no 30 min) gets no span read."""
    assert gen_models._stored_spans(native[ident]) is not None
    assert "span" not in native[ident]["read"]


def test_two_choices_stored_as_one_span_get_no_span_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two choices whose writes store the same duration cannot be told apart by a span,
    even when the handler reads every probe back as the choice asked."""
    entry = {
        "kind": "enum",
        "values": [0, 1, -1],
        "read": {"param": 1271, "map": {}},
        "write": {
            "cmd": 1271,
            "update": {
                "cmd": 1271,
                "paramValue": {
                    "$map": {
                        "0": _b64_text('{"snooze_time":1800}'),
                        "1": _b64_text('{"snooze_time":1800}'),
                        "-1": _b64_text('{"snooze_time":0}'),
                    }
                },
            },
        },
    }
    asked = [v for v in (0, 1, -1) for _ in gen_models.SPAN_EPOCHS]

    def read_back(_pn: str, _handler: Path, requests: list[Any], *_: Any) -> list[Any]:
        assert len(requests) == len(asked)
        return [{"data": {"p2p": {"snooze": v}}} for v in asked]

    monkeypatch.setattr(gen_models, "run_driver", read_back)
    settings = {"snooze": entry}
    gen_models.span_reads(PN, Path("unused.js"), settings, gen_models.codec.CHILD, {})
    assert "span" not in entry["read"]


@pytest.mark.parametrize(("settings_ui", "chirp"), [("native", "rw"), ("rn", "ro")])
def test_only_a_natively_drawn_model_gets_its_screen_s_scalar_write(
    cache: Path, native: dict[str, Any], settings_ui: str, chirp: str
) -> None:
    """A write only a native screen sends stays writable on a model the app draws natively
    and is read-only on one its RN bundle draws."""
    settings = native if settings_ui == "native" else _settings(cache, settings_ui)
    assert settings["chirp"]["access"] == chirp
    assert settings["snooze"]["access"] == "rw"


def _b64_text(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    ("stored", "found"),
    [
        ({"0": '{"snooze_time":1800}', "1": '{"snooze_time":3600}',
          "": '{"snooze_time":undefined}'},
         ("snooze_time", {0: 1800, 1: 3600})),
        ({"0": '{"snooze_time":1800}', "1": '{"other":3600}'}, None),
        ({"0": '{"snooze_time":1800}', "1": '{"snooze_time":true}'}, None),
        ({"0": '{"snooze_time":1800,"x":1}', "1": '{"snooze_time":3600,"x":1}'}, None),
    ],
)  # fmt: skip
def test_a_span_needs_two_values_stored_as_one_shared_integer_member(
    stored: dict[str, str], found: tuple[str, dict[object, int]] | None
) -> None:
    """A value the write stores in another form is left out; fewer than two spans, or
    two members, is no span."""
    values = {"0": 0, "1": 1, "": ""}
    texts = {k: _b64_text(t) for k, t in stored.items()}
    entry = {
        "kind": "enum",
        "values": [values[k] for k in stored],
        "read": {"param": 1271, "map": {}},
        "write": {"cmd": 1271, "update": {"cmd": 1271, "paramValue": {"$map": texts}}},
    }
    assert gen_models._stored_spans(entry) == found
