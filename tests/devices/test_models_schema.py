"""Schema of the committed ``devices/data/models/<PN>.json`` files (pure Python).

Needs neither Node nor the thing-model cache: it reads only committed files. The schema is
described in docs/reference/models-schema.md.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.recipes import ConnectType

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
# The generator's list of the bundled codes; the one place the file set is pinned.
INDEX: dict[str, Any] = json.loads((MODELS / "INDEX.json").read_text(encoding="utf-8"))
CODES: list[str] = INDEX["codes"]

KINDS = {"enum", "bool", "range", "string", "other", "flags"}
WRITE_KEYS = ("write", "write_table")
SCALAR_SLOTS = {"$v", "$v:str", "$v:int", "$channel", "$device_sn", "$station_sn"}
PARAM_SLOT = re.compile(r"\$param:\d+:(int|str)")
CONTEXTS = {"standalone"} | {c.value for c in ConnectType if c is not ConnectType.SINGLE}
OBJECT_SLOTS = {"$map", "$affine"}
RO_NOTES = {
    "no handler write path",
    "handler ignores the value",
    "handler rejects the probed values",
    "handler rejects some values",
    "handler transforms the value",
    "handler expects a structured value",
    "non-linear range",
    "serial embedded in a string",
}
ROUND_TRIP_NOTE = "round trip does not return the written value"
SETTING_KEYS = {
    "kind",
    "access",
    "read",
    "values",
    "min",
    "max",
    "step",
    "unit",
    "default",
    "labels",
    "group",
    "order",
    "page",
    "applies_when",
    "note",
    "name",
    "variant_of",
    "control",
    "flags",
    "bit",
    "domain",
    "contexts",
    *WRITE_KEYS,
}
CONTROLS = {
    "bool": {"switch"},
    "enum": {"select"},
    "range": {"slider", "box"},
    "flags": {"toggles"},
    "string": {"text"},
    "other": set(),
}
DOMAINS = {"timezone"}
UNITS = {"s", "ms", "d", "%"}
IDENT = re.compile(r"[a-z0-9_]+")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SERIAL = re.compile(r"T[0-9A-Z]{4}[A-Z0-9]{11}")


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")


def _key(value: Any) -> str:
    return ("true" if value else "false") if isinstance(value, bool) else str(value)


def _doc(code: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((MODELS / f"{code}.json").read_text(encoding="utf-8"))
    return doc


def _slots(x: Any) -> Iterator[tuple[str, Any]]:
    """Every placeholder of a recipe: ``(name, argument)``; argument None for scalars."""
    if isinstance(x, dict):
        dollar = [k for k in x if k.startswith("$")]
        if dollar:
            assert len(x) == 1, f"placeholder object with other keys: {sorted(x)}"
            yield dollar[0], x[dollar[0]]
            return
        for v in x.values():
            yield from _slots(v)
    elif isinstance(x, list):
        for v in x:
            yield from _slots(v)
    elif isinstance(x, str) and x.startswith("$"):
        yield x, None


def _strings(x: Any) -> Iterator[str]:
    if isinstance(x, dict):
        for k, v in x.items():
            yield k
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)
    elif isinstance(x, str):
        yield x


def _in_context(setting: dict[str, Any], context: str | None) -> dict[str, Any]:
    """``setting`` as ``context`` sees it (None: the base): its contexts item applied,
    null fields removed."""
    out = {k: v for k, v in setting.items() if k != "contexts"}
    for item in setting.get("contexts", []) if context is not None else ():
        if context in item["names"]:
            for k, v in item["entry"].items():
                if v is None:
                    out.pop(k, None)
                else:
                    out[k] = v
    return out


def _check_setting(ident: str, s: dict[str, Any], settings: dict[str, Any]) -> None:
    assert IDENT.fullmatch(ident), ident
    assert set(s) <= SETTING_KEYS, sorted(set(s) - SETTING_KEYS)
    assert s["kind"] in KINDS
    assert s["access"] in {"rw", "ro"}
    kind = s["kind"]
    if kind == "enum":
        assert isinstance(s["values"], list)
        assert s["values"]
    else:
        assert "values" not in s
    if kind == "range":
        assert all(isinstance(s[k], int | float) for k in ("min", "max", "step"))
    if kind == "flags":
        assert s["flags"]
        assert all(isinstance(b, int) for b in s["flags"].values())
        assert all(b > 0 for b in s["flags"].values())
        assert set(s.get("labels", {})) <= set(s["flags"])
    else:
        assert "flags" not in s
    if "bit" in s:
        bit = s["bit"]
        assert kind == "bool", ident
        assert bit > 0, ident
        assert bit & (bit - 1) == 0, ident
    allowed = CONTROLS[kind]
    if "domain" in s:
        assert kind == "string", ident
        assert s["domain"] in DOMAINS, s["domain"]
        allowed = {"select"}
    if s["access"] == "rw" and allowed:
        assert s.get("control") in allowed, (ident, s.get("control"))
    else:
        assert "control" not in s, ident
    keys = {_key(v) for v in s.get("values", [])} if kind == "enum" else {"false", "true"}
    present = [k for k in WRITE_KEYS if k in s]
    if s["access"] == "rw":
        assert ("write" in s) != ("write_table" in s), "rw needs exactly one of write/write_table"
        if "write_table" in s:
            assert set(s["write_table"]) == keys
        if "note" in s:
            parts = s["note"].split("; ")
            assert all(p == ROUND_TRIP_NOTE or p in RO_NOTES for p in parts), s["note"]
    else:
        assert present == [], present
        assert s.get("read") is None
        assert s.get("note", next(iter(RO_NOTES))) in RO_NOTES
    templates = [s["write"]] if "write" in s else []
    templates += list(s.get("write_table", {}).values())
    for template in templates:
        for name, arg in _slots(template):
            if arg is None:
                assert name in SCALAR_SLOTS or PARAM_SLOT.fullmatch(name), name
                continue
            assert name in OBJECT_SLOTS, name
            if name == "$map":
                assert kind in {"enum", "bool"}
                assert set(arg) == keys
            else:
                assert kind == "range"
                assert len(arg) == 2
    read = s.get("read")
    if read is not None:
        assert {"param", "map"} <= set(read) <= {"param", "map", "view"}
        assert isinstance(read["param"], int)
        assert not isinstance(read["param"], bool)
        assert read["map"] is None or isinstance(read["map"], dict)
        if "view" in read:
            view = read["view"]
            assert kind == "enum", ident
            assert set(view) == {"by", "map"}
            assert view["by"] is None or view["by"] == "cur_mode" or type(view["by"]) is int
            assert set(view["map"].values()) <= set(s["values"])
    if "labels" in s and kind != "flags":
        assert set(s["labels"]) <= {_key(v) for v in s.get("values", [])}
    if "bit" in s or kind == "flags":
        assert read is not None, ident
        assert read["map"] is None, ident  # the raw mask is read
    if "applies_when" in s:
        gate, value = s["applies_when"]
        assert settings[gate]["kind"] == "enum"
        assert value in settings[gate]["values"]
    if "unit" in s:
        assert s["unit"] in UNITS, s["unit"]
    if "name" in s:
        assert isinstance(s["name"], str)
        assert s["name"] == s["name"].strip() != ""
    if "variant_of" in s:
        primary = s["variant_of"]
        assert primary != ident
        assert primary in settings
        assert "variant_of" not in settings[primary]
    assert ("group" in s) == ("order" in s)
    if "group" in s:
        assert isinstance(s["group"], str)
        assert isinstance(s["order"], int)


@pytest.mark.parametrize("code", CODES)
def test_model_file_matches_the_schema(code: str) -> None:
    path = MODELS / f"{code}.json"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    doc = json.loads(text, object_pairs_hook=dict)
    assert set(doc) == {"schema_version", "product_code", "source", "settings"}
    assert doc["schema_version"] == 3
    assert doc["product_code"] == code
    source = doc["source"]
    assert set(source) == {"td_version", "handler", "handler_date", "app_version"}
    assert isinstance(source["td_version"], int)
    assert source["handler"].endswith("Handle.mix.js")
    assert DATE.fullmatch(source["handler_date"])
    assert isinstance(source["app_version"], str)
    settings = doc["settings"]
    assert settings
    for ident, setting in settings.items():
        _check_setting(ident, _in_context(setting, None), settings)
    named = set()
    for setting in settings.values():
        for item in setting.get("contexts", []):
            assert set(item) == {"names", "entry"}
            assert item["names"] == sorted(item["names"]), item["names"]
            assert set(item["names"]) <= CONTEXTS, item["names"]
            assert item["entry"], "a contexts item changes nothing"
            assert "contexts" not in item["entry"]
            named.update(item["names"])
    for context in sorted(named):
        resolved = {k: _in_context(v, context) for k, v in settings.items()}
        for ident, setting in resolved.items():
            _check_setting(ident, setting, resolved)
    assert text == codec.dump(doc)
    assert [s for s in _strings(doc) if SERIAL.search(s)] == []


def test_models_holds_exactly_the_indexed_codes() -> None:
    assert len(CODES) == 107
    assert sorted(set(CODES)) == CODES
    assert (INDEX["schema_version"], (MODELS / "INDEX.json").read_text("utf-8")) == (
        3,
        codec.dump(INDEX),
    )
    names = {p.name for p in MODELS.iterdir() if p.is_file()}
    assert names == {f"{c}.json" for c in CODES} | {"INDEX.json", "__init__.py"}
    assert list(model_settings.bundled_codes()) == CODES


@pytest.mark.parametrize(
    "ident",
    ["power_manager_mode", "video_clip_length", "trigger_interval_time", "motion_stop_end_early"],
)
def test_t8160_core_settings_have_write_and_read_codecs(ident: str) -> None:
    setting = _doc("T8160")["settings"][ident]
    assert setting["access"] == "rw"
    assert isinstance(setting["write"], dict)
    assert setting["read"] is not None
