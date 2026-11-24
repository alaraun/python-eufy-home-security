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
from eufy_home_security.devices.model_settings import BINARY_MEANINGS, SettingMeaning
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.devices.sections import SETTING_SECTIONS

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
# The generator's list of the bundled codes; the one place the file set is pinned.
INDEX: dict[str, Any] = json.loads((MODELS / "INDEX.json").read_text(encoding="utf-8"))
CODES: list[str] = INDEX["codes"]

KINDS = {"enum", "bool", "range", "string", "other", "flags", "object"}
WRITE_KEYS = ("write", "write_table")
SCALAR_SLOTS = {"$v", "$v:str", "$v:int", "$channel", "$device_sn", "$station_sn", "$account_id"}
PARAM_SLOT = re.compile(r"\$param:\d+:(int|str)")
CONTEXTS = {"standalone"} | {c.value for c in ConnectType if c is not ConnectType.SINGLE}
OBJECT_SLOTS = {"$map", "$affine"}
VALUE_OBJECT_SLOT = re.compile(  # an object value's forms; text and switch of a member only
    r"\$v(\.[A-Za-z0-9_]+)*:(json|b64json)|\$v(\.[A-Za-z0-9_]+)+:(str|flag)"
)
DERIVED_SLOTS = {"$format", "$jsontext", "$each", "$or"}  # built from an object value's slots
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
# Appended to a read-only setting's note when the app's objects get no object write.
OBJECT_NOTES = {
    "no object form reproduces the app's object write",
    "handler rejects some of the app's objects",
}
ROUND_TRIP_NOTE = "round trip does not return the written value"
NOT_SENT_NOTE = "the eufy app sends nothing for this write"  # appended: no frame the app sends
STATUS_NOTE = "status the eufy app only reads"  # ro with its read kept
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
    "section",
    "role",
    "shown",
    "applies_when",
    "note",
    "name",
    "variant_of",
    "advanced",
    "structured",
    "control",
    "flags",
    "bit",
    "domain",
    "meaning",
    "contexts",
    "variants",
    *WRITE_KEYS,
}
CONDITION_KEYS = {"type", "qualifier", "value"}
ASSOCIATED_KEYS = {"prop", "param", "map", "default"}
CONTROLS = {
    "bool": {"switch"},
    "enum": {"select"},
    "range": {"slider", "box"},
    "flags": {"toggles"},
    "string": {"text"},
    "other": set(),
    "object": {"object"},
}
DOMAINS = {"timezone"}
UNITS = {"s", "ms", "d", "%"}
IDENT = re.compile(r"[a-z0-9_]+")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SERIAL = re.compile(r"T[0-9A-Z]{4}[A-Z0-9]{11}")
SECTIONS = {s.id for s in SETTING_SECTIONS}
ROLES = {r.value for r in model_settings.SettingRole}
PLACES = {p.value for p in model_settings.SettingShown}


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


def _derived_slots(name: str, arg: Any) -> Iterator[str]:
    """The value slots a derived placeholder object renders from, nested ones included."""
    if name == "$format":
        parts = list(arg[1:])
    elif name == "$jsontext":
        parts = [arg]
    elif name == "$or":
        parts = [arg[0]]
    else:  # $each: the list slot and the item template
        parts = [arg[0], arg[1]]
    for part in parts:
        for inner, inner_arg in _slots(part):
            if inner_arg is None:
                yield inner
            else:
                yield from _derived_slots(inner, inner_arg)


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


def _check_setting(ident: str, s: dict[str, Any], settings: dict[str, Any]) -> None:  # noqa: C901
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
    if "meaning" in s:
        meaning = SettingMeaning(s["meaning"])
        assert kind == "bool" or meaning not in BINARY_MEANINGS, ident
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
    if "structured" in s:
        assert s["structured"] is True, ident
        assert kind in {"string", "other", "object"}, ident  # an open value holds the structure
    if kind == "object":
        assert s.get("structured") is True, ident
        assert not {"values", "labels", "default", "min", "max", "unit"} & set(s), ident
        assert s.get("read") is None or s["read"]["map"] is None, ident
    if "advanced" in s:
        assert s["advanced"] is True, ident
        assert s.get("note"), ident  # the app's warning
    # the last note part of an advanced setting is the app's warning, free text
    parts = s["note"].split("; ")[: -1 if "advanced" in s else None] if "note" in s else []
    if s["access"] == "rw":
        assert ("write" in s) != ("write_table" in s), "rw needs exactly one of write/write_table"
        if "write_table" in s:
            assert set(s["write_table"]) == keys
        assert all(p == ROUND_TRIP_NOTE or p in RO_NOTES for p in parts), s["note"]
    else:
        assert present == [], present
        if s.get("note") != STATUS_NOTE:
            assert len([p for p in parts if p not in OBJECT_NOTES | {NOT_SENT_NOTE}]) <= 1
            allowed_notes = RO_NOTES | OBJECT_NOTES | {NOT_SENT_NOTE, ROUND_TRIP_NOTE}
            assert all(p in allowed_notes for p in parts), s["note"]
    templates = [s["write"]] if "write" in s else []
    templates += list(s.get("write_table", {}).values())
    for template in templates:
        for name, arg in _slots(template):
            if arg is None and VALUE_OBJECT_SLOT.fullmatch(name):
                assert kind == "object", (ident, name)
                continue
            if name in DERIVED_SLOTS:
                assert kind == "object", (ident, name)
                inner = list(_derived_slots(name, arg))
                assert inner, (ident, name)
                assert all(VALUE_OBJECT_SLOT.fullmatch(n) or n in SCALAR_SLOTS for n in inner)
                continue
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
    if s["kind"] == "enum" and "default" in s:
        assert s["default"] in s["values"]  # a select shows its default
    read = s.get("read")
    if read is not None:
        assert {"param", "map"} <= set(read) <= {
            "param", "map", "view", "no_default", "fallback", "members"
        }  # fmt: skip
        for member in (read.get("members") or {}).values():
            assert kind == "object", ident
            assert type(member["param"]) is int, ident
            assert member in (
                {"param": member["param"], "as": "flag"},
                {"param": member["param"], "member": member.get("member")},
            )
            assert member.get("as") == "flag" or isinstance(member["member"], str), ident
        if "no_default" in read:
            assert read["no_default"] is True
            assert s["access"] == "ro"  # a status only the device reports
        if "fallback" in read:
            assert read["fallback"] in s["values"]
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
        assert s["section"] == settings[primary]["section"], ident
        assert "variants" not in s
    for rule in s.get("variants", []):
        _check_variant(ident, rule, settings)
    assert s["section"] in SECTIONS, ident
    assert s["role"] in ROLES, ident
    if s["access"] == "rw":
        assert s["role"] == "setting", ident  # a setting the library writes is a control
    assert s.get("shown", "page") in PLACES, ident
    if s["role"] == "status":
        assert "shown" in s, ident  # a status is one the app shows
    assert ("group" in s) == ("order" in s)
    if "group" in s:
        assert isinstance(s["group"], str)
        assert isinstance(s["order"], int)


def _check_variant(primary: str, rule: dict[str, Any], settings: dict[str, Any]) -> None:
    assert set(rule) == {"id", "key", "read_conditions"}
    assert rule["id"].startswith(primary + "__v"), rule["id"]
    key = rule["key"]
    assert key is None or key == primary or settings[key].get("variant_of") == primary
    assert rule["read_conditions"], "a variant without read conditions never competes"
    for group in rule["read_conditions"]:
        for cond in group:
            assert CONDITION_KEYS <= set(cond) <= CONDITION_KEYS | ASSOCIATED_KEYS, cond
            assert all(isinstance(cond[k], str) for k in CONDITION_KEYS)
            if cond["type"] not in ("associated_field", "parent_associated_field"):
                assert not set(cond) & ASSOCIATED_KEYS, cond
            if "prop" in cond:
                assert isinstance(cond["default"], str)
            assert isinstance(cond.get("param", 0), int)
            assert all(isinstance(v, str) for v in cond.get("map", {}).values())


@pytest.mark.parametrize("code", CODES)
def test_model_file_matches_the_schema(code: str) -> None:
    path = MODELS / f"{code}.json"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    doc = json.loads(text, object_pairs_hook=dict)
    optional = {"battery", "sd_status_groups"}
    assert set(doc) - optional == {"schema_version", "product_code", "source", "settings"}
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
            assert "section" not in item["entry"]  # one section in every context
            assert "role" not in item["entry"]  # one role in every context
            assert "shown" not in item["entry"]  # one place in every context
            named.update(item["names"])
    for context in sorted(named):
        resolved = {k: _in_context(v, context) for k, v in settings.items()}
        for ident, setting in resolved.items():
            _check_setting(ident, setting, resolved)
    if "battery" in doc:
        _check_battery(doc["battery"], settings)
    if "sd_status_groups" in doc:
        _check_sd_status_groups(doc["sd_status_groups"])
    assert text == codec.dump(doc)
    assert [s for s in _strings(doc) if SERIAL.search(s)] == []


def _check_sd_status_groups(groups: Any) -> None:
    """A default group and the int32 statuses whose group differs from it (at least one),
    what the table is read from, and the parameter the handler groups in place of the
    answer's status, if any (only on a table read from the answer)."""
    assert set(groups) - {"param"} == {"default", "codes", "from"}
    assert groups["from"] in {"answer", "status_property"}
    assert "param" not in groups or groups["from"] == "answer"
    assert type(groups["default"]) is int
    assert groups["codes"]
    for code, group in groups["codes"].items():
        assert str(int(code)) == code
        assert -(2**31) <= int(code) < 2**31
        assert type(group) is int
        assert group != groups["default"]
    if "param" in groups:
        assert type(groups["param"]) is int
        assert 1000 <= groups["param"] < 65536


def _check_battery(battery: Any, settings: dict[str, Any]) -> None:
    """A non-empty list of distinct parameters, each with the levels of raw values 0-255
    that read as another level (0-100) or as none, for a model with a battery."""
    assert "battery_value" in settings
    assert isinstance(battery, list)
    assert battery
    assert len({r["param"] for r in battery}) == len(battery)
    for read in battery:
        assert set(read) <= {"param", "levels"}
        assert type(read["param"]) is int
        assert 1000 <= read["param"] < 65536
        levels = read.get("levels")
        if levels is None:
            continue
        assert levels
        for raw, level in levels.items():
            assert raw.isdigit()
            assert int(raw) <= 255
            assert str(int(raw)) == raw
            assert level is None or (type(level) is int and 0 <= level <= 100 and level != int(raw))


def test_models_holds_exactly_the_indexed_codes() -> None:
    assert len(CODES) == 166
    assert sorted(set(CODES)) == CODES
    assert (INDEX["schema_version"], (MODELS / "INDEX.json").read_text("utf-8")) == (
        3,
        codec.dump(INDEX),
    )
    names = {p.name for p in MODELS.iterdir() if p.is_file()}
    assert names == {f"{c}.json" for c in CODES} | {
        "INDEX.json",
        "__init__.py",
    }
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
