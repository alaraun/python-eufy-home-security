"""The control-shaping transforms of the settings generator (scripts/gen_models_controls.py)."""

from __future__ import annotations

import importlib.util
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
controls = _load("gen_models_controls")


def _bit_switch() -> dict[str, Any]:
    return {
        "access": "rw",
        "kind": "bool",
        "note": "round trip does not return the written value",
        "read": None,
        "write": {
            "cmd": 1350,
            "subCmd": 1283,
            "params": {"arm_push_mode": {"$map": {"false": 0, "true": 256}}},
            "update": {
                "needUpdate": True,
                "cmd": 1283,
                "paramValue": {"$map": {"false": "0", "true": "256"}},
            },
        },
    }


def test_a_read_modify_write_bool_becomes_a_bit_switch() -> None:
    settings = {"notification_ignore_switch": _bit_switch()}
    cands = controls.bit_candidates(settings)
    assert cands == {"notification_ignore_switch": (256, 1283)}
    other = controls._OTHER_BITS & ~256
    replies = {
        ("notification_ignore_switch", True): {"params": {"arm_push_mode": other | 256}},
        ("notification_ignore_switch", False): {"params": {"arm_push_mode": other}},
    }
    counts: dict[str, int] = {}
    controls.apply_bits(settings, cands, replies, counts)
    entry = settings["notification_ignore_switch"]
    assert entry["bit"] == 256
    assert entry["read"] == {"param": 1283, "map": None}
    assert entry["write"]["params"] == {"arm_push_mode": "$v:int"}
    assert entry["write"]["update"]["paramValue"] == "$v:str"
    assert "note" not in entry
    assert counts == {"bit": 1}


def test_a_bool_the_handler_writes_blind_stays_a_plain_switch() -> None:
    settings = {"k": _bit_switch()}
    cands = controls.bit_candidates(settings)
    replies = {
        ("k", True): {"params": {"arm_push_mode": 256}},
        ("k", False): {"params": {"arm_push_mode": 0}},
    }
    counts: dict[str, int] = {}
    controls.apply_bits(settings, cands, replies, counts)
    assert "bit" not in settings["k"]
    assert counts == {"bit:handler writes blind": 1}


def _detection() -> dict[str, Any]:
    return {
        "access": "rw",
        "kind": "enum",
        "values": [1, 2, 3],
        "labels": {"1": "Human", "2": "Vehicle", "3": "Pet"},
        "read": {"param": 1298, "map": {"3": 1, "4": 2, "8": 3}},
        "write": {
            "cmd": 1350,
            "subCmd": 1298,
            "params": {"ai_detect_type": {"$map": {"1": 3, "2": 4, "3": 8}}, "channel": "$channel"},
        },
    }


def _replies(
    ident: str, bits: dict[str, int], *, joined_or: bool = True
) -> tuple[dict[str, list[tuple[Any, Any]]], dict[tuple[str, str], Any]]:
    singles = {
        ident: [(int(k), {"params": {"ai_detect_type": b, "channel": 3}}) for k, b in bits.items()]
    }
    joined = {}
    for payload in controls.flag_payloads([int(k) for k in bits]):
        mask = 0
        for part in payload.split(","):
            mask = (mask | bits[part]) if joined_or else bits[part]
        joined[(ident, payload)] = {"params": {"ai_detect_type": mask, "channel": 3}}
    return singles, joined


def test_an_enum_the_handler_ors_becomes_flags() -> None:
    settings = {"detection_type_set": _detection()}
    cands = controls.flag_candidates(settings, gates=set())
    singles, joined = _replies("detection_type_set", {"1": 3, "2": 4, "3": 8})
    counts: dict[str, int] = {}
    controls.apply_flags(settings, cands, singles, joined, counts)
    entry = settings["detection_type_set"]
    assert entry["kind"] == "flags"
    assert entry["flags"] == {"1": 3, "2": 4, "3": 8}
    assert entry["read"] == {"param": 1298, "map": None}
    assert entry["write"]["params"]["ai_detect_type"] == "$v:int"
    assert "values" not in entry
    assert counts == {"flags": 1}


def test_an_enum_the_handler_does_not_or_stays_an_enum() -> None:
    settings = {"k": _detection()}
    singles, joined = _replies("k", {"1": 3, "2": 4, "3": 8}, joined_or=False)
    controls.apply_flags(settings, controls.flag_candidates(settings, set()), singles, joined, {})
    assert settings["k"]["kind"] == "enum"


def test_a_gating_enum_is_never_flags() -> None:
    settings = {"power_manager_mode": _detection()}
    assert controls.flag_candidates(settings, gates={"power_manager_mode"}) == {}


def test_a_numbered_enum_becomes_a_range_that_writes_the_same() -> None:
    entry: dict[str, Any] = {
        "access": "rw",
        "kind": "enum",
        "values": [0, 1, 2, 3, 4],
        "default": 2,
        "labels": {str(i): str(i + 1) for i in range(5)},
        "read": {"param": 6015, "map": {str(i + 1): i for i in range(5)}},
        "write": {
            "cmd": 1700,
            "subCmd": 6015,
            "params": {"value": {"$map": {str(i): i + 1 for i in range(5)}}},
        },
    }
    settings = {"ptz_turn_speed": entry}
    counts: dict[str, int] = {}
    controls.apply_scales(settings, gates=set(), counts=counts)
    new = settings["ptz_turn_speed"]
    assert (new["kind"], new["min"], new["max"], new["step"], new["default"]) == (
        "range",
        1,
        5,
        1,
        3,
    )
    assert new["read"] == {"param": 6015, "map": None}
    assert new["write"]["params"] == {"value": "$v"}
    assert counts == {"scale": 1}


def test_a_numbered_enum_whose_labels_skip_stays_an_enum() -> None:
    entry = {**_detection(), "labels": {"1": "1", "2": "3", "3": "4"}}
    settings = {"k": entry}
    controls.apply_scales(settings, gates=set(), counts={})
    assert settings["k"]["kind"] == "enum"


def test_a_same_write_alias_is_a_variant_and_lends_its_read() -> None:
    write = {
        "cmd": 1700,
        "subCmd": 6070,
        "params": {"value": "$v"},
        "update": {"needUpdate": True, "cmd": 6070, "paramValue": "$v:str"},
    }
    base = {
        "access": "rw",
        "kind": "range",
        "min": 1,
        "max": 7,
        "read": None,
        "write": write,
        "note": "round trip does not return the written value",
    }
    alias = {**base, "read": {"param": 6070, "map": None}}
    alias.pop("note")
    settings = {"detection_sensitivity": base, "detection_sensitivity_test_mode": alias}
    controls.apply_duplicate_variants(settings, {})
    assert settings["detection_sensitivity_test_mode"]["variant_of"] == "detection_sensitivity"
    assert settings["detection_sensitivity"]["read"] == {"param": 6070, "map": None}
    assert "note" not in settings["detection_sensitivity"]


def _rw(write: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"access": "rw", "kind": "range", "min": 1, "max": 7, "write": write, **extra}


_W6070 = {"cmd": 1700, "subCmd": 6070, "params": {"value": "$v"}}


def test_a_same_codec_variant_is_dropped_and_its_key_resolves_to_the_primary() -> None:
    settings = {
        "detection_sensitivity": _rw(_W6070, page="P", group="A", order=1),
        "detection_sensitivity_test_mode": _rw(_W6070, variant_of="detection_sensitivity"),
    }
    counts: dict[str, int] = {}
    controls.drop_same_codec_variants(settings, counts)
    assert list(settings) == ["detection_sensitivity"]
    assert counts == {"dropped:same codec variant": 1}
    key = "detection_sensitivity_test_mode"
    assert controls.absorbed_by(key, settings) == "detection_sensitivity"


@pytest.mark.parametrize(
    ("variant", "note"),
    [
        (_rw(_W6070, max=5), "a different domain"),
        (_rw({**_W6070, "subCmd": 6071}), "a different write"),
        (_rw(_W6070, labels={"1": "Low"}), "different labels"),
        (_rw(_W6070, page="Other"), "a placement the primary lacks"),
        ({**_rw(_W6070), "access": "ro"}, "not rw"),
    ],
)
def test_a_variant_that_differs_is_kept(variant: dict[str, Any], note: str) -> None:
    settings = {"k": _rw(_W6070), "k__v1": {**variant, "variant_of": "k"}}
    controls.drop_same_codec_variants(settings, {})
    assert "k__v1" in settings, note


def test_a_variant_whose_key_does_not_extend_its_primary_is_kept() -> None:
    settings = {"nightvision_type_new": _rw(_W6070), "nightvision_type": _rw(_W6070)}
    settings["nightvision_type"]["variant_of"] = "nightvision_type_new"
    controls.drop_same_codec_variants(settings, {})
    assert "nightvision_type" in settings


def test_a_variant_a_gate_names_is_kept() -> None:
    settings = {
        "k": _rw(_W6070),
        "k__v1": _rw(_W6070, variant_of="k"),
        "other": {"access": "ro", "kind": "bool", "applies_when": ["k__v1", 1]},
    }
    controls.drop_same_codec_variants(settings, {})
    assert "k__v1" in settings


def test_controls_follow_the_kind_and_the_range_size() -> None:
    assert controls.control_of({"kind": "bool"}) == "switch"
    assert controls.control_of({"kind": "flags"}) == "toggles"
    assert controls.control_of({"kind": "range", "min": 1, "max": 100, "step": 1}) == "slider"
    assert controls.control_of({"kind": "range", "min": 0, "max": 86399, "step": 1}) == "box"
    assert controls.control_of({"kind": "other"}) is None
    assert controls.control_of({"kind": "string"}) == "text"
    assert controls.control_of({"kind": "string", "domain": "timezone"}) == "select"


def test_a_time_zone_write_gets_the_timezone_domain() -> None:
    zone = {"cmd": 1215, "params": {"value": "$v"}}
    settings = {
        "timezone_set": {"kind": "string", "access": "rw", "write": zone},
        "smart_lock_set_timezone": {
            "kind": "string",
            "access": "rw",
            "write": {"cmd": 1350, "subCmd": 1931, "params": "$v"},
        },
        "ro_zone": {"kind": "string", "access": "ro", "write": zone},
        "device_name": {"kind": "string", "access": "rw", "write": {"cmd": 1217}},
    }
    counts: dict[str, int] = {}
    controls.apply_domains(settings, counts)
    assert {k for k, v in settings.items() if "domain" in v} == {"timezone_set"}
    assert settings["timezone_set"]["domain"] == "timezone"
    assert counts == {"domain:timezone": 1}
