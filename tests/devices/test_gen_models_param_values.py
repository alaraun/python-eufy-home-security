"""Synthetic tests for explicit app direct-parameter mappings."""

from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
KEY = "synthetic_motion_level"
PN = "T9ZZ8"
RAW = {"0": 80, "1": 53, "2": 37, "3": 18, "4": 8}


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen_models = _load("gen_models")


def _fixture() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    props = [
        {
            "identifier": KEY,
            "access_mode": "RW",
            "data_type": {
                "type": "ienum",
                "specs": {
                    "eunmList": [{"value": str(i), "associatedValue": 999} for i in range(5)]
                },
            },
        }
    ]
    settings: dict[str, Any] = {
        KEY: {
            "kind": "enum",
            "access": "rw",
            "values": list(range(5)),
            "note": "round trip does not return the written value",
            "write": {
                "cmd": 1609,
                "params": {"value": {"$map": {str(i): (i if i < 3 else 1) for i in range(5)}}},
                "update": {
                    "needUpdate": True,
                    "cmd": 1609,
                    "paramValue": {"$map": {str(i): str(i if i < 3 else 1) for i in range(5)}},
                },
            },
            "read": None,
        }
    }
    titles = {
        "param_values": {
            KEY: {
                "source": "synthetic app direct parameter write",
                "models": {PN: RAW.copy()},
            }
        }
    }
    return settings, props, titles


def test_direct_values_replace_handler_values_and_preserve_command() -> None:
    settings, props, titles = _fixture()
    original = deepcopy(settings[KEY]["write"])
    gen_models.apply_param_values(PN, settings, props, None, titles)
    entry = settings[KEY]

    assert entry["write"]["cmd"] == original["cmd"]
    assert entry["write"]["update"]["needUpdate"] is True
    assert entry["write"]["params"]["value"] == {"$map": RAW}
    assert entry["write"]["update"]["paramValue"] == {
        "$map": {key: str(value) for key, value in RAW.items()}
    }
    assert entry["read"] == {
        "param": 1609,
        "map": {
            **{str(raw): int(public) for public, raw in RAW.items()},
            **{str(i): i for i in range(5)},
        },
    }
    assert "note" not in entry


def test_unlisted_model_keeps_handler_recipe() -> None:
    settings, props, titles = _fixture()
    before = deepcopy(settings)
    gen_models.apply_param_values("T9ZZ9", settings, props, None, titles)
    assert settings == before


@pytest.mark.parametrize(
    "bad",
    [
        {"0": 80, "1": 53, "2": 37, "3": 18},
        {"0": 80, "1": 53, "2": 37, "3": 18, "4": 8, "5": 7},
        {"0": 80, "1": 80, "2": 37, "3": 18, "4": 8},
        {"0": 80, "1": 53, "2": 37, "3": 18, "4": True},
        {"0": 80, "1": 53, "2": 37, "3": 18, "4": "8"},
    ],
)
def test_invalid_direct_value_tables_fail(bad: dict[str, Any]) -> None:
    settings, props, titles = _fixture()
    titles["param_values"][KEY]["models"][PN] = bad
    with pytest.raises(gen_models.CheckError):
        gen_models.apply_param_values(PN, settings, props, None, titles)


def test_rn_screen_rejected() -> None:
    settings, props, titles = _fixture()
    with pytest.raises(gen_models.CheckError, match="RN"):
        gen_models.apply_param_values(
            PN, settings, props, {"settings_ui": gen_models.joiner.RN_SETTINGS}, titles
        )


def test_missing_parameter_value_slot_rejected() -> None:
    settings, props, titles = _fixture()
    del settings[KEY]["write"]["params"]["value"]
    with pytest.raises(gen_models.CheckError, match="value slot"):
        gen_models.apply_param_values(PN, settings, props, None, titles)


def test_missing_update_value_slot_rejected() -> None:
    settings, props, titles = _fixture()
    del settings[KEY]["write"]["update"]["paramValue"]
    with pytest.raises(gen_models.CheckError, match="update value slot"):
        gen_models.apply_param_values(PN, settings, props, None, titles)


def test_unknown_identifier_rejected() -> None:
    _, props, titles = _fixture()
    with pytest.raises(gen_models.CheckError, match="unknown identifier"):
        gen_models.apply_param_values(PN, {}, props, None, titles)
