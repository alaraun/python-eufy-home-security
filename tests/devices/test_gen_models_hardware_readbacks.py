"""Hardware-verified overrides of generated model readbacks."""

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
    """Load a generator module without importing scripts into mypy's source graph."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen_models = _load("gen_models")

KEY = "sensor_motion_detection_sensitivity_level"
VERIFIED = {
    "param": 1609,
    "map": {"80": 0, "53": 1, "37": 2, "18": 3, "8": 4},
}


def test_t8910_verified_readback_survives_generation() -> None:
    settings: dict[str, dict[str, Any]] = {KEY: {"read": None}, "other": {"read": None}}

    gen_models.apply_hardware_readbacks("T8910", settings)

    assert settings[KEY]["read"] == VERIFIED
    assert settings["other"]["read"] is None

    module_file = gen_models.__file__
    assert module_file is not None
    model = (
        Path(module_file).resolve().parents[1]
        / "src/eufy_home_security/devices/data/models/T8910.json"
    )
    committed = json.loads(model.read_text())
    assert committed["settings"][KEY]["read"] == VERIFIED


def test_verified_readback_does_not_change_other_models() -> None:
    settings = {KEY: {"read": None}}

    gen_models.apply_hardware_readbacks("T8911", settings)

    assert settings[KEY]["read"] is None


def test_verified_readback_rejects_conflicting_generated_codec() -> None:
    settings = {KEY: {"read": {"param": 1609, "map": {"8": 0}}}}

    with pytest.raises(gen_models.CheckError):
        gen_models.apply_hardware_readbacks("T8910", settings)


def test_verified_readback_rejects_missing_setting() -> None:
    with pytest.raises(gen_models.CheckError):
        gen_models.apply_hardware_readbacks("T8910", {})
