"""Hardware-verified overrides of generated model readbacks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import gen_models

KEY = "sensor_motion_detection_sensitivity_level"
VERIFIED = {
    "param": 1609,
    "map": {"80": 0, "53": 1, "37": 2, "18": 3, "8": 4},
}


def test_t8910_verified_readback_survives_generation() -> None:
    settings = {KEY: {"read": None}, "other": {"read": None}}

    gen_models.apply_hardware_readbacks("T8910", settings)

    assert settings[KEY]["read"] == VERIFIED
    assert settings["other"]["read"] is None

    model = (
        Path(gen_models.__file__).resolve().parents[1]
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
