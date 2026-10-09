from __future__ import annotations

import pytest

from eufy_home_security.devices.support import Support
from eufy_home_security.devices.types import (
    MODELS,
    ON_DEMAND_EVIDENCE,
    DeviceKind,
    connects_on_demand,
    model_for_serial,
    serial_prefix,
)


def test_registry_keys_match_models() -> None:
    assert all(key == model.model for key, model in MODELS.items())


def test_only_live_proven_models_are_verified() -> None:
    verified = {m.model for m in MODELS.values() if m.evidence.support is Support.VERIFIED}
    assert verified == {"T8030", "T8160"}


def test_evidence_has_a_source() -> None:
    assert all(m.evidence.source for m in MODELS.values())


@pytest.mark.parametrize(
    ("serial", "model", "kind"),
    [
        ("T8030P0000000000", "T8030", DeviceKind.STATION),
        ("T8160P0000000000", "T8160", DeviceKind.CAMERA),
        (" t8161p0000000000", "T8161", DeviceKind.CAMERA),
        ("T8410P0000000000", "T8410", DeviceKind.CAMERA),
    ],
)
def test_model_for_serial(serial: str, model: str, kind: DeviceKind) -> None:
    found = model_for_serial(serial)
    assert found is not None
    assert (found.model, found.kind) == (model, kind)


@pytest.mark.parametrize("serial", ["", "T80", "T9999P0000000000"])
def test_model_for_serial_unknown(serial: str) -> None:
    assert model_for_serial(serial) is None


@pytest.mark.parametrize(
    ("serial", "prefix"),
    [(" t8160p0000000000", "T8160"), ("T9999P0000000000", "T9999"), ("T80", None), ("", None)],
)
def test_serial_prefix(serial: str, prefix: str | None) -> None:
    assert serial_prefix(serial) == prefix


def test_model_for_serial_fixture(station_sn: str) -> None:
    found = model_for_serial(station_sn)
    assert found is not None
    assert found.model == "T8030"


def test_cloud_device_type_homebase3() -> None:
    assert MODELS["T8030"].cloud_device_type == 18


@pytest.mark.parametrize("model", ["T8001", "T8002", "T8010", "T8020"])
def test_the_first_homebases_share_device_type_0(model: str) -> None:
    assert MODELS[model].cloud_device_type == 0


def test_every_model_but_the_live_proven_is_declared_from_the_app() -> None:
    graded = {m.evidence.support for m in MODELS.values() if m.model not in {"T8030", "T8160"}}
    assert graded == {Support.DECLARED}
    declared = [m for m in MODELS.values() if m.evidence.support is Support.DECLARED]
    assert all("eufy app" in m.evidence.source for m in declared)


@pytest.mark.parametrize(
    ("model", "kind", "device_type", "name"),
    [
        ("T8113", DeviceKind.CAMERA, 8, "Camera 2C"),
        ("T8142", DeviceKind.CAMERA, 15, "Camera 2C Pro"),
        ("T8123", DeviceKind.CAMERA, 61, "Battery Solo Cam Spotlight 2K"),
        ("T8960", DeviceKind.KEYPAD, 11, "Keypad"),
        ("T8200", DeviceKind.DOORBELL, 5, "Doorbell 2K"),
        ("T8500", DeviceKind.LOCK, 52, "BLE Lock No Finger"),
        ("T90R0", DeviceKind.SENSOR, None, "Siren Sensor T90R0"),
        ("T87B0", DeviceKind.OTHER, None, "Tracker 87B0"),
    ],
)
def test_the_apps_models_are_catalogued(
    model: str, kind: DeviceKind, device_type: int | None, name: str
) -> None:
    found = MODELS[model]
    assert (found.kind, found.cloud_device_type, found.name) == (kind, device_type, name)
    assert found.evidence.support is Support.DECLARED
    assert found.evidence.source.startswith("eufy app 6.1.10 model list: ")


def test_a_prefix_the_app_names_as_two_kinds_is_not_catalogued() -> None:
    assert "T8215" not in MODELS  # a battery doorbell and a battery SoloCam constant


def test_a_hand_written_entry_wins_over_the_generated_one() -> None:
    assert MODELS["T8030"].name == "HomeBase 3 (S380)"
    assert MODELS["T8910"].evidence.source.endswith("MOTION_SENSOR; eufy app device-type map (10)")


def test_connects_on_demand_on_demand_prefixes() -> None:
    assert connects_on_demand("T8170P0000000000") is True
    assert connects_on_demand(" t8170p0000000000") is True
    assert connects_on_demand("T8030P0000000000") is False
    assert connects_on_demand("T8160P0000000000") is False
    assert connects_on_demand("T817") is False


def test_t8170_in_models() -> None:
    assert "T8170" in MODELS
    model = MODELS["T8170"]
    assert model.kind == DeviceKind.CAMERA
    assert model.cloud_device_type == 48
    assert model.evidence.support is Support.DECLARED
    assert ON_DEMAND_EVIDENCE.support is Support.DECLARED


def test_the_t8410_is_the_apps_pan_tilt_indoor_cam_of_type_31() -> None:
    found = model_for_serial("T8410P0000000000")
    assert found is not None
    assert found.name == "Indoor Cam 2K Pan & Tilt (Solo IndoorCam P24)"
    assert found.cloud_device_type == 31
    assert found.evidence.support is Support.DECLARED
    assert "INDOOR_CAMERA_PT" in found.evidence.source
    assert not connects_on_demand("T8410P0000000000")
