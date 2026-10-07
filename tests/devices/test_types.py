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


def test_models_known_only_from_the_cloud_list_are_unknown() -> None:
    # declared is reserved for eufy app sources
    assert MODELS["T8910"].evidence.support is Support.UNKNOWN


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
