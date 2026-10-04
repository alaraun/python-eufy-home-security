from __future__ import annotations

import pytest

from eufy_home_security.devices.capabilities import (
    FALLBACK_PROFILES,
    KIND_MARKERS,
    PROFILES,
    Capability,
    kind_from_params,
    profile_for_serial,
)
from eufy_home_security.devices.support import Evidence, Support
from eufy_home_security.devices.types import MODELS, DeviceKind

from .verification_log import VERIFIED_MARK, log_rows

# The hardware-verification row that traces each capability (settings: per device kind).
LOG_AREA: dict[Capability, str] = {
    Capability.GUARD_MODE_READ: "Parameter dump",
    Capability.GUARD_MODE_WRITE: "Guard mode write",
    Capability.PARAM_DUMP: "Parameter dump",
    Capability.LOCAL_EVENTS: "Local event push (2037)",
    Capability.CLOUD_EVENTS: "Cloud push (FCM)",
    Capability.EVENT_HISTORY: "Event history",
    Capability.SNAPSHOT_FETCH: "Image fetch (1308)",
    Capability.LIVE_KEYFRAME: "Live stream (1003/1004)",
    Capability.LIVE_STREAM: "Live stream (1003/1004)",
    Capability.RECORDING_DOWNLOAD: "Recording playback (1025) and download (1024)",
    Capability.SETTINGS_WRITE: "Settings, {kind}",
    Capability.PTZ_PRESETS: "T8170 presets (query, go to)",
    Capability.PTZ_CONTROL: "T8170 pan/tilt step (6030)",
    Capability.PTZ_ZOOM: "T8170 picture zoom (6203)",
    Capability.BATTERY: "Parameter dump",
    Capability.RSSI: "Parameter dump",
    Capability.PIR_EVENT_TIME: "Motion sensor param 1605",
}
# A model whose settings write was proven in a row of its own.
LOG_AREA_BY_MODEL: dict[tuple[str, Capability], str] = {
    ("T8170", Capability.SETTINGS_WRITE): "Settings, T8170",
}


def test_profiles_belong_to_catalogued_models() -> None:
    for model, profile in PROFILES.items():
        assert profile.model == model
        assert model in MODELS


def test_every_capability_has_a_source() -> None:
    for profile in PROFILES.values():
        assert all(e.source for e in profile.capabilities.values())


def test_profile_for_serial(station_sn: str) -> None:
    station = profile_for_serial(station_sn)
    assert station is PROFILES["T8030"]
    assert station.support(Capability.GUARD_MODE_WRITE) is Support.VERIFIED
    assert station.support(Capability.BATTERY) is Support.UNKNOWN
    camera = profile_for_serial("T8160P0000000000")
    assert camera is PROFILES["T8160"]
    assert camera.params["battery"] == 1101
    assert camera.support(Capability.CLOUD_EVENTS) is Support.DECLARED


def test_motion_sensor_profile_is_declared_from_dumps() -> None:
    profile = profile_for_serial("T8910P0000000000")
    assert profile is PROFILES["T8910"]
    assert MODELS[profile.model].kind is DeviceKind.SENSOR
    assert profile.params["sub1g_rssi"] == 1141
    assert profile.params["pir_event_ms"] == 1605
    # values from a sensor that never changed: nothing is verified without a live change
    assert {e.support for e in profile.capabilities.values()} == {Support.DECLARED}
    assert profile.support(Capability.PIR_EVENT_TIME) is Support.DECLARED


def test_kind_markers_are_merged_per_kind_and_single_valued() -> None:
    assert KIND_MARKERS[DeviceKind.CAMERA] == {1400, 1401}
    assert KIND_MARKERS[DeviceKind.SENSOR] == {1601, 1605, 1609}
    assert FALLBACK_PROFILES[DeviceKind.SENSOR].kind_markers == KIND_MARKERS[DeviceKind.SENSOR]
    assert kind_from_params({1400: "0", 1101: "90"}) is DeviceKind.CAMERA
    assert kind_from_params({1609: "8"}) is DeviceKind.SENSOR
    assert kind_from_params({1101: "90"}) is None  # no marker
    assert kind_from_params({1400: "0", 1605: "1"}) is None  # conflicting markers


def test_declared_model_without_profile_gets_fallback() -> None:
    profile = profile_for_serial("T8161P0000000000")
    assert profile is FALLBACK_PROFILES[DeviceKind.CAMERA]
    assert not profile.params


def test_uncatalogued_serial_has_no_profile() -> None:
    assert profile_for_serial("T9999P0000000000") is None


def test_fallback_profiles_claim_nothing() -> None:
    assert set(FALLBACK_PROFILES) == set(DeviceKind)
    for profile in FALLBACK_PROFILES.values():
        assert all(profile.support(cap) is Support.UNKNOWN for cap in Capability)


def test_every_verified_capability_is_in_the_verification_log() -> None:
    assert set(LOG_AREA) == set(Capability)
    rows = log_rows()
    for model, profile in PROFILES.items():
        for cap, evidence in profile.capabilities.items():
            if evidence.support is not Support.VERIFIED:
                continue
            area = LOG_AREA_BY_MODEL.get((model, cap)) or LOG_AREA[cap].format(
                kind=MODELS[model].kind
            )
            assert area in rows, (model, cap, area)
            assert rows[area][0] == VERIFIED_MARK, (model, cap, area)


def test_profiles_are_read_only() -> None:
    profile = PROFILES["T8030"]
    with pytest.raises(TypeError):
        profile.capabilities[Capability.BATTERY] = Evidence(Support.VERIFIED, "x")  # type: ignore[index]
    with pytest.raises(TypeError):
        PROFILES["T8160"].params["battery"] = 1  # type: ignore[index]


def test_ptz_presets_capabilities() -> None:
    assert PROFILES["T8170"].capabilities[Capability.PTZ_PRESETS].support == Support.VERIFIED
    assert (
        PROFILES["T8160"]
        .capabilities.get(Capability.PTZ_PRESETS, Evidence(Support.UNKNOWN, ""))
        .support
        == Support.UNKNOWN
    )
