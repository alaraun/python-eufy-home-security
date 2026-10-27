from __future__ import annotations

from types import MappingProxyType

import pytest

from eufy_home_security.devices.capabilities import (
    FALLBACK_PROFILES,
    KIND_MARKERS,
    PROFILES,
    PTZ_ACTION_NEEDS,
    PTZ_ACTIONS,
    VIDEO_SMART_LOCK_CATEGORY,
    Capability,
    DeviceProfile,
    _build_with_ring,
    kind_from_params,
    profile_for_serial,
    ring_evidence,
)
from eufy_home_security.devices.ptz import PTZ_IDENTIFIERS
from eufy_home_security.devices.recipes import PtzAction
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
    Capability.DOORBELL_RING: "Cloud push (FCM)",  # a press arrives as a cloud push
}
# The hardware-verification row that traces each pan/tilt preset action.
LOG_AREA_PTZ_ACTION: dict[PtzAction, str] = {
    PtzAction.STORE: "T8170 preset store and delete (6032, 6033)",
    PtzAction.DELETE: "T8170 preset store and delete (6032, 6033)",
    PtzAction.SET_DEFAULT: "T8170 default preset (6242) and auto-return",
    PtzAction.SLOT_PICTURE: "T8170 preset picture (6097)",
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
        assert all(e.source for e in profile.ptz_actions.values())


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


def test_the_t8010_profile_grades_only_local_events_unknown() -> None:
    profile = profile_for_serial("T8010P0000000000")
    assert profile is PROFILES["T8010"]
    assert set(profile.capabilities) == {Capability.LOCAL_EVENTS}
    evidence = profile.capabilities[Capability.LOCAL_EVENTS]
    assert evidence.support is Support.UNKNOWN
    assert "cloud push" in evidence.note
    assert not profile.params
    assert not profile.kind_markers


def test_declared_model_without_profile_gets_fallback() -> None:
    profile = profile_for_serial("T8002P0000000000")
    assert profile is FALLBACK_PROFILES[DeviceKind.STATION]
    assert not profile.params


def test_the_t8161_profile_mirrors_the_t8160s_declared() -> None:
    profile = profile_for_serial("T8161P0000000000")
    assert profile is PROFILES["T8161"]
    assert set(profile.capabilities) == set(PROFILES["T8160"].capabilities)
    assert profile.params == PROFILES["T8160"].params
    assert {
        cap for cap, e in profile.capabilities.items() if e.support is not Support.DECLARED
    } == {Capability.LOCAL_EVENTS}
    assert profile.support(Capability.LOCAL_EVENTS) is Support.UNKNOWN
    assert "T8161 handler" in profile.capabilities[Capability.LIVE_STREAM].source
    assert not profile.kind_markers


def test_the_t8410_profile_is_live_and_pan_tilt_without_presets_or_zoom() -> None:
    profile = profile_for_serial("T8410P0000000000")
    assert profile is PROFILES["T8410"]
    assert {cap: e.support for cap, e in profile.capabilities.items()} == {
        Capability.LIVE_KEYFRAME: Support.DECLARED,
        Capability.LIVE_STREAM: Support.DECLARED,
        Capability.PTZ_CONTROL: Support.DECLARED,
    }
    assert profile.support(Capability.PTZ_PRESETS) is Support.UNKNOWN
    assert profile.support(Capability.PTZ_ZOOM) is Support.UNKNOWN
    for evidence in profile.capabilities.values():
        assert "T8410 handler" in evidence.source
        assert "RSA session variant" in evidence.note


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


def test_every_verified_ptz_action_is_in_the_verification_log() -> None:
    assert set(LOG_AREA_PTZ_ACTION) == set(PtzAction)
    rows = log_rows()
    verified = [
        (model, action)
        for model, profile in PROFILES.items()
        for action, evidence in profile.ptz_actions.items()
        if evidence.support is Support.VERIFIED
    ]
    assert verified
    for model, action in verified:
        assert rows[LOG_AREA_PTZ_ACTION[action]][0] == VERIFIED_MARK, (model, action)
        assert model in LOG_AREA_PTZ_ACTION[action]


def test_every_ptz_action_needs_presets() -> None:
    assert set(PTZ_ACTION_NEEDS) == set(PtzAction)
    for needs in PTZ_ACTION_NEEDS.values():
        assert Capability.PTZ_PRESETS in needs
        assert set(needs) <= set(PTZ_ACTIONS)


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


@pytest.mark.parametrize(
    ("serial", "support"),
    [
        ("T8113P2000067890", Support.DECLARED),  # behind a HomeBase: the station open
        ("T8400P2000067890", Support.DECLARED),  # standalone: 1700 without extValue
        ("T8170P0000054321", Support.VERIFIED),  # its profile's grade stands
        ("T8172P2000067890", Support.DECLARED),  # two lenses: the multi-camera open
        ("T8530P2000067890", Support.UNKNOWN),  # an open not implemented
        ("T8030P0000054321", Support.UNKNOWN),  # a station has no live open
    ],
)
def test_live_video_is_declared_where_the_library_sends_the_handlers_open(
    serial: str, support: Support
) -> None:
    profile = profile_for_serial(serial)
    assert profile is not None
    for capability in (Capability.LIVE_STREAM, Capability.LIVE_KEYFRAME):
        assert profile.support(capability) is support
    if serial.startswith(("T8113", "T8400")):
        evidence = profile.capabilities[Capability.LIVE_STREAM]
        assert "open_live_stream" in evidence.source
        assert "Station.live_support" in evidence.note
    assert profile_for_serial(serial) is profile


def test_a_t8224_lists_live_video_behind_a_homebase_3_outside_the_webrtc_window() -> None:
    profile = profile_for_serial("T8224P2000067890")
    assert profile is not None
    where = profile.capabilities[Capability.LIVE_STREAM].source.split(" under ")[1]
    assert "HB3" in where.split(" (")[0].split(", ")


def test_the_generic_profile_itself_claims_no_live_video() -> None:
    assert FALLBACK_PROFILES[DeviceKind.CAMERA].support(Capability.LIVE_STREAM) is Support.UNKNOWN


@pytest.mark.parametrize(
    ("serial", "control", "presets", "zoom"),
    [
        # the handler declares and builds every action: all three, from the generic profile
        ("T8425P2000067890", Support.DECLARED, Support.DECLARED, Support.DECLARED),
        # no set_picture_zoom action in its thing description
        ("T8426P2000067890", Support.DECLARED, Support.DECLARED, Support.UNKNOWN),
        # its pan/tilt step is a 1350 recipe the library does not send
        ("T8423P2000067890", Support.UNKNOWN, Support.DECLARED, Support.UNKNOWN),
        # its profile's own grades stand
        ("T8170P0000054321", Support.VERIFIED, Support.VERIFIED, Support.VERIFIED),
        # no pan/tilt action at all
        ("T8160P2000067890", Support.UNKNOWN, Support.UNKNOWN, Support.UNKNOWN),
    ],
)
def test_pan_tilt_zoom_is_declared_where_the_library_sends_the_handlers_actions(
    serial: str, control: Support, presets: Support, zoom: Support
) -> None:
    profile = profile_for_serial(serial)
    assert profile is not None
    assert profile.support(Capability.PTZ_CONTROL) is control
    assert profile.support(Capability.PTZ_PRESETS) is presets
    assert profile.support(Capability.PTZ_ZOOM) is zoom
    if serial.startswith("T8425"):
        evidence = profile.capabilities[Capability.PTZ_PRESETS]
        assert "query_preset_positions and set_ptz_cruise_preview are" in evidence.source
        assert "HB3" in evidence.source
        assert "Station.ptz_support" in evidence.note
    assert profile_for_serial(serial) is profile


def test_ptz_actions_cover_the_three_capabilities() -> None:
    assert set(PTZ_ACTIONS) == {
        Capability.PTZ_CONTROL,
        Capability.PTZ_PRESETS,
        Capability.PTZ_ZOOM,
    }
    assert set().union(*PTZ_ACTIONS.values()) <= set(PTZ_IDENTIFIERS)


def _catalogued_serial(model: str) -> str:
    return model + "P" + "0" * 10


def test_a_model_rings_when_the_app_files_it_as_a_doorbell_or_a_video_lock() -> None:
    for model in MODELS.values():
        profile = profile_for_serial(_catalogued_serial(model.model))
        assert profile is not None, model.model
        rings = model.kind is DeviceKind.DOORBELL or VIDEO_SMART_LOCK_CATEGORY in model.categories
        expected = Support.DECLARED if rings else Support.UNKNOWN
        assert profile.support(Capability.DOORBELL_RING) is expected, model.model
        assert (ring_evidence(model) is not None) is rings, model.model


def test_a_video_lock_rings_and_a_lock_without_a_camera_does_not() -> None:
    video = [m for m in MODELS.values() if VIDEO_SMART_LOCK_CATEGORY in m.categories]
    plain = [m for m in MODELS.values() if m.kind is DeviceKind.LOCK and m not in video]
    assert video
    assert plain
    for model in video:
        assert model.kind is DeviceKind.LOCK
        evidence = ring_evidence(model)
        assert evidence is not None
        assert evidence.support is Support.DECLARED
        assert VIDEO_SMART_LOCK_CATEGORY in evidence.source
        assert "DOORBELL_PRESS" in evidence.note
    assert all(ring_evidence(m) is None for m in plain)


def test_the_video_locks_ring_and_a_plain_lock_and_a_camera_do_not() -> None:
    assert VIDEO_SMART_LOCK_CATEGORY == "VideoSmartLock"
    for model in ("T8530", "T8531", "T8532", "T853A", "T85M0", "T85M1", "T85M2", "T85V0"):
        profile = profile_for_serial(_catalogued_serial(model))
        assert profile is not None, model
        assert profile.support(Capability.DOORBELL_RING) is Support.DECLARED, model
    for model in ("T8500", "T8160"):
        profile = profile_for_serial(_catalogued_serial(model))
        assert profile is not None, model
        assert profile.support(Capability.DOORBELL_RING) is Support.UNKNOWN, model


def test_generated_grades_follow_the_serials_product_code() -> None:
    # serial rule: a T8420 serial with 6 at index 6 is product T8420X, which streams live
    t8420 = profile_for_serial("T8420P0000000000")
    assert t8420 is not None
    assert t8420.support(Capability.LIVE_STREAM) is Support.UNKNOWN
    profile = profile_for_serial("T8420P6000000000")
    assert profile is not None
    assert profile.support(Capability.LIVE_STREAM) is Support.DECLARED
    assert "T8420X handler" in profile.capabilities[Capability.LIVE_STREAM].source
    t8210c = profile_for_serial("T8210P8000067890")
    assert t8210c is not None
    assert "T8210C handler" in t8210c.capabilities[Capability.LIVE_STREAM].source


def test_a_doorbell_rings_by_its_kind() -> None:
    evidence = ring_evidence(MODELS["T8214"])
    assert evidence is not None
    assert "video doorbell" in evidence.source
    profile = profile_for_serial("T8210P8000067890")  # serial rule: product T8210C
    assert profile is not None
    assert profile.support(Capability.DOORBELL_RING) is Support.DECLARED
    assert profile_for_serial("T8210P8000067890") is profile


def test_a_profiles_own_ring_grade_stands() -> None:
    own = Evidence(Support.VERIFIED, "live")
    profile = DeviceProfile(
        model="T8214",
        capabilities=MappingProxyType({Capability.DOORBELL_RING: own}),
        params=MappingProxyType({}),
    )
    assert _build_with_ring(profile, MODELS["T8214"]) is profile
    generic = FALLBACK_PROFILES[DeviceKind.CAMERA]
    assert _build_with_ring(generic, MODELS["T8160"]) is generic
