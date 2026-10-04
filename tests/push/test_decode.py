"""decode_push: FCM data message → SecurityEvent."""

from __future__ import annotations

import base64
import dataclasses
import json
from typing import Any

import pytest

from eufy_home_security.events import (
    AlarmPhase,
    ArmingSource,
    EventDeduplicator,
    EventScope,
    EventSource,
    SecurityEvent,
)
from eufy_home_security.models import FrameCipher
from eufy_home_security.p2p.notify import decode_camera_push
from eufy_home_security.push.decode import SERVER_PUSH_MIN_TYPE, decode_push, is_security_push
from eufy_home_security.testing import SYNTHETIC


def _message(payload: dict[str, Any], **outer: str) -> dict[str, Any]:
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return {"payload": encoded, "app_tab": "eufy_security", **outer}


def test_guard_mode_is_lifted_from_arming() -> None:
    event = decode_push(
        _message(
            {"arming": 1, "mode": 1, "msg_type": 9, "name": "HomeBase"},
            type="30",
            station_sn=SYNTHETIC.station_sn,
            event_time="1789213725",
        )
    )
    assert event.source is EventSource.CLOUD
    assert event.guard_mode == 1
    assert event.station_sn == SYNTHETIC.station_sn
    assert event.msg_type == 9


@pytest.mark.parametrize(
    "message",
    [
        _message({"msg_type": 18, "event_type": 3102}, type="30"),  # lifted fields
        _message({}, type=str(SERVER_PUSH_MIN_TYPE)),  # raw-only server push
        _message({}, type="30") | {"payload": "not base64"},  # undecodable
    ],
)
def test_cloud_events_are_not_p2p_frames_and_are_authenticated(message: dict[str, Any]) -> None:
    event = decode_push(message)
    assert event.frame_cipher is None
    assert event.authenticated  # TLS from eufy's servers


def test_camera_detection_fields() -> None:
    event = decode_push(
        _message(
            {
                "msg_type": 18,
                "event_type": 3102,
                "name": "Front",
                "channel": 1,
                "pic_url": "https://example/x.jpg",
            },
            type="19",
            station_sn=SYNTHETIC.station_sn,
            device_sn=SYNTHETIC.camera_sn,
            event_time="1789130460170",
        )
    )
    assert event.device_sn == SYNTHETIC.camera_sn
    assert event.channel == 1
    assert event.event_type == 3102
    assert event.device_name == "Front"
    assert event.pic_url == "https://example/x.jpg"
    assert event.event_time_ms == 1789130460170  # ms passes through unscaled


def test_short_keys_decode_to_the_same_event() -> None:
    event = decode_push(
        _message(
            {"a": 9, "s": SYNTHETIC.camera_sn, "c": 1, "n": "Front", "t": 1789130460, "f": "Alice"}
        )
    )
    assert event.msg_type == 9
    assert event.device_sn == SYNTHETIC.camera_sn
    assert event.channel == 1
    assert event.device_name == "Front"
    assert event.person_name == "Alice"
    # `t` is SECONDS on the short form — normalised to ms on the way in.
    assert event.event_time_ms == 1789130460000


def test_url_safe_alphabet_and_trailing_nul_tolerated() -> None:
    payload = json.dumps({"arming": 0, "mode": 63}).encode() + b"\x00\x00"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    event = decode_push({"payload": encoded, "type": "30"})
    assert event.guard_mode == 0


@pytest.mark.parametrize("payload", ["", "not base64!!", base64.b64encode(b"{nope").decode()])
def test_undecodable_payload_never_raises(payload: str) -> None:
    event = decode_push({"payload": payload, "type": "19", "station_sn": "T8030X"})
    assert event.station_sn == "T8030X"
    assert event.guard_mode is None


def test_push_id_is_the_span_id_and_the_dedupe_key_is_second_granular() -> None:
    event = decode_push(_message({"arming": 1}, span_id="abc123"))
    assert event.push_id == "abc123"
    assert event.dedupe_key is None  # no device
    detection = decode_push(
        _message({"s": SYNTHETIC.camera_sn, "event_type": 3102}, event_time="1700000000")
    )
    assert detection.event_time_ms == 1_700_000_000_000
    assert detection.dedupe_key == f"{SYNTHETIC.camera_sn}:1700000000:3102"


def test_the_event_time_is_the_inner_time_the_p2p_copy_carries() -> None:
    # On hardware the outer event_time of a detection is the inner create_time
    # + 2979-3313 ms, so a key from the outer time lands a second after the P2P copy's.
    created_ms = 1_789_223_110_416
    inner = {
        "msg_type": 18,
        "event_type": 3102,
        "device_sn": SYNTHETIC.camera_sn,
        "create_time": created_ms,
        "trigger_time": created_ms,
        "unique_id": "0123456789abcdef0123456789abcdef",
        "record_id": 2026091600049,
    }
    outer = str(created_ms + 3_000)
    cloud = decode_push(_message(inner, event_time=outer), now_ms=lambda: NOW_MS)
    local = decode_camera_push(
        {"cmd": 2037, "payload": json.dumps(inner)},
        station_sn=SYNTHETIC.station_sn,
        now_ms=lambda: NOW_MS,
    )
    assert local is not None
    assert cloud.event_time_ms == local.event_time_ms == created_ms
    assert cloud.dedupe_key == local.dedupe_key == "unique:0123456789abcdef0123456789abcdef"
    assert cloud.record_id == 2026091600049
    del inner["unique_id"]
    without_id = decode_push(_message(inner, event_time=outer), now_ms=lambda: NOW_MS)
    assert without_id.dedupe_key == f"{SYNTHETIC.camera_sn}:{created_ms // 1000}:3102"
    no_inner_time = decode_push(_message({"msg_type": 18}, event_time=outer))
    assert no_inner_time.event_time_ms == created_ms + 3_000


def test_video_path_from_file_path() -> None:
    event = decode_push(_message({"msg_type": 1, "file_path": "/zx/Camera00/clip.zxvideo"}))
    assert event.video_path == "/zx/Camera00/clip.zxvideo"
    bad = decode_push(_message({"msg_type": 1, "file_path": "/Camera00/clip.mp4"}))
    assert bad.video_path is None
    assert bad.rejected_fields == {"video_path"}


def test_channel_zero_is_kept_not_treated_as_falsy() -> None:
    event = decode_push(_message({"c": 0, "s": SYNTHETIC.camera_sn}))
    assert event.channel == 0


@pytest.mark.parametrize(
    ("app_tab", "expected"),
    [("eufy_security", True), (None, True), ("", True), ("eufy_home", False)],
)
def test_is_security_push_checks_app_tab(app_tab: str | None, expected: bool) -> None:
    data = {"payload": ""} if app_tab is None else {"payload": "", "app_tab": app_tab}
    assert is_security_push(data) is expected


def test_server_push_is_raw_only() -> None:
    msg = _message(
        {"arming": 1, "name": "HomeBase"},
        type=str(SERVER_PUSH_MIN_TYPE),
        station_sn=SYNTHETIC.station_sn,
        span_id="srv1",
    )
    event = decode_push(msg)
    assert event.push_id == "srv1"
    assert (event.guard_mode, event.station_sn, event.device_name) == (None, None, None)
    assert event.raw == msg


@pytest.mark.parametrize(
    ("event_time", "expected"),
    [
        ("1789130460", 1789130460000),  # outer seconds are scaled
        ("1789130460.5", 1789130460500),
        (1789130460.0, 1789130460000),
        ("1789130460170", 1789130460170),
        ("0", None),
        ("-5", None),
        ("nan", None),
        ("soon", None),
    ],
)
def test_event_time_parsing(event_time: object, expected: int | None) -> None:
    msg: dict[str, Any] = _message({"msg_type": 1})
    msg["event_time"] = event_time
    assert decode_push(msg).event_time_ms == expected


def test_name_fallbacks() -> None:
    event = decode_push(_message({"device_name": "Garage", "nick_name": "Bob"}))
    assert event.device_name == "Garage"
    assert event.person_name == "Bob"


NOW_MS = 1_789_223_130_000


def test_second_times_are_checked_after_the_ms_conversion() -> None:
    msg = _message({"msg_type": 18}, event_time="1700000000")
    event = decode_push(msg, now_ms=lambda: NOW_MS)
    assert event.event_time_ms == 1_700_000_000_000
    assert event.rejected_fields == frozenset()


def test_a_future_time_is_rejected_and_takes_the_guard_mode_with_it() -> None:
    ahead = str(NOW_MS // 1000 + 3600)
    msg = _message({"msg_type": 9, "arming": 1}, event_time=ahead)
    event = decode_push(msg, now_ms=lambda: NOW_MS)
    assert (event.event_time_ms, event.guard_mode) == (None, None)
    assert event.rejected_fields == {"event_time_ms", "guard_mode"}


def test_arming_push_fields() -> None:
    """An arming payload mixing short and long keys, as the cloud sends it."""
    event = decode_push(
        _message(
            {
                "a": 9,
                "s": SYNTHETIC.station_sn,
                "n": "Base",
                "t": "1789223120",
                "arming": 1,
                "mode": 1,
                "alarm": 0,
                "alarm_delay": 0,
                "user": 2,
                "user_name": "someone",
            },
            type="43",
        ),
        now_ms=lambda: NOW_MS,
    )
    assert event.scope is EventScope.STATION
    assert (event.guard_mode, event.mode, event.alarm_delay) == (1, 1, 0)
    assert (event.arming_user, event.user_name) == (2, "someone")
    assert event.arming_source is ArmingSource.APP
    assert event.alarm_phase is None
    assert event.event_time_ms == 1_789_223_120_000


def test_alarm_type_is_the_inner_type_never_the_device_type() -> None:
    event = decode_push(_message({"msg_type": 10, "type": 16}, type="43"))
    assert event.alarm_type == 16
    assert event.alarm_phase is AlarmPhase.STOPPED  # a cloud push is authenticated
    no_inner = decode_push(_message({"msg_type": 10}, type="16"))
    assert no_inner.alarm_type is None
    assert no_inner.alarm_phase is AlarmPhase.TRIGGERED


_SHARED_FIELDS = (
    "device_sn",
    "channel",
    "device_name",
    "msg_type",
    "event_type",
    "event_time_ms",
    "person_name",
    "push_count",
    "alarm_type",
    "alarm_delay",
    "mode",
    "arming_user",
    "user_name",
    "unique_id",
    "record_id",
    "video_path",
    "rejected_fields",
    "scope",
    "alarm_phase",
    "arming_source",
)


@pytest.mark.parametrize(
    "inner",
    [
        {"msg_type": 10, "type": 16},
        {"msg_type": 10, "type": 3},
        {"msg_type": 16, "alarm_delay": 30},
        {"msg_type": 9, "arming": 1, "mode": 1, "user": 5, "user_name": "someone"},
        {"msg_type": 18, "event_type": 3111, "nick_name": "Alice", "push_count": 2},
        {"msg_type": 18, "event_type": 3102, "file_path": "/etc/passwd.zxvideo"},
        {"msg_type": 18, "event_type": 3102, "unique_id": "ab" * 16, "record_id": 7},
        {"msg_type": 18, "event_type": 3102, "unique_id": "a b", "record_id": -1},
    ],
)
def test_both_channels_lift_the_same_fields(inner: dict[str, Any]) -> None:
    payload = inner | {
        "device_sn": SYNTHETIC.camera_sn,
        "channel": 1,
        "name": "Front",
        "trigger_time": 1_789_223_120_000,
        "event_time": 1_789_223_120,
    }
    cloud = decode_push(_message(payload, type="19"), now_ms=lambda: NOW_MS)
    local = decode_camera_push(
        {"cmd": 2037, "payload": json.dumps(payload)},
        station_sn=SYNTHETIC.station_sn,
        frame_cipher=FrameCipher.GCM,
        now_ms=lambda: NOW_MS,
    )
    assert local is not None
    for name in _SHARED_FIELDS:
        assert getattr(cloud, name) == getattr(local, name), name


def _standalone_pair(file_path: str) -> tuple[SecurityEvent, SecurityEvent]:
    """A standalone camera's two cloud pushes for one detection."""
    sn = "T8170P2000054321"
    common = {
        "msg_type": 18,
        "event_type": 3102,
        "device_sn": sn,
        "channel": 0,
        "trigger_time": 1790956653093,
        "session_id": "20261002_185734",  # hygiene: ok
    }
    first = {**common, "create_time": 1790956654114, "file_path": "", "push_count": 1}
    second = {**common, "create_time": 1790956656034, "file_path": file_path, "push_count": 2}
    outer = {"type": "48", "station_sn": sn, "device_sn": sn}
    return (
        decode_push(_message({**first, "unique_id": "a" * 32}, **outer)),
        decode_push(_message({**second, "unique_id": "b" * 32}, **outer)),
    )


def test_a_standalone_cameras_second_push_with_the_recording_enriches_the_first() -> None:
    first, second = _standalone_pair("/zx/Camera00/20261002185734.zxvideo")
    assert first.dedupe_key != second.dedupe_key
    dedupe = EventDeduplicator()
    assert dedupe.admit(first) is first
    enrichment = dedupe.admit(second)
    assert enrichment is not None
    assert enrichment.enriches
    assert enrichment.video_path == "/zx/Camera00/20261002185734.zxvideo"
    assert dedupe.admit(second) is None  # a redelivery of the second copy


def test_a_standalone_cameras_second_push_without_new_media_is_a_repeat() -> None:
    first, second = _standalone_pair("")
    dedupe = EventDeduplicator()
    assert dedupe.admit(first) is first
    assert dedupe.admit(second) is None
    assert dedupe.dropped_repeats == 1


def test_a_first_push_at_the_same_moment_is_still_its_own_detection() -> None:
    """Only a re-announcement (push_count > 1) is matched by its moment."""
    first, second = _standalone_pair("")
    other = dataclasses.replace(second, push_count=1)
    dedupe = EventDeduplicator()
    assert dedupe.admit(first) is first
    assert dedupe.admit(other) is other
