"""Camera-push decoding (NOTIFY_PAYLOAD / cmd 2037)."""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security import events
from eufy_home_security._logging import LogThrottle
from eufy_home_security.events import (
    NAME_MAX,
    AlarmPhase,
    ArmingSource,
    DetectionType,
    EventScope,
    EventSource,
    PushMessageType,
    SecurityEvent,
)
from eufy_home_security.models import FrameCipher
from eufy_home_security.p2p.notify import decode_camera_push, is_command_result, stamped_accounts
from eufy_home_security.testing import SYNTHETIC

OTHER_CAMERA_SN = "T8160P2000011111"
NOW_MS = 1_789_130_470_000
EVENT_MS = 1_789_130_460_170
CLIP = "/zx/hdd_data0/Camera01/x/x.zxvideo"


def _payload(**overrides: Any) -> dict[str, Any]:
    """A synthetic person-detection payload, shaped like a real one."""
    payload: dict[str, Any] = {
        "msg_type": 18,
        "event_type": 3102,
        "device_sn": SYNTHETIC.camera_sn,
        "name": "Front",
        "channel": 1,
        "create_time": EVENT_MS,
        "trigger_time": EVENT_MS,
        "file_path": CLIP,
        "pic_url": "",
        "push_count": 1,
        "notification_style": 1,
        "rec_content": [
            {
                "account": SYNTHETIC.account_id,
                "device_sn": SYNTHETIC.camera_sn,
                "station_sn": SYNTHETIC.station_sn,
                "storage_path": CLIP,
                "thumb_path": "/zx/hdd_data0/Camera01/x/snapshort.jpg",
                "trigger_type": 4,
            }
        ],
        "pic_content": [{"crop_path": "/zx/hdd_data0/Camera01/x/face.jpg", "detection_type": 1}],
    }
    payload.update(overrides)
    return payload


def _decode(
    payload: dict[str, Any], *, cipher: FrameCipher | None = None, station_sn: str | None = None
) -> SecurityEvent:
    ev = decode_camera_push(
        {"cmd": 2037, "payload": json.dumps(payload)},
        station_sn=station_sn or SYNTHETIC.station_sn,
        frame_cipher=cipher,
        now_ms=lambda: NOW_MS,
    )
    assert ev is not None
    return ev


def test_stamped_accounts_are_the_record_stamps_lowercased() -> None:
    payload = {
        "rec_content": [
            {"account": SYNTHETIC.account_id.upper()},
            {"account": ""},
            {"account": 7},
            "not a record",
            {"device_sn": SYNTHETIC.camera_sn},
        ]
    }
    assert stamped_accounts(payload) == {SYNTHETIC.account_id}
    assert stamped_accounts({"rec_content": "x"}) == frozenset()
    assert stamped_accounts({}) == frozenset()


def test_decode_camera_push_reads_a_person_event() -> None:
    ev = _decode(_payload())
    assert ev.dedupe_key == f"{SYNTHETIC.camera_sn}:{EVENT_MS // 1000}:3102"  # seconds
    assert ev.source is EventSource.P2P
    assert ev.message_type is PushMessageType.INDOOR
    assert ev.detection is DetectionType.PERSON
    assert ev.scope is EventScope.DEVICE
    assert (ev.device_sn, ev.device_name, ev.channel) == (SYNTHETIC.camera_sn, "Front", 1)
    assert ev.event_time_ms == EVENT_MS
    assert ev.station_sn == SYNTHETIC.station_sn
    assert ev.push_count == 1
    # the fetchable thumb/crop come from the bound rec_content / pic_content
    assert ev.thumb_path == "/zx/hdd_data0/Camera01/x/snapshort.jpg"
    assert ev.crop_path == "/zx/hdd_data0/Camera01/x/face.jpg"
    assert ev.video_path == CLIP
    assert ev.dedupe_key
    assert ev.rejected_fields == frozenset()
    assert ev.frame_cipher is None  # the caller did not name a frame
    assert (ev.alarm_phase, ev.arming_source, ev.guard_mode) == (None, None, None)


@pytest.mark.parametrize(
    ("cipher", "authenticated"), [(FrameCipher.GCM, True), (FrameCipher.ECB, False)]
)
def test_decode_camera_push_records_the_frame_cipher(
    cipher: FrameCipher, authenticated: bool
) -> None:
    ev = _decode(_payload(), cipher=cipher)  # an ECB push is still delivered
    assert ev.frame_cipher is cipher
    assert ev.authenticated is authenticated


# ── attached records ─────────────────────────────────────────────────────────


def test_a_record_about_another_device_is_not_lifted() -> None:
    rec = {"device_sn": OTHER_CAMERA_SN, "thumb_path": "/zx/Camera00/t.jpg"}
    ev = _decode(
        _payload(
            file_path="",
            rec_content=[rec | {"storage_path": "/zx/Camera00/c.zxvideo"}],
            pic_content=[{"crop_path": "/zx/Camera00/face.jpg"}],
        )
    )
    assert (ev.thumb_path, ev.video_path, ev.crop_path) == (None, None, None)
    assert ev.rejected_fields == frozenset()  # unbound, not invalid


def test_the_matching_record_is_found_past_a_stale_one() -> None:
    stale = {"device_sn": OTHER_CAMERA_SN, "thumb_path": "/zx/Camera00/t.jpg"}
    own = {"device_sn": SYNTHETIC.camera_sn, "thumb_path": "/zx/Camera01/t.jpg"}
    ev = _decode(_payload(rec_content=[stale, own]))
    assert ev.thumb_path == "/zx/Camera01/t.jpg"


RECORD_ID = 2026091600058
EARLIER_RECORD_ID = 2026091600052


@pytest.mark.parametrize("attached_id", [EARLIER_RECORD_ID, None])
def test_records_of_an_earlier_event_are_not_lifted(attached_id: int | None) -> None:
    # Verified on hardware: a push's attached records are an earlier event's, same
    # camera, while the push's own record_id names the new clip.
    rec = {
        "device_sn": SYNTHETIC.camera_sn,
        "thumb_path": "/zx/hdd_data0/Camera01/old/snapshort.jpg",
        "storage_path": "/zx/hdd_data0/Camera01/old/old.zxvideo",
        "record_id": attached_id,
    }
    pic = {"crop_path": "/zx/hdd_data0/Camera01/old/face.jpg", "record_id": attached_id}
    ev = _decode(_payload(record_id=RECORD_ID, rec_content=[rec], pic_content=[pic]))
    assert (ev.thumb_path, ev.crop_path) == (None, None)
    assert ev.video_path == CLIP  # the push's own file_path
    assert ev.record_id == RECORD_ID
    assert ev.rejected_fields == frozenset()
    no_clip = _decode(
        _payload(file_path="", record_id=RECORD_ID, rec_content=[rec], pic_content=[pic])
    )
    assert no_clip.video_path is None  # not the earlier record's storage_path


def test_records_with_the_push_record_id_are_lifted() -> None:
    old = {
        "device_sn": SYNTHETIC.camera_sn,
        "record_id": EARLIER_RECORD_ID,
        "thumb_path": "/zx/o.jpg",
    }
    own = {"device_sn": SYNTHETIC.camera_sn, "record_id": RECORD_ID, "thumb_path": "/zx/n.jpg"}
    pics = [
        {"crop_path": "/zx/Camera00/o.jpg", "record_id": EARLIER_RECORD_ID},
        {"crop_path": "/zx/Camera00/n.jpg", "record_id": str(RECORD_ID)},
    ]
    ev = _decode(_payload(record_id=RECORD_ID, rec_content=[old, own], pic_content=pics))
    assert (ev.thumb_path, ev.crop_path) == ("/zx/n.jpg", "/zx/Camera00/n.jpg")


@pytest.mark.parametrize(
    ("unique_id", "record_id", "lifted", "rejected"),
    [
        ("ab" * 16, 12, ("ab" * 16, 12), frozenset()),
        ("", 0, (None, None), frozenset()),  # none
        ("a b", -3, (None, None), {"unique_id", "record_id"}),
        (7, "x", (None, None), {"unique_id", "record_id"}),
        ("u" * (events.UNIQUE_ID_MAX + 1), None, (None, None), {"unique_id"}),
    ],
)
def test_occurrence_ids_are_validated(
    unique_id: object, record_id: object, lifted: tuple[object, object], rejected: frozenset[str]
) -> None:
    ev = _decode(_payload(unique_id=unique_id, record_id=record_id))
    assert (ev.unique_id, ev.record_id) == lifted
    assert ev.rejected_fields == rejected


def test_the_record_station_serial_never_replaces_the_sessions() -> None:
    rec = {"device_sn": SYNTHETIC.camera_sn, "station_sn": "T8030P2000099999"}
    assert _decode(_payload(rec_content=[rec])).station_sn == SYNTHETIC.station_sn


@pytest.mark.parametrize(
    ("crop", "file_path", "record_matches", "kept"),
    [
        ("/zx/Camera00/face.jpg", "/zx/Camera01/c.zxvideo", True, False),  # stale crop
        ("/zx/Camera01/face.jpg", "/zx/Camera01/c.zxvideo", False, True),  # by CameraNN
        ("/zx/face.jpg", "/zx/c.zxvideo", True, True),  # no CameraNN: the binding decides
        ("/zx/face.jpg", "/zx/c.zxvideo", False, False),
        ("/zx/Camera01/face.jpg", "", False, False),  # nothing to agree with
    ],
)
def test_crop_path_binding(crop: str, file_path: str, record_matches: bool, kept: bool) -> None:
    rec_sn = SYNTHETIC.camera_sn if record_matches else OTHER_CAMERA_SN
    ev = _decode(
        _payload(
            file_path=file_path,
            rec_content=[{"device_sn": rec_sn}],
            pic_content=[{"crop_path": crop}],
        )
    )
    assert (ev.crop_path == crop) is kept
    assert (ev.crop_path is None) is not kept


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd.jpg",
        "/zx/../x.jpg",
        "/zx/a" + chr(0x2028) + "b.jpg",  # a Unicode line separator
        "/zx/" + "a" * 292 + ".jpg",  # 300 characters
        "/zx/a\x00.jpg",
        "/zx/a.png",
    ],
)
def test_invalid_paths_are_rejected(path: str) -> None:
    rec = {"device_sn": SYNTHETIC.camera_sn, "thumb_path": path, "storage_path": path}
    ev = _decode(_payload(file_path=path, rec_content=[rec], pic_content=[{"crop_path": path}]))
    assert (ev.thumb_path, ev.video_path, ev.crop_path) == (None, None, None)
    assert ev.rejected_fields == {"thumb_path", "video_path", "crop_path"}


def test_a_256_character_path_is_accepted() -> None:
    path = "/zx/Camera01/" + "a" * 239 + ".jpg"
    assert len(path) == events.MEDIA_PATH_MAX
    rec = {"device_sn": SYNTHETIC.camera_sn, "thumb_path": path}
    assert _decode(_payload(rec_content=[rec])).thumb_path == path


@pytest.mark.parametrize(
    "trigger_time",
    [
        1_700_000_000,  # seconds, not ms
        events.EVENT_TIME_MAX_MS,
        NOW_MS + 3_600_000,  # an hour ahead of the host clock
    ],
)
def test_implausible_event_times_are_rejected(trigger_time: int) -> None:
    ev = _decode(_payload(trigger_time=trigger_time))
    assert ev.event_time_ms is None
    assert ev.dedupe_key is None
    assert ev.rejected_fields == {"event_time_ms"}


def test_a_time_within_the_skew_allowance_is_kept() -> None:
    ahead = NOW_MS + int(events.EVENT_TIME_MAX_SKEW_S * 1000)
    assert _decode(_payload(trigger_time=ahead)).event_time_ms == ahead


def test_clock_skew_is_logged_once(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(events, "_SKEW_LOG", LogThrottle(interval=float("inf")))
    with caplog.at_level(logging.WARNING, logger="eufy_home_security.events"):
        for _ in range(3):
            _decode(_payload(trigger_time=NOW_MS + 3_600_000))
    assert len([r for r in caplog.records if "ahead of the host clock" in r.message]) == 1


def test_create_time_is_the_fallback_event_time() -> None:
    payload = _payload()
    del payload["trigger_time"]
    assert _decode(payload).event_time_ms == EVENT_MS


def test_names_are_capped() -> None:
    long = "n" * 200
    ev = _decode(_payload(name=long, nick_name=long, user_name=long))
    assert ev.device_name == ev.person_name == ev.user_name == "n" * NAME_MAX


# ── station pushes (shared with the cloud decoder) ───────────────────────────


@pytest.mark.parametrize(
    ("cipher", "phase"), [(FrameCipher.GCM, AlarmPhase.STOPPED), (FrameCipher.ECB, None)]
)
def test_alarm_stop_needs_an_authenticated_frame(
    cipher: FrameCipher, phase: AlarmPhase | None
) -> None:
    ev = _decode(_payload(msg_type=10, type=16), cipher=cipher)
    assert ev.scope is EventScope.STATION
    assert ev.alarm_type == 16
    assert ev.alarm_phase is phase


def test_alarm_trigger_and_delay() -> None:
    assert _decode(_payload(msg_type=10, type=3)).alarm_phase is AlarmPhase.TRIGGERED
    delay = _decode(_payload(msg_type=16, alarm_delay=30))
    assert (delay.alarm_phase, delay.alarm_delay) == (AlarmPhase.DELAY, 30)


def test_alarm_type_is_lifted_only_on_alarm_pushes() -> None:
    assert _decode(_payload(type=16)).alarm_type is None


@pytest.mark.parametrize(
    ("cipher", "source"), [(FrameCipher.GCM, ArmingSource.KEY_FOB), (FrameCipher.ECB, None)]
)
def test_arming_fields_and_source(cipher: FrameCipher, source: ArmingSource | None) -> None:
    ev = _decode(_payload(msg_type=9, arming=1, mode=1, user=5, user_name="someone"), cipher=cipher)
    assert ev.scope is EventScope.STATION
    assert (ev.mode, ev.arming_user, ev.user_name) == (1, 5, "someone")
    assert ev.arming_source is source
    # `arming` moves the guard mode only from an authenticated frame
    assert ev.guard_mode == (None if cipher is FrameCipher.ECB else 1)
    assert ("guard_mode" in ev.rejected_fields) is (cipher is FrameCipher.ECB)
    assert ev.raw["arming"] == 1


def test_an_arming_push_with_a_rejected_time_moves_no_guard_mode() -> None:
    ev = _decode(_payload(msg_type=9, arming=1, trigger_time=NOW_MS + 3_600_000))
    assert (ev.event_time_ms, ev.guard_mode) == (None, None)
    assert {"event_time_ms", "guard_mode"} <= ev.rejected_fields


def test_identified_person_name_from_nick_name() -> None:
    ev = _decode(_payload(event_type=3111, nick_name="Alice"))
    assert ev.detection is DetectionType.IDENTITY_PERSON
    assert ev.person_name == "Alice"


# ── framing and robustness ───────────────────────────────────────────────────


def test_decode_camera_push_returns_none_for_non_pushes() -> None:
    assert decode_camera_push({"cmd": 1151, "payload": "{}"}, station_sn=None) is None
    assert decode_camera_push({"cmd": 2037, "payload": "not json"}, station_sn=None) is None
    assert decode_camera_push({"cmd": 2037, "payload": 42}, station_sn=None) is None
    assert decode_camera_push({"mode_type": 1}, station_sn=None) is None


def test_is_command_result_complements_camera_push() -> None:
    assert is_command_result({"cmd": 1151})
    assert not is_command_result({"cmd": 2037})
    # a decimal-string cmd names the same push; a bool/float does not
    assert not is_command_result({"cmd": "2037"})
    assert decode_camera_push({"cmd": "2037", "payload": "{}"}, station_sn=None) is not None
    assert is_command_result({"cmd": 2037.0})


def test_wrongly_typed_fields_are_dropped_and_no_dedupe_key_without_identity() -> None:
    payload = {
        "device_sn": 12345,
        "name": ["x"],
        "channel": "1",
        "msg_type": 18.5,
        "event_type": {"a": 1},
        "trigger_time": True,
        "file_path": 7,
        "pic_url": None,
        "rec_content": [{"station_sn": 1, "thumb_path": ["p"]}],
    }
    ev = decode_camera_push({"cmd": 2037, "payload": json.dumps(payload)}, station_sn="S")
    assert ev is not None
    assert (ev.device_sn, ev.device_name, ev.msg_type, ev.event_type) == (None, None, None, None)
    assert (ev.event_time_ms, ev.video_path, ev.thumb_path) == (None, None, None)
    assert ev.channel == 1
    assert ev.station_sn == "S"
    assert ev.dedupe_key is None
    # two malformed pushes must not collapse onto one shared key
    empty = decode_camera_push({"cmd": 2037, "payload": "{}"}, station_sn=None)
    assert empty is not None
    assert empty.dedupe_key is None


def test_non_finite_or_deep_payloads_are_not_events() -> None:
    assert decode_camera_push({"cmd": 2037, "payload": '{"a":NaN}'}, station_sn=None) is None
    deep = "[" * 100_000 + "]" * 100_000
    assert decode_camera_push({"cmd": 2037, "payload": deep}, station_sn=None) is None


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=40,
)
_PUSH_FIELDS = st.fixed_dictionaries(
    {},
    optional=dict.fromkeys(
        (
            "device_sn",
            "name",
            "channel",
            "msg_type",
            "event_type",
            "trigger_time",
            "create_time",
            "file_path",
            "pic_url",
            "rec_content",
            "pic_content",
            "type",
            "user",
            "user_name",
            "nick_name",
            "unique_id",
            "record_id",
        ),
        _JSON,
    ),
)


@given(payload=st.one_of(_PUSH_FIELDS, _JSON), encode=st.booleans(), cmd=_JSON)
@settings(max_examples=200)
def test_any_json_push_decodes_without_raising(payload: Any, encode: bool, cmd: Any) -> None:
    if encode:
        with contextlib.suppress(ValueError):
            payload = json.dumps(payload)
    for obj in ({"cmd": 2037, "payload": payload}, {"cmd": cmd, "payload": payload}):
        is_command_result(obj)
        ev = decode_camera_push(obj, station_sn=None)
        if ev is not None:
            for text in (ev.device_sn, ev.device_name, ev.user_name, ev.pic_url):
                assert text is None or isinstance(text, str)
            for path in (ev.thumb_path, ev.video_path, ev.crop_path):
                assert path is None or path.startswith(events.MEDIA_PATH_PREFIX)
            for num in (ev.channel, ev.msg_type, ev.event_type, ev.event_time_ms, ev.alarm_type):
                assert num is None or type(num) is int
            assert ev.record_id is None or (type(ev.record_id) is int and ev.record_id > 0)
            assert ev.unique_id is None or isinstance(ev.unique_id, str)


def test_unknown_codes_degrade_rather_than_raise() -> None:
    ev = _decode({"msg_type": 99, "event_type": 9999})
    assert ev.message_type is None
    assert ev.detection is None
    assert ev.scope is EventScope.DEVICE
