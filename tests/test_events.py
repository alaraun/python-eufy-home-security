from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from eufy_home_security.devices.support import Support
from eufy_home_security.events import (
    ALARM_PUSH_MAX_AGE_SECONDS,
    GUARD_PUSH_MAX_AGE_SECONDS,
    GUARD_REPORT_SLACK_SECONDS,
    AlarmChanged,
    AlarmStopSource,
    AlarmTracker,
    ArmingSource,
    CloudProblem,
    ConnectionChanged,
    DetectionType,
    DisconnectCause,
    Event,
    EventBus,
    EventDeduplicator,
    EventSource,
    GuardModeTracker,
    HistoryRecord,
    PushChanged,
    PushMessageType,
    SecurityEvent,
    coerce_int,
    coerce_str,
)
from eufy_home_security.exceptions import (
    AuthenticationError,
    CipherUnusableError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    KeyRejectedError,
    LoginLimitedError,
    ProtocolError,
    RateLimitedError,
    RefreshCooldownError,
    SessionReplacedError,
    StationUnreachableError,
)
from eufy_home_security.models import FrameCipher, GuardMode
from eufy_home_security.testing import SYNTHETIC


def test_connection_changed_equality_ignores_the_error() -> None:
    up = ConnectionChanged(station_sn=SYNTHETIC.station_sn, connected=True)
    assert up == ConnectionChanged(station_sn=SYNTHETIC.station_sn, connected=True)
    down = ConnectionChanged(
        station_sn=SYNTHETIC.station_sn,
        connected=False,
        cause=DisconnectCause.UNREACHABLE,
        error=StationUnreachableError("a"),
    )
    assert down == dataclasses.replace(down, error=StationUnreachableError("b"))
    assert hash(down) == hash(dataclasses.replace(down, error=None))


def test_push_changed_equality_ignores_the_error() -> None:
    down = PushChanged(running=False, error=CommunicationError("a"))
    assert down == PushChanged(running=False)
    assert down != PushChanged(running=True)


@pytest.mark.parametrize(
    ("error", "cause"),
    [
        (HandshakeError("x"), DisconnectCause.KEY_REJECTED),
        (KeyRejectedError("x"), DisconnectCause.KEY_REJECTED),
        (
            CipherUnusableError("x", cipher_id=40, reason="rsa_unparsable"),
            DisconnectCause.KEY_UNUSABLE,
        ),
        (RateLimitedError(), DisconnectCause.CREDENTIALS_UNAVAILABLE),
        (RefreshCooldownError(), DisconnectCause.CREDENTIALS_UNAVAILABLE),
        (DeviceTimeoutError("x"), DisconnectCause.PROBE_UNANSWERED),
        (StationUnreachableError("x"), DisconnectCause.UNREACHABLE),
        (ProtocolError("x"), DisconnectCause.PROTOCOL),
        (EufySecurityError("x"), DisconnectCause.PROTOCOL),
    ],
)
def test_disconnect_cause_for_error(error: EufySecurityError, cause: DisconnectCause) -> None:
    assert DisconnectCause.for_error(error) is cause


@pytest.mark.parametrize(
    ("error", "covered"),
    [
        (AuthenticationError("x"), True),
        (SessionReplacedError(), True),
        (RateLimitedError(code=26145), True),
        (LoginLimitedError(), True),  # the login budget is the cloud's limit, applied locally
        (RefreshCooldownError(), False),  # the library's own cooldown
        (KeyRejectedError("x"), False),
        (None, False),
    ],
)
def test_cloud_problem_covers_cloud_errors_but_not_the_local_cooldown(
    error: EufySecurityError | None, covered: bool
) -> None:
    assert CloudProblem.covers(error) is covered


def test_security_event_enums() -> None:
    ev = SecurityEvent(source=EventSource.P2P, msg_type=18, event_type=3102)
    assert ev.message_type is PushMessageType.INDOOR
    assert ev.detection is DetectionType.PERSON
    assert SecurityEvent(source=EventSource.CLOUD, event_type=9999).detection is None


@pytest.mark.parametrize(
    ("source", "cipher", "authenticated"),
    [
        (EventSource.P2P, FrameCipher.GCM, True),  # tag verified under the session key
        (EventSource.P2P, FrameCipher.ECB, False),  # static key: derivable on the LAN
        (EventSource.CLOUD, None, True),  # not a P2P frame: TLS from eufy's servers
    ],
)
def test_security_event_authenticated_follows_the_frame_cipher(
    source: EventSource, cipher: FrameCipher | None, authenticated: bool
) -> None:
    event = SecurityEvent(source=source, frame_cipher=cipher)
    assert event.authenticated is authenticated


def test_history_record_parses_str_extra() -> None:
    row = {
        "record_id": 2026091400034,
        "device_sn": "T8030P2000012345",
        "station_sn": "T8030P2000012345",
        "start_time": "2026-09-14 15:14:43",  # hygiene: ok
        "end_time": "2026-09-14 15:14:43",  # hygiene: ok
        "storage_type": 5,
        "thumb_path": "",
        "storage_path": "/zx/rec.zxvideo",
        "str_extra": '{"arm_mode":63,"cur_mode":63,"msg_type":9,"user":2,"user_name":"someone"}',
    }
    rec = HistoryRecord.from_row(row)
    assert rec.record_id == 2026091400034
    assert rec.storage_type == 5
    assert rec.thumb_path is None  # empty string normalises to None
    assert rec.storage_path == "/zx/rec.zxvideo"
    assert (rec.msg_type, rec.arm_mode, rec.user_name) == (9, 63, "someone")
    assert rec.message_type is PushMessageType.ARMING
    assert rec.raw == row  # the whole row is preserved
    assert rec.raw is not row  # as a defensive copy


def test_history_record_tolerates_missing_and_bad_extra() -> None:
    rec = HistoryRecord.from_row({"str_extra": "not json"})
    assert rec.record_id == 0
    assert rec.arm_mode is None
    assert rec.msg_type is None
    assert rec.device_sn is None


def _clip_row(**extra: object) -> dict[str, object]:
    return {
        "record_id": 2026100100010,
        "device_sn": "T8160P2000067890",
        "start_time": "2026-10-01 07:24:14",  # hygiene: ok
        "end_time": "2026-10-01 07:24:20",  # hygiene: ok
        "time_zone": "+0300",
        "storage_path": "/zx/hdd_data0/Camera01/202610/20261001072414/20261001072414.zxvideo",
        "frame_num": 90,
        "folder_size": 1717081,
        **extra,
    }


def test_a_history_record_names_its_recording_times_and_size() -> None:
    rec = HistoryRecord.from_row(_clip_row())
    assert rec.video_path == rec.storage_path
    plus3 = timezone(timedelta(hours=3))
    assert rec.started_at == datetime(2026, 10, 1, 7, 24, 14, tzinfo=plus3)
    assert rec.ended_at == datetime(2026, 10, 1, 7, 24, 20, tzinfo=plus3)
    assert rec.started_at is not None
    assert rec.started_at.utcoffset() == timedelta(hours=3)
    assert rec.duration_s == 6.0
    assert (rec.frame_count, rec.size_bytes) == (90, 1717081)


@pytest.mark.parametrize(
    "path",
    ["", "/zx/../etc/x.zxvideo", "/zx/hdd_data0/Camera01/x.jpg", "/var/x.zxvideo", 5],
)
def test_a_history_record_without_a_valid_recording_has_no_video_path(path: object) -> None:
    assert HistoryRecord.from_row(_clip_row(storage_path=path)).video_path is None


@pytest.mark.parametrize(
    ("time_zone", "offset"),
    [("-0530", timedelta(hours=-5, minutes=-30)), ("+02:00", timedelta(hours=2))],
)
def test_a_history_record_reads_its_times_in_its_own_offset(
    time_zone: str, offset: timedelta
) -> None:
    started = HistoryRecord.from_row(_clip_row(time_zone=time_zone)).started_at
    assert started is not None
    assert started.utcoffset() == offset


@pytest.mark.parametrize("time_zone", [None, "", "Europe/Tallinn", "+2500"])
def test_a_history_record_without_a_usable_offset_is_read_in_the_host_zone(
    time_zone: object,
) -> None:
    started = HistoryRecord.from_row(_clip_row(time_zone=time_zone)).started_at
    assert started == datetime(2026, 10, 1, 7, 24, 14).astimezone()


@pytest.mark.parametrize(
    ("start", "expected"),
    [
        (1_759_292_654, datetime(2025, 10, 1, 4, 24, 14, tzinfo=UTC)),
        (1_759_292_654_000, datetime(2025, 10, 1, 4, 24, 14, tzinfo=UTC)),
        ("not a time", None),
        ("2026-13-01 00:00:00", None),  # hygiene: ok
    ],
)
def test_a_history_record_time_is_epoch_or_formatted(start: object, expected: object) -> None:
    assert HistoryRecord.from_row(_clip_row(start_time=start)).started_at == expected


def test_a_history_record_without_times_or_counts_reports_none() -> None:
    rec = HistoryRecord.from_row(
        _clip_row(start_time="", end_time=None, frame_num=-1, folder_size="x")
    )
    assert (rec.started_at, rec.ended_at, rec.duration_s) == (None, None, None)
    assert (rec.frame_count, rec.size_bytes) == (None, None)
    backwards = HistoryRecord.from_row(_clip_row(end_time="2026-10-01 07:24:00"))  # hygiene: ok
    assert backwards.duration_s is None


def test_bus_isolates_failing_subscribers() -> None:
    bus = EventBus()
    seen: list[Event] = []

    def boom(_: Event) -> None:
        raise RuntimeError("subscriber bug")

    bus.subscribe(boom)
    unsub = bus.subscribe(seen.append)
    ev = SecurityEvent(source=EventSource.P2P)
    bus.emit(ev)
    unsub()
    bus.emit(ev)
    assert seen == [ev]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (5, 5),
        (" 7 ", 7),
        ("12.0", 12),
        (3.0, 3),
        (3.5, None),
        ("3.5", None),
        (True, None),
        (float("nan"), None),
        ("x", None),
        (None, None),
        ([1], None),
    ],
)
def test_coerce_int(value: object, expected: int | None) -> None:
    assert coerce_int(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("a ", "a"), ("", None), ("  ", None), (5, "5"), (True, None), ({"k": 1}, None)],
)
def test_coerce_str(value: object, expected: str | None) -> None:
    assert coerce_str(value) == expected


def test_history_record_normalises_field_types() -> None:
    rec = HistoryRecord.from_row(
        {
            "record_id": True,
            "start_time": 1_700_000_000_000,
            "storage_type": "5",
            "str_extra": '{"user_name": 5, "msg_type": true, "arm_mode": "63"}',
        }
    )
    assert rec.record_id == 0  # a bool is not an id
    assert rec.start_time == "1700000000000"  # time fields are always strings
    assert rec.storage_type == 5
    assert rec.user_name == "5"
    assert rec.msg_type is None
    assert rec.arm_mode == 63


@pytest.mark.parametrize(
    "make",
    [
        lambda raw: SecurityEvent(source=EventSource.CLOUD, station_sn="T8030X", raw=raw),
        lambda raw: HistoryRecord(record_id=1, raw=raw),
    ],
)
def test_raw_is_a_read_only_snapshot_ignored_by_equality_and_hash(make: Any) -> None:
    source: dict[str, Any] = {"k": 1}
    event = make(source)
    source["k"] = 2
    assert event.raw == {"k": 1}  # a snapshot, not the caller's dict
    with pytest.raises(TypeError):
        event.raw["k"] = 3
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.raw = {}
    twin = make({"other": True})
    assert event == twin
    assert hash(event) == hash(twin)
    assert len({event, twin}) == 1
    assert "raw" not in repr(event)


def test_bus_same_callback_twice_is_two_subscriptions() -> None:
    bus = EventBus()
    seen: list[Event] = []
    first = bus.subscribe(seen.append)
    bus.subscribe(seen.append)
    first()
    first()  # idempotent: must not remove the second subscription
    ev = SecurityEvent(source=EventSource.P2P)
    bus.emit(ev)
    assert seen == [ev]


def test_bus_skips_subscribers_removed_during_emit() -> None:
    bus = EventBus()
    seen: list[str] = []
    unsubs: list[Any] = []

    def remover(_: Event) -> None:
        seen.append("remover")
        unsubs[0]()
        bus.subscribe(lambda _e: seen.append("late"))  # added mid-emit: next event only

    bus.subscribe(remover)
    unsubs.append(bus.subscribe(lambda _e: seen.append("removed")))
    bus.emit(SecurityEvent(source=EventSource.P2P))
    assert seen == ["remover"]


def test_push_enum_members_carry_their_evidence() -> None:
    assert PushMessageType.INDOOR.evidence.support is Support.VERIFIED
    assert PushMessageType.ARMING.evidence.support is Support.VERIFIED
    assert PushMessageType.ALARM.evidence.support is Support.VERIFIED
    assert PushMessageType.ALARM_DELAY.evidence.support is Support.DECLARED
    assert PushMessageType.ALARM_DELAY.evidence.source == "eufy app CusPushMode"
    assert DetectionType.PERSON.evidence.support is Support.VERIFIED
    assert DetectionType.DOG_POOP.evidence.support is Support.DECLARED
    assert AlarmStopSource.APP.evidence.support is Support.VERIFIED
    for member in (AlarmStopSource.KEYPAD, AlarmStopSource.HOMEBASE, *ArmingSource):
        assert member.evidence.support is Support.DECLARED
        assert member.evidence.source == "eufy app CusPushMode"


@pytest.mark.parametrize(
    ("user", "source"),
    [(1, ArmingSource.KEYPAD), (5, ArmingSource.KEY_FOB), (2, ArmingSource.APP), (None, None)],
)
def test_arming_source_for_user(user: int | None, source: ArmingSource | None) -> None:
    assert ArmingSource.for_user(user) is source


def test_arming_source_needs_an_arming_push_that_is_authenticated() -> None:
    arm = SecurityEvent(source=EventSource.P2P, msg_type=9, arming_user=1)
    assert arm.arming_source is ArmingSource.KEYPAD
    assert dataclasses.replace(arm, frame_cipher=FrameCipher.ECB).arming_source is None
    assert dataclasses.replace(arm, msg_type=10).arming_source is None
    assert dataclasses.replace(arm, arming_user=None).arming_source is None


def test_rejected_fields_are_frozen() -> None:
    event = SecurityEvent(source=EventSource.CLOUD, rejected_fields={"thumb_path"})  # type: ignore[arg-type]
    assert isinstance(event.rejected_fields, frozenset)
    assert hash(event) == hash(
        SecurityEvent(source=EventSource.CLOUD, rejected_fields=frozenset({"thumb_path"}))
    )


# ── de-duplication ───────────────────────────────────────────────────────────

_P2P = SecurityEvent(
    source=EventSource.P2P,
    device_sn="camera-a",
    msg_type=18,
    event_type=3102,
    event_time_ms=1_700_000_000_400,  # P2P trigger_time: true milliseconds
    frame_cipher=FrameCipher.GCM,
    thumb_path="/zx/Camera00/thumb.jpg",
)
_CLOUD = SecurityEvent(
    source=EventSource.CLOUD,
    device_sn="camera-a",
    msg_type=18,
    event_type=3102,
    event_time_ms=1_700_000_000_000,  # FCM event_time: whole seconds
    push_id="span-1",
)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_the_dedupe_key_is_second_granular_and_names_the_event_type() -> None:
    assert _P2P.dedupe_key == _CLOUD.dedupe_key == "camera-a:1700000000:3102"
    assert dataclasses.replace(_P2P, event_type=None).dedupe_key == "camera-a:1700000000:"
    assert dataclasses.replace(_P2P, device_sn=None).dedupe_key is None
    assert dataclasses.replace(_P2P, event_time_ms=None).dedupe_key is None


def test_the_dedupe_key_is_the_unique_id_when_there_is_one() -> None:
    p2p = dataclasses.replace(_P2P, unique_id="u-1")
    cloud = dataclasses.replace(_CLOUD, unique_id="u-1", event_time_ms=1_700_000_003_300)
    assert p2p.dedupe_key == cloud.dedupe_key == "unique:u-1"
    dedupe = EventDeduplicator()
    assert dedupe.admit(cloud) is cloud
    enrichment = dedupe.admit(p2p)  # a later second, still the same occurrence
    assert enrichment is not None
    assert enrichment.enriches
    other = dataclasses.replace(p2p, unique_id="u-2")
    assert dedupe.admit(other) is other  # another occurrence in the same second


def test_the_cloud_copy_after_the_p2p_copy_is_dropped() -> None:
    dedupe = EventDeduplicator()
    assert dedupe.admit(_P2P) is _P2P
    assert dedupe.admit(_CLOUD) is None
    assert dedupe.admit(_P2P) is None
    assert (dedupe.dropped_duplicates, dedupe.dropped_repeats) == (2, 0)


def test_a_p2p_copy_with_new_media_after_the_cloud_copy_is_an_enrichment() -> None:
    dedupe = EventDeduplicator()
    assert dedupe.admit(_CLOUD) is _CLOUD
    enrichment = dedupe.admit(_P2P)
    assert enrichment == _P2P  # enriches is delivery metadata, not identity
    assert enrichment is not None
    assert enrichment.enriches
    assert enrichment.thumb_path == _P2P.thumb_path
    assert dedupe.admit(_P2P) is None  # no media the earlier copies lacked
    crop = dataclasses.replace(_P2P, crop_path="/zx/Camera00/crop.jpg")
    enriched = dedupe.admit(crop)
    assert enriched is not None
    assert enriched.enriches
    assert dedupe.dropped_duplicates == 1


def test_a_repeat_is_dropped_only_when_its_occurrence_was_seen() -> None:
    dedupe = EventDeduplicator()
    repeat = dataclasses.replace(_P2P, push_count=2)
    assert dedupe.admit(repeat) is repeat  # its first copy was lost: the only copy
    assert dedupe.admit(repeat) is None
    assert (dedupe.dropped_repeats, dedupe.dropped_duplicates) == (1, 0)


def test_station_events_and_events_without_a_key_are_always_admitted() -> None:
    dedupe = EventDeduplicator()
    alarm = dataclasses.replace(_P2P, msg_type=PushMessageType.ALARM, alarm_type=3)
    stop = dataclasses.replace(alarm, alarm_type=AlarmStopSource.APP)  # same trigger_time
    keyless = SecurityEvent(source=EventSource.CLOUD, msg_type=18)
    for event in (alarm, stop, alarm, keyless, keyless):
        assert dedupe.admit(event) is event
    assert (dedupe.dropped_duplicates, dedupe.dropped_repeats) == (0, 0)


def test_two_detection_types_in_one_second_are_both_delivered() -> None:
    dedupe = EventDeduplicator()
    motion = dataclasses.replace(_P2P, event_type=DetectionType.MOTION)
    assert dedupe.admit(motion) is motion
    assert dedupe.admit(_P2P) is _P2P


# ── guard-mode ordering ──────────────────────────────────────────────────────

_NOW_MS = 1_789_130_470_000
_OTHER_STATION_SN = "T8030P2000000002"


def _guard_push(
    at_ms: int, *, station: str = SYNTHETIC.station_sn, source: EventSource = EventSource.CLOUD
) -> SecurityEvent:
    return SecurityEvent(
        source=source, station_sn=station, msg_type=9, guard_mode=1, event_time_ms=at_ms
    )


def _tracker() -> GuardModeTracker:
    return GuardModeTracker(now_ms=lambda: _NOW_MS)


def test_stale_and_out_of_order_guard_pushes_are_dropped() -> None:
    tracker = _tracker()
    admitted = [
        tracker.admit_push(_guard_push(_NOW_MS - (GUARD_PUSH_MAX_AGE_SECONDS + 60) * 1000)),
        tracker.admit_push(_guard_push(_NOW_MS - 10_000)),
        tracker.admit_push(_guard_push(_NOW_MS - 60_000)),  # older than the one applied
        tracker.admit_push(_guard_push(_NOW_MS - 60_000, station=_OTHER_STATION_SN)),  # own order
    ]
    assert admitted == [False, True, False, True]


def test_guard_pushes_are_ordered_in_whole_seconds() -> None:
    tracker = _tracker()
    p2p_ms = _NOW_MS - 2_300
    assert tracker.admit_push(_guard_push(p2p_ms, source=EventSource.P2P))
    cloud_ms = p2p_ms // 1000 * 1000  # the cloud copy of the same change: whole seconds
    assert tracker.admit_push(_guard_push(cloud_ms))
    assert tracker.stamps == {SYNTHETIC.station_sn: p2p_ms}  # a stamp never moves back
    assert not tracker.admit_push(_guard_push(cloud_ms - 1))


def test_a_report_orders_the_pushes_after_it() -> None:
    tracker = _tracker()
    tracker.note_report(SYNTHETIC.station_sn)
    slack_ms = GUARD_REPORT_SLACK_SECONDS * 1000
    assert tracker.stamps == {SYNTHETIC.station_sn: _NOW_MS - slack_ms}
    assert not tracker.admit_push(_guard_push(_NOW_MS - slack_ms - 1000))  # an earlier change
    assert tracker.admit_push(_guard_push(_NOW_MS - 1000))  # the push for the reported change


def test_a_guard_push_without_a_time_is_admitted_and_stamps_nothing() -> None:
    tracker = _tracker()
    assert tracker.admit_push(
        SecurityEvent(source=EventSource.CLOUD, station_sn=SYNTHETIC.station_sn, guard_mode=1)
    )
    assert tracker.stamps == {}


def test_a_mode_is_a_change_only_when_the_pair_differs() -> None:
    tracker = _tracker()
    station = SYNTHETIC.station_sn
    assert tracker.changed(station, GuardMode.HOME, GuardMode.HOME)
    assert not tracker.changed(station, 1, 1)  # the same codes
    assert tracker.changed(station, GuardMode.AWAY, GuardMode.AWAY)
    assert tracker.changed(_OTHER_STATION_SN, GuardMode.AWAY, GuardMode.AWAY)
    # a schedule boundary moves only the effective mode: one change per boundary
    assert tracker.changed(station, GuardMode.SCHEDULE, GuardMode.AWAY)
    assert tracker.changed(station, GuardMode.SCHEDULE, GuardMode.HOME)
    assert not tracker.changed(station, GuardMode.SCHEDULE, GuardMode.HOME)


def test_the_effective_mode_of_a_push() -> None:
    tracker = _tracker()
    station = SYNTHETIC.station_sn
    assert tracker.active_mode(station, GuardMode.SCHEDULE, 1) is GuardMode.HOME  # pushed
    assert tracker.active_mode(station, GuardMode.AWAY, None) is GuardMode.AWAY
    assert tracker.active_mode(station, GuardMode.SCHEDULE, None) is None  # nothing known
    tracker.changed(station, GuardMode.SCHEDULE, GuardMode.DISARMED)
    assert tracker.active_mode(station, GuardMode.SCHEDULE, None) is GuardMode.DISARMED


# ── alarm lifecycle ───────────────────────────────────────────────────────────


def _alarm_push(
    alarm_type: int, at_ms: int | None, *, cipher: FrameCipher | None = None
) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.CLOUD if cipher is None else EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        channel=1,
        msg_type=PushMessageType.ALARM,
        alarm_type=alarm_type,
        event_time_ms=at_ms,
        frame_cipher=cipher,
    )


def _p2p_alarm(alarming: bool) -> AlarmChanged:
    return AlarmChanged(station_sn=SYNTHETIC.station_sn, alarming=alarming, source=EventSource.P2P)


class _MsClock:
    def __init__(self) -> None:
        self.now = _NOW_MS

    def __call__(self) -> int:
        return self.now


def test_an_alarm_on_both_channels_is_one_start_and_one_end() -> None:
    clock = _MsClock()
    alarms = AlarmTracker(now_ms=clock)
    assert alarms.report(_p2p_alarm(True))
    assert alarms.alarming(SYNTHETIC.station_sn)
    assert alarms.push(_alarm_push(3, _NOW_MS - 20)) is None  # its cloud copy
    assert alarms.push(_alarm_push(25, _NOW_MS - 10)) is None  # the siren's
    clock.now += 12_000
    assert alarms.report(_p2p_alarm(False))  # stopped from the app
    assert not alarms.report(_p2p_alarm(False))
    assert alarms.push(_alarm_push(AlarmStopSource.APP, clock.now - 5)) is None
    assert alarms.push(_alarm_push(3, _NOW_MS + 300)) is None  # a late trigger copy
    assert not alarms.alarming(SYNTHETIC.station_sn)
    assert alarms.alarming(_OTHER_STATION_SN) is False


def test_a_cloud_only_alarm() -> None:
    clock = _MsClock()
    alarms = AlarmTracker(now_ms=clock)
    started = alarms.push(_alarm_push(25, _NOW_MS - 1_000))
    assert started == AlarmChanged(
        station_sn=SYNTHETIC.station_sn,
        alarming=True,
        source=EventSource.CLOUD,
        channel=1,
        event_type=25,
    )
    stopped = alarms.push(_alarm_push(AlarmStopSource.KEYPAD, _NOW_MS))
    assert stopped is not None
    assert (stopped.alarming, stopped.stop_source) == (False, AlarmStopSource.KEYPAD)
    assert alarms.push(_alarm_push(3, None)) is not None  # no time: now
    disarm = alarms.disarmed(SYNTHETIC.station_sn, EventSource.CLOUD)
    assert disarm == AlarmChanged(
        station_sn=SYNTHETIC.station_sn, alarming=False, source=EventSource.CLOUD
    )
    assert alarms.disarmed(SYNTHETIC.station_sn, EventSource.CLOUD) is None


@pytest.mark.parametrize(
    "push",
    [
        _alarm_push(3, _NOW_MS - (ALARM_PUSH_MAX_AGE_SECONDS + 1) * 1000),  # a redelivery
        _alarm_push(3, _NOW_MS, cipher=FrameCipher.ECB),  # forgeable
        dataclasses.replace(_alarm_push(3, _NOW_MS), msg_type=PushMessageType.ALARM_DELAY),
        dataclasses.replace(_alarm_push(3, _NOW_MS), msg_type=PushMessageType.ARMING),
        dataclasses.replace(_alarm_push(3, _NOW_MS), station_sn=None),
    ],
)
def test_pushes_that_move_no_alarm(push: SecurityEvent) -> None:
    alarms = AlarmTracker(now_ms=lambda: _NOW_MS)
    assert alarms.push(push) is None
    assert not alarms.alarming(SYNTHETIC.station_sn)


def test_persisted_stamps_merge_forward_and_skip_malformed_entries() -> None:
    tracker = _tracker()
    tracker.admit_push(_guard_push(_NOW_MS - 1000))
    tracker.load(
        {
            SYNTHETIC.station_sn: _NOW_MS - 5000,
            _OTHER_STATION_SN: _NOW_MS - 7000,
            "b": True,
            "s": "1",
        }
    )
    tracker.load([["not", "a mapping"]])
    assert tracker.stamps == {
        SYNTHETIC.station_sn: _NOW_MS - 1000,
        _OTHER_STATION_SN: _NOW_MS - 7000,
    }


def test_a_key_is_forgotten_after_max_age_or_when_the_ring_is_full() -> None:
    clock = _Clock()
    dedupe = EventDeduplicator(max_entries=2, max_age=10.0, clock=clock)
    assert dedupe.admit(_P2P) is _P2P
    clock.now = 9.9
    assert dedupe.admit(_P2P) is None
    clock.now = 10.0
    assert dedupe.admit(_P2P) is _P2P
    for event_type in (DetectionType.VEHICLE, DetectionType.DOG):
        dedupe.admit(dataclasses.replace(_P2P, event_type=event_type))
    assert dedupe.admit(_P2P) is _P2P  # the oldest key made room


@pytest.mark.parametrize("limits", [{"max_entries": 0}, {"max_age": 0.0}])
def test_the_ring_limits_must_be_positive(limits: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="positive"):
        EventDeduplicator(**limits)
