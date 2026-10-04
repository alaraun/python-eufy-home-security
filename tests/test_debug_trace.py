"""The DEBUG trace of pushes, binding, dedupe and media: its lines, and no identifiers in them."""

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import EventDeduplicator, EventSource, PushMessageType, SecurityEvent
from eufy_home_security.exceptions import DeviceTimeoutError, RecordNotFoundError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.p2p.xzyh import FrameCipher, FrameType
from eufy_home_security.station import Station
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation
from tests.p2p.test_session import Provider, make_session  # the session test double

PUSH_RECORD_ID = 2026091700042
PUSH_UNIQUE_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    fake.params[255][1224] = "63"
    await fake.start()
    yield fake
    fake.stop()


def assert_no_identifiers(records: list[logging.LogRecord], extra: tuple[str, ...] = ()) -> None:
    forbidden = [
        SYNTHETIC.station_sn,
        SYNTHETIC.camera_sn,
        SYNTHETIC.did,
        SYNTHETIC.account_id,
        "/zx/",
        "SecurityEvent(",
        "Front",
        *list(extra),
    ]

    for record in records:
        if record.name.startswith("eufy_home_security") and not record.name.startswith(
            "eufy_home_security.wire"
        ):
            msg = record.getMessage()
            for f in forbidden:
                assert str(f) not in msg, f"Found forbidden identifier {f!r} in log message: {msg}"


def filter_caplog(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name.startswith("eufy_home_security")
        and not r.name.startswith("eufy_home_security.wire")
    ]


async def test_a_push_logs_its_cipher_and_type(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        station.push_camera_event(3102, cipher=FrameCipher.GCM)
        station.push_camera_event(3102, cipher=FrameCipher.ECB)
        await asyncio.sleep(0.1)
    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    gcm_found = any("camera push" in msg and "gcm" in msg and "18:3102" in msg for msg in messages)
    ecb_found = any("camera push" in msg and "ecb" in msg and "18:3102" in msg for msg in messages)
    assert gcm_found, f"GCM push log not found in: {messages}"
    assert ecb_found, f"ECB push log not found in: {messages}"

    assert_no_identifiers(records)


async def test_a_push_attaching_an_earlier_record_logs_what_was_bound(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()

        inner = {
            "msg_type": 18,
            "event_type": 3102,
            "device_sn": SYNTHETIC.camera_sn,
            "channel": 0,
            "name": "Front",
            "trigger_time": 1_700_000_000_000,
            "record_id": PUSH_RECORD_ID,
            "unique_id": PUSH_UNIQUE_ID,
            "file_path": "/zx/new.zxvideo",
            "rec_content": [
                {
                    "device_sn": SYNTHETIC.camera_sn,
                    "thumb_path": "/zx/earlier.jpg",
                    "storage_path": "/zx/earlier.zxvideo",
                    "station_sn": SYNTHETIC.station_sn,
                    "account": SYNTHETIC.account_id,
                    "record_id": PUSH_RECORD_ID - 1,
                }
            ],
        }
        station.send_json(
            FrameType.NOTIFY_PAYLOAD,
            {"cmd": 2037, "payload": json.dumps(inner)},
            cipher=FrameCipher.GCM,
        )
        await asyncio.sleep(0.1)
    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    bound_found = any(
        "push binding: record_id present, attached 1 record(s)" in msg
        and "bound thumb False, video True" in msg
        for msg in messages
    )
    assert bound_found, f"Push binding log not found in: {messages}"

    assert_no_identifiers(
        records, extra=(str(PUSH_RECORD_ID), str(PUSH_RECORD_ID - 1), PUSH_UNIQUE_ID)
    )


def test_dedupe_logs_each_drop_and_enrichment_with_its_reason(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    dedupe = EventDeduplicator()

    # The first copy is admitted.
    ev1 = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1700000000000,
        device_sn=SYNTHETIC.camera_sn,
        station_sn=SYNTHETIC.station_sn,
        channel=0,
        unique_id="id1",
        push_count=1,
    )
    assert dedupe.admit(ev1)

    # Second copy: duplicate
    ev2 = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1700000000000,
        device_sn=SYNTHETIC.camera_sn,
        station_sn=SYNTHETIC.station_sn,
        channel=0,
        unique_id="id1",
        push_count=1,
    )
    assert not dedupe.admit(ev2)

    # Second copy with push_count 2: repeat
    ev3 = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1700000000000,
        device_sn=SYNTHETIC.camera_sn,
        station_sn=SYNTHETIC.station_sn,
        channel=0,
        unique_id="id1",
        push_count=2,
    )
    assert not dedupe.admit(ev3)

    # Enrichment
    ev4 = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1700000000000,
        device_sn=SYNTHETIC.camera_sn,
        station_sn=SYNTHETIC.station_sn,
        channel=0,
        unique_id="id1",
        push_count=1,
        thumb_path="/zx/thumb.jpg",
    )
    assert dedupe.admit(ev4)

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    drop_dup = any("dropping" in msg and "duplicate" in msg for msg in messages)
    drop_rep = any("dropping" in msg and "repeat" in msg for msg in messages)
    enrich = any("enrichment" in msg for msg in messages)

    assert drop_dup, f"Duplicate drop log not found in: {messages}"
    assert drop_rep, f"Repeat drop log not found in: {messages}"
    assert enrich, f"Enrichment log not found in: {messages}"

    assert_no_identifiers(records, extra=("id1",))


STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)

CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=1,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    p2p_did=SYNTHETIC.did,
)


@pytest.fixture
async def real_station(station: FakeStation) -> AsyncIterator[Station]:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=station.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])
    yield st
    await st.async_close()


async def test_the_event_thumbnail_logs_each_history_lookup_outcome(
    station: FakeStation, real_station: Station, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    # Pre-populate station rows
    station.rows = [
        {"record_id": 2023101500001, "device_sn": "OTHER_CAMERA", "thumb_path": "/zx/t1.jpg"},
        {"record_id": 2023101500002, "device_sn": SYNTHETIC.camera_sn},  # no thumb_path
        {"record_id": 2023101500003, "device_sn": SYNTHETIC.camera_sn, "thumb_path": "/zx/t3.jpg"},
    ]
    station.images["/zx/t3.jpg"] = b"thumb3"

    await real_station.session.async_get_params()

    # missing row
    ev_missing = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1,
        device_sn=CAMERA.device_sn,
        station_sn=STATION.device_sn,
        channel=0,
        unique_id="x1",
        push_count=1,
        record_id=2023101500000,
    )
    with pytest.raises(RecordNotFoundError) as exc_info:
        await real_station.async_event_thumbnail(ev_missing)
    assert "2023101500000" not in str(exc_info.value)

    # another camera's row (ID 1)
    ev_another = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1,
        device_sn=CAMERA.device_sn,
        station_sn=STATION.device_sn,
        channel=0,
        unique_id="x2",
        push_count=1,
        record_id=2023101500001,
    )
    with pytest.raises(RecordNotFoundError) as exc_info:
        await real_station.async_event_thumbnail(ev_another)
    assert "2023101500001" not in str(exc_info.value)

    # a row without thumbnail (ID 2)
    ev_no_thumb = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1,
        device_sn=CAMERA.device_sn,
        station_sn=STATION.device_sn,
        channel=0,
        unique_id="x3",
        push_count=1,
        record_id=2023101500002,
    )
    with pytest.raises(RecordNotFoundError) as exc_info:
        await real_station.async_event_thumbnail(ev_no_thumb)
    assert "2023101500002" not in str(exc_info.value)

    # a good row (ID 3)
    ev_good = SecurityEvent(
        source=EventSource.P2P,
        msg_type=PushMessageType(18),
        event_type=3102,
        event_time_ms=1,
        device_sn=CAMERA.device_sn,
        station_sn=STATION.device_sn,
        channel=0,
        unique_id="x4",
        push_count=1,
        record_id=2023101500003,
    )
    res = await real_station.async_event_thumbnail(ev_good)
    assert res is not None

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    assert any("history record none" in msg for msg in messages)
    assert any("history record another camera's" in msg for msg in messages)
    assert any("history record no thumbnail yet" in msg for msg in messages)
    assert any("history record found" in msg for msg in messages)

    assert_no_identifiers(
        records,
        extra=("2023101500000", "2023101500001", "2023101500002", "2023101500003", "OTHER_CAMERA"),
    )


async def test_a_still_fetch_logs_send_bind_timeout_and_late_reply(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    station.images["/zx/success.jpg"] = b"\xff\xd8SUCCESS"
    station.images["/zx/timeout.jpg"] = b"\xff\xd8TIMEOUT"
    station.image_reply_delay["/zx/timeout.jpg"] = 0.5

    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()

        # Success
        await session.async_fetch_still("/zx/success.jpg")

        # Timeout and late reply
        with contextlib.suppress(DeviceTimeoutError):
            await session.async_fetch_still("/zx/timeout.jpg", timeout=0.1)

        await asyncio.sleep(0.6)  # Let the late reply arrive
    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    success_sent = any("image fetch sent" in msg for msg in messages)
    success_bound = any("image fetch bound" in msg and "in 0." in msg for msg in messages)
    timeout_log = any("no reply within" in msg for msg in messages)
    late_log = any("late image reply" in msg and "after its request" in msg for msg in messages)

    assert success_sent, f"'image fetch sent' not found in: {messages}"
    assert success_bound, f"'image fetch bound' with duration not found in: {messages}"
    assert timeout_log, f"'no reply within' not found in: {messages}"
    assert late_log, f"'late image reply' not found in: {messages}"

    assert_no_identifiers(records)


async def test_a_trigger_frame_logs_its_short_lived_session(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        inits_before = station.conn_inits

        await session.async_trigger_frame("/zx/clip.zxvideo", 0)

        inits_after = station.conn_inits
        assert inits_after == inits_before + 1
    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    open_log = any("short-lived session open in" in msg for msg in messages)
    close_log = any("short-lived session closed after" in msg for msg in messages)

    assert open_log, f"'short-lived session open in' not found in: {messages}"
    assert close_log, f"'short-lived session closed after' not found in: {messages}"

    assert_no_identifiers(records)


async def test_a_command_waiting_for_the_lock_logs_the_wait(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        # A parameter read holds the lock while the dump settles; the arm waits for it.
        read = asyncio.create_task(session.async_get_params())
        await asyncio.sleep(0.01)
        await session.async_set_guard_mode(GuardMode.HOME)
        await read
    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    waited_log = any("guard mode write waited" in msg for msg in messages)
    assert waited_log, f"'guard mode write waited' not found in: {messages}"

    assert_no_identifiers(records)


async def test_a_live_stream_logs_its_open_and_close(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()

        async with await session.async_open_live(0):
            await asyncio.sleep(0.1)

    finally:
        await session.async_close()

    records = filter_caplog(caplog)
    messages = [r.getMessage() for r in records]

    open_log = any("opening live media" in msg for msg in messages)
    close_log = any("closed after" in msg for msg in messages)

    assert open_log, f"'opening live media' not found in: {messages}"
    assert close_log, f"'closed after' not found in: {messages}"

    assert_no_identifiers(records)


async def test_frames_are_not_logged_one_by_one(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")

    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()

        async with await session.async_open_live(0) as stream:
            count = 0
            # Past the first frame, whose 'first keyframe' line is not steady delivery.
            await anext(stream)

            # Clear, so only the logs of steady frame delivery are counted
            caplog.clear()

            async for _frame in stream:
                count += 1
                if count >= 30:
                    break

            records = filter_caplog(caplog)
            assert len(records) < 10, f"Too many log records during live stream: {len(records)}"

    finally:
        await session.async_close()
