"""A station's recordings: listing them from the history, and downloading one as a clip."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import HistoryRecord
from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import RECORDING_QUIET, Station
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)
CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    channel=0,
)
OTHER_SN = "T8160P2000099999"
FORMAT = "%Y-%m-%d %H:%M:%S"


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    await station.start()
    yield station
    station.stop()


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])
    yield st
    await st.async_close()


def _row(day: datetime, counter: int, device_sn: str, **extra: object) -> dict[str, object]:
    start = day.replace(hour=12, minute=0, second=0, microsecond=0) + timedelta(minutes=counter)
    return {
        "record_id": int(day.strftime("%Y%m%d")) * HISTORY_RECORD_COUNTER + counter,
        "device_sn": device_sn,
        "start_time": start.strftime(FORMAT),
        "end_time": (start + timedelta(seconds=10)).strftime(FORMAT),
        "storage_path": f"/zx/hdd_data0/Camera00/{counter}.zxvideo",
        "frame_num": 6,
        **extra,
    }


async def test_recordings_list_valid_clips_of_paired_cameras_newest_first(
    station: Station, fake: FakeStation
) -> None:
    today = datetime.now().astimezone()
    yesterday = today - timedelta(days=1)
    fake.rows = [
        _row(today, 3, SYNTHETIC.camera_sn),
        _row(today, 2, OTHER_SN),  # not paired here
        _row(today, 1, SYNTHETIC.camera_sn, storage_path=""),  # an arming row
        _row(yesterday, 5, SYNTHETIC.camera_sn, storage_path="/zx/../x.zxvideo"),
        _row(yesterday, 4, SYNTHETIC.camera_sn),
        _row(today - timedelta(days=2), 9, SYNTHETIC.camera_sn),  # outside the window
    ]
    rows = await station.async_list_recordings()
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in rows] == [3, 4]
    assert [q["start_date"] for q in fake.history_queries] == [
        today.strftime("%Y%m%d"),
        yesterday.strftime("%Y%m%d"),
    ]
    assert await station.async_list_recordings(SYNTHETIC.camera_sn, days=1) == rows[:1]


async def test_recordings_since_skip_older_days_and_rows(
    station: Station, fake: FakeStation
) -> None:
    today = datetime.now().astimezone()
    fake.rows = [_row(today, 30, SYNTHETIC.camera_sn), _row(today, 10, SYNTHETIC.camera_sn)]
    since = today.replace(hour=12, minute=20, second=0, microsecond=0)
    rows = await station.async_list_recordings(days=7, since=since)
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in rows] == [30]
    assert [q["start_date"] for q in fake.history_queries] == [today.strftime("%Y%m%d")]


async def test_recordings_refuse_bad_arguments_and_standalone_lists_none(
    station: Station, fake: FakeStation
) -> None:
    with pytest.raises(ValueError, match="days"):
        await station.async_list_recordings(days=0)
    with pytest.raises(ValueError, match="limit"):
        await station.async_list_recordings(limit=0)
    with pytest.raises(ValueError, match="no day"):
        await station.async_list_recordings(before=42)
    with pytest.raises(UnsupportedError, match="not paired"):
        await station.async_list_recordings(OTHER_SN)
    with pytest.raises(UnsupportedError, match="no day"):
        await station.async_history_record(42)
    assert not fake.history_queries


async def test_a_recordings_page_stops_at_its_limit_and_goes_on_from_its_last_row(
    station: Station, fake: FakeStation
) -> None:
    today = datetime.now().astimezone()
    days = [today - timedelta(days=n) for n in range(4)]
    fake.rows = [
        _row(days[0], 9, SYNTHETIC.camera_sn),
        _row(days[0], 8, OTHER_SN),  # not this camera: not counted
        _row(days[0], 7, SYNTHETIC.camera_sn),
        _row(days[0], 6, SYNTHETIC.camera_sn),
        _row(days[2], 5, SYNTHETIC.camera_sn),
        _row(days[3], 4, SYNTHETIC.camera_sn),  # outside a 3-day window
    ]

    def stamps() -> list[str]:
        asked = [q["start_date"] for q in fake.history_queries]
        fake.history_queries.clear()
        return asked

    def day(n: int) -> str:
        return days[n].strftime("%Y%m%d")

    sn = SYNTHETIC.camera_sn
    page = await station.async_list_recordings(sn, days=3, limit=2)
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in page] == [9, 7]
    assert stamps() == [day(0)]  # day 1 not asked

    page = await station.async_list_recordings(sn, days=3, limit=2, before=page[-1].record_id)
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in page] == [6, 5]
    assert stamps() == [day(0), day(1), day(2)]

    page = await station.async_list_recordings(sn, days=3, limit=2, before=page[-1].record_id)
    assert page == []  # short: the window is exhausted, the day before it not asked
    assert stamps() == [day(2)]


async def test_a_recordings_page_pages_a_busy_day_only_until_the_limit(
    station: Station, fake: FakeStation
) -> None:
    today = datetime.now().astimezone()
    fake.rows = [_row(today, n, OTHER_SN) for n in range(40, 100)]
    fake.rows += [_row(today, n, SYNTHETIC.camera_sn) for n in range(100, 110)]
    fake.rows += [_row(today, n, SYNTHETIC.camera_sn) for n in range(1, 40)]
    page = await station.async_list_recordings(SYNTHETIC.camera_sn, limit=5)
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in page] == [109, 108, 107, 106, 105]
    assert len(fake.history_queries) == 1  # one page of 50 held them


def test_a_recording_settles_once_its_end_is_quiet() -> None:
    end = datetime(2026, 10, 1, 12, 0, 10).astimezone()
    start = "2026-10-01 12:00:00"  # hygiene: ok
    rec = HistoryRecord.from_row(
        {"record_id": 1, "start_time": start, "end_time": end.strftime(FORMAT)}
    )
    just_before = end + timedelta(seconds=RECORDING_QUIET - 1)
    assert not Station.recording_settled(rec, now=just_before)
    assert Station.recording_settled(rec, now=end + timedelta(seconds=RECORDING_QUIET))
    assert not Station.recording_settled(HistoryRecord(record_id=1))


async def test_a_downloaded_recording_carries_its_record_and_completeness(
    station: Station, fake: FakeStation
) -> None:
    fake.recording_frames = 6
    today = datetime.now().astimezone()
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    chunks: list[bytes] = []

    async def write(chunk: bytes) -> None:
        chunks.append(chunk)

    clip = await station.async_download_recording(record, write)
    assert b"".join(chunks)[0] == 0x47
    assert len(b"".join(chunks)) % TS_PACKET_LEN == 0
    assert (clip.record_id, clip.device_sn) == (record.record_id, SYNTHETIC.camera_sn)
    assert clip.started_at == record.started_at
    assert (clip.video_frames, clip.expected_frames) == (6, 6)
    assert clip.complete
    opens = [o for o in fake.received if o["cmd"] == 1025]
    assert opens[0]["mChannel"] == 0
    assert record.video_path is not None
    assert record.video_path in str(opens[0]["payload"])


async def test_a_clip_that_grew_during_its_download_is_not_complete(
    station: Station, fake: FakeStation
) -> None:
    fake.recording_frames = 6
    today = datetime.now().astimezone()
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn, frame_num=40)]  # still recording

    async def write(_chunk: bytes) -> None:
        return None

    clip = await station.async_download_recording(record, write)
    assert clip.expected_frames == 40
    assert not clip.complete


@pytest.mark.parametrize(
    ("row", "match"),
    [
        ({"record_id": 1, "device_sn": SYNTHETIC.camera_sn}, "no recording"),
        ({"record_id": 1, "storage_path": "/zx/a.zxvideo"}, "names no camera"),
        ({"record_id": 1, "device_sn": OTHER_SN, "storage_path": "/zx/a.zxvideo"}, "not paired"),
    ],
)
async def test_a_record_without_a_downloadable_clip_is_refused_before_sending(
    station: Station, fake: FakeStation, row: dict[str, object], match: str
) -> None:
    async def write(_chunk: bytes) -> None:
        raise AssertionError("nothing is written")

    with pytest.raises(UnsupportedError, match=match):
        await station.async_download_recording(HistoryRecord.from_row(row), write)
    assert fake.sessions == 0
