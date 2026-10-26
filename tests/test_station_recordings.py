"""A station's recordings: listing them from the history, and downloading one as a clip."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import Any

import pytest

import eufy_home_security.station as station_mod
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import HistoryRecord
from eufy_home_security.exceptions import (
    DeviceTimeoutError,
    RecordingCursorError,
    UnsupportedError,
)
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.recordings import RecordingPosition, RecordingsPage, encode_cursor
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
#: The tests' reference time; the station's clock is frozen to it (see ``today``).
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)  # hygiene: ok


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


class _AnyDatetime(type):
    """Keeps ``isinstance(x, datetime)`` true in the station module while it is patched."""

    def __instancecheck__(cls, obj: object) -> bool:
        return isinstance(obj, datetime)


@pytest.fixture
def today(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """:data:`NOW`, host-local, with the station's clock frozen to it: rows built from it
    and the window the station asks for fall on the same days at any hour."""
    now = NOW.astimezone()

    class Frozen(datetime, metaclass=_AnyDatetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
            return now if tz is None else now.astimezone(tz)

    monkeypatch.setattr(station_mod, "datetime", Frozen)
    return now


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
    station: Station, fake: FakeStation, today: datetime
) -> None:
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
    station: Station, fake: FakeStation, today: datetime
) -> None:
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
    station: Station, fake: FakeStation, today: datetime
) -> None:
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
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [_row(today, n, OTHER_SN) for n in range(40, 100)]
    fake.rows += [_row(today, n, SYNTHETIC.camera_sn) for n in range(100, 110)]
    fake.rows += [_row(today, n, SYNTHETIC.camera_sn) for n in range(1, 40)]
    page = await station.async_list_recordings(SYNTHETIC.camera_sn, limit=5)
    assert [r.record_id % HISTORY_RECORD_COUNTER for r in page] == [109, 108, 107, 106, 105]
    assert len(fake.history_queries) == 1  # one page of 50 held them


@pytest.fixture
def four_days(fake: FakeStation, today: datetime) -> list[datetime]:
    """Today and the three days before it (host-local), two camera rows on each."""
    days = [today - timedelta(days=n) for n in range(4)]
    fake.rows = [
        _row(d, c, SYNTHETIC.camera_sn)
        for n, d in enumerate(days)
        for c in (20 - 2 * n, 19 - 2 * n)
    ]
    return days


def _counters(rows: list[HistoryRecord]) -> list[int]:
    return [r.record_id % HISTORY_RECORD_COUNTER for r in rows]


def _asked(fake: FakeStation) -> list[str]:
    asked = [q["start_date"] for q in fake.history_queries]
    fake.history_queries.clear()
    return asked


async def test_recordings_until_a_day_list_that_day_and_older(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    rows = await station.async_list_recordings(days=4, until=four_days[1].date())
    assert _counters(rows) == [18, 17, 16, 15, 14, 13]
    assert _asked(fake) == [d.strftime("%Y%m%d") for d in four_days[1:]]

    page = await station.async_list_recordings(days=4, until=four_days[1], limit=3)
    assert _counters(page) == [18, 17, 16]  # a datetime counts as its day
    assert _asked(fake) == [four_days[1].strftime("%Y%m%d"), four_days[2].strftime("%Y%m%d")]


async def test_recordings_before_wins_over_until(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    newest = four_days[0].strftime("%Y%m%d")
    before = int(newest) * HISTORY_RECORD_COUNTER + 20
    rows = await station.async_list_recordings(
        days=4, limit=2, before=before, until=four_days[2].date()
    )
    assert _counters(rows) == [19, 18]
    assert _asked(fake)[0] == newest


async def test_recordings_until_outside_the_window(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    """``days`` counts from today: an ``until`` before the window lists nothing; a day
    after today lists from today."""
    assert await station.async_list_recordings(days=2, until=four_days[2].date()) == []
    assert _asked(fake) == []
    later = (four_days[0] + timedelta(days=3)).date()
    rows = await station.async_list_recordings(days=1, until=later)
    assert _counters(rows) == [20, 19]
    assert _asked(fake) == [four_days[0].strftime("%Y%m%d")]


def _cursor(position: RecordingPosition, device_sn: str | None = SYNTHETIC.camera_sn) -> str:
    return encode_cursor(position, station_sn=SYNTHETIC.station_sn, device_sn=device_sn)


def _day(day: datetime) -> str:
    return day.strftime("%Y%m%d")


async def test_recordings_pages_go_on_from_the_last_row_within_page_days(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    sn = SYNTHETIC.camera_sn
    page = await station.async_list_recordings_page(sn, days=4, limit=3, page_days=2)
    assert _counters(list(page.rows)) == [20, 19, 18]
    assert _asked(fake) == [_day(four_days[0]), _day(four_days[1])]
    assert page.next_cursor == _cursor(
        RecordingPosition(four_days[1].date(), page.rows[-1].record_id)
    )

    page = await station.async_list_recordings_page(
        sn, days=4, limit=3, page_days=2, cursor=page.next_cursor
    )
    assert _counters(list(page.rows)) == [17, 16, 15]  # from its row, two days at most
    assert _asked(fake) == [_day(four_days[1]), _day(four_days[2])]
    assert fake.history_queries == []

    page = await station.async_list_recordings_page(
        sn, days=4, limit=3, page_days=2, cursor=page.next_cursor
    )
    assert _counters(list(page.rows)) == [14, 13]
    assert page.next_cursor is None  # short, and the window ends with it
    assert _asked(fake) == [_day(four_days[2]), _day(four_days[3])]


async def test_a_short_page_with_window_days_left_names_the_next_day(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    cursor = None
    pages: list[list[int]] = []
    cursors: list[str | None] = []
    for _ in range(4):
        page = await station.async_list_recordings_page(days=4, limit=5, page_days=1, cursor=cursor)
        pages.append(_counters(list(page.rows)))
        cursors.append(cursor := page.next_cursor)
    assert pages == [[20, 19], [18, 17], [16, 15], [14, 13]]
    assert cursors == [
        *(_cursor(RecordingPosition(d.date()), None) for d in four_days[1:]),
        None,
    ]
    assert _asked(fake) == [_day(d) for d in four_days]


async def test_a_page_without_page_days_asks_the_whole_window_and_until_starts_it(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    page = await station.async_list_recordings_page(days=4, limit=10, until=four_days[1])
    assert page == RecordingsPage(tuple(page.rows), None)
    assert _counters(list(page.rows)) == [18, 17, 16, 15, 14, 13]
    assert _asked(fake) == [_day(d) for d in four_days[1:]]
    cursor = _cursor(RecordingPosition(four_days[2].date()), None)
    page = await station.async_list_recordings_page(
        days=4, limit=10, until=four_days[0].date(), cursor=cursor
    )
    assert _counters(list(page.rows)) == [16, 15, 14, 13]  # the cursor wins over until
    assert _asked(fake) == [_day(d) for d in four_days[2:]]


async def test_a_cursor_after_today_lists_from_today(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    """A row of a later station day than the host's today: the walk starts at today."""
    later = four_days[0] + timedelta(days=1)
    cursor = _cursor(
        RecordingPosition.after(int(_day(later)) * HISTORY_RECORD_COUNTER + 5, date.min)
    )
    page = await station.async_list_recordings_page(
        SYNTHETIC.camera_sn, days=1, limit=5, cursor=cursor
    )
    assert _counters(list(page.rows)) == [20, 19]
    assert _asked(fake) == [_day(four_days[0])]


async def test_a_cursor_before_the_window_lists_nothing(
    station: Station, fake: FakeStation, four_days: list[datetime]
) -> None:
    cursor = _cursor(RecordingPosition(four_days[2].date()), None)
    page = await station.async_list_recordings_page(days=2, limit=5, cursor=cursor)
    assert page == RecordingsPage((), None)
    assert _asked(fake) == []


@pytest.mark.parametrize("record_id", [0, -5])
async def test_a_full_page_of_rows_without_an_id_goes_on_from_the_day_before(
    station: Station, fake: FakeStation, today: datetime, record_id: int
) -> None:
    """An id of 0 or below cannot be paged from: no row cursor names it."""
    fake.rows = [_row(today, 5, SYNTHETIC.camera_sn, record_id=record_id)]
    day_before = (today - timedelta(days=1)).date()
    page = await station.async_list_recordings_page(SYNTHETIC.camera_sn, days=2, limit=1)
    assert page.next_cursor == _cursor(RecordingPosition(day_before))
    page = await station.async_list_recordings_page(SYNTHETIC.camera_sn, days=1, limit=1)
    assert len(page.rows) == 1
    assert page.next_cursor is None  # the day before lies outside the window


async def test_a_full_page_ending_on_rows_without_an_id_goes_on_after_its_last_id(
    station: Station, monkeypatch: pytest.MonkeyPatch, today: datetime
) -> None:
    """The rows after the page's last row with an id may come again; none of that day's
    older rows is skipped."""
    day = today.date()
    ids = [int(_day(today)) * HISTORY_RECORD_COUNTER + n for n in (9, 8)]
    listed = [(day, HistoryRecord(record_id=i)) for i in ids]
    listed += [(day, HistoryRecord(record_id=0)), (day, HistoryRecord(record_id=-3))]

    async def by_day(*_args: object, **_kwargs: object) -> list[tuple[date, HistoryRecord]]:
        return listed

    monkeypatch.setattr(station.session, "async_list_history_by_day", by_day)
    page = await station.async_list_recordings_page(SYNTHETIC.camera_sn, limit=4)
    assert page.rows == tuple(row for _day, row in listed)
    assert page.next_cursor == _cursor(RecordingPosition(day, ids[1]))


@pytest.fixture
async def two_cameras(fake: FakeStation) -> AsyncIterator[Station]:
    """A station with :data:`CAMERA` and a second camera (:data:`OTHER_SN`) paired."""

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    second = dataclasses.replace(CAMERA, device_sn=OTHER_SN, name="Back", channel=1)
    st = Station(STATION, session, sub_devices=[CAMERA, second])
    yield st
    await st.async_close()


async def test_a_camera_page_lists_only_that_camera_of_two_paired(
    two_cameras: Station, fake: FakeStation, today: datetime
) -> None:
    sn = SYNTHETIC.camera_sn
    fake.rows = [_row(today, n, sn if n % 2 else OTHER_SN) for n in range(10, 0, -1)]
    page = await two_cameras.async_list_recordings_page(sn, days=1, limit=3)
    assert _counters(list(page.rows)) == [9, 7, 5]
    page = await two_cameras.async_list_recordings_page(
        sn, days=1, limit=3, cursor=page.next_cursor
    )
    assert _counters(list(page.rows)) == [3, 1]
    page = await two_cameras.async_list_recordings_page(days=1, limit=3)
    assert _counters(list(page.rows)) == [10, 9, 8]  # both are paired


@pytest.mark.parametrize(
    ("cursor", "device_sn"),
    [
        ("garbled", SYNTHETIC.camera_sn),
        (str(20260916 * HISTORY_RECORD_COUNTER + 3), SYNTHETIC.camera_sn),  # a bare record id
        (_cursor(RecordingPosition(date(2026, 9, 16)), None), SYNTHETIC.camera_sn),
        (_cursor(RecordingPosition(date(2026, 9, 16))), None),
        (_cursor(RecordingPosition(date(2026, 9, 16))), OTHER_SN),  # refused before pairing
    ],
)
async def test_a_page_cursor_that_does_not_check_out_is_refused_before_sending(
    station: Station, fake: FakeStation, cursor: str, device_sn: str | None
) -> None:
    with pytest.raises(RecordingCursorError):
        await station.async_list_recordings_page(device_sn, limit=5, cursor=cursor)
    assert fake.sessions == 0
    assert not fake.history_queries


@pytest.mark.parametrize(
    ("args", "match"),
    [((0, 1, None), "limit"), ((5, 0, None), "days"), ((5, 1, 0), "page_days")],
)
async def test_a_page_refuses_bad_arguments_before_sending(
    station: Station, fake: FakeStation, args: tuple[int, int, int | None], match: str
) -> None:
    limit, days, page_days = args
    with pytest.raises(ValueError, match=match):
        await station.async_list_recordings_page(limit=limit, days=days, page_days=page_days)
    assert fake.sessions == 0


async def test_a_standalone_device_pages_no_recordings() -> None:
    device = CloudDevice(
        device_sn=SYNTHETIC.camera_sn,
        station_sn=SYNTHETIC.camera_sn,
        p2p_did=SYNTHETIC.did,
        device_type=48,
        channel=0,
        name="standalone",
    )

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("nothing connects")

    session = StationSession(SYNTHETIC.camera_sn, credentials, host="127.0.0.1", port=9)
    standalone = Station(device, session)
    try:
        page = await standalone.async_list_recordings_page(limit=5)
    finally:
        await standalone.async_close()
    assert page == RecordingsPage((), None)


HB2_SN = "T8010P2000054321"


async def test_a_homebase_2_pages_its_sequential_ids_by_their_station_day(
    fake: FakeStation, today: datetime
) -> None:
    """Ids without a day: the cursor carries the day its query named, so the next page
    starts in that day below the row, without repeating or skipping rows."""
    fake.serial = HB2_SN
    fake.static_key = static_key(HB2_SN, fake.did)

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    day_before = today - timedelta(days=1)
    sn = SYNTHETIC.camera_sn
    fake.rows = [_row(today, n, sn, record_id=n) for n in (7, 6)]
    fake.rows += [_row(day_before, n, sn, record_id=n) for n in (5, 4, 3)]
    session = StationSession(HB2_SN, credentials, host="127.0.0.1", port=fake.discovery_port)
    hb2 = Station(
        dataclasses.replace(STATION, device_sn=HB2_SN),
        session,
        sub_devices=[dataclasses.replace(CAMERA, station_sn=HB2_SN)],
    )
    try:
        first = await hb2.async_list_recordings_page(sn, days=2, limit=3)
        asked_first = _asked(fake)
        second = await hb2.async_list_recordings_page(sn, days=2, limit=3, cursor=first.next_cursor)
    finally:
        await hb2.async_close()
    assert [r.record_id for r in first.rows] == [7, 6, 5]
    assert asked_first == [_day(today), _day(day_before)]
    assert first.next_cursor == encode_cursor(
        RecordingPosition(day_before.date(), 5), station_sn=HB2_SN, device_sn=sn
    )
    assert [r.record_id for r in second.rows] == [4, 3]
    assert second.next_cursor is None
    assert _asked(fake) == [_day(day_before)]


async def test_recordings_timeout_bounds_each_history_query(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    send = station.session._send_secure
    asked: list[bytes] = []

    def drop_history(plaintext: bytes, **kwargs: Any) -> int:
        if b"start_id" not in plaintext:
            return send(plaintext, **kwargs)
        asked.append(plaintext)
        return 1

    monkeypatch.setattr(station.session, "_send_secure", drop_history)
    async with asyncio.timeout(3.0):  # the default would wait 15 s per query
        with pytest.raises(DeviceTimeoutError):
            await station.async_list_recordings(timeout=0.2)
    assert len(asked) == 2  # the page asked once more, then the error


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
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.recording_frames = 6
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
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.recording_frames = 6
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
