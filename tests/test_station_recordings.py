"""A station's recordings: listing them from the history, and downloading one as a clip."""

from __future__ import annotations

import asyncio
import dataclasses
import gc
import logging
import os
import time
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from typing import Any

import pytest

import eufy_home_security.station as station_module
import eufy_home_security.station.history as station_history
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.support import Support
from eufy_home_security.devices.timezones import encode_zone
from eufy_home_security.events import EventSource, HistoryRecord, SecurityEvent
from eufy_home_security.exceptions import (
    DeviceTimeoutError,
    RecordingCursorError,
    RecordingRefError,
    RecordNotFoundError,
    StationUnreachableError,
    UnsupportedError,
)
from eufy_home_security.images import ImageSource
from eufy_home_security.p2p.clip import ClipWriter, MediaClip
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.recordings import (
    DetectionRecording,
    DetectionRecordingState,
    RecordingPosition,
    RecordingRef,
    RecordingsPage,
    encode_cursor,
    encode_ref,
)
from eufy_home_security.station import (
    RECORDING_MATCH_GIVE_UP,
    RECORDING_MATCH_RETRY,
    RECORDING_MATCH_WINDOW,
    RECORDING_QUIET,
    Station,
)
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
SAST = timezone(timedelta(hours=2))
"""Africa/Johannesburg's offset (it keeps no daylight saving)."""
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
    """Keeps ``isinstance(x, datetime)`` true in the history module while it is patched."""

    def __instancecheck__(cls, obj: object) -> bool:
        return isinstance(obj, datetime)


@pytest.fixture
def today(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """:data:`NOW`, host-local, with the station's clock frozen to it: rows built from it
    and the window the station asks for fall on the same days at any hour."""
    return _freeze(monkeypatch, NOW)


def _freeze(monkeypatch: pytest.MonkeyPatch, moment: datetime) -> datetime:
    """Freeze the station's clock to ``moment``; returns it host-local."""
    now = moment.astimezone()

    class Frozen(datetime, metaclass=_AnyDatetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
            return now if tz is None else now.astimezone(tz)

    monkeypatch.setattr(station_history, "datetime", Frozen)
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


HB2_SN = SYNTHETIC.homebase2_station_sn


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
        assert fake.history_queries
        assert all(q["device_info"] == [{"device_sn": sn}] for q in fake.history_queries), (
            "both pages must filter at the station for this camera"
        )
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


@pytest.fixture
async def hb2(fake: FakeStation) -> AsyncIterator[Station]:
    """A HomeBase 2 (ids without a day, paged by start time) with two cameras."""
    fake.serial = HB2_SN
    fake.static_key = static_key(HB2_SN, fake.did)

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(HB2_SN, credentials, host="127.0.0.1", port=fake.discovery_port)
    st = Station(
        dataclasses.replace(STATION, device_sn=HB2_SN),
        session,
        sub_devices=[
            dataclasses.replace(CAMERA, station_sn=HB2_SN),
            dataclasses.replace(CAMERA, device_sn=OTHER_SN, station_sn=HB2_SN, channel=1),
        ],
    )
    yield st
    await st.async_close()


def _hb2_rows(today: datetime) -> list[dict[str, object]]:
    day_before = today - timedelta(days=1)
    rows = [_row(today, n, SYNTHETIC.camera_sn, record_id=n) for n in (9, 7)]
    rows.append(_row(today, 8, OTHER_SN, record_id=8))
    rows += [_row(day_before, n, SYNTHETIC.camera_sn, record_id=n) for n in (5, 4)]
    return rows


async def test_a_homebase_2_recording_is_found_by_its_ref_with_one_query_of_its_day(
    hb2: Station, fake: FakeStation, today: datetime
) -> None:
    """Every listed row of both cameras comes back by its ref, each with one query of the
    station day it was listed under, the row and its ref unchanged."""
    fake.rows = _hb2_rows(today)
    page = await hb2.async_list_recordings_page(days=2, limit=10)
    fake.history_queries.clear()
    assert [r.record_id for r in page.rows] == [9, 8, 7, 5, 4]
    for row in page.rows:
        assert row.ref is not None
        found = await hb2.async_history_record_by_ref(row.ref)
        assert (found, found.ref) == (row, row.ref)
        assert fake.history_queries[-1]["device_info"] == [{"device_sn": row.device_sn}]
        listed_day = today if row.record_id > 5 else today - timedelta(days=1)
        assert _asked(fake) == [_day(listed_day)]
    fake.history_queries.clear()
    camera_rows = await hb2.async_list_recordings(OTHER_SN)
    assert fake.history_queries
    assert all(q["device_info"] == [{"device_sn": OTHER_SN}] for q in fake.history_queries)
    assert camera_rows[0].ref == page.rows[1].ref
    found = await hb2.async_history_record_by_ref(camera_rows[0].ref or "", device_sn=OTHER_SN)
    assert found == camera_rows[0]


async def test_a_ref_that_does_not_check_out_is_refused_before_sending(
    hb2: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = _hb2_rows(today)
    page = await hb2.async_list_recordings_page(days=1, limit=10)
    fake.history_queries.clear()
    other_camera = page.rows[1]
    assert other_camera.device_sn == OTHER_SN
    assert other_camera.ref is not None
    with pytest.raises(RecordingRefError, match="does not check out"):
        await hb2.async_history_record_by_ref(other_camera.ref, device_sn=SYNTHETIC.camera_sn)
    another_station = encode_ref(
        RecordingRef(today.date(), 9, SYNTHETIC.camera_sn, "20260916120900"),
        station_sn=SYNTHETIC.station_sn,
    )
    for text in (another_station, page.next_cursor or "v1.d", "9", other_camera.ref[:-1] + "x"):
        with pytest.raises(RecordingRefError):
            await hb2.async_history_record_by_ref(text)
    with pytest.raises(UnsupportedError, match="not paired"):
        await hb2.async_history_record_by_ref(other_camera.ref, device_sn="T8160P2000011111")
    assert fake.history_queries == []


async def test_a_ref_whose_recording_is_gone_raises_not_found(
    hb2: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = _hb2_rows(today)
    page = await hb2.async_list_recordings_page(days=1, limit=10)
    fake.rows = [row for row in fake.rows if row["record_id"] != 7]
    fake.history_queries.clear()
    with pytest.raises(RecordNotFoundError, match="no such recording"):
        await hb2.async_history_record_by_ref(page.rows[2].ref or "")
    assert len(fake.history_queries) == 1


async def test_a_homebase_3_recording_is_found_by_its_ref_or_its_id(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [_row(today, n, SYNTHETIC.camera_sn) for n in (3, 2, 1)]
    rows = await station.async_list_recordings()
    fake.history_queries.clear()
    found = await station.async_history_record_by_ref(rows[1].ref or "")
    by_id = await station.async_history_record(rows[1].record_id)
    assert (found, found.ref) == (rows[1], rows[1].ref)
    assert by_id is not None
    assert by_id.ref == rows[1].ref
    assert [q["start_id"] for q in fake.history_queries] == [rows[1].record_id] * 2


async def test_a_lookup_by_ref_passes_its_timeout_to_the_query(
    station: Station, fake: FakeStation, today: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.rows = [_row(today, 3, SYNTHETIC.camera_sn)]
    (row,) = await station.async_list_recordings()
    find = station.session.async_find_history_record
    timeouts: list[float | None] = []

    async def spy(ref: RecordingRef, *, timeout: float | None = None) -> HistoryRecord:
        timeouts.append(timeout)
        return await find(ref, timeout=timeout)

    monkeypatch.setattr(station.session, "async_find_history_record", spy)
    await station.async_history_record_by_ref(row.ref or "", timeout=4.5)
    assert timeouts == [4.5]


async def test_a_station_row_of_the_station_itself_is_found_by_its_ref(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [_row(today, 4, SYNTHETIC.station_sn, storage_path="")]  # an arming row
    rows = await station.async_list_history(_day(today))
    found = await station.async_history_record_by_ref(rows[0].ref or "")
    assert (found, found.ref) == (rows[0], rows[0].ref)


async def test_a_history_listing_passes_its_options_to_the_session(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [_row(today, 4, SYNTHETIC.camera_sn), _row(today, 3, SYNTHETIC.camera_sn)]
    assert len(await station.async_list_history(_day(today))) == 2
    assert len(await station.async_list_history(_day(today), count=1)) == 1


async def test_a_standalone_device_finds_no_recording_by_ref() -> None:
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
    ref = encode_ref(
        RecordingRef(NOW.date(), 7, SYNTHETIC.camera_sn, "20260916120000"),
        station_sn=SYNTHETIC.camera_sn,
    )
    try:
        with pytest.raises(UnsupportedError, match="standalone"):
            await standalone.async_history_record_by_ref(ref)
    finally:
        await standalone.async_close()


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


@pytest.mark.parametrize("transfer", ["async_download_recording", "async_play_recording"])
async def test_a_transferred_recording_carries_its_record_and_completeness(
    station: Station, fake: FakeStation, today: datetime, transfer: str
) -> None:
    fake.recording_frames = 6
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    chunks: list[bytes] = []

    async def write(chunk: bytes) -> None:
        chunks.append(chunk)

    clip = await getattr(station, transfer)(record, write)
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


@pytest.mark.parametrize("transfer", ["async_download_recording", "async_play_recording"])
async def test_a_clip_that_grew_during_its_transfer_is_not_complete(
    station: Station, fake: FakeStation, today: datetime, transfer: str
) -> None:
    fake.recording_frames = 6
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn, frame_num=40)]  # still recording

    async def write(_chunk: bytes) -> None:
        return None

    clip = await getattr(station, transfer)(record, write)
    assert clip.expected_frames == 40
    assert not clip.complete


async def test_a_download_passes_wait_to_the_session(
    station: Station, fake: FakeStation, today: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.recording_frames = 6
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    download = station.session.async_download_recording
    waits: list[bool] = []

    async def spy(path: str, channel: int, write: ClipWriter, *, wait: bool = True) -> MediaClip:
        waits.append(wait)
        return await download(path, channel, write, wait=wait)

    async def write(_chunk: bytes) -> None:
        return None

    monkeypatch.setattr(station.session, "async_download_recording", spy)
    await station.async_download_recording(record, write, wait=False)
    assert waits == [False]


async def test_a_play_passes_wait_and_realtime_to_the_session(
    station: Station, fake: FakeStation, today: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.rows = [_row(today, 7, SYNTHETIC.camera_sn)]
    (record,) = await station.async_list_recordings()
    play = station.session.async_play_recording
    calls: list[tuple[str, int, bool, bool]] = []

    async def spy(
        path: str, channel: int, write: ClipWriter, *, wait: bool = True, realtime: bool = True
    ) -> MediaClip:
        calls.append((path, channel, wait, realtime))
        return await play(path, channel, write, wait=wait, realtime=realtime)

    async def write(_chunk: bytes) -> None:
        return None

    monkeypatch.setattr(station.session, "async_play_recording", spy)
    await station.async_play_recording(record, write, wait=False, realtime=False)
    await station.async_play_recording(record, write)
    assert calls == [(record.video_path, 0, False, False), (record.video_path, 0, True, True)]


@pytest.mark.parametrize(
    ("row", "match"),
    [
        ({"record_id": 1, "device_sn": SYNTHETIC.camera_sn}, "no recording"),
        ({"record_id": 1, "storage_path": "/zx/a.zxvideo"}, "names no camera"),
        ({"record_id": 1, "device_sn": OTHER_SN, "storage_path": "/zx/a.zxvideo"}, "not paired"),
    ],
)
@pytest.mark.parametrize("transfer", ["async_download_recording", "async_play_recording"])
async def test_a_record_without_a_downloadable_clip_is_refused_before_sending(
    station: Station, fake: FakeStation, row: dict[str, object], match: str, transfer: str
) -> None:
    async def write(_chunk: bytes) -> None:
        raise AssertionError("nothing is written")

    with pytest.raises(UnsupportedError, match=match):
        await getattr(station, transfer)(HistoryRecord.from_row(row), write)
    assert fake.sessions == 0


async def test_a_10011_station_does_not_offer_native_dat_clips(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [
        _row(
            today,
            8,
            SYNTHETIC.camera_sn,
            storage_path="/media/mmcblk0p1/Camera05/20310203112233.dat",
        ),
        _row(today, 7, SYNTHETIC.camera_sn),
    ]
    rows = await station.async_list_recordings(SYNTHETIC.camera_sn, days=1)
    assert len(rows) == 1
    assert rows[0].record_id == int(today.strftime("%Y%m%d")) * HISTORY_RECORD_COUNTER + 7
    page = await station.async_list_recordings_page(SYNTHETIC.camera_sn, days=1, limit=10)
    assert [r.record_id for r in page.rows] == [rows[0].record_id]


async def test_local_events_station_filters_camera(
    hb2: Station, fake: FakeStation, today: datetime
) -> None:
    fake.rows = [
        {
            "record_id": 47051,
            "device_sn": SYNTHETIC.camera_sn,
            "start_time": today.strftime(FORMAT),
            "storage_path": "/media/mmcblk0p1/Camera05/20310203112233.dat",
            "frame_num": 6,
        }
    ]
    rows = await hb2.async_list_recordings(SYNTHETIC.camera_sn, days=1)
    assert [r.record_id for r in rows] == [47051]
    assert fake.history_queries[0]["device_info"] == [{"device_sn": SYNTHETIC.camera_sn}]


# ── the recording of a detection ─────────────────────────────────────────────


def _at(start: datetime, device_sn: str, record_id: int, **extra: object) -> dict[str, object]:
    """A recording row that started at ``start`` (host-local whole seconds) and ran 20 s."""
    local = start.astimezone()
    return {
        "record_id": record_id,
        "device_sn": device_sn,
        "start_time": local.strftime(FORMAT),
        "end_time": (local + timedelta(seconds=20)).strftime(FORMAT),
        "storage_path": f"/zx/hdd_data0/Camera00/{record_id}.zxvideo",
        "frame_num": 6,
        **extra,
    }


def _dayed(start: datetime, counter: int) -> int:
    """A HomeBase 3 record id: the row's host-local day and a counter."""
    return int(start.astimezone().strftime("%Y%m%d")) * HISTORY_RECORD_COUNTER + counter


def _detection(at: datetime, **fields: Any) -> SecurityEvent:
    """A cloud-push motion detection of the camera at ``at``, naming no recording."""
    values: dict[str, Any] = {
        "source": EventSource.CLOUD,
        "device_sn": SYNTHETIC.camera_sn,
        "msg_type": 1,
        "event_type": 3101,
        "event_time_ms": round(at.timestamp() * 1000),
    }
    values.update(fields)
    return SecurityEvent(**values)


def _whole(now: datetime, seconds_ago: float) -> datetime:
    """``seconds_ago`` before ``now``, on a whole second (history rows keep no fractions)."""
    return (now - timedelta(seconds=seconds_ago)).replace(microsecond=0)


async def test_a_detection_finds_its_settled_recording_by_camera_and_start_time(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 120)
    fake.rows = [_at(started, SYNTHETIC.camera_sn, _dayed(started, 4))]
    found = await station.async_recording_for_detection(_detection(started + timedelta(seconds=2)))
    assert found == DetectionRecording(
        state=DetectionRecordingState.SETTLED,
        record=HistoryRecord.from_row(fake.rows[0]),
        retry_at=None,
        offset_s=-2.0,
    )
    assert found.record is not None
    assert found.record.ref is not None


async def test_a_detection_whose_recording_still_runs_says_when_it_settles(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 30)  # ended 10 s ago: settles RECORDING_QUIET after its end
    fake.rows = [_at(started, SYNTHETIC.camera_sn, _dayed(started, 4))]
    found = await station.async_recording_for_detection(_detection(started))
    assert found.state is DetectionRecordingState.RECORDING
    assert found.record == HistoryRecord.from_row(fake.rows[0])
    assert found.retry_at == started + timedelta(seconds=20 + RECORDING_QUIET)
    shorter = await station.async_recording_for_detection(_detection(started), quiet=5.0)
    assert shorter.state is DetectionRecordingState.SETTLED


async def test_a_running_recording_without_an_end_time_is_asked_again_after_the_retry(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 30)
    fake.rows = [_at(started, SYNTHETIC.camera_sn, _dayed(started, 4), end_time="")]
    found = await station.async_recording_for_detection(_detection(started))
    assert found.state is DetectionRecordingState.RECORDING
    assert found.retry_at == today + timedelta(seconds=RECORDING_MATCH_RETRY)


@pytest.mark.parametrize(
    ("seconds_ago", "retry_in"),
    [
        (20.0, RECORDING_MATCH_RETRY),  # asked again after the retry
        (RECORDING_MATCH_GIVE_UP - 5.0, 5.0),  # no later than the give-up time
        (RECORDING_MATCH_GIVE_UP, None),  # given up
        (RECORDING_MATCH_GIVE_UP + 60.0, None),
    ],
)
async def test_a_detection_with_no_recording_listed_yet_is_asked_again_until_its_bound(
    station: Station, fake: FakeStation, today: datetime, seconds_ago: float, retry_in: float | None
) -> None:
    fake.rows = []
    found = await station.async_recording_for_detection(
        _detection(today - timedelta(seconds=seconds_ago))
    )
    assert found.state is DetectionRecordingState.NOT_LISTED
    assert (found.record, found.offset_s) == (None, None)
    expected = None if retry_in is None else today + timedelta(seconds=retry_in)
    assert found.retry_at == expected


@pytest.mark.usefixtures("no_reuse")
async def test_of_two_recordings_in_the_window_the_closest_start_wins_and_a_tie_the_earlier(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    event = _whole(today, 300)
    before, after, closest = (event + timedelta(seconds=s) for s in (-4, 4, 2))
    fake.rows = [
        _at(closest, SYNTHETIC.camera_sn, _dayed(closest, 3)),
        _at(after, SYNTHETIC.camera_sn, _dayed(after, 2)),
        _at(before, SYNTHETIC.camera_sn, _dayed(before, 1)),
    ]
    found = await station.async_recording_for_detection(_detection(event))
    assert found.record is not None
    assert (found.record.record_id, found.offset_s) == (_dayed(closest, 3), 2.0)
    fake.rows = fake.rows[1:]  # 4 s before and 4 s after: the one that began first
    tie = await station.async_recording_for_detection(_detection(event))
    assert tie.record is not None
    assert (tie.record.record_id, tie.offset_s) == (_dayed(before, 1), -4.0)
    fake.rows = [_at(event, SYNTHETIC.camera_sn, _dayed(event, n)) for n in (8, 9)]
    same = await station.async_recording_for_detection(_detection(event))  # one start second
    assert same.record is not None
    assert same.record.record_id == _dayed(event, 8)  # the lower record id


@pytest.mark.usefixtures("no_reuse")
async def test_a_recording_of_another_camera_is_never_a_detections(
    two_cameras: Station, fake: FakeStation, today: datetime
) -> None:
    event = _whole(today, 300)
    own = event + timedelta(seconds=6)
    fake.rows = [
        _at(event, OTHER_SN, _dayed(event, 2)),  # the closest start, but another camera's
        _at(own, SYNTHETIC.camera_sn, _dayed(own, 1)),
    ]
    found = await two_cameras.async_recording_for_detection(_detection(event))
    assert found.record is not None
    assert found.record.device_sn == SYNTHETIC.camera_sn
    fake.rows = fake.rows[:1]
    none = await two_cameras.async_recording_for_detection(_detection(event))
    assert none.state is DetectionRecordingState.NOT_LISTED


@pytest.mark.parametrize(("ends_after", "held"), [(0, True), (-1, False)])
async def test_a_detection_inside_a_running_clip_gets_that_clips_row(
    station: Station, fake: FakeStation, today: datetime, ends_after: int, held: bool
) -> None:
    """No row starts near a second detection inside one clip: the row that holds the
    detection's time (it ended at or after it) is the detection's."""
    early, _late = RECORDING_MATCH_WINDOW
    event = _whole(today, 300)
    older = event + timedelta(seconds=early - 40)
    clip = event + timedelta(seconds=early - 20)
    end = (event + timedelta(seconds=ends_after)).astimezone()
    fake.rows = [
        _at(clip, SYNTHETIC.camera_sn, _dayed(clip, 2), end_time=end.strftime(FORMAT)),
        _at(older, SYNTHETIC.camera_sn, _dayed(older, 1), end_time=""),
    ]
    found = await station.async_recording_for_detection(_detection(event))
    assert found.record is not None
    if held:
        assert found.record.record_id == _dayed(clip, 2)  # the latest start of those holding it
        assert found.offset_s == early - 20
    else:
        assert found.record.record_id == _dayed(older, 1)  # still running: it holds the event


async def test_a_detection_with_no_holding_or_near_row_is_not_listed(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    event = _whole(today, 300)
    before = event - timedelta(seconds=60)
    end = (event - timedelta(seconds=1)).astimezone()
    fake.rows = [_at(before, SYNTHETIC.camera_sn, _dayed(before, 1), end_time=end.strftime(FORMAT))]
    found = await station.async_recording_for_detection(_detection(event))
    assert found.state is DetectionRecordingState.NOT_LISTED


@pytest.mark.parametrize("bound", ["early", "late"])
@pytest.mark.parametrize("beyond", [0, 1])
async def test_a_recording_matches_only_within_the_window_bounds_included(
    station: Station, fake: FakeStation, today: datetime, bound: str, beyond: int
) -> None:
    early, late = RECORDING_MATCH_WINDOW
    event = _whole(today, 300)
    offset = early - beyond if bound == "early" else late + beyond
    start = event + timedelta(seconds=offset)
    end = (start + timedelta(seconds=5)).astimezone()  # over before the event
    fake.rows = [_at(start, SYNTHETIC.camera_sn, _dayed(start, 1), end_time=end.strftime(FORMAT))]
    found = await station.async_recording_for_detection(_detection(event))
    if beyond:
        assert found.state is DetectionRecordingState.NOT_LISTED
    else:
        assert found.state is DetectionRecordingState.SETTLED
        assert found.offset_s == offset


async def test_a_homebase_2_detection_finds_its_recording_through_paged_history(
    hb2: Station, fake: FakeStation, today: datetime
) -> None:
    """Ids without a day, paged by start time: newer recordings of the camera fill more
    than one page before the detection's own."""
    event = _whole(today, 600)
    newer = [
        _at(event + timedelta(seconds=60 + 10 * n), SYNTHETIC.camera_sn, 100 + n) for n in range(25)
    ]
    path = "/media/mmcblk0p1/Camera00/20260916120000.dat"  # hygiene: ok
    own = _at(event + timedelta(seconds=1), SYNTHETIC.camera_sn, 99, storage_path=path)
    fake.rows = [*newer, own, _at(event, OTHER_SN, 98)]
    found = await hb2.async_recording_for_detection(_detection(event, station_sn=HB2_SN))
    assert found.state is DetectionRecordingState.SETTLED
    assert found.record is not None
    assert (found.record.record_id, found.record.video_path) == (99, path)
    assert len(fake.history_queries) > 1
    assert all(
        q["device_info"] == [{"device_sn": SYNTHETIC.camera_sn}] for q in fake.history_queries
    )


async def test_a_detection_naming_its_record_id_is_looked_up_by_it(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 120)
    fake.rows = [_at(started, SYNTHETIC.camera_sn, _dayed(started, 4))]
    event = _detection(started, record_id=_dayed(started, 4), event_time_ms=None)
    found = await station.async_recording_for_detection(event)
    assert found.state is DetectionRecordingState.SETTLED
    assert found.record == HistoryRecord.from_row(fake.rows[0])
    assert found.offset_s is None
    assert [q["start_id"] for q in fake.history_queries] == [_dayed(started, 4)]


async def test_a_detection_naming_a_record_not_written_yet_is_asked_again(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 10)
    fake.rows = []
    found = await station.async_recording_for_detection(
        _detection(started, record_id=_dayed(started, 4))
    )
    assert found.state is DetectionRecordingState.NOT_LISTED
    assert found.retry_at == today + timedelta(seconds=RECORDING_MATCH_RETRY)


async def test_a_detection_whose_record_id_names_another_cameras_row_raises(
    two_cameras: Station, fake: FakeStation, today: datetime
) -> None:
    started = _whole(today, 120)
    fake.rows = [_at(started, OTHER_SN, _dayed(started, 4))]
    with pytest.raises(RecordNotFoundError, match="another camera"):
        await two_cameras.async_recording_for_detection(
            _detection(started, record_id=_dayed(started, 4))
        )


async def test_a_detection_naming_its_recording_path_takes_that_row_in_the_window(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    event = _whole(today, 300)
    named, closer = event + timedelta(seconds=-5), event
    fake.rows = [
        _at(closer, SYNTHETIC.camera_sn, _dayed(closer, 2)),
        _at(named, SYNTHETIC.camera_sn, _dayed(named, 1)),
    ]
    path = str(fake.rows[1]["storage_path"])
    found = await station.async_recording_for_detection(_detection(event, video_path=path))
    assert found.record is not None
    assert found.record.video_path == path


async def test_a_detection_that_cannot_be_matched_is_refused_before_sending(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    with pytest.raises(UnsupportedError, match="no time"):
        await station.async_recording_for_detection(_detection(today, event_time_ms=None))
    with pytest.raises(UnsupportedError, match="belongs to"):
        await station.async_recording_for_detection(_detection(today, station_sn=HB2_SN))
    with pytest.raises(UnsupportedError, match="no camera"):
        await station.async_recording_for_detection(
            _detection(today, device_sn="T8160P2000011111", channel=None)
        )
    assert fake.history_queries == []


async def test_a_standalone_device_refuses_to_match_a_detection() -> None:
    """A standalone camera lists no history, whatever its local-detection grade (a T8170
    has none recorded)."""
    solo_sn = "T8170P0000000000"
    device = CloudDevice(
        device_sn=solo_sn,
        station_sn=solo_sn,
        p2p_did=SYNTHETIC.did,
        device_type=48,
        channel=0,
        name="standalone",
    )

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("nothing connects")

    session = StationSession(solo_sn, credentials, host="127.0.0.1", port=9)
    standalone = Station(device, session)
    event = _detection(NOW, device_sn=solo_sn)
    try:
        assert standalone.local_detections_for(solo_sn).support is not Support.VERIFIED
        with pytest.raises(UnsupportedError, match="standalone"):
            await standalone.async_recording_for_detection(event)
        assert not standalone.needs_recording_match(event)
    finally:
        await standalone.async_close()


async def test_a_detection_match_bounds_each_history_query_by_its_timeout(
    station: Station, fake: FakeStation, today: datetime, monkeypatch: pytest.MonkeyPatch
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
            await station.async_recording_for_detection(_detection(today), timeout=0.2)
    assert len(asked) == 2  # the page asked once more, then the error


async def test_only_a_station_without_local_detections_needs_a_recording_match(
    station: Station, hb2: Station, today: datetime
) -> None:
    """The HomeBase 3 sends each detection with its recording over P2P; the HomeBase 2
    does not (its grade is not verified), so its cloud detections need the match."""
    pushed = _detection(today, station_sn=HB2_SN)
    assert hb2.needs_recording_match(pushed)
    assert not station.needs_recording_match(_detection(today))
    for named in (
        {"video_path": "/zx/hdd_data0/Camera00/1.zxvideo"},
        {"record_id": 7},
        {"event_time_ms": None},
        {"msg_type": 9, "event_type": None},  # an arming push: no detection
        {"device_sn": "T8160P2000011111", "channel": None},  # not paired here
        {"station_sn": SYNTHETIC.station_sn},  # another station's
    ):
        assert not hb2.needs_recording_match(dataclasses.replace(pushed, **named)), named


async def test_a_detection_of_a_device_without_a_camera_needs_no_recording_match(
    fake: FakeStation,
) -> None:
    sensor_sn = "T8910P2000054321"
    hb2 = Station(
        dataclasses.replace(STATION, device_sn=HB2_SN),
        StationSession(HB2_SN, _no_credentials, host="127.0.0.1", port=9),
        sub_devices=[
            dataclasses.replace(CAMERA, station_sn=HB2_SN),
            dataclasses.replace(
                CAMERA, device_sn=sensor_sn, station_sn=HB2_SN, channel=2, device_type=10
            ),
        ],
    )
    try:
        motion = _detection(NOW, station_sn=HB2_SN, device_sn=sensor_sn, msg_type=14)
        assert not hb2.needs_recording_match(motion)
        assert hb2.needs_recording_match(dataclasses.replace(motion, device_sn=CAMERA.device_sn))
    finally:
        await hb2.async_close()


async def _no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
    raise AssertionError("nothing connects")


@pytest.fixture
def short_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-list every 0.2 s and give up 5 s after a detection."""
    monkeypatch.setattr(station_module, "RECORDING_MATCH_RETRY", 0.2)
    monkeypatch.setattr(station_module, "RECORDING_MATCH_GIVE_UP", 5.0)


def _states(station: Station, monkeypatch: pytest.MonkeyPatch) -> list[DetectionRecordingState]:
    """The state of every answer the waiting call reads."""
    states: list[DetectionRecordingState] = []
    ask = station.async_recording_for_detection

    async def spy(event: SecurityEvent, **kwargs: Any) -> DetectionRecording:
        found = await ask(event, **kwargs)
        states.append(found.state)
        return found

    monkeypatch.setattr(station, "async_recording_for_detection", spy)
    return states


@pytest.mark.usefixtures("short_match")
async def test_a_homebase_2_detection_waits_for_its_running_recording_then_its_trigger_frame(
    hb2: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the next whole second: rows keep whole seconds, so a running row's end lags the
    # clock by up to 1 s and ``quiet`` must exceed that
    started = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)
    record_id = fake.add_detection_recording(SYNTHETIC.camera_sn, started, 1.0, listed_after=0.5)
    event = _detection(started, station_sn=HB2_SN)
    assert hb2.needs_recording_match(event)
    states = _states(hb2, monkeypatch)
    async with asyncio.timeout(6.0):
        row = await hb2.async_wait_recording_for_detection(event, quiet=1.1)
    assert row is not None
    assert (row.record_id, row.device_sn) == (record_id, SYNTHETIC.camera_sn)
    assert Station.recording_settled(row, quiet=1.1)
    assert states[0] is DetectionRecordingState.NOT_LISTED
    assert DetectionRecordingState.RECORDING in states
    assert states[-1] is DetectionRecordingState.SETTLED
    named = hb2.event_with_recording(event, row)
    assert (named.video_path, named.record_id) == (row.video_path, record_id)
    assert not hb2.needs_recording_match(named)
    image = await hb2.async_event_image(named, ImageSource.TRIGGER_FRAME)
    assert (image.device_sn, image.record_id) == (SYNTHETIC.camera_sn, record_id)
    assert image.data


@pytest.mark.usefixtures("short_match")
async def test_waiting_for_a_detection_without_its_recording_gives_none_at_the_bound(
    hb2: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = datetime.now(UTC).replace(microsecond=0)
    fake.add_detection_recording(OTHER_SN, started, 1.0)  # another camera's
    fake.add_detection_recording(
        SYNTHETIC.camera_sn, started - timedelta(seconds=60), 10.0
    )  # over long before
    monkeypatch.setattr(station_module, "RECORDING_MATCH_GIVE_UP", 1.5)
    states = _states(hb2, monkeypatch)
    event = _detection(started, station_sn=HB2_SN)
    async with asyncio.timeout(4.0):
        assert await hb2.async_wait_recording_for_detection(event) is None
    assert set(states) == {DetectionRecordingState.NOT_LISTED}
    assert len(states) > 2  # listed again until the bound
    assert datetime.now(UTC) >= started + timedelta(seconds=1.5)


async def test_a_settled_homebase_3_recording_names_its_thumbnail_for_the_event_image(
    station: Station, fake: FakeStation
) -> None:
    started = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=120)
    record_id = fake.add_detection_recording(SYNTHETIC.camera_sn, started, 20.0)
    event = _detection(started)
    row = await station.async_wait_recording_for_detection(event)
    assert row is not None
    assert row.record_id == record_id
    named = station.event_with_recording(event, row)
    assert named.thumb_path == row.thumb_path
    jpeg = b"\xff\xd8\xff\xe0" + bytes(16) + b"\xff\xd9"
    fake.images[str(row.thumb_path)] = jpeg
    image = await station.async_event_image(named, ImageSource.THUMBNAIL)
    assert (image.data, image.record_id) == (jpeg, record_id)


async def test_a_record_of_another_camera_or_without_a_clip_names_no_recording(
    two_cameras: Station, today: datetime
) -> None:
    event = _detection(today)
    other = HistoryRecord.from_row(_at(today, OTHER_SN, 1))
    with pytest.raises(ValueError, match="another camera"):
        two_cameras.event_with_recording(event, other)
    bare = HistoryRecord.from_row(_at(today, SYNTHETIC.camera_sn, 1, storage_path=""))
    with pytest.raises(ValueError, match="no recording"):
        two_cameras.event_with_recording(event, bare)
    unlisted = HistoryRecord.from_row(_at(today, SYNTHETIC.camera_sn, 0, thumb_path="/media/x.jpg"))
    named = two_cameras.event_with_recording(event, unlisted)
    assert (named.record_id, named.thumb_path) == (None, None)  # no id, no valid still path


# ── one look per camera ──────────────────────────────────────────────────────


@pytest.fixture
def no_reuse(monkeypatch: pytest.MonkeyPatch) -> None:
    """A finished listing answers no later look (only one in flight is shared)."""
    monkeypatch.setattr(station_module, "RECORDING_MATCH_FRESH", 0.0)


def _busy_day(
    event: datetime, *, hb2: bool, step: float, first: float, count: int = 100
) -> list[dict[str, object]]:
    """``count`` recordings of the camera ``first`` s, ``first + step`` s ... before
    ``event``, newest first, on the event's host-local day only."""
    day = event.astimezone().date()
    starts = [event - timedelta(seconds=first + step * n) for n in range(count)]
    return [
        _at(start, SYNTHETIC.camera_sn, 1999 - n if hb2 else _dayed(start, 1000 - n))
        for n, start in enumerate(starts)
        if start.astimezone().date() == day
    ]


@pytest.fixture(params=["homebase_3", "homebase_2"])
async def homebase(request: pytest.FixtureRequest, fake: FakeStation) -> AsyncIterator[Station]:
    """A HomeBase 3 (:data:`STATION`), then a HomeBase 2 (:data:`HB2_SN`), with :data:`CAMERA`."""
    serial = SYNTHETIC.station_sn if request.param == "homebase_3" else HB2_SN
    fake.serial = serial
    fake.static_key = static_key(serial, fake.did)

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(serial, credentials, host="127.0.0.1", port=fake.discovery_port)
    st = Station(
        dataclasses.replace(STATION, device_sn=serial),
        session,
        sub_devices=[dataclasses.replace(CAMERA, station_sn=serial)],
    )
    yield st
    await st.async_close()


async def test_a_look_at_a_busy_day_stops_at_the_page_that_reaches_its_bound(
    homebase: Station, fake: FakeStation, today: datetime
) -> None:
    """A camera day of 101 recordings: one look asks only the page that reaches back past
    :data:`RECORDING_MATCH_GIVE_UP` before the detection, not the rest of the day."""
    st = homebase
    hb2 = st.serial == HB2_SN
    event = _whole(today, 30)
    own_id = 3000 if hb2 else _dayed(event, 2000)
    fake.rows = [
        _at(event, SYNTHETIC.camera_sn, own_id),
        *_busy_day(event, hb2=hb2, step=60, first=300),
    ]
    found = await st.async_recording_for_detection(_detection(event, station_sn=st.serial))
    assert found.record is not None
    assert found.record.record_id == own_id
    assert len(fake.history_queries) == 1


@pytest.mark.usefixtures("no_reuse")
async def test_concurrent_looks_at_one_camera_share_one_listing(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    event = _whole(today, 120)
    fake.rows = [_at(event, SYNTHETIC.camera_sn, _dayed(event, 4))]
    detection = _detection(event)
    first, second = await asyncio.gather(
        station.async_recording_for_detection(detection),
        station.async_recording_for_detection(_detection(event + timedelta(seconds=1))),
    )
    assert first.record == second.record
    assert len(fake.history_queries) == 1
    await station.async_recording_for_detection(detection)  # the listing is over: a new one
    assert len(fake.history_queries) == 2


async def test_a_look_soon_after_another_of_the_camera_reuses_its_listing(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    """A listing finished less than :data:`RECORDING_MATCH_FRESH` ago answers the next look
    of the camera; with ``quiet`` 0 no listing is fresh."""
    event = _whole(today, 120)
    fake.rows = [_at(event, SYNTHETIC.camera_sn, _dayed(event, 4))]
    await station.async_recording_for_detection(_detection(event))
    await station.async_recording_for_detection(_detection(event + timedelta(seconds=5)))
    assert len(fake.history_queries) == 1
    await station.async_recording_for_detection(_detection(event), quiet=0.0)
    assert len(fake.history_queries) == 2


@pytest.mark.usefixtures("no_reuse")
@pytest.mark.parametrize(("older_ago", "pages"), [(150, 2), (190, 1)])
async def test_a_look_lists_back_to_the_oldest_detection_of_the_camera_still_searched(
    hb2: Station, fake: FakeStation, today: datetime, older_ago: int, pages: int
) -> None:
    """A newer detection's listing reaches the bound of an older one still within its
    give-up time (so the older one's next look can share it), not of one past it."""
    newer = _whole(today, 20)
    fake.rows = [
        _at(newer, SYNTHETIC.camera_sn, 3000),
        *_busy_day(newer, hb2=True, step=10, first=10),
    ]
    older = _detection(_whole(today, older_ago), station_sn=HB2_SN)
    await hb2.async_recording_for_detection(older)
    assert len(fake.history_queries) == 2  # its bound lies on the second page
    fake.history_queries.clear()
    await hb2.async_recording_for_detection(_detection(newer, station_sn=HB2_SN))
    assert len(fake.history_queries) == pages


@pytest.mark.usefixtures("short_match")
async def test_a_burst_of_detections_of_one_camera_shares_the_listings_of_their_waits(
    hb2: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)
    record_id = fake.add_detection_recording(SYNTHETIC.camera_sn, started, 1.0, listed_after=0.5)
    events = [_detection(started + timedelta(seconds=s), station_sn=HB2_SN) for s in (3, 0, 2, 1)]
    states = _states(hb2, monkeypatch)
    async with asyncio.timeout(6.0):
        rows = await asyncio.gather(
            *(hb2.async_wait_recording_for_detection(e, quiet=1.1) for e in events)
        )
    assert {None if r is None else r.record_id for r in rows} == {record_id}
    assert len(fake.history_queries) * 3 <= len(states)


async def test_a_failed_listing_fails_the_looks_sharing_it_and_answers_no_later_look(
    station: Station, fake: FakeStation, today: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The looks waiting on a listing get its error (one query); a look cancelled meanwhile
    leaves nothing for the loop's exception handler; the next look lists again."""
    event = _whole(today, 120)
    fake.rows = [_at(event, SYNTHETIC.camera_sn, _dayed(event, 4))]
    real = station.session.async_list_history
    release = asyncio.Event()
    calls = 0

    async def fail_first(*args: Any, **kwargs: Any) -> list[HistoryRecord]:
        nonlocal calls
        calls += 1
        if calls == 1:
            await release.wait()
            raise StationUnreachableError("no route")
        return await real(*args, **kwargs)

    monkeypatch.setattr(station.session, "async_list_history", fail_first)
    loop = asyncio.get_running_loop()
    seen: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: seen.append(context))
    try:
        looks = [
            asyncio.create_task(
                station.async_recording_for_detection(_detection(event + timedelta(seconds=s)))
            )
            for s in (0, 1, 2)
        ]
        for _ in range(5):
            await asyncio.sleep(0)
        looks[2].cancel()
        release.set()
        results = await asyncio.gather(*looks, return_exceptions=True)
        assert [type(r) for r in results] == [
            StationUnreachableError,
            StationUnreachableError,
            asyncio.CancelledError,
        ]
        assert calls == 1
        found = await station.async_recording_for_detection(_detection(event))
        assert (found.state, calls) == (DetectionRecordingState.SETTLED, 2)
        await asyncio.sleep(0)
        gc.collect()
        assert seen == []
    finally:
        loop.set_exception_handler(None)


# ── a wait that rides out a failed listing ───────────────────────────────────


def _failing_lists(
    station: Station, monkeypatch: pytest.MonkeyPatch, failures: int | None
) -> list[int]:
    """Make the first ``failures`` history listings (None: every one) raise
    :class:`StationUnreachableError`; returns the running count of listings."""
    real = station.session.async_list_history
    calls = [0]

    async def listing(*args: Any, **kwargs: Any) -> list[HistoryRecord]:
        calls[0] += 1
        if failures is None or calls[0] <= failures:
            raise StationUnreachableError(f"no route {calls[0]}")
        return await real(*args, **kwargs)

    monkeypatch.setattr(station.session, "async_list_history", listing)
    return calls


@pytest.mark.usefixtures("short_match")
async def test_a_wait_asks_again_after_a_failed_listing(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=3)
    record_id = fake.add_detection_recording(SYNTHETIC.camera_sn, started, 1.0)
    calls = _failing_lists(station, monkeypatch, 1)
    async with asyncio.timeout(3.0):
        row = await station.async_wait_recording_for_detection(_detection(started), quiet=1.1)
    assert row is not None
    assert row.record_id == record_id
    assert calls[0] == 2


@pytest.mark.usefixtures("short_match")
async def test_a_wait_whose_every_listing_fails_raises_the_last_error_at_its_bound(
    station: Station, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No look ever answered: the bound ends the wait with the last listing's error,
    logged once."""
    monkeypatch.setattr(station_module, "RECORDING_MATCH_GIVE_UP", 1.0)
    calls = _failing_lists(station, monkeypatch, None)
    event = _detection(datetime.now(UTC))
    with caplog.at_level(logging.INFO, logger="eufy_home_security.station"):
        async with asyncio.timeout(3.0):
            with pytest.raises(StationUnreachableError) as raised:
                await station.async_wait_recording_for_detection(event)
    assert calls[0] > 2
    assert str(raised.value) == f"no route {calls[0]}"
    assert datetime.now(UTC) >= _from_ms(event.event_time_ms) + timedelta(seconds=1.0)
    failed = [r for r in caplog.records if "listing failed" in r.getMessage()]
    assert len(failed) == 1


@pytest.mark.usefixtures("short_match")
async def test_a_wait_that_listed_once_gives_none_at_its_bound_whatever_fails_after(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(station_module, "RECORDING_MATCH_GIVE_UP", 1.0)
    real = station.session.async_list_history
    calls = 0

    async def fail_after_first(*args: Any, **kwargs: Any) -> list[HistoryRecord]:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise DeviceTimeoutError("no reply")
        return await real(*args, **kwargs)

    monkeypatch.setattr(station.session, "async_list_history", fail_after_first)
    async with asyncio.timeout(3.0):
        assert (
            await station.async_wait_recording_for_detection(_detection(datetime.now(UTC))) is None
        )
    assert calls > 2


async def test_a_wait_raises_at_once_what_no_retry_can_change(
    two_cameras: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another camera's row named by ``record_id``, and an event without a time whose
    lookup fails: raised by the first look."""
    started = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=30)
    fake.rows = [_at(started, OTHER_SN, _dayed(started, 4))]
    async with asyncio.timeout(3.0):
        with pytest.raises(RecordNotFoundError):
            await two_cameras.async_wait_recording_for_detection(
                _detection(started, record_id=_dayed(started, 4))
            )
        lookups = len(fake.history_queries)

        async def unreachable(*args: Any, **kwargs: Any) -> HistoryRecord | None:
            raise StationUnreachableError("no route")

        monkeypatch.setattr(two_cameras.session, "async_history_record", unreachable)
        with pytest.raises(StationUnreachableError):
            await two_cameras.async_wait_recording_for_detection(
                _detection(started, record_id=_dayed(started, 5), event_time_ms=None)
            )
    assert len(fake.history_queries) == lookups


def _from_ms(value: int | None) -> datetime:
    assert value is not None
    return datetime.fromtimestamp(value / 1000, UTC)


# ── rows written without an offset ───────────────────────────────────────────


@pytest.fixture
def host_utc() -> Iterator[None]:
    """The host's zone is UTC for the test."""
    old = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        time.tzset()


def _zoneless(
    start: datetime, zone: tzinfo, record_id: int, seconds: int = 20
) -> dict[str, object]:
    """A recording row written in ``zone``'s local time, with no ``time_zone`` beside it."""
    local = start.astimezone(zone)
    return {
        "record_id": record_id,
        "device_sn": SYNTHETIC.camera_sn,
        "start_time": local.strftime(FORMAT),
        "end_time": (local + timedelta(seconds=seconds)).strftime(FORMAT),
        "storage_path": f"/zx/hdd_data0/Camera00/{record_id}.zxvideo",
        "frame_num": 6,
    }


def _in_zone(station: Station, zone: str) -> None:
    """Give ``station`` the cloud entry of a station set to ``zone``."""
    station.apply_cloud_device(dataclasses.replace(STATION, raw={"time_zone": encode_zone(zone)}))


async def test_a_row_without_an_offset_is_read_in_the_stations_zone(
    host_utc: None, station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host keeps UTC, the station runs two hours ahead and writes its local time:
    its row matches the detection, and settles by the station's clock."""
    now = _freeze(monkeypatch, NOW)
    _in_zone(station, "Africa/Johannesburg")  # UTC+2, no daylight saving
    event = _whole(now, 120)
    started = event - timedelta(seconds=2)
    record_id = int(started.astimezone(SAST).strftime("%Y%m%d")) * HISTORY_RECORD_COUNTER + 4
    fake.rows = [_zoneless(started, SAST, record_id)]
    found = await station.async_recording_for_detection(_detection(event))
    assert (found.state, found.offset_s) == (DetectionRecordingState.SETTLED, -2.0)
    assert found.record is not None
    assert found.record.record_id == record_id


async def test_a_row_without_an_offset_in_a_repeated_hour_is_read_nearest_the_detection(
    host_utc: None, station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """02:30 happens twice when the station's clock goes back from summer time: a row
    written at 02:30 is read as the pass nearer the detection, so it matches a detection
    in either pass."""
    _in_zone(station, "Europe/Berlin")
    second_pass = datetime(2026, 10, 25, 1, 30, 2, tzinfo=UTC)  # winter time  # hygiene: ok
    _freeze(monkeypatch, second_pass + timedelta(seconds=120))
    naive_row = {**_zoneless(second_pass, UTC, 2026102500004), "time_zone": ""}  # hygiene: ok
    naive_row["start_time"] = "2026-10-25 02:30:00"  # hygiene: ok
    naive_row["end_time"] = "2026-10-25 02:30:20"  # hygiene: ok
    fake.rows = [naive_row]
    found = await station.async_recording_for_detection(_detection(second_pass))
    assert (found.state, found.offset_s) == (DetectionRecordingState.SETTLED, -2.0)
    first_pass = second_pass - timedelta(hours=1)  # the same wall time in summer time
    _freeze(monkeypatch, first_pass + timedelta(seconds=120))
    found = await station.async_recording_for_detection(_detection(first_pass))
    assert (found.state, found.offset_s) == (DetectionRecordingState.SETTLED, -2.0)


@pytest.mark.usefixtures("no_reuse")
async def test_no_row_listed_names_the_offset_of_the_nearest_recording(
    host_utc: None,
    station: Station,
    fake: FakeStation,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A station two hours ahead whose zone is unknown here: nothing matches, and the
    answer and its log line carry how far the nearest recording of the camera lies."""
    now = _freeze(monkeypatch, NOW)
    event = _whole(now, 120)
    started = event - timedelta(seconds=2)
    record_id = int(started.astimezone(SAST).strftime("%Y%m%d")) * HISTORY_RECORD_COUNTER + 4
    far = event - timedelta(seconds=100)
    fake.rows = [
        _zoneless(started, SAST, record_id),
        _at(far, SYNTHETIC.camera_sn, _dayed(far, 3)),  # over before the detection
        _at(event, OTHER_SN, _dayed(event, 5)),
    ]
    with caplog.at_level(logging.DEBUG, logger="eufy_home_security.station"):
        found = await station.async_recording_for_detection(_detection(event))
    assert found.state is DetectionRecordingState.NOT_LISTED
    assert (found.record, found.offset_s) == (None, -100.0)
    assert any("not_listed, row None, offset -100s" in r.getMessage() for r in caplog.records)
    fake.rows = fake.rows[:1]
    ahead = await station.async_recording_for_detection(_detection(event))
    assert (ahead.state, ahead.offset_s) == (DetectionRecordingState.NOT_LISTED, 7198.0)


@pytest.mark.usefixtures("no_reuse")
async def test_a_row_before_a_detections_own_bound_never_holds_it(
    station: Station, fake: FakeStation, today: datetime
) -> None:
    """The camera's listing reaches back to an older detection still searched; a row that
    started before the newer detection's own bound (still running) is not the newer's."""
    older_event = _whole(today, 150)
    newer_event = _whole(today, 10)
    stuck = newer_event - timedelta(seconds=RECORDING_MATCH_GIVE_UP + 20)
    fake.rows = [_at(stuck, SYNTHETIC.camera_sn, _dayed(stuck, 1), end_time="")]
    older = await station.async_recording_for_detection(_detection(older_event))
    assert older.record is not None  # it holds the older detection
    newer = await station.async_recording_for_detection(_detection(newer_event))
    assert newer.state is DetectionRecordingState.NOT_LISTED
