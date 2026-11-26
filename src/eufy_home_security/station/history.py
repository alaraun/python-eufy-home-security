"""A station's event history and the recordings on its disk (:class:`StationHistory`)."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import Any, Protocol

from ..cloud.models import CloudDevice
from ..events import HistoryRecord, SecurityEvent
from ..exceptions import EufySecurityError, RecordNotFoundError, UnsupportedError
from ..models import E2EKeyType
from ..p2p.clip import ClipWriter, MediaClip
from ..p2p.media import pin_key_refusal
from ..p2p.messages import DB_QUERY_HISTORY, history_query_verb, record_id_day
from ..p2p.session import StationSession
from ..recordings import (
    DetectionRecording,
    DetectionRecordingState,
    RecordingPosition,
    RecordingsPage,
    decode_cursor,
    decode_ref,
    encode_cursor,
)


def _host_today() -> date:
    """Today in the host's zone: the newest day of a recordings window."""
    return datetime.now().astimezone().date()


def _host_day(value: date) -> date:
    """A day, or a ``datetime``'s host-local day."""
    return value.astimezone().date() if isinstance(value, datetime) else value


@dataclass(frozen=True, slots=True)
class _Timed:
    """A recording row read against a detection's time."""

    row: HistoryRecord
    offset: float
    """Its start minus the detection's time, in seconds."""
    ended: datetime | None


def _timed_rows(rows: list[HistoryRecord], event_at: datetime, zone: tzinfo | None) -> list[_Timed]:
    """The rows with a start, read against ``event_at`` in the station's ``zone`` (see
    :meth:`HistoryRecord.times_near`)."""
    timed = []
    for row in rows:
        started, ended = row.times_near(event_at, zone)
        if started is not None:
            timed.append(_Timed(row, (started - event_at).total_seconds(), ended))
    return timed


def _ended_before(timed: _Timed, moment: datetime) -> bool:
    """Whether the row ended before ``moment``."""
    return timed.ended is not None and timed.ended < moment


def _detection_match(
    timed: list[_Timed],
    event_at: datetime,
    video_path: str | None,
    early: float,
    late: float,
) -> _Timed | None:
    """The row of a detection at ``event_at``, or None.

    A row named by ``video_path`` wins; else the row whose start lies within
    ``early``..``late`` seconds of the event (both included): a row that ended before the
    event after every other, then the closest start first, on a tie the one that began
    first, then the lower ``record_id``; else the row that holds
    the event (began before the window and has not ended before the event, or has no end
    yet), the latest start first.
    """
    if video_path is not None:
        named = [c for c in timed if c.row.video_path == video_path]
        if named:
            return named[0]
    near = [c for c in timed if early <= c.offset <= late]
    if near:
        return min(
            near,
            key=lambda c: (_ended_before(c, event_at), abs(c.offset), c.offset, c.row.record_id),
        )
    holding = [c for c in timed if c.offset < early and (c.ended is None or c.ended >= event_at)]
    if holding:
        return max(holding, key=lambda c: (c.offset, -c.row.record_id))
    return None


@dataclass(frozen=True, slots=True)
class _MatchClock:
    """When a detection's recording is looked at, and the bounds its answer follows."""

    now: datetime
    """After the rows were listed: retries count from it."""
    asked: datetime
    """When the rows' listing began: a row's end is read as of then."""
    event_at: datetime | None
    retry: float
    give_up: float
    quiet: float

    def not_listed(self, nearest: float | None = None) -> DetectionRecording:
        """No row of the detection (``nearest``: the start offset of the camera's nearest
        recording): ask again after the retry, within the bound."""
        return DetectionRecording(
            state=DetectionRecordingState.NOT_LISTED,
            retry_at=self._bounded(self.now + timedelta(seconds=self.retry), self.event_at),
            offset_s=nearest,
        )

    def of_row(
        self,
        row: HistoryRecord,
        offset: float | None,
        started: datetime | None,
        ended: datetime | None,
        *,
        provisional: bool = False,
    ) -> DetectionRecording:
        """The detection's row, settled or still recording, with its start and end read
        in the station's zone. A ``provisional`` row (one that ended before the event: a
        better one may still be listed) stays ``RECORDING``, asked again after the retry,
        until the bound."""
        if provisional:
            retry_at = self._bounded(self.now + timedelta(seconds=self.retry), self.event_at)
            if retry_at is not None:
                return DetectionRecording(
                    state=DetectionRecordingState.RECORDING,
                    record=row,
                    retry_at=retry_at,
                    offset_s=offset,
                )
        if ended is not None and (self.asked - ended).total_seconds() >= self.quiet:
            return DetectionRecording(
                state=DetectionRecordingState.SETTLED, record=row, offset_s=offset
            )
        wanted = self.now + timedelta(seconds=self.retry)
        if ended is not None and ended + timedelta(seconds=self.quiet) > self.now:
            wanted = ended + timedelta(seconds=self.quiet)  # a listing begun then settles it
        return DetectionRecording(
            state=DetectionRecordingState.RECORDING,
            record=row,
            retry_at=self._bounded(wanted, self.event_at or started),
            offset_s=offset,
        )

    def _bounded(self, wanted: datetime, since: datetime | None) -> datetime | None:
        """``wanted``, but no later than ``give_up`` seconds after ``since``; None once
        that bound has passed or without ``since``."""
        if since is None:
            return None
        bound = since + timedelta(seconds=self.give_up)
        if self.now >= bound:
            return None
        return min(wanted, bound)


@dataclass(slots=True)
class _Look:
    """One listing of a camera's recordings, shared by the looks that start while it
    runs or soon after it ends."""

    since: datetime
    """The oldest start it lists down to."""
    last_day: date
    """The newest day it lists."""
    asked: datetime
    """When it began."""
    rows: asyncio.Future[list[HistoryRecord]]
    """The rows it listed, or its error."""
    done_at: float | None = None
    """``time.monotonic()`` when it was listed; None while it runs or after it failed."""

    def serves(self, since: datetime, last_day: date, fresh: float) -> bool:
        """Whether a look down to ``since`` and up to ``last_day`` may take its rows: it
        reaches both and runs still, or was listed less than ``fresh`` seconds ago."""
        if self.since > since or self.last_day < last_day:
            return False
        if not self.rows.done():
            return True
        return self.done_at is not None and time.monotonic() - self.done_at < fresh


@dataclass(slots=True)
class _Searches:
    """A camera's looks: the last listing, and the bounds of the detections still
    searched (a listing reaches the oldest, so their next looks can share it)."""

    look: _Look | None = None
    bounds: dict[datetime, datetime] = field(default_factory=dict)
    """Lower bound -> when its detection's search ends."""

    def floor(self, since: datetime, until: datetime, now: datetime) -> datetime:
        """The oldest bound of the searches still running at ``now``, ``since``
        (searched until ``until``) among them."""
        self.bounds[since] = until
        self.bounds = {b: end for b, end in self.bounds.items() if end > now}
        return min((since, *self.bounds))


class HistoryOwner(Protocol):
    """The station members a :class:`StationHistory` uses."""

    session: StationSession

    @property
    def serial(self) -> str: ...

    @property
    def is_standalone(self) -> bool: ...

    @property
    def devices(self) -> tuple[CloudDevice, ...]: ...

    def channel_for(self, device_sn: str) -> int: ...


class StationHistory:
    """A station's history rows and recordings: lists, single rows, pages, downloads.

    Requests over the station's session; the only state is each camera's last listing
    for a detection's recording, which the looks of that camera share. Every default the
    public API documents (``days``, ``quiet``) is resolved by :class:`Station` before
    calling.
    """

    def __init__(self, station: HistoryOwner) -> None:
        self._station = station
        self._searches: dict[str, _Searches] = {}

    async def list_history(
        self, start_date: str, end_date: str | None = None, **kwargs: Any
    ) -> list[HistoryRecord]:
        """See :meth:`Station.async_list_history`."""
        return await self._station.session.async_list_history(start_date, end_date, **kwargs)

    async def history_record(self, record_id: int) -> HistoryRecord | None:
        """See :meth:`Station.async_history_record`."""
        if self._station.is_standalone:
            raise UnsupportedError("a standalone device lists no history")
        if record_id_day(record_id) is None:
            raise UnsupportedError(f"record_id {record_id} carries no day")
        return await self._station.session.async_history_record(record_id)

    async def history_record_by_ref(
        self, ref: str, *, device_sn: str | None = None, timeout: float | None = None
    ) -> HistoryRecord:
        """See :meth:`Station.async_history_record_by_ref`."""
        if device_sn is not None:
            self._station.channel_for(device_sn)  # raises for a device not paired here
            cameras: tuple[str, ...] = (device_sn,)
        else:
            cameras = (self._station.serial, *(d.device_sn for d in self._station.devices))
        found = decode_ref(ref, station_sn=self._station.serial, device_sns=cameras)
        if self._station.is_standalone:
            raise UnsupportedError("a standalone device lists no history")
        return await self._station.session.async_find_history_record(found, timeout=timeout)

    async def list_recordings(
        self,
        device_sn: str | None = None,
        *,
        days: int,
        since: datetime | None = None,
        limit: int | None = None,
        before: int | None = None,
        until: date | None = None,
        timeout: float | None = None,
    ) -> list[HistoryRecord]:
        """See :meth:`Station.async_list_recordings`."""
        if days < 1:
            raise ValueError("days must be at least 1")
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1")
        cursor_day = None if before is None else record_id_day(before)
        if before is not None and cursor_day is None:
            raise ValueError(f"before {before} carries no day")
        if device_sn is not None:
            self._station.channel_for(device_sn)  # raises for a device not paired here
        if self._station.is_standalone:
            return []
        today = _host_today()
        first = today - timedelta(days=days - 1)
        if since is not None:
            first = max(first, since.astimezone().date())
        if cursor_day is not None:
            last = min(today, cursor_day)
        elif until is not None:
            last = min(today, _host_day(until))
        else:
            last = today
        if first > last:
            return []
        return await self._station.session.async_list_history(
            first.strftime("%Y%m%d"),
            last.strftime("%Y%m%d"),
            count=limit,
            before=before if cursor_day is not None and cursor_day <= last else None,
            keep=self._recording_filter(device_sn, since),
            device_sn=device_sn,
            timeout=timeout,
        )

    async def list_recordings_page(
        self,
        device_sn: str | None = None,
        *,
        limit: int,
        days: int,
        cursor: str | None = None,
        until: date | None = None,
        page_days: int | None = None,
        timeout: float | None = None,
    ) -> RecordingsPage:
        """See :meth:`Station.async_list_recordings_page`."""
        if days < 1:
            raise ValueError("days must be at least 1")
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if page_days is not None and page_days < 1:
            raise ValueError("page_days must be at least 1")
        position = None
        if cursor is not None:
            position = decode_cursor(cursor, station_sn=self._station.serial, device_sn=device_sn)
        if device_sn is not None:
            self._station.channel_for(device_sn)  # raises for a device not paired here
        if self._station.is_standalone:
            return RecordingsPage((), None)
        today = _host_today()
        first = today - timedelta(days=days - 1)
        if position is not None:
            start = min(today, position.day)
        elif until is not None:
            start = min(today, _host_day(until))
        else:
            start = today
        oldest = first if page_days is None else max(first, start - timedelta(days=page_days - 1))
        if oldest > start:
            return RecordingsPage((), None)
        record_id = None if position is None else position.record_id
        listed = await self._station.session.async_list_history_by_day(
            oldest.strftime("%Y%m%d"),
            start.strftime("%Y%m%d"),
            count=limit,
            before=record_id,  # the session pages it only on its own day
            before_day=None if position is None or record_id is None else position.day,
            keep=self._recording_filter(device_sn, None),
            device_sn=device_sn,
            timeout=timeout,
        )
        rows = tuple(row for _day, row in listed)
        # rows without an id (none above 0) cannot be paged from: go on after the page's
        # last row with one, so they may come again but none is skipped
        paged = [(day, row.record_id) for day, row in listed if row.record_id > 0]
        if len(listed) < limit:  # the days asked hold no more: go on before them
            following = RecordingPosition(oldest - timedelta(days=1))
        elif paged:
            following = RecordingPosition.after(paged[-1][1], paged[-1][0])
        else:  # no row to page from: go on with the day before the last one
            following = RecordingPosition(listed[-1][0] - timedelta(days=1))
        if following.record_id is None and following.day < first:
            return RecordingsPage(rows, None)  # the window holds no more
        text = encode_cursor(following, station_sn=self._station.serial, device_sn=device_sn)
        return RecordingsPage(rows, text)

    def _recording_filter(
        self, device_sn: str | None, since: datetime | None
    ) -> Callable[[HistoryRecord], bool]:
        """Which history rows are recordings of ``device_sn`` (None: of every camera
        paired here) that started at or after ``since``."""
        paired = {d.device_sn for d in self._station.devices}

        def wanted(row: HistoryRecord) -> bool:
            if row.video_path is None or row.device_sn is None:
                return False
            if (
                row.video_path.endswith(".dat")
                and history_query_verb(self._station.serial) == DB_QUERY_HISTORY
            ):
                return False
            if device_sn is not None and row.device_sn != device_sn:
                return False
            if device_sn is None and row.device_sn not in paired:
                return False
            if since is not None:
                started = row.started_at
                return started is not None and started >= since
            return True

        return wanted

    async def recording_for_detection(
        self,
        event: SecurityEvent,
        device_sn: str,
        *,
        window: tuple[float, float],
        retry: float,
        give_up: float,
        fresh: float,
        quiet: float,
        zone: tzinfo | None,
        timeout: float | None,
    ) -> DetectionRecording:
        """See :meth:`Station.async_recording_for_detection`; ``device_sn`` is the
        event's camera, paired here; a listing of the camera finished less than ``fresh``
        seconds ago answers the look; ``zone`` is the station's (None: the host's), for
        row times written without an offset and for the days asked."""
        if self._station.is_standalone:
            raise UnsupportedError("a standalone device lists no history")
        event_at = (
            None
            if event.event_time_ms is None
            else datetime.fromtimestamp(event.event_time_ms / 1000, UTC)
        )
        record_id = event.record_id
        if record_id and record_id_day(record_id) is not None:
            asked = datetime.now(UTC)
            row = await self._station.session.async_history_record(record_id, timeout=timeout)
            clock = _MatchClock(datetime.now(UTC), asked, event_at, retry, give_up, quiet)
            if row is not None and row.device_sn is not None and row.device_sn != device_sn:
                raise RecordNotFoundError(
                    "the event's record_id names another camera's row", device_sn=device_sn
                )
            if row is None or row.video_path is None:
                return clock.not_listed()
            return clock.of_row(row, None, *row.times_near(event_at or clock.now, zone))
        if event_at is None:
            raise UnsupportedError("the event carries no time to match a recording to")
        early, late = window
        first = event_at - timedelta(seconds=give_up)  # the earliest start of a holding clip
        asked = datetime.now(UTC)
        last_day = min(
            asked.astimezone(zone).date(),
            (event_at + timedelta(seconds=late)).astimezone(zone).date(),
        )
        searches = self._searches.setdefault(device_sn, _Searches())
        floor = searches.floor(first, event_at + timedelta(seconds=give_up), asked)
        rows, listed_from = await self._shared_look(
            searches,
            _Look(floor, last_day, asked, asyncio.get_running_loop().create_future()),
            first,
            fresh,
            lambda: self._camera_recordings(device_sn, floor, last_day, zone, timeout),
        )
        clock = _MatchClock(datetime.now(UTC), listed_from, event_at, retry, give_up, quiet)
        listed = _timed_rows(rows, event_at, zone)
        # a row that started before the detection's own bound is never its recording
        timed = [c for c in listed if c.offset >= -give_up]
        found = _detection_match(timed, event_at, event.video_path, early, late)
        if found is None:
            nearest = min(listed, key=lambda c: abs(c.offset), default=None)
            return clock.not_listed(None if nearest is None else nearest.offset)
        started = event_at + timedelta(seconds=found.offset)
        return clock.of_row(
            found.row,
            found.offset,
            started,
            found.ended,
            provisional=_ended_before(found, event_at),
        )

    @staticmethod
    async def _shared_look(
        searches: _Searches,
        look: _Look,
        since: datetime,
        fresh: float,
        listing: Callable[[], Awaitable[list[HistoryRecord]]],
    ) -> tuple[list[HistoryRecord], datetime]:
        """The camera's rows down to ``since`` and up to ``look``'s last day, and when
        their listing began: from the camera's last listing when it serves (see
        :meth:`_Look.serves`), else from ``listing``, run as ``look`` and shared with
        the looks that come while it runs (its error too)."""
        while (last := searches.look) is not None and last.serves(since, look.last_day, fresh):
            await asyncio.wait((last.rows,))
            if not last.rows.cancelled():
                return last.rows.result(), last.asked
        searches.look = look
        try:
            rows = await listing()
            look.done_at = time.monotonic()
            look.rows.set_result(rows)
        except Exception as err:
            look.rows.set_exception(err)
            look.rows.exception()  # read: a failure no other look shares logs nothing
            raise
        finally:
            if not look.rows.done():
                look.rows.cancel()
        return look.rows.result(), look.asked

    async def _camera_recordings(
        self,
        device_sn: str,
        since: datetime,
        last_day: date,
        zone: tzinfo | None,
        timeout: float | None,
    ) -> list[HistoryRecord]:
        """The recordings of ``device_sn`` from the station day ``last_day`` back to the
        page holding a row that started before ``since`` (rows read in ``zone``)."""

        def older(row: HistoryRecord) -> bool:
            started, _ended = row.times_near(since, zone)
            return started is not None and started < since

        first_day = since.astimezone(zone).date()
        if first_day > last_day:
            return []
        return await self._station.session.async_list_history(
            first_day.strftime("%Y%m%d"),
            last_day.strftime("%Y%m%d"),
            keep=self._recording_filter(device_sn, None),
            stop=older,
            device_sn=device_sn,
            timeout=timeout,
        )

    @staticmethod
    def recording_settled(
        record: HistoryRecord, *, now: datetime | None = None, quiet: float
    ) -> bool:
        """See :meth:`Station.recording_settled`."""
        ended = record.ended_at
        if ended is None:
            return False
        current = now if now is not None else datetime.now(ended.tzinfo)
        return (current - ended).total_seconds() >= quiet

    async def download_recording(
        self, record: HistoryRecord, write: ClipWriter, *, wait: bool = True
    ) -> MediaClip:
        """See :meth:`Station.async_download_recording`."""
        path, channel = self._recording_of(record)
        clip = await self._station.session.async_download_recording(path, channel, write, wait=wait)
        return await self._clip_of(record, clip)

    async def play_recording(
        self, record: HistoryRecord, write: ClipWriter, *, wait: bool = True, realtime: bool = True
    ) -> MediaClip:
        """See :meth:`Station.async_play_recording`."""
        path, channel = self._recording_of(record)
        clip = await self._station.session.async_play_recording(
            path, channel, write, wait=wait, realtime=realtime
        )
        return await self._clip_of(record, clip)

    def _recording_of(self, record: HistoryRecord) -> tuple[str, int]:
        """The record's recording path and its camera's channel; raises
        :class:`UnsupportedError` for a record without either, and
        :class:`~..exceptions.PinProtectedKeyError` for one its row names end-to-end encrypted with the
        user's PIN key, as the app refuses it before playing."""
        path = record.video_path
        if path is None:
            raise UnsupportedError("the record carries no recording")
        if record.device_sn is None:
            raise UnsupportedError("the record names no camera")
        key = record.e2e_key
        if key is not None and key.key_type is E2EKeyType.PIN:
            raise pin_key_refusal(key.key_id)
        return path, self._station.channel_for(record.device_sn)

    async def _clip_of(self, record: HistoryRecord, clip: MediaClip) -> MediaClip:
        """``clip`` named after ``record``, held against its frame count read again."""
        # Read the row again: a clip still recording when the transfer began has more
        # frames now than were delivered, and then the clip is not complete.
        expected = record.frame_count
        if record.record_id and record_id_day(record.record_id) is not None:
            with contextlib.suppress(EufySecurityError):
                fresh = await self._station.session.async_history_record(record.record_id)
                if fresh is not None and fresh.frame_count is not None:
                    expected = max(expected or 0, fresh.frame_count)
        return replace(
            clip,
            started_at=record.started_at,
            device_sn=record.device_sn,
            record_id=record.record_id or None,
            expected_frames=expected,
        )
