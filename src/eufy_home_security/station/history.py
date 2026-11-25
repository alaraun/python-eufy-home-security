"""A station's event history and the recordings on its disk (:class:`StationHistory`)."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from ..cloud.models import CloudDevice
from ..events import HistoryRecord, SecurityEvent
from ..exceptions import EufySecurityError, RecordNotFoundError, UnsupportedError
from ..p2p.clip import ClipWriter, MediaClip
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


def _holds(row: HistoryRecord, moment: datetime) -> bool:
    """Whether ``row`` has not ended before ``moment`` (a row without an end still runs)."""
    ended = row.ended_at
    return ended is None or ended >= moment


def _detection_match(
    rows: list[HistoryRecord],
    event_at: datetime,
    video_path: str | None,
    early: float,
    late: float,
) -> tuple[HistoryRecord, float] | None:
    """The row of a detection at ``event_at`` and its start offset (seconds), or None.

    A row named by ``video_path`` wins; else the row whose start lies within
    ``early``..``late`` seconds of the event (both included), the closest start first,
    on a tie the one that began first, then the lower ``record_id``; else the row that
    holds the event (began before the window and has not ended before the event, or
    has no end yet), the latest start first.
    """
    timed = [
        (row, (row.started_at - event_at).total_seconds())
        for row in rows
        if row.started_at is not None
    ]
    if video_path is not None:
        named = [c for c in timed if c[0].video_path == video_path]
        if named:
            return named[0]
    near = [c for c in timed if early <= c[1] <= late]
    if near:
        return min(near, key=lambda c: (abs(c[1]), c[1], c[0].record_id))
    holding = [c for c in timed if c[1] < early and _holds(c[0], event_at)]
    if holding:
        return max(holding, key=lambda c: (c[1], -c[0].record_id))
    return None


@dataclass(frozen=True, slots=True)
class _MatchClock:
    """When a detection's recording is looked at, and the bounds its answer follows."""

    now: datetime
    event_at: datetime | None
    retry: float
    give_up: float
    quiet: float

    def not_listed(self) -> DetectionRecording:
        """No row of the detection: ask again after the retry, within the bound."""
        return DetectionRecording(
            state=DetectionRecordingState.NOT_LISTED,
            retry_at=self._bounded(self.now + timedelta(seconds=self.retry), self.event_at),
        )

    def of_row(self, row: HistoryRecord, offset: float | None) -> DetectionRecording:
        """The detection's row, settled or still recording."""
        if StationHistory.recording_settled(row, now=self.now, quiet=self.quiet):
            return DetectionRecording(
                state=DetectionRecordingState.SETTLED, record=row, offset_s=offset
            )
        ended = row.ended_at
        wanted = self.now + timedelta(seconds=self.retry)
        if ended is not None:
            wanted = ended + timedelta(seconds=self.quiet)
        return DetectionRecording(
            state=DetectionRecordingState.RECORDING,
            record=row,
            retry_at=self._bounded(wanted, self.event_at or row.started_at),
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

    Requests only, over the station's session; it holds no state. Every default the
    public API documents (``days``, ``quiet``) is resolved by :class:`Station` before
    calling.
    """

    def __init__(self, station: HistoryOwner) -> None:
        self._station = station

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
        quiet: float,
        timeout: float | None,
    ) -> DetectionRecording:
        """See :meth:`Station.async_recording_for_detection`; ``device_sn`` is the
        event's camera, paired here."""
        if self._station.is_standalone:
            raise UnsupportedError("a standalone device lists no history")
        event_at = (
            None
            if event.event_time_ms is None
            else datetime.fromtimestamp(event.event_time_ms / 1000, UTC)
        )
        clock = _MatchClock(datetime.now(UTC), event_at, retry, give_up, quiet)
        record_id = event.record_id
        if record_id and record_id_day(record_id) is not None:
            row = await self._station.session.async_history_record(record_id, timeout=timeout)
            if row is not None and row.device_sn is not None and row.device_sn != device_sn:
                raise RecordNotFoundError(
                    "the event's record_id names another camera's row", device_sn=device_sn
                )
            if row is None or row.video_path is None:
                return clock.not_listed()
            return clock.of_row(row, None)
        if event_at is None:
            raise UnsupportedError("the event carries no time to match a recording to")
        early, late = window
        first = event_at - timedelta(seconds=give_up)  # the earliest start of a holding clip
        days = max(1, (_host_today() - first.astimezone().date()).days + 1)
        rows = await self.list_recordings(
            device_sn,
            days=days,
            since=first,
            until=(event_at + timedelta(seconds=late)).astimezone().date(),
            timeout=timeout,
        )
        found = _detection_match(rows, event_at, event.video_path, early, late)
        if found is None:
            return clock.not_listed()
        return clock.of_row(*found)

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
        :class:`UnsupportedError` for a record without either."""
        path = record.video_path
        if path is None:
            raise UnsupportedError("the record carries no recording")
        if record.device_sn is None:
            raise UnsupportedError("the record names no camera")
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
