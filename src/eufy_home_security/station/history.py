"""A station's event history and the recordings on its disk (:class:`StationHistory`)."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import replace
from datetime import date, datetime, timedelta
from typing import Any, Protocol

from ..cloud.models import CloudDevice
from ..events import HistoryRecord
from ..exceptions import EufySecurityError, UnsupportedError
from ..p2p.clip import ClipWriter, MediaClip
from ..p2p.messages import DB_QUERY_HISTORY, history_query_verb, record_id_day
from ..p2p.session import StationSession
from ..recordings import RecordingPosition, RecordingsPage, decode_cursor, decode_ref, encode_cursor


def _host_today() -> date:
    """Today in the host's zone: the newest day of a recordings window."""
    return datetime.now().astimezone().date()


def _host_day(value: date) -> date:
    """A day, or a ``datetime``'s host-local day."""
    return value.astimezone().date() if isinstance(value, datetime) else value


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
        path = record.video_path
        if path is None:
            raise UnsupportedError("the record carries no recording")
        if record.device_sn is None:
            raise UnsupportedError("the record names no camera")
        channel = self._station.channel_for(record.device_sn)
        clip = await self._station.session.async_download_recording(path, channel, write, wait=wait)
        # Read the row again: a clip still recording when the download began has more
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
