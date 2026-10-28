"""Event history queries of a station session (``DB_QUERY_HISTORY``, ``DB_QUERY_LOCAL_EVENTS``)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import date, timedelta
from typing import cast

from ...events import HistoryRecord
from ...exceptions import DeviceTimeoutError, RecordingRefError, RecordNotFoundError
from ...models import STATION_CHANNEL
from ...recordings import RecordingRef, encode_ref, issue_ref, row_started
from .._json import json_int
from ..messages import (
    CMD_DATABASE,
    DB_QUERY_HISTORY,
    DB_QUERY_LOCAL_EVENTS,
    device_msg,
    flatten_history_rows,
    history_cursor_time,
    history_query_payload,
    history_query_verb,
    local_events_query_payload,
    record_id_day,
)
from ..xzyh import FrameType
from .core import Inbound, RequestCore

_LOGGER = logging.getLogger(__name__)

HISTORY_PAGE_SIZE = 50
"""Default history page size for a ``DB_QUERY_HISTORY`` station."""
HISTORY_LOCAL_PAGE_SIZE = 20
"""The page the app asks of a station queried with ``DB_QUERY_LOCAL_EVENTS``."""
HISTORY_MAX_PAGES = 1000
"""Pages read for one day before giving up on a station that never runs out."""
HISTORY_DATE_FORMAT = "%Y%m%d"


class HistoryQueries:
    """A station's event history over its session: day pages, one record, a reference.

    Queries are serialised: a reply without a ``transaction`` binds to any. Every
    ``timeout`` is a number; the session resolves the default
    (``p2p.session.HISTORY_QUERY_TIMEOUT``) before calling.
    """

    def __init__(self, core: RequestCore) -> None:
        self._core = core
        self._lock = asyncio.Lock()

    async def list_by_day(
        self,
        start_date: str,
        end_date: str | None = None,
        *,
        count: int | None = None,
        before: int | None = None,
        before_day: date | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        device_sn: str | None = None,
        page_size: int | None = None,
        timeout: float,
    ) -> list[tuple[date, HistoryRecord]]:
        """See :meth:`StationSession.async_list_history_by_day`."""
        verb = history_query_verb(self._core.serial)
        # A camera's own list is filtered at the station (device_info), as the app does.
        native_device_sn = device_sn if verb == DB_QUERY_LOCAL_EVENTS else None
        if page_size is None:
            page_size = HISTORY_PAGE_SIZE if verb == DB_QUERY_HISTORY else HISTORY_LOCAL_PAGE_SIZE
        if page_size < 2:
            raise ValueError("page_size must be at least 2")
        if count is not None and count < 1:
            raise ValueError("count must be at least 1")
        first = _parse_day(start_date)
        last = first if end_date is None else _parse_day(end_date)
        if first > last:
            raise ValueError(f"start date {start_date} is after end date {end_date}")
        cursor_day = _cursor_day(before, before_day)
        records: list[tuple[date, HistoryRecord]] = []
        seen: set[int] = set()
        day = last if cursor_day is None else min(last, cursor_day)
        while day >= first:
            await self._history_day(
                day,
                records,
                seen,
                verb=verb,
                count=count,
                start_id=before if day == cursor_day else None,
                keep=keep,
                device_sn=native_device_sn,
                page_size=page_size,
                timeout=timeout,
            )
            if count is not None and len(records) >= count:
                return records[:count]
            day -= timedelta(days=1)
        return records

    async def record(self, record_id: int, *, timeout: float) -> HistoryRecord | None:
        """See :meth:`StationSession.async_history_record`."""
        day = _record_day(record_id)
        page, _ = await self._history_page(day, record_id, 2, timeout)
        row = next((r for r in page if r.record_id == record_id), None)
        return (
            None if row is None else self._with_ref(row, day, history_query_verb(self._core.serial))
        )

    async def find(self, ref: RecordingRef, *, timeout: float) -> HistoryRecord:
        """See :meth:`StationSession.async_find_history_record`."""
        if history_query_verb(self._core.serial) == DB_QUERY_LOCAL_EVENTS:
            row = await self._find_local_event(ref, timeout)
        else:
            page, _ = await self._history_page(ref.day, ref.record_id, 2, timeout)
            names = (ref.record_id, ref.device_sn)
            row = next((r for r in page if (r.record_id, r.device_sn) == names), None)
        if row is None:
            raise RecordNotFoundError(
                f"{self._core._log_name}: the station lists no such recording",
                device_sn=ref.device_sn,
            )
        return replace(row, ref=encode_ref(ref, station_sn=self._core.serial))

    async def _find_local_event(self, ref: RecordingRef, timeout: float) -> HistoryRecord | None:
        """The row ``ref`` names under ``DB_QUERY_LOCAL_EVENTS``, or None (see
        :meth:`async_find_history_record`)."""
        cursors = ref.time_cursors()
        if cursors is None:
            raise RecordingRefError("the recording reference names no start time to ask by")
        names = (ref.record_id, ref.device_sn, ref.started)
        for cursor in cursors:
            page, _ = await self._history_page(
                ref.day,
                0,
                HISTORY_LOCAL_PAGE_SIZE,
                timeout,
                verb=DB_QUERY_LOCAL_EVENTS,
                start_time=cursor,
                device_sn=ref.device_sn,
            )
            for row in page:
                if (row.record_id, row.device_sn, row_started(row)) == names:
                    return row
            starts = [s for r in page if (s := row_started(r)) is not None]
            # a full page with no row started before the ref may hide it: ask on once
            if len(page) < HISTORY_LOCAL_PAGE_SIZE or min(starts, default=cursors[1]) < cursors[1]:
                return None
        return None

    def _with_ref(self, row: HistoryRecord, day: date, verb: int) -> HistoryRecord:
        """``row`` listed under the station ``day`` with its reference (see
        :func:`~...recordings.issue_ref`; under ``DB_QUERY_LOCAL_EVENTS`` a row is found
        again by its start time)."""
        ref = issue_ref(
            row, day, station_sn=self._core.serial, need_started=verb == DB_QUERY_LOCAL_EVENTS
        )
        return row if ref is None else replace(row, ref=ref)

    async def _history_day(
        self,
        day: date,
        records: list[tuple[date, HistoryRecord]],
        seen: set[int],
        *,
        verb: int = DB_QUERY_HISTORY,
        count: int | None,
        start_id: int | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        device_sn: str | None = None,
        page_size: int,
        timeout: float,
    ) -> None:
        """Add one day's records to ``records``, page by page, until the day or ``count``
        runs out; ``seen`` holds the ``record_id`` values already met. With
        ``start_id`` the day is paged from that row, which is left out (under
        ``DB_QUERY_LOCAL_EVENTS`` the day is paged from its newest row and the rows
        from ``start_id`` up are left out); only rows ``keep`` accepts are added."""
        cursor = start_id or 0
        if start_id:
            seen.add(start_id)  # the first page starts with the cursor row
        local = verb == DB_QUERY_LOCAL_EVENTS
        time_cursor = "0"
        first_id: int | None = None
        for number in range(1, HISTORY_MAX_PAGES + 1):
            page, oldest = await self._history_page(
                day,
                cursor if not local else 0,
                page_size,
                timeout,
                resend=True,
                verb=verb,
                start_time=time_cursor,
                device_sn=device_sn,
            )
            wanted = page
            if local and start_id:
                wanted = [r for r in page if not r.record_id or r.record_id < start_id]
            fresh = [r for r in wanted if not r.record_id or r.record_id not in seen]
            seen.update(r.record_id for r in fresh)
            kept = [r for r in fresh if keep is None or keep(r)]
            records.extend((day, self._with_ref(r, day, verb)) for r in kept)
            stop: str | None = None
            if count is not None and len(records) >= count:
                stop = "enough rows"
            elif len(page) < page_size:
                stop = "short page"
            elif local:
                # The app's paging: the oldest start_time of the page, and a page that
                # starts with the same row as the last one ends the day.
                times = [r.start_time for r in page if r.start_time]
                if page[0].record_id and page[0].record_id == first_id:
                    stop = "first row repeats"
                elif not times:
                    stop = "no start_time to page from"
                else:
                    first_id = page[0].record_id
                    time_cursor = history_cursor_time(min(times))
            elif not fresh or oldest is None or oldest == cursor:
                stop = "no new cursor"
            else:
                cursor = oldest
            _LOGGER.debug(
                "%s: history of %s, page %d: %d row(s), %d new, %d kept; %s",
                self._core._log_name,
                day.isoformat(),
                number,
                len(page),
                len(fresh),
                len(kept),
                f"last page ({stop})" if stop else "asking the next",
            )
            if stop:
                return
        _LOGGER.warning(
            "%s: history of %s still had rows after %d pages; the rest is left out",
            self._core._log_name,
            day.isoformat(),
            HISTORY_MAX_PAGES,
        )

    async def _history_page(
        self,
        day: date,
        start_id: int,
        page_size: int,
        timeout: float,
        *,
        resend: bool = False,
        verb: int = DB_QUERY_HISTORY,
        start_time: str = "0",
        device_sn: str | None = None,
    ) -> tuple[list[HistoryRecord], int | None]:
        """One page of a day's history and the cursor for the next (its oldest ``record_id``).

        ``verb`` picks the query: ``DB_QUERY_HISTORY`` pages from ``start_id``,
        ``DB_QUERY_LOCAL_EVENTS`` from ``start_time``. ``resend``: after a timeout, ask
        the same page once more; a late reply to the first query answers the second as
        well.
        """
        await self._core.async_connect()
        creds = self._core._require_creds()
        sent: set[str] = set()

        def send() -> None:
            transaction = str(int(time.time() * 1000))
            sent.add(transaction)
            dates = (
                day.strftime(HISTORY_DATE_FORMAT),
                (day + timedelta(days=1)).strftime(HISTORY_DATE_FORMAT),
            )
            if verb == DB_QUERY_LOCAL_EVENTS:
                payload = local_events_query_payload(
                    *dates,
                    count=page_size,
                    start_time=start_time,
                    device_sns=() if device_sn is None else (device_sn,),
                    transaction=transaction,
                )
            else:
                payload = history_query_payload(
                    *dates, count=page_size, start_id=start_id, transaction=transaction
                )
            self._core._send_secure(
                device_msg(creds.account_id, CMD_DATABASE, payload, channel=STATION_CHANNEL)
            )

        def match(inbound: Inbound) -> tuple[list[HistoryRecord], int | None] | None:
            if inbound.type != FrameType.DB_SYNC or (obj := inbound.json()) is None:
                return None
            if json_int(obj.get("cmd")) != verb:
                return None
            echoed = obj.get("transaction")
            if echoed is not None and str(echoed) not in sent:
                return None  # another client's page: every session sees the replies
            page = [HistoryRecord.from_row(row) for row in flatten_history_rows(obj)]
            ids = [r.record_id for r in page if r.record_id]
            oldest = json_int(obj.get("end_id"))
            if oldest is None or oldest not in ids:
                oldest = min(ids, default=None)
            return page, oldest

        async with self._lock:
            try:
                result = await self._core._request(
                    send, match, timeout=timeout, label="history query", send_only_under_lock=True
                )
            except DeviceTimeoutError:
                if not resend:
                    raise
                _LOGGER.info(
                    "%s: history query of %s unanswered within %.0fs; asking once more",
                    self._core._log_name,
                    day.isoformat(),
                    timeout,
                )
                result = await self._core._request(
                    send, match, timeout=timeout, label="history query", send_only_under_lock=True
                )
        return cast(tuple[list[HistoryRecord], int | None], result)


def _record_day(record_id: int) -> date:
    """The day of a date-prefixed ``record_id``; ValueError when it has none."""
    day = record_id_day(record_id)
    if day is None:
        raise ValueError(f"record_id {record_id} carries no day")
    return day


def _cursor_day(before: int | None, before_day: date | None) -> date | None:
    """The day a history cursor pages from: the day ``before`` carries, else
    ``before_day``; ValueError for a cursor without a day or two that disagree."""
    if before is None:
        if before_day is not None:
            raise ValueError("before_day needs before")
        return None
    own = record_id_day(before)
    if own is None:
        if before_day is None:
            raise ValueError(f"record_id {before} carries no day")
        return before_day
    if before_day is not None and before_day != own:
        raise ValueError(f"before_day {before_day} is not the day record_id {before} carries")
    return own


def _parse_day(text: str) -> date:
    """A ``YYYYMMDD`` date; ValueError for anything else."""
    if len(text) != 8 or not text.isascii() or not text.isdigit():
        raise ValueError(f"not a YYYYMMDD date: {text!r}")
    return date(int(text[:4]), int(text[4:6]), int(text[6:]))
