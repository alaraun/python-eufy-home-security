"""A station's session budget: extra sessions, trigger frames, downloads (:class:`SessionBudget`)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Protocol, cast

from ...devices.live_open import LiveOpen, LiveStop
from ...devices.live_view import LiveView
from ...events import DisconnectCause
from ...exceptions import (
    DeviceTimeoutError,
    EufySecurityError,
    LiveStreamLimitError,
    UnsupportedError,
)
from ..clip import ClipWriter, MediaClip, mux_frames
from ..media import MediaKeyType, MediaKind
from ..messages import DB_QUERY_LOCAL_EVENTS, history_query_verb
from .media_stream import MediaStream
from .stats import HealthCounters, MediaCounters
from .wake import WakeBackoff

if TYPE_CHECKING:
    from .media_slot import MediaSlot

_LOGGER = logging.getLogger(__name__)


class SessionBudget:
    """How many sessions a station session holds to its station, and which.

    A station session keeps its own media slot and up to ``max_sessions - 2`` extra
    sessions shared by live streams and recording downloads (one more session is the
    trigger frame's). An extra session's own budget names its station session as
    :attr:`owner`; ending it returns it to that budget and wakes the opens waiting for
    capacity.
    """

    def __init__(self, session: BudgetOwner, *, max_sessions: int) -> None:
        self._session = session
        self.max_sessions = max_sessions
        """See :attr:`StationSession.max_sessions`."""
        self.extra_live: set[BudgetOwner] = set()
        """Extra sessions carrying (or opening) a live stream while this session's slot is
        busy, or a recording download."""
        self.capacity_waiters: list[asyncio.Future[None]] = []
        """Live opens and downloads waiting for this session's slot or an extra session."""
        self.owner: BudgetOwner | None = None
        """On an extra session: the station session whose budget it counts against."""
        self.slot_claimed = False
        """A live open routed to this session's slot has not set its stream yet."""
        self.trigger_frame_lock = asyncio.Lock()
        """At most one short-lived trigger-frame session per station at a time."""
        self.download_lock = asyncio.Lock()
        """At most one recording download per station at a time."""

    async def live_route(self, timeout: float, wait: bool) -> BudgetOwner | None:
        """Where a HomeBase live open goes: None for this session's own media slot (then
        claimed), else an extra session reserved for it.

        The slot is taken first; while it is busy (any stream, any camera) the open gets
        an extra session, up to ``max_sessions - 2`` of them. Past that it raises
        :class:`LiveStreamLimitError` at once, or with ``wait`` once ``timeout`` passes
        without the slot or an extra session coming free.
        """
        return await self.reserve(timeout, wait, slot=True)

    async def reserve(self, timeout: float, wait: bool, *, slot: bool) -> BudgetOwner | None:
        """An extra session reserved from the budget (``max_sessions - 2`` of them, shared
        by live streams and recording downloads); with ``slot``, this session's own free
        media slot first (None, then claimed). Past the budget :class:`LiveStreamLimitError`
        at once, or with ``wait`` once ``timeout`` passes without one coming free."""
        deadline = time.monotonic() + timeout
        while True:
            self._session._raise_if_closed()
            self._session._media_slot.close_abandoned()
            if slot and self._session._media_slot.stream is None and not self.slot_claimed:
                self.slot_claimed = True
                return None
            limit = self.max_sessions - 1
            if len(self.extra_live) < limit - 1:
                extra = self._session._short_lived_session()
                extra._budget.owner = self._session
                extra._media_counters = self._session._media_counters  # diagnostics count here
                extra._wake_backoff = self._session._wake_backoff  # one wake backoff per camera
                self.extra_live.add(extra)
                if slot:
                    self._session._health.extra_live_opened += 1
                return extra
            remaining = deadline - time.monotonic()
            if not wait or remaining <= 0:
                raise LiveStreamLimitError(
                    f"{limit} extra sessions (live streams, downloads) are already open to "
                    f"this station (the library's cap)"
                    + (f"; none closed within {timeout:g}s" if wait else ""),
                    limit=limit,
                )
            waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            self.capacity_waiters.append(waiter)
            try:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(remaining):
                        await waiter
            finally:
                if waiter in self.capacity_waiters:
                    self.capacity_waiters.remove(waiter)

    async def open_extra_live(
        self,
        extra: BudgetOwner,
        channel: int,
        first: float,
        idle: float,
        media_key: MediaKeyType = MediaKeyType.RSA,
        *,
        live_open: LiveOpen | None = None,
        live_stop: LiveStop | None = None,
        live_view: LiveView | None = None,
    ) -> MediaStream:
        """Open live on ``extra`` (the same open as this session's); the stream's end
        closes the session (PPPP CLOSE)."""
        started = time.monotonic()
        try:
            await extra.async_connect()
            _LOGGER.debug(
                "%s: live channel %d on an extra session (%d of %d), open in %.2fs",
                self._session._log_name,
                channel,
                len(self.extra_live),
                self.max_sessions - 2,
                time.monotonic() - started,
            )
            return await extra.async_open_live(
                channel,
                first_frame_timeout=first,
                idle_timeout=idle,
                media_key=media_key,
                live_open=live_open,
                live_stop=live_stop,
                live_view=live_view,
            )
        except BaseException:
            extra._budget.end_extra_live()
            raise

    def end_extra_live(self) -> None:
        """Close this extra session (a live stream or a download) and return it to its
        station session's budget."""
        if not self._session._closed:
            self._session._closed = True
            self._session._teardown("extra session ended", cause=DisconnectCause.CLOSED)
            _LOGGER.debug("%s: extra session closed", self._session._log_name)
        owner = self.owner
        if owner is not None and self._session in owner._budget.extra_live:
            owner._budget.extra_live.discard(self._session)
            owner._budget.notify_capacity()

    def notify_capacity(self) -> None:
        """Wake the live opens and downloads waiting for the slot or an extra session."""
        waiters, self.capacity_waiters = self.capacity_waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)

    async def trigger_frame(
        self,
        path: str,
        channel: int,
        *,
        trailing_frames: int = 0,
        first_frame_timeout: float | None = None,
    ) -> bytes:
        """See :meth:`StationSession.async_trigger_frame`."""
        if trailing_frames < 0:
            raise ValueError("trailing_frames must not be negative")
        self._session._raise_if_closed()
        parts: list[bytes] = []
        async with self.trigger_frame_lock:
            short = self._session._short_lived_session()
            short._media_counters.codecs_by_channel = (
                self._session._media_counters.codecs_by_channel
            )
            self._session._health.trigger_frame_sessions += 1
            started = time.monotonic()
            try:
                await short.async_connect()
                _LOGGER.debug(
                    "%s: trigger frame on channel %d: short-lived session open in %.2fs",
                    self._session._log_name,
                    channel,
                    time.monotonic() - started,
                )
                stream = await short.async_open_recording(
                    path, channel, first_frame_timeout=first_frame_timeout
                )
                async for frame in stream:
                    if frame.kind is not MediaKind.VIDEO:
                        continue
                    if parts and frame.is_keyframe:
                        break  # the next picture group: only P-frames trail
                    parts.append(frame.data)
                    if len(parts) > trailing_frames:
                        break
            finally:
                await short.async_close()  # PPPP CLOSE: the station stops sending
                _LOGGER.debug(
                    "%s: trigger frame on channel %d: short-lived session closed after %.2fs, "
                    "%d bytes",
                    self._session._log_name,
                    channel,
                    time.monotonic() - started,
                    sum(len(part) for part in parts),
                )
        if not parts:
            raise DeviceTimeoutError("the recording ended before a keyframe arrived")
        return b"".join(parts)

    async def download_recording(
        self,
        path: str,
        channel: int,
        write: ClipWriter,
        *,
        first_frame_timeout: float,
        wait: bool = True,
    ) -> MediaClip:
        """See :meth:`StationSession.async_download_recording`."""
        if self._session.standalone:
            raise UnsupportedError("a standalone device lists no recordings to download")
        self._session._raise_if_closed()
        async with self.download_lock:
            extra = cast(BudgetOwner, await self.reserve(first_frame_timeout, wait, slot=False))
            self._session._health.recording_downloads += 1
            started = time.monotonic()
            try:
                await extra.async_connect()
                stream = await extra.async_open_recording(
                    path,
                    channel,
                    download=history_query_verb(self._session.serial) == DB_QUERY_LOCAL_EVENTS,
                    first_frame_timeout=first_frame_timeout,
                )
                async with stream:
                    muxer, _ = await mux_frames(aiter(stream), write)
            finally:
                extra._budget.end_extra_live()
                _LOGGER.debug(
                    "%s: recording on channel %d downloaded on an extra session in %.2fs",
                    self._session._log_name,
                    channel,
                    time.monotonic() - started,
                )
        if not muxer.started:
            raise DeviceTimeoutError("the recording ended before a keyframe arrived")
        return muxer.clip()


class BudgetOwner(Protocol):
    """The station session members a :class:`SessionBudget` uses, on the station session
    and on its extra sessions."""

    serial: str
    _log_name: str
    _closed: bool
    _budget: SessionBudget
    _health: HealthCounters
    _media_counters: MediaCounters
    _wake_backoff: WakeBackoff
    _media_slot: MediaSlot

    @property
    def standalone(self) -> bool: ...

    def _raise_if_closed(self) -> None: ...

    def _short_lived_session(self) -> BudgetOwner: ...

    def _teardown(
        self,
        reason: str,
        *,
        cause: DisconnectCause | None = None,
        error: EufySecurityError | None = None,
    ) -> None: ...

    async def async_connect(self) -> None: ...

    async def async_open_live(
        self,
        channel: int,
        *,
        first_frame_timeout: float | None = None,
        idle_timeout: float | None = None,
        wait: bool = False,
        live_open: LiveOpen | None = None,
        live_stop: LiveStop | None = None,
        media_key: MediaKeyType = MediaKeyType.RSA,
        live_view: LiveView | None = None,
    ) -> MediaStream: ...

    async def async_open_recording(
        self,
        path: str,
        channel: int,
        *,
        download: bool = False,
        first_frame_timeout: float | None = None,
        idle_timeout: float | None = None,
        wait: bool = False,
    ) -> MediaStream: ...

    async def async_close(self) -> None: ...
