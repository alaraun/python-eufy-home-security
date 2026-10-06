"""Share one camera's live stream between several viewers.

A live stream costs a station session and, on a battery camera, battery. Two browser
tabs on the same camera must therefore not open two streams: :class:`StreamBroadcast`
opens one, muxes it once, and fans the bytes out to every subscriber.

It also decides what to do when a subscriber cannot keep up. A slow reader must never
stall the camera — the station drops a stream whose frames are not acknowledged — so a
subscriber that falls behind loses data rather than holding everyone back.

A picture-size change mid-stream (a T8170 zoom from 2x to 2.5x, a go-to between presets
of different zoom) keeps the subscribers' stream by default (``on_resize="continue"``):
the video resumes at the next keyframe at the new size. The camera's opening resolution
ramp is carried the same way, so by default the stream starts at the first keyframe.
``on_resize="end"`` ends the subscribers' stream instead, optionally keeping the camera
open for ``resize_grace`` seconds so the consumer's reconnect needs no wake and no
settle; it waits for the ramp to finish (the settle window) before starting.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Literal, Protocol

from ..exceptions import DeviceTimeoutError
from .clip import ClipWriter, MediaClip, mux_frames
from .encoder import SETTLE_STANDALONE, SETTLE_STATION, StreamEncoder
from .media import MediaFrame, MediaKind

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "CAPTURE_QUEUE_FRAMES",
    "CAPTURE_START_TIMEOUT",
    "DEFAULT_QUEUE_CHUNKS",
    "FrameStream",
    "ResizePolicy",
    "StreamBroadcast",
]

#: How many muxed chunks a subscriber may fall behind before it is resynchronised.
#: A chunk is one frame, so this is a few seconds of video.
DEFAULT_QUEUE_CHUNKS = 120

ResizePolicy = Literal["continue", "end"]
"""What a broadcast does when the picture size changes after the stream started."""


def out_size(size: tuple[int, int] | None) -> str:
    """``WxH`` for a log line."""
    return "unknown" if size is None else f"{size[0]}x{size[1]}"


class FrameStream(Protocol):
    """What a broadcast needs of a stream: iterate its frames, then close it.

    :class:`~.session.MediaStream` satisfies this. Stating it as a protocol keeps the
    broadcast testable without a station, and says plainly that nothing else about a
    stream is used.
    """

    def __aiter__(self) -> AsyncIterator[MediaFrame]: ...

    async def aclose(self) -> None: ...


class _Subscriber:
    """One reader's queue, and how far behind it has fallen."""

    __slots__ = ("dropped", "queue")

    def __init__(self, limit: int) -> None:
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=limit)
        self.dropped = 0


#: Frames a live capture may fall behind its writer before video is skipped to the next
#: keyframe (about a minute of 15 fps video with its audio).
CAPTURE_QUEUE_FRAMES = 2000
#: Seconds a live capture allows beyond its length for the camera to open and deliver.
CAPTURE_START_TIMEOUT = 30.0


class _Tap:
    """One live capture's copy of the camera's frames."""

    __slots__ = ("dropped", "need_keyframe", "queue", "started_at")

    def __init__(self) -> None:
        self.queue: asyncio.Queue[MediaFrame | None] = asyncio.Queue(maxsize=CAPTURE_QUEUE_FRAMES)
        self.need_keyframe = False
        self.dropped = 0
        self.started_at: datetime | None = None
        """When the first keyframe reached the capture (UTC): the clip's first frame."""

    def offer(self, frame: MediaFrame) -> None:
        """Queue ``frame``; when full, skip video until the next keyframe."""
        is_video = frame.kind is MediaKind.VIDEO
        if is_video and self.need_keyframe and not frame.is_keyframe:
            self.dropped += 1
            return
        try:
            self.queue.put_nowait(frame)
        except asyncio.QueueFull:
            self.dropped += 1
            self.need_keyframe = self.need_keyframe or is_video
            return
        if is_video:
            self.need_keyframe = False
            if frame.is_keyframe and self.started_at is None:
                self.started_at = datetime.now(UTC)

    def end(self) -> None:
        """Tell the capture the stream is over, even with its queue full."""
        while True:
            try:
                self.queue.put_nowait(None)
                return
            except asyncio.QueueFull:
                self.queue.get_nowait()

    async def frames(self, deadline: float) -> AsyncIterator[MediaFrame]:
        """The queued frames until the stream ends or the loop clock reaches ``deadline``."""
        loop = asyncio.get_running_loop()
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            try:
                async with asyncio.timeout(remaining):
                    frame = await self.queue.get()
            except TimeoutError:
                return
            if frame is None:
                return
            yield frame


class StreamBroadcast:
    """One muxed MPEG-TS stream, shared by any number of subscribers.

    The stream is opened by ``open_stream`` on the first subscriber and closed when the
    last one leaves, so a camera is only woken while someone is watching. Subscribe with
    :meth:`subscribe`, which yields muxed TS bytes:

    ```python
    broadcast = StreamBroadcast(lambda: session.async_open_live(0))
    async for chunk in broadcast.subscribe():
        await response.write(chunk)
    ```

    Every subscriber receives :attr:`header` first — the tables and the opening keyframe
    — so one joining mid-stream can start decoding immediately instead of waiting for
    the next keyframe.

    ``on_resize`` (see :data:`ResizePolicy`): ``"continue"`` keeps the subscribers'
    stream across a picture-size change, including the camera's opening ramp, and
    starts at the first keyframe (settle 0). ``"end"`` ends it and sets
    :attr:`ended_by_resize`, and starts only once the size has held for the settle
    window (:data:`~.encoder.SETTLE_STATION` or :data:`~.encoder.SETTLE_STANDALONE`,
    by ``standalone``). An explicit ``settle`` wins in both cases. With ``"end"``,
    ``resize_grace`` > 0 keeps the camera stream open that many seconds with no
    subscriber, and a subscriber joining within it reuses the open stream. A battery
    camera stays awake for the grace time.

    ``fill_audio`` (with ``audio``) declares the AAC track at the start and carries
    silence until the camera's audio arrives, so a stream started before the first
    audio frame still has audio; a camera that sends none yields a silent track.
    """

    def __init__(
        self,
        open_stream: Callable[[], Awaitable[FrameStream]],
        *,
        audio: bool = True,
        settle: float | None = None,
        standalone: bool = False,
        queue_chunks: int = DEFAULT_QUEUE_CHUNKS,
        on_resize: ResizePolicy = "continue",
        resize_grace: float = 0.0,
        fill_audio: bool = True,
        name: str = "stream",
    ) -> None:
        if on_resize not in ("continue", "end"):
            msg = f"on_resize must be 'continue' or 'end', not {on_resize!r}"
            raise ValueError(msg)
        self._open_stream = open_stream
        self._audio = audio
        self._fill_audio = fill_audio
        # A followed stream carries the opening ramp and starts at once. An ending one
        # waits out the ramp, whose length is library knowledge: the two kinds ramp in
        # opposite directions. Pass ``standalone`` (``Station.is_standalone`` or
        # ``StationSession.standalone``); an explicit ``settle`` still wins.
        if settle is None:
            settle = (
                0.0
                if on_resize == "continue"
                else (SETTLE_STANDALONE if standalone else SETTLE_STATION)
            )
        self._settle: float = settle
        self._queue_chunks = max(1, queue_chunks)
        self._on_resize: ResizePolicy = on_resize
        self._resize_grace = max(0.0, resize_grace)
        self._name = name
        self._subscribers: set[_Subscriber] = set()
        self._taps: set[_Tap] = set()
        self._encoder = self._new_encoder()
        self._pump: asyncio.Task[None] | None = None
        self._stream: FrameStream | None = None
        self._started = asyncio.Event()
        self._error: Exception | None = None
        self._ended_by_resize = False
        self._grace_until: float | None = None
        self._grace_handle: asyncio.TimerHandle | None = None
        self._grace_stop: asyncio.Task[None] | None = None

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def subscribers(self) -> int:
        """How many readers are attached."""
        return len(self._subscribers)

    @property
    def running(self) -> bool:
        """Whether the camera stream is open."""
        return self._pump is not None and not self._pump.done()

    @property
    def settle(self) -> float:
        """The settle window in use, in seconds."""
        return self._settle

    @property
    def error(self) -> Exception | None:
        """Why the last stream ended, or ``None`` if it ended cleanly.

        A subscriber only ever sees its iteration end, because a failed or slow stream
        must never hang a reader. This says what happened, so a caller can tell a
        camera that could not be woken (:class:`~..exceptions.StationUnreachableError`)
        from one that simply stopped — the first is worth retrying and worth telling the
        user about, the second is not.

        Cleared when a new stream starts.
        """
        return self._error

    @property
    def ended_by_resize(self) -> bool:
        """Whether the subscribers' last stream ended at a picture-size change.

        Only with ``on_resize="end"``; :attr:`error` stays ``None`` for it. Cleared when
        a new stream starts or a subscriber joins the camera stream kept open for
        ``resize_grace``.
        """
        return self._ended_by_resize

    @property
    def resizes(self) -> int:
        """Picture-size changes the running stream followed (``on_resize="continue"``)."""
        return self._encoder.resizes

    @property
    def header(self) -> bytes:
        """Tables and the latest start keyframe, sent to each new subscriber.

        After a followed size change this is the keyframe at the new size.
        """
        return self._encoder.header

    @property
    def size(self) -> tuple[int, int] | None:
        """The frame size being streamed, once the stream has settled."""
        return self._encoder.size

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def __aenter__(self) -> StreamBroadcast:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Stop the camera stream and release every subscriber and capture."""
        self._end_grace()
        await self._stop()
        self._finish_subscribers()
        self._end_taps()

    async def _close_stream(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            with contextlib.suppress(Exception):
                await stream.aclose()

    def _finish_subscribers(self) -> None:
        """Tell every subscriber the stream is over.

        The sentinel must arrive even when a reader's queue is full, or that reader
        waits forever on a stream that has already ended. A subscriber that is behind
        has lost data anyway, so its backlog is dropped to make room.
        """
        for sub in list(self._subscribers):
            try:
                sub.queue.put_nowait(None)
            except asyncio.QueueFull:
                self._drain(sub)
                with contextlib.suppress(asyncio.QueueFull):
                    sub.queue.put_nowait(None)

    # ── subscription ─────────────────────────────────────────────────────────

    async def subscribe(self) -> AsyncGenerator[bytes]:
        """Yield muxed TS bytes until the stream ends or the subscriber goes away.

        The first chunk is :attr:`header` when the stream has already started, so a late
        joiner can decode at once. Close the generator (or simply stop iterating) to
        unsubscribe; the camera is released when the last subscriber leaves.
        """
        sub = _Subscriber(self._queue_chunks)
        self._subscribers.add(sub)
        try:
            if self._grace_until is not None and self.running:
                # Joining the camera stream kept open after a resize end.
                _LOGGER.debug("%s: a subscriber rejoined within the resize grace", self._name)
                self._end_grace()
                self._ended_by_resize = False
            self._ensure_pump()
            header = self._encoder.header
            if header:
                yield header
            while True:
                chunk = await sub.queue.get()
                if chunk is None:
                    break
                yield chunk
        finally:
            self._subscribers.discard(sub)
            if sub.dropped:
                _LOGGER.debug(
                    "%s: subscriber fell behind and lost %d chunks", self._name, sub.dropped
                )
            if not self._subscribers and not self._taps and not self._in_grace():
                # The last viewer left: stop the camera rather than keep it awake.
                await self._stop()

    @property
    def captures(self) -> int:
        """Live captures (:meth:`async_capture`) running."""
        return len(self._taps)

    async def async_capture(
        self, seconds: float, write: ClipWriter, *, start_timeout: float | None = None
    ) -> MediaClip:
        """Write ``seconds`` of the live stream, from its next keyframe, as one MPEG-TS clip.

        Opens the camera when nothing streams (a battery camera wakes) and holds it
        open like a subscriber until the clip is done, sharing the one camera stream
        with every viewer and other capture. The clip has its own muxer: the tables and
        a keyframe first, the camera's HEVC and AAC untouched, a picture-size change
        carried at the next keyframe, its own timestamps whatever a viewer joined.
        ``seconds`` is camera time from that keyframe. ``write`` receives the bytes in
        order (see :mod:`~.clip`); a writer slower than the camera loses video to the
        next keyframe rather than stalling the stream.

        A stream that ends, or stops delivering, before ``seconds`` returns what it got
        with ``ended_early``; the camera is given ``start_timeout`` (None:
        :data:`CAPTURE_START_TIMEOUT`, read at call time) beyond ``seconds``
        to deliver it all. Raises the open's error (:attr:`error`), or
        :class:`~..exceptions.DeviceTimeoutError` when no keyframe arrived, and
        ``ValueError`` for ``seconds`` that is not a positive finite number.
        """
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError(f"seconds must be a positive number, not {seconds!r}")
        tap = _Tap()
        self._taps.add(tap)
        try:
            if self._grace_until is not None and self.running:
                self._end_grace()
                self._ended_by_resize = False
            self._ensure_pump()
            extra = CAPTURE_START_TIMEOUT if start_timeout is None else start_timeout
            deadline = asyncio.get_running_loop().time() + seconds + extra
            muxer, reached = await mux_frames(
                tap.frames(deadline), write, max_ms=round(seconds * 1000)
            )
        finally:
            self._taps.discard(tap)
            if not self._subscribers and not self._taps and not self._in_grace():
                await self._stop()
        if tap.dropped:
            _LOGGER.debug("%s: a capture fell behind and lost %d frames", self._name, tap.dropped)
        if not muxer.started:
            if self._error is not None:
                raise self._error
            raise DeviceTimeoutError("the live stream delivered no keyframe for the capture")
        return muxer.clip(started_at=tap.started_at, ended_early=not reached)

    async def _stop(self) -> None:
        """Stop the pump and the camera stream, leaving subscribers untouched."""
        pump, self._pump = self._pump, None
        if pump is not None and not pump.done():
            pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pump
        await self._close_stream()

    def _ensure_pump(self) -> None:
        """Start the camera stream if it is not already running.

        A broadcast is reusable: after the last viewer leaves and the stream closes, a
        new subscriber starts it again. That needs a **fresh encoder**, because the old
        one holds the previous stream's muxer, timestamps and header — replaying those
        to a new stream would hand a decoder continuity counters and a clock that do not
        match the frames that follow.
        """
        if self._pump is not None and not self._pump.done():
            return
        self._end_grace()
        self._encoder = self._new_encoder()
        self._started = asyncio.Event()
        self._error = None
        self._ended_by_resize = False
        self._pump = asyncio.get_running_loop().create_task(self._run())

    def _new_encoder(
        self, *, settle: float | None = None, assume_audio: bool = False
    ) -> StreamEncoder:
        return StreamEncoder(
            audio=self._audio,
            settle=self._settle if settle is None else settle,
            follow_resize=self._on_resize == "continue",
            assume_audio=assume_audio,
            fill_audio=self._fill_audio,
        )

    # ── resize grace ─────────────────────────────────────────────────────────

    def _in_grace(self) -> bool:
        return self._grace_until is not None and time.monotonic() < self._grace_until

    def _begin_grace(self) -> None:
        """Keep the camera stream open ``resize_grace`` s for a reconnecting subscriber."""
        self._grace_until = time.monotonic() + self._resize_grace
        self._grace_handle = asyncio.get_running_loop().call_later(
            self._resize_grace, self._grace_expired
        )

    def _end_grace(self) -> None:
        self._grace_until = None
        handle, self._grace_handle = self._grace_handle, None
        if handle is not None:
            handle.cancel()

    def _grace_expired(self) -> None:
        self._grace_handle = None
        self._grace_until = None
        if self._subscribers:
            return
        _LOGGER.debug("%s: nobody rejoined within the resize grace; closing", self._name)
        self._grace_stop = asyncio.get_running_loop().create_task(self._stop())

    # ── the pump ─────────────────────────────────────────────────────────────

    async def _run(self) -> None:
        """Read the camera, mux, and hand the bytes to every subscriber."""
        try:
            stream = await self._open_stream()
        except Exception as err:
            self._error = err
            _LOGGER.debug("%s: could not open the camera stream: %s", self._name, err)
            self._finish_subscribers()
            self._end_taps()
            return

        self._stream = stream
        try:
            async for frame in stream:
                for tap in self._taps:
                    tap.offer(frame)
                out = self._encoder.feed(frame)
                if out.resized:
                    # on_resize="end": the subscribers' stream ends here.
                    self._ended_by_resize = True
                    if self._resize_grace <= 0:
                        _LOGGER.info(
                            "%s: the camera changed resolution mid-stream; ending", self._name
                        )
                        break
                    _LOGGER.info(
                        "%s: the camera changed resolution mid-stream; ending the "
                        "subscribers' stream, camera kept open %.0f s",
                        self._name,
                        self._resize_grace,
                    )
                    # The camera has settled already: start again at the first
                    # keyframe of the new size, with the audio decision carried over.
                    self._encoder = self._new_encoder(
                        settle=0.0, assume_audio=self._encoder.has_audio
                    )
                    self._begin_grace()  # before the sentinels: leavers must not stop the camera
                    self._finish_subscribers()
                    self._encoder.feed(frame)
                    continue
                if out.restarted:
                    _LOGGER.debug(
                        "%s: the camera changed resolution mid-stream; following at %s",
                        self._name,
                        out_size(self._encoder.size),
                    )
                if out.started:
                    self._started.set()
                if out.data:
                    self._publish(out.data)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self._error = err
            _LOGGER.debug("%s: stream ended: %s", self._name, err)
        finally:
            await self._close_stream()
            self._finish_subscribers()
            self._end_taps()

    def _end_taps(self) -> None:
        for tap in list(self._taps):
            tap.end()

    def _publish(self, chunk: bytes) -> None:
        """Hand one muxed chunk to every subscriber, dropping for those behind.

        A subscriber that cannot keep up must not stall the camera: the station stops
        sending when its frames are not read. A full queue is drained back to the
        header instead, so the reader resumes at a keyframe rather than mid-picture.
        """
        for sub in list(self._subscribers):
            try:
                sub.queue.put_nowait(chunk)
            except asyncio.QueueFull:
                sub.dropped += self._resync(sub)

    @staticmethod
    def _drain(sub: _Subscriber) -> int:
        """Empty a subscriber's queue; returns how many chunks were lost."""
        lost = 0
        while True:
            try:
                sub.queue.get_nowait()
            except asyncio.QueueEmpty:
                return lost
            lost += 1

    def _resync(self, sub: _Subscriber) -> int:
        """Empty a subscriber's queue and restart it at the header. Returns the loss."""
        lost = self._drain(sub)
        header = self._encoder.header
        if header:
            with contextlib.suppress(asyncio.QueueFull):
                sub.queue.put_nowait(header)
        return lost
