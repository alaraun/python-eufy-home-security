"""Release a stored recording's frames at the pace they were recorded (:class:`FramePacer`).

A station plays a recording off its disk faster than it was recorded (a HomeBase 3 sent
a 26.5 s recording in 9.2 s). A consumer that shows it as it arrives, such as a live HLS window,
needs it at the recorded pace, or the window slides past what the viewer has seen.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from types import TracebackType
from typing import Final, Self

from .media import MediaFrame, MediaKind

__all__ = ["PACE_MAX_STEP_MS", "FramePacer"]

PACE_MAX_STEP_MS: Final = 1000
"""The longest wait between two video frames: a larger step of the stream clock (a gap,
a jump) is played as this long."""


class FramePacer:
    """Read ``frames`` ahead as fast as they come; hand them out at the stream clock's pace.

    With ``pace`` False the frames go as soon as they are read (read-ahead only).

    Every frame is read into memory at once (a :class:`~.session.MediaStream` drops video
    for a reader that falls behind), so the buffer holds what arrived ahead of its time,
    up to the whole recording. The first video frame goes at once; each later one when
    the stream clock has advanced by as much since the previous one (a step backwards
    counts as 0, one longer than :data:`PACE_MAX_STEP_MS` as that). A video frame that is
    already late goes at once, and the frames after it are paced from then. Audio and
    other frames go in arrival order without a wait. An error of ``frames`` is raised
    after the frames read before it.

    Use as ``async with FramePacer(frames) as paced: async for frame in paced: ...``;
    leaving the block stops the read-ahead.
    """

    def __init__(
        self,
        frames: AsyncIterator[MediaFrame],
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
        pace: bool = True,
    ) -> None:
        self._frames = frames
        self._pace_frames = pace
        self._clock = clock
        self._sleep = sleep
        self._buffer: deque[MediaFrame] = deque()
        self._wake = asyncio.Event()
        self._done = False
        self._error: Exception | None = None
        self._task: asyncio.Task[None] | None = None
        self._due = 0.0
        self._last_ms: int | None = None
        self.peak_frames = 0
        """The most frames held ahead of their time at once."""

    async def __aenter__(self) -> Self:
        self._task = asyncio.create_task(self._read())
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> MediaFrame:
        if self._task is None and not self._done:
            raise RuntimeError("iterate a FramePacer inside its 'async with' block")
        while not self._buffer:
            if self._done:
                if self._error is not None:
                    error, self._error = self._error, None
                    raise error
                raise StopAsyncIteration
            self._wake.clear()
            await self._wake.wait()
        frame = self._buffer.popleft()
        if self._pace_frames and frame.kind is MediaKind.VIDEO:
            await self._pace(frame.timestamp_ms)
        return frame

    async def _read(self) -> None:
        try:
            async for frame in self._frames:
                self._buffer.append(frame)
                self.peak_frames = max(self.peak_frames, len(self._buffer))
                self._wake.set()
        except Exception as err:  # handed to the reader, raised there
            self._error = err
        finally:
            self._done = True
            self._wake.set()

    async def _pace(self, timestamp_ms: int) -> None:
        now = self._clock()
        if self._last_ms is None:
            self._due = now
        else:
            # A step backwards leaves the frame due before now: it goes at once.
            step = min(timestamp_ms - self._last_ms, PACE_MAX_STEP_MS)
            self._due += step / 1000
        self._last_ms = timestamp_ms
        if self._due <= now:
            self._due = now
            return
        await self._sleep(self._due - now)
