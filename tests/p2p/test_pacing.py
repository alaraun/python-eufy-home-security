"""Releasing a stored recording's frames at the pace they were recorded."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p.media import MediaFrame, MediaKind
from eufy_home_security.p2p.pacing import PACE_MAX_STEP_MS, FramePacer


def _video(ms: int) -> MediaFrame:
    return MediaFrame(MediaKind.VIDEO, b"v%d" % ms, timestamp_ms=ms)


def _audio(ms: int) -> MediaFrame:
    return MediaFrame(MediaKind.AUDIO, b"a%d" % ms, timestamp_ms=ms)


async def _source(
    frames: list[MediaFrame], error: Exception | None = None
) -> AsyncIterator[MediaFrame]:
    for frame in frames:
        yield frame
    if error is not None:
        raise error


class _Clock:
    """A clock that only a sleep (or the test) advances."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds


async def _paced(
    frames: list[MediaFrame], clock: _Clock, *, between: dict[int, float] | None = None
) -> list[MediaFrame]:
    """Read every frame; ``between`` advances the clock before reading the frame at that index."""
    out: list[MediaFrame] = []
    async with FramePacer(_source(frames), clock=clock, sleep=clock.sleep) as paced:
        while True:
            clock.now += (between or {}).get(len(out), 0.0)
            try:
                out.append(await anext(paced))
            except StopAsyncIteration:
                return out


async def test_video_goes_at_the_stream_clock_pace_and_audio_without_a_wait() -> None:
    clock = _Clock()
    frames = [_video(5000), _audio(5000), _video(5040), _audio(5040), _audio(5060), _video(5080)]
    assert await _paced(frames, clock) == frames, "arrival order kept"
    assert clock.sleeps == [0.04, 0.04], "the first video frame at once, audio never waits"


@pytest.mark.parametrize(
    ("steps_ms", "sleeps"),
    [
        ([0, 40, 20], [0.04]),  # a step backwards counts as 0: no wait
        ([0, 40, 40], [0.04]),  # an equal stamp: no wait, not a zero-length sleep
        ([0, PACE_MAX_STEP_MS], [PACE_MAX_STEP_MS / 1000]),  # the longest step as it is
        ([0, PACE_MAX_STEP_MS + 4000], [PACE_MAX_STEP_MS / 1000]),  # a jump is cut to it
    ],
)
async def test_odd_clock_steps_are_bounded(steps_ms: list[int], sleeps: list[float]) -> None:
    clock = _Clock()
    await _paced([_video(ms) for ms in steps_ms], clock)
    assert clock.sleeps == sleeps


async def test_a_late_frame_goes_at_once_and_the_next_is_paced_from_it() -> None:
    clock = _Clock()
    frames = [_video(0), _video(40), _video(80), _video(120)]
    # The reader comes back 0.1 s late for the second frame; the third waits a whole
    # step after it, not the debt of the second one.
    await _paced(frames, clock, between={1: 0.1})
    assert clock.sleeps == [0.04, 0.04]
    assert clock.now == pytest.approx(100.0 + 0.1 + 0.08)


async def test_a_reader_partly_late_waits_only_the_rest_of_the_step() -> None:
    clock = _Clock()
    await _paced([_video(0), _video(40)], clock, between={1: 0.015})
    assert clock.sleeps == [0.025]


async def test_the_source_is_read_ahead_while_the_reader_waits() -> None:
    """A MediaStream drops video for a slow reader, so the pacer must take every frame
    as it comes, however long the reader waits."""
    taken: list[int] = []
    release = asyncio.Event()

    async def source() -> AsyncIterator[MediaFrame]:
        for ms in range(0, 400, 40):
            taken.append(ms)
            yield _video(ms)

    async def held(_seconds: float) -> None:
        await release.wait()

    async with FramePacer(source(), sleep=held) as paced:
        assert (await anext(paced)).timestamp_ms == 0
        second = asyncio.create_task(anext(paced))
        async with asyncio.timeout(1):
            while len(taken) < 10:
                await asyncio.sleep(0)
        assert not second.done(), "the reader is still held on the second frame"
        assert paced.peak_frames >= 9
        release.set()
        assert (await second).timestamp_ms == 40


async def test_an_error_of_the_source_comes_after_the_frames_read_before_it() -> None:
    clock = _Clock()
    out: list[MediaFrame] = []

    async def read() -> None:
        source = _source([_video(0), _video(40)], ProtocolError("lost"))
        async with FramePacer(source, clock=clock, sleep=clock.sleep) as paced:
            while True:  # ends with the source's error
                out.append(await anext(paced))

    with pytest.raises(ProtocolError, match="lost"):
        await read()
    assert [f.timestamp_ms for f in out] == [0, 40]


async def test_leaving_the_block_stops_the_read_ahead() -> None:
    closed = asyncio.Event()

    async def endless() -> AsyncIterator[MediaFrame]:
        ms = 0
        try:
            while True:
                yield _video(ms)
                ms += 40
                await asyncio.sleep(0)
        finally:
            closed.set()

    clock = _Clock()
    async with FramePacer(endless(), clock=clock, sleep=clock.sleep) as paced:
        await anext(paced)
    async with asyncio.timeout(1):
        await closed.wait()


async def test_a_cancel_while_the_read_ahead_stops_is_not_swallowed() -> None:
    stopping = asyncio.Event()

    async def slow_to_stop() -> AsyncIterator[MediaFrame]:
        try:
            yield _video(0)
            await asyncio.Event().wait()
        finally:
            stopping.set()
            await asyncio.sleep(0.2)  # still stopping when the reader is cancelled

    async def reader() -> None:
        async with FramePacer(slow_to_stop()) as paced:
            await anext(paced)

    task = asyncio.create_task(reader())
    async with asyncio.timeout(1):
        await stopping.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        async with asyncio.timeout(1):
            await task
    assert task.cancelled()
    await asyncio.sleep(0.3)  # let the read-ahead finish stopping


async def test_unpaced_frames_go_as_soon_as_read() -> None:
    clock = _Clock()
    frames = [_video(0), _video(40), _video(5000)]
    out: list[MediaFrame] = []
    async with FramePacer(_source(frames), clock=clock, sleep=clock.sleep, pace=False) as paced:
        out.extend([frame async for frame in paced])
    assert (out, clock.sleeps) == (frames, [])


async def test_a_pacer_is_read_only_inside_its_block() -> None:
    with pytest.raises(RuntimeError, match="async with"):
        await anext(FramePacer(_source([_video(0)])))
