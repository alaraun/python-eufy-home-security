"""Sharing one camera stream between viewers: fanout, late joiners, slow readers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import StationUnreachableError
from eufy_home_security.p2p.broadcast import StreamBroadcast
from eufy_home_security.p2p.encoder import SETTLE_STANDALONE, SETTLE_STATION
from eufy_home_security.p2p.media import MediaFrame, MediaKind, VideoCodec
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN


def _ended_by_resize(broadcast: StreamBroadcast) -> bool:
    """Read the flag afresh: mypy keeps it narrowed from an earlier assert."""
    return broadcast.ended_by_resize


def video(*, keyframe: bool = False, ms: int = 1000, size: int = 40) -> MediaFrame:
    return MediaFrame(
        MediaKind.VIDEO,
        b"\x00\x00\x00\x01\x26\x01" + b"\xa5" * size,
        is_keyframe=keyframe,
        timestamp_ms=ms,
        codec=VideoCodec.HEVC,
        width=2304,
        height=1296,
    )


class FakeStream:
    """A MediaStream stand-in: yields the frames it is given, records its closing."""

    def __init__(self, frames: list[MediaFrame], *, hold: bool = False) -> None:
        self._frames = frames
        self._hold = hold
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    def __aiter__(self) -> AsyncIterator[MediaFrame]:
        return self._iter()

    async def _iter(self) -> AsyncIterator[MediaFrame]:
        for frame in self._frames:
            await asyncio.sleep(0)
            yield frame
        while self._hold:  # pragma: no cover - only for the "still running" cases
            await asyncio.sleep(0.01)


def settled(count: int = 6) -> list[MediaFrame]:
    """Frames that settle immediately (settle=0) and then keep coming."""
    return [video(keyframe=True, ms=1000)] + [
        video(keyframe=i % 4 == 0, ms=1040 + i * 40) for i in range(count)
    ]


async def drain(broadcast: StreamBroadcast, limit: int) -> list[bytes]:
    out: list[bytes] = []
    async for chunk in broadcast.subscribe():
        out.append(chunk)
        if len(out) >= limit:
            break
    return out


async def test_the_camera_opens_once_for_many_subscribers() -> None:
    """Two viewers on one camera must not cost two station sessions."""
    opens = 0

    async def open_stream() -> FakeStream:
        nonlocal opens
        opens += 1
        return FakeStream(settled(40), hold=True)

    broadcast = StreamBroadcast(open_stream, settle=0.0, name="test")
    first = broadcast.subscribe()
    second = broadcast.subscribe()
    try:
        assert await asyncio.wait_for(anext(first), 3)
        assert await asyncio.wait_for(anext(second), 3)
        assert broadcast.subscribers == 2, "both viewers are attached at once"
        assert opens == 1, "one camera stream, however many viewers"
    finally:
        await first.aclose()
        await second.aclose()
        await broadcast.aclose()


async def test_a_late_joiner_gets_the_header_first() -> None:
    """Without the tables and a keyframe, a late joiner cannot decode anything."""
    broadcast = StreamBroadcast(lambda: _as_stream(settled(30), hold=True), settle=0.0, name="test")
    warmup = asyncio.create_task(drain(broadcast, 4))
    await asyncio.sleep(0.05)
    assert broadcast.header, "the stream has started"

    chunks = await drain(broadcast, 1)
    assert chunks[0] == broadcast.header
    assert chunks[0][0] == 0x47
    warmup.cancel()
    await asyncio.gather(warmup, return_exceptions=True)
    await broadcast.aclose()


async def test_the_stream_closes_when_the_last_subscriber_leaves() -> None:
    """A live stream holds a station session and drains a battery camera."""
    stream = FakeStream(settled(40), hold=True)
    broadcast = StreamBroadcast(lambda: _wrap(stream), settle=0.0, name="test")
    await drain(broadcast, 2)
    await asyncio.sleep(0.05)
    assert stream.closed, "nobody is watching, so the camera is released"
    assert broadcast.subscribers == 0
    assert not broadcast.running


async def test_a_slow_subscriber_is_resynced_not_allowed_to_stall_the_camera() -> None:
    """The station stops sending when frames are not read, so a slow reader must lose.

    The queue is capped: a reader that falls behind has its backlog dropped and is
    restarted at the header, rather than being allowed to grow without bound or hold
    the camera back.
    """
    stream = FakeStream(settled(60), hold=True)
    broadcast = StreamBroadcast(lambda: _wrap(stream), settle=0.0, queue_chunks=3, name="test")

    agen = broadcast.subscribe()
    header = await anext(agen)
    assert header == broadcast.header
    await asyncio.sleep(0.2)  # let the pump run far ahead of this reader

    # The backlog was capped rather than growing to the 60 frames produced.
    queued = next(iter(broadcast._subscribers)).queue
    assert queued.qsize() <= 3

    # And what the reader receives next is still well-formed TS.
    chunk = await asyncio.wait_for(anext(agen), 3)
    assert chunk
    assert len(chunk) % TS_PACKET_LEN == 0
    assert chunk[0] == 0x47

    await agen.aclose()
    await broadcast.aclose()


async def test_a_resynced_subscriber_restarts_at_the_header() -> None:
    """After dropping, a reader must resume at a keyframe, not mid-picture."""
    stream = FakeStream(settled(60), hold=True)
    broadcast = StreamBroadcast(lambda: _wrap(stream), settle=0.0, queue_chunks=2, name="test")
    agen = broadcast.subscribe()
    await anext(agen)
    await asyncio.sleep(0.2)
    # The next chunk after a resync is the header itself.
    following = await anext(agen)
    assert following == broadcast.header
    await agen.aclose()
    await broadcast.aclose()


async def test_subscribers_are_released_when_the_stream_ends() -> None:
    """A finite stream must end the iteration, not hang the reader."""
    broadcast = StreamBroadcast(lambda: _as_stream(settled(4)), settle=0.0, name="test")
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert chunks
    assert not broadcast.running


async def test_a_failed_open_releases_the_subscriber() -> None:
    async def failing() -> FakeStream:
        raise RuntimeError("camera is asleep")

    broadcast = StreamBroadcast(failing, settle=0.0, name="test")
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert chunks == []


def resized(*, keyframe: bool = True, ms: int = 1120) -> MediaFrame:
    return MediaFrame(
        MediaKind.VIDEO,
        b"\x00\x00\x00\x01\x26\x01payload",
        is_keyframe=keyframe,
        timestamp_ms=ms,
        codec=VideoCodec.HEVC,
        width=1920,
        height=1080,
    )


def _resize_run() -> list[MediaFrame]:
    # settle=0: the first keyframe starts the stream.
    return [
        video(keyframe=True, ms=1000),
        video(keyframe=True, ms=1040),
        video(keyframe=False, ms=1080),
        resized(keyframe=False, ms=1120),
        resized(keyframe=True, ms=1160),
        resized(keyframe=False, ms=1200),
    ]


async def test_a_resolution_change_is_followed_by_default() -> None:
    broadcast = StreamBroadcast(
        lambda: _as_stream(_resize_run()), settle=0.0, fill_audio=False, name="test"
    )
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert len(chunks) == 5, "header (start keyframe), keyframe, P, resumed keyframe, P"
    assert chunks[3] == broadcast.header, "the resumed keyframe is the new header"
    assert broadcast.resizes == 1
    assert not broadcast.ended_by_resize
    assert broadcast.error is None


async def test_a_resolution_change_ends_the_stream_when_asked() -> None:
    broadcast = StreamBroadcast(
        lambda: _as_stream(_resize_run()), settle=0.0, on_resize="end", name="test"
    )
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert chunks, "the frames before the change were delivered"
    assert broadcast.ended_by_resize
    assert broadcast.error is None
    assert not broadcast.running


async def test_a_clean_end_is_not_a_resize_end() -> None:
    broadcast = StreamBroadcast(
        lambda: _as_stream(settled(4)), settle=0.0, on_resize="end", name="test"
    )
    assert [chunk async for chunk in broadcast.subscribe()]
    assert not broadcast.ended_by_resize


async def test_a_resize_grace_keeps_the_camera_open_for_a_reconnect() -> None:
    frames = [*_resize_run(), *(resized(keyframe=i % 4 == 0, ms=1240 + 40 * i) for i in range(8))]
    stream = FakeStream(frames, hold=True)
    opens = 0

    async def open_stream() -> FakeStream:
        nonlocal opens
        opens += 1
        return stream

    broadcast = StreamBroadcast(
        open_stream, settle=0.0, on_resize="end", resize_grace=5.0, name="test"
    )
    first = [chunk async for chunk in broadcast.subscribe()]
    assert first
    assert broadcast.ended_by_resize
    assert broadcast.running, "the camera stays open through the grace time"
    assert not stream.closed
    second = await asyncio.wait_for(drain(broadcast, 2), 2)
    assert second[0] == broadcast.header, "the reconnect starts at the new size's keyframe"
    assert opens == 1, "no second open, so no wake"
    assert not _ended_by_resize(broadcast), "a new subscriber clears it"
    await broadcast.aclose()
    assert stream.closed


async def test_the_camera_closes_when_nobody_returns_within_the_grace() -> None:
    stream = FakeStream(_resize_run(), hold=True)
    broadcast = StreamBroadcast(
        lambda: _wrap(stream), settle=0.0, on_resize="end", resize_grace=0.05, name="test"
    )
    assert [chunk async for chunk in broadcast.subscribe()]
    assert broadcast.running
    await asyncio.sleep(0.2)
    assert stream.closed
    assert not broadcast.running


async def test_an_unknown_resize_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match="on_resize"):
        StreamBroadcast(lambda: _as_stream([]), on_resize="restart")  # type: ignore[arg-type]


async def test_a_subscriber_with_a_full_queue_is_still_released_at_the_end() -> None:
    """The end-of-stream sentinel must reach a reader whose queue is full.

    Otherwise a slow reader waits forever on a stream that has already ended — which,
    behind an HTTP handler, is a connection that never closes.
    """
    broadcast = StreamBroadcast(
        lambda: _as_stream(settled(40)), settle=0.0, queue_chunks=2, name="test"
    )
    agen = broadcast.subscribe()
    await anext(agen)
    await asyncio.sleep(0.2)  # the pump finishes and the reader's queue fills

    async def drain() -> int:
        seen = 0
        async for _chunk in agen:
            seen += 1
        return seen

    seen = await asyncio.wait_for(drain(), 3)
    assert seen >= 0, "the iteration ended rather than hanging"
    await broadcast.aclose()


async def test_a_followed_stream_starts_at_once_and_an_ending_one_waits_out_the_ramp() -> None:
    """``on_resize="continue"`` carries the opening ramp, so it needs no settle window.

    ``"end"`` would end at the first ramp step, so it waits for the size to hold; which
    window a camera needs is library knowledge (the two kinds ramp in opposite
    directions), picked by ``standalone``.
    """
    assert StreamBroadcast(lambda: _as_stream([]), name="test").settle == 0.0
    assert StreamBroadcast(lambda: _as_stream([]), standalone=True, name="test").settle == 0.0

    station = StreamBroadcast(lambda: _as_stream([]), on_resize="end", name="test")
    assert station.settle == SETTLE_STATION
    battery = StreamBroadcast(lambda: _as_stream([]), on_resize="end", standalone=True, name="test")
    assert battery.settle == SETTLE_STANDALONE
    assert SETTLE_STANDALONE > SETTLE_STATION

    explicit = StreamBroadcast(lambda: _as_stream([]), settle=1.0, standalone=True, name="test")
    assert explicit.settle == 1.0, "an explicit value still wins"


async def test_the_default_stream_starts_at_the_first_keyframe_with_an_audio_track() -> None:
    """No audio has arrived at the first keyframe; the track is declared and filled."""
    broadcast = StreamBroadcast(lambda: _as_stream(settled(8)), name="test")
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert chunks[0] == broadcast.header
    assert b"\x0f\xe1\x01" in broadcast.header, "ADTS AAC on the audio PID in the PMT"
    assert any(b"\xff\xf1" in chunk for chunk in chunks[1:]), "silent AAC carried"


async def test_the_error_says_why_a_stream_never_started() -> None:
    """A subscriber only sees its iteration end; the caller needs the reason.

    "Could not reach the camera, try again" is a different message from a stream that
    simply stopped, and only the first deserves a retry.
    """

    async def failing() -> FakeStream:
        msg = "camera is asleep"
        raise StationUnreachableError(msg)

    broadcast = StreamBroadcast(failing, settle=0.0, name="test")
    assert broadcast.error is None
    chunks = [chunk async for chunk in broadcast.subscribe()]
    assert not chunks, "a stream that never opened delivers nothing"
    failed_with = broadcast.error
    assert isinstance(failed_with, StationUnreachableError)


async def test_a_clean_run_reports_no_error() -> None:
    broadcast = StreamBroadcast(lambda: _as_stream(settled(4)), settle=0.0, name="test")
    delivered = [chunk async for chunk in broadcast.subscribe()]
    assert delivered, "the run really did deliver frames"
    assert broadcast.error is None


async def _as_stream(frames: list[MediaFrame], *, hold: bool = False) -> FakeStream:
    return FakeStream(frames, hold=hold)


async def _wrap(stream: FakeStream) -> FakeStream:
    return stream


pytestmark = pytest.mark.asyncio
