"""Live captures from a broadcast: a clip of the shared camera stream, of a set length."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import (
    CaptureStoppedError,
    DeviceTimeoutError,
    StationUnreachableError,
)
from eufy_home_security.p2p.broadcast import StreamBroadcast
from eufy_home_security.p2p.media import MediaFrame, MediaKind, VideoCodec
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN

AAC = b"\xff\xf1\x60\x40\x01\x7f\xfc" + b"\x11" * 16


def video(ms: int, *, keyframe: bool = False, width: int = 2304) -> MediaFrame:
    return MediaFrame(
        MediaKind.VIDEO,
        b"\x00\x00\x00\x01\x26\x01" + b"\xa5" * 40,
        is_keyframe=keyframe,
        timestamp_ms=ms,
        codec=VideoCodec.HEVC,
        width=width,
        height=1296,
    )


def camera(seconds: float, *, start_ms: int = 5000, gop: int = 15) -> list[MediaFrame]:
    """``seconds`` of 15 fps video with audio, joined mid-GOP (a P-frame first)."""
    frames = [video(start_ms - 66)]
    for i in range(round(seconds * 15)):
        ms = start_ms + i * 66
        frames.append(video(ms, keyframe=i % gop == 0))
        frames.append(MediaFrame(MediaKind.AUDIO, AAC, timestamp_ms=ms))
    return frames


class FakeStream:
    """Yields its frames ``pace`` seconds apart, then holds open until closed (``hold``)."""

    def __init__(self, frames: list[MediaFrame], *, hold: bool = False, pace: float = 0.0) -> None:
        self._frames = frames
        self._hold = hold
        self._pace = pace
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    def __aiter__(self) -> AsyncIterator[MediaFrame]:
        return self._iter()

    async def _iter(self) -> AsyncIterator[MediaFrame]:
        for frame in self._frames:
            await asyncio.sleep(self._pace)
            yield frame
        while self._hold and not self.closed:
            await asyncio.sleep(0.01)


class Sink:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    async def __call__(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


def _opener(*streams: FakeStream) -> tuple[list[FakeStream], object]:
    opened: list[FakeStream] = []
    queue = list(streams)

    async def open_stream() -> FakeStream:
        stream = queue.pop(0)
        opened.append(stream)
        return stream

    return opened, open_stream


async def test_a_capture_opens_the_camera_and_writes_its_length_from_a_keyframe() -> None:
    stream = FakeStream(camera(6), hold=True)
    opened, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    sink = Sink()
    clip = await broadcast.async_capture(2.0, sink)
    assert len(opened) == 1
    assert sink.data[0] == 0x47
    assert len(sink.data) % TS_PACKET_LEN == 0
    assert clip.bytes_written == len(sink.data)
    assert clip.keyframes >= 1
    assert 1.9 <= clip.duration_s < 2.0
    assert clip.complete
    assert not clip.ended_early
    assert clip.started_at is not None
    await asyncio.sleep(0.05)
    assert stream.closed, "nobody else watched: the camera closes with the capture"
    assert not broadcast.running


async def test_a_capture_shares_a_running_view_and_leaves_it_running() -> None:
    stream = FakeStream(camera(20), hold=True, pace=0.002)
    opened, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    viewer = broadcast.subscribe()
    try:
        assert await asyncio.wait_for(anext(viewer), 3)
        clip = await broadcast.async_capture(1.0, Sink())
        assert clip.complete
        assert len(opened) == 1, "one camera stream for the viewer and the capture"
        assert broadcast.running, "the viewer still watches"
        assert not stream.closed
        assert broadcast.captures == 0
    finally:
        await viewer.aclose()
        await broadcast.aclose()


async def test_a_capture_holds_the_camera_after_the_last_viewer_leaves() -> None:
    stream = FakeStream(camera(20), hold=True, pace=0.002)
    _, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    viewer = broadcast.subscribe()
    await asyncio.wait_for(anext(viewer), 3)
    capture = asyncio.create_task(broadcast.async_capture(1.5, Sink()))
    await asyncio.sleep(0.02)
    await viewer.aclose()
    await asyncio.sleep(0.02)
    assert broadcast.running, "the capture keeps the camera open"
    clip = await capture
    assert clip.complete
    await asyncio.sleep(0.05)
    assert stream.closed


async def test_a_stream_that_ends_early_returns_what_it_got() -> None:
    _, open_stream = _opener(FakeStream(camera(1)))
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    clip = await broadcast.async_capture(10.0, Sink())
    assert clip.ended_early
    assert not clip.complete
    assert clip.video_frames > 0


async def test_a_capture_that_never_opens_raises_the_open_error() -> None:
    async def failing() -> FakeStream:
        raise StationUnreachableError("asleep")

    broadcast = StreamBroadcast(failing, name="test")
    with pytest.raises(StationUnreachableError):
        await broadcast.async_capture(1.0, Sink())


async def test_a_capture_without_a_keyframe_times_out() -> None:
    frames = [video(5000 + i * 66) for i in range(5)]
    _, open_stream = _opener(FakeStream(frames, hold=True))
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    with pytest.raises(DeviceTimeoutError):
        await broadcast.async_capture(0.1, Sink(), start_timeout=0.2)
    await broadcast.aclose()


@pytest.mark.parametrize("seconds", [0, -1, float("nan"), float("inf")])
async def test_a_capture_length_must_be_positive_and_finite(seconds: float) -> None:
    broadcast = StreamBroadcast(lambda: None, name="test")  # type: ignore[arg-type, return-value]
    with pytest.raises(ValueError, match="seconds"):
        await broadcast.async_capture(seconds, Sink())
    assert not broadcast.running


async def test_a_capture_carries_a_resize_at_the_next_keyframe() -> None:
    frames = [
        *camera(1, gop=5),
        video(6000, width=1920),  # a P-frame at the new size: dropped
        video(6066, keyframe=True, width=1920),
        video(6132, width=1920),
        video(6200, width=1920),  # past the length: ends the capture, not written
    ]
    _, open_stream = _opener(FakeStream(frames, hold=True))
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    clip = await broadcast.async_capture(1.15, Sink())
    assert clip.resizes == 1
    assert clip.width == 1920
    await broadcast.aclose()


async def test_closing_the_broadcast_ends_a_running_capture() -> None:
    _, open_stream = _opener(FakeStream(camera(1), hold=True))
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    capture = asyncio.create_task(broadcast.async_capture(60.0, Sink()))
    await asyncio.sleep(0.1)
    await broadcast.aclose()
    clip = await asyncio.wait_for(capture, 3)
    assert clip.ended_early


async def test_a_stopped_capture_returns_what_it_wrote_as_complete() -> None:
    stream = FakeStream(camera(20), hold=True, pace=0.002)
    _, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    stop = asyncio.Event()
    sink = Sink()
    capture = asyncio.create_task(broadcast.async_capture(60.0, sink, stop=stop))
    await asyncio.sleep(0.2)
    stop.set()
    clip = await asyncio.wait_for(capture, 3)
    assert clip.stopped
    assert not clip.ended_early
    assert clip.complete
    assert 0 < clip.duration_s < 60
    assert clip.bytes_written == len(sink.data)
    assert len(sink.data) % TS_PACKET_LEN == 0
    await asyncio.sleep(0.05)
    assert stream.closed, "the stopped capture was the last holder"


async def test_a_stopped_capture_leaves_a_viewer_and_another_capture_running() -> None:
    stream = FakeStream(camera(20), hold=True, pace=0.002)
    opened, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    viewer = broadcast.subscribe()
    try:
        await asyncio.wait_for(anext(viewer), 3)
        stop = asyncio.Event()
        stopped = asyncio.create_task(broadcast.async_capture(60.0, Sink(), stop=stop))
        other = asyncio.create_task(broadcast.async_capture(60.0, Sink()))
        await asyncio.sleep(0.1)
        stop.set()
        assert (await asyncio.wait_for(stopped, 3)).stopped
        assert broadcast.running
        assert broadcast.captures == 1
        assert not other.done()
        assert len(opened) == 1
    finally:
        await viewer.aclose()
        await broadcast.aclose()
    assert (await asyncio.wait_for(other, 3)).ended_early


async def test_a_stop_before_the_first_keyframe_raises_capture_stopped() -> None:
    frames = [video(5000 + i * 66) for i in range(5)]
    stream = FakeStream(frames, hold=True)
    _, open_stream = _opener(stream)
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    stop = asyncio.Event()
    sink = Sink()
    capture = asyncio.create_task(broadcast.async_capture(10.0, sink, stop=stop))
    await asyncio.sleep(0.05)
    stop.set()
    with pytest.raises(CaptureStoppedError):
        await asyncio.wait_for(capture, 3)
    assert not sink.data
    await asyncio.sleep(0.05)
    assert stream.closed


async def test_a_capture_that_reaches_its_length_is_not_stopped() -> None:
    _, open_stream = _opener(FakeStream(camera(6), hold=True))
    broadcast = StreamBroadcast(open_stream, name="test")  # type: ignore[arg-type]
    clip = await broadcast.async_capture(1.0, Sink(), stop=asyncio.Event())
    assert clip.complete
    assert not clip.stopped
    assert not clip.ended_early


pytestmark = pytest.mark.asyncio
