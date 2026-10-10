"""Stored recordings downloaded as one MPEG-TS clip on an extra session."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import LiveStreamLimitError, UnsupportedError
from eufy_home_security.p2p.clip import CLIP_CONTENT_TYPE
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

CLIP = "/zx/hdd_data0/Camera00/202610/20261001072414/20261001072414.zxvideo"
VIDEO_PID = 0x0100
AUDIO_PID = 0x0101


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


def _session(station: FakeStation, serial: str = SYNTHETIC.station_sn) -> StationSession:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    return StationSession(serial, provider, host="127.0.0.1", port=station.discovery_port)


async def _until(predicate: object, timeout: float = 3.0) -> None:
    assert callable(predicate)
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


def _pids(ts: bytes) -> set[int]:
    return {
        ((ts[o + 1] & 0x1F) << 8) | ts[o + 2]
        for o in range(0, len(ts), TS_PACKET_LEN)
        if ts[o] == 0x47
    }


async def test_a_recording_downloads_whole_on_an_extra_session_closed_after(
    station: FakeStation,
) -> None:
    station.recording_frames = 9
    session = _session(station)
    chunks: list[bytes] = []

    async def write(chunk: bytes) -> None:
        chunks.append(chunk)

    try:
        await session.async_connect()
        clip = await session.async_download_recording(CLIP, 0, write)
        data = b"".join(chunks)
        assert data[0] == 0x47
        assert len(data) % TS_PACKET_LEN == 0
        assert len(data) == clip.bytes_written
        assert {0x0000, VIDEO_PID, AUDIO_PID} <= _pids(data), "PAT, video and audio"
        assert clip.video_frames == 9
        assert clip.keyframes >= 2
        assert clip.content_type == CLIP_CONTENT_TYPE
        assert clip.complete  # no record frame count to hold it against
        await _until(lambda: station.sessions == 1)
        stats = session.stats()
        assert (stats.recording_downloads, stats.extra_live_sessions_open) == (1, 0)
        assert stats.extra_live_sessions == 0, "a download is not a live stream"
        assert stats.media_opens == 1, "the extra session's open counts here"
        assert stats.media_slot_channel is None
        assert not station.live_cameras, "no camera was woken"
    finally:
        await session.async_close()


async def test_a_download_shares_the_live_budget_and_waits_for_a_free_session(
    station: FakeStation,
) -> None:
    station.recording_frames = 4
    session = _session(station)
    session.max_sessions = 3  # station session, trigger frames, one extra session

    async def write(_chunk: bytes) -> None:
        return None

    try:
        first = await session.async_open_live(0)  # this session's slot
        second = await session.async_open_live(1)  # the one extra session
        with pytest.raises(LiveStreamLimitError):
            await session.async_download_recording(CLIP, 0, write, wait=False)
        waiting = asyncio.create_task(session.async_download_recording(CLIP, 0, write))
        await asyncio.sleep(0.1)
        assert not waiting.done()
        await second.aclose()
        clip = await asyncio.wait_for(waiting, 5)
        assert clip.video_frames == 4
        await first.aclose()
    finally:
        await session.async_close()


async def test_a_cancelled_download_closes_its_session(station: FakeStation) -> None:
    station.recording_frames = 10_000
    session = _session(station)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        await session.async_connect()
        task = asyncio.create_task(session.async_download_recording(CLIP, 0, write))
        await _until(lambda: station.media_frames_sent > 20)
        assert station.sessions == 2
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _until(lambda: station.sessions == 1)
        assert session.stats().extra_live_sessions_open == 0
    finally:
        await session.async_close()


async def test_a_standalone_device_downloads_nothing(station: FakeStation) -> None:
    session = _session(station, serial="T8170P2000054321")

    async def write(_chunk: bytes) -> None:
        raise AssertionError("nothing is written")

    with pytest.raises(UnsupportedError):
        await session.async_download_recording(CLIP, 0, write)
    assert station.sessions == 0
