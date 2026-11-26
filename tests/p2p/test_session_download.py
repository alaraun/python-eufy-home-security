"""Stored recordings downloaded as one MPEG-TS clip, or played for a viewer, on an extra session."""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import LiveStreamLimitError, UnsupportedError
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.clip import CLIP_CONTENT_TYPE, IncompleteReason, MediaClip
from eufy_home_security.p2p.messages import CMD_DOWNLOAD_VIDEO, CMD_RECORD_VIEW
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

CLIP = "/zx/hdd_data0/Camera00/202610/20261001072414/20261001072414.zxvideo"
NATIVE_CLIP = "/media/mmcblk0p1/Camera05/20310203112233.dat"
VIDEO_PID = 0x0100
AUDIO_PID = 0x0101


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


@pytest.fixture
async def native() -> AsyncIterator[FakeStation]:
    """A station whose history is local events (10017): its downloads are 1024."""
    fake = FakeStation(serial=SYNTHETIC.homebase2_station_sn)
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
        assert (clip.complete, clip.end_frame) == (True, None), "a 1025 playback here"
        await _until(lambda: station.sessions == 1)
        stats = session.stats()
        assert (stats.recording_downloads, stats.recording_plays) == (1, 0)
        assert stats.extra_live_sessions_open == 0
        assert stats.extra_live_sessions == 0, "a download is not a live stream"
        assert stats.media_opens == 1, "the extra session's open counts here"
        assert stats.media_slot_channel is None
        assert not station.live_cameras, "no camera was woken"
    finally:
        await session.async_close()


async def test_a_download_with_no_end_frame_keeps_its_last_frame(
    native: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A download that ends at its idle wait with no end-of-download frame still writes
    every frame; it is complete only when the record's frame count shows it whole."""
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", 0.3)
    native.recording_frames = 10
    native.download_end_delay = None
    session = _session(native, serial=SYNTHETIC.homebase2_station_sn)

    async def write(chunk: bytes) -> None:
        pass

    try:
        await session.async_connect()
        clip = await session.async_download_recording(NATIVE_CLIP, 5, write)
    finally:
        await session.async_close()
    assert (clip.video_frames, clip.end_frame) == (10, False)
    assert clip.incomplete_reason is IncompleteReason.NO_END_FRAME
    assert not clip.complete, "no end frame and no frame count: not known to be whole"
    judged = dataclasses.replace(clip, expected_frames=10)  # the history row's frame_num
    assert (judged.complete, judged.incomplete_reason) == (True, None)


async def _download(station: FakeStation) -> tuple[MediaClip, float]:
    session = _session(station, serial=station.serial)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        await session.async_connect()
        started = time.monotonic()
        clip = await asyncio.wait_for(session.async_download_recording(NATIVE_CLIP, 5, write), 10)
        return clip, time.monotonic() - started
    finally:
        await session.async_close()


async def test_a_download_ends_on_the_end_of_download_frame(
    native: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The station's 0x0518 ends a download without waiting out the idle wait."""
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", 8.0)
    monkeypatch.setattr(session_module, "MEDIA_IDLE_TIMEOUT", 8.0)
    native.recording_frames = 10
    clip, took = await _download(native)
    assert (clip.video_frames, clip.end_frame, clip.complete) == (10, True, True)
    assert took < 4.0, "ended by the station's frame, not the idle wait"


async def test_frames_still_in_flight_after_the_end_frame_are_kept(
    native: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Frames arriving just after the end-of-download frame still go into the clip."""
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", 8.0)
    native.recording_frames = 10
    native.download_finish_early = 4
    clip, _ = await _download(native)
    assert (clip.video_frames, clip.end_frame, clip.complete) == (10, True, True)


async def test_a_download_whose_station_pauses_past_the_live_idle_wait_gets_every_frame(
    native: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A download waits out a station's pause longer than the live idle wait."""
    monkeypatch.setattr(session_module, "MEDIA_IDLE_TIMEOUT", 0.3)
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", 3.0)
    native.recording_frames = 10
    native.recording_pause = (4, 0.8)
    clip, _ = await _download(native)
    assert (clip.video_frames, clip.end_frame, clip.complete) == (10, True, True)


async def test_a_download_the_station_stops_early_is_incomplete(
    native: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A station that stops mid-download and sends no end frame gives an incomplete clip."""
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", 0.3)
    native.recording_frames = 10
    native.recording_stops_after = 4
    clip, _ = await _download(native)
    assert (clip.video_frames, clip.end_frame, clip.complete) == (4, False, False)
    assert clip.incomplete_reason is IncompleteReason.NO_END_FRAME
    judged = dataclasses.replace(clip, expected_frames=10)
    assert judged.incomplete_reason is IncompleteReason.MISSING_FRAMES


@pytest.mark.parametrize("download", [True, False])
async def test_a_recording_open_waits_its_own_idle_default(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, download: bool
) -> None:
    """A download (1024) idles out on the download wait, a playback (1025) on the live one."""
    short, long = 0.2, 6.0
    monkeypatch.setattr(session_module, "MEDIA_DOWNLOAD_IDLE_TIMEOUT", short if download else long)
    monkeypatch.setattr(session_module, "MEDIA_IDLE_TIMEOUT", long if download else short)
    station.recording_frames = 6
    station.download_end_delay = station.playback_end_delay = None
    session = _session(station)
    try:
        await session.async_connect()
        stream = await session.async_open_recording(CLIP, 0, download=download)
        async with asyncio.timeout(3):
            frames = [frame async for frame in stream]
        assert frames
        assert (stream.ended, stream.end_frame) == (True, False)
    finally:
        await session.async_close()


def test_the_download_idle_wait_is_the_apps_and_live_keeps_its_own() -> None:
    """A download gets the app's 15 s without data; live and playback keep 3 s; the settle
    after an end frame is shorter than either."""
    assert session_module.MEDIA_IDLE_TIMEOUT == 3.0
    assert session_module.MEDIA_DOWNLOAD_IDLE_TIMEOUT == 15.0
    assert session_module.MEDIA_DRAIN_GAP < session_module.MEDIA_IDLE_TIMEOUT


class _Stream:
    """The members the end-of-download handler reads, recording its call."""

    def __init__(self, command: int, *, started: bool) -> None:
        self.command = command
        self._has_media = started
        self.finished: list[float] = []

    def _download_finished(self, settle: float) -> None:
        self.finished.append(settle)


@pytest.mark.parametrize(
    ("command", "started", "taken"),
    [
        (CMD_DOWNLOAD_VIDEO, True, True),
        (CMD_DOWNLOAD_VIDEO, False, False),
        (CMD_RECORD_VIEW, True, False),
    ],
)
def test_only_a_started_download_takes_the_end_of_download_frame(
    station: FakeStation, command: int, started: bool, taken: bool
) -> None:
    """The frame carries no stream id: a download that has not started (an earlier
    download's end) and a playback leave it."""
    session = _session(station)
    stream = _Stream(command, started=started)
    session._on_download_finish(stream)  # type: ignore[arg-type]
    session._on_download_finish(None)
    assert stream.finished == ([session_module.MEDIA_DRAIN_GAP] if taken else [])


async def test_native_local_events_download_uses_1024_and_decodes_mpegts() -> None:
    """The public download API, not only the raw open, must select native 1024."""
    local_sn = SYNTHETIC.homebase2_station_sn
    native_path = "/media/mmcblk0p1/Camera05/20310203112233.dat"
    fake = FakeStation(serial=local_sn)
    await fake.start()
    session = _session(fake, serial=local_sn)
    chunks: list[bytes] = []

    async def write(chunk: bytes) -> None:
        chunks.append(chunk)

    try:
        clip = await session.async_download_recording(native_path, 5, write)
        data = b"".join(chunks)
        assert clip.video_frames == fake.recording_frames
        assert data.startswith(b"\x47")
        assert len(data) % TS_PACKET_LEN == 0
        assert fake.native_recording_requests == [(1024, 5, native_path)]
    finally:
        await session.async_close()
        fake.stop()


async def test_a_download_failing_before_its_stream_returns_the_extra_session(
    station: FakeStation,
) -> None:
    """A download refused before its stream exists releases the extra session it reserved."""
    session = _session(station)

    async def write(chunk: bytes) -> None:
        pass

    try:
        await session.async_connect()
        with pytest.raises(UnsupportedError):
            await session.async_download_recording("/not/a/recording", 0, write)
        await asyncio.sleep(0.1)
        assert session.stats().extra_live_sessions_open == 0
    finally:
        await session.async_close()


async def test_a_play_writes_each_frame_on_an_extra_session_closed_after(
    station: FakeStation,
) -> None:
    station.recording_frames = 50  # 2 s of the fake's stream clock
    session = _session(station)
    chunks: list[bytes] = []

    async def write(chunk: bytes) -> None:
        chunks.append(chunk)

    try:
        await session.async_connect()
        started = time.monotonic()
        clip = await session.async_play_recording(CLIP, 0, write, realtime=False)
        assert time.monotonic() - started < 1.5, "not paced: as fast as the station sends"
        data = b"".join(chunks)
        assert data[0] == 0x47
        assert all(len(chunk) % TS_PACKET_LEN == 0 for chunk in chunks)
        assert {0x0000, VIDEO_PID, AUDIO_PID} <= _pids(data), "PAT, video and audio"
        assert (clip.video_frames, clip.end_frame) == (50, None), "no download end frame"
        assert len(chunks) >= clip.video_frames, "every frame written as it is muxed"
        assert len(data) == clip.bytes_written
        await _until(lambda: station.sessions == 1)
        stats = session.stats()
        assert (stats.recording_plays, stats.recording_downloads) == (1, 0)
        assert stats.extra_live_sessions_open == 0
        assert not station.live_cameras, "no camera was woken"
    finally:
        await session.async_close()


async def test_a_play_does_not_wait_for_a_download_of_the_same_station(
    station: FakeStation,
) -> None:
    station.recording_frames = 10_000
    session = _session(station)
    playing = asyncio.Event()

    async def download_write(_chunk: bytes) -> None:
        return None

    async def play_write(_chunk: bytes) -> None:
        playing.set()

    try:
        await session.async_connect()
        download = asyncio.create_task(session.async_download_recording(CLIP, 0, download_write))
        await _until(lambda: station.media_frames_sent > 20)  # the download is running
        play = asyncio.create_task(session.async_play_recording(CLIP, 1, play_write))
        async with asyncio.timeout(3):
            await playing.wait()
        assert not download.done()
        for task in (play, download):
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await _until(lambda: station.sessions == 1)
        assert session.stats().extra_live_sessions_open == 0
    finally:
        await session.async_close()


async def test_native_local_events_play_uses_1025() -> None:
    """A station whose history is local events plays with the native playback command."""
    local_sn = SYNTHETIC.homebase2_station_sn
    native_path = "/media/mmcblk0p1/Camera05/20310203112233.dat"
    fake = FakeStation(serial=local_sn)
    await fake.start()
    session = _session(fake, serial=local_sn)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        clip = await session.async_play_recording(native_path, 5, write, realtime=False)
        assert clip.video_frames == fake.recording_frames
        assert fake.native_recording_requests == [(1025, 5, native_path)]
    finally:
        await session.async_close()
        fake.stop()


TRANSFERS = ["async_download_recording", "async_play_recording"]


@pytest.mark.parametrize("transfer", TRANSFERS)
async def test_a_transfer_shares_the_live_budget_and_waits_for_a_free_session(
    station: FakeStation, transfer: str
) -> None:
    station.recording_frames = 4
    session = _session(station)
    session.max_sessions = 3  # station session, trigger frames, one extra session
    run = getattr(session, transfer)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        first = await session.async_open_live(0)  # this session's slot
        second = await session.async_open_live(1)  # the one extra session
        with pytest.raises(LiveStreamLimitError):
            await run(CLIP, 0, write, wait=False)
        async with asyncio.timeout(2):  # the wait is first_frame_timeout, not the default
            with pytest.raises(LiveStreamLimitError, match=r"none closed within 0\.2s"):
                await run(CLIP, 0, write, first_frame_timeout=0.2)
        waiting = asyncio.create_task(run(CLIP, 0, write))
        await asyncio.sleep(0.1)
        assert not waiting.done()
        await second.aclose()
        clip = await asyncio.wait_for(waiting, 5)
        assert clip.video_frames == 4
        await first.aclose()
    finally:
        await session.async_close()


@pytest.mark.parametrize("transfer", TRANSFERS)
async def test_a_cancelled_transfer_closes_its_session(station: FakeStation, transfer: str) -> None:
    station.recording_frames = 10_000
    session = _session(station)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        await session.async_connect()
        task = asyncio.create_task(getattr(session, transfer)(CLIP, 0, write))
        await _until(lambda: station.media_frames_sent > 20)
        assert station.sessions == 2
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _until(lambda: station.sessions == 1)
        assert session.stats().extra_live_sessions_open == 0
    finally:
        await session.async_close()


@pytest.mark.parametrize("transfer", TRANSFERS)
async def test_a_standalone_device_transfers_nothing(station: FakeStation, transfer: str) -> None:
    session = _session(station, serial="T8170P2000054321")

    async def write(_chunk: bytes) -> None:
        raise AssertionError("nothing is written")

    with pytest.raises(UnsupportedError, match="standalone"):
        await getattr(session, transfer)(CLIP, 0, write)
    assert station.sessions == 0


async def test_a_realtime_play_takes_the_recordings_own_time(station: FakeStation) -> None:
    station.recording_frames = 9  # 8 steps of the fake's 40 ms stream clock after the first
    session = _session(station)
    first: float | None = None

    async def write(_chunk: bytes) -> None:
        nonlocal first
        if first is None:
            first = time.monotonic()

    try:
        await session.async_connect()
        clip = await session.async_play_recording(CLIP, 0, write)
        assert clip.video_frames == 9
        assert first is not None
        assert time.monotonic() - first >= 0.3
    finally:
        await session.async_close()


async def test_an_unpaced_play_with_a_slow_writer_loses_no_frame(station: FakeStation) -> None:
    """A writer slower than the station: frames are read ahead, not dropped from the
    stream's queue."""
    station.recording_frames = 300
    session = _session(station)

    async def write(_chunk: bytes) -> None:
        await asyncio.sleep(0.005)

    try:
        await session.async_connect()
        clip = await asyncio.wait_for(
            session.async_play_recording(CLIP, 0, write, realtime=False), 15
        )
        assert clip.video_frames == 300
        assert session.stats().media_frames_dropped_for_reader == 0
    finally:
        await session.async_close()


async def test_a_paced_play_returns_its_session_once_the_station_has_sent_all(
    station: FakeStation,
) -> None:
    station.recording_frames = 30  # 1.2 s of the fake's stream clock
    session = _session(station)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        await session.async_connect()
        task = asyncio.create_task(session.async_play_recording(CLIP, 0, write))
        await _until(lambda: station.sessions == 2)  # the extra session is up
        await _until(lambda: station.sessions == 1)
        assert not task.done(), "still writing at the recording's pace"
        assert session.stats().extra_live_sessions_open == 0
        clip = await asyncio.wait_for(task, 5)
        assert clip.video_frames == 30
    finally:
        await session.async_close()
