"""Live streams of several cameras of one HomeBase: extra sessions under a per-station cap."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

import eufy_home_security.p2p.session as session_module
from eufy_home_security.exceptions import (
    CameraWakeError,
    CommunicationError,
    LiveStreamLimitError,
)
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session import MediaStream, P2PCredentials, StationSession
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

STANDALONE_SN = "T8170P2000054321"


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


async def _first_keyframe(stream: MediaStream) -> None:
    async for frame in stream:
        if frame.is_keyframe:
            return
    raise AssertionError("the stream ended before a keyframe")


async def test_a_second_camera_streams_on_an_extra_session_closed_with_it(
    station: FakeStation,
) -> None:
    session = _session(station)
    try:
        first = await session.async_open_live(0)
        await _first_keyframe(first)
        second = await session.async_open_live(1)
        await _first_keyframe(second)
        assert sorted(station.live_cameras) == [0, 1]
        assert station.sessions == 2
        assert session.stats().extra_live_sessions_open == 1
        await second.aclose()
        await _until(lambda: station.client_closes == 1)
        assert station.live_cameras == [0]  # the first camera streams on
        await _first_keyframe(first)
        stats = session.stats()
        assert (stats.extra_live_sessions, stats.extra_live_sessions_open) == (1, 0)
        assert stats.media_opens == 1  # the extra session's open is its own
        await first.aclose()
    finally:
        await session.async_close()


async def test_media_slot_channel_names_the_view_holding_the_slot(station: FakeStation) -> None:
    """The slot's channel is the live view on the station session; an extra-session view is not it."""
    session = _session(station)
    try:
        free = session.media_slot_channel  # local snapshot: narrowing the property to
        assert free is None  # None would poison every later read of it (mypy)
        first = await session.async_open_live(0)
        await _first_keyframe(first)
        assert session.media_slot_channel == 0
        assert session.stats().media_slot_channel == 0
        second = await session.async_open_live(1)
        await _first_keyframe(second)
        # Camera 1 runs on an extra session, so the slot still names camera 0.
        assert session.media_slot_channel == 0
        await first.aclose()
        await _until(lambda: session.media_slot_channel is None)
    finally:
        await session.async_close()


async def test_the_same_camera_twice_takes_an_extra_session(station: FakeStation) -> None:
    session = _session(station)
    try:
        async with await session.async_open_live(0) as first:
            await _first_keyframe(first)
            async with await session.async_open_live(0) as second:
                await _first_keyframe(second)
                assert station.live_cameras == [0, 0]
    finally:
        await session.async_close()


async def test_a_live_open_past_the_cap_raises_or_waits(station: FakeStation) -> None:
    session = _session(station)
    session.max_sessions = 3  # station session, trigger frames, one extra live session
    try:
        first = await session.async_open_live(0)
        second = await session.async_open_live(1)
        with pytest.raises(LiveStreamLimitError, match="2 extra sessions") as err:
            await session.async_open_live(2)
        assert err.value.limit == 2
        assert isinstance(err.value, CommunicationError)
        with pytest.raises(LiveStreamLimitError, match=r"none closed within 0\.2s"):
            await session.async_open_live(2, wait=True, first_frame_timeout=0.2)
        waiting = asyncio.create_task(session.async_open_live(2, wait=True))
        await asyncio.sleep(0.1)
        assert not waiting.done()
        await second.aclose()
        third = await asyncio.wait_for(waiting, 3)
        await _first_keyframe(third)
        assert sorted(station.live_cameras) == [0, 2]
        await third.aclose()
        await first.aclose()
    finally:
        await session.async_close()


async def test_the_slot_freeing_serves_a_waiting_open_on_the_station_session(
    station: FakeStation,
) -> None:
    session = _session(station)
    session.max_sessions = session_module.MIN_STATION_SESSIONS
    try:
        first = await session.async_open_live(0)
        waiting = asyncio.create_task(session.async_open_live(1, wait=True))
        await asyncio.sleep(0.1)
        await first.aclose()
        second = await asyncio.wait_for(waiting, 3)
        await _first_keyframe(second)
        assert station.sessions == 1
        assert session.stats().extra_live_sessions == 0
        await second.aclose()
    finally:
        await session.async_close()


async def test_a_failed_extra_open_closes_its_session_and_shares_the_wake_backoff(
    station: FakeStation,
) -> None:
    session = _session(station)
    try:
        first = await session.async_open_live(0)
        await _first_keyframe(first)
        station.live_open_receipt_code = -204
        second = await session.async_open_live(1)
        with pytest.raises(CameraWakeError):
            await anext(second)
        await _until(lambda: session.stats().extra_live_sessions_open == 0)
        await _until(lambda: station.sessions == 1)
        assert session.wake_backoff_left(1) > 0
        with pytest.raises(CameraWakeError, match="not retried"):
            await session.async_open_live(1)
        assert session.stats().extra_live_sessions == 1  # refused before a session
        await first.aclose()
    finally:
        await session.async_close()


async def test_closing_the_station_session_closes_its_extra_sessions(
    station: FakeStation,
) -> None:
    session = _session(station)
    first = await session.async_open_live(0)
    second = await session.async_open_live(1)
    await _first_keyframe(second)
    await session.async_close()
    await _until(lambda: station.sessions == 0)
    assert first.closed
    assert second.closed


async def test_a_standalone_camera_keeps_one_stream(station: FakeStation) -> None:
    station.serial = STANDALONE_SN
    station.static_key = static_key(STANDALONE_SN, station.did)
    session = _session(station, STANDALONE_SN)
    try:
        async with await session.async_open_live(0):
            with pytest.raises(CommunicationError, match="already open"):
                await session.async_open_live(0)
        assert station.sessions == 1
    finally:
        await session.async_close()


async def test_the_fake_station_closes_the_oldest_session_past_its_limit(
    station: FakeStation,
) -> None:
    station.max_sessions = 1
    first, second = _session(station), _session(station)
    try:
        await first.async_connect()
        await second.async_connect()
        await _until(lambda: not first.connected)
        assert (station.sessions, station.station_closes) == (1, 1)
        assert second.connected
    finally:
        await first.async_close()
        await second.async_close()


async def test_the_default_budget_serves_five_live_streams(station: FakeStation) -> None:
    session = _session(station)
    assert session.max_sessions == session_module.DEFAULT_STATION_SESSIONS == 6
    try:
        streams = [await session.async_open_live(channel) for channel in range(5)]
        with pytest.raises(LiveStreamLimitError) as err:
            await session.async_open_live(5)
        assert err.value.limit == 5
        for stream in streams:
            await _first_keyframe(stream)
        assert sorted(station.live_cameras) == [0, 1, 2, 3, 4]
    finally:
        await session.async_close()


async def test_raising_the_budget_serves_a_waiting_open(station: FakeStation) -> None:
    session = _session(station)
    session.max_sessions = 2
    try:
        first = await session.async_open_live(0)
        waiting = asyncio.create_task(session.async_open_live(1, wait=True))
        await asyncio.sleep(0.1)
        assert not waiting.done()
        session.max_sessions = 3
        second = await asyncio.wait_for(waiting, 3)
        await _first_keyframe(second)
        session.max_sessions = 2  # lowering ends no stream
        await _first_keyframe(second)
        with pytest.raises(LiveStreamLimitError, match="1 extra sessions"):
            await session.async_open_live(2)
        await first.aclose()
        await second.aclose()
    finally:
        await session.async_close()


@pytest.mark.parametrize("value", [1, 10, 0, 6.0, True])
def test_a_budget_outside_the_station_range_is_refused(value: object) -> None:
    with pytest.raises(ValueError, match="max_sessions must be an int from 2 to 9"):
        session_module._session_budget(value)
