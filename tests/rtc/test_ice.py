"""``rtc/ice.py``: the aioice adapter, over real loopback ICE."""

from __future__ import annotations

import asyncio
import gc
import importlib.util
import inspect
import logging
import sys
from collections.abc import AsyncIterator
from typing import Any

import pytest

from eufy_home_security._logging import LogThrottle
from eufy_home_security.exceptions import CommunicationError, MissingDependencyError, ProtocolError
from eufy_home_security.rtc import ice as ice_mod
from eufy_home_security.rtc.ice import MAX_REMOTE_CANDIDATES, IceAgent, IceTransport, require_aioice

needs_aioice = pytest.mark.skipif(
    importlib.util.find_spec("aioice") is None, reason="needs the rtc extra"
)


@pytest.fixture
def aioice() -> Any:
    return require_aioice()


@pytest.fixture
def loopback_only(monkeypatch: pytest.MonkeyPatch, aioice: Any) -> None:
    """Host candidates on 127.0.0.1 only (aioice leaves loopback out by default)."""
    monkeypatch.setattr(aioice.ice, "get_host_addresses", lambda **_kw: ["127.0.0.1"])


@pytest.fixture
def fast_stun(monkeypatch: pytest.MonkeyPatch, aioice: Any) -> None:
    """STUN retries every 20 ms, so a check left running shows within the test."""
    monkeypatch.setattr(aioice.stun, "RETRY_RTO", 0.02)


@pytest.fixture
async def loop_errors() -> AsyncIterator[list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, ctx: seen.append(ctx))
    yield seen
    loop.set_exception_handler(None)


@pytest.fixture
async def silent_port() -> AsyncIterator[int]:
    """A UDP port that receives the checks and never answers."""
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    yield transport.get_extra_info("sockname")[1]
    transport.close()


def check_tasks() -> list[asyncio.Task[Any]]:
    return [
        t
        for t in asyncio.all_tasks()
        if getattr(t.get_coro(), "__qualname__", "") == "Connection.check_start"
    ]


async def checking(port: int) -> IceTransport:
    """A client whose checks run against ``port`` (which never answers)."""
    client = IceTransport()
    client.add_remote_candidate(f"candidate:1 1 udp 2130706431 127.0.0.1 {port} typ host")
    await client.gather(local_ufrag="abcd", local_pwd="p" * 22, turn=None)
    return client


async def settled(errors: list[dict[str, Any]]) -> None:
    """Let timers of anything left running fire, then collect garbage."""
    await asyncio.sleep(0.3)
    gc.collect()
    await asyncio.sleep(0)
    assert errors == []


@needs_aioice
def test_the_aioice_internals_the_transport_stops_are_there(aioice: Any) -> None:
    """The check list and the pair's task are aioice internals: an upgrade renaming them
    must fail here."""
    connection = aioice.Connection(ice_controlling=False, components=1, use_ipv6=False)
    assert isinstance(connection._check_list, list)
    candidate = aioice.Candidate.from_sdp("1 1 udp 1 127.0.0.1 9 typ host")
    pair = aioice.ice.CandidatePair(None, candidate)
    assert pair.task is None
    assert aioice.Connection.check_start.__qualname__ == "Connection.check_start"
    gather = inspect.signature(aioice.Connection.get_component_candidates)
    assert gather.parameters["timeout"].default == ice_mod.AIOICE_GATHER_TIMEOUT


@needs_aioice
async def test_a_timed_out_connect_leaves_no_check_running(
    loopback_only: None, fast_stun: None, silent_port: int, loop_errors: list[dict[str, Any]]
) -> None:
    client = await checking(silent_port)
    try:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.3):
                await client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22)
        assert check_tasks() == []
        await settled(loop_errors)
    finally:
        await client.close()
    await settled(loop_errors)


@needs_aioice
async def test_close_during_the_checks_stops_them_and_fails_connect(
    loopback_only: None, fast_stun: None, silent_port: int, loop_errors: list[dict[str, Any]]
) -> None:
    client = await checking(silent_port)
    connect = asyncio.create_task(client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22))
    await asyncio.sleep(0.2)
    assert check_tasks()  # the checks run
    await client.close()
    assert check_tasks() == []
    with pytest.raises(CommunicationError):
        async with asyncio.timeout(2):
            await connect
    await settled(loop_errors)


@needs_aioice
async def test_close_stops_the_checks_before_and_after_the_sockets_close(
    loopback_only: None, fast_stun: None, silent_port: int, loop_errors: list[dict[str, Any]]
) -> None:
    """None runs while the sockets close; one a request starts meanwhile is stopped too."""
    client = await checking(silent_port)
    connect = asyncio.create_task(client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22))
    await asyncio.sleep(0.2)
    connection = client._connection
    assert connection is not None
    assert check_tasks()
    real_close = connection.close
    running_at_close: list[int] = []

    async def closing() -> None:
        running_at_close.append(len(check_tasks()))
        pair = connection._check_list[0]
        pair.task = None
        connection.check_start_task(pair)  # as an incoming check request would
        await real_close()

    connection.close = closing  # type: ignore[method-assign]
    await client.close()
    assert running_at_close == [0]
    assert check_tasks() == []
    with pytest.raises(CommunicationError):
        await connect
    await settled(loop_errors)


@needs_aioice
async def test_without_the_check_list_close_warns_once_and_still_closes(
    loopback_only: None, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An aioice that renamed its check list: the checks are left to aioice, said once."""
    monkeypatch.setattr(ice_mod, "_CHECK_LIST", "_renamed")
    monkeypatch.setattr(ice_mod, "_contract_warned", LogThrottle())
    for _ in range(2):
        client = IceTransport()
        await client.gather(local_ufrag="abcd", local_pwd="p" * 22, turn=None)
        connection = client._connection
        assert connection is not None
        await client.close()
        assert connection._protocols == []
    warnings = [
        r
        for r in caplog.records
        if r.name == ice_mod.__name__
        and r.levelno == logging.WARNING
        and "check list" in r.getMessage()
    ]
    assert len(warnings) == 1


@needs_aioice
def test_the_transport_is_an_ice_agent() -> None:
    assert isinstance(IceTransport(), IceAgent)


def test_without_aioice_the_transport_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "aioice", None)
    with pytest.raises(MissingDependencyError) as caught:
        require_aioice()
    assert caught.value.extra == "rtc"
    with pytest.raises(MissingDependencyError):
        IceTransport()


@needs_aioice
async def test_the_controlled_client_connects_to_a_controlling_peer(
    loopback_only: None, aioice: Any
) -> None:
    client = IceTransport()
    device = aioice.Connection(ice_controlling=True, components=1, use_ipv6=False)
    try:
        await device.gather_candidates()
        for candidate in device.local_candidates:
            client.add_remote_candidate(f"a=candidate:{candidate.to_sdp()}")  # before gather
        lines = await client.gather(local_ufrag="abcd", local_pwd="p" * 22, turn=None)
        assert lines
        connection = client._connection
        assert connection is not None
        assert connection.ice_controlling is False  # the device controls
        assert connection._use_ipv6 is False
        assert (connection.local_username, connection.local_password) == ("abcd", "p" * 22)
        assert all(line.startswith("candidate:") for line in lines)
        for line in lines:
            await device.add_remote_candidate(aioice.Candidate.from_sdp(line[len("candidate:") :]))
        device.remote_username, device.remote_password = "abcd", "p" * 22
        async with asyncio.timeout(10):
            await asyncio.gather(
                client.connect(
                    remote_ufrag=device.local_username, remote_pwd=device.local_password
                ),
                device.connect(),
            )
        await client.send(b"to device")
        async with asyncio.timeout(5):
            assert await device.recv() == b"to device"
            await device.send(b"to client")
            assert await client.recv() == b"to client"
    finally:
        await client.close()
        await device.close()
    with pytest.raises(CommunicationError):
        await client.recv()


@needs_aioice
async def test_failed_ice_checks_raise_a_communication_error(loopback_only: None) -> None:
    client = IceTransport()
    await client.gather(local_ufrag="abcd", local_pwd="p" * 22, turn=None)
    connection = client._connection
    assert connection is not None
    await connection.add_remote_candidate(None)  # end of candidates, none to check
    try:
        with pytest.raises(CommunicationError):
            async with asyncio.timeout(5):
                await client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22)
    finally:
        await client.close()


@needs_aioice
async def test_before_gather_the_connection_is_not_there() -> None:
    client = IceTransport()
    with pytest.raises(CommunicationError):
        await client.send(b"x")
    with pytest.raises(CommunicationError):
        await client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22)
    await client.close()


@needs_aioice
def test_an_unreadable_candidate_is_a_protocol_error() -> None:
    with pytest.raises(ProtocolError):
        IceTransport().add_remote_candidate("a=candidate:junk")


@needs_aioice
def test_a_tcp_candidate_is_ignored() -> None:
    client = IceTransport()
    client.add_remote_candidate("candidate:1 1 tcp 1 127.0.0.1 9 typ host tcptype passive")
    assert client._pending == []


@needs_aioice
def test_remote_candidates_are_capped() -> None:
    client = IceTransport()
    for port in range(MAX_REMOTE_CANDIDATES + 3):
        client.add_remote_candidate(f"candidate:1 1 udp 1 127.0.0.1 {port + 1} typ host")
    assert len(client._pending) == MAX_REMOTE_CANDIDATES


class _InstantConnection:
    """An aioice connection stand-in whose checks succeed at once."""

    def __init__(self) -> None:
        self._check_list: list[Any] = []
        self.remote_username: str | None = None
        self.remote_password: str | None = None
        self.closed = False

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


@needs_aioice
async def test_a_close_after_the_checks_ended_but_before_connect_returns_fails_it() -> None:
    client = IceTransport()
    client._connection = _InstantConnection()  # type: ignore[assignment]
    connect = asyncio.create_task(client.connect(remote_ufrag="wxyz", remote_pwd="q" * 22))
    await asyncio.sleep(0)  # connect waits for its checks
    checks = client._checks
    assert checks is not None
    await asyncio.sleep(0)  # the checks ended; connect has not run since
    assert checks.done()
    assert not connect.done()
    await client.close()
    with pytest.raises(CommunicationError):
        await connect
