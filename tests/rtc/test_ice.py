"""``rtc/ice.py``: the aioice adapter, over real loopback ICE."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from typing import Any

import pytest

from eufy_home_security.exceptions import CommunicationError, MissingDependencyError, ProtocolError
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
