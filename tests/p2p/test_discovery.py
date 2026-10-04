from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from eufy_home_security.exceptions import CommunicationError
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation, discover_stations
from eufy_home_security.p2p.pppp import MsgType, decode_packet, encode_packet
from eufy_home_security.testing import SYNTHETIC, FakeStation


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


async def test_a_station_is_listed_with_the_did_from_its_punch(station: FakeStation) -> None:
    found = await discover_stations(timeout=0.4, port=station.discovery_port, target="127.0.0.1")
    assert len(found) == 1
    assert found[0].ip == "127.0.0.1"
    assert found[0].did == Did.parse(SYNTHETIC.did)
    assert found[0].port != station.discovery_port  # the answer comes from the session socket


async def test_search_repeats_past_an_ignored_one_and_dedupes(station: FakeStation) -> None:
    station.ignore_searches = 1
    found = await discover_stations(timeout=2.3, port=station.discovery_port, target="127.0.0.1")
    assert station.searches >= 3  # two answered: still listed once
    assert [s.did for s in found] == [Did.parse(SYNTHETIC.did)]


async def test_non_punch_and_malformed_answers_are_ignored() -> None:
    loop = asyncio.get_running_loop()
    junk = (b"not pppp", encode_packet(MsgType.ALIVE), encode_packet(MsgType.PUNCH_PKT, b"short"))

    class Responder(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            self.transport = transport

        def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
            assert decode_packet(data)[0] == MsgType.LAN_SEARCH
            assert isinstance(self.transport, asyncio.DatagramTransport)
            for packet in junk:
                self.transport.sendto(packet, addr)

    transport, _ = await loop.create_datagram_endpoint(Responder, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        found = await discover_stations(timeout=0.3, port=port, target="127.0.0.1")
    finally:
        transport.close()
    assert found == []


async def test_a_busy_local_port_raises_communication_error() -> None:
    loop = asyncio.get_running_loop()
    holder, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        local_addr=("0.0.0.0", 0),  # noqa: S104 — must be the wildcard to collide with discovery
    )
    try:
        busy = holder.get_extra_info("sockname")[1]
        with pytest.raises(CommunicationError):
            await discover_stations(timeout=0.1, local_port=busy, target="127.0.0.1")
    finally:
        holder.close()


class _FailingTransport:
    """A datagram transport whose sendto fails the asyncio way: via error_received."""

    def __init__(self, protocol: asyncio.DatagramProtocol) -> None:
        self.protocol = protocol
        self.closed = False

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.protocol.error_received(OSError(101, "Network is unreachable"))

    def close(self) -> None:
        self.closed = True


async def test_a_send_failure_with_no_answer_raises_communication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = asyncio.get_running_loop()
    made: list[_FailingTransport] = []

    async def fake_endpoint(factory: Any, **_: Any) -> tuple[_FailingTransport, Any]:
        protocol = factory()
        made.append(_FailingTransport(protocol))
        return made[-1], protocol

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_endpoint)
    with pytest.raises(CommunicationError, match="unreachable"):
        await discover_stations(timeout=0.05, target="192.0.2.1")
    assert made[0].closed


async def test_a_send_failure_does_not_hide_stations_that_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = asyncio.get_running_loop()
    punch = encode_packet(MsgType.PUNCH_PKT, Did.parse(SYNTHETIC.did).to_struct())

    class Partial(_FailingTransport):
        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            self.protocol.datagram_received(punch, ("192.0.2.10", 4321))
            super().sendto(data, addr)

    async def fake_endpoint(factory: Any, **_: Any) -> tuple[Partial, Any]:
        protocol = factory()
        return Partial(protocol), protocol

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_endpoint)
    found = await discover_stations(timeout=0.05, target="192.0.2.10")
    assert [s.did for s in found] == [Did.parse(SYNTHETIC.did)]


def test_discovered_station_is_a_value() -> None:
    did = Did.parse(SYNTHETIC.did)
    assert DiscoveredStation("127.0.0.1", 1, did) == DiscoveredStation("127.0.0.1", 1, did)
