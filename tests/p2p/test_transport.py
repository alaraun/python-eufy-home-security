from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.pppp import (
    DrwChunk,
    MsgType,
    decode_packet,
    encode_drw_ack,
    encode_packet,
)
from eufy_home_security.p2p.transport import ACKED_MEMORY, RENDEZVOUS_PORT, PPPPTransport, Wake
from eufy_home_security.testing import SYNTHETIC, FakeStation

PEER = ("127.0.0.1", 40000)


def make_transport() -> PPPPTransport:
    def on_chunk(_chunk: DrwChunk) -> None:
        pass

    def on_lost(_exc: Exception) -> None:
        pass

    return PPPPTransport(on_chunk=on_chunk, on_lost=on_lost)


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


async def test_cancel_while_waiting_for_p2p_rdy_closes_the_socket(station: FakeStation) -> None:
    station.send_ready = False
    transport = make_transport()
    task = asyncio.create_task(transport.connect("127.0.0.1", port=station.discovery_port))
    async with asyncio.timeout(3):
        while transport.peer is None:
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not transport.is_open
    assert transport._transport is not None
    assert transport._transport.is_closing()


class JunkPunchFirst(FakeStation):
    """Answers every search with an undecodable PUNCH_PKT before the real one."""

    def _on_discovery(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._session is not None:
            self._session.sendto(encode_packet(MsgType.PUNCH_PKT, b"\xff" * 20), addr)
        super()._on_discovery(data, addr)


async def test_undecodable_punch_is_ignored_during_discovery() -> None:
    fake = JunkPunchFirst()
    await fake.start()
    transport = make_transport()
    try:
        did = await transport.connect("127.0.0.1", port=fake.discovery_port)
    finally:
        transport.close()
        fake.stop()
    assert did == Did.parse(SYNTHETIC.did)


async def test_pinned_port_bind_waits_for_the_previous_socket(station: FakeStation) -> None:
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("", 0))
    port = holder.getsockname()[1]
    asyncio.get_running_loop().call_later(0.25, holder.close)  # the old session lets go
    transport = make_transport()
    try:
        await transport.connect("127.0.0.1", port=station.discovery_port, local_port=port)
        assert transport.local_port == port
    finally:
        transport.close()
        holder.close()


async def test_a_pinned_peer_admits_only_its_own_port(station: FakeStation) -> None:
    transport = make_transport()
    loop = asyncio.get_running_loop()
    other, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    try:
        await transport.connect("127.0.0.1", port=station.discovery_port)  # discovery still works
        assert transport.peer is not None
        assert transport.peer[1] != station.discovery_port  # pinned to the session socket
        local = ("127.0.0.1", transport.local_port)
        other.sendto(encode_packet(MsgType.CLOSE), local)  # the base's host, another port
        async with asyncio.timeout(3):
            while transport.wrong_port_drops == 0:
                await asyncio.sleep(0.01)
        assert transport.is_open  # the forged CLOSE did not end the session
    finally:
        other.close()
        transport.close()


def test_the_same_host_from_another_port_is_dropped_after_pinning() -> None:
    transport = make_transport()
    transport._peer = PEER
    sent = transport.send_drw(0, b"x")
    transport.datagram_received(encode_drw_ack(0, [sent]), (PEER[0], PEER[1] + 1))
    assert not transport.is_acked(0, sent)
    assert transport.wrong_port_drops == 1
    transport.datagram_received(encode_drw_ack(0, [sent]), ("127.0.0.2", PEER[1] + 1))
    assert transport.wrong_port_drops == 1  # another host: not counted as a wrong port
    transport.datagram_received(encode_drw_ack(0, [sent]), PEER)
    assert transport.is_acked(0, sent)


def test_acknowledgements_are_bounded_oldest_first_and_cleared_on_resend() -> None:
    transport = make_transport()
    transport._peer = PEER  # no socket: sends go nowhere, the bookkeeping still runs

    def ack(channel: int, indices: list[int]) -> None:
        transport.datagram_received(encode_drw_ack(channel, indices), PEER)

    first = transport.send_drw(0, b"x")
    ack(0, [first])
    assert transport.is_acked(0, first)
    transport._tx_index[0] = first  # the 16-bit index wrapped back round
    assert transport.send_drw(0, b"y") == first
    assert not transport.is_acked(0, first)  # an old ACK does not vouch for the new chunk

    ack(1, list(range(ACKED_MEMORY + 10)))
    assert not transport.is_acked(1, 0)  # the oldest are forgotten first
    assert transport.is_acked(1, ACKED_MEMORY + 9)


class _FakeRendezvous(asyncio.DatagramProtocol):
    """A rendezvous server that records the wake LOOKUP and punches back on it."""

    def __init__(self, did: Did) -> None:
        self._did = did
        self.lookups: list[bytes] = []
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:

        msg, payload = decode_packet(data)
        if msg == MsgType.LOOKUP and self._transport is not None:
            self.lookups.append(payload)
            # Stand in for the station punching the caller back over the LAN.
            self._transport.sendto(encode_packet(MsgType.PUNCH_PKT, self._did.to_struct()), addr)


async def test_wake_sends_a_lookup_and_punches_on_the_reply() -> None:

    loop = asyncio.get_running_loop()
    did = Did.parse(SYNTHETIC.did)
    server = _FakeRendezvous(did)
    server_tr, _ = await loop.create_datagram_endpoint(lambda: server, local_addr=("127.0.0.1", 0))
    server_port = server_tr.get_extra_info("sockname")[1]

    transport = make_transport()
    orig_sendto = transport._sendto

    def route(packet: bytes, addr: tuple[str, int]) -> None:
        # Send the LOOKUP to the fake server instead of the real rendezvous port.
        orig_sendto(packet, ("127.0.0.1", server_port) if addr[1] == RENDEZVOUS_PORT else addr)

    transport._sendto = route  # type: ignore[method-assign]
    try:
        did_out = await transport.connect(
            "127.0.0.1",
            port=59999,  # nothing answers a LAN_SEARCH here; only the wake works
            expected_did=did,
            timeout=5.0,
            wake=Wake(servers=("10.0.0.1",), dsk="XaDbKBfe4sMgsUFo91nw"),
        )
        assert did_out == did
        assert server.lookups
        assert server.lookups[0][40:].rstrip(b"\x00") == b"XaDbKBfe4sMgsUFo91nw"
    finally:
        transport.close()
        server_tr.close()


async def test_wake_requires_the_did() -> None:

    transport = make_transport()
    try:
        with pytest.raises(ProtocolError):
            await transport.connect("127.0.0.1", wake=Wake(servers=("10.0.0.1",), dsk="x" * 8))
    finally:
        transport.close()
