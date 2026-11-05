from __future__ import annotations

import asyncio
import errno
import logging
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import cast

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p import transport as transport_module
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.pppp import (
    DrwChunk,
    MsgType,
    decode_packet,
    encode_drw_ack,
    encode_packet,
)
from eufy_home_security.p2p.transport import (
    ACKED_MEMORY,
    RENDEZVOUS_PORT,
    PPPPTransport,
    SilentLinkError,
    Wake,
)
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


class ThreadedPeer:
    """A station on a blocking socket in its own thread: it answers and stamps each
    ``ALIVE`` on arrival while the client's event loop is held."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.02)
        self.port: int = self.sock.getsockname()[1]
        self.alive_at: list[float] = []
        self.answer = True
        """Whether ``ALIVE`` gets an ``ALIVE_ACK``."""
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except TimeoutError:
                continue
            msg, _ = decode_packet(data)
            if msg == MsgType.LAN_SEARCH:
                did = Did.parse(SYNTHETIC.did)
                self.sock.sendto(encode_packet(MsgType.PUNCH_PKT, did.to_struct()), addr)
            elif msg == MsgType.PUNCH_PKT:
                self.sock.sendto(encode_packet(MsgType.P2P_RDY), addr)
            elif msg == MsgType.ALIVE:
                self.alive_at.append(time.monotonic())
                if self.answer:
                    self.sock.sendto(encode_packet(MsgType.ALIVE_ACK), addr)

    def alives_between(self, start: float, end: float) -> list[float]:
        return [t for t in self.alive_at if start <= t <= end]

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()
        self.sock.close()


@pytest.fixture
def peer(monkeypatch: pytest.MonkeyPatch) -> Iterator[ThreadedPeer]:
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.05)
    fake = ThreadedPeer()
    yield fake
    fake.stop()


def _hold_the_loop(seconds: float) -> tuple[float, float]:
    """Block the event loop (as a busy Home Assistant start does); the hold's bounds."""
    start = time.monotonic()
    time.sleep(seconds)
    return start, time.monotonic()


def _alive_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == transport_module.ALIVE_THREAD_NAME]


async def test_alive_keeps_going_while_the_event_loop_is_held(peer: ThreadedPeer) -> None:
    """The station ends a session that sends no ALIVE for a few seconds; a held loop must
    not stop them."""
    transport = make_transport()
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        start, end = _hold_the_loop(0.6)
        assert len(peer.alives_between(start, end)) >= 6  # one per 0.05 s, ~12
    finally:
        transport.close()


async def test_no_alive_after_close(peer: ThreadedPeer) -> None:
    transport = make_transport()
    await transport.connect("127.0.0.1", port=peer.port)
    await asyncio.sleep(0.2)
    assert peer.alive_at
    transport.close()
    assert not _alive_threads()  # the sender has ended when close() returns
    await asyncio.sleep(0.05)  # anything already on the wire lands
    sent = len(peer.alive_at)
    await asyncio.sleep(0.3)
    assert len(peer.alive_at) == sent


async def test_a_lost_link_stops_the_alive_sender(peer: ThreadedPeer) -> None:
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    await transport.connect("127.0.0.1", port=peer.port)
    assert _alive_threads()
    assert transport._transport is not None
    transport._transport.close()  # the socket goes away under the session
    async with asyncio.timeout(3):
        while not lost:
            await asyncio.sleep(0.01)
    assert not _alive_threads()


async def test_a_hold_past_the_silence_bound_keeps_an_answering_link(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The station's answers queued during the hold are read before the link is judged."""
    monkeypatch.setattr(transport_module, "SILENCE_TIMEOUT", 0.3)
    monkeypatch.setattr(transport_module, "LOOP_HELD_REPORT", 0.2)
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    caplog.set_level(logging.DEBUG, logger=transport_module.__name__)
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(0.1)  # the keepalive tick is waiting
        _hold_the_loop(0.6)  # past the silence bound
        await asyncio.sleep(0.4)
        assert not lost
        assert transport.is_open
        assert any("the event loop was held" in r.getMessage() for r in caplog.records)
    finally:
        transport.close()


async def test_a_hold_does_not_hide_a_silent_station(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "SILENCE_TIMEOUT", 0.3)
    monkeypatch.setattr(transport_module, "LOOP_HELD_REPORT", 0.2)
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(0.1)
        peer.answer = False
        _hold_the_loop(0.6)  # past the silence bound
        async with asyncio.timeout(3):
            while not lost:
                await asyncio.sleep(0.01)
        assert isinstance(lost[0], SilentLinkError)
    finally:
        transport.close()


@pytest.mark.parametrize(
    ("late", "verdict_waits"),
    [
        (0.0, False),
        (transport_module.LOOP_HELD_REPORT - 0.01, False),
        (transport_module.LOOP_HELD_REPORT, True),
        (30.0, True),
    ],
)
def test_a_held_tick_defers_the_silence_verdict(late: float, verdict_waits: bool) -> None:
    """A tick that ends late may run before the datagrams queued during the hold are read:
    it logs the hold and leaves the verdict to the next tick."""
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    transport._peer = PEER
    transport._last_rx = time.monotonic() - 60  # nothing read yet since before the hold
    assert transport._link_alive(late) is verdict_waits
    assert bool(lost) is not verdict_waits


class _FlakySocket:
    """A socket whose first send fails, as on a network that is briefly down."""

    def __init__(self, stop: threading.Event) -> None:
        self._stop = stop
        self.sent = 0
        self.failed = 0

    def sendto(self, _data: bytes, _addr: tuple[str, int]) -> None:
        if not self.failed:
            self.failed += 1
            raise OSError(errno.ENETUNREACH, "network unreachable")
        self.sent += 1
        if self.sent == 2:
            self._stop.set()

    def __enter__(self) -> _FlakySocket:
        return self

    def __exit__(self, *_exc: object) -> None:
        pass


def test_a_failed_send_does_not_end_the_alive_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.01)
    stop = threading.Event()
    sock = _FlakySocket(stop)
    transport_module._send_alive(cast(socket.socket, sock), PEER, stop)
    assert (sock.failed, sock.sent) == (1, 2)


async def test_a_sender_that_cannot_start_fails_the_connect(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    socks: list[socket.socket] = []

    class NoThread(threading.Thread):
        def start(self) -> None:
            socks.append(self._args[0])  # type: ignore[attr-defined]
            raise RuntimeError("can't start new thread")

    fake_threading = SimpleNamespace(Thread=NoThread, Event=threading.Event)
    monkeypatch.setattr(transport_module, "threading", fake_threading)
    transport = make_transport()
    with pytest.raises(RuntimeError):
        await transport.connect("127.0.0.1", port=peer.port)
    assert not transport.is_open
    assert transport._transport is not None
    assert transport._transport.is_closing()
    assert socks[0].fileno() == -1  # the duplicate socket is closed too
