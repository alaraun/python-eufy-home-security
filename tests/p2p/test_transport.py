from __future__ import annotations

import asyncio
import errno
import gc
import logging
import socket
import threading
import time
import warnings
from collections.abc import AsyncIterator, Iterator
from ipaddress import IPv4Network
from types import SimpleNamespace
from typing import Any, cast

import pytest

from eufy_home_security.exceptions import (
    CommunicationError,
    ProtocolError,
    StationUnreachableError,
)
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p import transport as transport_module
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.pppp import (
    DrwChunk,
    MsgType,
    decode_packet,
    decode_sockaddr,
    encode_drw_ack,
    encode_p2p_req,
    encode_p2p_req_dsk,
    encode_packet,
    encode_sockaddr,
)
from eufy_home_security.p2p.transport import (
    ACKED_MEMORY,
    P2P_REQ_PORTS,
    RENDEZVOUS_PORT,
    ConnectPath,
    PPPPTransport,
    SilentLinkError,
    StationClosedLinkError,
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
    """A rendezvous server that records the wake P2P_REQ_DSK and punches back on it."""

    def __init__(self, did: Did) -> None:
        self._did = did
        self.requests: list[bytes] = []
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:

        msg, payload = decode_packet(data)
        if msg == MsgType.P2P_REQ_DSK and self._transport is not None:
            self.requests.append(payload)
            # Stand in for the station punching the caller back over the LAN.
            self._transport.sendto(encode_packet(MsgType.PUNCH_PKT, self._did.to_struct()), addr)


async def test_wake_sends_a_p2p_req_dsk_and_punches_on_the_reply() -> None:

    loop = asyncio.get_running_loop()
    did = Did.parse(SYNTHETIC.did)
    server = _FakeRendezvous(did)
    server_tr, _ = await loop.create_datagram_endpoint(lambda: server, local_addr=("127.0.0.1", 0))
    server_port = server_tr.get_extra_info("sockname")[1]

    transport = make_transport()
    orig_sendto = transport._sendto

    def route(packet: bytes, addr: tuple[str, int]) -> None:
        # Send the P2P_REQ_DSK to the fake server instead of the real rendezvous port.
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
        assert server.requests
        assert server.requests[0][40:].rstrip(b"\x00") == b"XaDbKBfe4sMgsUFo91nw"
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
        self.punch_reply: MsgType | None = MsgType.P2P_RDY
        """What a client's ``PUNCH_PKT`` gets (None: nothing)."""
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
            elif msg == MsgType.PUNCH_PKT and self.punch_reply is not None:
                self.sock.sendto(encode_packet(self.punch_reply), addr)
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


async def test_no_alive_after_close(peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch) -> None:
    send_alive = transport_module._send_alive

    def slow_to_end(*args: Any) -> None:
        send_alive(*args)
        time.sleep(0.1)  # close() must wait for the thread, not only signal it

    monkeypatch.setattr(transport_module, "_send_alive", slow_to_end)
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


@pytest.mark.parametrize("on_time_between", [False, True])
def test_only_one_verdict_in_a_row_waits(on_time_between: bool) -> None:
    """Holds at every tick do not hide a silent station; an on-time tick allows the next wait."""
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    transport._peer = PEER
    held = transport_module.LOOP_HELD_REPORT
    assert transport._link_alive(held)
    if on_time_between:
        transport._last_rx = time.monotonic()  # the queued answers were read
        assert transport._link_alive(0.0)
    transport._last_rx = time.monotonic() - 60
    assert transport._link_alive(held) is on_time_between
    assert bool(lost) is not on_time_between


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
    transport_module._send_alive(cast(socket.socket, sock), PEER, stop, time.monotonic)
    assert (sock.failed, sock.sent) == (1, 2)


async def test_a_sender_that_cannot_start_fails_the_connect(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    socks: list[socket.socket] = []

    class NoThread(threading.Thread):
        def __init__(self, *, args: tuple[Any, ...], **kwargs: Any) -> None:
            socks.append(args[0])
            super().__init__(args=args, **kwargs)

        def start(self) -> None:
            raise RuntimeError("can't start new thread")

    fake_threading = SimpleNamespace(Thread=NoThread, Event=threading.Event)
    monkeypatch.setattr(transport_module, "threading", fake_threading)
    transport = make_transport()
    with pytest.raises(CommunicationError, match="cannot start the ALIVE thread") as caught:
        await transport.connect("127.0.0.1", port=peer.port)
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert not transport.is_open
    assert transport._transport is not None
    assert transport._transport.is_closing()
    assert socks[0].fileno() == -1  # the duplicate socket is closed too


async def test_a_close_before_the_link_is_up_fails_the_connect(peer: ThreadedPeer) -> None:
    peer.punch_reply = MsgType.CLOSE
    transport = make_transport()
    with pytest.raises(StationClosedLinkError):
        await transport.connect("127.0.0.1", port=peer.port)
    assert not transport.is_open
    assert not _alive_threads()


async def test_a_socket_lost_before_the_link_is_up_fails_the_connect(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer.punch_reply = None  # no P2P_RDY: the connect waits it out
    monkeypatch.setattr(transport_module, "READY_TIMEOUT", 0.5)
    transport = make_transport()

    def lose_the_socket() -> None:
        assert transport._transport is not None
        transport._transport.close()

    asyncio.get_running_loop().call_later(0.2, lose_the_socket)
    with pytest.raises(StationUnreachableError) as caught:
        await transport.connect("127.0.0.1", port=peer.port)
    assert isinstance(caught.value.__cause__, CommunicationError)
    assert not _alive_threads()


def test_the_alive_thread_ends_with_the_event_loop(peer: ThreadedPeer) -> None:
    """An event loop that ends without close() does not keep the station's session slot."""

    left: list[PPPPTransport] = []

    async def connect_and_leave() -> None:
        left.append(make_transport())
        await left[0].connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(0.1)

    asyncio.run(connect_and_leave())
    time.sleep(0.1)
    assert not _alive_threads()
    sent = len(peer.alive_at)
    time.sleep(0.3)
    assert len(peer.alive_at) == sent
    with warnings.catch_warnings():  # the loop is gone: its socket can no longer close cleanly
        warnings.simplefilter("ignore", ResourceWarning)
        left.clear()
        gc.collect()


async def test_the_alive_thread_ends_when_the_loop_is_held_too_long(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "ALIVE_HOLD_LIMIT", 0.3)
    transport = make_transport()
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(0.6)  # past the limit, the loop ticking: the thread goes on
        assert _alive_threads()
        start, end = _hold_the_loop(1.0)
        during = peer.alives_between(start, end)
        assert len(during) >= 3
        assert max(during) < start + 0.3 + 0.15  # none after the limit
        assert not _alive_threads()
        await asyncio.sleep(0.3)  # the next tick restarts it
        assert _alive_threads()
        assert peer.alives_between(end, time.monotonic())
        assert transport.is_open
    finally:
        transport.close()


async def test_an_alive_thread_that_cannot_restart_ends_the_link(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "ALIVE_HOLD_LIMIT", 0.3)
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(0.1)

        class NoThread(threading.Thread):
            def start(self) -> None:
                raise RuntimeError("can't start new thread")

        fake_threading = SimpleNamespace(Thread=NoThread, Event=threading.Event)
        monkeypatch.setattr(transport_module, "threading", fake_threading)
        _hold_the_loop(0.6)
        async with asyncio.timeout(3):
            while not lost:
                await asyncio.sleep(0.01)
        assert type(lost[0]) is CommunicationError
        assert "cannot start the ALIVE thread" in str(lost[0])
    finally:
        transport.close()


async def test_a_close_during_the_ready_wait_fails_the_connect(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer.punch_reply = None  # no P2P_RDY: the connect waits it out
    monkeypatch.setattr(transport_module, "READY_TIMEOUT", 0.5)
    lost: list[Exception] = []
    transport = PPPPTransport(on_chunk=lambda _c: None, on_lost=lost.append)
    asyncio.get_running_loop().call_later(0.2, transport.close)
    with pytest.raises(StationUnreachableError):
        await transport.connect("127.0.0.1", port=peer.port)
    assert not lost
    assert not _alive_threads()


async def test_an_on_time_loop_logs_no_hold(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.3)
    monkeypatch.setattr(transport_module, "LOOP_HELD_REPORT", 0.2)
    caplog.set_level(logging.DEBUG, logger=transport_module.__name__)
    transport = make_transport()
    try:
        await transport.connect("127.0.0.1", port=peer.port)
        await asyncio.sleep(1.0)
    finally:
        transport.close()
    assert not any("the event loop was held" in r.getMessage() for r in caplog.records)


async def test_a_socket_that_cannot_be_duplicated_fails_the_connect(
    peer: ThreadedPeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_dup(_sock: socket.socket) -> socket.socket:
        raise OSError(errno.EMFILE, "too many open files")

    monkeypatch.setattr(socket.socket, "dup", no_dup)
    transport = make_transport()
    with pytest.raises(CommunicationError, match="cannot duplicate the socket") as caught:
        await transport.connect("127.0.0.1", port=peer.port)
    assert isinstance(caught.value.__cause__, OSError)
    assert not transport.is_open
    assert not _alive_threads()


def test_no_socket_for_the_route_lookup_falls_back_to_any_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_socket(*_args: object) -> socket.socket:
        raise OSError(errno.EMFILE, "too many open files")

    monkeypatch.setattr(socket, "socket", no_socket)
    assert transport_module._local_ip_towards("127.0.0.1") == "0.0.0.0"  # noqa: S104


async def test_a_wake_cancelled_while_resolving_closes_the_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolving = asyncio.Event()

    async def hang(_host: str) -> str:
        resolving.set()
        await asyncio.Event().wait()
        return _host

    monkeypatch.setattr(transport_module, "_resolve", hang)
    transport = make_transport()
    task = asyncio.create_task(
        transport.connect(
            "127.0.0.1",
            port=59999,
            expected_did=Did.parse(SYNTHETIC.did),
            wake=Wake(servers=("rendezvous.example",), dsk="x" * 8),
        )
    )
    try:
        async with asyncio.timeout(3):
            await resolving.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport._transport is not None
        assert transport._transport.is_closing()
    finally:
        transport.close()


async def test_a_server_name_that_does_not_resolve_is_never_sent_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name reaching a socket call would be resolved on the event loop."""
    addresses = {"10.0.0.1": "10.0.0.1", "rendezvous.example": None, "alias.example": "10.0.0.1"}

    async def resolve(host: str) -> str | None:
        return addresses[host]

    looked_up: list[str] = []

    def route_to(host: str) -> str:
        looked_up.append(host)
        return "192.0.2.10"

    monkeypatch.setattr(transport_module, "_resolve", resolve)
    monkeypatch.setattr(transport_module, "_local_ip_towards", route_to)
    transport = make_transport()
    sent: list[tuple[int, tuple[str, int]]] = []

    def record(packet: bytes, addr: tuple[str, int]) -> None:
        sent.append((decode_packet(packet)[0], addr))

    transport._sendto = record  # type: ignore[method-assign]
    try:
        with pytest.raises(StationUnreachableError):
            await transport.connect(
                "127.0.0.1",
                port=59999,
                expected_did=Did.parse(SYNTHETIC.did),
                timeout=0.3,
                wake=Wake(servers=("rendezvous.example", "10.0.0.1", "alias.example"), dsk="x" * 8),
            )
    finally:
        transport.close()
    assert looked_up == ["10.0.0.1"]
    to_servers = [(msg, addr) for msg, addr in sent if addr[1] == RENDEZVOUS_PORT]
    hellos = [addr for msg, addr in to_servers if msg == MsgType.HELLO]
    assert hellos == [("10.0.0.1", RENDEZVOUS_PORT)]  # one per address, not per name
    assert {addr for msg, addr in to_servers if msg == MsgType.P2P_REQ_DSK} == {
        ("10.0.0.1", RENDEZVOUS_PORT)
    }


async def test_no_server_resolves_and_the_request_names_any_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve(_host: str) -> str | None:
        return None

    looked_up: list[str] = []

    def route_to(host: str) -> str:
        looked_up.append(host)
        return "192.0.2.10"

    monkeypatch.setattr(transport_module, "_resolve", resolve)
    monkeypatch.setattr(transport_module, "_local_ip_towards", route_to)
    transport = make_transport()
    payloads: list[bytes] = []

    def record(packet: bytes, addr: tuple[str, int]) -> None:
        if addr[1] == RENDEZVOUS_PORT:
            payloads.append(packet)

    transport._sendto = record  # type: ignore[method-assign]
    try:
        request, servers = await transport._prepare_wake(
            Wake(servers=("rendezvous.example",), dsk="x" * 8), Did.parse(SYNTHETIC.did)
        )
    finally:
        transport.close()
    assert (servers, payloads, looked_up) == ((), [], [])
    did = Did.parse(SYNTHETIC.did)
    any_address = encode_p2p_req_dsk(did.to_struct(), transport_module.ANY_ADDRESS, 0, "x" * 8)
    assert request == encode_packet(MsgType.P2P_REQ_DSK, any_address)


async def test_resolve_gives_none_for_a_name_that_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise socket.gaierror(socket.EAI_NONAME, "no such name")

    async def nothing(*_args: object, **_kwargs: object) -> list[object]:
        return []

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fail)
    assert await transport_module._resolve("rendezvous.example") is None
    monkeypatch.setattr(loop, "getaddrinfo", nothing)
    assert await transport_module._resolve("rendezvous.example") is None
    assert await transport_module._resolve("10.0.0.1") == "10.0.0.1"
    assert await transport_module._resolve("::1") is None  # the P2P_REQ_DSK and socket are IPv4


async def test_a_dsk_that_is_not_ascii_fails_the_connect_typed() -> None:
    transport = make_transport()
    with pytest.raises(ProtocolError, match="not ASCII"):
        await transport.connect(
            "127.0.0.1",
            port=59999,
            expected_did=Did.parse(SYNTHETIC.did),
            wake=Wake(servers=("10.0.0.1",), dsk="ä" * 8),
        )
    assert transport._transport is not None
    assert transport._transport.is_closing()


# ── rendezvous connect ──────────────────────────────────────────────────────

CAMERA_WAN = "198.51.100.7"
"""A PUNCH_TO address this host cannot reach (the route below drops it)."""
SEARCHED = "192.0.2.10"
"""The searched LAN address: the camera is not there, so only a punch reaches it."""
CAMERA_LAN = "192.0.2.77"
"""The camera's LAN address; the route carries it to and from its loopback socket."""


class _PunchToServer(asyncio.DatagramProtocol):
    """A rendezvous server: answers each P2P_REQ_DSK with one PUNCH_TO per entry."""

    def __init__(self, entries: list[bytes]) -> None:
        self.entries = entries
        self.received: list[tuple[int, bytes]] = []
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        msg, payload = decode_packet(data)
        self.received.append((msg, payload))
        if msg == MsgType.P2P_REQ_DSK and self._transport is not None:
            for entry in self.entries:
                self._transport.sendto(encode_packet(MsgType.PUNCH_TO, entry), addr)


class _RemoteCamera(asyncio.DatagramProtocol):
    """A station on another network: it never answers a LAN_SEARCH, and answers a
    client's PUNCH_PKT with its own PUNCH_PKT (``did``) and a P2P_RDY, sent from
    ``reply_from`` (its own socket by default)."""

    def __init__(self, did: Did) -> None:
        self.did = did
        self.punches: list[bytes] = []
        self.reply_from: asyncio.DatagramTransport | None = None
        self.answer_search: int | None = None
        """Answer the n-th LAN_SEARCH (from 1) and every later one; None: never."""
        self.searches = 0
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        msg, payload = decode_packet(data)
        if msg == MsgType.LAN_SEARCH:
            self.searches += 1
            if self.answer_search is not None and self.searches >= self.answer_search:
                assert self._transport is not None
                self._transport.sendto(encode_packet(MsgType.PUNCH_PKT, self.did.to_struct()), addr)
            return
        if msg != MsgType.PUNCH_PKT:
            return
        self.punches.append(payload)
        out = self.reply_from or self._transport
        if out is not None:
            out.sendto(encode_packet(MsgType.PUNCH_PKT, self.did.to_struct()), addr)
            out.sendto(encode_packet(MsgType.P2P_RDY, self.did.to_struct()), addr)


class _Rendezvous:
    """A punch-reachable camera, its rendezvous server and the route between them."""

    def __init__(self) -> None:
        self.did = Did.parse(SYNTHETIC.did)
        self.camera = _RemoteCamera(self.did)
        self.server = _PunchToServer([])
        self.sent: list[tuple[int, tuple[str, int], bytes]] = []
        self._endpoints: list[asyncio.DatagramTransport] = []
        self.camera_port = 0
        self.server_port = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        for proto in (self.camera, self.server):
            endpoint, _ = await loop.create_datagram_endpoint(
                lambda proto=proto: proto,  # type: ignore[misc]
                local_addr=("127.0.0.1", 0),
            )
            self._endpoints.append(endpoint)
        self.camera_port = self._endpoints[0].get_extra_info("sockname")[1]
        self.server_port = self._endpoints[1].get_extra_info("sockname")[1]
        self.server.entries = [
            encode_sockaddr(CAMERA_WAN, self.camera_port),
            encode_sockaddr(CAMERA_LAN, self.camera_port),
            encode_sockaddr("0.0.0.0", self.camera_port),  # noqa: S104 - the empty entry
        ]

    async def second_socket(self) -> asyncio.DatagramTransport:
        endpoint, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
        )
        self._endpoints.append(endpoint)
        return endpoint

    def route(self, transport: PPPPTransport) -> None:
        """Record every send; the rendezvous port goes to the fake server,
        :data:`CAMERA_LAN` to and from the camera's socket, and anything else that is
        not loopback is dropped (unreachable)."""
        send, receive = transport._sendto, transport.datagram_received
        start_alive = transport._start_alive_thread

        def routed(packet: bytes, addr: tuple[str, int]) -> None:
            msg, payload = decode_packet(packet)
            self.sent.append((msg, addr, payload))
            if addr[1] == RENDEZVOUS_PORT:
                send(packet, ("127.0.0.1", self.server_port))
            elif addr[0] in ("127.0.0.1", CAMERA_LAN):
                send(packet, ("127.0.0.1", addr[1]))

        def received(data: bytes, addr: tuple[str | Any, int]) -> None:
            if addr == ("127.0.0.1", self.camera_port):
                addr = (CAMERA_LAN, self.camera_port)
            receive(data, addr)

        def alive_to(peer: tuple[str, int]) -> None:
            start_alive(("127.0.0.1", peer[1]) if peer[0] == CAMERA_LAN else peer)

        transport._sendto = routed  # type: ignore[method-assign]
        transport.datagram_received = received  # type: ignore[method-assign]
        transport._start_alive_thread = alive_to  # type: ignore[method-assign]

    def punched(self) -> set[tuple[str, int]]:
        return {addr for msg, addr, _ in self.sent if msg == MsgType.PUNCH_PKT}

    def stop(self) -> None:
        for endpoint in self._endpoints:
            endpoint.close()


@pytest.fixture
async def rendezvous() -> AsyncIterator[_Rendezvous]:
    fake = _Rendezvous()
    await fake.start()
    yield fake
    fake.stop()


async def _connect_via(
    rendezvous: _Rendezvous,
    *,
    servers: tuple[str, ...] = ("127.0.0.1",),
    timeout: float = 3.0,
    host: str | None = SEARCHED,
    port: int = 59999,
) -> PPPPTransport:
    transport = make_transport()
    rendezvous.route(transport)
    try:
        await transport.connect(
            host,
            port=port,
            expected_did=rendezvous.did,
            timeout=timeout,
            wake=Wake(servers=servers, dsk="x" * 8),
        )
    except BaseException:
        transport.close()
        raise
    return transport


async def test_a_rendezvous_connect_punches_every_named_address_but_the_empty_one(
    rendezvous: _Rendezvous,
) -> None:
    transport = await _connect_via(rendezvous)
    try:
        assert transport.peer == (CAMERA_LAN, rendezvous.camera_port)
        assert transport.path is ConnectPath.RENDEZVOUS
        assert rendezvous.punched() == {
            (CAMERA_WAN, rendezvous.camera_port),
            (CAMERA_LAN, rendezvous.camera_port),
        }
        # The punch carries the station's DID, as its own PUNCH_PKT does.
        assert rendezvous.camera.punches[0] == rendezvous.did.to_struct()
    finally:
        transport.close()


async def test_the_first_punch_to_sends_a_p2p_req_to_each_server_once(
    rendezvous: _Rendezvous, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "_local_ip_towards", lambda _host: "192.0.2.20")
    transport = await _connect_via(rendezvous)
    try:
        local_port = transport.local_port or 0
        requests = [(addr, body) for msg, addr, body in rendezvous.sent if msg == MsgType.P2P_REQ]
        assert sorted(addr for addr, _ in requests) == [
            ("127.0.0.1", port) for port in P2P_REQ_PORTS
        ]
        assert {body for _, body in requests} == {
            encode_p2p_req(rendezvous.did.to_struct(), "192.0.2.20", local_port)
        }
    finally:
        transport.close()


async def test_a_punch_from_an_address_not_punched_is_ignored(
    rendezvous: _Rendezvous,
) -> None:
    rendezvous.camera.reply_from = await rendezvous.second_socket()
    with pytest.raises(StationUnreachableError):
        await _connect_via(rendezvous, timeout=1.5)
    assert (CAMERA_LAN, rendezvous.camera_port) in rendezvous.punched()  # it was punched


async def test_a_punch_with_another_stations_did_is_ignored(rendezvous: _Rendezvous) -> None:
    rendezvous.camera.did = Did.parse("EUPRAMA-654321-ZYXWV")
    with pytest.raises(StationUnreachableError):
        await _connect_via(rendezvous, timeout=1.5)
    assert rendezvous.camera.punches  # punched, answered, refused


async def test_every_discovery_round_punches_again(rendezvous: _Rendezvous) -> None:
    """The station is punched in each round the servers name it (two rounds in 1.5 s)."""
    rendezvous.camera.did = Did.parse("EUPRAMA-654321-ZYXWV")  # never taken: rounds go on
    with pytest.raises(StationUnreachableError):
        await _connect_via(rendezvous, timeout=1.5)
    assert len(rendezvous.camera.punches) >= 2 * transport_module.PUNCH_BURST


async def test_a_punch_to_from_another_host_than_the_servers_is_ignored(
    rendezvous: _Rendezvous,
) -> None:
    # The route still delivers to the fake server, but its answers come from
    # 127.0.0.1, which is not the server address the connect was given.
    with pytest.raises(StationUnreachableError):
        await _connect_via(rendezvous, servers=("127.0.0.2",), timeout=1.5)
    assert any(msg == MsgType.P2P_REQ_DSK for msg, _ in rendezvous.server.received)
    assert rendezvous.punched() == set()


async def test_lan_discovery_still_wins_when_the_station_answers_it(
    rendezvous: _Rendezvous, station: FakeStation
) -> None:
    rendezvous.server.entries = [encode_sockaddr(CAMERA_WAN, rendezvous.camera_port)]
    transport = await _connect_via(rendezvous, host="127.0.0.1", port=station.discovery_port)
    try:
        assert transport.peer is not None
        assert transport.peer[1] != rendezvous.camera_port
        assert transport.path is ConnectPath.LAN
    finally:
        transport.close()


# ── punch probe ─────────────────────────────────────────────────────────────


async def test_a_punch_probe_ends_at_the_stations_first_punch_with_a_close(
    rendezvous: _Rendezvous,
) -> None:
    """Success is the station's first PUNCH_PKT: no echo, no P2P_RDY wait, no ALIVE;
    the station gets a CLOSE and the socket is closed."""
    transport = make_transport()
    rendezvous.route(transport)
    peer = (CAMERA_LAN, rendezvous.camera_port)
    assert (
        await transport.punch_probe(
            expected_did=rendezvous.did,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            timeout=3.0,
        )
        == peer
    )
    assert transport.path is ConnectPath.RENDEZVOUS
    to_station = [msg for msg, addr, _ in rendezvous.sent if addr == peer]
    assert to_station == [MsgType.PUNCH_PKT] * transport_module.PUNCH_BURST + [MsgType.CLOSE]
    assert rendezvous.sent[-1][:2] == (MsgType.CLOSE, peer)
    assert MsgType.LAN_SEARCH not in {msg for msg, _, _ in rendezvous.sent}
    assert transport._alive_thread is None
    assert not transport.is_open
    assert transport._transport is not None
    assert transport._transport.is_closing()


async def test_an_unanswered_punch_probe_names_the_servers_and_closes_the_socket(
    rendezvous: _Rendezvous,
) -> None:
    rendezvous.camera.did = Did.parse("EUPRAMA-654321-ZYXWV")  # its punch is refused
    transport = make_transport()
    rendezvous.route(transport)
    with pytest.raises(
        StationUnreachableError, match=r"^no punch through 1 rendezvous server within 1s$"
    ):
        await transport.punch_probe(
            expected_did=rendezvous.did,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            timeout=1.0,
        )
    sent = {msg for msg, _, _ in rendezvous.sent}
    assert MsgType.P2P_REQ_DSK in sent
    assert not sent & {MsgType.LAN_SEARCH, MsgType.CLOSE}
    assert transport._transport is not None
    assert transport._transport.is_closing()


@pytest.mark.parametrize(
    ("servers", "text"),
    [
        ((), "0 rendezvous servers"),
        (("a",), "1 rendezvous server"),
        (("a", "b"), "2 rendezvous servers"),
    ],
)
def test_an_unanswered_punch_probe_counts_its_servers(servers: tuple[str, ...], text: str) -> None:
    assert transport_module._unpunched(servers, 5.0) == f"no punch through {text} within 5s"


async def test_without_a_wake_nothing_goes_to_the_servers(station: FakeStation) -> None:
    transport = make_transport()
    sent: list[tuple[str, int]] = []
    send = transport._sendto

    def record(packet: bytes, addr: tuple[str, int]) -> None:
        sent.append(addr)
        send(packet, addr)

    transport._sendto = record  # type: ignore[method-assign]
    try:
        await transport.connect("127.0.0.1", port=station.discovery_port)
        assert transport.path is ConnectPath.LAN
    finally:
        transport.close()
    assert all(port not in (RENDEZVOUS_PORT, *P2P_REQ_PORTS) for _, port in sent)


OUR_ENDPOINT = ("192.0.2.20", 40001)
"""This host's address towards the servers and its bound port, in :func:`_discovering`."""


def _discovering(transport: PPPPTransport, *, servers: frozenset[str]) -> list[tuple[str, int]]:
    """``transport`` in the discovery phase of a rendezvous connect, bound to
    :data:`OUR_ENDPOINT` without a socket; returns the list its punches are recorded
    into."""
    transport._punch = asyncio.get_running_loop().create_future()
    transport._transport = cast(
        asyncio.DatagramTransport,
        SimpleNamespace(get_extra_info=lambda _name: ("0.0.0.0", OUR_ENDPOINT[1])),  # noqa: S104
    )
    transport._our_ip = OUR_ENDPOINT[0]
    transport._servers = servers
    transport._rendezvous_did = Did.parse(SYNTHETIC.did)
    punched: list[tuple[str, int]] = []

    def record(packet: bytes, addr: tuple[str, int]) -> None:
        if decode_packet(packet)[0] == MsgType.PUNCH_PKT:
            punched.append(addr)

    transport._sendto = record  # type: ignore[method-assign]
    return punched


@pytest.mark.parametrize(
    ("body", "punches"),
    [
        (encode_sockaddr("203.0.113.9", 4000), True),
        (encode_sockaddr("203.0.113.9", 4000) + b"\x00\x00", True),  # trailing bytes
        (encode_sockaddr("192.88.99.9", 4000), True),  # public
        (encode_sockaddr(OUR_ENDPOINT[0], 4000), True),  # this host, another port
        (encode_sockaddr("0.0.0.0", 4000), False),  # noqa: S104 - names no address
        (encode_sockaddr("0.1.2.3", 4000), False),  # "this network"
        (encode_sockaddr("192.0.2.255", 4000), True),  # a /24's broadcast: netmask unknown
        (encode_sockaddr("255.255.255.255", 4000), False),
        (encode_sockaddr("127.0.0.1", 4000), False),
        (encode_sockaddr("127.1.2.3", 4000), False),
        (encode_sockaddr("224.0.0.1", 4000), False),
        (encode_sockaddr("239.255.255.250", 4000), False),
        (encode_sockaddr("169.254.1.1", 4000), False),
        (encode_sockaddr("240.0.0.1", 4000), False),
        (encode_sockaddr(*OUR_ENDPOINT), False),  # this host's own socket
        (encode_sockaddr("203.0.113.9", 0), False),
        (encode_sockaddr("203.0.113.9", 4000)[:15], False),  # truncated
        (b"\x00\x0a" + encode_sockaddr("203.0.113.9", 4000)[2:], False),  # not IPv4
    ],
)
async def test_which_punch_to_entries_are_punched(body: bytes, punches: bool) -> None:
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport.datagram_received(encode_packet(MsgType.PUNCH_TO, body), ("192.0.2.1", 32100))
    assert bool(punched) is punches
    if punches:
        assert set(punched) == {decode_sockaddr(body)}
        assert len(punched) == transport_module.PUNCH_BURST


LAN_SOURCE = ("192.0.2.60", 4000)
CGNAT_SOURCE = ("100.64.0.60", 4000)
"""A LAN numbered from the shared address space."""
PUBLIC_SOURCE = ("192.88.99.60", 4000)
"""Not a LAN address (:func:`~eufy_home_security.p2p.pppp.is_lan_address`)."""


@pytest.mark.parametrize(
    ("searched", "extra", "source", "punched", "path"),
    [
        # A broadcast reaches only this host's networks: a LAN address answers it.
        (None, (), LAN_SOURCE, None, ConnectPath.LAN),
        (None, (), CGNAT_SOURCE, None, ConnectPath.LAN),
        (None, (), LAN_SOURCE, (LAN_SOURCE[0], 4001), ConnectPath.LAN),  # another port
        (None, (), PUBLIC_SOURCE, None, None),
        (None, (), ("127.0.0.1", 4000), None, None),
        (None, (), LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        (None, (), PUBLIC_SOURCE, PUBLIC_SOURCE, ConnectPath.RENDEZVOUS),
        # A host searched by unicast answers the search; punched first, it counts as
        # rendezvous (the punch admits the reply through a stateful gateway).
        (LAN_SOURCE[0], (), LAN_SOURCE, None, ConnectPath.LAN),
        (LAN_SOURCE[0], (), LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        (LAN_SOURCE[0], (), LAN_SOURCE, (LAN_SOURCE[0], 4001), ConnectPath.LAN),
        (PUBLIC_SOURCE[0], (), PUBLIC_SOURCE, None, ConnectPath.LAN),
        (None, (LAN_SOURCE[0],), LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        (None, (LAN_SOURCE[0],), LAN_SOURCE, None, ConnectPath.LAN),
        (SEARCHED, (LAN_SOURCE[0],), LAN_SOURCE, None, ConnectPath.LAN),
        # Any other source counts only once punched, at that port.
        (SEARCHED, (), LAN_SOURCE, None, None),
        (SEARCHED, (), LAN_SOURCE, (LAN_SOURCE[0], 4001), None),
        (SEARCHED, (), LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        (SEARCHED, (), PUBLIC_SOURCE, PUBLIC_SOURCE, ConnectPath.RENDEZVOUS),
    ],
)
async def test_which_station_punch_is_taken_and_how_it_is_classified(
    searched: str | None,
    extra: tuple[str, ...],
    source: tuple[str, int],
    punched: tuple[str, int] | None,
    path: ConnectPath | None,
) -> None:
    transport = make_transport()
    _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport._discover_host = searched
    transport._extra_hosts = extra
    if punched is not None:
        transport.datagram_received(
            encode_packet(MsgType.PUNCH_TO, encode_sockaddr(*punched)), ("192.0.2.1", 32100)
        )
    did = Did.parse(SYNTHETIC.did)
    transport.datagram_received(encode_packet(MsgType.PUNCH_PKT, did.to_struct()), source)
    assert transport._punch is not None
    assert transport._punch.done() is (path is not None)
    assert transport.path is path


OUR_LAN = IPv4Network("192.0.2.0/24")
"""This host's connected network, holding :data:`LAN_SOURCE`."""
OTHER_LAN = IPv4Network("198.51.100.0/24")
"""Another network of this host, not holding :data:`LAN_SOURCE`."""


@pytest.mark.parametrize(
    ("networks", "searched", "source", "punched", "path"),
    [
        # A punched address in one of this host's networks is on the LAN.
        ((OUR_LAN,), None, LAN_SOURCE, LAN_SOURCE, ConnectPath.LAN),
        ((OTHER_LAN, OUR_LAN), LAN_SOURCE[0], LAN_SOURCE, LAN_SOURCE, ConnectPath.LAN),
        # Outside them, a punched address is the rendezvous path (another subnet, off-site).
        ((OTHER_LAN,), None, LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        ((OUR_LAN,), None, PUBLIC_SOURCE, PUBLIC_SOURCE, ConnectPath.RENDEZVOUS),
        ((), None, LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        # Not punched: the search's answer, inside the networks or not.
        ((OTHER_LAN,), LAN_SOURCE[0], LAN_SOURCE, None, ConnectPath.LAN),
        ((OUR_LAN,), None, LAN_SOURCE, None, ConnectPath.LAN),
        # Unknown networks: punched counts as rendezvous.
        (None, None, LAN_SOURCE, LAN_SOURCE, ConnectPath.RENDEZVOUS),
        (None, None, LAN_SOURCE, None, ConnectPath.LAN),
    ],
)
async def test_a_punched_station_on_this_hosts_network_counts_as_lan(
    networks: tuple[IPv4Network, ...] | None,
    searched: str | None,
    source: tuple[str, int],
    punched: tuple[str, int] | None,
    path: ConnectPath,
) -> None:
    transport = make_transport()
    _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport._discover_host = searched
    transport._local_networks = networks
    if punched is not None:
        transport.datagram_received(
            encode_packet(MsgType.PUNCH_TO, encode_sockaddr(*punched)), ("192.0.2.1", 32100)
        )
    did = Did.parse(SYNTHETIC.did)
    transport.datagram_received(encode_packet(MsgType.PUNCH_PKT, did.to_struct()), source)
    assert transport.path is path


@pytest.mark.parametrize(
    ("networks", "path"),
    [
        ((OUR_LAN,), ConnectPath.LAN),  # holds CAMERA_LAN
        ((OTHER_LAN,), ConnectPath.RENDEZVOUS),
    ],
)
async def test_a_station_answering_the_punch_to_its_lan_address_first_is_on_the_lan(
    rendezvous: _Rendezvous,
    networks: tuple[IPv4Network, ...],
    path: ConnectPath,
) -> None:
    """A station that ignores the search (it does so once after a close) but answers
    the punch toward its LAN address: on this host's network that link is a LAN one;
    on another subnet it is the rendezvous path."""
    transport = make_transport()
    rendezvous.route(transport)
    try:
        await transport.connect(
            SEARCHED,
            port=59999,
            expected_did=rendezvous.did,
            timeout=3.0,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            local_networks=networks,
        )
        assert transport.peer == (CAMERA_LAN, rendezvous.camera_port)
        assert transport.path is path
    finally:
        transport.close()


def _discovery_sends(transport: PPPPTransport) -> list[tuple[float, int, tuple[str, int]]]:
    """Record (monotonic time, type, address) of each LAN_SEARCH and PUNCH_PKT
    ``transport`` sends before its peer is pinned (the punch echo is left out)."""
    sent: list[tuple[float, int, tuple[str, int]]] = []
    inner = transport._sendto

    def timed(packet: bytes, addr: tuple[str, int]) -> None:
        msg = decode_packet(packet)[0]
        if transport.peer is None and msg in (MsgType.LAN_SEARCH, MsgType.PUNCH_PKT):
            sent.append((time.monotonic(), msg, addr))
        inner(packet, addr)

    transport._sendto = timed  # type: ignore[method-assign]
    return sent


def _first(sent: list[tuple[float, int, tuple[str, int]]], msg: int, host: str) -> float | None:
    return next((at for at, kind, addr in sent if kind == msg and addr[0] == host), None)


@pytest.mark.parametrize(
    ("host", "extra", "blocked"),
    [
        (CAMERA_LAN, (), True),  # searched by unicast
        (None, (), True),  # a broadcast covers this host's networks
        (SEARCHED, (CAMERA_LAN,), True),  # an extra search host
        # A stale searched address: the search never reached the station.
        (SEARCHED, (), False),
    ],
)
async def test_an_on_link_station_whose_lan_reply_is_blocked_is_punched_after_the_grace(
    rendezvous: _Rendezvous,
    monkeypatch: pytest.MonkeyPatch,
    host: str | None,
    extra: tuple[str, ...],
    blocked: bool,
) -> None:
    """The station's LAN address lies in this host's networks, but its LAN replies never
    arrive: that address is punched only once :data:`ON_LINK_PUNCH_GRACE` has passed
    since the first LAN_SEARCH, its public one at once; the link is a LAN one, recorded
    as LAN reply blocked only when discovery searched the station's address."""
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 0.5)
    transport = make_transport()
    rendezvous.route(transport)
    sent = _discovery_sends(transport)
    try:
        await transport.connect(
            host,
            port=rendezvous.camera_port,
            expected_did=rendezvous.did,
            timeout=3.0,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            extra_hosts=extra,
            local_networks=(OUR_LAN,),
            on_link_grace=True,
        )
        assert transport.peer == (CAMERA_LAN, rendezvous.camera_port)
        assert transport.path is ConnectPath.LAN
        assert transport.lan_reply_blocked is blocked
    finally:
        transport.close()
    search = next((at for at, kind, _ in sent if kind == MsgType.LAN_SEARCH), None)
    public = _first(sent, MsgType.PUNCH_PKT, CAMERA_WAN)
    on_link = _first(sent, MsgType.PUNCH_PKT, CAMERA_LAN)
    assert search is not None
    assert public is not None
    assert on_link is not None
    assert public - search < 0.15  # off-link: at once
    # When the grace ends, not at the next round's PUNCH_TO (1 s after the first).
    assert 0.5 - 0.01 <= on_link - search < 0.8


def test_the_on_link_grace_spans_two_search_rounds_inside_one_attempt() -> None:
    """The grace outlasts the third LAN_SEARCH (sent two rounds after the first) and
    ends inside one connect attempt."""
    assert (
        transport_module.DISCOVERY_RETRY_INTERVAL * 2
        < transport_module.ON_LINK_PUNCH_GRACE
        < session_module.DISCOVERY_TIMEOUT
    )


@pytest.mark.parametrize("answers", [2, 3])
async def test_an_on_link_station_answering_the_search_within_the_grace_is_never_punched(
    rendezvous: _Rendezvous, answers: int
) -> None:
    """At the real timing, a station that ignores the first LAN_SEARCH (as after a
    close) or the first two and answers the next, while its servers name its LAN
    address from the first round: the LAN reply wins, that address is never punched,
    and nothing is flagged."""
    rendezvous.camera.answer_search = answers
    transport = make_transport()
    rendezvous.route(transport)
    sent = _discovery_sends(transport)
    try:
        await transport.connect(
            CAMERA_LAN,
            port=rendezvous.camera_port,
            expected_did=rendezvous.did,
            timeout=session_module.DISCOVERY_TIMEOUT,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            local_networks=(OUR_LAN,),
            on_link_grace=True,
        )
        assert transport.path is ConnectPath.LAN
        assert transport.lan_reply_blocked is False
    finally:
        transport.close()
    assert rendezvous.camera.searches == answers
    assert _first(sent, MsgType.PUNCH_PKT, CAMERA_WAN) is not None  # PUNCH_TOs were taken
    assert _first(sent, MsgType.PUNCH_PKT, CAMERA_LAN) is None


@pytest.mark.parametrize(
    ("networks", "grace", "path"),
    [
        # The LAN address is outside this host's networks (another subnet): no grace.
        ((IPv4Network("203.0.113.0/24"),), True, ConnectPath.RENDEZVOUS),
        # Networks unknown: no grace, and a punched address is rendezvous.
        (None, True, ConnectPath.RENDEZVOUS),
        # No grace asked (a station reached on demand): punched at once, a LAN link.
        ((OUR_LAN,), False, ConnectPath.LAN),
    ],
)
async def test_without_an_on_link_grace_the_lan_address_is_punched_at_once(
    rendezvous: _Rendezvous,
    monkeypatch: pytest.MonkeyPatch,
    networks: tuple[IPv4Network, ...] | None,
    grace: bool,
    path: ConnectPath,
) -> None:
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 2.0)
    transport = make_transport()
    rendezvous.route(transport)
    sent = _discovery_sends(transport)
    try:
        await transport.connect(
            SEARCHED,
            port=59999,
            expected_did=rendezvous.did,
            timeout=3.0,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            local_networks=networks,
            on_link_grace=grace,
        )
        assert transport.path is path
        assert transport.lan_reply_blocked is False
    finally:
        transport.close()
    search = _first(sent, MsgType.LAN_SEARCH, SEARCHED)
    on_link = _first(sent, MsgType.PUNCH_PKT, CAMERA_LAN)
    assert search is not None
    assert on_link is not None
    assert on_link - search < 1.0


async def test_a_punch_to_after_the_peer_is_pinned_is_ignored() -> None:
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport._peer = PEER
    transport.datagram_received(
        encode_packet(MsgType.PUNCH_TO, encode_sockaddr("203.0.113.9", 4000)), ("192.0.2.1", 32100)
    )
    assert punched == []


async def test_a_punch_to_bursts_once_per_discovery_round() -> None:
    """Each server names the same addresses every round: one burst per address and
    round, however many servers name it."""
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1", "192.0.2.2"}))
    entry = encode_packet(MsgType.PUNCH_TO, encode_sockaddr("203.0.113.9", 4000))
    transport.datagram_received(entry, ("192.0.2.1", 32100))
    transport.datagram_received(entry, ("192.0.2.2", 32100))
    assert len(punched) == transport_module.PUNCH_BURST
    transport._search_round += 1
    transport.datagram_received(entry, ("192.0.2.2", 32100))
    assert len(punched) == 2 * transport_module.PUNCH_BURST


async def test_a_connect_punches_a_bounded_number_of_addresses() -> None:
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1"}))
    cap = transport_module.MAX_PUNCH_TARGETS
    targets = [("192.88.99.9", 4000 + n) for n in range(cap + 3)]
    for target in [*targets, targets[0]]:
        transport.datagram_received(
            encode_packet(MsgType.PUNCH_TO, encode_sockaddr(*target)), ("192.0.2.1", 32100)
        )
        transport._search_round += 1
    assert set(punched) == set(targets[:cap])
    # An address punched before the cap was reached is punched again.
    assert punched.count(targets[0]) == 2 * transport_module.PUNCH_BURST


async def test_on_link_punch_tos_after_the_grace_are_punched_each_round(
    rendezvous: _Rendezvous, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the grace has ended, the station's LAN address is punched in every later
    round its servers name it, like any other address."""
    monkeypatch.setattr(transport_module, "DISCOVERY_RETRY_INTERVAL", 0.2)
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 0.3)
    rendezvous.camera.did = Did.parse("EUPRAMA-654321-ZYXWV")  # never taken: rounds go on
    transport = make_transport()
    rendezvous.route(transport)
    with pytest.raises(StationUnreachableError):
        await transport.connect(
            CAMERA_LAN,
            port=rendezvous.camera_port,
            expected_did=rendezvous.did,
            timeout=1.0,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            local_networks=(OUR_LAN,),
            on_link_grace=True,
        )
    lan = [
        addr
        for msg, addr, _ in rendezvous.sent
        if msg == MsgType.PUNCH_PKT and addr[0] == CAMERA_LAN
    ]
    assert len(lan) >= 3 * transport_module.PUNCH_BURST  # the grace's end, then each round


async def test_a_grace_ending_after_the_punch_was_taken_punches_nothing() -> None:
    """The grace's timer can fire after a reply was taken but before the connect
    resumed: the held addresses are then left alone."""
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport._local_networks = (OUR_LAN,)
    assert transport._punch is not None
    transport._punch.set_result((Did.parse(SYNTHETIC.did), b"", (CAMERA_LAN, 4000)))
    transport._held_back = {(CAMERA_LAN, 4000): None}
    transport._end_grace()
    assert punched == []


@pytest.mark.parametrize("end", ["close", "cancel", "timeout"])
async def test_a_connect_ended_inside_the_grace_leaves_no_timer(
    rendezvous: _Rendezvous, monkeypatch: pytest.MonkeyPatch, end: str
) -> None:
    """A connect closed, cancelled or timed out while an on-link address is held back
    cancels the grace's timer, and that address is never punched."""
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 0.4)
    transport = make_transport()
    rendezvous.route(transport)
    task = asyncio.create_task(
        transport.connect(
            SEARCHED,
            port=59999,
            expected_did=rendezvous.did,
            timeout=0.2 if end == "timeout" else 3.0,
            wake=Wake(servers=("127.0.0.1",), dsk="x" * 8),
            local_networks=(OUR_LAN,),
            on_link_grace=True,
        )
    )
    await asyncio.sleep(0.1)
    timer = transport._grace_timer
    assert timer is not None
    assert transport._held_back  # the LAN address waits for the grace
    if end == "close":
        transport.close()
    elif end == "cancel":
        task.cancel()
    with pytest.raises((asyncio.CancelledError, StationUnreachableError)):
        await task
    assert timer.cancelled()
    await asyncio.sleep(0.4)
    assert (CAMERA_LAN, rendezvous.camera_port) not in rendezvous.punched()


async def test_the_grace_holds_back_no_more_addresses_than_may_still_be_punched(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """During the grace, held-back addresses count against :data:`MAX_PUNCH_TARGETS`
    with those already punched; an address named again is held (and logged) once."""
    caplog.set_level(logging.DEBUG, logger=transport_module.__name__)
    transport = make_transport()
    punched = _discovering(transport, servers=frozenset({"192.0.2.1"}))
    transport._local_networks = (OUR_LAN,)
    loop = asyncio.get_running_loop()
    transport._grace_timer = loop.call_later(60, lambda: None)
    cap = transport_module.MAX_PUNCH_TARGETS

    def name(target: tuple[str, int]) -> None:
        transport.datagram_received(
            encode_packet(MsgType.PUNCH_TO, encode_sockaddr(*target)), ("192.0.2.1", 32100)
        )

    off_link = [("198.51.100.9", 4000 + n) for n in range(3)]
    on_link = [(CAMERA_LAN, 5000 + n) for n in range(cap + 2)]
    try:
        for target in [*off_link, *on_link, on_link[0]]:
            name(target)
    finally:
        transport._grace_timer.cancel()
    assert list(transport._held_back) == on_link[: cap - len(off_link)]
    held = [r for r in caplog.records if "is on this host's network" in r.getMessage()]
    assert len(held) == cap - len(off_link)
    transport._end_grace()
    assert set(punched) == {*off_link, *on_link[: cap - len(off_link)]}


async def test_an_extra_search_host_is_searched_and_answers(station: FakeStation) -> None:
    transport = make_transport()
    searched: list[tuple[str, int]] = []
    send = transport._sendto

    def route(packet: bytes, addr: tuple[str, int]) -> None:
        if decode_packet(packet)[0] == MsgType.LAN_SEARCH:
            searched.append(addr)
        if addr[0] == "127.0.0.1":
            send(packet, addr)

    transport._sendto = route  # type: ignore[method-assign]
    try:
        await transport.connect(
            SEARCHED,
            port=station.discovery_port,
            expected_did=Did.parse(SYNTHETIC.did),
            extra_hosts=("127.0.0.1",),
        )
        assert transport.peer is not None
        assert transport.peer[0] == "127.0.0.1"
        assert transport.path is ConnectPath.LAN
    finally:
        transport.close()
    assert (SEARCHED, station.discovery_port) in searched
    assert ("127.0.0.1", station.discovery_port) in searched


async def test_without_the_extra_host_its_answer_is_ignored(station: FakeStation) -> None:
    """The control for the extra host: the same station answering from a host that
    was not searched is not adopted."""
    transport = make_transport()
    send = transport._sendto

    def route(packet: bytes, addr: tuple[str, int]) -> None:
        if addr[0] != "127.0.0.1":
            send(packet, ("127.0.0.1", addr[1]))  # deliver the search, from another host

    transport._sendto = route  # type: ignore[method-assign]
    with pytest.raises(StationUnreachableError):
        await transport.connect(
            SEARCHED,
            port=station.discovery_port,
            expected_did=Did.parse(SYNTHETIC.did),
            timeout=1.2,
        )


@pytest.mark.parametrize(
    ("host", "extra", "servers", "message"),
    [
        (SEARCHED, (), None, f"no LAN discovery reply from {SEARCHED}"),
        (
            None,
            ("192.0.2.33",),
            None,
            "no LAN discovery reply from the broadcast address or 192.0.2.33",
        ),
        (
            SEARCHED,
            (),
            ("192.0.2.1", "192.0.2.2", "2001:db8::1"),
            f"no LAN discovery reply from {SEARCHED} and no punch through 2 rendezvous servers",
        ),
        (
            SEARCHED,
            (),
            ("192.0.2.1",),
            f"no LAN discovery reply from {SEARCHED} and no punch through 1 rendezvous server",
        ),
        # No server address resolved: nothing went to the servers, so nothing is claimed.
        (SEARCHED, (), ("2001:db8::1",), f"no LAN discovery reply from {SEARCHED}"),
    ],
)
async def test_an_unanswered_connect_names_what_it_sent(
    host: str | None, extra: tuple[str, ...], servers: tuple[str, ...] | None, message: str
) -> None:
    transport = make_transport()
    transport._sendto = lambda packet, addr: None  # type: ignore[method-assign]
    with pytest.raises(StationUnreachableError) as caught:
        await transport.connect(
            host,
            expected_did=Did.parse(SYNTHETIC.did),
            timeout=0.05,
            wake=None if servers is None else Wake(servers=servers, dsk="x" * 8),
            extra_hosts=extra,
        )
    assert str(caught.value) == f"{message} within 0s"


async def test_only_the_first_punch_to_sends_the_p2p_reqs() -> None:
    transport = make_transport()
    _discovering(transport, servers=frozenset({"192.0.2.1"}))
    requests: list[tuple[str, int]] = []

    def record(packet: bytes, addr: tuple[str, int]) -> None:
        if decode_packet(packet)[0] == MsgType.P2P_REQ:
            requests.append(addr)

    transport._sendto = record  # type: ignore[method-assign]
    for port in (4000, 4001, 4002):
        transport.datagram_received(
            encode_packet(MsgType.PUNCH_TO, encode_sockaddr("203.0.113.9", port)),
            ("192.0.2.1", 32100),
        )
        assert sorted(requests) == [("192.0.2.1", port) for port in P2P_REQ_PORTS]
