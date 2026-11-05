"""PPPP transport: one UDP socket to one station.

This layer knows datagrams, not commands. It discovers the station on the LAN,
punches the session, keeps it alive, acknowledges and retransmits DRW chunks, and
hands every inbound chunk to the session above. Everything is driven by the event
loop through :class:`asyncio.DatagramProtocol` — there is exactly one reader.

Wire facts that shape it:

* Discovery is a ``LAN_SEARCH`` to UDP 32108; the station answers ``PUNCH_PKT``
  carrying its DID, **from a random high port that changes every session** (and
  not the port the search went to). Its later traffic comes from that port, so the peer is
  pinned to the address the ``PUNCH_PKT`` came from, and once pinned only datagrams
  from that exact (host, port) are accepted: everything in a session (replies,
  pushes, media) rides that one port.
* The station ignores the first ``LAN_SEARCH`` after a session was closed, so
  discovery re-sends until the timeout instead of trying once.
* A firewall can only admit the station's replies by the *local* port; pin it with
  ``local_port`` when that is needed (0 = ephemeral).
* The station answers ``ALIVE`` whether or not the encrypted session above still
  works, so packets arriving prove only that the link is up. Application-level
  liveness is the session's job.
* A HomeBase 3 ends a session (``CLOSE``) that sends no ``ALIVE`` for 5 to 7 s, so
  ``ALIVE`` goes out from a thread of its own, on a duplicate of the session's socket:
  a host that holds the event loop longer (a busy Home Assistant start) does not end
  the session. Everything else, reading included, stays on the event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from .._logging import Address, HexDump, Identifier, LogThrottle, Secret, wire_logger
from ..exceptions import CommunicationError, ProtocolError, StationUnreachableError
from .did import Did
from .pppp import (
    BROADCAST,
    DISCOVERY_PORT,
    DrwChunk,
    MsgType,
    decode_drw,
    decode_drw_ack,
    decode_packet,
    encode_drw,
    encode_drw_ack,
    encode_lookup,
    encode_packet,
)

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("p2p")

KEEPALIVE_INTERVAL = 0.7
"""Seconds between ``ALIVE`` pings — the cadence a live session uses."""
DISCOVERY_RETRY_INTERVAL = 1.0
READY_TIMEOUT = 2.0
RETRANSMIT_AFTER = 1.5
MAX_RETRANSMITS = 3
SILENCE_TIMEOUT = 15.0
"""Declare the link lost after this long without any datagram from the station."""
LOOP_HELD_REPORT = 2.0
"""A keepalive tick ending at least this late (seconds) means the event loop was held."""
ALIVE_HOLD_LIMIT = 60.0
"""The ALIVE thread ends after this long (seconds) without a keepalive tick: a loop held
that long, or gone, does not keep the station's session slot. The next tick restarts it."""
ALIVE_THREAD_NAME = "pppp-alive"
BIND_RETRIES = 5
BIND_RETRY_DELAY = 0.1
"""A pinned ``local_port`` can still be held for a moment by the socket of the session
just closed; retry the bind this many times, this far apart, before giving up."""
ACKED_MEMORY = 4096
"""Acknowledged (channel, index) pairs remembered for :meth:`PPPPTransport.is_acked`."""

#: The UDP port a station's rendezvous servers listen on for a wake ``LOOKUP``.
RENDEZVOUS_PORT = 32100
ANY_ADDRESS = "0.0.0.0"  # noqa: S104 - the LOOKUP's address when this host's is not known

type ChunkHandler = Callable[[DrwChunk], None]
type LostHandler = Callable[[Exception], None]


class StationClosedLinkError(StationUnreachableError):
    """The station sent a PPPP ``CLOSE``: it ended this session."""


class SilentLinkError(StationUnreachableError):
    """No datagram from the station for :data:`SILENCE_TIMEOUT` on an open session."""


@dataclass(frozen=True, slots=True)
class Wake:
    """What a battery station needs to be woken through its rendezvous servers: the
    server hosts (from the cloud ``app_conn``, :func:`~.pppp.decode_init_string`) and
    the device session key (:meth:`~..cloud.api.EufyCloudApi.async_get_dsk_key`)."""

    servers: tuple[str, ...]
    dsk: str


def _local_ip_towards(host: str) -> str:
    """This host's LAN address on the route to ``host`` (no packet is sent).

    ``host`` must already be an IP address: connecting a UDP socket to a literal only
    consults the routing table, but a *name* would resolve here, and a slow resolver
    would block the event loop for its whole timeout. Callers resolve first. Without a
    route, or without a socket to ask with, ``0.0.0.0`` (best effort: a ``LOOKUP`` naming
    it may not bring the station's punch to this host).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((host, RENDEZVOUS_PORT))
            return str(probe.getsockname()[0])
    except OSError:
        return ANY_ADDRESS


async def _resolve(host: str) -> str | None:
    """``host`` as an IPv4 address, resolving a name off the event loop; None when it
    does not resolve. Rendezvous servers arrive from the cloud's ``app_conn`` and may be
    names; a name must never reach a socket call, which would resolve it on the loop."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, RENDEZVOUS_PORT, family=socket.AF_INET, type=socket.SOCK_DGRAM
        )
    except OSError:
        return None
    return str(infos[0][4][0]) if infos else None


@dataclass(slots=True)
class _Pending:
    packet: bytes
    sent_at: float
    tries: int = 0


class PPPPTransport(asyncio.DatagramProtocol):
    """A single PPPP session to one station."""

    def __init__(self, *, on_chunk: ChunkHandler, on_lost: LostHandler) -> None:
        self._on_chunk = on_chunk
        self._on_lost = on_lost
        self._transport: asyncio.DatagramTransport | None = None
        self._discover_host: str | None = None
        self._expected_did: Did | None = None
        self._punch: asyncio.Future[tuple[Did, bytes, tuple[str, int]]] | None = None
        self._ready = asyncio.Event()
        self._peer: tuple[str, int] | None = None
        self._did: Did | None = None
        self._tx_index: dict[int, int] = {}
        self._unacked: dict[tuple[int, int], _Pending] = {}
        # Insertion-ordered, so trimming drops the oldest acknowledgements.
        self._acked: dict[tuple[int, int], None] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._last_rx = 0.0
        self._closed = False
        self._lost_reported = False
        self._lost_error: Exception | None = None
        self._alive_stop = threading.Event()
        self._alive_thread: threading.Thread | None = None
        self._tick_at = 0.0
        self._verdict_deferred = False
        self._wrong_port_drops = 0
        self._throttle = LogThrottle()

    # ── properties ───────────────────────────────────────────────────────────

    @property
    def peer(self) -> tuple[str, int] | None:
        """The station's session address, once punched."""
        return self._peer

    @property
    def did(self) -> Did | None:
        """The station's P2P id, once discovered."""
        return self._did

    @property
    def wrong_port_drops(self) -> int:
        """Datagrams dropped for coming from the peer's host but not its pinned port."""
        return self._wrong_port_drops

    @property
    def local_port(self) -> int | None:
        if self._transport is None:
            return None
        sockname = self._transport.get_extra_info("sockname")
        return int(sockname[1]) if sockname else None

    @property
    def is_open(self) -> bool:
        return self._peer is not None and not self._closed

    @property
    def seconds_since_rx(self) -> float:
        return time.monotonic() - self._last_rx if self._last_rx else float("inf")

    # ── connect / close ──────────────────────────────────────────────────────

    async def connect(
        self,
        host: str | None,
        *,
        port: int = DISCOVERY_PORT,
        local_port: int = 0,
        timeout: float = 6.0,
        expected_did: Did | None = None,
        wake: Wake | None = None,
    ) -> Did:
        """Discover and punch the station; returns its DID.

        ``host`` = the station's LAN address, or None to broadcast. Every station
        on the LAN answers a broadcast, so ``expected_did`` (from the cloud's
        device list) is what keeps a session from adopting a neighbour's reply.
        Raises :class:`StationUnreachableError` when nothing matching answers
        within ``timeout``.

        ``wake`` (a battery station, which does not answer a plain ``LAN_SEARCH``
        while asleep) also sends the station's rendezvous servers a ``LOOKUP`` each
        round; the server pokes the station over its standing cloud link and it
        punches back over the LAN. ``expected_did`` is required with it.
        """
        if wake is not None and expected_did is None:
            raise ProtocolError("a wake needs the station's DID to build its LOOKUP")
        wake_did = expected_did if wake is not None else None
        loop = asyncio.get_running_loop()
        for attempt in range(BIND_RETRIES + 1):
            try:
                await loop.create_datagram_endpoint(
                    # All interfaces: LAN discovery is a broadcast, and the reply arrives
                    # on whichever interface faces the station.
                    lambda: self,
                    local_addr=("0.0.0.0", local_port),  # noqa: S104
                    allow_broadcast=True,
                )
            except OSError as err:
                if local_port and err.errno == errno.EADDRINUSE and attempt < BIND_RETRIES:
                    await asyncio.sleep(BIND_RETRY_DELAY)
                    continue
                raise CommunicationError(
                    f"cannot bind local UDP port {local_port}: {err}; "
                    "another client may be using it — choose another or use 0 (ephemeral)"
                ) from err
            break
        _LOGGER.debug(
            "bound UDP port %s; searching %s:%d for DID %s",
            self.local_port,
            Address(host or BROADCAST),
            port,
            Secret(expected_did) if expected_did else "(any)",
        )

        self._discover_host = host
        self._expected_did = expected_did
        self._punch = loop.create_future()
        search = encode_packet(MsgType.LAN_SEARCH)
        target = (host or BROADCAST, port)
        try:
            lookup, servers = (
                await self._prepare_wake(wake, wake_did)
                if wake is not None and wake_did
                else (None, ())
            )
            deadline = loop.time() + timeout
            searches = 0
            while not self._punch.done():
                remaining = deadline - loop.time()
                if remaining <= 0:
                    _LOGGER.debug("no PUNCH_PKT after %d LAN_SEARCH(es)", searches)
                    raise StationUnreachableError(
                        f"no {'wake reply' if wake else 'LAN discovery reply'} from "
                        f"{host or ('the rendezvous servers' if wake else 'the broadcast address')} "
                        f"within {timeout:.0f}s"
                    )
                searches += 1
                _LOGGER.debug("LAN_SEARCH #%d to %s:%d", searches, Address(target[0]), target[1])
                self._sendto(search, target)
                if lookup is not None:
                    for server in servers:
                        self._sendto(lookup, (server, RENDEZVOUS_PORT))
                await asyncio.wait({self._punch}, timeout=min(DISCOVERY_RETRY_INTERVAL, remaining))
            did, body, addr = self._punch.result()
        except BaseException:
            self.close(send_close=False)
            raise

        self._peer = addr
        self._did = did
        self._last_rx = time.monotonic()
        _LOGGER.debug(
            "PUNCH_PKT from %s:%d (DID %s); punching back",
            Address(addr[0]),
            addr[1],
            Identifier(str(did)),
        )
        try:
            self._sendto(encode_packet(MsgType.PUNCH_PKT, body), addr)
            try:
                await asyncio.wait_for(self._ready.wait(), READY_TIMEOUT)
            except TimeoutError:
                # Not fatal: the station often skips P2P_RDY on the LAN and talks anyway.
                _LOGGER.debug("no P2P_RDY from %s; continuing", Address(addr[0]))
            if self._closed:  # the station or the socket ended the link meanwhile
                if isinstance(self._lost_error, StationUnreachableError):
                    raise self._lost_error
                raise StationUnreachableError(
                    "the P2P link closed while it was set up"
                ) from self._lost_error
            self._start_alive_thread(addr)
            self._spawn(self._keepalive_loop())
            self._spawn(self._retransmit_loop())
        except BaseException:
            # Cancelled while waiting for P2P_RDY: the socket must not outlive the call.
            self.close(send_close=True)
            raise
        _LOGGER.debug(
            "P2P link up to %s:%d (local port %s)", Address(addr[0]), addr[1], self.local_port
        )
        return did

    async def _prepare_wake(self, wake: Wake, did: Did) -> tuple[bytes, tuple[str, ...]]:
        """Send HELLO to each rendezvous server; return the LOOKUP to poke them with and the
        servers' addresses. A server whose name does not resolve is left out."""
        resolved = [await _resolve(host) for host in wake.servers]
        servers = tuple(ip for ip in resolved if ip is not None)
        our_ip = _local_ip_towards(servers[0]) if servers else ANY_ADDRESS
        _LOGGER.debug(
            "waking via %d of %d rendezvous server(s); our LAN endpoint %s:%s",
            len(servers),
            len(wake.servers),
            Address(our_ip),
            self.local_port,
        )
        hello = encode_packet(MsgType.HELLO)
        for ip in servers:
            self._sendto(hello, (ip, RENDEZVOUS_PORT))
        lookup = encode_packet(
            MsgType.LOOKUP, encode_lookup(did.to_struct(), our_ip, self.local_port or 0, wake.dsk)
        )
        return lookup, servers

    def close(self, *, send_close: bool = True) -> None:
        """Tear the session down (idempotent)."""
        if self._closed:
            return
        self._closed = True
        if self._peer is not None:
            _LOGGER.debug(
                "closing link to %s:%d%s", *self._peer, " (sending CLOSE)" if send_close else ""
            )
        self._stop_alive_thread()  # no ALIVE after the CLOSE
        if send_close and self._peer is not None:
            self._sendto(encode_packet(MsgType.CLOSE), self._peer)
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        if self._punch is not None and not self._punch.done():
            self._punch.cancel()
        if self._transport is not None:
            self._transport.close()

    # ── sending ──────────────────────────────────────────────────────────────

    def send_drw(self, channel: int, data: bytes) -> int:
        """Send one DRW chunk on ``channel``; returns the index it was sent with."""
        if self._peer is None or self._closed:
            raise StationUnreachableError("P2P link is not open")
        index = self._tx_index.get(channel, 0)
        self._tx_index[channel] = (index + 1) & 0xFFFF
        packet = encode_drw(channel, index, data)
        # After the 16-bit index wraps, an old acknowledgement must not vouch for this chunk.
        self._acked.pop((channel, index), None)
        self._unacked[(channel, index)] = _Pending(packet, time.monotonic())
        _LOGGER.debug("DRW tx ch%d idx%d (%d bytes)", channel, index, len(data))
        self._sendto(packet, self._peer)
        return index

    def is_acked(self, channel: int, index: int) -> bool:
        """Whether the station acknowledged chunk ``index`` on ``channel``."""
        return (channel, index) in self._acked

    # ── asyncio.DatagramProtocol ─────────────────────────────────────────────

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        host, port = str(addr[0]), int(addr[1])
        if _WIRE.isEnabledFor(logging.DEBUG):
            _WIRE.debug("rx %s:%d %s", Address(host), port, HexDump(data))
        try:
            msg, payload = decode_packet(data)
        except ProtocolError:
            if self._throttle.should_log(("not-pppp", host)):
                _LOGGER.debug("ignoring non-PPPP datagram from %s", Address(host))
            return

        if self._peer is None:
            self._on_discovery_packet(msg, payload, (host, port))
            return
        if (host, port) != self._peer:
            if host == self._peer[0]:
                # The station's own IP, but not the port this session was punched on:
                # not this session's traffic (another socket on the base, or a spoof).
                self._wrong_port_drops += 1
                if self._throttle.should_log(("wrong-port", port)):
                    _LOGGER.debug(
                        "dropping a datagram from %s:%d (session peer port %d)",
                        Address(host),
                        port,
                        self._peer[1],
                    )
            return
        self._last_rx = time.monotonic()

        if msg == MsgType.ALIVE:
            if self._throttle.should_log("alive"):
                _LOGGER.debug("keepalive: ALIVE from the station (logged every 5 min)")
            self._sendto(encode_packet(MsgType.ALIVE_ACK), self._peer)
        elif msg == MsgType.ALIVE_ACK:
            if self._throttle.should_log("alive-ack"):
                _LOGGER.debug("keepalive: ALIVE_ACK from the station (logged every 5 min)")
        elif msg == MsgType.DRW:
            self._on_drw(payload)
        elif msg == MsgType.DRW_ACK:
            self._on_drw_ack(payload)
        elif msg == MsgType.P2P_RDY:
            if not self._ready.is_set():
                _LOGGER.debug("P2P_RDY from %s", Address(host))
            self._ready.set()
        elif msg == MsgType.CLOSE:
            _LOGGER.debug("CLOSE from %s", Address(host))
            self._report_lost(StationClosedLinkError("the station closed the session"))
        elif self._throttle.should_log(("other-msg", msg)):
            _LOGGER.debug("ignoring PPPP type 0x%02x from %s", msg, Address(host))

    def error_received(self, exc: Exception) -> None:
        if self._throttle.should_log(("error", type(exc))):
            _LOGGER.debug("UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._closed:
            self._report_lost(CommunicationError(f"UDP socket closed: {exc}"))

    # ── internals ────────────────────────────────────────────────────────────

    def _on_discovery_packet(self, msg: int, payload: bytes, addr: tuple[str, int]) -> None:
        if msg != MsgType.PUNCH_PKT or self._punch is None or self._punch.done():
            return
        if (
            self._discover_host
            and self._discover_host != BROADCAST
            and addr[0] != self._discover_host
        ):
            if self._throttle.should_log(("other-host", addr[0])):
                _LOGGER.debug(
                    "ignoring a PUNCH_PKT from %s (searching %s)",
                    Address(addr[0]),
                    Address(self._discover_host),
                )
            return
        if len(payload) < 17:
            return
        try:
            did = Did.from_struct(payload)
        except ProtocolError:
            if self._throttle.should_log(("bad-punch", addr[0])):
                _LOGGER.debug(
                    "ignoring a PUNCH_PKT from %s whose DID does not decode", Address(addr[0])
                )
            return
        if self._expected_did is not None and did != self._expected_did:
            _LOGGER.debug(
                "ignoring discovery reply from another station (%s)", Identifier(str(did))
            )
            return
        self._punch.set_result((did, payload, addr))

    def _on_drw(self, payload: bytes) -> None:
        try:
            chunk = decode_drw(payload)
        except ProtocolError:
            if self._throttle.should_log("bad-drw"):
                _LOGGER.debug("ignoring malformed DRW chunk")
            return
        # Channel 1 carries media at dozens of chunks a second: sample it.
        if chunk.channel != 1 or self._throttle.should_log("drw-rx-media"):
            _LOGGER.debug(
                "DRW rx ch%d idx%d (%d bytes)%s",
                chunk.channel,
                chunk.index,
                len(chunk.data),
                " (media, sampled every 5 min)" if chunk.channel == 1 else "",
            )
        if self._peer is not None:
            self._sendto(encode_drw_ack(chunk.channel, [chunk.index]), self._peer)
        try:
            self._on_chunk(chunk)
        except Exception:
            _LOGGER.exception("P2P chunk handler failed")

    def _on_drw_ack(self, payload: bytes) -> None:
        try:
            channel, indices = decode_drw_ack(payload)
        except ProtocolError:
            if self._throttle.should_log("bad-drw-ack"):
                _LOGGER.debug("ignoring malformed DRW_ACK")
            return
        _LOGGER.debug("DRW_ACK ch%d idx %s", channel, ",".join(map(str, indices)))
        for index in indices:
            key = (channel, index)
            self._unacked.pop(key, None)
            self._acked.pop(key, None)  # re-insert as the newest
            self._acked[key] = None
        while len(self._acked) > ACKED_MEMORY:
            del self._acked[next(iter(self._acked))]

    def _start_alive_thread(self, peer: tuple[str, int]) -> None:
        """Start sending ``ALIVE`` to ``peer`` every :data:`KEEPALIVE_INTERVAL` from a
        daemon thread, until :meth:`close`.

        Raises :class:`CommunicationError` when the socket cannot be duplicated or the
        thread cannot start (the process is out of file descriptors or threads).
        """
        if self._transport is None:
            return
        try:
            sock = cast(socket.socket, self._transport.get_extra_info("socket")).dup()
        except OSError as err:
            raise CommunicationError(f"cannot duplicate the socket for ALIVE: {err}") from err
        self._tick_at = time.monotonic()
        thread = threading.Thread(
            target=_send_alive,
            args=(sock, peer, self._alive_stop, lambda: self._tick_at),
            name=ALIVE_THREAD_NAME,
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError as err:
            sock.close()
            raise CommunicationError(f"cannot start the ALIVE thread: {err}") from err
        self._alive_thread = thread

    def _stop_alive_thread(self) -> None:
        self._alive_stop.set()
        if self._alive_thread is not None:
            self._alive_thread.join()  # wakes at once; a send does not block
            self._alive_thread = None

    async def _keepalive_loop(self) -> None:
        """Watch the link while the thread sends ``ALIVE`` (see :meth:`_link_alive`); the
        thread stops with this task, also when the event loop ends without :meth:`close`."""
        try:
            while not self._closed and self._peer is not None:
                started = time.monotonic()
                await asyncio.sleep(KEEPALIVE_INTERVAL)
                self._tick_at = time.monotonic()
                if not self._link_alive(self._tick_at - started - KEEPALIVE_INTERVAL):
                    return
                self._restart_alive_thread()
        finally:
            self._alive_stop.set()

    def _restart_alive_thread(self) -> None:
        """Restart the ``ALIVE`` thread when it ended at :data:`ALIVE_HOLD_LIMIT`; a thread
        that cannot start ends the link."""
        thread = self._alive_thread
        if thread is None or thread.is_alive() or self._peer is None:
            return
        _LOGGER.debug("the ALIVE thread stopped while the event loop was held; restarting it")
        try:
            self._start_alive_thread(self._peer)
        except CommunicationError as err:
            self._report_lost(err)

    def _link_alive(self, late: float) -> bool:
        """Judge the link after a keepalive tick that ended ``late`` seconds late.

        After :data:`SILENCE_TIMEOUT` without a datagram the link is reported lost. A
        tick at least :data:`LOOP_HELD_REPORT` late means the event loop was held: it is
        logged, and the verdict waits for the next tick, since this one can run before
        the datagrams queued during the hold are read. Only one verdict in a row waits,
        so holds at every tick do not hide a silent station.
        """
        held = late >= LOOP_HELD_REPORT
        if held:
            _LOGGER.debug(
                "the event loop was held: a keepalive check ran %.1fs late; "
                "ALIVE went on from its thread",
                late,
            )
            if not self._verdict_deferred:
                self._verdict_deferred = True
                return True
        self._verdict_deferred = False
        if self.seconds_since_rx > SILENCE_TIMEOUT:
            self._report_lost(
                SilentLinkError(f"no datagram from the station for {SILENCE_TIMEOUT:.0f}s")
            )
            return False
        return True

    async def _retransmit_loop(self) -> None:
        while not self._closed and self._peer is not None:
            await asyncio.sleep(RETRANSMIT_AFTER / 3)
            now = time.monotonic()
            for key, pending in list(self._unacked.items()):
                if now - pending.sent_at < RETRANSMIT_AFTER:
                    continue
                if pending.tries >= MAX_RETRANSMITS:
                    self._unacked.pop(key, None)
                    _LOGGER.debug("DRW ch%d idx%d never acknowledged; giving up", *key)
                    continue
                pending.tries += 1
                pending.sent_at = now
                _LOGGER.debug("DRW ch%d idx%d unacknowledged; retransmit %d", *key, pending.tries)
                self._sendto(pending.packet, self._peer)

    def _sendto(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self._transport is None or self._transport.is_closing():
            return
        if _WIRE.isEnabledFor(logging.DEBUG):
            _WIRE.debug("tx %s:%d %s", Address(addr[0]), addr[1], HexDump(packet))
        self._transport.sendto(packet, addr)

    def _spawn(self, coro: object) -> None:
        task: asyncio.Task[None] = asyncio.get_running_loop().create_task(coro)  # type: ignore[arg-type]
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _report_lost(self, exc: Exception) -> None:
        if self._lost_reported:
            return
        self._lost_reported = True
        self._lost_error = exc
        _LOGGER.debug("P2P link down: %s", exc)
        self.close(send_close=False)
        self._on_lost(exc)


def _send_alive(
    sock: socket.socket,
    peer: tuple[str, int],
    stop: threading.Event,
    tick_at: Callable[[], float],
) -> None:
    """Send ``ALIVE`` to ``peer`` on ``sock`` every :data:`KEEPALIVE_INTERVAL` until
    ``stop``, or until the event loop's last keepalive tick (``tick_at``, monotonic) is
    :data:`ALIVE_HOLD_LIMIT` old; closes ``sock``. Runs in its own thread."""
    alive = encode_packet(MsgType.ALIVE)
    with sock:
        while not stop.is_set() and time.monotonic() - tick_at() < ALIVE_HOLD_LIMIT:
            if _WIRE.isEnabledFor(logging.DEBUG):
                _WIRE.debug("tx %s:%d %s", Address(peer[0]), peer[1], HexDump(alive))
            # A failed send is dropped: the event loop's silence check reports a dead link.
            with contextlib.suppress(OSError):
                sock.sendto(alive, peer)
            stop.wait(KEEPALIVE_INTERVAL)
