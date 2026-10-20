"""The ANKE reliable channel carried inside RTCP APP packets on the media plane.

The eufy command/data channel runs a small reliable protocol inside RTCP APP
packets (``name = b"ANKE"``, subtype 30). With SDES (DTLS inactive) these go out
raw over ICE, not SRTCP, so inbound ANKE must be caught before any SRTCP
unprotect. This module is the pure codec plus the reliable channel; wrapping an
ANKE frame in an RTCP APP packet and moving it over the ICE connection is the
caller's job (:mod:`.media_plane`).

Wire frame (little-endian, 20-byte header + body), from the app's native SDK
(jingle ``rtcp_packet_sdk``, ``.work/notes/s1/B2_TRANSPORT_MEDIA.md``)::

    0x00  u32 magic = 0x12345678
    0x04  u32 seq
    0x08  u8  type            (1 DATA, 2 ACK, 4 HEARTBEAT, 8 MTU-req, 9 MTU-resp)
    0x09  3   unused
    0x0c  u32 len             (body length)
    0x10  u32 checksum        (byte sum of header[0:16] + body, skipped for 8/9)
    0x14  body

Behaviour mirrors the device: a DATA packet is deduplicated by seq, acked with a
20-byte type-2, and delivered; an ACK cancels the retransmission of its seq; an
unacked DATA is retransmitted on a 100/200/500 ms backoff up to five times; an
MTU-request is answered with a type-9; heartbeats (type 4, seq 0) are sent on a
one-second interval. The XOR obfuscation the protocol can carry is off on the
WebRTC path (the device configures no key), so bodies are plaintext here; command
encryption is the per-command GCM of :mod:`.command`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from ..exceptions import ProtocolError

_LOGGER = logging.getLogger(__name__)

#: Magic at the head of every ANKE frame.
ANKE_MAGIC: Final = 0x12345678
#: Length of the ANKE header before the body.
ANKE_HEADER_LEN: Final = 20
#: RTCP APP name and subtype the device uses for this channel.
APP_NAME: Final = b"ANKE"
APP_SUBTYPE: Final = 30

#: Retransmission backoff (seconds) of an unacked DATA packet; five attempts.
RETRANSMIT_DELAYS: Final = (0.1, 0.2, 0.5, 0.5, 0.5)
#: How often a heartbeat (type 4) goes out; the app's RTCP ping is one second.
HEARTBEAT_INTERVAL: Final = 1.0
#: How many recently seen inbound seqs to keep for deduplication.
_DEDUP_RING: Final = 1000

_HEADER = struct.Struct("<IIBxxxI")  # magic, seq, type, 3 unused, len


class AnkeType(IntEnum):
    """ANKE packet types (the device's ``type`` byte)."""

    DATA = 1
    ACK = 2
    HEARTBEAT = 4
    MTU_REQUEST = 8
    MTU_RESPONSE = 9


@dataclass(frozen=True, slots=True)
class AnkeFrame:
    """A decoded ANKE frame."""

    type: int
    seq: int
    body: bytes


def _checksum(packet_header16: bytes, body: bytes) -> int:
    return (sum(packet_header16[:16]) + sum(body)) & 0xFFFFFFFF


def encode_anke(ptype: int, seq: int, body: bytes = b"") -> bytes:
    """One ANKE frame: the 20-byte header (checksum computed) and ``body``."""
    header16 = _HEADER.pack(ANKE_MAGIC, seq & 0xFFFFFFFF, ptype & 0xFF, len(body))
    checksum = _checksum(header16, body)
    return header16 + struct.pack("<I", checksum) + body


def decode_anke(packet: bytes) -> AnkeFrame:
    """Parse an ANKE frame; validate the magic, and the checksum for every type
    but the MTU probes (8/9, which the device does not checksum). Raises
    :class:`~.exceptions.ProtocolError` on a bad magic, checksum or length."""
    if len(packet) < ANKE_HEADER_LEN:
        raise ProtocolError("ANKE packet shorter than its header")
    magic, seq, ptype, length = _HEADER.unpack_from(packet, 0)
    if magic != ANKE_MAGIC:
        raise ProtocolError(f"ANKE magic {magic:#010x}")
    body = packet[ANKE_HEADER_LEN : ANKE_HEADER_LEN + length]
    if len(body) != length:
        raise ProtocolError("ANKE body truncated")
    if (ptype & 0xFE) != 8:
        stored = struct.unpack_from("<I", packet, 0x10)[0]
        if _checksum(packet[:16], body) != stored:
            raise ProtocolError("ANKE checksum mismatch")
    return AnkeFrame(ptype, seq, body)


SendFrame = Callable[[bytes], Awaitable[None]]


class RtcpChannel:
    """The ANKE reliable channel over a ``send_frame`` callback.

    ``send_frame`` is handed one encoded ANKE frame to put on the wire (the caller
    wraps it in an RTCP APP packet). Inbound frames arrive through :meth:`feed`.
    Delivered DATA bodies surface from :meth:`recv_data`. Call :meth:`start` to run
    the heartbeat and :meth:`close` to stop everything.
    """

    def __init__(
        self,
        send_frame: SendFrame,
        *,
        heartbeat_interval: float = HEARTBEAT_INTERVAL,
        retransmit_delays: tuple[float, ...] = RETRANSMIT_DELAYS,
    ) -> None:
        self._send = send_frame
        self._heartbeat_interval = heartbeat_interval
        self._delays = retransmit_delays
        self._next_seq = 0
        self._seen: set[int] = set()
        self._seen_order: deque[int] = deque()
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self._acks: dict[int, asyncio.Event] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._heartbeat: asyncio.Task[None] | None = None
        self._closed = False

    def start(self) -> None:
        """Start the heartbeat (a no-op when its interval is not positive)."""
        if self._heartbeat is None and self._heartbeat_interval > 0:
            self._heartbeat = asyncio.ensure_future(self._heartbeat_loop())

    async def send_data(self, body: bytes) -> int:
        """Send ``body`` as a reliable DATA packet; returns its seq. Retransmits
        until the device acks it or the backoff is exhausted."""
        seq = self._next_seq
        self._next_seq = (self._next_seq + 1) & 0xFFFFFFFF
        frame = encode_anke(AnkeType.DATA, seq, body)
        acked = asyncio.Event()
        self._acks[seq] = acked
        await self._send(frame)
        self._spawn(self._retransmit(seq, frame, acked))
        return seq

    async def recv_data(self) -> bytes:
        """The body of the next inbound DATA packet (command replies, notifications)."""
        return await self._inbound.get()

    def feed(self, packet: bytes) -> None:
        """Hand one inbound ANKE frame (the RTCP APP data) to the channel."""
        try:
            frame = decode_anke(packet)
        except ProtocolError as exc:
            _LOGGER.debug("RTC ANKE packet dropped: %s", exc)
            return
        if frame.type == AnkeType.ACK:
            event = self._acks.get(frame.seq)
            if event is not None:
                event.set()
        elif frame.type == AnkeType.DATA:
            self._emit(encode_anke(AnkeType.ACK, frame.seq, b""))
            if not self._remember(frame.seq):
                return  # a duplicate: reacked above, not redelivered
            self._inbound.put_nowait(frame.body)
        elif frame.type == AnkeType.MTU_REQUEST:
            self._emit(encode_anke(AnkeType.MTU_RESPONSE, frame.seq, frame.body))
        # HEARTBEAT (4) and MTU_RESPONSE (9) need no reply.

    async def close(self) -> None:
        self._closed = True
        tasks = list(self._tasks)
        if self._heartbeat is not None:
            tasks.append(self._heartbeat)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def _remember(self, seq: int) -> bool:
        if seq in self._seen:
            return False
        self._seen.add(seq)
        self._seen_order.append(seq)
        if len(self._seen_order) > _DEDUP_RING:
            self._seen.discard(self._seen_order.popleft())
        return True

    def _emit(self, frame: bytes) -> None:
        """Send a frame from the synchronous :meth:`feed` path (fire and forget)."""
        self._spawn(self._send(frame))

    def _spawn(self, coro: Awaitable[None]) -> None:
        if self._closed:
            return
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _retransmit(self, seq: int, frame: bytes, acked: asyncio.Event) -> None:
        try:
            for delay in self._delays:
                try:
                    await asyncio.wait_for(acked.wait(), delay)
                    return
                except TimeoutError:
                    if self._closed:
                        return
                    await self._send(frame)
            if not acked.is_set():
                _LOGGER.debug(
                    "RTC ANKE data seq=%d not acked after %d retries", seq, len(self._delays)
                )
        finally:
            self._acks.pop(seq, None)

    async def _heartbeat_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(self._heartbeat_interval)
            await self._send(encode_anke(AnkeType.HEARTBEAT, 0, b""))
