"""The reliable command channel carried inside RTCP APP packets on an RTC call.

Commands travel in RTCP APP packets with name ``AZWC`` and subtype 0, sent with the
client's audio SSRC, raw over ICE (not SRTCP: the call keys SRTP through SDES and
runs no DTLS), so inbound packets are taken out before any SRTCP unprotect. Inside
each packet is one frame of a small reliable protocol. This module is the frame codec
and the channel; wrapping a frame in an RTCP APP packet (:class:`~.media.RtcpApp`) and
moving it over ICE is the caller's job.

Frame, little-endian, 20-byte header + body::

    0x00  u32 magic = 0x12345678
    0x04  u32 seq
    0x08  u8  type            (1 DATA, 2 ACK, 4 HEARTBEAT, 8 MTU request, 9 MTU response)
    0x09  3   unused
    0x0c  u32 body length
    0x10  u32 checksum        (byte sum of bytes 0-15 and the body; not checked for 8/9)
    0x14  body

A DATA frame is acknowledged with an ACK of its seq and delivered once; an
unacknowledged DATA is sent again after 100, 200 and 500 ms, five times at most; an
MTU request is answered with an MTU response; a heartbeat (seq 0) goes out every
second. Bodies are plaintext here: the command itself is sealed by :mod:`.command`.

Declared (eufy app); a HomeBase 3 acknowledges the client's DATA and sends its replies
as DATA (verified). See ``docs/protocol/rtc-signaling.md`` § Command channel.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from collections import deque
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Final

from .._logging import LogThrottle
from ..exceptions import CommunicationError, ProtocolError

_LOGGER = logging.getLogger(__name__)

#: Magic at the head of every frame.
FRAME_MAGIC: Final = 0x12345678
#: Length of the frame header before the body.
FRAME_HEADER_LEN: Final = 20
#: RTCP APP name and subtype of the command channel.
APP_NAME: Final = b"AZWC"
APP_SUBTYPE: Final = 0

#: Resend delays (seconds) of an unacknowledged DATA frame, one per resend.
RETRANSMIT_DELAYS: Final = (0.1, 0.2, 0.5, 0.5, 0.5)
#: How often a heartbeat goes out, in seconds.
HEARTBEAT_INTERVAL: Final = 1.0
#: How many recently seen inbound seqs are kept for deduplication.
DEDUP_WINDOW: Final = 1000

_HEADER = struct.Struct("<IIBxxxI")  # magic, seq, type, 3 unused, body length
#: The MTU frame types share every bit but the lowest (8 and 9).
_MTU_MASK: Final = 0xFE


class FrameType(IntEnum):
    """The frame's type byte."""

    DATA = 1
    ACK = 2
    HEARTBEAT = 4
    MTU_REQUEST = 8
    MTU_RESPONSE = 9


@dataclass(frozen=True, slots=True)
class Frame:
    """A decoded command-channel frame."""

    type: int
    seq: int
    body: bytes


def _checksum(header16: bytes, body: bytes) -> int:
    return (sum(header16[:16]) + sum(body)) & 0xFFFFFFFF


def encode_frame(frame_type: int, seq: int, body: bytes = b"") -> bytes:
    """One frame: the 20-byte header (checksum computed) and ``body``."""
    header16 = _HEADER.pack(FRAME_MAGIC, seq & 0xFFFFFFFF, frame_type & 0xFF, len(body))
    return header16 + struct.pack("<I", _checksum(header16, body)) + body


def decode_frame(packet: bytes) -> Frame:
    """Parse a frame: the magic, the length, and the checksum for every type but the
    MTU probes. Raises :class:`~.exceptions.ProtocolError` on a bad magic, checksum or
    length."""
    if len(packet) < FRAME_HEADER_LEN:
        raise ProtocolError("RTC command-channel frame is shorter than its header")
    magic, seq, frame_type, length = _HEADER.unpack_from(packet, 0)
    if magic != FRAME_MAGIC:
        raise ProtocolError(f"RTC command-channel frame magic {magic:#010x}")
    body = packet[FRAME_HEADER_LEN : FRAME_HEADER_LEN + length]
    if len(body) != length:
        raise ProtocolError("RTC command-channel frame body is truncated")
    if frame_type & _MTU_MASK != FrameType.MTU_REQUEST:
        stored = struct.unpack_from("<I", packet, 0x10)[0]
        if _checksum(packet[:16], body) != stored:
            raise ProtocolError("RTC command-channel frame checksum mismatch")
    return Frame(frame_type, seq, body)


SendFrame = Callable[[bytes], Awaitable[None]]


class RtcpChannel:
    """The reliable command channel over a ``send_frame`` callback.

    ``send_frame`` puts one encoded frame on the wire (the caller wraps it in an RTCP APP
    packet). Inbound frames arrive through :meth:`feed`; delivered DATA bodies come out
    of :meth:`recv_data`. :meth:`start` runs the heartbeat, :meth:`close` stops every
    task. Construct and use it inside a running event loop.
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
        self._heartbeat_warning = LogThrottle()
        self._closed = False

    def start(self) -> None:
        """Start the heartbeat unless it runs (none when its interval is not positive, or
        after :meth:`close`); a heartbeat that ended is started again."""
        if self._heartbeat_interval <= 0 or self._closed:
            return
        if self._heartbeat is None or self._heartbeat.done():
            self._heartbeat = self._spawn(self._heartbeat_loop())

    async def send_data(self, body: bytes) -> int:
        """Send ``body`` as a DATA frame and return its seq; it is sent again until the
        device acknowledges it or the resend delays run out. An error of the first send
        propagates; after :meth:`close` it raises
        :class:`~.exceptions.CommunicationError` and sends nothing."""
        if self._closed:
            raise CommunicationError("RTC command channel is closed")
        seq = self._next_seq
        self._next_seq = (self._next_seq + 1) & 0xFFFFFFFF
        frame = encode_frame(FrameType.DATA, seq, body)
        acked = asyncio.Event()
        self._acks[seq] = acked
        try:
            await self._send(frame)
        except BaseException:
            self._acks.pop(seq, None)
            raise
        self._spawn(self._retransmit(seq, frame, acked))
        return seq

    async def recv_data(self) -> bytes:
        """The body of the next inbound DATA frame (command replies, notifications)."""
        return await self._inbound.get()

    def feed(self, packet: bytes) -> None:
        """Hand one inbound frame (an RTCP APP packet's data) to the channel."""
        try:
            frame = decode_frame(packet)
        except ProtocolError as exc:
            _LOGGER.debug("RTC command-channel frame dropped: %s", exc)
            return
        if frame.type == FrameType.ACK:
            event = self._acks.get(frame.seq)
            if event is not None:
                event.set()
        elif frame.type == FrameType.DATA:
            self._spawn(self._send_one(encode_frame(FrameType.ACK, frame.seq)))
            if self._remember(frame.seq):
                self._inbound.put_nowait(frame.body)
        elif frame.type == FrameType.MTU_REQUEST:
            self._spawn(self._send_one(encode_frame(FrameType.MTU_RESPONSE, frame.seq, frame.body)))
        # A heartbeat and an MTU response need no answer.

    async def close(self) -> None:
        """Stop the heartbeat, the resends and any pending sends."""
        self._closed = True
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def _remember(self, seq: int) -> bool:
        """Whether ``seq`` is new; it is then kept among the last :data:`DEDUP_WINDOW`."""
        if seq in self._seen:
            return False
        self._seen.add(seq)
        self._seen_order.append(seq)
        if len(self._seen_order) > DEDUP_WINDOW:
            self._seen.discard(self._seen_order.popleft())
        return True

    async def _send_one(self, frame: bytes) -> None:
        await self._send(frame)

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None] | None:
        if self._closed:
            coro.close()
            return None
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and (exc := task.exception()) is not None:
            _LOGGER.debug("RTC command-channel send failed: %s", exc)

    async def _retransmit(self, seq: int, frame: bytes, acked: asyncio.Event) -> None:
        try:
            for delay in self._delays:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(delay):
                        await acked.wait()
                    return
                await self._send(frame)
            _LOGGER.debug(
                "RTC command-channel DATA seq %d not acknowledged after %d resends",
                seq,
                len(self._delays),
            )
        finally:
            self._acks.pop(seq, None)

    async def _heartbeat_loop(self) -> None:
        """One heartbeat per interval; a failed send is logged (WARNING once per five
        minutes, DEBUG in between) and the next tick tries again."""
        while True:
            await asyncio.sleep(self._heartbeat_interval)
            try:
                await self._send(encode_frame(FrameType.HEARTBEAT, 0))
            except Exception as exc:  # the caller's send: any failure, next tick retries
                level = (
                    logging.WARNING if self._heartbeat_warning.should_log("send") else logging.DEBUG
                )
                _LOGGER.log(level, "RTC command-channel heartbeat not sent: %s", exc)
