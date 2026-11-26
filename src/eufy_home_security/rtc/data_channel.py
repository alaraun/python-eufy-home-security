"""The RTC data channel: its message framing and the KCP channel that carries it.

The data channel is the media of a kind-5 (``priv1``) call: KCP over its own ICE
connection, on which the device is the ICE-controlling side. Inside KCP every
application message is::

    [outer head (20 B, device -> client only)] + link header + XZYH frame

- The **link header** (:func:`encode_link_frame` / :func:`decode_link_frame`) carries the
  message type (:class:`DataMsgType`), the payload length, a timestamp and a sequence
  counter; 24 bytes, or 20 for a peer on the older layout.
- The device may wrap a message in a 20-byte **outer head** with a length and a CRC32
  (:func:`strip_outer_head`); the client sends none.
- For a kcp_type-2 peer (:func:`~.config.data_channel_kcp_type`) every KCP datagram
  carries a 32-byte prefix selecting the KCP stream (:func:`encode_kcp_prefix` /
  :func:`strip_kcp_prefix`); a kcp_type-1 peer sends bare segments.

The eufy app can also run this channel over QUIC, chosen per call from the device's
answer; only KCP is implemented. Verified on a HomeBase 3 (KCP, both prefixes' framing,
the link header both ways, the outer head, heartbeats); see
``docs/protocol/rtc-signaling.md`` § Data channel.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
import zlib
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Final, Protocol, runtime_checkable

from ..exceptions import CommunicationError, ProtocolError
from . import _ikcp

_LOGGER = logging.getLogger(__name__)

#: Link-header version, in the first two bytes of every message.
LINK_VERSION: Final = 9
#: Length of the current link header.
LINK_HEADER_LEN: Final = 24
#: Length of the older link header (a peer on the older layout).
LINK_HEADER_LEN_OLD: Final = 20
#: Constant at link-header byte 8 (current) / 6 (older).
_LINK_CONST: Final = 1

#: Outer-head magic: the first u32 of a wrapped device message.
OUTER_HEAD_MAGIC: Final = 0x585A5948
#: Outer-head length: magic, flags, body length, CRC32, offset, then the body.
OUTER_HEAD_LEN: Final = 20

#: The KCP datagram prefix of a kcp_type-2 peer.
KCP_PREFIX_LEN: Final = 32
#: The first u32 of the command stream's prefix (the KCP conv).
KCP_CONV_COMMAND: Final = 1
#: The first u32 of the download stream's prefix.
KCP_DOWNLOAD_CONV: Final = 3


class DataMsgType(IntEnum):
    """The link header's message type."""

    COMMAND = 1
    """A command, a command reply or receipt (an XZYH frame)."""
    FILE_DATA = 2
    """A chunk of a file transfer."""
    NOTIFY = 3
    """An asynchronous notification."""
    PLAYBACK = 4
    """Playback stream data."""
    HEARTBEAT = 0x63
    """A keep-alive: a bare 16-byte XZYH frame of type 0x0473."""


@dataclass(frozen=True, slots=True)
class LinkMessage:
    """A decoded data-channel message: its type, sequence and payload."""

    msg_type: int
    seq: int
    payload: bytes


def encode_link_frame(
    payload: bytes, *, msg_type: int, seq: int, old: bool = False, now: int | None = None
) -> bytes:
    """``payload`` behind a link header.

    ``msg_type`` is a :class:`DataMsgType`, ``seq`` the channel's sequence counter.
    ``old`` selects the 20-byte older header; the default is the 24-byte one. ``now``
    sets the timestamp (default: the wall clock, in seconds). The bytes the client does
    not use stay zero; the device accepts that.
    """
    stamp = int(time.time()) if now is None else now
    if old:
        head = bytearray(LINK_HEADER_LEN_OLD)
        struct.pack_into("<HHH", head, 0, LINK_VERSION, LINK_HEADER_LEN_OLD, len(payload) & 0xFFFF)
        head[6] = _LINK_CONST
        struct.pack_into("<I", head, 8, stamp & 0xFFFFFFFF)
        head[12] = msg_type & 0xFF
        struct.pack_into("<I", head, 16, seq & 0xFFFFFFFF)
        return bytes(head) + payload
    head = bytearray(LINK_HEADER_LEN)
    struct.pack_into("<HHI", head, 0, LINK_VERSION, LINK_HEADER_LEN, len(payload))
    head[8] = _LINK_CONST
    struct.pack_into("<I", head, 12, stamp & 0xFFFFFFFF)
    head[16] = msg_type & 0xFF
    struct.pack_into("<I", head, 20, seq & 0xFFFFFFFF)
    return bytes(head) + payload


def decode_link_frame(buf: bytes) -> LinkMessage:
    """Decode a message behind either link header.

    Raises :class:`~.exceptions.ProtocolError` when the version is not
    :data:`LINK_VERSION`, the header length is neither known size, or the buffer is
    shorter than the header plus the declared payload.
    """
    if len(buf) < 4 or struct.unpack_from("<H", buf, 0)[0] != LINK_VERSION:
        raise ProtocolError("not an RTC data-channel message")
    header_len = struct.unpack_from("<H", buf, 2)[0]
    if header_len not in (LINK_HEADER_LEN, LINK_HEADER_LEN_OLD):
        raise ProtocolError(f"RTC data-channel header length {header_len} is unknown")
    if len(buf) < header_len:
        raise ProtocolError("RTC data-channel message is shorter than its header")
    if header_len == LINK_HEADER_LEN:
        payload_len = struct.unpack_from("<I", buf, 4)[0]
        msg_type, seq = buf[16], struct.unpack_from("<I", buf, 20)[0]
    else:
        payload_len = struct.unpack_from("<H", buf, 4)[0]
        msg_type, seq = buf[12], struct.unpack_from("<I", buf, 16)[0]
    if len(buf) < header_len + payload_len:
        raise ProtocolError("RTC data-channel payload is truncated")
    return LinkMessage(msg_type, seq, buf[header_len : header_len + payload_len])


def strip_outer_head(buf: bytes, *, verify_crc: bool = False) -> bytes:
    """``buf`` without its outer head, when it has one.

    The outer head is 20 bytes: :data:`OUTER_HEAD_MAGIC`, flags, a u32 body length at
    offset 8 and the body's CRC32 at offset 12. A buffer without the magic is returned
    unchanged. Raises :class:`~.exceptions.ProtocolError` for a body shorter than its
    length, and with ``verify_crc`` for a CRC mismatch.
    """
    if len(buf) < OUTER_HEAD_LEN or struct.unpack_from("<I", buf, 0)[0] != OUTER_HEAD_MAGIC:
        return buf
    data_len = struct.unpack_from("<I", buf, 8)[0]
    body = buf[OUTER_HEAD_LEN : OUTER_HEAD_LEN + data_len]
    if len(body) < data_len:
        raise ProtocolError("RTC data-channel outer head body is truncated")
    if verify_crc and zlib.crc32(body) != struct.unpack_from("<I", buf, 12)[0]:
        raise ProtocolError("RTC data-channel outer head CRC32 mismatch")
    return body


def encode_kcp_prefix(segment: bytes, *, conv: int = KCP_CONV_COMMAND) -> bytes:
    """A KCP ``segment`` behind the kcp_type-2 prefix ``u32 conv | u32 1 | 24 zero
    bytes``; ``conv`` is :data:`KCP_CONV_COMMAND` or :data:`KCP_DOWNLOAD_CONV`."""
    return struct.pack("<II", conv & 0xFFFFFFFF, 1) + bytes(KCP_PREFIX_LEN - 8) + segment


def strip_kcp_prefix(datagram: bytes) -> tuple[int, bytes]:
    """A received kcp_type-2 datagram as ``(conv, segment)``.

    A datagram longer than the prefix loses it, and its first u32 is the stream
    selector; a shorter one is a bare segment, returned whole with ``conv`` 0.
    """
    if len(datagram) > KCP_PREFIX_LEN:
        return struct.unpack_from("<I", datagram, 0)[0], datagram[KCP_PREFIX_LEN:]
    return 0, datagram


@runtime_checkable
class PacketTransport(Protocol):
    """The datagram pipe the KCP channel runs over (an ICE connection)."""

    async def recv(self) -> bytes: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


#: KCP settings of the command data channel: nodelay, a 2 ms interval (ikcp raises it
#: to its 10 ms floor), fast resend after 2 skips, no congestion window, windows of 512
#: segments, MTU 1200.
_KCP_INTERVAL_MS: Final = 2
_KCP_RESEND: Final = 2
_KCP_WINDOW: Final = 512
_KCP_MTU: Final = 1200
#: How often the channel drives KCP's timers, in seconds.
KCP_TICK: Final = 0.01


class KcpDataChannel:
    """The data channel over a :class:`PacketTransport`.

    An outbound message gets a link header and travels as reliable KCP segments, each
    behind the kcp_type-2 prefix unless ``prefixed`` is False (kcp_type 1: bare segments
    both ways). Inbound datagrams lose their prefix and any outer head and come out of
    :meth:`recv_message` as :class:`LinkMessage`. A task drives KCP's timers. Construct
    it inside a running event loop.

    When the transport fails, the channel stops: :meth:`recv_message` and
    :meth:`send_message` raise :class:`~.exceptions.CommunicationError`, as they do
    after :meth:`close`.
    """

    def __init__(
        self,
        transport: PacketTransport,
        *,
        conv: int = KCP_CONV_COMMAND,
        old_protocol: bool = False,
        prefixed: bool = True,
    ) -> None:
        self._transport = transport
        self._conv = conv
        self._old = old_protocol
        self._prefixed = prefixed
        self._kcp = _ikcp.KCP(conv)
        self._kcp.set_performance_options(True, _KCP_INTERVAL_MS, _KCP_RESEND, True)
        self._kcp.set_window_size(_KCP_WINDOW, _KCP_WINDOW)
        self._kcp.set_maximum_transmission(_KCP_MTU)
        self._kcp.include_outbound_handler(self._on_segment)
        self._outbound: deque[bytes] = deque()
        self._received: asyncio.Queue[LinkMessage | None] = asyncio.Queue()
        self._seq = 0
        self._failure: BaseException | None = None
        self._closed = False
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._read_loop()), loop.create_task(self._tick())]

    def _on_segment(self, _kcp: _ikcp.KCP, data: bytes) -> None:
        segment = bytes(data)
        self._outbound.append(
            encode_kcp_prefix(segment, conv=self._conv) if self._prefixed else segment
        )

    async def _drain(self) -> None:
        while self._outbound:
            await self._transport.send(self._outbound.popleft())

    def _check_open(self) -> None:
        if self._closed or self._failure is not None:
            raise CommunicationError("RTC data channel is closed") from self._failure

    async def send_message(self, payload: bytes, *, msg_type: int = DataMsgType.COMMAND) -> None:
        """Send one ``payload`` as a reliable message. Raises
        :class:`~.exceptions.CommunicationError` on a closed or failed channel."""
        self._check_open()
        frame = encode_link_frame(payload, msg_type=msg_type, seq=self._seq, old=self._old)
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        self._kcp.enqueue(frame)
        self._kcp.flush()
        try:
            await self._drain()
        except Exception as exc:
            self._fail(exc)
            raise CommunicationError("RTC data channel send failed") from exc

    async def recv_message(self) -> LinkMessage:
        """The next message the device sent. Raises
        :class:`~.exceptions.CommunicationError` once the channel is closed or failed and
        no message is left."""
        message = await self._received.get()
        if message is None:
            self._received.put_nowait(None)  # wake every later reader too
            raise CommunicationError("RTC data channel is closed") from self._failure
        return message

    def _fail(self, exc: BaseException) -> None:
        if self._failure is None and not self._closed:
            _LOGGER.debug("RTC data channel failed: %s", exc)
            self._failure = exc
            self._received.put_nowait(None)

    def _feed(self, datagram: bytes) -> None:
        segment = strip_kcp_prefix(datagram)[1] if self._prefixed else datagram
        if (code := self._kcp.receive(segment)) < 0:
            _LOGGER.debug("RTC data-channel datagram not taken by KCP (%d)", code)
        while self._kcp.next_packet_available:
            raw = bytes(self._kcp.get_received())
            try:
                self._received.put_nowait(decode_link_frame(strip_outer_head(raw)))
            except ProtocolError as exc:
                _LOGGER.debug("RTC data-channel message dropped: %s", exc)

    async def _read_loop(self) -> None:
        try:
            while True:
                self._feed(await self._transport.recv())
                await self._drain()  # KCP may owe an ack
        except Exception as exc:  # the transport's own errors end the channel
            self._fail(exc)

    async def _tick(self) -> None:
        try:
            while True:
                self._kcp.update()
                await self._drain()
                await asyncio.sleep(KCP_TICK)
        except Exception as exc:
            self._fail(exc)

    async def close(self) -> None:
        """Stop the channel's tasks and close the transport."""
        if self._closed:
            return
        self._closed = True
        self._received.put_nowait(None)
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._transport.close()
