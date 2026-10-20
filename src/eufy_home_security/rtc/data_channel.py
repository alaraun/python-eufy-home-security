"""The WebRTC data channel's message framing (pure).

For stations the app reaches only over WebRTC (and for every command/arming/live-open
on a T9000/T8N00), the app opens a kind-5 ("priv1") call whose media is a KCP data
channel over libjuice. Inside KCP, each application message is framed as:

    [file_head (20 B, device->client only)] + WrtcLinkProtocol header + XZYH frame

- The **WrtcLinkProtocol** header (:func:`encode_wrtc_link` / :func:`decode_wrtc_link`)
  carries the message type (:class:`DataMsgType`), a length, a timestamp and a sequence
  counter, then the payload (an XZYH command/notification/heartbeat frame).
- The client **sends** the WrtcLinkProtocol header directly; the device **may** wrap its
  replies in an extra 20-byte **file_head** (:func:`strip_file_head`) carrying a length
  and a CRC32, which the client strips before decoding.
- On the wire each KCP datagram for a kcp_type-2 peer carries a 32-byte prefix
  (:func:`encode_kcp_prefix` / :func:`strip_kcp_prefix`) selecting the KCP stream.

Verified on a HomeBase 3 (T8030); see ``docs/protocol/rtc-signaling.md``. This module is
pure: the KCP transport and the signaling live elsewhere.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
import zlib
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Final, Protocol, runtime_checkable

from ..exceptions import ProtocolError
from . import _ikcp

_LOGGER = logging.getLogger(__name__)

#: WrtcLinkProtocol version, in the first two header bytes of every frame.
WRTC_VERSION: Final = 9
#: Header length of the current ("new") WrtcLinkProtocol frame.
WRTC_HEADER_NEW: Final = 24
#: Header length of the legacy ("old") frame (a peer that negotiates the old protocol).
WRTC_HEADER_OLD: Final = 20
#: Constant at header byte 8 (new) / 6 (old).
_WRTC_CONST: Final = 1

#: file_head magic ("XZYH" reversed), first u32 of a device reply's outer wrapper.
FILE_HEAD_MAGIC: Final = 0x585A5948
#: file_head length: magic, flags, data_len, crc32, offset, then the body.
FILE_HEAD_LEN: Final = 20

#: The KCP datagram prefix a kcp_type-2 peer prepends to every segment.
KCP_PREFIX_LEN: Final = 32
#: First-u32 value of the download KCP stream's prefix (else the command stream).
KCP_DOWNLOAD_CONV: Final = 3


class DataMsgType(IntEnum):
    """The WrtcLinkProtocol message type (header byte 16 new / 12 old)."""

    COMMAND = 1
    """A command, or a command reply/receipt (an XZYH frame, GCM for 0x546)."""
    FILE_DATA = 2
    """A chunk of a reassembled file transfer."""
    NOTIFY = 3
    """An asynchronous notification."""
    PLAYBACK = 4
    """Playback stream data."""
    HEARTBEAT = 0x63
    """A keep-alive (its payload is a bare 16-byte XZYH frame, type 0x0473)."""


@dataclass(frozen=True, slots=True)
class WrtcLinkMessage:
    """A decoded WrtcLinkProtocol message: its type, sequence and payload."""

    msg_type: int
    seq: int
    payload: bytes


def encode_wrtc_link(
    payload: bytes, *, msg_type: int, seq: int, old: bool = False, now: int | None = None
) -> bytes:
    """Frame ``payload`` with a WrtcLinkProtocol header.

    ``msg_type`` is a :class:`DataMsgType`, ``seq`` the per-channel sequence counter.
    ``old`` selects the 20-byte legacy header (a peer on the old protocol); the default
    is the 24-byte current header. ``now`` overrides the timestamp (default: wall clock).
    The two small header pairs the sender leaves zero (the device accepts that).
    """
    stamp = int(time.time()) if now is None else now
    if old:
        head = bytearray(WRTC_HEADER_OLD)
        struct.pack_into("<HHH", head, 0, WRTC_VERSION, WRTC_HEADER_OLD, len(payload) & 0xFFFF)
        head[6] = _WRTC_CONST
        struct.pack_into("<I", head, 8, stamp & 0xFFFFFFFF)
        head[12] = msg_type & 0xFF
        struct.pack_into("<I", head, 16, seq & 0xFFFFFFFF)
        return bytes(head) + payload
    head = bytearray(WRTC_HEADER_NEW)
    struct.pack_into("<HHI", head, 0, WRTC_VERSION, WRTC_HEADER_NEW, len(payload))
    head[8] = _WRTC_CONST
    struct.pack_into("<I", head, 12, stamp & 0xFFFFFFFF)
    head[16] = msg_type & 0xFF
    struct.pack_into("<I", head, 20, seq & 0xFFFFFFFF)
    return bytes(head) + payload


def decode_wrtc_link(buf: bytes) -> WrtcLinkMessage:
    """Decode a WrtcLinkProtocol frame (either header length).

    Raises :class:`~.exceptions.ProtocolError` when the version is not
    :data:`WRTC_VERSION`, the header length is not one of the two known sizes, or the
    buffer is shorter than its header plus the declared payload length.
    """
    if len(buf) < 4 or struct.unpack_from("<H", buf, 0)[0] != WRTC_VERSION:
        raise ProtocolError("not a WrtcLinkProtocol frame")
    header_len = struct.unpack_from("<H", buf, 2)[0]
    if header_len not in (WRTC_HEADER_NEW, WRTC_HEADER_OLD):
        raise ProtocolError(f"WrtcLinkProtocol header length {header_len} is unknown")
    if len(buf) < header_len:
        raise ProtocolError("WrtcLinkProtocol frame is shorter than its header")
    if header_len == WRTC_HEADER_NEW:
        payload_len = struct.unpack_from("<I", buf, 4)[0]
        msg_type, seq = buf[16], struct.unpack_from("<I", buf, 20)[0]
    else:
        payload_len = struct.unpack_from("<H", buf, 4)[0]
        msg_type, seq = buf[12], struct.unpack_from("<I", buf, 16)[0]
    if len(buf) < header_len + payload_len:
        raise ProtocolError("WrtcLinkProtocol payload is truncated")
    return WrtcLinkMessage(msg_type, seq, buf[header_len : header_len + payload_len])


def strip_file_head(buf: bytes, *, verify_crc: bool = False) -> bytes:
    """Return ``buf`` without its outer file_head, if it has one.

    The device wraps some data-channel replies in a 20-byte head: magic
    :data:`FILE_HEAD_MAGIC`, flags, a u32 body length at offset 8 and a CRC32 at offset
    12. A buffer without the magic is returned unchanged (the client's own sends carry
    no file_head). With ``verify_crc`` a CRC mismatch raises
    :class:`~.exceptions.ProtocolError`.
    """
    if len(buf) < FILE_HEAD_LEN or struct.unpack_from("<I", buf, 0)[0] != FILE_HEAD_MAGIC:
        return buf
    data_len = struct.unpack_from("<I", buf, 8)[0]
    body = buf[FILE_HEAD_LEN : FILE_HEAD_LEN + data_len]
    if len(body) < data_len:
        raise ProtocolError("file_head body is truncated")
    if verify_crc:
        want = struct.unpack_from("<I", buf, 12)[0]
        if zlib.crc32(body) & 0xFFFFFFFF != want:
            raise ProtocolError("file_head CRC32 mismatch")
    return body


def encode_kcp_prefix(segment: bytes, *, conv: int = 1) -> bytes:
    """Prepend the kcp_type-2 32-byte datagram prefix to a KCP ``segment``.

    The prefix is ``u32 conv | u32 1 | 24 zero bytes``; ``conv`` is 1 for the command
    stream and :data:`KCP_DOWNLOAD_CONV` for the download stream.
    """
    return struct.pack("<II", conv & 0xFFFFFFFF, 1) + b"\x00" * 24 + segment


def strip_kcp_prefix(datagram: bytes) -> tuple[int, bytes]:
    """Split a received kcp_type-2 datagram into ``(conv, segment)``.

    A datagram longer than the 32-byte prefix has it stripped and its first u32 returned
    as the stream selector (:data:`KCP_DOWNLOAD_CONV` = download, else command). A
    shorter datagram is returned whole with ``conv`` 0 (the peer sent a bare segment).
    """
    if len(datagram) > KCP_PREFIX_LEN:
        return struct.unpack_from("<I", datagram, 0)[0], datagram[KCP_PREFIX_LEN:]
    return 0, datagram


@runtime_checkable
class PacketTransport(Protocol):
    """A datagram pipe the KCP channel runs over (an ICE connection)."""

    async def recv(self) -> bytes: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


#: KCP parameters the app configures for the command data channel (kcp_type 2): conv 1,
#: nodelay(1, interval 2 ms, fast-resend 2, no congestion control), window 512, mtu 1200.
KCP_CONV_COMMAND: Final = 1
_KCP_INTERVAL_MS: Final = 2
_KCP_RESEND: Final = 2
_KCP_WINDOW: Final = 512
_KCP_MTU: Final = 1200
_KCP_TICK_S: Final = 0.01


class KcpDataChannel:
    """The station's KCP data channel over a :class:`PacketTransport`.

    Outbound application messages are framed with a WrtcLinkProtocol header
    (:func:`encode_wrtc_link`) and carried as reliable KCP segments, each with the
    kcp_type-2 datagram prefix. Inbound datagrams have their prefix and any file_head
    stripped and are decoded to :class:`WrtcLinkMessage`; whole messages surface from
    :meth:`recv_message`. An update task drives KCP's timers.
    """

    def __init__(
        self,
        transport: PacketTransport,
        *,
        conv: int = KCP_CONV_COMMAND,
        old_protocol: bool = False,
    ) -> None:
        self._transport = transport
        self._conv = conv
        self._old = old_protocol
        self._kcp = _ikcp.KCP(conv)
        self._kcp.set_performance_options(True, _KCP_INTERVAL_MS, _KCP_RESEND, True)
        self._kcp.set_window_size(_KCP_WINDOW, _KCP_WINDOW)
        self._kcp.set_maximum_transmission(_KCP_MTU)
        self._kcp.include_outbound_handler(self._on_segment)
        self._outbound: deque[bytes] = deque()
        self._received: asyncio.Queue[WrtcLinkMessage] = asyncio.Queue()
        self._seq = 0
        self._closed = False
        self._tasks = [
            asyncio.ensure_future(self._read_loop()),
            asyncio.ensure_future(self._tick()),
        ]

    def _on_segment(self, _kcp: _ikcp.KCP, data: bytes) -> None:
        self._outbound.append(encode_kcp_prefix(bytes(data), conv=self._conv))

    async def _drain(self) -> None:
        while self._outbound:
            await self._transport.send(self._outbound.popleft())

    async def send_message(self, payload: bytes, *, msg_type: int = DataMsgType.COMMAND) -> None:
        """Frame and send one application ``payload`` as a reliable KCP message."""
        frame = encode_wrtc_link(payload, msg_type=msg_type, seq=self._seq, old=self._old)
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        self._kcp.enqueue(frame)
        self._kcp.flush()
        await self._drain()

    async def recv_message(self) -> WrtcLinkMessage:
        """The next decoded message the device sent on the channel."""
        return await self._received.get()

    async def _read_loop(self) -> None:
        while not self._closed:
            try:
                datagram = await self._transport.recv()
            except asyncio.CancelledError:
                raise
            except Exception:  # any transport error ends the channel
                return
            _conv, segment = strip_kcp_prefix(datagram)
            self._kcp.receive(segment)
            while self._kcp.next_packet_available:
                raw = bytes(self._kcp.get_received())
                try:
                    self._received.put_nowait(decode_wrtc_link(strip_file_head(raw)))
                except ProtocolError as exc:
                    _LOGGER.debug("RTC data-channel message dropped: %s", exc)
            await self._drain()  # KCP may owe an ack

    async def _tick(self) -> None:
        while not self._closed:
            self._kcp.update()
            await self._drain()
            await asyncio.sleep(_KCP_TICK_S)

    async def close(self) -> None:
        self._closed = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._transport.close()
