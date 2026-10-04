"""PPPP (CS2 Network / "PPCS") datagram layer.

Every datagram on the wire is::

    0xF1  <type:u8>  <length:u16 big-endian>  <payload>

A handful of message types carry the whole conversation with a eufy station:
discovery, the NAT punch, the DRW data channel and its ACKs, and the ALIVE
keepalive. The byte layouts here are the ones validated against a live
HomeBase 3 (T8030). Note that DRW is 0xD0/0xD1 and the ALIVE keepalive pair is
0xE0/0xE1; confusing the two sends a keepalive where a data chunk was meant.

DRW datagrams carry a second, inner header (the "sub-header", marker byte
0xD1) that names the logical channel and a 16-bit chunk index, so a large
application stream can be fragmented across many datagrams and reassembled in
order (see :mod:`.xzyh`).
"""

from __future__ import annotations

import ipaddress
import logging
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from .._logging import LogThrottle
from ..exceptions import ProtocolError

_LOGGER = logging.getLogger(__name__)
_THROTTLE = LogThrottle()

PPPP_MAGIC = 0xF1

#: The UDP port a station answers LAN discovery (LAN_SEARCH) on, and the address
#: a LAN_SEARCH is sent to when no station host is known.
DISCOVERY_PORT = 32108
BROADCAST = "255.255.255.255"
#: How long a LAN discovery listens by default. A HomeBase 3 answers at once; a T8170
#: standalone camera answered 2.1 s after the first search, and a 3 s search missed it.
LAN_DISCOVERY_TIMEOUT = 5.0

#: Marker byte that opens the DRW / DRW_ACK sub-header inside a datagram body.
_DRW_SUBHEADER_MARKER = 0xD1
#: A DRW_ACK body is ``D1 ch count_u16`` + 2 bytes per index and must fit one
#: PPPP payload (u16 length).
MAX_ACK_INDICES = (0xFFFF - 4) // 2


class MsgType(IntEnum):
    """PPPP message type (the byte after the magic)."""

    HELLO = 0x00
    HELLO_ACK = 0x01
    P2P_REQ = 0x20
    P2P_REQ_ACK = 0x21
    LOOKUP = 0x26
    LAN_SEARCH = 0x30
    PUNCH_TO = 0x40
    PUNCH_PKT = 0x41
    P2P_RDY = 0x42
    PUNCH_SUCCESS = 0x43
    DRW = 0xD0
    DRW_ACK = 0xD1
    ALIVE = 0xE0
    ALIVE_ACK = 0xE1
    CLOSE = 0xF0
    RLY_HELLO = 0xF9


def encode_packet(msg_type: int, payload: bytes = b"") -> bytes:
    """Frame one PPPP datagram: ``F1 <type> <len:u16be> <payload>``."""
    if not 0 <= msg_type <= 0xFF:
        raise ProtocolError(f"PPPP message type out of range: {msg_type}")
    if len(payload) > 0xFFFF:
        raise ProtocolError(f"PPPP payload too long: {len(payload)} bytes")
    return struct.pack(">BBH", PPPP_MAGIC, msg_type, len(payload)) + payload


#: The length a device session key (DSK) occupies in a LOOKUP, zero-padded.
DSK_FIELD_LEN = 24
#: The 4 constant bytes a LOOKUP carries between the sockaddr and the DSK, as the app's
#: wake request carries them (meaning unknown; the same in every request seen).
_LOOKUP_TAIL = bytes([0x02, 0x05, 0x01, 0x05])


def encode_sockaddr(ip: str, port: int) -> bytes:
    """A 16-byte PPPP ``sockaddr_in``: family ``0x0002`` (big-endian), the port
    (little-endian), the IPv4 address in reversed byte order, then 8 zero bytes.

    This is the caller's own LAN endpoint, told to the rendezvous servers so the
    station knows where to punch (see :func:`encode_lookup`).
    """
    packed = ipaddress.IPv4Address(ip).packed
    return struct.pack(">H", 2) + struct.pack("<H", port) + packed[::-1] + bytes(8)


def encode_lookup(did_struct: bytes, ip: str, port: int, dsk: str) -> bytes:
    """A ``LOOKUP`` (0x26) payload that wakes a battery station: the 20-byte DID
    struct, the caller's :func:`encode_sockaddr`, four constant bytes, and the DSK
    padded to :data:`DSK_FIELD_LEN`. Sent to the station's rendezvous servers
    (:func:`decode_init_string`) on UDP 32100 until the station punches back."""
    key = dsk.encode("ascii")
    if len(key) > DSK_FIELD_LEN:
        raise ProtocolError(f"DSK too long for a LOOKUP: {len(key)} bytes")
    return did_struct + encode_sockaddr(ip, port) + _LOOKUP_TAIL + key.ljust(DSK_FIELD_LEN, b"\x00")


#: The substitution table of the app's ``PPPP_DecodeString``.
_INIT_STRING_TABLE = bytes(
    [
        0x49, 0x59, 0x43, 0x3D, 0xB5, 0xBF, 0x6D, 0xA3, 0x47, 0x53, 0x4F, 0x61, 0x65, 0xE3,
        0x71, 0xE9, 0x67, 0x7F, 0x02, 0x03, 0x0B, 0xAD, 0xB3, 0x89, 0x2B, 0x2F, 0x35, 0xC1,
        0x6B, 0x8B, 0x95, 0x97, 0x11, 0xE5, 0xA7, 0x0D, 0xEF, 0xF1, 0x05, 0x07, 0x83, 0xFB,
        0x9D, 0x3B, 0xC5, 0xC7, 0x13, 0x17, 0x1D, 0x1F, 0x25, 0x29, 0xD3, 0xDF,
    ]
)  # fmt: skip


def decode_init_string(encoded: str) -> list[str]:
    """Decode a cloud ``app_conn`` / ``p2p_conn`` string into its list of rendezvous
    hosts (IP addresses or names).

    The cloud device list hides a station's PPPP servers behind this obfuscation.
    Each server list ends at the first ``:`` and its hosts are comma-separated. The
    transform mirrors the app's ``PPPP_DecodeString``: for each pair of characters,
    ``x = ((hi << 4) + lo - 0x451) & 0xFF`` (``hi``/``lo`` the raw byte values), then
    ``out[i] = x ^ table[i % 54] ^ (0x39 ^ running_xor_of_prior_output)``. Returns the
    non-empty hosts, in order.
    """
    body = encoded.split(":", 1)[0]
    out = bytearray()
    running = 0
    for i in range(len(body) // 2):
        x = ((ord(body[2 * i]) << 4) + ord(body[2 * i + 1]) - 0x451) & 0xFF
        out.append(x ^ _INIT_STRING_TABLE[i % len(_INIT_STRING_TABLE)] ^ (0x39 ^ running))
        running ^= out[-1]
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError as err:
        raise ProtocolError("init string did not decode to ASCII") from err
    return [host for host in text.split(",") if host]


def decode_packet(data: bytes) -> tuple[int, bytes]:
    """Parse one PPPP datagram into ``(msg_type, payload)``.

    The declared length is trusted only up to what is present: some keepalives
    carry a zero length field yet a fixed trailer, so the payload is whatever
    follows the 4-byte header, bounded by the declared length when it fits. A
    declared length larger than the datagram is accepted the same way (the body is
    what arrived) and logged at debug level, throttled.
    """
    if len(data) < 4 or data[0] != PPPP_MAGIC:
        raise ProtocolError("not a PPPP datagram (missing 0xF1 magic, or too short)")
    msg_type = data[1]
    declared = struct.unpack_from(">H", data, 2)[0]
    body = data[4:]
    if declared > len(body) and _THROTTLE.should_log(("overlong", msg_type)):
        _LOGGER.debug(
            "PPPP type 0x%02x declares %d payload bytes, datagram holds %d",
            msg_type,
            declared,
            len(body),
        )
    payload = body[:declared] if 0 < declared <= len(body) else body
    return msg_type, payload


@dataclass(frozen=True, slots=True)
class DrwChunk:
    """One fragment of an application stream carried in a DRW datagram."""

    channel: int
    index: int
    data: bytes


def _drw_subheader(channel: int, index: int) -> bytes:
    return bytes([_DRW_SUBHEADER_MARKER, channel & 0xFF]) + struct.pack(">H", index & 0xFFFF)


def encode_drw(channel: int, index: int, data: bytes) -> bytes:
    """Build a full DRW datagram: ``F1 D0 <len> | D1 ch idx_u16be | data``."""
    return encode_packet(MsgType.DRW, _drw_subheader(channel, index) + data)


def decode_drw(payload: bytes) -> DrwChunk:
    """Parse the *payload* of a DRW datagram into a :class:`DrwChunk`.

    ``payload`` is what :func:`decode_packet` returns for a DRW datagram: the
    inner ``D1 ch idx data`` sub-header, not the whole ``F1 D0 …`` datagram.
    """
    if len(payload) < 4:
        raise ProtocolError("DRW payload too short for its sub-header")
    if payload[0] != _DRW_SUBHEADER_MARKER:
        raise ProtocolError(f"DRW sub-header marker is 0x{payload[0]:02x}, expected 0xD1")
    channel = payload[1]
    index = struct.unpack_from(">H", payload, 2)[0]
    return DrwChunk(channel=channel, index=index, data=payload[4:])


def encode_drw_ack(channel: int, indices: Sequence[int]) -> bytes:
    """Build a full DRW_ACK datagram.

    ``F1 D1 <len> | D1 ch count_u16be idx_u16be…`` — the station stops sending a
    channel the moment its chunks go unacked, so every received chunk is acked.
    More than :data:`MAX_ACK_INDICES` indices do not fit one datagram and raise
    :class:`ProtocolError`, like any other oversize PPPP payload.
    """
    if len(indices) > MAX_ACK_INDICES:
        raise ProtocolError(
            f"DRW_ACK of {len(indices)} indices exceeds one datagram ({MAX_ACK_INDICES})"
        )
    body = bytearray([_DRW_SUBHEADER_MARKER, channel & 0xFF])
    body += struct.pack(">H", len(indices))
    for idx in indices:
        body += struct.pack(">H", idx & 0xFFFF)
    return encode_packet(MsgType.DRW_ACK, bytes(body))


def decode_drw_ack(payload: bytes) -> tuple[int, list[int]]:
    """Parse the payload of a DRW_ACK datagram into ``(channel, [indices])``."""
    if len(payload) < 4:
        raise ProtocolError("DRW_ACK payload too short for its sub-header")
    if payload[0] != _DRW_SUBHEADER_MARKER:
        raise ProtocolError(f"DRW_ACK sub-header marker is 0x{payload[0]:02x}, expected 0xD1")
    channel = payload[1]
    count = struct.unpack_from(">H", payload, 2)[0]
    indices: list[int] = []
    off = 4
    for _ in range(count):
        if off + 2 > len(payload):
            raise ProtocolError("DRW_ACK truncated: fewer indices than its count claims")
        indices.append(struct.unpack_from(">H", payload, off)[0])
        off += 2
    return channel, indices
