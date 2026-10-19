"""eufy RTC signaling wire format (pure: no I/O, no cryptography).

Every signaling packet is a 60-byte little-endian header followed by a body::

    0x00 u16  tag (3)
    0x02 u16  CRC-16/XMODEM over bytes 0x04..0x3c and the body
    0x04 u16  message type (:class:`MessageType`)
    0x06 u16  body length
    0x08 u32  packet id: the sender's time in seconds; also the body key's salt
    0x0c u8   protocol version (7)
    0x0d u8   sender kind (:class:`Endpoint`; the app sends ANDROID)
    0x0e u8   1 for a response
    0x0f u8   mode flag (LOGIN: the work protocol; CALL: 2 with a token)
    0x10 u16  response code (:class:`ResponseCode`)
    0x12 u8   1 when the body's attachment is encrypted
    0x13 u8   flags (bit 0: the server asks for a new DISCOVER)
    0x14 16B  station serial, ASCII
    0x28 u8   extension length (0x14)
    0x29 u8   body type (:class:`BodyType`)
    0x2a u8   packet counter 1..255 per client
    0x2b u8   route id: one random byte per client
    0x2c u8   login or call sub-id
    0x39 2B   SDK version bytes (0, 3)
    0x3b u8   2 when the packet travels obfuscated (UDP)

Over UDP a packet is wrapped in an obfuscation prefix (:func:`obfuscate`): a
22-byte header carrying a random 16-byte XOR key, the XORed packet, then random
padding. TCP carries the plain packet. See ``docs/protocol/rtc-signaling.md``.
"""

from __future__ import annotations

import binascii
import json
import os
import random
import struct
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any, Final

from ..exceptions import ProtocolError

TAG: Final = 3
VERSION: Final = 7
HEADER_LEN: Final = 60
EXTENSION_LEN: Final = 0x14
SDK_VERSION: Final = b"\x00\x03"
MAX_BODY_LEN: Final = 0x1000
#: Largest UDP datagram the receiver reads.
MAX_DATAGRAM: Final = 0x400

UDP_PORT: Final = 5062
TCP_PORTS: Final = (5061, 15061)

OBFUSCATION_MAGIC: Final = 8
OBFUSCATION_HEADER_LEN: Final = 22
OBFUSCATED_FLAG: Final = 2
_PAD_LIMIT: Final = 0x3D3

SERIAL_LEN: Final = 16
UUID_LEN: Final = 36
CONTACT_LEN: Final = 32
CALL_BODY_LEN: Final = 0x4C
MESSAGE_BODY_LEN: Final = 0x2E
KEY_BLOB_LEN: Final = 0x80
WORK_PROTOCOL: Final = 2
"""The mode the app works in: LOGIN carries it in the mode flag."""


class MessageType(IntEnum):
    """Header message type."""

    LOGIN = 1
    CALL = 2
    ACK = 3
    INFO = 4
    HANGUP = 5
    UPDATE = 6
    WAKEUP = 7
    REPORT = 8
    DISCOVER = 9
    PING = 10
    MESSAGE = 11
    LOGOUT = 12
    CONTROL = 13


class Endpoint(IntEnum):
    """Header sender kind."""

    DEVICE = 0
    WEB = 1
    ALEXA = 2
    GVA = 3
    SERVER = 4
    IOS = 5
    ANDROID = 6
    APP = 7
    CONTACT = 8


class BodyType(IntEnum):
    """Header body type: how the body is laid out."""

    NONE = 0
    JSON = 2
    DEFAULT_KEY_BLOB = 3
    """A blob encrypted with the protocol's default secret (the LOGIN challenge)."""
    KEY_EXCHANGE = 4
    """``blob[0x80] | u16 len | blob``: the login key exchange (:class:`KeyExchangeBody`)."""
    CONTACT = 6
    """``contact_id[32] | u16 len | data``: re-login and quick login (:class:`ContactBody`)."""
    CALL = 7
    """Call body (:class:`CallBody`): CALL, ACK, INFO, HANGUP, UPDATE, REPORT."""
    MESSAGE = 8
    """Message body (:class:`MessageBody`): MESSAGE, the ping."""


class ResponseCode(IntEnum):
    """Header response code."""

    NONE = 0
    TRYING = 100
    OK = 200
    UNAUTHORIZED = 401
    """LOGIN challenge: the body carries the server's public key."""
    UNAVAILABLE = 480
    BUSY = 486


class CallKind(IntEnum):
    """The kind of a CALL: which channel of the session it opens."""

    PLAIN = 0
    COMMAND = 1
    CHANNEL_P2P = 3
    """Media when the work protocol is not 2."""
    FILE = 4
    PRIV1 = 5
    PRIV_MEDIA = 6
    """Live media: the app's kind for the media channel (work protocol 2)."""


#: Per call kind: the attachment's ``call_type`` and ``eufy_p2p_type`` values.
CALL_TYPES: Final[Mapping[CallKind, tuple[str, str | None]]] = {
    CallKind.PLAIN: ("call", None),
    CallKind.COMMAND: ("cmd", None),
    CallKind.CHANNEL_P2P: ("call", "channel_p2p"),
    CallKind.FILE: ("call", "file_p2p"),
    CallKind.PRIV1: ("scall", "priv1"),
    CallKind.PRIV_MEDIA: ("scall", "priv_p2p"),
}

#: Call kinds whose attachment carries a token and an ``sdp_info``, and whose
#: traffic after the CALL uses a socket of its own.
PRIVATE_CALL_KINDS: Final = frozenset({CallKind.PRIV1, CallKind.PRIV_MEDIA})

PING_COMMAND_TYPE: Final = 2
PING_SUB_TYPE: Final = 0x66
#: Message command types whose JSON carries a base64 ``content``.
CONTENT_COMMAND_TYPES: Final = frozenset({2, 0x65})

FLAG_REDISCOVER: Final = 0x01


def crc16(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0, no reflection)."""
    return binascii.crc_hqx(data, 0)


@dataclass(frozen=True, slots=True, kw_only=True)
class Header:
    """The 60-byte header of one signaling packet."""

    message_type: int
    packet_id: int
    serial: str
    is_response: bool = False
    mode: int = 0
    code: int = 0
    encrypted: bool = False
    flags: int = 0
    body_type: int = BodyType.NONE
    counter: int = 0
    route: int = 0
    sub_id: int = 0
    sender: int = Endpoint.ANDROID
    version: int = VERSION
    transport_flag: int = 0

    @property
    def request_id(self) -> int:
        """The id that pairs a response with its request: packet id, counter, route."""
        return ((self.packet_id & 0xFFFFFFFF) << 16) | (self.counter << 8) | self.route

    def response(self, code: int, *, body_type: int | None = None) -> Header:
        """A response header for this request: same ids, ``code``, flagged response."""
        return replace(
            self,
            is_response=True,
            code=code,
            body_type=self.body_type if body_type is None else body_type,
            transport_flag=0,
        )


def encode_packet(header: Header, body: bytes = b"", *, obfuscated: bool = True) -> bytes:
    """The plain packet (header + body), with its CRC; ``obfuscated`` sets the
    transport flag the UDP wrapper requires. Wrap the result with :func:`obfuscate`
    for UDP."""
    if len(body) > MAX_BODY_LEN:
        raise ValueError(f"body of {len(body)} bytes exceeds {MAX_BODY_LEN}")
    serial = header.serial.encode("ascii")[:SERIAL_LEN]
    h = bytearray(HEADER_LEN)
    struct.pack_into(
        "<HHHHI", h, 0, TAG, 0, header.message_type, len(body), header.packet_id & 0xFFFFFFFF
    )
    h[0x0C] = header.version
    h[0x0D] = header.sender
    h[0x0E] = 1 if header.is_response else 0
    h[0x0F] = header.mode
    struct.pack_into("<H", h, 0x10, header.code)
    h[0x12] = 1 if header.encrypted else 0
    h[0x13] = header.flags
    h[0x14 : 0x14 + len(serial)] = serial
    h[0x28] = EXTENSION_LEN
    h[0x29] = header.body_type
    h[0x2A] = header.counter
    h[0x2B] = header.route
    h[0x2C] = header.sub_id
    h[0x39:0x3B] = SDK_VERSION
    h[0x3B] = OBFUSCATED_FLAG if obfuscated else header.transport_flag
    struct.pack_into("<H", h, 2, crc16(bytes(h[4:]) + body))
    return bytes(h) + body


def decode_packet(data: bytes, *, check_crc: bool = True) -> tuple[Header, bytes]:
    """Header and body of a plain packet (undo :func:`obfuscate` first).

    Raises :class:`~.exceptions.ProtocolError` for a short packet, a wrong tag, a
    body length beyond the data, or (with ``check_crc``) a CRC mismatch.
    """
    if len(data) < HEADER_LEN:
        raise ProtocolError(f"signaling packet of {len(data)} bytes is shorter than its header")
    tag, crc, mtype, blen, packet_id = struct.unpack_from("<HHHHI", data, 0)
    if tag != TAG:
        raise ProtocolError(f"signaling packet tag {tag}, expected {TAG}")
    header_len = 0x28 + data[0x28]
    if header_len < 0x29 or header_len + blen > len(data):
        raise ProtocolError(f"signaling packet declares {header_len}+{blen} bytes, has {len(data)}")
    body = data[header_len : header_len + blen]
    if check_crc and crc16(data[4:header_len] + body) != crc:
        raise ProtocolError("signaling packet CRC mismatch")
    serial = data[0x14:0x24].split(b"\0", 1)[0].decode("ascii", "replace")
    header = Header(
        message_type=mtype,
        packet_id=packet_id,
        serial=serial,
        is_response=data[0x0E] == 1,
        mode=data[0x0F],
        code=struct.unpack_from("<H", data, 0x10)[0],
        encrypted=data[0x12] == 1,
        flags=data[0x13],
        body_type=data[0x29],
        counter=data[0x2A],
        route=data[0x2B],
        sub_id=data[0x2C],
        sender=data[0x0D],
        version=data[0x0C],
        transport_flag=data[0x3B],
    )
    return header, body


def obfuscate(packet: bytes, *, rng: random.Random | None = None) -> bytes:
    """Wrap a plain packet for UDP: ``u16 8 | u16 len+pad | key[16] | u8 pad |
    u8 random | packet XOR key | pad random bytes``."""
    rand = rng or random.SystemRandom()
    key = bytes(rand.getrandbits(8) for _ in range(16)) if rng else os.urandom(16)
    limit = _PAD_LIMIT - len(packet) if len(packet) + OBFUSCATION_HEADER_LEN < 1000 else 1
    pad = (rand.randrange(limit) if limit > 1 else 0) & 0xFF
    body = bytes(b ^ key[i & 15] for i, b in enumerate(packet))
    tail = bytes(rand.getrandbits(8) for _ in range(pad))
    return (
        struct.pack("<HH", OBFUSCATION_MAGIC, len(packet) + pad)
        + key
        + bytes([pad, rand.getrandbits(8)])
        + body
        + tail
    )


def is_obfuscated(datagram: bytes) -> bool:
    """Whether a datagram carries the obfuscation prefix."""
    return (
        len(datagram) > OBFUSCATION_HEADER_LEN
        and struct.unpack_from("<H", datagram, 0)[0] == OBFUSCATION_MAGIC
    )


def deobfuscate(datagram: bytes) -> bytes:
    """The plain packet inside a datagram; a datagram without the prefix is returned
    as is (the receiver accepts both). Raises :class:`~.exceptions.ProtocolError` when
    the prefix declares more bytes than the datagram holds."""
    if not is_obfuscated(datagram):
        return datagram
    total = struct.unpack_from("<H", datagram, 2)[0]
    length = total - datagram[20]
    if length < 0 or OBFUSCATION_HEADER_LEN + total > len(datagram):
        raise ProtocolError("obfuscated signaling datagram is shorter than it declares")
    key = datagram[4:20]
    start = OBFUSCATION_HEADER_LEN
    return bytes(datagram[start + i] ^ key[i & 15] for i in range(length))


def _fixed(text: bytes, size: int) -> bytes:
    return text[:size].ljust(size, b"\0")


def _cstr(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", "replace")


@dataclass(frozen=True, slots=True)
class KeyExchangeBody:
    """Body type 4: ``blob1[0x80] | u16 len | blob2`` (the login key exchange:
    the session key sealed with the server's public key, then the sealed identity)."""

    sealed_key: bytes
    sealed_identity: bytes

    def encode(self) -> bytes:
        if len(self.sealed_key) > KEY_BLOB_LEN:
            raise ValueError("sealed key exceeds 128 bytes")
        return (
            _fixed(self.sealed_key, KEY_BLOB_LEN)
            + struct.pack("<H", len(self.sealed_identity))
            + self.sealed_identity
        )

    @classmethod
    def decode(cls, body: bytes) -> KeyExchangeBody:
        if len(body) < KEY_BLOB_LEN + 2:
            raise ProtocolError("key exchange body is too short")
        n = struct.unpack_from("<H", body, KEY_BLOB_LEN)[0]
        return cls(body[:KEY_BLOB_LEN], body[KEY_BLOB_LEN + 2 : KEY_BLOB_LEN + 2 + n])


@dataclass(frozen=True, slots=True)
class ContactBody:
    """Body type 6: ``contact_id[32] | u16 len | data``. A LOGIN 200 carries the
    contact id in it; re-login and quick login send it with the sealed identity."""

    contact_id: str
    data: bytes = b""

    def encode(self) -> bytes:
        return (
            _fixed(self.contact_id.encode("ascii"), CONTACT_LEN)
            + struct.pack("<H", len(self.data))
            + self.data
        )

    @classmethod
    def decode(cls, body: bytes) -> ContactBody:
        contact = _cstr(body[:CONTACT_LEN])
        if len(body) < CONTACT_LEN + 2:
            return cls(contact)
        n = struct.unpack_from("<H", body, CONTACT_LEN)[0]
        return cls(contact, body[CONTACT_LEN + 2 : CONTACT_LEN + 2 + n])


@dataclass(frozen=True, slots=True)
class CallBody:
    """Body type 7: ``u32 channel | u16 attach_len | uuid[36] | contact_id[32] |
    u8 no_attach | u8 0 | attach``. The attachment is a JSON text, encrypted when
    the header's encrypted flag is set."""

    channel: int
    uuid: str
    contact_id: str
    attachment: bytes = b""

    def encode(self) -> bytes:
        return (
            struct.pack("<IH", self.channel, len(self.attachment))
            + _fixed(self.uuid.encode("ascii"), UUID_LEN)
            + _fixed(self.contact_id.encode("ascii"), CONTACT_LEN)
            + bytes([0 if self.attachment else 1, 0])
            + self.attachment
        )

    def without_attachment(self) -> CallBody:
        """The same call, attachment dropped: the ACK's body."""
        return CallBody(self.channel, self.uuid, self.contact_id)

    @classmethod
    def decode(cls, body: bytes) -> CallBody:
        if len(body) < CALL_BODY_LEN:
            raise ProtocolError(f"call body of {len(body)} bytes, expected >= {CALL_BODY_LEN}")
        channel, n = struct.unpack_from("<IH", body, 0)
        return cls(
            channel,
            _cstr(body[6 : 6 + UUID_LEN]),
            _cstr(body[0x2A : 0x2A + CONTACT_LEN]),
            body[CALL_BODY_LEN : CALL_BODY_LEN + n],
        )


@dataclass(frozen=True, slots=True)
class MessageBody:
    """Body type 8: ``u32 channel | u16 data_len | u16 cmd_type | u16 sub_type |
    contact_id[32] | 4 zero | data``; ``data`` is encrypted like a call attachment."""

    channel: int
    command_type: int
    sub_type: int
    contact_id: str
    data: bytes = b""

    def encode(self) -> bytes:
        return (
            struct.pack("<IHHH", self.channel, len(self.data), self.command_type, self.sub_type)
            + _fixed(self.contact_id.encode("ascii"), CONTACT_LEN)
            + b"\0\0\0\0"
            + self.data
        )

    @property
    def is_ping(self) -> bool:
        return self.command_type == PING_COMMAND_TYPE and self.sub_type == PING_SUB_TYPE

    @classmethod
    def decode(cls, body: bytes) -> MessageBody:
        if len(body) < MESSAGE_BODY_LEN:
            raise ProtocolError(
                f"message body of {len(body)} bytes, expected >= {MESSAGE_BODY_LEN}"
            )
        channel, n, cmd, sub = struct.unpack_from("<IHHH", body, 0)
        return cls(
            channel,
            cmd,
            sub,
            _cstr(body[0x0A : 0x0A + CONTACT_LEN]),
            body[MESSAGE_BODY_LEN : MESSAGE_BODY_LEN + n],
        )


def json_text(data: bytes) -> dict[str, Any]:
    """A JSON object from a NUL-terminated text body (DISCOVER answer, decrypted
    attachments). Raises :class:`~.exceptions.ProtocolError` when it is not one."""
    text = data.split(b"\0", 1)[0].decode("utf-8", "replace")
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ProtocolError(f"signaling JSON does not parse: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError("signaling JSON is not an object")
    return value


def json_bytes(value: Mapping[str, Any]) -> bytes:
    """Compact JSON text of an attachment, as the app sends it."""
    return json.dumps(value, separators=(", ", ": ")).encode()


@dataclass(frozen=True, slots=True)
class DiscoverAnswer:
    """The DISCOVER 200 answer: which server to log in to, and the backups."""

    server_addr: str | None
    """An IPv4 address, ``"self"`` (stay) or None."""
    backups: tuple[str, ...]
    timestamp: int | None

    @classmethod
    def decode(cls, body: bytes) -> DiscoverAnswer:
        data = json_text(body)
        addrs = data.get("saddrs")
        stamp = data.get("timestamp")
        return cls(
            data.get("server_addr") if isinstance(data.get("server_addr"), str) else None,
            tuple(a for a in addrs if isinstance(a, str))[:16] if isinstance(addrs, list) else (),
            stamp if isinstance(stamp, int) else None,
        )

    def login_address(self, current: str) -> str:
        """The address to log in to: ``current`` for ``"self"``, a missing or equal
        answer, else the named server."""
        if self.server_addr in (None, "", "self", current):
            return current
        return self.server_addr
