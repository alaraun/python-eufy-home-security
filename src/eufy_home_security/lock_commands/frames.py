"""The frame layers of lock commands: a TLV body, the cm2 frame and the Anker cm frame.

Both frames start ``FF 09``, carry a little-endian total length and end in an XOR of every
byte before it. They differ after that (declared, eufy app; docs/protocol/locks.md):

- **cm2** (1940 route): ``FF 09 | len u16 LE | version | slave id | function type |
  u16 BE (multi << 15 | encrypted << 14 | command) | body | xor``;
- **Anker cm** (1930 route): ``FF 09 | len u16 LE | version | device type | command |
  package flag | index | key length | key | data | xor`` when sent, and without the
  index and key fields when answered.

Only single-packet frames are built or read: a lock command and its answer fit one.
Builders raise :class:`ValueError` on an argument outside its domain; parsers raise
:class:`~eufy_home_security.exceptions.ProtocolError` and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from ..exceptions import ProtocolError

START: Final = b"\xff\x09"
TLV_FIRST_TAG: Final = 0xA1

_CM2_HEAD: Final = 9  # start, length, version, slave id, function type, command word
_CM2_MULTI: Final = 0x8000
_CM2_ENCRYPTED: Final = 0x4000
_CM2_COMMAND_MASK: Final = 0x07FF

ANKER_DEVICE_TYPE: Final = 0xFF
ANKER_SINGLE: Final = 0xC0
"""Package flag of a frame sent in one packet."""
ANKER_INDEX: Final = 0xA0
_ANKER_ANSWER_HEAD: Final = 8  # start, length, version, device type, command, flag


def xor8(data: bytes) -> int:
    """XOR of every byte: the check byte both frames end in."""
    out = 0
    for byte in data:
        out ^= byte
    return out


def tlv(values: Iterable[bytes], *, first_tag: int = TLV_FIRST_TAG) -> bytes:
    """Values as ``[tag, length u8, value]`` entries, tags counting up from ``first_tag``."""
    out = bytearray()
    for tag, value in enumerate(values, start=first_tag):
        if len(value) > 0xFF:
            raise ValueError(f"TLV value of {len(value)} bytes exceeds 255")
        out += bytes([tag & 0xFF, len(value)]) + value
    return bytes(out)


def _length(total: int) -> bytes:
    if total > 0xFFFF:
        raise ValueError(f"lock frame of {total} bytes exceeds 65535")
    return total.to_bytes(2, "little")


def cm2_frame(
    body: bytes,
    *,
    command: int,
    function_type: int,
    version: int,
    encrypted: bool,
    slave_id: int = 0,
) -> bytes:
    """One single-packet cm2 frame around ``body``."""
    if not 0 <= command <= _CM2_COMMAND_MASK:
        raise ValueError(f"cm2 command {command} does not fit 11 bits")
    word = command | (_CM2_ENCRYPTED if encrypted else 0)
    head = START + _length(_CM2_HEAD + len(body) + 1)
    head += bytes([version & 0xFF, slave_id & 0xFF, function_type & 0xFF])
    frame = head + word.to_bytes(2, "big") + body
    return frame + bytes([xor8(frame)])


@dataclass(frozen=True, slots=True, kw_only=True)
class Cm2Frame:
    """A parsed cm2 frame; ``body`` is still encrypted when ``encrypted`` is set."""

    version: int
    slave_id: int
    function_type: int
    command: int
    encrypted: bool
    body: bytes


def _check(data: bytes, minimum: int, what: str) -> None:
    if len(data) < minimum:
        raise ProtocolError(f"{what} frame too short: {len(data)} bytes")
    if data[:2] != START:
        raise ProtocolError(f"{what} frame has a wrong start code {data[:2].hex()}")
    if xor8(data[:-1]) != data[-1]:
        raise ProtocolError(f"{what} frame check byte does not match")


def parse_cm2_frame(data: bytes) -> Cm2Frame:
    """Read one cm2 frame. A multi-packet frame is refused."""
    _check(data, _CM2_HEAD + 1, "cm2")
    if int.from_bytes(data[2:4], "little") != len(data):
        raise ProtocolError(f"cm2 frame length field does not match its {len(data)} bytes")
    word = int.from_bytes(data[7:9], "big")
    if word & _CM2_MULTI:
        raise ProtocolError("cm2 multi-packet frames are not supported")
    return Cm2Frame(
        version=data[4],
        slave_id=data[5],
        function_type=data[6],
        command=word & _CM2_COMMAND_MASK,
        encrypted=bool(word & _CM2_ENCRYPTED),
        body=data[_CM2_HEAD:-1],
    )


def anker_frame(data: bytes, *, command: int, version: int, key_field: bytes) -> bytes:
    """One single-packet Anker cm frame carrying ``key_field`` and ``data``."""
    if len(key_field) > 0xFF:
        raise ValueError(f"Anker key field of {len(key_field)} bytes exceeds 255")
    total = 11 + len(key_field) + len(data)
    frame = START + _length(total)
    frame += bytes([version & 0xFF, ANKER_DEVICE_TYPE, command & 0xFF, ANKER_SINGLE])
    frame += bytes([ANKER_INDEX, len(key_field)]) + key_field + data
    return frame + bytes([xor8(frame)])


@dataclass(frozen=True, slots=True, kw_only=True)
class AnkerFrame:
    """A parsed single-packet Anker cm answer."""

    version: int
    device_type: int
    command: int
    body: bytes


def parse_anker_frame(data: bytes) -> AnkerFrame:
    """Read one Anker cm answer. Its length field is not read, as the app does not."""
    _check(data, _ANKER_ANSWER_HEAD + 1, "Anker")
    if data[7] != ANKER_SINGLE:
        raise ProtocolError(f"Anker multi-packet frames are not supported (flag {data[7]:#x})")
    return AnkerFrame(
        version=data[4], device_type=data[5], command=data[6], body=data[_ANKER_ANSWER_HEAD:-1]
    )
