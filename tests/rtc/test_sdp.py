"""``rtc/sdp.py``: the ``pbsdp`` reader, over protobuf bytes built here."""

from __future__ import annotations

import base64

import pytest

from eufy_home_security.rtc.sdp import (
    MAX_PBSDP_FIELDS,
    MAX_PBSDP_TEXT,
    PbsdpReading,
    read_pbsdp,
)


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        out.append(low | (0x80 if value else 0))
        if not value:
            return bytes(out)


def tag(number: int, wire: int) -> bytes:
    return varint(number << 3 | wire)


def uint(number: int, value: int) -> bytes:
    return tag(number, 0) + varint(value)


def nested(number: int, data: bytes) -> bytes:
    return tag(number, 2) + varint(len(data)) + data


def text(data: bytes) -> str:
    return base64.b64encode(data).decode()


SDP_PART = uint(1, 5) + nested(6, b"abcde") + uint(15, 20) + uint(16, 3)
UNIT = uint(1, 1) + nested(2, uint(1, 7)) + nested(3, SDP_PART) + nested(10, b"x" * 4)


def test_transport_caps_is_field_3_sub_field_16() -> None:
    assert read_pbsdp(text(UNIT)) == PbsdpReading(
        transport_caps=3, decoded=True, fields=(1, 2, 3, 10), sdp_fields=(1, 6, 15, 16)
    )


def test_a_multi_byte_varint_and_fixed_width_fields_are_read() -> None:
    unit = tag(4, 5) + b"\x01\x02\x03\x04" + tag(5, 1) + bytes(8) + nested(3, uint(16, 300))
    reading = read_pbsdp(text(unit))
    assert reading is not None
    assert (reading.transport_caps, reading.decoded, reading.fields) == (300, True, (3, 4, 5))


@pytest.mark.parametrize(
    "unit",
    [
        uint(1, 1),  # no field 3
        uint(1, 1) + nested(3, uint(15, 20)),  # field 3 without 16
    ],
)
def test_without_the_field_the_caps_are_0(unit: bytes) -> None:
    reading = read_pbsdp(text(unit))
    assert reading is not None
    assert (reading.transport_caps, reading.decoded) == (0, True)


@pytest.mark.parametrize(
    "value",
    [
        text(tag(3, 2) + varint(10) + b"short"),  # length past the end
        text(tag(1, 2) + varint(10) + uint(1, 1)),  # the same, a valid message if cut
        text(b"\x80"),  # a varint that never ends
        text(tag(1, 0) + b"\xff" * 10 + b"\x01"),  # a varint over 10 bytes
        text(tag(1, 3)),  # a group (wire type 3)
        text(tag(1, 7)),  # no such wire type
        text(tag(3, 0) + varint(5)),  # field 3 not a message
        text(nested(3, tag(16, 2) + varint(1) + b"x")),  # field 16 not a varint
        text(tag(1, 5) + b"\x01"),  # a cut fixed32
        text(varint(0) + varint(1)),  # field number 0
        "not base64!",
        text(UNIT)[:4] + "!" + text(UNIT)[4:],  # a character outside base64
        text(nested(1, b"x" * (MAX_PBSDP_TEXT * 3 // 4))),  # valid, but too long
        text(uint(1, 1) * (MAX_PBSDP_FIELDS + 1)),
    ],
)
def test_a_malformed_pbsdp_reads_as_caps_0_not_decoded(value: str) -> None:
    reading = read_pbsdp(value)
    assert reading is not None
    assert (reading.transport_caps, reading.decoded) == (0, False)


def test_the_field_cap_is_inclusive() -> None:
    reading = read_pbsdp(text(uint(1, 1) * (MAX_PBSDP_FIELDS - 1) + nested(3, uint(16, 1))))
    assert reading is not None
    assert reading.decoded is True
    assert reading.transport_caps == 1


@pytest.mark.parametrize("value", [None, "", 3, ["x"]])
def test_an_absent_or_empty_pbsdp_is_none(value: object) -> None:
    assert read_pbsdp(value) is None


def test_a_repeated_field_3_reads_the_last_caps_and_lists_the_last_fields() -> None:
    unit = nested(3, uint(16, 1) + uint(6, 0)) + nested(3, uint(15, 2)) + nested(3, uint(16, 2))
    reading = read_pbsdp(text(unit))
    assert reading is not None
    assert (reading.transport_caps, reading.fields, reading.sdp_fields) == (2, (3,), (16,))
