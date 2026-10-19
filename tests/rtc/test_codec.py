"""``rtc/codec.py``: header, CRC, obfuscation and body layouts."""

from __future__ import annotations

import random

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc import codec
from eufy_home_security.rtc.codec import (
    BodyType,
    CallBody,
    ContactBody,
    DiscoverAnswer,
    Header,
    KeyExchangeBody,
    MessageBody,
    MessageType,
)
from eufy_home_security.testing import SYNTHETIC

SN = SYNTHETIC.station_sn

# Packets in the layout the app sends (header + body before the UDP wrapper).
GOLDEN = [
    (
        Header(
            message_type=MessageType.DISCOVER,
            packet_id=1789000000,
            serial=SN,
            counter=1,
            route=0x5A,
        ),
        b"",
        "030043990900000040f9a16a070600000000000054383033305032303030303132333435"
        "000000001400015a00000000000000000000000000000302",
    ),
    (
        Header(
            message_type=MessageType.LOGIN,
            packet_id=1789000001,
            serial=SN,
            counter=2,
            route=0x5A,
            mode=codec.WORK_PROTOCOL,
        ),
        b"",
        "03006c740100000041f9a16a070600020000000054383033305032303030303132333435"
        "000000001400025a00000000000000000000000000000302",
    ),
    (
        Header(
            message_type=MessageType.CALL,
            packet_id=1789000002,
            serial=SN,
            counter=3,
            route=0x5A,
            encrypted=True,
            sub_id=1,
            body_type=BodyType.CALL,
        ),
        b"\x01\x02\x03",
        "03002c000200030042f9a16a070600000000010054383033305032303030303132333435"
        "000000001407035a01000000000000000000000000000302010203",
    ),
]


@pytest.mark.parametrize(("header", "body", "packet"), GOLDEN)
def test_a_packet_is_laid_out_as_the_app_sends_it(header: Header, body: bytes, packet: str) -> None:
    assert codec.encode_packet(header, body).hex() == packet


@pytest.mark.parametrize(("header", "body", "packet"), GOLDEN)
def test_a_packet_decodes_to_its_header_and_body(header: Header, body: bytes, packet: str) -> None:
    decoded, data = codec.decode_packet(bytes.fromhex(packet))
    assert data == body
    assert decoded.message_type == header.message_type
    assert (decoded.packet_id, decoded.counter, decoded.route) == (
        header.packet_id,
        header.counter,
        header.route,
    )
    assert (decoded.serial, decoded.encrypted, decoded.sub_id) == (
        SN,
        header.encrypted,
        header.sub_id,
    )
    assert decoded.transport_flag == codec.OBFUSCATED_FLAG


def test_a_corrupted_packet_fails_its_crc() -> None:
    packet = bytearray(bytes.fromhex(GOLDEN[0][2]))
    packet[0x20] ^= 1
    with pytest.raises(ProtocolError, match="CRC"):
        codec.decode_packet(bytes(packet))
    codec.decode_packet(bytes(packet), check_crc=False)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\x03\x00" * 10, "shorter"),
        (b"\x04" + bytes(59), "tag"),
        (bytes.fromhex(GOLDEN[2][2])[:-1], "declares"),
    ],
)
def test_a_malformed_packet_is_refused(data: bytes, message: str) -> None:
    with pytest.raises(ProtocolError, match=message):
        codec.decode_packet(data)


def test_obfuscation_round_trips_with_padding() -> None:
    packet = bytes.fromhex(GOLDEN[2][2])
    wrapped = codec.obfuscate(packet, rng=random.Random(7))
    assert wrapped[:2] == b"\x08\x00"
    pad = wrapped[20]
    assert len(wrapped) == codec.OBFUSCATION_HEADER_LEN + len(packet) + pad
    assert wrapped[22 : 22 + len(packet)] != packet
    assert codec.deobfuscate(wrapped) == packet


def test_a_plain_datagram_is_accepted_as_is() -> None:
    packet = bytes.fromhex(GOLDEN[0][2])
    assert codec.deobfuscate(packet) == packet


def test_a_truncated_wrapper_is_refused() -> None:
    wrapped = codec.obfuscate(bytes.fromhex(GOLDEN[0][2]), rng=random.Random(1))
    with pytest.raises(ProtocolError):
        codec.deobfuscate(wrapped[: codec.OBFUSCATION_HEADER_LEN + 4])


def test_a_long_packet_gets_no_padding() -> None:
    packet = codec.encode_packet(GOLDEN[0][0], bytes(990))
    assert codec.obfuscate(packet, rng=random.Random(3))[20] == 0


def test_a_response_header_keeps_the_request_ids() -> None:
    request = GOLDEN[1][0]
    response = request.response(401)
    assert response.request_id == request.request_id
    assert (response.is_response, response.code) == (True, 401)


def test_the_request_id_combines_packet_id_counter_and_route() -> None:
    header = GOLDEN[0][0]
    assert header.request_id == (1789000000 << 16) | (1 << 8) | 0x5A


def test_call_body_layout() -> None:
    body = CallBody(2, "FF006" + "a" * 31, "c" * 32, b"attach")
    data = body.encode()
    assert len(data) == codec.CALL_BODY_LEN + 6
    assert data[:6] == b"\x02\x00\x00\x00\x06\x00"
    assert data[0x4A] == 0
    assert CallBody.decode(data) == body
    bare = body.without_attachment().encode()
    assert (len(bare), bare[0x4A]) == (codec.CALL_BODY_LEN, 1)


def test_message_body_layout_and_ping() -> None:
    body = MessageBody(0, codec.PING_COMMAND_TYPE, codec.PING_SUB_TYPE, "c" * 32, b"data")
    data = body.encode()
    assert len(data) == codec.MESSAGE_BODY_LEN + 4
    assert data[0x2A:0x2E] == b"\0\0\0\0"
    decoded = MessageBody.decode(data)
    assert decoded == body
    assert decoded.is_ping


def test_key_exchange_and_contact_bodies() -> None:
    exchange = KeyExchangeBody(b"k" * 128, b"identity")
    data = exchange.encode()
    assert data[0x80:0x82] == b"\x08\x00"
    assert KeyExchangeBody.decode(data) == exchange
    contact = ContactBody("c" * 32, b"x")
    assert ContactBody.decode(contact.encode()) == contact
    assert ContactBody.decode(b"c" * 32 + b"\0").contact_id == "c" * 32


@pytest.mark.parametrize("cls", [CallBody, MessageBody, KeyExchangeBody])
def test_a_short_body_is_refused(cls: type[CallBody | MessageBody | KeyExchangeBody]) -> None:
    with pytest.raises(ProtocolError):
        cls.decode(b"\0" * 10)


def test_discover_answer_names_the_login_server() -> None:
    answer = DiscoverAnswer.decode(
        b'{"server_addr": "198.51.100.7", "saddrs": ["198.51.100.8"], "timestamp": 5}\0'
    )
    assert answer.login_address("203.0.113.1") == "198.51.100.7"
    assert answer.backups == ("198.51.100.8",)
    assert (
        DiscoverAnswer.decode(b'{"server_addr": "self"}').login_address("203.0.113.1")
        == "203.0.113.1"
    )


def test_json_text_refuses_non_objects() -> None:
    with pytest.raises(ProtocolError):
        codec.json_text(b"[1]")
    with pytest.raises(ProtocolError):
        codec.json_text(b"{bad")
