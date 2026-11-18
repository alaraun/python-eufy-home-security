"""PPPP datagram layer."""

from __future__ import annotations

import contextlib
import logging

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p import pppp
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.pppp import (
    MsgType,
    decode_drw,
    decode_drw_ack,
    decode_packet,
    encode_drw,
    encode_drw_ack,
    encode_packet,
)


def test_lan_search_framing() -> None:
    assert encode_packet(MsgType.LAN_SEARCH) == b"\xf1\x30\x00\x00"
    assert decode_packet(b"\xf1\x30\x00\x00") == (MsgType.LAN_SEARCH, b"")


def test_decode_rejects_non_pppp() -> None:
    with pytest.raises(ProtocolError):
        decode_packet(b"\x00\x00\x00\x00")
    with pytest.raises(ProtocolError):
        decode_packet(b"\xf1")


def test_encode_rejects_out_of_range() -> None:
    with pytest.raises(ProtocolError):
        encode_packet(0x100)
    with pytest.raises(ProtocolError):
        encode_packet(MsgType.DRW, b"\x00" * 0x10000)


def test_drw_chunk_framing() -> None:
    dg = encode_drw(channel=2, index=42, data=b"HelloChannel")
    assert dg[:2] == bytes([pppp.PPPP_MAGIC, MsgType.DRW])
    _, payload = decode_packet(dg)
    chunk = decode_drw(payload)
    assert (chunk.channel, chunk.index, chunk.data) == (2, 42, b"HelloChannel")


def test_drw_ack_framing() -> None:
    dg = encode_drw_ack(channel=2, indices=[40, 41, 42])
    assert dg[1] == MsgType.DRW_ACK
    _, payload = decode_packet(dg)
    assert payload[0] == 0xD1
    assert payload[1] == 2
    assert decode_drw_ack(payload) == (2, [40, 41, 42])


def test_decode_drw_rejects_bad_subheader() -> None:
    with pytest.raises(ProtocolError):
        decode_drw(b"\x00\x00")
    with pytest.raises(ProtocolError):
        decode_drw(b"\x00\x02\x00\x01data")  # marker not 0xD1


def test_encode_drw_ack_rejects_more_indices_than_one_datagram_holds() -> None:
    dg = encode_drw_ack(1, [0] * pppp.MAX_ACK_INDICES)  # the largest that fits
    assert decode_drw_ack(decode_packet(dg)[1]) == (1, [0] * pppp.MAX_ACK_INDICES)
    for count in (pppp.MAX_ACK_INDICES + 1, 0x10000):
        with pytest.raises(ProtocolError):
            encode_drw_ack(1, [0] * count)


def test_a_declared_length_past_the_datagram_is_accepted_and_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=pppp.__name__)
    dg = b"\xf1\xd0\x01\x00" + b"\xd1\x00\x00\x01abc"  # declares 256, holds 7
    for _ in range(3):
        assert decode_packet(dg) == (MsgType.DRW, dg[4:])
    assert len([r for r in caplog.records if "declares" in r.message]) <= 1


def test_decode_drw_ack_rejects_truncated_index_list() -> None:
    # count claims 3 indices, only one present
    with pytest.raises(ProtocolError):
        decode_drw_ack(b"\xd1\x02\x00\x03\x00\x28")


@given(mt=st.integers(0, 0xFF), payload=st.binary(max_size=300))
@settings(max_examples=100)
def test_packet_round_trip(mt: int, payload: bytes) -> None:
    assert decode_packet(encode_packet(mt, payload)) == (mt, payload)


@given(
    channel=st.integers(0, 0xFF),
    index=st.integers(0, 0xFFFF),
    data=st.binary(max_size=300),
)
@settings(max_examples=100)
def test_drw_round_trip(channel: int, index: int, data: bytes) -> None:
    _, payload = decode_packet(encode_drw(channel, index, data))
    chunk = decode_drw(payload)
    assert (chunk.channel, chunk.index, chunk.data) == (channel, index, data)


@given(
    channel=st.integers(0, 0xFF),
    indices=st.lists(st.integers(0, 0xFFFF), max_size=40),
)
@settings(max_examples=100)
def test_drw_ack_round_trip(channel: int, indices: list[int]) -> None:
    _, payload = decode_packet(encode_drw_ack(channel, indices))
    assert decode_drw_ack(payload) == (channel, indices)


@given(data=st.binary(max_size=64))
@settings(max_examples=200)
def test_decoders_only_raise_protocol_error(data: bytes) -> None:
    for fn in (decode_packet, decode_drw, decode_drw_ack, pppp.decode_sockaddr):
        with contextlib.suppress(ProtocolError):
            fn(data)


def test_encode_sockaddr_matches_the_app_layout() -> None:
    # family 0x0002 big-endian, port little-endian, IPv4 reversed, 8 zero bytes.
    assert pppp.encode_sockaddr("203.0.113.5", 15238).hex() == "0002863b057100cb0000000000000000"


def test_encode_p2p_req_dsk_layout_and_dsk_padding() -> None:

    did = Did.parse("EUPRAMA-123456-ABCDE")
    body = pppp.encode_p2p_req_dsk(did.to_struct(), "203.0.113.5", 15238, "XaDbKBfe4sMgsUFo91nw")
    assert len(body) == 20 + 16 + 4 + pppp.DSK_FIELD_LEN
    assert body[:20] == did.to_struct()
    assert body[20:36] == pppp.encode_sockaddr("203.0.113.5", 15238)
    assert body[36:40] == bytes([0x02, 0x05, 0x01, 0x05])
    assert body[40:].rstrip(b"\x00") == b"XaDbKBfe4sMgsUFo91nw"


def test_encode_p2p_req_dsk_rejects_an_oversize_dsk() -> None:

    did = Did.parse("EUPRAMA-123456-ABCDE")
    with pytest.raises(ProtocolError):
        pppp.encode_p2p_req_dsk(did.to_struct(), "203.0.113.5", 1, "x" * (pppp.DSK_FIELD_LEN + 1))


def test_encode_p2p_req_is_the_did_and_the_sockaddr() -> None:
    did = Did.parse("EUPRAMA-123456-ABCDE")
    body = pppp.encode_p2p_req(did.to_struct(), "203.0.113.5", 15238)
    assert body == did.to_struct() + pppp.encode_sockaddr("203.0.113.5", 15238)


def test_decode_sockaddr_reads_what_encode_sockaddr_writes() -> None:
    raw = pppp.encode_sockaddr("203.0.113.5", 15238)
    assert pppp.decode_sockaddr(raw) == ("203.0.113.5", 15238)
    # A PUNCH_TO body may carry bytes after the 16-byte sockaddr.
    assert pppp.decode_sockaddr(raw + b"\x01\x02") == ("203.0.113.5", 15238)


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (pppp.encode_sockaddr("203.0.113.5", 1)[:15], "short"),
        (b"\x00\x0a" + pppp.encode_sockaddr("203.0.113.5", 1)[2:], "not IPv4"),
        (b"", "empty"),
    ],
)
def test_decode_sockaddr_rejects_what_is_not_an_ipv4_sockaddr(data: bytes, why: str) -> None:
    with pytest.raises(ProtocolError):
        pppp.decode_sockaddr(data)


def test_decode_sockaddr_accepts_exactly_sixteen_bytes() -> None:
    raw = pppp.encode_sockaddr("0.0.0.0", 32108)  # noqa: S104 - a PUNCH_TO's empty address
    assert len(raw) == 16
    assert pppp.decode_sockaddr(raw) == ("0.0.0.0", 32108)  # noqa: S104


@pytest.mark.parametrize(
    ("ip", "lan"),
    [
        # RFC 1918, edges included
        ("10.0.0.1", True),
        ("10.255.255.254", True),
        ("172.16.0.1", True),
        ("172.31.255.254", True),
        ("172.32.0.1", False),
        ("192.168.0.1", True),
        # shared address space (RFC 6598), edges included
        ("100.64.0.0", True),
        ("100.127.255.255", True),
        ("100.63.255.255", False),
        ("100.128.0.0", False),
        # benchmarking (RFC 2544) and documentation (RFC 5737) ranges
        ("198.18.0.1", True),
        ("198.19.255.254", True),
        ("192.0.2.5", True),
        ("198.51.100.5", True),
        ("203.0.113.5", True),
        # no LAN host
        ("0.0.0.0", False),  # noqa: S104 - names no host
        ("0.1.2.3", False),  # "this network"
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("192.0.0.8", False),  # IETF protocol assignments
        ("192.0.0.9", False),
        ("192.88.99.9", False),  # global
        ("224.0.0.251", False),
        ("240.0.0.1", False),
        ("255.255.255.255", False),
        ("fd00::1", False),  # IPv6: discovery is IPv4 only
        ("::ffff:192.168.1.2", False),
        ("not an address", False),
        ("", False),
    ],
)
def test_which_addresses_are_lan_addresses(ip: str, lan: bool) -> None:
    assert pppp.is_lan_address(ip) is lan


def test_decode_init_string_round_trips_through_the_app_transform() -> None:
    # Encode with the inverse of decode_init_string, then decode back.
    table = pppp._INIT_STRING_TABLE
    hosts = "203.0.113.10,p2p-par-5.anker-in.com"

    def encode(text: str) -> str:
        out = ""
        running = 0
        for i, ch in enumerate(text.encode()):
            x = (ch ^ table[i % len(table)] ^ (0x39 ^ running)) & 0xFF
            running ^= ch
            raw = (x + 0x451) & 0x1FF  # inverse of ((hi<<4)+lo-0x451)
            out += chr(raw >> 4) + chr(raw & 0xF)
        return out

    assert pppp.decode_init_string(encode(hosts)) == hosts.split(",")


def test_decode_init_string_stops_at_the_colon_and_drops_empties() -> None:
    assert pppp.decode_init_string("") == []
    assert pppp.decode_init_string(":anything") == []
