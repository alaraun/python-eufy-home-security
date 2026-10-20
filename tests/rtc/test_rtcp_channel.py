"""``rtc/rtcp_channel.py``: the ANKE reliable channel inside RTCP APP packets.

The codec tests are pure; the channel tests drive it with a recording send
callback and tiny retransmit/heartbeat intervals so nothing waits on a
production constant.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc.rtcp_channel import (
    ANKE_HEADER_LEN,
    ANKE_MAGIC,
    APP_NAME,
    APP_SUBTYPE,
    AnkeFrame,
    AnkeType,
    RtcpChannel,
    decode_anke,
    encode_anke,
)

# ── codec ────────────────────────────────────────────────────────────────────


def test_encode_round_trips_through_decode() -> None:
    frame = decode_anke(encode_anke(AnkeType.DATA, 5, b"hello"))
    assert frame.type == AnkeType.DATA
    assert frame.seq == 5
    assert frame.body == b"hello"


def test_encode_matches_the_device_wire_layout() -> None:
    packet = encode_anke(AnkeType.DATA, 0x11223344, b"\x01\x02")
    assert len(packet) == ANKE_HEADER_LEN + 2
    magic, seq, ptype = struct.unpack_from("<IIB", packet, 0)
    length = struct.unpack_from("<I", packet, 0x0C)[0]
    checksum = struct.unpack_from("<I", packet, 0x10)[0]
    assert magic == ANKE_MAGIC
    assert seq == 0x11223344
    assert ptype == AnkeType.DATA
    assert length == 2
    # byte sum of header[0:16] + body (checksum function @0x5f5104)
    assert checksum == (sum(packet[:16]) + sum(packet[0x14:])) & 0xFFFFFFFF


def test_decode_rejects_a_bad_magic() -> None:
    packet = bytearray(encode_anke(AnkeType.DATA, 1, b"x"))
    packet[0] ^= 0xFF
    with pytest.raises(ProtocolError, match="magic"):
        decode_anke(bytes(packet))


def test_decode_rejects_a_bad_checksum() -> None:
    packet = bytearray(encode_anke(AnkeType.DATA, 1, b"x"))
    packet[0x10] ^= 0xFF
    with pytest.raises(ProtocolError, match="checksum"):
        decode_anke(bytes(packet))


def test_mtu_types_skip_the_checksum() -> None:
    # Types 8 and 9 (`type & 0xfe == 8`) are not checksummed by the device.
    packet = bytearray(encode_anke(AnkeType.MTU_REQUEST, 1, b"mtu"))
    packet[0x10] ^= 0xFF  # corrupt the checksum
    frame = decode_anke(bytes(packet))
    assert frame.type == AnkeType.MTU_REQUEST
    assert frame.body == b"mtu"


def test_decode_rejects_a_truncated_body() -> None:
    packet = encode_anke(AnkeType.DATA, 1, b"abcd")[:-2]
    with pytest.raises(ProtocolError):
        decode_anke(packet)


# ── channel ──────────────────────────────────────────────────────────────────


class _Recorder:
    """A send callback that records every frame it is handed."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def __call__(self, frame: bytes) -> None:
        self.sent.append(frame)

    def of_type(self, ptype: int) -> list[AnkeFrame]:
        return [decode_anke(f) for f in self.sent if decode_anke(f).type == ptype]


def _channel(send: _Recorder, **kwargs: object) -> RtcpChannel:
    kwargs.setdefault("heartbeat_interval", 0.0)  # off unless a test asks
    return RtcpChannel(send, **kwargs)  # type: ignore[arg-type]


async def test_app_name_and_subtype_are_the_eufy_values() -> None:
    assert APP_NAME == b"AZWC"
    assert APP_SUBTYPE == 0


async def test_send_data_emits_type1_frames_with_incrementing_seq() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=())
    try:
        assert await channel.send_data(b"one") == 0
        assert await channel.send_data(b"two") == 1
    finally:
        await channel.close()
    data = send.of_type(AnkeType.DATA)
    assert [f.seq for f in data] == [0, 1]
    assert [f.body for f in data] == [b"one", b"two"]


async def test_inbound_data_is_acked_and_delivered() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_anke(AnkeType.DATA, 7, b"payload"))
        assert await asyncio.wait_for(channel.recv_data(), 1) == b"payload"
        await asyncio.sleep(0)  # let the ACK task run
        acks = send.of_type(AnkeType.ACK)
        assert [f.seq for f in acks] == [7]
        assert acks[0].body == b""
    finally:
        await channel.close()


async def test_a_duplicate_inbound_data_is_reacked_but_not_redelivered() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_anke(AnkeType.DATA, 7, b"payload"))
        channel.feed(encode_anke(AnkeType.DATA, 7, b"payload"))
        assert await asyncio.wait_for(channel.recv_data(), 1) == b"payload"
        await asyncio.sleep(0)
        assert [f.seq for f in send.of_type(AnkeType.ACK)] == [7, 7]
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(channel.recv_data(), 0.05)
    finally:
        await channel.close()


async def test_an_ack_stops_retransmission() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=(0.02, 0.02, 0.02))
    try:
        seq = await channel.send_data(b"cmd")
        channel.feed(encode_anke(AnkeType.ACK, seq, b""))
        await asyncio.sleep(0.1)
    finally:
        await channel.close()
    assert len(send.of_type(AnkeType.DATA)) == 1  # the first send only


async def test_an_unacked_data_is_retransmitted_then_given_up() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=(0.02, 0.02))
    try:
        await channel.send_data(b"cmd")
        await asyncio.sleep(0.1)
    finally:
        await channel.close()
    # first send + two retransmits, then it gives up
    assert len(send.of_type(AnkeType.DATA)) == 3


async def test_an_mtu_request_is_answered_with_an_mtu_response() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_anke(AnkeType.MTU_REQUEST, 3, b"\x01\x02\x03"))
        await asyncio.sleep(0)
    finally:
        await channel.close()
    resp = send.of_type(AnkeType.MTU_RESPONSE)
    assert [f.seq for f in resp] == [3]


async def test_a_heartbeat_is_sent_on_its_interval() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.02)
    channel.start()
    try:
        await asyncio.sleep(0.07)
    finally:
        await channel.close()
    hb = send.of_type(AnkeType.HEARTBEAT)
    assert len(hb) >= 2
    assert all(f.seq == 0 and f.body == b"" for f in hb)
