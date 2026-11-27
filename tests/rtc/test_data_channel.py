"""``rtc/data_channel.py``: the data channel's framing and its KCP channel.

Header bytes are synthetic, laid out like the device's: the bytes the client leaves
zero carry other values there, which the decoder ignores.
"""

from __future__ import annotations

import asyncio
import struct
import time
import zlib

import pytest

from eufy_home_security.exceptions import CommunicationError, ProtocolError, UnsupportedError
from eufy_home_security.rtc import _ikcp
from eufy_home_security.rtc.data_channel import (
    KCP_DOWNLOAD_CONV,
    KCP_PREFIX_LEN,
    LINK_HEADER_LEN,
    LINK_HEADER_LEN_OLD,
    MAX_FRAME_LEN,
    OUTER_HEAD_MAGIC,
    DataMsgType,
    KcpDataChannel,
    LinkMessage,
    decode_link_frame,
    encode_kcp_prefix,
    encode_link_frame,
    strip_kcp_prefix,
    strip_outer_head,
)


def test_new_header_round_trips() -> None:
    payload = bytes(range(80))
    frame = encode_link_frame(payload, msg_type=DataMsgType.COMMAND, seq=7, now=0x6AD77131)
    assert len(frame) == LINK_HEADER_LEN + len(payload)
    msg = decode_link_frame(frame)
    assert (msg.msg_type, msg.seq, msg.payload) == (DataMsgType.COMMAND, 7, payload)


def test_old_header_round_trips() -> None:
    payload = b"\xaa" * 40
    frame = encode_link_frame(payload, msg_type=DataMsgType.NOTIFY, seq=3, old=True, now=0x6AD77131)
    assert len(frame) == LINK_HEADER_LEN_OLD + len(payload)
    msg = decode_link_frame(frame)
    assert (msg.msg_type, msg.seq, msg.payload) == (DataMsgType.NOTIFY, 3, payload)


def test_new_header_bytes() -> None:
    # version 9, header_len 24, payload_len, const 1 @8, time @12, type @16, seq @20.
    frame = encode_link_frame(b"\x00" * 148, msg_type=1, seq=0, now=0x6AD77131)
    head = frame[:LINK_HEADER_LEN]
    assert struct.unpack_from("<H", head, 0) == (9,)
    assert struct.unpack_from("<H", head, 2) == (24,)
    assert struct.unpack_from("<I", head, 4) == (148,)
    assert head[8] == 1
    assert struct.unpack_from("<I", head, 12) == (0x6AD77131,)
    assert head[16] == 1
    assert struct.unpack_from("<I", head, 20) == (0,)


# A current link header with the device's extra bytes set: payload 148, type 1, seq 0.
DEVICE_HEAD = bytes.fromhex("090018009400000001a1b2003344556601c1d2e300000000")


def test_decodes_a_device_header() -> None:
    head = DEVICE_HEAD
    assert len(head) == LINK_HEADER_LEN
    msg = decode_link_frame(head + b"\x11" * 148)
    assert msg.msg_type == 1
    assert msg.seq == 0
    assert len(msg.payload) == 148


@pytest.mark.parametrize(
    "buf",
    [
        b"\x00\x00",  # too short for the version
        struct.pack("<HH", 8, 24) + b"\x00" * 24,  # wrong version
        struct.pack("<HH", 9, 22) + b"\x00" * 24,  # unknown header length
        struct.pack("<HHI", 9, 24, 10) + b"\x00" * 10,  # header truncated (needs 24)
        struct.pack("<HHI", 9, 24, 50) + b"\x00" * 20,  # payload truncated
    ],
)
def test_decode_rejects_malformed(buf: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode_link_frame(buf)


def test_strip_outer_head_strips_a_wrapped_reply() -> None:
    body = encode_link_frame(b"XZYH-payload", msg_type=1, seq=1, now=0)
    head = struct.pack(
        "<IIIII", OUTER_HEAD_MAGIC, 0x01000001, len(body), zlib.crc32(body) & 0xFFFFFFFF, 0
    )
    assert strip_outer_head(head + body) == body
    assert strip_outer_head(head + body, verify_crc=True) == body


def test_strip_outer_head_passes_through_unwrapped() -> None:
    frame = encode_link_frame(b"direct", msg_type=1, seq=0, now=0)
    assert strip_outer_head(frame) == frame  # the client's own messages carry none


def test_strip_outer_head_of_a_device_message() -> None:
    body = DEVICE_HEAD + b"\x22" * (0xAC - LINK_HEADER_LEN)
    outer = bytes.fromhex("48595a5801000001ac000000") + struct.pack("<II", zlib.crc32(body), 0)
    assert strip_outer_head(outer + body, verify_crc=True) == body
    stripped = strip_outer_head(outer + body)
    assert len(stripped) == 0xAC
    assert decode_link_frame(stripped).msg_type == 1


def test_strip_outer_head_crc_mismatch_raises() -> None:
    body = b"abcdef"
    head = struct.pack("<IIIII", OUTER_HEAD_MAGIC, 0, len(body), 0xDEADBEEF, 0)
    with pytest.raises(ProtocolError):
        strip_outer_head(head + body, verify_crc=True)


def test_strip_outer_head_truncated_body_raises() -> None:
    head = struct.pack("<IIII", OUTER_HEAD_MAGIC, 0, 100, 0) + b"\x00\x00\x00\x00"
    with pytest.raises(ProtocolError):
        strip_outer_head(head + b"short")


def test_kcp_prefix_round_trips() -> None:
    seg = b"kcp-segment-bytes"
    datagram = encode_kcp_prefix(seg, conv=1)
    assert len(datagram) == 32 + len(seg)
    conv, out = strip_kcp_prefix(datagram)
    assert conv == 1
    assert out == seg


def test_kcp_prefix_download_conv() -> None:
    conv, _ = strip_kcp_prefix(encode_kcp_prefix(b"x" * 40, conv=KCP_DOWNLOAD_CONV))
    assert conv == KCP_DOWNLOAD_CONV


def test_kcp_strip_short_datagram_is_bare() -> None:
    conv, out = strip_kcp_prefix(b"short-bare")
    assert conv == 0
    assert out == b"short-bare"
    assert strip_kcp_prefix(bytes(32)) == (0, bytes(32))
    assert strip_kcp_prefix(encode_kcp_prefix(b"x", conv=5)) == (5, b"x")


def test_kcp_prefix_layout() -> None:
    assert encode_kcp_prefix(b"s").hex() == "0100000001000000" + "00" * 24 + "73"


def test_old_header_bytes() -> None:
    frame = encode_link_frame(b"\x00" * 40, msg_type=3, seq=5, old=True, now=0x11223344)
    assert frame[:20].hex() == "0900140028000100443322110300000005000000"
    assert decode_link_frame(frame) == LinkMessage(3, 5, b"\x00" * 40)


def test_the_timestamp_defaults_to_the_clock() -> None:
    before = int(time.time())
    stamp = struct.unpack_from("<I", encode_link_frame(b"", msg_type=1, seq=0), 12)[0]
    assert before <= stamp <= int(time.time())


class _Pipe:
    """One end of an in-memory packet link (a :class:`PacketTransport`)."""

    def __init__(self, outbound: asyncio.Queue[bytes], inbound: asyncio.Queue[bytes]) -> None:
        self._out = outbound
        self._in = inbound

    async def send(self, data: bytes) -> None:
        self._out.put_nowait(data)

    async def recv(self) -> bytes:
        return await self._in.get()

    async def close(self) -> None:
        return None


async def test_kcp_data_channel_round_trips_messages_both_ways() -> None:
    a2b: asyncio.Queue[bytes] = asyncio.Queue()
    b2a: asyncio.Queue[bytes] = asyncio.Queue()
    left = KcpDataChannel(_Pipe(a2b, b2a), conv=1)
    right = KcpDataChannel(_Pipe(b2a, a2b), conv=1)
    try:
        await left.send_message(b'{"cmd":1307}', msg_type=DataMsgType.COMMAND)
        msg = await asyncio.wait_for(right.recv_message(), 2)
        assert (msg.msg_type, msg.payload) == (DataMsgType.COMMAND, b'{"cmd":1307}')
        await right.send_message(b"\x00" * 16, msg_type=DataMsgType.HEARTBEAT)
        back = await asyncio.wait_for(left.recv_message(), 2)
        assert (back.msg_type, back.payload) == (DataMsgType.HEARTBEAT, b"\x00" * 16)
    finally:
        await left.close()
        await right.close()


async def test_kcp_data_channel_strips_an_inbound_outer_head() -> None:
    chan_in: asyncio.Queue[bytes] = asyncio.Queue()
    chan_out: asyncio.Queue[bytes] = asyncio.Queue()
    chan = KcpDataChannel(_Pipe(chan_out, chan_in), conv=1)
    # A bare KCP peer sends a reply behind an outer head, as the device may.
    peer = _ikcp.KCP(1)
    peer.set_performance_options(True, 2, 2, True)
    peer.set_window_size(512, 512)
    peer.set_maximum_transmission(1200)
    segments: list[bytes] = []
    peer.include_outbound_handler(
        lambda _k, d: segments.append(encode_kcp_prefix(bytes(d), conv=1))
    )
    inner = encode_link_frame(b'{"reply":1}', msg_type=DataMsgType.COMMAND, seq=0, now=0)
    head = struct.pack(
        "<IIIII", OUTER_HEAD_MAGIC, 0x01000001, len(inner), zlib.crc32(inner) & 0xFFFFFFFF, 0
    )
    peer.enqueue(head + inner)
    peer.flush(0)
    try:
        for seg in segments:
            chan_in.put_nowait(seg)
        msg = await asyncio.wait_for(chan.recv_message(), 2)
        assert msg.payload == b'{"reply":1}'
        assert msg.msg_type == DataMsgType.COMMAND
    finally:
        await chan.close()


async def test_an_unprefixed_kcp_data_channel_sends_and_reads_bare_segments() -> None:
    a2b: asyncio.Queue[bytes] = asyncio.Queue()
    b2a: asyncio.Queue[bytes] = asyncio.Queue()
    sent: list[bytes] = []

    class Recording(_Pipe):
        async def send(self, data: bytes) -> None:
            sent.append(data)
            await super().send(data)

    left = KcpDataChannel(Recording(a2b, b2a), conv=1, prefixed=False)
    right = KcpDataChannel(_Pipe(b2a, a2b), conv=1, prefixed=False)
    try:
        payload = b"x" * 64  # longer than the prefix, so a stray strip would corrupt it
        await left.send_message(payload)
        datagram = sent[0]
        assert struct.unpack_from("<I", datagram, 0)[0] == 1  # the KCP conv, no prefix
        assert len(datagram) == 24 + 24 + len(payload)  # KCP header + link header + payload
        msg = await asyncio.wait_for(right.recv_message(), 2)
        assert msg.payload == payload
    finally:
        await left.close()
        await right.close()


class _Failing(_Pipe):
    """A pipe whose receive fails once its queue is told to."""

    async def recv(self) -> bytes:
        data = await super().recv()
        if data == b"fail":
            raise OSError("ice gone")
        return data


async def test_a_failed_transport_ends_the_channel() -> None:
    inbound: asyncio.Queue[bytes] = asyncio.Queue()
    chan = KcpDataChannel(_Failing(asyncio.Queue(), inbound))
    try:
        inbound.put_nowait(b"fail")
        with pytest.raises(CommunicationError, match="closed") as info:
            await asyncio.wait_for(chan.recv_message(), 2)
        assert isinstance(info.value.__cause__, OSError)
        with pytest.raises(CommunicationError):  # every later reader too
            await asyncio.wait_for(chan.recv_message(), 2)
        with pytest.raises(CommunicationError):
            await chan.send_message(b"x")
    finally:
        await chan.close()


async def test_a_closed_channel_refuses_reads_and_sends() -> None:
    chan = KcpDataChannel(_Pipe(asyncio.Queue(), asyncio.Queue()))
    reader = asyncio.ensure_future(chan.recv_message())
    await asyncio.sleep(0)
    await chan.close()
    with pytest.raises(CommunicationError):
        await asyncio.wait_for(reader, 2)
    with pytest.raises(CommunicationError):
        await chan.send_message(b"x")
    await chan.close()  # a second close is a no-op


async def test_a_failing_send_ends_the_channel() -> None:
    class SendFails(_Pipe):
        async def send(self, data: bytes) -> None:
            raise OSError("no route")

    chan = KcpDataChannel(SendFails(asyncio.Queue(), asyncio.Queue()))
    try:
        with pytest.raises(CommunicationError, match="send failed"):
            await chan.send_message(b"x")
        with pytest.raises(CommunicationError):
            await asyncio.wait_for(chan.recv_message(), 2)
    finally:
        await chan.close()


async def test_a_bad_message_inside_kcp_is_dropped() -> None:
    chan_in: asyncio.Queue[bytes] = asyncio.Queue()
    chan = KcpDataChannel(_Pipe(asyncio.Queue(), chan_in), prefixed=False)
    peer = _ikcp.KCP(1)
    peer.set_performance_options(True, 2, 2, True)
    segments: list[bytes] = []
    peer.include_outbound_handler(lambda _k, d: segments.append(bytes(d)))
    peer.enqueue(b"not a link frame")
    peer.enqueue(encode_link_frame(b"ok", msg_type=DataMsgType.NOTIFY, seq=1, now=0))
    peer.flush(0)
    try:
        for seg in segments:
            chan_in.put_nowait(seg)
        msg = await asyncio.wait_for(chan.recv_message(), 2)
        assert (msg.msg_type, msg.payload) == (DataMsgType.NOTIFY, b"ok")
    finally:
        await chan.close()


async def test_the_old_layout_channel_sends_the_short_header() -> None:
    a2b: asyncio.Queue[bytes] = asyncio.Queue()
    b2a: asyncio.Queue[bytes] = asyncio.Queue()
    sent: list[bytes] = []

    class Recording(_Pipe):
        async def send(self, data: bytes) -> None:
            sent.append(data)
            await super().send(data)

    left = KcpDataChannel(Recording(a2b, b2a), old_protocol=True)
    right = KcpDataChannel(_Pipe(b2a, a2b))
    try:
        await left.send_message(b"p")
        link = sent[0][KCP_PREFIX_LEN + 24 :]  # past the prefix and the KCP header
        assert struct.unpack_from("<HH", link, 0) == (9, LINK_HEADER_LEN_OLD)
        await left.send_message(b"q")
        first = await asyncio.wait_for(right.recv_message(), 2)
        second = await asyncio.wait_for(right.recv_message(), 2)
        assert (first.payload, first.seq, second.seq) == (b"p", 0, 1)
    finally:
        await left.close()
        await right.close()


def test_the_message_bound_is_127_kcp_segments() -> None:
    assert MAX_FRAME_LEN == 127 * (1200 - 24) == 149_352


@pytest.mark.parametrize(
    ("old", "bound"), [(False, MAX_FRAME_LEN - LINK_HEADER_LEN), (True, 0xFFFF)]
)
async def test_an_oversize_message_is_refused_before_it_takes_a_seq(old: bool, bound: int) -> None:
    a2b: asyncio.Queue[bytes] = asyncio.Queue()
    b2a: asyncio.Queue[bytes] = asyncio.Queue()
    left = KcpDataChannel(_Pipe(a2b, b2a), old_protocol=old)
    right = KcpDataChannel(_Pipe(b2a, a2b))
    try:
        with pytest.raises(UnsupportedError, match=f"exceeds {bound}"):
            await left.send_message(bytes(bound + 1))
        await left.send_message(bytes(bound))  # at the bound
        await left.send_message(b"next")
        big = await asyncio.wait_for(right.recv_message(), 5)
        small = await asyncio.wait_for(right.recv_message(), 5)
        assert (len(big.payload), big.seq) == (bound, 0)
        assert (small.payload, small.seq) == (b"next", 1)
    finally:
        await left.close()
        await right.close()


def test_the_older_header_refuses_a_payload_its_u16_cannot_count() -> None:
    assert len(encode_link_frame(bytes(0xFFFF), msg_type=1, seq=0, old=True)) == 20 + 0xFFFF
    with pytest.raises(ValueError, match="65536"):
        encode_link_frame(bytes(0x10000), msg_type=1, seq=0, old=True)
