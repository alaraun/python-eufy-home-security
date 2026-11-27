"""``rtc/rtcp_channel.py``: the reliable command channel inside RTCP APP packets.

The codec tests are pure; the channel tests drive it with a recording send
callback and tiny retransmit/heartbeat intervals so nothing waits on a
production constant.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from eufy_home_security.exceptions import CommunicationError, ProtocolError
from eufy_home_security.rtc.rtcp_channel import (
    APP_NAME,
    APP_SUBTYPE,
    DEDUP_WINDOW,
    FRAME_HEADER_LEN,
    FRAME_MAGIC,
    HEARTBEAT_INTERVAL,
    RETRANSMIT_DELAYS,
    Frame,
    FrameType,
    RtcpChannel,
    decode_frame,
    encode_frame,
)

# ── codec ────────────────────────────────────────────────────────────────────


def test_encode_round_trips_through_decode() -> None:
    frame = decode_frame(encode_frame(FrameType.DATA, 5, b"hello"))
    assert frame.type == FrameType.DATA
    assert frame.seq == 5
    assert frame.body == b"hello"


def test_encode_has_the_wire_layout() -> None:
    packet = encode_frame(FrameType.DATA, 0x11223344, b"\x01\x02")
    assert len(packet) == FRAME_HEADER_LEN + 2
    magic, seq, ptype = struct.unpack_from("<IIB", packet, 0)
    length = struct.unpack_from("<I", packet, 0x0C)[0]
    checksum = struct.unpack_from("<I", packet, 0x10)[0]
    assert magic == FRAME_MAGIC
    assert seq == 0x11223344
    assert ptype == FrameType.DATA
    assert length == 2
    # byte sum of header[0:16] + body
    assert checksum == (sum(packet[:16]) + sum(packet[0x14:])) & 0xFFFFFFFF


def test_decode_rejects_a_bad_magic() -> None:
    packet = bytearray(encode_frame(FrameType.DATA, 1, b"x"))
    packet[0] ^= 0xFF
    with pytest.raises(ProtocolError, match="magic"):
        decode_frame(bytes(packet))


def test_decode_rejects_a_bad_checksum() -> None:
    packet = bytearray(encode_frame(FrameType.DATA, 1, b"x"))
    packet[0x10] ^= 0xFF
    with pytest.raises(ProtocolError, match="checksum"):
        decode_frame(bytes(packet))


@pytest.mark.parametrize("frame_type", [FrameType.MTU_REQUEST, FrameType.MTU_RESPONSE])
def test_mtu_types_skip_the_checksum(frame_type: FrameType) -> None:
    packet = bytearray(encode_frame(frame_type, 1, b"mtu"))
    packet[0x10] ^= 0xFF  # corrupt the checksum
    frame = decode_frame(bytes(packet))
    assert frame.type == frame_type
    assert frame.body == b"mtu"


@pytest.mark.parametrize("frame_type", [FrameType.ACK, FrameType.HEARTBEAT, 10])
def test_other_types_check_the_checksum(frame_type: int) -> None:
    packet = bytearray(encode_frame(frame_type, 1, b"x"))
    packet[0x10] ^= 0xFF
    with pytest.raises(ProtocolError, match="checksum"):
        decode_frame(bytes(packet))


def test_the_checksum_covers_the_body() -> None:
    packet = bytearray(encode_frame(FrameType.DATA, 1, b"xy"))
    packet[-1] ^= 1
    with pytest.raises(ProtocolError, match="checksum"):
        decode_frame(bytes(packet))


def test_decode_rejects_a_truncated_body() -> None:
    packet = encode_frame(FrameType.DATA, 1, b"abcd")
    with pytest.raises(ProtocolError, match="truncated"):
        decode_frame(packet[:-2])
    with pytest.raises(ProtocolError, match="shorter than its header"):
        decode_frame(packet[:19])
    assert decode_frame(encode_frame(FrameType.ACK, 1)).body == b""


def test_the_production_timings() -> None:
    assert RETRANSMIT_DELAYS == (0.1, 0.2, 0.5, 0.5, 0.5)
    assert HEARTBEAT_INTERVAL == 1.0


# ── channel ──────────────────────────────────────────────────────────────────


class _Recorder:
    """A send callback that records every frame it is handed."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def __call__(self, frame: bytes) -> None:
        self.sent.append(frame)

    def of_type(self, ptype: int) -> list[Frame]:
        return [decode_frame(f) for f in self.sent if decode_frame(f).type == ptype]


def _channel(send: _Recorder, **kwargs: object) -> RtcpChannel:
    kwargs.setdefault("heartbeat_interval", 0.0)  # off unless a test asks
    return RtcpChannel(send, **kwargs)  # type: ignore[arg-type]


async def test_app_name_and_subtype() -> None:
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
    data = send.of_type(FrameType.DATA)
    assert [f.seq for f in data] == [0, 1]
    assert [f.body for f in data] == [b"one", b"two"]


async def test_inbound_data_is_acked_and_delivered() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_frame(FrameType.DATA, 7, b"payload"))
        assert await asyncio.wait_for(channel.recv_data(), 1) == b"payload"
        await asyncio.sleep(0)  # let the ACK task run
        acks = send.of_type(FrameType.ACK)
        assert [f.seq for f in acks] == [7]
        assert acks[0].body == b""
    finally:
        await channel.close()


async def test_a_duplicate_inbound_data_is_reacked_but_not_redelivered() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_frame(FrameType.DATA, 7, b"payload"))
        channel.feed(encode_frame(FrameType.DATA, 7, b"payload"))
        assert await asyncio.wait_for(channel.recv_data(), 1) == b"payload"
        await asyncio.sleep(0)
        assert [f.seq for f in send.of_type(FrameType.ACK)] == [7, 7]
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(channel.recv_data(), 0.05)
    finally:
        await channel.close()


async def test_an_ack_stops_retransmission() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=(0.02, 0.02, 0.02))
    try:
        seq = await channel.send_data(b"cmd")
        channel.feed(encode_frame(FrameType.ACK, seq, b""))
        await asyncio.sleep(0.1)
    finally:
        await channel.close()
    assert len(send.of_type(FrameType.DATA)) == 1  # the first send only


async def test_an_unacked_data_is_retransmitted_then_given_up() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=(0.02, 0.02))
    try:
        await channel.send_data(b"cmd")
        await asyncio.sleep(0.1)
    finally:
        await channel.close()
    # first send + two retransmits, then it gives up
    assert len(send.of_type(FrameType.DATA)) == 3


async def test_an_mtu_request_is_answered_with_an_mtu_response() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        channel.feed(encode_frame(FrameType.MTU_REQUEST, 3, b"\x01\x02\x03"))
        await asyncio.sleep(0)
    finally:
        await channel.close()
    resp = send.of_type(FrameType.MTU_RESPONSE)
    assert [f.seq for f in resp] == [3]


async def test_a_heartbeat_is_sent_on_its_interval() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.02)
    channel.start()
    try:
        await asyncio.sleep(0.07)
    finally:
        await channel.close()
    hb = send.of_type(FrameType.HEARTBEAT)
    assert len(hb) >= 2
    assert all(f.seq == 0 and f.body == b"" for f in hb)


async def test_the_heartbeat_starts_once() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.03)
    channel.start()
    channel.start()
    try:
        async with asyncio.timeout(2):
            while not send.sent:
                await asyncio.sleep(0.005)
        await asyncio.sleep(0.01)  # a second loop would have fired in the same tick
    finally:
        await channel.close()
    assert len(send.of_type(FrameType.HEARTBEAT)) == 1


async def test_no_heartbeat_without_a_positive_interval() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.0)
    channel.start()
    await asyncio.sleep(0.02)
    await channel.close()
    assert send.sent == []


async def test_close_stops_resends_and_heartbeat() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.02, retransmit_delays=(0.02,) * 5)
    channel.start()
    await channel.send_data(b"cmd")
    await channel.close()
    count = len(send.sent)
    await asyncio.sleep(0.08)
    assert len(send.sent) == count
    channel.feed(encode_frame(FrameType.DATA, 1, b"late"))  # nothing is spawned after close
    await asyncio.sleep(0)
    assert len(send.sent) == count


async def test_a_failing_first_send_propagates_and_is_not_resent() -> None:
    sent: list[bytes] = []

    async def failing(frame: bytes) -> None:
        sent.append(frame)
        raise OSError("gone")

    channel = RtcpChannel(failing, heartbeat_interval=0, retransmit_delays=(0.01,))
    with pytest.raises(OSError, match="gone"):
        await channel.send_data(b"cmd")
    await asyncio.sleep(0.03)
    assert channel._acks == {}
    await channel.close()
    assert len(sent) == 1


async def test_a_failing_ack_send_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    async def failing(frame: bytes) -> None:
        raise OSError("gone")

    channel = RtcpChannel(failing, heartbeat_interval=0)
    with caplog.at_level("DEBUG", logger="eufy_home_security.rtc.rtcp_channel"):
        channel.feed(encode_frame(FrameType.DATA, 1, b"x"))
        assert await asyncio.wait_for(channel.recv_data(), 1) == b"x"
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    await channel.close()
    assert any("send failed: gone" in r.getMessage() for r in caplog.records)


async def test_an_ack_for_an_unknown_seq_is_ignored() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=(0.02,))
    try:
        seq = await channel.send_data(b"cmd")
        channel.feed(encode_frame(FrameType.ACK, seq + 1))
        await asyncio.sleep(0.05)
    finally:
        await channel.close()
    assert len(send.of_type(FrameType.DATA)) == 2


async def test_a_corrupt_frame_is_dropped() -> None:
    send = _Recorder()
    channel = _channel(send)
    channel.feed(b"\x00" * 8)
    await asyncio.sleep(0)
    await channel.close()
    assert send.sent == []


async def test_dedup_forgets_the_oldest_seq_past_its_window() -> None:
    send = _Recorder()
    channel = _channel(send)
    try:
        for seq in range(DEDUP_WINDOW + 1):
            channel.feed(encode_frame(FrameType.DATA, seq, b"x"))
        channel.feed(encode_frame(FrameType.DATA, 1, b"again"))  # still remembered
        channel.feed(encode_frame(FrameType.DATA, 0, b"again"))  # forgotten: delivered again
        bodies = [channel._inbound.get_nowait() for _ in range(channel._inbound.qsize())]
    finally:
        await channel.close()
    assert len(bodies) == DEDUP_WINDOW + 2
    assert bodies[-1] == b"again"
    assert bodies.count(b"again") == 1


async def test_the_seq_wraps_at_32_bits() -> None:
    send = _Recorder()
    channel = _channel(send, retransmit_delays=())
    channel._next_seq = 0xFFFFFFFF
    try:
        assert await channel.send_data(b"a") == 0xFFFFFFFF
        assert await channel.send_data(b"b") == 0
    finally:
        await channel.close()


class _Flaky(_Recorder):
    """A send callback that fails its first ``failures`` calls."""

    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures

    async def __call__(self, frame: bytes) -> None:
        if self.failures > 0:
            self.failures -= 1
            raise OSError("transient")
        await super().__call__(frame)


async def _until_sent(send: _Recorder, count: int) -> None:
    async with asyncio.timeout(2):
        while len(send.sent) < count:
            await asyncio.sleep(0.005)


async def test_the_heartbeat_survives_failed_sends_and_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    send = _Flaky(failures=3)
    channel = _channel(send, heartbeat_interval=0.01)
    with caplog.at_level("DEBUG", logger="eufy_home_security.rtc.rtcp_channel"):
        channel.start()
        try:
            await _until_sent(send, 2)
        finally:
            await channel.close()
    assert all(f.type == FrameType.HEARTBEAT for f in map(decode_frame, send.sent))
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "heartbeat" in warnings[0].getMessage()


async def test_start_restarts_a_heartbeat_that_ended() -> None:
    send = _Recorder()
    channel = _channel(send, heartbeat_interval=0.01)
    channel.start()
    try:
        await _until_sent(send, 1)
        for task in list(channel._tasks):
            task.cancel()
        await asyncio.sleep(0.03)
        count = len(send.sent)
        channel.start()
        await _until_sent(send, count + 1)
    finally:
        await channel.close()


async def test_send_data_after_close_raises_and_sends_nothing() -> None:
    send = _Recorder()
    channel = _channel(send)
    await channel.close()
    with pytest.raises(CommunicationError, match="closed"):
        await channel.send_data(b"late")
    assert send.sent == []
    assert channel._acks == {}
    channel.start()  # no heartbeat after close
    assert channel._tasks == set()
