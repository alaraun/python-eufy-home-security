"""``rtc/media.py``: RTP parsing, RTCP APP, H.264 and H.265 depacketizing, the TURN
relay and candidate lines."""

from __future__ import annotations

import struct
from typing import Any

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc.media import (
    MAX_ACCESS_UNIT,
    START_CODE,
    AccessUnit,
    H264Depacketizer,
    H265Depacketizer,
    PayloadType,
    RtcpApp,
    RtpPacket,
    TurnServer,
    candidate_body,
    is_rtcp,
)


def rtp(
    payload: bytes,
    *,
    seq: int = 1,
    ts: int = 9000,
    marker: bool = False,
    pt: int = PayloadType.H264,
    csrc: int = 0,
    ext: bytes | None = None,
    pad: int = 0,
) -> bytes:
    b0 = 0x80 | csrc | (0x10 if ext is not None else 0) | (0x20 if pad else 0)
    data = (
        struct.pack("!BBHII", b0, (0x80 if marker else 0) | pt, seq, ts, 0x1234)
        + b"\0\0\0\0" * csrc
    )
    if ext is not None:
        data += struct.pack("!HH", 0xBEDE, len(ext) // 4) + ext
    data += payload
    if pad:
        data += b"\0" * (pad - 1) + bytes([pad])
    return data


def test_rtp_header_with_csrc_extension_and_padding() -> None:
    packet = RtpPacket.parse(rtp(b"nal", seq=7, marker=True, csrc=1, ext=b"\1\2\3\4", pad=3))
    assert (packet.payload_type, packet.marker, packet.sequence, packet.timestamp) == (
        PayloadType.H264,
        True,
        7,
        9000,
    )
    assert packet.payload == b"nal"


@pytest.mark.parametrize("data", [b"\x80" * 4, b"\x40" + bytes(11), rtp(b"", ext=b"")[:13]])
def test_a_malformed_rtp_packet_is_refused(data: bytes) -> None:
    with pytest.raises(ProtocolError):
        RtpPacket.parse(data)


def test_rtcp_is_told_apart_from_rtp() -> None:
    assert is_rtcp(RtcpApp(1, 5, b"EUFY", b"x").encode())
    assert not is_rtcp(rtp(b"x"))


def test_rtcp_app_round_trips_with_word_padding() -> None:
    app = RtcpApp(3, 0xABCD, b"EUFY", b"12345")
    data = app.encode()
    assert len(data) % 4 == 0
    assert data[1] == 204
    assert data[0] == 0x83
    assert struct.unpack_from("!H", data, 2)[0] == len(data) // 4 - 1
    parsed = RtcpApp.parse(data)
    assert (parsed.subtype, parsed.ssrc, parsed.name) == (3, 0xABCD, b"EUFY")
    assert parsed.data.rstrip(b"\0") == b"12345"


@pytest.mark.parametrize(
    ("name", "subtype", "message"), [(b"EUF", 0, "four bytes"), (b"EUFY", 32, "five bits")]
)
def test_rtcp_app_refuses_bad_fields(name: bytes, subtype: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        RtcpApp(subtype, 1, name, b"").encode()


def test_rtcp_app_parse_refuses_other_packets() -> None:
    with pytest.raises(ProtocolError):
        RtcpApp.parse(bytes([0x80, 200]) + bytes(10))


# ── H.264 ────────────────────────────────────────────────────────────────────

SPS, PPS, IDR, SLICE = b"\x67spsdata", b"\x68pps", b"\x65" + b"I" * 20, b"\x41pframe"


def _stap_a(*nals: bytes) -> bytes:
    return b"\x18" + b"".join(struct.pack("!H", len(n)) + n for n in nals)


def _fu_a(nal: bytes, size: int) -> list[bytes]:
    head, body = nal[0], nal[1:]
    parts = [body[i : i + size] for i in range(0, len(body), size)]
    out = []
    for i, part in enumerate(parts):
        fu = (head & 0x1F) | (0x80 if i == 0 else 0) | (0x40 if i == len(parts) - 1 else 0)
        out.append(bytes([(head & 0xE0) | 28, fu]) + part)
    return out


def test_h264_stap_a_and_fu_a_make_one_keyframe() -> None:
    dep = H264Depacketizer()
    out = dep.push(RtpPacket.parse(rtp(_stap_a(SPS, PPS), seq=1)))
    fragments = _fu_a(IDR, 7)
    for i, frag in enumerate(fragments):
        out += dep.push(RtpPacket.parse(rtp(frag, seq=2 + i, marker=i == len(fragments) - 1)))
    assert len(out) == 1
    assert out[0].keyframe
    assert out[0].data == START_CODE + SPS + START_CODE + PPS + START_CODE + IDR


def test_h264_an_idr_slice_alone_is_a_keyframe() -> None:
    out = H264Depacketizer().push(RtpPacket.parse(rtp(IDR, marker=True)))
    assert [u.keyframe for u in out] == [True]


def test_h264_a_new_timestamp_ends_a_frame_without_marker() -> None:
    dep = H264Depacketizer()
    assert dep.push(RtpPacket.parse(rtp(SLICE, seq=1, ts=1))) == []
    out = dep.push(RtpPacket.parse(rtp(SLICE, seq=2, ts=2, marker=True)))
    assert [(u.timestamp, u.keyframe) for u in out] == [(1, False), (2, False)]


def test_h264_a_lost_fragment_drops_its_nal_unit() -> None:
    dep = H264Depacketizer()
    fragments = _fu_a(IDR, 5)
    dep.push(RtpPacket.parse(rtp(fragments[0], seq=1)))
    out = dep.push(RtpPacket.parse(rtp(fragments[-1], seq=9, marker=True)))
    assert out == []


# ── H.265 ────────────────────────────────────────────────────────────────────

VPS, HSPS, HPPS = b"\x40\x01vps", b"\x42\x01sps", b"\x44\x01pps"
HIDR = b"\x26\x01" + b"K" * 30  # type 19 IDR_W_RADL
HTRAIL = b"\x02\x01trail"


def _ap(*nals: bytes) -> bytes:
    return bytes([48 << 1, 1]) + b"".join(struct.pack("!H", len(n)) + n for n in nals)


def _fu(nal: bytes, size: int) -> list[bytes]:
    kind = (nal[0] >> 1) & 0x3F
    body = nal[2:]
    parts = [body[i : i + size] for i in range(0, len(body), size)]
    out = []
    for i, part in enumerate(parts):
        fu = kind | (0x80 if i == 0 else 0) | (0x40 if i == len(parts) - 1 else 0)
        out.append(bytes([(nal[0] & 0x81) | (49 << 1), nal[1], fu]) + part)
    return out


def test_h265_aggregation_and_fragments_make_one_keyframe() -> None:
    dep = H265Depacketizer()
    out = dep.push(RtpPacket.parse(rtp(_ap(VPS, HSPS, HPPS), pt=PayloadType.H265, seq=10)))
    fragments = _fu(HIDR, 8)
    for i, frag in enumerate(fragments):
        out += dep.push(
            RtpPacket.parse(
                rtp(frag, pt=PayloadType.H265, seq=11 + i, marker=i == len(fragments) - 1)
            )
        )
    assert len(out) == 1
    assert out[0].keyframe
    assert out[0].data == b"".join(START_CODE + n for n in (VPS, HSPS, HPPS, HIDR))


def test_h265_trailing_picture_is_not_a_keyframe() -> None:
    out = H265Depacketizer().push(RtpPacket.parse(rtp(HTRAIL, pt=PayloadType.H265, marker=True)))
    assert len(out) == 1
    assert not out[0].keyframe
    assert out[0].data == START_CODE + HTRAIL


def test_a_sequence_wrap_is_not_a_loss() -> None:
    dep = H265Depacketizer()
    fragments = _fu(HIDR, 16)
    dep.push(RtpPacket.parse(rtp(fragments[0], pt=PayloadType.H265, seq=0xFFFF)))
    out = dep.push(RtpPacket.parse(rtp(fragments[1], pt=PayloadType.H265, seq=0, marker=True)))
    assert len(out) == 1
    assert out[0].keyframe


def test_turn_server_reads_the_primary_relay() -> None:
    turn = {
        "turn_addr": "198.51.100.9",
        "turn_port": "3478",
        "turn_user": "turnlogin",
        "turn_password": "secret",
        "alt_turn_addr": "198.51.100.10",
        "alt_turn_port": 3479,
    }
    server = TurnServer.from_json(turn)
    assert server == TurnServer("198.51.100.9", 3478, "turnlogin", "secret")
    assert "secret" not in repr(server)
    assert "turnlogin" not in repr(server)


@pytest.mark.parametrize(
    "turn",
    [
        None,
        {},
        {"turn_addr": "", "turn_port": 3478, "turn_user": "u", "turn_password": "p"},
        {"turn_addr": "h", "turn_port": 3478, "turn_user": "", "turn_password": "p"},
        {"turn_addr": "h", "turn_port": 3478, "turn_user": "u"},
        {"turn_addr": "h", "turn_port": None, "turn_user": "u", "turn_password": "p"},
        {"turn_addr": "h", "turn_port": "x", "turn_user": "u", "turn_password": "p"},
    ],
)
def test_turn_server_is_none_when_a_field_is_missing(turn: dict[str, Any] | None) -> None:
    assert TurnServer.from_json(turn) is None


@pytest.mark.parametrize(
    "line",
    [
        "a=candidate:1 1 UDP 2122317823 192.0.2.5 46963 typ host",
        "candidate:1 1 UDP 2122317823 192.0.2.5 46963 typ host",
        " 1 1 UDP 2122317823 192.0.2.5 46963 typ host\r\n",
    ],
)
def test_candidate_body_strips_both_prefixes(line: str) -> None:
    assert candidate_body(line) == "1 1 UDP 2122317823 192.0.2.5 46963 typ host"


@pytest.mark.parametrize(("second", "rtcp"), [(191, False), (192, True), (223, True), (224, False)])
def test_rtcp_is_the_rfc_5761_range(second: int, rtcp: bool) -> None:
    assert is_rtcp(bytes([0x80, second])) is rtcp
    assert not is_rtcp(bytes([0x80]))


def test_rtcp_app_parse_refuses_a_truncated_packet() -> None:
    data = RtcpApp(0, 1, b"AZWC", b"12345678").encode()
    with pytest.raises(ProtocolError, match="truncated"):
        RtcpApp.parse(data[:-4])
    assert RtcpApp.parse(data).data == b"12345678"


def test_rtp_header_extension_words_are_skipped() -> None:
    packet = RtpPacket.parse(rtp(b"payload", ext=b"\1\2\3\4\5\6\7\x08"))
    assert packet.payload == b"payload"


def test_h264_single_nal_units_of_one_timestamp_join_one_frame() -> None:
    dep = H264Depacketizer()
    assert dep.push(RtpPacket.parse(rtp(SPS, seq=1))) == []
    out = dep.push(RtpPacket.parse(rtp(SLICE, seq=2, marker=True)))
    assert [(u.data, u.keyframe) for u in out] == [(START_CODE + SPS + START_CODE + SLICE, False)]


def test_a_gap_inside_a_fragmented_nal_drops_only_that_nal() -> None:
    dep = H264Depacketizer()
    fragments = _fu_a(IDR, 5)
    dep.push(RtpPacket.parse(rtp(SPS, seq=1)))
    dep.push(RtpPacket.parse(rtp(fragments[0], seq=2)))
    out = dep.push(RtpPacket.parse(rtp(SLICE, seq=4, marker=True)))
    assert [u.data for u in out] == [START_CODE + SPS + START_CODE + SLICE]


def test_an_aggregate_stops_at_a_bad_length() -> None:
    dep = H265Depacketizer()
    payload = _ap(VPS) + struct.pack("!H", 200) + b"short"
    out = dep.push(RtpPacket.parse(rtp(payload, pt=PayloadType.H265, marker=True)))
    assert [u.data for u in out] == [START_CODE + VPS]


@pytest.mark.parametrize(("kind", "key"), [(15, False), (16, True), (21, True), (22, False)])
def test_h265_keyframes_are_the_irap_types(kind: int, key: bool) -> None:
    nal = bytes([kind << 1, 1]) + b"x"
    out = H265Depacketizer().push(RtpPacket.parse(rtp(nal, pt=PayloadType.H265, marker=True)))
    assert out[0].keyframe is key


def test_short_payloads_yield_nothing() -> None:
    assert H264Depacketizer().push(RtpPacket.parse(rtp(b"", marker=True))) == []
    assert H264Depacketizer().push(RtpPacket.parse(rtp(b"\x1c", marker=True))) == []
    h265 = H265Depacketizer()
    assert h265.push(RtpPacket.parse(rtp(b"\x62\x01", pt=PayloadType.H265, marker=True))) == []


def test_h265_fragments_keep_the_layer_bit_of_the_payload_header() -> None:
    nal = bytes([HIDR[0] | 1, 1]) + b"L" * 20  # LayerId's high bit set
    fragments = _fu(nal, 8)
    dep = H265Depacketizer()
    out: list[AccessUnit] = []
    for i, frag in enumerate(fragments):
        last = i == len(fragments) - 1
        out += dep.push(RtpPacket.parse(rtp(frag, pt=PayloadType.H265, seq=i, marker=last)))
    assert out[0].data == START_CODE + nal


def test_an_aggregate_stops_at_a_zero_length() -> None:
    payload = _stap_a(SPS) + b"\x00\x00" + struct.pack("!H", 3) + b"\x68ab"
    out = H264Depacketizer().push(RtpPacket.parse(rtp(payload, marker=True)))
    assert [u.data for u in out] == [START_CODE + SPS]


def test_an_access_unit_over_the_bound_is_dropped_and_the_next_one_kept() -> None:
    dep = H265Depacketizer()
    chunk = b"\x02\x01" + b"z" * 60_000
    packets = MAX_ACCESS_UNIT // len(chunk) + 2
    out = []
    for seq in range(1, packets + 1):
        out += dep.push(RtpPacket.parse(rtp(chunk, seq=seq, ts=1000, pt=PayloadType.H265)))
    out += dep.push(
        RtpPacket.parse(rtp(HTRAIL, seq=packets + 1, ts=1000, pt=PayloadType.H265, marker=True))
    )
    assert out == []
    kept = dep.push(
        RtpPacket.parse(rtp(HTRAIL, seq=packets + 2, ts=2000, pt=PayloadType.H265, marker=True))
    )
    assert [unit.data for unit in kept] == [START_CODE + HTRAIL]


def test_an_access_unit_at_the_bound_is_kept() -> None:
    dep = H265Depacketizer()
    nal = b"\x02\x01" + b"z" * (MAX_ACCESS_UNIT - 2)
    [unit] = dep.push(RtpPacket.parse(rtp(nal, ts=1000, pt=PayloadType.H265, marker=True)))
    assert unit.data == START_CODE + nal


def test_an_over_bound_frame_ended_by_a_new_timestamp_is_dropped_too() -> None:
    dep = H265Depacketizer()
    big = b"\x02\x01" + b"z" * MAX_ACCESS_UNIT
    assert dep.push(RtpPacket.parse(rtp(big, seq=1, ts=1000, pt=PayloadType.H265))) == []
    out = dep.push(RtpPacket.parse(rtp(HTRAIL, seq=2, ts=2000, pt=PayloadType.H265, marker=True)))
    assert [unit.data for unit in out] == [START_CODE + HTRAIL]
