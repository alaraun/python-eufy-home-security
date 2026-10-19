"""``rtc/media.py``: RTP parsing, RTCP APP, H.264 and H.265 depacketizing."""

from __future__ import annotations

import struct

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc.media import (
    START_CODE,
    H264Depacketizer,
    H265Depacketizer,
    PayloadType,
    RtcpApp,
    RtpPacket,
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
