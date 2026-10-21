"""``rtc/media_stats.py``: the live-view descriptors and the SPS parsers."""

from __future__ import annotations

import struct
from typing import Any

import pytest

from eufy_home_security.rtc.media import START_CODE, PayloadType, RtpPacket
from eufy_home_security.rtc.media_stats import (
    AUDIO_HEADS,
    MediaStats,
    parse_h264_sps,
    parse_h265_sps,
)


class _Writer:
    """MSB-first bit writer with exp-Golomb codes; ``nal`` adds emulation prevention."""

    def __init__(self) -> None:
        self.bits: list[int] = []

    def u(self, n: int, value: int) -> _Writer:
        self.bits += [(value >> (n - 1 - i)) & 1 for i in range(n)]
        return self

    def ue(self, value: int) -> _Writer:
        code = value + 1
        length = code.bit_length()
        return self.u(length - 1, 0).u(length, code)

    def se(self, value: int) -> _Writer:
        return self.ue(2 * value - 1 if value > 0 else -2 * value)

    def nal(self, header: bytes) -> bytes:
        bits = [*self.bits, 1]  # rbsp_stop_one_bit
        bits += [0] * (-len(bits) % 8)
        raw = bytes(int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8))
        out, zeros = bytearray(), 0
        for byte in raw:
            if zeros >= 2 and byte <= 3:
                out.append(3)
                zeros = 0
            out.append(byte)
            zeros = zeros + 1 if byte == 0 else 0
        return header + bytes(out)


def _h265_sps(width: int, height: int, *, crop_bottom: int = 0, sub_layers: int = 0) -> bytes:
    w = _Writer().u(4, 0).u(3, sub_layers).u(1, 1)
    w.u(2, 0).u(1, 0).u(5, 1).u(32, 0x60000000).u(48, 0).u(8, 120)
    for _ in range(sub_layers):
        w.u(1, 0).u(1, 1)
    if sub_layers:
        w.u(2 * (8 - sub_layers), 0)
    for _ in range(sub_layers):
        w.u(8, 90)
    w.ue(0).ue(1).ue(width).ue(height)
    if crop_bottom:
        w.u(1, 1).ue(0).ue(0).ue(0).ue(crop_bottom)
    else:
        w.u(1, 0)
    return w.nal(bytes([_H265_SPS << 1, 1]))


_H265_SPS = 33


def _h264_sps(
    width_mbs: int,
    height_mbs: int,
    *,
    profile: int = 66,
    crop_bottom: int = 0,
    scaling: bool = False,
    poc_type: int = 0,
    interlaced: bool = False,
) -> bytes:
    w = _Writer().u(8, profile).u(8, 0xC0).u(8, 31).ue(0)
    if profile == 100:
        w.ue(1).ue(0).ue(0).u(1, 0).u(1, int(scaling))
        if scaling:
            # The first list present (16 deltas: +8 then 0s), the other seven absent.
            w.u(1, 1).se(8)
            for _ in range(15):
                w.se(0)
            w.u(7, 0)
    w.ue(0).ue(poc_type)  # log2_max_frame_num, pic_order_cnt_type
    if poc_type == 0:
        w.ue(4)
    elif poc_type == 1:
        w.u(1, 0).se(-2).se(3).ue(2).se(1).se(-1)
    w.ue(1).u(1, 0).ue(width_mbs - 1).ue(height_mbs - 1).u(1, int(not interlaced))
    if interlaced:
        w.u(1, 1)  # mb_adaptive_frame_field_flag
    w.u(1, 1)
    if crop_bottom:
        w.u(1, 1).ue(0).ue(0).ue(0).ue(crop_bottom)
    else:
        w.u(1, 0)
    return w.nal(bytes([0x67]))


def test_an_h265_sps_gives_profile_level_and_the_cropped_size() -> None:
    assert parse_h265_sps(_h265_sps(1920, 1088, crop_bottom=4)) == {
        "profile_idc": 1,
        "tier": 0,
        "level_idc": 120,
        "chroma_format_idc": 1,
        "width": 1920,
        "height": 1080,
    }


def test_an_h265_sps_with_sub_layers_skips_their_levels() -> None:
    sps = parse_h265_sps(_h265_sps(2560, 1440, sub_layers=2))
    assert sps is not None
    assert (sps["width"], sps["height"]) == (2560, 1440)


def test_an_h264_sps_gives_the_size_for_baseline_and_high_profiles() -> None:
    assert parse_h264_sps(_h264_sps(80, 45)) == {
        "profile_idc": 66,
        "constraint_flags": 0xC0,
        "level_idc": 31,
        "chroma_format_idc": 1,
        "width": 1280,
        "height": 720,
    }
    high = parse_h264_sps(_h264_sps(120, 68, profile=100, crop_bottom=4))
    assert high is not None
    assert (high["profile_idc"], high["width"], high["height"]) == (100, 1920, 1080)


@pytest.mark.parametrize(
    "variant",
    [{"scaling": True}, {"poc_type": 1}, {"poc_type": 2}],
    ids=["scaling-matrix", "poc-type-1", "poc-type-2"],
)
def test_an_h264_sps_with_optional_syntax_still_gives_its_size(variant: dict[str, Any]) -> None:
    sps = parse_h264_sps(_h264_sps(120, 68, profile=100, crop_bottom=4, **variant))
    assert sps is not None
    assert (sps["width"], sps["height"]) == (1920, 1080)


def test_an_interlaced_h264_sps_counts_both_fields() -> None:
    sps = parse_h264_sps(_h264_sps(45, 18, interlaced=True))
    assert sps is not None
    assert (sps["width"], sps["height"]) == (720, 576)


def test_a_truncated_or_implausible_sps_is_none() -> None:
    assert parse_h265_sps(_h265_sps(1920, 1080)[:6]) is None
    assert parse_h264_sps(b"\x67\x42") is None
    assert parse_h264_sps(_h264_sps(1, 1)) is not None  # 16x16: the smallest plausible size
    assert parse_h264_sps(_h264_sps(1, 1, crop_bottom=1)) is None


def _packet(pt: int, payload: bytes, seq: int, ts: int, marker: bool = False) -> RtpPacket:
    return RtpPacket(pt, marker, seq, ts, 0x1234, payload)


def test_video_packets_are_described_by_packetization_and_nal_type() -> None:
    stats = MediaStats(clock=lambda: 0.0)
    ap = bytes([48 << 1, 1])
    for nal in (bytes([32 << 1, 1, 0]), bytes([33 << 1, 1, 0])):
        ap += struct.pack("!H", len(nal)) + nal
    stats.packet(_packet(PayloadType.H265, ap, 1, 0))
    stats.packet(_packet(PayloadType.H265, bytes([49 << 1, 1, 0x80 | 19]) + b"x", 2, 0))
    stats.packet(_packet(PayloadType.H265, bytes([49 << 1, 1, 0x40 | 19]) + b"x", 4, 0, True))
    stats.packet(_packet(PayloadType.H265, bytes([1 << 1, 1]) + b"p", 5, 3000, True))
    stats.packet(_packet(PayloadType.H264, bytes([24, 0, 2, 0x67, 0, 0, 2, 0x68, 0]), 1, 0))
    stats.packet(_packet(PayloadType.H264, bytes([28, 0x85]) + b"x", 2, 0))
    stats.packet(_packet(PayloadType.H264, bytes([28, 0x45]) + b"x", 3, 0))
    stats.packet(_packet(PayloadType.H264, bytes([0x41]) + b"x", 4, 0))
    rtp = stats.as_dict()["rtp"]
    assert isinstance(rtp, dict)
    h265 = rtp[str(int(PayloadType.H265))]
    assert h265["packetization"] == {"aggregation": 1, "fragment": 2, "single": 1}
    assert h265["nal_types"] == {"32": 1, "33": 1, "19": 1, "1": 1}  # an FU counts once
    assert (h265["packets"], h265["markers"], h265["seq_gaps"]) == (4, 2, 1)
    assert h265["timestamp_steps"] == {"3000": 1}
    h264 = rtp[str(int(PayloadType.H264))]
    assert h264["packetization"] == {"aggregation": 1, "fragment": 2, "single": 1}
    assert h264["nal_types"] == {"7": 1, "8": 1, "5": 1, "1": 1}


def test_audio_keeps_the_first_bytes_of_the_first_packets_and_estimates_its_clock() -> None:
    now = [0.0]
    stats = MediaStats(clock=lambda: now[0])
    for i in range(AUDIO_HEADS + 2):
        now[0] = i * 0.25
        stats.packet(_packet(PayloadType.AUDIO, bytes([0xFF, 0xF1, 0x50, 0x80, i]), i, i * 4000))
    audio = stats.as_dict()["rtp"][str(int(PayloadType.AUDIO))]  # type: ignore[index]
    assert audio["first_bytes_hex"] == ["fff15080"] * AUDIO_HEADS
    assert audio["clock_rate_estimate"] == 16000
    assert audio["timestamp_steps"] == {"4000": AUDIO_HEADS + 1}
    assert "packetization" not in audio


def test_a_clock_is_estimated_only_over_a_second_or_more() -> None:
    now = [0.0]
    stats = MediaStats(clock=lambda: now[0])
    stats.packet(_packet(PayloadType.AUDIO, b"a", 0, 0))
    now[0] = 0.99
    stats.packet(_packet(PayloadType.AUDIO, b"a", 1, 47520))
    assert "clock_rate_estimate" not in stats.as_dict()["rtp"]["111"]  # type: ignore[index]
    now[0] = 1.0
    stats.packet(_packet(PayloadType.AUDIO, b"a", 2, 48000))
    assert stats.as_dict()["rtp"]["111"]["clock_rate_estimate"] == 48000  # type: ignore[index]


def test_an_unknown_clock_is_reported_rounded() -> None:
    now = [0.0]
    stats = MediaStats(clock=lambda: now[0])
    stats.packet(_packet(PayloadType.AUDIO, b"a", 0, 0))
    now[0] = 2.0
    stats.packet(_packet(PayloadType.AUDIO, b"a", 1, 2 * 12345))
    assert stats.as_dict()["rtp"]["111"]["clock_rate_estimate"] == 12345  # type: ignore[index]


def test_frames_give_rate_keyframe_interval_parameter_sets_and_the_sps() -> None:
    stats = MediaStats()
    sps = _h265_sps(1920, 1080)
    for i in range(6):
        key = i % 3 == 0
        data = (
            (START_CODE + sps + START_CODE + bytes([19 << 1, 1]))
            if key
            else (START_CODE + bytes([1 << 1, 1]))
        )
        stats.frame("h265", data, i * 6000, keyframe=key, decrypted=i != 5)
    video = stats.as_dict()["video"]["h265"]  # type: ignore[index]
    assert (video["frames"], video["keyframes"], video["decrypted"]) == (6, 2, 5)
    assert video["fps_estimate"] == 15.0
    assert video["keyframe_interval_frames"] == 3.0
    assert video["parameter_sets"] == {"sps": 2}
    assert video["nal_types"] == {"1": 4, "33": 2, "19": 2}
    assert video["sps"]["width"] == 1920
    assert video["sps_unparsed"] == 0


def test_an_unparsable_sps_is_counted_and_retried_on_the_next() -> None:
    stats = MediaStats()
    stats.frame("h264", START_CODE + b"\x67\x42", 0, keyframe=True, decrypted=False)
    stats.frame("h264", START_CODE + _h264_sps(80, 45), 3000, keyframe=True, decrypted=False)
    stats.frame("h264", START_CODE + b"\x67\x42", 6000, keyframe=True, decrypted=False)
    video = stats.as_dict()["video"]["h264"]  # type: ignore[index]
    assert video["sps_unparsed"] == 1  # once parsed, a later SPS is not read again
    assert video["sps"]["height"] == 720
    assert "keyframe_interval_frames" in video
    assert video["parameter_sets"] == {"sps": 3}


def test_two_frames_give_a_rate() -> None:
    stats = MediaStats()
    for i in range(2):
        stats.frame(
            "h265", START_CODE + bytes([1 << 1, 1]), i * 3000, keyframe=False, decrypted=True
        )
    assert stats.as_dict()["video"]["h265"]["fps_estimate"] == 30.0  # type: ignore[index]


def test_one_frame_gives_no_rate_or_interval() -> None:
    stats = MediaStats()
    stats.frame("h265", START_CODE + bytes([1 << 1, 1]), 0, keyframe=True, decrypted=True)
    video = stats.as_dict()["video"]["h265"]  # type: ignore[index]
    assert "fps_estimate" not in video
    assert "keyframe_interval_frames" not in video
