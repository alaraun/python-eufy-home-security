"""Counters and stream properties of an RTC live view, for diagnostics (pure).

:class:`MediaStats` is fed every RTP packet (after SRTP) and every depacketized frame
of a live call. It keeps descriptors only, never payload: per payload type the packet
and byte counts, SSRC count, RTP clock estimate, sequence gaps and the most common
timestamp step; for video the packetization (single NAL, aggregation, fragmentation)
and NAL unit types, then per codec the frame and keyframe counts, frame rate,
keyframe interval, parameter sets seen and what the sequence parameter set declares
(profile, level, resolution); for audio the first bytes of the first packets (a
format header such as ADTS or an AU-header length). The SPS parsers read H.265
(ITU-T H.265 § 7.3.2.2) and H.264 (ITU-T H.264 § 7.3.2.1.1) as far as the picture
size.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from .media import START_CODE, PayloadType, RtpPacket

#: The clock rates an estimate is snapped to: the nearest, when within 10 % of it.
_CLOCK_RATES: Final = (8000, 16000, 22050, 24000, 32000, 44100, 48000, 90000)
#: Audio packets whose first bytes are kept, and how many bytes of each.
AUDIO_HEADS: Final = 4
AUDIO_HEAD_LEN: Final = 4
#: Distinct timestamp steps / NAL types / packetization kinds kept per stream.
_TOP: Final = 6
#: Bounds a plausible picture size must lie in.
_MIN_SIZE: Final = 16
_MAX_SIZE: Final = 8192
#: The 90 kHz RTP video clock.
VIDEO_CLOCK: Final = 90000

_H265_VPS: Final = 32
_H265_SPS: Final = 33
_H265_PPS: Final = 34
_H265_AP: Final = 48
_H265_FU: Final = 49
_H264_SPS: Final = 7
_H264_PPS: Final = 8
_H264_STAP_A: Final = 24
_H264_FU_A: Final = 28
#: H.264 profiles whose SPS carries the chroma format and bit depths.
_H264_HIGH_PROFILES: Final = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134})


class _Bits:
    """An MSB-first reader over an RBSP (emulation-prevention bytes removed)."""

    def __init__(self, data: bytes) -> None:
        self._data = _rbsp(data)
        self._pos = 0

    def u(self, n: int) -> int:
        value = 0
        for _ in range(n):
            byte = self._pos >> 3
            if byte >= len(self._data):
                raise ValueError("SPS truncated")
            value = (value << 1) | ((self._data[byte] >> (7 - (self._pos & 7))) & 1)
            self._pos += 1
        return value

    def ue(self) -> int:
        zeros = 0
        while self.u(1) == 0:
            zeros += 1
            if zeros > 31:
                raise ValueError("SPS exp-Golomb code too long")
        return (1 << zeros) - 1 + self.u(zeros)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


def _rbsp(data: bytes) -> bytes:
    """``data`` without its emulation-prevention bytes (``00 00 03`` → ``00 00``)."""
    out = bytearray()
    zeros = 0
    for byte in data:
        if zeros >= 2 and byte == 3:
            zeros = 0
            continue
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def _plausible(width: int, height: int) -> bool:
    return _MIN_SIZE <= width <= _MAX_SIZE and _MIN_SIZE <= height <= _MAX_SIZE


def parse_h265_sps(nal: bytes) -> dict[str, int] | None:
    """Profile, tier, level, chroma format and picture size of an H.265 SPS NAL unit
    (with its 2-byte header); None when it does not parse to a plausible size."""
    try:
        bits = _Bits(nal[2:])
        bits.u(4)  # sps_video_parameter_set_id
        sub_layers = bits.u(3)
        bits.u(1)  # sps_temporal_id_nesting_flag
        bits.u(2)  # general_profile_space
        tier = bits.u(1)
        profile = bits.u(5)
        bits.u(32)  # general_profile_compatibility_flags
        bits.u(48)  # progressive/interlaced/non-packed/frame-only and reserved flags
        level = bits.u(8)
        present = [(bits.u(1), bits.u(1)) for _ in range(sub_layers)]
        if sub_layers:
            bits.u(2 * (8 - sub_layers))
        for profile_present, level_present in present:
            bits.u(88 * profile_present)
            bits.u(8 * level_present)
        bits.ue()  # sps_seq_parameter_set_id
        chroma = bits.ue()
        if chroma == 3:
            bits.u(1)  # separate_colour_plane_flag
        width, height = bits.ue(), bits.ue()
        if bits.u(1):  # conformance_window_flag
            left, right, top, bottom = bits.ue(), bits.ue(), bits.ue(), bits.ue()
            sub_w = 2 if chroma in (1, 2) else 1
            sub_h = 2 if chroma == 1 else 1
            width -= sub_w * (left + right)
            height -= sub_h * (top + bottom)
    except ValueError:
        return None
    if not _plausible(width, height):
        return None
    return {
        "profile_idc": profile,
        "tier": tier,
        "level_idc": level,
        "chroma_format_idc": chroma,
        "width": width,
        "height": height,
    }


def _skip_scaling_list(bits: _Bits, size: int) -> None:
    last = following = 8
    for _ in range(size):
        if following:
            following = (last + bits.se() + 256) % 256
        last = following or last


def parse_h264_sps(nal: bytes) -> dict[str, int] | None:
    """Profile, level, chroma format and picture size of an H.264 SPS NAL unit (with
    its 1-byte header); None when it does not parse to a plausible size."""
    try:
        bits = _Bits(nal[1:])
        profile = bits.u(8)
        constraints = bits.u(8)
        level = bits.u(8)
        bits.ue()  # seq_parameter_set_id
        chroma = 1
        if profile in _H264_HIGH_PROFILES:
            chroma = bits.ue()
            if chroma == 3:
                bits.u(1)  # separate_colour_plane_flag
            bits.ue()  # bit_depth_luma_minus8
            bits.ue()  # bit_depth_chroma_minus8
            bits.u(1)  # qpprime_y_zero_transform_bypass_flag
            if bits.u(1):  # seq_scaling_matrix_present_flag
                for i in range(12 if chroma == 3 else 8):
                    if bits.u(1):
                        _skip_scaling_list(bits, 16 if i < 6 else 64)
        bits.ue()  # log2_max_frame_num_minus4
        poc_type = bits.ue()
        if poc_type == 0:
            bits.ue()  # log2_max_pic_order_cnt_lsb_minus4
        elif poc_type == 1:
            bits.u(1)  # delta_pic_order_always_zero_flag
            bits.se()  # offset_for_non_ref_pic
            bits.se()  # offset_for_top_to_bottom_field
            for _ in range(bits.ue()):
                bits.se()
        bits.ue()  # max_num_ref_frames
        bits.u(1)  # gaps_in_frame_num_value_allowed_flag
        width_mbs, height_units = bits.ue() + 1, bits.ue() + 1
        frame_mbs_only = bits.u(1)
        if not frame_mbs_only:
            bits.u(1)  # mb_adaptive_frame_field_flag
        bits.u(1)  # direct_8x8_inference_flag
        width = width_mbs * 16
        height = (2 - frame_mbs_only) * height_units * 16
        if bits.u(1):  # frame_cropping_flag
            left, right, top, bottom = bits.ue(), bits.ue(), bits.ue(), bits.ue()
            unit_x = 2 if chroma in (1, 2) else 1
            unit_y = (2 if chroma == 1 else 1) * (2 - frame_mbs_only)
            width -= unit_x * (left + right)
            height -= unit_y * (top + bottom)
    except ValueError:
        return None
    if not _plausible(width, height):
        return None
    return {
        "profile_idc": profile,
        "constraint_flags": constraints,
        "level_idc": level,
        "chroma_format_idc": chroma,
        "width": width,
        "height": height,
    }


def _nal_type(codec: str, nal: bytes) -> int:
    return (nal[0] >> 1) & 0x3F if codec == "h265" else nal[0] & 0x1F


def _snap_clock(rate: float) -> int:
    known = min(_CLOCK_RATES, key=lambda k: abs(rate - k) / k)
    return known if abs(rate - known) <= known * 0.1 else round(rate)


def _top(counter: Counter[int] | Counter[str]) -> dict[str, int]:
    return {str(key): count for key, count in counter.most_common(_TOP)}


@dataclass(slots=True)
class _Stream:
    """One RTP payload type's counters."""

    packets: int = 0
    bytes: int = 0
    markers: int = 0
    ssrcs: set[int] = field(default_factory=set)
    first_ts: int | None = None
    last_ts: int = 0
    first_at: float = 0.0
    last_at: float = 0.0
    next_seq: int | None = None
    seq_gaps: int = 0
    steps: Counter[int] = field(default_factory=Counter)
    packetization: Counter[str] = field(default_factory=Counter)
    nal_types: Counter[int] = field(default_factory=Counter)
    heads: list[str] = field(default_factory=list)

    def add(self, packet: RtpPacket, now: float) -> None:
        self.packets += 1
        self.bytes += len(packet.payload)
        self.markers += packet.marker
        if len(self.ssrcs) < _TOP:
            self.ssrcs.add(packet.ssrc)
        if self.next_seq is not None and packet.sequence != self.next_seq:
            self.seq_gaps += 1
        self.next_seq = (packet.sequence + 1) & 0xFFFF
        if self.first_ts is None:
            self.first_ts, self.first_at = packet.timestamp, now
        else:
            step = (packet.timestamp - self.last_ts) & 0xFFFFFFFF
            if step and len(self.steps) < 4 * _TOP:
                self.steps[step] += 1
        self.last_ts, self.last_at = packet.timestamp, now

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "packets": self.packets,
            "bytes": self.bytes,
            "markers": self.markers,
            "ssrcs": len(self.ssrcs),
            "seq_gaps": self.seq_gaps,
            "timestamp_steps": _top(self.steps),
        }
        span = self.last_at - self.first_at
        if self.first_ts is not None and span >= 1.0:
            ticks = (self.last_ts - self.first_ts) & 0xFFFFFFFF
            out["clock_rate_estimate"] = _snap_clock(ticks / span)
        if self.packetization:
            out["packetization"] = _top(self.packetization)
            out["nal_types"] = _top(self.nal_types)
        if self.heads:
            out["first_bytes_hex"] = list(self.heads)
        return out


@dataclass(slots=True)
class _Video:
    """One codec's frame counters."""

    frames: int = 0
    keyframes: int = 0
    decrypted: int = 0
    first_ts: int | None = None
    last_ts: int = 0
    key_indexes: list[int] = field(default_factory=list)
    nal_types: Counter[int] = field(default_factory=Counter)
    parameter_sets: Counter[str] = field(default_factory=Counter)
    sps: dict[str, int] | None = None
    sps_unparsed: int = 0

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "frames": self.frames,
            "keyframes": self.keyframes,
            "decrypted": self.decrypted,
            "nal_types": _top(self.nal_types),
            "parameter_sets": dict(self.parameter_sets),
            "sps": self.sps,
            "sps_unparsed": self.sps_unparsed,
        }
        if self.first_ts is not None and self.frames > 1:
            ticks = (self.last_ts - self.first_ts) & 0xFFFFFFFF
            if ticks:
                out["fps_estimate"] = round((self.frames - 1) * VIDEO_CLOCK / ticks, 1)
        if len(self.key_indexes) > 1:
            gaps = [b - a for a, b in zip(self.key_indexes, self.key_indexes[1:], strict=False)]
            out["keyframe_interval_frames"] = round(sum(gaps) / len(gaps), 1)
        return out


class MediaStats:
    """Descriptors of the packets and frames of one live view (see the module doc)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._streams: dict[int, _Stream] = {}
        self._video: dict[str, _Video] = {}

    def packet(self, packet: RtpPacket) -> None:
        """Count one RTP packet (after SRTP)."""
        stream = self._streams.setdefault(packet.payload_type, _Stream())
        stream.add(packet, self._clock())
        payload = packet.payload
        if packet.payload_type == PayloadType.AUDIO:
            if len(stream.heads) < AUDIO_HEADS:
                stream.heads.append(payload[:AUDIO_HEAD_LEN].hex())
        elif packet.payload_type == PayloadType.H265 and len(payload) >= 2:
            self._h265_packet(stream, payload)
        elif packet.payload_type == PayloadType.H264 and payload:
            self._h264_packet(stream, payload)

    @staticmethod
    def _h265_packet(stream: _Stream, payload: bytes) -> None:
        kind = _nal_type("h265", payload)
        if kind == _H265_AP:
            stream.packetization["aggregation"] += 1
            offset = 2
            while offset + 3 <= len(payload):
                size = int.from_bytes(payload[offset : offset + 2], "big")
                stream.nal_types[_nal_type("h265", payload[offset + 2 :])] += 1
                offset += 2 + max(size, 1)
        elif kind == _H265_FU:
            stream.packetization["fragment"] += 1
            if len(payload) > 2 and payload[2] & 0x80:
                stream.nal_types[payload[2] & 0x3F] += 1
        else:
            stream.packetization["single"] += 1
            stream.nal_types[kind] += 1

    @staticmethod
    def _h264_packet(stream: _Stream, payload: bytes) -> None:
        kind = _nal_type("h264", payload)
        if kind == _H264_STAP_A:
            stream.packetization["aggregation"] += 1
            offset = 1
            while offset + 3 <= len(payload):
                size = int.from_bytes(payload[offset : offset + 2], "big")
                stream.nal_types[_nal_type("h264", payload[offset + 2 :])] += 1
                offset += 2 + max(size, 1)
        elif kind == _H264_FU_A:
            stream.packetization["fragment"] += 1
            if len(payload) > 1 and payload[1] & 0x80:
                stream.nal_types[payload[1] & 0x1F] += 1
        else:
            stream.packetization["single"] += 1
            stream.nal_types[kind] += 1

    def frame(
        self, codec: str, data: bytes, timestamp: int, *, keyframe: bool, decrypted: bool
    ) -> None:
        """Count one Annex B frame of ``codec`` (``h265`` or ``h264``); ``decrypted``
        says whether its in-frame encryption was removed."""
        video = self._video.setdefault(codec, _Video())
        if video.first_ts is None:
            video.first_ts = timestamp
        video.last_ts = timestamp
        if keyframe:
            video.keyframes += 1
            video.key_indexes.append(video.frames)
        video.frames += 1
        video.decrypted += decrypted
        sps_type, names = (
            (_H265_SPS, {_H265_VPS: "vps", _H265_SPS: "sps", _H265_PPS: "pps"})
            if codec == "h265"
            else (_H264_SPS, {_H264_SPS: "sps", _H264_PPS: "pps"})
        )
        for nal in data.split(START_CODE):
            if not nal:
                continue
            kind = _nal_type(codec, nal)
            video.nal_types[kind] += 1
            if kind in names:
                video.parameter_sets[names[kind]] += 1
            if kind == sps_type and video.sps is None:
                video.sps = parse_h265_sps(nal) if codec == "h265" else parse_h264_sps(nal)
                video.sps_unparsed += video.sps is None

    def as_dict(self) -> dict[str, object]:
        """The counters, keyed by RTP payload type (``rtp``) and codec (``video``)."""
        return {
            "rtp": {str(pt): s.as_dict() for pt, s in sorted(self._streams.items())},
            "video": {codec: v.as_dict() for codec, v in sorted(self._video.items())},
        }
