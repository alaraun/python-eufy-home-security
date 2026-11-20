"""Synthetic video frames of either codec, shared by the encoder and broadcast tests."""

from __future__ import annotations

from eufy_home_security.p2p.media import MediaFrame, MediaKind, VideoCodec
from eufy_home_security.p2p.mpegts import TS_PACKET_LEN, VIDEO_PID

SC = b"\x00\x00\x00\x01"
#: Synthetic access units per codec: a keyframe (parameter sets + IRAP/IDR) and a P-frame,
#: each with a payload marker the tests look for in the muxed output.
UNITS = {
    VideoCodec.HEVC: (
        SC + b"\x40\x01\x0c" + SC + b"\x42\x01\x01" + SC + b"\x26\x01hevc-key",
        SC + b"\x02\x01hevc-p",
    ),
    VideoCodec.H264: (
        SC + b"\x67\x42\x00\x1f" + SC + b"\x68\xce\x3c\x80" + SC + b"\x65h264-key",
        SC + b"\x41\x9ah264-p",
    ),
}
SWITCHES = [(VideoCodec.HEVC, VideoCodec.H264), (VideoCodec.H264, VideoCodec.HEVC)]


def coded(
    codec: VideoCodec | None,
    *,
    keyframe: bool = False,
    ms: int = 1000,
    size: tuple[int, int] = (1600, 2300),
    units: VideoCodec | None = None,
) -> MediaFrame:
    """A video frame of ``codec`` whose bytes are that codec's synthetic unit."""
    body = UNITS[units or codec or VideoCodec.HEVC][0 if keyframe else 1]
    return MediaFrame(
        MediaKind.VIDEO,
        body,
        is_keyframe=keyframe,
        timestamp_ms=ms,
        codec=codec,
        width=size[0],
        height=size[1],
    )


def video_pes_payloads(ts: bytes) -> list[bytes]:
    """The elementary-stream bytes of each video PES in a muxed TS, in order."""
    pes: list[bytearray] = []
    for at in range(0, len(ts), TS_PACKET_LEN):
        packet = ts[at : at + TS_PACKET_LEN]
        if ((packet[1] & 0x1F) << 8 | packet[2]) != VIDEO_PID or not packet[3] & 0x10:
            continue
        offset = 4 + (1 + packet[4] if packet[3] & 0x20 else 0)
        if packet[1] & 0x40:  # payload_unit_start: a new PES
            pes.append(bytearray())
        if pes:
            pes[-1] += packet[offset:]
    return [bytes(unit[9 + unit[8] :]) for unit in pes]


def readable_nal_units(access_unit: bytes, codec: VideoCodec) -> list[bytes]:
    """The NAL units a consumer that reads only the units after a start code takes from
    one access unit: bytes before the first start code and access unit delimiters are
    skipped, and an empty unit counts for nothing."""
    starts = []
    at = access_unit.find(b"\x00\x00\x01")
    while at >= 0:
        starts.append(at)
        at = access_unit.find(b"\x00\x00\x01", at + 3)
    units = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(access_unit)
        unit = access_unit[start + 3 : end]
        if i + 1 < len(starts) and unit.endswith(b"\x00"):
            unit = unit[:-1]  # the leading zero of a four-byte start code
        if not unit:
            continue
        nal_type = (unit[0] >> 1) & 0x3F if codec is VideoCodec.HEVC else unit[0] & 0x1F
        if nal_type != (35 if codec is VideoCodec.HEVC else 9):  # not an AUD
            units.append(unit)
    return units
