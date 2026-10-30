"""Synthetic video frames of either codec, shared by the encoder and broadcast tests."""

from __future__ import annotations

from eufy_home_security.p2p.media import MediaFrame, MediaKind, VideoCodec

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
