"""Muxing frames into one MPEG-TS clip (captures and downloads)."""

from __future__ import annotations

from eufy_home_security.p2p.clip import mux_frames
from eufy_home_security.p2p.media import MediaFrame, VideoCodec
from tests.p2p.codec_frames import coded


async def _frames(frames: list[MediaFrame]):  # type: ignore[no-untyped-def]
    for frame in frames:
        yield frame


async def _clip(frames: list[MediaFrame]) -> tuple[bool, bool, VideoCodec | None]:
    async def write(chunk: bytes) -> None:
        pass

    muxer, _ = await mux_frames(_frames(frames), write)
    clip = muxer.clip()
    return clip.ended_early, clip.complete, clip.codec


async def test_a_clip_cut_at_a_codec_change_ended_early() -> None:
    """A download across a codec change keeps the first codec and is not complete."""
    hevc, h264 = VideoCodec.HEVC, VideoCodec.H264
    frames = [coded(hevc, keyframe=True), coded(hevc, ms=1066), coded(h264, keyframe=True, ms=1133)]
    assert await _clip(frames) == (True, False, hevc)
    assert await _clip(frames[:2]) == (False, True, hevc), "one codec: complete"
