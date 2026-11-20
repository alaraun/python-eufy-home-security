"""Muxing frames into one MPEG-TS clip (captures, downloads and plays)."""

from __future__ import annotations

import dataclasses

import pytest

from eufy_home_security.p2p.clip import CLIP_CHUNK_BYTES, IncompleteReason, MediaClip, mux_frames
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


async def test_a_play_writes_each_frame_and_a_download_writes_chunks() -> None:
    hevc = VideoCodec.HEVC
    frames = [coded(hevc, keyframe=True), coded(hevc, ms=1040), coded(hevc, ms=1080)]
    for chunk_bytes, writes in ((0, 3), (CLIP_CHUNK_BYTES, 1)):
        chunks: list[bytes] = []

        async def write(chunk: bytes, chunks: list[bytes] = chunks) -> None:
            chunks.append(chunk)

        muxer, _ = await mux_frames(_frames(frames), write, chunk_bytes=chunk_bytes)
        assert (len(chunks), muxer.video_frames) == (writes, 3), chunk_bytes


_WHOLE = MediaClip(
    video_frames=10,
    audio_frames=10,
    keyframes=2,
    bytes_written=1,
    duration_s=1.0,
    width=1,
    height=1,
    resizes=0,
)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({}, None),
        ({"end_frame": True}, None),
        ({"end_frame": False}, IncompleteReason.NO_END_FRAME),
        ({"end_frame": False, "expected_frames": 10}, None),
        ({"end_frame": True, "expected_frames": 11}, IncompleteReason.MISSING_FRAMES),
        ({"end_frame": False, "expected_frames": 11}, IncompleteReason.MISSING_FRAMES),
        ({"expected_frames": 9}, None),
        ({"ended_early": True, "expected_frames": 11}, IncompleteReason.ENDED_EARLY),
        ({"ended_early": True, "end_frame": True}, IncompleteReason.ENDED_EARLY),
    ],
)
def test_a_clip_names_why_it_is_not_whole(
    changes: dict[str, object], reason: IncompleteReason | None
) -> None:
    """A download without the station's end frame is whole only by the record's frame
    count; a count it falls short of, or a cut, is named first."""
    clip = dataclasses.replace(_WHOLE, **changes)  # type: ignore[arg-type]
    assert (clip.incomplete_reason, clip.complete) == (reason, reason is None)
