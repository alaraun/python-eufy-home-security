"""Mux a camera's media frames into one MPEG-TS clip, written out in chunks.

A clip is what a consumer stores as a video file: a stored recording downloaded off the
station's disk (:meth:`~eufy_home_security.station.Station.async_download_recording`)
or a stretch of a live stream (:meth:`~.broadcast.StreamBroadcast.async_capture`). Both
come as :class:`~.media.MediaFrame` sequences; this module muxes them with the same
:class:`~.encoder.StreamEncoder` the live view uses (HEVC and AAC carried untouched,
starting at the first keyframe, following a picture-size change) and hands the bytes to
the consumer's ``write`` coroutine in chunks of :data:`CLIP_CHUNK_BYTES`.

Remuxing the TS into MP4 is the consumer's (Home Assistant has ffmpeg): a stream copy,
no decode.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from .encoder import StreamEncoder
from .media import MediaFrame, MediaKind

__all__ = ["CLIP_CHUNK_BYTES", "CLIP_CONTENT_TYPE", "ClipWriter", "MediaClip"]

#: The MIME type of a clip's bytes.
CLIP_CONTENT_TYPE: Final = "video/mp2t"
#: Muxed bytes are handed to ``write`` in chunks of at least this size (the last one smaller).
CLIP_CHUNK_BYTES: Final = 512 * 1024

type ClipWriter = Callable[[bytes], Awaitable[object]]
"""Receives a clip's muxed bytes in order; awaited before the next chunk is muxed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class MediaClip:
    """What a clip download or capture wrote, and whether it is whole."""

    video_frames: int
    """Video frames written, the first a keyframe."""
    audio_frames: int
    """Audio frames written: the camera's AAC, plus silence before its first frame."""
    keyframes: int
    bytes_written: int
    duration_s: float
    """From the first to the last video frame written, by the camera's stream clock."""
    width: int
    height: int
    """The last video frame's size."""
    resizes: int
    """Picture-size changes the clip carries (a camera's opening ramp, a zoom)."""
    started_at: datetime | None = None
    """When the first frame was recorded: a recording's history ``started_at``, a live
    capture's arrival time of its first keyframe (UTC); None when unknown."""
    device_sn: str | None = None
    record_id: int | None = None
    """The history record a download came from; None for a live capture."""
    expected_frames: int | None = None
    """A download's video frames by the history record (``frame_num``); None when unknown."""
    ended_early: bool = False
    """A live capture whose stream ended before the asked duration."""
    content_type: str = CLIP_CONTENT_TYPE

    @property
    def complete(self) -> bool:
        """Whether the clip holds everything it should: all of a recording's frames
        (when the record counts them), or a live capture's whole duration."""
        if self.ended_early:
            return False
        return self.expected_frames is None or self.video_frames >= self.expected_frames


class _ClipMuxer:
    """Feed frames, collect chunks; :meth:`flush` writes what is left."""

    def __init__(self, write: ClipWriter) -> None:
        self._write = write
        self._encoder = StreamEncoder(
            audio=True, settle=0.0, follow_resize=True, fill_audio=True, tables_every=100
        )
        self._pending = bytearray()
        self.video_frames = 0
        self.audio_frames = 0
        self.keyframes = 0
        self.bytes_written = 0
        self.first_ms: int | None = None
        self.last_ms: int | None = None
        self.width = 0
        self.height = 0

    @property
    def started(self) -> bool:
        return self._encoder.started

    @property
    def resizes(self) -> int:
        return self._encoder.resizes

    async def feed(self, frame: MediaFrame) -> None:
        out = self._encoder.feed(frame)
        if not out.data:
            return
        if frame.kind is MediaKind.VIDEO:
            self.video_frames += 1
            self.keyframes += frame.is_keyframe
            if self.first_ms is None:
                self.first_ms = frame.timestamp_ms
            self.last_ms = frame.timestamp_ms
            self.width, self.height = frame.width, frame.height
        else:
            self.audio_frames += 1
        self._pending += out.data
        if len(self._pending) >= CLIP_CHUNK_BYTES:
            await self.flush()

    async def flush(self) -> None:
        if self._pending:
            chunk = bytes(self._pending)
            self._pending.clear()
            self.bytes_written += len(chunk)
            await self._write(chunk)

    @property
    def duration_s(self) -> float:
        if self.first_ms is None or self.last_ms is None:
            return 0.0
        return max(0, self.last_ms - self.first_ms) / 1000

    def clip(self, *, started_at: datetime | None = None, ended_early: bool = False) -> MediaClip:
        return MediaClip(
            video_frames=self.video_frames,
            audio_frames=self.audio_frames,
            keyframes=self.keyframes,
            bytes_written=self.bytes_written,
            duration_s=self.duration_s,
            width=self.width,
            height=self.height,
            resizes=self.resizes,
            started_at=started_at,
            ended_early=ended_early,
        )


async def mux_frames(
    frames: AsyncIterator[MediaFrame], write: ClipWriter, *, max_ms: int | None = None
) -> tuple[_ClipMuxer, bool]:
    """Mux ``frames`` into ``write`` from the first keyframe on.

    With ``max_ms`` it stops at the first video frame that many milliseconds of stream
    clock after the first keyframe (that frame is not written). Returns the muxer (its
    counters) and whether ``max_ms`` was reached; the rest is flushed either way.
    """
    muxer = _ClipMuxer(write)
    reached = False
    try:
        async for frame in frames:
            if (
                max_ms is not None
                and frame.kind is MediaKind.VIDEO
                and muxer.first_ms is not None
                and frame.timestamp_ms - muxer.first_ms >= max_ms
            ):
                reached = True
                break
            await muxer.feed(frame)
    finally:
        await muxer.flush()
    return muxer, reached
