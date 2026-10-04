"""Turn a live :class:`~.media.MediaFrame` sequence into a muxed MPEG-TS byte stream.

A camera's first seconds change resolution. Measured on real hardware:

* a HomeBase-attached camera opens at the sensor's full resolution and steps *down* to
  the configured streaming quality — 3840x2160 to 2304x1296 in about 0.6 s (no step at
  the 4K quality);
* a standalone battery camera does the opposite, climbing 1280x720 to 1920x1080 to
  2880x1616 over about 8.5 s, each step on a keyframe.

MPEG-TS carries no picture size: the size lives in the in-band VPS/SPS/PPS of each
keyframe. With ``follow_resize=True`` a size change needs only a keyframe at the new
size, so the stream can start at the first keyframe (``settle=0``) and carry the ramp.
Frames between a change and that keyframe reference pictures the decoder never had and
are dropped. With ``follow_resize=False`` :class:`StreamEncoder` waits for the size to
hold still for :attr:`~StreamEncoder.settle`, then starts on the next keyframe, and a
later size change is reported instead.

The PMT is written at the start and consumers pick their tracks from it once, so the
audio decision cannot wait for the camera's audio: ``fill_audio=True`` declares AAC at
the start and carries silent AAC frames until the camera's own audio arrives (see
:class:`StreamEncoder`).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .media import MediaFrame, MediaKind, VideoCodec, ms_to_pts
from .mpegts import TSMuxer

__all__ = [
    "DEFAULT_SETTLE",
    "SETTLE_STANDALONE",
    "SETTLE_STATION",
    "SILENT_AAC_FRAME",
    "EncodedStream",
    "StreamEncoder",
]

#: How long a frame size must hold before the stream starts, in seconds.
#:
#: The two kinds of camera ramp in opposite directions at the start of a stream, so
#: they need different windows: use :data:`SETTLE_STATION` for a camera behind a
#: station and :data:`SETTLE_STANDALONE` for a standalone (battery) camera.
#: :class:`~.broadcast.StreamBroadcast` picks the right one by itself.
DEFAULT_SETTLE = 6.0

SETTLE_STATION = 2.5
"""Settle window for a camera behind a station.

It opens at the sensor's full resolution and steps *down* to the configured streaming
quality within about 0.6 s.
"""

SETTLE_STANDALONE = 6.0
"""Settle window for a standalone (battery) camera.

It opens small and climbs — 1280x720, then 1920x1080, then its full size — taking about
10 s to settle, so it needs the longer window.
"""


SILENT_AAC_FRAME = bytes.fromhex("fff16040017ffc01182007")
"""One ADTS AAC-LC frame of silence, 16 kHz mono: the camera's audio format."""

SILENT_AAC_FRAME_MS = 64
"""Duration of :data:`SILENT_AAC_FRAME` (1024 samples at 16 kHz), in milliseconds."""

_FILL_MAX_CATCH_UP_MS = 1000
"""A video gap longer than this is not back-filled with silence frame by frame."""


@dataclass(frozen=True, slots=True)
class EncodedStream:
    """What :meth:`StreamEncoder.feed` produced for one frame."""

    data: bytes = b""
    """Muxed TS bytes, empty while the stream is still settling."""
    started: bool = False
    """True on the frame that started the stream (``data`` holds its keyframe)."""
    resized: bool = False
    """True when the frame's size differs from the started stream's and the encoder
    does not follow size changes (``follow_resize=False``).

    Once this is reported the encoder is **spent**: it keeps reporting it and muxes no
    further bytes. The caller must build a new encoder (and reconnect its consumers) or
    stop.
    """
    restarted: bool = False
    """True on the keyframe that resumes a followed stream at a new size (``data`` holds
    the tables and that keyframe, the same bytes as :attr:`StreamEncoder.header`)."""


class StreamEncoder:
    """Mux a camera's live frames into MPEG-TS once their size has settled.

    One instance per stream. ``tables_every`` repeats PAT/PMT so a consumer that joins
    mid-stream can tune in; :attr:`header` holds the tables and the opening keyframe for
    exactly that purpose.

    ``follow_resize=True`` keeps a started stream across a size change: the muxer, its
    continuity counters and its clock carry on, video is dropped until the first keyframe
    at the new size, and that keyframe goes out behind fresh tables and becomes the new
    :attr:`header`. Audio keeps flowing through the gap. With ``follow_resize=False`` a
    size change spends the encoder (:attr:`EncodedStream.resized`).

    ``audio=True`` carries the camera's AAC. The PMT is written when the stream starts
    and consumers pick their tracks from it once, so the track must be declared then and
    fed from then on: a declared track with no data makes HA's stream worker fail with
    "Error muxing stream", and a track added by a later PMT version is ignored. Without
    ``fill_audio`` the track is declared only if audio arrived before the start (during
    the settle window). With ``fill_audio=True`` it is always declared, and a silent
    frame (:data:`SILENT_AAC_FRAME`) is muxed every 64 ms of video time until the
    camera's first audio frame; a camera that never sends audio yields a silent track.
    """

    __slots__ = (
        "_audio_seen",
        "_awaiting_keyframe",
        "_clock",
        "_fill_audio",
        "_fill_ms",
        "_follow_resize",
        "_header",
        "_mux",
        "_resizes",
        "_size",
        "_size_since",
        "_started",
        "_tables_every",
        "_video_seen",
        "_want_audio",
        "settle",
    )

    def __init__(
        self,
        *,
        audio: bool = False,
        settle: float = DEFAULT_SETTLE,
        tables_every: int = 10,
        follow_resize: bool = False,
        assume_audio: bool = False,
        fill_audio: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settle = settle
        self._fill_audio = fill_audio
        self._fill_ms: int | None = None
        self._want_audio = audio
        # A camera already known to send audio (a restart of the same camera stream)
        # need not show it again inside the settle window.
        self._audio_seen = assume_audio
        self._tables_every = max(1, tables_every)
        self._follow_resize = follow_resize
        self._clock = clock
        self._mux: TSMuxer | None = None
        self._size: tuple[int, int] | None = None
        self._size_since = 0.0
        self._started = False
        self._awaiting_keyframe = False
        self._resizes = 0
        self._video_seen = 0
        self._header = b""

    @property
    def started(self) -> bool:
        """Whether the stream has settled and begun."""
        return self._started

    @property
    def size(self) -> tuple[int, int] | None:
        """The frame size being muxed, once the stream has started.

        A followed size change updates it at the resuming keyframe.
        """
        return self._size if self._started else None

    @property
    def has_audio(self) -> bool:
        """Whether the started stream declares an audio track."""
        return self._mux is not None and self._mux.has_audio

    @property
    def resizes(self) -> int:
        """How many size changes this stream has followed."""
        return self._resizes

    @property
    def header(self) -> bytes:
        """Tables and the opening keyframe, for a consumer that joins mid-stream."""
        return self._header

    def feed(self, frame: MediaFrame) -> EncodedStream:
        """Offer one frame; returns the bytes to send, if any.

        Audio is carried only once the video track has settled and only if this encoder
        was built with ``audio=True``: the PMT is written when the stream starts and a
        consumer will not re-read it, so a track cannot appear later.
        """
        if frame.kind is MediaKind.AUDIO:
            # Remember that this camera sends audio even before the stream starts: the
            # PMT is written at start and the decision cannot be revisited later.
            self._audio_seen = True
            self._fill_ms = None
            mux = self._mux
            if mux is None or not mux.has_audio:
                return EncodedStream()
            return EncodedStream(data=mux.audio(frame.data, frame.pts))

        now = self._clock()
        size = (frame.width, frame.height)

        if self._started:
            mux = self._mux
            if mux is None:  # pragma: no cover - started implies a muxer
                return EncodedStream()
            if size != self._size or self._awaiting_keyframe:
                if not self._follow_resize:
                    return EncodedStream(resized=True)
                silence = self._silence(mux, frame.timestamp_ms)
                if not frame.is_keyframe:
                    # References pictures the decoder never received: drop until the
                    # keyframe that carries the new size's parameter sets.
                    self._awaiting_keyframe = True
                    return EncodedStream(data=silence)
                self._awaiting_keyframe = False
                if size != self._size:
                    self._size = size
                    self._resizes += 1
                self._video_seen = 0  # the resuming keyframe carries the tables
                data = self._encode(mux, frame)
                self._header = data
                return EncodedStream(data=silence + data, restarted=True)
            silence = self._silence(mux, frame.timestamp_ms)
            return EncodedStream(data=silence + self._encode(mux, frame))

        if size != self._size:
            self._size, self._size_since = size, now
        if now - self._size_since < self.settle or not frame.is_keyframe:
            return EncodedStream()

        # Settled, and this is a keyframe: start here. The audio track is declared if the
        # camera sent audio during the settle window, or with silence until it does.
        declare = self._want_audio and (self._audio_seen or self._fill_audio)
        mux = TSMuxer(frame.codec or VideoCodec.HEVC, audio=declare)
        self._mux = mux
        if declare and not self._audio_seen:
            self._fill_ms = frame.timestamp_ms
        self._started = True
        self._video_seen = 0
        data = self._encode(mux, frame)
        self._header = data
        return EncodedStream(data=data, started=True)

    def _silence(self, mux: TSMuxer, video_ms: int) -> bytes:
        """Silent AAC frames up to ``video_ms`` while the camera's audio has not begun.

        Each frame ends at or before ``video_ms``; the camera's audio arrives no earlier
        than the video it accompanies, so the first real frame does not overlap them.
        """
        fill_ms = self._fill_ms
        if fill_ms is None:
            return b""
        if video_ms < fill_ms or video_ms - fill_ms > _FILL_MAX_CATCH_UP_MS:
            # A clock step or a long video gap: resume the silence from here.
            fill_ms = video_ms - SILENT_AAC_FRAME_MS
        out = b""
        while fill_ms + SILENT_AAC_FRAME_MS <= video_ms:
            out += mux.audio(SILENT_AAC_FRAME, ms_to_pts(fill_ms))
            fill_ms += SILENT_AAC_FRAME_MS
        self._fill_ms = fill_ms
        return out

    def _encode(self, mux: TSMuxer, frame: MediaFrame) -> bytes:
        out = b""
        if self._video_seen % self._tables_every == 0:
            out += mux.tables()
        self._video_seen += 1
        return out + mux.video(frame.data, frame.pts, keyframe=frame.is_keyframe)
