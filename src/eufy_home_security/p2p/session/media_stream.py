"""One open camera stream of a station session (:class:`MediaStream`)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol, cast

from ..._logging import LogThrottle, Secret
from ...exceptions import (
    CommandNotAppliedError,
    DeviceTimeoutError,
    EufySecurityError,
    ProtocolError,
    UnsupportedError,
)
from ..media import (
    ANNEX_B_STARTS,
    KEYFRAME_MIN,
    KEYFRAME_RSA_LEN,
    SHAPE_HEAD_LEN,
    VIDEO_HEADER_LEN,
    MediaDecoder,
    MediaFrame,
    MediaKind,
    MediaRecordShape,
    VideoCodec,
    VideoVariant,
    _ForeignKeyframeError,
    drop_empty_nals,
    keyframe_layout_probe,
    picture_codec,
    video_codec_label,
    video_header_ms,
    video_record_is_key,
    video_record_shape,
    video_variant,
)
from ..messages import CMD_START_REALTIME_MEDIA
from ..xzyh import FrameType
from .stats import MEDIA_SHAPE_RECORDS, MediaCounters, count_capped
from .wake import WakeBackoff

if TYPE_CHECKING:
    from .media_slot import MediaSlot

_LOGGER = logging.getLogger(__name__)

MEDIA_QUEUE_FRAMES = 250
"""Frames (video and audio together) held for a slow reader before new ones are dropped."""

MEDIA_OTHER_CAMERA_FRAMES = 25
"""A live stream fails when this many frames of another camera arrive before its own."""


def wrapped_key(payload: bytes) -> bytes | None:
    """The RSA-wrapped key bytes of a keyframe record, None when the body cannot hold one."""
    if len(payload) < VIDEO_HEADER_LEN:
        return None
    body = payload[VIDEO_HEADER_LEN : VIDEO_HEADER_LEN + KEYFRAME_RSA_LEN]
    data_len = int.from_bytes(payload[:4], "little")
    return body if data_len >= KEYFRAME_MIN and len(body) == KEYFRAME_RSA_LEN else None


class MediaStream:
    """One open camera stream: iterate it for :class:`~..media.MediaFrame`, close it to stop.

    Video and audio start at a keyframe, because the frames before one reference
    pictures the reader never saw. Each video frame is held until the next video record,
    as the app's player holds it: a record that does not start with a start code is the
    rest of that picture and is joined to it (a HomeBase 2 camera splits a large frame
    into several records); any other video record of the stream sends the held frame
    out. Empty NAL units are removed from the joined frame. A keyframe-flagged part joins
    a held keyframe only; after another frame it is a keyframe that did not decode. A part
    whose frame already went out (audio filled the hold) is dropped and video is skipped
    to the next keyframe, so no delivered video frame lacks a start code. Audio arriving
    meanwhile is queued behind the held frame, and records dropped before decoding
    (another camera's, another stream's) leave it held, so a frame waits for the next
    decoded video record. When video is lost while a P-frame is held, the P-frame may
    miss its rest and is dropped with the video up to the next keyframe; a held keyframe
    is kept. A frame no video record follows is delivered when the stream ends, by the
    station's end-of-playback frame or at ``idle_timeout``, after which :attr:`ended` is
    True (:attr:`end_frame` tells which). When a slow reader lets
    :data:`MEDIA_QUEUE_FRAMES` pile up, video is dropped until the next keyframe
    (counted in :attr:`dropped`); after a keyframe that does not decode, a frame with no
    NAL unit or a part whose frame already went out, video is skipped to the next keyframe
    (counted in :attr:`skipped`), so whatever is delivered still decodes.
    The first keyframe that decodes pins the stream's wrapped key: a later keyframe
    wrapped differently belongs to another (earlier) stream and is dropped. Before that,
    a keyframe that does not decode under this stream's RSA key is dropped at DEBUG as
    another stream's; only when none decodes by ``first_frame_timeout`` is it a WARNING.

    Iteration ends when the stream is closed, when the station sends a recording's
    end-of-playback frame (``0x0402`` = 2, after the frames already queued), when a
    download's end-of-download frame (``0x0518``) came and no media followed for the
    session's drain gap, or when it stays quiet for ``idle_timeout`` after a frame (the
    fallback; the held frame and the frames already queued are delivered first). It raises when the session is lost,
    when the station rejects the open, or when no keyframe decodes within
    ``first_frame_timeout``. Closing sends the stop command, which only a live stream has.
    """

    def __init__(
        self,
        session: StreamOwner,
        *,
        command: int,
        channel: int,
        decoder: MediaDecoder,
        stop_body: Callable[[], tuple[int, bytes]] | None,
        first_frame_timeout: float,
        idle_timeout: float,
    ) -> None:
        self.command = command
        self.channel = channel
        self.dropped = 0
        """Frames discarded because the reader fell behind."""
        self.skipped = 0
        """Video frames discarded while waiting for a keyframe after one that did not
        decode, a frame with no NAL unit, a lost record or a part whose frame already went
        out (not reader lag)."""
        self.other_camera_frames = 0
        """Live frames discarded because they carried another camera's channel."""
        self._session = session
        self._decoder = decoder
        self._stop_body = stop_body
        self._first_frame_timeout = first_frame_timeout
        self._idle_timeout = idle_timeout
        self._frames: deque[MediaFrame] = deque()
        self._wake = asyncio.Event()
        self._error: Exception | None = None
        self._closed = False
        self._ended = False
        self._end_frame = False
        self._opened_at = time.monotonic()
        self._last_rx: float | None = None
        """When the last media record arrived, decodable or not (liveness)."""
        self._need_keyframe = True
        self._lagging = False
        """Whether the current wait for a keyframe is the reader's lag (:attr:`dropped`)."""
        self._started = False
        self._wrapped_key: bytes | None = None
        """The RSA-wrapped key of the first keyframe that decoded (pinned)."""
        self._foreign_keyframes = 0
        """Keyframes dropped before the first one because they did not decode for this
        stream's key."""
        self._open_index: int | None = None
        self._open_frame_type: int | None = None
        """The frame type the open went out as (its receipt comes back as that type)."""
        self._throttle = LogThrottle()
        self._shapes: list[MediaRecordShape] = []
        """The first :data:`MEDIA_SHAPE_RECORDS` video records' shapes (diagnostics)."""
        session._media_counters.first_records = self._shapes
        self._head = b""
        self._probe = ""
        self._codec: VideoCodec | None = None
        """The codec the stream's last keyframe picture showed (:func:`~..media.picture_codec`),
        or its header named when the picture showed none and the header changed."""
        self._key_codec: VideoCodec | None = None
        """The codec the last keyframe went out as."""
        self._key_header: VideoCodec | None = None
        """The codec the last keyframe's video header named."""
        self._held: MediaFrame | None = None
        """The latest video frame, not yet queued: a continuation record may follow."""
        self._held_parts: list[bytes] = []
        self._held_audio: list[MediaFrame] = []
        """Audio that arrived while a video frame was held, queued after it."""
        self._last_video_at: float | None = None
        """When the previous video record arrived (diagnostics)."""
        self._last_video_outcome: str | None = None
        """What the stream did with the previous video record (diagnostics)."""
        self._last_key_ms: int | None = None
        """The header time of the latest keyframe that decoded."""

    @property
    def closed(self) -> bool:
        """Whether the stream has ended, failed or was closed; after its end or a failure,
        the frames already queued (the held last frame included) are still read."""
        return self._closed

    @property
    def ended(self) -> bool:
        """Whether the stream ended by itself: the station's end-of-playback frame or
        ``idle_timeout`` without a record. Frames read from then on were queued or held
        when it ended; a live stream has only its held last frame and the audio behind it
        then. False for a stream the client closed or that failed."""
        return self._ended

    @property
    def end_frame(self) -> bool:
        """Whether the station's end frame ended the stream: end of playback (0x0402) or
        end of download (0x0518); False when it went quiet for ``idle_timeout``, failed or
        was closed."""
        return self._end_frame

    def __aiter__(self) -> MediaStream:
        return self

    async def __anext__(self) -> MediaFrame:
        while True:
            if self._frames:
                return self._frames.popleft()
            if self._error is not None:
                error, self._error = self._error, None
                raise error
            now = time.monotonic()
            if self._closed:
                raise StopAsyncIteration
            if not self._started:
                remaining = self._opened_at + self._first_frame_timeout - now
            else:
                remaining = cast(float, self._last_rx) + self._idle_timeout - now
            if remaining <= 0:
                if self._held is not None:
                    # Quiet for the idle wait: nothing more can join the held frame.
                    _LOGGER.debug(
                        "media (cmd %d ch%d) quiet for %.1fs; delivering its last frame",
                        self.command,
                        self.channel,
                        self._idle_timeout,
                    )
                    self._finish()
                    continue
                await self.aclose()
                if self._started:
                    raise StopAsyncIteration
                if self._foreign_keyframes:
                    _LOGGER.warning(
                        "media (cmd %d ch%d): no keyframe decoded within %.0fs; "
                        "%d keyframe(s) not wrapped for this stream's key were dropped",
                        self.command,
                        self.channel,
                        self._first_frame_timeout,
                        self._foreign_keyframes,
                    )
                if self._last_rx is not None:
                    timed_out: EufySecurityError = ProtocolError(
                        f"media for command {self.command} arrived, but no keyframe decoded "
                        f"within {self._first_frame_timeout:.0f}s"
                    )
                else:
                    indices = [] if self._open_index is None else [self._open_index]
                    timed_out = self._session._unanswered_error(self.command, 0, indices)
                self._session._media_slot.count_failure(timed_out, self.channel)
                raise timed_out
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), remaining)

    async def __aenter__(self) -> MediaStream:
        return self

    def _expired(self, now: float) -> bool:
        """Whether this stream should be released even though nobody is reading it.

        Two ways a stream ends up unread. Its own deadlines are evaluated in
        :meth:`__anext__`, so a stream nobody iterates never notices them — that covers
        a station that went quiet. A station that keeps sending is the other case: the
        queue fills, every frame is dropped, and the deadlines never fire because
        frames keep arriving. Both mean the slot is held for nothing.
        """
        if self._closed:
            return False
        if len(self._frames) >= MEDIA_QUEUE_FRAMES and self.dropped:
            return True
        if not self._started:
            return now >= self._opened_at + self._first_frame_timeout
        return now >= cast(float, self._last_rx) + self._idle_timeout

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Stop the stream at the station and release the session (idempotent). Frames
        not read yet are discarded, also those its end left queued."""
        closing = not self._closed
        if closing:
            self._log_summary()
            self._closed = True
        self._frames.clear()
        self._held = None
        self._held_audio = []
        self._wake.set()
        if closing:
            self._session._media_slot.detach(self)

    def _log_summary(self) -> None:
        """The stream's end-of-stream line, once: how long it ran and what it lost."""
        _LOGGER.debug(
            "%s: media (cmd %d ch%d) closed after %.1fs; %d frame(s) dropped for a slow "
            "reader, %d skipped waiting for a keyframe",
            self._session._log_name,
            self.command,
            self.channel,
            time.monotonic() - self._opened_at,
            self.dropped,
            self.skipped,
        )

    def _feed(
        self,
        frame_type: int,
        payload: bytes,
        camera: int | None = None,
        subheader: bytes | None = None,
    ) -> None:
        if self._closed:
            return
        self._head = b""
        self._probe = ""
        is_video = frame_type == FrameType.VIDEO_FRAME
        now = time.monotonic()
        previous_at, previous = self._last_video_at, self._last_video_outcome
        if is_video:
            self._last_video_at = now
        outcome = self._take(frame_type, payload, camera, subheader)
        if not is_video:
            return
        self._last_video_outcome = outcome
        counters = self._session._media_counters
        rejected = outcome == "not_annex_b"
        if len(self._shapes) >= MEDIA_SHAPE_RECORDS and not rejected:
            return
        shape = video_record_shape(
            payload, subheader, outcome=outcome, head=self._head, probe=self._probe
        )
        if len(self._shapes) < MEDIA_SHAPE_RECORDS:
            self._shapes.append(shape)
        if rejected:
            since = None
            if self._last_key_ms is not None and len(payload) >= VIDEO_HEADER_LEN:
                since = video_header_ms(payload) - self._last_key_ms
            counters.keyframes_rejected += 1
            counters.rejected_keyframe = replace(
                shape,
                since_keyframe_ms=since,
                channel=self.channel,
                gap_ms=None if previous_at is None else round((now - previous_at) * 1000),
                previous_outcome=previous,
            )

    def _take(  # noqa: C901
        self,
        frame_type: int,
        payload: bytes,
        camera: int | None,
        subheader: bytes | None,
    ) -> str:
        """Queue the frame a media record carries, or drop it; returns what was done
        (:attr:`~..media.MediaRecordShape.outcome`)."""
        # Without a subheader the record's protection follows its keyframe flag.
        is_video = frame_type == FrameType.VIDEO_FRAME
        if (
            self.command == CMD_START_REALTIME_MEDIA
            and self._session.tags_live_camera
            and camera not in (None, self.channel)
        ):
            self._other_camera_frame(camera, is_video)
            return "other_camera"
        self._last_rx = time.monotonic()
        variant = video_variant(subheader) if is_video and subheader else None
        if variant is not None and not self._decoder.decodes(variant):
            self._undecodable_video(variant)
            return "undecodable"
        # Decide what to drop before decoding: a keyframe unwrap and its copies are
        # the expensive part, and they are wasted on a frame that is thrown away.
        if len(self._frames) >= MEDIA_QUEUE_FRAMES:
            if is_video and not self._need_keyframe:
                self._lagging = True
            if is_video:
                self._need_keyframe = True
                self._drop_held_pframe()
            if self._started:
                self.dropped += 1
                self._session._media_counters.dropped_for_reader += 1
            return "queue_full"
        is_key = is_video and video_record_is_key(payload, variant)
        # An ECC record without the keyframe flag is told only after its decrypt.
        if is_video and self._need_keyframe and not is_key and variant is not VideoVariant.ECC:
            self._skip_to_keyframe()
            return "waiting_keyframe"
        if not is_video and not self._started:
            return "waiting_keyframe"  # audio before the first picture: tracks out of step
        carries_key = is_key and variant in (None, VideoVariant.RSA_PREFIX)
        wrapped = wrapped_key(payload) if carries_key else None
        if wrapped is not None and self._wrapped_key not in (None, wrapped):
            # Another stream's keyframe. Dropping it leaves this stream's GOP intact,
            # so the need for a keyframe is not re-armed.
            if self._throttle.should_log("foreign-keyframe"):
                _LOGGER.debug("dropping a keyframe wrapped to another stream's key")
            return "foreign_key"
        outcome = "foreign_key"
        try:
            frame = self._decoder.decode(frame_type, payload, subheader)
            part = False
            if frame is not None and frame.kind is MediaKind.VIDEO:
                part = not frame.data.startswith(ANNEX_B_STARTS)
                if part and self._joins_held(frame):
                    self._continue_held(frame)
                    return "continuation"
                self._release_held()  # any other decoded video record ends the hold
            if part and frame is not None and frame.is_keyframe:
                outcome = "not_annex_b"
                self._head = frame.data[:SHAPE_HEAD_LEN]
                self._probe = keyframe_layout_probe(
                    self._decoder.aes_key, payload[VIDEO_HEADER_LEN:]
                )
                raise _ForeignKeyframeError("keyframe did not decrypt to Annex-B")
        except _ForeignKeyframeError as err:
            self._need_keyframe = True  # the P-frames after it would not decode
            self._lagging = False
            self._drop_held_pframe()  # nothing can join it while video waits for a keyframe
            if not self._started:
                # Nothing pinned yet: most likely a keyframe of the previous stream. A
                # stream that never decodes one is reported at the first-frame timeout.
                self._foreign_keyframes += 1
                if self._throttle.should_log("foreign-keyframe-unpinned"):
                    _LOGGER.debug(
                        "dropping a keyframe not wrapped for this stream's key "
                        "(before its first keyframe): %s",
                        err,
                    )
                return outcome
            # Past the pinned-key check, so wrapped like this stream's keyframes: corrupt.
            if self._throttle.should_log(("bad-media", frame_type)):
                _LOGGER.warning("undecodable media frame 0x%04x: %s", frame_type, err)
            return outcome
        except ProtocolError as err:
            if is_video:
                self._need_keyframe = True  # the P-frames after it would not decode
                self._lagging = False
                self._drop_held_pframe()
            if self._throttle.should_log(("bad-media", frame_type)):
                _LOGGER.warning("undecodable media frame 0x%04x: %s", frame_type, err)
            return "error"
        if frame is None:
            return "undecodable"
        self._head = frame.data[:SHAPE_HEAD_LEN]
        if frame.kind is MediaKind.VIDEO and self._need_keyframe and not frame.is_keyframe:
            self._skip_to_keyframe()
            return "waiting_keyframe"
        if part:
            self._drop_part()
            return "part_dropped"
        if frame.kind is MediaKind.VIDEO:
            checked = self._checked_video(frame)
            if checked is None:
                return "no_nal"
            frame = checked
        if (
            frame.kind is MediaKind.VIDEO
            and frame.codec is None
            and self._throttle.should_log("unknown-codec")
        ):
            _LOGGER.warning(
                "video header names codec %s, which the library does not know; "
                "a muxer that needs a codec assumes HEVC",
                video_codec_label(payload),
            )
        if frame.is_keyframe:
            if not self._started:
                _LOGGER.debug(
                    "first keyframe after %.1fs (cmd %d); stream AES key %s",
                    time.monotonic() - self._opened_at,
                    self.command,
                    Secret(self._decoder.aes_key),
                )
            self._need_keyframe = False
            self._lagging = False
            if not self._started and self.command == CMD_START_REALTIME_MEDIA:
                self._session._wake_backoff.failures.pop(self.channel, None)
            self._started = True
            if self._wrapped_key is None:
                self._wrapped_key = wrapped
        if (
            frame.kind is MediaKind.AUDIO
            and self._held is not None
            and len(self._held_audio) < MEDIA_QUEUE_FRAMES
        ):
            self._held_audio.append(frame)  # a video record ends the hold, not audio
            return "frame"
        self._release_held()
        if frame.kind is MediaKind.VIDEO:
            self._held, self._held_parts = frame, [frame.data]
            if not frame.is_keyframe:
                return "frame"
            self._last_key_ms = frame.timestamp_ms
            return "keyframe"
        self._frames.append(frame)
        self._wake.set()
        return "frame"

    def _skip_to_keyframe(self) -> None:
        """Count a video frame dropped while the stream waits for a keyframe, as reader
        lag or as skipped after a frame that did not decode."""
        if not self._started:
            return
        counters = self._session._media_counters
        if self._lagging:
            self.dropped += 1
            counters.dropped_for_reader += 1
        else:
            self.skipped += 1
            counters.skipped_for_keyframe += 1

    def _joins_held(self, part: MediaFrame) -> bool:
        """Whether a video record that does not start with a start code is the rest of
        the held frame: one is held, no video was lost since, and a keyframe-flagged
        part follows a keyframe."""
        held = self._held
        return (
            held is not None
            and not self._need_keyframe
            and (held.is_keyframe or not part.is_keyframe)
        )

    def _continue_held(self, part: MediaFrame) -> None:
        """Join a record that does not start with a start code to the held frame: the
        rest of its picture."""
        counters = self._session._media_counters
        if part.is_keyframe:
            counters.keyframe_continuations += 1
        else:
            counters.pframes_without_start_code += 1
        self._held_parts.append(part.data)

    def _drop_held_pframe(self) -> None:
        """Drop a held P-frame when video is lost: the lost record may be its rest. The
        audio held behind it is queued; a held keyframe is kept."""
        held = self._held
        if held is None or held.is_keyframe:
            return
        self._held, self._held_parts = None, []
        self._frames.extend(self._held_audio)
        self._held_audio = []
        self._wake.set()
        self._skip_to_keyframe()

    def _drop_part(self) -> None:
        """Drop a non-keyframe record without a start code whose frame already went out,
        and skip video to the next keyframe: the frames after it reference its picture."""
        self._session._media_counters.pframes_without_start_code += 1
        self._need_keyframe = True
        self._skip_to_keyframe()
        if self._throttle.should_log("part-dropped"):
            _LOGGER.debug(
                "media (cmd %d ch%d): dropping a video record without a start code whose "
                "frame already went out",
                self.command,
                self.channel,
            )

    def _release_held(self) -> None:
        """Queue the held video frame, joined with its continuation parts and without
        empty NAL units, then the audio that arrived while it was held."""
        held = self._held
        if held is None:
            return
        self._held = None
        joined = b"".join(self._held_parts)
        self._held_parts = []
        data, empty = drop_empty_nals(joined)
        self._session._media_counters.empty_nals += empty
        if data is not held.data:
            held = replace(held, data=data)
        self._frames.append(held)
        self._frames.extend(self._held_audio)
        self._held_audio = []
        self._wake.set()

    def _end(self) -> None:
        """The station says the recording is over: deliver what is queued, then stop."""
        if self._closed:
            return
        _LOGGER.debug(
            "media (cmd %d ch%d) ended by the station after %.1fs",
            self.command,
            self.channel,
            time.monotonic() - self._opened_at,
        )
        self._end_frame = True
        self._finish()

    def _download_finished(self, settle: float) -> None:
        """The station has sent the whole download: end once no media has arrived for
        ``settle`` seconds, so frames still in flight are taken first."""
        if self._closed:
            return
        _LOGGER.debug(
            "media (cmd %d ch%d) end-of-download frame after %.1fs; ending after %.1fs quiet",
            self.command,
            self.channel,
            time.monotonic() - self._opened_at,
            settle,
        )
        self._end_frame = True
        self._idle_timeout = min(self._idle_timeout, settle)
        self._wake.set()

    def _finish(self) -> None:
        """End the stream after the held frame and what is queued are delivered."""
        self._log_summary()
        self._release_held()
        self._ended = True
        self._closed = True
        self._wake.set()
        self._session._media_slot.detach(self)

    def _checked_video(self, frame: MediaFrame) -> MediaFrame | None:
        """``frame`` with the codec its picture shows; its empty NAL units are removed when
        the held frame is released. None (and video dropped to the next keyframe) when no
        NAL unit is left."""
        counters = self._session._media_counters
        data, empty = drop_empty_nals(frame.data)
        if not data:
            counters.empty_nals += empty
            counters.frames_without_nal += 1
            self._need_keyframe = True
            self._lagging = False
            if self._throttle.should_log("no-nal"):
                _LOGGER.debug(
                    "media (cmd %d ch%d): dropping a video frame with no NAL unit",
                    self.command,
                    self.channel,
                )
            return None
        if frame.is_keyframe:
            shown = picture_codec(data)
            if shown is not None and shown is not frame.codec:
                header = frame.codec.value if frame.codec is not None else "unknown"
                count_capped(counters.codec_overrides, f"{header}->{shown.value}")
                if self._throttle.should_log(("codec-override", shown)):
                    _LOGGER.debug(
                        "media (cmd %d ch%d): the video header names %s, the picture is %s; "
                        "muxing as %s",
                        self.command,
                        self.channel,
                        header,
                        shown.value,
                        shown.value,
                    )
            if shown is not None:
                self._codec = shown
                counters.codecs_by_channel[self.channel] = shown
            elif self._header_changed(frame):
                self._codec = frame.codec
            codec = self._codec or frame.codec
            previous = self._key_codec
            if codec is not None and previous is not None and codec is not previous:
                count_capped(counters.codec_changes, f"{previous.value}->{codec.value}")
                if self._throttle.should_log(("codec-change", codec)):
                    _LOGGER.debug(
                        "media (cmd %d ch%d): the video codec changed %s -> %s at %dx%d",
                        self.command,
                        self.channel,
                        previous.value,
                        codec.value,
                        frame.width,
                        frame.height,
                    )
            self._key_codec, self._key_header = codec, frame.codec
        elif self._header_changed(frame):
            # The next codec's frame, which its own picture cannot tell before that
            # codec's keyframe.
            codec = frame.codec
        else:
            codec = self._codec or frame.codec
        if codec is frame.codec:
            return frame
        return replace(frame, codec=codec)

    def _header_changed(self, frame: MediaFrame) -> bool:
        """Whether ``frame``'s header names another codec than the last keyframe's did."""
        return frame.codec is not None and self._key_header not in (None, frame.codec)

    def _undecodable_video(self, variant: VideoVariant) -> None:
        """Fail a stream whose video arrives in a protection its key does not decode;
        after its first keyframe, drop such records."""
        key = self._decoder.key_type
        if self._started:
            if self._throttle.should_log(("undecodable-video", variant)):
                _LOGGER.warning(
                    "dropping %s video records a stream opened with an %s key does not decode",
                    variant,
                    key,
                )
            return
        self._fail(
            UnsupportedError(
                f"the station sends {variant.value} video, which a stream opened with an "
                f"{key.value.upper()} key does not decode"
            )
        )
        self._session._media_slot.detach(self)

    def _other_camera_frame(self, camera: int, is_video: bool) -> None:
        """Drop a live frame tagged with another camera; fail when that is all that comes."""
        self.other_camera_frames += 1
        if self._throttle.should_log("other-camera"):
            _LOGGER.debug(
                "%s: live media for channel %d arrived tagged channel %d; dropped",
                self._session._log_name,
                self.channel,
                camera,
            )
        if is_video and not self._started and self.other_camera_frames >= MEDIA_OTHER_CAMERA_FRAMES:
            self._fail(
                ProtocolError(
                    f"the station streams channel {camera}, not the requested channel "
                    f"{self.channel}"
                )
            )
            self._session._media_slot.detach(self)

    def _fail(self, error: Exception) -> None:
        if self._closed:
            return
        self._session._media_slot.count_failure(error, self.channel)
        _LOGGER.debug("media (cmd %d ch%d) failed: %s", self.command, self.channel, error)
        self._closed = True
        self._error = error
        self._wake.set()


class StreamOwner(Protocol):
    """The station session members a :class:`MediaStream` uses."""

    _log_name: str
    _media_counters: MediaCounters
    _wake_backoff: WakeBackoff
    _media_slot: MediaSlot

    @property
    def tags_live_camera(self) -> bool: ...

    def _unanswered_error(
        self, command: int, channel: int, indices: Sequence[int]
    ) -> CommandNotAppliedError | DeviceTimeoutError: ...
