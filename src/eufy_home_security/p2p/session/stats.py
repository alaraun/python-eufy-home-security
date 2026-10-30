"""Health counters of a station session and the media counters behind them."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field

from ...devices.live_view import LensReport
from ..media import MediaRecordShape, VideoCodec

STAT_KEY_LIMIT = 64
"""Most distinct keys a wire-keyed statistic counts before bucketing the rest.

`events_by_type` and `receipts_by_code` are keyed on values taken off the wire, in an
object that lives for the process and is copied into every diagnostics dump. Without a
cap a station with odd firmware — or anything on the LAN able to inject pushes — grows
them without bound.
"""

MEDIA_SHAPE_RECORDS = 12
"""Video records per stream whose shape :class:`SessionStats` keeps (diagnostics)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionStats:
    """Health counters of one station session, for diagnostics.

    JSON-safe (``dataclasses.asdict`` then ``json.dumps``) and free of identifiers: no
    serial, DID, address, account id or path, and errors by class name only. Counters
    run from the session's creation (process start for a consumer) and a reconnect
    never resets them; ``connected`` alone describes the current connection. The
    de-duplication counters are account-wide, not per station, and live on
    ``EufySecurity.deduplicator``.
    """

    connected: bool
    """Whether a ``ConnectionChanged(connected=True)`` stands for a live connection."""
    connects: int
    """Sessions established (handshake completed), the first included."""
    reconnects: int
    """Sessions established after the first."""
    handshake_failures: int
    """``CONN_INIT`` exchanges that yielded no session key: unanswered, or a key that
    would not unwrap."""
    key_refreshes: int
    """Cipher keys re-fetched because the station rejected the cached one."""
    last_error: str | None
    """Class name of the most recent connection failure. Unlike ``Station.last_error``
    it is kept after the session recovers."""
    seconds_since_last_probe: float | None
    """Since the last answered parameter read; None before the first."""
    seconds_since_last_event: float | None
    """Since the last camera push over P2P; None before the first."""
    events_by_type: Mapping[str, int]
    """Camera pushes by ``"msg_type:event_type"`` (``?`` for a missing value)."""
    frames_by_cipher: Mapping[str, int]
    """Decoded camera pushes by frame cipher, ``"gcm"`` / ``"ecb"``."""
    ecb_state_refused: int
    """Always 0: state frames are taken under any encryption. Kept for compatibility; see
    :attr:`state_frames_by_encryption`."""
    dropped_undecodable: int
    """Non-media frames dropped undecoded: GCM authentication failure, a malformed ECB
    body, a body that is not a JSON object, or a DRW stream reset. Command receipts
    are never counted here."""
    receipts_by_code: Mapping[str, int]
    """Command receipts and results by code: on a GCM session the channel-0 receipts
    (not ciphertext; see :data:`~..messages.RECEIPT_LENS`), on an RSA session each
    channel-0 reply to a send of its type (:func:`~..messages.decode_command_result`).
    ``"0"`` taken (on an RSA session: done), ``"-108"`` a command the station does not
    handle."""
    wrong_port_drops: int
    """Datagrams from the station's host but not its session port, summed over every
    connection (the transport counts per connection)."""
    account_mismatch_seen: bool
    """Whether an ``AccountMismatch`` was emitted on any connection."""
    media_opens: int
    """Live or recording streams whose open was sent."""
    media_failures_by_type: Mapping[str, int]
    """Streams that ended in an error, by exception class name (a session closed by the
    client is not counted)."""
    media_failures_by_channel: Mapping[str, Mapping[str, int]]
    """The same failures by camera channel (``"3"``), then by exception class name."""
    media_frames_by_variant: Mapping[str, int]
    """Media records received, by protection: ``"video:<VideoVariant>"`` and
    ``"audio:<AudioVariant>"`` (:func:`~..media.media_variant_label`)."""
    media_video_codecs: Mapping[str, int]
    """Video records received, by the codec their header names
    (:func:`~..media.video_codec_label`; ``"code:<n>"`` for a code the library does not
    know, which a muxer takes as HEVC)."""
    media_keyframes_rejected: int
    """Keyframes dropped because they did not decrypt to Annex-B."""
    media_keyframe_continuations: int
    """Keyframe-flagged records joined to the keyframe before them: the rest of a
    keyframe a camera sends in several records (a HomeBase 2 camera)."""
    media_codecs_by_channel: Mapping[str, str]
    """The codec each camera channel's latest keyframe picture showed (``{"2": "h264"}``)."""
    media_codec_overrides: Mapping[str, int]
    """Keyframes whose picture is another codec than their header names, as
    ``"<header>-><picture>"`` (``"hevc->h264"``); the stream is muxed as the picture."""
    media_empty_nals: int
    """Empty NAL units removed from video frames before muxing."""
    media_frames_without_nal: int
    """Video frames dropped because no NAL unit was left in them."""
    media_first_records: tuple[MediaRecordShape, ...]
    """The latest stream's first :data:`MEDIA_SHAPE_RECORDS` video records: layout and
    what the stream did with each (:class:`~..media.MediaRecordShape`)."""
    media_rejected_keyframe: MediaRecordShape | None
    """The latest keyframe counted in :attr:`media_keyframes_rejected`, with the body
    layouts that do start with a start code (``probe``)."""
    stills_by_format: Mapping[str, int]
    """Stills fetched, by :class:`~..media.StillFormat` value."""
    still_late_replies: int
    """1308 replies discarded as the late answer to a timed-out request."""
    still_file_mismatches: int
    """1308 replies whose ``file`` differed from the requested path."""
    trigger_frame_sessions: int
    """Short-lived sessions opened for a recording's trigger frame (their own media
    counters are not included above)."""
    extra_live_sessions: int
    """Extra sessions opened for a live stream while this session's media slot was busy
    (their media is counted in the ``media_*`` fields above)."""
    extra_live_sessions_open: int
    """Extra sessions open now, live streams and recording downloads together (at most
    :attr:`StationSession.max_sessions` - 2)."""
    recording_downloads: int
    """Recordings downloaded on an extra session
    (:meth:`StationSession.async_download_recording`)."""
    media_slot_channel: int | None
    """The camera channel of the live stream holding this session's own media slot, or
    ``None`` when the slot is free or held by a recording/playback (no camera channel)."""
    conn_init_version: int | None = None
    """The version byte of the station's last CONN_INIT reply: :data:`~..crypto.CONN_INIT_ECC_VERSION`
    for the ECIES handshake, any other value for the legacy RSA one; None before a reply."""
    cipher_id: int | None = None
    """The cipher the station named in its last CONN_INIT reply; None before a reply."""
    static_key_session: bool = False
    """Whether the current RSA session runs under the static key
    (:attr:`StationSession.static_key_session`)."""
    media_frames_dropped_for_reader: int = 0
    """Media frames dropped because a stream's reader fell behind (``MediaStream.dropped``
    summed), the video up to the next keyframe included."""
    media_frames_skipped_for_keyframe: int = 0
    """Video frames skipped to the next keyframe after a keyframe that did not decode or
    a frame with no NAL unit (``MediaStream.skipped`` summed): pictures the viewer lost."""
    media_pframes_without_start_code: int = 0
    """Non-keyframe video frames whose data does not start with an Annex-B start code.
    The app's player appends such a record to the frame before it; the library delivers
    it as its own frame."""
    state_frames_by_encryption: Mapping[str, int] = field(default_factory=dict)
    """State frames (0x044F, 0x047F, the alarm frames) decoded and taken, by encryption: on
    an RSA session its type, ``"clear"``, ``"type1"`` (the fixed static key), ``"type2"``
    (its session key) or ``"other"``; on a GCM session the tag, ``"gcm"`` or ``"ecb"`` (the
    static key)."""
    state_authenticated: bool | None = None
    """Whether the station's state is authenticated, for information only: True once state
    came under a key only the session holds (GCM, an RSA session's own key), False while
    it came only in clear or under a key anyone can derive (the fixed key, a static-key
    session), None before any state."""
    lens_lists_by_channel: Mapping[str, LensReport] = field(default_factory=dict)
    """The lens list of each camera sent a layout (a HomeBase 3's multi-camera open), by
    channel in channel order: count and source (:class:`~...devices.live_view.LensReport`).
    Filled by ``Station.stats()``; empty from the session alone."""


class MediaCounters:
    """The media counters behind :class:`SessionStats`; a station session's extra live
    sessions count into their owner's."""

    __slots__ = (
        "codec_overrides",
        "codecs",
        "codecs_by_channel",
        "dropped_for_reader",
        "empty_nals",
        "failures",
        "failures_by_channel",
        "first_records",
        "frames_without_nal",
        "keyframe_continuations",
        "keyframes_rejected",
        "opens",
        "pframes_without_start_code",
        "rejected_keyframe",
        "skipped_for_keyframe",
        "variants",
    )

    def __init__(self) -> None:
        self.opens = 0
        self.failures: Counter[str] = Counter()
        self.failures_by_channel: dict[int, Counter[str]] = {}
        self.variants: Counter[str] = Counter()
        self.codecs: Counter[str] = Counter()
        self.codec_overrides: Counter[str] = Counter()
        self.codecs_by_channel: dict[int, VideoCodec] = {}
        self.empty_nals = 0
        self.frames_without_nal = 0
        self.keyframes_rejected = 0
        self.keyframe_continuations = 0
        self.dropped_for_reader = 0
        self.skipped_for_keyframe = 0
        self.pframes_without_start_code = 0
        self.first_records: list[MediaRecordShape] = []
        """The latest stream's first video records (the stream appends to it)."""
        self.rejected_keyframe: MediaRecordShape | None = None


class HealthCounters:
    """The station session's own counters behind :class:`SessionStats`; a reconnect
    resets none of them."""

    __slots__ = (
        "account_mismatch_seen",
        "connects",
        "dropped_undecodable",
        "events_by_type",
        "extra_live_opened",
        "frames_by_cipher",
        "handshake_failures",
        "key_refreshes",
        "last_event_at",
        "receipts_by_code",
        "recording_downloads",
        "retired_wrong_port_drops",
        "state_frames",
        "stills_by_format",
        "trigger_frame_sessions",
    )

    def __init__(self) -> None:
        self.state_frames: Counter[str] = Counter()
        """State frames taken, by encryption (``state_frames_by_encryption``)."""
        self.connects = 0
        self.handshake_failures = 0
        self.key_refreshes = 0
        self.last_event_at: float | None = None
        self.events_by_type: Counter[str] = Counter()
        self.frames_by_cipher: Counter[str] = Counter()
        self.dropped_undecodable = 0
        self.receipts_by_code: Counter[str] = Counter()
        self.retired_wrong_port_drops = 0
        """Wrong-port drops of transports this session no longer holds."""
        self.account_mismatch_seen = False
        self.stills_by_format: Counter[str] = Counter()
        self.trigger_frame_sessions = 0
        self.extra_live_opened = 0
        self.recording_downloads = 0


def count_capped(counter: Counter[str], key: str, *, limit: int = STAT_KEY_LIMIT) -> None:
    """Count ``key``, folding it into ``"other"`` once ``limit`` keys are known."""
    if key in counter or len(counter) < limit:
        counter[key] += 1
    else:
        counter["other"] += 1
