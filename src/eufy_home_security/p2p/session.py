"""A P2P session with one station.

One :class:`StationSession` owns one :class:`~.transport.PPPPTransport` and
everything that rides on it:

* **Handshake.** After the link is punched the session sends one empty
  ``CONN_INIT``; the station answers with an ECIES-wrapped session key that the
  private key of the cipher it names (40 on a HomeBase 3, 98 on a T8170; from the
  cloud) unwraps. The station mints exactly **one session
  per connection** and ignores a second ``CONN_INIT`` on a live one, so a new key
  always means a new connection.
* **Requests.** Every inbound frame is offered to the waiters of in-flight
  requests before the built-in handlers see it. Requests are serialised: the
  station's replies carry no reliable correlation id.
* **Events.** Parameter dumps are diffed into :class:`~..events.ParamChanged`,
  guard-mode reports become :class:`~..events.GuardModeChanged`, camera pushes
  become :class:`~..events.SecurityEvent`, and the alarm frames (tone, siren, light)
  become :class:`~..events.ParamChanged` plus :class:`~..events.AlarmChanged` on an
  alarm's start and end.
* **Media.** One :class:`MediaStream` at a time (live video or a stored
  recording) receives the video and audio frames of DRW channel 1.
* **Liveness.** An idle home is silent and the transport answers keepalives even
  when the encrypted session is dead, so the only honest check is an
  application round trip: :meth:`async_start` probes with a parameter query on a
  fixed schedule (independent of other traffic) and reconnects when it goes
  unanswered. :class:`~..events.ConnectionChanged` ``connected=True`` is emitted
  after the first parameter read on a new connection, not after the handshake
  alone, so a session that punches but never answers does not flap up and down.

Two facts about success that the API encodes: a transport ACK only proves the
datagram arrived — the station silently ignores a command carrying an
``account_id`` it does not know — so a write is reported as applied only on an
application-level reply; and many settings never send one, which is why
:meth:`async_send_command` distinguishes ``APPLIED`` from ``DELIVERED`` and the
caller confirms by reading the parameter back.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections import Counter, deque
from collections.abc import AsyncIterator, Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from enum import StrEnum
from typing import Any, Protocol, cast

from .._logging import (
    Address,
    LogThrottle,
    Payload,
    Secret,
    redact,
    redact_serial,
    register_secret_bytes,
    wire_logger,
)
from ..cloud.const import CIPHER_ID_P2P, KEY_REFRESH_SLOW_RETRY
from ..devices.param_info import ParamInfo, param_info
from ..devices.recipes import (
    ConnectType,
    Recipe,
    RecipeCommand,
    ResultFrom,
    close_live_stream,
    connect_type,
    open_live_stream_single,
)
from ..devices.settings import Scope
from ..events import (
    AccountMismatch,
    CloudProblem,
    ConnectionChanged,
    DisconnectCause,
    EventBus,
    EventCallback,
    EventSource,
    GuardModeChanged,
    HistoryRecord,
    ParamChanged,
    SecurityEvent,
    StorageChanged,
    Unsubscribe,
    as_guard_mode,
)
from ..exceptions import (
    CameraWakeError,
    CipherUnusableError,
    CloudError,
    CommandNotAppliedError,
    CommandRejectedError,
    CommandUnsupportedError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    KeyRejectedError,
    LiveStreamLimitError,
    ProtocolError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
)
from ..models import STATION_CHANNEL, GuardMode
from ._json import json_int
from .alarm import ALARM_FRAME_VALUES, decode_alarm_frame
from .clip import ClipWriter, MediaClip, mux_frames
from .crypto import (
    CONN_INIT_RSA_BLOB_LEN,
    FRAME_PLAIN,
    FRAME_SESSION_ECB,
    FRAME_STATIC_ECB,
    GCM_SEQ_START,
    ConnInit,
    aes_key_from_conn_init,
    ecb_decrypt,
    ecb_encrypt,
    frame_encryption,
    gcm_decrypt_broadcast,
    gcm_encrypt_command,
    parse_conn_init,
    session_key_from_conn_init,
)
from .did import Did, static_key
from .media import (
    KEYFRAME_MIN,
    KEYFRAME_RSA_LEN,
    PLAYBACK_ENDED,
    VIDEO_HEADER_LEN,
    MediaDecoder,
    MediaFrame,
    MediaKind,
    Still,
    StillFormat,
    _ForeignKeyframeError,
    classify_still,
    decode_record_play_ctrl,
    decode_v1_still,
    download_video_payload,
    generate_media_rsa_key,
    is_keyframe_record,
    record_view_payload,
    start_realtime_media_payload,
    stop_realtime_media_payload,
)
from .messages import (
    CAMERA_WAKE_CODES,
    CMD_CAMERA_PUSH_NOTIFY,
    CMD_DATABASE,
    CMD_DATABASE_IMAGE,
    CMD_DOWNLOAD_VIDEO,
    CMD_RECORD_VIEW,
    CMD_SET_ARMING,
    CMD_START_REALTIME_MEDIA,
    CMD_STOP_REALTIME_MEDIA,
    DB_EVENT_COUNT,
    DB_QUERY_HISTORY,
    ECB_RESULT_CODES,
    LIVE_OPEN_SUBHEADER_FLAG,
    PARAM_QUERY_ALL,
    RECEIPT_CODES,
    RECEIPT_NOT_HANDLED,
    RECEIPT_TAKEN,
    app_ping_frame,
    arm_payload,
    conn_init_request,
    database_query_payload,
    decode_alarm_mode_notify,
    decode_command_receipt,
    decode_database_rows,
    decode_ecb_scalar_result,
    decode_image_content,
    decode_json_payload,
    device_msg,
    encode_ecb_scalar_frame,
    event_count_payload,
    flatten_history_rows,
    gcm_subheader,
    history_query_payload,
    image_request_payload,
    record_id_day,
    string_command_body,
)
from .mode_actions import CMD_SET_ALL_ACTION, ModeTable
from .notify import decode_camera_push, stamped_accounts
from .params import ACTIVE_MODE_PARAM, GUARD_MODE_PARAM, ParamDump
from .pppp import DISCOVERY_PORT, DrwChunk
from .storage_info import (
    CMD_SD_INFO,
    CMD_STORAGE,
    StorageInfo,
    parse_sd_card_info,
    parse_storage_info,
    storage_query_payload,
    storage_record,
)
from .transport import PPPPTransport, SilentLinkError, StationClosedLinkError, Wake
from .xzyh import Frame, FrameCipher, FrameType, StreamDecoder, encode_frame

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("p2p")
"""Full decoded payloads (paths, serials, names): off unless wire logging is enabled."""

DISCOVERY_ATTEMPTS = 3
OP_LOCK_WAIT_LOG = 0.05
"""A wait for the command lock at least this long (seconds) gets a DEBUG line."""
DISCOVERY_TIMEOUT = 6.0
HANDSHAKE_TIMEOUT = 6.0
COMMAND_TIMEOUT = 6.0
LOOP_STALL_STEP = 0.25
"""A reply wait checks this often (seconds) whether the event loop was held."""
LOOP_STALL_LATENESS = 0.1
"""A wait step ending at least this late means something else held the event loop; the
reply deadline moves out by the lateness (replies that arrived meanwhile are still queued)."""
LOOP_STALL_MAX = 30.0
"""The most a reply deadline moves out for a held event loop, in all."""
PARAM_QUERY_TIMEOUT = 8.0
"""A parameter dump's wait for the station's own block."""
STILL_FETCH_TIMEOUT = 12.0
"""A still (1308) download's wait."""
COMMAND_RESEND_AFTER = 1.5
COMMAND_RECEIPT_TIMEOUT = 20.0
"""How long after sending a command acknowledged without a result waits for its receipt.

The station works through channel-0 frames one at a time; a rejected command holds
that queue until its -108 receipt, 11 to 17 s after it was sent. Waiting (under
the op lock) attributes the receipt to its own command and keeps the next request
from queueing behind the stall."""
PARAM_QUERY_RESEND_AFTER = 2.0
PARAM_SETTLE = 1.0
"""After the station block arrives, keep collecting sub-device blocks this long."""
MODE_REPORT_GRACE = 1.5
#: Parameter reads that confirm a mode-table write, and the pause between them.
MODE_TABLE_READBACK_ATTEMPTS = 3
MODE_TABLE_READBACK_DELAY = 0.8
"""After a command result, wait this long for the guard-mode report that confirms it."""
PROBE_EVERY = 300.0
STALE_AFTER = 30.0
UNSOLICITED_REPROBE_DELAY = 2.0
#: Seconds an on-demand session stays open after its last use: the eufy app closes
#: every session 120 s after it leaves the foreground (``P2PWatchDog``).
ON_DEMAND_IDLE_CLOSE = 120.0
#: How often an on-demand session checks whether it has been idle long enough.
_IDLE_CHECK_EVERY = 5.0
ON_DEMAND_ASLEEP_AFTER = 6.0
"""Seconds since an on-demand session was last used after which its station is taken
as asleep, and the link is dropped and made anew (with a wake) before the next use. A
T8170 stops answering commands about 7 s after its last application traffic while it
still answers transport keepalives, so link silence is not the signal; a command sent
into the sleep (a live open 8 s after the last use) goes unanswered and fails only
after the 15 s silence timeout."""
RECONNECT_BACKOFF = (5.0, 15.0, 60.0, 300.0)
MEDIA_LIVE_FIRST_FRAME_TIMEOUT = 20.0
"""A battery camera takes about 2 to 2.5 s from the open to its first frame."""
WAKE_BACKOFF = (60.0, 300.0, 900.0)
"""Seconds a HomeBase camera's live open is refused after its 1st, 2nd, 3rd and later
consecutive wake failure (:class:`CameraWakeError`); a stream that starts clears it."""
STATION_SESSION_LIMIT = 9
"""Sessions a HomeBase 3 holds across all clients; past that it CLOSEs one of them."""
DEFAULT_STATION_SESSIONS = 6
"""Sessions this library holds to one HomeBase at most, by default: the station session,
one trigger-frame session and 4 extra sessions (up to 5 live streams). Leaves 3 of
:data:`STATION_SESSION_LIMIT` for the app and other clients."""
MIN_STATION_SESSIONS = 2
"""The smallest budget: the station session and the trigger-frame session (1 live stream)."""
MEDIA_RECORDING_FIRST_FRAME_TIMEOUT = 10.0
MEDIA_IDLE_TIMEOUT = 3.0
"""A stream that sent frames and then stays quiet this long has ended. A 1025 playback
normally ends earlier, on the station's end-of-playback frame; this is the fallback
(a download, a lost end frame)."""
MEDIA_QUEUE_FRAMES = 250
"""Frames (video and audio together) held for a slow reader before new ones are dropped."""
MEDIA_DRAIN_GAP = 0.5
"""Opening a stream waits until no media frame has arrived for this long. A recording
closed early on this session keeps streaming to its end (no command stops a playback,
only closing the session does), a stopped live stream sends what was in flight, and
those frames carry no stream id: they would otherwise be delivered as the next stream's."""
MEDIA_OTHER_CAMERA_FRAMES = 25
"""A live stream fails when this many frames of another camera arrive before its own."""
MEDIA_DRAIN_MAX = 5.0
"""The longest an open waits for the previous stream to go quiet."""
EVENT_COUNT_RESEND = 2.0
"""How often an unanswered event-count query (10013) is sent again: a just-woken T8170
ignores one sent immediately but answers one sent 5 s later within 0.3 s."""
SD_INFO_RESEND = 2.0
"""How often the eMMC query (1144) is resent: a just-woken T8170 ignores it briefly."""
SD_INFO_TIMEOUT = 15.0
"""How long the eMMC query keeps retrying a just-woken camera before giving up."""
MEDIA_PING_INTERVAL = 3.0
"""How often a standalone device's open live stream gets the app's 1139 PING. A T8170
ends a stream about 10 s after it opens unless pinged; with a ping every 3 s (the app's
own rate) it streams for as long as it is wanted."""
BIND_STILL_REPLY_TO_PATH = True
"""Whether a 1308 reply whose ``file`` differs from the requested path is ignored.

On: the reply is exactly ``{"file", "content"}`` and ``file`` echoes the requested
path byte for byte, thumbnails and crops alike (HomeBase 3, fw 3.8.7.4).
A differing ``file`` is counted in :attr:`StationSession.still_file_mismatches` and
the reply is ignored (returned when off). A late reply to a timed-out request is
matched to it by ``file``, or by order when the reply names none, and discarded
(:data:`STILL_LATE_REPLY_WINDOW`)."""
CONN_INIT_MIN_LEN = 4 + CONN_INIT_RSA_BLOB_LEN
"""Smallest CONN_INIT payload that holds a key: the cipher id and the 128-byte RSA
ciphertext (the ECIES form needs 133, and a HomeBase 3 pads it to 144)."""
CONN_INIT_MAX_LEN = 4096
"""Largest CONN_INIT payload accepted. A real one is a few hundred bytes; the ECIES
unwrap searches candidate lengths on the event loop, so an oversized blob would stall
every session and stream in the process."""
STAT_KEY_LIMIT = 64
"""Most distinct keys a wire-keyed statistic counts before bucketing the rest.

`events_by_type` and `receipts_by_code` are keyed on values taken off the wire, in an
object that lives for the process and is copied into every diagnostics dump. Without a
cap a station with odd firmware — or anything on the LAN able to inject pushes — grows
them without bound.
"""
HISTORY_PAGE_SIZE = 50
"""Records per history page (the app asks 30, then 50)."""
HISTORY_MAX_PAGES = 1000
"""Pages read for one day before giving up on a station that never runs out."""
HISTORY_QUERY_TIMEOUT = 15.0
"""Seconds one station database query (a history page 10011, the event count 10013, an
event list) waits for its answer. An idle HomeBase 3 answers a history page within 3 s; a
busy one takes longer and sometimes leaves a query unanswered that it answers when asked
again, so a listing asks a page once more after a timeout."""
HISTORY_DATE_FORMAT = "%Y%m%d"
STILL_LATE_REPLY_WINDOW = 30.0
"""After a 1308 request times out, the next 1308 reply within this many seconds is
taken as its late answer and discarded, so it cannot answer a later request."""

_MEDIA_FRAME_TYPES = frozenset({FrameType.VIDEO_FRAME, FrameType.AUDIO_FRAME})
_RECORDING_COMMANDS = frozenset({CMD_DOWNLOAD_VIDEO, CMD_RECORD_VIEW})
_STATE_FRAME_TYPES = frozenset(
    {FrameType.PARAM_NOTIFY, FrameType.ALARM_MODE_NOTIFY, *ALARM_FRAME_VALUES}
)
"""Frames carrying station state: trusted only under GCM once a session key exists."""
_ANNEX_B_STARTS = (b"\x00\x00\x00\x01", b"\x00\x00\x01")
"""Every decrypted keyframe begins with an Annex-B start code; one that does not was
decrypted with the wrong key (a wrong RSA key unwraps to 16 bytes about once in 100)."""
_CLEAR_REPLY_TYPES = frozenset({FrameType.DB_SYNC, FrameType.MEDIA_DOWNLOAD})
"""Reply frame types a standalone device may send as clear JSON under the ECB tag."""


@dataclass(frozen=True, slots=True)
class P2PCredentials:
    """What a session needs from the cloud, all of it the station OWNER's.

    ``account_id`` is the owner's user id (``member.admin_user_id``) — a shared
    member's own id is silently ignored by the station. ``ecc_private_key`` is the
    owner's private key of cipher ``cipher_id``, the cipher the station names in its
    CONN_INIT (40 on a HomeBase 3, 98 on a T8170); empty when the cipher has none.
    ``rsa_private_key`` is the same cipher's RSA key (the cloud's ``private_key``),
    which a station answering with the RSA CONN_INIT needs; None when not held.
    """

    account_id: str
    user_name: str
    ecc_private_key: str
    cipher_id: int = CIPHER_ID_P2P
    rsa_private_key: str | None = None


class WakeProvider(Protocol):
    """Supplies the :class:`~.transport.Wake` for a battery station (its rendezvous
    servers and a device session key), or None when it cannot be built (no DSK yet, a
    cloud outage). Called before each connection attempt of an on-demand session."""

    async def __call__(self) -> Wake | None: ...


class CredentialProvider(Protocol):
    """Supplies :class:`P2PCredentials`; ``refresh=True`` means the cached key failed.

    ``cipher_id`` is the cipher the station named in its CONN_INIT: the session asks
    after the handshake. None lets the provider pick (the cipher this station named
    last, else :data:`~..cloud.const.CIPHER_ID_P2P`).
    """

    async def __call__(self, *, refresh: bool, cipher_id: int | None) -> P2PCredentials: ...


class KeyRefreshLatch(Protocol):
    """The per-station stale-key latch: set after a key refresh, cleared by a handshake."""

    def retry_blocked_for(self) -> float:
        """Seconds until another automatic refresh is allowed; 0.0 when allowed now."""
        ...

    async def async_refreshed(self) -> None:
        """A refresh returned a key: set (or re-stamp) the latch."""
        ...

    async def async_accepted(self) -> None:
        """A handshake succeeded: clear the latch."""
        ...


class MemoryKeyRefreshLatch:
    """A :class:`KeyRefreshLatch` that lives as long as the session (the default)."""

    def __init__(self) -> None:
        self._at: float | None = None

    def retry_blocked_for(self) -> float:
        if self._at is None:
            return 0.0
        return max(KEY_REFRESH_SLOW_RETRY - (time.monotonic() - self._at), 0.0)

    async def async_refreshed(self) -> None:
        self._at = time.monotonic()

    async def async_accepted(self) -> None:
        self._at = None


class CommandOutcome(StrEnum):
    """How far a command is known to have got."""

    APPLIED = "applied"
    """The station answered at the application level."""
    DELIVERED = "delivered"
    """The station acknowledged the datagram but sent no result (confirm by read-back)."""


@dataclass(frozen=True, slots=True)
class EventSummary:
    """One device's event count and the path of its newest event's still (10013)."""

    event_count: int
    newest_still: str | None
    """A station media path (``…_snapshot.jpg``), or None when there is no event."""


@dataclass(frozen=True, slots=True)
class RecipeReply:
    """What a recipe run got back: how far it went, and a notify-answered recipe's payload."""

    outcome: CommandOutcome
    payload: Mapping[str, Any] | None = None
    """The ``payload`` of the answering 1351 notify; None for a receipt-only recipe."""


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
    """ECB-ciphered state frames (0x044F, 0x047F, the alarm frames) refused on a GCM
    session."""
    dropped_undecodable: int
    """Non-media frames dropped undecoded: GCM authentication failure, a malformed ECB
    body, a body that is not a JSON object, or a DRW stream reset. Command receipts
    are never counted here."""
    receipts_by_code: Mapping[str, int]
    """Command receipts (channel 0, not ciphertext; see :data:`~.messages.RECEIPT_LENS`)
    by code: ``"0"`` taken off
    the station's queue, ``"-108"`` a command the station does not handle."""
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
    stills_by_format: Mapping[str, int]
    """Stills fetched, by :class:`~.media.StillFormat` value."""
    still_late_replies: int
    """1308 replies discarded as the late answer to a timed-out request."""
    still_file_mismatches: int
    """1308 replies whose ``file`` differed from the requested path."""
    trigger_frame_sessions: int
    """Short-lived sessions opened for a recording's trigger frame (their own media
    counters are not included above)."""
    extra_live_sessions: int
    """Extra sessions opened for a live stream while this session's media slot was busy
    (their own media counters are not included above)."""
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
    """The version byte of the station's last CONN_INIT reply: :data:`~.crypto.CONN_INIT_ECC_VERSION`
    for the ECIES handshake, any other value for the legacy RSA one; None before a reply."""
    cipher_id: int | None = None
    """The cipher the station named in its last CONN_INIT reply; None before a reply."""


@dataclass(slots=True)
class Inbound:
    """One reassembled frame, with its JSON body decrypted at most once."""

    channel: int
    frame: Frame
    _session: StationSession = field(repr=False)
    _json: dict[str, Any] | None = field(default=None, repr=False)
    _json_done: bool = field(default=False, repr=False)
    _mode: int | None = field(default=None, repr=False)
    _mode_done: bool = field(default=False, repr=False)

    @property
    def type(self) -> int:
        return self.frame.type

    def json(self) -> dict[str, Any] | None:
        if not self._json_done:
            self._json = self._session._decode_json(self.frame)
            self._json_done = True
        return self._json

    def receipt(self) -> int | None:
        """The code of a command receipt on the request channel (0); None for any other frame.

        On an RSA session a receipt is any clear frame (encryption type 0) of that shape.
        """
        if self.channel != 0:
            return None
        return decode_command_receipt(self.frame, clear=self._session.rsa_session)

    def alarm_mode(self) -> int | None:
        """The guard mode of a trusted 0x047F report, decoded at most once."""
        if not self._mode_done:
            self._mode = self._session._decode_alarm_mode(self.frame)
            self._mode_done = True
        return self._mode


type Matcher = Callable[[Inbound], object | None]


def _count_capped(counter: Counter[str], key: str, *, limit: int = STAT_KEY_LIMIT) -> None:
    """Count ``key``, folding it into ``"other"`` once ``limit`` keys are known."""
    if key in counter or len(counter) < limit:
        counter[key] += 1
    else:
        counter["other"] += 1


class MediaStream:
    """One open camera stream: iterate it for :class:`~.media.MediaFrame`, close it to stop.

    Video and audio start at a keyframe, because the frames before one reference
    pictures the reader never saw. When a slow reader lets :data:`MEDIA_QUEUE_FRAMES`
    pile up, or a keyframe does not decode, video is dropped until the next keyframe
    (reader lag counted in :attr:`dropped`), so whatever is delivered still decodes.
    The first keyframe that decodes pins the stream's wrapped key: a later keyframe
    wrapped differently belongs to another (earlier) stream and is dropped. Before that,
    a keyframe that does not decode under this stream's RSA key is dropped at DEBUG as
    another stream's; only when none decodes by ``first_frame_timeout`` is it a WARNING.

    Iteration ends when the stream is closed, when the station sends a recording's
    end-of-playback frame (``0x0402`` = 2, after the frames already queued), or when
    it stays quiet for ``idle_timeout`` after a frame (the fallback). It raises when the session
    is lost, when the station rejects the open, or when no keyframe decodes within
    ``first_frame_timeout``. Closing sends the stop command, which only a live stream has.
    """

    def __init__(
        self,
        session: StationSession,
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
        self._opened_at = time.monotonic()
        self._last_rx: float | None = None
        """When the last media record arrived, decodable or not (liveness)."""
        self._need_keyframe = True
        self._started = False
        self._wrapped_key: bytes | None = None
        """The RSA-wrapped key of the first keyframe that decoded (pinned)."""
        self._foreign_keyframes = 0
        """Keyframes dropped before the first one because they did not decode for this
        stream's key."""
        self._open_index: int | None = None
        self._throttle = LogThrottle()

    @property
    def closed(self) -> bool:
        return self._closed

    def __aiter__(self) -> MediaStream:
        return self

    async def __anext__(self) -> MediaFrame:
        while True:
            if self._frames:
                return self._frames.popleft()
            if self._error is not None:
                error, self._error = self._error, None
                raise error
            if self._closed:
                raise StopAsyncIteration
            now = time.monotonic()
            if not self._started:
                remaining = self._opened_at + self._first_frame_timeout - now
            else:
                remaining = cast(float, self._last_rx) + self._idle_timeout - now
            if remaining <= 0:
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
                self._session._count_media_failure(timed_out)
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
        """Stop the stream at the station and release the session (idempotent)."""
        if self._closed:
            return
        _LOGGER.debug(
            "%s: media (cmd %d ch%d) closed after %.1fs; %d frame(s) dropped for a slow reader",
            self._session._log_name,
            self.command,
            self.channel,
            time.monotonic() - self._opened_at,
            self.dropped,
        )
        self._closed = True
        self._frames.clear()
        self._wake.set()
        self._session._detach_media(self)

    def _feed(self, frame_type: int, payload: bytes, camera: int | None = None) -> None:
        if self._closed:
            return
        is_video = frame_type == FrameType.VIDEO_FRAME
        if self.command == CMD_START_REALTIME_MEDIA and camera not in (None, self.channel):
            self._other_camera_frame(camera, is_video)
            return
        self._last_rx = time.monotonic()
        # Decide what to drop before decoding: a keyframe unwrap and its copies are
        # the expensive part, and they are wasted on a frame that is thrown away.
        if len(self._frames) >= MEDIA_QUEUE_FRAMES:
            self._need_keyframe = self._need_keyframe or is_video
            if self._started:
                self.dropped += 1
            return
        is_key = is_video and is_keyframe_record(payload)
        if is_video and self._need_keyframe and not is_key:
            if self._started:
                self.dropped += 1
            return
        if not is_video and not self._started:
            return  # audio before the first picture would put the tracks out of step
        wrapped = _wrapped_key(payload) if is_key else None
        if wrapped is not None and self._wrapped_key not in (None, wrapped):
            # Another stream's keyframe. Dropping it leaves this stream's GOP intact,
            # so the need for a keyframe is not re-armed.
            if self._throttle.should_log("foreign-keyframe"):
                _LOGGER.debug("dropping a keyframe wrapped to another stream's key")
            return
        try:
            frame = self._decoder.decode(frame_type, payload)
            if (
                frame is not None
                and frame.is_keyframe
                and not frame.data.startswith(_ANNEX_B_STARTS)
            ):
                raise _ForeignKeyframeError("keyframe did not decrypt to Annex-B")
        except _ForeignKeyframeError as err:
            self._need_keyframe = True  # the P-frames after it would not decode
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
                return
            # Past the pinned-key check, so wrapped like this stream's keyframes: corrupt.
            if self._throttle.should_log(("bad-media", frame_type)):
                _LOGGER.warning("undecodable media frame 0x%04x: %s", frame_type, err)
            return
        except ProtocolError as err:
            if is_video:
                self._need_keyframe = True  # the P-frames after it would not decode
            if self._throttle.should_log(("bad-media", frame_type)):
                _LOGGER.warning("undecodable media frame 0x%04x: %s", frame_type, err)
            return
        if frame is None:
            return
        if frame.is_keyframe:
            if not self._started:
                _LOGGER.debug(
                    "first keyframe after %.1fs (cmd %d); stream AES key %s",
                    time.monotonic() - self._opened_at,
                    self.command,
                    Secret(self._decoder.aes_key),
                )
            self._need_keyframe = False
            if not self._started and self.command == CMD_START_REALTIME_MEDIA:
                self._session._wake_failures.pop(self.channel, None)
            self._started = True
            if self._wrapped_key is None:
                self._wrapped_key = wrapped
        self._frames.append(frame)
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
        self._closed = True
        self._wake.set()
        self._session._detach_media(self)

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
            self._session._detach_media(self)

    def _fail(self, error: Exception) -> None:
        if self._closed:
            return
        self._session._count_media_failure(error)
        _LOGGER.debug("media (cmd %d ch%d) failed: %s", self.command, self.channel, error)
        self._closed = True
        self._error = error
        self._wake.set()


@dataclass(slots=True, eq=False)
class _Waiter:
    match: Matcher
    future: asyncio.Future[object]


class StationSession:
    """A live, self-healing P2P session to one station."""

    def __init__(
        self,
        serial: str,
        credentials: CredentialProvider,
        *,
        host: str | None = None,
        port: int = DISCOVERY_PORT,
        local_port: int = 0,
        did: Did | str | None = None,
        expect_channels: Iterable[int] = (),
        block_aliases: Mapping[int, Sequence[int]] | None = None,
        on_demand: bool = False,
        idle_close: float = ON_DEMAND_IDLE_CLOSE,
        wake_provider: WakeProvider | None = None,
        key_refresh: KeyRefreshLatch | None = None,
        cloud_problems_reported: bool = False,
        max_sessions: int = DEFAULT_STATION_SESSIONS,
    ) -> None:
        # max_sessions: see the max_sessions property.
        # expect_channels: the paired sub-devices' channels, used by every parameter
        # read that does not name its own (the liveness probes included).
        # block_aliases: dump blocks filed under other dev_types (a standalone device's
        # block under 255 and its channel: params.standalone_aliases).
        # on_demand: never hold the session (a battery station): async_start connects
        # nothing, nothing reconnects, and a link idle for idle_close seconds is closed.
        # key_refresh: where the stale-key latch lives (in memory when None).
        # cloud_problems_reported: the owner delivers cloud errors as CloudProblem, so
        # ConnectionChanged carries only their cause.
        self.serial = serial.strip()
        self._max_sessions = _session_budget(max_sessions)
        self._expect_channels = frozenset(expect_channels)
        self._block_aliases = dict(block_aliases or {})
        # Values filed under a second alias are the same parameter: log their change once.
        self._alias_copies = frozenset(
            ch for targets in self._block_aliases.values() for ch in targets[1:]
        )
        self._station_blocks = next(
            (tuple(t) for t in self._block_aliases.values() if STATION_CHANNEL in t),
            (STATION_CHANNEL,),
        )
        self.on_demand = on_demand
        self._idle_close = idle_close
        self._wake_provider = wake_provider
        self._last_used = time.monotonic()
        """When an operation on this session last ended (an on-demand link closes after it)."""
        self._credentials = credentials
        self._key_refresh: KeyRefreshLatch = key_refresh or MemoryKeyRefreshLatch()
        self._cloud_problems_reported = cloud_problems_reported
        self._host = host
        self._search_host = host
        self._expected_did = Did.parse(did) if isinstance(did, str) else did
        self._port = port
        self._local_port = local_port

        self._transport: PPPPTransport | None = None
        self._creds: P2PCredentials | None = None
        self._cipher_id: int | None = None
        self._conn_init_version: int | None = None
        """The cipher the station named in its last CONN_INIT (None before one arrived)."""
        self._did: Did | None = None
        self._static_key: bytes | None = None
        self._session_key: bytes | None = None
        """The GCM session key of an ECIES handshake."""
        self._aes_key: bytes | None = None
        """The AES-128 session key of an RSA handshake: every frame is ECB under it."""
        self._decoders: dict[int, StreamDecoder] = {}
        self._gcm_seq = GCM_SEQ_START
        self._gcm_counter = 0
        self._ecb_seq = 0

        self._closed = False
        self._waiters: list[_Waiter] = []
        self._connect_lock = asyncio.Lock()
        self._op_lock = asyncio.Lock()
        self._still_lock = asyncio.Lock()
        """Serialises still fetches, whose replies are owed in request order."""
        self._history_lock = asyncio.Lock()
        """Serialises history queries (a reply without a ``transaction`` binds to any)."""
        self._recipe_lock = asyncio.Lock()
        """Serialises recipes. A recipe's receipt is bound by frame type alone, and
        every standalone-device recipe shares type 1700, so two in flight would each be
        able to complete or fail on the other's receipt."""
        self._bus = EventBus()
        self._params: dict[tuple[int, int], str | None] = {}
        self._param_at: dict[tuple[int, int], float] = {}
        """Epoch seconds each parameter's value dates from: its arrival over P2P, or the
        cloud snapshot's ``update_time`` (an older snapshot never overwrites it)."""
        self._meta: dict[str, Any] = {}
        """The dump's frame-level fields (firmware versions), latest value of each."""
        self._dump_listeners: list[Callable[[], None]] = []
        self._notify_listeners: list[Callable[[Mapping[str, Any], FrameCipher], None]] = []
        self._push_channels: set[int] = set()
        """Blocks of the unsolicited dump in progress (see :meth:`_note_pushed_blocks`)."""
        self._push_timer: asyncio.TimerHandle | None = None
        self._guard_mode: GuardMode | int | None = None
        """The selected guard mode (param 1224)."""
        self._active_mode: GuardMode | int | None = None
        """The effective guard mode (param 1151, the 0x047F report)."""
        self._alarming = False
        """Whether the last alarm-tone frame started the alarm (see :meth:`_handle_alarm`)."""
        self._arming_to: GuardMode | None = None
        """The mode an arm in flight asks for (see :meth:`_note_mode_report`)."""
        self.channel_scopes: dict[int, Scope] = {}
        """Each channel's device scope, set by the owning station once it knows the
        kinds; only log lines use it, to name a parameter precisely."""
        self._storage: StorageInfo | None = None
        self._last_probe = 0.0
        """When a parameter read last succeeded (the probe schedule's only clock)."""
        self._announced = False
        """Whether ConnectionChanged(connected=True) was emitted for this connection."""
        self._account_mismatch_reported = False
        """Whether AccountMismatch was emitted for this connection."""
        self._outage_reported: set[tuple[DisconnectCause, type[EufySecurityError] | None]] = set()
        """The (cause, error type) pairs already reported since the last connected=True."""
        self._last_error: EufySecurityError | None = None
        self._media_rx_at = 0.0
        """When the last media frame arrived, attached to a stream or not."""
        self._wake_failures: dict[int, tuple[int, float, int]] = {}
        """Per camera channel: consecutive wake failures, until when opens are refused,
        and the last failure's receipt code."""
        self._reprobe_at: float | None = None
        self._probing = False
        self._probe_ended_at: float | None = None
        """When this session's own parameter read last finished; stragglers right after
        it belong to that read."""
        self.ecb_state_refused = 0
        """ECB-ciphered state frames (0x044F, 0x047F, the alarm frames) refused on a GCM
        session."""
        self.still_file_mismatches = 0
        """1308 replies whose ``file`` differed from the requested path."""
        self.still_late_replies = 0
        """1308 replies discarded as the late answer to a timed-out request."""
        self._still_owed: deque[tuple[str, float]] = deque()
        """Timed-out 1308 requests whose reply may still arrive: (path, expiry)."""
        # Health counters behind stats(); none is reset by a reconnect.
        self._connects = 0
        self._handshake_failures = 0
        self._key_refreshes = 0
        self._last_error_name: str | None = None
        self._last_event_at: float | None = None
        self._events_by_type: Counter[str] = Counter()
        self._frames_by_cipher: Counter[str] = Counter()
        self._dropped_undecodable = 0
        self._receipts_by_code: Counter[str] = Counter()
        self._retired_wrong_port_drops = 0
        """Wrong-port drops of transports this session no longer holds."""
        self._account_mismatch_seen = False
        self._media_opens = 0
        self._media_failures: Counter[str] = Counter()
        self._stills_by_format: Counter[str] = Counter()
        self._trigger_frame_lock = asyncio.Lock()
        """At most one short-lived trigger-frame session per station at a time."""
        self._trigger_frame_sessions = 0
        self._extra_live: set[StationSession] = set()
        """Extra sessions carrying (or opening) a live stream while this session's slot is
        busy, or a recording download."""
        self._extra_live_opened = 0
        self._download_lock = asyncio.Lock()
        """At most one recording download per station at a time."""
        self._recording_downloads = 0
        self._live_capacity_waiters: list[asyncio.Future[None]] = []
        """Live opens and downloads waiting for this session's slot or an extra session."""
        self._live_owner: StationSession | None = None
        """On an extra session: the station session whose budget it counts against."""
        self._slot_claimed = False
        """A live open routed to this session's slot has not set its stream yet."""
        self._media_slot_free = asyncio.Event()
        self._media_slot_free.set()
        self._supervisor: asyncio.Task[None] | None = None
        self._media_pinger: asyncio.Task[None] | None = None
        self._media: MediaStream | None = None
        self._throttle = LogThrottle()
        self._log_name = redact_serial(self.serial)

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return (
            (self._session_key is not None or self._aes_key is not None)
            and self._transport is not None
            and self._transport.is_open
        )

    @property
    def rsa_session(self) -> bool:
        """Whether the station answered the RSA CONN_INIT, so the session runs
        AES-128-ECB under the key it carried instead of GCM."""
        return self._aes_key is not None

    @property
    def max_sessions(self) -> int:
        """Sessions this library holds to the station at most: this one, one for trigger
        frames, and ``max_sessions - 2`` extra sessions shared by live streams and
        recording downloads, so up to ``max_sessions - 1`` live streams (a standalone
        device keeps one). :data:`MIN_STATION_SESSIONS` to
        :data:`STATION_SESSION_LIMIT`, else ``ValueError``; default
        :data:`DEFAULT_STATION_SESSIONS`.

        Settable at any time: a lower budget refuses new live streams past it and ends
        none; a higher one serves live opens waiting for it at once.
        """
        return self._max_sessions

    @max_sessions.setter
    def max_sessions(self, value: int) -> None:
        self._max_sessions = _session_budget(value)
        self._notify_live_capacity()

    @property
    def standalone(self) -> bool:
        """Whether this station is a standalone device (its own station, like a SoloCam),
        by the app's rule: its serial names no station kind (:func:`~..devices.recipes.connect_type`)."""
        return connect_type(self.serial, self.serial) is ConnectType.SINGLE

    @property
    def announced(self) -> bool:
        """Whether a ``ConnectionChanged(connected=True)`` stands for a live connection."""
        return self._announced and self.connected

    @property
    def last_error(self) -> EufySecurityError | None:
        """The last connection failure; cleared by the next answered parameter read."""
        return self._last_error

    @property
    def host(self) -> str | None:
        """The station's LAN address (learned from discovery when not given)."""
        return self._host

    @property
    def search_host(self) -> str | None:
        """The address discovery is sent to, as configured; None broadcasts."""
        return self._search_host

    @property
    def local_port(self) -> int:
        """The pinned local UDP port; 0 binds an ephemeral one per session."""
        return self._local_port

    @property
    def did(self) -> Did | None:
        return self._did

    @property
    def guard_mode(self) -> GuardMode | int | None:
        """The last selected guard mode known (param 1224; :attr:`GuardMode.SCHEDULE`
        while a schedule runs): observed over P2P, or noted from a push."""
        return self._guard_mode

    @property
    def active_mode(self) -> GuardMode | int | None:
        """The last effective guard mode known: the mode in force (param 1151, the
        ``0x047F`` report), which differs from :attr:`guard_mode` only under Schedule."""
        return self._active_mode

    @property
    def media_slot_channel(self) -> int | None:
        """The camera channel of the live stream holding this session's own media slot.

        ``None`` when the slot is free, or when it holds a recording or playback (which
        answer a request and carry no camera channel). Only a live view
        (:data:`CMD_START_REALTIME_MEDIA`) blocks a live still or a preset capture, so
        a consumer can end just that view's broadcast instead of every live view.

        A read is a point-in-time answer: the freed slot can be taken by another live
        open before a capture claims it. A capture opened with ``wait`` then waits for
        the slot up to its first-frame timeout.
        """
        stream = self._media
        if stream is None or stream.command != CMD_START_REALTIME_MEDIA:
            return None
        return stream.channel

    def note_guard_mode(
        self, mode: GuardMode | int, active_mode: GuardMode | int | None = None
    ) -> None:
        """Record the modes a push delivered, without emitting a change.

        A report is emitted only when it differs from the last known modes; a change
        made elsewhere (the app) that only a push announced would otherwise swallow the
        report that moves the mode back. ``active_mode`` None: ``mode`` outside Schedule,
        else the effective mode stays as it was.
        """
        self._apply_modes(mode, active_mode)
        if not self.on_demand or self._guard_mode is None:
            return
        # A station reached on demand has no dump to follow the push: file the modes as
        # parameters, so its state (and a later, older cloud snapshot) sees them.
        self._file_modes("push")

    def _file_modes(self, origin: str) -> None:
        """File the known modes as the station's own parameters (1224, 1151), dated now.

        The station's state is built from the held parameters, so a mode learned without
        a dump (a push, an arm's own report) is filed there; a cloud snapshot dated
        before it then no longer overwrites it (:meth:`ingest_cloud_params`).
        """
        values = {GUARD_MODE_PARAM: self._guard_mode, ACTIVE_MODE_PARAM: self._active_mode}
        dump = ParamDump()
        for param_id, value in values.items():
            if value is None:
                continue
            for block in self._station_blocks:
                dump.devices.setdefault(block, {})[param_id] = str(int(value))
        if not dump.devices:
            return
        self._merge_dump(dump, origin, time.time())
        self._complete_dump(None)

    def ingest_cloud_params(
        self, dev_type: int, params: Iterable[tuple[int, str, float | None]]
    ) -> int:
        """Merge the cloud's snapshot of a device's parameters; returns how many were news.

        ``params`` are ``(param_id, value, updated_at)`` of one device, ``dev_type`` the
        block they belong to (a standalone device's ``device_type``, filed through
        :attr:`block_aliases`). A value is taken only when it is newer than the one held
        (by P2P arrival or an earlier snapshot); an undated one only fills a gap. News
        emits ``ParamChanged`` (and ``GuardModeChanged``, as a cloud report) and completes
        a dump, so the station's state follows.
        """
        targets = tuple(self._block_aliases.get(dev_type, (dev_type,)))
        fresh: list[dict[str, Any]] = []
        stamps: dict[int, float] = {}
        for param_id, value, updated_at in params:
            keys = [(block, param_id) for block in targets]
            if updated_at is None:
                if any(key in self._params for key in keys):
                    continue
            elif updated_at <= max((self._param_at.get(key, 0.0) for key in keys), default=0.0):
                continue
            fresh.append({"dev_type": dev_type, "param_type": param_id, "param_value": value})
            if updated_at is not None:
                stamps[param_id] = updated_at
        if not fresh:
            return 0
        dump = ParamDump()
        dump.ingest({"params": fresh}, aliases=self._block_aliases)
        self._merge_dump(dump, "cloud snapshot", time.time(), stamps, source=EventSource.CLOUD)
        self._complete_dump(None)
        return len(fresh)

    def apply_local_params(self, channel: int, values: Mapping[int, str]) -> None:
        """Merge parameter values a successful write just set on ``channel``, as one dump.

        The device does not report them back at once; the next real dump overrides them.
        A standalone device's values are filed under every alias of its block. Emits
        ``ParamChanged`` for each change and notifies the dump listeners.
        """
        if not values:
            return
        block = next(
            (dev for dev, targets in self._block_aliases.items() if channel in targets), channel
        )
        dump = ParamDump()
        dump.ingest(
            {
                "params": [
                    {"dev_type": block, "param_type": pid, "param_value": value}
                    for pid, value in values.items()
                ]
            },
            aliases=self._block_aliases,
        )
        self._merge_dump(dump, "local write", time.time())
        self._notify_dump_listeners()

    @property
    def storage(self) -> StorageInfo | None:
        """The last storage record read or pushed on this session; None until one arrives."""
        return self._storage

    @property
    def params(self) -> Mapping[tuple[int, int], str | None]:
        """Every parameter held, keyed by ``(dev_type, param_id)``: the latest value of
        each, minus the blocks a full read no longer carries (see :meth:`add_dump_listener`)."""
        return self._params

    @property
    def expect_channels(self) -> frozenset[int]:
        """The paired sub-devices' channels every read without its own list waits for."""
        return self._expect_channels

    @expect_channels.setter
    def expect_channels(self, channels: Iterable[int]) -> None:
        self._expect_channels = frozenset(channels)

    def merged_params(self) -> ParamDump:
        """A copy of :attr:`params` and the latest frame-level fields, as one dump."""
        dump = ParamDump()
        for (dev, pid), value in self._params.items():
            if value is not None:
                dump.devices.setdefault(dev, {})[pid] = value
        dump.meta.update(self._meta)
        return dump

    def add_dump_listener(self, callback: Callable[[], None]) -> Unsubscribe:
        """Call ``callback`` once per completed parameter dump; returns the unsubscribe.

        A dump spans frames, so completion is signalled, not each frame:

        * a read (:meth:`async_get_params`) completes when it returns. When it waited
          for at least every channel in :attr:`expect_channels`, it is *full*: the
          blocks of channels it did not carry are dropped from :attr:`params` before
          the signal (a device removed from the base disappears; parameters missing
          from a block that did arrive are kept, since a block may be partial);
        * a dump nobody asked for (or a read's late block) completes as soon as the
          station block and every expected channel have arrived, else
          :data:`PARAM_SETTLE` seconds after its last frame. It drops nothing.

        A failing read signals nothing. A failing callback is logged, never raised.
        """
        self._dump_listeners.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._dump_listeners.remove(callback)

        return unsubscribe

    def add_notify_listener(
        self, callback: Callable[[Mapping[str, Any], FrameCipher], None]
    ) -> Unsubscribe:
        """Call ``callback(obj, cipher)`` with every JSON notify (0x0547) decoded, a
        request's answer included; returns the unsubscribe.

        An :attr:`~.models.FrameCipher.ECB` notify is forgeable by anyone on the LAN:
        use it for display state only. A failing callback is logged, never raised.
        """
        self._notify_listeners.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._notify_listeners.remove(callback)

        return unsubscribe

    def subscribe(self, callback: EventCallback) -> Unsubscribe:
        """Receive this session's events; returns the unsubscribe callable."""
        return self._bus.subscribe(callback)

    def stats(self) -> SessionStats:
        """A snapshot of this session's health counters (see :class:`SessionStats`)."""
        now = time.monotonic()
        live_drops = self._transport.wrong_port_drops if self._transport is not None else 0
        return SessionStats(
            connected=self.announced,
            connects=self._connects,
            reconnects=max(self._connects - 1, 0),
            handshake_failures=self._handshake_failures,
            key_refreshes=self._key_refreshes,
            last_error=self._last_error_name,
            seconds_since_last_probe=now - self._last_probe if self._last_probe else None,
            seconds_since_last_event=(
                None if self._last_event_at is None else now - self._last_event_at
            ),
            events_by_type=dict(self._events_by_type),
            frames_by_cipher=dict(self._frames_by_cipher),
            ecb_state_refused=self.ecb_state_refused,
            dropped_undecodable=self._dropped_undecodable,
            receipts_by_code=dict(self._receipts_by_code),
            wrong_port_drops=self._retired_wrong_port_drops + live_drops,
            account_mismatch_seen=self._account_mismatch_seen,
            media_opens=self._media_opens,
            media_failures_by_type=dict(self._media_failures),
            stills_by_format=dict(self._stills_by_format),
            still_late_replies=self.still_late_replies,
            still_file_mismatches=self.still_file_mismatches,
            trigger_frame_sessions=self._trigger_frame_sessions,
            extra_live_sessions=self._extra_live_opened,
            extra_live_sessions_open=len(self._extra_live),
            recording_downloads=self._recording_downloads,
            media_slot_channel=self.media_slot_channel,
            conn_init_version=self._conn_init_version,
            cipher_id=self._cipher_id,
        )

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def async_connect(self) -> None:
        """Connect and establish the encrypted session (no-op when already up).

        The credentials are loaded after CONN_INIT, for the cipher the station names
        there; a cloud error from that load ends the attempt. A cipher key that no
        longer unwraps the station's challenge is re-fetched
        once through the credential provider (which enforces its own cooldown).
        Only a fetch that returned a key sets the stale-key latch; a failed fetch
        raises its own error and sets nothing. While the latch is set, a rejected key
        raises :class:`KeyRejectedError` without fetching, until a handshake
        succeeds (which clears it), ``KEY_REFRESH_SLOW_RETRY`` passes (one more fetch),
        or the latch is released. A re-fetched key that is rejected too raises
        :class:`KeyRejectedError`. A key that does not parse at all raises
        :class:`CipherUnusableError` without a re-fetch or latch (the cloud serves the
        same bytes again). After :meth:`async_close` every call raises
        :class:`StationUnreachableError`: a closed session has no owner left to close
        it again.
        """
        self._raise_if_closed()
        async with self._connect_lock:
            self._raise_if_closed()
            if self.connected and self._probably_asleep():
                self._teardown("the on-demand station is asleep", cause=DisconnectCause.IDLE)
            if self.connected:
                # A caller holds no lock between here and its `_op`, so without this
                # the idle check could tear the link down underneath the very command
                # that just connected for it.
                self._last_used = time.monotonic()
                return
            try:
                creds = await self._establish(None)
            except CipherUnusableError:
                # The key cannot be used and the cloud serves the same bytes again;
                # re-fetching is pointless and would set the stale-key latch. Let it
                # propagate: the cipher is retried only after a library change or the
                # cached key being dropped.
                raise
            except HandshakeError as err:
                creds = await self._refetch_rejected_key(err)
                try:
                    creds = await self._establish(creds)
                except CipherUnusableError:
                    raise
                except HandshakeError as again:
                    raise KeyRejectedError(
                        f"the station rejected the re-fetched cipher key too: {again}"
                    ) from again
            await self._key_refresh.async_accepted()
            self._creds = creds
            self._last_used = time.monotonic()
            if self._closed:  # closed while the handshake ran
                self._teardown("closed by the client", cause=DisconnectCause.CLOSED)
                self._raise_if_closed()

    async def async_start(
        self, *, probe_every: float = PROBE_EVERY, stale_after: float = STALE_AFTER
    ) -> None:
        """Keep the session up in the background: connect, poll, reconnect.

        The first connection is awaited so setup errors (bad credentials, an
        unreachable station) surface to the caller — but the supervisor is started
        either way, so a station that is off when its consumer boots is picked up
        as soon as it answers. Afterwards the supervisor retries with backoff and
        reports through :class:`~..events.ConnectionChanged`. A failed first start is
        reported there too (``connected=False`` with its cause), besides being raised.
        """
        self._raise_if_closed()
        if self.on_demand:
            # Nothing to hold: connect when an operation needs it, close when idle.
            if self._supervisor is None or self._supervisor.done():
                self._supervisor = asyncio.get_running_loop().create_task(
                    self._close_when_idle(), name=f"eufy-p2p-idle-{self._log_name}"
                )
            return
        try:
            await self.async_connect()
            await self.async_get_params()
        except EufySecurityError as err:
            self._report_failure(err)
            raise
        finally:
            # Only supervise a session that is still open. ``async_close`` can run while
            # this method is still awaiting the connect, and it cancels a supervisor
            # that does not exist yet; creating one here regardless would leave a task
            # nothing ever cancels, looping forever on a dead session.
            if not self._closed and (self._supervisor is None or self._supervisor.done()):
                self._supervisor = asyncio.get_running_loop().create_task(
                    self._supervise(probe_every, stale_after), name=f"eufy-p2p-{self._log_name}"
                )

    async def async_close(self) -> None:
        """Stop supervising and close the session for good."""
        self._closed = True
        self._cancel_push_timer()
        if self._supervisor is not None:
            self._supervisor.cancel()
            # A supervisor that died on an unexpected error holds it here; closing must
            # not re-raise someone else's failure.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._supervisor
            self._supervisor = None
        self._teardown("closed by the client", cause=DisconnectCause.CLOSED)
        for extra in list(self._extra_live):
            extra._end_extra_live()
        self._notify_live_capacity()

    # ── requests ─────────────────────────────────────────────────────────────

    async def async_get_params(
        self, *, timeout: float | None = None, expect_channels: Iterable[int] | None = None
    ) -> ParamDump:
        """Read every parameter of the station and its sub-devices (pure read).

        Returns once the station's own block (dev_type 255, which carries the guard
        mode) has arrived and either every channel in ``expect_channels`` has
        reported too or sub-device blocks have had :data:`PARAM_SETTLE` seconds to
        follow. Pass the paired devices' channels (here or to the constructor, the
        default) to skip the settle wait: on a HomeBase 3 they all ride in the
        station's own frame. With no channels expected, the settle always runs.

        ECB-ciphered dumps are refused (see :meth:`_decode_json`); a timeout while
        such dumps arrived says so.
        """
        timeout = _or(timeout, PARAM_QUERY_TIMEOUT)
        await self.async_connect()
        dump = ParamDump()
        channels = self._expect_channels if expect_channels is None else expect_channels
        expected = {STATION_CHANNEL, *channels}
        refused_before = self.ecb_state_refused

        def complete() -> bool:
            # Only the station itself expected: nothing tells the last block, so settle.
            return len(expected) > 1 and expected <= dump.devices.keys()

        def collect(inbound: Inbound) -> None:
            if inbound.type == FrameType.PARAM_NOTIFY and (obj := inbound.json()) is not None:
                dump.ingest(obj, aliases=self._block_aliases)

        def done(inbound: Inbound) -> ParamDump | None:
            collect(inbound)
            return dump if STATION_CHANNEL in dump.devices else None

        def send() -> None:
            self._send_secure(
                PARAM_QUERY_ALL, frame_type=FrameType.PARAM_NOTIFY, dev_type=STATION_CHANNEL
            )

        async with self._op("parameter read"):
            self._probing = True
            try:
                try:
                    await self._request(
                        send,
                        done,
                        timeout=timeout,
                        resend_after=PARAM_QUERY_RESEND_AFTER,
                        label="parameter query",
                    )
                except DeviceTimeoutError as err:
                    refused = self.ecb_state_refused - refused_before
                    if not refused:
                        raise
                    raise DeviceTimeoutError(
                        f"{err}; {refused} ECB-ciphered state frame(s) arrived and were refused "
                        "(this firmware may answer the parameter query under ECB only)"
                    ) from err
                self._last_probe = time.monotonic()
                self._last_error = None
                self._announce_connected()
                if not complete():
                    await self._listen(collect, PARAM_SETTLE, until=complete)
                full = self._expect_channels <= expected
                self._complete_dump(dump.devices.keys() if full else None)
            finally:
                self._probing = False
                self._probe_ended_at = time.monotonic()
        return dump

    async def async_set_guard_mode(
        self, mode: GuardMode, *, timeout: float | None = None
    ) -> GuardMode | int:
        """Arm or disarm; returns the mode the station reports it applied.

        :attr:`GuardMode.SCHEDULE` is confirmed by reading param 1224 back: the report
        that follows it carries the schedule slot's mode (the effective mode), never 2.

        The station answers a change with an alarm-mode report, but stays silent
        when asked for the mode it is already in — which is indistinguishable, on
        the wire, from a command it ignored. So silence is settled by reading the
        mode back: if it matches, the request is satisfied.

        Only the frames that are this command's own answer count: the guard-mode
        report (0x047F), or a 0x0547 reply naming cmd 1224. A reply with a non-zero
        code raises :class:`CommandRejectedError`. A zero-code reply without a mode
        report is confirmed by reading the mode back, never taken on trust.

        Raises :class:`CommandNotAppliedError` when the station acknowledged the
        datagram, never acted, and the read-back shows another mode (the classic
        wrong-``account_id`` case) or answered and still reports another mode, and
        :class:`CommandRejectedError` when it applied a different mode.

        :attr:`GuardMode.OFF` is report-only and raises :class:`UnsupportedError`
        before anything is sent: disarm with :attr:`GuardMode.DISARMED`.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        if mode is GuardMode.OFF:
            raise UnsupportedError("guard mode OFF (6) is report-only; disarm with DISARMED (63)")
        await self.async_connect()
        creds = self._require_creds()
        body = device_msg(creds.account_id, CMD_SET_ARMING, arm_payload(mode, creds.user_name))
        applied_at: float | None = None
        reported: list[int] = []
        schedule = mode is GuardMode.SCHEDULE

        def match(inbound: Inbound) -> int | None:
            nonlocal applied_at
            if inbound.type == FrameType.ALARM_MODE_NOTIFY:
                value = inbound.alarm_mode()
                if value is not None:
                    reported.append(value)
                    if schedule:
                        # A slot's mode, not the selection: processed, not confirmed.
                        applied_at = applied_at or time.monotonic()
                        return None
                    return value
                return None
            code = self._command_code(inbound, CMD_SET_ARMING)
            if code is not None:
                _raise_for_code(CMD_SET_ARMING, code)
                if applied_at is None:
                    applied_at = time.monotonic()
            return None

        async with self._op("guard mode write"):
            _LOGGER.info("%s: setting guard mode %s", self._log_name, mode.name)
            waiter = self._add_waiter(match)
            started = time.monotonic()
            self._arming_to = mode
            try:
                indices = [self._send_secure(body)]
                deadline = time.monotonic() + timeout
                resent = False
                while not waiter.future.done():
                    now = time.monotonic()
                    remaining = deadline - now
                    if applied_at is not None:
                        # The station processed it; give the mode report a moment.
                        remaining = min(remaining, applied_at + MODE_REPORT_GRACE - now)
                    if remaining <= 0:
                        break
                    step = remaining if resent else min(remaining, COMMAND_RESEND_AFTER)
                    await asyncio.wait({waiter.future}, timeout=step)
                    if not waiter.future.done() and not resent and applied_at is None:
                        _LOGGER.debug("%s: no answer to the arm yet; resending", self._log_name)
                        indices.append(self._send_secure(body))
                        resent = True
            finally:
                self._arming_to = None
                self._remove_waiter(waiter)
        _LOGGER.debug(
            "%s: arm settled after %.0f ms: result %s, mode reports %s",
            self._log_name,
            (time.monotonic() - started) * 1000,
            "code 0" if applied_at is not None else "none",
            reported or "none",
        )
        _raise_waiter_error(waiter)  # the session was lost, or the station rejected it

        if reported and not schedule:
            result = as_guard_mode(reported[-1])
            self._set_modes(result, result)
            # The report is the station's word on its mode: file it as its parameters,
            # so the state follows it on a station no dump follows (one reached on
            # demand) until a newer dump or cloud snapshot says otherwise.
            self._file_modes("arm")
            if result != mode:
                raise CommandRejectedError(
                    CMD_SET_ARMING, int(result), f"station applied {result!r}"
                )
            return result
        error = self._unanswered_error(CMD_SET_ARMING, 0, indices)
        current = (await self.async_get_params()).guard_mode
        if current == mode:
            _LOGGER.debug(
                "%s: no mode report for the arm; the station reports %s", self._log_name, mode.name
            )
            return mode
        if applied_at is not None:
            raise CommandNotAppliedError(
                CMD_SET_ARMING, f"the station answered the arm but reports guard mode {current!r}"
            )
        raise error

    async def async_send_command(
        self,
        command: int,
        *,
        channel: int = STATION_CHANNEL,
        value3: int = 0,
        payload: Mapping[str, Any] | Sequence[Any] | None = None,
        timeout: float | None = None,
    ) -> CommandOutcome:
        """Send a GCM ``DeviceMsgBean`` command and report how far it got.

        The frame's subheader names ``channel`` (0 for the station, 255), as the app's
        does for a device: a HomeBase passes the command on to a paired Wi-Fi camera
        only then.

        ``APPLIED`` needs a 0x0547 reply naming ``command`` with a zero code; a
        non-zero code raises :class:`CommandRejectedError`. ``DELIVERED`` means the
        station acknowledged the datagram (and usually sent receipt code 0, "taken off
        the queue") but no result within ``timeout``. Raises
        :class:`DeviceTimeoutError` when not even the datagram was acknowledged.

        The station's command receipt decides two things. A receipt with code -108
        raises :class:`CommandUnsupportedError` (the firmware does not handle the
        command), any other non-zero code :class:`CommandRejectedError`. The command
        is resent once only when neither a receipt nor an ACK came back: resending
        into the station's queue would queue a second copy. A command acknowledged
        but without a receipt by ``timeout`` waits for it up to
        :data:`COMMAND_RECEIPT_TIMEOUT` after sending, still holding the op lock.

        Receipts carry no command id. One arriving while this command is in flight is
        taken as its receipt: commands are serialised, but a media open, still fetch,
        history query or live-stream stop sent just before (none of them holds the lock
        until its receipt) can still have its receipt arrive now. Those are taken
        (code 0), so the effect is at most a skipped resend.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = device_msg(
            creds.account_id,
            command,
            payload if payload is not None else {},
            channel=channel,
            value3=value3,
            transaction=str(int(time.time() * 1000)),
        )
        receipt = asyncio.Event()
        header = _command_header_channel(channel)

        def match(inbound: Inbound) -> bool | None:
            if inbound.type == FrameType.CMD_TRANSFER and (code := inbound.receipt()) is not None:
                receipt.set()
                if code != RECEIPT_TAKEN:
                    raise _receipt_error(command, code)
                return None
            code = self._command_code(inbound, command)
            if code is None:
                return None
            _raise_for_code(command, code)
            return True

        async with self._op("command"):
            _LOGGER.debug(
                "%s: cmd %d ch%d value3=%d / %s",
                self._log_name,
                command,
                channel,
                value3,
                self._param(command, channel).describe(),
            )
            waiter = self._add_waiter(match)
            try:
                indices = [self._send_secure(body, dev_type=header)]
                started = time.monotonic()
                await _wait_any(waiter.future, receipt, min(COMMAND_RESEND_AFTER, timeout))
                if not waiter.future.done() and not receipt.is_set() and not self._acked(indices):
                    _LOGGER.debug(
                        "%s: cmd %d (%s): no receipt or ACK after %.1fs; resending",
                        self._log_name,
                        command,
                        self._param(command, channel).label,
                        COMMAND_RESEND_AFTER,
                    )
                    indices.append(self._send_secure(body, dev_type=header))
                await self._wait_until(waiter.future, started + timeout, f"cmd {command}")
                if not waiter.future.done() and not receipt.is_set() and self._acked(indices):
                    _LOGGER.debug(
                        "%s: cmd %d (%s) acknowledged without a receipt; waiting for it",
                        self._log_name,
                        command,
                        self._param(command, channel).label,
                    )
                    await _wait_any(
                        waiter.future,
                        receipt,
                        started + COMMAND_RECEIPT_TIMEOUT - time.monotonic(),
                    )
            finally:
                self._remove_waiter(waiter)
        _raise_waiter_error(waiter)  # the session was lost, or the station rejected it
        if waiter.future.done() and not waiter.future.cancelled():
            return CommandOutcome.APPLIED
        if receipt.is_set() or self._acked(indices):
            _LOGGER.debug(
                "%s: cmd %d (%s) acknowledged without a result (receipt %s): DELIVERED",
                self._log_name,
                command,
                self._param(command, channel).label,
                "0" if receipt.is_set() else "none",
            )
            return CommandOutcome.DELIVERED
        raise DeviceTimeoutError(f"no reply from the station within {timeout:.0f}s")

    async def async_set_mode_table(
        self, table: ModeTable, *, verify: bool = True, timeout: float | None = None
    ) -> None:
        """Write one guard mode's whole action table (``SET_ALL_ACTION``, 1255) and
        confirm it by reading the parameters back.

        The frame type is 1255 and the body the table's JSON (see
        :mod:`.mode_actions`). The station answers only with a receipt; a non-zero
        receipt code raises :class:`CommandRejectedError`, but a zero one is not taken
        as success: every value the table leaves (each device's action and delays for
        the mode) is read back, and :class:`CommandNotAppliedError` names the first that
        differs after :data:`MODE_TABLE_READBACK_ATTEMPTS` reads. No resend: the station
        queues channel-0 frames, so a resend would only queue a second table. Raises
        :class:`DeviceTimeoutError` when not even the datagram was acknowledged, and
        ``UnsupportedError`` for a table whose delays cannot be expressed (before
        anything is sent). ``verify=False`` skips the read-back.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = table.encode(creds.account_id)

        def match(inbound: Inbound) -> int | None:
            if inbound.type != CMD_SET_ALL_ACTION or inbound.channel != 0:
                return None
            return decode_command_receipt(inbound.frame)

        async with self._op("mode table write"):
            _LOGGER.info(
                "%s: writing the %s mode table (%d devices)",
                self._log_name,
                table.mode.name,
                len(table.actions),
            )
            indices: list[int] = []
            code: int | None
            try:
                code = cast(
                    int,
                    await self._request(
                        lambda: indices.append(
                            self._send_secure(body, frame_type=CMD_SET_ALL_ACTION)
                        ),
                        match,
                        timeout=timeout,
                        label=f"cmd {CMD_SET_ALL_ACTION}",
                    ),
                )
            except DeviceTimeoutError:
                error = self._unanswered_error(CMD_SET_ALL_ACTION, 0, indices)
                if isinstance(error, DeviceTimeoutError):
                    raise error from None
                code = None  # acknowledged without a receipt: the read-back decides
        if code:
            _raise_for_code(CMD_SET_ALL_ACTION, code)
        if verify:
            await self._confirm_params(CMD_SET_ALL_ACTION, table.params())

    async def _confirm_params(
        self, command: int, expected: Mapping[int, Mapping[int, int]]
    ) -> None:
        """Read parameters until every ``channel → {param: value}`` in ``expected`` holds."""
        problem = ""
        for attempt in range(MODE_TABLE_READBACK_ATTEMPTS):
            dump = await self.async_get_params(expect_channels=expected.keys())
            problem = ""
            for channel, values in sorted(expected.items()):
                block = dump.devices.get(channel, {})
                for param, want in sorted(values.items()):
                    got = json_int(block[param]) if block.get(param) is not None else None
                    if got != want:
                        reported = "does not report it" if got is None else f"reports {got}"
                        label = self._param(param, channel).label
                        problem = (
                            f"channel {channel} param {param} ({label}): wrote {want}, "
                            f"station {reported}"
                        )
                        break
                if problem:
                    break
            if not problem:
                return
            if attempt + 1 < MODE_TABLE_READBACK_ATTEMPTS:
                await asyncio.sleep(MODE_TABLE_READBACK_DELAY)
        raise CommandNotAppliedError(command, f"command {command} not confirmed: {problem}")

    async def async_run_recipe(
        self,
        recipe: Recipe,
        *,
        channel: int = 0,
        timeout: float | None = None,
    ) -> RecipeReply:
        """Send a handler recipe (:mod:`~..devices.recipes`) and wait for its answer.

        The recipe's frame (:meth:`Recipe.plaintext`, of type ``recipe.cmd``) goes to
        ``channel``'s subheader. A receipt with code -108 raises
        :class:`CommandUnsupportedError`, any other non-zero code
        :class:`CommandRejectedError`. A notify-answered recipe returns the payload
        of the 1351 notify naming its :attr:`~Recipe.answer_cmd` (``APPLIED``) and raises
        :class:`DeviceTimeoutError` without one; any other recipe returns
        ``DELIVERED`` on its receipt, since nothing else confirms it.

        A 1350 recipe (:attr:`RecipeCommand.SET_PAYLOAD`) is a ``DeviceMsgBean`` of its
        sub-command and goes through :meth:`async_send_command`; a standalone T8170
        receipts it and sends no result, so it returns ``DELIVERED`` after ``timeout``
        (confirm by read-back).
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        if recipe.cmd == RecipeCommand.SET_PAYLOAD and recipe.sub_cmd is not None:
            outcome = await self.async_send_command(
                recipe.sub_cmd,
                channel=channel,
                payload=dict(recipe.params) if recipe.params else {},
                timeout=timeout,
            )
            return RecipeReply(outcome)
        async with self._recipe_lock:
            return await self._run_recipe(recipe, channel=channel, timeout=timeout)

    async def _run_recipe(self, recipe: Recipe, *, channel: int, timeout: float) -> RecipeReply:
        await self.async_connect()
        plaintext = recipe.plaintext()
        command = recipe.sub_cmd if recipe.sub_cmd is not None else recipe.cmd
        wants_notify = recipe.result_from is not ResultFrom.CALLBACK

        def match(inbound: Inbound) -> RecipeReply | None:
            if inbound.type == recipe.cmd and (code := inbound.receipt()) is not None:
                if code != RECEIPT_TAKEN:
                    raise _receipt_error(command, code)
                return None if wants_notify else RecipeReply(CommandOutcome.DELIVERED)
            if not wants_notify or inbound.type != FrameType.NOTIFY_PAYLOAD:
                return None
            obj = inbound.json()
            if obj is None or json_int(obj.get("cmd")) != recipe.answer_cmd:
                return None
            payload = obj.get("payload")
            return RecipeReply(
                CommandOutcome.APPLIED, payload if isinstance(payload, Mapping) else {}
            )

        _LOGGER.debug(
            "%s: recipe %s: cmd %d sub %s ch%d",
            self._log_name,
            recipe.identifier,
            recipe.cmd,
            recipe.sub_cmd,
            channel,
        )
        reply = await self._request(
            lambda: self._send_secure(plaintext, frame_type=recipe.cmd, dev_type=channel),
            match,
            timeout=timeout,
            label=f"recipe {recipe.identifier}",
            send_only_under_lock=True,
        )
        return cast(RecipeReply, reply)

    async def async_send_ecb_scalar(
        self,
        command: int,
        value: int,
        *,
        channel: int = STATION_CHANNEL,
        timeout: float | None = None,
    ) -> None:
        """Send a legacy scalar setting (frame type = command id, AES-ECB body).

        Raises :class:`CommandRejectedError` with the station's result code, or
        :class:`CommandNotAppliedError` / :class:`DeviceTimeoutError` when no
        result came back. A ``channel`` or account id the frame cannot carry raises
        :class:`ValueError` before anything is sent, like any out-of-domain argument.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        key = self._require_static_key()
        encryption = FRAME_STATIC_ECB
        if self._aes_key is not None:  # an RSA session: every command under its key
            key, encryption = self._aes_key, FRAME_SESSION_ECB

        def match(inbound: Inbound) -> tuple[int, int | None] | None:
            frame = inbound.frame
            if inbound.type != command or len(frame.payload) < 4:
                return None
            if self._session_ecb_frame(frame) and len(frame.payload) % 16 == 0:
                plain = ecb_decrypt(cast(bytes, self._aes_key), frame.payload)
                return decode_ecb_scalar_result(plain), frame.cipher
            return decode_ecb_scalar_result(frame.payload), frame.cipher

        async with self._op("ECB command"):
            seq = self._ecb_seq
            self._ecb_seq = (seq + 1) & 0xFF
            frame = encode_ecb_scalar_frame(
                key,
                command,
                value,
                creds.account_id,
                channel=channel,
                seq=seq,
                encryption=encryption,
            )
            transport = self._require_transport()
            indices: list[int] = []
            _LOGGER.debug(
                "%s: tx ECB scalar cmd %d value %d ch%d seq %d (account %s) / %s",
                self._log_name,
                command,
                value,
                channel,
                seq,
                Secret(creds.account_id),
                self._param(command, channel).describe(value),
            )
            try:
                result = await self._request(
                    lambda: indices.append(transport.send_drw(0, frame)),
                    match,
                    timeout=timeout,
                    label=f"ECB cmd {command}",
                )
            except DeviceTimeoutError:
                raise self._unanswered_error(command, 0, indices) from None
        code, cipher = cast(tuple[int, int | None], result)
        _LOGGER.debug(
            "%s: ECB cmd %d (%s) result %d %s",
            self._log_name,
            command,
            self._param(command, channel).label,
            code,
            ECB_RESULT_CODES.get(code, ""),
        )
        if cipher == FrameCipher.GCM and self._throttle.should_log(("ecb-migrated", command)):
            _LOGGER.warning(
                "%s: cmd %d replied under GCM, not ECB — this firmware may have moved it to the "
                "payload-object path",
                self._log_name,
                command,
            )
        if code != 0:
            raise CommandRejectedError(command, code, ECB_RESULT_CODES.get(code, ""))

    async def async_send_string_command(
        self,
        command: int,
        value: str,
        *,
        channel: int = STATION_CHANNEL,
        timeout: float | None = None,
    ) -> None:
        """Send a string setting the way the app does (its set-with-string handler).

        A GCM frame whose type is ``command``, subheader channel 255, body
        :func:`~.messages.string_command_body` (``channel`` addresses the device inside
        it). The station answers with a receipt of the same type: a non-zero code raises
        :class:`CommandRejectedError`, no answer :class:`CommandNotAppliedError` or
        :class:`DeviceTimeoutError`. A receipt is not a read-back. A value, account id or
        ``channel`` the body cannot carry raises ``ValueError`` before anything is sent.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = string_command_body(value, creds.account_id, channel=channel)

        def match(inbound: Inbound) -> int | None:
            if inbound.type != command:
                return None
            return decode_command_receipt(inbound.frame)

        async with self._op("string command"):
            _LOGGER.debug("%s: tx string cmd %d ch%d: %r", self._log_name, command, channel, value)
            indices: list[int] = []
            try:
                code = cast(
                    int,
                    await self._request(
                        lambda: indices.append(
                            self._send_secure(body, frame_type=command, dev_type=STATION_CHANNEL)
                        ),
                        match,
                        timeout=timeout,
                        label=f"string cmd {command}",
                    ),
                )
            except DeviceTimeoutError:
                raise self._unanswered_error(command, 0, indices) from None
        _LOGGER.debug("%s: string cmd %d receipt %d", self._log_name, command, code)
        _raise_for_code(command, code)

    async def async_get_storage(self, *, timeout: float | None = None) -> StorageInfo:
        """Read the station's storage record (``1307`` / ``11001``): disk and eMMC figures.

        Read-only. The reply carries no correlation id, so a record the station sends
        to this session for another client's query in the same moment answers it too
        (it is the same record). Raises :class:`CommandRejectedError` for a non-zero
        result, :class:`ProtocolError` for a reply without a ``body``, and
        :class:`DeviceTimeoutError` when nothing answers. The record also becomes
        :attr:`storage` and, when it changed, a :class:`~..events.StorageChanged`.

        The answer to this query is taken under either cipher: on a fresh session the
        station answers it under ECB. It is the record this
        session asked for, and disk figures are not security state. Records nobody here
        asked for are kept only under GCM.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = device_msg(
            creds.account_id,
            CMD_STORAGE,
            storage_query_payload(),
            transaction=str(int(time.time() * 1000)),
        )

        def match(inbound: Inbound) -> StorageInfo | None:
            if inbound.type != FrameType.NOTIFY_PAYLOAD:
                return None
            if (obj := inbound.json()) is None or (record := storage_record(obj)) is None:
                return None
            _raise_for_code(CMD_STORAGE, record.code)
            if record.body is None:
                raise ProtocolError("the storage record carries no body")
            info = parse_storage_info(record.body)
            self._keep_storage(info)
            return info

        async with self._op("storage read"):
            info = await self._request(
                lambda: self._send_secure(body), match, timeout=timeout, label="storage query"
            )
        return cast(StorageInfo, info)

    async def async_get_sd_info(self, *, timeout: float | None = None) -> StorageInfo:
        """A standalone camera's built-in eMMC, via ``SDINFO_EX`` (``1144``).

        The query a standalone device answers where it does not answer the HomeBase
        storage record (``1307`` / ``11001``): a bare command frame of type ``1144``,
        answered by a frame of the same type carrying a 12-byte body (three ``int32``:
        status, total, free — see :func:`~.storage_info.parse_sd_card_info`). The result
        is a :class:`StorageInfo` with only ``emmc`` set, kept as :attr:`storage` and
        announced with :class:`~..events.StorageChanged` when it changed.

        A T8170 just woken ignores the query for a few seconds (as it does the
        event-count query), so it is resent every :data:`SD_INFO_RESEND` seconds until
        answered or ``timeout``; raises :class:`DeviceTimeoutError` when nothing does.
        """
        timeout = _or(timeout, SD_INFO_TIMEOUT)
        await self.async_connect()

        def match(inbound: Inbound) -> StorageInfo | None:
            # The answer is a frame of the request's own type on channel 0: GCM-tagged
            # but clear, like a receipt (never a JSON reply), so bind by type alone.
            if inbound.type != CMD_SD_INFO or inbound.channel != 0:
                return None
            emmc = parse_sd_card_info(inbound.frame.payload)
            if emmc is None:
                return None  # a receipt-shaped 1144 frame (no usable eMMC); keep waiting
            info = StorageInfo(emmc=emmc)
            self._keep_storage(info)
            return info

        deadline = time.monotonic() + timeout
        async with self._op("sd info read"):
            while True:
                remaining = deadline - time.monotonic()
                try:
                    info = await self._request(
                        lambda: self._send_secure(b"", frame_type=CMD_SD_INFO),
                        match,
                        timeout=max(min(SD_INFO_RESEND, remaining), 0.1),
                        label="sd info query",
                    )
                    return cast(StorageInfo, info)
                except DeviceTimeoutError:
                    if remaining <= SD_INFO_RESEND:
                        raise

    async def async_query_events(
        self,
        device_sns: Sequence[str],
        start_date: str,
        end_date: str,
        *,
        count: int = 100,
        table: str = "history_record_info",
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        """List the station's own event records (dates are ``YYYYMMDD``)."""
        timeout = _or(timeout, HISTORY_QUERY_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        payload = database_query_payload(
            device_sns,
            start_date,
            end_date,
            count=count,
            table=table,
            transaction=str(int(time.time() * 1000)),
        )
        body = device_msg(creds.account_id, CMD_DATABASE, payload)

        def match(inbound: Inbound) -> list[dict[str, Any]] | None:
            if inbound.type != FrameType.DB_SYNC or (obj := inbound.json()) is None:
                return None
            return decode_database_rows(obj)

        async with self._op("event query"):
            rows = await self._request(
                lambda: self._send_secure(body), match, timeout=timeout, label="event query"
            )
        return cast(list[dict[str, Any]], rows)

    async def async_event_summary(
        self, device_sn: str, *, timeout: float | None = None
    ) -> EventSummary:
        """How many events ``device_sn`` has and the path of its newest still (10013).

        The query a standalone device answers where it does not answer the history
        list (10011). A device the reply does not list has no events. A T8170 just
        woken ignores database queries for a few seconds (its storage is not ready),
        so the query is resent every :data:`EVENT_COUNT_RESEND` seconds until
        answered or ``timeout``.
        """
        timeout = _or(timeout, HISTORY_QUERY_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()

        def match(inbound: Inbound) -> EventSummary | None:
            if inbound.type != FrameType.DB_SYNC or (obj := inbound.json()) is None:
                return None
            if json_int(obj.get("cmd")) != DB_EVENT_COUNT:
                return None
            code = json_int(obj.get("mIntRet"))
            if code is not None and code != 0:
                raise CommandRejectedError(CMD_DATABASE, code, str(obj.get("msg", "")))
            data = obj.get("data")
            items = [i for i in (data if isinstance(data, list) else ()) if isinstance(i, Mapping)]
            # A T8170 sometimes names no device ("device_sn": ""): its one item is its own.
            unnamed = len(items) == 1 and not items[0].get("device_sn")
            for item in items:
                if item.get("device_sn") == device_sn or unnamed:
                    info = item.get("payload")
                    info = info if isinstance(info, Mapping) else {}
                    path = info.get("crop_hb3_path")
                    return EventSummary(
                        event_count=json_int(info.get("event_count")) or 0,
                        newest_still=path if isinstance(path, str) and path else None,
                    )
            return EventSummary(event_count=0, newest_still=None)

        def send() -> None:
            transaction = str(int(time.time() * 1000))
            payload = event_count_payload(transaction)
            self._send_secure(device_msg(creds.account_id, CMD_DATABASE, payload))

        deadline = time.monotonic() + timeout
        async with self._op("event count"):
            while True:
                remaining = deadline - time.monotonic()
                try:
                    summary = await self._request(
                        send,
                        match,
                        timeout=max(min(EVENT_COUNT_RESEND, remaining), 0.1),
                        label="event count",
                    )
                    return cast(EventSummary, summary)
                except DeviceTimeoutError:
                    if remaining <= EVENT_COUNT_RESEND:
                        raise

    async def async_list_history(
        self,
        start_date: str,
        end_date: str | None = None,
        *,
        count: int | None = None,
        before: int | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        page_size: int = HISTORY_PAGE_SIZE,
        timeout: float | None = None,
    ) -> list[HistoryRecord]:
        """History records across all devices from ``start_date`` to ``end_date``, newest first.

        Dates are ``YYYYMMDD`` and both days are included (``end_date`` None: only
        ``start_date``). ``count`` caps the number of records (None: all of them).
        ``before`` (a ``record_id``) keeps only older rows: the days after its day are
        not asked and its day is paged from it. ``keep`` filters the rows as they
        arrive, and ``count`` then counts the kept ones, so paging stops as soon as
        enough rows pass the filter.

        Uses the app's verb (``DB_QUERY_HISTORY`` = 10011) the way the app does: one
        day at a time (``start_date`` = the day, ``end_date`` = the next day), paging
        with ``count`` = ``page_size`` and ``start_id`` = the previous page's oldest
        ``record_id`` until a page comes back short. The station answers a query
        with the rows of a single day only, so a multi-day window asked in one
        query misses every day after the first; a day with more rows than one page
        is cut short without the paging. ``timeout`` bounds each query (None:
        :data:`HISTORY_QUERY_TIMEOUT`); a query left unanswered is sent once more with
        the same cursor, and :class:`DeviceTimeoutError` is raised when that one times
        out too. Raises :class:`ValueError`, before sending,
        for a malformed date, a start after the end, a ``before`` that carries no day,
        or a ``page_size`` below 2 (a page repeats the cursor row, so a page of 1
        cannot move).
        """
        if page_size < 2:
            raise ValueError("page_size must be at least 2")
        if count is not None and count < 1:
            raise ValueError("count must be at least 1")
        first = _parse_day(start_date)
        last = first if end_date is None else _parse_day(end_date)
        if first > last:
            raise ValueError(f"start date {start_date} is after end date {end_date}")
        cursor_day = None if before is None else _record_day(before)
        records: list[HistoryRecord] = []
        seen: set[int] = set()
        day = last if cursor_day is None else min(last, cursor_day)
        while day >= first:
            await self._history_day(
                day,
                records,
                seen,
                count=count,
                start_id=before if day == cursor_day else None,
                keep=keep,
                page_size=page_size,
                timeout=timeout,
            )
            if count is not None and len(records) >= count:
                return records[:count]
            day -= timedelta(days=1)
        return records

    async def async_history_record(
        self, record_id: int, *, timeout: float | None = None
    ) -> HistoryRecord | None:
        """The history row of one ``record_id``, or None when the station has none.

        One query, not resent (``timeout`` None: :data:`HISTORY_QUERY_TIMEOUT`): the
        record's day comes from the id (``YYYYMMDD`` and a five-digit counter), and a
        page asked from ``start_id`` starts with that row. Raises
        :class:`ValueError`, before sending, for an id that carries no valid day
        (check it with :func:`~.messages.record_id_day`).
        """
        day = _record_day(record_id)
        page, _ = await self._history_page(day, record_id, 2, timeout)
        return next((r for r in page if r.record_id == record_id), None)

    async def _history_day(
        self,
        day: date,
        records: list[HistoryRecord],
        seen: set[int],
        *,
        count: int | None,
        start_id: int | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        page_size: int,
        timeout: float | None,
    ) -> None:
        """Add one day's records to ``records``, page by page, until the day or ``count``
        runs out; ``seen`` holds the ``record_id`` values already met. With
        ``start_id`` the day is paged from that row, which is left out; only rows
        ``keep`` accepts are added."""
        cursor = start_id or 0
        if start_id:
            seen.add(start_id)  # the first page starts with the cursor row
        for _ in range(HISTORY_MAX_PAGES):
            page, oldest = await self._history_page(day, cursor, page_size, timeout, resend=True)
            fresh = [r for r in page if not r.record_id or r.record_id not in seen]
            seen.update(r.record_id for r in fresh)
            records.extend(r for r in fresh if keep is None or keep(r))
            if count is not None and len(records) >= count:
                return
            if len(page) < page_size or not fresh or oldest is None or oldest == cursor:
                return
            cursor = oldest
        _LOGGER.warning(
            "%s: history of %s still had rows after %d pages; the rest is left out",
            self._log_name,
            day.isoformat(),
            HISTORY_MAX_PAGES,
        )

    async def _history_page(
        self,
        day: date,
        start_id: int,
        page_size: int,
        timeout: float | None,
        *,
        resend: bool = False,
    ) -> tuple[list[HistoryRecord], int | None]:
        """One page of a day's history and the cursor for the next (its oldest ``record_id``).

        ``resend``: after a timeout, ask the same page once more; a late reply to the
        first query answers the second as well.
        """
        timeout = HISTORY_QUERY_TIMEOUT if timeout is None else timeout
        await self.async_connect()
        creds = self._require_creds()
        sent: set[str] = set()

        def send() -> None:
            transaction = str(int(time.time() * 1000))
            sent.add(transaction)
            payload = history_query_payload(
                day.strftime(HISTORY_DATE_FORMAT),
                (day + timedelta(days=1)).strftime(HISTORY_DATE_FORMAT),
                count=page_size,
                start_id=start_id,
                transaction=transaction,
            )
            self._send_secure(
                device_msg(creds.account_id, CMD_DATABASE, payload, channel=STATION_CHANNEL)
            )

        def match(inbound: Inbound) -> tuple[list[HistoryRecord], int | None] | None:
            if inbound.type != FrameType.DB_SYNC or (obj := inbound.json()) is None:
                return None
            if obj.get("cmd") != DB_QUERY_HISTORY:
                return None
            echoed = obj.get("transaction")
            if echoed is not None and str(echoed) not in sent:
                return None  # another client's page: every session sees the replies
            page = [HistoryRecord.from_row(row) for row in flatten_history_rows(obj)]
            ids = [r.record_id for r in page if r.record_id]
            oldest = json_int(obj.get("end_id"))
            if oldest is None or oldest not in ids:
                oldest = min(ids, default=None)
            return page, oldest

        async with self._history_lock:
            try:
                result = await self._request(
                    send, match, timeout=timeout, label="history query", send_only_under_lock=True
                )
            except DeviceTimeoutError:
                if not resend:
                    raise
                _LOGGER.info(
                    "%s: history query of %s unanswered within %.0fs; asking once more",
                    self._log_name,
                    day.isoformat(),
                    timeout,
                )
                result = await self._request(
                    send, match, timeout=timeout, label="history query", send_only_under_lock=True
                )
        return cast(tuple[list[HistoryRecord], int | None], result)

    async def async_fetch_image(self, path: str, *, timeout: float | None = None) -> bytes:
        """The bytes of :meth:`async_fetch_still`, whatever their format."""
        return (await self.async_fetch_still(path, timeout=timeout)).data

    async def async_fetch_still(self, path: str, *, timeout: float | None = None) -> Still:
        """Download one still (``thumb_path`` / ``crop_path``) off the station's disk.

        The result carries its :class:`~.media.StillFormat`. A V1 still is decoded with
        the station's DID (``data`` is then the JPEG); another obfuscated still, or a V1
        still that does not decode, is returned as it came, not raised, and
        ``is_image`` is False for it. Content that is not
        strict URL-safe base64, is empty or exceeds 1 MiB raises
        :class:`ProtocolError`. A reply that arrives after its request timed out is
        discarded, never returned for a later request.
        """
        timeout = _or(timeout, STILL_FETCH_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = device_msg(
            creds.account_id, CMD_DATABASE_IMAGE, image_request_payload(path), transaction=path
        )

        def match(inbound: Inbound) -> bytes | None:
            if inbound.type != FrameType.MEDIA_DOWNLOAD or (obj := inbound.json()) is None:
                return None
            if "content" not in obj:
                return None
            if not self._still_reply_is_for(path, obj.get("file")):
                return None
            return decode_image_content(obj)

        def send() -> None:
            self._send_secure(body)
            _LOGGER.debug("%s: image fetch sent", self._log_name)

        started = time.monotonic()
        async with self._still_lock:
            # A new request for this path supersedes an abandoned one: leaving the old
            # entry owed would make this request's own reply look like the late answer
            # to its predecessor.
            self._still_owed = deque(entry for entry in self._still_owed if entry[0] != path)
            try:
                data = await self._request(
                    send, match, timeout=timeout, label="image fetch", send_only_under_lock=True
                )
            except DeviceTimeoutError:
                self._still_owed.append((path, time.monotonic() + STILL_LATE_REPLY_WINDOW))
                raise
        data = cast(bytes, data)
        still = Still(path, data, classify_still(data))
        if still.format is StillFormat.V1:
            still = self._decode_v1(still)
        self._stills_by_format[still.format.value] += 1
        _LOGGER.debug(
            "%s: image fetch bound: %s, %d bytes in %.2fs",
            self._log_name,
            still.format,
            len(data),
            time.monotonic() - started,
        )
        return still

    def _decode_v1(self, still: Still) -> Still:
        """``still`` with its V1 body decoded, or unchanged when it cannot be."""
        did = self._did or self._expected_did
        if did is None:
            _LOGGER.debug("%s: V1 still not decoded: no DID known", self._log_name)
            return still
        try:
            return Still(still.path, decode_v1_still(still.data, str(did)), still.format)
        except ProtocolError as err:
            _LOGGER.debug("%s: V1 still not decoded: %s", self._log_name, err)
            return still

    def _param(self, param_id: int, channel: int) -> ParamInfo:
        """What ``param_id`` means on ``channel``, for a log line."""
        return param_info(param_id, channel, self.channel_scopes.get(channel))

    @contextlib.asynccontextmanager
    async def _op(self, label: str) -> AsyncIterator[None]:
        """Hold the command lock for ``label``, logging a wait of :data:`OP_LOCK_WAIT_LOG` or more."""
        started = time.monotonic()
        async with self._op_lock:
            waited = time.monotonic() - started
            if waited >= OP_LOCK_WAIT_LOG:
                _LOGGER.debug(
                    "%s: %s waited %.2fs for the command lock", self._log_name, label, waited
                )
            # Stamp on entry as well as exit: the idle check reads `_last_used`, and an
            # operation that runs longer than the idle window would otherwise look
            # idle while it is still working.
            self._last_used = time.monotonic()
            try:
                yield
            finally:
                self._last_used = time.monotonic()

    def _still_reply_is_for(self, path: str, file: object) -> bool:
        """Whether a 1308 reply naming ``file`` answers the request for ``path``."""
        if not isinstance(file, str) or file == path:
            return True
        self.still_file_mismatches += 1
        if self._throttle.should_log("still-file-mismatch"):
            _LOGGER.debug(
                "%s: image reply file %s differs from the requested %s (%s)",
                self._log_name,
                redact(file),
                redact(path),
                "ignored" if BIND_STILL_REPLY_TO_PATH else "accepted",
            )
        return not BIND_STILL_REPLY_TO_PATH

    def _take_late_still_reply(self, inbound: Inbound) -> bool:
        """Whether ``inbound`` is the late reply to a timed-out 1308 (then it is dropped).

        This runs before the waiter loop, so it must not take a reply that answers a
        live request: doing so hands that request's answer to the bookkeeping, and the
        request then times out while its own reply is discarded. While a fetch is in
        flight only a reply that names a *different* path can be a late one — a reply
        naming no path is left to the live request's own matcher, which binds it.

        With :data:`BIND_STILL_REPLY_TO_PATH` a reply naming a path is matched by it;
        otherwise requests are serialised, so the replies owed arrive in request order.
        """
        now = time.monotonic()
        while self._still_owed and self._still_owed[0][1] <= now:
            self._still_owed.popleft()
        if not self._still_owed:
            return False
        obj = inbound.json()
        if obj is None or "content" not in obj:
            return False
        file = obj.get("file")
        if BIND_STILL_REPLY_TO_PATH and isinstance(file, str):
            owed = next((entry for entry in self._still_owed if entry[0] == file), None)
            if owed is None:
                return False
            self._still_owed.remove(owed)
        else:
            # No path to bind by. The owed replies arrive in request order, so the
            # oldest entry names this one — and because a fetch drops its own path from
            # the owed list before sending, a request's own reply is never taken here.
            #
            # A station that names no path cannot be served safely in every case: a
            # stale reply arriving while another fetch waits is indistinguishable from
            # that fetch's answer, whichever guard sees it first. Real hardware always
            # echoes `file` (see BIND_STILL_REPLY_TO_PATH), so this is the degraded
            # path, not the normal one.
            owed = self._still_owed.popleft()
        owed_deadline = owed[1]
        self.still_late_replies += 1
        if self._throttle.should_log("still-late-reply"):
            _LOGGER.debug(
                "%s: discarded a late image reply, %.1fs after its request",
                self._log_name,
                now - (owed_deadline - STILL_LATE_REPLY_WINDOW),
            )
        return True

    # ── media ────────────────────────────────────────────────────────────────

    async def async_trigger_frame(
        self,
        path: str,
        channel: int,
        *,
        trailing_frames: int = 0,
        first_frame_timeout: float | None = None,
    ) -> bytes:
        """A recording's first keyframe, the moment that triggered the event, as Annex-B HEVC.

        With ``trailing_frames`` the P-frames that follow it (up to that many, never
        past the next keyframe) are appended. The camera is not woken.

        No command stops a playback, so the recording (1025) is played on a
        **short-lived second session** to the same station, closed as soon as the
        frames are in: the station stops sending to a closed session within about
        5 ms. This session is never flooded by the rest of the recording, never waits
        for it to drain, and its command queue is never stalled. The short-lived
        session:

        * binds its own ephemeral local port, also when this session pins one (a
          pinned port is held by this session). A firewall that admits only the
          pinned port blocks it, and discovery fails with
          :class:`StationUnreachableError`;
        * uses the same credential provider and key-refresh latch, and the station
          address this session learned;
        * runs at most one at a time per station (calls queue), and is always closed.
          It counts in :attr:`max_sessions`, so live streams never take its place.

        Raises what the recording's open raises (see :meth:`async_open_recording`),
        and :class:`DeviceTimeoutError` when the recording ends before a keyframe.
        """
        if trailing_frames < 0:
            raise ValueError("trailing_frames must not be negative")
        self._raise_if_closed()
        parts: list[bytes] = []
        async with self._trigger_frame_lock:
            short = self._short_lived_session()
            self._trigger_frame_sessions += 1
            started = time.monotonic()
            try:
                await short.async_connect()
                _LOGGER.debug(
                    "%s: trigger frame on channel %d: short-lived session open in %.2fs",
                    self._log_name,
                    channel,
                    time.monotonic() - started,
                )
                stream = await short.async_open_recording(
                    path, channel, first_frame_timeout=first_frame_timeout
                )
                async for frame in stream:
                    if frame.kind is not MediaKind.VIDEO:
                        continue
                    if parts and frame.is_keyframe:
                        break  # the next picture group: only P-frames trail
                    parts.append(frame.data)
                    if len(parts) > trailing_frames:
                        break
            finally:
                await short.async_close()  # PPPP CLOSE: the station stops sending
                _LOGGER.debug(
                    "%s: trigger frame on channel %d: short-lived session closed after %.2fs, "
                    "%d bytes",
                    self._log_name,
                    channel,
                    time.monotonic() - started,
                    sum(len(part) for part in parts),
                )
        if not parts:
            raise DeviceTimeoutError("the recording ended before a keyframe arrived")
        return b"".join(parts)

    def _short_lived_session(self) -> StationSession:
        """A second, unsupervised session to this station for one media request."""
        return StationSession(
            self.serial,
            self._credentials,
            host=self._host or self._search_host,
            port=self._port,
            local_port=0,
            did=self._did or self._expected_did,
            key_refresh=self._key_refresh,
            cloud_problems_reported=self._cloud_problems_reported,
        )

    async def async_open_live(
        self,
        channel: int,
        *,
        first_frame_timeout: float | None = None,
        idle_timeout: float | None = None,
        wait: bool = False,
        live_ext_value: bool = True,
    ) -> MediaStream:
        """Open a camera's live video and audio. This wakes a battery camera.

        Close the returned stream (``async with``) to stop it. A session carries one
        stream at a time. On a HomeBase the first live stream takes this session's
        slot; while the slot is busy (any stream, any camera, the same one included)
        the open runs on an extra session to the station, which the stream's end
        closes, up to ``max_sessions - 1`` live streams (:attr:`max_sessions`). Past
        that cap this raises
        :class:`LiveStreamLimitError`, or with ``wait`` waits for the slot or an extra
        session to free, for at most ``first_frame_timeout``. A standalone device
        keeps one stream: while it is open this raises :class:`CommunicationError`,
        or with ``wait`` waits for it to close. Timeouts default to
        :data:`MEDIA_LIVE_FIRST_FRAME_TIMEOUT` and :data:`MEDIA_IDLE_TIMEOUT`.

        A standalone device (:attr:`standalone`) gets its handler's open, a 1700
        frame with sub-command 1000 (``extValue`` left out with ``live_ext_value``
        False, see :class:`~..devices.recipes.HandlerVariant`), and a bare 1004 stop;
        a station's camera gets the station's 1003 in a ``DeviceMsgBean`` and a 1004
        naming the channel.
        """
        if self.standalone:

            def open_standalone(account_id: str, key_hex: str) -> tuple[int, bytes]:
                recipe = open_live_stream_single(
                    channel=channel,
                    account_id=account_id,
                    key_hex=key_hex,
                    ext_value=live_ext_value,
                )
                return recipe.cmd, recipe.plaintext()

            def stop_standalone(account_id: str) -> tuple[int, bytes]:
                del account_id  # the bare stop names no account
                recipe = close_live_stream()
                return recipe.cmd, recipe.plaintext()

            open_frame, stop_frame = open_standalone, stop_standalone
        else:

            def open_station(account_id: str, key_hex: str) -> tuple[int, bytes]:
                payload = start_realtime_media_payload(account_id, channel, key_hex)
                body = self._media_msg(account_id, CMD_START_REALTIME_MEDIA, channel, payload)
                return FrameType.CMD_TRANSFER, body

            def stop_station(account_id: str) -> tuple[int, bytes]:
                payload = stop_realtime_media_payload(account_id, channel)
                body = self._media_msg(account_id, CMD_STOP_REALTIME_MEDIA, channel, payload)
                return FrameType.CMD_TRANSFER, body

            open_frame, stop_frame = open_station, stop_station
            left = self.wake_backoff_left(channel)
            if left > 0:
                raise CameraWakeError(
                    CMD_START_REALTIME_MEDIA,
                    self._wake_failures[channel][2],
                    f"the station could not wake the camera on channel {channel}; "
                    f"not retried for another {left:.0f}s",
                    retry_after=left,
                )

        first = _or(first_frame_timeout, MEDIA_LIVE_FIRST_FRAME_TIMEOUT)
        idle = _or(idle_timeout, MEDIA_IDLE_TIMEOUT)
        if self.standalone or self._live_owner is not None:
            return await self._open_media(
                CMD_START_REALTIME_MEDIA,
                channel,
                open_frame,
                stop_frame,
                first_frame_timeout=first,
                idle_timeout=idle,
                wait=wait,
            )
        extra = await self._live_route(first, wait)
        if extra is not None:
            return await self._open_extra_live(extra, channel, first, idle)
        try:
            return await self._open_media(
                CMD_START_REALTIME_MEDIA,
                channel,
                open_frame,
                stop_frame,
                first_frame_timeout=first,
                idle_timeout=idle,
                wait=wait,
            )
        finally:
            self._slot_claimed = False
            self._notify_live_capacity()

    async def _live_route(self, timeout: float, wait: bool) -> StationSession | None:
        """Where a HomeBase live open goes: None for this session's own media slot (then
        claimed), else an extra session reserved for it.

        The slot is taken first; while it is busy (any stream, any camera) the open gets
        an extra session, up to ``max_sessions - 2`` of them. Past that it raises
        :class:`LiveStreamLimitError` at once, or with ``wait`` once ``timeout`` passes
        without the slot or an extra session coming free.
        """
        return await self._reserve_media_session(timeout, wait, slot=True)

    async def _reserve_media_session(
        self, timeout: float, wait: bool, *, slot: bool
    ) -> StationSession | None:
        """An extra session reserved from the budget (``max_sessions - 2`` of them, shared
        by live streams and recording downloads); with ``slot``, this session's own free
        media slot first (None, then claimed). Past the budget :class:`LiveStreamLimitError`
        at once, or with ``wait`` once ``timeout`` passes without one coming free."""
        deadline = time.monotonic() + timeout
        while True:
            self._raise_if_closed()
            self._close_abandoned_media()
            if slot and self._media is None and not self._slot_claimed:
                self._slot_claimed = True
                return None
            limit = self._max_sessions - 1
            if len(self._extra_live) < limit - 1:
                extra = self._short_lived_session()
                extra._live_owner = self
                extra._wake_failures = self._wake_failures  # one wake backoff per camera
                self._extra_live.add(extra)
                if slot:
                    self._extra_live_opened += 1
                return extra
            remaining = deadline - time.monotonic()
            if not wait or remaining <= 0:
                raise LiveStreamLimitError(
                    f"{limit} extra sessions (live streams, downloads) are already open to "
                    f"this station (the library's cap)"
                    + (f"; none closed within {timeout:g}s" if wait else ""),
                    limit=limit,
                )
            waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            self._live_capacity_waiters.append(waiter)
            try:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(remaining):
                        await waiter
            finally:
                if waiter in self._live_capacity_waiters:
                    self._live_capacity_waiters.remove(waiter)

    async def async_download_recording(
        self,
        path: str,
        channel: int,
        write: ClipWriter,
        *,
        first_frame_timeout: float | None = None,
        wait: bool = True,
    ) -> MediaClip:
        """Play a stored recording to its end and mux it into one MPEG-TS clip.

        The camera is not woken: the station serves the clip off its own disk, about
        as fast as it was recorded or faster. The playback (1025) runs on an extra
        session reserved from the budget a live stream on an extra session uses
        (:attr:`max_sessions`), closed when the clip ends or this call is cancelled, so
        this session's slot, commands and trigger frames are never held up. Downloads
        queue: one at a time per station. Past the budget this raises
        :class:`LiveStreamLimitError`, or with ``wait`` (the default) waits up to
        ``first_frame_timeout`` for a stream to end.

        ``write`` receives the muxed bytes in order (see :mod:`~.clip`). Raises what
        :meth:`async_open_recording` raises, and :class:`DeviceTimeoutError` when the
        recording ends before a keyframe; bytes already written stay written. A
        standalone device raises :class:`UnsupportedError` before anything is sent.
        """
        if self.standalone:
            raise UnsupportedError("a standalone device lists no recordings to download")
        self._raise_if_closed()
        first = _or(first_frame_timeout, MEDIA_RECORDING_FIRST_FRAME_TIMEOUT)
        async with self._download_lock:
            extra = cast(StationSession, await self._reserve_media_session(first, wait, slot=False))
            self._recording_downloads += 1
            started = time.monotonic()
            try:
                await extra.async_connect()
                stream = await extra.async_open_recording(path, channel, first_frame_timeout=first)
                async with stream:
                    muxer, _ = await mux_frames(aiter(stream), write)
            finally:
                extra._end_extra_live()
                _LOGGER.debug(
                    "%s: recording on channel %d downloaded on an extra session in %.2fs",
                    self._log_name,
                    channel,
                    time.monotonic() - started,
                )
        if not muxer.started:
            raise DeviceTimeoutError("the recording ended before a keyframe arrived")
        return muxer.clip()

    async def _open_extra_live(
        self, extra: StationSession, channel: int, first: float, idle: float
    ) -> MediaStream:
        """Open live on ``extra``; the stream's end closes the session (PPPP CLOSE)."""
        started = time.monotonic()
        try:
            await extra.async_connect()
            _LOGGER.debug(
                "%s: live channel %d on an extra session (%d of %d), open in %.2fs",
                self._log_name,
                channel,
                len(self._extra_live),
                self._max_sessions - 2,
                time.monotonic() - started,
            )
            return await extra.async_open_live(
                channel, first_frame_timeout=first, idle_timeout=idle
            )
        except BaseException:
            extra._end_extra_live()
            raise

    def _end_extra_live(self) -> None:
        """Close this extra session (a live stream or a download) and return it to its
        station session's budget."""
        if not self._closed:
            self._closed = True
            self._teardown("extra session ended", cause=DisconnectCause.CLOSED)
            _LOGGER.debug("%s: extra session closed", self._log_name)
        owner = self._live_owner
        if owner is not None and self in owner._extra_live:
            owner._extra_live.discard(self)
            owner._notify_live_capacity()

    def _notify_live_capacity(self) -> None:
        """Wake the live opens and downloads waiting for the slot or an extra session."""
        waiters, self._live_capacity_waiters = self._live_capacity_waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)

    async def async_open_recording(
        self,
        path: str,
        channel: int,
        *,
        download: bool = False,
        first_frame_timeout: float | None = None,
        idle_timeout: float | None = None,
        wait: bool = False,
    ) -> MediaStream:
        """Play a stored recording (a ``.zxvideo`` path from an event) off the station's disk.

        Sends the app's playback command (1025), or the download command (1024)
        when ``download`` is set. Its first keyframe is the moment that triggered
        the event, and the camera is not woken. The stream ends by itself after the
        last frame. ``wait`` is as for :meth:`async_open_live`. Timeouts default to
        :data:`MEDIA_RECORDING_FIRST_FRAME_TIMEOUT` and :data:`MEDIA_IDLE_TIMEOUT`.

        Closing the stream early sends nothing: no command stops a playback (1051 is
        rejected with -108 after 11 to 12 s and stalls the session's command queue until
        then; 1055 and 1026 change nothing), so the rest of the recording keeps
        arriving and the next open on this session waits for it to drain. To take
        frames without that, use :meth:`async_trigger_frame`, which plays the
        recording on a short-lived session and closes it.
        """
        command = CMD_DOWNLOAD_VIDEO if download else CMD_RECORD_VIEW
        build = download_video_payload if download else record_view_payload
        return await self._open_media(
            command,
            channel,
            lambda account_id, key_hex: (
                FrameType.CMD_TRANSFER,
                self._media_msg(account_id, command, channel, build(path, key_hex)),
            ),
            None,
            first_frame_timeout=_or(first_frame_timeout, MEDIA_RECORDING_FIRST_FRAME_TIMEOUT),
            idle_timeout=_or(idle_timeout, MEDIA_IDLE_TIMEOUT),
            wait=wait,
        )

    async def _open_media(
        self,
        command: int,
        channel: int,
        open_frame: Callable[[str, str], tuple[int, bytes]],
        stop_body: Callable[[str], tuple[int, bytes]] | None,
        *,
        first_frame_timeout: float,
        idle_timeout: float,
        wait: bool,
    ) -> MediaStream:
        await self.async_connect()
        creds = self._require_creds()
        # RSA key generation takes tens of milliseconds: keep it off the event loop.
        key_hex, rsa_key = await asyncio.to_thread(generate_media_rsa_key)
        frame_type, body = open_frame(creds.account_id, key_hex)
        slot_deadline = time.monotonic() + first_frame_timeout
        # The slot wait and the drain run without the op lock, so commands are not
        # queued behind them; the lock is taken only to open, after re-checking both.
        drain_deadline: float | None = None
        while True:
            if self._media is not None:
                # An abandoned stream holds the slot for good: its deadlines are only
                # evaluated while something reads it. Reclaim it here as well as in the
                # supervisor, so an unsupervised session is not stuck either.
                self._close_abandoned_media()
            if self._media is not None:
                await self._wait_for_media_slot(wait, slot_deadline, first_frame_timeout)
                drain_deadline = None
                continue
            if drain_deadline is None:
                drain_deadline = time.monotonic() + MEDIA_DRAIN_MAX
            pause = self._media_drain_wait(drain_deadline)
            if pause > 0:
                await asyncio.sleep(pause)
                continue
            async with self._op("media open"):
                if not self._media_slot_free.is_set() or self._media_drain_wait(drain_deadline) > 0:
                    continue  # another open won the slot, or frames arrived meanwhile
                stream = MediaStream(
                    self,
                    command=command,
                    channel=channel,
                    decoder=MediaDecoder(rsa_key),
                    stop_body=(None if stop_body is None else lambda: stop_body(creds.account_id)),
                    first_frame_timeout=first_frame_timeout,
                    idle_timeout=idle_timeout,
                )
                _LOGGER.debug(
                    "%s: opening %s (cmd %d) on channel %d",
                    self._log_name,
                    "a recording" if command in _RECORDING_COMMANDS else "live media",
                    command,
                    channel,
                )
                self._set_media(stream)
                try:
                    if command == CMD_START_REALTIME_MEDIA:
                        # The station picks the live camera from the subheader, not the JSON.
                        stream._open_index = self._send_secure(
                            body,
                            frame_type=frame_type,
                            dev_type=channel,
                            flag=LIVE_OPEN_SUBHEADER_FLAG,
                        )
                    else:
                        stream._open_index = self._send_secure(body, frame_type=frame_type)
                except BaseException:
                    self._set_media(None)
                    raise
                self._media_opens += 1
                return stream

    async def _wait_for_media_slot(self, wait: bool, deadline: float, timeout: float) -> None:
        """Wait for the open stream to close (``wait``), or raise at once / at ``deadline``."""
        if wait:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(remaining):
                        await self._media_slot_free.wait()
                if self._media is None:
                    return
            raise CommunicationError(
                f"a media stream is still open on this session after {timeout:g}s"
            )
        raise CommunicationError("a media stream is already open on this session; close it first")

    def _set_media(self, stream: MediaStream | None) -> None:
        self._media = stream
        self._last_used = time.monotonic()
        if stream is None:
            self._media_slot_free.set()
            self._notify_live_capacity()
            if self._live_owner is not None and not self._closed:
                # After the caller's stop (1004) goes out: then the CLOSE.
                asyncio.get_running_loop().call_soon(self._end_extra_live)
            if self._media_pinger is not None:
                self._media_pinger.cancel()
                self._media_pinger = None
        else:
            self._media_slot_free.clear()
            if self.standalone and self._media_pinger is None:
                self._media_pinger = asyncio.get_running_loop().create_task(
                    self._ping_while_streaming(), name=f"eufy-security-ping-{self._log_name}"
                )

    async def _ping_while_streaming(self) -> None:
        """Send the app's 1139 PING every :data:`MEDIA_PING_INTERVAL` while a stream is open."""
        while self._media is not None and self.connected:
            self._gcm_counter = (self._gcm_counter + 2) & 0xFF
            with contextlib.suppress(EufySecurityError):
                self._require_transport().send_drw(0, app_ping_frame(self._gcm_counter))
            await asyncio.sleep(MEDIA_PING_INTERVAL)

    def _media_drain_wait(self, deadline: float) -> float:
        """Seconds to wait until the previous stream's frames stop arriving (0: open now).

        Whatever ended that stream — a close, its idle end, a rejected open or a
        first-frame timeout — the station may still be sending it, and on the wire
        its P-frames are indistinguishable from the next stream's. The wait is
        bounded by ``deadline``.
        """
        now = time.monotonic()
        quiet_at = self._media_rx_at + MEDIA_DRAIN_GAP
        if now >= quiet_at:
            return 0.0
        if now >= deadline:
            if self._throttle.should_log("media-drain-max"):
                _LOGGER.debug(
                    "%s: media still arriving after %.0fs; opening anyway",
                    self._log_name,
                    MEDIA_DRAIN_MAX,
                )
            return 0.0
        return min(quiet_at, deadline) - now

    @staticmethod
    def _media_msg(
        account_id: str, command: int, channel: int, payload: Mapping[str, Any]
    ) -> bytes:
        return device_msg(
            account_id,
            command,
            payload,
            channel=channel,
            value3=command,
            transaction=str(int(time.time() * 1000)),
            media=True,
        )

    def _detach_media(self, stream: MediaStream) -> None:
        """Release the session from ``stream`` and send its stop, if it has one (live: 1004)."""
        if self._media is not stream:
            return
        self._set_media(None)
        if stream._stop_body is not None and self.connected:
            _LOGGER.debug("%s: stopping media (cmd %d)", self._log_name, stream.command)
            frame_type, body = stream._stop_body()
            with contextlib.suppress(EufySecurityError):
                self._send_secure(body, frame_type=frame_type, dev_type=stream.channel)

    def _take_media_reply(self, stream: MediaStream, inbound: Inbound) -> bool:
        """Whether ``inbound`` is the reply to ``stream``'s open (then it is consumed here)."""
        obj = inbound.json()
        if obj is None or json_int(obj.get("cmd")) != stream.command:
            return False
        _LOGGER.debug(
            "%s: media cmd %d reply code %s", self._log_name, stream.command, obj.get("code")
        )
        code = json_int(obj.get("code"))
        if code is not None and code != 0:
            self._fail_media(
                CommandRejectedError(stream.command, code, ECB_RESULT_CODES.get(code, ""))
            )
        return True

    def _take_wake_failure(self, stream: MediaStream | None, inbound: Inbound, code: int) -> bool:
        """Fail a HomeBase live open that has not started on a wake-failure receipt.

        Receipts carry no command id; a wake failure can only answer a command that
        wakes a camera, and the live open is the only one of those.
        """
        if (
            stream is None
            or stream._started
            or stream.command != CMD_START_REALTIME_MEDIA
            or inbound.type != FrameType.CMD_TRANSFER
        ):
            return False
        failures = self._wake_failures.get(stream.channel, (0, 0.0, code))[0] + 1
        backoff = WAKE_BACKOFF[min(failures, len(WAKE_BACKOFF)) - 1]
        self._wake_failures[stream.channel] = (failures, time.monotonic() + backoff, code)
        _LOGGER.info(
            "%s: the station could not wake the camera on channel %d (code %d %s); "
            "live opens of it refused for %.0fs",
            self._log_name,
            stream.channel,
            code,
            RECEIPT_CODES.get(code, ""),
            backoff,
        )
        self._fail_media(_receipt_error(stream.command, code))
        return True

    def wake_backoff_left(self, channel: int) -> float:
        """Seconds a live open of the camera on ``channel`` is still refused (0: none).

        Set by a :class:`CameraWakeError`, per :data:`WAKE_BACKOFF`; cleared by a live
        stream of that channel that starts, or by :meth:`clear_wake_backoff`.
        """
        entry = self._wake_failures.get(channel)
        return 0.0 if entry is None else max(entry[1] - time.monotonic(), 0.0)

    def clear_wake_backoff(self, channel: int | None = None) -> None:
        """Allow the next live open of ``channel`` (every channel when None) at once."""
        if channel is None:
            self._wake_failures.clear()
        else:
            self._wake_failures.pop(channel, None)

    def _on_play_ctrl(self, stream: MediaStream | None, frame: Frame) -> None:
        """End ``stream`` on the station's end-of-playback frame (0x0402 = 2).

        Only a recording that has started takes it. The frame carries no stream id, and
        an earlier playback's end can arrive just after the next open (it follows the
        last frame by about 0.5 s, the drain gap), before that stream's first keyframe.
        """
        value = (
            self._rsa_play_ctrl(frame)
            if self.rsa_session
            else decode_record_play_ctrl(frame, self._session_key)
        )
        _LOGGER.debug("%s: playback control %s", self._log_name, value)
        if (
            value != PLAYBACK_ENDED
            or stream is None
            or stream.command not in _RECORDING_COMMANDS
            or not stream._started
        ):
            return
        stream._end()

    def _fail_media(self, error: Exception) -> None:
        if self._media is not None:
            self._media._fail(error)
            self._set_media(None)

    # ── connection internals ─────────────────────────────────────────────────

    async def _wake(self) -> Wake | None:
        """The wake for this connection attempt, or None when it cannot be built.

        A failure to fetch the DSK (a cloud outage) is not fatal: discovery falls back
        to a plain ``LAN_SEARCH``, which still finds the station if it happens to be awake.
        A :class:`SessionReplacedError` is: it is raised at once, since no wake can be
        built until someone takes the cloud session back.
        """
        if self._wake_provider is None:
            return None
        try:
            wake = await self._wake_provider()
        except SessionReplacedError:
            raise
        except EufySecurityError as err:
            _LOGGER.debug(
                "%s: no wake material (%s); trying LAN discovery only", self._log_name, err
            )
            return None
        if wake is not None:
            register_secret_bytes(wake.dsk)
        return wake

    async def _establish(self, creds: P2PCredentials | None) -> P2PCredentials:
        """Connect and unwrap the session key; returns the credentials that unwrapped it.

        The station names its cipher in CONN_INIT. Without ``creds``, or when they are
        another cipher's, the named cipher's credentials are loaded (from the cache,
        else the cloud) before the unwrap: a different cipher is not a stale key.
        """
        self._teardown("reconnecting")
        # A closed UDP transport releases its socket on the next loop iteration; a
        # pinned local port is only free again after that.
        await asyncio.sleep(0)
        self._media_rx_at = 0.0
        last_error: EufySecurityError = StationUnreachableError("no discovery attempt made")
        for attempt in range(1, DISCOVERY_ATTEMPTS + 1):
            _LOGGER.debug(
                "%s: connecting (attempt %d/%d) to %s, local port %s",
                self._log_name,
                attempt,
                DISCOVERY_ATTEMPTS,
                Address(self._host or "broadcast"),
                self._local_port or "ephemeral",
            )
            wake = await self._wake() if self.on_demand else None
            transport = PPPPTransport(on_chunk=self._on_chunk, on_lost=self._on_lost)
            try:
                did = await transport.connect(
                    self._host,
                    port=self._port,
                    local_port=self._local_port,
                    expected_did=self._expected_did,
                    timeout=DISCOVERY_TIMEOUT,
                    wake=wake,
                )
            except StationUnreachableError as err:
                last_error = err
                _LOGGER.debug("%s: discovery attempt %d failed: %s", self._log_name, attempt, err)
                await asyncio.sleep(0.5)
                continue
            except BaseException:
                transport.close()
                raise
            break
        else:
            raise last_error

        try:
            ecb_key = static_key(self.serial, did)
        except ProtocolError as err:
            # Not a HandshakeError: re-fetching the cipher key cannot fix a serial or
            # DID that does not yield a static key.
            self._retire_transport(transport)
            transport.close()
            raise ProtocolError(f"cannot derive the static key for this station: {err}") from err
        self._transport = transport
        self._did = did
        self._static_key = ecb_key
        if transport.peer is not None:
            self._host = transport.peer[0]
        self._decoders.clear()
        self._gcm_seq = GCM_SEQ_START
        self._gcm_counter = 0
        self._ecb_seq = 0

        key = self._static_key
        _LOGGER.debug(
            "%s: link up (DID %s); static ECB key %s; sending CONN_INIT",
            self._log_name,
            Secret(did),
            Secret(key),
        )

        def match(inbound: Inbound) -> Frame | None:
            if inbound.type != FrameType.CONN_INIT:
                return None
            # Bound the blob before it reaches the ECIES unwrap. A real CONN_INIT is a
            # few hundred bytes; the unwrap searches candidate lengths and runs on the
            # event loop, so an oversized one — corrupt, or from whatever won the punch
            # race on the LAN — would stall every session and stream in the process.
            if not CONN_INIT_MIN_LEN <= len(inbound.frame.payload) <= CONN_INIT_MAX_LEN:
                return None
            return inbound.frame

        try:
            payload = await self._request(
                lambda: transport.send_drw(0, conn_init_request()),
                match,
                timeout=HANDSHAKE_TIMEOUT,
                label="CONN_INIT",
            )
        except DeviceTimeoutError as err:
            self._handshake_failures += 1
            self._teardown("no handshake reply")
            raise StationUnreachableError(
                "the station did not answer the session handshake"
            ) from err
        except BaseException:
            self._teardown("handshake interrupted")
            raise
        try:
            creds, conn_init, session_key = await self._unwrap_conn_init(
                cast(Frame, payload), key, creds
            )
        except CipherUnusableError as err:
            _LOGGER.debug("%s: handshake failed: %s", self._log_name, err)
            self._handshake_failures += 1
            self._teardown("cipher key unusable")
            raise
        except HandshakeError as err:
            _LOGGER.debug("%s: handshake failed: %s", self._log_name, err)
            self._handshake_failures += 1
            self._teardown("handshake failed")
            raise
        except CloudError:
            self._teardown("no credentials for the cipher the station named")
            raise
        except BaseException:
            self._teardown("handshake interrupted")
            raise
        if conn_init.rsa:
            self._aes_key = session_key
        else:
            self._session_key = session_key
        self._connects += 1
        self._creds = creds
        self._account_mismatch_reported = False  # a new connection may report it again
        _LOGGER.debug(
            "%s: %s session key %s",
            self._log_name,
            "AES-128-ECB" if conn_init.rsa else "GCM",
            Secret(session_key),
        )
        _LOGGER.info("%s: P2P session established via %s", self._log_name, Address(self._host))
        return creds

    async def _unwrap_conn_init(
        self, frame: Frame, static: bytes, creds: P2PCredentials | None
    ) -> tuple[P2PCredentials, ConnInit, bytes]:
        """The credentials of the cipher CONN_INIT names, the parsed reply, and the
        session key they unwrap: a 32-byte GCM key (version 8, ECIES) or a 16-byte
        AES-128 key (any other version, RSA)."""
        conn_init = parse_conn_init(frame.payload, frame.subheader, static)
        named = conn_init.cipher_id
        self._cipher_id = named
        self._conn_init_version = conn_init.version
        _LOGGER.debug(
            "%s: CONN_INIT reply (%d bytes, version %d, encryption %s) names cipher %d",
            self._log_name,
            len(frame.payload),
            conn_init.version,
            frame_encryption(frame.subheader),
            named,
        )
        if creds is None:
            creds = await self._load_credentials(refresh=False)
        elif named != creds.cipher_id:
            _LOGGER.debug(
                "%s: the station uses cipher %d, not %d; loading its key",
                self._log_name,
                named,
                creds.cipher_id,
            )
            creds = await self._load_credentials(refresh=False)
        if creds.cipher_id != named:
            raise HandshakeError(
                f"CONN_INIT names cipher {named}, the key is cipher {creds.cipher_id}"
            )
        if not conn_init.rsa:
            return creds, conn_init, session_key_from_conn_init(conn_init, creds.ecc_private_key)
        if not creds.rsa_private_key:
            raise HandshakeError(f"no RSA private key held for cipher {named}")
        try:
            return creds, conn_init, aes_key_from_conn_init(conn_init, creds.rsa_private_key)
        except CipherUnusableError as exc:
            if exc.cipher_id is None:
                exc.cipher_id = named
            raise

    async def _refetch_rejected_key(self, err: HandshakeError) -> P2PCredentials:
        """Re-fetch the credentials after ``err``, unless the stale-key latch holds it back."""
        wait = self._key_refresh.retry_blocked_for()
        if wait > 0:
            raise KeyRejectedError(
                f"the station rejects its cipher key, which was already re-fetched; "
                f"no automatic re-fetch for {wait:.0f}s ({err})"
            ) from err
        _LOGGER.warning(
            "%s: session key would not unwrap (%s); re-fetching the cipher key once",
            self._log_name,
            err,
        )
        creds = await self._load_credentials(refresh=True)
        await self._key_refresh.async_refreshed()  # only now: the fetch returned a key
        self._key_refreshes += 1
        return creds

    async def _load_credentials(self, *, refresh: bool) -> P2PCredentials:
        creds = await self._credentials(refresh=refresh, cipher_id=self._cipher_id)
        _LOGGER.debug(
            "%s: credentials%s: owner account %s, user %s, cipher-%d private key %s, RSA key %s",
            self._log_name,
            " (re-fetched)" if refresh else "",
            Secret(creds.account_id),
            Secret(creds.user_name),
            creds.cipher_id,
            Secret(creds.ecc_private_key),
            "held" if creds.rsa_private_key else "none",
        )
        return creds

    def _announce_connected(self) -> None:
        """Emit ConnectionChanged(True) once per connection, after an application reply."""
        if self._announced or not self.connected:
            return
        self._announced = True
        self._outage_reported.clear()  # the outage, if any, is over
        self._bus.emit(ConnectionChanged(station_sn=self.serial, connected=True))

    def _teardown(
        self,
        reason: str,
        *,
        cause: DisconnectCause | None = None,
        error: EufySecurityError | None = None,
    ) -> None:
        """Drop the link; with a ``cause``, report it when the connection was announced."""
        was_announced, self._announced = self._announced, False
        if self._transport is not None:
            _LOGGER.debug("%s: tearing the session down: %s", self._log_name, reason)
            self._transport.close()
            self._retire_transport(self._transport)
            self._transport = None
        self._session_key = None
        self._aes_key = None
        self._still_owed.clear()  # a late reply cannot cross into a new connection
        # A pending settle timer would otherwise fire _complete_dump on a dead link and
        # announce a completed dump assembled from whatever arrived before the drop.
        self._cancel_push_timer()
        self._fail_waiters(StationUnreachableError(reason))
        if cause is not None and was_announced:
            self._emit_down(cause, error, reason)

    def _probably_asleep(self) -> bool:
        """Whether an on-demand station was last used over :data:`ON_DEMAND_ASLEEP_AFTER`
        ago with nothing in flight: it has since gone to sleep, and a command now would
        go unanswered rather than wake it. ``_last_used`` tracks application traffic
        (every op and media open/close), not the keepalives that outlast the sleep."""
        return (
            self.on_demand
            and self._transport is not None
            and self._media is None
            and not self._waiters
            and time.monotonic() - self._last_used >= ON_DEMAND_ASLEEP_AFTER
        )

    def _on_lost(self, exc: Exception) -> None:
        # A battery station goes quiet a few seconds after its last command (a T8170:
        # about 7 s, then the link times out): with nothing in flight that is its
        # sleep, not an outage. Anything waiting still fails.
        asleep = (
            self.on_demand
            and self._media is None
            and not self._op_lock.locked()
            and not self._waiters
        )
        if asleep:
            _LOGGER.debug("%s: the on-demand station went quiet (asleep): %s", self._log_name, exc)
        else:
            _LOGGER.info("%s: P2P session lost: %s", self._log_name, exc)
        was_announced, self._announced = self._announced, False
        if self._transport is not None:
            self._retire_transport(self._transport)
        self._transport = None
        self._session_key = None
        self._aes_key = None
        error = StationUnreachableError(str(exc))
        self._last_error_name = type(error).__name__
        self._fail_waiters(error)
        if was_announced:
            self._emit_down(_lost_cause(exc, asleep=asleep), None if asleep else error, str(exc))

    def _report_failure(self, error: EufySecurityError) -> None:
        """A failed start, connect or probe: record it and report it once per outage.

        A failure while an announced connection is still up is not a disconnect
        (the link is torn down, and reported, by whatever ended it), so only
        ``last_error`` records it.
        """
        self._last_error = error
        self._last_error_name = type(error).__name__
        if not self.announced:
            self._emit_down(DisconnectCause.for_error(error), error, str(error))

    def _retire_transport(self, transport: PPPPTransport) -> None:
        """Keep the counters of a transport this session is letting go of."""
        self._retired_wrong_port_drops += transport.wrong_port_drops

    def _count_media_failure(self, error: Exception) -> None:
        """Count a stream that ended in ``error``, unless the client closed the session."""
        if not self._closed:
            self._media_failures[type(error).__name__] += 1

    def _emit_down(
        self, cause: DisconnectCause, error: EufySecurityError | None, reason: str
    ) -> None:
        if error is not None:
            self._last_error = error
            self._last_error_name = type(error).__name__
        # An error the owner delivers as a CloudProblem is not delivered twice.
        shown = None if self._cloud_problems_reported and CloudProblem.covers(error) else error
        key = (cause, type(shown) if shown is not None else None)
        if key in self._outage_reported:
            return
        self._outage_reported.add(key)
        self._bus.emit(
            ConnectionChanged(
                station_sn=self.serial, connected=False, reason=reason, cause=cause, error=shown
            )
        )

    async def _close_when_idle(self) -> None:
        """An on-demand session's only background task: close a link left idle."""
        while True:
            await asyncio.sleep(_IDLE_CHECK_EVERY)
            if (
                self.connected
                and self._media is None
                and not self._op_lock.locked()
                and not self._connect_lock.locked()
                and time.monotonic() - self._last_used >= self._idle_close
            ):
                _LOGGER.debug(
                    "%s: idle for %.0fs; closing the on-demand session",
                    self._log_name,
                    self._idle_close,
                )
                self._teardown("idle on-demand session", cause=DisconnectCause.IDLE)

    def _close_abandoned_media(self) -> None:
        """Release a media stream whose deadline passed with nobody reading it.

        A stream evaluates its own timeouts only while it is being iterated, so
        ``async for ... : break`` without closing leaves the session's one media slot
        taken and the camera streaming for good. Waking the stream makes the next read
        raise as it would have; detaching frees the slot for the next open.
        """
        for extra in list(self._extra_live):
            extra._close_abandoned_media()
        stream = self._media
        if stream is None or not stream._expired(time.monotonic()):
            return
        _LOGGER.debug(
            "%s: media stream for command %d timed out unread; releasing the slot",
            self._log_name,
            stream.command,
        )
        stream._wake.set()
        self._detach_media(stream)

    async def _supervise(self, probe_every: float, stale_after: float) -> None:
        # The backoff resets only on a successful probe: a station that punches and
        # handshakes but never answers is retried with growing delays, not in a loop.
        failures = 0
        while True:
            try:
                fresh = not self.connected
                if fresh:
                    await self.async_connect()
                now = time.monotonic()
                # Scheduled by the last successful probe alone: media or other traffic
                # must not postpone the guard-mode poll.
                due = fresh or now - self._last_probe >= probe_every
                cued = self._reprobe_at is not None and now >= self._reprobe_at
                if due or cued:
                    _LOGGER.debug(
                        "%s: liveness probe (%s)",
                        self._log_name,
                        "new connection" if fresh else "scheduled" if due else "unsolicited dump",
                    )
                    self._reprobe_at = None
                    try:
                        await self.async_get_params(timeout=stale_after)
                    except DeviceTimeoutError:
                        error = DeviceTimeoutError(
                            f"parameter probe unanswered in {stale_after:.0f}s; re-establishing"
                        )
                        self._teardown(
                            "parameter probe unanswered",
                            cause=DisconnectCause.PROBE_UNANSWERED,
                            error=error,
                        )
                        raise error from None
                    failures = 0
                await asyncio.sleep(1.0)
                self._close_abandoned_media()
            except asyncio.CancelledError:
                raise
            except EufySecurityError as err:
                self._report_failure(err)
                delay = RECONNECT_BACKOFF[min(failures, len(RECONNECT_BACKOFF) - 1)]
                failures += 1
                if self._throttle.should_log(("supervise", type(err))):
                    _LOGGER.warning("%s: %s; retrying in %.0fs", self._log_name, err, delay)
                else:
                    _LOGGER.debug("%s: %s; retrying in %.0fs", self._log_name, err, delay)
                await asyncio.sleep(delay)
            except Exception:
                # Anything unexpected — a decoder bug, a shape no known firmware sends —
                # must degrade to a retry, not end supervision. A supervisor that stops
                # here never probes or reconnects again, while `connected` keeps
                # reporting the last value it saw, so the session looks healthy for the
                # life of the process.
                delay = RECONNECT_BACKOFF[min(failures, len(RECONNECT_BACKOFF) - 1)]
                failures += 1
                _LOGGER.exception(
                    "%s: unexpected supervisor error; retrying in %.0fs", self._log_name, delay
                )
                await asyncio.sleep(delay)

    # ── frame dispatch ───────────────────────────────────────────────────────

    def _on_chunk(self, chunk: DrwChunk) -> None:
        decoder = self._decoders.get(chunk.channel)
        if decoder is None:
            decoder = self._decoders[chunk.channel] = StreamDecoder()
        try:
            frames = decoder.feed(chunk.index, chunk.data)
        except ProtocolError as err:
            _LOGGER.warning("%s: channel %d stream reset: %s", self._log_name, chunk.channel, err)
            self._dropped_undecodable += 1
            # Resume from the next chunk that arrives. A reset to index 0 would wait
            # for an index the station has long passed, silencing the channel for
            # the rest of the session.
            self._decoders[chunk.channel] = StreamDecoder(first_index=None)
            return
        for frame in frames:
            self._dispatch(Inbound(chunk.channel, frame, self))

    def _dispatch(self, inbound: Inbound) -> None:
        stream = self._media
        if inbound.type in _MEDIA_FRAME_TYPES:
            self._media_rx_at = time.monotonic()
            if stream is not None:
                stream._feed(inbound.type, inbound.frame.payload, _frame_camera(inbound.frame))
            elif self._throttle.should_log("media-orphan"):
                _LOGGER.debug("%s: media frame with no open stream", self._log_name)
            return
        _LOGGER.debug(
            "%s: rx frame 0x%04x ch%d cipher %s (%d bytes)",
            self._log_name,
            inbound.type,
            inbound.channel,
            inbound.frame.cipher,
            len(inbound.frame.payload),
        )
        receipt = inbound.receipt()
        if receipt is not None:
            _count_capped(self._receipts_by_code, str(receipt))
            _LOGGER.debug(
                "%s: receipt for a 0x%04x frame: code %d %s",
                self._log_name,
                inbound.type,
                receipt,
                RECEIPT_CODES.get(receipt, ""),
            )
            if receipt in CAMERA_WAKE_CODES and self._take_wake_failure(stream, inbound, receipt):
                return
        elif inbound.type == FrameType.RECORD_PLAY_CTRL:
            self._on_play_ctrl(stream, inbound.frame)
            return
        if (
            stream is not None
            and inbound.type == FrameType.NOTIFY_PAYLOAD
            and self._take_media_reply(stream, inbound)
        ):
            return  # not a result for whatever other command is waiting
        if inbound.type == FrameType.MEDIA_DOWNLOAD and self._take_late_still_reply(inbound):
            return

        matched = False
        for waiter in list(self._waiters):
            if waiter.future.done():
                continue
            try:
                result = waiter.match(inbound)
            except EufySecurityError as err:
                waiter.future.set_exception(err)
                matched = True
                continue
            except Exception:
                _LOGGER.exception("%s: request matcher failed", self._log_name)
                continue
            if result is not None:
                waiter.future.set_result(result)
                matched = True

        if receipt is not None:
            return  # not ciphertext: nothing for the built-in handlers
        if inbound.type == FrameType.PARAM_NOTIFY:
            self._handle_params(inbound)
        elif inbound.type == FrameType.ALARM_MODE_NOTIFY:
            value = inbound.alarm_mode()
            _LOGGER.debug("%s: alarm-mode report %s", self._log_name, value)
            if value is not None:
                self._note_mode_report(as_guard_mode(value))
        elif inbound.type in ALARM_FRAME_VALUES:
            self._handle_alarm(inbound.frame)
        elif inbound.type == FrameType.NOTIFY_PAYLOAD and (obj := inbound.json()) is not None:
            if _WIRE.isEnabledFor(logging.DEBUG):
                _WIRE.debug(
                    "%s: notify%s %s",
                    self._log_name,
                    "" if matched else " (no request waiting)",
                    Payload(obj),
                )
            # _decode_json only decodes ECB or GCM frames, so the tag always names one;
            # anything else is dropped rather than mislabelled as authenticated.
            tag = inbound.frame.cipher
            if tag is None or tag not in FrameCipher:
                return
            cipher = FrameCipher(tag)
            for listener in list(self._notify_listeners):
                try:
                    listener(obj, cipher)
                except Exception:
                    _LOGGER.exception("%s: notify listener failed", self._log_name)
            trusted = cipher is FrameCipher.GCM or self._session_ecb_frame(inbound.frame)
            if trusted and self._note_storage(obj):
                return
            event = decode_camera_push(obj, station_sn=self.serial, frame_cipher=cipher)
            if event is not None:
                if _LOGGER.isEnabledFor(logging.DEBUG):
                    _log_camera_push(self._log_name, event, cipher)
                self._last_event_at = time.monotonic()
                self._frames_by_cipher[cipher.name.lower()] += 1
                _count_capped(
                    self._events_by_type,
                    f"{_or_unknown(event.msg_type)}:{_or_unknown(event.event_type)}",
                )
                self._bus.emit(event)
                if event.authenticated:
                    self._check_stamped_account(event.raw)

    def _note_storage(self, obj: Mapping[str, Any]) -> bool:
        """Keep a storage record (asked for or pushed); whether ``obj`` was one.

        Only an authenticated (GCM) record is kept: it is station state.
        """
        record = storage_record(obj)
        if record is None:
            return False
        if record.code != 0 or record.body is None:
            _LOGGER.debug("%s: storage record without data (code %d)", self._log_name, record.code)
            return True
        self._keep_storage(parse_storage_info(record.body))
        return True

    def _keep_storage(self, info: StorageInfo) -> None:
        """Make ``info`` the current storage record; announce it when it changed."""
        if info != self._storage:
            self._storage = info
            _LOGGER.debug("%s: storage record %r", self._log_name, info)
            self._bus.emit(StorageChanged(station_sn=self.serial, storage=info))

    def _check_stamped_account(self, payload: Mapping[str, Any]) -> None:
        """Emit :class:`AccountMismatch` once per connection when no stamp is the session's id.

        Only authenticated pushes reach here: an ECB frame is forgeable by anyone on
        the LAN. Neither id is logged except as a :class:`Secret`.
        """
        creds = self._creds
        if self._account_mismatch_reported or creds is None:
            return
        stamped = stamped_accounts(payload)
        if not stamped or creds.account_id.lower() in stamped:
            return
        self._account_mismatch_reported = True
        self._account_mismatch_seen = True
        _LOGGER.warning(
            "%s: the station stamps its records with another account id than the one "
            "commands carry (%s, stamped %s); commands may be dropped silently",
            self._log_name,
            Secret(creds.account_id),
            Secret(", ".join(sorted(stamped))),
        )
        self._bus.emit(AccountMismatch(station_sn=self.serial))

    def _handle_params(self, inbound: Inbound) -> None:
        obj = inbound.json()
        if obj is None:
            return
        dump = ParamDump()
        dump.ingest(obj, aliases=self._block_aliases)
        self._merge_dump(dump, "read" if self._probing else "unsolicited", time.time())
        now = time.monotonic()
        straggler = self._probe_ended_at is not None and now - self._probe_ended_at < PARAM_SETTLE
        if not self._probing and not straggler and self._reprobe_at is None:
            # A dump nobody asked for means something changed at the house — and a
            # guard change made outside P2P may send no 0x047F, so ask for everything.
            # A block right after this session's own read is that read's late sub-device block.
            self._reprobe_at = now + UNSOLICITED_REPROBE_DELAY
        if not self._probing:
            self._note_pushed_blocks(dump.devices)

    def _merge_dump(
        self,
        dump: ParamDump,
        origin: str,
        now: float,
        stamps: Mapping[int, float] | None = None,
        *,
        source: EventSource = EventSource.P2P,
    ) -> None:
        """Merge ``dump`` into the held parameters: emit each change, then the guard modes.

        ``stamps`` date values by parameter id (a cloud snapshot); others date from ``now``.
        """
        self._meta.update(dump.meta)
        flat = dump.flatten()
        changed = sum(
            1 for key, new in flat.items() if key in self._params and self._params[key] != new
        )
        _LOGGER.debug(
            "%s: parameter dump (%s): channels %s, %d value(s), %d changed",
            self._log_name,
            origin,
            sorted(dump.devices),
            len(flat),
            changed,
        )
        for key, new in flat.items():
            known = key in self._params
            old = self._params.get(key)
            self._params[key] = new
            self._param_at[key] = stamps.get(key[1], now) if stamps else now
            if known and old != new:
                if key[0] not in self._alias_copies and _LOGGER.isEnabledFor(logging.DEBUG):
                    info = self._param(key[1], key[0])
                    _LOGGER.debug(
                        "%s: param ch%d/%d: %s → %s / %s",
                        self._log_name,
                        key[0],
                        key[1],
                        info.raw(old),
                        info.raw(new),
                        info.change(old, new),
                    )
                self._bus.emit(
                    ParamChanged(
                        station_sn=self.serial, channel=key[0], param_id=key[1], old=old, new=new
                    )
                )
        mode, active = dump.guard_mode, dump.active_mode
        if mode is not None or active is not None:
            self._set_modes(mode, active, source=source)

    def _handle_alarm(self, frame: Frame) -> None:
        """An alarm frame (tone, siren, light): cache its value per channel, emit
        :class:`ParamChanged` when it moved, and :class:`AlarmChanged` when a tone frame
        starts or ends the alarm. Only GCM frames, and an RSA session's frames under its
        key, count (:meth:`_refuse_ecb_state`)."""
        if self._refuse_ecb_state(frame):
            return
        if self._session_ecb_frame(frame):
            if len(frame.payload) % 16:
                self._dropped_undecodable += 1
                return
            plain = ecb_decrypt(cast(bytes, self._aes_key), frame.payload)
        elif frame.cipher != FrameCipher.GCM or self._session_key is None:
            return
        else:
            try:
                plain = gcm_decrypt_broadcast(self._session_key, frame.payload)
            except ProtocolError:
                self._dropped_undecodable += 1
                return
        alarm = decode_alarm_frame(frame, plain)
        if alarm is None:
            self._dropped_undecodable += 1
            return
        _LOGGER.debug(
            "%s: alarm frame %d ch%d %s / %s",
            self._log_name,
            alarm.param_id,
            alarm.channel,
            alarm.values,
            self._param(alarm.param_id, alarm.channel).describe(),
        )
        key = (alarm.channel, alarm.param_id)
        old, new = self._params.get(key), alarm.value
        if old != new:
            self._params[key] = new
            self._bus.emit(
                ParamChanged(
                    station_sn=self.serial,
                    channel=alarm.channel,
                    param_id=alarm.param_id,
                    old=old,
                    new=new,
                )
            )
        change = alarm.alarm_change(self.serial)
        if change is not None and change.alarming != self._alarming:
            self._alarming = change.alarming
            _LOGGER.debug("%s: alarm %s", self._log_name, "on" if change.alarming else "off")
            self._bus.emit(change)

    def _note_pushed_blocks(self, channels: Iterable[int]) -> None:
        """Track a frame of an unsolicited dump; signal its completion (see
        :meth:`add_dump_listener`) at once when the station block and every expected
        channel are in, else :data:`PARAM_SETTLE` seconds after its last frame."""
        self._push_channels.update(channels)
        self._cancel_push_timer()
        expected = {STATION_CHANNEL, *self._expect_channels}
        if len(expected) > 1 and expected <= self._push_channels:
            self._complete_dump(None)
        else:
            self._push_timer = asyncio.get_running_loop().call_later(
                PARAM_SETTLE, self._complete_dump, None
            )

    def _cancel_push_timer(self) -> None:
        if self._push_timer is not None:
            self._push_timer.cancel()
            self._push_timer = None

    def _complete_dump(self, carried: Collection[int] | None) -> None:
        """A dump completed; ``carried``: the blocks of a full read (others are dropped).

        Only pass ``carried`` for a read that waited for every expected channel — then a
        block that is absent really has departed. A read that gave up waiting must pass
        ``None``: dropping a block that was merely late erases the device's whole
        parameter set, and a camera would vanish from the caller's state, battery and
        signal entities with it, until the next complete dump.
        """
        self._cancel_push_timer()
        self._push_channels.clear()
        if carried is not None:
            for key in [key for key in self._params if key[0] not in carried]:
                del self._params[key]
                # The freshness stamp is only meaningful with the value it describes.
                # Leaving it behind leaks a key per departed device, and a re-paired
                # device's fresh cloud value would be rejected as older than a stamp
                # that outlived the value.
                self._param_at.pop(key, None)
        self._notify_dump_listeners()

    def _notify_dump_listeners(self) -> None:
        for listener in list(self._dump_listeners):
            try:
                listener()
            except Exception:
                _LOGGER.exception("%s: parameter dump listener failed", self._log_name)

    def _note_mode_report(self, value: GuardMode | int) -> None:
        """A ``0x047F`` report: the effective mode.

        Outside Schedule (or before the selection is known) the selected mode is the
        same. While Schedule is selected the report is a slot boundary — or a change of
        selection that says the same thing, so a parameter read is cued to tell them
        apart; a report of the mode this session's own arm asks for is that arm's. A report
        during an arm to Schedule is the slot's mode that selection put in force; the arm's
        read-back confirms the selection (or corrects it).
        """
        arming = self._arming_to
        if arming is GuardMode.SCHEDULE:
            self._set_modes(GuardMode.SCHEDULE, value)
            return
        if self._guard_mode != GuardMode.SCHEDULE or value == arming:
            self._set_modes(value, value)
            return
        self._set_modes(None, value)
        if self._reprobe_at is None:
            self._reprobe_at = time.monotonic() + UNSOLICITED_REPROBE_DELAY

    def _apply_modes(self, mode: GuardMode | int | None, active: GuardMode | int | None) -> bool:
        """Update the selected and effective mode; whether either changed.

        None leaves a value as it is, except that a selected mode other than Schedule
        without an effective one is its own effective mode.
        """
        before = (self._guard_mode, self._active_mode)
        if mode is not None:
            self._guard_mode = mode
        if active is not None:
            self._active_mode = active
        elif mode is not None and mode != GuardMode.SCHEDULE:
            self._active_mode = mode
        return (self._guard_mode, self._active_mode) != before

    def _set_modes(
        self,
        mode: GuardMode | int | None,
        active: GuardMode | int | None,
        *,
        source: EventSource = EventSource.P2P,
    ) -> None:
        """Apply the modes the station reported; emit :class:`GuardModeChanged` on a change."""
        before = (self._guard_mode, self._active_mode)
        if not self._apply_modes(mode, active) or self._guard_mode is None:
            return
        _LOGGER.debug(
            "%s: guard mode %r → %r", self._log_name, before, (self._guard_mode, self._active_mode)
        )
        self._bus.emit(
            GuardModeChanged(
                station_sn=self.serial,
                mode=self._guard_mode,
                active_mode=self._active_mode,
                source=source,
            )
        )

    def _refuse_ecb_state(self, frame: Frame) -> bool:
        """Whether ``frame`` is ECB-ciphered state that a GCM session must not trust.

        The single choke point for that refusal: every reader of a parameter dump (0x044F),
        a guard-mode report (0x047F) or an alarm frame (0x04B1, 0x04B2, 0x0578) gets its
        value through :meth:`_decode_json`, :meth:`_decode_alarm_mode` or
        :meth:`_handle_alarm`, which all ask here. The static ECB key is
        derivable from the serial and DID alone, so once a session key exists, only
        GCM state is authenticated. ECB image replies, scalar results and camera
        pushes are not state and still decode. On an RSA session, state under its
        session key (encryption type 2) is the station's own and decodes; state under
        the static key or in clear is refused.
        """
        if frame.cipher != FrameCipher.ECB or frame.type not in _STATE_FRAME_TYPES:
            return False
        if self._aes_key is not None:
            if self._session_ecb_frame(frame):
                return False
        elif self._session_key is None:
            return False
        self.ecb_state_refused += 1
        if self._throttle.should_log(("ecb-state", frame.type)):
            _LOGGER.debug(
                "%s: refusing static-key ECB state frame 0x%04x (%d refused)",
                self._log_name,
                frame.type,
                self.ecb_state_refused,
            )
        return True

    def _decode_alarm_mode(self, frame: Frame) -> int | None:
        if self._refuse_ecb_state(frame):
            return None
        return decode_alarm_mode_notify(
            frame, static_key=self._ecb_key(frame), session_key=self._session_key
        )

    def _decode_json(self, frame: Frame) -> dict[str, Any] | None:
        payload = frame.payload
        if self._refuse_ecb_state(frame):
            return None
        if self._plain_rsa_frame(frame):
            # An RSA session's clear frame (encryption type 0): a receipt, or JSON.
            if decode_command_receipt(frame, clear=True) is not None:
                return None
            return self._counted_json(payload)
        if (
            frame.cipher == FrameCipher.ECB
            and frame.type in _CLEAR_REPLY_TYPES
            and payload[:1] == b"{"
        ):
            # A standalone T8170 answers database queries and still fetches in clear
            # JSON under the ECB tag. Replies, not state: each
            # binds to its request by cmd, transaction or path.
            return self._counted_json(payload)
        if frame.cipher == FrameCipher.ECB:
            key = self._ecb_key(frame)
            if key is None:
                return None
            if len(payload) < 16 or len(payload) % 16:
                self._dropped_undecodable += 1
                return None
            return self._counted_json(ecb_decrypt(key, payload))
        if frame.cipher == FrameCipher.GCM:
            if self._session_key is None or len(payload) < 29:
                return None
            if decode_command_receipt(frame) is not None:
                return None  # a command receipt: GCM-tagged, but not ciphertext
            try:
                return self._counted_json(gcm_decrypt_broadcast(self._session_key, payload))
            except ProtocolError:
                self._dropped_undecodable += 1
                if self._throttle.should_log(("gcm-auth", frame.type)):
                    _LOGGER.debug(
                        "%s: frame 0x%04x failed GCM authentication", self._log_name, frame.type
                    )
                return None
        return None

    def _counted_json(self, plain: bytes) -> dict[str, Any] | None:
        """The JSON object in ``plain``; one that has none counts as undecodable."""
        obj = decode_json_payload(plain)
        if obj is None:
            self._dropped_undecodable += 1
        return obj

    @staticmethod
    def _command_code(inbound: Inbound, command: int) -> int | None:
        """The result code when ``inbound`` is ``command``'s own reply, else None.

        A reply carries no correlation id but its ``cmd``, so only a 0x0547 whose
        JSON decodes and names ``command`` counts. Never a result: a frame that does
        not decode (it cannot be attributed), a camera push (cmd 2037), another
        command's reply, a reply whose code is not an integer, and the undecoded
        0x04B1/0x04B2 blocks seen after an arm. The code is ``code`` or ``mIntRet``
        (absent = 0).
        """
        if inbound.type != FrameType.NOTIFY_PAYLOAD or (obj := inbound.json()) is None:
            return None
        cmd = json_int(obj.get("cmd"))
        if cmd is None or cmd == CMD_CAMERA_PUSH_NOTIFY or cmd != command:
            return None
        for key in ("code", "mIntRet"):
            if key in obj:
                return json_int(obj[key])
        return 0

    # ── request plumbing ─────────────────────────────────────────────────────

    def _add_waiter(self, match: Matcher) -> _Waiter:
        waiter = _Waiter(match, asyncio.get_running_loop().create_future())
        self._waiters.append(waiter)
        return waiter

    def _remove_waiter(self, waiter: _Waiter) -> None:
        if waiter in self._waiters:
            self._waiters.remove(waiter)
        if not waiter.future.done():
            waiter.future.cancel()
        elif not waiter.future.cancelled():
            waiter.future.exception()  # retrieved: a caller that stopped early is not "unhandled"

    def _fail_waiters(self, exc: Exception) -> None:
        self._fail_media(exc)
        for waiter in self._waiters:
            if not waiter.future.done():
                waiter.future.set_exception(exc)

    async def _request(
        self,
        send: Callable[[], object],
        match: Matcher,
        *,
        timeout: float,
        resend_after: float | None = None,
        label: str = "request",
        send_only_under_lock: bool = False,
    ) -> object:
        """Register ``match`` BEFORE sending, then wait for its first non-None result.

        ``send_only_under_lock``: take the command lock for the send alone and wait
        for the reply outside it, so a guard-mode write is not held up by a slow
        reply. Only for a request whose ``match`` binds its own reply (a path or a
        transaction) and that is serialised against its own kind by the caller.
        """
        if send_only_under_lock and resend_after is not None:
            raise ValueError("a request that waits outside the lock is never resent")
        waiter: _Waiter | None = None
        try:
            lock = self._op(label) if send_only_under_lock else contextlib.nullcontext()
            async with lock:  # registered once the send is due, so no earlier frame binds
                waiter = self._add_waiter(match)
                send()
            started = time.monotonic()
            deadline = started + timeout
            if resend_after is not None and resend_after < timeout:
                await asyncio.wait({waiter.future}, timeout=resend_after)
                if not waiter.future.done():
                    _LOGGER.debug(
                        "%s: %s unanswered after %.1fs; resending",
                        self._log_name,
                        label,
                        resend_after,
                    )
                    send()
            if not await self._wait_until(waiter.future, deadline, label):
                _LOGGER.debug("%s: %s: no reply within %.0fs", self._log_name, label, timeout)
                raise DeviceTimeoutError(f"no reply from the station within {timeout:.0f}s")
            _LOGGER.debug(
                "%s: %s answered in %.0f ms",
                self._log_name,
                label,
                (time.monotonic() - started) * 1000,
            )
            return waiter.future.result()
        finally:
            if waiter is not None:
                self._remove_waiter(waiter)

    async def _wait_until(
        self, future: asyncio.Future[object], deadline: float, label: str
    ) -> bool:
        """Wait for ``future`` until ``deadline`` (monotonic); whether it is done.

        The wait runs in steps of :data:`LOOP_STALL_STEP`. A step that ends at least
        :data:`LOOP_STALL_LATENESS` late means something else held the event loop, and
        replies that arrived meanwhile are still queued (read one datagram per loop turn):
        the deadline moves out by that lateness, up to :data:`LOOP_STALL_MAX` in all, so
        the station gets its full timeout of time in which this client could hear it.
        """
        credited = 0.0
        while not future.done():
            started = time.monotonic()
            left = deadline + credited - started
            if left <= 0:
                break
            step = min(left, LOOP_STALL_STEP)
            await asyncio.wait({future}, timeout=step)
            late = time.monotonic() - started - step
            if late >= LOOP_STALL_LATENESS and credited < LOOP_STALL_MAX:
                extra = min(late, LOOP_STALL_MAX - credited)
                credited += extra
                _LOGGER.debug(
                    "%s: %s: the event loop was held %.1fs; deadline moved out by %.1fs",
                    self._log_name,
                    label,
                    late,
                    extra,
                )
        return future.done()

    async def _listen(
        self,
        handler: Callable[[Inbound], None],
        duration: float,
        *,
        until: Callable[[], bool] | None = None,
    ) -> None:
        """Feed frames to ``handler`` for ``duration`` seconds, or until ``until()`` holds."""

        def match(inbound: Inbound) -> bool | None:
            handler(inbound)
            return True if until is not None and until() else None

        waiter = self._add_waiter(match)
        try:
            await asyncio.wait({waiter.future}, timeout=duration)
        finally:
            self._remove_waiter(waiter)
        _raise_waiter_error(waiter)

    def _send_secure(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int:
        """Send ``plaintext`` under the session's cipher: GCM after an ECIES handshake,
        AES-128-ECB under the session key after an RSA one (subheader
        ``01 <seq> <dev_type> 02 <flag> 00``, as the app sends every command then)."""
        if self._aes_key is not None:
            return self._send_session_ecb(
                plaintext, frame_type=frame_type, dev_type=dev_type, flag=flag
            )
        key = self._session_key
        if key is None:
            raise StationUnreachableError("no P2P session")
        seq = self._gcm_seq
        self._gcm_seq += 1
        nonce = os.urandom(12)
        payload = gcm_encrypt_command(key, plaintext, nonce=nonce, seq=seq)
        self._gcm_counter = (self._gcm_counter + 2) & 0xFF
        frame = encode_frame(
            frame_type, payload, gcm_subheader(self._gcm_counter, dev_type, flag=flag)
        )
        if _WIRE.isEnabledFor(logging.DEBUG):
            obj = decode_json_payload(plaintext)
            _WIRE.debug(
                "%s: tx GCM frame 0x%04x seq 0x%08x nonce %s: %s",
                self._log_name,
                frame_type,
                seq,
                Secret(nonce),
                plaintext.hex() if obj is None else Payload(obj),
            )
        return self._require_transport().send_drw(0, frame)

    def _send_session_ecb(
        self, plaintext: bytes, *, frame_type: int, dev_type: int, flag: int
    ) -> int:
        """An RSA session's frame: AES-128-ECB under the session key, zero-padded."""
        key = cast(bytes, self._aes_key)
        seq = self._ecb_seq
        self._ecb_seq = (seq + 1) & 0xFF
        subheader = bytes(
            [FrameCipher.ECB, seq, dev_type & 0xFF, FRAME_SESSION_ECB, flag & 0xFF, 0x00]
        )
        frame = encode_frame(frame_type, ecb_encrypt(key, plaintext), subheader)
        if _WIRE.isEnabledFor(logging.DEBUG):
            obj = decode_json_payload(plaintext)
            _WIRE.debug(
                "%s: tx session-ECB frame 0x%04x seq %d: %s",
                self._log_name,
                frame_type,
                seq,
                plaintext.hex() if obj is None else Payload(obj),
            )
        return self._require_transport().send_drw(0, frame)

    def _ecb_key(self, frame: Frame) -> bytes | None:
        """The key of an ECB-tagged station frame: the RSA session's key when its
        encryption type (subheader byte 3) is 2, else the static key."""
        if self._aes_key is not None and frame_encryption(frame.subheader) == FRAME_SESSION_ECB:
            return self._aes_key
        return self._static_key

    def _rsa_play_ctrl(self, frame: Frame) -> int | None:
        """An RSA session's end-of-playback value: the first ``u32le`` of a clear body,
        or of one under its key."""
        body = frame.payload
        if self._session_ecb_frame(frame):
            if not body or len(body) % 16:
                return None
            body = ecb_decrypt(cast(bytes, self._aes_key), body)
        elif not self._plain_rsa_frame(frame):
            return None
        return int.from_bytes(body[:4], "little") if len(body) >= 4 else None

    def _session_ecb_frame(self, frame: Frame) -> bool:
        """Whether ``frame`` is ECB under an RSA session's key: authenticated by the key
        only the cipher's owner could unwrap, unlike the static key."""
        return (
            self._aes_key is not None
            and frame.cipher == FrameCipher.ECB
            and frame_encryption(frame.subheader) == FRAME_SESSION_ECB
        )

    def _plain_rsa_frame(self, frame: Frame) -> bool:
        """Whether ``frame`` is an RSA session's clear frame (encryption type 0)."""
        return self._aes_key is not None and frame_encryption(frame.subheader) == FRAME_PLAIN

    def _unanswered_error(
        self, command: int, channel: int, indices: Sequence[int]
    ) -> CommandNotAppliedError | DeviceTimeoutError:
        if self._acked(indices, channel):
            return CommandNotAppliedError(
                command,
                f"the station acknowledged command {command} but never acted on it — usually an "
                "account_id that is not the station owner's",
            )
        return DeviceTimeoutError(f"command {command} got no answer from the station")

    def _acked(self, indices: Sequence[int], channel: int = 0) -> bool:
        """Whether the station acknowledged any of the DRW chunks ``indices`` on ``channel``."""
        transport = self._transport
        return transport is not None and any(transport.is_acked(channel, i) for i in indices)

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise StationUnreachableError("session closed")

    def _require_transport(self) -> PPPPTransport:
        if self._transport is None or not self._transport.is_open:
            raise StationUnreachableError("P2P link is not open")
        return self._transport

    def _require_creds(self) -> P2PCredentials:
        if self._creds is None:
            raise CommunicationError("session credentials not loaded")
        return self._creds

    def _require_static_key(self) -> bytes:
        if self._static_key is None:
            raise StationUnreachableError("no P2P link")
        return self._static_key


def _session_budget(value: object) -> int:
    """``value`` as a session budget, or ``ValueError`` outside the range the station takes."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not MIN_STATION_SESSIONS <= value <= STATION_SESSION_LIMIT
    ):
        raise ValueError(
            f"max_sessions must be an int from {MIN_STATION_SESSIONS} to "
            f"{STATION_SESSION_LIMIT}, not {value!r}"
        )
    return value


def _command_header_channel(channel: int) -> int:
    """The subheader channel (byte 2) of a 1350 command to ``channel``: the device's
    channel, 0 for the station (255).

    A HomeBase passes a command on to a paired Wi-Fi camera (a T8170) only when the
    header names its channel; with 0 it answers receipt -108 (see
    docs/protocol/p2p-transport.md).
    """
    return 0 if channel == STATION_CHANNEL else channel


def _receipt_error(command: int, code: int) -> CommandRejectedError:
    """The error a non-zero command receipt raises."""
    name = RECEIPT_CODES.get(code, "")
    if code == RECEIPT_NOT_HANDLED:
        return CommandUnsupportedError(command, code, name)
    if code in CAMERA_WAKE_CODES:
        return CameraWakeError(command, code, f"the station could not wake the camera ({name})")
    return CommandRejectedError(command, code, f"command receipt {name}".rstrip())


def _lost_cause(exc: Exception, *, asleep: bool) -> DisconnectCause:
    """The cause an announced link's loss is reported under."""
    if asleep:
        return DisconnectCause.IDLE
    if isinstance(exc, StationClosedLinkError):
        return DisconnectCause.STATION_CLOSED
    if isinstance(exc, SilentLinkError):
        return DisconnectCause.LINK_SILENT
    return DisconnectCause.UNREACHABLE  # the local socket closed


def _wrapped_key(payload: bytes) -> bytes | None:
    """The RSA-wrapped key bytes of a keyframe record, None when the body cannot hold one."""
    if len(payload) < VIDEO_HEADER_LEN:
        return None
    body = payload[VIDEO_HEADER_LEN : VIDEO_HEADER_LEN + KEYFRAME_RSA_LEN]
    data_len = int.from_bytes(payload[:4], "little")
    return body if data_len >= KEYFRAME_MIN and len(body) == KEYFRAME_RSA_LEN else None


def _log_camera_push(log_name: str, event: SecurityEvent, cipher: FrameCipher) -> None:
    """Two redacted DEBUG lines for a decoded camera push: what arrived, and what was bound.

    No serial (only :func:`redact_serial`), path, record id, unique id or name is logged:
    the full payload goes to the wire logger only.
    """
    _LOGGER.debug(
        "%s: camera push %s:%s under %s from %s ch%s%s",
        log_name,
        _or_unknown(event.msg_type),
        _or_unknown(event.event_type),
        cipher.name.lower(),
        redact_serial(event.device_sn),
        _or_unknown(event.channel),
        "" if event.push_count is None else f", push_count {event.push_count}",
    )
    raw = event.raw
    attached = [_list_len(raw.get(key)) for key in ("rec_content", "pic_content")]
    _LOGGER.debug(
        "%s: push binding: record_id %s, attached %d record(s) / %d crop(s); bound thumb %s, "
        "video %s, crop %s; rejected %s",
        log_name,
        "present" if event.record_id else "absent",
        attached[0],
        attached[1],
        event.thumb_path is not None,
        event.video_path is not None,
        event.crop_path is not None,
        ", ".join(sorted(event.rejected_fields)) or "none",
    )


def _list_len(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _frame_camera(frame: Frame) -> int | None:
    """The channel a station media frame carries (subheader byte 2), or None."""
    return frame.subheader[2] if len(frame.subheader) > 2 else None


def _record_day(record_id: int) -> date:
    """The day of a date-prefixed ``record_id``; ValueError when it has none."""
    day = record_id_day(record_id)
    if day is None:
        raise ValueError(f"record_id {record_id} carries no day")
    return day


def _parse_day(text: str) -> date:
    """A ``YYYYMMDD`` date; ValueError for anything else."""
    if len(text) != 8 or not text.isascii() or not text.isdigit():
        raise ValueError(f"not a YYYYMMDD date: {text!r}")
    return date(int(text[:4]), int(text[4:6]), int(text[6:]))


def _raise_for_code(command: int, code: int) -> None:
    if code != 0:
        raise CommandRejectedError(command, code, ECB_RESULT_CODES.get(code, ""))


def _raise_waiter_error(waiter: _Waiter) -> None:
    """Re-raise an exception the dispatcher set on ``waiter`` (session loss, a rejection)."""
    future = waiter.future
    if future.done() and not future.cancelled() and (error := future.exception()) is not None:
        raise error


async def _wait_any(future: asyncio.Future[object], event: asyncio.Event, timeout: float) -> None:
    """Wait until ``future`` is done or ``event`` is set, for at most ``timeout`` seconds."""
    if future.done() or event.is_set() or timeout <= 0:
        return
    flag = asyncio.ensure_future(event.wait())
    either: set[asyncio.Future[Any]] = {future, flag}
    try:
        await asyncio.wait(either, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        flag.cancel()


def _or(value: float | None, default: float) -> float:
    return default if value is None else value


def _or_unknown(value: int | None) -> str:
    return "?" if value is None else str(value)
