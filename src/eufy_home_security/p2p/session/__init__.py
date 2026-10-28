"""A P2P session with one station.

One :class:`StationSession` owns one :class:`~..transport.PPPPTransport` and
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
* **Events.** Parameter dumps are diffed into :class:`~...events.ParamChanged`,
  guard-mode reports become :class:`~...events.GuardModeChanged`, camera pushes
  become :class:`~...events.SecurityEvent`, and the alarm frames (tone, siren, light)
  become :class:`~...events.ParamChanged` plus :class:`~...events.AlarmChanged` on an
  alarm's start and end.
* **Media.** One :class:`MediaStream` at a time (live video or a stored
  recording) receives the video and audio frames of DRW channel 1.
* **Liveness.** An idle home is silent and the transport answers keepalives even
  when the encrypted session is dead, so the only honest check is an
  application round trip: :meth:`async_start` probes with a parameter query on a
  fixed schedule (independent of other traffic) and reconnects when it goes
  unanswered. :class:`~...events.ConnectionChanged` ``connected=True`` is emitted
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
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, cast

from ..._logging import (
    Address,
    LogThrottle,
    Payload,
    Secret,
    redact,
    redact_serial,
    register_secret_bytes,
    wire_logger,
)
from ...cloud.const import CIPHER_ID_P2P, KEY_REFRESH_SLOW_RETRY
from ...devices.device_alarm import USER_NAME_SLOT
from ...devices.live_open import LiveOpen, LiveStop
from ...devices.live_view import LiveView
from ...devices.param_info import ParamInfo, param_info
from ...devices.recipes import (
    ConnectType,
    Recipe,
    RecipeCommand,
    ResultFrom,
    connect_type,
)
from ...devices.settings import Scope
from ...events import (
    AccountMismatch,
    AlarmChanged,
    CloudProblem,
    ConnectionChanged,
    DisconnectCause,
    EventBus,
    EventCallback,
    HistoryRecord,
    SecurityEvent,
    StorageChanged,
    Unsubscribe,
    as_guard_mode,
)
from ...exceptions import (
    CipherUnusableError,
    CloudError,
    CommandNotAppliedError,
    CommandRejectedError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    KeyRejectedError,
    ProtocolError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
)
from ...models import STATION_CHANNEL, GuardMode
from ...recordings import RecordingRef
from .._json import json_int
from ..alarm import ALARM_FRAME_VALUES, AlarmFrame, decode_alarm_frame
from ..clip import ClipWriter, MediaClip
from ..crypto import (
    CONN_INIT_NO_CIPHER,
    CONN_INIT_RSA_BLOB_LEN,
    FRAME_PLAIN,
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
from ..did import Did, static_key
from ..media import (
    DECODABLE_STILLS,
    PLAYBACK_ENDED,
    MediaKeyType,
    Still,
    VideoCodec,
    classify_still,
    decode_record_play_ctrl,
    decode_still,
    media_variant_label,
    video_codec_label,
)
from ..messages import (
    CAMERA_WAKE_CODES,
    CMD_CAMERA_PUSH_NOTIFY,
    CMD_DATABASE,
    CMD_DATABASE_IMAGE,
    CMD_DOWNLOAD_VIDEO,
    CMD_RECORD_VIEW,
    CMD_SET_ARMING,
    CMD_SET_DEVS_TONE_FILE,
    CMD_SET_TONE_FILE,
    DB_EVENT_COUNT,
    ECB_RESULT_CODES,
    PARAM_QUERY_ALL,
    RECEIPT_CODES,
    RECEIPT_TAKEN,
    arm_payload,
    conn_init_request,
    database_query_payload,
    decode_alarm_mode_notify,
    decode_command_receipt,
    decode_command_result,
    decode_database_rows,
    decode_ecb_scalar_result,
    decode_image_content,
    decode_json_payload,
    device_msg,
    encode_ecb_scalar_frame,
    event_count_payload,
    gcm_subheader,
    image_request_payload,
    native_recording_frame,
    string_command_body,
    tone_file_payload,
)
from ..mode_actions import CMD_SET_ALL_ACTION, ModeTable
from ..notify import decode_camera_push, stamped_accounts
from ..params import ParamDump
from ..pppp import DISCOVERY_PORT, DrwChunk
from ..storage_info import (
    CMD_HUB_STORAGE,
    CMD_SD_INFO,
    CMD_STORAGE,
    StorageInfo,
    hub_storage_query_payload,
    parse_hub_storage,
    parse_sd_card_info,
    parse_storage_info,
    result_code,
    storage_query_payload,
    storage_record,
)
from ..transport import PPPPTransport, SilentLinkError, StationClosedLinkError, Wake
from ..xzyh import Frame, FrameCipher, FrameType, StreamDecoder, encode_frame
from .budget import SessionBudget
from .core import _RECORDING_COMMANDS, Inbound, Matcher, _receipt_error, _rejection
from .history import HistoryQueries
from .keys import SessionKeys
from .media_slot import MediaSlot, MediaWaits
from .media_stream import MediaStream
from .param_state import ParamOrigin, ParamState
from .stats import HealthCounters, MediaCounters, SessionStats, count_capped
from .wake import WakeBackoff

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("p2p")
"""Full decoded payloads (paths, serials, names): off unless wire logging is enabled."""

DISCOVERY_ATTEMPTS = 3
OP_LOCK_WAIT_LOG = 0.05
"""A wait for the command lock at least this long (seconds) gets a DEBUG line."""
DISCOVERY_TIMEOUT = 6.0
DISCOVERY_RETRY_DELAY = 0.5
"""Pause (seconds) before the next discovery attempt after one failed; none after the last."""
HANDSHAKE_TIMEOUT = 6.0
COMMAND_TIMEOUT = 6.0
TONE_CONFIRM_TIMEOUT = 10.0
"""How long (seconds from the call) a SET_TONE_FILE write left without a result waits
for the alarm-tone frame."""
LOOP_STALL_STEP = 0.25
"""A reply wait checks this often (seconds) whether the event loop was held."""
LOOP_STALL_LATENESS = 0.1
"""A wait step ending at least this late means something else held the event loop; the
reply deadline moves out by the step's duration (replies that arrived meanwhile are still
queued)."""
LOOP_STALL_MAX = 30.0
"""The most a reply deadline moves out for a held event loop, in all."""
PARAM_QUERY_TIMEOUT = 8.0
"""A parameter dump's wait for the station's own block."""
STILL_FETCH_TIMEOUT = 12.0
"""A still (1308) download's wait."""
COMMAND_RESEND_AFTER = 1.5
RSA_RESULT_WINDOW = 35.0
"""How long (seconds) after a send on an RSA session a channel-0 frame of the sent type
is read as its result: the longest the eufy app waits for one (declared)."""
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
MEDIA_DRAIN_GAP = 0.5
"""Opening a stream waits until no media frame has arrived for this long. A recording
closed early on this session keeps streaming to its end (no command stops a playback,
only closing the session does), a stopped live stream sends what was in flight, and
those frames carry no stream id: they would otherwise be delivered as the next stream's."""
MEDIA_DRAIN_MAX = 5.0
"""The longest an open waits for the previous stream to go quiet."""
EVENT_COUNT_RESEND = 2.0
"""How often an unanswered event-count query (10013) is sent again: a just-woken T8170
ignores one sent immediately but answers one sent 5 s later within 0.3 s."""
STORAGE_TIMEOUT = 30.0
"""Seconds a JSON storage query waits for its reply: the app's default request timeout.
A station that refuses the query ends the wait sooner with its receipt (a HomeBase 2
sent -1 after 18 s)."""
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
"""Largest CONN_INIT payload accepted. A real one is a few hundred bytes; a larger one
(corrupt, or from whatever won the punch race on the LAN) is dropped before any of the
handshake's decryption runs on the event loop."""

HISTORY_QUERY_TIMEOUT = 15.0
"""Seconds one station database query (a history page 10011, the event count 10013, an
event list) waits for its answer. An idle HomeBase 3 answers a history page within 3 s; a
busy one takes longer and sometimes leaves a query unanswered that it answers when asked
again, so a listing asks a page once more after a timeout."""
STILL_LATE_REPLY_WINDOW = 30.0
"""After a 1308 request times out, the next 1308 reply within this many seconds is
taken as its late answer and discarded, so it cannot answer a later request."""

_MEDIA_FRAME_TYPES = frozenset({FrameType.VIDEO_FRAME, FrameType.AUDIO_FRAME})
_STATE_FRAME_TYPES = frozenset(
    {FrameType.PARAM_NOTIFY, FrameType.ALARM_MODE_NOTIFY, *ALARM_FRAME_VALUES}
)
"""Frames carrying station state, taken under any encryption
(:meth:`StationSession._take_state`)."""
_UNAUTHENTICATED_STATE: Mapping[str, str] = MappingProxyType(
    {
        "clear": "in clear",
        "type1": "under the fixed key",
        "ecb": "under the fixed key",
        "other": "under an unknown encryption type",
    }
)
"""How the log line on unauthenticated state names each state-frame label."""
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
    """Supplies the :class:`~..transport.Wake` for a battery station (its rendezvous
    servers and a device session key), or None when it cannot be built (no DSK yet, a
    cloud outage). Called before each connection attempt of an on-demand session."""

    async def __call__(self) -> Wake | None: ...


class CredentialProvider(Protocol):
    """Supplies :class:`P2PCredentials`; ``refresh=True`` means the cached key failed.

    ``cipher_id`` is the cipher the station named in its CONN_INIT: the session asks
    after the handshake. None lets the provider pick (the cipher this station named
    last, else :data:`~...cloud.const.CIPHER_ID_P2P`).
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
        max_sessions = _session_budget(max_sessions)
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
        # The static key slices the id's text as the cloud lists it (see static_key).
        self._did_text = did if isinstance(did, str) else None
        self._port = port
        self._local_port = local_port

        self._transport: PPPPTransport | None = None
        self._creds: P2PCredentials | None = None
        self._cipher_id: int | None = None
        """The cipher the station named in its last CONN_INIT (None before one arrived)."""
        self._keys = SessionKeys(self.serial)
        self._conn_init_version: int | None = None
        """The version (subheader byte 0) of the last CONN_INIT reply."""
        self._did: Did | None = None
        self._decoders: dict[int, StreamDecoder] = {}
        self._results_due: dict[int, list[tuple[float, int]]] = {}
        """An RSA session's sends awaiting their result: frame type → (deadline (monotonic),
        slot), oldest first."""
        self._result_slot = 0
        """The slot of the latest RSA send awaiting its result (:meth:`_send_request`)."""

        self._closed = False
        self._waiters: list[_Waiter] = []
        self._connect_lock = asyncio.Lock()
        self._op_lock = asyncio.Lock()
        self._still_lock = asyncio.Lock()
        """Serialises still fetches, whose replies are owed in request order."""
        self._recipe_lock = asyncio.Lock()
        """Serialises recipes. A recipe's receipt is bound by frame type alone, and
        every standalone-device recipe shares type 1700, so two in flight would each be
        able to complete or fail on the other's receipt."""
        self._bus = EventBus()
        self._notify_listeners: list[Callable[[Mapping[str, Any], FrameCipher], None]] = []
        self._alarm_listeners: list[Callable[[AlarmFrame], None]] = []
        self._alarming = False
        """Whether the last alarm-tone frame started the alarm (see :meth:`_handle_alarm`)."""
        self._tone_waiters: list[tuple[bool, asyncio.Future[AlarmChanged]]] = []
        """SET_TONE_FILE writes waiting for an alarm-tone frame: (siren on?, result)."""
        self._siren_waiters: list[tuple[int, bool, asyncio.Future[None]]] = []
        """SET_DEVS_TONE_FILE writes waiting for a device-siren frame: (channel, on?,
        result)."""
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
        self._wake_backoff = WakeBackoff()
        """Per camera channel: the wake failures that refuse live opens for a while."""
        self._reprobe_at: float | None = None
        self._probing = False
        self._probe_ended_at: float | None = None
        """When this session's own parameter read last finished; stragglers right after
        it belong to that read."""
        self.ecb_state_refused = 0
        """Always 0 (:attr:`SessionStats.ecb_state_refused`)."""
        self._state_authenticated: bool | None = None
        """Whether authenticated state was taken; False after unauthenticated state only."""
        self._unauthenticated_logged: set[tuple[int, str]] = set()
        """The (frame type, encryption) kinds of unauthenticated state already logged."""
        self.still_file_mismatches = 0
        """1308 replies whose ``file`` differed from the requested path."""
        self.still_late_replies = 0
        """1308 replies discarded as the late answer to a timed-out request."""
        self._still_owed: deque[tuple[str, float]] = deque()
        """Timed-out 1308 requests whose reply may still arrive: (path, expiry)."""
        self._health = HealthCounters()
        self._last_error_name: str | None = None
        self._media_counters = MediaCounters()
        self._supervisor: asyncio.Task[None] | None = None
        self._throttle = LogThrottle()
        self._log_name = redact_serial(self.serial)
        self._history = HistoryQueries(self)
        self._param_state = ParamState(
            self.serial,
            bus=self._bus,
            log_name=self._log_name,
            throttle=self._throttle,
            param=self._param,
            block_aliases=block_aliases,
            expect_channels=expect_channels,
        )
        self._budget = SessionBudget(self, max_sessions=max_sessions)
        self._media_slot = MediaSlot(self)

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return (
            (self._keys.session_key is not None or self._keys.aes_key is not None)
            and self._transport is not None
            and self._transport.is_open
        )

    @property
    def rsa_session(self) -> bool:
        """Whether the station answered the RSA CONN_INIT, so the session runs
        AES-128-ECB under the key it carried instead of GCM."""
        return self._keys.rsa_session

    def video_codec(self, channel: int) -> VideoCodec | None:
        """The codec the latest keyframe picture of ``channel`` showed; None before any."""
        return self._media_counters.codecs_by_channel.get(channel)

    @property
    def static_key_session(self) -> bool:
        """Whether the RSA session's key is the static key: its CONN_INIT names no cipher,
        the cipher's RSA key does not parse, or the key it carries is the static key. Such a session authenticates nothing
        (the static key follows from the serial and DID): like the app, it takes the
        station's frames under every encryption type (clear, 1, 2), and none of its
        pushes is authenticated."""
        return self._keys.static_key_session

    @property
    def state_authenticated(self) -> bool | None:
        """See :attr:`SessionStats.state_authenticated`."""
        return self._state_authenticated

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
        return self._budget.max_sessions

    @max_sessions.setter
    def max_sessions(self, value: int) -> None:
        self._budget.max_sessions = _session_budget(value)
        self._budget.notify_capacity()

    @property
    def standalone(self) -> bool:
        """Whether this station is a standalone device (its own station, like a SoloCam),
        by the app's rule: its serial names no station kind (:func:`~...devices.recipes.connect_type`)."""
        return connect_type(self.serial, self.serial) is ConnectType.SINGLE

    @property
    def tags_live_camera(self) -> bool:
        """Whether this station's live frames name the streaming camera (subheader byte 2)
        and a frame for another camera is dropped: a HomeBase (serial ``T80…``), as in the
        eufy app's live decryptor. A standalone device's tag is not its channel (a T8442 and a
        T8200 tag channel-0 video 1), and the app does not check it there."""
        return "T80" in self.serial

    @property
    def homebase3(self) -> bool:
        """Whether this station is a HomeBase 3 (T8030): the app's live open then carries
        its multi-camera fields."""
        return connect_type(self.serial, self.serial) is ConnectType.HB3

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
        return self._param_state.guard_mode

    @property
    def active_mode(self) -> GuardMode | int | None:
        """The last effective guard mode known: the mode in force (param 1151, the
        ``0x047F`` report), which differs from :attr:`guard_mode` only under Schedule."""
        return self._param_state.active_mode

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
        return self._media_slot.live_channel

    def note_guard_mode(
        self, mode: GuardMode | int, active_mode: GuardMode | int | None = None
    ) -> None:
        """Record the modes a push delivered, without emitting a change.

        A report is emitted only when it differs from the last known modes; a change
        made elsewhere (the app) that only a push announced would otherwise swallow the
        report that moves the mode back. ``active_mode`` None: ``mode`` outside Schedule,
        else the effective mode stays as it was.
        """
        self._param_state.apply_modes(mode, active_mode)
        if not self.on_demand or self._param_state.guard_mode is None:
            return
        # A station reached on demand has no dump to follow the push: file the modes as
        # parameters, so its state (and a later, older cloud snapshot) sees them.
        self._param_state.file_modes("push")

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
        return self._param_state.ingest_cloud_params(dev_type, params)

    def apply_local_params(self, channel: int, values: Mapping[int, str]) -> None:
        """Merge parameter values a successful write just set on ``channel``, as one dump.

        The device does not report them back at once; the next real dump overrides them.
        A standalone device's values are filed under every alias of its block. Emits
        ``ParamChanged`` for each change and notifies the dump listeners.
        """
        self._param_state.apply_local_params(channel, values)

    @property
    def storage(self) -> StorageInfo | None:
        """The last storage record read or pushed on this session; None until one arrives."""
        return self._storage

    @property
    def params(self) -> Mapping[tuple[int, int], str | None]:
        """Every parameter held, keyed by ``(dev_type, param_id)``: the latest value of
        each, minus the blocks a full read no longer carries (see :meth:`add_dump_listener`)."""
        return self._param_state.params

    @property
    def param_origins(self) -> Mapping[tuple[int, int], ParamOrigin]:
        """The :attr:`params` keys whose value no dump delivered: a cloud snapshot's
        (:meth:`ingest_cloud_params`) or this library's own write
        (:meth:`apply_local_params`), until a dump carries the key again."""
        return self._param_state.param_origins

    def param_time(self, key: tuple[int, int]) -> float | None:
        """Epoch seconds :attr:`params` ``[key]`` dates from (see :meth:`ingest_cloud_params`);
        None when the key is not held."""
        return self._param_state.param_time(key)

    @property
    def expect_channels(self) -> frozenset[int]:
        """The paired sub-devices' channels every read without its own list waits for."""
        return self._param_state.expect_channels

    @expect_channels.setter
    def expect_channels(self, channels: Iterable[int]) -> None:
        self._param_state.expect_channels = channels

    @property
    def unread_dump_keys(self) -> frozenset[str]:
        """Top-level keys of this session's parameter dumps that the library does not read."""
        return self._param_state.unread_dump_keys

    def merged_params(self) -> ParamDump:
        """A copy of :attr:`params` and the latest frame-level fields, as one dump."""
        return self._param_state.merged_params()

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
        return self._param_state.add_dump_listener(callback)

    def add_notify_listener(
        self, callback: Callable[[Mapping[str, Any], FrameCipher], None]
    ) -> Unsubscribe:
        """Call ``callback(obj, cipher)`` with every JSON notify (0x0547) decoded, a
        request's answer included; returns the unsubscribe.

        An :attr:`~..models.FrameCipher.ECB` notify is forgeable by anyone on the LAN:
        use it for display state only. A failing callback is logged, never raised.
        """
        self._notify_listeners.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._notify_listeners.remove(callback)

        return unsubscribe

    def add_alarm_listener(self, callback: Callable[[AlarmFrame], None]) -> Unsubscribe:
        """Call ``callback(frame)`` with every alarm frame decoded (tone, siren, light),
        after the session took it; returns the unsubscribe. A failing callback is
        logged, never raised."""
        self._alarm_listeners.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._alarm_listeners.remove(callback)

        return unsubscribe

    def subscribe(self, callback: EventCallback) -> Unsubscribe:
        """Receive this session's events; returns the unsubscribe callable."""
        return self._bus.subscribe(callback)

    def stats(self) -> SessionStats:
        """A snapshot of this session's health counters (see :class:`SessionStats`)."""
        now = time.monotonic()
        live_drops = self._transport.wrong_port_drops if self._transport is not None else 0
        media = self._media_counters
        return SessionStats(
            connected=self.announced,
            connects=self._health.connects,
            reconnects=max(self._health.connects - 1, 0),
            handshake_failures=self._health.handshake_failures,
            key_refreshes=self._health.key_refreshes,
            last_error=self._last_error_name,
            seconds_since_last_probe=now - self._last_probe if self._last_probe else None,
            seconds_since_last_event=(
                None if self._health.last_event_at is None else now - self._health.last_event_at
            ),
            events_by_type=dict(self._health.events_by_type),
            frames_by_cipher=dict(self._health.frames_by_cipher),
            ecb_state_refused=self.ecb_state_refused,
            dropped_undecodable=self._health.dropped_undecodable,
            receipts_by_code=dict(self._health.receipts_by_code),
            wrong_port_drops=self._health.retired_wrong_port_drops + live_drops,
            account_mismatch_seen=self._health.account_mismatch_seen,
            media_opens=media.opens,
            media_failures_by_type=dict(media.failures),
            media_failures_by_channel={
                str(channel): dict(counts)
                for channel, counts in sorted(media.failures_by_channel.items())
            },
            media_frames_by_variant=dict(media.variants),
            media_video_codecs=dict(media.codecs),
            media_codecs_by_channel={
                str(channel): codec.value
                for channel, codec in sorted(media.codecs_by_channel.items())
            },
            media_codec_overrides=dict(media.codec_overrides),
            media_empty_nals=media.empty_nals,
            media_frames_without_nal=media.frames_without_nal,
            media_keyframes_rejected=media.keyframes_rejected,
            media_keyframe_continuations=media.keyframe_continuations,
            media_first_records=tuple(media.first_records),
            media_rejected_keyframe=media.rejected_keyframe,
            stills_by_format=dict(self._health.stills_by_format),
            still_late_replies=self.still_late_replies,
            still_file_mismatches=self.still_file_mismatches,
            trigger_frame_sessions=self._health.trigger_frame_sessions,
            extra_live_sessions=self._health.extra_live_opened,
            extra_live_sessions_open=len(self._budget.extra_live),
            recording_downloads=self._health.recording_downloads,
            media_slot_channel=self.media_slot_channel,
            conn_init_version=self._conn_init_version,
            cipher_id=self._cipher_id,
            static_key_session=self.static_key_session,
            media_frames_dropped_for_reader=media.dropped_for_reader,
            media_frames_skipped_for_keyframe=media.skipped_for_keyframe,
            media_pframes_without_start_code=media.pframes_without_start_code,
            state_frames_by_encryption=dict(self._health.state_frames),
            state_authenticated=self.state_authenticated,
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
        :class:`KeyRejectedError`. An RSA key that does not parse at all is neither
        re-fetched (the cloud serves the same bytes again) nor latched: like the eufy app,
        the session runs under the static key (:attr:`static_key_session`). Credentials
        without the key the station's handshake needs
        are re-fetched once, and still without it raise :class:`CipherUnusableError`
        (reason ``no_rsa_key`` or ``no_ecc_key``) without the latch. Credentials for
        another cipher than the station names are re-fetched once, and still for another
        cipher raise :class:`HandshakeError` without the latch. After
        :meth:`async_close` every call raises :class:`StationUnreachableError`: a closed
        session has no owner left to close it again.
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
                except _MissingKeyError as again:
                    raise again.unusable() from again
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
        reports through :class:`~...events.ConnectionChanged`. A failed first start is
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
        self._param_state.cancel_push_timer()
        if self._supervisor is not None:
            self._supervisor.cancel()
            # A supervisor that died on an unexpected error holds it here; closing must
            # not re-raise someone else's failure.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._supervisor
            self._supervisor = None
        self._teardown("closed by the client", cause=DisconnectCause.CLOSED)
        for extra in list(self._budget.extra_live):
            extra._budget.end_extra_live()
        self._budget.notify_capacity()

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
        """
        timeout = _or(timeout, PARAM_QUERY_TIMEOUT)
        await self.async_connect()
        dump = ParamDump()
        channels = self._param_state.expect_channels if expect_channels is None else expect_channels
        expected = {STATION_CHANNEL, *channels}

        def complete() -> bool:
            # Only the station itself expected: nothing tells the last block, so settle.
            return len(expected) > 1 and expected <= dump.devices.keys()

        def collect(inbound: Inbound) -> None:
            if inbound.type == FrameType.PARAM_NOTIFY and (obj := inbound.json()) is not None:
                self._param_state.ingest_dump(dump, obj)

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
                await self._request(
                    send,
                    done,
                    timeout=timeout,
                    resend_after=PARAM_QUERY_RESEND_AFTER,
                    label="parameter query",
                )
                self._last_probe = time.monotonic()
                self._last_error = None
                self._announce_connected()
                if not complete():
                    await self._listen(collect, PARAM_SETTLE, until=complete)
                full = self._param_state.expect_channels <= expected
                self._param_state.complete_dump(dump.devices.keys() if full else None)
            finally:
                self._probing = False
                self._probe_ended_at = time.monotonic()
        return dump

    async def async_set_guard_mode(  # noqa: C901
        self, mode: GuardMode, *, timeout: float | None = None, scalar: bool = False
    ) -> GuardMode | int:
        """Arm or disarm; returns the mode the station applied.

        The request is the 1350 payload object ``{mode_type, user_name}``, or with
        ``scalar`` the station scalar 1224 (frame type 1224, channel 255,
        ``[u32 mode][char[128] account]``): the form the eufy app sends a station whose
        handler builds a bare 1224 (see docs/protocol/commands.md § Guard mode).

        The station's answer is read as the eufy app reads it (declared, eufy app):

        - the arm's own result with code 0 (a 0x0547 naming 1224, the scalar's reply, on
          an RSA session the channel-0 result of the arm's own send, after every result
          owed to an earlier send) is final: the mode is filed as this library's write
          (:attr:`param_origins`) and returned, without waiting for a mode report;
        - a non-zero code raises: -108 and -103 :class:`CommandUnsupportedError`, -104
          :class:`AccountRejectedError`, any other :class:`CommandRejectedError`; on a GCM
          session a non-zero receipt too;
        - a GCM receipt 0 only says the station took the command off its queue: it stops
          the resend, and the arm waits on for its result, a report or the read-back;
        - a guard-mode report (0x047F) that comes first answers it, under any encryption
          (:meth:`_take_state`); another mode than asked raises
          :class:`CommandRejectedError`. While :attr:`GuardMode.SCHEDULE` is asked for,
          a report carries the slot's mode and answers nothing;
        - with neither, the mode is read back: the station is silent when asked for the
          mode it is in, so the asked mode is success. Anything else raises
          :class:`CommandNotAppliedError` (the transport ACK alone is no success; the
          classic case is an ``account_id`` that is not the owner's), or
          :class:`DeviceTimeoutError` when not even the datagram was acknowledged.

        A later report or dump still moves the mode. :attr:`GuardMode.OFF` is report-only
        and raises :class:`UnsupportedError` before anything is sent: disarm with
        :attr:`GuardMode.DISARMED`.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        if mode is GuardMode.OFF:
            raise UnsupportedError("guard mode OFF (6) is report-only; disarm with DISARMED (63)")
        await self.async_connect()
        creds = self._require_creds()
        if scalar:
            key, encryption = self._keys.scalar_cipher()

            def send_once() -> int:
                seq = self._keys.ecb_seq
                self._keys.ecb_seq = (seq + 1) & 0xFF
                frame = encode_ecb_scalar_frame(
                    key, CMD_SET_ARMING, int(mode), creds.account_id, seq=seq, encryption=encryption
                )
                return self._send_request(CMD_SET_ARMING, frame, self._require_transport())

        else:
            body = device_msg(creds.account_id, CMD_SET_ARMING, arm_payload(mode, creds.user_name))

            def send_once() -> int:
                return self._send_secure(body)

        slots: set[int] = set()  # an RSA session's result slots of the arm's sends

        def send() -> int:
            first = self._result_slot
            index = send_once()
            slots.update(range(first + 1, self._result_slot + 1))
            return index

        applied = False
        taken = False
        processed_at: float | None = None
        reported: list[int] = []
        schedule = mode is GuardMode.SCHEDULE

        def match(inbound: Inbound) -> int | None:
            nonlocal applied, taken, processed_at
            code = self._arm_result(inbound, scalar=scalar)
            if code is None and inbound.type == FrameType.CMD_TRANSFER and not scalar:
                code = inbound.receipt()
                if code is not None:
                    slot = inbound.result_slot()
                    if slot is not None and slot not in slots:
                        return None  # the result of a send before the arm
                    if slot is None and code == RECEIPT_TAKEN:
                        taken = True  # a GCM receipt: off the queue, not applied
                        return None
            if code is not None:
                if code != 0:
                    raise _receipt_error(CMD_SET_ARMING, code)
                applied = True
                return int(mode)
            if inbound.type == FrameType.ALARM_MODE_NOTIFY:
                value = inbound.alarm_mode()
                if value is not None:
                    reported.append(value)
                    if not schedule:
                        return value
                    # A slot's mode, not the selection: processed, not confirmed.
                    processed_at = processed_at or time.monotonic()
            return None

        async with self._op("guard mode write"):
            _LOGGER.info(
                "%s: setting guard mode %s%s",
                self._log_name,
                mode.name,
                " (station scalar)" if scalar else "",
            )
            waiter = self._add_waiter(match)
            started = time.monotonic()
            self._arming_to = mode
            try:
                indices = [send()]
                deadline = time.monotonic() + timeout
                resent = False
                while not waiter.future.done():
                    now = time.monotonic()
                    remaining = deadline - now
                    if processed_at is not None:
                        # The station took it; give its result a moment.
                        remaining = min(remaining, processed_at + MODE_REPORT_GRACE - now)
                    if remaining <= 0:
                        break
                    step = remaining if resent else min(remaining, COMMAND_RESEND_AFTER)
                    await asyncio.wait({waiter.future}, timeout=step)
                    if not (waiter.future.done() or resent or taken or processed_at is not None):
                        _LOGGER.debug("%s: no answer to the arm yet; resending", self._log_name)
                        indices.append(send())
                        resent = True
            finally:
                self._arming_to = None
                self._remove_waiter(waiter)
        _LOGGER.debug(
            "%s: arm settled after %.0f ms: result %s, receipt %s, mode reports %s",
            self._log_name,
            (time.monotonic() - started) * 1000,
            "code 0" if applied else "none",
            "0" if taken else "none",
            reported or "none",
        )
        _raise_waiter_error(waiter)  # the session was lost, or the station rejected it

        if applied:
            self._param_state.set_modes(mode, None if schedule else mode)
            self._param_state.file_modes("arm", origin_kind=ParamOrigin.LOCAL_WRITE)
            return mode
        if reported and not schedule:
            result = as_guard_mode(reported[-1])
            self._param_state.set_modes(result, result)
            # The report is the station's word on its mode: file it as its parameters,
            # so the state follows it on a station no dump follows (one reached on
            # demand, one whose dump lacks the mode) until a newer dump or cloud
            # snapshot says otherwise.
            self._param_state.file_modes("arm", origin_kind=ParamOrigin.LOCAL_WRITE)
            if result != mode:
                raise CommandRejectedError(
                    CMD_SET_ARMING, int(result), f"station applied {result!r}"
                )
            return result
        error = self._unanswered_error(CMD_SET_ARMING, 0, indices)
        current = (await self.async_get_params()).guard_mode
        if current == mode:
            _LOGGER.debug(
                "%s: no result for the arm; the station reports %s", self._log_name, mode.name
            )
            return mode
        if taken:
            raise CommandNotAppliedError(
                CMD_SET_ARMING,
                f"the station took the arm (receipt 0) but reports guard mode {current!r}",
            )
        raise error

    def _arm_result(self, inbound: Inbound, *, scalar: bool) -> int | None:
        """The code of a reply naming the arm in ``inbound``, else None: the scalar's
        reply (frame type 1224, the code in clear at ``payload[0:4]``), or a 0x0547 reply
        naming 1224 to the payload form. Its channel-0 receipt or result names no
        command and is attributed in the arm's matcher."""
        if scalar:
            return _scalar_result(inbound, CMD_SET_ARMING)
        return self._command_code(inbound, CMD_SET_ARMING)

    async def async_send_command(
        self,
        command: int,
        *,
        channel: int = STATION_CHANNEL,
        value3: int = 0,
        payload: Mapping[str, Any] | Sequence[Any] | None = None,
        timeout: float | None = None,
        confirm: Callable[[], asyncio.Future[Any]] | None = None,
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
        command), -104 :class:`AccountRejectedError`, any other non-zero code
        :class:`CommandRejectedError`. The command is resent once only when neither a
        receipt nor an ACK came back: resending into the station's queue would queue a
        second copy. A command acknowledged but without a receipt by ``timeout`` waits
        for it up to :data:`COMMAND_RECEIPT_TIMEOUT` after sending, still holding the op
        lock.

        Receipts carry no command id. One arriving while this command is in flight is
        taken as its receipt: commands are serialised, but a media open, still fetch,
        history query or live-stream stop sent just before (none of them holds the lock
        until its receipt) can still have its receipt arrive now. Those are taken
        (code 0), so the effect is at most a skipped resend.

        ``confirm``, for a command whose effect the station reports in another frame, is
        called under the command lock just before the send; the future it returns counts
        as the result once done (``APPLIED``), ending the wait like a 0x0547 reply.
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

            def settle(_: asyncio.Future[Any]) -> None:
                if not waiter.future.done():
                    waiter.future.set_result(True)

            confirmed: asyncio.Future[Any] | None = None
            try:
                if confirm is not None:
                    confirmed = confirm()
                    confirmed.add_done_callback(settle)
                indices = [self._send_secure(body, dev_type=header)]
                started = time.monotonic()
                clock, label = _StallClock(), f"cmd {command}"
                await self._wait_until(
                    waiter.future,
                    started + min(COMMAND_RESEND_AFTER, timeout),
                    label,
                    clock=clock,
                    event=receipt,
                )
                if not waiter.future.done() and not receipt.is_set() and not self._acked(indices):
                    _LOGGER.debug(
                        "%s: cmd %d (%s): no receipt or ACK after %.1fs; resending",
                        self._log_name,
                        command,
                        self._param(command, channel).label,
                        COMMAND_RESEND_AFTER,
                    )
                    indices.append(self._send_secure(body, dev_type=header))
                await self._wait_until(waiter.future, started + timeout, label, clock=clock)
                if not waiter.future.done() and not receipt.is_set() and self._acked(indices):
                    _LOGGER.debug(
                        "%s: cmd %d (%s) acknowledged without a receipt; waiting for it",
                        self._log_name,
                        command,
                        self._param(command, channel).label,
                    )
                    await self._wait_until(
                        waiter.future,
                        started + COMMAND_RECEIPT_TIMEOUT,
                        label,
                        clock=clock,
                        event=receipt,
                    )
            finally:
                if confirmed is not None:
                    confirmed.remove_done_callback(settle)
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
        :mod:`..mode_actions`). The station answers only with a receipt; a non-zero
        receipt code raises :class:`CommandRejectedError`, but a zero one is not taken
        as success: every value the table leaves (each device's action and delays for
        the mode) is read back, and :class:`CommandNotAppliedError` names the first that
        differs after :data:`MODE_TABLE_READBACK_ATTEMPTS` reads. No resend: the station
        queues channel-0 frames, so a resend would only queue a second table. Raises
        :class:`DeviceTimeoutError` when not even the datagram was acknowledged, and
        ``UnsupportedError`` for a table whose delays cannot be expressed (before
        anything is sent). ``verify=False`` skips the read-back.
        """
        _LOGGER.info(
            "%s: writing the %s mode table (%d devices)",
            self._log_name,
            table.mode.name,
            len(table.actions),
        )
        # Acknowledged without a receipt: the read-back decides.
        await self.async_send_json_frame(CMD_SET_ALL_ACTION, table.encode, timeout=timeout)
        if verify:
            await self._confirm_params(CMD_SET_ALL_ACTION, table.params())

    async def async_send_json_frame(
        self, command: int, body: Callable[[str], bytes], *, timeout: float | None = None
    ) -> bool:
        """Send ``body(owner account id)`` (a JSON document) as a frame whose type is
        ``command``, the way the app sends a mode table (1255), the mode list (1256) and
        the schedule (1254), and wait for the station's receipt of that type on channel 0.

        Returns True for receipt code 0 and False when the station acknowledged the
        datagram but sent no receipt within ``timeout``. Neither is a read-back: the
        caller confirms the write. A non-zero receipt raises
        :class:`CommandRejectedError`; no acknowledgement :class:`DeviceTimeoutError`.
        No resend: the station queues channel-0 frames, so a resend would queue a
        second copy.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        plaintext = body(self._require_creds().account_id)

        def match(inbound: Inbound) -> int | None:
            return inbound.receipt() if inbound.type == command else None

        async with self._op(f"cmd {command} write"):
            _LOGGER.debug(
                "%s: tx JSON frame %d (%d bytes)", self._log_name, command, len(plaintext)
            )
            indices: list[int] = []
            try:
                code = cast(
                    int,
                    await self._request(
                        lambda: indices.append(self._send_secure(plaintext, frame_type=command)),
                        match,
                        timeout=timeout,
                        label=f"cmd {command}",
                    ),
                )
            except DeviceTimeoutError:
                error = self._unanswered_error(command, 0, indices)
                if isinstance(error, DeviceTimeoutError):
                    raise error from None
                return False
        _raise_for_code(command, code)
        return True

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

    async def async_set_tone_file(
        self, seconds: int, *, timeout: float | None = None
    ) -> CommandOutcome:
        """Sound the station's siren for ``seconds`` (0 stops it): SET_TONE_FILE (1201)
        :func:`~..messages.tone_file_payload` with the session's user name, ``mChannel`` 0.

        Alarm-affecting. A HomeBase 3 acknowledges the command without a result and
        reports the siren in its alarm-tone frame (:mod:`..alarm`). Returns and raises as
        :meth:`async_send_alarm`.
        """
        return await self.async_send_alarm(
            CMD_SET_TONE_FILE,
            tone_file_payload(seconds, USER_NAME_SLOT),
            channel=0,
            on=seconds > 0,
            timeout=timeout,
        )

    async def async_send_alarm(
        self,
        command: int,
        payload: Mapping[str, Any],
        *,
        channel: int,
        on: bool,
        timeout: float | None = None,
    ) -> CommandOutcome:
        """Start (``on``) or stop an alarm: SET_TONE_FILE (1201) or SET_DEVS_TONE_FILE
        (1202) with ``payload`` on ``channel``; a payload value equal to
        :data:`~..devices.device_alarm.USER_NAME_SLOT` is the session's user name.

        Alarm-affecting. Returns ``APPLIED`` as soon as a result arrives or an alarm frame
        received after the send shows the alarm in the asked state: for 1201 the
        alarm-tone frame on any channel (the alarm on, or ended), for 1202 the device-siren
        frame on ``channel`` (:attr:`~..alarm.AlarmFrame.alarm_state`; a frame that changes
        no state, ``[10, 0]`` or ``[16, 5]``, confirms nothing). A frame arriving after the
        command's own wait still counts within ``timeout`` (:data:`TONE_CONFIRM_TIMEOUT`)
        of the call. Otherwise returns and raises as :meth:`async_send_command`
        (``DELIVERED``: acknowledged, never confirmed). ``ValueError`` for another
        command; nothing is sent.
        """
        if command not in (CMD_SET_TONE_FILE, CMD_SET_DEVS_TONE_FILE):
            raise ValueError(f"command {command} is no alarm command")
        await self.async_connect()
        creds = self._require_creds()
        body = {k: creds.user_name if v == USER_NAME_SLOT else v for k, v in payload.items()}
        started = time.monotonic()
        tone: asyncio.Future[AlarmChanged] = asyncio.get_running_loop().create_future()
        siren: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        tone_entry, siren_entry = (on, tone), (channel, on, siren)
        future: asyncio.Future[Any] = tone if command == CMD_SET_TONE_FILE else siren

        def watch() -> asyncio.Future[Any]:
            # Under the lock: only frames after the send count.
            if command == CMD_SET_TONE_FILE:
                self._tone_waiters.append(tone_entry)
            else:
                self._siren_waiters.append(siren_entry)
            return future

        try:
            outcome = await self.async_send_command(
                command, channel=channel, payload=body, timeout=timeout, confirm=watch
            )
            if outcome is CommandOutcome.APPLIED:
                return outcome
            left = started + _or(timeout, TONE_CONFIRM_TIMEOUT) - time.monotonic()
            try:
                await asyncio.wait_for(future, max(left, 0.0))
            except TimeoutError:
                return outcome
            return CommandOutcome.APPLIED
        finally:
            if tone_entry in self._tone_waiters:
                self._tone_waiters.remove(tone_entry)
            if siren_entry in self._siren_waiters:
                self._siren_waiters.remove(siren_entry)
            tone.cancel()
            siren.cancel()

    async def async_run_recipe(
        self,
        recipe: Recipe,
        *,
        channel: int = 0,
        timeout: float | None = None,
    ) -> RecipeReply:
        """Send a handler recipe (:mod:`~...devices.recipes`) and wait for its answer.

        The recipe's frame (:meth:`Recipe.plaintext`, of type ``recipe.cmd``) goes to
        ``channel``'s subheader. A receipt with code -108 raises
        :class:`CommandUnsupportedError`, -104 :class:`AccountRejectedError`, any other
        non-zero code :class:`CommandRejectedError`. A notify-answered recipe returns the
        payload of the 1351 notify naming its :attr:`~Recipe.answer_cmd` (``APPLIED``)
        and raises :class:`DeviceTimeoutError` without one; any other recipe returns
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

        Raises :class:`CommandRejectedError` with the station's result code
        (:class:`CommandUnsupportedError` for -103, a command it takes in no scalar
        form; :class:`AccountRejectedError` for -104), or
        :class:`CommandNotAppliedError` / :class:`DeviceTimeoutError` when no result came
        back. A ``channel`` or account id the frame cannot carry raises
        :class:`ValueError` before anything is sent, like any out-of-domain argument.
        """
        timeout = _or(timeout, COMMAND_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        key, encryption = self._keys.scalar_cipher()

        def match(inbound: Inbound) -> tuple[int, int | None] | None:
            code = _scalar_result(inbound, command)
            return None if code is None else (code, inbound.frame.cipher)

        async with self._op("ECB command"):
            seq = self._keys.ecb_seq
            self._keys.ecb_seq = (seq + 1) & 0xFF
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
                    lambda: indices.append(self._send_request(command, frame, transport)),
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
        _raise_for_code(command, code)

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
        :func:`~..messages.string_command_body` (``channel`` addresses the device inside
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
            return inbound.receipt() if inbound.type == command else None

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

        The query of the HomeBase 3 family; see
        :func:`~..storage_info.storage_query` for which station answers which. Read-only.
        The reply carries no correlation id, so a record the station sends to this
        session for another client's query in the same moment answers it too (it is the
        same record). Raises :class:`CommandRejectedError` for a non-zero result or a
        non-zero command receipt (:class:`CommandUnsupportedError` for ``NOT_HANDLED``;
        a station that refuses the query sends no record), :class:`ProtocolError` for a
        reply without a ``body``, and :class:`DeviceTimeoutError` when nothing answers
        within ``timeout`` (default :data:`STORAGE_TIMEOUT`). The record also becomes
        :attr:`storage` and, when it changed, a :class:`~...events.StorageChanged`.

        The answer to this query is taken under either cipher: on a fresh session the
        station answers it under ECB. It is the record this
        session asked for, and disk figures are not security state. Records nobody here
        asked for are kept only under GCM.
        """

        def parse(obj: Mapping[str, Any]) -> StorageInfo | None:
            if (record := storage_record(obj)) is None:
                return None
            _raise_for_code(CMD_STORAGE, record.code)
            if record.body is None:
                raise ProtocolError("the storage record carries no body")
            return parse_storage_info(record.body)

        return await self._read_storage(
            CMD_STORAGE, lambda _account: storage_query_payload(), parse, timeout, "storage"
        )

    async def async_get_hub_storage(self, *, timeout: float | None = None) -> StorageInfo:
        """Read a HomeBase 2's storage (``55000``, ``APP_CMD_GET_HUB_STORAGE_INFO``).

        The query the app sends a HomeBase 2 from firmware 3.3.7.7 **[declared: app]**:
        the eMMC and disk totals and free space (:func:`~..storage_info.parse_hub_storage`).
        Read-only; errors, timeout and the kept :attr:`storage` as for
        :meth:`async_get_storage`.
        """

        def parse(obj: Mapping[str, Any]) -> StorageInfo | None:
            info = parse_hub_storage(obj)
            if info is not None:
                _raise_for_code(CMD_HUB_STORAGE, result_code(obj))
            return info

        return await self._read_storage(
            CMD_HUB_STORAGE, hub_storage_query_payload, parse, timeout, "hub storage"
        )

    async def _read_storage(
        self,
        command: int,
        payload: Callable[[str], Mapping[str, Any]],
        parse: Callable[[Mapping[str, Any]], StorageInfo | None],
        timeout: float | None,
        label: str,
    ) -> StorageInfo:
        """Send the JSON storage query ``command`` and take the reply ``parse`` accepts.

        Like the app's request client, a non-zero command receipt ends the wait with
        that code, and the reply may take up to :data:`STORAGE_TIMEOUT`.
        """
        timeout = _or(timeout, STORAGE_TIMEOUT)
        await self.async_connect()
        creds = self._require_creds()
        body = device_msg(
            creds.account_id,
            command,
            dict(payload(creds.account_id)),
            transaction=str(int(time.time() * 1000)),
        )

        def match(inbound: Inbound) -> StorageInfo | None:
            if inbound.type == FrameType.CMD_TRANSFER and (code := inbound.receipt()) is not None:
                if code != RECEIPT_TAKEN:
                    raise _receipt_error(command, code)
                return None
            if inbound.type != FrameType.NOTIFY_PAYLOAD or (obj := inbound.json()) is None:
                return None
            info = parse(obj)
            if info is not None:
                self._keep_storage(info)
            return info

        async with self._op(f"{label} read"):
            info = await self._request(
                lambda: self._send_secure(body), match, timeout=timeout, label=f"{label} query"
            )
        return cast(StorageInfo, info)

    async def async_get_sd_info(self, *, timeout: float | None = None) -> StorageInfo:
        """A standalone camera's built-in eMMC, via ``SDINFO_EX`` (``1144``).

        The query a standalone device answers where it does not answer the HomeBase
        storage record (``1307`` / ``11001``): a bare command frame of type ``1144``,
        answered by a frame of the same type carrying a 12-byte body (three ``int32``:
        status, total, free — see :func:`~..storage_info.parse_sd_card_info`). The result
        is a :class:`StorageInfo` with only ``emmc`` set, kept as :attr:`storage` and
        announced with :class:`~...events.StorageChanged` when it changed.

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
                raise _rejection(CMD_DATABASE, code, str(obj.get("msg", "")))
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
        before_day: date | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        device_sn: str | None = None,
        page_size: int | None = None,
        timeout: float | None = None,
    ) -> list[HistoryRecord]:
        """History records across all devices from ``start_date`` to ``end_date``, newest first.

        Dates are ``YYYYMMDD`` and both days are included (``end_date`` None: only
        ``start_date``). ``count`` caps the number of records (None: all of them).
        ``before`` (a ``record_id``) keeps only older rows: the days after its day are
        not asked and its day is paged from it. Its day is the one the id carries, else
        ``before_day`` (the station day it was listed under, as
        :meth:`async_list_history_by_day` gives it). ``keep`` filters the rows as they
        arrive, and ``count`` then counts the kept ones, so paging stops as soon as
        enough rows pass the filter.

        ``device_sn`` (a camera) filters a ``DB_QUERY_LOCAL_EVENTS`` (10017) query at
        the station with ``device_info``, as the eufy app does **[declared: app]**,
        measured on a HomeBase 2; ``keep`` still filters the rows, and a
        ``DB_QUERY_HISTORY`` (10011) query stays station-wide.

        Uses the verb the app sends this station's model
        (:func:`~..messages.history_query_verb`) the way the app does: one day at a
        time (``start_date`` = the day, ``end_date`` = the next day), paging with
        ``count`` = ``page_size`` (None: :data:`~.history.HISTORY_PAGE_SIZE`, or
        :data:`~.history.HISTORY_LOCAL_PAGE_SIZE` under ``DB_QUERY_LOCAL_EVENTS``) until a
        page comes back short. Under ``DB_QUERY_HISTORY`` (10011, the HomeBase 3 family)
        the cursor is ``start_id`` = the previous page's oldest ``record_id``; under
        ``DB_QUERY_LOCAL_EVENTS`` (10017, every other station, **[declared: app]**,
        unverified on hardware) it is ``start_time`` = the previous page's oldest
        ``start_time``, and a page whose first row repeats ends the day. The station
        answers a query with the rows of a single day only, so a multi-day window
        asked in one query misses every day after the first; a day with more rows
        than one page is cut short without the paging. ``timeout`` bounds each query
        (None:
        :data:`HISTORY_QUERY_TIMEOUT`); a query left unanswered is sent once more with
        the same cursor, and :class:`DeviceTimeoutError` is raised when that one times
        out too. Raises :class:`ValueError`, before sending,
        for a malformed date, a start after the end, a ``before`` without a day (none
        carried, no ``before_day``), a ``before_day`` other than the day ``before``
        carries or without ``before``, or a ``page_size`` below 2 (a page repeats the
        cursor row, so a page of 1 cannot move).
        """
        rows = await self.async_list_history_by_day(
            start_date,
            end_date,
            count=count,
            before=before,
            before_day=before_day,
            keep=keep,
            device_sn=device_sn,
            page_size=page_size,
            timeout=timeout,
        )
        return [row for _day, row in rows]

    async def async_list_history_by_day(
        self,
        start_date: str,
        end_date: str | None = None,
        *,
        count: int | None = None,
        before: int | None = None,
        before_day: date | None = None,
        keep: Callable[[HistoryRecord], bool] | None = None,
        device_sn: str | None = None,
        page_size: int | None = None,
        timeout: float | None = None,
    ) -> list[tuple[date, HistoryRecord]]:
        """:meth:`async_list_history`, each row with the station day its query named (the
        day it belongs to on the station, whether or not its ``record_id`` carries one)."""
        return await self._history.list_by_day(
            start_date,
            end_date,
            count=count,
            before=before,
            before_day=before_day,
            keep=keep,
            device_sn=device_sn,
            page_size=page_size,
            timeout=_or(timeout, HISTORY_QUERY_TIMEOUT),
        )

    async def async_history_record(
        self, record_id: int, *, timeout: float | None = None
    ) -> HistoryRecord | None:
        """The history row of one ``record_id``, or None when the station has none.

        One query, not resent (``timeout`` None: :data:`HISTORY_QUERY_TIMEOUT`): the
        record's day comes from the id (``YYYYMMDD`` and a five-digit counter), and a
        page asked from ``start_id`` starts with that row. Raises
        :class:`ValueError`, before sending, for an id that carries no valid day
        (check it with :func:`~..messages.record_id_day`).
        """
        return await self._history.record(record_id, timeout=_or(timeout, HISTORY_QUERY_TIMEOUT))

    async def async_find_history_record(
        self, ref: RecordingRef, *, timeout: float | None = None
    ) -> HistoryRecord:
        """The history row ``ref`` names (as :func:`~...recordings.decode_ref` gives it),
        carrying its :attr:`~...events.HistoryRecord.ref`.

        Queries of the ref's day with the verb the app sends this station, none resent
        (``timeout`` None: :data:`HISTORY_QUERY_TIMEOUT` each). Under
        ``DB_QUERY_HISTORY`` one page of 2 from ``start_id`` = its ``record_id`` (the
        page starts with that row), matched by ``record_id`` and camera. Under
        ``DB_QUERY_LOCAL_EVENTS`` a page of :data:`~.history.HISTORY_LOCAL_PAGE_SIZE`
        from each cursor of :meth:`~...recordings.RecordingRef.time_cursors`, matched by
        ``record_id``, camera and start time: the second page is asked only when the
        first is full, lacks the row and holds no row that started before it. That
        finds the row whether the station lists the rows before the cursor or up to
        it, unless a full page of rows that started in its own second comes before it.

        Raises :class:`RecordingRefError`, before sending, under
        ``DB_QUERY_LOCAL_EVENTS`` for a ref without a start time;
        :class:`RecordNotFoundError` when no page asked holds the row: the station no
        longer lists it (deleted), or lists that id for another camera.
        """
        return await self._history.find(ref, timeout=_or(timeout, HISTORY_QUERY_TIMEOUT))

    async def async_fetch_image(self, path: str, *, timeout: float | None = None) -> bytes:
        """The bytes of :meth:`async_fetch_still`, whatever their format."""
        return (await self.async_fetch_still(path, timeout=timeout)).data

    async def async_fetch_still(self, path: str, *, timeout: float | None = None) -> Still:
        """Download one still (``thumb_path`` / ``crop_path``) off the station's disk.

        The result carries its :class:`~..media.StillFormat`. A V1 or V2 still is decoded
        with the station's DID (``data`` is then the picture); another obfuscated still,
        or one that does not decode, is returned as it came, not raised, and
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
        if still.format in DECODABLE_STILLS:
            still = self._decode_still(still)
        self._health.stills_by_format[still.format.value] += 1
        _LOGGER.debug(
            "%s: image fetch bound: %s, %d bytes in %.2fs",
            self._log_name,
            still.format,
            len(data),
            time.monotonic() - started,
        )
        return still

    def _decode_still(self, still: Still) -> Still:
        """``still`` (V1 or V2) decoded with the station's DID, or unchanged when it
        cannot be."""
        did = self._did or self._expected_did
        if did is None:
            _LOGGER.debug("%s: %s still not decoded: no DID known", self._log_name, still.format)
            return still
        try:
            return Still(still.path, decode_still(still.data, lambda _: (str(did),)), still.format)
        except ProtocolError as err:
            _LOGGER.debug("%s: %s still not decoded: %s", self._log_name, still.format, err)
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
        """A recording's first keyframe, the moment that triggered the event, as Annex-B in
        the camera's codec (:func:`~..media.picture_codec`).

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
        return await self._budget.trigger_frame(
            path, channel, trailing_frames=trailing_frames, first_frame_timeout=first_frame_timeout
        )

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

    def _media_waits(self) -> MediaWaits:
        """The media waits as ``p2p.session`` holds them now, where tests and consumers
        patch them (:class:`~.media_slot.MediaSlot` asks each time it waits)."""
        return MediaWaits(
            ping_interval=MEDIA_PING_INTERVAL,
            drain_gap=MEDIA_DRAIN_GAP,
            drain_max=MEDIA_DRAIN_MAX,
            wake_backoff=WAKE_BACKOFF,
        )

    async def async_open_live(
        self,
        channel: int,
        *,
        first_frame_timeout: float | None = None,
        idle_timeout: float | None = None,
        wait: bool = False,
        live_open: LiveOpen | None = None,
        live_stop: LiveStop | None = None,
        media_key: MediaKeyType = MediaKeyType.RSA,
        live_view: LiveView | None = None,
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

        ``live_open`` is the open the device's handler sends
        (:func:`~...devices.live_open.library_live_open`; :meth:`~...station.Station.async_open_live`
        passes it). A standalone device (:attr:`standalone`) gets a 1700 frame with
        sub-command 1000 (:attr:`~...devices.live_open.LiveOpen.SINGLE`, the default, or
        without ``extValue``), or the station open below
        (:attr:`~...devices.live_open.LiveOpen.STATION`), and a bare 1004 stop.
        A HomeBase 3's camera gets the app's T8030 1003 in a ``DeviceMsgBean`` and a
        1004 ``DeviceMsgBean`` naming the channel; a camera behind any other station
        (a HomeBase 2) the camera handlers' 1003 without the T8030 fields
        (:func:`~...devices.recipes.open_live_stream_station`) and a bare 1004 carrying
        the channel. A 1700 ``live_open`` behind a station goes on this session with the
        camera's channel in the frame header (subheader byte 4 is 0 without
        ``extValue``) and gets no 1139 ping; its stop is ``live_stop``
        (:func:`~...devices.live_open.live_stop`), else the station's stop above. A
        non-zero receipt to a 1700 open fails the stream at once
        (:class:`CommandRejectedError`, :class:`CameraWakeError` for a wake failure).

        A multi-camera ``live_open`` (:data:`~...devices.live_open.NVR_OPENS`) sends the
        handler's 1350/1003 for ``live_view`` (:mod:`~...devices.live_view`; default: the
        fixed lens alone), with the view fields only to a HomeBase 3, as the app's
        player does; behind a station its stop is ``live_stop``, as for a 1700 open.

        ``media_key`` is the key pair the open offers (its ``key`` field): RSA, or ECC,
        which the app offers a device whose param 1103 is 128 or more
        (:func:`~..media.media_key_type_for`; :meth:`~...station.Station.async_open_live`
        picks it so). The station protects the stream for the key it is offered.
        """
        return await self._media_slot.open_live(
            channel,
            first_frame_timeout=_or(first_frame_timeout, MEDIA_LIVE_FIRST_FRAME_TIMEOUT),
            idle_timeout=_or(idle_timeout, MEDIA_IDLE_TIMEOUT),
            wait=wait,
            live_open=live_open,
            live_stop=live_stop,
            media_key=media_key,
            live_view=live_view,
        )

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
        as fast as it was recorded or faster. Stations using local events
        (10017) use native download (1024); the 10011 family keeps the JSON commands. It runs
        on an extra session reserved from the live-stream session budget
        (:attr:`max_sessions`), closed when the clip ends or this call is cancelled, so
        this session's slot, commands and trigger frames are never held up. Downloads
        queue: one at a time per station. Past the budget this raises
        :class:`LiveStreamLimitError`, or with ``wait`` (the default) waits up to
        ``first_frame_timeout`` for a stream to end.

        ``write`` receives the muxed bytes in order (see :mod:`~..clip`). Raises what
        :meth:`async_open_recording` raises, and :class:`DeviceTimeoutError` when the
        recording ends before a keyframe; bytes already written stay written. A
        standalone device raises :class:`UnsupportedError` before anything is sent.
        """
        return await self._budget.download_recording(
            path,
            channel,
            write,
            first_frame_timeout=_or(first_frame_timeout, MEDIA_RECORDING_FIRST_FRAME_TIMEOUT),
            wait=wait,
        )

    def _send_native_recording(
        self, path: str, channel: int, account_id: str, *, download: bool
    ) -> int:
        """Send native playback 1025 or download 1024 under the static ECB key."""
        command = CMD_DOWNLOAD_VIDEO if download else CMD_RECORD_VIEW
        frame = native_recording_frame(
            path, account_id, channel, self._keys.require_static_key(), command=command
        )
        if _WIRE.isEnabledFor(logging.DEBUG):
            _WIRE.debug(
                "%s: tx native recording cmd %d channel %d (path and account redacted)",
                self._log_name,
                command,
                channel,
            )
        return self._require_transport().send_drw(0, frame)

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
        """Play a validated stored recording (``.zxvideo`` or native ``.dat``) off disk.

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
        return await self._media_slot.open_recording(
            path,
            channel,
            download=download,
            first_frame_timeout=_or(first_frame_timeout, MEDIA_RECORDING_FIRST_FRAME_TIMEOUT),
            idle_timeout=_or(idle_timeout, MEDIA_IDLE_TIMEOUT),
            wait=wait,
        )

    def wake_backoff_left(self, channel: int) -> float:
        """Seconds a live open of the camera on ``channel`` is still refused (0: none).

        Set by a :class:`CameraWakeError`, per :data:`WAKE_BACKOFF`; cleared by a live
        stream of that channel that starts, or by :meth:`clear_wake_backoff`.
        """
        return self._wake_backoff.left(channel)

    def clear_wake_backoff(self, channel: int | None = None) -> None:
        """Allow the next live open of ``channel`` (every channel when None) at once."""
        self._wake_backoff.clear(channel)

    def _on_play_ctrl(self, stream: MediaStream | None, frame: Frame) -> None:
        """End ``stream`` on the station's end-of-playback frame (0x0402 = 2).

        Only a recording that has started takes it. The frame carries no stream id, and
        an earlier playback's end can arrive just after the next open (it follows the
        last frame by about 0.5 s, the drain gap), before that stream's first keyframe.
        """
        value = (
            self._rsa_play_ctrl(frame)
            if self.rsa_session
            else decode_record_play_ctrl(frame, self._keys.session_key)
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
        self._media_slot.rx_at = 0.0
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
                if attempt < DISCOVERY_ATTEMPTS:
                    await asyncio.sleep(DISCOVERY_RETRY_DELAY)
                continue
            except BaseException:
                transport.close()
                raise
            break
        else:
            raise last_error

        try:
            ecb_key = static_key(self.serial, self._did_text or did)
        except ProtocolError as err:
            # Not a HandshakeError: re-fetching the cipher key cannot fix a serial or
            # DID that does not yield a static key.
            self._retire_transport(transport)
            transport.close()
            raise ProtocolError(f"cannot derive the static key for this station: {err}") from err
        self._transport = transport
        self._did = did
        self._keys.static_key = ecb_key
        if transport.peer is not None:
            self._host = transport.peer[0]
        self._decoders.clear()
        self._results_due.clear()
        self._keys.gcm_seq = GCM_SEQ_START
        self._keys.gcm_counter = 0
        self._keys.ecb_seq = 0

        key = self._keys.static_key
        _LOGGER.debug(
            "%s: link up (DID %s); static ECB key %s; sending CONN_INIT",
            self._log_name,
            Secret(did),
            Secret(key),
        )

        def match(inbound: Inbound) -> Frame | None:
            if inbound.type != FrameType.CONN_INIT:
                return None
            # Bound the payload before the handshake decrypts it (CONN_INIT_MAX_LEN).
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
            self._health.handshake_failures += 1
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
            self._health.handshake_failures += 1
            self._teardown("cipher key unusable")
            raise
        except HandshakeError as err:
            _LOGGER.debug("%s: handshake failed: %s", self._log_name, err)
            self._health.handshake_failures += 1
            self._teardown("handshake failed")
            raise
        except CloudError:
            self._teardown("no credentials for the cipher the station named")
            raise
        except BaseException:
            self._teardown("handshake interrupted")
            raise
        if conn_init.rsa:
            self._keys.aes_key = session_key
        else:
            self._keys.session_key = session_key
        self._health.connects += 1
        self._creds = creds
        self._account_mismatch_reported = False  # a new connection may report it again
        _LOGGER.debug(
            "%s: %s session key %s%s",
            self._log_name,
            "AES-128-ECB" if conn_init.rsa else "GCM",
            Secret(session_key),
            " (the static key)" if self.static_key_session else "",
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
        self._keys.rsa_keyless = False
        _LOGGER.debug(
            "%s: CONN_INIT reply (%d bytes, version %d, encryption %s) names cipher %d",
            self._log_name,
            len(frame.payload),
            conn_init.version,
            frame_encryption(frame.subheader),
            named,
        )
        if conn_init.rsa and named == CONN_INIT_NO_CIPHER:
            # No session key: the app fetches no cipher and keeps the static key.
            if creds is None or creds.cipher_id != named:
                creds = await self._load_credentials(refresh=False)
            self._keys.rsa_keyless = True
            return creds, conn_init, static
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
            raise _CipherMismatchError(named, creds.cipher_id)
        missing = _MissingKeyError(named, rsa=conn_init.rsa)
        if not missing.held_by(creds):
            raise missing
        if not conn_init.rsa:
            return creds, conn_init, session_key_from_conn_init(conn_init, creds.ecc_private_key)
        rsa_key = cast(str, creds.rsa_private_key)  # held_by checked it
        try:
            return creds, conn_init, aes_key_from_conn_init(conn_init, rsa_key)
        except CipherUnusableError as exc:
            # The app sets no session key when the RSA key fails to parse and runs the
            # session under the static key, as for a CONN_INIT naming no cipher.
            _LOGGER.info(
                "%s: cipher %d's RSA key cannot be used (%s); the session runs under the "
                "static key, as in the eufy app",
                self._log_name,
                named,
                exc.reason,
            )
            self._keys.rsa_keyless = True
            return creds, conn_init, static

    async def _refetch_rejected_key(self, err: HandshakeError) -> P2PCredentials:
        """Re-fetch the credentials after ``err``, unless the stale-key latch holds it back."""
        wait = self._key_refresh.retry_blocked_for()
        if wait > 0:
            raise KeyRejectedError(
                f"the station rejects its cipher key, which was already re-fetched; "
                f"no automatic re-fetch for {wait:.0f}s ({err})"
            ) from err
        _LOGGER.warning(
            "%s: %s (%s); re-fetching the cipher key once",
            self._log_name,
            "credentials without the key"
            if isinstance(err, _MissingKeyError)
            else "session key would not unwrap",
            err,
        )
        creds = await self._load_credentials(refresh=True)
        if isinstance(err, _MissingKeyError) and not err.held_by(creds):
            raise err.unusable() from err  # no key came back: nothing for the latch
        if isinstance(err, _CipherMismatchError) and creds.cipher_id != err.named:
            # Another cipher's key is no stale key of this one: nothing for the latch.
            raise HandshakeError(
                f"{err}; the re-fetched credentials are for cipher {creds.cipher_id} too"
            ) from err
        await self._key_refresh.async_refreshed()  # only now: the fetch returned a key
        self._health.key_refreshes += 1
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
        self._keys.session_key = None
        self._keys.aes_key = None
        self._still_owed.clear()  # a late reply cannot cross into a new connection
        # A pending settle timer would otherwise fire _complete_dump on a dead link and
        # announce a completed dump assembled from whatever arrived before the drop.
        self._param_state.cancel_push_timer()
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
            and self._media_slot.stream is None
            and not self._waiters
            and time.monotonic() - self._last_used >= ON_DEMAND_ASLEEP_AFTER
        )

    def _on_lost(self, exc: Exception) -> None:
        # A battery station goes quiet a few seconds after its last command (a T8170:
        # about 7 s, then the link times out): with nothing in flight that is its
        # sleep, not an outage. Anything waiting still fails.
        asleep = (
            self.on_demand
            and self._media_slot.stream is None
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
        self._keys.session_key = None
        self._keys.aes_key = None
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
        self._health.retired_wrong_port_drops += transport.wrong_port_drops

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
                and self._media_slot.stream is None
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
                self._media_slot.close_abandoned()
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
            self._health.dropped_undecodable += 1
            # Resume from the next chunk that arrives. A reset to index 0 would wait
            # for an index the station has long passed, silencing the channel for
            # the rest of the session.
            self._decoders[chunk.channel] = StreamDecoder(first_index=None)
            return
        for frame in frames:
            self._dispatch(Inbound(chunk.channel, frame, self))

    def _dispatch(self, inbound: Inbound) -> None:  # noqa: C901
        stream = self._media_slot.stream
        if inbound.type in _MEDIA_FRAME_TYPES:
            self._media_slot.rx_at = time.monotonic()
            label = media_variant_label(
                inbound.type, inbound.frame.payload, inbound.frame.subheader
            )
            if label is not None:
                count_capped(self._media_counters.variants, label)
            if inbound.type == FrameType.VIDEO_FRAME:
                count_capped(self._media_counters.codecs, video_codec_label(inbound.frame.payload))
            if stream is not None:
                stream._feed(
                    inbound.type,
                    inbound.frame.payload,
                    _frame_camera(inbound.frame),
                    inbound.frame.subheader,
                )
            elif self._throttle.should_log("media-orphan"):
                _LOGGER.debug("%s: media frame with no open stream", self._log_name)
            return
        _LOGGER.debug(
            "%s: rx frame 0x%04x ch%d v%s enc%s (%d bytes)",
            self._log_name,
            inbound.type,
            inbound.channel,
            inbound.frame.cipher,
            frame_encryption(inbound.frame.subheader),
            len(inbound.frame.payload),
        )
        receipt = inbound.receipt()
        if receipt is not None:
            self._note_receipt(inbound, receipt)
            if receipt in CAMERA_WAKE_CODES and self._media_slot.take_wake_failure(
                stream, inbound, receipt
            ):
                return
            if receipt != RECEIPT_TAKEN and self._media_slot.take_open_refusal(
                stream, inbound, receipt
            ):
                return
        elif inbound.type == FrameType.RECORD_PLAY_CTRL:
            self._on_play_ctrl(stream, inbound.frame)
            return
        if (
            stream is not None
            and inbound.type == FrameType.NOTIFY_PAYLOAD
            and self._media_slot.take_reply(stream, inbound)
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
            # _decode_json decodes only ECB-tagged frames (static key, an RSA session's
            # key, or clear) and GCM frames under the session key; any other tag is dropped
            # rather than mislabelled as authenticated.
            tag = inbound.frame.cipher
            if tag is None or tag not in FrameCipher:
                return
            cipher = FrameCipher(tag)
            for listener in list(self._notify_listeners):
                try:
                    listener(obj, cipher)
                except Exception:
                    _LOGGER.exception("%s: notify listener failed", self._log_name)
            session_ecb = self._keys.session_ecb_frame(inbound.frame)
            own = cipher is FrameCipher.GCM or self._keys.station_frame(inbound.frame)
            if own and self._note_storage(obj):
                return
            event = decode_camera_push(
                obj, station_sn=self.serial, frame_cipher=cipher, session_ecb=session_ecb
            )
            if event is not None:
                if _LOGGER.isEnabledFor(logging.DEBUG):
                    _log_camera_push(self._log_name, event, cipher)
                self._health.last_event_at = time.monotonic()
                self._health.frames_by_cipher[cipher.name.lower()] += 1
                count_capped(
                    self._health.events_by_type,
                    f"{_or_unknown(event.msg_type)}:{_or_unknown(event.event_type)}",
                )
                self._bus.emit(event)
                if event.authenticated:
                    self._check_stamped_account(event.raw)

    def _note_storage(self, obj: Mapping[str, Any]) -> bool:
        """Keep a storage record (asked for or pushed); whether ``obj`` was one.

        Only an authenticated record (GCM, or under an RSA session's key) is kept: it is
        station state.
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
        self._health.account_mismatch_seen = True
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
        self._param_state.ingest_dump(dump, obj)
        self._param_state.merge_dump(dump, "read" if self._probing else "unsolicited", time.time())
        now = time.monotonic()
        straggler = self._probe_ended_at is not None and now - self._probe_ended_at < PARAM_SETTLE
        if not self._probing and not straggler and self._reprobe_at is None:
            # A dump nobody asked for means something changed at the house — and a
            # guard change made outside P2P may send no 0x047F, so ask for everything.
            # A block right after this session's own read is that read's late sub-device block.
            self._reprobe_at = now + UNSOLICITED_REPROBE_DELAY
        if not self._probing:
            self._param_state.note_pushed_blocks(dump.devices, PARAM_SETTLE)

    def _handle_alarm(self, frame: Frame) -> None:
        """An alarm frame (tone, siren, light): cache its value per channel, emit
        :class:`ParamChanged` when it moved, hand it to the alarm listeners, and emit
        :class:`AlarmChanged` when a tone frame starts or ends the alarm. Taken under any
        encryption (:meth:`_take_state`)."""
        plain = self._state_body(frame)
        if plain is None:
            return
        alarm = decode_alarm_frame(frame, plain)
        if alarm is None:
            self._health.dropped_undecodable += 1
            return
        self._take_state(frame)
        _LOGGER.debug(
            "%s: alarm frame %d ch%d %s / %s",
            self._log_name,
            alarm.param_id,
            alarm.channel,
            alarm.values,
            self._param(alarm.param_id, alarm.channel).describe(),
        )
        self._param_state.take_alarm_value(alarm.channel, alarm.param_id, alarm.value)
        for listener in list(self._alarm_listeners):
            try:
                listener(alarm)
            except Exception:
                _LOGGER.exception("%s: alarm listener failed", self._log_name)
        if alarm.param_id == FrameType.SIREN_NOTIFY:
            for channel, on, waiter in self._siren_waiters:
                if channel == alarm.channel and alarm.alarm_state is on and not waiter.done():
                    waiter.set_result(None)
        change = alarm.alarm_change(self.serial, at=datetime.now(UTC))
        if change is not None:
            for alarming, future in self._tone_waiters:
                if alarming == change.alarming and not future.done():
                    future.set_result(change)
        if change is not None and change.alarming != self._alarming:
            self._alarming = change.alarming
            _LOGGER.debug("%s: alarm %s", self._log_name, "on" if change.alarming else "off")
            self._bus.emit(change)

    def _note_mode_report(self, value: GuardMode | int) -> None:
        """A ``0x047F`` report: the effective mode.

        Outside Schedule (or before the selection is known) the selected mode is the
        same. While Schedule is selected the report is a slot boundary — or a change of
        selection that says the same thing, so a parameter read is cued to tell them
        apart; a report of the mode this session's own arm asks for is that arm's. A report
        during an arm to Schedule is the slot's mode that selection put in force; the arm's
        result or read-back confirms the selection (or corrects it). On a station whose
        dump does not carry the mode, the report is filed as its parameters.
        """
        arming = self._arming_to
        if arming is GuardMode.SCHEDULE:
            self._param_state.set_modes(GuardMode.SCHEDULE, value)
        elif self._param_state.guard_mode != GuardMode.SCHEDULE or value == arming:
            self._param_state.set_modes(value, value)
        else:
            self._param_state.set_modes(None, value)
            if self._reprobe_at is None:
                self._reprobe_at = time.monotonic() + UNSOLICITED_REPROBE_DELAY
        if not self._param_state.dump_carries_mode():
            # A station whose dump lacks the mode: the report is its only local word.
            self._param_state.file_modes("mode report", origin_kind=ParamOrigin.LOCAL_WRITE)

    def _take_state(self, frame: Frame) -> None:
        """Count a decoded state frame (0x044F, 0x047F, an alarm frame) as taken.

        State is taken under any encryption, as the eufy app takes it: clear, the static
        key, the session key (see docs/protocol/session-crypto.md). Only GCM and an RSA
        session's own key authenticate it (:attr:`state_authenticated`, information
        only). State in clear, or under the static key on a session that holds its own
        key, is logged at INFO once per session, frame type and encryption.
        """
        encryption = self._keys.state_encryption(frame)
        self._health.state_frames[encryption] += 1
        if frame.cipher == FrameCipher.GCM or self._keys.session_ecb_frame(frame):
            self._state_authenticated = True
            return
        if self._state_authenticated is None:
            self._state_authenticated = False
        if encryption != "clear" and not self._keys.holds_own_key:
            return
        kind = (frame.type, encryption)
        if kind in self._unauthenticated_logged:
            return
        self._unauthenticated_logged.add(kind)
        _LOGGER.info(
            "%s: station state 0x%04x arrived %s (unauthenticated), taken as the eufy app does",
            self._log_name,
            frame.type,
            _UNAUTHENTICATED_STATE[encryption],
        )

    def _state_body(self, frame: Frame) -> bytes | None:
        """The plaintext of a binary state frame: an RSA session's clear body as is, an
        ECB body under the key its encryption type names
        (:meth:`~.keys.SessionKeys.ecb_key`), a GCM body under the session key. None when
        it has no key or does not decode (counted)."""
        payload = frame.payload
        if self._keys.plain_rsa_frame(frame):
            return payload
        if frame.cipher == FrameCipher.ECB:
            key = self._keys.ecb_key(frame)
            if key is None or len(payload) % 16:
                self._health.dropped_undecodable += 1
                return None
            return ecb_decrypt(key, payload)
        if frame.cipher != FrameCipher.GCM or self._keys.session_key is None:
            return None
        try:
            return gcm_decrypt_broadcast(self._keys.session_key, payload)
        except ProtocolError:
            self._health.dropped_undecodable += 1
            return None

    def _decode_alarm_mode(self, frame: Frame) -> int | None:
        if self._keys.plain_rsa_frame(frame):
            mode = decode_alarm_mode_notify(frame, clear=True)
        else:
            mode = decode_alarm_mode_notify(
                frame, static_key=self._keys.ecb_key(frame), session_key=self._keys.session_key
            )
        if mode is not None:
            self._take_state(frame)
        return mode

    def _decode_json(self, frame: Frame) -> dict[str, Any] | None:
        plain_rsa = self._keys.plain_rsa_frame(frame)
        obj = self._decode_json_body(frame, plain_rsa=plain_rsa)
        if obj is not None and frame.type in _STATE_FRAME_TYPES:
            self._take_state(frame)
        return obj

    def _decode_json_body(self, frame: Frame, *, plain_rsa: bool) -> dict[str, Any] | None:
        """The JSON object of a frame :meth:`_decode_json` lets through."""
        payload = frame.payload
        if plain_rsa:
            return self._counted_json(payload)  # an RSA session's clear reply
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
            key = self._keys.ecb_key(frame)
            if key is None:
                return None
            if len(payload) < 16 or len(payload) % 16:
                self._health.dropped_undecodable += 1
                return None
            return self._counted_json(ecb_decrypt(key, payload))
        if frame.cipher == FrameCipher.GCM:
            if self._keys.session_key is None or len(payload) < 29:
                return None
            if decode_command_receipt(frame) is not None:
                return None  # a command receipt: GCM-tagged, but not ciphertext
            try:
                return self._counted_json(gcm_decrypt_broadcast(self._keys.session_key, payload))
            except ProtocolError:
                self._health.dropped_undecodable += 1
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
            self._health.dropped_undecodable += 1
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
        self._media_slot.fail(exc)
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
            clock = _StallClock()
            if resend_after is not None and resend_after < timeout:
                await self._wait_until(waiter.future, started + resend_after, label, clock=clock)
                if not waiter.future.done():
                    _LOGGER.debug(
                        "%s: %s unanswered after %.1fs; resending",
                        self._log_name,
                        label,
                        resend_after,
                    )
                    send()
            if not await self._wait_until(waiter.future, deadline, label, clock=clock):
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
        self,
        future: asyncio.Future[object],
        deadline: float,
        label: str,
        *,
        clock: _StallClock | None = None,
        event: asyncio.Event | None = None,
    ) -> bool:
        """Wait for ``future`` (or ``event``) until ``deadline`` (monotonic); whether
        ``future`` is done.

        The wait runs in steps of :data:`LOOP_STALL_STEP`. A step that ends at least
        :data:`LOOP_STALL_LATENESS` late means something else held the event loop, and
        replies that arrived meanwhile are still queued (read one datagram per loop turn):
        the deadline moves out by that step's whole duration (the hold may have taken all
        of it), up to :data:`LOOP_STALL_MAX` in all, so the station gets its full timeout
        of time in which this client could hear it, and a held last step still leaves a
        step to read the queue. ``clock`` carries that credit across the wait phases of
        one request. A wait entered past its deadline still yields to the loop once.
        """
        clock = _StallClock() if clock is None else clock
        flag = None if event is None else asyncio.ensure_future(event.wait())
        waits: set[asyncio.Future[Any]] = {future} if flag is None else {future, flag}
        first = True
        try:
            while not future.done() and (event is None or not event.is_set()):
                started = time.monotonic()
                left = deadline + clock.credited - started
                if left <= 0 and not first:
                    break
                first = False
                step = min(max(left, 0.0), LOOP_STALL_STEP)
                await asyncio.wait(waits, timeout=step, return_when=asyncio.FIRST_COMPLETED)
                held = time.monotonic() - started
                late = held - step
                if late >= LOOP_STALL_LATENESS and clock.credited < LOOP_STALL_MAX:
                    extra = min(held, LOOP_STALL_MAX - clock.credited)
                    clock.credited += extra
                    _LOGGER.debug(
                        "%s: %s: the event loop was held %.1fs; deadline moved out by %.1fs",
                        self._log_name,
                        label,
                        held,
                        extra,
                    )
        finally:
            if flag is not None:
                flag.cancel()
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
        if self._keys.aes_key is not None:
            return self._send_session_ecb(
                plaintext, frame_type=frame_type, dev_type=dev_type, flag=flag
            )
        key = self._keys.session_key
        if key is None:
            raise StationUnreachableError("no P2P session")
        seq = self._keys.gcm_seq
        self._keys.gcm_seq += 1
        nonce = os.urandom(12)
        payload = gcm_encrypt_command(key, plaintext, nonce=nonce, seq=seq)
        self._keys.gcm_counter = (self._keys.gcm_counter + 2) & 0xFF
        frame = encode_frame(
            frame_type, payload, gcm_subheader(self._keys.gcm_counter, dev_type, flag=flag)
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
        """An RSA session's frame: AES-128-ECB under the session key, zero-padded, or
        clear when the session sends encryption type 0."""
        key = cast(bytes, self._keys.aes_key)
        seq = self._keys.ecb_seq
        self._keys.ecb_seq = (seq + 1) & 0xFF
        encryption = self._keys.session_encryption
        subheader = bytes([FrameCipher.ECB, seq, dev_type & 0xFF, encryption, flag & 0xFF, 0x00])
        body = plaintext if encryption == FRAME_PLAIN else ecb_encrypt(key, plaintext)
        frame = encode_frame(frame_type, body, subheader)
        if _WIRE.isEnabledFor(logging.DEBUG):
            obj = decode_json_payload(plaintext)
            _WIRE.debug(
                "%s: tx session-ECB frame 0x%04x seq %d: %s",
                self._log_name,
                frame_type,
                seq,
                plaintext.hex() if obj is None else Payload(obj),
            )
        return self._send_request(frame_type, frame, self._require_transport())

    def _send_request(self, frame_type: int, frame: bytes, transport: PPPPTransport) -> int:
        """Send ``frame`` on channel 0; on an RSA session the next channel-0 frame of
        ``frame_type`` within :data:`RSA_RESULT_WINDOW` is read as its result, under a new
        slot (:attr:`_result_slot`)."""
        if self._keys.aes_key is not None:
            due = time.monotonic() + RSA_RESULT_WINDOW
            self._result_slot += 1
            self._results_due.setdefault(frame_type, []).append((due, self._result_slot))
        return transport.send_drw(0, frame)

    def _take_result_due(self, frame_type: int) -> int | None:
        """The slot of the oldest send of ``frame_type`` that awaits its result, taken;
        None when none does."""
        due = self._results_due.get(frame_type)
        if not due:
            return None
        now = time.monotonic()
        while due and due[0][0] < now:
            due.pop(0)
        if not due:
            return None
        return due.pop(0)[1]

    def _rsa_play_ctrl(self, frame: Frame) -> int | None:
        """An RSA session's end-of-playback value: the first ``u32le`` of its body under
        any encryption type (:meth:`~.keys.SessionKeys.rsa_plaintext`)."""
        body = self._keys.rsa_plaintext(frame)
        return int.from_bytes(body[:4], "little") if body is not None and len(body) >= 4 else None

    def _decode_receipt(self, channel: int, frame: Frame) -> tuple[int, int | None] | None:
        """The code of a command receipt on the request channel (0) and, on an RSA
        session, the slot of the send it answers; None for any other frame.

        A GCM session: a GCM-tagged clear receipt (:func:`decode_command_receipt`). An
        RSA session: the first channel-0 frame of a sent request's type whose payload
        holds 4 to 132 bytes is that request's result, its code the clear ``int32le``
        at ``payload[0:4]`` (:func:`decode_command_result`), as the eufy app reads it:
        nothing decrypted, the encryption type and the tail ignored. Frames of any other
        type stay notifies.
        """
        if channel != 0:
            return None
        if self._keys.aes_key is None:
            code = decode_command_receipt(frame)
            return None if code is None else (code, None)
        code = decode_command_result(frame.payload)
        if code is None or (slot := self._take_result_due(frame.type)) is None:
            return None
        return code, slot

    def _note_receipt(self, inbound: Inbound, code: int) -> None:
        """Count a command receipt and log it at DEBUG: frame type, channel, encryption
        type (subheader byte 3), payload length, code and whether the bytes after the
        code are zero."""
        count_capped(self._health.receipts_by_code, str(code))
        frame = inbound.frame
        _LOGGER.debug(
            "%s: result 0x%04x ch%d enc%s len %d: code %d %s, tail %s",
            self._log_name,
            frame.type,
            inbound.channel,
            frame_encryption(frame.subheader),
            len(frame.payload),
            code,
            RECEIPT_CODES.get(code, ""),
            "nonzero" if any(frame.payload[4:]) else "zero",
        )

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


def _scalar_result(inbound: Inbound, command: int) -> int | None:
    """The result code of an ECB scalar reply to ``command``, else None: frame type
    ``command``, the code in clear at ``payload[0:4]`` on every session, as the eufy app
    reads it."""
    if inbound.type != command or len(inbound.frame.payload) < 4:
        return None
    return decode_ecb_scalar_result(inbound.frame.payload)


def _lost_cause(exc: Exception, *, asleep: bool) -> DisconnectCause:
    """The cause an announced link's loss is reported under."""
    if asleep:
        return DisconnectCause.IDLE
    if isinstance(exc, StationClosedLinkError):
        return DisconnectCause.STATION_CLOSED
    if isinstance(exc, SilentLinkError):
        return DisconnectCause.LINK_SILENT
    return DisconnectCause.UNREACHABLE  # the local socket closed


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


def _raise_for_code(command: int, code: int) -> None:
    """Raise the :func:`_rejection` of a non-zero result code."""
    if code != 0:
        raise _rejection(command, code, ECB_RESULT_CODES.get(code, ""))


def _raise_waiter_error(waiter: _Waiter) -> None:
    """Re-raise an exception the dispatcher set on ``waiter`` (session loss, a rejection)."""
    future = waiter.future
    if future.done() and not future.cancelled() and (error := future.exception()) is not None:
        raise error


class _MissingKeyError(HandshakeError):
    """The credentials hold no key for the handshake the station chose."""

    def __init__(self, cipher_id: int, *, rsa: bool) -> None:
        self.cipher_id = cipher_id
        self.rsa = rsa
        self.reason = "no_rsa_key" if rsa else "no_ecc_key"
        kind = "RSA" if rsa else "ECC"
        super().__init__(f"no {kind} private key held for cipher {cipher_id}")

    def held_by(self, creds: P2PCredentials) -> bool:
        """Whether ``creds`` hold the key this handshake needs."""
        return bool(creds.rsa_private_key if self.rsa else creds.ecc_private_key)

    def unusable(self) -> CipherUnusableError:
        return CipherUnusableError(str(self), cipher_id=self.cipher_id, reason=self.reason)


class _CipherMismatchError(HandshakeError):
    """The credentials are for another cipher than the one CONN_INIT names."""

    def __init__(self, named: int, held: int) -> None:
        self.named = named
        super().__init__(f"CONN_INIT names cipher {named}, the key is cipher {held}")


class _StallClock:
    """The event-loop hold credited to one request, shared by its wait phases."""

    __slots__ = ("credited",)

    def __init__(self) -> None:
        self.credited = 0.0


def _or(value: float | None, default: float) -> float:
    return default if value is None else value


def _or_unknown(value: int | None) -> str:
    return "?" if value is None else str(value)
