"""Events the library emits.

Security events arrive two ways — pushed by the station over local P2P, and
relayed by the eufy cloud over FCM — and both decode into the same
:class:`SecurityEvent`, tagged with its :class:`EventSource`. The two channels
overlap but are not interchangeable: P2P is about a second faster for camera
detections and works without internet; only the cloud reaches a station off the LAN
and carries arming pushes (see ``docs/protocol/events.md``). The station's own
guard-mode reports over P2P become :class:`GuardModeChanged`, not a
:class:`SecurityEvent`. :class:`~.client.EufySecurity` de-duplicates across both
channels (:class:`EventDeduplicator`): each real occurrence is emitted once, plus at
most one enrichment copy that adds media paths (:attr:`SecurityEvent.enriches`).

Subscribers receive the :data:`Event` union and return nothing; subscribing
returns a callable that unsubscribes (the Home Assistant convention).
"""

from __future__ import annotations

import json
import logging
import math
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, TypeGuard

from ._logging import LogThrottle, redact_serial
from .devices.recipes import PresetPosition
from .devices.support import Evidence, Support
from .exceptions import (
    CloudError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    RefreshCooldownError,
)
from .models import FrameCipher, GuardMode

if TYPE_CHECKING:
    from .p2p.storage_info import StorageInfo
    from .station import StationState

_LOGGER = logging.getLogger(__name__)


class EventSource(StrEnum):
    """Which channel delivered an event."""

    P2P = "p2p"
    CLOUD = "cloud"


_APP_PUSH_ENUM: Final = Evidence(Support.DECLARED, "eufy app push message enum")
_CUS_PUSH_MODE: Final = Evidence(
    Support.DECLARED, "eufy app CusPushMode", "no msg_type 16 push captured on any channel"
)
_ALARM_PUSH_SEEN: Final = Evidence(
    Support.VERIFIED,
    "live FCM capture",
    "alarm_type 3 and 25 at a trigger, 16 when stopped from the app; never sent over P2P",
)


class PushMessageType(IntEnum):
    """``msg_type``: the subsystem that raised a push (HomeBase-paired devices)."""

    SECURITY = 1
    TFCARD = 2
    DOOR_SENSOR = 3
    CAM_STATE = 4
    GSENSOR = 5
    BATTERY_LOW = 6
    BATTERY_HOT = 7
    LIGHT_STATE = 8
    ARMING = 9
    ALARM = 10
    BATTERY_FULL = 11
    REPEATER_RSSI_WEAK = 12
    UPGRADE_STATUS = 13
    MOTION_SENSOR = 14
    BAT_DOORBELL = 15
    ALARM_DELAY = 16
    HUB_BATT_POWERED = 17
    INDOOR = 18
    SMARTLOCK = 19
    LOCK = 20
    BBM_SOCK = 21
    DOOR_STATUS = 22
    HHD = 23

    @property
    def evidence(self) -> Evidence:
        """How this value is known: seen live, or only named by the app."""
        return _MESSAGE_TYPE_EVIDENCE.get(self, _APP_PUSH_ENUM)


_MESSAGE_TYPE_EVIDENCE: Final[Mapping[PushMessageType, Evidence]] = MappingProxyType(
    {
        PushMessageType.ARMING: Evidence(
            Support.VERIFIED, "live FCM capture", "never captured over P2P"
        ),
        PushMessageType.ALARM: _ALARM_PUSH_SEEN,
        PushMessageType.ALARM_DELAY: _CUS_PUSH_MODE,
        PushMessageType.INDOOR: Evidence(Support.VERIFIED, "live P2P and FCM capture"),
    }
)


class DetectionType(IntEnum):
    """``event_type``: what a camera detected."""

    MOTION = 3101
    PERSON = 3102
    DOORBELL_PRESS = 3103
    CRYING = 3104
    SOUND = 3105
    PET = 3106
    VEHICLE = 3107
    DOG = 3108
    DOG_LICK = 3109
    DOG_POOP = 3110
    IDENTITY_PERSON = 3111
    STRANGER_PERSON = 3112

    @property
    def evidence(self) -> Evidence:
        """How this value is known: seen live, or only named by the app."""
        return _DETECTION_EVIDENCE.get(self, _APP_PUSH_ENUM)


_SEEN_LIVE: Final = Evidence(Support.VERIFIED, "live P2P capture")
_DETECTION_EVIDENCE: Final[Mapping[DetectionType, Evidence]] = MappingProxyType(
    {
        DetectionType.PERSON: _SEEN_LIVE,
        DetectionType.VEHICLE: _SEEN_LIVE,
        DetectionType.IDENTITY_PERSON: _SEEN_LIVE,
    }
)


_ARMING_USER_EVIDENCE: Final = Evidence(
    Support.DECLARED, "eufy app CusPushMode", "every FCM arming push captured carried user 2"
)


class EventScope(StrEnum):
    """Whether an event is about the station as a whole or about one device."""

    STATION = "station"
    """Arming, alarm and alarm-delay pushes (:data:`STATION_MESSAGE_TYPES`)."""
    DEVICE = "device"
    """Everything else: detections and device notifications."""


#: The ``msg_type`` values that describe the station, not one device.
STATION_MESSAGE_TYPES: Final = frozenset(
    {PushMessageType.ARMING, PushMessageType.ALARM, PushMessageType.ALARM_DELAY}
)


class AlarmPhase(StrEnum):
    """Where an alarm push puts the station's alarm."""

    TRIGGERED = "triggered"
    DELAY = "delay"
    """The entry delay is running (``alarm_delay`` seconds)."""
    STOPPED = "stopped"


class AlarmStopSource(IntEnum):
    """``alarm_type`` values (inner ``type`` on an alarm push) that end an alarm."""

    KEYPAD = 15
    APP = 16
    HOMEBASE = 17

    @property
    def evidence(self) -> Evidence:
        """APP was seen live (a cloud push and the P2P tone frame); the others are only
        named by the app."""
        return _ALARM_PUSH_SEEN if self is AlarmStopSource.APP else _CUS_PUSH_MODE


class ArmingSource(StrEnum):
    """Who changed the guard mode, from the arming push's ``user`` code."""

    KEYPAD = "keypad"
    KEY_FOB = "key_fob"
    APP = "app"
    """Any other ``user`` code (an FCM arming push carries 2)."""

    @property
    def evidence(self) -> Evidence:
        """Every member is DECLARED from the app; no keypad or key-fob arm was captured."""
        return _ARMING_USER_EVIDENCE

    @classmethod
    def for_user(cls, user: int | None) -> ArmingSource | None:
        """The source a ``user`` code maps to; None when the push named none."""
        if user is None:
            return None
        return _ARMING_USERS.get(user, cls.APP)


_ARMING_USERS: Final[Mapping[int, ArmingSource]] = MappingProxyType(
    {1: ArmingSource.KEYPAD, 5: ArmingSource.KEY_FOB}
)


def coerce_int(value: object) -> int | None:
    """A wire value as an int, or None when it is not one.

    Shared by every decoder of loosely typed station/cloud JSON. Accepts ints,
    integral finite floats and their string forms (``"12"``, ``"12.0"``). Rejects
    booleans (an ``int`` subclass that is never a count or code on the wire),
    fractional or non-finite numbers, and everything else.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                value = float(text)
            except ValueError:
                return None
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    return None


def coerce_str(value: object) -> str | None:
    """A wire value as a non-empty, stripped string, or None.

    Numbers are rendered with ``str`` (a station sends ``start_time`` as either a
    formatted string or an epoch int, and a name field can arrive as a number);
    booleans, containers and blank strings are None.
    """
    if value is None or isinstance(value, (bool, dict, list, tuple)):
        return None
    text = str(value).strip()
    return text or None


# ── untrusted push fields ────────────────────────────────────────────────────
# A push payload is the station's (or, over P2P under ECB, anyone's on the LAN).
# Its paths become command payloads (a still fetch's ``file``, a playback's
# ``filepath``), so they are checked before they are lifted.

#: Every station media path starts here.
MEDIA_PATH_PREFIX: Final = "/zx/"
#: The longest media path accepted.
MEDIA_PATH_MAX: Final = 256
#: Suffix of a still (thumbnail, detection crop).
STILL_SUFFIX: Final = ".jpg"
#: Suffix of a recording.
RECORDING_SUFFIX: Final = ".zxvideo"
#: Event times outside [2020-01-01, 2100-01-01) were not produced by this hardware.
EVENT_TIME_MIN_MS: Final = 1_577_836_800_000
EVENT_TIME_MAX_MS: Final = 4_102_444_800_000
#: An event time further ahead of the host clock than this is rejected.
EVENT_TIME_MAX_SKEW_S: Final = 600.0
#: Names (device, person, user) are cut to this many characters.
NAME_MAX: Final = 64
#: The longest ``unique_id`` accepted (a captured one is 32 hex characters).
UNIQUE_ID_MAX: Final = 64

#: The ``SecurityEvent`` fields holding station media paths (an enrichment adds one).
MEDIA_PATH_FIELDS: Final = ("thumb_path", "crop_path", "video_path")

_CAMERA_DIR: Final = re.compile(r"Camera\d+")
_UNIQUE_ID: Final = re.compile(rf"[\x21-\x7e]{{1,{UNIQUE_ID_MAX}}}")
_SKEW_LOG: Final = LogThrottle(interval=math.inf)  # once per process and channel


def wall_ms() -> int:
    """The host clock as epoch milliseconds."""
    return time.time_ns() // 1_000_000


def is_station_media_path(value: object, suffix: str) -> TypeGuard[str]:
    """Whether ``value`` is a plausible station media path ending in ``suffix``.

    It must start with :data:`MEDIA_PATH_PREFIX`, be at most :data:`MEDIA_PATH_MAX`
    characters of printable ASCII, and contain no ``..``.
    """
    return (
        isinstance(value, str)
        and value.startswith(MEDIA_PATH_PREFIX)
        and value.endswith(suffix)
        and len(value) <= MEDIA_PATH_MAX
        and value.isascii()
        and value.isprintable()
        and ".." not in value
    )


def camera_dir(path: str | None) -> str | None:
    """The ``CameraNN`` directory of a station media path, or None."""
    if path is None:
        return None
    return next((part for part in path.split("/") if _CAMERA_DIR.fullmatch(part)), None)


def payload_text(value: object) -> str | None:
    """A JSON string field as a stripped, non-empty string capped at :data:`NAME_MAX`."""
    if not isinstance(value, str):
        return None
    return value.strip()[:NAME_MAX] or None


class PushFieldReader:
    """Lifts and checks the fields of one push payload, collecting what it rejects.

    The P2P decoder and the cloud decoder read the same inner JSON through one
    reader, so both produce the same fields. A rejected value becomes None and its
    ``SecurityEvent`` field name lands in :attr:`rejected`.
    """

    def __init__(self, source: EventSource, *, now_ms: Callable[[], int] = wall_ms) -> None:
        self._source = source
        self._now_ms = now_ms
        self.rejected: set[str] = set()

    def guard_mode(self, inner: Mapping[str, Any], *, authenticated: bool = True) -> int | None:
        """``arming`` as the guard mode, or None.

        Call it after :meth:`event_time`. A push whose event time was rejected cannot
        be ordered, and an unauthenticated one (a P2P frame under ECB) could be forged,
        so neither may move the reported mode: its ``guard_mode`` is listed as rejected.
        """
        arming = coerce_int(inner.get("arming"))
        if arming is None:
            return None
        if not authenticated or "event_time_ms" in self.rejected:
            self.rejected.add("guard_mode")
            return None
        return arming

    def path(self, name: str, value: object, suffix: str) -> str | None:
        """A media path, or None (listed as rejected when present but invalid)."""
        if value is None or value == "":
            return None
        if is_station_media_path(value, suffix):
            return value
        self.rejected.add(name)
        return None

    def payload_time(self, inner: Mapping[str, Any]) -> int | None:
        """The inner payload's own event time (``trigger_time``, else ``create_time``), in
        epoch ms, validated like :meth:`event_time`; None when it names neither.

        Both channels carry the same inner payload, so a time taken from it is the same
        on both copies of an occurrence. The FCM *outer* ``event_time`` is not: it is
        about 3 s later than the inner ``create_time``.
        """
        trigger = coerce_int(inner.get("trigger_time"))
        return trigger if trigger is not None else coerce_int(inner.get("create_time"))

    def unique_id(self, value: object) -> str | None:
        """The per-occurrence ``unique_id``: printable ASCII without spaces, at most
        :data:`UNIQUE_ID_MAX` characters; None when absent or empty, rejected otherwise."""
        if value is None or value == "":
            return None
        if isinstance(value, str) and _UNIQUE_ID.fullmatch(value):
            return value
        self.rejected.add("unique_id")
        return None

    def record_id(self, value: object) -> int | None:
        """The occurrence's event-database ``record_id``: a positive int. ``0`` (no
        record) and absence are None; anything else is rejected."""
        if value is None or value == 0:
            return None
        record = coerce_int(value)
        if record is not None and record > 0:
            return record
        self.rejected.add("record_id")
        return None

    def event_time(self, value_ms: int | None) -> int | None:
        """An epoch-ms event time within the plausible range, else None (rejected).

        Call it on milliseconds: a cloud time in seconds must be converted first.
        """
        if value_ms is None:
            return None
        if not EVENT_TIME_MIN_MS <= value_ms < EVENT_TIME_MAX_MS:
            self.rejected.add("event_time_ms")
            return None
        now = self._now_ms()
        if value_ms - now > EVENT_TIME_MAX_SKEW_S * 1000:
            self.rejected.add("event_time_ms")
            if _SKEW_LOG.should_log(self._source):
                _LOGGER.warning(
                    "%s push event time %.0fs ahead of the host clock: time dropped "
                    "(a wrong host or station clock; logged once)",
                    self._source,
                    (value_ms - now) / 1000,
                )
            return None
        return value_ms

    def common(self, inner: Mapping[str, Any]) -> dict[str, Any]:
        """The ``SecurityEvent`` fields both channels lift the same way from ``inner``.

        ``alarm_type`` is the inner ``type``, lifted only on alarm and alarm-delay
        pushes (elsewhere ``type`` means something else). ``guard_mode`` is not
        included: read it with :meth:`guard_mode`, after the event time.
        """
        msg_type = coerce_int(inner.get("msg_type"))
        alarm = msg_type in (PushMessageType.ALARM, PushMessageType.ALARM_DELAY)
        return {
            "channel": coerce_int(inner.get("channel")),
            "device_name": payload_text(inner.get("name"))
            or payload_text(inner.get("device_name")),
            "msg_type": msg_type,
            "event_type": coerce_int(inner.get("event_type")),
            "person_name": (
                payload_text(inner.get("person_name")) or payload_text(inner.get("nick_name"))
            ),
            "push_count": coerce_int(inner.get("push_count")),
            "alarm_type": coerce_int(inner.get("type")) if alarm else None,
            "alarm_delay": coerce_int(inner.get("alarm_delay")),
            "mode": coerce_int(inner.get("mode")),
            "arming_user": coerce_int(inner.get("user")),
            "user_name": payload_text(inner.get("user_name")),
            "unique_id": self.unique_id(inner.get("unique_id")),
            "record_id": self.record_id(inner.get("record_id")),
        }


def _frozen_raw(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """A read-only snapshot of ``raw``, so a frozen event never shares mutable state."""
    return raw if isinstance(raw, MappingProxyType) else MappingProxyType(dict(raw))


def _raw_field() -> Any:
    return field(
        default_factory=lambda: MappingProxyType({}), repr=False, compare=False, hash=False
    )


def _enum_or_none[E: IntEnum](enum: type[E], value: int | None) -> E | None:
    if value is None:
        return None
    try:
        return enum(value)
    except ValueError:
        return None


_ROW_TIME_FORMAT: Final = "%Y-%m-%d %H:%M:%S"
_ROW_OFFSET: Final = re.compile(r"([+-])(\d{2}):?(\d{2})")
_EPOCH_MS_MIN: Final = 100_000_000_000
"""An epoch value at or above this is milliseconds, below it seconds (year 5138 vs 1973)."""


def _row_time(value: str | None, offset: object) -> datetime | None:
    """A history row time (``YYYY-MM-DD HH:MM:SS`` in the row's ``±HHMM`` offset, or an
    epoch in seconds or milliseconds) as an aware time; None when it does not parse."""
    if value is None:
        return None
    if value.isdigit():
        number = int(value)
        try:
            seconds = number / 1000 if number >= _EPOCH_MS_MIN else number
            return datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        naive = datetime.strptime(value, _ROW_TIME_FORMAT)  # noqa: DTZ007 - zoned below
    except ValueError:
        return None
    match = _ROW_OFFSET.fullmatch(offset) if isinstance(offset, str) else None
    if match is None:
        return naive.astimezone()  # the host's zone: stations keep local time
    sign, hours, minutes = match.groups()
    delta = timedelta(hours=int(hours), minutes=int(minutes))
    if delta >= timedelta(hours=24):
        return naive.astimezone()
    return naive.replace(tzinfo=timezone(-delta if sign == "-" else delta))


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityEvent:
    """A detection, alarm or device notification from a station or the cloud.

    Only fields observed on the wire are lifted out; everything else stays in
    ``raw``. Paths (``thumb_path`` …) point at the station's own disk and are
    fetched over P2P; ``pic_url`` is a cloud URL.

    ``event_time_ms`` is when the device raised the event (epoch ms), not when it
    arrived: the cloud redelivers and reorders pushes, so order by it, not by
    arrival. ``raw`` is a read-only snapshot; it is ignored by equality and
    hashing, so two decodes of the same event compare equal.

    ``frame_cipher`` is the cipher of the P2P frame that carried the event, or None
    when it did not come over P2P (a cloud push); see :attr:`authenticated`.

    Untrusted fields are checked before they are lifted: media paths must be
    station paths (:func:`is_station_media_path`), event times plausible and not
    far ahead of the host clock, names at most :data:`NAME_MAX` characters. A value
    that fails becomes None and its field name is listed in ``rejected_fields``.

    Station pushes (arming, alarm, alarm delay) carry ``guard_mode`` (``arming``: the
    **selected** mode, 2 while Schedule is selected), ``mode`` (the **effective** mode, in
    force: a schedule slot's mode under Schedule; see :class:`GuardModeChanged`),
    ``alarm_type`` (the inner ``type``),
    ``alarm_delay`` (seconds), ``arming_user`` (the raw ``user`` code) and
    ``user_name``. ``user_name`` is whatever the arming client sent: never an
    authenticated identity. Read them through :attr:`scope`, :attr:`alarm_phase`
    and :attr:`arming_source`, which apply the authentication rules.

    ``push_id`` is the cloud's ``span_id`` (None over P2P); the push listener
    de-duplicates redeliveries on it. ``unique_id`` (the station's per-occurrence id)
    and ``record_id`` (its event-database row) come from the inner payload, which is
    identical on both channels. :attr:`dedupe_key` names the occurrence across
    both channels. ``enriches`` is True on a later copy of an occurrence already
    delivered, admitted only because it carries media paths the earlier copies lacked
    (see :class:`EventDeduplicator`): update the existing occurrence with its paths,
    do not count a new detection.
    """

    source: EventSource
    station_sn: str | None = None
    device_sn: str | None = None
    channel: int | None = None
    device_name: str | None = None
    msg_type: int | None = None
    event_type: int | None = None
    event_time_ms: int | None = None
    guard_mode: int | None = None
    person_name: str | None = None
    thumb_path: str | None = None
    video_path: str | None = None
    crop_path: str | None = None
    pic_url: str | None = None
    push_id: str | None = None
    unique_id: str | None = None
    record_id: int | None = None
    frame_cipher: FrameCipher | None = None
    push_count: int | None = None
    alarm_type: int | None = None
    alarm_delay: int | None = None
    mode: int | None = None
    arming_user: int | None = None
    user_name: str | None = None
    rejected_fields: frozenset[str] = frozenset()
    enriches: bool = field(default=False, compare=False)
    """Delivery metadata (see :class:`EventDeduplicator`); ignored by equality and hashing."""
    raw: Mapping[str, Any] = _raw_field()

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", _frozen_raw(self.raw))
        object.__setattr__(self, "rejected_fields", frozenset(self.rejected_fields))

    @property
    def dedupe_key(self) -> str | None:
        """The occurrence's key, the same on both channels.

        ``unique:<unique_id>`` when the payload carries a ``unique_id`` (both copies of a
        detection do). Otherwise ``device_sn:event second:event_type``, None without a
        device or a time: seconds, because an FCM time without an inner time is whole
        seconds while P2P ``trigger_time`` is milliseconds, and ``event_type`` stays in
        the key, so at worst two detections of one second are both delivered.
        """
        if self.unique_id is not None:
            return f"unique:{self.unique_id}"
        if self.device_sn is None or self.event_time_ms is None:
            return None
        event_type = "" if self.event_type is None else self.event_type
        return f"{self.device_sn}:{self.event_time_ms // 1000}:{event_type}"

    @property
    def media_paths(self) -> frozenset[str]:
        """The names of the station media path fields this event carries."""
        return frozenset(name for name in MEDIA_PATH_FIELDS if getattr(self, name) is not None)

    @property
    def authenticated(self) -> bool:
        """Whether the event's origin is authenticated.

        True for a P2P frame under GCM (its tag was verified against the session
        key) and for a cloud push (``frame_cipher`` None: TLS from eufy's servers).
        False for a P2P frame under ECB, whose static key anyone on the LAN can
        derive: such an event is still delivered, but must not drive a security
        decision (clearing an alarm, attributing an arm).

        This proves **origin, not freshness**: station → client GCM frames carry no
        sequence number, so a genuine frame can be replayed within one session.
        Order and de-duplicate by ``event_time_ms`` / ``dedupe_key``.
        """
        return self.frame_cipher is not FrameCipher.ECB

    @property
    def message_type(self) -> PushMessageType | None:
        """``msg_type`` as an enum, or None when unknown."""
        return _enum_or_none(PushMessageType, self.msg_type)

    @property
    def detection(self) -> DetectionType | None:
        """``event_type`` as an enum, or None when unknown."""
        return _enum_or_none(DetectionType, self.event_type)

    @property
    def scope(self) -> EventScope:
        """STATION for arming, alarm and alarm-delay pushes; DEVICE otherwise."""
        return EventScope.STATION if self.msg_type in STATION_MESSAGE_TYPES else EventScope.DEVICE

    @property
    def alarm_phase(self) -> AlarmPhase | None:
        """The alarm state an alarm push reports, or None.

        An ALARM push is TRIGGERED, or STOPPED when ``alarm_type`` is an
        :class:`AlarmStopSource`; an ALARM_DELAY push is DELAY. A stop is reported
        only when :attr:`authenticated`: an unauthenticated stop is None (a forged
        ECB frame must not clear an alarm), with ``alarm_type`` still set.
        Verified over FCM for triggers (``alarm_type`` 3, 25) and the app's stop (16);
        the alarm-delay push is declared from the app. For the alarm's state across both
        channels, use :class:`AlarmChanged`.
        """
        match self.message_type:
            case PushMessageType.ALARM_DELAY:
                return AlarmPhase.DELAY
            case PushMessageType.ALARM:
                if _enum_or_none(AlarmStopSource, self.alarm_type) is None:
                    return AlarmPhase.TRIGGERED
                return AlarmPhase.STOPPED if self.authenticated else None
            case _:
                return None

    @property
    def arming_source(self) -> ArmingSource | None:
        """Who changed the guard mode, on an authenticated ARMING push; else None.

        Declared from the app; a live arming push carries ``user`` 2 (APP).
        """
        if self.message_type is not PushMessageType.ARMING or not self.authenticated:
            return None
        return ArmingSource.for_user(self.arming_user)


@dataclass(frozen=True, slots=True, kw_only=True)
class HistoryRecord:
    """One row of the station's ``history_record_info`` table.

    This is a **query result** (from
    :meth:`~.p2p.session.StationSession.async_list_history`), not a live push — a
    different lifecycle from :class:`SecurityEvent`, so it is a separate type. The
    fields a consumer usually wants are lifted out; the arming
    context (``arm_mode``/``msg_type``/``user_name``) is parsed out of the row's
    ``str_extra`` JSON string. Everything else stays in ``raw``.

    Field types are normalised with :func:`coerce_int` / :func:`coerce_str`:
    ``start_time``/``end_time`` stay strings whatever the firmware sent (an epoch
    int becomes its decimal string), blank strings become None. ``raw`` is a
    read-only snapshot ignored by equality and hashing.
    """

    record_id: int
    device_sn: str | None = None
    station_sn: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    storage_type: int | None = None
    thumb_path: str | None = None
    storage_path: str | None = None
    msg_type: int | None = None
    arm_mode: int | None = None
    user_name: str | None = None
    raw: Mapping[str, Any] = _raw_field()

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", _frozen_raw(self.raw))

    @property
    def message_type(self) -> PushMessageType | None:
        """``msg_type`` as an enum, or None when unknown."""
        return _enum_or_none(PushMessageType, self.msg_type)

    @property
    def video_path(self) -> str | None:
        """The row's recording (``storage_path``) when it is a valid station media path
        ending in ``.zxvideo`` (:func:`is_station_media_path`), else None."""
        path = self.storage_path
        return path if is_station_media_path(path, RECORDING_SUFFIX) else None

    @property
    def started_at(self) -> datetime | None:
        """``start_time`` as an aware time, in the row's own ``time_zone`` offset.

        The station writes local time with a ``±HHMM`` offset beside it; a row without a
        valid offset is read in the host's zone (stations keep local time). An epoch
        value (seconds or milliseconds) is UTC. None when it does not parse.
        """
        return _row_time(self.start_time, self.raw.get("time_zone"))

    @property
    def ended_at(self) -> datetime | None:
        """``end_time`` as an aware time, read as :attr:`started_at`."""
        return _row_time(self.end_time, self.raw.get("time_zone"))

    @property
    def duration_s(self) -> float | None:
        """Seconds from :attr:`started_at` to :attr:`ended_at`; None when either is
        unknown or the end is before the start. Whole seconds: the row stores no
        fractions."""
        start, end = self.started_at, self.ended_at
        if start is None or end is None or end < start:
            return None
        return (end - start).total_seconds()

    @property
    def frame_count(self) -> int | None:
        """The recording's video frames as the row counts them (``frame_num``); a
        finished clip's playback delivers exactly this many. None when absent."""
        value = coerce_int(self.raw.get("frame_num"))
        return value if value is not None and value >= 0 else None

    @property
    def size_bytes(self) -> int | None:
        """The recording's size on the station's disk (``folder_size``); None when absent."""
        value = coerce_int(self.raw.get("folder_size"))
        return value if value is not None and value >= 0 else None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> HistoryRecord:
        """Parse one ``history_record_info`` row, unpacking its ``str_extra`` JSON."""
        extra: Mapping[str, Any] = {}
        raw_extra = row.get("str_extra")
        if isinstance(raw_extra, str) and raw_extra:
            try:
                parsed = json.loads(raw_extra)
            except ValueError:
                parsed = None
            if isinstance(parsed, Mapping):
                extra = parsed
        return cls(
            record_id=coerce_int(row.get("record_id")) or 0,
            device_sn=coerce_str(row.get("device_sn")),
            station_sn=coerce_str(row.get("station_sn")),
            start_time=coerce_str(row.get("start_time")),
            end_time=coerce_str(row.get("end_time")),
            storage_type=coerce_int(row.get("storage_type")),
            thumb_path=coerce_str(row.get("thumb_path")),
            storage_path=coerce_str(row.get("storage_path")),
            msg_type=coerce_int(extra.get("msg_type")),
            arm_mode=coerce_int(extra.get("arm_mode")),
            user_name=coerce_str(extra.get("user_name")),
            raw=row,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardModeChanged:
    """A station's guard mode changed (or was first observed).

    A station has two modes. ``mode`` is the **selected** mode (param 1224, the cloud
    push's ``arming``): what the user chose, :attr:`GuardMode.SCHEDULE` while a schedule
    runs. ``active_mode`` is the **effective** mode (param 1151, the ``0x047F`` report,
    the cloud push's ``mode``): the mode in force, which is the schedule slot's mode
    while Schedule is selected and equals ``mode`` otherwise; None while unknown.
    Emitted once when either value changes.
    """

    station_sn: str
    mode: GuardMode | int
    source: EventSource
    active_mode: GuardMode | int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AlarmChanged:
    """A station's alarm started or ended.

    Emitted on transitions only, per station. Over P2P from the station's alarm-tone
    frame (``0x04B1``, param 1201): ``[event_type, seconds]`` on the triggering camera's
    channel starts it, ``[0, 0]`` ends it (the tone timed out, or a disarm), ``[16, 0]``
    on the station's channel ends it from the app. Over the cloud from an ALARM push
    (``msg_type`` 10): ``alarm_type`` 3 or 25 starts it, an authenticated 15/16/17
    ends it. :class:`~.client.EufySecurity` passes both channels through one
    :class:`AlarmTracker`, so an alarm seen on both is one start and one end, and a
    change of guard mode to a disarmed mode ends an alarm too.

    ``channel`` is the frame's or push's channel (255 = the station), ``event_type``
    the tone's event type or the push's ``alarm_type`` (3 = the HomeBase alarm, 25 =
    the camera siren, or the stop code), ``duration_s`` the tone's length (P2P only),
    ``stop_source`` who ended it when known (never for a timeout or a disarm).
    """

    station_sn: str
    alarming: bool
    source: EventSource
    channel: int | None = None
    event_type: int | None = None
    duration_s: int | None = None
    stop_source: AlarmStopSource | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ParamChanged:
    """One station/sub-device parameter changed between two parameter dumps.

    ``channel`` is the parameter's ``dev_type``: 255 is the station itself, other
    values are paired sub-devices.
    """

    station_sn: str
    channel: int
    param_id: int
    old: str | None
    new: str | None


class DisconnectCause(StrEnum):
    """Why a station session is down (see :class:`ConnectionChanged`)."""

    UNREACHABLE = "unreachable"
    """No discovery or handshake reply, or no local socket to reach the station with
    (including the local socket closing under an open session)."""
    KEY_REJECTED = "key_rejected"
    """The session key did not unwrap with the cipher key (``HandshakeError``), or a
    re-fetched key was rejected too (``KeyRejectedError``)."""
    PROBE_UNANSWERED = "probe_unanswered"
    """The link came up but the parameter probe went unanswered."""
    STATION_CLOSED = "station_closed"
    """The station sent a PPPP ``CLOSE``: it ended the session. A HomeBase ends a
    session of its own accord when a new one takes it over its session limit
    (:data:`~.p2p.session.STATION_SESSION_LIMIT` across all clients) or when it
    reboots."""
    LINK_SILENT = "link_silent"
    """No datagram from the station for 15 s on an open session: the station, or the
    network between, went quiet without a ``CLOSE``."""
    CREDENTIALS_UNAVAILABLE = "credentials_unavailable"
    """The credential provider failed (a cloud error: throttled, logged out …)."""
    CLOSED = "closed"
    """The library's own ``async_close``."""
    IDLE = "idle"
    """A station reached on demand, left idle: the session's idle close, or the station falling
    asleep with nothing in flight (a T8170 goes quiet about 7 s after its last
    command). Not an outage."""
    PROTOCOL = "protocol"
    """Any other library error."""

    @classmethod
    def for_error(cls, error: EufySecurityError) -> DisconnectCause:
        """The cause a connection failure maps to; never None (``PROTOCOL`` catches all)."""
        if isinstance(error, HandshakeError):
            return cls.KEY_REJECTED
        if isinstance(error, CloudError):
            return cls.CREDENTIALS_UNAVAILABLE
        if isinstance(error, DeviceTimeoutError):
            return cls.PROBE_UNANSWERED
        if isinstance(error, CommunicationError):
            return cls.UNREACHABLE
        return cls.PROTOCOL


@dataclass(frozen=True, slots=True, kw_only=True)
class ConnectionChanged:
    """A station session came up, went down, or failed to come up.

    ``connected=False`` is emitted when an announced connection ends, and also when a
    first connect or a reconnect fails — at most once per distinct
    ``(cause, type(error))`` per outage, an outage lasting until the next
    ``connected=True``. ``cause`` is None only when connected. ``error`` is the
    failure (secret-free, like every library error) and is ignored by equality. On
    sessions built by :class:`~.client.EufySecurity`, a cloud error that
    :meth:`CloudProblem.covers` is delivered as a :class:`CloudProblem` instead, and
    ``error`` is None.
    """

    station_sn: str
    connected: bool
    reason: str = ""
    cause: DisconnectCause | None = None
    error: EufySecurityError | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudProblem:
    """A background cloud call failed: a credential refresh or the push-token upload.

    Emitted by :class:`~.client.EufySecurity` once per error type until the next
    successful cloud call or login (a key fetch, a token upload, ``async_login``,
    ``async_reauthenticate``). ``station_sn`` names the station whose credential
    refresh hit it; None for the push listener. The error is account-level, so it is
    delivered here only: the station's ``ConnectionChanged`` carries just the cause
    (``CREDENTIALS_UNAVAILABLE``, ``error=None``). The library's own cipher-refresh
    cooldown (:class:`~.exceptions.RefreshCooldownError`) is not a cloud problem and
    stays on ``ConnectionChanged.error``.
    """

    error: CloudError
    station_sn: str | None = None

    @staticmethod
    def covers(error: object) -> bool:
        """Whether ``error`` is reported as a :class:`CloudProblem`."""
        return isinstance(error, CloudError) and not isinstance(error, RefreshCooldownError)


@dataclass(frozen=True, slots=True, kw_only=True)
class PushChanged:
    """The cloud push listener started or stopped listening.

    ``running`` means the FCM client is listening (connected and registered). The
    listener never gives up: after it stops listening it retries with a capped
    back-off, and ``running=False`` stands until it listens again. Emitted by
    :class:`~.client.EufySecurity` on every change of ``running`` (a failed first start
    included, and ``async_close``), not once per retry; while not running, a failure of
    a new error type is emitted again. ``error`` is the failure (None for a clean stop)
    and is ignored by equality. As on :class:`ConnectionChanged`, a cloud error that
    :meth:`CloudProblem.covers` is delivered as a :class:`CloudProblem` instead, and
    ``error`` is None: ``EufySecurity.push_error`` always holds the last failure.
    """

    running: bool
    error: EufySecurityError | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialsRefreshed:
    """A station's credentials were re-fetched after its session key would not unwrap.

    At most one automatic refresh per station until a handshake succeeds, the slow
    retry window passes, or the latch is released (``async_reset_key_refresh``).
    """

    station_sn: str
    cipher: bool
    """The cipher key was fetched."""
    owner_id: bool
    """The owner id (device list) was re-read."""
    login: bool
    """The refresh cost a login."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AccountMismatch:
    """A station stamps its records with an account id other than the one the session sends.

    The station silently drops a command whose ``account_id`` it does not recognise,
    so arming and still fetches may fail without a rejection. Emitted by the station
    session at most once per connection, only from an authenticated (GCM) push whose
    ``rec_content[].account`` ids all differ (case-insensitively) from the session's.
    The observed id is never exposed, logged in clear or adopted: re-check which
    account serves the station (the owner's id is ``member.admin_user_id``).
    """

    station_sn: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DevicesChanged:
    """The cloud device list changed the devices paired to a station already built.

    Emitted by a discovery (:meth:`~.client.EufySecurity.async_discover`) that updated
    the station's paired devices in place, only when something changed. Each field
    holds serials, sorted: ``added`` and ``removed`` against the previous list,
    ``moved`` for a serial whose channel changed. A consumer that keys entities by
    serial reloads on this event rather than diffing the lists itself.
    """

    station_sn: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    moved: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class StationStateChanged:
    """A completed parameter dump changed a station's built state.

    Emitted by :class:`~.station.Station` (not the session) once per completed dump,
    pushed or read, whose :attr:`~.station.Station.state` differs from the last one
    it emitted; a dump that changes nothing emits nothing. ``state`` is the whole
    snapshot, so a consumer replaces its data instead of patching per
    :class:`ParamChanged`.
    """

    station_sn: str
    state: StationState


@dataclass(frozen=True, slots=True, kw_only=True)
class StorageChanged:
    """A station's storage record (disk and eMMC figures) changed.

    Emitted by the station's session for every ``1307`` / ``11001`` record whose parsed
    value differs from the last one it saw, the first included: the answer to
    :meth:`~.station.Station.async_get_storage`, another client's query (the station
    answers every session), and the record the station pushes when a format finishes.
    ``storage`` is the whole record.
    """

    station_sn: str
    storage: StorageInfo


@dataclass(frozen=True, slots=True, kw_only=True)
class CameraBusyChanged:
    """A camera started or finished a capture that holds it (a live or preset image).

    Emitted by :class:`~.station.Station`. While ``busy``, another capture on the same
    camera raises :class:`~.exceptions.DeviceBusyError` (the same capture, live or the
    same preset, joins it).
    """

    station_sn: str
    device_sn: str
    busy: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class PresetsChanged:
    """A pan/tilt camera's preset slots differ from the ones the station last knew.

    Emitted by :class:`~.station.Station` whenever a preset query (explicit, or taken
    while the camera was awake anyway) returns other slots than the cached ones, the
    first read included. ``presets`` is every slot, enabled or not.
    """

    station_sn: str
    device_sn: str
    presets: tuple[PresetPosition, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ZoomChanged:
    """A camera reported another picture zoom than the station last knew.

    Emitted by :class:`~.station.Station` for each 6203 report whose zoom differs, the
    first included: the echo of :meth:`~.station.Station.async_set_zoom`, and the report
    the camera sends after a go-to or a live open. ``zoom`` is the factor, 1.0 for 1x.
    """

    station_sn: str
    device_sn: str
    zoom: float


# ── guard-mode ordering ──────────────────────────────────────────────────────

#: A guard-mode push whose event time is older than this is a redelivery, not news:
#: applying it would move the reported mode backwards.
GUARD_PUSH_MAX_AGE_SECONDS: Final = 300
#: A live guard-mode report stamps its station this long before it was received, so
#: the push announcing the same change (whole seconds, another clock, about 1 s after
#: the report) still passes, while a push about an earlier change cannot undo it.
GUARD_REPORT_SLACK_SECONDS: Final = 30


def as_guard_mode(code: int) -> GuardMode | int:
    """A guard-mode code as a :class:`GuardMode`, or the plain int when it is unknown."""
    try:
        return GuardMode(code)
    except ValueError:
        return code


class GuardModeTracker:
    """The one guard-mode ordering rule, per station, for both channels.

    :class:`~.client.EufySecurity` holds one for the account and passes every guard
    mode through it, whichever channel carried it:

    * a **push** (a :class:`SecurityEvent` with ``guard_mode``: a cloud arming push, or
      a P2P one, which the station does not send) is stale, and :meth:`admit_push`
      False, when its event time is more than :data:`GUARD_PUSH_MAX_AGE_SECONDS` old,
      or earlier (compared in whole seconds, as cloud times are) than the station's
      stamp. An admitted push moves the stamp to its event time. A push without an
      event time is admitted;
    * a **report** (the station's own state over P2P: a ``0x047F`` report, a
      parameter dump, an arm's read-back) is never stale. :meth:`note_report` moves the
      stamp to its receipt minus :data:`GUARD_REPORT_SLACK_SECONDS`, so a late push
      about an earlier change cannot move the mode back;
    * :meth:`changed` says whether the pair of selected and effective mode differs
      from the last pair passed for the station, so the same change arriving on both
      channels is one change.

    Stamps only ever move forward. :attr:`stamps` is what to persist and :meth:`load`
    merges it back; the last modes live only as long as this object.
    """

    def __init__(self, *, now_ms: Callable[[], int] = wall_ms) -> None:
        self._now_ms = now_ms
        self._stamps: dict[str, int] = {}
        self._modes: dict[str, tuple[GuardMode | int, GuardMode | int | None]] = {}

    @property
    def stamps(self) -> dict[str, int]:
        """A copy of station serial → the latest guard-mode time applied (epoch ms)."""
        return dict(self._stamps)

    def load(self, stored: object) -> None:
        """Merge persisted :attr:`stamps`; the later stamp wins, malformed entries are skipped."""
        if not isinstance(stored, Mapping):
            return
        for serial, ms in stored.items():
            if isinstance(serial, str) and isinstance(ms, int) and not isinstance(ms, bool):
                self._advance(serial, ms)

    def admit_push(self, event: SecurityEvent) -> bool:
        """Whether a guard-mode push is fresh enough to apply (see the class docstring)."""
        if event.guard_mode is None or event.event_time_ms is None:
            return True
        age_ms = self._now_ms() - event.event_time_ms
        if age_ms > GUARD_PUSH_MAX_AGE_SECONDS * 1000:
            _LOGGER.debug("dropping a %s guard-mode push %.0fs old", event.source, age_ms / 1000)
            return False
        if event.station_sn is None:
            return True
        last = self._stamps.get(event.station_sn)
        if last is not None and event.event_time_ms // 1000 < last // 1000:
            _LOGGER.debug(
                "dropping a %s guard-mode push older than the last mode applied", event.source
            )
            return False
        self._advance(event.station_sn, event.event_time_ms)
        return True

    def note_report(self, station_sn: str) -> None:
        """The station reported its guard mode just now: order later pushes after it."""
        self._advance(station_sn, self._now_ms() - GUARD_REPORT_SLACK_SECONDS * 1000)

    def changed(
        self, station_sn: str, mode: GuardMode | int, active_mode: GuardMode | int | None
    ) -> bool:
        """Record the selected ``mode`` and the effective ``active_mode`` for the station;
        False when that pair is the one already recorded."""
        pair = (mode, active_mode)
        if self._modes.get(station_sn) == pair:
            return False
        self._modes[station_sn] = pair
        return True

    def active_mode(
        self, station_sn: str, mode: GuardMode | int, pushed: int | None
    ) -> GuardMode | int | None:
        """The effective mode that goes with the selected ``mode`` of a push.

        ``pushed`` is the push's own ``mode`` field and wins. Without one, the effective
        mode is ``mode`` itself outside Schedule, and the last one recorded for the
        station while Schedule is selected.
        """
        if pushed is not None:
            return as_guard_mode(pushed)
        if mode != GuardMode.SCHEDULE:
            return mode
        last = self._modes.get(station_sn)
        return None if last is None else last[1]

    def _advance(self, station_sn: str, ms: int) -> None:
        self._stamps[station_sn] = max(ms, self._stamps.get(station_sn, ms))


# ── alarm lifecycle ───────────────────────────────────────────────────────────

#: An alarm push older than this is a redelivery: an alarm tone lasts 30 s.
ALARM_PUSH_MAX_AGE_SECONDS: Final = GUARD_PUSH_MAX_AGE_SECONDS


class AlarmTracker:
    """The one alarm state per station, for both channels.

    :class:`~.client.EufySecurity` holds one for the account:

    * :meth:`report` takes an :class:`AlarmChanged` from a station session (the
      station's own frames, authenticated): applied at once, stamped with the host
      clock;
    * :meth:`push` turns an ALARM push into an :class:`AlarmChanged`, or None. A push
      that is unauthenticated, older than :data:`ALARM_PUSH_MAX_AGE_SECONDS`, or older
      than the station's last transition (a late trigger after the alarm ended) is
      ignored, and so is one that repeats the state already known;
    * :meth:`disarmed` ends an alarm when the guard mode changes to a disarmed mode.

    Only transitions return True / an event. A cloud-only alarm that times out sends
    no push, so it stays on until a stop push or a disarm.
    """

    def __init__(self, *, now_ms: Callable[[], int] = wall_ms) -> None:
        self._now_ms = now_ms
        self._alarming: dict[str, bool] = {}
        self._stamps: dict[str, int] = {}

    def alarming(self, station_sn: str) -> bool:
        """Whether the station's alarm is on, as far as this tracker knows."""
        return self._alarming.get(station_sn, False)

    def report(self, change: AlarmChanged) -> bool:
        """Apply a transition the station reported; False when it is the known state."""
        return self._apply(change.station_sn, change.alarming, self._now_ms())

    def push(self, event: SecurityEvent) -> AlarmChanged | None:
        """The transition an alarm push makes, or None (see the class docstring)."""
        phase = event.alarm_phase
        station_sn = event.station_sn
        if (
            event.message_type is not PushMessageType.ALARM
            or phase not in (AlarmPhase.TRIGGERED, AlarmPhase.STOPPED)
            or station_sn is None
            or not event.authenticated
        ):
            return None
        now = self._now_ms()
        at = now if event.event_time_ms is None else event.event_time_ms
        last = self._stamps.get(station_sn)
        if now - at > ALARM_PUSH_MAX_AGE_SECONDS * 1000 or (last is not None and at < last):
            _LOGGER.debug("dropping a %s alarm push older than the alarm state", event.source)
            return None
        alarming = phase is AlarmPhase.TRIGGERED
        if not self._apply(station_sn, alarming, at):
            return None
        return AlarmChanged(
            station_sn=station_sn,
            alarming=alarming,
            source=event.source,
            channel=event.channel,
            event_type=event.alarm_type,
            stop_source=None if alarming else _enum_or_none(AlarmStopSource, event.alarm_type),
        )

    def disarmed(self, station_sn: str, source: EventSource) -> AlarmChanged | None:
        """End the station's alarm on a disarm; None when none was on."""
        if not self._apply(station_sn, False, self._now_ms()):
            return None
        return AlarmChanged(station_sn=station_sn, alarming=False, source=source)

    def _apply(self, station_sn: str, alarming: bool, at_ms: int) -> bool:
        if self.alarming(station_sn) == alarming:
            return False
        self._alarming[station_sn] = alarming
        self._stamps[station_sn] = max(at_ms, self._stamps.get(station_sn, at_ms))
        return True


@dataclass(slots=True)
class _Occurrence:
    first_seen: float
    media: frozenset[str]


def _moment_key(event: SecurityEvent) -> str | None:
    """Device, event time in ms and event type: what the copies of one detection share
    when their ``unique_id`` differs. None without a device or a time."""
    if event.device_sn is None or event.event_time_ms is None:
        return None
    event_type = "" if event.event_type is None else event.event_type
    return f"moment:{event.device_sn}:{event.event_time_ms}:{event_type}"


class EventDeduplicator:
    """Admits each real :class:`SecurityEvent` occurrence once, across channels.

    The key is :attr:`SecurityEvent.dedupe_key` (the payload's ``unique_id``, else
    device, event second and event type).
    A bounded ring remembers keys for ``max_age`` seconds of ``clock``, at most
    ``max_entries`` of them (oldest forgotten first); it lives as long as this object,
    so it survives session reconnects. Rules, in order:

    * a station-scope event (arming, alarm, alarm delay: a stop may reuse its alarm's
      time) or one without a key is always admitted and not remembered;
    * a ``push_count > 1`` copy whose key is new but whose device, event time (ms) and
      event type match a remembered occurrence is that occurrence: a standalone T8170
      sends a second push per detection with its own ``unique_id`` and the recording
      path, at the first push's ``trigger_time``;
    * a key not seen (or forgotten) is admitted — a ``push_count > 1`` repeat too, as
      its first copy may have been lost while a channel was down;
    * a seen key whose copy carries media paths (:data:`MEDIA_PATH_FIELDS`) none of the
      earlier copies had is admitted as an **enrichment**, with
      :attr:`SecurityEvent.enriches` True: the typical case is the P2P copy, with
      ``thumb_path`` / ``crop_path``, arriving after the cloud copy;
    * anything else is dropped, counted in :attr:`dropped_repeats` when
      ``push_count > 1`` and in :attr:`dropped_duplicates` otherwise.
    """

    def __init__(
        self,
        *,
        max_entries: int = 256,
        max_age: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1 or not max_age > 0:
            raise ValueError("max_entries and max_age must be positive")
        self._max_entries = max_entries
        self._max_age = max_age
        self._clock = clock
        self._seen: OrderedDict[str, _Occurrence] = OrderedDict()
        self._dropped_repeats = 0
        self._dropped_duplicates = 0

    @property
    def dropped_repeats(self) -> int:
        """Copies dropped that the station marked as re-announcements (``push_count > 1``)."""
        return self._dropped_repeats

    @property
    def dropped_duplicates(self) -> int:
        """Other copies dropped (the second channel's copy, a redelivery)."""
        return self._dropped_duplicates

    def admit(self, event: SecurityEvent) -> SecurityEvent | None:
        """The event to deliver (``event``, or its enrichment copy), or None to drop it."""
        key = event.dedupe_key
        if key is None or event.scope is EventScope.STATION:
            return event
        now = self._clock()
        while self._seen:
            oldest = next(iter(self._seen.values()))
            if now - oldest.first_seen < self._max_age:
                break
            self._seen.popitem(last=False)
        media = event.media_paths
        seen = self._seen.get(key)
        moment = _moment_key(event)
        if seen is None and moment is not None and (event.push_count or 0) > 1:
            seen = self._seen.get(moment)
            if seen is not None:
                self._seen[key] = seen  # later copies under this key are the same occurrence
        if seen is None:
            occurrence = _Occurrence(now, media)
            self._seen[key] = occurrence
            if moment is not None and moment != key:
                self._seen[moment] = occurrence
            while len(self._seen) > self._max_entries:
                self._seen.popitem(last=False)
            return event
        if not media <= seen.media:
            seen.media |= media
            _LOGGER.debug("admitting a %s copy as an enrichment (new media path)", event.source)
            return replace(event, enriches=True)
        if event.push_count is not None and event.push_count > 1:
            self._dropped_repeats += 1
            reason = "repeat"
        else:
            self._dropped_duplicates += 1
            reason = "duplicate"
        _LOGGER.debug(
            "dropping a %s copy of %s:%s from %s: %s, seen %.1fs ago",
            event.source,
            event.msg_type,
            event.event_type,
            redact_serial(event.device_sn),
            reason,
            now - seen.first_seen,
        )
        return None


type Event = (
    SecurityEvent
    | GuardModeChanged
    | AlarmChanged
    | ParamChanged
    | ConnectionChanged
    | CloudProblem
    | PushChanged
    | CredentialsRefreshed
    | AccountMismatch
    | DevicesChanged
    | StationStateChanged
    | StorageChanged
    | CameraBusyChanged
    | PresetsChanged
    | ZoomChanged
)
type EventCallback = Callable[[Event], None]
type Unsubscribe = Callable[[], None]


class _Subscription:
    """One ``subscribe`` call. Identity, not the callback, is what unsubscribes."""

    __slots__ = ("active", "callback")

    def __init__(self, callback: EventCallback) -> None:
        self.callback = callback
        self.active = True


class EventBus:
    """Minimal synchronous fan-out. A failing subscriber is logged, never propagated.

    Every :meth:`subscribe` is its own subscription, even for a callable that is
    already subscribed; its unsubscribe removes only that one and is idempotent. A
    subscription removed while an event is being emitted does not receive it.
    """

    def __init__(self) -> None:
        self._subscriptions: list[_Subscription] = []

    def subscribe(self, callback: EventCallback) -> Unsubscribe:
        sub = _Subscription(callback)
        # Copy-on-write: an emit in progress keeps iterating its own snapshot.
        self._subscriptions = [*self._subscriptions, sub]

        def unsubscribe() -> None:
            if not sub.active:
                return
            sub.active = False
            self._subscriptions = [s for s in self._subscriptions if s is not sub]

        return unsubscribe

    def emit(self, event: Event) -> None:
        for sub in self._subscriptions:
            if not sub.active:
                continue
            try:
                sub.callback(event)
            except Exception:
                _LOGGER.exception("event subscriber %r failed", sub.callback)
