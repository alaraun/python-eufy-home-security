"""High-level API for one station and the devices paired to it."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import logging
import time
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, Final, Literal, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ._logging import LogThrottle, redact_serial
from .cloud.models import CloudDevice
from .devices.capabilities import (
    Capability,
    DeviceProfile,
    kind_from_params,
    profile_for_serial,
)
from .devices.model_settings import (
    Setting,
    SettingKind,
    Value,
    WireCommand,
    WriteContext,
    WritePath,
    mode_table_settings,
    product_code_of,
    settings_of,
)
from .devices.recipes import (
    MAX_PRESET_SLOTS,
    MAX_ZOOM,
    MIN_ZOOM,
    PanTilt,
    PresetPosition,
    Recipe,
    RecipeCommand,
    SubCommand,
    delete_preset,
    free_preset_slot,
    goto_preset,
    pan_tilt,
    parse_preset_positions,
    preset_picture,
    query_preset_positions,
    reported_zoom,
    set_default_preset,
    set_picture_zoom,
    store_preset,
)
from .devices.settings import (
    DUAL_VIEW,
    VIEW_MODE_PARAM,
    Scope,
    SettingDef,
    mode_action_key,
    mode_table_setting,
    report_value,
    scope_for_kind,
)
from .devices.support import Evidence, Support
from .devices.types import DeviceKind, DeviceModel, model_for_serial
from .events import (
    RECORDING_SUFFIX,
    STILL_SUFFIX,
    CameraBusyChanged,
    ConnectionChanged,
    DevicesChanged,
    Event,
    EventBus,
    EventCallback,
    HistoryRecord,
    PresetsChanged,
    SecurityEvent,
    StationStateChanged,
    Unsubscribe,
    ZoomChanged,
    is_station_media_path,
)
from .exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    EufySecurityError,
    PresetSlotsFullError,
    RecordNotFoundError,
    StillNotWrittenError,
    UnsupportedError,
)
from .images import (
    HEVC_CONTENT_TYPE,
    JPEG_CONTENT_TYPE,
    CameraImage,
    ImageSource,
)
from .models import (
    DEV_STATUS_ONLINE,
    NOT_CHARGING_SOURCES,
    PARAM_BATTERY,
    PARAM_BATTERY_TEMPERATURE,
    PARAM_DETECTED_EVENTS,
    PARAM_DEV_STATUS,
    PARAM_DEVICE_NAME,
    PARAM_EMMC_USED_PERCENT,
    PARAM_FIRMWARE,
    PARAM_HUB_NAME,
    PARAM_LAN_IP,
    PARAM_PIR_EVENT_MS,
    PARAM_POWER_SOURCE,
    PARAM_RECORDED_EVENTS,
    PARAM_SD_INFO,
    PARAM_SENSOR_LOW_BATTERY,
    PARAM_SENSOR_PIR_SENSITIVITY,
    PARAM_SOLAR_INTENSITY,
    PARAM_STORAGE_STATUS,
    PARAM_SUB1G_RSSI,
    PARAM_WIFI_RSSI,
    PARAM_WORKING_DAYS,
    SIREN_ACTION_PARAMS,
    SOLAR_SOURCES,
    STATION_CHANNEL,
    STORAGE_STATUS_NORMAL,
    SUBSYSTEM_FIRMWARE_PARAMS,
    FrameCipher,
    GuardMode,
)
from .network import LanPath, lan_path_for
from .p2p import session as p2p_session
from .p2p._json import json_int
from .p2p.clip import ClipWriter, MediaClip
from .p2p.encoder import SETTLE_STANDALONE, SETTLE_STATION
from .p2p.media import MediaFrame, Still
from .p2p.messages import decode_preset_picture, record_id_day
from .p2p.mode_actions import MODE_TABLE_PARAMS, ModeTableField, mode_table_from_params
from .p2p.params import (
    ACTIVE_MODE_PARAM,
    GUARD_MODE_PARAM,
    SUB_DEVICE_SERIALS_PARAM,
    ParamDump,
    standalone_aliases,
)
from .p2p.session import (
    CommandOutcome,
    MediaStream,
    RecipeReply,
    SessionStats,
    StationSession,
)
from .p2p.storage_info import StorageInfo

if TYPE_CHECKING:
    from .storage import SessionCache

_LOGGER = logging.getLogger(__name__)

READBACK_ATTEMPTS = 3
READBACK_DELAY = 0.8

CAMERA_IMAGE_DAYS = 7
"""Days of history :meth:`Station.async_camera_image` searches for a camera's newest event."""
RECORDINGS_DAYS = 2
"""Days :meth:`Station.async_list_recordings` covers by default: today and yesterday."""
RECORDING_QUIET = 30.0
"""Seconds past a history row's end time before :meth:`Station.recording_settled` calls its
clip finished (clips of 6 to 37 s seen; a detection's row exists while it records)."""
STANDALONE_STILL_WINDOW: Final = (-2.0, 30.0)
"""Seconds a standalone device's newest still may lie before and after a detection's time
to be that detection's (its file name is the device's local second)."""
PRESET_SETTLE_SECONDS: Final = 7.0
"""How long a preset image streams after the turn before its keyframe is kept: a T8170
reports its zoom about 2 s after the turn and stands still within 7 s."""
DEFAULT_PRESET_RESULT_WAIT: Final = 1.0
"""How long the default-preset write (6242) waits for a result after its receipt: a
T8170 receipts it within 0.1 s and never sends one, so the read-back confirms it."""
PRESET_STREAM_IDLE_SECONDS: Final = 12.0
"""A preset image's stream may stay quiet this long: a T8170 can send no frame for more
than 3 s while turning between distant presets, which the default idle timeout would
take for the end of the stream."""
PTZ_SETTLE_SECONDS: Final = 1.5
"""How long a one-step pan/tilt (6030) takes to finish: a T8170's view moves for about
0.7 s, ending about 1.0 s after the send. A step sent 1.0 s after the previous one moves
a full step; one sent 0.5 s after it shortens the pair."""
PTZ_BUSY_CODE: Final = 1
"""The receipt code a moving camera answers a preset command with (it is busy, not broken)."""
PTZ_BUSY_ATTEMPTS: Final = 4
"""How often a preset command is re-sent while the camera answers :data:`PTZ_BUSY_CODE`."""
PTZ_BUSY_DELAY: Final = 3.0
"""Wait between those attempts: a T8170 settles within a few seconds of a turn."""
FRESH_KEYFRAME_WINDOW: Final = 0.5
"""After a live stream's first keyframe, wait this long for a second one and prefer it:
a T8170 woken again may first replay its last keyframe of the previous stream (minutes
old) and follow it with a fresh one about 0.2 s later."""
FULL_RESOLUTION_TIMEOUT: Final = 30.0
"""Seconds after the first keyframe a ``full_resolution`` live image waits at most for the
picture size to hold: a woken T8170 climbs 1280x720 -> 1920x1080 -> 2880x1616 at about
4.2, 8.4 and 12.7 s after the open."""

#: The plausible window for an epoch-ms device time: 2015-01-01 to 2100-01-01 UTC.
#: An epoch in seconds (10 digits) falls below it.
EPOCH_MS_RANGE = (1_420_070_400_000, 4_102_444_800_000)

type SerialSource = Literal["cloud", "param_1072"]

SUB_DEVICE_SERIALS_ORDER_EVIDENCE: Final = Evidence(
    Support.UNKNOWN,
    "two parameter dumps of one HomeBase 3",
    note="station param 1072 listed the two cameras in channel order both times; the "
    "motion sensor was not in it. Relied on only where cloud-known serials anchor it.",
)
"""That 1072 lists the cameras by channel: the rule behind the ``param_1072`` serial."""


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _percent_or_none(value: str | None) -> int | None:
    number = _int_or_none(value)
    return number if number is not None and 0 <= number <= 100 else None


def _count_or_none(value: str | None) -> int | None:
    number = _int_or_none(value)
    return number if number is not None and number >= 0 else None


def _flag_or_none(value: str | None) -> bool | None:
    number = _int_or_none(value)
    return None if number not in (0, 1) else number == 1


def _text_or_none(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _ip_or_none(value: str | None) -> str | None:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    return None if address.is_unspecified else str(address)


def _read(
    settings: Mapping[str, Setting], key: str, params: Mapping[int, str | None]
) -> Value | None:
    """The public value of setting ``key`` in one block's ``params``: None when the
    block does not report it or the setting is not readable; ``UnsupportedError`` for a
    key the device does not have."""
    setting = settings.get(key)
    if setting is None:
        raise UnsupportedError(f"unknown setting {key!r} for this device")
    if setting.read_param is None:
        return None
    raw = params.get(setting.read_param)
    if setting._mode_table is not None:
        return report_value(raw)
    value = setting.decode(raw)
    if value is None and raw is not None and not raw.lstrip("-").isdigit():
        quality = report_value(raw, params.get(VIEW_MODE_PARAM))
        if quality is not None:
            # A multi-view camera reports base64 JSON with one quality per view; the
            # app caches the current view's quality as base64 of its digits.
            value = setting.decode(base64.b64encode(str(quality).encode()).decode())
    return value


def _epoch_ms_or_none(value: str | None) -> int | None:
    number = _int_or_none(value)
    low, high = EPOCH_MS_RANGE
    return number if number is not None and low <= number < high else None


@dataclass(frozen=True, slots=True, kw_only=True)
class SubDeviceState:
    """A paired camera or sensor as reported in the station's parameter dump.

    The dump carries no device type: ``kind`` comes from the serial's catalogued
    model, else from marker parameters on the block (``None`` when neither says).

    ``online`` is the one field that says whether the device is still reporting:
    every other value here is the station's last-known copy, which it keeps serving
    long after the device stops answering (a sensor offline for months still reports
    its last battery and signal).
    """

    channel: int
    serial: str | None
    serial_source: SerialSource | None = None
    """Where ``serial`` came from: ``"cloud"`` (the device list's channel), or
    ``"param_1072"`` for a channel the cloud list lacks (a device paired since it was
    fetched), taken from the station's serial list only when cloud-known serials
    anchor its order (:data:`SUB_DEVICE_SERIALS_ORDER_EVIDENCE`). None with no serial,
    including a channel two cloud devices claim."""
    kind: DeviceKind | None = None
    name: str | None
    battery: int | None
    wifi_rssi: int | None = None
    """Wi-Fi signal in dBm (param 1142), reported by cameras."""
    sub1g_rssi: int | None = None
    """Sub-1 GHz signal in dBm (param 1141), the motion sensor's only signal; None
    when a Wi-Fi value is present and this one is 0 (not applicable)."""
    firmware: str | None
    pir_event_ms: int | None = None
    """Param 1605 in epoch ms, which the app names ``MOTION_SENSOR_PIR_EVT``: read
    as the time of the last PIR event (declared, not proven to move on motion). It is
    not a last-seen time. None when absent or outside :data:`EPOCH_MS_RANGE`."""
    online: bool | None = None
    """Whether the station still reaches this device (param 1131). None when the
    block omits it, which is never a default: no answer is not the same as offline.

    The station keeps serving a departed device's last block, so this is the only
    field that separates "reporting" from "remembered" — the rest stay frozen at
    their last values. The station's own reachability is not part of it: a state
    exists because a dump arrived, and a closed session is signalled by
    :class:`~.events.ConnectionChanged`."""
    offline_code: int | None = None
    """The raw 1131 value when it is above 1 — an offline reason the app shows but
    whose codes it never names, so it is passed through unmapped. None when the
    device is online, plainly offline (0), or silent about it."""
    battery_temperature: int | None = None
    """Battery temperature (param 1138, °C by its range; the handlers give no unit)."""
    working_days: int | None = None
    """Days since the battery was last charged by USB (param 1191; the app's power
    manager "Working Days")."""
    detected_events: int | None = None
    """Events detected over the same period (param 1192, app "Detected Events")."""
    recorded_events: int | None = None
    """Events recorded over the same period (param 1193, app "Recordings")."""
    power_source: int | None = None
    """The raw charging-source code (param 2111): 0 or 2 not charging, 1 USB, 3 AC,
    4 built-in solar, 5 USB and built-in solar, 6/8 external solar panel, 7/12
    external and built-in solar (the thing descriptions; the code set varies by model),
    20 a connected panel (handler ``is_connected_solar_panel``)."""
    solar_intensity: int | None = None
    """Raw solar input (param 1309); 0 with no light or no panel. Its scale is model
    specific: some models' thing descriptions band it 0-20/20-40/40-85/85-100."""
    siren_actions: Mapping[GuardMode, int] = field(default_factory=dict)
    """The raw per-mode siren action (params 1509-1513, app ``getSirenAction``), by mode;
    only the modes the block reports."""
    low_battery: bool | None = None
    """A motion sensor's low-battery flag (param 1601, handler ``sensor_is_low_power``)."""
    pir_sensitivity_raw: int | None = None
    """A motion sensor's raw PIR sensitivity (param 1609). The handler maps only 0-2
    to a level; other values (a T8910 reported 8) have no vendor meaning."""
    params: Mapping[int, str | None] = field(repr=False)
    settings: Mapping[str, Setting] = field(default_factory=dict, repr=False, compare=False)
    """This device's settings by key (:meth:`Station.settings_for`), resolved when the
    state is built."""

    @property
    def rssi(self) -> int | None:
        """The device's signal in dBm: Wi-Fi when reported, else sub-1 GHz."""
        return self.wifi_rssi if self.wifi_rssi is not None else self.sub1g_rssi

    @property
    def charging(self) -> bool | None:
        """Whether the battery is charging from any source (the handlers'
        ``charging_status``: every :attr:`power_source` but 0 and 2); None unreported."""
        if self.power_source is None:
            return None
        return self.power_source not in NOT_CHARGING_SOURCES

    @property
    def solar_charging(self) -> bool | None:
        """Whether :attr:`power_source` names a solar source (built-in or external
        panel, alone or with USB); None unreported."""
        if self.power_source is None:
            return None
        return self.power_source in SOLAR_SOURCES

    def pir_quiet_for(self, *, now_ms: int, max_age_s: float) -> bool:
        """Whether the last PIR event is older than ``max_age_s`` (opt-in, no default).

        False when there is no PIR event time. Graded *declared*: it rests on the app's
        name for param 1605, and is NOT an availability rule — a healthy sensor in a
        quiet spot has no recent PIR event.
        """
        if max_age_s < 0:
            raise ValueError("max_age_s must not be negative")
        if self.pir_event_ms is None:
            return False
        return now_ms - self.pir_event_ms > max_age_s * 1000

    def setting(self, key: str) -> Value | None:
        """The public value of setting ``key`` on this device's block (the setting's
        read codec); None when the block does not report it or the setting is not
        readable, never a default. Raises ``UnsupportedError`` for a key this device
        does not have (:attr:`settings`).
        """
        return _read(self.settings, key, self.params)


#: Parameters the library reads into :class:`StationState` itself rather than through
#: a setting, per scope. Coverage reports subtract them, so an "unread"
#: parameter means one nothing in the library reads at all.
STATE_PARAMS: Final[Mapping[Scope, frozenset[int]]] = {
    Scope.STATION: frozenset(
        {
            GUARD_MODE_PARAM,
            ACTIVE_MODE_PARAM,
            SUB_DEVICE_SERIALS_PARAM,
            PARAM_LAN_IP,
            PARAM_EMMC_USED_PERCENT,
            PARAM_HUB_NAME,
            PARAM_STORAGE_STATUS,
            PARAM_SD_INFO,
            *SUBSYSTEM_FIRMWARE_PARAMS,
        }
    ),
    Scope.SUB_DEVICE: frozenset(
        {
            PARAM_BATTERY,
            PARAM_DEV_STATUS,
            PARAM_SUB1G_RSSI,
            PARAM_WIFI_RSSI,
            PARAM_DEVICE_NAME,
            PARAM_PIR_EVENT_MS,
            PARAM_FIRMWARE,
            PARAM_BATTERY_TEMPERATURE,
            PARAM_WORKING_DAYS,
            PARAM_DETECTED_EVENTS,
            PARAM_RECORDED_EVENTS,
            PARAM_POWER_SOURCE,
            PARAM_SOLAR_INTENSITY,
            *SIREN_ACTION_PARAMS.values(),
            PARAM_SENSOR_LOW_BATTERY,
            PARAM_SENSOR_PIR_SENSITIVITY,
        }
    ),
}


@dataclass(frozen=True, slots=True, kw_only=True)
class SettingsCoverage:
    """What one block of a dump and the device's model settings say about each other.

    The model settings decide which entities a consumer offers, and they are keyed on
    the model, not on the unit at hand — so they can claim a setting this unit
    never reports. This compares the two for a single dump and names the difference
    in both directions.

    Read it as a maintenance lead, never as a capability statement. Three measured
    reasons a row here does not mean what it looks like:

    * **A parameter can exist and not be served.** The station's own block does not
      carry 1158 ``ARM_DELAY_AWAY``, although the cloud's snapshot of the same
      station has a value for it. So ``unreported`` can mean
      "this query does not return it", not "the device lacks it".
    * **Presence does not mean ownership.** The hub mirrors its alarm policy onto
      every channel: the motion sensor reports all ten ``ALARM_DELAY_*`` and
      ``LEAVING_DELAY_*`` parameters, which are the hub's to manage, not a
      capability of a PIR sensor.
    * **A block is only what the station said this time.** An offline device may
      report a short block, so ``unreported`` is a question to ask of a device known
      to be ``online``, not a verdict on its own.
    """

    channel: int
    serial: str | None
    kind: DeviceKind | None
    online: bool | None = None
    """The block's :attr:`SubDeviceState.online`; None for the station, whose
    reachability the dump itself proves."""
    has_settings: bool
    """Whether the device's model has a settings file. False means the library claims
    nothing, so ``reported`` and ``unreported`` are both empty and every parameter
    lands in ``unread``."""
    reported: tuple[str, ...]
    """Readable settings whose parameter the block carries."""
    unreported: tuple[str, ...]
    """Readable settings the block does not carry — the model claims more than this
    device showed."""
    unread: tuple[int, ...]
    """Parameters the block carries that no setting reads and :data:`STATE_PARAMS`
    does not name — what the library ignores entirely."""

    @property
    def complete(self) -> bool:
        """Whether every readable setting of the model was actually reported."""
        return not self.unreported


@dataclass(frozen=True, slots=True, kw_only=True)
class StationState:
    """One consistent snapshot of a station, taken from a single parameter dump."""

    serial: str
    guard_mode: GuardMode | int | None
    """The selected guard mode (param 1224): :attr:`GuardMode.SCHEDULE` while a schedule
    runs."""
    active_mode: GuardMode | int | None = None
    """The effective guard mode, the one in force (param 1151; ``guard_mode`` when the
    dump lacks it): a schedule slot's mode while Schedule is selected."""
    firmware: str | None
    devices: Mapping[int, SubDeviceState]
    params: Mapping[int, str | None] = field(repr=False)
    name: str | None = None
    """The hub name (param 1216), else the cloud name."""
    lan_ip: str | None = None
    """The station's LAN address (param 1176), only when it parses as an IP literal."""
    sec_firmware: str | None = None
    """The secondary firmware (dump ``sec_sw_version``, else the cloud's)."""
    emmc_used_percent: int | None = None
    """Internal eMMC storage used, 0-100 (param 1190; 0 is a real value)."""
    storage_status: int | None = None
    """The raw storage status code (param 1135, ``GET_TFCARD_STATUS``)."""
    sd_info: int | None = None
    """Param 1102 (``SDINFO``) as an integer. No vendor code decodes it; use
    :meth:`Station.async_get_storage` for disk figures."""
    subsystem_firmware: Mapping[int, str] = field(default_factory=dict)
    """The station's subsystem version strings by param id (5006-5012), as reported;
    no vendor code names the subsystems."""
    settings: Mapping[str, Setting] = field(default_factory=dict, repr=False, compare=False)
    """The station's own settings by key (:meth:`Station.settings_for`)."""
    settings_by_serial: Mapping[str, Mapping[str, Setting]] = field(
        default_factory=dict, repr=False, compare=False
    )
    """Every known device's settings (the station's own serial and each
    :attr:`Station.devices` serial), whether or not this dump has its block, so a key of
    an absent device reads ``None`` rather than raising."""
    settings_by_channel: Mapping[int, Mapping[str, Setting]] = field(
        default_factory=dict, repr=False, compare=False
    )
    """The same settings by the channel the cloud lists each device on."""

    @property
    def storage_ok(self) -> bool | None:
        """Whether :attr:`storage_status` is a code the handlers show as normal
        (0, 25, 30); None unreported."""
        if self.storage_status is None:
            return None
        return self.storage_status in STORAGE_STATUS_NORMAL

    def coverage(self) -> tuple[SettingsCoverage, ...]:
        """How this dump lines up with the model settings, station first, then each channel.

        The settings are keyed on the model, so they can claim a value a given unit
        never reports; this says where that happened, and which parameters the device
        reports that the library reads nowhere. It is a maintenance view, not a rule
        for building entities: a consumer that dropped an entity whenever a block
        omitted its parameter would make entities come and go with the dump.
        """
        station = SettingsCoverage(
            channel=STATION_CHANNEL,
            serial=self.serial,
            kind=None,
            **_coverage_of(Scope.STATION, self.params, self.settings),
        )
        return (
            station,
            *(
                SettingsCoverage(
                    channel=channel,
                    serial=d.serial,
                    kind=d.kind,
                    online=d.online,
                    **_coverage_of(Scope.SUB_DEVICE, d.params, d.settings),
                )
                for channel, d in sorted(self.devices.items())
            ),
        )

    def setting(
        self, key: str, *, device_sn: str | None = None, channel: int | None = None
    ) -> Value | None:
        """The public value of setting ``key``: the station's own (no target, or channel
        255) or a paired device's, by its cloud serial or its channel.

        None when the param, or the device's whole block, is absent from this
        snapshot, or the setting is not readable — never a default. Raises
        ``UnsupportedError`` for a key the addressed device does not have (an unknown
        device has none), and ``ValueError`` when both targets are given.
        """
        if device_sn is not None and channel is not None:
            raise ValueError("pass at most one of device_sn or channel")
        if device_sn is None and channel in (None, STATION_CHANNEL):
            return _read(self.settings, key, self.params)
        if device_sn is not None:
            device = next((d for d in self.devices.values() if d.serial == device_sn), None)
            settings = self.settings_by_serial.get(device_sn, {})
        else:
            device = self.devices.get(cast(int, channel))
            settings = self.settings_by_channel.get(cast(int, channel), {})
        if device is not None:
            return device.setting(key)
        return _read(settings, key, {})


def _coverage_of(
    scope: Scope, params: Mapping[int, str | None], settings: Mapping[str, Setting]
) -> dict[str, Any]:
    """The :class:`SettingsCoverage` fields one block and its device's settings give."""
    reported: list[str] = []
    unreported: list[str] = []
    read_params: set[int] = set()
    for key, setting in settings.items():
        if setting.read_param is None:
            continue
        read_params.add(setting.read_param)
        (reported if setting.read_param in params else unreported).append(key)
    return {
        "has_settings": bool(settings),
        "reported": tuple(reported),
        "unreported": tuple(unreported),
        "unread": tuple(sorted(set(params) - read_params - STATE_PARAMS[scope])),
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteStation:
    """A station included without local reach: its devices and cloud push events only.

    There is no P2P session, so no commands, settings, state dumps or media, and the
    guard mode is known only from a push after it changes. Its events arrive on
    ``EufySecurity.subscribe`` with its serial as ``station_sn``.
    """

    device: CloudDevice
    sub_devices: tuple[CloudDevice, ...] = ()

    @property
    def serial(self) -> str:
        return self.device.device_sn

    @property
    def name(self) -> str:
        return self.device.name


def device_channels(sub_devices: Sequence[CloudDevice]) -> frozenset[int]:
    """The station channels the given paired devices occupy."""
    return frozenset(d.channel for d in sub_devices if d.channel is not None)


def own_channel(device: CloudDevice) -> int | None:
    """The channel a standalone station's own block is filed under (its
    ``device_channel``, 0 when the cloud gives none); None for a hub."""
    if not device.is_standalone:
        return None
    return 0 if device.channel is None else device.channel


def station_channels(device: CloudDevice, sub_devices: Sequence[CloudDevice]) -> frozenset[int]:
    """The channels a parameter read of ``device`` waits for: its paired devices', and a
    standalone station's own."""
    own = own_channel(device)
    return device_channels(sub_devices) | (frozenset() if own is None else {own})


def station_block_aliases(device: CloudDevice) -> dict[int, tuple[int, ...]]:
    """The session's ``block_aliases`` for ``device``: a standalone station's block goes
    under 255 and its own channel (:func:`~.p2p.params.standalone_aliases`)."""
    channel = own_channel(device)
    return {} if channel is None else standalone_aliases(device.device_type, channel)


def _still_time(path: str) -> str | None:
    """The station-local time a still's file name carries (``…/20260917112324_snapshot.jpg``),
    as ``YYYY-MM-DD HH:MM:SS`` like a history row's ``start_time``; None when it has none."""
    stamp = path.rsplit("/", 1)[-1][:14]
    if len(stamp) != 14 or not stamp.isdigit():
        return None
    return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[8:10]}:{stamp[10:12]}:{stamp[12:14]}"


async def _settle(settle: float | None, default: float) -> None:
    """Wait ``settle`` seconds, or ``default`` (read at call time) when it is None."""
    seconds = default if settle is None else settle
    if seconds > 0:
        await asyncio.sleep(seconds)


async def _fresh_keyframe(stream: MediaStream) -> bytes:
    """The data of :func:`_fresh_keyframe_frame`."""
    return (await _fresh_keyframe_frame(stream)).data


async def _fresh_keyframe_frame(stream: MediaStream) -> MediaFrame:
    """The stream's first keyframe, or the next one when it follows within
    :data:`FRESH_KEYFRAME_WINDOW` (the first was then a replayed, stale one)."""
    first: MediaFrame | None = None
    async for frame in stream:
        if frame.is_keyframe:
            first = frame
            break
    if first is None:
        raise DeviceTimeoutError("the stream ended before a keyframe arrived")
    try:
        async with asyncio.timeout(FRESH_KEYFRAME_WINDOW):
            async for frame in stream:
                if frame.is_keyframe:
                    return frame
    except (TimeoutError, EufySecurityError):
        pass  # no second keyframe in time, or the stream failed after the first: keep it
    return first


async def _held_size_keyframe(stream: MediaStream, settle: float, bound: float) -> MediaFrame:
    """The largest keyframe of a stream whose picture size has stopped changing.

    Starts from :func:`_fresh_keyframe_frame` (a replayed stale keyframe is skipped).
    A size change shows on a keyframe; the walk ends once the current size has held for
    ``settle`` seconds, ``bound`` seconds after the first keyframe, or when the stream
    ends or fails. It returns the keyframe that opened the latest run of the largest
    size seen: on a woken T8170 the last rung of its climb, not a replayed keyframe of
    the same size from its previous stream.
    """
    loop = asyncio.get_running_loop()
    best = await _fresh_keyframe_frame(stream)
    run_size = (best.width, best.height)
    run_since = loop.time()
    deadline = run_since + bound

    def area(frame: MediaFrame) -> int:
        return frame.width * frame.height

    try:
        async with asyncio.timeout(min(run_since + settle, deadline)) as scope:
            async for frame in stream:
                now = loop.time()
                if now - run_since >= settle:
                    break
                if not frame.is_keyframe or (frame.width, frame.height) == run_size:
                    continue
                run_size, run_since = (frame.width, frame.height), now
                if area(frame) >= area(best):
                    best = frame
                scope.reschedule(min(run_since + settle, deadline))
    except (TimeoutError, EufySecurityError):
        pass  # the size held (no frame since), the bound ran out, or the stream failed
    return best


def _ranks(names: Sequence[str | None]) -> dict[str | None, int]:
    """Each name's first position in ``names``; None ranks after every name."""
    ranks: dict[str | None, int] = {}
    for name in names:
        if name is not None:
            ranks.setdefault(name, len(ranks))
    ranks[None] = len(ranks)
    return ranks


def _sorted_settings(settings: Mapping[str, Setting]) -> tuple[Setting, ...]:
    """``settings`` by (group, page, order, key): a group ranks where its first setting
    stands in (order, key) order, pages sort by name; settings without a group, page or
    order come after those that have one."""
    by_order = sorted(settings.values(), key=lambda s: (s.order is None, s.order or 0, s.key))
    groups = _ranks([s.group for s in by_order])
    return tuple(sorted(by_order, key=lambda s: (groups[s.group], s.page is None, s.page or "")))


def _load_settings(codes: set[str]) -> None:
    for code in codes:
        settings_of(code)


@dataclass(frozen=True, slots=True)
class _Capture:
    """The capture holding a camera: a live image (``preset`` None) or a preset image."""

    preset: int | None
    task: asyncio.Task[CameraImage]


class Station:
    """A HomeBase and its paired devices, reached over local P2P."""

    def __init__(
        self,
        device: CloudDevice,
        session: StationSession,
        *,
        sub_devices: Sequence[CloudDevice] = (),
        cache: SessionCache | None = None,
        listed_settings: Callable[[str], Sequence[Setting]] | None = None,
    ) -> None:
        """``listed_settings`` gives the read-only settings listed for a product code
        without a bundled file (the client's model scan); None lists nothing."""
        self.device = device
        self.session = session
        self.sub_devices: tuple[CloudDevice, ...] = tuple(sub_devices)
        self._cache = cache
        self._listed_settings = listed_settings
        self._log_name = redact_serial(device.device_sn)
        self._bus = EventBus()
        self._presets: dict[str, tuple[PresetPosition, ...]] = {}
        self._captures: dict[str, _Capture] = {}
        """The capture holding each camera (a live or preset image), by serial."""
        self._throttle = LogThrottle()
        self._emitted_state: StationState | None = None
        self._settings_memo: dict[tuple[str, str], tuple[Setting, ...]] = {}
        """:meth:`settings_for` per ``(serial, product code)``."""
        self._zooms: dict[str, float] = {}
        session.add_dump_listener(self._on_dump_complete)
        session.add_notify_listener(self._on_notify)
        session.subscribe(self._on_session_event)

    # ── identity ─────────────────────────────────────────────────────────────

    @property
    def serial(self) -> str:
        return self.device.device_sn

    @property
    def name(self) -> str:
        return self.device.name

    @property
    def model(self) -> DeviceModel | None:
        return self.device.model

    @property
    def profile(self) -> DeviceProfile | None:
        return profile_for_serial(self.serial)

    @property
    def lan_path(self) -> LanPath:
        """How this host reaches the station, for firewall and fixed-address advice."""
        session = self.session
        return lan_path_for(
            self.device,
            search_host=session.search_host,
            local_port=session.local_port,
            learned_host=session.host,
        )

    @property
    def is_standalone(self) -> bool:
        """Whether this station is itself the device (a standalone camera), see
        :attr:`~.cloud.models.CloudDevice.is_standalone`. Its one parameter block is
        both :attr:`StationState.params` and ``StationState.devices[own channel]``,
        whose serial is the station's own."""
        return self.device.is_standalone

    @property
    def devices(self) -> tuple[CloudDevice, ...]:
        """Every device with a channel on this station, each with its own entities: the
        paired devices, and a standalone station itself (first) on its own channel.

        Build per-device entities (battery, signal, detections, camera) from this, not
        from :attr:`sub_devices`, which a standalone camera leaves empty. For a
        standalone station the device's serial is the station's own, so skip the
        entity keys the station view already has (firmware, model).
        """
        return (self.device, *self.sub_devices) if self.is_standalone else self.sub_devices

    def sub_device(self, device_sn: str) -> CloudDevice:
        for device in self.devices:
            if device.device_sn == device_sn:
                return device
        raise UnsupportedError(f"{redact_serial(device_sn)} is not paired to {self._log_name}")

    def settings_for(self, device_sn: str | None = None) -> tuple[Setting, ...]:
        """The settings of the station (``None``, or its own serial) or of a paired
        device: its model's settings sorted by (group, page, order, key), then for a
        paired device the per-mode delays and actions of its kind
        (:func:`~.devices.model_settings.mode_table_settings`). A model the library has
        no settings file for lists the read-only settings of its cloud thing description
        when the client's model scan found one (``note`` "not in bundled data"), else
        ``()``.

        Sync and free of I/O once the model's file is loaded: :meth:`async_start`
        (:meth:`async_load_settings`) and :class:`~.client.EufySecurity` load every
        product code off the event loop. Raises ``UnsupportedError`` when ``device_sn``
        is not paired to this station.
        """
        serial = self.serial if device_sn in (None, self.serial) else device_sn
        if serial != self.serial:
            self.sub_device(serial)
        return self._settings_of(serial)

    def _settings_of(self, serial: str) -> tuple[Setting, ...]:
        """:meth:`settings_for` of ``serial``, paired or not (a dump can name a device
        the cloud does not list)."""
        code = self._product_code(serial)
        if code is None:
            return ()
        memo = self._settings_memo.get((serial, code))
        if memo is None:
            bundled = settings_of(code)
            if not bundled and self._listed_settings is not None:
                # Not memoised: a listing can arrive after the first lookup.
                return tuple(self._listed_settings(code))
            memo = _sorted_settings(bundled)
            if memo and serial != self.serial:
                model = model_for_serial(serial)
                memo += mode_table_settings(scope_for_kind(model.kind if model else None))
            self._settings_memo[(serial, code)] = memo
        return memo

    def setting(
        self, key: str, *, device_sn: str | None = None, channel: int | None = None
    ) -> Setting:
        """Setting ``key`` of the station (no target, or channel 255), of the paired
        device ``device_sn``, or of the device the cloud lists on ``channel``.

        Raises ``UnsupportedError`` for a key the addressed device does not have or a
        device that is not paired here, and ``ValueError`` when both targets are given.
        """
        serial = self._write_context(device_sn, channel).device_sn
        found = next((s for s in self.settings_for(serial) if s.key == key), None)
        if found is None:
            raise UnsupportedError(f"unknown setting {key!r} for this device")
        return found

    async def async_load_settings(self) -> None:
        """Load the settings file of the station's and every paired device's model off
        the event loop, so :meth:`settings_for` and the state never read package data."""
        codes = {self._product_code(d.device_sn) for d in (self.device, *self.sub_devices)}
        await asyncio.to_thread(_load_settings, {c for c in codes if c is not None})

    def _product_code(self, serial: str) -> str | None:
        """``serial``'s product code: the cloud's ``device_new_pn`` (canonical), else the
        serial's catalogued model; ``None`` when neither names one."""
        new_pn = next(
            (
                device.raw.get("device_new_pn")
                for device in (self.device, *self.sub_devices)
                if device.device_sn == serial
            ),
            None,
        )
        return product_code_of(new_pn, serial)

    def _settings_by_key(self, serial: str) -> Mapping[str, Setting]:
        return {s.key: s for s in self._settings_of(serial)}

    def _write_context(self, device_sn: str | None, channel: int | None) -> WriteContext:
        """The device a setting of ``device_sn`` (or the device on ``channel``) addresses.

        The station itself (no target, its own serial, or channel 255) is a standalone
        context: a hub on 255, a standalone camera on its own channel. A paired device is
        a station child on its channel. Raises ``ValueError`` when both targets are given
        and ``UnsupportedError`` for a device that is not paired here.
        """
        if device_sn is not None and channel is not None:
            raise ValueError("pass at most one of device_sn or channel")
        serial: str | None = device_sn
        if serial is None and channel not in (None, STATION_CHANNEL):
            cloud = self._cloud_by_channel().get(channel)
            if cloud is None:
                raise UnsupportedError(f"no paired device on channel {channel}")
            serial = cloud.device_sn
        if serial is None or serial == self.serial:
            own = own_channel(self.device)
            return WriteContext(
                standalone=True,
                channel=STATION_CHANNEL if own is None else own,
                device_sn=self.serial,
                station_sn=self.serial,
            )
        return WriteContext(
            standalone=False,
            channel=self.channel_for(serial),
            device_sn=serial,
            station_sn=self.serial,
        )

    async def _async_write(
        self, setting: Setting, value: object, ctx: WriteContext
    ) -> CommandOutcome:
        """Render ``value`` for ``ctx``, send it on the codec's path and, once sent, merge
        the values the write sets into the session's parameters (the next dump wins)."""
        return await self._async_send_write(setting, setting.encode(value, ctx), ctx)

    async def _async_send_write(
        self, setting: Setting, wire: WireCommand, ctx: WriteContext
    ) -> CommandOutcome:
        """Send a rendered write on its path, then merge the values it sets."""
        params = dict(wire.params) if wire.params is not None else {}
        match wire.path:
            case WritePath.ECB:
                await self.session.async_send_ecb_scalar(
                    wire.cmd, cast(int, wire.value), channel=ctx.channel
                )
                outcome = CommandOutcome.APPLIED
            case WritePath.RECIPE_1700:
                recipe = Recipe(
                    identifier=setting.key,
                    cmd=RecipeCommand.DOORBELL_PAYLOAD,
                    sub_cmd=wire.cmd,
                    params=params,
                )
                outcome = (await self.session.async_run_recipe(recipe, channel=ctx.channel)).outcome
            case WritePath.SUB_1350:
                outcome = await self.session.async_send_command(
                    wire.cmd, channel=ctx.channel, payload=params
                )
            case WritePath.STRING:
                await self.session.async_send_string_command(
                    wire.cmd, cast(str, wire.text), channel=ctx.channel
                )
                outcome = CommandOutcome.APPLIED
            case _:
                # A GCM DeviceMsgBean of the codec's own command: not observed on hardware.
                outcome = await self.session.async_send_command(
                    wire.cmd, channel=ctx.channel, payload=params
                )
        self.session.apply_local_params(ctx.channel, dict(wire.updates))
        return outcome

    def channel_for(self, device_sn: str) -> int:
        """The station slot (``device_channel``) a paired device is addressed on (a
        standalone station's own serial: its own channel)."""
        if device_sn == self.serial and (own := own_channel(self.device)) is not None:
            return own
        channel = self.sub_device(device_sn).channel
        if channel is None:
            raise UnsupportedError(f"the cloud reports no channel for {redact_serial(device_sn)}")
        return channel

    # ── lifecycle and events ─────────────────────────────────────────────────

    def subscribe(self, callback: EventCallback) -> Unsubscribe:
        """The session's events plus this station's own (:class:`~.events.DevicesChanged`,
        :class:`~.events.StationStateChanged`, :class:`~.events.CameraBusyChanged`,
        :class:`~.events.PresetsChanged`, :class:`~.events.ZoomChanged`); returns the
        unsubscribe callable."""
        unsubscribes = (self.session.subscribe(callback), self._bus.subscribe(callback))

        def unsubscribe() -> None:
            for unsub in unsubscribes:
                unsub()

        return unsubscribe

    def update_sub_devices(self, sub_devices: Sequence[CloudDevice]) -> DevicesChanged | None:
        """Replace the paired devices (a newer cloud list) and the channels reads wait for.

        Emits and returns :class:`~.events.DevicesChanged` when a serial was added,
        removed or moved to another channel; None (and no event) otherwise.
        """
        old = {d.device_sn: d.channel for d in self.sub_devices}
        new = {d.device_sn: d.channel for d in sub_devices}
        self.sub_devices = tuple(sub_devices)
        self.session.expect_channels = self.channels
        event = DevicesChanged(
            station_sn=self.serial,
            added=tuple(sorted(new.keys() - old.keys())),
            removed=tuple(sorted(old.keys() - new.keys())),
            moved=tuple(sorted(sn for sn in new.keys() & old.keys() if new[sn] != old[sn])),
        )
        if not (event.added or event.removed or event.moved):
            return None
        self._bus.emit(event)
        return event

    def _on_notify(self, obj: Mapping[str, Any], cipher: FrameCipher) -> None:
        zoom = reported_zoom(obj)
        if zoom is None:
            return
        device_sn = self._zoom_device(obj)
        if device_sn is not None:
            self._keep_zoom(device_sn, zoom)

    def _zoom_device(self, obj: Mapping[str, Any]) -> str | None:
        """The camera a 6203 report is about: the one on its ``mChannel``; a standalone
        station's own serial when it names none. None when that is not a zoom camera."""
        channel = json_int(obj.get("mChannel"))
        if self.is_standalone and channel in (None, own_channel(self.device)):
            device_sn: str | None = self.serial
        else:
            device_sn = next(
                (
                    d.device_sn
                    for d in self.sub_devices
                    if channel is not None and d.channel == channel
                ),
                None,
            )
        if device_sn is None:
            return None
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_ZOOM) is Support.UNKNOWN:
            return None
        return device_sn

    def _keep_zoom(self, device_sn: str, zoom: float) -> None:
        if self._zooms.get(device_sn) == zoom:
            return
        self._zooms[device_sn] = zoom
        self._bus.emit(ZoomChanged(station_sn=self.serial, device_sn=device_sn, zoom=zoom))

    def _on_session_event(self, event: Event) -> None:
        # A camera that loses its link has gone idle, and an idle camera returns to 1x.
        if isinstance(event, ConnectionChanged) and not event.connected:
            for device_sn in list(self._zooms):
                self._keep_zoom(device_sn, MIN_ZOOM)

    def _on_dump_complete(self) -> None:
        state = self.state
        if state is None or state == self._emitted_state:
            return
        self._emitted_state = state
        self._bus.emit(StationStateChanged(station_sn=self.serial, state=state))

    async def async_start(self) -> None:
        """Load the model settings, connect, take a baseline parameter dump, and keep the
        session healthy."""
        await self.async_load_settings()
        await self.session.async_start()

    async def async_close(self) -> None:
        await self.session.async_close()

    @property
    def connected(self) -> bool:
        """Whether the last :class:`~.events.ConnectionChanged` said connected and still holds."""
        return self.session.announced

    @property
    def last_error(self) -> EufySecurityError | None:
        """The last connection failure; cleared by the next answered probe."""
        return self.session.last_error

    def stats(self) -> SessionStats:
        """Health counters of this station's session, JSON-safe and identifier-free."""
        return self.session.stats()

    # ── reads ────────────────────────────────────────────────────────────────

    async def async_update(self, *, wake: bool = False) -> StationState:
        """Read a fresh dump of the station and every paired device; returns :attr:`state`
        right after it (the same snapshot a :class:`~.events.StationStateChanged` carries).

        A station reached on demand (:attr:`connects_on_demand`) is not woken for it: the
        state it has (the cloud snapshot, pushes, the last session) is returned as is,
        unless there is none yet or ``wake`` asks for a live read.
        """
        if self.connects_on_demand and not wake and (state := self.state) is not None:
            return state
        dump = await self.session.async_get_params(expect_channels=self.channels)
        return self.state or self._state(dump)

    @property
    def max_sessions(self) -> int:
        """P2P sessions this library holds to the station at most; ``max_sessions - 1``
        live streams at once (see :attr:`~.p2p.session.StationSession.max_sessions`).
        Settable: ``ValueError`` outside :data:`~.p2p.session.MIN_STATION_SESSIONS` ..
        :data:`~.p2p.session.STATION_SESSION_LIMIT`. A lower value ends no stream."""
        return self.session.max_sessions

    @max_sessions.setter
    def max_sessions(self, value: int) -> None:
        self.session.max_sessions = value

    @property
    def media_slot_camera(self) -> str | None:
        """Serial of the camera whose live view holds the station session's one media slot.

        ``None`` when the slot is free, when it holds a recording or playback (no camera),
        or when no cloud device maps to the slot's channel. Live views past the first run
        on their own extra sessions and do not hold this slot.

        A live still or preset capture on a HomeBase is a live open like any other: while
        this slot is busy it runs on an extra session, so a live view blocks it only when
        the session budget (:attr:`max_sessions`) is used up. Then the capture raises
        :class:`~.exceptions.LiveStreamLimitError`, or with ``wait`` waits for a stream to
        end; ending this camera's view frees the slot. A standalone camera has one stream:
        its own view blocks its captures.

        Point-in-time: the freed slot can be claimed by another live open before a capture
        takes it.
        """
        channel = self.session.media_slot_channel
        if channel is None:
            return None
        cloud = self._cloud_by_channel().get(channel)
        return cloud.device_sn if cloud is not None else None

    @property
    def connects_on_demand(self) -> bool:
        """Whether this station is reached only on demand (a battery device, see
        :func:`~.devices.types.connects_on_demand`): no held session, its state comes from
        the cloud snapshot and pushes, and every command connects, then the link closes
        after :data:`~.p2p.session.ON_DEMAND_IDLE_CLOSE` seconds idle."""
        return self.session.on_demand

    def apply_cloud_device(self, device: CloudDevice) -> int:
        """Merge a device-list entry's parameter snapshot into this station's state;
        returns how many values were news (see
        :meth:`~.p2p.session.StationSession.ingest_cloud_params`).

        Only this station's own entry counts (a hub's paired devices report through the
        hub); an entry without a snapshot, or of another serial, changes nothing.
        """
        if device.device_sn != self.serial:
            return 0
        dev_type = device.device_type if self.is_standalone else STATION_CHANNEL
        return self.session.ingest_cloud_params(
            dev_type, ((p.param_id, p.value, p.updated_at) for p in device.cloud_params)
        )

    @property
    def state(self) -> StationState | None:
        """The station built from the session's merged parameters; None before the
        station's own block has arrived.

        Each parameter holds its latest value from any dump, pushed or read. A device
        block absent from a full read is gone (see
        :meth:`~.p2p.session.StationSession.add_dump_listener`).
        """
        dump = self.session.merged_params()
        return self._state(dump) if STATION_CHANNEL in dump.devices else None

    @property
    def channels(self) -> frozenset[int]:
        """The station channels of every paired device the cloud reports (and a
        standalone station's own channel)."""
        return station_channels(self.device, self.sub_devices)

    def _cloud_by_channel(self) -> dict[int, CloudDevice | None]:
        """The cloud device on each channel; None where two or more claim it (warned)."""
        by_channel: dict[int, CloudDevice | None] = {}
        own = own_channel(self.device)
        if own is not None:
            by_channel[own] = self.device
        for device in self.sub_devices:
            if device.channel is None:
                continue
            if device.channel in by_channel:
                by_channel[device.channel] = None
                if self._throttle.should_log(("duplicate channel", device.channel)):
                    _LOGGER.warning(
                        "%s: the cloud lists more than one device on channel %d; "
                        "its serial stays unknown",
                        self._log_name,
                        device.channel,
                    )
            else:
                by_channel[device.channel] = device
        return by_channel

    def _serials_from_1072(
        self,
        dump: ParamDump,
        kinds: Mapping[int, DeviceKind | None],
        cloud: Mapping[int, CloudDevice | None],
    ) -> dict[int, str]:
        """Serials for channels the cloud list lacks, from station param 1072 (anchored).

        1072 is read as the camera serials in channel order
        (:data:`SUB_DEVICE_SERIALS_ORDER_EVIDENCE`). Its positions are used only when
        the dump's camera blocks number exactly ``len(1072)``, at least one cloud-known
        serial appears in it, and every one that does sits at the rank of its own
        channel among the camera channels. Otherwise nothing is assigned.
        """
        listed = dump.sub_device_serials(station_sn=self.serial)
        cameras = sorted(ch for ch, kind in kinds.items() if kind is DeviceKind.CAMERA)
        if not listed or len(listed) != len(cameras):
            return {}
        known = {d.device_sn: d.channel for d in self.sub_devices}
        anchors = 0
        for rank, serial in enumerate(listed):
            if serial is None or serial not in known:
                continue
            channel = known[serial]
            if channel != cameras[rank] or cloud.get(channel) is None:
                return {}
            anchors += 1
        if not anchors:
            return {}
        assigned = {}
        for rank, serial in enumerate(listed):
            channel = cameras[rank]
            model = model_for_serial(serial) if serial is not None else None
            if (
                serial is None
                or serial in known
                or channel in cloud
                or (model is not None and model.kind is not DeviceKind.CAMERA)
            ):
                continue
            assigned[channel] = serial
        return assigned

    def _state(self, dump: ParamDump) -> StationState:
        cloud_by_channel = self._cloud_by_channel()
        blocks = {ch: params for ch, params in dump.devices.items() if ch != STATION_CHANNEL}
        cloud_kinds = {}
        for channel, params in blocks.items():
            cloud = cloud_by_channel.get(channel)
            model = model_for_serial(cloud.device_sn) if cloud else None
            cloud_kinds[channel] = model.kind if model else kind_from_params(params)
        from_1072 = self._serials_from_1072(dump, cloud_kinds, cloud_by_channel)
        devices = {}
        for channel, params in blocks.items():
            cloud = cloud_by_channel.get(channel)
            serial: str | None
            source: SerialSource | None
            if cloud is not None:
                serial, source = cloud.device_sn, "cloud"
            elif channel in from_1072:
                serial, source = from_1072[channel], "param_1072"
            else:
                serial, source = None, None
            model = model_for_serial(serial) if serial else None
            wifi_rssi = _int_or_none(params.get(PARAM_WIFI_RSSI))
            sub1g_rssi = _int_or_none(params.get(PARAM_SUB1G_RSSI))
            status = _int_or_none(params.get(PARAM_DEV_STATUS))
            devices[channel] = SubDeviceState(
                channel=channel,
                serial=serial,
                serial_source=source,
                kind=model.kind if model else kind_from_params(params),
                name=params.get(PARAM_DEVICE_NAME) or (cloud.name if cloud else None),
                battery=_int_or_none(params.get(PARAM_BATTERY)),
                wifi_rssi=wifi_rssi,
                sub1g_rssi=None if wifi_rssi is not None and sub1g_rssi == 0 else sub1g_rssi,
                firmware=params.get(PARAM_FIRMWARE),
                pir_event_ms=_epoch_ms_or_none(params.get(PARAM_PIR_EVENT_MS)),
                online=None if status is None else status == DEV_STATUS_ONLINE,
                offline_code=status if status is not None and status > DEV_STATUS_ONLINE else None,
                battery_temperature=_int_or_none(params.get(PARAM_BATTERY_TEMPERATURE)),
                working_days=_count_or_none(params.get(PARAM_WORKING_DAYS)),
                detected_events=_count_or_none(params.get(PARAM_DETECTED_EVENTS)),
                recorded_events=_count_or_none(params.get(PARAM_RECORDED_EVENTS)),
                power_source=_count_or_none(params.get(PARAM_POWER_SOURCE)),
                solar_intensity=_count_or_none(params.get(PARAM_SOLAR_INTENSITY)),
                siren_actions={
                    mode: action
                    for mode, pid in SIREN_ACTION_PARAMS.items()
                    if (action := _count_or_none(params.get(pid))) is not None
                },
                low_battery=_flag_or_none(params.get(PARAM_SENSOR_LOW_BATTERY)),
                pir_sensitivity_raw=_count_or_none(params.get(PARAM_SENSOR_PIR_SENSITIVITY)),
                params=dict(params),
                settings=self._settings_by_key(serial) if serial else {},
            )
        # Log lines on the session name a parameter by the device kind on its channel.
        self.session.channel_scopes.update(
            {ch: scope_for_kind(d.kind) for ch, d in devices.items() if d.kind is not None}
        )
        station = dump.station
        return StationState(
            serial=self.serial,
            guard_mode=dump.guard_mode,
            active_mode=dump.guard_mode if dump.active_mode is None else dump.active_mode,
            firmware=_text_or_none(dump.meta.get("main_sw_version")) or self.device.main_sw_version,
            devices=devices,
            params=dict(station),
            name=_text_or_none(station.get(PARAM_HUB_NAME)) or self.device.name,
            lan_ip=_ip_or_none(station.get(PARAM_LAN_IP)),
            sec_firmware=_text_or_none(dump.meta.get("sec_sw_version"))
            or self.device.sec_sw_version,
            emmc_used_percent=_percent_or_none(station.get(PARAM_EMMC_USED_PERCENT)),
            storage_status=_count_or_none(station.get(PARAM_STORAGE_STATUS)),
            sd_info=_int_or_none(station.get(PARAM_SD_INFO)),
            subsystem_firmware={
                pid: version
                for pid in SUBSYSTEM_FIRMWARE_PARAMS
                if (version := _text_or_none(station.get(pid))) is not None
            },
            settings=self._settings_by_key(self.serial),
            settings_by_serial={
                serial: self._settings_by_key(serial)
                for serial in dict.fromkeys((self.serial, *(d.device_sn for d in self.devices)))
            },
            settings_by_channel={
                channel: self._settings_by_key(cloud.device_sn)
                for channel, cloud in cloud_by_channel.items()
                if cloud is not None and channel != STATION_CHANNEL
            },
        )

    # ── writes ───────────────────────────────────────────────────────────────

    async def async_set_guard_mode(self, mode: GuardMode | str | int) -> GuardMode | int:
        """Arm/disarm; returns the mode the station reports it applied."""
        return await self.session.async_set_guard_mode(GuardMode.parse(mode))

    async def async_set_setting(
        self,
        key: str,
        value: object,
        *,
        device_sn: str | None = None,
        channel: int | None = None,
    ) -> CommandOutcome:
        """Write setting ``key`` of the station (no target, or channel 255), of the
        paired device ``device_sn`` or of the device on ``channel``; returns how far the
        write got (:class:`~.p2p.session.CommandOutcome`).

        ``value`` is validated (:meth:`~.devices.model_settings.Setting.validate`) and
        rendered for the device (station child or standalone) before anything is sent,
        then sent on the path the setting's codec names: an ECB scalar, a 1350 or 1700
        sub-command, or a GCM command of its own id. Once sent, the values the write
        sets are merged into the session's parameters, so :attr:`state` shows them
        until the next dump. Nothing is read back.

        A per-mode delay or action (:func:`~.devices.model_settings.mode_table_settings`)
        is written as that guard mode's whole table and confirmed by reading every value
        back; see :meth:`_async_set_mode_table_value` for what that reads, refuses and
        moves.

        Raises ``UnsupportedError`` for a key the device does not have or a setting the
        library does not write (its ``note`` says why), ``ValueError`` for a value
        outside the domain or both targets, and the session's typed errors when the
        device rejects the write.
        """
        ctx = self._write_context(device_sn, channel)
        setting = self.setting(key, device_sn=device_sn, channel=channel)
        if not setting.writable:
            raise UnsupportedError(f"{key} is not writable: {setting.note or 'read-only'}")
        public = setting.validate(value)
        if setting._mode_table is not None:
            await self._async_set_mode_table_value(setting._mode_table, int(public), ctx.channel)
            return CommandOutcome.APPLIED
        if setting.bit is not None:
            current = await self._current_mask(setting, ctx.channel)
            wanted = setting.mask_with(current, bool(public))
            if wanted == current:
                return CommandOutcome.APPLIED
            return await self._async_send_write(setting, setting.encode_mask(wanted, ctx), ctx)
        return await self._async_write(setting, public, ctx)

    async def async_set_flag(
        self,
        key: str,
        flag: str,
        on: bool,
        *,
        device_sn: str | None = None,
        channel: int | None = None,
    ) -> int:
        """Turn one member of a ``FLAGS`` setting on or off (``detection_type_set``,
        member ``"3"`` = pets); returns the mask written (or already in effect).

        The current mask is read fresh, the member's bits are changed with every other
        bit kept, and the mask is written. Per-mode action masks go through
        :meth:`async_set_mode_action`. Raises ``UnsupportedError`` for a key that is not
        a writable ``FLAGS`` setting, ``ValueError`` for an unknown member (both before
        anything is sent) and :class:`CommandNotAppliedError` when the current mask
        cannot be read.
        """
        ctx = self._write_context(device_sn, channel)
        setting = self.setting(key, device_sn=device_sn, channel=channel)
        if setting.kind is not SettingKind.FLAGS or not setting.writable:
            raise UnsupportedError(f"{key} is not a writable flags setting")
        setting.with_flag(0, flag, on=on)  # refuses an unknown member before any traffic
        current = await self._current_mask(setting, ctx.channel)
        wanted = setting.with_flag(current, flag, on=on)
        if wanted != current:
            await self._async_write(setting, wanted, ctx)
        return wanted

    async def _current_mask(self, setting: Setting, channel: int) -> int:
        """The mask ``setting``'s parameter holds now, from a fresh read; raises
        :class:`CommandNotAppliedError` when the station does not report it, since a
        mask written blind would clear the bits other settings own."""
        param = setting.read_param
        current = None if param is None else await self._read_back(param, channel)
        if current is None or current < 0:
            raise CommandNotAppliedError(
                param or 0,
                f"{setting.key}: the station does not report the current mask on channel "
                f"{channel}; refusing to write the whole mask blind",
            )
        return current

    async def async_set_mode_action(
        self,
        mode: GuardMode | str | int,
        flag: str,
        on: bool,
        *,
        device_sn: str | None = None,
        channel: int | None = None,
    ) -> int:
        """Turn one action of a paired device on or off for one guard mode — "sound this
        camera's siren in Away" is ``("away", "camera_siren", True)``; returns the mask now
        in effect.

        The setting is the device kind's ``<kind>_action_<mode>`` (``camera_action_away``),
        whose ``flags`` name the actions. The current mask is read fresh, one bit is
        changed with every other bit kept, and the mode table is written and confirmed by
        read-back; nothing is written when the flag is already as asked. A library write
        of the mask is proven on hardware; the flag names come from the app and are not.

        Raises ``UnsupportedError`` for a mode without per-device actions (Schedule,
        Off, Disarmed, Geofence), a device whose kind is unknown or has no catalogued
        actions, or a flag that kind does not name (all before anything is sent);
        :class:`CommandNotAppliedError` when the current mask cannot be read; and
        ``ValueError`` when both or neither target is given.
        """
        if (device_sn is None) == (channel is None):
            raise ValueError("pass exactly one of device_sn or channel")
        target = self.channel_for(device_sn) if device_sn is not None else cast(int, channel)
        key = mode_action_key(GuardMode.parse(mode), scope_for_kind(self._kind_on(target)))
        spec = mode_table_setting(key)
        spec.with_flag(0, flag, on)  # refuses an unknown flag before any traffic
        current = await self._read_back(spec.read_param, target)
        if current is None:
            raise CommandNotAppliedError(
                spec.command_id,
                f"{key}: the station does not report the current mask on channel {target}; "
                "refusing to write a whole mask blind",
            )
        wanted = spec.with_flag(current, flag, on)
        if wanted == current:
            return current
        return await self._async_set_mode_table_value(spec, wanted, target)

    def _kind_on(self, channel: int) -> DeviceKind | None:
        """The kind of the device on ``channel``: its cloud serial's model, else the last
        snapshot's reading of its block; None when neither says."""
        cloud = self._cloud_by_channel().get(channel)
        model = model_for_serial(cloud.device_sn) if cloud is not None else None
        if model is not None:
            return model.kind
        state = self.state
        device = state.devices.get(channel) if state is not None else None
        return device.kind if device is not None else None

    async def _async_set_mode_table_value(self, spec: SettingDef, value: int, target: int) -> int:
        """Write one mode-table value: read the whole mode fresh, change ``target``'s
        entry, send the table (``SET_ALL_ACTION``) and confirm every value by read-back.

        Refuses (``UnsupportedError``, nothing sent) when the setting does not apply to
        the device on ``target``, when a device of the table is of no known kind (it may
        be a siren accessory, whose triggers a library table would clear), or when a
        delay the table must carry unchanged differs between devices; and
        (``CommandNotAppliedError``) when a paired device or the target is missing from
        the fresh read, since a table without it would drop it. A non-zero delay also
        moves the delay of every device that has it on (one value per mode). Returns
        ``value`` without writing when the table already holds it.
        """
        mode, table_field = MODE_TABLE_PARAMS[spec.command_id]
        wanted = self.channels | {target}
        dump = await self.session.async_get_params(expect_channels=wanted)
        missing = sorted(wanted - dump.devices.keys())
        if missing:
            raise CommandNotAppliedError(
                spec.command_id,
                f"{spec.key}: channels {missing} are missing from the parameter dump; "
                "refusing to write a mode table without them",
            )
        state = self._state(dump)
        device = state.devices.get(target)
        if device is None:
            # `state.devices` holds sub-devices only, so a station channel (or one that
            # went away between the dump and here) lands here. A public write must
            # raise a typed error, not a KeyError.
            raise UnsupportedError(
                f"setting {spec.key!r} names channel {target}, which is no paired device"
            )
        if not spec.applies_to(scope_for_kind(device.kind)):
            raise UnsupportedError(
                f"setting {spec.key!r} is a {spec.scope} setting, not one of channel {target}"
            )
        table = mode_table_from_params(dump.devices, mode)
        # A station's own block can carry a per-mode action parameter, and it is not in
        # `state.devices` (which holds sub-devices only). Treat a channel with no known
        # device the same as one of an unknown kind: a typed refusal, not a KeyError.
        unknown = sorted(
            ch
            for ch in table.actions
            if ch not in state.devices
            or state.devices[ch].kind not in (DeviceKind.CAMERA, DeviceKind.SENSOR)
        )
        if unknown:
            raise UnsupportedError(
                f"{spec.key}: channels {unknown} are of no known device kind; a mode table "
                "always clears siren-accessory triggers, so it is not written"
            )
        if table_field is ModeTableField.ACTION:
            new = table.with_action(target, value)
        else:
            new = table.with_delay(table_field, target, value)
        if new.same_values(table):
            return value
        new.request("")  # refuses a delay the table cannot carry, before any traffic
        await self.session.async_set_mode_table(new)
        return value

    async def _read_back(self, param_id: int, channel: int) -> int | None:
        # A single dump can end before a camera's block arrives; retry a few times.
        for attempt in range(READBACK_ATTEMPTS):
            dump = await self.session.async_get_params(expect_channels=(channel,))
            block = dump.devices.get(channel, {})
            raw = block.get(param_id)
            if raw is not None:
                return report_value(raw, block.get(VIEW_MODE_PARAM))
            if attempt + 1 < READBACK_ATTEMPTS:
                await asyncio.sleep(READBACK_DELAY)
        return None

    # ── media and history ────────────────────────────────────────────────────

    async def async_fetch_image(self, path: str) -> bytes:
        """The bytes of :meth:`async_fetch_still`, whatever their format."""
        return await self.session.async_fetch_image(path)

    async def async_fetch_still(self, path: str, *, timeout: float | None = None) -> Still:
        """Download a still (an event's ``thumb_path`` or ``crop_path``) with its format.

        Check ``is_image`` before showing it: obfuscated stills are returned, not raised.
        """
        return await self.session.async_fetch_still(path, timeout=timeout)

    async def async_open_live(
        self,
        device_sn: str | None = None,
        *,
        channel: int | None = None,
        preset: int | None = None,
        wait: bool = False,
        **kwargs: Any,
    ) -> MediaStream:
        """Open a paired camera's live stream (by serial or channel). Wakes a battery camera.

        On a HomeBase, a stream opened while the station session's slot is busy runs on an
        extra session, up to ``session.max_sessions - 1`` live streams; past that
        :class:`~.exceptions.LiveStreamLimitError`, or with ``wait`` a wait for a
        stream to end (see :meth:`~.p2p.session.StationSession.async_open_live`).

        With ``preset`` (needs ``device_sn``), the camera is first turned to that stored
        slot and the stream is opened straight after, so a battery camera stays awake
        through the turn; the first frames may show it turning. Checked before anything
        is sent, as :meth:`async_goto_preset`; a go-to the camera refuses raises and
        opens nothing.
        """
        ch = self._media_channel(device_sn, channel)
        if preset is not None:
            if device_sn is None:
                raise ValueError("preset needs device_sn")
            slot_channel = self._stored_slot(device_sn, preset)
            self._refuse_while_capturing(device_sn)
            await self._ptz_recipe(goto_preset(preset), slot_channel)
        return await self.session.async_open_live(ch, wait=wait, **kwargs)

    async def async_open_recording(
        self,
        path: str,
        device_sn: str | None = None,
        *,
        channel: int | None = None,
        wait: bool = False,
        **kwargs: Any,
    ) -> MediaStream:
        """Play a stored recording (an event's ``.zxvideo`` path) recorded by that camera."""
        return await self.session.async_open_recording(
            path, self._media_channel(device_sn, channel), wait=wait, **kwargs
        )

    async def async_snapshot(
        self,
        device_sn: str | None = None,
        *,
        channel: int | None = None,
        recording: str | None = None,
        wait: bool = False,
        **kwargs: Any,
    ) -> bytes:
        """One full-resolution picture as Annex-B HEVC (a single decodable keyframe).

        With ``recording`` it is :meth:`async_trigger_frame`: the recording's first
        keyframe, the moment that triggered the event, taken on a short-lived session
        (the camera stays asleep; ``wait`` does not apply, such calls queue per
        station). Without it the camera is woken and its next keyframe is returned
        from this station's session: the second keyframe when one follows the first
        within :data:`FRESH_KEYFRAME_WINDOW`, since a camera woken again may first
        replay a keyframe of its previous stream. A live snapshot opens live video as
        :meth:`async_open_live` does: on a HomeBase with the slot busy it runs on an extra
        session, and past the session budget it raises
        :class:`~.exceptions.LiveStreamLimitError`; a standalone camera with its stream
        open raises :class:`~.exceptions.CommunicationError`. With ``wait`` it waits for
        a stream to end instead.
        """
        ch = self._media_channel(device_sn, channel)
        if recording is not None:
            return await self.session.async_trigger_frame(recording, ch, **kwargs)
        stream = await self.session.async_open_live(ch, wait=wait, **kwargs)
        async with stream:
            return await _fresh_keyframe(stream)

    async def async_trigger_frame(
        self,
        path: str,
        device_sn: str | None = None,
        *,
        channel: int | None = None,
        trailing_frames: int = 0,
        first_frame_timeout: float | None = None,
    ) -> bytes:
        """A recording's trigger frame (its first keyframe) as Annex-B HEVC, by path.

        Played on a short-lived second session that is closed as soon as the frames
        are in, so this station's session is neither flooded nor stalled (see
        :meth:`~.p2p.session.StationSession.async_trigger_frame`). ``trailing_frames``
        appends up to that many following P-frames.
        """
        return await self.session.async_trigger_frame(
            path,
            self._media_channel(device_sn, channel),
            trailing_frames=trailing_frames,
            first_frame_timeout=first_frame_timeout,
        )

    async def async_event_trigger_frame(
        self,
        event: SecurityEvent,
        *,
        trailing_frames: int = 0,
        first_frame_timeout: float | None = None,
    ) -> bytes:
        """The trigger frame of an event's recording (:meth:`async_trigger_frame`).

        The camera is the event's ``device_sn`` when it is paired here, else its
        ``channel``. Raises :class:`~.exceptions.UnsupportedError`, before anything is
        sent, when the event has no ``video_path``, names another station, or names
        no camera this station can address.
        """
        if event.video_path is None:
            raise UnsupportedError("the event carries no recording (video_path)")
        self._require_own_event(event)
        _, channel = self._event_camera(event)
        return await self.async_trigger_frame(
            event.video_path,
            channel=channel,
            trailing_frames=trailing_frames,
            first_frame_timeout=first_frame_timeout,
        )

    async def async_event_thumbnail(
        self, event: SecurityEvent, *, timeout: float | None = None
    ) -> Still:
        """An event's thumbnail (the 640x360 still the app lists), with its format.

        The push's own ``thumb_path`` when it carried one bound to the event;
        otherwise the ``thumb_path`` of the event's history row, found by
        ``record_id`` with one query. On fw 3.8.7.4 a push's attached records
        describe an earlier event, so the history row is the usual source. Check
        ``is_image`` before showing the still.

        Raises :class:`~.exceptions.UnsupportedError`, before anything is sent, when
        the event names another station or carries neither a ``thumb_path`` nor a
        ``record_id`` with a day; :class:`~.exceptions.RecordNotFoundError` when the
        history has no row for it, the row is another camera's, or the row has no
        valid thumbnail yet (the station writes it when the clip is saved: retry
        later). ``timeout`` bounds the history query and the still fetch each.

        On a standalone device (its detections come by cloud push, with no path or
        record) the device's newest event still (event-count query, waking it) is
        returned when its time falls within :data:`STANDALONE_STILL_WINDOW` of the
        event's; :class:`~.exceptions.RecordNotFoundError` when it is older (not
        written yet: retry once, later) or newer (a later detection replaced it).
        """
        timeout = p2p_session.STILL_FETCH_TIMEOUT if timeout is None else timeout
        self._require_own_event(event)
        if self.session.standalone and event.thumb_path is None:
            return await self._standalone_event_still(event, timeout=timeout)
        path = event.thumb_path
        if path is not None:
            _LOGGER.debug("%s: event thumbnail from the push's bound path", self._log_name)
        else:
            record_id = event.record_id
            if not record_id or record_id_day(record_id) is None:
                raise UnsupportedError("the event carries no thumbnail and no record_id")
            started = time.monotonic()
            row = await self.session.async_history_record(record_id, timeout=timeout)
            if row is None:
                outcome = "none"
            elif (
                event.device_sn is not None
                and row.device_sn is not None
                and row.device_sn != event.device_sn
            ):
                outcome = "another camera's"
            elif not row.thumb_path:
                outcome = "no thumbnail yet"
            elif not is_station_media_path(row.thumb_path, STILL_SUFFIX):
                outcome = "no valid thumbnail path"
            else:
                outcome = "found"
            _LOGGER.debug(
                "%s: event thumbnail: history record %s in %.2fs",
                self._log_name,
                outcome,
                time.monotonic() - started,
            )
            if outcome in ("none", "no thumbnail yet"):
                # No record id in the message: consumers log it.
                raise StillNotWrittenError(f"the event's history record: {outcome}")
            if outcome != "found":
                raise RecordNotFoundError(f"the event's history record: {outcome}")
            path = cast(str, cast(HistoryRecord, row).thumb_path)
        return await self.async_fetch_still(path, timeout=timeout)

    async def async_event_image(
        self,
        event: SecurityEvent,
        source: ImageSource = ImageSource.TRIGGER_FRAME,
        *,
        full_resolution: bool = False,
    ) -> CameraImage:
        """One image of a detection, from ``source`` (see :data:`~.images.IMAGE_SOURCES`).

        * ``THUMBNAIL``: :meth:`async_event_thumbnail`, a JPEG.
        * ``TRIGGER_FRAME``: :meth:`async_event_trigger_frame`, the recording's first
          keyframe as HEVC at full resolution; the camera stays asleep. Not on a
          standalone device (it lists no recordings, see :meth:`image_sources`).
        * ``LIVE``: a live keyframe of the event's camera now, as HEVC; wakes a battery
          camera. ``full_resolution`` as for :meth:`async_camera_image`.

        Each source fails on its own: a consumer that wants "the thumbnail at once, then
        the HD frame" calls it twice. Raises what the underlying call raises, and
        :class:`~.exceptions.UnsupportedError` before anything is sent for an event of
        another station, naming no paired camera, a trigger frame of a standalone
        device, or (thumbnail) a still that is not a plain JPEG.
        """
        self._require_own_event(event)
        device_sn, channel = self._event_camera(event)
        if source is ImageSource.TRIGGER_FRAME and self.session.standalone:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} is a standalone device: it lists no recordings, "
                "so there is no trigger frame (use THUMBNAIL or LIVE)"
            )
        if source is ImageSource.THUMBNAIL:
            still = await self.async_event_thumbnail(event)
            if not still.is_image:
                raise UnsupportedError(f"the event's thumbnail is not a JPEG ({still.format})")
            return CameraImage(
                source=source,
                device_sn=device_sn,
                data=still.data,
                content_type=JPEG_CONTENT_TYPE,
                record_id=event.record_id or None,
            )
        if source is ImageSource.TRIGGER_FRAME:
            data = await self.async_event_trigger_frame(event)
            return CameraImage(
                source=source,
                device_sn=device_sn,
                data=data,
                content_type=HEVC_CONTENT_TYPE,
                record_id=event.record_id or None,
            )
        return await self._live_image(device_sn, channel, full_resolution=full_resolution)

    def image_sources(self, device_sn: str) -> tuple[ImageSource, ...]:
        """The :class:`~.images.ImageSource` values :meth:`async_camera_image` can serve
        for ``device_sn``: all three behind a station; on a standalone device
        ``THUMBNAIL`` and ``LIVE``, since it lists no recordings (no trigger frame).
        Offer only these."""
        self.channel_for(device_sn)  # raises for a device not paired here
        if self.session.standalone:
            return (ImageSource.THUMBNAIL, ImageSource.LIVE)
        return tuple(ImageSource)

    async def async_camera_image(
        self,
        device_sn: str,
        source: ImageSource = ImageSource.TRIGGER_FRAME,
        *,
        days: int = CAMERA_IMAGE_DAYS,
        wait: bool = True,
        full_resolution: bool = False,
    ) -> CameraImage:
        """An image of a paired camera on demand, without waiting for a detection.

        ``THUMBNAIL`` and ``TRIGGER_FRAME`` come from the camera's newest recorded event
        in the station's history (today, then day by day back over ``days`` days); the
        camera stays asleep. ``LIVE`` is a live keyframe now and wakes a battery camera.
        The image's ``record_id`` and ``recorded_at`` say which event it shows.

        ``wait`` applies to ``LIVE`` only (see :meth:`async_snapshot`): past the session
        budget it waits up to the first-frame timeout for a stream to end (the default),
        or with ``wait=False`` raises :class:`~.exceptions.LiveStreamLimitError` at once.

        A ``LIVE`` image carries its picture ``width`` and ``height``. By default it is
        the first fresh keyframe, which on a woken standalone camera is the small first
        rung of its climb (1280x720 on a T8170). With ``full_resolution`` the stream is
        held until the picture size stops changing for the settle window
        (:data:`~.p2p.encoder.SETTLE_STANDALONE` on a standalone camera, else
        :data:`~.p2p.encoder.SETTLE_STATION`), at most :data:`FULL_RESOLUTION_TIMEOUT`
        after the first keyframe, and the largest size's keyframe is returned; the
        camera stays awake that long.

        Raises :class:`~.exceptions.UnsupportedError` for a device not paired here, and
        :class:`~.exceptions.RecordNotFoundError` when the history holds no event of the
        camera with that media in the window (for example after a format).
        """
        if days < 1:
            raise ValueError("days must be at least 1")
        channel = self.channel_for(device_sn)
        if source is ImageSource.LIVE:
            return await self._live_image(
                device_sn, channel, wait=wait, full_resolution=full_resolution
            )
        if self.session.standalone:
            return await self._standalone_image(device_sn, source)
        row = await self._newest_camera_record(device_sn, source, days)
        if source is ImageSource.THUMBNAIL:
            still = await self.async_fetch_still(cast(str, row.thumb_path))
            if not still.is_image:
                raise UnsupportedError(f"the record's thumbnail is not a JPEG ({still.format})")
            data, content_type = still.data, JPEG_CONTENT_TYPE
        else:
            data = await self.async_trigger_frame(cast(str, row.storage_path), channel=channel)
            content_type = HEVC_CONTENT_TYPE
        return CameraImage(
            source=source,
            device_sn=device_sn,
            data=data,
            content_type=content_type,
            record_id=row.record_id or None,
            recorded_at=row.start_time,
        )

    async def _standalone_event_still(self, event: SecurityEvent, *, timeout: float) -> Still:
        """A standalone device's newest event still, when it is ``event``'s."""
        if event.event_time_ms is None:
            raise UnsupportedError("the event carries no time to match a still to")
        device_sn = event.device_sn or self.serial
        started = time.monotonic()
        summary = await self.session.async_event_summary(device_sn, timeout=timeout)
        path = summary.newest_still
        stamp = None if path is None else _still_time(path)
        if path is None or stamp is None:
            raise RecordNotFoundError(f"{redact_serial(device_sn)} has no dated event still")
        zone = await self._device_zone()
        taken = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=zone)
        offset = taken.timestamp() - event.event_time_ms / 1000
        early, late = STANDALONE_STILL_WINDOW
        _LOGGER.debug(
            "%s: newest still is %+.1fs from the event (found in %.2fs)",
            self._log_name,
            offset,
            time.monotonic() - started,
        )
        if offset < early:
            raise StillNotWrittenError("the event's still is not written yet", offset=offset)
        if offset > late:
            raise RecordNotFoundError("a later event's still replaced the event's")
        return await self.async_fetch_still(path, timeout=timeout)

    async def _device_zone(self) -> tzinfo | None:
        """The zone the device's clock (and its still names) follow: its ``timezone_set``,
        else the host's (None)."""
        state = self.state
        own = own_channel(self.device)
        zone_id: object = None
        if state is not None and own is not None:
            with contextlib.suppress(UnsupportedError):
                zone_id = state.setting("timezone_set", channel=own)
        if not isinstance(zone_id, str):
            return None
        try:
            return await asyncio.to_thread(ZoneInfo, zone_id)  # reads the zone file
        except (ZoneInfoNotFoundError, ValueError):
            return None

    async def _standalone_image(self, device_sn: str, source: ImageSource) -> CameraImage:
        """A standalone device's thumbnail: its newest still by the event-count query
        (10013), which it answers where it does not answer the history list."""
        if source is not ImageSource.THUMBNAIL:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} is a standalone device: it lists no recordings, "
                "so there is no trigger frame (use THUMBNAIL or LIVE)"
            )
        summary = await self.session.async_event_summary(device_sn)
        if summary.newest_still is None:
            raise RecordNotFoundError(f"{redact_serial(device_sn)} has no event still")
        still = await self.async_fetch_still(summary.newest_still)
        if not still.is_image:
            raise UnsupportedError(f"the newest still is not a JPEG ({still.format})")
        return CameraImage(
            source=ImageSource.THUMBNAIL,
            device_sn=device_sn,
            data=still.data,
            content_type=JPEG_CONTENT_TYPE,
            recorded_at=_still_time(summary.newest_still),
        )

    async def _newest_camera_record(
        self, device_sn: str, source: ImageSource, days: int
    ) -> HistoryRecord:
        """The newest history record of ``device_sn`` carrying ``source``'s media path."""

        def usable(row: HistoryRecord) -> bool:
            if row.device_sn != device_sn:
                return False
            if source is ImageSource.THUMBNAIL:
                return is_station_media_path(row.thumb_path, STILL_SUFFIX)
            return is_station_media_path(row.storage_path, RECORDING_SUFFIX)

        today = datetime.now().astimezone().date()  # the host's day; stations keep local time
        for back in range(days):
            day = (today - timedelta(days=back)).strftime("%Y%m%d")
            rows = await self.async_list_history(day)
            if found := next((row for row in rows if usable(row)), None):
                return found
        raise RecordNotFoundError(
            f"no {source} of {redact_serial(device_sn)} in the last {days} day(s) of history"
        )

    async def _live_image(
        self,
        device_sn: str,
        channel: int,
        *,
        wait: bool = True,
        full_resolution: bool = False,
    ) -> CameraImage:
        async def capture() -> CameraImage:
            stream = await self.session.async_open_live(channel, wait=wait)
            async with stream:
                if full_resolution:
                    held = SETTLE_STANDALONE if self.session.standalone else SETTLE_STATION
                    frame = await _held_size_keyframe(stream, held, FULL_RESOLUTION_TIMEOUT)
                else:
                    frame = await _fresh_keyframe_frame(stream)
            await self._refresh_presets_while_awake(device_sn)
            _LOGGER.debug(
                "%s: live image of %s: %dx%d",
                self._log_name,
                redact_serial(device_sn),
                frame.width,
                frame.height,
            )
            return CameraImage(
                source=ImageSource.LIVE,
                device_sn=device_sn,
                data=frame.data,
                content_type=HEVC_CONTENT_TYPE,
                width=frame.width or None,
                height=frame.height or None,
            )

        return await self._run_capture(device_sn, None, capture)

    # ── pan/tilt presets ─────────────────────────────────────────────────────

    def presets(self, device_sn: str) -> tuple[PresetPosition, ...] | None:
        """Camera ``device_sn``'s preset slots as last read, enabled or not; None when
        never read. No I/O: the slots are read by :meth:`async_refresh_presets`, and
        again whenever the camera is awake for an image (see :class:`~.events.PresetsChanged`)."""
        cached = self._presets.get(device_sn)
        if cached is not None or self._cache is None:
            return cached
        stored = self._cache.presets(self.serial, device_sn)
        if stored is None:
            return None
        try:
            slots = parse_preset_positions({"points": stored})
        except (EufySecurityError, TypeError, ValueError):
            return None
        self._presets[device_sn] = slots
        return slots

    def default_preset(self, device_sn: str) -> int | None:
        """The slot camera ``device_sn`` returns to on its own when idle, from the last
        read of :meth:`presets`; None when never read or no slot is the default."""
        slots = self.presets(device_sn)
        if slots is None:
            return None
        return next((s.index for s in slots if s.is_default), None)

    async def async_set_default_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]:
        """Make slot ``preset`` the one camera ``device_sn`` returns to when idle, and
        turn the camera there now, as the app does. Wakes a battery camera.

        The camera receipts the write and sends no result, so the slots are read back
        (:meth:`presets`, :class:`~.events.PresetsChanged`) and the write counts only
        when the read shows the slot as default: otherwise
        :class:`~.exceptions.CommandNotAppliedError`. A camera that refuses with
        code -502 wants ``confirm`` (the app's "set anyway?" dialog). Raises
        ``UnsupportedError`` for a model without presets or a slot the last read
        showed empty, and :class:`~.exceptions.DeviceBusyError` while a capture holds
        the camera (the turn would spoil its image).
        """
        channel = self._stored_slot(device_sn, preset)
        self._refuse_while_capturing(device_sn)
        await self.session.async_run_recipe(
            set_default_preset(preset, confirm=confirm),
            channel=channel,
            timeout=DEFAULT_PRESET_RESULT_WAIT,
        )
        await self.session.async_run_recipe(goto_preset(preset), channel=channel)
        slots = await self.async_refresh_presets(device_sn)
        if not any(s.index == preset and s.is_default for s in slots):
            raise CommandNotAppliedError(
                SubCommand.COMMAND_APP_SET_DEFAULT_POSITION,
                f"{redact_serial(device_sn)} did not make preset {preset} its default",
            )
        return slots

    def zoom(self, device_sn: str) -> float | None:
        """Camera ``device_sn``'s picture zoom as last reported (1.0 = 1x); None until it
        reports one. Kept from the camera's 6203 reports: the echo of
        :meth:`async_set_zoom` and the report after each go-to and live open. Set to 1.0
        when the session goes down: the camera is idle then, and idle resets the zoom.
        Changes are announced as :class:`~.events.ZoomChanged`."""
        return self._zooms.get(device_sn)

    async def async_set_zoom(self, device_sn: str, zoom: float) -> None:
        """Zoom camera ``device_sn``'s picture to ``zoom`` (1x-12x) about its centre.
        Wakes a battery camera.

        Returns at the camera's receipt; the camera echoes the zoom within about 0.1 s
        (:meth:`zoom`) and the picture follows within about 3 s, in a running live
        stream too. A T8170 streams from 2.5x up at a smaller size (2304x1296 instead
        of 2880x1616), so a live view's size changes when the zoom crosses 2x-2.5x.
        The zoom lasts while the camera is awake and in view: a go-to, the idle return
        to the default preset and a reopened live view each reset it to the preset's
        own zoom (1x for most). Send it while a view is open.

        Raises ``ValueError`` for a zoom outside :data:`~.devices.recipes.MIN_ZOOM`
        .. :data:`~.devices.recipes.MAX_ZOOM`, ``UnsupportedError`` for a model without
        zoom or a camera in dual view (param 6243), and
        :class:`~.exceptions.DeviceBusyError` while a capture holds the camera; nothing
        is sent for these.
        """
        if not (MIN_ZOOM <= zoom <= MAX_ZOOM):
            raise ValueError(f"zoom {zoom!r} is outside {MIN_ZOOM:g}..{MAX_ZOOM:g}")
        channel = self.channel_for(device_sn)
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_ZOOM) is Support.UNKNOWN:
            raise UnsupportedError(f"{redact_serial(device_sn)} has no picture zoom")
        view_mode = self.session.merged_params().devices.get(channel, {}).get(VIEW_MODE_PARAM)
        if json_int(view_mode) == DUAL_VIEW:
            raise UnsupportedError(f"{redact_serial(device_sn)} is in dual view; zoom needs single")
        self._refuse_while_capturing(device_sn)
        await self._ptz_recipe(set_picture_zoom(zoom), channel)

    def is_capturing(self, device_sn: str) -> bool:
        """Whether a live or preset image of ``device_sn`` is being taken (see
        :class:`~.events.CameraBusyChanged`)."""
        return device_sn in self._captures

    async def async_refresh_presets(self, device_sn: str) -> tuple[PresetPosition, ...]:
        """Read camera ``device_sn``'s preset slots from the camera. Wakes a battery camera.

        Stores them (:meth:`presets`) and emits :class:`~.events.PresetsChanged` when
        they differ from the last read. Raises ``UnsupportedError`` for a camera whose
        model has no pan/tilt presets.
        """
        channel = self._preset_channel(device_sn)
        reply = await self._ptz_recipe(query_preset_positions(), channel)
        slots = parse_preset_positions(reply.payload or {})
        self._store_presets(device_sn, slots)
        return slots

    # ── pan/tilt control ─────────────────────────────────────────────────────

    async def async_pan_tilt(
        self, device_sn: str, direction: PanTilt, *, settle: float | None = None
    ) -> None:
        """Move camera ``device_sn`` one step in ``direction``. Wakes a battery camera.

        The camera receipts the move and sends no result, so this waits ``settle``
        seconds (None: :data:`PTZ_SETTLE_SECONDS`) for it to finish rather than
        confirming anything. The new position
        lasts only while the camera is awake: once idle it returns to its default
        preset on its own (:meth:`default_preset`). Keep it with
        :meth:`async_save_preset` while the camera is still awake.

        Raises ``UnsupportedError`` for a model without pan/tilt control,
        :class:`~.exceptions.DeviceBusyError` while a capture holds the camera, and
        :class:`~.exceptions.CommandRejectedError` when the camera is still moving
        after :data:`PTZ_BUSY_ATTEMPTS` tries.
        """
        channel = self._ptz_channel(device_sn)
        self._refuse_while_capturing(device_sn)
        await self._ptz_recipe(pan_tilt(direction), channel)
        await _settle(settle, PTZ_SETTLE_SECONDS)

    async def async_goto_preset(
        self, device_sn: str, preset: int, *, settle: float | None = None
    ) -> None:
        """Turn camera ``device_sn`` to stored slot ``preset``. Wakes a battery camera.

        No image is taken and no stream is opened. The camera receipts the turn and
        sends no result, so this waits ``settle`` seconds (None:
        :data:`PRESET_SETTLE_SECONDS`) for it to stand still rather than confirming
        anything; ``settle=0`` returns at the receipt. A live stream of
        the camera keeps running across the turn. The position lasts only while the
        camera is awake: once idle (about 7 s without traffic) it returns to its default
        preset on its own, and a running live view keeps it awake.

        Raises ``UnsupportedError`` for a model without presets or a slot the last read
        showed empty, :class:`~.exceptions.DeviceBusyError` while a capture holds the
        camera, and :class:`~.exceptions.CommandRejectedError` when the camera is still
        moving after :data:`PTZ_BUSY_ATTEMPTS` tries; nothing is sent for the first two.
        """
        channel = self._stored_slot(device_sn, preset)
        self._refuse_while_capturing(device_sn)
        await self._ptz_recipe(goto_preset(preset), channel)
        await _settle(settle, PRESET_SETTLE_SECONDS)

    async def async_store_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]:
        """Store camera ``device_sn``'s current view in slot ``preset``, and read back.

        The camera receipts the write and sends no result, so the slots are read
        back and the write counts only when the slot shows as enabled:
        :class:`~.exceptions.CommandNotAppliedError` otherwise. A camera whose slots
        are **full stores nothing while still receipting the command** — a T8170 keeps
        at most :data:`~.devices.recipes.MAX_PRESET_SLOTS` — so free one with
        :meth:`async_delete_preset` first. ``confirm`` sends the app's
        "set anyway?" answer.

        Raises ``UnsupportedError`` for a model without pan/tilt control or a slot
        outside the camera's range, and :class:`~.exceptions.DeviceBusyError` while a
        capture holds the camera (the view is the capture's, not the one to keep);
        nothing is sent for these.
        """
        channel = self._ptz_channel(device_sn)
        self._check_slot(device_sn, preset)
        self._refuse_while_capturing(device_sn)
        await self._ptz_recipe(store_preset(preset, confirm=confirm), channel)
        slots = await self.async_refresh_presets(device_sn)
        if not any(s.index == preset and s.enabled for s in slots):
            raise self._not_stored(device_sn, preset, slots)
        return slots

    async def async_save_preset(
        self,
        device_sn: str,
        *,
        preset: int | None = None,
        make_default: bool = False,
        confirm: bool = False,
    ) -> PresetPosition:
        """Store camera ``device_sn``'s current view as a preset and return its slot,
        as read back. Wakes a battery camera.

        ``preset=None`` picks the lowest free slot (:meth:`free_preset`) from a fresh
        read, so a slot stored elsewhere since the last read is never overwritten. A
        named ``preset`` is stored as asked, in use or not (that it then holds the new
        view is not confirmed on hardware). ``make_default`` then makes the slot
        the default (:meth:`async_set_default_preset`); ``confirm`` is passed to both
        writes. Store the view while the camera is still awake at it (within a few
        seconds of :meth:`async_pan_tilt`, or while a live view runs): an idle camera
        is back at its default.

        Raises :class:`~.exceptions.CommandNotAppliedError` when the camera already
        holds :data:`~.devices.recipes.MAX_PRESET_SLOTS` slots (before sending, when
        the last read shows it) or the read-back does not show the store or the
        default; ``UnsupportedError`` for a model without presets or a slot outside
        the camera's range; :class:`~.exceptions.DeviceBusyError` while a capture
        holds the camera. Only the store and default writes change the camera.
        """
        self._preset_channel(device_sn)
        self._ptz_channel(device_sn)
        if preset is not None:
            self._check_slot(device_sn, preset)
        self._refuse_while_capturing(device_sn)
        known = self.presets(device_sn)
        if known is not None and self._is_full(known, preset):
            raise self._not_stored(device_sn, preset, known)
        if preset is None:
            known = await self.async_refresh_presets(device_sn)
            preset = free_preset_slot(known)
            if preset is None:
                raise self._not_stored(device_sn, None, known)
        slots = await self.async_store_preset(device_sn, preset, confirm=confirm)
        if make_default:
            slots = await self.async_set_default_preset(device_sn, preset, confirm=confirm)
        return next(s for s in slots if s.index == preset)

    def free_preset(self, device_sn: str) -> int | None:
        """The slot :meth:`async_save_preset` would store into, from the last read of
        :meth:`presets`; None when never read or when no slot can take a store (the
        camera holds :data:`~.devices.recipes.MAX_PRESET_SLOTS`). No I/O."""
        slots = self.presets(device_sn)
        return None if slots is None else free_preset_slot(slots)

    @staticmethod
    def _is_full(slots: Sequence[PresetPosition], preset: int | None) -> bool:
        """Whether a store into ``preset`` (None: a free slot) cannot take: the camera
        holds the most it stores and ``preset`` is not one of them."""
        stored = {s.index for s in slots if s.enabled}
        return len(stored) >= MAX_PRESET_SLOTS and preset not in stored

    def _not_stored(
        self, device_sn: str, preset: int | None, slots: Sequence[PresetPosition]
    ) -> CommandNotAppliedError:
        """The error for a store that did not take (or cannot), naming a full camera.

        A camera at :data:`~.devices.recipes.MAX_PRESET_SLOTS` yields
        :class:`~.exceptions.PresetSlotsFullError` so a consumer can tell a full
        camera from a genuine not-applied store without re-deriving the rule.
        """
        stored = [s.index for s in slots if s.enabled]
        full = len(stored) >= MAX_PRESET_SLOTS
        hint = (
            f" (the camera already holds {MAX_PRESET_SLOTS} slots; delete one first)"
            if full
            else ""
        )
        target = "a preset" if preset is None else f"preset {preset}"
        message = (
            f"{redact_serial(device_sn)} did not store {target}{hint} (slots in use: {stored})"
        )
        if full:
            return PresetSlotsFullError(
                SubCommand.COMMAND_INDOOR_SPAN_SET_POINT,
                message,
                slots=MAX_PRESET_SLOTS,
                in_use=tuple(stored),
            )
        return CommandNotAppliedError(SubCommand.COMMAND_INDOOR_SPAN_SET_POINT, message)

    async def async_delete_preset(self, device_sn: str, preset: int) -> tuple[PresetPosition, ...]:
        """Clear slot ``preset`` of camera ``device_sn``, and read the slots back.

        Clearing the default slot clears its default flag too: :meth:`default_preset`
        is None until :meth:`async_set_default_preset` names another slot.

        Raises :class:`~.exceptions.CommandNotAppliedError` when the read-back still
        shows the slot in use, and ``UnsupportedError`` for a model without pan/tilt
        control or a slot outside the camera's range.
        """
        channel = self._ptz_channel(device_sn)
        self._check_slot(device_sn, preset)
        await self._ptz_recipe(delete_preset(preset), channel)
        slots = await self.async_refresh_presets(device_sn)
        if any(s.index == preset and s.enabled for s in slots):
            raise CommandNotAppliedError(
                SubCommand.COMMAND_INDOOR_SPAN_DEL_POINT,
                f"{redact_serial(device_sn)} still holds preset {preset}",
            )
        return slots

    async def async_preset_picture(self, device_sn: str, preset: int) -> bytes | None:
        """The JPEG camera ``device_sn`` stored for slot ``preset``, or None when empty.

        The camera's own thumbnail of the slot, taken when the slot was stored — it
        shows the slot's view without turning the camera there. Wakes a battery camera
        but does not move it. Raises ``UnsupportedError`` for a model without pan/tilt
        control or a slot outside the camera's range.
        """
        channel = self._ptz_channel(device_sn)
        self._check_slot(device_sn, preset)
        reply = await self._ptz_recipe(preset_picture(preset), channel)
        data = decode_preset_picture(reply.payload or {})
        return data or None

    def _check_slot(self, device_sn: str, preset: int) -> None:
        """Refuse a slot the camera does not have, before anything is sent.

        The slot range and the store limit are different numbers: a T8170 offers ten
        slot indices (0-9) but stores at most :data:`~.devices.recipes.MAX_PRESET_SLOTS`
        of them at a time. Only the range can be checked up front; a store beyond the
        limit is caught by the read-back.
        """
        known = self.presets(device_sn)
        if known and not any(s.index == preset for s in known):
            raise UnsupportedError(
                f"{redact_serial(device_sn)} has no preset slot {preset} "
                f"(slots 0-{max(s.index for s in known)})"
            )
        if preset < 0:
            raise UnsupportedError(f"preset {preset} is not a slot number")

    async def _ptz_recipe(self, recipe: Recipe, channel: int) -> RecipeReply:
        """Run a preset/pan-tilt recipe, re-sending while the camera answers "busy".

        A camera that is still moving rejects the next preset command with receipt
        code :data:`PTZ_BUSY_CODE` (verified on a T8170: a 6034 read right after a
        6032 store). That is a transient state, not a failure, so it is retried;
        anything else propagates.
        """
        for attempt in range(PTZ_BUSY_ATTEMPTS):
            try:
                return await self.session.async_run_recipe(recipe, channel=channel)
            except CommandRejectedError as err:
                if err.code != PTZ_BUSY_CODE or attempt + 1 == PTZ_BUSY_ATTEMPTS:
                    raise
                _LOGGER.debug(
                    "%s: %s: the camera is still moving (code %d), retrying",
                    self._log_name,
                    recipe.identifier,
                    err.code,
                )
                await asyncio.sleep(PTZ_BUSY_DELAY)
        raise AssertionError("unreachable")  # pragma: no cover

    def _ptz_channel(self, device_sn: str) -> int:
        """``device_sn``'s channel, after checking its model has pan/tilt control."""
        channel = self.channel_for(device_sn)
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_CONTROL) is Support.UNKNOWN:
            raise UnsupportedError(f"{redact_serial(device_sn)} has no pan/tilt control")
        return channel

    async def async_preset_image(
        self, device_sn: str, preset: int, *, settle: float | None = None, wait: bool = False
    ) -> CameraImage:
        """A live image of camera ``device_sn`` turned to preset slot ``preset``.

        Turns the camera, opens live video at once (a battery camera sleeps about 7 s
        after its last traffic, so the stream keeps it awake while it turns), and keeps
        the first keyframe that arrives ``settle`` seconds after the open (None:
        :data:`PRESET_SETTLE_SECONDS`). The camera stays at the preset only
        while it is awake: once idle it returns to its default slot on its own
        (:meth:`default_preset`, :meth:`async_set_default_preset`).

        One capture holds a camera at a time: a call for the same preset while one runs
        gets that capture's image; any other capture of the camera raises
        :class:`~.exceptions.DeviceBusyError` at once, before anything is sent
        (:class:`~.events.CameraBusyChanged` reports the state). Raises
        ``UnsupportedError`` for a model without presets, or for a slot the last read
        showed empty. The live open is :meth:`async_open_live`'s: past the session budget
        it raises :class:`~.exceptions.LiveStreamLimitError` at once (the default), or
        with ``wait`` waits up to the first-frame timeout for a stream to end.
        """
        channel = self._stored_slot(device_sn, preset)

        async def capture() -> CameraImage:
            await self.session.async_run_recipe(goto_preset(preset), channel=channel)
            data = await self._settled_keyframe(
                channel, PRESET_SETTLE_SECONDS if settle is None else settle, wait=wait
            )
            await self._refresh_presets_while_awake(device_sn)
            return CameraImage(
                source=ImageSource.LIVE,
                device_sn=device_sn,
                data=data,
                content_type=HEVC_CONTENT_TYPE,
                preset=preset,
            )

        return await self._run_capture(device_sn, preset, capture)

    async def _settled_keyframe(self, channel: int, settle: float, *, wait: bool) -> bytes:
        """The first keyframe of live video that arrives ``settle`` seconds from now.

        A keyframe from before then may show the camera still turning, so none is
        returned instead: a stream that ends first raises ``DeviceTimeoutError``.
        """
        deadline = time.monotonic() + settle
        stream = await self.session.async_open_live(
            channel, idle_timeout=max(PRESET_STREAM_IDLE_SECONDS, settle), wait=wait
        )
        async with stream:
            async for frame in stream:
                if frame.is_keyframe and time.monotonic() >= deadline:
                    return frame.data
        raise DeviceTimeoutError(f"the stream ended before the camera settled ({settle:g}s)")

    async def _run_capture(
        self,
        device_sn: str,
        preset: int | None,
        capture: Callable[[], Coroutine[Any, Any, CameraImage]],
    ) -> CameraImage:
        """Run ``capture`` as the one capture holding ``device_sn``: join the running one
        when it is the same (live, or the same preset), else raise ``DeviceBusyError``."""
        running = self._captures.get(device_sn)
        if running is not None and running.preset == preset:
            return await asyncio.shield(running.task)
        self._refuse_while_capturing(device_sn)
        task = asyncio.get_running_loop().create_task(
            capture(), name=f"eufy-security-capture-{self._log_name}"
        )
        self._captures[device_sn] = _Capture(preset=preset, task=task)
        self._bus.emit(CameraBusyChanged(station_sn=self.serial, device_sn=device_sn, busy=True))

        def release(_task: asyncio.Task[CameraImage]) -> None:
            if self._captures.get(device_sn) is not None and self._captures[device_sn].task is task:
                del self._captures[device_sn]
                self._bus.emit(
                    CameraBusyChanged(station_sn=self.serial, device_sn=device_sn, busy=False)
                )

        task.add_done_callback(release)
        return await asyncio.shield(task)

    def _refuse_while_capturing(self, device_sn: str) -> None:
        """Raise ``DeviceBusyError`` when a capture holds ``device_sn``: a command that
        turns the camera would spoil the image being taken."""
        running = self._captures.get(device_sn)
        if running is not None:
            raise DeviceBusyError(
                f"{redact_serial(device_sn)} is busy with "
                + ("a live image" if running.preset is None else f"preset {running.preset}")
            )

    def _stored_slot(self, device_sn: str, preset: int) -> int:
        """``device_sn``'s channel, after checking its model has presets and ``preset``
        is not a slot the last read showed empty; nothing is sent."""
        channel = self._preset_channel(device_sn)
        known = self.presets(device_sn)
        if known is not None and not any(s.index == preset and s.enabled for s in known):
            raise UnsupportedError(f"preset {preset} is not set on {redact_serial(device_sn)}")
        return channel

    def _preset_channel(self, device_sn: str) -> int:
        """``device_sn``'s channel, after checking its model has pan/tilt presets."""
        channel = self.channel_for(device_sn)
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_PRESETS) is Support.UNKNOWN:
            raise UnsupportedError(f"{redact_serial(device_sn)} has no pan/tilt presets")
        return channel

    async def _refresh_presets_while_awake(self, device_sn: str) -> None:
        """Re-read the presets of a pan/tilt camera that is awake anyway (best effort)."""
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_PRESETS) is Support.UNKNOWN:
            return
        try:
            await self.async_refresh_presets(device_sn)
        except EufySecurityError as err:
            _LOGGER.debug("%s: preset read while awake failed: %s", self._log_name, err)

    def _store_presets(self, device_sn: str, slots: tuple[PresetPosition, ...]) -> None:
        if self.presets(device_sn) == slots:
            return
        self._presets[device_sn] = slots
        if self._cache is not None:
            self._cache.set_presets(
                self.serial,
                device_sn,
                [
                    {
                        "index": s.index,
                        "enable": int(s.enabled),
                        "zoom": s.zoom,
                        "isdefault": int(s.is_default),
                    }
                    for s in slots
                ],
            )
            self._cache.schedule_save()
        _LOGGER.debug(
            "%s: presets of %s: %s enabled",
            self._log_name,
            redact_serial(device_sn),
            [s.index for s in slots if s.enabled],
        )
        self._bus.emit(PresetsChanged(station_sn=self.serial, device_sn=device_sn, presets=slots))

    def _event_camera(self, event: SecurityEvent) -> tuple[str, int]:
        """The paired camera an event names: its ``device_sn``, else its ``channel``; on a
        standalone camera, the camera itself."""
        if event.device_sn == self.serial and (own := own_channel(self.device)) is not None:
            return self.serial, own
        by_serial = {d.device_sn: d.channel for d in self.devices}
        by_channel = {d.channel: d.device_sn for d in self.devices}
        if event.device_sn is not None and by_serial.get(event.device_sn) is not None:
            return event.device_sn, cast(int, by_serial[event.device_sn])
        if event.channel is not None and event.channel in by_channel:
            return by_channel[event.channel], event.channel
        raise UnsupportedError("the event names no camera paired to this station")

    def _require_own_event(self, event: SecurityEvent) -> None:
        if event.station_sn is not None and event.station_sn != self.serial:
            raise UnsupportedError(
                f"the event belongs to {redact_serial(event.station_sn)}, not {self._log_name}"
            )

    def _media_channel(self, device_sn: str | None, channel: int | None) -> int:
        if channel is not None and device_sn is None:
            return channel
        if device_sn is not None and channel is None:
            return self.channel_for(device_sn)
        raise ValueError("pass exactly one of device_sn or channel")

    async def async_query_events(
        self,
        start_date: str,
        end_date: str,
        *,
        device_sns: Sequence[str] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """The station's own event records between two ``YYYYMMDD`` dates."""
        sns = list(device_sns) if device_sns is not None else [d.device_sn for d in self.devices]
        return await self.session.async_query_events(sns, start_date, end_date, **kwargs)

    async def async_get_storage(self, *, timeout: float | None = None) -> StorageInfo:
        """Read the storage record: internal disk, external disk and eMMC figures.

        Read-only (the app's HDD screen). On a standalone camera (a T8170), which does
        not answer the HomeBase storage record, this reads its built-in eMMC through
        ``SDINFO_EX`` (``1144``) instead, so :attr:`~.p2p.storage_info.StorageInfo.emmc`
        alone is set. Wakes a battery camera. The result is also kept as :attr:`storage`.
        """
        if self.session.standalone:
            return await self.session.async_get_sd_info(timeout=timeout)
        return await self.session.async_get_storage(timeout=timeout)

    @property
    def storage(self) -> StorageInfo | None:
        """The last storage record read or pushed; None until one arrived.

        The station pushes a record when a format finishes and whenever another client
        reads it, each announced as :class:`~.events.StorageChanged`.
        """
        return self.session.storage

    async def async_list_history(
        self, start_date: str, end_date: str | None = None, **kwargs: Any
    ) -> list[HistoryRecord]:
        """History records across all devices from ``start_date`` to ``end_date``
        (``YYYYMMDD``, both included), newest first; paged like the app (see
        :meth:`~.p2p.session.StationSession.async_list_history`)."""
        return await self.session.async_list_history(start_date, end_date, **kwargs)

    async def async_history_record(self, record_id: int) -> HistoryRecord | None:
        """The history row of one ``record_id`` (one query), or None when the station has
        none. Raises :class:`~.exceptions.UnsupportedError`, before sending, on a
        standalone device (it lists no history) and for an id that carries no day."""
        if self.is_standalone:
            raise UnsupportedError("a standalone device lists no history")
        if record_id_day(record_id) is None:
            raise UnsupportedError(f"record_id {record_id} carries no day")
        return await self.session.async_history_record(record_id)

    async def async_list_recordings(
        self,
        device_sn: str | None = None,
        *,
        days: int = RECORDINGS_DAYS,
        since: datetime | None = None,
        limit: int | None = None,
        before: int | None = None,
        until: date | None = None,
        timeout: float | None = None,
    ) -> list[HistoryRecord]:
        """The recordings on the station's disk, newest first: the history rows with a
        valid :attr:`~.events.HistoryRecord.video_path`, of ``device_sn`` (None: every
        camera paired here).

        Covers today and ``days - 1`` days back (the host's days; stations keep local
        time), one history query per day and page; with ``since``, only rows that
        started at or after it, and days before its day are not asked. The camera is not
        woken. A standalone device lists no recordings: an empty list.

        Pages: ``limit`` stops the walk as soon as that many rows are found, so only
        the days (and pages) up to the last row are asked; ``before`` (the
        ``record_id`` of the previous page's last row) starts below that row, in its
        day. A page shorter than ``limit`` means the window holds no more; a full page
        may be followed by an empty one. ``until`` starts the walk at that day: its rows
        and older ones (a later day counts as today; a ``datetime`` as its host-local
        day). ``days`` still counts back from today, so an ``until`` before the window
        lists nothing. ``before`` wins over ``until``. Raises :class:`ValueError`,
        before anything is sent, for ``days`` or ``limit`` below 1 and a ``before``
        that carries no day (:func:`~.p2p.messages.record_id_day`).

        ``timeout`` bounds each history query (None:
        :data:`~.p2p.session.HISTORY_QUERY_TIMEOUT`); an unanswered one is asked once
        more, then :class:`~.exceptions.DeviceTimeoutError` is raised.

        A detection's row exists while its clip still records: download a row once
        :meth:`recording_settled` says so.
        """
        if days < 1:
            raise ValueError("days must be at least 1")
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1")
        cursor_day = None if before is None else record_id_day(before)
        if before is not None and cursor_day is None:
            raise ValueError(f"before {before} carries no day")
        if device_sn is not None:
            self.channel_for(device_sn)  # raises for a device not paired here
        if self.is_standalone:
            return []
        paired = {d.device_sn for d in self.devices}
        today = datetime.now().astimezone().date()
        first = today - timedelta(days=days - 1)
        if since is not None:
            first = max(first, since.astimezone().date())
        if cursor_day is not None:
            last = min(today, cursor_day)
        elif until is not None:
            until_day = until.astimezone().date() if isinstance(until, datetime) else until
            last = min(today, until_day)
        else:
            last = today
        if first > last:
            return []

        def wanted(row: HistoryRecord) -> bool:
            if row.video_path is None or row.device_sn is None:
                return False
            if device_sn is not None and row.device_sn != device_sn:
                return False
            if device_sn is None and row.device_sn not in paired:
                return False
            if since is not None:
                started = row.started_at
                return started is not None and started >= since
            return True

        return await self.session.async_list_history(
            first.strftime("%Y%m%d"),
            last.strftime("%Y%m%d"),
            count=limit,
            before=before if cursor_day is not None and cursor_day <= last else None,
            keep=wanted,
            timeout=timeout,
        )

    @staticmethod
    def recording_settled(
        record: HistoryRecord, *, now: datetime | None = None, quiet: float = RECORDING_QUIET
    ) -> bool:
        """Whether ``record``'s clip looks finished: its end time lies ``quiet`` seconds
        (:data:`RECORDING_QUIET`) in the past. A row without times is not.

        A detection's row exists while its clip still records, so download only settled
        rows; :meth:`async_download_recording` reads the row again afterwards and
        :attr:`~.p2p.clip.MediaClip.complete` is False when it gained frames meanwhile.
        """
        ended = record.ended_at
        if ended is None:
            return False
        current = now if now is not None else datetime.now(ended.tzinfo)
        return (current - ended).total_seconds() >= quiet

    async def async_download_recording(
        self, record: HistoryRecord, write: ClipWriter, *, wait: bool = True
    ) -> MediaClip:
        """Download a history record's recording as one MPEG-TS clip into ``write``.

        The station plays it off its disk on an extra session (the camera is not woken;
        see :meth:`~.p2p.session.StationSession.async_download_recording`): about as fast
        as it was recorded or faster, the original HEVC and AAC untouched. The clip
        carries the record's ``started_at``, ``record_id`` and its frame count, so
        :attr:`~.p2p.clip.MediaClip.complete` says whether everything arrived.

        Raises :class:`~.exceptions.UnsupportedError`, before anything is sent, for a
        record without a valid recording path, of a device not paired here, or on a
        standalone device; :class:`~.exceptions.LiveStreamLimitError` past the session
        budget (with ``wait``, after waiting for a stream to end); otherwise what the
        playback raises.
        """
        path = record.video_path
        if path is None:
            raise UnsupportedError("the record carries no recording")
        if record.device_sn is None:
            raise UnsupportedError("the record names no camera")
        channel = self.channel_for(record.device_sn)
        clip = await self.session.async_download_recording(path, channel, write, wait=wait)
        # Read the row again: a clip still recording when the download began has more
        # frames now than were delivered, and then the clip is not complete.
        expected = record.frame_count
        if record.record_id and record_id_day(record.record_id) is not None:
            with contextlib.suppress(EufySecurityError):
                fresh = await self.session.async_history_record(record.record_id)
                if fresh is not None and fresh.frame_count is not None:
                    expected = max(expected or 0, fresh.frame_count)
        return replace(
            clip,
            started_at=record.started_at,
            device_sn=record.device_sn,
            record_id=record.record_id or None,
            expected_frames=expected,
        )
