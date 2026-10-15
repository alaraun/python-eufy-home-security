"""A station's configuration as one read model (pure).

:func:`build_station_config` turns a :class:`~.station.StationState` into a
:class:`StationConfig`: the guard modes the station has, with their names, the mode
tables, the schedule, cross-camera tracking and the alarm and time settings, each with
the source it came from and one :attr:`StationConfig.revision` over all of it.
:meth:`~.station.Station.async_get_config` is the call that reads it; see
``docs/how-to/home-assistant.md`` § Station configuration.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import time
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from .devices.settings import MOTION_SENSOR_DEVICE_TYPES
from .devices.timezones import TIMEZONE_DOMAIN
from .devices.types import model_for_serial
from .exceptions import ConfigChangedError, ProtocolError, UnsupportedError
from .models import GuardMode, ValueSource
from .p2p.mode_actions import (
    ACTION_FLAGS,
    MODE_ACTION_INVERTED,
    MODE_TABLE_MODES,
    mode_action_on,
    mode_table_from_params,
)
from .p2p.params import ACTIVE_MODE_PARAM, GUARD_MODE_PARAM
from .p2p.station_config_codecs import (
    CMD_CUSTOM_MODES,
    CMD_SCHEDULE,
    CMD_SCHEDULE_DEFAULT,
    CUSTOM_MODES,
    PARAM_TRACKING_CAMERAS,
    PARAM_TRACKING_GROUPS,
    STORED_MODE_TABLE_PARAMS,
    CustomModes,
    Schedule,
    decode_custom_modes,
    decode_schedule,
    decode_schedule_default,
    decode_stored_mode_table,
    decode_tracking_cameras,
    decode_tracking_groups,
)

if TYPE_CHECKING:
    from .devices.model_settings import Value
    from .station import StationState

__all__ = [
    "MODE_ORDER",
    "CrossCameraConfig",
    "ModeDeviceAction",
    "ModeInfo",
    "ModeTableView",
    "StationConfig",
    "build_station_config",
    "changed_fields",
    "check_revision",
    "guard_mode_label",
]

MODE_ORDER: Final[tuple[GuardMode, ...]] = (
    GuardMode.HOME,
    GuardMode.AWAY,
    GuardMode.OFF,
    *CUSTOM_MODES,
    GuardMode.DISARMED,
    GuardMode.SCHEDULE,
    GuardMode.GEOFENCE,
)
"""The order the eufy app lists the guard modes in."""

_REVISION_BITS: Final = 53
"""A revision fits a JSON number exactly (JavaScript's safe integer range)."""

_SETTING_PARAMS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "alarm_volume": 1235,
        "alarm_tone": 1281,
        "time_format": 1253,
        "working_mode": 1296,
        "cross_camera.enabled": 1065,
        "cross_camera.assistance": 1069,
        "cross_camera.continuous_time": 1070,
    }
)
"""Config fields read from a station setting, by the setting's read parameter."""
_TIME_ZONE: Final = "time_zone"


def guard_mode_label(mode: GuardMode | int) -> str:
    """The display name of ``mode`` (:attr:`GuardMode.label`); ``"Mode <code>"`` for a code
    :class:`GuardMode` does not name. A custom mode's own title comes from
    :attr:`StationConfig.modes`."""
    try:
        return GuardMode(mode).label
    except ValueError:
        return f"Mode {int(mode)}"


@dataclass(frozen=True, slots=True, kw_only=True)
class ModeInfo:
    """One guard mode the station has."""

    code: GuardMode | int
    """The guard-mode code (param 1224); a plain int for a code :class:`GuardMode` does
    not name."""
    name: str
    """The display name: a custom mode's own title, else :func:`guard_mode_label`."""
    icon: int | None
    """The mode list's ``iconType`` for this mode; None when the list does not carry it."""
    custom: bool
    """Whether the user added the mode (Custom 1-3)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ModeDeviceAction:
    """One paired device's entry in a mode table."""

    channel: int
    device_sn: str | None
    """The device's cloud serial; None when the cloud lists none on :attr:`channel`."""
    action: int
    """The action bitmask (:data:`~.p2p.mode_actions.ACTION_FLAGS`)."""
    alarm_delay: int
    """Seconds between a trigger and the alarm (entry delay); 0 is off."""
    leaving_delay: int
    """Seconds between arming and the mode taking effect (exit delay); 0 is off."""

    @property
    def flags(self) -> frozenset[str]:
        """The names of the actions on in :attr:`action` (:func:`~.p2p.mode_actions.mode_action_on`):
        a bit set, or, for a catalogued motion sensor only, ``motion_sensor_respond``
        while its bit is clear (:data:`~.p2p.mode_actions.MODE_ACTION_INVERTED`)."""
        model = model_for_serial(self.device_sn) if self.device_sn else None
        motion = model is not None and model.cloud_device_type in MOTION_SENSOR_DEVICE_TYPES
        return frozenset(
            name
            for name in ACTION_FLAGS
            if (motion or name not in MODE_ACTION_INVERTED) and mode_action_on(name, self.action)
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ModeTableView:
    """What each paired device does in one guard mode, by channel."""

    mode: GuardMode
    devices: tuple[ModeDeviceAction, ...]
    """One entry per device of the table, by channel."""

    def device(self, device_sn: str) -> ModeDeviceAction | None:
        """The entry of the device with cloud serial ``device_sn``, if the table has it."""
        return next((d for d in self.devices if d.device_sn == device_sn), None)


@dataclass(frozen=True, slots=True, kw_only=True)
class CrossCameraConfig:
    """Cross-camera tracking: the three switches and the cameras and groups it uses."""

    enabled: bool | None
    assistance: bool | None
    continuous_time: Value | None
    """The setting's public value; :attr:`StationConfig.setting_keys` names the setting
    whose ``labels`` show it."""
    cameras: tuple[str, ...] | None
    """The serials chosen for tracking (param 1072); None means every camera."""
    groups: tuple[tuple[str, ...], ...]
    """The tracking groups (param 1073), each a tuple of serials."""


@dataclass(frozen=True, slots=True, kw_only=True)
class StationConfig:
    """A station's configuration at one :attr:`revision`.

    A field the station does not report is None (an absent mode table, schedule or
    setting); nothing is invented. :attr:`sources` says where each reported value came
    from, :attr:`unreadable` which values could not be decoded.
    """

    revision: int
    """Changes whenever any other field changes; equal configs have equal revisions,
    across processes too. Pass it as ``expect_revision`` to a write."""
    modes: tuple[ModeInfo, ...]
    """The defined modes in the app's order (:data:`MODE_ORDER`); see :meth:`is_defined`
    for the rule."""
    settable_modes: tuple[GuardMode, ...]
    """The defined modes :meth:`~.station.Station.async_set_guard_mode` writes: every
    defined mode except Off, which is report-only."""
    guard_mode: GuardMode | int | None
    """The selected mode (param 1224); None before the station reports it."""
    effective_mode: GuardMode | int | None
    """The mode in force (param 1151): a schedule slot's mode while Schedule is
    selected, else :attr:`guard_mode`."""
    mode_tables: Mapping[GuardMode, ModeTableView | None]
    """Each defined mode that has a table (Home, Away, Custom 1-3, Disarmed) → its table;
    None where the station reports none."""
    schedule: Schedule | None
    """The weekly schedule (param 1254); None when no source carries it."""
    schedule_default: GuardMode | None
    """The mode outside every schedule slot (param 1257)."""
    cross_camera: CrossCameraConfig | None
    """None when the model has no cross-camera setting and no source carries the lists."""
    alarm_volume: Value | None
    alarm_tone: Value | None
    time_zone: Value | None
    time_format: Value | None
    working_mode: Value | None
    setting_keys: Mapping[str, str]
    """Field (``alarm_tone``, ``cross_camera.enabled``, ...) → the station setting it
    reads, for its labels and its write (:meth:`~.station.Station.async_set_setting`)."""
    sources: Mapping[str, ValueSource]
    """Field → where its value came from, for every field with a value. Mode tables are
    keyed ``mode_tables.<mode>`` (``mode_tables.custom_1``)."""
    unreadable: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    """Field → why a value a source carries could not be decoded; the field falls back to
    the next source, else None."""

    def mode(self, code: GuardMode | int) -> ModeInfo | None:
        """The defined mode with ``code``; None when the station does not have it."""
        return next((m for m in self.modes if m.code == code), None)

    def is_defined(self, code: GuardMode | int) -> bool:
        """Whether the station has mode ``code``, as the eufy app lists it.

        Home, Away and Disarmed always. Custom 1-3 when the mode list (param 1256)
        lists them, or while the station reports one as its mode. Schedule when the
        schedule has a slot or Schedule is selected. Geofencing while it is selected,
        Off while the station reports it (current or in force): the library cannot see
        whether either is offered otherwise.
        """
        return self.mode(code) is not None

    def mode_name(self, code: GuardMode | int) -> str:
        """The display name of ``code``: a defined mode's name, else :func:`guard_mode_label`."""
        info = self.mode(code)
        return info.name if info is not None else guard_mode_label(code)


# ── build ────────────────────────────────────────────────────────────────────


def build_station_config(state: StationState) -> StationConfig:
    """The :class:`StationConfig` of ``state``. No I/O.

    Station values come from :attr:`~.station.StationState.setting_params` (the P2P
    dump, then the cloud's copy) with their :attr:`~.station.StationState.param_sources`;
    a mode table from the paired devices' per-mode parameters in the dump, else from its
    stored parameter (1157-1161, 1177) where a source carries it.
    """
    sources: dict[str, ValueSource] = {}
    unreadable: dict[str, str] = {}

    def decode[T](name: str, pid: int, decoder: Callable[[Any], T]) -> T | None:
        raw, source = _param(state, pid)
        if raw is None:
            return None
        try:
            value = decoder(raw)
        except ProtocolError as err:
            unreadable[name] = str(err)
            return None
        if value is not None and source is not None:
            sources[name] = source
        return value

    custom_modes = decode("modes", CMD_CUSTOM_MODES, decode_custom_modes)
    if custom_modes is None:
        sources["modes"] = ValueSource.APP_DEFAULT
    schedule = decode("schedule", CMD_SCHEDULE, decode_schedule)
    schedule_default = decode("schedule_default", CMD_SCHEDULE_DEFAULT, decode_schedule_default)
    guard_mode, active_mode = state.guard_mode, state.active_mode
    for name, pid, value in (
        ("guard_mode", GUARD_MODE_PARAM, guard_mode),
        ("effective_mode", ACTIVE_MODE_PARAM, active_mode),
    ):
        if value is not None:
            sources[name] = state.param_sources.get(pid, ValueSource.P2P)

    modes = _defined_modes(custom_modes, schedule, (guard_mode, active_mode))
    # Off is report-only; geofencing follows the phones running the eufy app.
    settable = tuple(
        m.code
        for m in modes
        if isinstance(m.code, GuardMode) and m.code not in (GuardMode.OFF, GuardMode.GEOFENCE)
    )
    defined = [m.code for m in modes if isinstance(m.code, GuardMode)]
    mode_tables = {
        mode: _mode_table(state, mode, sources, unreadable)
        for mode in defined
        if mode in STORED_MODE_TABLE_PARAMS or mode in MODE_TABLE_MODES
    }

    setting_keys = _setting_keys(state)
    values: dict[str, Value | None] = {}
    for name, key in setting_keys.items():
        values[name], source = state.setting(key), state.setting_source(key)
        if source is not None:
            sources[name] = source

    cameras = decode("cross_camera.cameras", PARAM_TRACKING_CAMERAS, decode_tracking_cameras)
    groups = decode("cross_camera.groups", PARAM_TRACKING_GROUPS, decode_tracking_groups)
    cross_camera = None
    if any(n.startswith("cross_camera.") for n in (*setting_keys, *sources)):
        enabled, assistance = (
            values.get("cross_camera.enabled"),
            values.get("cross_camera.assistance"),
        )
        cross_camera = CrossCameraConfig(
            enabled=enabled if isinstance(enabled, bool) else None,
            assistance=assistance if isinstance(assistance, bool) else None,
            continuous_time=values.get("cross_camera.continuous_time"),
            cameras=cameras,
            groups=groups or (),
        )

    content: dict[str, Any] = {
        "modes": modes,
        "settable_modes": settable,
        "guard_mode": guard_mode,
        "effective_mode": active_mode,
        "mode_tables": MappingProxyType(mode_tables),
        "schedule": schedule,
        "schedule_default": schedule_default,
        "cross_camera": cross_camera,
        "alarm_volume": values.get("alarm_volume"),
        "alarm_tone": values.get("alarm_tone"),
        "time_zone": values.get(_TIME_ZONE),
        "time_format": values.get("time_format"),
        "working_mode": values.get("working_mode"),
        "setting_keys": MappingProxyType(setting_keys),
        "sources": MappingProxyType(sources),
        "unreadable": MappingProxyType(unreadable),
    }
    return StationConfig(revision=_revision(content), **content)


def _param(state: StationState, pid: int) -> tuple[str | None, ValueSource | None]:
    if state.setting_params.get(pid) is None:
        return None, None
    return state.setting_params[pid], state.param_sources.get(pid, ValueSource.P2P)


def _defined_modes(
    custom_modes: CustomModes | None,
    schedule: Schedule | None,
    reported: tuple[GuardMode | int | None, GuardMode | int | None],
) -> tuple[ModeInfo, ...]:
    """The modes the app lists (see :meth:`StationConfig.is_defined`), in its order."""
    in_use = {m for m in reported if m is not None}
    listed = {e.mode: e for e in custom_modes.modes} if custom_modes is not None else {}
    out: list[ModeInfo] = []
    for mode in MODE_ORDER:
        entry = listed.get(mode)
        custom = mode in CUSTOM_MODES
        if custom:
            defined = entry is not None or mode in in_use
        elif mode is GuardMode.SCHEDULE:
            defined = bool(schedule is not None and schedule.slots) or mode in in_use
        elif mode in (GuardMode.OFF, GuardMode.GEOFENCE):
            defined = mode in in_use
        else:
            defined = True
        if not defined:
            continue
        title = entry.title.strip() if custom and entry is not None else ""
        out.append(
            ModeInfo(
                code=mode,
                name=title or mode.label,
                icon=entry.icon_type if entry is not None else None,
                custom=custom,
            )
        )
    out.extend(
        ModeInfo(code=code, name=guard_mode_label(code), icon=None, custom=False)
        for code in sorted(c for c in in_use if c not in MODE_ORDER)
    )
    return tuple(out)


def _mode_table(
    state: StationState,
    mode: GuardMode,
    sources: dict[str, ValueSource],
    unreadable: dict[str, str],
) -> ModeTableView | None:
    name = f"mode_tables.{mode.name.lower()}"
    serials = {ch: d.serial for ch, d in state.devices.items()}
    # The devices' own per-mode parameters first: a write's read-back updates them at
    # once, while the stored copy in the cloud list lags until the next list fetch.
    if mode in MODE_TABLE_MODES:
        blocks = {ch: d.params for ch, d in state.devices.items()}
        try:
            table = mode_table_from_params(blocks, mode)
        except (UnsupportedError, ValueError) as err:
            unreadable[name] = str(err)
        else:
            if table.actions:
                sources[name] = ValueSource.P2P
                return _view(mode, table.actions, table.alarm_delays, table.leaving_delays, serials)
    pid = STORED_MODE_TABLE_PARAMS.get(mode)
    raw, source = _param(state, pid) if pid is not None else (None, None)
    if raw is None:
        return None
    try:
        stored = decode_stored_mode_table(raw, mode)
    except ProtocolError as err:
        unreadable[name] = str(err)
        return None
    if stored is None or source is None:
        return None
    sources[name] = source
    return _view(mode, stored.actions, stored.alarm_delays(), stored.leaving_delays(), serials)


def _view(
    mode: GuardMode,
    actions: Mapping[int, int],
    alarm: Mapping[int, int],
    leaving: Mapping[int, int],
    serials: Mapping[int, str | None],
) -> ModeTableView:
    return ModeTableView(
        mode=mode,
        devices=tuple(
            ModeDeviceAction(
                channel=channel,
                device_sn=serials.get(channel),
                action=actions[channel],
                alarm_delay=alarm.get(channel, 0),
                leaving_delay=leaving.get(channel, 0),
            )
            for channel in sorted(actions)
        ),
    )


def _setting_keys(state: StationState) -> dict[str, str]:
    """Field → the readable station setting that reads its parameter."""
    out: dict[str, str] = {}
    for key, setting in state.settings.items():
        if not setting.readable:
            continue
        if setting.domain == TIMEZONE_DOMAIN:
            out.setdefault(_TIME_ZONE, key)
        for name, pid in _SETTING_PARAMS.items():
            if setting.read_param == pid and setting.bit is None:
                out.setdefault(name, key)
    return dict(sorted(out.items()))


# ── revision and changes ─────────────────────────────────────────────────────


def _canonical(value: object) -> object:
    """``value`` as nested tuples whose ``repr`` is the same in every process."""
    if isinstance(value, Enum):
        return (type(value).__name__, value.value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__name__,
            tuple((f.name, _canonical(getattr(value, f.name))) for f in dataclasses.fields(value)),
        )
    if isinstance(value, Mapping):
        items = ((_canonical(k), _canonical(v)) for k, v in value.items())
        return ("map", tuple(sorted(items, key=repr)))
    if isinstance(value, (set, frozenset)):
        return ("set", tuple(sorted((_canonical(v) for v in value), key=repr)))
    if isinstance(value, (tuple, list)):
        return tuple(_canonical(v) for v in value)
    if isinstance(value, time):
        return value.isoformat()
    return value


def _revision(content: Mapping[str, object]) -> int:
    digest = hashlib.blake2b(repr(_canonical(content)).encode(), digest_size=8).digest()
    return int.from_bytes(digest) >> (64 - _REVISION_BITS)


_CONTENT_FIELDS: Final = tuple(
    f.name for f in dataclasses.fields(StationConfig) if f.name != "revision"
)


def changed_fields(old: StationConfig | None, new: StationConfig) -> frozenset[str]:
    """The fields of ``new`` that differ from ``old`` (every field when ``old`` is None)."""
    if old is None:
        return frozenset(_CONTENT_FIELDS)
    return frozenset(f for f in _CONTENT_FIELDS if getattr(old, f) != getattr(new, f))


def check_revision(config: StationConfig, expect_revision: int | None) -> None:
    """Raise :class:`~.exceptions.ConfigChangedError` (carrying ``config``) when
    ``expect_revision`` is given and is not ``config``'s revision."""
    if expect_revision is not None and expect_revision != config.revision:
        raise ConfigChangedError(config, expect_revision)
