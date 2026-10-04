"""Setting scopes and units, and the per-mode settings of the station's mode tables.

The per-model settings come from the bundled model files (:mod:`.model_settings`). This
module holds what those files do not: which device a setting addresses
(:class:`Scope`), the units a numeric setting reports (:class:`SettingUnit`), and the
per-mode delays and action masks every paired camera or sensor carries
(:data:`MODE_TABLE_SETTINGS`), written as a whole ``SET_ALL_ACTION`` table
(see ``p2p.mode_actions``).
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ..exceptions import UnsupportedError
from ..models import STATION_CHANNEL, GuardMode
from ..p2p.mode_actions import ACTION_FLAGS, FIELD_PARAMS, MODE_TABLE_MODES, ModeTableField
from .types import DeviceKind


class Scope(StrEnum):
    """Which device a setting addresses."""

    STATION = "station"
    CAMERA = "camera"
    SENSOR = "sensor"
    SUB_DEVICE = "sub_device"
    """Every paired device (cameras and sensors alike), never the station itself."""


_KIND_SCOPES: Final[Mapping[DeviceKind, Scope]] = MappingProxyType(
    {
        DeviceKind.STATION: Scope.STATION,
        DeviceKind.CAMERA: Scope.CAMERA,
        DeviceKind.SENSOR: Scope.SENSOR,
    }
)


def scope_for_kind(kind: DeviceKind | None) -> Scope:
    """The setting scope a device of ``kind`` is addressed as.

    A paired device of any other kind, or of unknown kind (``None``), is only known to
    be *some* sub-device: :data:`Scope.SUB_DEVICE`, to which only the settings every
    sub-device carries apply.
    """
    return Scope.SUB_DEVICE if kind is None else _KIND_SCOPES.get(kind, Scope.SUB_DEVICE)


SCOPE_DEFAULT_CHANNEL: Final[Mapping[Scope, int]] = MappingProxyType(
    {Scope.STATION: STATION_CHANNEL, Scope.CAMERA: 0, Scope.SENSOR: 0, Scope.SUB_DEVICE: 0}
)
"""The channel used when the caller names none: the station addresses itself on
255; a sub-device is addressed on its own slot (``device_channel``), 0 by default."""


class SettingKind(StrEnum):
    """The value shape of a mode-table setting (see :attr:`SettingDef.kind`)."""

    NUMBER = "number"
    """An integer in ``value_range``."""
    FLAGS = "flags"
    """A bitmask with named single-bit ``flags``; unnamed bits must be preserved."""


class SettingUnit(StrEnum):
    """The physical unit of a numeric setting's value."""

    NONE = ""
    SECONDS = "s"
    MILLISECONDS = "ms"
    DAYS = "d"
    PERCENT = "%"


@dataclass(frozen=True, slots=True, kw_only=True)
class SettingDef:
    """One per-mode setting: a delay (``value_range``) or an action mask (``flags``).

    ``command_id`` is the parameter that reports the value; the write is the whole
    mode table (``SET_ALL_ACTION``), never a frame of its own.
    """

    key: str
    command_id: int
    scope: Scope
    name: str
    description: str
    unit: SettingUnit = SettingUnit.NONE
    value_range: tuple[int, int] | None = None
    flags: Mapping[str, int] | None = None

    @property
    def read_param(self) -> int:
        """The parameter id that reports this setting's current value."""
        return self.command_id

    @property
    def kind(self) -> SettingKind:
        """FLAGS for an action mask, NUMBER for a delay."""
        return SettingKind.NUMBER if self.flags is None else SettingKind.FLAGS

    def applies_to(self, scope: Scope) -> bool:
        """Whether a device of ``scope`` carries this setting.

        A ``SUB_DEVICE`` setting applies to every scope but the station's.
        """
        if self.scope is Scope.SUB_DEVICE:
            return scope is not Scope.STATION
        return self.scope is scope

    def decode_flags(self, raw: str | int) -> tuple[frozenset[str], int]:
        """A reported bitmask as the set of named flags that are on, plus the leftover
        bits no name covers (preserve those on every write).

        Raises ``UnsupportedError`` for a setting that is not ``FLAGS`` and
        ``ValueError`` for a value that is not a non-negative integer.
        """
        flags = self._flags()
        number = _bitmask(self.key, raw)
        names = frozenset(name for name, bit in flags.items() if number & bit)
        named = 0
        for bit in flags.values():
            named |= bit
        return names, number & ~named

    def with_flag(self, current: int, name: str, on: bool) -> int:
        """``current`` with the flag ``name`` set or cleared; every other bit is kept.

        Raises ``UnsupportedError`` for a setting that is not ``FLAGS`` or a flag name
        it does not name, and ``ValueError`` for a negative ``current``.
        """
        flags = self._flags()
        if name not in flags:
            raise UnsupportedError(
                f"{name!r} is not a flag of {self.key}; known flags: {', '.join(flags)}"
            )
        number = _bitmask(self.key, current)
        return number | flags[name] if on else number & ~flags[name]

    def _flags(self) -> Mapping[str, int]:
        if self.flags is None:
            raise UnsupportedError(f"setting {self.key!r} is a {self.kind}, not a bitmask of flags")
        return self.flags

    def decode(self, raw: str | int) -> int | str:
        """A reported value as an int; a value that is not an integer is returned unchanged."""
        try:
            return int(raw)
        except ValueError:
            return raw


#: The camera's view mode (``CMD_SET_VIDEO_AND_RECORD_TYPE``): 0 single view,
#: :data:`DUAL_VIEW` dual. Selects which view a per-view quality report applies to.
VIEW_MODE_PARAM: Final = 6243
DUAL_VIEW: Final = 12


def report_value(raw: str | None, view_mode: str | None = None) -> int | None:
    """A reported parameter value as an int: a decimal integer, or the current view's
    ``quality`` from a per-view base64 JSON report; None when it does not decode.

    A multi-view camera's quality parameters (a T8170's 2730) report base64 JSON with one
    quality per view, ``{"mode_0": {"quality": q}, "mode_1": {…}, "cur_mode": m}``; the
    value is the quality of the view ``view_mode`` (:data:`VIEW_MODE_PARAM`) selects, as
    the app's handler reads it (``doLiveStreamingResolutionToUIValue_8170``).
    """
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        text = raw.strip()
        report = json.loads(base64.b64decode(text + "=" * (-len(text) % 4), validate=True))
    except (ValueError, binascii.Error):
        return None
    try:
        dual = view_mode is not None and int(view_mode) == DUAL_VIEW
    except ValueError:
        dual = False
    view = report.get("mode_1" if dual else "mode_0") if isinstance(report, dict) else None
    quality = view.get("quality") if isinstance(view, dict) else None
    if isinstance(quality, bool) or not isinstance(quality, int | str):
        return None
    try:
        return int(quality)
    except ValueError:
        return None


def _bitmask(key: str, raw: str | int) -> int:
    number = int(raw)
    if number < 0:
        raise ValueError(f"{number} is not a bitmask for {key}")
    return number


_DELAY_DESCRIPTIONS: Final[Mapping[ModeTableField, str]] = MappingProxyType(
    {
        ModeTableField.ALARM_DELAY: "Alarm (entry) delay after this device triggers",
        ModeTableField.LEAVING_DELAY: "Leaving (exit) delay for this device after arming",
    }
)

MODE_ACTION_FLAGS: Final[Mapping[Scope, Mapping[str, int]]] = MappingProxyType(
    {
        # ArmingManager.g for a camera (device_type 1, 8, 9, 14, 15, 19, 23 ...): record,
        # notification, its own siren, the HomeBase alarm and the light; plus the
        # monitoring-centre report every device gets. No privacy or respond bit.
        Scope.CAMERA: MappingProxyType(
            {
                name: ACTION_FLAGS[name]
                for name in (
                    "record",
                    "camera_siren",
                    "station_alarm",
                    "notification",
                    "report_monitor_center",
                    "light_alarm",
                )
            }
        ),
        # ArmingManager.g for a motion sensor (device_type 10, 127): notification, the
        # HomeBase alarm and "respond"; plus the monitoring-centre report.
        Scope.SENSOR: MappingProxyType(
            {
                name: ACTION_FLAGS[name]
                for name in (
                    "station_alarm",
                    "notification",
                    "motion_sensor_respond",
                    "report_monitor_center",
                )
            }
        ),
    }
)
"""The named action bits per device scope; the other bits of a mask are kept on a write."""


def _mode_suffix(mode: GuardMode) -> str:
    return mode.name.lower()


def _mode_title(mode: GuardMode) -> str:
    return mode.name.replace("_", " ").title()


def mode_action_key(mode: GuardMode, scope: Scope) -> str:
    """The key of a device's action bitmask for ``mode`` (``camera_action_away``).

    Raises ``UnsupportedError`` for a mode without an action table or a scope without
    named action bits (the station, a device of unknown kind).
    """
    if mode not in MODE_TABLE_MODES:
        raise UnsupportedError(f"guard mode {mode!r} has no per-device actions")
    if scope not in MODE_ACTION_FLAGS:
        raise UnsupportedError(f"a {scope} device has no catalogued per-mode actions")
    return f"{scope}_action_{_mode_suffix(mode)}"


def mode_delay_key(table_field: ModeTableField, mode: GuardMode) -> str:
    """The key of a per-mode delay (``alarm_delay_home``)."""
    if table_field is ModeTableField.ACTION or mode not in MODE_TABLE_MODES:
        raise UnsupportedError(f"no {table_field} delay for guard mode {mode!r}")
    return f"{table_field}_{_mode_suffix(mode)}"


MODE_TABLE_SETTINGS: Final[tuple[SettingDef, ...]] = (
    *(
        SettingDef(
            key=mode_delay_key(table_field, mode),
            command_id=FIELD_PARAMS[table_field][mode],
            scope=Scope.SUB_DEVICE,
            name=f"{table_field.replace('_', ' ').capitalize()} ({_mode_title(mode)})",
            description=(
                f"{_DELAY_DESCRIPTIONS[table_field]}, {_mode_title(mode)} mode: one value per "
                "mode, so a non-zero write also moves every device whose delay is on"
            ),
            unit=SettingUnit.SECONDS,
            value_range=(0, 300),
        )
        for table_field in _DELAY_DESCRIPTIONS
        for mode in sorted(MODE_TABLE_MODES, key=FIELD_PARAMS[table_field].__getitem__)
    ),
    *(
        SettingDef(
            key=mode_action_key(mode, scope),
            command_id=FIELD_PARAMS[ModeTableField.ACTION][mode],
            scope=scope,
            name=f"{scope.capitalize()} actions ({_mode_title(mode)})",
            description=(
                f"What this {scope} does when it triggers in {_mode_title(mode)} mode, a "
                "bitmask; bits outside the named flags are kept"
            ),
            flags=flags,
        )
        for scope, flags in MODE_ACTION_FLAGS.items()
        for mode in MODE_TABLE_MODES
    ),
)
"""The per-mode delays and action masks: one value per guard mode in the station's
mode table, carried by every paired camera or sensor."""

_BY_KEY: Final[Mapping[str, SettingDef]] = MappingProxyType(
    {spec.key: spec for spec in MODE_TABLE_SETTINGS}
)


def mode_table_setting(key: str) -> SettingDef:
    """The mode-table setting ``key``; ``UnsupportedError`` lists the known keys."""
    try:
        return _BY_KEY[key]
    except KeyError:
        raise UnsupportedError(
            f"unknown mode-table setting {key!r}; known: {', '.join(sorted(_BY_KEY))}"
        ) from None
