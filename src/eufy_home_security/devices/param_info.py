"""What a parameter id means, for log lines: its name, description and readable values.

A station parameter (or the command of the same number) is described from, in order:
the per-mode settings (:data:`~.settings.MODE_TABLE_SETTINGS`: key, description, flags
and unit), the parameters the library reads into device state itself, and the
app's name for the id (:data:`~.command_types.COMMAND_NAMES`, a lead rather than a
meaning). An id none of them names is ``unknown``. Values that identify the account or
the house (names, the serial list, the LAN address) are never shown in clear unless
secret logging is on.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final

from .._logging import Address, Identifier
from ..models import (
    DEV_STATUS_ONLINE,
    IDENTIFYING_PARAMS,
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
    PARAM_SUB_DEVICE_ASSOCIATION,
    PARAM_SUB_DEVICE_SERIALS,
    PARAM_WIFI_RSSI,
    PARAM_WORKING_DAYS,
    SIREN_ACTION_PARAMS,
    STATION_CHANNEL,
    SUBSYSTEM_FIRMWARE_PARAMS,
    GuardMode,
)
from ..p2p.params import ACTIVE_MODE_PARAM, GUARD_MODE_PARAM
from .command_types import COMMAND_NAMES
from .settings import MODE_TABLE_SETTINGS, Scope, SettingDef, SettingKind

UNKNOWN: Final = "unknown"


def _number(unit: str) -> Callable[[str], str]:
    return lambda raw: f"{raw} {unit}"


def _guard_mode(raw: str) -> str:
    try:
        return GuardMode(int(raw)).name.lower()
    except ValueError:
        return raw


def _online(raw: str) -> str:
    try:
        code = int(raw)
    except ValueError:
        return raw
    if code == DEV_STATUS_ONLINE:
        return "online"
    return "offline" if code == 0 else f"offline (code {code})"


def _epoch_ms(raw: str) -> str:
    try:
        stamp = datetime.fromtimestamp(int(raw) / 1000, UTC)
    except (ValueError, OverflowError, OSError):
        return raw
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _identifier(raw: str) -> str:
    return str(Identifier(raw))


def _address(raw: str) -> str:
    return str(Address(raw))


@dataclass(frozen=True, slots=True)
class _StateParam:
    key: str
    description: str
    render: Callable[[str], str] | None = None


#: Parameters the library reads into device state rather than through a setting.
STATE_PARAM_INFO: Final[Mapping[int, _StateParam]] = MappingProxyType(
    {
        PARAM_BATTERY: _StateParam("battery", "battery level", _number("%")),
        PARAM_DEV_STATUS: _StateParam("online", "online status", _online),
        PARAM_SUB1G_RSSI: _StateParam("sub1g_rssi", "sub-1 GHz signal", _number("dBm")),
        PARAM_WIFI_RSSI: _StateParam("wifi_rssi", "Wi-Fi signal", _number("dBm")),
        PARAM_DEVICE_NAME: _StateParam("device_name", "device name", _identifier),
        PARAM_PIR_EVENT_MS: _StateParam("pir_event_ms", "last PIR event", _epoch_ms),
        PARAM_FIRMWARE: _StateParam("firmware", "firmware version"),
        PARAM_LAN_IP: _StateParam("lan_ip", "station LAN address", _address),
        PARAM_EMMC_USED_PERCENT: _StateParam("emmc_used_percent", "eMMC used", _number("%")),
        PARAM_HUB_NAME: _StateParam("hub_name", "station name", _identifier),
        GUARD_MODE_PARAM: _StateParam("guard_mode", "selected guard mode", _guard_mode),
        ACTIVE_MODE_PARAM: _StateParam("active_mode", "guard mode in force", _guard_mode),
        PARAM_SUB_DEVICE_SERIALS: _StateParam(
            "sub_device_serials", "paired device serials", _identifier
        ),
        PARAM_SUB_DEVICE_ASSOCIATION: _StateParam(
            "sub_device_association", "paired device map", _identifier
        ),
        PARAM_BATTERY_TEMPERATURE: _StateParam("battery_temperature", "battery temperature"),
        PARAM_WORKING_DAYS: _StateParam("working_days", "days since last USB charge"),
        PARAM_DETECTED_EVENTS: _StateParam("detected_events", "events detected"),
        PARAM_RECORDED_EVENTS: _StateParam("recorded_events", "events recorded"),
        PARAM_POWER_SOURCE: _StateParam("power_source", "charging source code"),
        PARAM_SOLAR_INTENSITY: _StateParam("solar_intensity", "solar input"),
        **{
            pid: _StateParam(f"siren_action_{mode.name.lower()}", "per-mode siren action")
            for mode, pid in SIREN_ACTION_PARAMS.items()
        },
        PARAM_SENSOR_LOW_BATTERY: _StateParam("low_battery", "sensor low-battery flag"),
        PARAM_SENSOR_PIR_SENSITIVITY: _StateParam("pir_sensitivity_raw", "raw PIR sensitivity"),
        PARAM_STORAGE_STATUS: _StateParam("storage_status", "storage status code"),
        PARAM_SD_INFO: _StateParam("sd_info", "SDINFO value"),
        **{
            pid: _StateParam(f"subsystem_firmware_{pid}", "subsystem firmware version")
            for pid in SUBSYSTEM_FIRMWARE_PARAMS
        },
    }
)


@dataclass(frozen=True, slots=True)
class ParamInfo:
    """What the library knows about one parameter id on one channel."""

    param_id: int
    label: str
    """The setting key (keys joined by ``|`` when the device kind is unknown and
    several apply), the state name, the app's name followed by ``?``, or ``unknown``."""
    description: str | None
    settings: tuple[SettingDef, ...] = ()
    state: _StateParam | None = None

    @property
    def identifying(self) -> bool:
        """Whether the value names the account or the house (shown redacted)."""
        return self.param_id in IDENTIFYING_PARAMS or self.param_id == PARAM_LAN_IP

    def raw(self, value: object) -> str:
        """The wire value as ``repr``, redacted when it is identifying."""
        if value is None or not self.identifying:
            return repr(value)
        return repr(self.value(value))

    def value(self, value: object) -> str:
        """A readable value: choice names, flag names, units, guard-mode names."""
        if value is None:
            return "unset"
        text = str(value)
        if self.state is not None and self.state.render is not None:
            return self.state.render(text)
        if not self.settings:
            return text
        spec = self.settings[0]
        if spec.kind is SettingKind.FLAGS:
            try:
                names, rest = spec.decode_flags(text)
            except ValueError:
                return text
            shown = ", ".join(sorted(names)) or "none"
            return f"{shown} (+0x{rest:x})" if rest else shown
        decoded = spec.decode(text)
        unit = spec.unit.value
        return f"{decoded} {unit}" if unit and isinstance(decoded, int) else str(decoded)

    @property
    def known(self) -> bool:
        """Whether a setting or the device state gives the id a meaning."""
        return bool(self.settings) or self.state is not None

    def change(self, old: object, new: object) -> str:
        """``label (description): old → new``; flags as ``+added -removed``.

        Only the label for an id without a known meaning: its values mean nothing more
        than the raw ones.
        """
        if not self.known:
            return self._head()
        if self.settings and self.settings[0].kind is SettingKind.FLAGS:
            moved = self._flag_change(self.settings[0], old, new)
            if moved is not None:
                return f"{self._head()}: {moved}"
        return f"{self._head()}: {self.value(old)} → {self.value(new)}"

    def describe(self, value: object = None) -> str:
        """``label (description)``, with ``= value`` when one is given."""
        shown = "" if value is None or not self.known else f" = {self.value(value)}"
        return f"{self._head()}{shown}"

    def _head(self) -> str:
        if self.description is None:
            return self.label
        return f"{self.label} ({_first_clause(self.description)})"

    @staticmethod
    def _flag_change(spec: SettingDef, old: object, new: object) -> str | None:
        try:
            before, _ = spec.decode_flags(str(old))
            after, _ = spec.decode_flags(str(new))
        except ValueError:
            return None
        moved = [f"+{name}" for name in sorted(after - before)]
        moved += [f"-{name}" for name in sorted(before - after)]
        return f"{' '.join(moved) or 'no named flag moved'} ({old} → {new})"


def _first_clause(description: str) -> str:
    """A setting description up to its first ``;`` or ``:`` (the rest is caveats)."""
    for mark in (";", ":"):
        description = description.split(mark, 1)[0]
    return description.removesuffix(", a bitmask").strip()


def param_info(param_id: int, channel: int, scope: Scope | None = None) -> ParamInfo:
    """Describe ``param_id`` (a parameter or the command of the same number) on ``channel``.

    ``scope`` is the device kind's scope when known; otherwise channel 255 is the
    station and any other channel a sub-device of unknown kind.
    """

    def applies(spec: SettingDef) -> bool:
        if scope is not None:
            return spec.applies_to(scope)
        return (spec.scope is Scope.STATION) == (channel == STATION_CHANNEL)

    specs = tuple(
        spec
        for spec in MODE_TABLE_SETTINGS
        if param_id in (spec.read_param, spec.command_id) and applies(spec)
    )
    if specs:
        label = "|".join(spec.key for spec in specs)
        return ParamInfo(param_id, label, specs[0].description, settings=specs)
    if (state := STATE_PARAM_INFO.get(param_id)) is not None:
        return ParamInfo(param_id, state.key, state.description, state=state)
    if (name := COMMAND_NAMES.get(param_id)) is not None:
        return ParamInfo(param_id, f"{name}?", "the app's name, meaning unknown")
    return ParamInfo(param_id, UNKNOWN, None)
