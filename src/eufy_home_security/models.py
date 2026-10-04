"""Models shared across subsystems."""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum
from types import MappingProxyType
from typing import Final

#: The station addresses itself on channel 255; sub-devices use their own channel.
STATION_CHANNEL = 255


class FrameCipher(IntEnum):
    """The per-frame cipher of a P2P frame, named by XZYH subheader byte 0.

    ``ECB`` (AES-128-ECB) uses the static key, which anyone on the LAN can derive
    from the serial and DID, and carries no integrity tag. ``GCM`` (AES-256-GCM)
    uses the per-connection session key, and its tag authenticates the origin.
    """

    ECB = 0x01
    GCM = 0x08


class GuardMode(IntEnum):
    """Station guard (arming) mode, as carried by command 1224 and param 1224."""

    AWAY = 0
    HOME = 1
    SCHEDULE = 2
    CUSTOM_1 = 3
    CUSTOM_2 = 4
    CUSTOM_3 = 5
    OFF = 6
    """Report-only: a station may report it, the library never writes it (see
    ``devices.capabilities.GUARD_MODE_EVIDENCE``)."""
    GEOFENCE = 47
    DISARMED = 63

    @property
    def is_disarmed(self) -> bool:
        """Whether the mode is a disarm (``DISARMED`` or ``OFF``)."""
        return self in (GuardMode.DISARMED, GuardMode.OFF)

    @classmethod
    def parse(cls, value: str | int) -> GuardMode:
        """Parse a mode from its name (``"away"``, ``"custom_2"``, ``"off"``) or code.

        The name ``"off"`` is :attr:`DISARMED` (63, the code that is written), not
        :attr:`OFF`. Raises :class:`ValueError` (listing the valid names) for anything
        else, including booleans — ``True`` is an ``int`` to Python, not a guard mode.
        """
        if isinstance(value, GuardMode):
            return value
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise cls._invalid(value)
        if isinstance(value, int):
            return cls._from_code(value, value)
        text = value.strip().lower().replace("-", "_").replace(" ", "_")
        if text.isdigit():
            return cls._from_code(int(text), value)
        alias = _ALIASES.get(text, text)
        try:
            return cls[alias.upper()]
        except KeyError:
            raise cls._invalid(value) from None

    @classmethod
    def _from_code(cls, code: int, original: object) -> GuardMode:
        try:
            return cls(code)
        except ValueError:
            raise cls._invalid(original) from None

    @classmethod
    def _invalid(cls, value: object) -> ValueError:
        # A member whose name is an alias for another ("off") would mislead here.
        valid = ", ".join(m.name.lower() for m in cls if m.name.lower() not in _ALIASES)
        return ValueError(f"invalid guard mode {value!r}; valid: {valid}")


_ALIASES = {
    "armed_away": "away",
    "armed_home": "home",
    "custom1": "custom_1",
    "custom2": "custom_2",
    "custom3": "custom_3",
    "geofencing": "geofence",
    "disarm": "disarmed",
    "off": "disarmed",
}


# Parameter ids (param_type) every paired device reports in the station's dump.
# Names follow the app's CommandType enum; the guard-mode id lives with the dump
# model (``p2p.params.GUARD_MODE_PARAM``).
PARAM_BATTERY = 1101
PARAM_DEV_STATUS = 1131
"""The sub-device's own online flag, which the eufy app names ``GET_DEV_STATUS``: ``1``
online, ``0`` offline, and anything above ``1`` offline with a reason code the app
renders but does not name. Only sub-device blocks carry it — the station's does not,
because a dump is itself proof the station answered."""
DEV_STATUS_ONLINE = 1
"""The one :data:`PARAM_DEV_STATUS` value that means online (the eufy app compares it
against ``CameraParams.PARAM_ENABLE``)."""
PARAM_SUB1G_RSSI = 1141
"""Sub-1 GHz signal (dBm): the motion sensor's only signal; a camera reports 0 here."""
PARAM_WIFI_RSSI = 1142
PARAM_DEVICE_NAME = 1217
PARAM_PIR_EVENT_MS = 1605
"""Epoch ms on a motion sensor's block; the eufy app names it ``MOTION_SENSOR_PIR_EVT``."""
PARAM_FIRMWARE = 7013
PARAM_BATTERY_TEMPERATURE = 1138
"""Battery temperature; the handlers pass it through without a unit (°C by its range)."""
PARAM_WORKING_DAYS = 1191
"""Days since the camera's battery was last charged by USB (the app's power manager)."""
PARAM_DETECTED_EVENTS = 1192
PARAM_RECORDED_EVENTS = 1193
PARAM_SOLAR_INTENSITY = 1309
"""Raw solar input; a camera without a panel reports 0."""
PARAM_POWER_SOURCE = 2111
"""The charging source code (handlers' ``BATTERY_STATUS``; app ``SUB1G_REP_UNPLUG_POWER_LINE``)."""
NOT_CHARGING_SOURCES: Final = frozenset({0, 2})
"""Power-source codes the handlers read as not charging (``charging_status`` 0)."""
SOLAR_SOURCES: Final = frozenset({4, 5, 6, 7, 8, 12, 20})
"""Power-source codes the handlers or thing descriptions name as solar charging."""
SIREN_ACTION_PARAMS: Final[Mapping[GuardMode, int]] = MappingProxyType(
    {
        GuardMode.AWAY: 1509,
        GuardMode.HOME: 1510,
        GuardMode.CUSTOM_1: 1511,
        GuardMode.CUSTOM_2: 1512,
        GuardMode.CUSTOM_3: 1513,
    }
)
"""Per-mode siren action of a sub-device (app ``CameraParams`` ``m<Mode>SirenEnableParam``)."""
PARAM_SENSOR_LOW_BATTERY = 1601
"""Motion sensor low-battery flag (handler ``sensor_is_low_power``: 1 = low)."""
PARAM_SENSOR_PIR_SENSITIVITY = 1609

# Parameter ids on the station's own block (dev_type 255).
PARAM_LAN_IP = 1176
PARAM_EMMC_USED_PERCENT = 1190
PARAM_HUB_NAME = 1216
PARAM_SUB_DEVICE_SERIALS = 1072
"""The station's list of paired serials (base64 JSON)."""
PARAM_SUB_DEVICE_ASSOCIATION = 1073
"""The station's map of paired devices (base64)."""
PARAM_SD_INFO = 1102
"""``SDINFO``: one integer the handlers never decode; use the storage record instead."""
PARAM_STORAGE_STATUS = 1135
"""``GET_TFCARD_STATUS``: the storage status code (0 = normal)."""
STORAGE_STATUS_NORMAL: Final = frozenset({0, 25, 30})
"""Storage status codes the handlers show as normal (their UI status 0)."""
SUBSYSTEM_FIRMWARE_PARAMS: Final = tuple(range(5006, 5013))
"""Version strings of the station's subsystems; no vendor code names the subsystems."""

#: Parameters whose values name the house or its devices: logs show them redacted.
IDENTIFYING_PARAMS = frozenset(
    {PARAM_DEVICE_NAME, PARAM_HUB_NAME, PARAM_SUB_DEVICE_SERIALS, PARAM_SUB_DEVICE_ASSOCIATION}
)
