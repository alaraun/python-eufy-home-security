"""A device's own siren and light, sent as the eufy app's handler sends them (generated data).

``_device_alarm_data.py`` is written by ``scripts/gen_device_alarm.py`` from the product
handlers and thing descriptions the eufy app runs. A product is listed when its thing
description declares ``set_alarm_type`` (or a ``__v`` form of it); per connect type the
table holds each alarm choice the app offers there (the identifier's enum, the
HomeBase-alarm choice aside) with the command and payload the handler sends to start it
and to stop it, and the choice the app preselects. The handler picks the command per
request: SET_DEVS_TONE_FILE (1202) goes on the device's channel and is confirmed by a
device-siren frame (``0x04B2``) on that channel; SET_TONE_FILE (1201) is confirmed by an
alarm-tone frame. Start and stop may use different commands. Requests with any other
command are not recorded. **[declared: eufy app]**; see docs/protocol/commands.md,
*Device siren*. Pure lookups: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Any, Final

from ..p2p.messages import CMD_SET_DEVS_TONE_FILE, CMD_SET_TONE_FILE
from ._device_alarm_data import DEVICE_ALARMS
from .recipes import ConnectType

__all__ = [
    "ALARM_COMMANDS",
    "ALARM_IDENTIFIER",
    "CHANNEL_SLOT",
    "HOMEBASE_CHOICE",
    "USER_NAME_SLOT",
    "AlarmRequest",
    "DeviceAlarm",
    "DeviceAlarms",
    "device_alarms",
    "render",
]

ALARM_IDENTIFIER: Final = "set_alarm_type"
"""The thing-description property behind the app's alarm button."""
ALARM_COMMANDS: Final = frozenset({CMD_SET_TONE_FILE, CMD_SET_DEVS_TONE_FILE})
"""SET_TONE_FILE and SET_DEVS_TONE_FILE: the commands a device alarm is sent with."""
CHANNEL_SLOT: Final = "$channel"
"""A payload value the device's channel fills."""
USER_NAME_SLOT: Final = "$user_name"
"""A payload value the session's user name fills (the app sends its nickname)."""


class DeviceAlarm(IntEnum):
    """An alarm choice of the app's alarm button: the thing description's enum value."""

    SOUND = 0
    LIGHT = 1
    SOUND_AND_LIGHT = 2


#: The enum value of the choice that sounds the station instead (not a device alarm).
HOMEBASE_CHOICE: Final = 3


@dataclass(frozen=True, slots=True)
class AlarmRequest:
    """One command the handler sends: ``command`` with the payload template ``params``."""

    command: int
    params: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class DeviceAlarms:
    """The alarm choices a device offers under one connect type."""

    default: DeviceAlarm
    """The choice the app preselects (the thing description's default)."""
    start: Mapping[DeviceAlarm, AlarmRequest]
    stop: Mapping[DeviceAlarm, AlarmRequest]

    @property
    def choices(self) -> tuple[DeviceAlarm, ...]:
        """The offered choices, in enum order."""
        return tuple(sorted(self.start))


def _request(raw: Any) -> AlarmRequest:
    command, params = raw
    if command not in ALARM_COMMANDS or not isinstance(params, dict):
        raise ValueError(f"not a device alarm request: {raw!r}")
    return AlarmRequest(int(command), MappingProxyType(dict(params)))


def _alarms(raw: Mapping[str, Any]) -> DeviceAlarms:
    choices = raw["choices"]
    return DeviceAlarms(
        default=DeviceAlarm(raw["default"]),
        start=MappingProxyType({DeviceAlarm(c): _request(r[0]) for c, r in choices.items()}),
        stop=MappingProxyType({DeviceAlarm(c): _request(r[1]) for c, r in choices.items()}),
    )


_TABLE: Final[Mapping[str, Mapping[ConnectType, DeviceAlarms]]] = MappingProxyType(
    {
        code: MappingProxyType(
            {ConnectType(kind): _alarms(entry) for kinds, entry in groups for kind in kinds}
        )
        for code, groups in DEVICE_ALARMS.items()
    }
)


def device_alarms(product_code: str | None, connect: ConnectType) -> DeviceAlarms | None:
    """The alarm choices of ``product_code`` under ``connect``; None when the app offers
    the device no alarm of its own there (no such property, or no handler request the
    station confirms)."""
    if product_code is None:
        return None
    return _TABLE.get(product_code.upper(), {}).get(connect)


def render(params: Mapping[str, Any], *, channel: int) -> dict[str, Any]:
    """A payload template with :data:`CHANNEL_SLOT` filled; :data:`USER_NAME_SLOT` stays
    for the session to fill."""
    return {k: channel if v == CHANNEL_SLOT else v for k, v in params.items()}
