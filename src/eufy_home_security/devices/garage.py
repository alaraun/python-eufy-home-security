"""Garage doors of a garage-door camera: which doors a unit drives, their state, and the
command that moves one (declared, eufy app).

The parameters and the command come from the model's file (``garage``, generated from its
handler); the bit meanings are the handler's, which the generator checks against
:func:`door_state` and :func:`bound` for every model. A unit has up to two doors, ``1``
and ``2`` (the app's doors A and B). See docs/how-to/home-assistant.md § Garage doors and
docs/protocol/commands.md § Garage doors.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Final

from ..p2p._json import json_int
from .model_settings import GarageParams, garage_params
from .support import Evidence, Support

DOORS: Final = (1, 2)
"""The doors of a unit: 1 (the app's door A) and 2 (door B)."""


class GarageDoorState(StrEnum):
    """The state of one garage door."""

    OPEN = "open"
    CLOSED = "closed"
    OPENING = "opening"
    """Between this client's open command and the door's next report (the device reports
    no movement; the eufy app shows the same between its send and the report)."""
    CLOSING = "closing"
    """As :attr:`OPENING`, for a close command."""
    UNKNOWN = "unknown"
    """No report, the door's unknown bit, or a report naming neither open nor closed."""


class GarageDoorSource(StrEnum):
    """What delivered a garage door's state."""

    P2P = "p2p"
    """The device's parameter dump over P2P."""
    NOTIFY = "notify"
    """The device's door-state notify or parameter notify between dumps."""
    CLOUD = "cloud"
    """The device list's parameters (the cloud's copy)."""
    COMMAND = "command"
    """This client's door command: opening or closing until the door's next report."""


# Bits of the state parameter and its notify, per door (declared, eufy app handler).
_OPEN_BIT: Final[Mapping[int, int]] = MappingProxyType({1: 0x01, 2: 0x04})
_CLOSED_BIT: Final[Mapping[int, int]] = MappingProxyType({1: 0x02, 2: 0x08})
_UNKNOWN_BIT: Final[Mapping[int, int]] = MappingProxyType({1: 0x10, 2: 0x20})
# Bits of the motor and sensor binding parameters, per door.
_BOUND_BIT: Final[Mapping[int, int]] = MappingProxyType({1: 0x01, 2: 0x02})
_CALIBRATED_BIT: Final[Mapping[int, int]] = MappingProxyType({1: 0x04, 2: 0x08})


def door_state(bits: int, door: int) -> GarageDoorState:
    """The state the state bits report for ``door``, as the handler reads them: its
    unknown bit first, then open, then closed; neither is unknown."""
    if bits & _UNKNOWN_BIT[door]:
        return GarageDoorState.UNKNOWN
    if bits & _OPEN_BIT[door]:
        return GarageDoorState.OPEN
    if bits & _CLOSED_BIT[door]:
        return GarageDoorState.CLOSED
    return GarageDoorState.UNKNOWN


def bound(bits: int, door: int) -> bool:
    """Whether a binding parameter (motors or sensors) marks ``door`` bound."""
    return bool(bits & _BOUND_BIT[door])


def calibrated(bits: int, door: int) -> bool:
    """Whether the sensor binding parameter marks ``door``'s sensor calibrated, as the
    eufy app's door card reads it (declared, eufy app)."""
    return bool(bits & _CALIBRATED_BIT[door])


def parse_bits(raw: object) -> int | None:
    """A reported bit value (a parameter's text or a notify's number); None for anything
    that is no non-negative integer."""
    value = json_int(raw.strip() if isinstance(raw, str) else raw)
    return value if value is not None and value >= 0 else None


class GarageAction(StrEnum):
    """What a door command asks for."""

    OPEN = "open"
    CLOSE = "close"
    OPERATE = "operate"
    """The eufy app's command for a door in an unknown state: the motor runs, in
    whichever direction it moves the door from where it is."""


class GarageCommandType(IntEnum):
    """The ``type`` of a door command (declared, eufy app)."""

    CLOSE_1 = 0
    OPEN_1 = 1
    CLOSE_2 = 2
    OPEN_2 = 3
    OPERATE_1 = 4
    OPERATE_2 = 5


COMMAND_TYPES: Final[Mapping[tuple[int, GarageAction], GarageCommandType]] = MappingProxyType(
    {
        (1, GarageAction.CLOSE): GarageCommandType.CLOSE_1,
        (1, GarageAction.OPEN): GarageCommandType.OPEN_1,
        (2, GarageAction.CLOSE): GarageCommandType.CLOSE_2,
        (2, GarageAction.OPEN): GarageCommandType.OPEN_2,
        (1, GarageAction.OPERATE): GarageCommandType.OPERATE_1,
        (2, GarageAction.OPERATE): GarageCommandType.OPERATE_2,
    }
)
"""The command type per door and action."""


def command_body(door: int, action: GarageAction, user_name: str) -> dict[str, Any]:
    """The body of a door command, as the eufy app builds it: the ``type`` of ``door`` and
    ``action``, the account's nickname, and the fields the app always sends as 0."""
    return {
        "type": int(COMMAND_TYPES[(door, action)]),
        "user_name": user_name,
        "source": 0,
        "disable_push": 0,
        "cmdType": 0,
    }


def state_notify_bits(obj: Mapping[str, Any], params: GarageParams) -> int | None:
    """The state bits a JSON notify reports (``{"cmd": <state param>, "payload":
    {"type": <bits>}}``); None when ``obj`` is no door-state notify of ``params``."""
    if json_int(obj.get("cmd")) != params.state_param:
        return None
    payload = obj.get("payload")
    if not isinstance(payload, Mapping):
        return None
    return parse_bits(payload.get("type"))


@dataclass(frozen=True, slots=True, kw_only=True)
class GarageDoor:
    """One door of a garage-door camera.

    ``motor_bound`` and ``sensor_bound`` are the unit's binding reports; a door without a
    bound motor cannot be moved. ``sensor_calibrated`` is the sensor's calibration as the
    eufy app's door card reads it. ``state`` is the last reported state, or
    :attr:`GarageDoorState.OPENING` / ``CLOSING`` while a command of this client waits for
    the next report.
    """

    device_sn: str
    door: int
    motor_bound: bool
    sensor_bound: bool
    sensor_calibrated: bool
    state: GarageDoorState


_DECLARED: Final = Evidence(
    Support.DECLARED,
    "declared (eufy app): the model's garage_door_on_off state and binding reads and its "
    "1700 door command",
    "not verified on hardware; a command confirms by the door's next state report",
)


def garage_evidence(product_code: str | None) -> Evidence | None:
    """The grade of a model's garage doors; None for a model without them (no file, or no
    ``garage`` in it). Reads the model's file like
    :func:`~.model_settings.settings_of` (same memo) and raises like it."""
    return None if garage_params(product_code) is None else _DECLARED
