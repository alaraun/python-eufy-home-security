"""``SET_ALL_ACTION`` (1255): one guard mode's per-device actions and delays (pure).

The station keeps, per paired device and per guard mode, an action bitmask (what the
device does when it triggers in that mode) and an alarm (entry) and a leaving (exit)
delay. None of them has a write of its own: the app replaces a whole mode at once
with a GCM frame whose frame type is 1255 and whose body is a JSON table (not a
``DeviceMsgBean``)::

    {
        "account_id": "<owner>",
        "mode_id": 1,
        "devices": [{"device_channel": 16, "action": 0}, ...],
        "count_down_alarm": {"channel_list": [1, 0], "delay_time": 30},
        "count_down_arm": {"channel_list": [1], "delay_time": 30},
        "siren_sensor_action": [{"device_channel": 16, "action": 0}, ...],
    }

This module builds that table from the parameter dump with one change applied. It
does no I/O; ``StationSession.async_set_mode_table`` sends it.

Sources: the eufy app's ``ModeManager``/``ModeActionRequest`` (the body),
``ArmingManager`` (mode → parameter ids, and how the app derives the channel lists
from the dump) and ``DeviceParam`` (the bit names). Verified on a HomeBase 3 (fw
3.8.7.4), by the app's write and the library's write + read-back: each
``devices[].action`` lands in that device's action parameter and ``delay_time`` in the
delay of every listed channel.

**The delays are one value per mode.** A table carries a single ``delay_time`` per
count-down and a list of the channels it applies to; the station mirrors it into
each listed channel's parameter. The app reads a list back as "the channels whose
delay for this mode is non-zero" (``ArmingManager.f``), and so does
:meth:`ModeTable.count_down`. Hence the rule :meth:`ModeTable.with_delay` applies:

- a non-zero delay on one device sets the mode's delay to that value on that device
  **and on every device whose delay for the mode is already on**;
- a zero delay turns it off for that one device and leaves the others as they are.
  When no other device has it on, the table lists the device with delay 0 (the
  station writes 0 into a listed channel); otherwise the device is left out of the
  list, and the station writes 0 into a device of the table that no list names.

**The table is whole.** Every device the mode lists must be written back with its
current action, and the other count-down with its current value: the station
takes the table as the mode's new state. ``siren_sensor_action`` (per device: whether
its trigger sounds a paired eufy siren accessory, 0/1 in the app's
``GuardSirenAlarmAdapter``) is not in the dump in a form the library reads, so it is
always sent as 0 — what the app sent from a station without a siren. A client must
not write a table for a station with a siren accessory paired.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from ..exceptions import UnsupportedError
from ..models import STATION_CHANNEL, GuardMode
from ._json import json_int

CMD_SET_ALL_ACTION: Final = 1255
"""``SET_ALL_ACTION``: the frame type of a mode-table write (``0x04E7``)."""

MODE_TABLE_MODES: Final[tuple[GuardMode, ...]] = (
    GuardMode.AWAY,
    GuardMode.HOME,
    GuardMode.CUSTOM_1,
    GuardMode.CUSTOM_2,
    GuardMode.CUSTOM_3,
)
"""The modes a table can be written for; its ``mode_id`` is the guard-mode code (0, 1,
3, 4, 5 — ``ArmingManager`` and ``CameraParams.setCurrentGuardType``). The Off mode
(6) has an action parameter of its own (1177 ``GET_OFF_ACTION``) but no delay ids,
and the app never arms it, so it is not written."""


class ModeTableField(StrEnum):
    """What one per-mode parameter of a device holds."""

    ACTION = "action"
    """The action bitmask (:data:`ACTION_FLAGS`)."""
    ALARM_DELAY = "alarm_delay"
    """Seconds between a trigger and the alarm (``count_down_alarm``)."""
    LEAVING_DELAY = "leaving_delay"
    """Seconds between arming and the mode taking effect (``count_down_arm``)."""


FIELD_PARAMS: Final[Mapping[ModeTableField, Mapping[GuardMode, int]]] = MappingProxyType(
    {
        # CameraParams: GET_AWAY_ACTION, GET_HOME_ACTION, GET_CUSTOM1..3_ACTION.
        ModeTableField.ACTION: MappingProxyType(
            {
                GuardMode.AWAY: 1239,
                GuardMode.HOME: 1225,
                GuardMode.CUSTOM_1: 1148,
                GuardMode.CUSTOM_2: 1149,
                GuardMode.CUSTOM_3: 1150,
            }
        ),
        # ArmingManager.c: ALARM_DELAY_HOME/AWAY/CUSTOM1..3 (note Home before Away).
        ModeTableField.ALARM_DELAY: MappingProxyType(
            {
                GuardMode.HOME: 1166,
                GuardMode.AWAY: 1167,
                GuardMode.CUSTOM_1: 1168,
                GuardMode.CUSTOM_2: 1169,
                GuardMode.CUSTOM_3: 1170,
            }
        ),
        # ArmingManager.d: LEAVING_DELAY_HOME/AWAY/CUSTOM1..3.
        ModeTableField.LEAVING_DELAY: MappingProxyType(
            {
                GuardMode.HOME: 1171,
                GuardMode.AWAY: 1172,
                GuardMode.CUSTOM_1: 1173,
                GuardMode.CUSTOM_2: 1174,
                GuardMode.CUSTOM_3: 1175,
            }
        ),
    }
)
"""The parameter id of each field for each mode, on every sub-device block."""

MODE_TABLE_PARAMS: Final[Mapping[int, tuple[GuardMode, ModeTableField]]] = MappingProxyType(
    {
        param: (mode, table_field)
        for table_field, by_mode in FIELD_PARAMS.items()
        for mode, param in by_mode.items()
    }
)
"""Every parameter a mode table writes → (mode, field)."""

ACTION_FLAGS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "record": 1,  # BIT_RECORD
        "camera_siren": 2,  # BIT_ALARM: the device's own siren
        "station_alarm": 4,  # BIT_STATION_ALARM (= BIT_SENSOR_STATION_ALARM)
        "notification": 8,  # BIT_NOTIFICATION (= BIT_SENSOR_NOTIFICATION)
        "privacy": 16,  # BIT_PRAVACY_ON
        "motion_sensor_respond": 32,  # BIT_MOTION_SENSOR_RESPOND
        "report_monitor_center": 64,  # BIT_REPORT_MONITOR_CENTER
        "light_alarm": 128,  # BIT_LIGHT_ALARM
        "privacy_new": 256,  # BIT_PRIVACY_ON_NEW
    }
)
"""The action bits, named after the eufy app ``DeviceParam.BIT_*`` constants. Which of them
apply to a device depends on its type (``ArmingManager.g``);
:data:`~..devices.settings.MODE_ACTION_FLAGS` names those per device scope."""

_DELAY_KEYS: Final[Mapping[ModeTableField, str]] = MappingProxyType(
    {
        ModeTableField.ALARM_DELAY: "count_down_alarm",
        ModeTableField.LEAVING_DELAY: "count_down_arm",
    }
)


def _require_mode(mode: GuardMode) -> GuardMode:
    if mode not in MODE_TABLE_MODES:
        names = ", ".join(m.name.lower() for m in MODE_TABLE_MODES)
        raise UnsupportedError(f"guard mode {mode!r} has no action table; one of {names}")
    return mode


def _non_negative(what: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a non-negative integer, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class CountDown:
    """One count-down of a table: the channels it applies to and its delay in seconds."""

    channels: tuple[int, ...]
    delay: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ModeTable:
    """One guard mode's whole table, as per-channel values.

    ``actions`` holds every device of the mode (channel → bitmask); the delay maps
    hold the per-channel delay in seconds (0 = off), with a channel missing meaning 0.
    Build one with :func:`mode_table_from_params`, change it with :meth:`with_action`
    or :meth:`with_delay`, send :meth:`request`, confirm with :meth:`params`.
    """

    mode: GuardMode
    actions: Mapping[int, int]
    alarm_delays: Mapping[int, int] = field(default_factory=dict)
    leaving_delays: Mapping[int, int] = field(default_factory=dict)
    cleared: frozenset[tuple[ModeTableField, int]] = frozenset()
    """(delay field, channel) pairs :meth:`with_delay` turned off in this table."""

    def __post_init__(self) -> None:
        _require_mode(self.mode)
        for channel, action in self.actions.items():
            if channel == STATION_CHANNEL or not 0 <= channel < STATION_CHANNEL:
                raise ValueError(f"channel {channel} is not a sub-device channel")
            _non_negative(f"the action of channel {channel}", action)
        for table_field in _DELAY_KEYS:
            for channel, seconds in self._delays(table_field).items():
                if channel not in self.actions:
                    raise ValueError(
                        f"channel {channel} has a {table_field} but no action in the table"
                    )
                _non_negative(f"the {table_field} of channel {channel}", seconds)

    def _delays(self, table_field: ModeTableField) -> Mapping[int, int]:
        if table_field is ModeTableField.ALARM_DELAY:
            return self.alarm_delays
        if table_field is ModeTableField.LEAVING_DELAY:
            return self.leaving_delays
        raise ValueError(f"{table_field} is not a delay")

    def _require_channel(self, channel: int) -> None:
        if channel not in self.actions:
            param = FIELD_PARAMS[ModeTableField.ACTION][self.mode]
            raise UnsupportedError(
                f"channel {channel} does not report its {self.mode.name.lower()} action "
                f"(param {param}), so it is not part of that mode's table"
            )

    def with_action(self, channel: int, action: int) -> ModeTable:
        """This table with ``channel``'s action bitmask replaced."""
        self._require_channel(channel)
        _non_negative("an action", action)
        return replace(self, actions={**self.actions, channel: action})

    def with_delay(self, table_field: ModeTableField, channel: int, seconds: int) -> ModeTable:
        """This table with ``channel``'s delay set, by the one-value-per-mode rule.

        Non-zero: every channel whose delay is already on moves to ``seconds`` with
        ``channel``. Zero: only ``channel`` goes to 0.
        """
        self._require_channel(channel)
        _non_negative("a delay", seconds)
        current = self._delays(table_field)
        cleared = self.cleared - {(table_field, channel)}
        if seconds:
            delays = {ch: seconds for ch, value in current.items() if value}
            delays[channel] = seconds
        else:
            delays = {**current, channel: 0}
            cleared |= {(table_field, channel)}
        if table_field is ModeTableField.ALARM_DELAY:
            return replace(self, alarm_delays=delays, cleared=cleared)
        return replace(self, leaving_delays=delays, cleared=cleared)

    def count_down(self, table_field: ModeTableField) -> CountDown:
        """The count-down that carries this table's delays for ``table_field``.

        The channels whose delay is on, with their shared value. With none on: an
        empty list with delay 0 (as the app's Away table), or, when :meth:`with_delay`
        turned a delay off, those channels listed with delay 0 so the station writes
        the 0 into them. Raises ``UnsupportedError`` when the channels that have it on
        disagree: one table cannot carry two values, so writing it would silently
        change some of them.
        """
        on = {ch: value for ch, value in self._delays(table_field).items() if value}
        values = set(on.values())
        if len(values) > 1:
            detail = ", ".join(f"channel {ch} = {v} s" for ch, v in sorted(on.items()))
            raise UnsupportedError(
                f"the {self.mode.name.lower()} {table_field} differs between devices "
                f"({detail}); a mode table carries one value, so it cannot be written back "
                "unchanged"
            )
        if on:
            return CountDown(tuple(sorted(on, reverse=True)), values.pop())
        cleared = (ch for f, ch in self.cleared if f is table_field)
        return CountDown(tuple(sorted(cleared, reverse=True)), 0)

    def request(self, account_id: str) -> dict[str, Any]:
        """The 1255 JSON object for the station owner ``account_id``.

        Channels are listed highest first, as the app lists them. Raises
        ``UnsupportedError`` when a count-down cannot be expressed (:meth:`count_down`).
        """
        channels = sorted(self.actions, reverse=True)
        body: dict[str, Any] = {
            "account_id": account_id,
            "mode_id": int(self.mode),
            "devices": [{"device_channel": ch, "action": self.actions[ch]} for ch in channels],
        }
        for table_field, key in _DELAY_KEYS.items():
            count_down = self.count_down(table_field)
            body[key] = {"channel_list": list(count_down.channels), "delay_time": count_down.delay}
        body["siren_sensor_action"] = [{"device_channel": ch, "action": 0} for ch in channels]
        return body

    def encode(self, account_id: str) -> bytes:
        """:meth:`request` as the compact JSON bytes of the frame body."""
        return json.dumps(self.request(account_id), separators=(",", ":")).encode()

    def params(self) -> dict[int, dict[int, int]]:
        """channel → {param id: value} this table must leave on the station (for read-back).

        Every device's action; a delay for each channel its count-down lists and each
        channel :meth:`with_delay` turned off. A channel whose delay was off and stays
        off is not checked: a block may not report the parameter at all.
        """
        out: dict[int, dict[int, int]] = {}
        for channel, action in self.actions.items():
            out[channel] = {FIELD_PARAMS[ModeTableField.ACTION][self.mode]: action}
        for table_field in _DELAY_KEYS:
            param = FIELD_PARAMS[table_field][self.mode]
            cleared = {ch for f, ch in self.cleared if f is table_field}
            for channel in {*self.count_down(table_field).channels, *cleared}:
                out[channel][param] = self._delays(table_field).get(channel, 0)
        return out

    def same_values(self, other: ModeTable) -> bool:
        """Whether ``other`` holds the same mode, actions and delays (a write would change
        nothing), whatever it records as cleared."""
        return (self.mode, self.actions, self.alarm_delays, self.leaving_delays) == (
            other.mode,
            other.actions,
            other.alarm_delays,
            other.leaving_delays,
        )


def _param_int(params: Mapping[int, str | None], param: int, channel: int) -> int | None:
    raw = params.get(param)
    if raw is None:
        return None
    value = json_int(raw)
    if value is None or value < 0:
        raise UnsupportedError(
            f"channel {channel} reports {raw!r} for param {param}, not a non-negative integer; "
            "refusing to write a mode table built on it"
        )
    return value


def mode_table_from_params(
    devices: Mapping[int, Mapping[int, str | None]], mode: GuardMode
) -> ModeTable:
    """The table the station holds for ``mode``, from a parameter dump's blocks.

    Every sub-device block that reports the mode's action parameter is a device of the
    table (the app leaves keypads out, and a keypad block carries none); a delay the
    block does not report counts as 0, as the app reads it. Raises ``UnsupportedError``
    for a mode without a table or a value that is not a non-negative integer.
    """
    _require_mode(mode)
    action_param = FIELD_PARAMS[ModeTableField.ACTION][mode]
    actions: dict[int, int] = {}
    delays: dict[ModeTableField, dict[int, int]] = {f: {} for f in _DELAY_KEYS}
    for channel, params in devices.items():
        if channel == STATION_CHANNEL:
            continue
        action = _param_int(params, action_param, channel)
        if action is None:
            continue
        actions[channel] = action
        for table_field, by_channel in delays.items():
            value = _param_int(params, FIELD_PARAMS[table_field][mode], channel)
            by_channel[channel] = value or 0
    return ModeTable(
        mode=mode,
        actions=actions,
        alarm_delays=delays[ModeTableField.ALARM_DELAY],
        leaving_delays=delays[ModeTableField.LEAVING_DELAY],
    )


def applied_params(request: Mapping[str, Any]) -> dict[int, dict[int, int]]:
    """channel → {param id: value} a 1255 ``request`` sets, as the station was seen to.

    Each ``devices[]`` action lands in that channel's action parameter, and each
    count-down's ``delay_time`` in the delay parameter of every channel it lists; a
    ``devices[]`` channel that a count-down does not list gets 0 for that delay.
    Malformed entries are skipped. Raises ``UnsupportedError`` for a ``mode_id``
    without a table.
    """
    mode_id = json_int(request.get("mode_id"))
    modes = {int(m): m for m in MODE_TABLE_MODES}
    if mode_id not in modes:
        raise UnsupportedError(f"mode_id {request.get('mode_id')!r} has no action table")
    mode = modes[mode_id]
    out: dict[int, dict[int, int]] = {}
    devices = request.get("devices")
    for entry in devices if isinstance(devices, list) else ():
        if not isinstance(entry, Mapping):
            continue
        channel, action = json_int(entry.get("device_channel")), json_int(entry.get("action"))
        if channel is not None and action is not None:
            out.setdefault(channel, {})[FIELD_PARAMS[ModeTableField.ACTION][mode]] = action
    for table_field, key in _DELAY_KEYS.items():
        count_down = request.get(key)
        if not isinstance(count_down, Mapping):
            continue
        delay = json_int(count_down.get("delay_time"))
        listed = count_down.get("channel_list")
        if delay is None or not isinstance(listed, list):
            continue
        param = FIELD_PARAMS[table_field][mode]
        named = set(_ints(listed))
        for channel in named:
            out.setdefault(channel, {})[param] = delay
        for channel, values in out.items():
            if channel not in named and FIELD_PARAMS[ModeTableField.ACTION][mode] in values:
                values[param] = 0
    return out


def _ints(values: Iterable[object]) -> Iterable[int]:
    for value in values:
        number = json_int(value)
        if number is not None:
            yield number
