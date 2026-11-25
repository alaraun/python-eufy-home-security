"""The garage doors of a station's garage-door cameras (:class:`StationGarage`)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Any, Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.capabilities import Capability, profile_for_serial
from ..devices.garage import (
    DOORS,
    GarageAction,
    GarageDoor,
    GarageDoorSource,
    GarageDoorState,
    bound,
    calibrated,
    command_body,
    door_state,
    notify_doors,
    parse_bits,
    state_notify_bits,
)
from ..devices.model_settings import GarageParams, garage_params
from ..devices.recipes import Recipe
from ..devices.support import Support
from ..events import EventBus, GarageDoorChanged, ParamChanged
from ..exceptions import (
    DeviceBusyError,
    DeviceTimeoutError,
    DoorNotMovedError,
    DoorStateUnknownError,
    UnsupportedError,
)
from ..models import STATION_CHANNEL, FrameCipher, ValueSource
from ..p2p._json import json_int
from .base import own_channel

if TYPE_CHECKING:
    from . import Station

_LOGGER = logging.getLogger(__name__)

GARAGE_CONFIRM_TIMEOUT: Final = 300.0
"""Seconds a door command waits for the door's report, as long as the eufy app waits
(declared, eufy app)."""

_SOURCES: Final[Mapping[ValueSource, GarageDoorSource]] = {
    ValueSource.P2P: GarageDoorSource.P2P,
    ValueSource.NOTIFY: GarageDoorSource.NOTIFY,
    ValueSource.CLOUD: GarageDoorSource.CLOUD,
}
_MOVING: Final[Mapping[GarageAction, GarageDoorState]] = {
    GarageAction.OPEN: GarageDoorState.OPENING,
    GarageAction.CLOSE: GarageDoorState.CLOSING,
}
_TARGET: Final[Mapping[GarageAction, GarageDoorState]] = {
    GarageAction.OPEN: GarageDoorState.OPEN,
    GarageAction.CLOSE: GarageDoorState.CLOSED,
}

_Waiter = tuple[GarageDoorState | None, asyncio.Future[GarageDoorState]]
"""A waiting command's asked state (None: any known state) and its future."""


class StationGarage:
    """Door state and door commands of every device on a station that the model data
    gives doors (:func:`~..devices.model_settings.garage_params`).

    A door's state is the last report: the state parameter (a dump, a parameter notify,
    the cloud's copy; a value is taken when it differs from the previous one of that
    parameter) or the device's door-state notify, whose bits become the held state
    parameter. While a command of this client waits, the door reads opening or closing
    until its report.
    """

    def __init__(self, station: Station, bus: EventBus) -> None:
        self._station = station
        self._bus = bus
        self._raw: dict[str, str] = {}
        """Per device, the state parameter's value last taken."""
        self._reported: dict[tuple[str, int], GarageDoorState] = {}
        self._moving: dict[tuple[str, int], GarageDoorState] = {}
        self._sources: dict[tuple[str, int], GarageDoorSource] = {}
        """Per door, what delivered :attr:`_reported`."""
        self._emitted: dict[tuple[str, int], GarageDoorState] = {}
        self._busy: set[str] = set()
        """The devices a door command of this client waits on."""
        self._waiters: dict[tuple[str, int], _Waiter] = {}

    # ── reading ──────────────────────────────────────────────────────────────

    def params_of(self, device_sn: str) -> GarageParams | None:
        """The door parameters of ``device_sn``'s model when it is graded
        :attr:`~..devices.capabilities.Capability.GARAGE_DOOR`; else None."""
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.GARAGE_DOOR) is Support.UNKNOWN:
            return None
        return garage_params(self._station._product_code(device_sn))

    def doors(self, device: CloudDevice) -> tuple[GarageDoor, ...]:
        params = self.params_of(device.device_sn)
        if params is None:
            return ()
        motors = self._bits(device, params.motor_param)
        sensors = self._bits(device, params.sensor_param)
        return tuple(
            GarageDoor(
                device_sn=device.device_sn,
                door=door,
                motor_bound=bound(motors, door),
                sensor_bound=bound(sensors, door),
                sensor_calibrated=calibrated(sensors, door),
                state=self.state(device.device_sn, door),
            )
            for door in DOORS
            if bound(motors, door) or bound(sensors, door)
        )

    def state(self, device_sn: str, door: int) -> GarageDoorState:
        key = (device_sn, door)
        return self._moving.get(key) or self._reported.get(key, GarageDoorState.UNKNOWN)

    def _bits(self, device: CloudDevice, param: int) -> int:
        report = self._station._param_report(device, param)
        bits = None if report is None else parse_bits(report.value)
        return bits or 0

    # ── reports ──────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Take each garage device's state parameter where it changed."""
        for device in self._station.devices:
            params = self.params_of(device.device_sn)
            if params is None:
                continue
            report = self._station._param_report(device, params.state_param)
            if report is None or self._raw.get(device.device_sn) == report.value:
                continue
            self._raw[device.device_sn] = report.value
            bits = parse_bits(report.value)
            if bits is not None:
                source = _SOURCES.get(report.source, GarageDoorSource.P2P)
                self._take(device.device_sn, bits, source)

    def on_param(self, event: ParamChanged) -> None:
        if any(
            (params := self.params_of(d.device_sn)) is not None
            and event.param_id == params.state_param
            for d in self._station.devices
        ):
            self.refresh()

    def on_notify(self, obj: Mapping[str, Any], cipher: FrameCipher) -> None:
        """Take a door-state notify of a garage device (any cipher: display state).

        Its bits become the device's held door-state parameter, as the eufy app keeps
        them, so a later report of the value from before the notify is news again.
        """
        device = self._notify_device(obj)
        if device is None:
            return
        params = self.params_of(device.device_sn)
        bits = None if params is None else state_notify_bits(obj, params)
        if params is None or bits is None:
            return
        self._take(device.device_sn, bits, GarageDoorSource.NOTIFY, doors=notify_doors(obj))
        channel = STATION_CHANNEL if device is self._station.device else device.channel
        if channel is not None:
            self._station.session.apply_reported_params(channel, {params.state_param: str(bits)})

    def _notify_device(self, obj: Mapping[str, Any]) -> CloudDevice | None:
        """The device a notify is about: the one on its ``mChannel``, a standalone
        station itself when it names none."""
        station = self._station
        channel = json_int(obj.get("mChannel"))
        if station.is_standalone and channel in (None, own_channel(station.device)):
            return station.device
        return next(
            (d for d in station.sub_devices if channel is not None and d.channel == channel),
            None,
        )

    def _take(
        self, device_sn: str, bits: int, source: GarageDoorSource, *, doors: Collection[int] = ()
    ) -> None:
        """Take a report of ``device_sn``'s door-state bits; ``doors``: the doors a door
        notify reports on. A report that ends a waiting command (:func:`_ends`) shows the
        reported state at once."""
        for door in DOORS:
            key = (device_sn, door)
            state = door_state(bits, door)
            self._reported[key] = state
            self._sources[key] = source
            waiter = self._waiters.get(key)
            if (
                waiter is not None
                and not waiter[1].done()
                and _ends(waiter[0], state, door in doors)
            ):
                self._moving.pop(key, None)
                waiter[1].set_result(state)
            self._emit(device_sn, door, source)  # reads moving while a command waits

    def _emit(self, device_sn: str, door: int, source: GarageDoorSource) -> None:
        key = (device_sn, door)
        state = self.state(device_sn, door)
        if self._emitted.get(key) is state:
            return
        self._emitted[key] = state
        self._bus.emit(
            GarageDoorChanged(
                station_sn=self._station.serial,
                device_sn=device_sn,
                door=door,
                state=state,
                source=source,
            )
        )

    # ── commands ─────────────────────────────────────────────────────────────

    async def async_move(
        self,
        device_sn: str,
        door: int,
        action: GarageAction,
        *,
        operate: bool,
        timeout: float | None,
    ) -> GarageDoorState:
        device = self._station.sub_device(device_sn)
        params = self.params_of(device_sn)
        if params is None:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} has no garage doors", device_sn=device_sn
            )
        if door not in DOORS:
            raise ValueError(f"door {door} is not one of {DOORS}")
        if not bound(self._bits(device, params.motor_param), door):
            raise UnsupportedError(
                f"{redact_serial(device_sn)} reports no motor bound to door {door}",
                device_sn=device_sn,
            )
        if device_sn in self._busy:
            raise DeviceBusyError(
                f"{redact_serial(device_sn)}: a door command is still waiting for its door",
                device_sn=device_sn,
            )
        key = (device_sn, door)
        current = self._reported.get(key, GarageDoorState.UNKNOWN)
        if current is _TARGET[action]:
            return current
        target: GarageDoorState | None = _TARGET[action]
        if current is GarageDoorState.UNKNOWN:
            if not operate:
                raise DoorStateUnknownError(
                    f"{redact_serial(device_sn)}: door {door}'s state is unknown; pass "
                    "operate=True to run its motor whichever way it moves",
                    device_sn=device_sn,
                )
            action, target = GarageAction.OPERATE, None
        return await self._run(
            device, params=params, door=door, action=action, target=target, timeout=timeout
        )

    async def _run(
        self,
        device: CloudDevice,
        *,
        params: GarageParams,
        door: int,
        action: GarageAction,
        target: GarageDoorState | None,
        timeout: float | None,
    ) -> GarageDoorState:
        device_sn = device.device_sn
        key = (device_sn, door)
        budget = GARAGE_CONFIRM_TIMEOUT if timeout is None else timeout
        deadline = time.monotonic() + budget
        moving = _MOVING.get(action)
        future: asyncio.Future[GarageDoorState] = asyncio.get_running_loop().create_future()
        self._busy.add(device_sn)
        self._waiters[key] = (target, future)
        try:
            session = self._station.session
            await session.async_connect()
            recipe = Recipe(
                identifier="garage_door_on_off",
                cmd=params.cmd,
                sub_cmd=params.sub_cmd,
                params=command_body(door, action, session.user_name),
            )
            await session.async_run_recipe(recipe, channel=self._station.channel_for(device_sn))
            _LOGGER.debug(
                "%s: door %d %s taken; waiting for its state",
                redact_serial(device_sn),
                door,
                action,
            )
            if moving is not None and not future.done():
                self._moving[key] = moving
                self._emit(device_sn, door, GarageDoorSource.COMMAND)
            try:
                async with asyncio.timeout(max(0.0, deadline - time.monotonic())):
                    state = await future
            except TimeoutError as err:
                raise DeviceTimeoutError(
                    f"{redact_serial(device_sn)}: door {door} reported no "
                    f"{'known state' if target is None else target.value} within {budget:g} s",
                    device_sn=device_sn,
                ) from err
            if target is None or state is target:
                return state
            raise DoorNotMovedError(
                params.sub_cmd,
                f"{redact_serial(device_sn)}: door {door} reported {state.value} after the "
                f"{action.value} command",
                door=door,
                state=state,
                device_sn=device_sn,
            )
        finally:
            self._busy.discard(device_sn)
            self._waiters.pop(key, None)
            if self._moving.pop(key, None) is not None:
                self._emit(device_sn, door, self._sources.get(key, GarageDoorSource.COMMAND))


def _ends(target: GarageDoorState | None, state: GarageDoorState, door_report: bool) -> bool:
    """Whether a reported state ends the wait of a command that asked for ``target`` (None:
    operate): for an open or close, any report of the door itself (``door_report``, as the
    eufy app ends its wait on the door's notify) or another report of the asked state; for
    an operate command, any report of a known state."""
    if target is None:
        return state is not GarageDoorState.UNKNOWN
    return door_report or state is target
