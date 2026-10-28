"""A station's alarm state and its devices' own alarms (:class:`StationAlarms`)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.device_alarm import DeviceAlarm, DeviceAlarms
from ..devices.device_alarm import device_alarms as alarms_for
from ..devices.device_alarm import render as render_alarm
from ..devices.recipes import ConnectType
from ..devices.station_config_support import StationFeature
from ..events import AlarmChanged, DeviceAlarmChanged, EventBus
from ..exceptions import UnsupportedError
from ..p2p.alarm import AlarmFrame
from ..p2p.session import CommandOutcome, StationSession
from ..p2p.xzyh import FrameType
from .base import own_channel

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AlarmWaits:
    """The waits a :class:`StationAlarms` reads, as ``station`` holds them when asked
    (``SIREN_EXPIRY_MARGIN_S``)."""

    siren_expiry_margin: float


class AlarmsOwner(Protocol):
    """The station members a :class:`StationAlarms` uses."""

    device: CloudDevice
    sub_devices: tuple[CloudDevice, ...]
    session: StationSession
    _bus: EventBus
    _log_name: str

    @property
    def serial(self) -> str: ...

    def channel_for(self, device_sn: str) -> int: ...

    def sub_device(self, device_sn: str) -> CloudDevice: ...

    def _product_code(self, serial: str) -> str | None: ...

    def _connect_type_of(self, device_sn: str) -> ConnectType: ...

    def _require_action(self, feature: StationFeature) -> None: ...

    def _answered(self, command: int, outcome: CommandOutcome) -> CommandOutcome: ...

    def _alarm_waits(self) -> AlarmWaits: ...


class StationAlarms:
    """A station's alarm state and the own alarms (siren, light) of its devices.

    It keeps the last station alarm transition and each channel's device-siren state
    with its expiry, takes the device-siren frames, announces
    :class:`~..events.DeviceAlarmChanged` and sends the device alarm requests.
    """

    def __init__(self, station: AlarmsOwner) -> None:
        self._station = station
        self.alarm: AlarmChanged | None = None
        """The last alarm transition (:attr:`Station.last_alarm`)."""
        self.sirens: dict[int, bool] = {}
        """The device-siren state per channel (:meth:`Station.device_alarm_on`)."""
        self.siren_expiry: dict[int, asyncio.TimerHandle] = {}
        """The pending off of each channel whose siren is on (:data:`~.SIREN_EXPIRY_MARGIN_S`)."""

    def device_alarms(self, device_sn: str) -> tuple[DeviceAlarm, ...]:
        """See :meth:`Station.device_alarms`."""
        alarms = self._device_alarms_of(device_sn)
        return () if alarms is None else alarms.choices

    def device_alarm_default(self, device_sn: str) -> DeviceAlarm | None:
        """See :meth:`Station.device_alarm_default`."""
        alarms = self._device_alarms_of(device_sn)
        return None if alarms is None else alarms.default

    def _device_alarms_of(self, device_sn: str) -> DeviceAlarms | None:
        if all(
            d.device_sn != device_sn for d in (self._station.device, *self._station.sub_devices)
        ):
            return None
        return alarms_for(
            self._station._product_code(device_sn), self._station._connect_type_of(device_sn)
        )

    def device_alarm_on(self, device_sn: str) -> bool | None:
        """See :meth:`Station.device_alarm_on`."""
        alarms = self._device_alarms_of(device_sn)
        if alarms is None:
            return None
        if alarms.station_tone:
            return None if self.alarm is None else self.alarm.alarming
        try:
            return self.sirens.get(self._alarm_channel(device_sn))
        except UnsupportedError:
            return None

    def _alarm_channel(self, device_sn: str) -> int:
        """The channel ``device_sn``'s alarm is addressed on: a hub's own on channel 0, as
        SET_TONE_FILE does; else :meth:`Station.channel_for`."""
        if device_sn == self._station.serial and own_channel(self._station.device) is None:
            return 0
        return self._station.channel_for(device_sn)

    def on_alarm_frame(self, frame: AlarmFrame) -> None:
        """Take a device-siren frame's state for its channel; an on state expires after
        its time left plus :data:`~.SIREN_EXPIRY_MARGIN_S`, the next counted frame on that
        channel replaces or cancels the expiry."""
        if frame.param_id != FrameType.SIREN_NOTIFY:
            return
        on = frame.alarm_state
        if on is None:
            return
        timer = self.siren_expiry.pop(frame.channel, None)
        if timer is not None:
            timer.cancel()
        if on:
            self.siren_expiry[frame.channel] = asyncio.get_running_loop().call_later(
                frame.seconds_left + self._station._alarm_waits().siren_expiry_margin,
                self._expire_siren,
                frame.channel,
            )
        self._set_siren(frame.channel, on, frame.values[0])

    def _expire_siren(self, channel: int) -> None:
        # A loop callback: an error is logged, the state is set before the emit.
        try:
            self.siren_expiry.pop(channel, None)
            self._set_siren(channel, False, None)
        except Exception:
            _LOGGER.exception(
                "%s: siren expiry on channel %d failed", self._station._log_name, channel
            )

    def _set_siren(self, channel: int, on: bool, event_type: int | None) -> None:
        """Store ``channel``'s siren state; announce a change for the devices it reports
        (an unseen channel counts as off)."""
        was = self.sirens.get(channel, False)
        self.sirens[channel] = on
        if was == on:
            return

        def reported(alarms: DeviceAlarms, device_sn: str) -> bool:
            if alarms.station_tone:
                return False
            try:
                return self._alarm_channel(device_sn) == channel
            except UnsupportedError:
                return False

        self.emit_device_alarms(reported, on, event_type, datetime.now(UTC))

    def emit_device_alarms(
        self,
        reports: Callable[[DeviceAlarms, str], bool],
        on: bool,
        event_type: int | None,
        at: datetime,
    ) -> None:
        """Emit :class:`~..events.DeviceAlarmChanged` for every device here with an alarm
        whose state ``reports(alarms, device_sn)`` says changed."""
        for device in (self._station.device, *self._station.sub_devices):
            alarms = self._device_alarms_of(device.device_sn)
            if alarms is None or not reports(alarms, device.device_sn):
                continue
            self._station._bus.emit(
                DeviceAlarmChanged(
                    station_sn=self._station.serial,
                    device_sn=device.device_sn,
                    on=on,
                    alarm=alarms.choice_for(event_type) if on else None,
                    event_type=event_type,
                    at=at,
                )
            )

    async def trigger_device_alarm(
        self,
        device_sn: str,
        alarm: DeviceAlarm | int | None = None,
        *,
        timeout: float | None = None,
    ) -> CommandOutcome:
        """See :meth:`Station.async_trigger_device_alarm`."""
        return await self._device_alarm(device_sn, alarm, start=True, timeout=timeout)

    async def stop_device_alarm(
        self,
        device_sn: str,
        alarm: DeviceAlarm | int | None = None,
        *,
        timeout: float | None = None,
    ) -> CommandOutcome:
        """See :meth:`Station.async_stop_device_alarm`."""
        return await self._device_alarm(device_sn, alarm, start=False, timeout=timeout)

    async def _device_alarm(
        self,
        device_sn: str,
        alarm: DeviceAlarm | int | None,
        *,
        start: bool,
        timeout: float | None,
    ) -> CommandOutcome:
        if device_sn != self._station.serial:
            self._station.sub_device(device_sn)  # UnsupportedError when not paired here
        alarms = self._device_alarms_of(device_sn)
        if alarms is None:
            raise UnsupportedError(
                f"{redact_serial(device_sn)}: the eufy app offers this device no alarm",
                device_sn=device_sn,
            )
        try:
            choice = alarms.default if alarm is None else DeviceAlarm(alarm)
        except ValueError:
            choice = None
        request = None if choice is None else (alarms.start if start else alarms.stop).get(choice)
        if request is None:
            name = alarm if choice is None else choice.name
            raise UnsupportedError(
                f"{redact_serial(device_sn)}: the eufy app offers no {name} alarm here",
                device_sn=device_sn,
            )
        if device_sn == self._station.serial and own_channel(self._station.device) is None:
            self._station._require_action(StationFeature.SOUND_ALARM)
        channel = self._alarm_channel(device_sn)
        outcome = await self._station.session.async_send_alarm(
            request.command,
            render_alarm(request.params, channel=channel),
            channel=channel,
            on=start,
            timeout=timeout,
        )
        return self._station._answered(request.command, outcome)
