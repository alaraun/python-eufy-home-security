"""A station's alarm state and its devices' own alarms (:class:`StationAlarms`)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.device_alarm import (
    T8970_HB2_ALARMS,
    DeviceAlarm,
    DeviceAlarms,
)
from ..devices.device_alarm import device_alarms as alarms_for
from ..devices.device_alarm import render as render_alarm
from ..devices.recipes import ConnectType
from ..devices.station_config_support import StationFeature
from ..events import (
    AlarmChanged,
    DeviceAlarmChanged,
    DeviceAlarmOperationChanged,
    EventBus,
)
from ..exceptions import (
    DeviceBusyError,
    StationUnreachableError,
    UnsupportedError,
)
from ..p2p.alarm import AlarmFrame
from ..p2p.session import CommandOutcome, StationSession
from ..p2p.xzyh import FrameType
from .base import own_channel
from .siren_loop import PulseResult, SirenLoop

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


class _SirenPulseSkippedError(Exception):
    """The pre-transmission guard suppressed a siren activation."""


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
        self._siren_loops: dict[str, SirenLoop] = {}
        self._siren_locks: dict[str, asyncio.Lock] = {}
        self._siren_stop_epochs: dict[str, int] = {}
        self._siren_binding_epochs: dict[str, int] = {}
        self._siren_requests: set[asyncio.Task[CommandOutcome]] = set()
        self._siren_closing = False

        self.siren_expiry: dict[int, asyncio.TimerHandle] = {}
        """The pending off of each channel whose siren is on (:data:`~.SIREN_EXPIRY_MARGIN_S`)."""

    def _supports_momentary_siren(self, device_sn: str) -> bool:
        """Whether a paired device has a hardware-verified sound-test command."""
        return any(
            device.device_sn == device_sn
            and device.model_id == "T8970"
            and device.device_type == 21
            and device.channel is not None
            and 0 <= device.channel < 255
            and device.station_sn == self._station.serial
            and self._station._connect_type_of(device_sn) is ConnectType.HB2
            for device in self._station.sub_devices
        )

    def device_alarms(self, device_sn: str) -> tuple[DeviceAlarm, ...]:
        """See :meth:`Station.device_alarms`."""
        alarms = self._device_alarms_of(device_sn)
        return () if alarms is None else alarms.choices

    def device_alarm_default(self, device_sn: str) -> DeviceAlarm | None:
        """See :meth:`Station.device_alarm_default`."""
        alarms = self._device_alarms_of(device_sn)
        return None if alarms is None else alarms.default

    def _device_alarms_of(self, device_sn: str) -> DeviceAlarms | None:
        if self._supports_momentary_siren(device_sn):
            return T8970_HB2_ALARMS
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

    def _request_siren_stop(self, device_sn: str) -> None:
        """Invalidate pending starts and prevent further pulses."""
        self._siren_stop_epochs[device_sn] = self._siren_stop_epochs.get(device_sn, 0) + 1

        controller = self._siren_loops.get(device_sn)
        if controller is not None:
            controller.request_stop()

    def connection_lost(self) -> None:
        """End dedicated siren operations without reconnecting."""
        for device_sn in self._siren_locks:
            self._request_siren_stop(device_sn)

    def devices_changed(self, device_sns: tuple[str, ...]) -> None:
        """Invalidate operations for removed or reassigned devices."""
        for device_sn in device_sns:
            if device_sn not in self._siren_locks:
                continue

            self._siren_binding_epochs[device_sn] = self._siren_binding_epochs.get(device_sn, 0) + 1
            self._request_siren_stop(device_sn)

    def _new_siren_loop(
        self,
        device_sn: str,
        channel: int,
        *,
        timeout: float | None,
    ) -> SirenLoop:
        """Bind a dedicated siren operation to its current connection."""
        session = self._station.session
        generation = session.link_generation
        binding_epoch = self._siren_binding_epochs.get(device_sn, 0)

        def is_current() -> bool:
            return (
                session.connected
                and session.link_generation == generation
                and self._siren_binding_epochs.get(device_sn, 0) == binding_epoch
                and self._supports_momentary_siren(device_sn)
                and self._alarm_channel(device_sn) == channel
            )

        async def pulse(
            can_send: Callable[[], bool],
        ) -> PulseResult:
            sent_at: float | None = None

            def before_send() -> None:
                nonlocal sent_at

                if self._siren_closing or not is_current() or not can_send():
                    raise _SirenPulseSkippedError()

                sent_at = asyncio.get_running_loop().time()

            request = T8970_HB2_ALARMS.start[DeviceAlarm.SOUND]

            try:
                outcome = await session.async_send_command(
                    request.command,
                    channel=channel,
                    value3=0,
                    payload={
                        **render_alarm(request.params, channel=channel),
                        "transaction": str(time.time_ns() // 1_000_000),
                    },
                    timeout=timeout,
                    resend=False,
                    receipt_only=True,
                    expected_link_generation=generation,
                    before_send=before_send,
                )
            except _SirenPulseSkippedError:
                return None

            if sent_at is None:
                raise RuntimeError("siren transmission timestamp was not recorded")

            return outcome, sent_at

        async def interrupt() -> CommandOutcome:
            def before_send() -> None:
                if not is_current():
                    raise StationUnreachableError("dedicated siren binding is no longer current")

            request = T8970_HB2_ALARMS.stop[DeviceAlarm.SOUND]

            return await session.async_send_command(
                request.command,
                channel=channel,
                value3=0,
                payload={
                    **render_alarm(request.params, channel=channel),
                    "transaction": str(time.time_ns() // 1_000_000),
                },
                timeout=timeout,
                resend=False,
                receipt_only=True,
                expected_link_generation=generation,
                before_send=before_send,
            )

        def active_changed(active: bool) -> None:
            self._station._bus.emit(
                DeviceAlarmOperationChanged(
                    station_sn=self._station.serial,
                    device_sn=device_sn,
                    active=active,
                )
            )

        return SirenLoop(
            pulse,
            interrupt,
            is_current,
            log_name=self._station._log_name,
            on_active_changed=active_changed,
        )

    def _release_siren_request(
        self,
        task: asyncio.Task[CommandOutcome],
    ) -> None:
        self._siren_requests.discard(task)
        if not task.cancelled():
            task.exception()

    async def _run_dedicated_alarm(
        self,
        device_sn: str,
        *,
        start: bool,
        test: bool,
        epoch: int,
        timeout: float | None,
    ) -> CommandOutcome:
        async with self._siren_locks[device_sn]:

            def require_available() -> None:
                if self._siren_closing:
                    raise StationUnreachableError("station is closing")

                if not self._supports_momentary_siren(device_sn):
                    raise UnsupportedError(
                        "dedicated siren is no longer paired here",
                        device_sn=device_sn,
                    )

                if start and self._siren_stop_epochs.get(device_sn, 0) != epoch:
                    raise DeviceBusyError(
                        "siren activation was superseded by a stop request",
                        device_sn=device_sn,
                    )

            require_available()

            controller = self._siren_loops.get(device_sn)

            if controller is not None and controller.running:
                if test:
                    raise DeviceBusyError(
                        "cannot test a siren with an active alarm",
                        device_sn=device_sn,
                    )
                if start:
                    return await controller.start()
                return await controller.stop()

            # Only an explicit new operation may establish a connection.
            await self._station.session.async_connect()

            require_available()

            controller = self._new_siren_loop(
                device_sn,
                self._alarm_channel(device_sn),
                timeout=timeout,
            )

            self._siren_loops[device_sn] = controller

            if test:
                try:
                    return await controller.test()
                finally:
                    # If shutdown began during the single pulse,
                    # attempt interruption before closing the link.
                    if self._siren_closing:
                        try:
                            await controller.stop()
                        except Exception:
                            _LOGGER.exception(
                                "%s: siren test shutdown failed",
                                self._station._log_name,
                            )

            if start:
                return await controller.start()

            return await controller.stop()

    async def _dedicated_alarm(
        self,
        device_sn: str,
        *,
        start: bool,
        timeout: float | None,
        test: bool = False,
    ) -> CommandOutcome:
        if self._siren_closing:
            raise StationUnreachableError("station is closing")

        self._siren_locks.setdefault(device_sn, asyncio.Lock())

        if not start:
            # Signal OFF before waiting for the per-device operation lock.
            self._request_siren_stop(device_sn)

        epoch = self._siren_stop_epochs.get(device_sn, 0)

        task = asyncio.create_task(
            self._run_dedicated_alarm(
                device_sn,
                start=start,
                test=test,
                epoch=epoch,
                timeout=timeout,
            ),
            name="dedicated-siren-request",
        )

        self._siren_requests.add(task)
        task.add_done_callback(self._release_siren_request)

        # Do not abandon an outstanding receipt on caller cancellation.
        return await asyncio.shield(task)

    async def close(self) -> None:
        """Stop dedicated operations before the session is closed."""
        self._siren_closing = True

        for device_sn in self._siren_locks:
            self._request_siren_stop(device_sn)

        if self._siren_requests:
            await asyncio.gather(
                *tuple(self._siren_requests),
                return_exceptions=True,
            )

        active = [controller for controller in self._siren_loops.values() if controller.running]

        if active:
            results = await asyncio.gather(
                *(controller.stop() for controller in active),
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, BaseException):
                    _LOGGER.error(
                        "%s: dedicated siren shutdown failed",
                        self._station._log_name,
                        exc_info=result,
                    )

        self._siren_loops.clear()
        self._siren_locks.clear()
        self._siren_stop_epochs.clear()
        self._siren_binding_epochs.clear()

    def device_alarm_operation_active(
        self,
        device_sn: str,
    ) -> bool | None:
        """The managed alarm operation state, not physical ringing."""
        if not self._supports_momentary_siren(device_sn):
            return None

        controller = self._siren_loops.get(device_sn)

        return controller is not None and controller.active

    def supports_siren_test(self, device_sn: str) -> bool:
        """Whether this device supports a native sound test."""
        return self._supports_momentary_siren(device_sn)

    async def test_siren(
        self,
        device_sn: str,
        *,
        timeout: float | None = None,
    ) -> CommandOutcome:
        """Submit one native sound-test request."""
        if not self.supports_siren_test(device_sn):
            raise UnsupportedError(
                f"{redact_serial(device_sn)}: no dedicated siren test",
                device_sn=device_sn,
            )

        return await self._dedicated_alarm(
            device_sn,
            start=True,
            timeout=timeout,
            test=True,
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
        if alarms.momentary:
            return await self._dedicated_alarm(
                device_sn,
                start=start,
                timeout=timeout,
            )
        outcome = await self._station.session.async_send_alarm(
            request.command,
            render_alarm(request.params, channel=channel),
            channel=channel,
            on=start,
            timeout=timeout,
        )
        return self._station._answered(request.command, outcome)
