"""The lock state of smart locks: one merged reading per lock (:class:`LockStates`), kept for
a station's locks by :class:`StationLocks` and for locks no station serves by
:class:`ListedLocks`."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.capabilities import Capability, profile_for_serial
from ..devices.locks import PUSH_STATES, LockReading, LockStateSource, state_of_code
from ..devices.model_settings import lock_state_read, product_code_of
from ..devices.support import Support
from ..events import (
    GUARD_PUSH_MAX_AGE_SECONDS,
    GUARD_REPORT_SLACK_SECONDS,
    EventBus,
    LockStateChanged,
    ParamChanged,
    SecurityEvent,
    wall_ms,
)
from ..models import ValueSource
from .base import ParamReport

if TYPE_CHECKING:
    from . import Station

_LOGGER = logging.getLogger(__name__)

LOCK_PUSH_MAX_AGE_SECONDS: Final = GUARD_PUSH_MAX_AGE_SECONDS
"""A lock push whose event time is older than this is a redelivery, not news."""
LOCK_REPORT_SLACK_SECONDS: Final = GUARD_REPORT_SLACK_SECONDS
"""A lock push (or a cloud copy of the lock-state parameter) older than the lock's last
report by more than this is about an earlier change and is dropped; one inside it (the
push announcing the change the report carries, on another clock) is taken."""

_SOURCES: Final[Mapping[ValueSource, LockStateSource]] = {
    ValueSource.P2P: LockStateSource.P2P,
    ValueSource.NOTIFY: LockStateSource.NOTIFY,
    ValueSource.CLOUD: LockStateSource.CLOUD,
}


_DATED_BY_ARRIVAL: Final = frozenset({LockStateSource.PUSH, LockStateSource.LOCK})
"""Sources whose reading is dated by its arrival: a parameter report after it replaces it
even when it repeats the value taken before."""


def _ms(seconds: float | None) -> int | None:
    return None if seconds is None else int(seconds * 1000)


class LockStates:
    """One merged lock state per lock, from every source, ordered by report time.

    Sources (:class:`~..devices.locks.LockStateSource`):

    * the lock-state parameter of the lock's context (a station's dump or parameter
      notify, dated by its arrival; the device list's copy, dated by the cloud's upload
      time or undated);
    * a cloud push about the lock (its ``event_type``), dated by its event time (its
      arrival when it has none);
    * the lock's own status report, over a station session or the MQTT broker, dated by
      its arrival.

    The newest report wins:

    * a parameter report is taken when its value differs from the lock's last value (the
      lock's own report writes its code there, as one value is kept per lock), and also
      when it repeats but dates from after the push or status report the state came from
      (a dump taken after a push replaces it). A changed value from the device list's copy
      is dropped when it dates from before the lock's reading by more than
      :data:`LOCK_REPORT_SLACK_SECONDS`; an undated copy never replaces a dated reading;
    * a push is dropped when more than :data:`LOCK_PUSH_MAX_AGE_SECONDS` old, older than
      the last push or status report taken, or older than the lock's last dated parameter
      report by more than :data:`LOCK_REPORT_SLACK_SECONDS`;
    * the lock's own status report is always taken.

    Subclasses name the locks and their parameter reports.
    """

    def __init__(self, bus: EventBus, *, now_ms: Callable[[], int] = wall_ms) -> None:
        self._bus = bus
        self._now_ms = now_ms
        self._readings: dict[str, LockReading] = {}
        self._raw: dict[str, str] = {}
        """Per lock, the lock-state value last taken (a parameter's, or the code of the
        lock's own report)."""
        self._push_ms: dict[str, int] = {}
        """Per lock, the time of the last push or own status report taken (epoch ms)."""
        self._report_ms: dict[str, int] = {}
        """Per lock, the latest time a dated parameter report dates from (epoch ms)."""
        self._watchers: dict[str, list[Callable[[LockReading], None]]] = {}

    # ── the locks (subclasses) ───────────────────────────────────────────────

    def _lock_devices(self) -> Iterable[CloudDevice]:
        raise NotImplementedError

    def param_of(self, device: CloudDevice) -> int | None:
        """The parameter ``device`` reports its lock state in, in its context; None for a
        device that is no graded lock."""
        raise NotImplementedError

    def _report(self, device: CloudDevice, param_id: int) -> ParamReport | None:
        raise NotImplementedError

    @property
    def _station_sn(self) -> str | None:
        return None

    # ── reading ──────────────────────────────────────────────────────────────

    def reading(self, device_sn: str) -> LockReading | None:
        return self._readings.get(device_sn)

    def serves(self, device_sn: str) -> bool:
        """Whether ``device_sn`` is one of the devices these states are kept for (its own
        status reports are taken whether or not its model names a lock-state parameter)."""
        return any(d.device_sn == device_sn for d in self._lock_devices())

    def _graded(self, device_sn: str) -> bool:
        """Whether ``device_sn`` is one of these devices and its model names a lock-state
        parameter (a lock whose pushes are read)."""
        return any(
            d.device_sn == device_sn and self.param_of(d) is not None for d in self._lock_devices()
        )

    def watch(self, device_sn: str, callback: Callable[[LockReading], None]) -> Callable[[], None]:
        """Call ``callback`` with every reading taken for ``device_sn`` (a repeated state
        included) until the returned unsubscribe is called."""
        watchers = self._watchers.setdefault(device_sn, [])
        watchers.append(callback)

        def unsubscribe() -> None:
            if callback in watchers:
                watchers.remove(callback)

        return unsubscribe

    # ── reports ──────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Take each lock's state parameter where it is news (see the class docstring)."""
        for device in self._lock_devices():
            param = self.param_of(device)
            if param is None:
                continue
            report = self._report(device, param)
            if report is None:
                continue
            device_sn = device.device_sn
            at = _ms(report.at)
            if at is not None:
                self._report_ms[device_sn] = max(at, self._report_ms.get(device_sn, at))
            if self._raw.get(device_sn) == report.value:
                if not self._after_push(device_sn, at):
                    continue
            elif report.source is ValueSource.CLOUD and self._older_copy(device_sn, at):
                continue
            self._raw[device_sn] = report.value
            self._set(
                device_sn,
                LockReading(
                    state=state_of_code(report.value),
                    source=_SOURCES.get(report.source, LockStateSource.P2P),
                    raw=report.value,
                    observed_at=report.at,
                ),
            )

    def _after_push(self, device_sn: str, at: int | None) -> bool:
        """Whether a report dated ``at`` replaces the push the lock's state came from."""
        reading = self._readings.get(device_sn)
        if reading is None or reading.source not in _DATED_BY_ARRIVAL or at is None:
            return False
        return at > self._push_ms[device_sn]

    def _older_copy(self, device_sn: str, at: int | None) -> bool:
        """Whether a cloud copy dated ``at`` (None: undated) is older than the lock's
        reading: undated against a dated reading, or dated before it by more than the
        slack."""
        reading = self._readings.get(device_sn)
        held = None if reading is None else _ms(reading.observed_at)
        if reading is None or held is None:
            return False
        return at is None or at < held - LOCK_REPORT_SLACK_SECONDS * 1000

    def on_param(self, event: ParamChanged) -> None:
        if any(self.param_of(d) == event.param_id for d in self._lock_devices()):
            self.refresh()

    def on_push(self, event: SecurityEvent) -> bool:
        """Take a cloud push about one of these locks; whether it set a state."""
        device_sn, event_type = event.device_sn, event.event_type
        if device_sn is None or event_type is None or event_type not in PUSH_STATES:
            return False
        if not self._graded(device_sn):
            return False
        now = self._now_ms()
        at = now if event.event_time_ms is None else event.event_time_ms
        if (
            now - at > LOCK_PUSH_MAX_AGE_SECONDS * 1000
            or at < self._push_ms.get(device_sn, at)
            or at < self._report_ms.get(device_sn, at) - LOCK_REPORT_SLACK_SECONDS * 1000
        ):
            _LOGGER.debug("%s: dropping a lock push older than its state", redact_serial(device_sn))
            return False
        self._push_ms[device_sn] = at
        self._set(
            device_sn,
            LockReading(
                state=PUSH_STATES[event_type],
                source=LockStateSource.PUSH,
                event_type=event_type,
                observed_at=at / 1000,
            ),
        )
        return True

    def on_report(self, device_sn: str, state_code: int) -> None:
        """Take the lock's own status report (a lock-state code), news from now; its code
        becomes the lock's last value, so a later parameter report of another value is
        news."""
        now = self._now_ms()
        self._push_ms[device_sn] = now
        self._raw[device_sn] = str(state_code)
        self._set(
            device_sn,
            LockReading(
                state=state_of_code(state_code),
                source=LockStateSource.LOCK,
                raw=str(state_code),
                observed_at=now / 1000,
            ),
        )

    def _set(self, device_sn: str, reading: LockReading) -> None:
        old = self._readings.get(device_sn)
        self._readings[device_sn] = reading
        for watcher in list(self._watchers.get(device_sn, ())):
            watcher(reading)
        self._bus.emit(
            LockStateChanged(
                device_sn=device_sn,
                state=reading.state,
                source=reading.source,
                station_sn=self._station_sn,
                raw=reading.raw,
                event_type=reading.event_type,
                observed_at=reading.observed_at,
                changed=old is None or old.state is not reading.state,
            )
        )


class StationLocks(LockStates):
    """The lock state of every device on a station graded
    :attr:`~..devices.capabilities.Capability.LOCK` (:class:`LockStates`): the lock-state
    parameter of its context as the station last reported it (over the cloud's copy)."""

    def __init__(
        self, station: Station, bus: EventBus, *, now_ms: Callable[[], int] = wall_ms
    ) -> None:
        super().__init__(bus, now_ms=now_ms)
        self._station = station

    def _lock_devices(self) -> Iterable[CloudDevice]:
        return self._station.devices

    @property
    def _station_sn(self) -> str | None:
        return self._station.serial

    def param_of(self, device: CloudDevice) -> int | None:
        profile = profile_for_serial(device.device_sn)
        if profile is None or profile.support(Capability.LOCK) is Support.UNKNOWN:
            return None
        read = lock_state_read(self._station._product_code(device.device_sn))
        if read is None:
            return None
        station = self._station
        if device is station.device and station.is_standalone:
            return read.param_for(standalone=True)
        return read.param_for(station._connect_type_of(device.device_sn))

    def _report(self, device: CloudDevice, param_id: int) -> ParamReport | None:
        return self._station._param_report(device, param_id)


class ListedLocks(LockStates):
    """The lock state of the listed locks no station of the client serves
    (:class:`LockStates`), each its own: the device list's copy of its lock-state
    parameter, pushes and its own status reports (over the MQTT broker).

    ``devices`` gives those locks' current device-list entries; events name no station.
    """

    def __init__(
        self,
        bus: EventBus,
        devices: Callable[[], Iterable[CloudDevice]],
        *,
        now_ms: Callable[[], int] = wall_ms,
    ) -> None:
        super().__init__(bus, now_ms=now_ms)
        self._devices = devices

    def _lock_devices(self) -> Iterable[CloudDevice]:
        return self._devices()

    def param_of(self, device: CloudDevice) -> int | None:
        profile = profile_for_serial(device.device_sn)
        if profile is None or profile.support(Capability.LOCK) is Support.UNKNOWN:
            return None
        read = lock_state_read(product_code_of(device.raw.get("device_new_pn"), device.device_sn))
        return None if read is None else read.param_for(standalone=True)

    def _report(self, device: CloudDevice, param_id: int) -> ParamReport | None:
        cloud = next((p for p in device.cloud_params if p.param_id == param_id), None)
        return (
            None if cloud is None else ParamReport(cloud.value, ValueSource.CLOUD, cloud.updated_at)
        )
