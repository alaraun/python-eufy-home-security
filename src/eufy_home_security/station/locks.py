"""The lock state of a station's smart locks (:class:`StationLocks`)."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.capabilities import Capability, profile_for_serial
from ..devices.locks import PUSH_STATES, LockReading, LockStateSource, state_of_code
from ..devices.model_settings import lock_state_read
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

if TYPE_CHECKING:
    from . import Station

_LOGGER = logging.getLogger(__name__)

LOCK_PUSH_MAX_AGE_SECONDS: Final = GUARD_PUSH_MAX_AGE_SECONDS
"""A lock push whose event time is older than this is a redelivery, not news."""
LOCK_REPORT_SLACK_SECONDS: Final = GUARD_REPORT_SLACK_SECONDS
"""A lock push older than the lock's last parameter report by more than this is about an
earlier change and is dropped; one inside it (the push announcing the change the report
carries, on another clock) is taken."""

_SOURCES: Final[Mapping[ValueSource, LockStateSource]] = {
    ValueSource.P2P: LockStateSource.P2P,
    ValueSource.NOTIFY: LockStateSource.NOTIFY,
    ValueSource.CLOUD: LockStateSource.CLOUD,
}


class StationLocks:
    """The lock state of every device on a station graded
    :attr:`~..devices.capabilities.Capability.LOCK`.

    Two sources feed it, ordered by time as the guard mode's are
    (:class:`~..events.GuardModeTracker`):

    * the lock-state parameter of the device's context (a dump, a parameter notify, the
      cloud's copy), the station's own report: taken when its value differs from the one
      taken before, and also when it repeats but dates from after the push the state came
      from (a dump taken after a push replaces it);
    * a cloud push about the lock (its ``event_type``), dated by its event time (its
      arrival when it has none): dropped when more than :data:`LOCK_PUSH_MAX_AGE_SECONDS`
      old, older than the last push taken, or older than the lock's last dated parameter
      report by more than :data:`LOCK_REPORT_SLACK_SECONDS`.
    """

    def __init__(
        self, station: Station, bus: EventBus, *, now_ms: Callable[[], int] = wall_ms
    ) -> None:
        self._station = station
        self._bus = bus
        self._now_ms = now_ms
        self._readings: dict[str, LockReading] = {}
        self._raw: dict[str, str] = {}
        """Per lock, the lock-state parameter's value last taken."""
        self._push_ms: dict[str, int] = {}
        """Per lock, the time of the last push taken (epoch ms)."""
        self._report_ms: dict[str, int] = {}
        """Per lock, the latest time a dated parameter report dates from (epoch ms)."""

    def reading(self, device_sn: str) -> LockReading | None:
        return self._readings.get(device_sn)

    def param_of(self, device: CloudDevice) -> int | None:
        """The parameter ``device`` reports its lock state in, in its context; None for a
        device that is no graded lock."""
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

    def refresh(self) -> None:
        """Take each lock's state parameter where it is news (see the class docstring)."""
        for device in self._station.devices:
            param = self.param_of(device)
            if param is None:
                continue
            report = self._station._param_report(device, param)
            if report is None:
                continue
            device_sn = device.device_sn
            at = None if report.at is None else int(report.at * 1000)
            if at is not None:
                self._report_ms[device_sn] = max(at, self._report_ms.get(device_sn, at))
            if self._raw.get(device_sn) == report.value and not self._after_push(device_sn, at):
                continue
            self._raw[device_sn] = report.value
            self._set(
                device_sn,
                LockReading(
                    state=state_of_code(report.value),
                    source=_SOURCES.get(report.source, LockStateSource.P2P),
                    raw=report.value,
                ),
            )

    def _after_push(self, device_sn: str, at: int | None) -> bool:
        """Whether a report dated ``at`` replaces the push the lock's state came from."""
        reading = self._readings.get(device_sn)
        if reading is None or reading.source is not LockStateSource.PUSH or at is None:
            return False
        return at > self._push_ms[device_sn]

    def on_param(self, event: ParamChanged) -> None:
        if any(self.param_of(d) == event.param_id for d in self._station.devices):
            self.refresh()

    def on_push(self, event: SecurityEvent) -> bool:
        """Take a cloud push about a lock of this station; whether it set a state."""
        device_sn, event_type = event.device_sn, event.event_type
        if device_sn is None or event_type is None or event_type not in PUSH_STATES:
            return False
        device = next((d for d in self._station.devices if d.device_sn == device_sn), None)
        if device is None or self.param_of(device) is None:
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
                state=PUSH_STATES[event_type], source=LockStateSource.PUSH, event_type=event_type
            ),
        )
        return True

    def _set(self, device_sn: str, reading: LockReading) -> None:
        old = self._readings.get(device_sn)
        self._readings[device_sn] = reading
        if old is not None and old.state is reading.state:
            return
        self._bus.emit(
            LockStateChanged(
                device_sn=device_sn,
                state=reading.state,
                source=reading.source,
                station_sn=self._station.serial,
                raw=reading.raw,
                event_type=reading.event_type,
            )
        )
