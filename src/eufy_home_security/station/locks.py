"""The lock state of a station's smart locks (:class:`StationLocks`)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from ..cloud.models import CloudDevice
from ..devices.capabilities import Capability, profile_for_serial
from ..devices.locks import PUSH_STATES, LockReading, LockStateSource, state_of_code
from ..devices.model_settings import lock_state_read
from ..devices.support import Support
from ..events import EventBus, LockStateChanged, ParamChanged, SecurityEvent
from ..models import ValueSource

if TYPE_CHECKING:
    from . import Station

_SOURCES: Final[Mapping[ValueSource, LockStateSource]] = {
    ValueSource.P2P: LockStateSource.P2P,
    ValueSource.NOTIFY: LockStateSource.NOTIFY,
    ValueSource.CLOUD: LockStateSource.CLOUD,
}


class StationLocks:
    """The lock state of every device on a station graded
    :attr:`~..devices.capabilities.Capability.LOCK`.

    The state is the latest news from any source: the lock-state parameter of the
    device's context (a dump, a parameter notify, the cloud's copy; a value is taken when
    it differs from the previous one of that parameter) or a cloud push about the lock
    (one older than the last push taken is ignored: the cloud redelivers and reorders).
    """

    def __init__(self, station: Station, bus: EventBus) -> None:
        self._station = station
        self._bus = bus
        self._readings: dict[str, LockReading] = {}
        self._raw: dict[str, str] = {}
        """Per lock, the lock-state parameter's value last taken."""
        self._push_ms: dict[str, int] = {}
        """Per lock, the event time of the last push taken."""

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
        """Take each lock's state parameter where it changed."""
        for device in self._station.devices:
            param = self.param_of(device)
            if param is None:
                continue
            report = self._station._param_report(device, param)
            if report is None or self._raw.get(device.device_sn) == report[0]:
                continue
            raw, source = report
            self._raw[device.device_sn] = raw
            self._set(
                device.device_sn,
                LockReading(
                    state=state_of_code(raw),
                    source=_SOURCES.get(source, LockStateSource.P2P),
                    raw=raw,
                ),
            )

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
        at = event.event_time_ms
        if at is not None:
            if at < self._push_ms.get(device_sn, at):
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
