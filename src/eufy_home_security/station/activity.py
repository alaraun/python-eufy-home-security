"""Counter-driven per-camera motion activity; no recording history requests.

A rising counter yields one observation (with its delta), not one synthetic event
per counted item. The first usable value and values after an outage are baselines.
Pushes are a fallback only for devices without a usable detection counter; normal
push handling and the existing detection entity remain independent.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from ..devices.types import model_for_serial
from ..events import DETECTION_KINDS, MotionDetected, MotionRecorded, SecurityEvent

if TYPE_CHECKING:
    from . import StationState


class ActivityStation(Protocol):
    @property
    def serial(self) -> str: ...


class StationActivity:
    """Observe the station's existing parameter snapshots without extra I/O."""

    def __init__(
        self,
        station: ActivityStation,
        emit: Callable[[MotionDetected | MotionRecorded], None],
    ) -> None:
        self._station = station
        self._emit = emit
        self._previous: dict[str, tuple[int | None, int | None]] = {}
        self._known_online: set[str] = set()
        self._closed = False

    def reopen(self) -> None:
        """Clear counter baselines at startup or after a station link loss."""
        self._closed = False
        self._previous.clear()
        self._known_online.clear()

    def observe(self, state: StationState) -> None:
        """Report camera deltas unless explicitly offline.

        A missing online flag (None) is unknown, not an offline report.
        """
        if self._closed:
            return
        next_values: dict[str, tuple[int | None, int | None]] = {}
        known_online: set[str] = set()
        now = datetime.now(UTC)
        for device in state.devices.values():
            serial = device.serial
            if serial is None or device.online is False:
                continue
            model = model_for_serial(serial)
            if model is None or not model.has_camera:
                continue
            known_online.add(serial)
            current = (device.detected_events, device.recorded_events)
            previous = self._previous.get(serial)
            next_values[serial] = current
            if previous is None:
                continue  # first sighting after startup or reconnection
            detected_old, recorded_old = previous
            detected_new, recorded_new = current
            if (
                detected_old is not None
                and detected_new is not None
                and detected_new > detected_old
            ):
                self._emit(
                    MotionDetected(
                        station_sn=self._station.serial,
                        device_sn=serial,
                        source="counter",
                        count=detected_new - detected_old,
                        observed_at=now,
                    )
                )
            if (
                recorded_old is not None
                and recorded_new is not None
                and recorded_new > recorded_old
            ):
                self._emit(
                    MotionRecorded(
                        station_sn=self._station.serial,
                        device_sn=serial,
                        count=recorded_new - recorded_old,
                        observed_at=now,
                    )
                )
        # A missing/offline device or missing counter never causes a false delta.
        self._previous = next_values
        self._known_online = known_online

    def on_security_event(self, event: SecurityEvent) -> None:
        """Fall back to admitted pushes only when no detection counter is available."""
        if (
            self._closed
            or event.station_sn != self._station.serial
            or event.device_sn is None
            or event.device_sn not in self._known_online
            or event.detection not in DETECTION_KINDS
            or event.enriches
        ):
            return
        if self._previous.get(event.device_sn, (None, None))[0] is not None:
            return  # the counter is authoritative; don't produce push+counter duplicates
        self._emit(
            MotionDetected(
                station_sn=self._station.serial,
                device_sn=event.device_sn,
                source="push",
                count=1,
                observed_at=datetime.now(UTC),
            )
        )

    async def close(self) -> None:
        """Shut down the observer (no tasks or background workers to cancel)."""
        self._closed = True
        self._previous.clear()
        self._known_online.clear()
