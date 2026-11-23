"""Counter-only per-camera activity observations; no recording history requests.

A rising counter emits one aggregate observation (with its delta), not one event
per counted item. First usable values, reconnects and missing values rebaseline.
SecurityEvent pushes are separate and never generate counted-events observations.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from ..devices.types import model_for_serial
from ..events import DetectedEventsCounted, RecordedEventsCounted

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
        emit: Callable[[DetectedEventsCounted | RecordedEventsCounted], None],
    ) -> None:
        self._station = station
        self._emit = emit
        self._previous: dict[str, tuple[int | None, int | None]] = {}
        self._closed = False

    def reopen(self) -> None:
        """Clear counter baselines at startup or after a station link loss."""
        self._closed = False
        self._previous.clear()

    def observe(self, state: StationState) -> None:
        """Report camera deltas unless explicitly offline.

        A missing online flag (None) is unknown, not an offline report.
        """
        if self._closed:
            return
        next_values: dict[str, tuple[int | None, int | None]] = {}
        now = datetime.now(UTC)
        for device in state.devices.values():
            serial = device.serial
            if serial is None or device.online is False:
                continue
            model = model_for_serial(serial)
            # Known non-camera devices are excluded. An uncatalogued camera
            # may still report 1192/1193 and should not be excluded.
            if model is not None and not model.has_camera:
                continue
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
                    DetectedEventsCounted(
                        station_sn=self._station.serial,
                        device_sn=serial,
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
                    RecordedEventsCounted(
                        station_sn=self._station.serial,
                        device_sn=serial,
                        count=recorded_new - recorded_old,
                        observed_at=now,
                    )
                )
        # A missing/offline device or missing counter never causes a false delta.
        self._previous = next_values

    async def close(self) -> None:
        """Shut down the observer (no tasks or background workers to cancel)."""
        self._closed = True
        self._previous.clear()
