"""Per-camera wake back-off of a station's sessions (:class:`WakeBackoff`)."""

from __future__ import annotations

import time


class WakeBackoff:
    """The cameras the station could not wake, and until when their live opens are refused.

    A station session and its extra sessions share one, so a camera has one back-off.
    """

    def __init__(self) -> None:
        self.failures: dict[int, tuple[int, float, int]] = {}
        """Per camera channel: consecutive wake failures, until when opens are refused,
        and the last failure's receipt code."""

    def left(self, channel: int) -> float:
        """See :meth:`StationSession.wake_backoff_left`."""
        entry = self.failures.get(channel)
        return 0.0 if entry is None else max(entry[1] - time.monotonic(), 0.0)

    def clear(self, channel: int | None = None) -> None:
        """See :meth:`StationSession.clear_wake_backoff`."""
        if channel is None:
            self.failures.clear()
        else:
            self.failures.pop(channel, None)
