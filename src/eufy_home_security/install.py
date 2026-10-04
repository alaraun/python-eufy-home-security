"""State shared by every account of one install (one process).

The eufy cloud's request limit (``API_REQUEST_LIMIT``, HTTP 429) may apply to the
host rather than to one account. Each account's :class:`~.storage.SessionCache`
persists its own hold-off; :class:`InstallState` carries a request hold-off seen by
one account over to every other account of the running process, so a second account
does not keep calling a cloud that has just throttled the first.

In-process only: nothing here is persisted. After a restart each account's own store
still holds its own hold-off. A login hold-off is never shared: a lockout belongs to
the account whose password was refused.
"""

from __future__ import annotations

import time


class InstallState:
    """Process-wide state shared by every :class:`~.client.EufySecurity` of one install.

    Pass one instance to every account of a process (like
    :class:`~.identity.StationClaims`); in Home Assistant, keep it in ``hass.data``.
    """

    def __init__(self) -> None:
        self._requests_until: float | None = None  # time.monotonic() deadline

    def request_held_off_for(self) -> float | None:
        """Seconds left on the shared request hold-off, or None when there is none."""
        if self._requests_until is None:
            return None
        left = self._requests_until - time.monotonic()
        if left <= 0:
            self._requests_until = None
            return None
        return left

    def hold_off_requests(self, seconds: float) -> None:
        """Hold every account's cloud requests off for ``seconds``; never shortens one."""
        if seconds <= 0:
            return
        until = time.monotonic() + seconds
        if self._requests_until is None or until > self._requests_until:
            self._requests_until = until
