"""Lock sequence numbers, kept as the eufy app keeps them (declared, eufy app).

Per lock (1940 and 1930 forms): a sequence number ``R`` the lock reports is stored as
``R + 1``; each send uses the stored value plus one and stores it, the current Unix time
standing in for a lock with nothing stored. The 1961 form counts on one number shared by
every lock, starting at a random value below 1000. Kept in memory, as the app keeps them.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

_SHARED_START_BELOW = 1000


class LockSequences:
    """The stored sequence number of each lock."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._stored: dict[str, int] = {}

    def next(self, serial: str) -> int:
        """The sequence number to send to ``serial`` now (stored as sent)."""
        value = self._stored.get(serial, int(self._clock())) + 1
        self._stored[serial] = value
        return value

    def report(self, serial: str, seq_num: int) -> None:
        """Take the sequence number ``serial`` reported."""
        self._stored[serial] = seq_num + 1


class SharedSequence:
    """The one counter of the 1961 form: each send takes the next value."""

    def __init__(self, *, start: int | None = None) -> None:
        self._next = random.randrange(_SHARED_START_BELOW) if start is None else start

    def next(self) -> int:
        value = self._next
        self._next += 1
        return value
