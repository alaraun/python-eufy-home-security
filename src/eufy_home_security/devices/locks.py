"""The lock state of a smart lock, as the eufy app shows it on the lock's card (declared,
eufy app).

The state parameter per context comes from the model's file (``lock``, generated from its
handler's read of ``smart_lock_onoff_status``); its raw code, a push's ``event_type`` and
their meanings are the app's. See docs/how-to/home-assistant.md § Locks and
docs/protocol/events.md § Lock pushes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ..p2p._json import json_int
from .model_settings import lock_state_read
from .support import Evidence, Support


class LockState(StrEnum):
    """The state of a lock."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    LOCKING = "locking"
    UNLOCKING = "unlocking"
    JAMMED = "jammed"
    """The app's fault state, which its card shows as jammed: a mechanical fault the lock
    reports, and every code the app names no state for."""
    NOT_CALIBRATED = "not_calibrated"
    SYNCING = "syncing"
    UNKNOWN = "unknown"
    """Nothing reported yet, a value that is no code, or a lock the eufy cloud reports
    offline."""


class LockStateSource(StrEnum):
    """What delivered a lock state."""

    P2P = "p2p"
    """A station's parameter dump over P2P."""
    NOTIFY = "notify"
    """A station's parameter notify between dumps."""
    CLOUD = "cloud"
    """The device list's parameters (the cloud's copy)."""
    PUSH = "push"
    """A cloud push about the lock (its ``event_type``)."""


CODE_STATES: Final[Mapping[int, LockState]] = MappingProxyType(
    {
        0: LockState.SYNCING,
        1: LockState.NOT_CALIBRATED,
        2: LockState.JAMMED,
        3: LockState.UNLOCKED,
        4: LockState.LOCKED,
        5: LockState.JAMMED,
        6: LockState.UNLOCKING,
        7: LockState.LOCKING,
        8: LockState.UNLOCKED,
        9: LockState.JAMMED,
    }
)
"""The state of each raw code of the lock-state parameter; any other integer is
:attr:`LockState.JAMMED`, as the app's card shows it (declared, eufy app)."""


def state_of_code(raw: object) -> LockState:
    """The state of a lock-state parameter's value (its text or number): the code's state,
    :attr:`LockState.JAMMED` for an integer no state is named for, and
    :attr:`LockState.UNKNOWN` for None or a value that is no integer (the library's
    reading; the app shows its syncing state when the parameter is missing)."""
    code = json_int(raw.strip() if isinstance(raw, str) else raw)
    if code is None:
        return LockState.UNKNOWN
    return CODE_STATES.get(code, LockState.JAMMED)


_UNLOCK_EVENTS: Final = (257, 258, 259, 260, 261, 269, 270, 530, 532, 538, 549, 550, 562)
_LOCK_EVENTS: Final = (262, 263, 264, 265, 266, 267, 268, 271, 531, 533, 551, 552, 561)
_JAMMED_EVENTS: Final = (517, 519)
LOCK_OFFLINE_EVENT: Final = 516
"""The push ``event_type`` of a lock the cloud reports offline."""

PUSH_STATES: Final[Mapping[int, LockState]] = MappingProxyType(
    {
        **dict.fromkeys(_UNLOCK_EVENTS, LockState.UNLOCKED),
        **dict.fromkeys(_LOCK_EVENTS, LockState.LOCKED),
        **dict.fromkeys(_JAMMED_EVENTS, LockState.JAMMED),
        LOCK_OFFLINE_EVENT: LockState.UNKNOWN,
    }
)
"""The state a lock's push ``event_type`` sets, as the eufy app sets its card from the
push (declared, eufy app): each unlock event (by hand, code, fingerprint, app, NFC, palm,
face, one key, Matter, ...) unlocked, each lock event locked, a mechanical fault jammed.
An offline lock (:data:`LOCK_OFFLINE_EVENT`) is :attr:`LockState.UNKNOWN`: the library's
reading; the app sets a code its card shows as its fault state."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LockReading:
    """A lock's state and where it came from.

    ``raw`` is the lock-state parameter's value for a parameter source, None for a push;
    ``event_type`` is the push's for :attr:`LockStateSource.PUSH`, else None.
    """

    state: LockState
    source: LockStateSource
    raw: str | None = None
    event_type: int | None = None


_DECLARED: Final = Evidence(
    Support.DECLARED,
    "declared (eufy app): the model's smart_lock_onoff_status read and the lock card's "
    "state codes and push events",
    "state only: no lock or unlock command; not verified on hardware",
)


def lock_evidence(product_code: str | None) -> Evidence | None:
    """The grade of a model's lock state; None for a model without one (no file, or no
    ``lock`` in it). Reads the model's file like :func:`~.model_settings.settings_of`
    (same memo) and raises like it."""
    return None if lock_state_read(product_code) is None else _DECLARED
