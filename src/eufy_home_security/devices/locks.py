"""The lock state of a smart lock, as the eufy app reads it (declared, eufy app).

The state parameter per context comes from the model's file (``lock``, generated from its
handler's read of ``smart_lock_onoff_status``); its codes are read as the app's lock
controls read that property, a push's ``event_type`` as the app sets the lock from it.
See docs/how-to/home-assistant.md § Locks and docs/protocol/events.md § Lock pushes.
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
    """The state of a lock: the lock-state codes as the eufy app's lock controls name them,
    plus the push-only :attr:`JAMMED` and :attr:`UNKNOWN`."""

    INITIAL = "initial"
    """Code 0: the lock reported no state yet."""
    UNCALIBRATED = "uncalibrated"
    CALIBRATING = "calibrating"
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    INTERMEDIATE = "intermediate"
    """Code 5: the bolt stopped between its positions; the app shows it as jammed."""
    UNLOCKING = "unlocking"
    LOCKING = "locking"
    PASSAGE_MODE = "passage_mode"
    """Code 8: held unlocked (passage mode)."""
    PRIVACY_MODE = "privacy_mode"
    """Code 9: locked against every key but the owner's (privacy mode)."""
    JAMMED = "jammed"
    """A mechanical fault the lock's push reports (no lock-state code); it lasts until the
    next report of the lock's state (a parameter report taken after the push, or a push)."""
    UNKNOWN = "unknown"
    """Nothing reported, a value that is no code or a code the app names no state for, or a
    lock the eufy cloud reports offline."""


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
        0: LockState.INITIAL,
        1: LockState.UNCALIBRATED,
        2: LockState.CALIBRATING,
        3: LockState.UNLOCKED,
        4: LockState.LOCKED,
        5: LockState.INTERMEDIATE,
        6: LockState.UNLOCKING,
        7: LockState.LOCKING,
        8: LockState.PASSAGE_MODE,
        9: LockState.PRIVACY_MODE,
    }
)
"""The state of each code of the lock-state parameter, as the eufy app's lock controls read
the lock's ``smart_lock_onoff_status`` (declared, eufy app)."""


def state_of_code(raw: object) -> LockState:
    """The state of a lock-state parameter's value (its text or number): the code's state,
    :attr:`LockState.UNKNOWN` for None, a value that is no integer, or another integer."""
    code = json_int(raw.strip() if isinstance(raw, str) else raw)
    return LockState.UNKNOWN if code is None else CODE_STATES.get(code, LockState.UNKNOWN)


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
