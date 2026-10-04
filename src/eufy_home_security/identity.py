"""Stable identifiers, and which account serves a station when several can.

A consumer that keeps a registry (Home Assistant's device and entity registries)
needs two guarantees, and both are decided here rather than in each consumer:

* **A stable id per device and entity.** A device is identified by its serial alone:
  a camera keeps its serial when it is moved to another HomeBase (its station and
  channel change), so ids built from (station, channel) would break. An entity is one
  ``(serial, key)`` pair, where ``key`` names what the entity shows — a setting key
  or a fixed name such as ``"guard_mode"``.
* **One account per station.** A HomeBase shared from its owner to another account
  is in both accounts' device lists. Serving it from both would open two P2P
  sessions to one base (which limits them, media first), deliver each event twice,
  and register every id twice. :class:`StationClaims` gives each station to exactly
  one account in the process: the owner's account when it is present, otherwise the
  first to claim it.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

from ._logging import redact, redact_serial
from .cloud.models import CloudDevice

_LOGGER = logging.getLogger(__name__)

_SERIAL: Final = re.compile(r"[A-Za-z0-9]+")
_KEY: Final = re.compile(r"[a-z0-9_]+")


def is_device_serial(serial: str) -> bool:
    """Whether ``serial`` can name a device in an id (letters and digits, not empty)."""
    return _SERIAL.fullmatch(serial) is not None


def entity_unique_id(serial: str, key: str) -> str:
    """The unique id of the entity showing ``key`` on the device ``serial``.

    ``serial_key``: a serial never contains ``_``, so the first ``_`` separates the
    two and different pairs can never produce the same id.
    """
    if not _SERIAL.fullmatch(serial):
        raise ValueError(f"not a device serial: {redact(serial)!r}")
    if not _KEY.fullmatch(key):
        raise ValueError(f"entity key {key!r} must be lower-case letters, digits and _")
    return f"{serial}_{key}"


@dataclass(slots=True)
class _Claim:
    holder: str
    owner: bool
    waiting: dict[str, None] = field(default_factory=dict)  # insertion-ordered set


class StationClaims:
    """Which account serves each station, shared by every account in one process.

    Accounts are named by any stable string — :class:`~.client.EufySecurity` uses its
    normalised e-mail. ``on_change(account)`` is called when an account should
    rebuild its stations: it lost a station to the owner's account, or a station it
    was waiting for was released. The account keeps its sessions until it rebuilds;
    in Home Assistant, reload that account's config entry.
    """

    def __init__(self, on_change: Callable[[str], None] | None = None) -> None:
        self._on_change = on_change
        self._claims: dict[str, _Claim] = {}

    def holder(self, serial: str) -> str | None:
        """The account serving ``serial``, if any."""
        claim = self._claims.get(serial)
        return claim.holder if claim else None

    def claim(self, account: str, stations: Iterable[CloudDevice]) -> frozenset[str]:
        """Claim ``stations`` (as ``account`` sees them); returns the serials it serves.

        A free station, or one this account already serves, is won. A station
        another account serves is won only by its owner's account from a shared
        member's; otherwise this account waits for it.
        """
        won: set[str] = set()
        preempted: dict[str, None] = {}
        for device in stations:
            serial, owner = device.device_sn, device.account_is_owner
            claim = self._claims.get(serial)
            if claim is None:
                self._claims[serial] = _Claim(account, owner)
            elif claim.holder == account:
                claim.owner = owner
            elif owner and not claim.owner:
                _LOGGER.info(
                    "%s moves to its owner's account; the shared account stops serving it",
                    redact_serial(serial),
                )
                preempted[claim.holder] = None
                claim.waiting.pop(account, None)
                claim.waiting[claim.holder] = None
                claim.holder, claim.owner = account, True
            else:
                _LOGGER.info("%s is served by another account", redact_serial(serial))
                claim.waiting[account] = None
                continue
            won.add(serial)
        for other in preempted:
            self._notify(other)
        return frozenset(won)

    def release(self, account: str) -> None:
        """Give up every station ``account`` serves; the accounts waiting for them rebuild."""
        rebuild: dict[str, None] = {}
        for serial, claim in list(self._claims.items()):
            claim.waiting.pop(account, None)
            if claim.holder == account:
                rebuild.update(claim.waiting)
                del self._claims[serial]
        for other in rebuild:
            self._notify(other)

    def _notify(self, account: str) -> None:
        if self._on_change is None:
            return
        try:
            self._on_change(account)
        except Exception:
            _LOGGER.exception("station claim change callback raised")
