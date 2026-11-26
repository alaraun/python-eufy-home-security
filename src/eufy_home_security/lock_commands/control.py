"""What every lock command path decides before and after it sends: refusals, the state it
asks for, and how a reading ends its wait (declared, eufy app; docs/protocol/locks.md §
Commands). No I/O beyond the bundled model data the MQTT selection reads, which the client
loads at discovery.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, NoReturn, Protocol

from .._logging import redact_serial
from ..devices.lock_routes import LockForm
from ..devices.locks import LockState
from ..exceptions import GuestAccessError, UnsupportedError
from ..mqtt.selection import is_mqtt_device
from .actions import LockAction

if TYPE_CHECKING:
    from ..cloud.models import CloudDevice

LOCK_PUBLISH_TIMEOUT: Final = 15.0
"""Seconds an MQTT lock command waits for the broker to take it, as the eufy app waits; its
answer wait (:data:`LOCK_ANSWER_TIMEOUT`) starts then."""
LOCK_ANSWER_TIMEOUT: Final = 20.0
"""Seconds a command waits for the lock's answer once the station took it, as the eufy app
waits."""
LOCK_CONFIRM_TIMEOUT: Final = 30.0
"""Seconds a command waits for the lock's new state after the lock accepted it, as the eufy
app waits."""
SEQUENCE_REFUSED: Final = -151
"""The station's result for a lock command whose sequence number it refused; on the
through-data forms the eufy app keeps waiting for the lock's answer."""
GUEST_MEMBER_TYPE: Final = 0
"""``member.member_type`` of a guest."""


class LockAccount(Protocol):
    """The account a lock command is sent for (the cloud client), read per command."""

    @property
    def user_id(self) -> str | None:
        """The account's cloud user id; None before a login."""
        ...

    @property
    def display_name(self) -> str:
        """The account's name a command names as its sender."""
        ...


TARGET_STATES: Final[Mapping[LockAction, LockState]] = {
    LockAction.LOCK: LockState.LOCKED,
    LockAction.UNLOCK: LockState.UNLOCKED,
}
FAULT_STATES: Final = frozenset({LockState.JAMMED, LockState.INTERMEDIATE})
"""States that end a command's wait as not applied: the bolt is stuck."""


class LockPath(StrEnum):
    """Which channel carries a lock's commands."""

    STATION = "station"
    """The lock's station session (P2P)."""
    MQTT = "mqtt"
    """The eufy security MQTT broker."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LockControl:
    """Whether and how the library can lock and unlock a lock.

    ``form`` is the lock's command form (None: the lock has no route); ``path`` the channel
    that carries it, None when the library cannot send it; ``reason`` why not, in words a UI
    can show (None when ``writable``).
    """

    form: LockForm | None
    path: LockPath | None
    reason: str | None = None
    guest: bool = False
    """The account is a guest of the lock."""

    @property
    def writable(self) -> bool:
        return self.path is not None


def is_guest(device: CloudDevice) -> bool:
    """Whether the account is a guest of ``device``: its member record names
    ``member_type`` 0, or names none, which the eufy app reads as 0. No member record: not
    a guest."""
    if device.member_type is not None:
        return device.member_type == GUEST_MEMBER_TYPE
    return device.has_member_relation


def has_member_record(device: CloudDevice) -> bool:
    """Whether ``device``'s cloud entry carries a member record for the account (any of its
    fields; a record without ``admin_user_id`` is enough), which a lock command needs, as
    the eufy app sends none without one. A record naming none of them reads as a guest's
    (:func:`is_guest`), refused before this matters."""
    return any(
        value is not None
        for value in (
            device.owner_user_id,
            device.member_type,
            device.member_user_id,
            device.short_user_id,
        )
    )


NOT_SELECTED_FOR_MQTT: Final = (
    "the lock takes its commands over MQTT, but no MQTT connection of the eufy app serves it"
)
"""The reason of an MQTT lock that neither of the app's MQTT connectors selects
(:func:`~..mqtt.selection.is_mqtt_device`): the account would serve no connection for it."""


def lock_control(form: LockForm | None, device: CloudDevice) -> LockControl:
    """The control a lock with route ``form`` offers this account, from ``device``'s cloud
    record: its member record (a guest has none) and, on the MQTT path, whether the eufy
    app's MQTT selection serves it (the account's own rule,
    :func:`~..mqtt.selection.is_mqtt_device`, so a writable MQTT lock is always one the
    account connects). Reads the model's bundled data the client loaded at discovery."""
    if form is None:
        return LockControl(form=None, path=None, reason="no lock command route for this model")
    if form is LockForm.P2P_1911:
        return LockControl(
            form=form,
            path=None,
            reason="the lock takes its commands as Bluetooth frames through its station, "
            "which this library does not build",
        )
    if form is LockForm.MQTT and not is_mqtt_device(device):
        return LockControl(form=form, path=None, reason=NOT_SELECTED_FOR_MQTT)
    if is_guest(device):
        return LockControl(
            form=form,
            path=None,
            reason="the account is a guest of the lock: no lock control",
            guest=True,
        )
    return LockControl(form=form, path=LockPath.MQTT if form is LockForm.MQTT else LockPath.STATION)


def refuse(control: LockControl, device_sn: str) -> NoReturn:
    """Raise the refusal of a control that cannot send: :class:`GuestAccessError` for a
    guest, :class:`UnsupportedError` with ``control.reason`` otherwise."""
    name = redact_serial(device_sn)
    if control.guest:
        raise GuestAccessError(f"{name}: {control.reason}", device_sn=device_sn)
    raise UnsupportedError(f"{name}: {control.reason}", device_sn=device_sn)


def check_control(control: LockControl, device_sn: str, path: LockPath) -> LockForm:
    """``control``'s form when ``path`` can send it; else the typed refusal, before sending
    (:func:`refuse`, or :class:`UnsupportedError` for another path)."""
    if control.path is None or control.form is None:
        refuse(control, device_sn)
    name = redact_serial(device_sn)
    if control.path is not path:
        raise UnsupportedError(
            f"{name} takes its commands over {control.path.value}, not {path.value}",
            device_sn=device_sn,
        )
    return control.form


def phase_wait(default: float, deadline: float | None, now: float) -> float:
    """The bound of one wait of a command: its own ``default`` (the app's wait), cut to
    what is left at ``now`` before the call's ``deadline`` (None: the call has none)."""
    if deadline is None:
        return default
    return max(0.0, min(default, deadline - now))


def ends_wait(reading_state: LockState, target: LockState) -> bool:
    """Whether a reading taken while a command waits ends the wait: the asked state, or a
    fault state (the command did not move the bolt)."""
    return reading_state is target or reading_state in FAULT_STATES
