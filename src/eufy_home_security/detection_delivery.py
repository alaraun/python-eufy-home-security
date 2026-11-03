"""Whether a device's detections are sent in the station's guard mode in force (pure).

Each camera, doorbell and sensor paired to a station has an action mask per guard mode
(the mode tables, ``docs/protocol/commands.md`` § Mode actions). Its Notification bit
(8, :data:`~.p2p.mode_actions.ACTION_FLAGS` ``notification``) decides whether the
station sends the device's detection pushes in that mode: with the bit clear, the
station sends none, neither over P2P nor through the cloud. The app's mode editor shows
the bit as the device's Notification switch, and the app reads a device whose action for
the mode is missing as on.

:func:`detection_delivery` reads the bit of the mode in force from a
:class:`~.station_config.StationConfig`; :meth:`~.station.Station.detection_delivery`
is the call a consumer makes. See ``docs/how-to/home-assistant.md`` § Detections held
back by the guard mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from .exceptions import ProtocolError
from .models import GuardMode
from .p2p.mode_actions import MODE_TABLE_MODES, mode_action_on
from .station_config import stored_mode_table

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .station import StationState
    from .station_config import ModeTableView, StationConfig

__all__ = [
    "NOTIFICATION_FLAG",
    "DetectionDelivery",
    "DetectionDeliveryReport",
    "detection_delivery",
    "table_mode",
]

NOTIFICATION_FLAG: Final = "notification"
"""The action flag that lets a device's detection pushes out in a mode."""

_TABLE_MODES: Final = frozenset({*MODE_TABLE_MODES, GuardMode.DISARMED})


class DetectionDelivery(StrEnum):
    """What the mode in force does to a device's detection pushes."""

    SENT = "sent"
    """The device's action in the mode in force has Notification on (or the station
    reports the device's actions and none is set for that mode, which reads as on): the
    mode holds nothing back."""
    NOT_SENT_IN_MODE = "not_sent_in_mode"
    """The device's action in the mode in force has Notification off: the station sends
    no detection push for it, over P2P or through the cloud, while that mode is in force."""
    UNKNOWN = "unknown"
    """The library cannot tell: no configuration yet, the mode in force unknown or
    without per-device actions, its table not reported, the device's own actions not
    reported, a device on a channel the cloud lists for several devices, or a device
    without a Notification action (the station itself, a keypad, a device of unknown
    kind)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionDeliveryReport:
    """Whether the station sends a device's detections in the guard mode in force."""

    device_sn: str
    delivery: DetectionDelivery
    mode: GuardMode | int | None
    """The guard mode in force the answer is for; None when it is not known."""
    action: int | None
    """The device's action mask in :attr:`mode`'s table; None when no reported table
    lists the device."""
    sending_modes: tuple[GuardMode, ...]
    """The modes, in the app's order, whose table the station reports and in which the
    device's detections are sent (Notification on, or no action set, read as on). Empty when
    no reported table sends them, or when nothing is known. Name them with
    :meth:`~.station_config.StationConfig.mode_name`."""
    reason: str
    """A sentence naming why, for a log line or a hint."""


def table_mode(mode: GuardMode | int) -> GuardMode | None:
    """The mode whose table holds the per-device actions in force while ``mode`` is in
    force: the mode itself for Away, Home, Custom 1-3 and Disarmed, Disarmed for Off
    (both read param 1177); None for a mode without per-device actions (Schedule, which
    is never in force itself, Geofencing, a code :class:`GuardMode` does not name)."""
    if mode == GuardMode.OFF:
        return GuardMode.DISARMED
    return next((m for m in _TABLE_MODES if m == mode), None)


def detection_delivery(
    config: StationConfig | None,
    device_sn: str,
    *,
    mode: GuardMode | int | None,
    has_notification_action: bool,
    state: StationState | None,
    channel: int | None,
) -> DetectionDeliveryReport:
    """Whether the station of ``config`` sends ``device_sn``'s detections while ``mode``
    is in force.

    ``has_notification_action`` says whether the device's kind and type have the
    Notification action (:func:`~.devices.settings.mode_action_flags`); without it, or
    without ``config``, the answer is :attr:`DetectionDelivery.UNKNOWN`. ``state`` is
    the station state ``config`` was built from (or a later one) and ``channel`` the
    channel the cloud lists the device on; a channel whose entries the cloud names no
    single device for (several devices claim it) is unknown.

    Otherwise the device's action in the table of ``mode`` (:func:`table_mode`) decides:
    Notification on is :attr:`~DetectionDelivery.SENT`, off is
    :attr:`~DetectionDelivery.NOT_SENT_IN_MODE`; a mode without a table, or a table the
    station does not report, is unknown. The action is the table's entry for the device,
    else the entry for ``channel`` in the station's stored table of that mode (a table
    built from the device blocks lacks the devices whose block the dump does not carry).
    With neither, the eufy app's rule applies: a missing action reads as on, so the
    answer is ``SENT`` when the device's own source is reported (its block in the dump,
    or the stored table) and unknown when it is not: an absent block is no missing
    action.
    """

    def report(
        delivery: DetectionDelivery,
        reason: str,
        *,
        action: int | None = None,
        sending: tuple[GuardMode, ...] = (),
    ) -> DetectionDeliveryReport:
        return DetectionDeliveryReport(
            device_sn=device_sn,
            delivery=delivery,
            mode=mode,
            action=action,
            sending_modes=sending,
            reason=reason,
        )

    if not has_notification_action:
        return report(DetectionDelivery.UNKNOWN, "the device has no per-mode Notification action")
    if config is None:
        return report(DetectionDelivery.UNKNOWN, "the station's configuration is not known yet")
    if (
        state is not None
        and channel is not None
        and state.serials_by_channel.get(channel) != device_sn
    ):
        return report(DetectionDelivery.UNKNOWN, "the cloud lists several devices on its channel")
    sending = _sending_modes(config, device_sn, state, channel)
    if mode is None:
        return report(DetectionDelivery.UNKNOWN, "the mode in force is not known", sending=sending)
    name = config.mode_name(mode)
    table_of = table_mode(mode)
    if table_of is None:
        return report(
            DetectionDelivery.UNKNOWN, f"{name} has no per-device actions", sending=sending
        )
    table = config.mode_tables.get(table_of)
    if table is None:
        return report(
            DetectionDelivery.UNKNOWN,
            f"the station reports no {config.mode_name(table_of)} table",
            sending=sending,
        )
    action, known = _action(table, device_sn, state, channel)
    if not known:
        return report(
            DetectionDelivery.UNKNOWN,
            f"no {name} action is reported for the device",
            sending=sending,
        )
    if action is None:
        return report(
            DetectionDelivery.SENT,
            f"no {name} action is set; read as on, as the eufy app does",
            sending=sending,
        )
    if mode_action_on(NOTIFICATION_FLAG, action):
        return report(
            DetectionDelivery.SENT,
            f"Notification is on in {name}",
            action=action,
            sending=sending,
        )
    return report(
        DetectionDelivery.NOT_SENT_IN_MODE,
        f"Notification is off in {name}: the station sends no detection push for this "
        "device in this mode",
        action=action,
        sending=sending,
    )


def _action(
    table: ModeTableView, device_sn: str, state: StationState | None, channel: int | None
) -> tuple[int | None, bool]:
    """(the device's action in ``table``'s mode, whether it is known): the table's entry,
    else the stored table's entry for ``channel``; (None, True) when the device's source
    is reported without one (read as on), (None, False) when it is not."""
    entry = table.device(device_sn)
    if entry is not None:
        return entry.action, True
    if state is None or channel is None:
        return None, False
    stored = _stored_actions(state, table.mode)
    if stored is not None and channel in stored:
        return stored[channel], True
    return None, stored is not None or channel in state.devices


def _stored_actions(state: StationState, mode: GuardMode) -> Mapping[int, int] | None:
    """channel → action of ``mode``'s table as the station stores it; None when the
    station reports none or it does not decode."""
    try:
        stored = stored_mode_table(state.setting_params, state.product_code, mode)
    except ProtocolError:
        return None
    return None if stored is None else stored.actions


def _sending_modes(
    config: StationConfig, device_sn: str, state: StationState | None, channel: int | None
) -> tuple[GuardMode, ...]:
    """The modes with a reported table in which ``device_sn``'s known action notifies or
    is unset, in the order of :attr:`~.station_config.StationConfig.mode_tables`."""
    sending: list[GuardMode] = []
    for mode, table in config.mode_tables.items():
        if table is None:
            continue
        action, known = _action(table, device_sn, state, channel)
        if known and (action is None or mode_action_on(NOTIFICATION_FLAG, action)):
            sending.append(mode)
    return tuple(sending)
