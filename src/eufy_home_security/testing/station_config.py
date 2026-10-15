"""A station's mode list and schedule as parameter values, encoded by the library's codecs.

Each helper returns ``{param: value}`` for the station's own block: put it in
:attr:`.FakeStation.params` (``station.params[255].update(...)``, or
:meth:`.FakeStation.set_mode_list` / :meth:`.FakeStation.set_schedule`) for the parameter
dump, or in the cloud's copy (:func:`.station_device` ``params=``,
:meth:`.FakeCloud.set_station_params`), where a HomeBase 3 keeps them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..models import GuardMode
from ..p2p.station_config_codecs import (
    BUILT_IN_MODE_TITLES,
    CMD_CUSTOM_MODES,
    CMD_SCHEDULE,
    CMD_SCHEDULE_DEFAULT,
    DEFAULT_MODE_ICON,
    CustomModes,
    ModeDefinition,
    Schedule,
    ScheduleSlot,
    encode_schedule_default,
    require_custom_mode,
)
from .synthetic import SYNTHETIC

__all__ = ["mode_list_params", "schedule_params"]

_BUILT_IN_ICONS = {GuardMode.HOME: 1, GuardMode.AWAY: 0}
"""The icons the app gives the built-in modes in its list."""


def mode_list_params(
    titles: Mapping[GuardMode | int, str],
    *,
    icons: Mapping[GuardMode | int, int] | None = None,
    account_id: str = SYNTHETIC.account_id,
) -> dict[int, str]:
    """The mode list (1256) naming custom modes ``titles`` (Custom 1-3 → title).

    Home and Away are listed first, as the app stores the list; a custom mode left out
    of ``titles`` does not exist on the station. ``icons`` gives a custom mode's
    ``iconType`` (default :data:`~..p2p.station_config_codecs.DEFAULT_MODE_ICON`).
    Raises ``ValueError`` for a mode in ``titles`` that is not Custom 1-3.
    """
    icon_of = {GuardMode(m): i for m, i in (icons or {}).items()}
    customs = sorted((require_custom_mode(m, "name"), t) for m, t in titles.items())
    entries = [
        ModeDefinition(mode=mode, title=BUILT_IN_MODE_TITLES[mode], icon_type=icon)
        for mode, icon in _BUILT_IN_ICONS.items()
    ]
    entries += [
        ModeDefinition(mode=mode, title=title, icon_type=icon_of.get(mode, DEFAULT_MODE_ICON))
        for mode, title in customs
    ]
    doc = CustomModes(account_id=account_id, mode_id=None, operate_type=None, modes=tuple(entries))
    return {CMD_CUSTOM_MODES: doc.param_value()}


def schedule_params(
    slots: Schedule | Iterable[ScheduleSlot],
    *,
    default: GuardMode | int | None = None,
    account_id: str = SYNTHETIC.account_id,
) -> dict[int, str]:
    """The weekly schedule (1254) of ``slots`` and, with ``default``, the mode outside
    every slot (1257).

    Raises ``ValueError`` for slots :class:`~..p2p.station_config_codecs.Schedule` refuses
    (overlapping) or a default no schedule can name.
    """
    if not isinstance(slots, Schedule):
        slots = Schedule(account_id=account_id, slots=tuple(slots))
    elif slots.account_id is None:
        slots = Schedule(account_id=account_id, slots=slots.slots)
    out = {CMD_SCHEDULE: slots.param_value()}
    if default is not None:
        out[CMD_SCHEDULE_DEFAULT] = str(encode_schedule_default(default))
    return out
