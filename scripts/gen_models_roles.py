"""Assign each generated setting its role (``setting``, ``status`` or ``diagnostic``) and
where the eufy app shows it (``shown``: ``card``, ``page`` or none).

``shown`` is ``card`` when the app's device card or home page reads the property, else
``page`` when one of its settings pages reads it, the model's layout places it or the
app lists it as a status it only reads; absent otherwise. It does not depend on the role.

The first role rule that applies decides, from the eufy app's own data:

1. ``setting``: the library writes it in some context (``access`` ``rw``).
2. ``diagnostic``: it is read from, or the handler fills it from, a parameter whose
   value the library already reports
   (:data:`~eufy_home_security.devices.param_info.STATE_PARAM_INFO`), so a consumer has
   the value from the device already.
3. ``setting``: the thing description declares it writable and the app does not list it
   as a status it only reads: the app's control, for which the library has no write.
4. ``status``: the app shows it (``shown`` is ``card`` or ``page``).
5. ``diagnostic``: otherwise.

A ``<base>__v<n>`` variant is also looked up under its base: the app shows it in the
base's place. Pure; see docs/reference/models-schema.md.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator, Mapping
from typing import Any

from eufy_home_security.devices.model_settings import SettingRole, SettingShown

__all__ = ["CARD", "DIAGNOSTIC", "PAGE", "SETTING", "STATUS", "assign", "role_of", "shown_of"]

SETTING = SettingRole.SETTING.value
STATUS = SettingRole.STATUS.value
DIAGNOSTIC = SettingRole.DIAGNOSTIC.value
CARD = SettingShown.CARD.value
PAGE = SettingShown.PAGE.value

_VERSIONED = re.compile(r"(.+)__v\d+")

type Settings = dict[str, dict[str, Any]]


def _forms(entry: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    """The entry and the fields each of its contexts changes."""
    yield entry
    for item in entry.get("contexts") or ():
        yield item["entry"]


def _read_params(entry: Mapping[str, Any]) -> set[int]:
    out: set[int] = set()
    for form in _forms(entry):
        read = form.get("read")
        if isinstance(read, dict) and isinstance(read.get("param"), int):
            out.add(read["param"])
    return out


def _names(ident: str) -> tuple[str, ...]:
    """``ident`` and, for a ``<base>__v<n>`` variant, its base."""
    m = _VERSIONED.fullmatch(ident)
    return (ident,) if m is None else (ident, m.group(1))


def shown_of(ident: str, *, shown: Mapping[str, str], app_read_only: Collection[str]) -> str | None:
    """Where the app shows ``ident``: :data:`CARD`, :data:`PAGE` or None.

    ``shown``: identifier -> :data:`CARD` (a device card or home page reads it) or
    :data:`PAGE` (a settings page reads it or the model's layout places it);
    ``app_read_only``: identifiers the app lists as statuses it only reads (a page).
    """
    names = _names(ident)
    places = {shown.get(name) for name in names}
    if CARD in places:
        return CARD
    if PAGE in places or any(name in app_read_only for name in names):
        return PAGE
    return None


def role_of(
    ident: str,
    entry: Mapping[str, Any],
    *,
    td_writable: Collection[str],
    app_read_only: Collection[str],
    shown: Mapping[str, str],
    state_params: Collection[int],
    located: Mapping[str, int],
) -> tuple[str, str]:
    """``(role, rule)`` of one merged setting entry; ``rule`` names the deciding rule.

    ``td_writable``: identifiers the thing description declares writable;
    ``app_read_only``: identifiers the app lists as statuses it only reads; ``shown``: as
    in :func:`shown_of`; ``state_params``: parameter ids whose value the library already
    reports; ``located``: identifier -> the one parameter the handler fills it from,
    whether or not the setting reads it.
    """
    if any(form.get("access") == "rw" for form in _forms(entry)):
        return SETTING, "written"
    params = _read_params(entry)
    if ident in located:
        params.add(located[ident])
    if params & set(state_params):
        return DIAGNOSTIC, "device state"
    listed = any(name in app_read_only for name in _names(ident))
    if ident in td_writable and not listed:
        return SETTING, "app control"
    if shown_of(ident, shown=shown, app_read_only=app_read_only) is not None:
        return STATUS, "shown"
    return DIAGNOSTIC, "not shown"


def assign(
    settings: Settings,
    *,
    td_writable: Collection[str],
    app_read_only: Collection[str],
    shown: Mapping[str, str],
    state_params: Collection[int],
    located: Mapping[str, int],
) -> dict[str, int]:
    """Set ``role`` and, where the app shows the setting, ``shown`` on every entry of
    ``settings`` in place (see :func:`role_of`, :func:`shown_of`); return counts per role
    rule and per place."""
    counts: dict[str, int] = {}
    for ident, entry in settings.items():
        role, rule = role_of(
            ident,
            entry,
            td_writable=td_writable,
            app_read_only=app_read_only,
            shown=shown,
            state_params=state_params,
            located=located,
        )
        entry["role"] = role
        key = f"role:{role}:{rule}"
        counts[key] = counts.get(key, 0) + 1
        place = shown_of(ident, shown=shown, app_read_only=app_read_only)
        if place is not None:
            entry["shown"] = place
            counts[f"shown:{place}"] = counts.get(f"shown:{place}", 0) + 1
    return counts
