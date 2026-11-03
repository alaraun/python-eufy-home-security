"""Assign each generated setting its role: ``setting``, ``status`` or ``diagnostic``.

The first rule that applies decides, from the eufy app's own data:

1. ``setting``: the library writes it in some context (``access`` ``rw``).
2. ``diagnostic``: it is read from a parameter the library already reads into device
   state (:data:`~eufy_home_security.devices.param_info.STATE_PARAM_INFO`), so a
   consumer has the value from the device already.
3. ``setting``: the thing description declares it writable and the app does not list it
   as a status it only reads: the app's control, for which the library has no write.
4. ``status``: the app shows it to the user: its device card or home page reads it, a
   settings page reads it or places it, or the app lists it as a status it only reads.
5. ``diagnostic``: otherwise.

A ``<base>__v<n>`` variant is looked up under its base in rule 4: the app shows it in
the base's place. Pure; see docs/reference/models-schema.md.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator, Mapping
from typing import Any

from eufy_home_security.devices.model_settings import SettingRole

__all__ = ["DIAGNOSTIC", "SETTING", "STATUS", "assign", "role_of"]

SETTING = SettingRole.SETTING.value
STATUS = SettingRole.STATUS.value
DIAGNOSTIC = SettingRole.DIAGNOSTIC.value

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


def role_of(
    ident: str,
    entry: Mapping[str, Any],
    *,
    td_writable: Collection[str],
    app_read_only: Collection[str],
    shown: Collection[str],
    state_params: Collection[int],
) -> tuple[str, str]:
    """``(role, rule)`` of one merged setting entry; ``rule`` names the deciding rule.

    ``td_writable``: identifiers the thing description declares writable;
    ``app_read_only``: identifiers the app lists as statuses it only reads;
    ``shown``: identifiers a device card, home page or settings page of the app reads or
    places; ``state_params``: parameter ids the library reads into device state.
    """
    if any(form.get("access") == "rw" for form in _forms(entry)):
        return SETTING, "written"
    if _read_params(entry) & set(state_params):
        return DIAGNOSTIC, "device state"
    m = _VERSIONED.fullmatch(ident)
    base = ident if m is None else m.group(1)
    listed = ident in app_read_only or base in app_read_only
    if ident in td_writable and not listed:
        return SETTING, "app control"
    if listed or ident in shown or base in shown:
        return STATUS, "shown"
    return DIAGNOSTIC, "not shown"


def assign(
    settings: Settings,
    *,
    td_writable: Collection[str],
    app_read_only: Collection[str],
    shown: Collection[str],
    state_params: Collection[int],
) -> dict[str, int]:
    """Set ``role`` on every entry of ``settings`` in place; return counts per rule."""
    counts: dict[str, int] = {}
    for ident, entry in settings.items():
        role, rule = role_of(
            ident,
            entry,
            td_writable=td_writable,
            app_read_only=app_read_only,
            shown=shown,
            state_params=state_params,
        )
        entry["role"] = role
        key = f"role:{role}:{rule}"
        counts[key] = counts.get(key, 0) + 1
    return counts
