"""Which member of a setting's variant group the eufy app uses for one unit.

A model's settings can hold a primary and variants of it (:attr:`.Setting.variant_of`):
thing-description properties ``<primary>__v<n>`` the app reads in the primary's place
under conditions, or a legacy identifier the app has replaced. The app reads the primary
through its ``__v`` variants (:func:`.conditions.choices`), so per unit one member is in
use; the generated settings files carry each variant's read conditions on the primary
(see docs/reference/models-schema.md, *Variants*). Pure functions: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping

from .conditions import ConditionUnit, choices
from .model_settings import Setting

__all__ = ["setting_in_use"]


def setting_in_use(settings: Mapping[str, Setting], key: str, unit: ConditionUnit) -> bool | None:
    """Whether the eufy app uses setting ``key`` of ``settings`` (one device's) for
    ``unit``: True for the member of its variant group the app reads (a setting without
    variants is always in use), False for every other member, None when an input the
    client lacks (:class:`.conditions.ConditionUnit`) decides between this member and
    another. Raises KeyError for a key not in ``settings``."""
    setting = settings[key]
    primary_key = setting.variant_of or key
    primary = settings.get(primary_key)
    rules = primary._variants if primary is not None else ()
    picked = choices([(i, rule.read_conditions) for i, rule in enumerate(rules)], unit)
    members = {primary_key if i is None else rules[i].key for i in picked}
    if key not in members:
        return False
    return True if len(members) == 1 else None
