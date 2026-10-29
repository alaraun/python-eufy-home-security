"""The ``variants`` field of a settings file: which ``__v`` variant the app reads, per unit.

For each primary of a variant group (a setting other settings name in ``variant_of``),
every thing-description property the app resolves the primary's identifier to (the
identifier followed by ``__v``, any case) that has read conditions, in
thing-description order: ``id`` (the property), ``key`` (the bundled setting that
stands for it: itself, the primary when it was dropped as a same-codec variant, None
when the file has no setting for it) and ``read_conditions`` (plain groups,
:func:`~eufy_home_security.devices.conditions.td_conditions`). An associated condition
also carries how the device reports its property: ``param`` and ``map`` from the
property's own read in the file, else the parameter the handler reads it from as
reported (``probe``), and ``default``, the value the app reads when the device reports
none; ``prop`` is left out for a property the thing description lacks (the app reads
``""`` for it). See docs/reference/models-schema.md, *Variants*.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping, Sequence
from typing import Any

from eufy_home_security.devices.conditions import ASSOCIATED_TYPES, td_conditions, variant_rest

type Settings = dict[str, dict[str, Any]]
type Probe = Callable[[str, Sequence[str]], int | None]
"""``probe(identifier, values)``: the parameter the handler reports ``identifier`` from
as is (each of ``values`` read back unchanged), or None."""


def default_value(prop: Mapping[str, Any]) -> str:
    """The value the app reads when nothing reports one: the enum entry marked default
    (``""`` when none is), else ``defaultValue``, else ``""``."""
    specs = (prop.get("data_type") or {}).get("specs") or {}
    enums = specs.get("eunmList") or specs.get("enumList")
    if enums:
        found = next((e for e in enums if str(e.get("isDefault")) == "1"), None)
        return "" if found is None else str(found.get("value") or "")
    value = specs.get("defaultValue")
    return "" if value is None else str(value)


def text(value: Any) -> str:
    """A thing value as the app's text form of it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _read_of(
    prop: str,
    values: Sequence[str],
    settings: Settings,
    props: Mapping[str, Mapping[str, Any]],
    probe: Probe,
) -> dict[str, Any]:
    out: dict[str, Any] = {"default": default_value(props[prop])}
    read = (settings.get(prop) or {}).get("read")
    if read is not None:
        out["param"] = read["param"]
        if read.get("map") is not None:
            out["map"] = {raw: text(v) for raw, v in read["map"].items()}
        return out
    param = probe(prop, sorted({*values, out["default"]}))
    if param is not None:
        out["param"] = param
    return out


def add_variants(
    settings: Settings,
    td_props: Sequence[Mapping[str, Any]],
    dropped: Collection[str],
    probe: Probe,
    counts: dict[str, int],
) -> None:
    """Set ``variants`` on every group primary of ``settings`` (the merged file entries)
    that has candidates; ``dropped`` are the same-codec variants left out of the file."""
    props = {p["identifier"]: p for p in td_props}
    compared: dict[str, set[str]] = {}
    for prop in td_props:
        for group in td_conditions(prop.get("read_conditions")):
            for cond in group:
                if cond["type"] in ASSOCIATED_TYPES and "prop" in cond:
                    compared.setdefault(cond["prop"], set()).add(cond["value"])
    primaries = sorted({e["variant_of"] for e in settings.values() if e.get("variant_of")})
    reads: dict[str, dict[str, Any]] = {}
    for primary in primaries:
        rules = []
        for prop in td_props:
            ident = prop["identifier"]
            groups = td_conditions(prop.get("read_conditions"))
            if not variant_rest(ident, primary) or not groups:
                continue
            if (settings.get(ident) or {}).get("variant_of") == primary:
                key: str | None = ident
            else:
                key = primary if ident in dropped else None
            for cond in (c for g in groups for c in g):
                name = cond.get("prop")
                if name is None:
                    continue
                if name not in props:
                    del cond["prop"]
                    continue
                if name not in reads:
                    reads[name] = _read_of(name, sorted(compared[name]), settings, props, probe)
                    found = "found" if "param" in reads[name] else "unknown"
                    counts[f"variants:read {found}"] = counts.get(f"variants:read {found}", 0) + 1
                cond.update(reads[name])
            rules.append({"id": ident, "key": key, "read_conditions": groups})
        if rules:
            settings[primary]["variants"] = rules
            counts["variants"] = counts.get("variants", 0) + 1
