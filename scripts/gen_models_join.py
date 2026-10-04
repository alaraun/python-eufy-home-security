"""Pure join of app labels, titles and settings-tree placement onto generated settings.

Adds to each setting dict of a model: ``labels`` (enum titles keyed by public value),
``applies_when`` (the app's value gate), ``group``/``order``/``page`` (the app's settings
layout), ``name`` (the app's title), ``unit`` (the app control's unit where the TD gives
none), ``variant_of`` (the identifier the app uses instead), and builds the file's
``source`` block. Stdlib plus the TD readers of ``eufy_home_security.devices.td``; no
I/O. See docs/reference/models-schema.md.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from gen_models_codec import GeneratorError, public_value, specs_of, value_key

from eufy_home_security.devices.labels import setting_name
from eufy_home_security.devices.td import enum_label
from eufy_home_security.devices.td import normalise_unit as _td_unit

__all__ = ["GeneratorError", "join", "normalise_unit", "source_block"]

PRESENT = "present"  # a gate on the property's existence, not on a value
_DATE_SEGMENT = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")
_VERSIONED = re.compile(r"(.+)__v\d+")  # the app's versioned identifier form
RN_SETTINGS = "rn"  # tree settings_ui of a model whose settings the RN bundle renders

type Settings = dict[str, dict[str, Any]]


def _count(counts: dict[str, int], key: str, n: int = 1) -> None:
    counts[key] = counts.get(key, 0) + n


def _td_enums(td: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Identifier -> TD ``eunmList`` of every enum property."""
    out: dict[str, list[dict[str, Any]]] = {}
    for prop in td.get("properties", []):
        if isinstance(prop, dict) and isinstance(prop.get("identifier"), str):
            rows = specs_of(prop).get("eunmList")
            if isinstance(rows, list):
                out[prop["identifier"]] = [r for r in rows if isinstance(r, dict)]
    return out


def _app_titles(pn: str, ident: str, rows: list[Mapping[str, Any]]) -> dict[str, str]:
    """UI value -> app title; one UI value with two titles is an error."""
    titles: dict[str, str] = {}
    for row in rows:
        ui, title = str(row.get("ui")), row.get("app")
        if not isinstance(title, str) or not title.strip():
            continue
        if titles.get(ui, title) != title:
            raise GeneratorError(f"{pn}: {ident} value {ui} has two app titles")
        titles[ui] = title
    return titles


def _labels(
    pn: str,
    settings: Settings,
    td: Mapping[str, Any],
    app: Mapping[str, Any] | None,
    counts: dict[str, int],
) -> None:
    enums = _td_enums(td)
    for ident, entry in settings.items():
        if entry.get("kind") != "enum" or ident not in enums:
            continue
        titles = _app_titles(pn, ident, list((app or {}).get(ident) or []))
        labels: dict[str, str] = {}
        td_values = set()
        for row in enums[ident]:
            raw = str(row.get("value"))
            td_values.add(raw)
            value = public_value(raw)
            desc = str(row.get("desc") or "")
            if raw in titles:
                label, source = titles[raw].strip(), "app"
            else:
                label, from_td = enum_label(ident, value, desc)
                source = "td" if from_td else "none"
            labels[value_key(value)] = label
            _count(counts, f"label:{source}")
        _count(counts, "labels:app row without TD value", len(set(titles) - td_values))
        if labels:
            entry["labels"] = labels
            _count(counts, "labels")


def _gate_value(pn: str, ident: str, desc: str, tree: Mapping[str, Any]) -> Any:
    """The public value whose TD enum desc is ``desc`` (tree triples ``[value, wire, desc]``)."""
    triples = ((tree.get("properties") or {}).get(ident) or {}).get("enum") or []
    matches = {str(t[0]) for t in triples if len(t) >= 3 and t[2] == desc}
    if len(matches) != 1:
        raise GeneratorError(f"{pn}: gate on {ident}: desc {desc!r} maps to {sorted(matches)}")
    return public_value(matches.pop())


def _gates(
    pn: str, settings: Settings, tree: Mapping[str, Any], counts: dict[str, int]
) -> dict[str, str]:
    """Set ``applies_when``; return identifier -> page of the gate that shows it."""
    pages: dict[str, str] = {}
    shown_by: set[str] = set()
    for gate in tree.get("gates") or []:
        when = gate.get("when") or {}
        if len(when) != 1:
            raise GeneratorError(f"{pn}: gate with {len(when)} conditions: {sorted(when)}")
        ((ident, desc),) = when.items()
        if desc == PRESENT:
            continue
        if ident not in settings:
            raise GeneratorError(f"{pn}: gate on {ident}, which is not a setting")
        value = _gate_value(pn, ident, desc, tree)
        for shown in gate.get("shows") or []:
            if shown in shown_by:
                raise GeneratorError(f"{pn}: {shown} is shown by two gates")
            shown_by.add(shown)
            if shown not in settings:
                _count(counts, "applies_when:shown not a setting")
                continue
            settings[shown]["applies_when"] = [ident, value]
            _count(counts, "applies_when")
            if isinstance(gate.get("page"), str):
                pages[shown] = gate["page"]
    return pages


def _positions(tree: Mapping[str, Any]) -> dict[str, list[tuple[str, str, str]]]:
    """Identifier -> ``(page, section, position)`` from ``setting_model_config``."""
    config = (tree.get("positions") or {}).get("setting_model_config") or {}
    out: dict[str, list[tuple[str, str, str]]] = {}
    for page, keys in sorted(config.items()):
        for key in keys:
            ident, _, rest = str(key).partition("#")
            section, _, pos = rest.partition("#")
            out.setdefault(ident, []).append((page, section, pos))
    return out


def _routes(tree: Mapping[str, Any]) -> dict[str, set[str]]:
    """Identifier -> the app routes whose screen reads it."""
    out: dict[str, set[str]] = {}
    for screens in (tree.get("pages") or {}).values():
        for screen in screens:
            route = screen.get("route")
            if not isinstance(route, str):
                continue
            for ident in screen.get("props") or []:
                out.setdefault(ident, set()).add(route)
    return out


def _placement(
    settings: Settings, tree: Mapping[str, Any], gate_pages: dict[str, str], counts: dict[str, int]
) -> None:
    positions = _positions(tree)
    routes = _routes(tree)
    for ident, entry in settings.items():
        spots = positions.get(ident, [])
        if len(spots) == 1:
            _, section, pos = spots[0]
            if section:
                entry["group"] = section
                _count(counts, "group")
            if pos.isdigit():
                entry["order"] = int(pos)
        config_pages = {page for page, _, _ in spots}
        if ident in gate_pages:
            entry["page"] = gate_pages[ident]
        elif len(config_pages) == 1:
            entry["page"] = config_pages.pop()
        elif not spots and len(routes.get(ident, ())) == 1:
            entry["page"] = next(iter(routes[ident]))
        if "page" in entry:
            _count(counts, "page")


def _names(pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]) -> None:
    """Set ``name``: the model's own app title, else the identifier's, if its kind matches.

    A ``<base>__v<n>`` identifier takes its base's title: the app shows it in that place.
    A title that another setting of the model (not a variant of the same primary) would
    also be named is not applied, so two entities never share a name.
    """
    own = (titles.get("models") or {}).get(pn) or {}
    common = titles.get("titles") or {}
    app: dict[str, str] = {}
    for ident, entry in settings.items():
        m = _VERSIONED.fullmatch(ident)
        keys = [ident] if m is None else [ident, m.group(1)]
        row = next((r for k in keys for r in (own.get(k), common.get(k)) if r), None)
        if row is None or row.get("kind", entry["kind"]) != entry["kind"]:
            continue
        title = row.get("title")
        if not isinstance(title, str) or not title.strip():
            raise GeneratorError(f"{pn}: {ident} has an empty app title")
        app[ident] = title.strip()

    def primary(ident: str) -> str:
        return str(settings[ident].get("variant_of", ident))

    while True:
        final = {i: app.get(i) or setting_name(i) for i in settings}
        clash = {
            i
            for i in app
            for j in settings
            if j != i and primary(j) != primary(i) and final[j].casefold() == app[i].casefold()
        }
        if not clash:
            break
        for i in clash:
            del app[i]
            _count(counts, "name:app title shared with another setting")
    for ident, title in app.items():
        settings[ident]["name"] = title
        _count(counts, "name:app")


def _units(pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]) -> None:
    """Set ``unit`` from the app's control for a setting on the page that shows it."""
    for ident, rule in (titles.get("units") or {}).items():
        entry = settings.get(ident)
        if entry is None or entry.get("page") != rule["page"]:
            continue
        unit = normalise_unit(pn, ident, rule["unit"], entry.get("min"), entry.get("max"))
        if entry.get("unit", unit) != unit:
            _count(counts, "unit:app differs from TD")
            continue
        if "unit" not in entry and unit is not None:
            entry["unit"] = unit
            _count(counts, "unit:app")


def _variants(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Set ``variant_of``: ``<base>__v<n>`` of a present base, and the listed legacy pairs.

    The app resolves a ``__v<n>`` identifier to its base and shows one of them; a listed
    legacy identifier counts only with the listed TD kind. Chains resolve to the end.
    """
    listed = titles.get("variants") or {}
    direct: dict[str, str] = {}
    for ident, entry in settings.items():
        m = _VERSIONED.fullmatch(ident)
        if m is not None and m.group(1) in settings:
            direct[ident] = m.group(1)
            continue
        rule = listed.get(ident)
        if (
            rule is not None
            and rule["primary"] in settings
            and rule.get("kind", entry["kind"]) == entry["kind"]
        ):
            direct[ident] = rule["primary"]
    for ident, first in direct.items():
        target, seen = first, {ident}
        while target in direct:
            if target in seen:
                raise GeneratorError(f"{pn}: variant cycle at {ident}")
            seen.add(target)
            target = direct[target]
        settings[ident]["variant_of"] = target
        _count(counts, "variant_of")


def join(
    product_code: str,
    settings: Settings,
    td: Mapping[str, Any],
    app_labels: Mapping[str, Any] | None,
    tree: Mapping[str, Any] | None,
    *,
    titles: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Add labels, applies_when, group/order/page, name, unit and variant_of to
    ``settings`` in place; return counts.

    ``app_labels`` is the model's ``{identifier: [{ui, app, ...}]}`` (None: TD labels
    only); ``tree`` its settings tree (None: no placement); ``titles`` the app's setting
    titles, units and variant pairs (None: none). Names and units apply only to a model
    whose tree says the app shows its settings on the RN screens. Raises
    GeneratorError on a gate whose desc does not map to one TD value, an identifier shown
    by two gates, an empty title or a variant cycle.
    """
    counts: dict[str, int] = {}
    _labels(product_code, settings, td, app_labels, counts)
    if tree is not None:
        gate_pages = _gates(product_code, settings, tree, counts)
        _placement(settings, tree, gate_pages, counts)
    if titles is not None:
        _variants(product_code, settings, titles, counts)
        # titles and units are read from the app's RN settings screens
        if tree is not None and tree.get("settings_ui") == RN_SETTINGS:
            _names(product_code, settings, titles, counts)
            _units(product_code, settings, titles, counts)
    return counts


def normalise_unit(
    pn: str, ident: str, raw: str, minimum: float | None, maximum: float | None
) -> str | None:
    """The SettingUnit value of a TD unit, or None for none; an unmapped unit raises."""
    try:
        unit = _td_unit(raw, minimum, maximum)
    except ValueError as err:
        raise GeneratorError(f"{pn}: {ident} unit {raw!r} has no mapping") from err
    return None if unit is None else unit.value


def source_block(td: Mapping[str, Any], app_version: str) -> dict[str, Any]:
    """``{td_version, handler, handler_date, app_version}`` of a model file."""
    version = td.get("large_version")
    path = (td.get("profile") or {}).get("plugin_path")
    if not isinstance(version, int) or not isinstance(path, str):
        raise GeneratorError("td.json lacks large_version or profile.plugin_path")
    m = _DATE_SEGMENT.search(path)
    if m is None:
        raise GeneratorError(f"plugin_path has no /YYYY/MM/DD/ date segment: {path}")
    return {
        "td_version": version,
        "handler": path.rsplit("/", 1)[-1],
        "handler_date": "-".join(m.groups()),
        "app_version": app_version,
    }
