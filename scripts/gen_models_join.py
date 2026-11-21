"""Pure join of app labels, titles and settings-tree placement onto generated settings.

Adds to each setting dict of a model: ``labels`` (enum titles keyed by public value),
``applies_when`` (the app's value gate), ``group``/``order``/``page`` (the app's settings
layout), ``name`` (the app's title, in sentence case), ``unit`` (the unit the app's screen
shows, over the TD's), ``meaning`` (what the app reads the value as), ``variant_of`` (the
identifier the app uses instead), the hand-read app facts of the title file (``default``,
read-only status, option labels, ``advanced``, excluded actions, held flags members), and
builds the file's ``source``
block. Stdlib plus the TD readers of ``eufy_home_security.devices.td``; no
I/O. See docs/reference/models-schema.md.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from gen_models_codec import GeneratorError, kind_of, public_value, specs_of, value_key

from eufy_home_security.devices.labels import sentence_case, setting_name
from eufy_home_security.devices.model_settings import BINARY_MEANINGS, SettingMeaning
from eufy_home_security.devices.td import enum_label
from eufy_home_security.devices.td import normalise_unit as _td_unit

__all__ = [
    "STATUS_NOTE",
    "GeneratorError",
    "apply_domains",
    "hold_members",
    "join",
    "mark_structured",
    "normalise_unit",
    "screen_values",
    "source_block",
    "switches",
]

PRESENT = "present"  # a gate on the property's existence, not on a value
_DATE_SEGMENT = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")
_VERSIONED = re.compile(r"(.+)__v\d+")  # the app's versioned identifier form
RN_SETTINGS = "rn"  # tree settings_ui of a model whose settings the RN bundle renders
STATUS_NOTE = "status the eufy app only reads"  # the note of a listed read-only setting

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


def _names(
    pn: str,
    settings: Settings,
    own: Mapping[str, Any],
    common: Mapping[str, Any],
    counts: dict[str, int],
) -> None:
    """Set ``name``: the model's own app title, else the identifier's, if its kind matches,
    in sentence case.

    A ``<base>__v<n>`` identifier takes its base's title: the app shows it in that place.
    A title that another setting of the model (not a variant of the same primary) would
    also be named is not applied, so two entities never share a name.
    """
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
        app[ident] = sentence_case(title.strip())

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


def _members(settings: Settings, ident: str) -> list[str]:
    """``ident`` and its ``<ident>__v<n>`` variants present in ``settings``."""
    return [
        k
        for k in settings
        if k == ident or ((m := _VERSIONED.fullmatch(k)) is not None and m.group(1) == ident)
    ]


def _units(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int], *, rn: bool
) -> None:
    """Set ``unit`` to the one the app's screen shows, over the TD's.

    A rule with a ``page`` is a settings-page control: it applies on an RN-screen model
    (``rn``) to the setting placed on that page. A rule with ``page`` None is a screen that
    reads the property wherever it sits (a statistics block, an icon): it applies to the
    identifier on every model. ``unit`` None is a bare number on that screen: the TD unit is
    dropped.
    """
    for ident, rule in (titles.get("units") or {}).items():
        page = rule.get("page")
        if page is not None and not rn:
            continue
        for key in _members(settings, ident):
            entry = settings[key]
            if page is not None and entry.get("page") != page:
                continue
            raw = rule["unit"]
            unit = (
                None
                if raw is None
                else normalise_unit(pn, key, raw, entry.get("min"), entry.get("max"))
            )
            if entry.get("unit") == unit:
                continue
            if unit is None:
                del entry["unit"]
                _count(counts, "unit:app drops TD unit")
            else:
                _count(counts, "unit:app replaces TD" if "unit" in entry else "unit:app")
                entry["unit"] = unit


def _meanings(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Set ``meaning`` from the hand-read ``meanings`` (``{identifier: {meaning, source}}``)
    on the identifier and its variants; a binary meaning only on a bool setting."""
    for ident, rule in (titles.get("meanings") or {}).items():
        try:
            meaning = SettingMeaning(rule["meaning"])
        except (KeyError, TypeError, ValueError) as err:
            raise GeneratorError(f"{pn}: meaning rule of {ident} is not a meaning") from err
        for key in _members(settings, ident):
            entry = settings[key]
            if meaning in BINARY_MEANINGS and entry["kind"] != "bool":
                _count(counts, "meaning:binary on a non-bool")
                continue
            entry["meaning"] = meaning.value
            _count(counts, "meaning:app")


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


def switches(pn: str, titles: Mapping[str, Any] | None) -> dict[str, dict[bool, str | bool]]:
    """``{identifier: {state: value}}``: the string properties the app shows as an on/off
    switch for model ``pn``, with the value it writes for on (True) and off (False).

    From the title file's ``switches`` (texts ``on``/``off``, a per-model pair under
    ``models``) and ``bool_switches`` (the identifiers whose switch writes the JSON bool
    itself, ``{identifier: {"source": text}}``); raises GeneratorError when the two texts
    are equal or not strings, when a bool switch entry has no source text, or when both
    lists name one identifier.
    """
    out: dict[str, dict[bool, str | bool]] = {}
    for ident, rule in ((titles or {}).get("switches") or {}).items():
        texts = {**rule, **(rule.get("models") or {}).get(pn, {})}
        on, off = texts.get("on"), texts.get("off")
        if not isinstance(on, str) or not isinstance(off, str) or on == off:
            raise GeneratorError(f"{pn}: switch {ident} needs two distinct on/off texts")
        out[ident] = {True: on, False: off}
    bool_rules = (titles or {}).get("bool_switches") or {}
    if not isinstance(bool_rules, Mapping):
        raise GeneratorError(f"{pn}: bool switches need a mapping of identifier to source")
    for ident, rule in bool_rules.items():
        if not isinstance(rule, Mapping) or not isinstance(rule.get("source"), str):
            raise GeneratorError(f"{pn}: bool switch {ident} needs a source text")
        if ident in out:
            raise GeneratorError(f"{pn}: switch {ident} is listed with texts and as a bool")
        out[ident] = {True: True, False: False}
    return out


_DOMAIN_FILL = "fill"  # only where the product's TD declares no values or range
_DOMAIN_REPLACE = "replace"  # the app's screen ignores the TD's domain


def _domain_spec(pn: str, ident: str, rule: Any) -> dict[str, Any]:
    """The TD ``data_type`` a ``domains`` rule stands for; GeneratorError on a bad shape."""
    if not isinstance(rule, Mapping) or not isinstance(rule.get("source"), str):
        raise GeneratorError(f"{pn}: domain {ident} needs a source text")
    if rule.get("td") not in (_DOMAIN_FILL, _DOMAIN_REPLACE):
        raise GeneratorError(f"{pn}: domain {ident} needs td fill or replace")
    if rule.get("kind") == "enum":
        labels = rule.get("labels")
        if (
            not isinstance(labels, Mapping)
            or not labels
            or not all(re.fullmatch(r"-?\d+", str(k)) for k in labels)
            or not all(isinstance(v, str) and v.strip() for v in labels.values())
        ):
            raise GeneratorError(f"{pn}: domain {ident} needs integer-keyed labels")
        rows = [{"value": str(k), "desc": v, "associatedValue": str(k)} for k, v in labels.items()]
        return {"type": "enum", "specs": {"eunmList": rows}}
    if rule.get("kind") == "range":
        bounds = [rule.get(k) for k in ("min", "max", "step")]
        ints = [b for b in bounds if isinstance(b, int) and not isinstance(b, bool)]
        if len(ints) != len(bounds):
            raise GeneratorError(f"{pn}: domain {ident} needs integer min, max and step")
        lo, hi, step = ints
        if not lo < hi or step <= 0:
            raise GeneratorError(f"{pn}: domain {ident} has an empty range")
        return {"type": "int", "specs": {"min": lo, "max": hi, "step": step}}
    raise GeneratorError(f"{pn}: domain {ident} kind must be enum or range")


def apply_domains(
    pn: str, td: Mapping[str, Any], titles: Mapping[str, Any] | None, counts: dict[str, int]
) -> dict[str, Any]:
    """``td`` with each property named in the title file's ``domains`` given the domain the
    app's screen offers (enum labels or an integer range), before the handler sweep.

    A ``fill`` rule applies where the product's own TD declares no values or range (kind
    ``other``), a ``replace`` rule always (the screen never reads the TD's domain). The TD
    default is kept. Raises GeneratorError on a malformed rule.
    """
    rules = (titles or {}).get("domains") or {}
    if not isinstance(rules, Mapping):
        raise GeneratorError(f"{pn}: domains must be a mapping of identifier to rule")
    specs = {ident: _domain_spec(pn, ident, rule) for ident, rule in rules.items()}
    props = []
    for prop in td.get("properties", []):
        ident = prop.get("identifier") if isinstance(prop, dict) else None
        base = _VERSIONED.sub(r"\1", ident) if isinstance(ident, str) else ""
        rule = rules.get(base)
        if rule is None or (rule["td"] == _DOMAIN_FILL and kind_of(prop) != "other"):
            props.append(prop)
            continue
        dtype = dict(specs[base])
        marked = {
            str(row.get("value")): row["isDefault"]
            for row in specs_of(prop).get("eunmList") or ()
            if isinstance(row, dict) and "isDefault" in row
        }
        if "eunmList" in dtype["specs"] and marked:
            rows = [
                {**r, "isDefault": marked.get(r["value"], 0)} for r in dtype["specs"]["eunmList"]
            ]
            dtype["specs"] = {**dtype["specs"], "eunmList": rows}
        default = specs_of(prop).get("defaultValue")
        if default is not None:
            dtype["specs"] = {**dtype["specs"], "defaultValue": default}
        props.append({**prop, "data_type": dtype})
        _count(counts, f"domain:app {rule['td']}")
    return {**td, "properties": props}


def mark_structured(
    pn: str, settings: Settings, titles: Mapping[str, Any] | None, counts: dict[str, int]
) -> None:
    """Mark ``structured`` the settings whose value the app's screen builds and parses as
    JSON itself (title file ``structured``: ``{identifier: {source}}``), on the identifier
    and its variants. A writable one keeps its control: a consumer shows no free-text entity
    for a structured value."""
    rules = (titles or {}).get("structured") or {}
    for ident, rule in rules.items():
        if not isinstance(rule, Mapping) or not isinstance(rule.get("source"), str):
            raise GeneratorError(f"{pn}: structured {ident} needs a source text")
        for key in _members(settings, ident):
            if not settings[key].get("structured"):
                settings[key]["structured"] = True
                _count(counts, "structured:app")


def screen_values(pn: str, titles: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """``{identifier: {value key: value}}``: the enum properties whose app screen writes
    its own value for a thing-description value, for model ``pn``.

    From the title file's ``screen_values`` (``values``, a per-model map under
    ``models`` overriding it); raises GeneratorError for a value that is no scalar.
    """
    out: dict[str, dict[str, Any]] = {}
    for ident, rule in ((titles or {}).get("screen_values") or {}).items():
        values = {**(rule.get("values") or {}), **(rule.get("models") or {}).get(pn, {})}
        for key, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int | float | str):
                raise GeneratorError(f"{pn}: screen value {ident} {key} is not a scalar")
        out[ident] = values
    return out


def _excluded(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Drop the listed identifiers (and their ``__v<n>`` forms): actions, not settings."""
    listed = titles.get("excluded") or {}
    for ident in list(settings):
        m = _VERSIONED.fullmatch(ident)
        if ident in listed or (m is not None and m.group(1) in listed):
            del settings[ident]
            _count(counts, "excluded")
    for ident, entry in settings.items():
        gate = (entry.get("applies_when") or [None])[0]
        if gate is not None and gate not in settings:
            raise GeneratorError(f"{pn}: {ident} applies when excluded {gate} has a value")


def _defaults(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Set ``default`` to the value the app shows while the device reports none."""
    for ident, rule in (titles.get("defaults") or {}).items():
        entry = settings.get(ident)
        if entry is None or pn not in rule["models"]:
            continue
        value = rule["value"]
        if not _in_domain(entry, value):
            raise GeneratorError(f"{pn}: {ident} default {value!r} is outside its domain")
        entry["default"] = value
        _count(counts, "default:app")


def _read_empty(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Map an empty read to the value the app shows for it (the handler's decode differs)."""
    for ident, rule in (titles.get("read_empty") or {}).items():
        entry = settings.get(ident)
        read = None if entry is None else entry.get("read")
        if not isinstance(read, dict) or not isinstance(read.get("map"), dict):
            continue
        value = rule["value"]
        if not _in_domain(entry, value):
            raise GeneratorError(f"{pn}: {ident} empty read {value!r} is outside its domain")
        read["map"][""] = value
        _count(counts, "read:empty as the app")


def _in_domain(entry: Mapping[str, Any], value: Any) -> bool:
    kind = entry["kind"]
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "enum":
        return not isinstance(value, bool) and value in entry.get("values", ())
    if kind == "range":
        return bool(entry.get("min", value) <= value <= entry.get("max", value))
    return False


def _read_only(settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]) -> None:
    """Make a listed setting a status: ``ro`` with its read kept and STATUS_NOTE."""
    for ident in titles.get("read_only") or {}:
        entry = settings.get(ident)
        if entry is None:
            continue
        for key in ("write", "write_table", "control"):
            entry.pop(key, None)
        entry["access"] = "ro"
        entry["note"] = STATUS_NOTE
        _count(counts, "ro:app reads only")


def _hand_labels(
    pn: str, settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]
) -> None:
    """Replace enum labels with the app's option titles read by hand."""
    for ident, rule in (titles.get("labels") or {}).items():
        entry = settings.get(ident)
        if entry is None or entry["kind"] != "enum":
            continue
        keys = {value_key(v) for v in entry.get("values", ())}
        if not set(rule["labels"]) <= keys:
            raise GeneratorError(f"{pn}: {ident} hand labels name values it lacks")
        entry["labels"] = {**entry.get("labels", {}), **rule["labels"]}
        _count(counts, "labels:hand", len(rule["labels"]))


def _advanced(settings: Settings, titles: Mapping[str, Any], counts: dict[str, int]) -> None:
    """Mark the settings the app puts behind a warning ``advanced``; the warning is the note."""
    for ident, rule in (titles.get("advanced") or {}).items():
        entry = settings.get(ident)
        if entry is None or entry["kind"] != rule.get("kind", entry["kind"]):
            continue
        entry["advanced"] = True
        note = entry.get("note")
        entry["note"] = rule["note"] if not note else f"{note}; {rule['note']}"
        _count(counts, "advanced")


def hold_members(
    pn: str, settings: Settings, titles: Mapping[str, Any] | None, counts: dict[str, int]
) -> None:
    """Leave the listed members out of a ``flags`` setting: their bit is not established.

    Runs after the shaping (``gen_models_controls.apply_flags``); the bit stays in the
    mask, unnamed. Raises GeneratorError when no member would remain.
    """
    for ident, members in ((titles or {}).get("held_members") or {}).items():
        entry = settings.get(ident)
        if entry is None or entry["kind"] != "flags":
            continue
        held = set(members) & set(entry["flags"])
        if not held:
            continue
        if held == set(entry["flags"]):
            raise GeneratorError(f"{pn}: {ident} would keep no flags member")
        for key in held:
            del entry["flags"][key]
            entry.get("labels", {}).pop(key, None)
            _count(counts, "flags:member held")


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
    titles, units, variant pairs and hand-read facts (None: none). A model whose tree says
    the app shows its settings on the RN screens takes the RN titles and units
    (``models``, ``titles``, ``units``); a model on the native screens only its own native
    titles (``native_models``). The hand-read facts apply to every model: ``excluded``
    identifiers are dropped, ``defaults`` set ``default`` on their listed models,
    ``read_empty`` maps an empty read to the value the app shows,
    ``read_only`` ones become ``ro`` with their read kept, ``labels`` replace option
    titles and ``advanced`` ones are marked with the app's warning as ``note``
    (``held_members`` apply after shaping: :func:`hold_members`). Raises GeneratorError on
    a gate whose desc does not map to one TD value, an identifier shown by two gates, an
    empty title, a variant cycle, a gate on an excluded identifier, a default outside the
    domain or hand labels for values the setting lacks.
    """
    counts: dict[str, int] = {}
    _labels(product_code, settings, td, app_labels, counts)
    if tree is not None:
        gate_pages = _gates(product_code, settings, tree, counts)
        _placement(settings, tree, gate_pages, counts)
    if titles is not None:
        _excluded(product_code, settings, titles, counts)
        _defaults(product_code, settings, titles, counts)
        _read_empty(product_code, settings, titles, counts)
        _read_only(settings, titles, counts)
        _hand_labels(product_code, settings, titles, counts)
        _advanced(settings, titles, counts)
        _variants(product_code, settings, titles, counts)
        rn = tree is not None and tree.get("settings_ui") == RN_SETTINGS
        _units(product_code, settings, titles, counts, rn=rn)
        _meanings(product_code, settings, titles, counts)
        if rn:
            own = (titles.get("models") or {}).get(product_code) or {}
            _names(product_code, settings, own, titles.get("titles") or {}, counts)
        elif tree is not None:
            own = (titles.get("native_models") or {}).get(product_code) or {}
            _names(product_code, settings, own, {}, counts)
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
