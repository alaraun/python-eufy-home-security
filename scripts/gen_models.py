"""Generate the per-model settings files from the cached vendor thing models.

For each model in the cache (``<cache>/<PN>/{td.json, <PN>Handle.mix.js}``), run the
vendor handler through ``scripts/gen_models_driver.js`` with setProperty over every
property's domain (whatever its ``access_mode``, :func:`td_writable`), in a station-child
and a standalone context, infer the write codecs (``scripts/gen_models_codec.py``), feed
each written recipe's parameter dump back to getProperty for the read codec (a setting
without a write: the parameter getProperty fills it from, ``locate_params``), join the
app's labels and settings layout (``scripts/gen_models_join.py``) with the app's setting
titles, units and variant pairs, give each setting its role and where the app shows it (``--shown``,
``scripts/gen_models_roles.py``), add the battery reads, the handler's grouping of an
``SDINFO_EX`` status (``sd_status_groups``), a lock's state parameter per context (``lock``)
and a garage camera's door parameters and command (``garage``), and write
``<out>/<PN>.json``, then ``<out>/INDEX.json``, the sorted list of every ``<PN>.json`` in
``<out>``.

Every model is checked before it is written: each codec must render back every swept
recipe, and every row of the frozen v1 reference (``tests/fixtures/models_v1_reference.json``)
must render to its recorded cmd/subCmd/params unless ``RELEASE_ACCEPTED`` names it. A model
that fails is not written and the run exits 1. ``--check`` regenerates into a temporary
directory and compares byte for byte with ``--out``.

A same-codec variant is kept when the released-keys manifest (``--released``, committed
as ``scripts/data/released_keys.json``, not shipped) lists its key for the model; the
generator never reads ``--out`` to decide what to write. ``--update-released REF`` unions
the setting keys of every model file bundled at git ``REF`` (a release tag) into the
manifest and writes nothing else.

``--jobs N`` generates N models at a time, each in its own process with one long-lived
Node worker (``scripts/gen_models_node.py``); a model that fails is reported and the run
goes on, exit 1 at the end. Node failing a job (no worker survives it, or none replies in
time) stops the run at once: exit 2 and the cause. Runs on a maintainer host only (needs Node of the pinned major and the private
cache); nothing at runtime executes vendor code. See docs/reference/models-schema.md.

Driver replies are kept in a private answer store (``--answers DIR``, default
``.work/cache/gen_models_answers``; ``scripts/gen_models_answers.py``): a job asked
before with the same Node runtime and environment, driver, handler and requests is
replayed without Node. ``--no-answers`` asks Node for every job.

    gen_models.py [PN ...] [--check] [--cache DIR] [--out DIR] [--jobs N]
                  [--labels FILE] [--trees FILE] [--titles FILE] [--shown FILE]
                  [--routing FILE] [--app-version V] [--released FILE] [--update-released REF]
                  [--answers DIR | --no-answers]
"""

from __future__ import annotations

import argparse
import atexit
import base64
import contextlib
import copy
import functools
import importlib.util
import io
import json
import multiprocessing
import multiprocessing.connection
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import traceback
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from eufy_home_security.devices.garage import GarageDoorState, bound, door_state
from eufy_home_security.devices.model_settings import (
    ACCOUNT_SLOT,
    BATTERY_PROPERTY,
    SdStatusGroups,
    SdStatusSource,
    decode_object,
    members_read,
    object_slot,
)
from eufy_home_security.devices.param_info import STATE_PARAM_INFO
from eufy_home_security.devices.settings import DUAL_VIEW, VIEW_MODE_PARAM
from eufy_home_security.devices.td import UNIT_MEANINGS
from eufy_home_security.devices.types import DeviceKind, model_for_serial

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
INDEX = "INDEX.json"  # {"schema_version", "codes"}: the bundled product codes, sorted
# {PN: sorted setting keys a release bundled}: a generator input, not package data
DEFAULT_RELEASED = ROOT / "scripts" / "data" / "released_keys.json"
# {PN: sorted released keys the model's thing description no longer declares}: the keys a
# release bundled that a later regeneration drops, so the release checks expect them gone
DEFAULT_RETIRED = ROOT / "scripts" / "data" / "retired_keys.json"
DEFAULT_LABELS = ROOT / ".work" / "tools" / "data" / "app_choice_labels.json"
DEFAULT_TREES = ROOT / ".work" / "tools" / "data" / "settings_trees.json"
DEFAULT_TITLES = ROOT / ".work" / "tools" / "data" / "app_setting_titles.json"
DEFAULT_SHOWN = ROOT / ".work" / "tools" / "data" / "app_shown.json"
DEFAULT_ROUTING = ROOT / ".work" / "tools" / "data" / "app_routing.json"
DEFAULT_ANSWERS = ROOT / ".work" / "cache" / "gen_models_answers"  # the driver answer store
REFERENCE = ROOT / "tests" / "fixtures" / "models_v1_reference.json"
DEFAULT_APP_VERSION = "6.1.32"  # the app build the label and tree data come from
SCHEMA_VERSION = 3
BASE = "SINGLE"  # the base context: a station child whose parent is no station kind
STANDALONE = "standalone"
IDENTIFIER = re.compile(r"[a-z0-9_]+")
PROBE_PARAMS = range(1000, 65536)  # the parameter ids locate_params() looks among
# Ids held at once: getProperty matches every held id against its commandId list.
PROBE_CHUNK = 9000
PROBE_ON, PROBE_OFF = "1", "0"  # the two values a held parameter takes while locating
# A number literal of handler source: decimal, decimal with exponent (7e3) or hex.
JS_NUMBER = re.compile(r"(?<![\w$.])(?:0[xX][0-9a-fA-F]+|\d+(?:[eE]\d{1,2})?)(?![\w$])")
# Probes of an open-kind read beyond its domain: a multi-digit number and a JSON object.
OPEN_NUMBER_PROBE, OPEN_JSON_PROBE = "4321", '{"probe":1}'
BOOL_EXTRA_PROBE = "2"  # a parameter value no bool form names
FLAG_PROBE_BITS = 32  # the single bits a status of booleans is held at (an int32 mask)
BATTERY_PROBE = "57"  # the value a candidate battery parameter is listed at
BATTERY_SAMPLES = range(256)  # the raw levels a battery parameter is read at
BATTERY_LEVEL_TEXT = re.compile(r"-?[0-9]+")
SD_STATUS_ACTION = "get_storage_info_parse_payload"  # the parse of an SDINFO_EX answer
SD_STATUS_PROPERTY = "get_storage_status"  # filled from the device's status parameter
SD_STATUS_SAMPLES = range(-1, 256)  # statuses swept besides the handler's number literals
SD_STATUS_RANGE = range(-(2**31), 2**31)  # an SDINFO_EX status is an int32
SD_STATUS_UNLISTED = 2**31 - 1  # a status no grouping lists: its group is the default
SD_PROBE_TOTAL, SD_PROBE_FREE = 1000, 500  # the sizes the swept answers carry
SD_SOURCE_COUNTS = {  # the run summary's name of each source
    SdStatusSource.ANSWER: "answer",
    SdStatusSource.STATUS_PROPERTY: "status property (library's choice)",
}
SD_PARAM_TEXTS = (" 4 ", "+4", "4.0", "0x4", "abc", "  ")  # status parameter values no code names


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
node = _load("gen_models_node")
joiner = _load("gen_models_join")
controls = _load("gen_models_controls")
sections = _load("gen_models_sections")
variants = _load("gen_models_variants")
roles = _load("gen_models_roles")
answers = _load("gen_models_answers")
routing = _load("gen_models_routing")
GeneratorError = codec.GeneratorError
DRIVERS = node.DriverPool()  # one Node worker per generating thread
# Replays stored driver replies; the command line sets its root (--answers).
ANSWERS = answers.AnswerStore(
    None,
    driver=node.DRIVER,
    runtime=lambda: answers.runtime_version(node.node_path()),
)
RECIPE_FIELDS = ("cmd", "subCmd", "params")
type LeafPath = tuple[str | int, ...]

# v1 reference rows whose render may differ, keyed (PN, identifier), with the reason.
RELEASE_ACCEPTED: dict[tuple[str, str], str] = {
    ("T8030", "hb_keypad_is_password_set"): "a status the eufy app only reads: read-only",
}


class CheckError(GeneratorError):
    """A generated codec does not reproduce a swept recipe or a v1 reference row."""


def _canon(x: Any) -> str:
    """JSON text that tells ``1``, ``1.0`` and ``true`` apart."""
    return json.dumps(x, sort_keys=True)


def _render_or_error(setting: dict[str, Any], value: Any, channel: int) -> Any:
    try:
        return codec.render(setting, value, channel=channel)
    except ValueError as err:
        return f"render error: {err}"


def sweep_mismatches(
    settings: dict[str, Any], samples: dict[str, Sweep], context: codec.Context
) -> list[tuple[str, str]]:
    """``(identifier, detail)`` for every recipe swept in ``context`` (on both of its
    channels) that its rw codec does not render back."""
    out = []
    alt = codec.alt_channel(context)
    for ident, entry in settings.items():
        if entry["access"] != "rw":
            continue
        for ctx, rows in ((context, samples[ident].main), (alt, samples[ident].alt)):
            for value, recipe in rows:
                got = _render_or_error(entry, value, ctx.channel)
                if _canon(got) != _canon(recipe):
                    out.append(
                        (ident, f"ch {ctx.channel} payload {value!r}: {got!r} != {recipe!r}")
                    )
    return out


def reference_key(settings: dict[str, Any], ident: str) -> str | None:
    """The key a reference row of ``ident`` renders through: ``ident`` itself, else the key
    that absorbed it as a same-codec variant, else None."""
    return ident if ident in settings else controls.absorbed_by(ident, settings)


def reference_setting(settings: dict[str, Any], ident: str) -> dict[str, Any] | None:
    key = reference_key(settings, ident)
    return None if key is None else settings[key]


def reference_mismatches(
    settings: dict[str, Any], rows: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """``(identifier, detail)`` for every v1 reference row the model does not reproduce.

    Each row is rendered in its recorded context and channel; cmd, subCmd and params are
    compared (presence and JSON type included). A row of a key dropped as a same-codec
    variant renders through the key that absorbed it (``reference_setting``).
    """
    out = []
    for row in rows:
        ident, payload = row["identifier"], row["payload"]
        where = f"{row['context']} ch {row['channel']} payload {payload!r}"
        entry = reference_setting(settings, ident)
        if entry is None:
            out.append((ident, f"{where}: setting missing"))
            continue
        try:
            value = controls.reference_value(entry, row)
            if entry.get("kind") != "flags" and entry.get("bit") is None:
                value = codec.coerce(entry, value)
        except ValueError as err:
            out.append((ident, f"{where}: {err}"))
            continue
        got = _render_or_error(entry, value, row["channel"])
        if isinstance(got, dict):
            got = {k: got[k] for k in RECIPE_FIELDS if k in got}
        want = {k: row["recipe"][k] for k in RECIPE_FIELDS if k in row["recipe"]}
        if _canon(got) != _canon(want):
            out.append((ident, f"{where}: {got!r} != {want!r}"))
    return out


def load_reference(path: Path = REFERENCE) -> dict[str, list[dict[str, Any]]]:
    """The v1 reference rows per product code (empty when the fixture is absent)."""
    if not path.is_file():
        return {}
    rows: dict[str, list[dict[str, Any]]] = {}
    for row in _read_json(path)["rows"]:
        rows.setdefault(row["product_code"], []).append(row)
    return rows


def run_driver(
    product_code: str,
    handler: Path,
    requests: list[dict[str, Any]],
    wire: codec.WireValues | None = None,
) -> list[Any]:
    """One driver job on this thread's worker (``DRIVERS``), or its stored replies
    (``ANSWERS``): a reply per request, in order. A value of ``wire`` is sent as the value
    the app writes for it, and read back as that value. NodeError when Node fails the
    job, GeneratorError for any other failure."""
    sent = [codec.to_wire(r, wire) for r in requests] if wire else requests
    try:
        replies = ANSWERS.run({"handler": str(handler), "requests": sent}, DRIVERS.run)
    except node.NodeError as err:
        raise node.NodeError(f"{product_code}: {err}") from None
    except node.DriverError as err:
        raise GeneratorError(f"{product_code}: {err}") from err
    if len(replies) != len(requests):
        raise GeneratorError(f"{product_code}: driver returned {len(replies)} replies")
    if wire:
        return [codec.from_wire(r, rep, wire) for r, rep in zip(sent, replies, strict=True)]
    return replies


@dataclass(frozen=True)
class Located:
    """The device parameter getProperty reads a property from, and whether the ask names
    it as a command id (a handler that parses the property only from its command)."""

    param: int
    as_command: bool

    def request(
        self, product_code: str, context: codec.Context, ident: str, raw: str
    ) -> dict[str, Any]:
        """getProperty for ``ident`` on a device that holds only this parameter, at ``raw``."""
        device = context.device(product_code)
        device["params"] = [{"param_type": self.param, "param_value": raw}]
        cmds = [self.param] if self.as_command else []
        return {"kind": "get", "cmds": cmds, "device": device, "props": [ident]}


def _property_values(reply: Any) -> dict[str, Any]:
    """The properties of a getProperty reply, also beside another parameter's parse error."""
    data = reply.get("data") if isinstance(reply, dict) else None
    found = data.get("p2p") if isinstance(data, dict) else None
    return found if isinstance(found, dict) else {}


def _answer(reply: Any, ident: str) -> str:
    """``ident``'s value in a getProperty reply, canonical; "" when it has none."""
    values = _property_values(reply)
    return _canon(values[ident]) if ident in values else ""


def _held_request(
    product_code: str,
    context: codec.Context,
    idents: Sequence[str],
    params: Mapping[int, str],
    *,
    as_command: bool,
) -> dict[str, Any]:
    """getProperty for ``idents`` on a device holding ``params`` (their ids as command ids
    too when ``as_command``)."""
    device = context.device(product_code)
    device["params"] = [{"param_type": p, "param_value": v} for p, v in params.items()]
    cmds = list(params) if as_command else []
    return {"kind": "get", "cmds": cmds, "device": device, "props": list(idents)}


def _held_block(
    product_code: str,
    handler: Path,
    context: codec.Context,
    idents: Sequence[str],
    params: Mapping[int, str],
    *,
    as_command: bool,
) -> dict[str, str]:
    """getProperty for ``idents`` on a device holding ``params``, by identifier (``_answer``)."""
    request = _held_request(product_code, context, idents, params, as_command=as_command)
    (reply,) = run_driver(product_code, handler, [request])
    return {i: _answer(reply, i) for i in idents}


def handler_numbers(handler: Path) -> set[int]:
    """Every number literal of the handler's source (decimal, with exponent, or hex)."""
    return set(_source_numbers(handler.read_text(encoding="utf-8", errors="replace")))


@functools.lru_cache(maxsize=2)  # a model asks for its handler's numbers several times
def _source_numbers(source: str) -> frozenset[int]:
    found: set[int] = set()
    for literal in JS_NUMBER.findall(source):
        if literal[:2].lower() == "0x":
            found.add(int(literal, 16))
        else:
            mantissa, _, exponent = literal.lower().partition("e")
            found.add(int(mantissa) * 10 ** int(exponent or 0))
    return frozenset(found)


def handler_param_ids(handler: Path) -> list[int]:
    """The ids of :data:`PROBE_PARAMS` the handler's source writes as a number literal,
    ascending: the only parameter ids its property table and parsers compare against."""
    return sorted(n for n in handler_numbers(handler) if n in PROBE_PARAMS)


def _locate_in_block(
    product_code: str,
    handler: Path,
    context: codec.Context,
    idents: Sequence[str],
    block: Sequence[int],
    *,
    as_command: bool,
) -> dict[str, Located]:
    """The identifiers of ``idents`` one parameter of ``block`` decides (see
    :func:`locate_params`), each with that parameter."""

    def held(
        on: Callable[[int], bool], asked: Sequence[str], *, descending: bool = False
    ) -> dict[str, str]:
        order = range(len(block) - 1, -1, -1) if descending else range(len(block))
        params = {block[n]: PROBE_ON if on(n) else PROBE_OFF for n in order}
        return _held_block(product_code, handler, context, asked, params, as_command=as_command)

    def search(asked: Sequence[str], *, descending: bool) -> dict[str, int]:
        """Per identifier, the position in ``block`` of the parameter that decides it."""
        index = dict.fromkeys(asked, 0)
        for bit in range((len(block) - 1).bit_length()):
            if not index:
                break
            answer = held(lambda n, bit=bit: bool(n >> bit & 1), list(index), descending=descending)
            for ident in index:
                if answer[ident] == high[ident]:
                    index[ident] |= 1 << bit
        return index

    high = held(lambda _: True, idents)
    low = held(lambda _: False, idents)
    up = search([i for i in idents if high[i] != low[i]], descending=False)
    up = {i: n for i, n in up.items() if n < len(block)}
    # Held in the other order, the search must find the same parameter: when it does
    # not, several parameters fill the property and the one the handler meets last wins.
    down = search(list(up), descending=True)
    candidates = {i: n for i, n in up.items() if down[i] == n}
    asks = [(i, raw) for i in candidates for raw in (PROBE_ON, PROBE_OFF)]
    requests = [
        Located(block[candidates[i]], as_command).request(product_code, context, i, raw)
        for i, raw in asks
    ]
    # The block with only the found id at PROBE_OFF: no other id may turn the value.
    requests += [
        _held_request(
            product_code,
            context,
            [i],
            {p: PROBE_OFF if k == n else PROBE_ON for k, p in enumerate(block)},
            as_command=as_command,
        )
        for i, n in candidates.items()
    ]
    replies = run_driver(product_code, handler, requests) if requests else []
    alone = {
        key: _answer(reply, key[0]) for key, reply in zip(asks, replies[: len(asks)], strict=True)
    }
    others_on = {
        i: _answer(reply, i) for i, reply in zip(candidates, replies[len(asks) :], strict=True)
    }
    # Held alone, the parameter must decide the value as it did in the block, and the
    # block with only it off must read as the block all off.
    return {
        i: Located(block[n], as_command)
        for i, n in candidates.items()
        if (alone[i, PROBE_ON], alone[i, PROBE_OFF], others_on[i]) == (high[i], low[i], low[i])
    }


def locate_params(
    product_code: str,
    handler: Path,
    context: codec.Context,
    idents: Sequence[str],
    counts: dict[str, int],
) -> dict[str, Located]:
    """Per identifier, the parameter getProperty reads it from in ``context``, among the
    ids :func:`handler_param_ids` lists; an identifier no single parameter decides is
    left out.

    The device holds a block of ids at :data:`PROBE_ON`, then at :data:`PROBE_OFF`; for
    an identifier whose value differs between the two, each bit of the deciding id's
    position in the block is the answer with only the ids at positions that have that
    bit at :data:`PROBE_ON`. The search runs again with the block in descending order and
    must find the same id (else several parameters fill the property, the last one met
    winning); the id held alone must give both values again, and the block with only
    that id at :data:`PROBE_OFF` the value of the block all off (else another id turns
    the value too). Asked for the properties alone, as the app asks
    for them, then with the held ids as command ids for those still unplaced; the first
    block that places an identifier wins.
    """
    found: dict[str, Located] = {}
    ids = handler_param_ids(handler)
    blocks = [ids[start : start + PROBE_CHUNK] for start in range(0, len(ids), PROBE_CHUNK)]
    for as_command in (False, True):
        for block in blocks:
            pending = [i for i in idents if i not in found]
            if not pending:
                return found
            placed = _locate_in_block(
                product_code, handler, context, pending, block, as_command=as_command
            )
            found.update(placed)
            if placed:
                _count(counts, "locate:" + ("command" if as_command else "property"), len(placed))
    return found


def _stored(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    *,
    param: int,
    value: str,
) -> str | None:
    """The text the handler's write of ``value`` to ``ident`` stores in ``param``
    (``update`` or ``extUpdates``); None when it stores none there."""
    device = context.device(product_code)
    request = {"kind": "set", "identifier": ident, "payload": value, "device": device}
    (reply,) = run_driver(product_code, handler, [request])
    hits = [d["param_value"] for d in _param_dump(p2p(reply)) if d["param_type"] == param]
    return variants.text(hits[0]) if hits else None


def held_texts(kind: str, values: Sequence[codec.Value]) -> list[str]:
    """The texts a located parameter is held at to read a property of ``kind`` with
    domain ``values``: each value's text form, plus :data:`OPEN_NUMBER_PROBE` and
    :data:`OPEN_JSON_PROBE` for an open kind and :data:`BOOL_EXTRA_PROBE` for a bool."""
    extra: tuple[str, ...] = ()
    if kind in codec.SINGLE_PROBE_KINDS:
        extra = (OPEN_NUMBER_PROBE, OPEN_JSON_PROBE)
    elif kind == "bool":
        extra = (BOOL_EXTRA_PROBE,)
    return list(dict.fromkeys([*(codec.str_form(v) for v in values), *extra]))


def _reads_as_is(answers: Mapping[str, Any]) -> bool:
    """getProperty gave back every held text unchanged."""
    return all(
        a is not codec.MISSING and not isinstance(a, dict | list) and variants.text(a) == raw
        for raw, a in answers.items()
    )


def _reads_as_number(answers: Mapping[str, Any]) -> bool:
    """getProperty gave every held integer text back as that integer, and the held JSON
    object parsed whole (a JSON parse of the whole value) or not at all, never as
    another structure (a field of it)."""
    for raw, a in answers.items():
        if raw == OPEN_JSON_PROBE:
            if isinstance(a, dict | list) and a != json.loads(raw):
                return False
        elif type(a) is not int or str(a) != raw:
            return False
    return True


def open_read_ok(
    kind: str,
    answers: Mapping[str, Any],
    *,
    shared: bool,
    stores_as_is: Callable[[Sequence[str]], bool],
) -> bool:
    """Whether a located parameter is an open-kind property's value (``answers``: held
    text -> getProperty's value, :func:`held_texts`): every text reads back unchanged,
    or, for ``other``, every integer text reads back as that integer (a numeric parse,
    :func:`_reads_as_number`) while no other property is read from the parameter
    (``shared``: it holds a structure) and the handler's own write, if any, stores each
    integer text in it as is (``stores_as_is``). A handler that reads one field of a JSON
    value fails both: the JSON probe does not read back as itself, and its numbers are
    fields of a structure another property or its own write shows."""
    if _reads_as_is(answers):
        return True
    if kind != "other" or shared or not _reads_as_number(answers):
        return False
    return stores_as_is([raw for raw in answers if raw != OPEN_JSON_PROBE])


def reported_param(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    values: Collection[str],
    *,
    located: Mapping[str, Located],
    kind: str | None = None,
) -> int | None:
    """The device parameter getProperty reports ``ident`` from as is, in ``context``:
    the one :func:`locate_params` placed it on (``located``), which reads each of
    ``values`` back unchanged, which the handler's own write of ``ident`` (if any)
    stores each of them in as is, and, for an open ``kind``, which :func:`open_read_ok`
    accepts; None when there is none.
    """
    where = located.get(ident)
    if where is None:
        return None

    def read(value: str) -> Any:
        request = where.request(product_code, context, ident, value)
        (reply,) = run_driver(product_code, handler, [request])
        return _property_values(reply).get(ident, codec.MISSING)

    def stores_as_is(texts: Iterable[str]) -> bool:
        return all(
            _stored(product_code, handler, context, ident, param=where.param, value=v) in (None, v)
            for v in texts
        )

    if not all(variants.text(read(v)) == v for v in values) or not stores_as_is(values):
        return None
    if kind in codec.SINGLE_PROBE_KINDS:
        answers = {raw: read(raw) for raw in held_texts(kind, [])}
        shared = sum(w.param == where.param for w in located.values()) > 1
        if not open_read_ok(kind, answers, shared=shared, stores_as_is=stores_as_is):
            return None
    return where.param


def located_reads(
    product_code: str,
    handler: Path,
    context: codec.Context,
    props: Mapping[str, dict[str, Any]],
    located: Mapping[str, Located],
    *,
    counts: dict[str, int],
    wire: codec.WireValues | None = None,
) -> dict[str, dict[str, Any]]:
    """The read codec of each of ``props`` (identifier -> property) from the parameter
    :func:`locate_params` placed it on, in ``context``: the device holds the parameter at
    each text of :func:`held_texts`, and the codec is inferred from the domain values'
    round trips as a write's is (``codec.infer_read``), marked ``no_default``. A bool
    reads only when getProperty
    gives a boolean for every held text; an open kind only when :func:`open_read_ok`
    accepts the answers."""
    asks = [
        (ident, raw, where)
        for ident, prop in sorted(props.items())
        if (where := located.get(ident)) is not None
        for raw in held_texts(*codec.domain(prop))
    ]
    requests = [where.request(product_code, context, ident, raw) for ident, raw, where in asks]
    replies = run_driver(product_code, handler, requests, wire) if requests else []
    answers: dict[str, dict[str, Any]] = {}
    for (ident, raw, _), reply in zip(asks, replies, strict=True):
        answers.setdefault(ident, {})[raw] = _property_values(reply).get(ident, codec.MISSING)
    holders = Counter(where.param for where in located.values())
    out: dict[str, dict[str, Any]] = {}
    for ident, got in answers.items():
        kind, values = codec.domain(props[ident])
        where = located[ident]
        if kind == "bool" and not all(isinstance(a, bool) for a in got.values()):
            _count(counts, "read:handler parameter not a bool")
            continue
        if kind in codec.SINGLE_PROBE_KINDS and not open_read_ok(
            kind,
            got,
            shared=holders[where.param] > 1,
            stores_as_is=lambda texts, ident=ident, param=where.param: all(
                _stored(product_code, handler, context, ident, param=param, value=v) in (None, v)
                for v in texts
            ),
        ):
            _count(counts, "read:handler parameter parsed")
            continue
        samples = [
            codec.ReadSample(v, where.param, codec.str_form(v), got[codec.str_form(v)])
            for v in values
        ]
        read, _ = codec.infer_read(kind, samples)
        if read is not None:
            # A status only the device reports: nothing reported reads None, no default.
            out[ident] = {**read, "no_default": True}
            _count(counts, "read:handler parameter")
    return out


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object's members; ValueError when a name repeats."""
    if len({name for name, _ in pairs}) != len(pairs):
        raise ValueError("a repeated member name")
    return dict(pairs)


def _bool_struct(answer: Any) -> dict[str, bool] | None:
    """A getProperty value as a non-empty object of booleans: the object, or its JSON text
    naming each member once; None for anything else."""
    if isinstance(answer, str):
        try:
            answer = json.loads(answer, object_pairs_hook=_unique_members)
        except ValueError:
            return None
    if not isinstance(answer, dict) or not answer:
        return None
    if not all(type(v) is bool for v in answer.values()):
        return None
    return answer


def _single_bit_members(answers: Mapping[int, Any]) -> dict[str, int] | None:
    """Member -> bit from getProperty's values (``answers``: held mask -> value) at 0, every
    member off, and at each single bit below :data:`FLAG_PROBE_BITS`: the same members, at
    most one of them on, none on for two bits. A member no bit turns on is left out."""
    zero = _bool_struct(answers.get(0, codec.MISSING))
    if zero is None or any(zero.values()):
        return None
    members: dict[str, int] = {}
    for bit in (1 << k for k in range(FLAG_PROBE_BITS)):
        got = _bool_struct(answers.get(bit, codec.MISSING))
        if got is None or got.keys() != zero.keys():
            return None
        on = [name for name, value in got.items() if value]
        if len(on) > 1 or (on and on[0] in members):
            return None
        if on:
            members[on[0]] = bit
    return members


def flag_members(answers: Mapping[int, Any]) -> dict[str, int] | None:
    """Member -> bit of a status the handler builds as an object of booleans, one per bit
    of its parameter (``answers``: held mask -> getProperty's value): one member per bit
    (:func:`_single_bit_members`), and at the OR of their bits the same members, every
    one on (no member without a bit; a mask, not a value compared with each bit); None
    otherwise."""
    members = _single_bit_members(answers)
    if members is None:
        return None
    every = _bool_struct(answers.get(sum(members.values()), codec.MISSING))
    if every is None or every.keys() != members.keys() or not all(every.values()):
        return None
    return members


def flags_reads(
    product_code: str,
    handler: Path,
    context: codec.Context,
    idents: Iterable[str],
    located: Mapping[str, Located],
    *,
    counts: dict[str, int],
) -> dict[str, tuple[dict[str, Any], dict[str, int]]]:
    """The read and the members (:func:`flag_members`) of each of ``idents`` (settings
    without a read) that getProperty fills from its located parameter as an object of
    booleans, one per bit, in ``context``. The parameter is held at 0 first; those read
    as such an object with every member off are held at each single bit, then at the OR
    of the members' bits."""

    def ask(masks: Mapping[str, Iterable[int]]) -> dict[str, dict[int, Any]]:
        asks = [(ident, mask) for ident, held in masks.items() for mask in held]
        requests = [located[i].request(product_code, context, i, str(m)) for i, m in asks]
        replies = run_driver(product_code, handler, requests) if requests else []
        got: dict[str, dict[int, Any]] = {}
        for (ident, mask), reply in zip(asks, replies, strict=True):
            got.setdefault(ident, {})[mask] = _property_values(reply).get(ident, codec.MISSING)
        return got

    zero = ask({i: [0] for i in sorted(idents) if i in located})
    off = [
        ident
        for ident, got in zero.items()
        if (struct := _bool_struct(got[0])) is not None and not any(struct.values())
    ]
    bits = [1 << k for k in range(FLAG_PROBE_BITS)]
    answers = {i: {**zero[i], **got} for i, got in ask(dict.fromkeys(off, bits)).items()}
    singles = {i: m for i, a in answers.items() if (m := _single_bit_members(a)) is not None}
    every = ask({i: [sum(m.values())] for i, m in singles.items()})
    out: dict[str, tuple[dict[str, Any], dict[str, int]]] = {}
    for ident in off:
        members = flag_members({**answers[ident], **every.get(ident, {})})
        if members is None:
            _count(counts, "read:flags no mask")
            continue
        read = {"param": located[ident].param, "map": None, "no_default": True}
        out[ident] = (read, members)
        _count(counts, "read:flags")
    return out


def as_flags_status(entry: dict[str, Any], read: dict[str, Any], members: dict[str, int]) -> None:
    """Make ``entry`` the read-only ``flags`` status of ``members`` (member -> bit) read by
    ``read``, without the thing description's domain."""
    for key in TD_DOMAIN_FIELDS:
        entry.pop(key, None)
    entry.update(kind="flags", flags=members, read=read)


def _level(answer: Any) -> int | None:
    """A getProperty value as a battery level: an integer, or the text of one."""
    if type(answer) is int:
        return answer
    if isinstance(answer, str) and BATTERY_LEVEL_TEXT.fullmatch(answer):
        return int(answer)
    return None


def _battery_request(
    product_code: str, context: codec.Context, params: Sequence[tuple[int, str]]
) -> dict[str, Any]:
    """getProperty for the battery on a device listing ``params`` in that order, their ids
    also as command ids."""
    device = context.device(product_code)
    device["params"] = [{"param_type": p, "param_value": v} for p, v in params]
    cmds = [p for p, _ in params]
    return {"kind": "get", "cmds": cmds, "device": device, "props": [BATTERY_PROPERTY]}


def battery_sources(product_code: str, handler: Path, context: codec.Context) -> list[int]:
    """The parameters of :func:`handler_param_ids` each of which, listed alone at
    :data:`BATTERY_PROBE`, gives the battery property another value than a device
    listing none, ascending. Found by halving the id list: a half is split again while
    it changes the value."""
    ids = handler_param_ids(handler)

    def ask(groups: list[list[int]]) -> list[str]:
        requests = [
            _battery_request(product_code, context, [(p, BATTERY_PROBE) for p in g]) for g in groups
        ]
        return [_answer(r, BATTERY_PROPERTY) for r in run_driver(product_code, handler, requests)]

    (none,) = ask([[]])
    found: list[int] = []
    pending = [ids] if ids else []
    while pending:
        split: list[list[int]] = []
        for group, answer in zip(pending, ask(pending), strict=True):
            if answer == none:
                continue
            if len(group) == 1:
                found.extend(group)
            else:
                split += [group[: len(group) // 2], group[len(group) // 2 :]]
        pending = split
    return sorted(found)


def battery_reads(
    product_code: str, handler: Path, context: codec.Context, counts: dict[str, int]
) -> list[dict[str, Any]]:
    """The model's battery reads (the settings file's ``battery``): each parameter of
    :func:`battery_sources` with ``levels``, the level getProperty gives for each held
    text of :data:`BATTERY_SAMPLES` where it is not that number (null for a level below
    0, the handler's no level), in the handler's precedence
    (:func:`battery_precedence`). Empty when no parameter fills the battery, or when one
    gives a value that is no level (counted)."""
    sources = battery_sources(product_code, handler, context)
    if not sources:
        return []
    texts = [str(n) for n in BATTERY_SAMPLES]
    asks = [(p, t) for p in sources for t in texts]
    replies = run_driver(
        product_code, handler, [_battery_request(product_code, context, [a]) for a in asks]
    )
    levels: dict[int, dict[str, int | None]] = {p: {} for p in sources}
    for (param, text), reply in zip(asks, replies, strict=True):
        level = _level(_property_values(reply).get(BATTERY_PROPERTY))
        if level is None:
            _count(counts, "battery:not a level")
            return []
        if level != int(text):
            levels[param][text] = None if level < 0 else level
    _count(counts, "battery", len(sources))
    return [
        {"param": p, **({"levels": levels[p]} if levels[p] else {})}
        for p in battery_precedence(product_code, handler, context, sources, levels)
    ]


def battery_precedence(
    product_code: str,
    handler: Path,
    context: codec.Context,
    sources: Sequence[int],
    levels: Mapping[int, Mapping[str, Any]],
) -> list[int]:
    """``sources`` in the order the handler prefers them: by how many others each wins
    over when listed first (its value is read although another follows it), then
    ascending. A handler that takes the one the device lists last (or first) prefers
    none, so its order is ascending."""
    if len(sources) < 2:
        return list(sources)
    plain = [str(n) for n in BATTERY_SAMPLES if all(str(n) not in m for m in levels.values())]
    if len(plain) < 2:
        raise GeneratorError(f"{product_code}: no two battery levels every source reads as is")
    first, second = plain[:2]
    pairs = [(a, b) for a in sources for b in sources if a != b]
    requests = [
        _battery_request(product_code, context, [(a, first), (b, second)]) for a, b in pairs
    ]
    replies = run_driver(product_code, handler, requests)
    beats = Counter(
        a
        for (a, _), r in zip(pairs, replies, strict=True)
        if _level(_property_values(r).get(BATTERY_PROPERTY)) == int(first)
    )
    return sorted(sources, key=lambda p: (-beats[p], p))


def battery_block(
    product_code: str,
    handler: Path,
    props: Sequence[Mapping[str, Any]],
    context: codec.Context,
    counts: dict[str, int],
) -> dict[str, Any]:
    """The settings file's ``battery`` (:func:`battery_reads`) for a model whose thing
    description has the battery property; empty when it has none or no read is found."""
    if not any(p["identifier"] == BATTERY_PROPERTY for p in props):
        return {}
    reads = battery_reads(product_code, handler, context, counts)
    return {"battery": reads} if reads else {}


def _sd_answer(device: Mapping[str, Any], status: int) -> dict[str, Any]:
    """The handler's parse of an ``SDINFO_EX`` answer carrying ``status``, on ``device``."""
    fields = {"ivalue1": SD_PROBE_TOTAL, "ivalue2": SD_PROBE_FREE, "ivalue3": status}
    return {"kind": "parse", "action": SD_STATUS_ACTION, "input": fields, "device": device}


def _sd_group(status: Any) -> int | None:
    """The group of a status object ``{"status": <group>, ...}`` (or its JSON text)."""
    if isinstance(status, str):
        try:
            status = json.loads(status)
        except ValueError:
            return None
    group = status.get("status") if isinstance(status, dict) else None
    return group if type(group) is int else None


def _sd_parsed(reply: Any) -> int | None:
    """The status group of a parse reply (``mapOf.status``); None for any other shape."""
    map_of = (p2p(reply) or {}).get("mapOf")
    return _sd_group(map_of.get("status")) if isinstance(map_of, dict) else None


def sd_status_codes(handler: Path) -> list[int]:
    """The statuses the grouping is swept at, ascending: :data:`SD_STATUS_SAMPLES` and
    every int32 number literal of the handler's source, with its negative."""
    found = set(SD_STATUS_SAMPLES)
    for n in handler_numbers(handler):
        found.update(v for v in (n, -n) if v in SD_STATUS_RANGE)
    found.discard(SD_STATUS_UNLISTED)
    return sorted(found)


def _sd_table(groups: Sequence[int | None]) -> tuple[int, list[int]] | None:
    """The default group and the group of each status of the sweep, from the groups of
    :data:`SD_STATUS_UNLISTED` (first) and of each status; None when one is no group or
    every status has the same group (the handler reads no status)."""
    default, *rest = groups
    if default is None or any(g is None for g in rest) or all(g == default for g in rest):
        return None
    return default, cast(list[int], rest)


def sd_status_groups(
    product_code: str,
    handler: Path,
    contexts: Mapping[str, codec.Context],
    located: Mapping[str, Located],
    counts: dict[str, int],
) -> dict[str, Any] | None:
    """How the handler groups an ``SDINFO_EX`` status (the settings file's
    ``sd_status_groups``): ``{"default": <group>, "codes": {"<status>": <group>},
    "from": <SdStatusSource>}`` with each status of :func:`sd_status_codes` whose group is
    not the default and what the table is read from, plus ``"param"`` when the handler
    groups that device parameter in place of the answer's status whenever the device
    lists it with a value (:func:`sd_status_param`).

    The groups come from the handler's parse of the answer (:data:`SD_STATUS_ACTION`);
    where that parse reads no status (one group for every status, or no parse), from the
    property the handler fills from the device's status parameter
    (:data:`SD_STATUS_PROPERTY`, at the parameter :func:`_status_param` names in the base
    context). Each sweep, and :func:`sd_status_param`, runs in every context, one driver
    job per context, and the contexts must agree. None when neither reads the status.
    Raises GeneratorError when the contexts disagree.
    """
    codes = sd_status_codes(handler)
    asked = [SD_STATUS_UNLISTED, *codes]
    tables = []
    for ctx in contexts.values():
        device = ctx.device(product_code)
        replies = run_driver(product_code, handler, [_sd_answer(device, s) for s in asked])
        tables.append(_sd_table([_sd_parsed(r) for r in replies]))
    table, source = _agreed(product_code, "grouping", tables), SdStatusSource.ANSWER
    if table is None and (where := _status_param(product_code, handler, contexts[BASE], located)):
        tables = []
        for ctx in contexts.values():
            requests = [where.request(product_code, ctx, SD_STATUS_PROPERTY, str(s)) for s in asked]
            replies = run_driver(product_code, handler, requests)
            groups = [_sd_group(_property_values(r).get(SD_STATUS_PROPERTY)) for r in replies]
            tables.append(_sd_table(groups))
        table = _agreed(product_code, "status property's grouping", tables)
        source = SdStatusSource.STATUS_PROPERTY
    if table is None:
        return None
    _count(counts, f"sd status:{SD_SOURCE_COUNTS[source]}")
    default, groups = table
    by_code = dict(zip(codes, groups, strict=True))
    out: dict[str, Any] = {
        "codes": {str(c): g for c, g in by_code.items() if g != default},
        "default": default,
        "from": source.value,
    }
    if source is SdStatusSource.ANSWER:
        param = sd_status_param(product_code, handler, contexts, by_code, default)
        if param is not None:
            out["param"] = param
    return out


def _agreed[T](product_code: str, what: str, per_context: Sequence[T]) -> T:
    """The one value every context gave; raises GeneratorError when they differ."""
    if any(v != per_context[0] for v in per_context):
        raise GeneratorError(f"{product_code}: the SDINFO_EX {what} differs between contexts")
    return per_context[0]


def sd_status_block(
    product_code: str,
    handler: Path,
    contexts: Mapping[str, codec.Context],
    located: Mapping[str, Located],
    counts: dict[str, int],
) -> dict[str, Any]:
    """The settings file's ``sd_status_groups`` (:func:`sd_status_groups`); empty when
    the handler reads no ``SDINFO_EX`` status."""
    groups = sd_status_groups(product_code, handler, contexts, located, counts)
    return {} if groups is None else {"sd_status_groups": groups}


def _status_param(
    product_code: str, handler: Path, context: codec.Context, located: Mapping[str, Located]
) -> Located | None:
    """Where getProperty reads :data:`SD_STATUS_PROPERTY` from: its located parameter,
    else the one :func:`locate_params` finds for it (the thing description need not
    declare it); None when no parameter fills it."""
    if (where := located.get(SD_STATUS_PROPERTY)) is not None:
        return where
    return locate_params(product_code, handler, context, [SD_STATUS_PROPERTY], {}).get(
        SD_STATUS_PROPERTY
    )


LOCK_PROPERTY = "smart_lock_onoff_status"  # the lock state the lock's card shows
LOCK_PROBE = "7"  # the value a candidate lock-state parameter is listed at
LOCK_SAMPLES = range(-1, 64)  # the raw codes the lock-state read is checked at
GARAGE_STATE_PROPERTY = "garage_door_on_off"  # the doors' state bits; its write moves one
GARAGE_MOTOR_PROPERTY = "garage_door_binding_status"  # the doors with a motor bound
GARAGE_SENSOR_PROPERTY = "garage_sensor_binding_status"  # the doors with a sensor bound
GARAGE_STATE_PROBE = "5"  # door 1 open and door 2 open
GARAGE_BIND_PROBE = "3"  # both doors bound
GARAGE_STATE_SAMPLES = range(64)  # every combination of the six state bits
GARAGE_BIND_SAMPLES = range(16)  # every combination of the four binding bits
GARAGE_COMMAND_PROBE = {"type": 1, "user_name": "probe", "source": 0}  # a door command body
GARAGE_DOOR_CODES = {  # the handler's code of each door state
    GarageDoorState.UNKNOWN: 0,
    GarageDoorState.OPEN: 1,
    GarageDoorState.CLOSED: 2,
}


def _get_request(
    product_code: str, context: codec.Context, ident: str, params: Sequence[tuple[int, str]]
) -> dict[str, Any]:
    """getProperty for ``ident`` on a device listing ``params`` (their ids also as command
    ids), as :func:`_battery_request` asks."""
    device = context.device(product_code)
    device["params"] = [{"param_type": p, "param_value": v} for p, v in params]
    return {"kind": "get", "cmds": [p for p, _ in params], "device": device, "props": [ident]}


def held_sources(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    *,
    probe: str,
    hit: Callable[[Any], bool],
) -> list[int]:
    """The parameters of :func:`handler_param_ids` that, listed at ``probe``, make
    getProperty give ``ident`` a value ``hit`` accepts, ascending. Found by halving the id
    list: a half is split again while its value is a hit (a parameter the handler reads
    in place of the listed one, such as a context's other state parameter, is no hit)."""
    ids = handler_param_ids(handler)

    def ask(groups: list[list[int]]) -> list[bool]:
        requests = [
            _get_request(product_code, context, ident, [(p, probe) for p in g]) for g in groups
        ]
        replies = run_driver(product_code, handler, requests)
        return [hit(_property_values(r).get(ident)) for r in replies]

    found: list[int] = []
    pending = [ids] if ids else []
    while pending:
        split: list[list[int]] = []
        for group, hits in zip(pending, ask(pending), strict=True):
            if not hits:
                continue
            if len(group) == 1:
                found.extend(group)
            else:
                split += [group[: len(group) // 2], group[len(group) // 2 :]]
        pending = split
    return sorted(found)


def _one_source(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    *,
    probe: str,
    hit: Callable[[Any], bool],
) -> int | None:
    """The one parameter :func:`held_sources` finds for ``ident``; None for none. Raises
    GeneratorError when several do."""
    found = held_sources(product_code, handler, context, ident, probe=probe, hit=hit)
    if len(found) > 1:
        raise GeneratorError(f"{product_code}: {ident} is read from {found} in {context.name}")
    return found[0] if found else None


def _held_values(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    *,
    param: int,
    samples: Iterable[int],
) -> list[tuple[int, Any]]:
    """``ident``'s getProperty value with ``param`` held at each of ``samples``."""
    texts = list(samples)
    requests = [_get_request(product_code, context, ident, [(param, str(n))]) for n in texts]
    replies = run_driver(product_code, handler, requests)
    return [(n, _property_values(r).get(ident)) for n, r in zip(texts, replies, strict=True)]


def lock_block(
    product_code: str,
    handler: Path,
    props: Sequence[Mapping[str, Any]],
    contexts: Mapping[str, codec.Context],
    counts: dict[str, int],
) -> dict[str, Any]:
    """The settings file's ``lock``: the parameter getProperty reads
    :data:`LOCK_PROPERTY` from in each context, the base context's as ``param`` and each
    other context's that differs under ``contexts``. Empty when the thing description has
    no such property or no context reads one parameter for it.

    The read must give the raw code back as that integer for every
    :data:`LOCK_SAMPLES` text (the code the eufy app maps to a state); raises
    GeneratorError when it does not, when only some contexts read a parameter, or when
    several parameters fill the property in one context.
    """
    if not any(p["identifier"] == LOCK_PROPERTY for p in props):
        return {}

    def hit(value: Any) -> bool:
        return _level(value) == int(LOCK_PROBE)

    by_context: dict[str, int | None] = {}
    for name, ctx in contexts.items():
        param = _one_source(product_code, handler, ctx, LOCK_PROPERTY, probe=LOCK_PROBE, hit=hit)
        by_context[name] = param
        if param is None:
            continue
        for code, value in _held_values(
            product_code, handler, ctx, LOCK_PROPERTY, param=param, samples=LOCK_SAMPLES
        ):
            if _level(value) != code:
                raise GeneratorError(
                    f"{product_code}: {LOCK_PROPERTY} reads {code} as {value!r} in {name}"
                )
    found = {name: p for name, p in by_context.items() if p is not None}
    if not found:
        _count(counts, "lock:no read")
        return {}
    if len(found) != len(by_context):
        missing = sorted(set(by_context) - set(found))
        raise GeneratorError(f"{product_code}: {LOCK_PROPERTY} has no read in {missing}")
    base = found[BASE]
    _count(counts, "lock")
    return {
        "lock": {
            "param": base,
            "contexts": {name: p for name, p in sorted(found.items()) if p != base},
        }
    }


def _door_codes(value: Any) -> tuple[Any, Any] | None:
    """``(door_1, door_2)`` of a JSON object text the handler gives a door property."""
    try:
        parsed = json.loads(value) if isinstance(value, str) else None
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed.get("door_1"), parsed.get("door_2")


def _garage_source(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ident: str,
    *,
    probe: str,
    want: Callable[[int], tuple[int, int]],
    samples: Iterable[int],
) -> int | None:
    """The parameter getProperty reads the door property ``ident`` from in ``context`` (the
    one whose value at ``probe`` makes it a door object), checked at every sample against
    ``want`` (the library's door codes of a value); None when no parameter fills it.
    Raises GeneratorError on a mismatch."""

    def hit(value: Any) -> bool:
        return _door_codes(value) is not None

    param = _one_source(product_code, handler, context, ident, probe=probe, hit=hit)
    if param is None:
        return None
    held = _held_values(product_code, handler, context, ident, param=param, samples=samples)
    for bits, value in held:
        if _door_codes(value) != want(bits):
            raise GeneratorError(
                f"{product_code}: {ident} reads {bits} as {value!r}, the library as {want(bits)}"
            )
    return param


def _state_codes(bits: int) -> tuple[int, int]:
    return GARAGE_DOOR_CODES[door_state(bits, 1)], GARAGE_DOOR_CODES[door_state(bits, 2)]


def _bind_codes(bits: int) -> tuple[int, int]:
    return int(bound(bits, 1)), int(bound(bits, 2))


def _garage_control(
    product_code: str, handler: Path, context: codec.Context
) -> tuple[int, int] | None:
    """``(cmd, subCmd)`` of the handler's write of :data:`GARAGE_STATE_PROPERTY` with a
    door command body, when it sends that body as its params unchanged; else None."""
    request = {
        "kind": "set",
        "identifier": GARAGE_STATE_PROPERTY,
        "payload": GARAGE_COMMAND_PROBE,
        "device": context.device(product_code),
    }
    (reply,) = run_driver(product_code, handler, [request])
    recipe = p2p(reply)
    if recipe is None or recipe.get("params") != GARAGE_COMMAND_PROBE:
        return None
    cmd, sub = recipe.get("cmd"), recipe.get("subCmd")
    return (cmd, sub) if type(cmd) is int and type(sub) is int else None


def garage_block(
    product_code: str,
    handler: Path,
    props: Sequence[Mapping[str, Any]],
    contexts: Mapping[str, codec.Context],
    counts: dict[str, int],
) -> dict[str, Any]:
    """The settings file's ``garage``: the parameters getProperty reads the door state
    (:data:`GARAGE_STATE_PROPERTY`), the bound motors and the bound sensors from, and the
    command the state property's write sends a door command body with. Empty when the
    thing description lacks one of the three properties, or the handler fills one from no
    parameter or sends no such write.

    Each read is checked at every combination of its bits against the library's reading
    (:func:`~eufy_home_security.devices.garage.door_state`,
    :func:`~eufy_home_security.devices.garage.bound`); raises GeneratorError on a
    mismatch or when the contexts disagree.
    """
    declared = {p["identifier"] for p in props}
    wanted = (GARAGE_STATE_PROPERTY, GARAGE_MOTOR_PROPERTY, GARAGE_SENSOR_PROPERTY)
    if not set(wanted) <= declared:
        if declared & set(wanted):
            _count(counts, "garage:incomplete")
        return {}
    per_context = []
    for ctx in contexts.values():
        reads = (
            _garage_source(
                product_code,
                handler,
                ctx,
                GARAGE_STATE_PROPERTY,
                probe=GARAGE_STATE_PROBE,
                want=_state_codes,
                samples=GARAGE_STATE_SAMPLES,
            ),
            *(
                _garage_source(
                    product_code,
                    handler,
                    ctx,
                    ident,
                    probe=GARAGE_BIND_PROBE,
                    want=_bind_codes,
                    samples=GARAGE_BIND_SAMPLES,
                )
                for ident in (GARAGE_MOTOR_PROPERTY, GARAGE_SENSOR_PROPERTY)
            ),
        )
        per_context.append((reads, _garage_control(product_code, handler, ctx)))
    if any(entry != per_context[0] for entry in per_context):
        raise GeneratorError(f"{product_code}: the garage door reads differ between contexts")
    (state, motors, sensors), control = per_context[0]
    if state is None or motors is None or sensors is None or control is None:
        _count(counts, "garage:no read or write")
        return {}
    _count(counts, "garage")
    cmd, sub = control
    return {
        "garage": {
            "state": state,
            "motors": motors,
            "sensors": sensors,
            "control": {"cmd": cmd, "subCmd": sub},
        }
    }


def _sd_parse_with(
    product_code: str,
    handler: Path,
    context: codec.Context,
    asks: Sequence[tuple[Sequence[tuple[int, str]], int]],
) -> list[int | None]:
    """The parse's group for each ``(device params, answer status)`` of ``asks``, in one
    driver job."""
    requests = []
    for params, status in asks:
        device = context.device(product_code)
        device["params"] = [{"param_type": p, "param_value": v} for p, v in params]
        requests.append(_sd_answer(device, status))
    return [_sd_parsed(r) for r in run_driver(product_code, handler, requests)] if asks else []


def sd_status_param(
    product_code: str,
    handler: Path,
    contexts: Mapping[str, codec.Context],
    by_code: Mapping[int, int],
    default: int,
) -> int | None:
    """The device parameter the handler's parse groups in place of the answer's status
    when the device lists it with a value (an empty value keeps the answer's status);
    None when none does.

    Found in the base context by halving :func:`handler_param_ids`, held at a status
    whose group is not the default while the answer carries :data:`SD_STATUS_UNLISTED`.
    Checked in every context, one driver job each: the parse groups it as
    :meth:`SdStatusGroups.group` does at each swept status, empty at each swept answer
    status and at each of :data:`SD_PARAM_TEXTS`; outside the base context the other
    ids, held together, leave the default group. Raises GeneratorError when several
    parameters change the group, or a check fails.
    """
    probe = next(c for c, g in by_code.items() if g != default)
    ids = handler_param_ids(handler)
    param = _sd_find_param(product_code, handler, contexts[BASE], ids, probe=probe, default=default)
    checks: list[tuple[Sequence[tuple[int, str]], int]] = []
    if param is not None:
        checks += [([(param, str(c))], probe) for c in by_code]
        checks += [([(param, "")], c) for c in by_code]
        checks += [([(param, text)], probe) for text in SD_PARAM_TEXTS]
    library = SdStatusGroups(by_code, default, param)
    held = [(p, str(probe)) for p in ids if p != param]
    others = [(held, SD_STATUS_UNLISTED)] if held else []
    for name, ctx in contexts.items():
        asks = checks if name == BASE else [*others, *checks]
        want = [library.group(status, dict(params)) for params, status in asks]
        got = _sd_parse_with(product_code, handler, ctx, asks)
        bad = next((a for a, g, w in zip(asks, got, want, strict=True) if g != w), None)
        if bad is None:
            continue
        if name != BASE:
            raise GeneratorError(
                f"{product_code}: the SDINFO_EX status parameter differs between contexts "
                f"({name}: asked {bad})"
            )
        raise GeneratorError(
            f"{product_code}: the SDINFO_EX parse reads the status parameter {param} "
            f"otherwise than as a status in place of the answer's (asked {bad})"
        )
    return param


def _sd_find_param(
    product_code: str,
    handler: Path,
    context: codec.Context,
    ids: Sequence[int],
    *,
    probe: int,
    default: int,
) -> int | None:
    """The one of ``ids`` that, listed at ``probe``, changes the parse's group of an
    answer carrying :data:`SD_STATUS_UNLISTED` in ``context``, found by halving; None
    when none does. Raises GeneratorError when several do."""
    found: list[int] = []
    pending = [list(ids)] if ids else []
    while pending:
        asks = [([(p, str(probe)) for p in group], SD_STATUS_UNLISTED) for group in pending]
        split: list[list[int]] = []
        for group, got in zip(
            pending, _sd_parse_with(product_code, handler, context, asks), strict=True
        ):
            if got == default:
                continue
            if len(group) == 1:
                found.extend(group)
            else:
                split += [group[: len(group) // 2], group[len(group) // 2 :]]
        pending = split
    if len(found) > 1:
        raise GeneratorError(f"{product_code}: the SDINFO_EX parse reads parameters {found}")
    return found[0] if found else None


def _json_structure(raw: Any) -> bool:
    """``raw`` is a JSON object or array, or the JSON text of one."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return False
    return isinstance(raw, dict | list)


def _probe_param(entry: Mapping[str, Any], located: Located | None) -> Located | None:
    """Where to hold a setting's value: its read parameter (the first context that reads
    one), else the one the handler fills it from. A read parameter other than the located
    one is also named as a command id."""
    for form in (entry, *(item["entry"] for item in entry.get("contexts") or ())):
        read = form.get("read")
        if isinstance(read, dict) and isinstance(read.get("param"), int):
            if located is not None and located.param == read["param"]:
                return located
            return Located(read["param"], as_command=True)
    return located


def _add_counts(counts: dict[str, int], more: Mapping[str, int]) -> None:
    for key, n in more.items():
        _count(counts, key, n)


def structured_values(
    product_code: str,
    handler: Path,
    context: codec.Context,
    settings: dict[str, Any],
    located: Mapping[str, Located],
    *,
    counts: dict[str, int],
) -> None:
    """Mark ``structured`` on each open-kind setting whose value is a JSON structure: held
    at a JSON object, its parameter reads back as that object parsed, or held at the
    object's base64, as the object or its JSON text (the handler decodes structured
    data); or, unreadable, its default is the JSON text of an object or array."""
    probe = json.loads(OPEN_JSON_PROBE)
    held = (OPEN_JSON_PROBE, _b64_json(probe))
    asks: list[tuple[str, str, Located]] = []
    for ident, entry in sorted(settings.items()):
        if entry.get("kind") not in codec.SINGLE_PROBE_KINDS:
            continue
        where = _probe_param(entry, located.get(ident))
        if where is None:
            if _json_structure(entry.get("default")):
                entry["structured"] = True
                _count(counts, "structured:default")
            continue
        asks += [(ident, raw, where) for raw in held]
    requests = [where.request(product_code, context, ident, raw) for ident, raw, where in asks]
    replies = run_driver(product_code, handler, requests) if requests else []
    found: set[str] = set()
    for (ident, raw, _), reply in zip(asks, replies, strict=True):
        got = _property_values(reply).get(ident, codec.MISSING)
        if isinstance(got, str) and raw != OPEN_JSON_PROBE:
            with contextlib.suppress(ValueError):
                got = json.loads(got)  # the handler decoded the base64 to JSON text
        if isinstance(got, dict | list) and got == probe:
            found.add(ident)
    for ident in sorted(found):
        settings[ident]["structured"] = True
        _count(counts, "structured:handler")


def p2p(reply: Any) -> dict[str, Any] | None:
    """The recipe of a handler reply: ``data.p2p`` when it is a dict without ``error``."""
    data = reply.get("data") if isinstance(reply, dict) else None
    recipe = data.get("p2p") if isinstance(data, dict) else None
    if isinstance(recipe, dict) and recipe and not recipe.get("error"):
        return recipe
    return None


def _is_error(reply: Any) -> bool:
    """A reply whose handler threw or whose recipe carries ``error``."""
    if not isinstance(reply, dict):
        return False
    data = reply.get("data")
    recipe = data.get("p2p") if isinstance(data, dict) else None
    return "error" in reply or (isinstance(recipe, dict) and bool(recipe.get("error")))


def td_fields(
    product_code: str, prop: dict[str, Any], kind: str, values: list[Any]
) -> dict[str, Any]:
    """``min``/``max``/``step``/``unit``/``default``/``values`` from the TD where present.

    The unit is normalised (``gen_models_join.normalise_unit``); raises GeneratorError for
    a unit without a mapping.
    """
    specs = codec.specs_of(prop)
    out: dict[str, Any] = {}
    if kind == "range":
        lo, hi, step = codec.range_spec(prop)
        out.update(min=codec.intify(lo), max=codec.intify(hi), step=codec.intify(step))
    if kind == "enum":
        out["values"] = values
    unit = specs.get("unit")
    if isinstance(unit, str) and unit.strip():
        normal = joiner.normalise_unit(
            product_code, prop["identifier"], unit.strip(), out.get("min"), out.get("max")
        )
        if normal is not None:
            out["unit"] = normal
        meaning = UNIT_MEANINGS.get(unit.strip())
        if meaning is not None:
            out["meaning"] = meaning.value
    default = codec.td_default(prop, kind)
    if default is not None:
        out["default"] = default
    return out


def _param_dump(recipe: dict[str, Any] | None) -> list[dict[str, Any]]:
    """``[{param_type, param_value}]`` from a recipe's ``update`` and ``extUpdates`` items
    (``update`` first)."""
    if recipe is None:
        return []
    dump = []
    update = recipe.get("update")
    if (
        isinstance(update, dict)
        and isinstance(update.get("cmd"), int)
        and update.get("paramValue") is not None
    ):
        dump.append({"param_type": update["cmd"], "param_value": update["paramValue"]})
    ext = recipe.get("extUpdates")
    dump.extend(
        {"param_type": item["cmd"], "param_value": item.get("paramValue")}
        for item in (ext if isinstance(ext, list) else [])
        if isinstance(item, dict) and isinstance(item.get("cmd"), int)
    )
    return dump


def stores_failed_conversion(rows: list[tuple[Any, dict[str, Any] | None]]) -> bool:
    """Whether a swept write stores a value its handler could not convert (``NaN``) in
    any parameter: the probe is no value the app writes, or the write not this setting's
    alone."""
    return any(
        isinstance(item["param_value"], str) and item["param_value"] in codec.FAILED_CONVERSIONS
        for _, recipe in rows
        for item in _param_dump(recipe)
    )


def write_read(
    kind: str, raw: list[tuple[Any, dict[str, Any] | None]], samples: list[Any]
) -> tuple[dict[str, Any] | None, str | None, bool]:
    """``(read, note, inverse)`` of a written setting from the round trip of its swept
    writes ``raw`` (``samples``: :func:`read_samples`); ``inverse`` when the read is the
    inverse of an enum's write, taken only when no write stores a failed conversion."""
    read, note = codec.infer_read(kind, samples)
    if read is None and not stores_failed_conversion(raw):
        inverse = codec.inverse_read(kind, samples)
        if inverse is not None:
            return inverse, None, True
    return read, note, False


@dataclass
class Sweep:
    """One identifier's setProperty replies in one context, on both of its channels:
    slotted ``(value, recipe or None)`` rows, plus the unslotted ``raw`` rows of the
    main channel whose ``update`` items the read inference feeds back, and an open
    number's slotted replies to the type probes (``typed``, main channel only)."""

    main: list[tuple[Any, Any]] = field(default_factory=list)
    alt: list[tuple[Any, Any]] = field(default_factory=list)
    raw: list[tuple[Any, dict[str, Any] | None]] = field(default_factory=list)
    rejected: bool = False
    typed: list[tuple[Any, Any]] = field(default_factory=list)


def td_writable(prop: Mapping[str, Any]) -> bool:
    """The thing description declares ``prop`` writable (``W`` in its ``access_mode``).

    The handler's write is probed for every property, as the app writes a property
    without checking its ``access_mode``. The declaration decides the role rule "app
    control", the note of a write that is not proven, and whether a proven write must
    read back: an undeclared one is written only when its write gives a read
    (:func:`write_read`), getProperty returning the written value or, for an enum whose
    write stores each value as its own parameter value, the inverse of the write.
    """
    return "W" in (prop.get("access_mode") or "")


def contexts_of(product_code: str) -> dict[str, codec.Context]:
    """Every context a model is generated for, by name: the base (``SINGLE``, a parent of
    no station kind), ``standalone`` and each station connect type."""
    out = {BASE: codec.CHILD, STANDALONE: codec.standalone_context(product_code)}
    for name in sorted(codec.CONNECT_PARENTS):
        out[name] = codec.child_context(name)
    return out


def sweep(
    product_code: str,
    handler: Path,
    props: list[dict[str, Any]],
    contexts: dict[str, codec.Context],
    wire: codec.WireValues | None = None,
) -> dict[str, dict[str, Sweep]]:
    """setProperty over every property's domain in every context, on both of each
    context's channels, and over each open number's type probes
    (:data:`codec.TYPE_PROBES`) on the main channel: ``{context: {identifier: Sweep}}``.

    Each context and channel, and each context's type probes, is its own driver job (a
    fresh handler sandbox): a handler can keep state between requests, so one sweep must
    not see another's.
    """
    out: dict[str, dict[str, Sweep]] = {name: {} for name in contexts}
    numbers = [p["identifier"] for p in props if codec.kind_of(p) == "other"]
    for name, ctx in contexts.items():
        for alt, c in ((False, ctx), (True, codec.alt_channel(ctx))):
            requests: list[dict[str, Any]] = []
            index: list[tuple[str, Any]] = []
            for prop in props:
                _, values = codec.domain(prop)
                for v in values:
                    requests.append(
                        {
                            "kind": "set",
                            "identifier": prop["identifier"],
                            "payload": v,
                            "device": c.device(product_code),
                        }
                    )
                    index.append((prop["identifier"], v))
            replies = run_driver(product_code, handler, requests, wire) if requests else []
            for (ident, v), reply in zip(index, replies, strict=True):
                recipe = p2p(reply)
                row = out[name].setdefault(ident, Sweep())
                if recipe is None and _is_error(reply):
                    row.rejected = True
                slotted = codec.slot(recipe, ctx) if recipe is not None else None
                (row.alt if alt else row.main).append((v, slotted))
                if not alt:
                    row.raw.append((v, recipe))
        device = ctx.device(product_code)
        typed = [
            {"kind": "set", "identifier": ident, "payload": text, "device": device}
            for ident in numbers
            for text in codec.TYPE_PROBES
        ]
        replies = run_driver(product_code, handler, typed, wire) if typed else []
        for request, reply in zip(typed, replies, strict=True):
            recipe = p2p(reply)
            slotted = codec.slot(recipe, ctx) if recipe is not None else None
            out[name][request["identifier"]].typed.append((request["payload"], slotted))
    return out


type ObjectRows = dict[str, tuple[list[tuple[Any, Any]], list[tuple[Any, Any]]]]
"""``{identifier: (main channel rows, second channel rows)}`` of one context: each row the
app's object and the handler's slotted recipe for it (None: no recipe)."""
TD_DOMAIN_FIELDS = ("values", "min", "max", "step", "unit", "meaning", "default", "labels")
"""Fields of a thing-description domain that a value of another shape (an object, a flags
mask) does not carry."""


def object_sweep(
    product_code: str,
    handler: Path,
    props: list[dict[str, Any]],
    contexts: dict[str, codec.Context],
    objects: Mapping[str, Sequence[dict[str, Any]]],
) -> dict[str, ObjectRows]:
    """setProperty of each property ``objects`` names, whatever its ``access_mode``, with
    each object the app writes for it, in every context on both of its channels (one driver
    job each); :func:`apply_object_writes` decides which writes a file keeps."""
    out: dict[str, ObjectRows] = {name: {} for name in contexts}
    idents = [p["identifier"] for p in props if p["identifier"] in objects]
    if not idents:
        return out
    for name, ctx in contexts.items():
        for alt, c in ((False, ctx), (True, codec.alt_channel(ctx))):
            index = [(ident, payload) for ident in idents for payload in objects[ident]]
            requests = [
                {
                    "kind": "set",
                    "identifier": ident,
                    "payload": payload,
                    "device": c.device(product_code),
                }
                for ident, payload in index
            ]
            replies = run_driver(product_code, handler, requests)
            for (ident, payload), reply in zip(index, replies, strict=True):
                recipe = p2p(reply)
                slotted = codec.slot(recipe, ctx, texts=True) if recipe is not None else None
                rows = out[name].setdefault(ident, ([], []))
                rows[1 if alt else 0].append((payload, slotted))
    return out


def object_reads(
    product_code: str, handler: Path, context: codec.Context, fits: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """The read of each object write that stores its value's base64 in a parameter, when
    the handler fills the property from that parameter: held at each written value's
    stored form, getProperty answers for the property every time, with as many distinct
    answers as there are distinct values. A write that stores no base64 of its value gets
    the read :func:`member_reads` finds."""
    asks: list[tuple[str, int]] = []
    requests: list[dict[str, Any]] = []
    found: dict[str, dict[str, Any]] = {}
    for ident, fit in sorted(fits.items()):
        if fit.write is not None and fit.stored is None:
            if (read := member_reads(product_code, handler, context, ident, fit)) is not None:
                found[ident] = read
            continue
        if fit.write is None:
            continue
        where = Located(fit.stored, as_command=True)
        for value in fit.values:
            stored = object_slot("$v:b64json", value)
            requests.append(where.request(product_code, context, ident, stored))
            asks.append((ident, fit.stored))
    replies = run_driver(product_code, handler, requests) if requests else []
    answers: dict[str, list[Any]] = {}
    for (ident, _), reply in zip(asks, replies, strict=True):
        answers.setdefault(ident, []).append(_property_values(reply).get(ident, codec.MISSING))
    out: dict[str, dict[str, Any]] = dict(found)
    for ident, got in answers.items():
        fit = fits[ident]
        if any(a is codec.MISSING or a is None for a in got):
            continue
        if len({_canon(a) for a in got}) != len({_canon(v) for v in fit.values}):
            continue
        out[ident] = {"param": fit.stored, "map": None}
    return out


MEMBER_PROBE = "member-probe"
"""A member text no write stores: held in a stored JSON object to find a member it fills."""


def _stored_params(
    write: Mapping[str, Any], value: Any, context: codec.Context
) -> dict[int, str] | None:
    """``{parameter: text}`` a write stores for ``value`` (its ``update``/``extUpdates``),
    or None when one is no text."""
    recipe = codec.render(
        {"access": "rw", "write": write},
        value,
        channel=context.channel,
        device_sn=context.device_sn,
        station_sn=context.station_sn,
    )
    out: dict[int, str] = {}
    for item in codec.stored_items(recipe):
        text = item.get("paramValue")
        if not isinstance(text, str):
            return None
        out[item["cmd"]] = text
    return out


def member_reads(
    product_code: str, handler: Path, context: codec.Context, ident: str, fit: Any
) -> dict[str, Any] | None:
    """The read of an object write that stores its members in several parameters, when the
    handler fills the property from them: held at each written value's stored parameters,
    getProperty answers an object whose every member is one parameter read as a switch or
    one member of a parameter's JSON object (found by holding a probe text there), and
    the library's member read (``read.members``) of the held parameters gives that answer
    every time, distinct per value. Else None."""
    held = [_stored_params(fit.write, v, context) for v in fit.values]
    if not held or any(h is None or not h for h in held):
        return None
    blocks = cast(list[dict[int, str]], held)
    asks = [_held_request(product_code, context, [ident], b, as_command=True) for b in blocks]
    answers = [_member_answer(r, ident) for r in run_driver(product_code, handler, asks)]
    if any(a is None for a in answers) or len({_canon(a) for a in answers}) != len(answers):
        return None
    first = cast(dict[str, Any], answers[0])
    members: dict[str, dict[str, Any]] = {}
    for name in first:
        spec = _member_source(name, blocks, cast(list[dict[str, Any]], answers))
        if spec is None:
            spec = _probed_member(
                product_code, handler, context, ident=ident, name=name, block=blocks[0]
            )
        if spec is None:
            return None
        members[name] = spec
    specs = {n: (m["param"], m.get("member")) for n, m in members.items()}
    for block, answer in zip(blocks, answers, strict=True):
        if _canon(members_read(specs, block)) != _canon(answer):
            return None
    return {"param": next(iter(blocks[0])), "map": None, "members": members}


def _member_answer(reply: Any, ident: str) -> dict[str, Any] | None:
    """A getProperty answer as an object (a JSON object's text decoded), else None."""
    got = _property_values(reply).get(ident)
    if isinstance(got, str):
        got = decode_object(got)
    return got if isinstance(got, dict) and got else None


def _member_source(
    name: str, blocks: Sequence[Mapping[int, str]], answers: Sequence[Mapping[str, Any]]
) -> dict[str, Any] | None:
    """Where every answer's member ``name`` comes from in the held parameters: one read
    as a switch, or the same-named member of one holding a JSON object."""
    got = [_canon(a.get(name)) for a in answers]
    for param in blocks[0]:
        texts = [b.get(param) for b in blocks]
        if any(t is None for t in texts):
            continue
        objects = [decode_object(cast(str, t)) for t in texts]
        if all(o is not None and name in o for o in objects):
            found = [_canon(cast(dict[str, Any], o)[name]) for o in objects]
            spec: dict[str, Any] = {"param": param, "member": name}
        elif all(o is None for o in objects) and len(set(got)) > 1:
            found = [
                _canon(members_read({name: (param, None)}, {param: cast(str, t)})[name])
                for t in texts
            ]
            spec = {"param": param, "as": "flag"}
        else:
            continue
        if found == got:
            return spec
    return None


def _probed_member(
    product_code: str,
    handler: Path,
    context: codec.Context,
    *,
    ident: str,
    name: str,
    block: Mapping[int, str],
) -> dict[str, Any] | None:
    """The stored JSON object whose member ``name`` the answer shows when it is held there
    (the write never stores it)."""
    for param, text in block.items():
        stored = decode_object(text)
        if stored is None or name in stored or not text.startswith("{"):
            continue
        probe = {**block, param: json.dumps({**stored, name: MEMBER_PROBE}, separators=(",", ":"))}
        (reply,) = run_driver(
            product_code,
            handler,
            [_held_request(product_code, context, [ident], probe, as_command=True)],
        )
        answer = _member_answer(reply, ident)
        if answer is not None and answer.get(name) == MEMBER_PROBE:
            return {"param": param, "member": name}
    return None


def apply_object_writes(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    objects: ObjectRows,
    *,
    context: codec.Context,
    counts: dict[str, int],
    undeclared: Collection[str],
) -> None:
    """Turn each setting whose app objects the handler writes in a form an object write
    reproduces (``gen_models_codec.infer_object_write``) into an ``object`` setting with
    that write and its read (:func:`object_reads`); a setting whose app objects get recipes
    no object form reproduces keeps its entry, its note naming why. A property the thing
    description does not declare writable (``undeclared``, :func:`td_writable`) is turned
    only when its write gives a read, and otherwise keeps its entry without a note."""
    alt = codec.alt_channel(context)
    fits = {
        ident: codec.infer_object_write(main, second, context.channel, alt.channel)
        for ident, (main, second) in sorted(objects.items())
        if ident in settings
    }
    reads = object_reads(product_code, handler, context, fits)
    for ident, fit in fits.items():
        entry = settings[ident]
        read = reads.get(ident)
        if ident in undeclared and read is None:
            continue
        if fit.write is None:
            if fit.note is not None:
                entry["note"] = f"{entry['note']}; {fit.note}" if entry.get("note") else fit.note
                _count(counts, f"object:{fit.note}")
            continue
        for key in (*TD_DOMAIN_FIELDS, "write_table", "note"):
            entry.pop(key, None)
        entry.update(kind="object", access="rw", write=fit.write, read=read, structured=True)
        _count(counts, "object:write")
        _count(counts, "object:read" if read is not None else "object:no read")


def read_samples(
    product_code: str,
    handler: Path,
    raw: dict[str, list[tuple[Any, dict[str, Any] | None]]],
    context: codec.Context,
    counts: dict[str, int],
    *,
    background: Mapping[int, Any] | None = None,
    wire: codec.WireValues | None = None,
) -> dict[str, list[Any]]:
    """getProperty over each recipe's own parameter dump in ``context``, per identifier,
    the way the app asks: ``commandId`` = every parameter of the device.

    ``background`` (param -> value) are further parameters the device is given ahead of
    the dump, as a real block reports them beside the written ones. An identifier gets
    samples only when at least one written value yields a dump; a value without one is
    a sample with no ``cmd`` (its round trip fails). When the dump holds several
    parameters and the decode depends on exactly one of them on every sample (leaving it
    out loses the value, leaving out any other does not), that parameter is the sample's
    ``cmd`` instead of the ``update`` one.
    """
    requests: list[dict[str, Any]] = []
    index: list[tuple[str, int, int | None]] = []

    def ask(dump: list[dict[str, Any]], ident: str, i: int, left_out: int | None) -> None:
        own = {p["param_type"] for p in dump}
        rest = [
            {"param_type": k, "param_value": v}
            for k, v in (background or {}).items()
            if k not in own
        ]
        device = context.device(product_code)
        device["params"] = rest + dump
        requests.append(
            {"kind": "get", "cmds": [p["param_type"] for p in device["params"]], "device": device}
        )
        index.append((ident, i, left_out))

    for ident, rows in raw.items():
        for i, (_, recipe) in enumerate(rows):
            dump = _param_dump(recipe)
            if not dump:
                continue
            ask(dump, ident, i, None)
            if len({p["param_type"] for p in dump}) > 1:
                for p in dump:
                    ask([q for q in dump if q is not p], ident, i, p["param_type"])
    replies = run_driver(product_code, handler, requests, wire) if requests else []
    decoded: dict[tuple[str, int, int | None], Any] = {}
    for key, reply in zip(index, replies, strict=True):
        values = p2p(reply) or {}
        decoded[key] = values.get(key[0], codec.MISSING)
    out: dict[str, list[Any]] = {}
    for ident, rows in raw.items():
        if not any((ident, i, None) in decoded for i in range(len(rows))):
            continue
        samples = []
        needed: set[tuple[int, ...]] = set()
        for i, (v, recipe) in enumerate(rows):
            got = decoded.get((ident, i, None), codec.MISSING)
            if (ident, i, None) in decoded:
                first = _param_dump(recipe)[0]
                samples.append(codec.ReadSample(v, first["param_type"], first["param_value"], got))
                needed.add(
                    tuple(
                        p
                        for (d_ident, d_i, p), d in decoded.items()
                        if d_ident == ident and d_i == i and p is not None
                        if not codec.decodes_to(d, v)
                    )
                )
            else:
                samples.append(codec.ReadSample(v, None, None, codec.MISSING))
        if len(needed) == 1 and len(only := next(iter(needed))) == 1:
            (param,) = only
            dumps = [{p["param_type"]: p["param_value"] for p in _param_dump(r)} for _, r in rows]
            if any(s.cmd != param for s in samples) and all(param in d for d in dumps):
                samples = [
                    codec.ReadSample(s.value, param, d[param], s.decoded)
                    for s, d in zip(samples, dumps, strict=True)
                ]
                _count(counts, "read:param from the decode")
        out[ident] = samples
    return out


def param_slots(
    product_code: str,
    handler: Path,
    context: codec.Context,
    rows: dict[str, Sweep],
    seen: Mapping[int, list[str]],
    *,
    counts: dict[str, int],
    wire: codec.WireValues | None = None,
) -> dict[str, dict[LeafPath, str]]:
    """``{identifier: {path: "$param:<id>:<form>"}}`` for each write leaf the handler takes
    from a device parameter: null in every swept recipe (the parameter is absent there)
    and, with the parameter set to two of the values the model's writes give it, that
    value each time (as int or as the string).

    ``seen`` holds those values per parameter. A leaf two parameters explain stays null.
    """
    asks: list[tuple[str, int, str]] = []
    requests: list[dict[str, Any]] = []
    null_paths: dict[str, set[LeafPath]] = {}
    for ident, row in rows.items():
        recipes = [r for _, r in row.main if r is not None]
        if not recipes:
            continue
        nulls = set.intersection(*({p for p, x in codec.leaves(r) if x is None} for r in recipes))
        null_paths[ident] = nulls
        for param, values in seen.items():
            for raw in values[:2] if len(values) > 1 and nulls else ():
                device = context.device(product_code)
                device["params"] = [{"param_type": param, "param_value": raw}]
                requests.append(
                    {
                        "kind": "set",
                        "identifier": ident,
                        "payload": row.main[0][0],
                        "device": device,
                    }
                )
                asks.append((ident, param, raw))
    replies = run_driver(product_code, handler, requests, wire) if requests else []
    leaves: dict[tuple[str, int], list[tuple[str, dict[LeafPath, Any]]]] = {}
    for (ident, param, raw), reply in zip(asks, replies, strict=True):
        recipe = p2p(reply)
        flat = dict(codec.leaves(codec.slot(recipe, context))) if recipe is not None else {}
        leaves.setdefault((ident, param), []).append((raw, flat))
    out: dict[str, dict[LeafPath, str]] = {}
    for ident, nulls in null_paths.items():
        for path in sorted(nulls, key=str):
            found = set()
            for param in seen:
                probes = leaves.get((ident, param), [])
                for form in ("int", "str"):
                    got = [flat.get(path, codec.MISSING) for _, flat in probes]
                    want = [codec.param_leaf(raw, form) for raw, _ in probes]
                    if len(probes) == 2 and want[0] != want[1] and got == want:
                        found.add(codec.param_slot(param, form))
                        break
            if len(found) == 1:
                out.setdefault(ident, {})[path] = found.pop()
                _count(counts, "write:param slot")
    return out


def _set_leaf(recipe: dict[str, Any], path: LeafPath, value: Any) -> None:
    node: Any = recipe
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def view_reads(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    context: codec.Context,
    counts: dict[str, int],
    *,
    inverted: set[str],
) -> None:
    """Add a per-view read to each enum whose write sends a ``quality`` per value and
    whose handler decodes a per-view report of that quality parameter. A read by the
    inverse of the write (``inverted``) gives way to it.

    A multi-view camera reports such a parameter as base64 JSON
    ``{"mode_0": {"quality": q}, "mode_1": {…}, "cur_mode": m}``. Each value's quality is
    put in one view and another value's in the other, and getProperty is asked three
    times; the view rule whose picks match every answer is kept (``read.view``): ``by``
    the view-mode parameter (12 selects ``mode_1``), ``cur_mode`` (0 or 1 selects
    ``mode_0``) or null (always ``mode_0``). Read-map keys that are such reports are
    dropped, since the view read decodes them.
    """
    view, dual = VIEW_MODE_PARAM, DUAL_VIEW
    # Per rule and probe, whose quality getProperty returns: 0 the value's, 1 the other's.
    rules: dict[str | int | None, tuple[int, int, int]] = {
        view: (0, 0, 1),
        "cur_mode": (0, 1, 0),
        None: (0, 1, 1),
    }
    asks: list[tuple[str, int, Any, Any]] = []
    requests: list[dict[str, Any]] = []
    for ident, entry in settings.items():
        write, read = entry.get("write"), entry.get("read")
        params = write.get("params") if isinstance(write, dict) else None
        quality = params.get("quality") if isinstance(params, dict) else None
        if entry["kind"] != "enum" or not isinstance(quality, dict) or "$map" not in quality:
            continue
        param = (write.get("update") or {}).get("cmd") or write.get("subCmd")
        if not isinstance(param, int) or (read is not None and read["param"] != param):
            continue
        wire = {k: q for k, q in quality["$map"].items() if isinstance(q, int)}
        values = [v for v in entry.get("values") or () if codec.value_key(v) in wire]
        if len(values) < 2 or len(set(wire.values())) != len(wire):
            continue
        for i, v in enumerate(values):
            q, other = wire[codec.value_key(v)], values[(i + 1) % len(values)]
            q2 = wire[codec.value_key(other)]
            probes = ((q, q2, 0, 0), (q2, q, 0, dual), (q2, q, 2, 0))
            for n, (m0, m1, cur, mode) in enumerate(probes):
                report = {"mode_0": {"quality": m0}, "mode_1": {"quality": m1}, "cur_mode": cur}
                device = context.device(product_code)
                device["params"] = [
                    {"param_type": param, "param_value": _b64_json(report)},
                    {"param_type": view, "param_value": str(mode)},
                ]
                requests.append({"kind": "get", "cmds": [param, view], "device": device})
                asks.append((ident, n, v, other))
    replies = run_driver(product_code, handler, requests) if requests else []
    picks: dict[str, list[tuple[int, int | None]]] = {}
    for (ident, n, v, other), reply in zip(asks, replies, strict=True):
        got = (p2p(reply) or {}).get(ident, codec.MISSING)
        pick = 0 if codec.decodes_to(got, v) else 1 if codec.decodes_to(got, other) else None
        picks.setdefault(ident, []).append((n, pick))
    for ident, rows in picks.items():
        matching = [by for by, want in rules.items() if all(p == want[n] for n, p in rows)]
        if len(matching) != 1:
            continue
        entry = settings[ident]
        quality = entry["write"]["params"]["quality"]["$map"]
        values = {codec.value_key(v): v for v in entry["values"]}
        qmap = {str(q): values[k] for k, q in quality.items() if k in values}
        read = entry["read"]
        if read is None or ident in inverted:
            read = {"param": param_of(entry), "map": {}}
            inverted.discard(ident)
        if read["map"] is not None:
            read["map"] = {k: v for k, v in read["map"].items() if not _is_view_report(k)}
        read["view"] = {"by": matching[0], "map": dict(sorted(qmap.items()))}
        entry["read"] = read
        note = entry.get("note")
        if note is not None:
            parts = [p for p in note.split("; ") if p != codec.ROUND_TRIP_NOTE]
            if parts:
                entry["note"] = "; ".join(parts)
            else:
                del entry["note"]
        _count(counts, "read:per view")


OWNER_PROBE = "0" * 39 + "1"
"""The user id a setProperty message names when the generator asks which members of a
handler's write take the app's account (:func:`owner_members`)."""


def owner_members(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    *,
    props: Sequence[Mapping[str, Any]],
    routes: Any,
    screens: Mapping[str, Collection[str | None]],
    context: codec.Context,
    counts: dict[str, int],
) -> None:
    """Put the owner's id into each bare JSON-text frame write, whose body is the params as
    the handler builds them: a member the handler fills from the user id the app's message
    names becomes ``$account_id``, in the handler's member order. The other runs drive the
    handler without a user id, so such a member is missing from their templates; the other
    frame forms carry the account outside the body. A native screen's own form (``screens``,
    from ``routing.apply``) is sent as the screen builds it and is left as it is."""
    domains = {p["identifier"]: codec.domain(p)[1] for p in props}
    asks: list[list[dict[str, Any]]] = []
    requests: list[dict[str, Any]] = []
    for ident, entry in settings.items():
        templates = _json_text_templates(entry, routes, screens.get(ident, ()))
        if not templates or not domains.get(ident):
            continue
        base = {
            "kind": "set",
            "identifier": ident,
            "payload": domains[ident][0],
            "device": context.device(product_code),
        }
        requests += [base, {**base, "user_id": OWNER_PROBE}]
        asks.append(templates)
    replies = run_driver(product_code, handler, requests) if requests else []
    for n, templates in enumerate(asks):
        without, with_owner = (p2p(r) or {} for r in replies[2 * n : 2 * n + 2])
        plain, named = without.get("params"), with_owner.get("params")
        if not isinstance(plain, dict) or not isinstance(named, dict):
            continue
        owner = [k for k, v in named.items() if v == OWNER_PROBE and plain.get(k) != OWNER_PROBE]
        if not owner:
            continue
        for template in templates:
            params = template["params"]
            order = [*named, *(k for k in params if k not in named)]
            template["params"] = {
                k: ACCOUNT_SLOT if k in owner else params[k]
                for k in order
                if k in owner or k in params
            }
        _count(counts, "routing:owner id")


def _json_text_templates(
    entry: Mapping[str, Any], routes: Any, screen: Collection[str | None]
) -> list[dict[str, Any]]:
    """The write templates of a writable setting that go out as a bare JSON-text frame
    with an object body, except those a native screen sends (``screen``: their
    ``write_table`` keys, None for the ``write``)."""
    if entry.get("access") != "rw":
        return []
    found = [(None, entry.get("write")), *(entry.get("write_table") or {}).items()]
    return [
        t
        for key, t in found
        if key not in screen
        and isinstance(t, dict)
        and "subCmd" not in t
        and isinstance(t.get("params"), dict)
        and isinstance(t.get("cmd"), int)
        and t["cmd"] not in routing.WRAPPERS
        and routes.forms.get(t["cmd"]) == "json_text"
    ]


SPAN_START = "startTime"
"""The member a device stores beside a timed value's end epoch: its start epoch (verified
on hardware for 1271 on a HomeBase 3)."""
SPAN_EPOCHS = (codec.FIXED_CLOCK_MS // 1000, codec.FIXED_CLOCK_MS // 1000 + 86_399)
"""Start epochs a stored span is probed at: a read that follows the span reads the same."""


def span_reads(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    context: codec.Context,
    counts: dict[str, int],
) -> None:
    """Add a span read (``read.span``) to each enum whose write stores a one-member JSON
    object ``{member: n}`` per value (base64) and whose handler reads a stored
    ``{member: start + n, startTime: start}`` as that value at every probed start: the
    device stores a timed value as its end and start epochs, and the app shows the
    duration's choice."""
    asks: list[tuple[str, Any, int]] = []
    requests: list[dict[str, Any]] = []
    found: dict[str, tuple[str, dict[str, Any]]] = {}
    for ident, entry in settings.items():
        spans = _stored_spans(entry)
        if spans is None:
            continue
        member, by_value = spans
        found[ident] = (member, by_value)
        param = entry["read"]["param"]
        for value, duration in by_value.items():
            for start in SPAN_EPOCHS:
                device = context.device(product_code)
                stored = {member: start + duration, SPAN_START: start}
                device["params"] = [{"param_type": param, "param_value": _b64_json(stored)}]
                requests.append({"kind": "get", "cmds": [param], "device": device})
                asks.append((ident, value, duration))
    replies = run_driver(product_code, handler, requests) if requests else []
    matched: dict[str, bool] = {}
    for (ident, value, _), reply in zip(asks, replies, strict=True):
        got = (p2p(reply) or {}).get(ident, codec.MISSING)
        matched[ident] = matched.get(ident, True) and codec.decodes_to(got, value)
    for ident, ok in matched.items():
        if not ok:
            continue
        member, by_value = found[ident]
        spans = {str(d): v for v, d in by_value.items()}
        if len(spans) != len(by_value):
            continue  # two values share a duration: a span cannot tell them apart
        settings[ident]["read"]["span"] = {
            "member": member,
            "start": SPAN_START,
            "map": dict(sorted(spans.items(), key=lambda kv: int(kv[0]))),
        }
        _count(counts, "read:span")


def _stored_spans(entry: Mapping[str, Any]) -> tuple[str, dict[Any, int]] | None:
    """``(member, value -> n)`` when an enum's write stores ``{member: n}`` (base64 JSON,
    one int member, the same member for each such value; at least two values) in the
    parameter it reads. A value stored in another form is no span and is left out."""
    write, read = entry.get("write"), entry.get("read")
    if entry.get("kind") != "enum" or not isinstance(write, dict) or not isinstance(read, dict):
        return None
    update = write.get("update")
    stored = update.get("paramValue") if isinstance(update, dict) else None
    if (
        not isinstance(stored, dict)
        or set(stored) != {"$map"}
        or read.get("param") != update.get("cmd")
    ):
        return None
    values = {codec.value_key(v): v for v in entry.get("values") or ()}
    members: set[str] = set()
    out: dict[Any, int] = {}
    for key, text in stored["$map"].items():
        found = decode_object(text) if isinstance(text, str) and not text.startswith("{") else None
        if key not in values or found is None or len(found) != 1:
            continue
        ((member, n),) = found.items()
        if isinstance(n, bool) or not isinstance(n, int):
            continue
        members.add(member)
        out[values[key]] = n
    if len(members) != 1 or len(out) < 2:
        return None
    return members.pop(), out


def param_of(entry: Mapping[str, Any]) -> int:
    write = entry["write"]
    cmd = (write.get("update") or {}).get("cmd") or write.get("subCmd")
    return int(cmd)


def _b64_json(obj: Any) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def _is_view_report(raw: str) -> bool:
    """``raw`` is base64 of a JSON object with a ``mode_0`` key."""
    try:
        obj = json.loads(base64.b64decode(raw, validate=True))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(obj, dict) and "mode_0" in obj


ABSENT_PRIOR = frozenset({"{}", _b64_json({})})
"""An update value the handler builds by changing a parameter the device does not hold:
the encoding of an empty JSON object."""


def _absent_prior(item: Mapping[str, Any]) -> bool:
    value = item.get("paramValue")
    return isinstance(value, str) and value in ABSENT_PRIOR


def drop_absent_prior_updates(settings: dict[str, Any], counts: dict[str, int]) -> None:
    """Leave out each ``update`` / ``extUpdates`` item whose value is :data:`ABSENT_PRIOR`.

    Such a value is the handler's read-modify-write of a parameter that was absent in the
    sweep; written to the local cache it would replace the device's real value with an
    empty object. The next parameter dump carries the new value.
    """
    for entry in settings.values():
        templates = [entry.get("write"), *(entry.get("write_table") or {}).values()]
        for template in templates:
            if not isinstance(template, dict):
                continue
            update = template.get("update")
            if isinstance(update, dict) and _absent_prior(update):
                del template["update"]
                _count(counts, "write:absent-prior update dropped")
            ext = template.get("extUpdates")
            if isinstance(ext, list):
                kept = [i for i in ext if not (isinstance(i, dict) and _absent_prior(i))]
                if len(kept) != len(ext):
                    _count(counts, "write:absent-prior update dropped", len(ext) - len(kept))
                    if kept:
                        template["extUpdates"] = kept
                    else:
                        del template["extUpdates"]


def empty_value_reads(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    context: codec.Context,
    counts: dict[str, int],
    *,
    wire: codec.WireValues | None = None,
    skip: frozenset[str] = frozenset(),
) -> None:
    """Add the empty parameter value to the read map of each readable enum or bool
    whose handler decodes ``""`` to one of its values (a dump can report the parameter
    empty). ``skip``: settings read by the inverse of their write, not by the handler."""
    asks: list[tuple[str, list[Any]]] = []
    requests: list[dict[str, Any]] = []
    for ident, entry in settings.items():
        read = entry.get("read")
        if not isinstance(read, dict) or entry.get("bit") is not None or ident in skip:
            continue
        if entry["kind"] == "bool":
            values: list[Any] = [False, True]
        elif entry["kind"] == "enum":
            values = list(entry.get("values") or ())
        else:
            continue
        rmap = read.get("map")
        if rmap is not None and "" in rmap:
            continue
        device = context.device(product_code)
        device["params"] = [{"param_type": read["param"], "param_value": ""}]
        requests.append({"kind": "get", "cmds": [read["param"]], "device": device})
        asks.append((ident, values))
    replies = run_driver(product_code, handler, requests, wire) if requests else []
    for (ident, values), reply in zip(asks, replies, strict=True):
        got = (p2p(reply) or {}).get(ident, codec.MISSING)
        hits = [v for v in values if codec.decodes_to(got, v)]
        if len(hits) != 1:
            continue
        read = settings[ident]["read"]
        rmap = read["map"]
        if rmap is None:
            rmap = {codec.str_form(v): v for v in values}
        read["map"] = {**rmap, "": hits[0]}
        _count(counts, "read:empty value")


def written_params(
    swept: Mapping[str, Mapping[str, Sweep]], written: Collection[str]
) -> tuple[dict[int, Any], dict[int, list[str]]]:
    """``(background, seen)`` of the swept writes of the identifiers ``written`` in every
    context: each parameter they set with the first value set, and per parameter the
    distinct text values set, in sweep order."""
    background: dict[int, Any] = {}
    seen: dict[int, list[str]] = {}
    for rows in swept.values():
        for ident, row in rows.items():
            if ident not in written:
                continue
            for _, recipe in row.raw:
                for p in _param_dump(recipe):
                    background.setdefault(p["param_type"], p["param_value"])
                    if isinstance(p["param_value"], str):
                        found = seen.setdefault(p["param_type"], [])
                        if p["param_value"] not in found:
                            found.append(p["param_value"])
    return background, seen


def build_context(  # noqa: C901
    product_code: str,
    handler: Path,
    td: dict[str, Any],
    props: list[dict[str, Any]],
    *,
    context: codec.Context,
    swept: dict[str, Sweep],
    app_labels: dict[str, Any] | None,
    tree: dict[str, Any] | None,
    titles: dict[str, Any] | None,
    reference: list[dict[str, Any]],
    background: Mapping[int, Any],
    seen: Mapping[int, list[str]],
    located: Mapping[str, Located],
    wire: codec.WireValues | None = None,
    objects: ObjectRows | None = None,
    routes: Any = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    """The settings of one model in one context and its counters. ``background``: every
    parameter the writes the model's file carries set in any context, with one value each;
    ``seen``: the distinct values they set per parameter (both :func:`written_params`);
    ``located``: the parameter each property is read from (:func:`locate_params`), for the
    settings without a write; ``objects``: the handler's recipes for the objects the app
    writes (:func:`object_sweep`); ``routes`` the app's write routing (``gen_models_routing``;
    None: the writes are kept as the handler makes them).

    Raises CheckError when a codec does not reproduce a swept recipe or an unaccepted
    reference row of this context.
    """
    counts: dict[str, int] = {}
    alt = codec.alt_channel(context)
    raw = {i: s.raw for i, s in swept.items()}
    reads = read_samples(product_code, handler, raw, context, counts, wire=wire)
    kinds = {p["identifier"]: codec.domain(p)[0] for p in props}
    # A handler keeps state between the requests of one driver run, so a read can fail
    # only for what the batch asked before it: ask each failed one again on its own.
    failed = {i for i, rows in reads.items() if codec.infer_read(kinds[i], rows)[0] is None}
    for ident in sorted(failed):
        alone = read_samples(product_code, handler, {ident: raw[ident]}, context, {}, wire=wire)
        if ident in alone and codec.infer_read(kinds[ident], alone[ident])[0] is not None:
            reads[ident] = alone[ident]
            _count(counts, "read:asked alone")
    # A parser can need a parameter the write does not set (a trigger, a mode): ask once
    # more with every parameter the model's writes set, for the reads that failed.
    failed = {i for i, rows in reads.items() if codec.infer_read(kinds[i], rows)[0] is None}
    if failed and background:
        retry = read_samples(
            product_code,
            handler,
            {i: rows for i, rows in raw.items() if i in failed},  # same jobs every run
            context,
            counts,
            background=background,
            wire=wire,
        )
        for ident, rows in retry.items():
            if codec.infer_read(kinds[ident], rows)[0] is not None:
                reads[ident] = rows
                _count(counts, "read:with the other parameters")
    slots = param_slots(product_code, handler, context, swept, seen, counts=counts, wire=wire)
    settings: dict[str, Any] = {}
    inverted: set[str] = set()
    for prop in props:
        ident = prop["identifier"]
        kind, values = codec.domain(prop)
        entry: dict[str, Any] = {
            "kind": kind,
            **td_fields(product_code, prop, kind, values),
            "access": "ro",
            "read": None,
        }
        settings[ident] = entry
        row = swept[ident]
        result = codec.infer_write(
            kind, row.main, row.alt, context.channel, alt.channel, typed=row.typed
        )
        read, read_note, inverse = None, None, False
        if result.access == "rw":
            read, read_note, inverse = write_read(kind, row.raw, reads.get(ident, []))
        if not td_writable(prop):
            # Not declared writable: written only when the handler's write is proven and
            # gives a read (getProperty or an enum's inverse); otherwise ro without a note,
            # read as the handler fills it.
            if read is None:
                continue
            _count(counts, "writable:undeclared")
        else:
            _count(counts, "writable")
        if result.note == "no handler write path" and row.rejected:
            result.note = "handler rejects the probed values"
        entry.update(copy.deepcopy(codec.codec_fields(result)))
        for template in [entry.get("write"), *(entry.get("write_table") or {}).values()]:
            for path, slot_name in slots.get(ident, {}).items() if template else ():
                _set_leaf(template, path, slot_name)
        if result.access == "rw":
            if inverse:
                inverted.add(ident)
                _count(counts, "read:inverse of the write")
            _count(counts, "read:codec" if read else "read:null")
            if read is not None:
                _count(counts, "read:identity" if read["map"] is None else "read:map")
            elif read_note:
                _count(counts, f"read:{read_note}")
        entry["read"] = read
        if read_note:
            entry["note"] = f"{entry['note']}; {read_note}" if "note" in entry else read_note
        if result.access == "rw":
            _count(counts, f"rw:{result.form}")
        else:
            _count(counts, f"ro:{result.note}")
    # A setting without a write reads as the handler fills it from the device's parameters.
    unwritten = {p["identifier"]: p for p in props if settings[p["identifier"]]["access"] == "ro"}
    found = located_reads(
        product_code, handler, context, unwritten, located, counts=counts, wire=wire
    )
    for ident, read in found.items():
        settings[ident]["read"] = read
    # A status the handler builds as an object of booleans, one per bit of its parameter,
    # is that parameter's mask, whatever kind the description declares.
    unread = [i for i in unwritten if i not in found]
    for ident, (read, members) in flags_reads(
        product_code, handler, context, unread, located, counts=counts
    ).items():
        as_flags_status(settings[ident], read, members)
    try:
        joined = joiner.join(product_code, settings, td, app_labels, tree, titles=titles)
    except GeneratorError as err:
        raise GeneratorError(f"{product_code}: {err}") from err
    for key, n in joined.items():
        _count(counts, key, n)
    found = sweep_mismatches(settings, swept, context)
    found += reference_mismatches(settings, reference)
    _raise_unaccepted(product_code, context, found, "codec mismatches")
    if reference:
        _count(counts, "reference_rows", len(reference))
    apply_object_writes(
        product_code,
        handler,
        settings,
        objects or {},
        context=context,
        counts=counts,
        undeclared={p["identifier"] for p in props if not td_writable(p)},
    )
    if routes is not None:
        native = tree is not None and tree.get("settings_ui") != joiner.RN_SETTINGS
        screens = routing.apply(settings, routes, native_screens=native, counts=counts)
        owner_members(
            product_code,
            handler,
            settings,
            props=props,
            routes=routes,
            screens=screens,
            context=context,
            counts=counts,
        )
    shape_controls(product_code, handler, settings, counts, context, wire=wire)
    joiner.hold_members(product_code, settings, titles, counts)
    view_reads(product_code, handler, settings, context, counts, inverted=inverted)
    span_reads(product_code, handler, settings, context, counts)
    drop_absent_prior_updates(settings, counts)
    empty_value_reads(
        product_code, handler, settings, context, counts, wire=wire, skip=frozenset(inverted)
    )
    return settings, counts


def _raise_unaccepted(
    product_code: str, context: codec.Context, found: list[tuple[str, str]], what: str
) -> None:
    failed = [(i, d) for i, d in found if (product_code, i) not in RELEASE_ACCEPTED]
    if failed:
        lines = "\n".join(f"  {product_code} {i}: {d}" for i, d in failed)
        raise CheckError(f"{product_code} ({context_name(context)}): {len(failed)} {what}\n{lines}")


def context_name(context: codec.Context) -> str:
    if context.name == codec.STANDALONE.name:
        return STANDALONE
    return next((n for n, sn in codec.CONNECT_PARENTS.items() if sn == context.station_sn), BASE)


def merge_contexts(per_context: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The base context's settings, each carrying under ``contexts`` the fields every
    other context changes: ``[{"names": [...], "entry": {field: value or null}}]``, one
    item per distinct change, ``null`` for a field the context lacks.

    Raises GeneratorError when the contexts do not list the same settings.
    """
    base = per_context[BASE]
    for name, settings in per_context.items():
        if set(settings) != set(base):
            missing = sorted(set(base) ^ set(settings))
            raise GeneratorError(f"context {name} lists other settings: {missing}")
    out: dict[str, Any] = {}
    for key, entry in base.items():
        groups: dict[str, tuple[dict[str, Any], list[str]]] = {}
        for name in sorted(n for n in per_context if n != BASE):
            other = per_context[name][key]
            diff = {
                k: other.get(k)
                for k in sorted(set(entry) | set(other))
                if _canon(entry.get(k)) != _canon(other.get(k))
            }
            if diff:
                groups.setdefault(_canon(diff), (diff, []))[1].append(name)
        merged = dict(entry)
        if groups:
            merged["contexts"] = [
                {"names": names, "entry": diff}
                for diff, names in sorted(groups.values(), key=lambda g: g[1])
            ]
        out[key] = merged
    return out


def apply_param_values(  # noqa: C901
    product_code: str,
    settings: dict[str, Any],
    props: list[dict[str, Any]],
    tree: Mapping[str, Any] | None,
    titles: Mapping[str, Any] | None,
) -> None:
    """Apply explicitly sourced app direct-parameter values after handler inference.

    The per-model ``param_values`` rule bypasses the handler's value conversion,
    but keeps the command, update and channel fields that the handler discovered.
    The read map inverts the raw values and accepts legacy public enum numbers.
    """
    rules = (titles or {}).get("param_values") or {}
    if not isinstance(rules, dict):
        raise CheckError(f"{product_code}: param_values must be an object")

    by_identifier = {prop["identifier"]: prop for prop in props}

    for ident, rule in rules.items():
        if not isinstance(rule, dict) or not isinstance(rule.get("models"), dict):
            raise CheckError(f"{product_code}: param_values {ident}: missing models")
        if product_code not in rule["models"]:
            continue
        if not isinstance(rule.get("source"), str) or not rule["source"].strip():
            raise CheckError(f"{product_code}: param_values {ident}: missing app source")
        if tree is not None and tree.get("settings_ui") == joiner.RN_SETTINGS:
            raise CheckError(f"{product_code}: param_values {ident}: RN settings")
        if ident not in by_identifier or ident not in settings:
            raise CheckError(f"{product_code}: param_values {ident}: unknown identifier")

        kind, public = codec.domain(by_identifier[ident])
        if kind != "enum":
            raise CheckError(f"{product_code}: param_values {ident}: not an enum")

        choices = rule["models"][product_code]
        expected = [codec.value_key(value) for value in public]
        if not isinstance(choices, dict) or set(choices) != set(expected):
            raise CheckError(f"{product_code}: param_values {ident}: missing/unknown choices")
        if any(type(value) is not int for value in choices.values()):
            raise CheckError(f"{product_code}: param_values {ident}: values must be integers")
        if len(set(choices.values())) != len(choices):
            raise CheckError(f"{product_code}: param_values {ident}: duplicate raw values")

        entry = settings[ident]
        if entry.get("access") != "rw" or entry.get("write_table"):
            raise CheckError(f"{product_code}: param_values {ident}: no single write recipe")

        direct = {key: choices[key] for key in expected}
        read_map = {str(direct[key]): value for key, value in zip(expected, public, strict=True)}

        for key, value in zip(expected, public, strict=True):
            if key in read_map and read_map[key] != value:
                raise CheckError(f"{product_code}: param_values {ident}: legacy read conflict")
            read_map[key] = value

        def rewrite_write(write: Any, ident: str, direct: dict[str, int]) -> int:
            if not isinstance(write, dict):
                raise CheckError(f"{product_code}: param_values {ident}: missing write")

            params = write.get("params")
            update = write.get("update")
            if not isinstance(params, dict) or not isinstance(update, dict):
                raise CheckError(f"{product_code}: param_values {ident}: missing parameter slots")

            mapped = [
                key for key, item in params.items() if isinstance(item, dict) and "$map" in item
            ]

            if len(mapped) == 1:
                leaf = mapped[0]
            elif not mapped and "value" in params:
                leaf = "value"
            else:
                raise CheckError(f"{product_code}: param_values {ident}: ambiguous value slot")

            if "paramValue" not in update or not isinstance(update.get("cmd"), int):
                raise CheckError(f"{product_code}: param_values {ident}: no update value slot")

            params[leaf] = {"$map": direct.copy()}
            update["paramValue"] = {"$map": {key: str(raw) for key, raw in direct.items()}}
            return update["cmd"]

        param = rewrite_write(entry.get("write"), ident, direct)
        entry["read"] = {"param": param, "map": read_map}

        note = entry.get("note")
        if isinstance(note, str):
            remaining = [part for part in note.split("; ") if part != codec.ROUND_TRIP_NOTE]
            if remaining:
                entry["note"] = "; ".join(remaining)
            else:
                entry.pop("note", None)

        for group in entry.get("contexts") or ():
            difference = group.get("entry")
            if not isinstance(difference, dict):
                raise CheckError(f"{product_code}: param_values {ident}: invalid context")
            if difference.get("write_table"):
                raise CheckError(f"{product_code}: param_values {ident}: context write table")
            if (
                "write" in difference
                and difference["write"] is not None
                and rewrite_write(difference["write"], ident, direct) != param
            ):
                raise CheckError(f"{product_code}: param_values {ident}: context parameter differs")
            if "read" in difference:
                difference["read"] = {"param": param, "map": read_map.copy()}
            if isinstance(difference.get("note"), str):
                parts = [
                    part for part in difference["note"].split("; ") if part != codec.ROUND_TRIP_NOTE
                ]
                if parts:
                    difference["note"] = "; ".join(parts)
                else:
                    difference.pop("note")


def generate(
    product_code: str,
    cache: Path,
    app_labels: dict[str, Any] | None = None,
    tree: dict[str, Any] | None = None,
    app_version: str = DEFAULT_APP_VERSION,
    *,
    reference: list[dict[str, Any]] | None = None,
    titles: dict[str, Any] | None = None,
    released: Collection[str] = (),
    shown: Mapping[str, str] | None = None,
    routes: Any = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    """The settings-file object of one model and its counters (the base context's).

    ``app_labels`` / ``tree`` are the model's entries of the label and settings-tree
    files (None: TD labels only / no UI placement); ``reference`` its v1 reference rows
    (``child`` rows check the base context, ``standalone`` rows the standalone one);
    ``titles`` the app setting-title file (None: no names, app units or variants);
    ``released`` the model's keys in the released-keys manifest (never dropped);
    ``shown`` where the app's device cards, home page and settings pages read each
    identifier (:func:`shown_places`; the model's tree adds the ones its layout places
    as pages); ``routes`` the app's write routing (:func:`build_context`).
    Raises CheckError when a codec does not reproduce a swept recipe or an unaccepted
    reference row.
    """
    folder = cache / product_code
    domain_counts: dict[str, int] = {}
    domains: dict[str, Mapping[str, Any]] = {}
    own_td = json.loads((folder / "td.json").read_text(encoding="utf-8"))
    td = joiner.apply_domains(product_code, own_td, titles, domain_counts, domains)
    joiner.check_screen_switches(product_code, td, titles)
    handler = folder / f"{product_code}Handle.mix.js"
    props = []
    skipped = 0
    for prop in td.get("properties", []):
        if not isinstance(prop, dict):
            continue
        ident = prop.get("identifier")
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident):
            skipped += 1
            continue
        props.append(prop)
    # A string property the app shows as an on/off switch is the bool it shows; so is a
    # bare value (kind other) an app screen writes from a switch, with the screen's values.
    switch_texts: dict[str, Mapping[bool, Any]] = dict(joiner.switches(product_code, titles))
    screen = joiner.screen_switches(product_code, titles)
    typed = []
    for prop in props:
        ident = prop["identifier"]
        if ident in switch_texts:
            typed.append(codec.as_switch(prop, switch_texts[ident]))
        elif ident in screen and codec.kind_of(prop) == "other":
            typed.append(codec.as_switch(prop, screen[ident], kind="other"))
            switch_texts[ident] = screen[ident]
        else:
            typed.append(prop)
    props = typed
    wire = app_wire_values(props, switch_texts, joiner.screen_values(product_code, titles))
    contexts = contexts_of(product_code)
    swept = sweep(product_code, handler, props, contexts, wire)
    objects = object_sweep(
        product_code, handler, props, contexts, joiner.object_writes(product_code, titles)
    )
    rows = reference or []
    per_context: dict[str, dict[str, Any]] = {}
    references: dict[str, list[dict[str, Any]]] = {}
    counts: dict[str, int] = {}
    located_counts: dict[str, int] = {}
    located = locate_params(
        product_code, handler, contexts[BASE], [p["identifier"] for p in props], located_counts
    )
    kinds = {p["identifier"]: codec.kind_of(p) for p in props}
    # The other parameters a read is retried with, and a template's parameter slots, come
    # from the writes the file carries: every declared one, and the undeclared ones kept,
    # which only a build decides. Rebuild until the kept writes are the ones used.
    declared = {p["identifier"] for p in props if td_writable(p)}
    written, tried = declared, [declared]
    while True:
        background, seen = written_params(swept, written)
        for name, ctx in contexts.items():
            wanted = {BASE: "child", STANDALONE: "standalone"}.get(name)
            references[name] = [r for r in rows if r["context"] == wanted]
            settings, ctx_counts = build_context(
                product_code,
                handler,
                td,
                props,
                context=ctx,
                swept=swept[name],
                app_labels=app_labels,
                tree=tree,
                titles=titles,
                reference=references[name],
                background=background,
                seen=seen,
                located=located,
                wire=wire,
                objects=objects[name],
                routes=routes,
            )
            per_context[name] = settings
            if name == BASE:
                counts = ctx_counts
        kept = declared | {
            ident
            for settings in per_context.values()
            for ident, entry in settings.items()
            if entry["access"] == "rw"
        }
        if kept == written:
            break
        if kept in tried:
            raise GeneratorError(f"{product_code}: the kept writes do not settle: {sorted(kept)}")
        written = kept
        tried.append(kept)
    for key, n in located_counts.items():
        _count(counts, key, n)
    drop = controls.variants_to_drop(list(per_context.values()), released)
    for name, settings in per_context.items():
        controls.drop_same_codec_variants(settings, counts if name == BASE else {}, only=drop)
        shaped = reference_mismatches(settings, references[name])
        _raise_unaccepted(product_code, contexts[name], shaped, "shaped settings differ")
    if skipped:
        counts["skipped"] = skipped
    merged = merge_contexts(per_context)
    apply_param_values(product_code, merged, props, tree, titles)
    variants.add_variants(
        merged,
        props,
        drop,
        lambda ident, values: reported_param(
            product_code,
            handler,
            contexts[BASE],
            ident,
            values,
            located=located,
            kind=kinds[ident],
        ),
        counts,
    )
    structured_values(product_code, handler, contexts[BASE], merged, located, counts=counts)
    joiner.mark_structured(product_code, merged, titles, counts)
    joiner.finish_domains(merged, domains, domain_counts)
    _add_counts(counts, domain_counts)
    model = model_for_serial(product_code)
    station = model is not None and model.kind is DeviceKind.STATION
    for key, n in sections.assign(merged, station=station).items():
        _count(counts, key, n)
    for key, n in roles.assign(
        merged,
        td_writable={p["identifier"] for p in props if td_writable(p)},
        app_read_only=set((titles or {}).get("read_only") or {}),
        shown=model_shown(shown or {}, tree),
        state_params=STATE_PARAM_INFO.keys(),
        located={ident: where.param for ident, where in located.items()},
    ).items():
        _count(counts, key, n)
    for entry in merged.values():
        for item in entry.get("contexts", ()):
            for name in item["names"]:
                _count(counts, f"context:{name}")
    doc = {
        "schema_version": SCHEMA_VERSION,
        "product_code": product_code,
        "source": joiner.source_block(td, app_version),
        "settings": merged,
        **battery_block(product_code, handler, props, contexts[BASE], counts),
        **sd_status_block(product_code, handler, contexts, located, counts),
        **lock_block(product_code, handler, props, contexts, counts),
        **garage_block(product_code, handler, props, contexts, counts),
    }
    return doc, counts


def placed_identifiers(tree: Mapping[str, Any] | None) -> set[str]:
    """The identifiers a model's settings tree places in one of the app's layouts
    (``positions``: ``{config: {page: ["<identifier>#<group>#<order>", ...]}}``)."""
    out: set[str] = set()
    for config in ((tree or {}).get("positions") or {}).values():
        for keys in config.values():
            out.update(str(key).partition("#")[0] for key in keys)
    return out


def model_shown(shown: Mapping[str, str], tree: Mapping[str, Any] | None) -> dict[str, str]:
    """Where the app shows each identifier on one model: ``shown`` (:func:`shown_places`),
    and ``page`` for every other identifier the model's ``tree`` places."""
    out: dict[str, str] = dict.fromkeys(placed_identifiers(tree), roles.PAGE)
    out.update(shown)
    return out


def shown_places(shown: Mapping[str, Any]) -> dict[str, str]:
    """Identifier -> ``card`` or ``page`` from the shown-property file: ``cards`` (device
    card and home page code that reads it, which wins) and ``pages`` (settings screens
    that read it), each ``{identifier: [where, ...]}``; raises GeneratorError on another
    shape."""
    out: dict[str, str] = {}
    for part, place in (("pages", roles.PAGE), ("cards", roles.CARD)):
        block = shown.get(part)
        if not isinstance(block, dict):
            raise GeneratorError(f"shown-property data has no {part} object")
        out.update(dict.fromkeys(block, place))
    return out


def app_wire_values(
    props: list[dict[str, Any]],
    switch_texts: Mapping[str, Mapping[bool, Any]],
    screens: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[tuple[Any, Any], ...]]:
    """The values the app writes for the model's ``props``: a switch's text per state, an
    enum's screen value per thing-description value it lists."""
    out: dict[str, tuple[tuple[Any, Any], ...]] = {}
    for prop in props:
        ident = prop["identifier"]
        if ident in switch_texts:
            out[ident] = tuple(switch_texts[ident].items())
        elif ident in screens:
            screen = screens[ident]
            _, values = codec.domain(prop)
            out[ident] = tuple(
                (v, screen[k]) for v in values if (k := codec.value_key(v)) in screen
            )
    return out


def shape_controls(
    product_code: str,
    handler: Path,
    settings: dict[str, Any],
    counts: dict[str, int],
    context: codec.Context,
    *,
    wire: codec.WireValues | None = None,
) -> None:
    """Bit switches, flags, scales, same-write variants and controls
    (``scripts/gen_models_controls.py``), probing the handler once more in ``context``
    for the first two. Same-codec variants are dropped across contexts (``generate``)."""

    def device(params: dict[int, str]) -> dict[str, Any]:
        dev = context.device(product_code)
        dev["params"] = [{"param_type": k, "param_value": v} for k, v in params.items()]
        return dev

    gates = {e["applies_when"][0] for e in settings.values() if e.get("applies_when")}
    bits = controls.bit_candidates(settings)
    flags = controls.flag_candidates(settings, gates)
    bit_reqs = controls.bit_requests(bits, device)
    # Members are probed as text, the form the app's multi-choice screens send.
    flag_reqs = [
        (
            ident,
            payload,
            {
                "kind": "set",
                "identifier": ident,
                "payload": payload,
                "device": context.device(product_code),
            },
        )
        for ident, values in flags.items()
        for payload in [codec.value_key(v) for v in values] + controls.flag_payloads(values)
    ]
    requests = [r for *_, r in bit_reqs] + [r for *_, r in flag_reqs]
    replies = run_driver(product_code, handler, requests, wire) if requests else []

    def slotted(reply: Any) -> Any:
        recipe = p2p(reply)
        return None if recipe is None else codec.slot(recipe, context)

    bit_replies = {
        (ident, value): slotted(rep)
        for (ident, value, _), rep in zip(bit_reqs, replies, strict=False)
    }
    flag_replies = {
        (ident, payload): slotted(rep)
        for (ident, payload, _), rep in zip(flag_reqs, replies[len(bit_reqs) :], strict=True)
    }
    controls.apply_bits(settings, bits, bit_replies, counts, channel=context.channel)
    singles = {
        ident: [(v, flag_replies.get((ident, codec.value_key(v)))) for v in values]
        for ident, values in flags.items()
    }
    controls.apply_flags(settings, flags, singles, flag_replies, counts, channel=context.channel)
    controls.apply_scales(settings, gates, counts)
    controls.apply_duplicate_variants(settings, counts)
    controls.apply_domains(settings, counts)
    controls.apply_controls(settings, counts)


def _count(counts: dict[str, int], key: str, n: int = 1) -> None:
    counts[key] = counts.get(key, 0) + n


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise GeneratorError(f"{path.name}: not a JSON object")
    return data


def _summary(counts: dict[str, int]) -> str:
    """The per-model log line: headline counters first, then every counter."""
    head = {
        "rw": sum(n for k, n in counts.items() if k.startswith("rw:")),
        "read": counts.get("read:codec", 0),
        "read_null": counts.get("read:null", 0),
        "labels_app": counts.get("label:app", 0),
        "labels_td": counts.get("label:td", 0),
        "applies_when": counts.get("applies_when", 0),
        "group": counts.get("group", 0),
        "names_app": counts.get("name:app", 0),
        "units_app": counts.get("unit:app", 0),
        "variants": counts.get("variant_of", 0),
        "bits": counts.get("bit", 0),
        "flags": counts.get("flags", 0),
        "scales": counts.get("scale", 0),
    }
    return (
        " ".join(f"{k}={v}" for k, v in head.items())
        + " "
        + json.dumps(counts, sort_keys=True, ensure_ascii=False)
    )


def _missing_inputs(cache: Path, pns: list[str]) -> str | None:
    """Why a run cannot start (no node of the pinned major, no cache, a model not in the
    cache), or None."""
    try:
        node.node_path()  # checked once: the generating processes inherit the result
    except node.DriverError as err:
        return str(err)
    if not cache.is_dir():
        return f"no thing-model cache at {cache}"
    absent = [pn for pn in pns if not (cache / pn / "td.json").is_file()]
    return f"not in the cache: {' '.join(absent)}" if absent else None


def index_text(codes: list[str]) -> str:
    """The text of ``INDEX.json`` listing ``codes``."""
    return codec.dump({"schema_version": SCHEMA_VERSION, "codes": sorted(codes)})


def write_index(out: Path) -> None:
    """Write ``out/INDEX.json`` from the ``<PN>.json`` files in ``out``."""
    codes = [p.stem for p in out.glob("*.json") if p.name != INDEX]
    (out / INDEX).write_text(index_text(codes), encoding="utf-8")


def compare(fresh: Path, committed: Path, pns: list[str] | None) -> list[str]:
    """Names of the files that differ (or exist on one side only, for a full run)."""
    if pns:
        names = {f"{pn}.json" for pn in pns}
    else:
        names = {p.name for p in fresh.glob("*.json")} | {p.name for p in committed.glob("*.json")}
    return sorted(
        name
        for name in names
        if not (fresh / name).is_file()
        or not (committed / name).is_file()
        or (fresh / name).read_bytes() != (committed / name).read_bytes()
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate models/<PN>.json from the vendor thing-model cache."
    )
    parser.add_argument("product_codes", nargs="*", metavar="PN")
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate into a temporary directory and compare with --out byte for byte",
    )
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--trees", type=Path, default=DEFAULT_TREES)
    parser.add_argument("--titles", type=Path, default=DEFAULT_TITLES)
    parser.add_argument("--shown", type=Path, default=DEFAULT_SHOWN)
    parser.add_argument("--routing", type=Path, default=DEFAULT_ROUTING)
    parser.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    parser.add_argument(
        "--answers",
        type=Path,
        default=DEFAULT_ANSWERS,
        help="driver answer store: replies of jobs asked before are replayed without Node",
    )
    parser.add_argument(
        "--no-answers",
        dest="answers",
        action="store_const",
        const=None,
        help="ask Node for every job; read and write no answer store",
    )
    parser.add_argument(
        "--released",
        type=Path,
        default=DEFAULT_RELEASED,
        help="released-keys manifest: same-codec variants it lists stay as variant_of",
    )
    parser.add_argument(
        "--update-released",
        metavar="REF",
        help="union the keys of the model files bundled at git REF into --released, then exit",
    )
    args = parser.parse_args(argv)
    if args.update_released:
        try:
            bundled = keys_at(args.update_released)
        except GeneratorError as err:
            print(f"gen_models: {err}", file=sys.stderr)
            return 2
        update_released(args.released, bundled)
        return 0
    cache: Path = args.cache
    missing = _missing_inputs(cache, args.product_codes)
    inputs = (args.labels, args.trees, args.titles, args.shown, args.routing)
    if missing is None and not all(p.is_file() for p in inputs):
        missing = "label, settings-tree, title, shown-property or routing data not found"
    if missing is None and not args.released.is_file():
        missing = f"no released-keys manifest at {args.released}"
    if missing is not None:
        print(f"gen_models: {missing}", file=sys.stderr)
        return 2
    try:
        if not args.check:
            return _generate_all(args, cache, args.out, quiet=False)
        with tempfile.TemporaryDirectory() as tmp:
            rc = _generate_all(args, cache, Path(tmp), quiet=True)
            if rc:
                return rc
            differ = compare(Path(tmp), args.out, args.product_codes)
    except node.NodeError as err:
        print(f"{err.notices}gen_models: {err}", file=sys.stderr)
        return 2
    for name in differ:
        print(f"differs: {name}")
    print(f"check: {len(differ)} files differ")
    return 1 if differ else 0


def released_text(released: Mapping[str, Collection[str]]) -> str:
    """The text of the released-keys manifest: product code -> sorted setting keys."""
    return codec.dump({pn: sorted(set(keys)) for pn, keys in released.items()})


def merge_released(
    released: Mapping[str, Collection[str]], bundled: Mapping[str, Collection[str]]
) -> dict[str, list[str]]:
    """``released`` with the keys of ``bundled`` (product code -> setting keys) added."""
    out = {pn: set(keys) for pn, keys in released.items()}
    for pn, keys in bundled.items():
        out.setdefault(pn, set()).update(keys)
    return {pn: sorted(keys) for pn, keys in sorted(out.items())}


def keys_at(ref: str) -> dict[str, list[str]]:
    """The setting keys of every model file that ``INDEX.json`` lists at git ``ref``.

    Raises ``GeneratorError`` when git is missing or ``ref`` bundles no readable models.
    """
    git = shutil.which("git")
    if git is None:
        raise GeneratorError("git is not on PATH")
    folder = DEFAULT_OUT.relative_to(ROOT).as_posix()

    def show(name: str) -> dict[str, Any]:
        text = subprocess.run(
            [git, "show", f"{ref}:{folder}/{name}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        data = json.loads(text)
        if not isinstance(data, dict):
            raise GeneratorError(f"{ref}:{name}: not a JSON object")
        return data

    try:
        return {pn: sorted(show(f"{pn}.json")["settings"]) for pn in show(INDEX)["codes"]}
    except (subprocess.CalledProcessError, KeyError) as err:
        raise GeneratorError(f"{ref}: no bundled models at {folder}") from err


def update_released(path: Path, bundled: Mapping[str, Collection[str]]) -> None:
    """Union ``bundled`` (product code -> setting keys) into the manifest at ``path``."""
    current = _read_json(path) if path.is_file() else {}
    path.write_text(released_text(merge_released(current, bundled)), encoding="utf-8")


@dataclass(frozen=True)
class _Task:
    """The inputs of one model's ``generate`` call (the model's slices of the input files)."""

    product_code: str
    cache: Path
    labels: dict[str, Any] | None
    tree: dict[str, Any] | None
    app_version: str
    reference: list[dict[str, Any]] | None
    titles: dict[str, Any]
    released: Collection[str]
    shown: Mapping[str, str] | None = None
    routes: Any = None


type _Result = tuple[str, str | None, dict[str, int], str, answers.Stats]


def _build(task: _Task) -> _Result:
    """``(product code, file text or None, counters, report, answer stats)`` of one
    model; the report holds what the model printed to stderr (driver notices) and, for a
    model that fails, the failure. A failure is reported, not raised, so the run goes on
    to the end; the report is returned, not printed, so the run prints the reports in
    model order. NodeError (the run stops) is raised, the model's notices in its
    ``notices``."""
    pn = task.product_code
    stop: node.NodeError | None = None
    failure = ""
    with contextlib.redirect_stderr(io.StringIO()) as notes:
        ANSWERS.open(pn)
        try:
            doc, counts = generate(
                pn,
                task.cache,
                task.labels,
                task.tree,
                task.app_version,
                reference=task.reference,
                titles=task.titles,
                released=task.released,
                shown=task.shown,
                routes=task.routes,
            )
        except node.NodeError as err:
            stop = err
        except GeneratorError as err:
            failure = f"{err}\n"
        except Exception as err:  # a shape the generator does not handle
            failure = f"{pn}: {type(err).__name__}: {err}\n{traceback.format_exc()}"
        notice = ANSWERS.close(ok=not (stop or failure))
        if notice:
            print(notice, file=sys.stderr)
    if stop is not None:
        stop.notices = notes.getvalue()  # the earlier deaths' causes, printed with it
        raise stop
    if failure:
        return pn, None, {}, notes.getvalue() + failure, ANSWERS.stats
    return pn, codec.dump(doc), counts, notes.getvalue(), ANSWERS.stats


def _open_drivers() -> None:
    """Start a generating process: accept driver jobs, end the worker on exit (a forked
    process runs only the exit handlers registered after the fork), and end with the
    parent process. SIGTERM ends this process at once (the parent's handler is the run's)."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    DRIVERS.open()
    atexit.register(DRIVERS.close)
    parent = multiprocessing.parent_process()
    if parent is not None:
        threading.Thread(target=_exit_with_parent, args=(parent.sentinel,), daemon=True).start()


def _exit_with_parent(sentinel: int) -> None:
    """Once the parent process has ended without shutting the pool down (killed), end
    this process and its worker."""
    multiprocessing.connection.wait([sentinel])
    DRIVERS.close()
    os._exit(1)


def _terminated(signum: int, _frame: object) -> None:
    """SIGTERM ends a run as Ctrl-C does: the pool shuts down on the way out."""
    raise SystemExit(128 + signum)


def _run_tasks(tasks: list[_Task], jobs: int) -> Iterator[_Result]:
    """``_build`` of every task, in task order: in this process for one job, else in
    ``jobs`` processes, each with its own Node worker (the codec inference is Python and
    would serialize on one interpreter).

    On an interrupt or error no queued model starts. A SIGTERM to this process alone lets
    the models in flight finish; one to the process group (or Ctrl-C) ends them too.
    """
    if jobs == 1:
        DRIVERS.open()
        try:
            yield from map(_build, tasks)
        finally:
            DRIVERS.close()
        return
    # fork: the workers inherit the loaded generator modules, however this one was loaded;
    # the caller must have no other threads (the command line has none).
    method = "fork" if "fork" in multiprocessing.get_all_start_methods() else None
    previous = signal.signal(signal.SIGTERM, _terminated)
    try:
        pool = ProcessPoolExecutor(
            max_workers=jobs,
            mp_context=multiprocessing.get_context(method),
            initializer=_open_drivers,
        )
        try:
            # map() yields in input order, so output and log do not depend on --jobs.
            yield from pool.map(_build, tasks)
        finally:
            pool.shutdown(cancel_futures=True)
    finally:
        signal.signal(signal.SIGTERM, previous)


def _generate_all(args: argparse.Namespace, cache: Path, out: Path, *, quiet: bool) -> int:
    """Generate the requested models into ``out``; 1 when any model failed. NodeError
    (from the first model that meets it) stops the run.

    Nothing in ``out`` is read: the same-codec variants kept are those the released-keys
    manifest (``args.released``) lists.
    """
    labels = _read_json(args.labels)
    trees = _read_json(args.trees)
    titles = _read_json(args.titles)
    shown = shown_places(_read_json(args.shown))
    try:
        routes = routing.load(args.routing)
    except GeneratorError as err:
        print(f"gen_models: {err}", file=sys.stderr)
        return 2
    released = _read_json(args.released)
    reference = load_reference()
    pns = args.product_codes or sorted(d.name for d in cache.iterdir() if d.is_dir())
    out.mkdir(parents=True, exist_ok=True)
    ANSWERS.root = args.answers  # before the fork: the generating processes inherit it
    if args.answers is not None:
        ANSWERS.prepare()  # once per run, inherited too
    tasks = [
        _Task(
            pn,
            cache,
            labels.get(pn),
            trees.get(pn),
            args.app_version,
            reference.get(pn),
            titles,
            released.get(pn, ()),
            shown,
            routes,
        )
        for pn in pns
    ]
    total: dict[str, int] = {}
    failed: list[str] = []
    replies = answers.Stats()
    for pn, text, counts, report, stats in _run_tasks(tasks, max(1, min(args.jobs, len(tasks)))):
        print(report, end="", file=sys.stderr)
        replies.add(stats)
        if text is None:
            failed.append(pn)
            continue
        (out / f"{pn}.json").write_text(text, encoding="utf-8")
        if not quiet:
            print(pn, _summary(counts))
        for key, n in counts.items():
            total[key] = total.get(key, 0) + n
    write_index(out)
    if not quiet:
        print(f"total {len(pns)} models", _summary(total))
    if args.answers is not None:
        print(
            f"answers: {replies.replayed} jobs replayed, {replies.asked} asked of Node"
            + (f", {replies.unkeyed} asked without the store" if replies.unkeyed else "")
            + (f", {replies.damaged} damaged in the store" if replies.damaged else "")
            + f" ({args.answers})",
            file=sys.stderr,
        )
    if failed:
        print(f"check failed, not written: {' '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
