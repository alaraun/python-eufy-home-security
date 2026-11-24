"""The eufy app's write routing, applied to the settings generator's write templates.

Input: the routing file (private, generated from the eufy app by an offline extractor;
docs/how-to/regenerate-models.md): the frame form the app's send handler gives each
frame command (``native``), the request type and the field its request builder reads
per bare command (``executor``), and the native settings screens' senders and write
forms (``screens``). The rule (docs/reference/models-schema.md § Write routing):

- A handler template is sent when its command gets a request type (its params'
  ``msgType``, else the builder's case) and a frame form the library sends; a JSON-text
  case that adds the owner's id (``json+account``) gets the ``$account_id`` member.
- Otherwise, for a model whose settings the app draws natively, the native screen's
  form: its own template params where the input gives them, else the same scalar frame
  when a screen sends the command as one.
- Otherwise the app sends nothing: the setting is read-only.

The library's frame-form tables and per-command value fields must equal the input's
(:func:`drift`): a regenerated input that moves a command fails the run.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gen_models_codec import GeneratorError

from eufy_home_security.devices.model_settings import ACCOUNT_SLOT
from eufy_home_security.p2p import messages

NOT_SENT_NOTE = "the eufy app sends nothing for this write"
SCREEN_OBJECT_NOTE = (
    "the eufy app's screen sends this write as an object, which this setting is not"
)
"""Note of a write only a native screen sends, in a form that reads members of an object."""
SENT_FORMS = frozenset(
    {"ecb_channel_value", "ecb_station", "ecb_value", "channel_value", "json_text", "string_int"}
)
"""The native frame forms the library sends a bare command in."""
SCALAR_FORMS = frozenset({"ecb_channel_value", "ecb_station", "ecb_value", "channel_value"})
WRAPPERS = {1350: "json_text", 1700: "wrap_1700"}
"""Commands that carry a ``subCmd``, with the frame form that sends them."""
LIBRARY_FORMS = {
    "ecb_channel_value": messages.ECB_CHANNEL_VALUE_CMDS,
    "ecb_station": messages.ECB_STATION_CMDS,
    "ecb_value": messages.ECB_VALUE_CMDS,
    "channel_value": messages.CHANNEL_VALUE_CMDS,
    "json_text": messages.JSON_TEXT_CMDS,
    "string_int": messages.STRING_CMDS,
}
_FIELD_READERS = {"int": False, "flag": True}  # reader -> EcbValueField.flag
_INT_REQUEST = 10  # the request type that sends one int (and the owner id)
OWNER_JSON_READER = "json+account"
"""The request case that sends the params as JSON text with the owner's id added."""
_TRANSPORT_KEYS = ("sendRequestUrl", "http", "multipleRequest", "localParams", "storeToLocal",
                   "ble", "mqttCmdCode")  # fmt: skip


@dataclass(frozen=True)
class Routing:
    """The routing input, by command id."""

    forms: Mapping[int, str]
    caller_channel: frozenset[int]
    msg_types: Mapping[int, int]
    fields: Mapping[int, tuple[str, str | None]]
    screen_forms: Mapping[int, Mapping[str, Any]]
    screen_senders: Mapping[int, frozenset[int | None]]


def parse(doc: Mapping[str, Any]) -> Routing:
    """The routing of a routing file's object; GeneratorError for a malformed one."""
    try:
        forms = {
            int(cmd): name for name, form in doc["native"]["forms"].items() for cmd in form["cmds"]
        }
        caller = frozenset(
            int(c) for c in doc["native"]["forms"]["json_text"]["caller_channel_cmds"]
        )
        cases = doc["executor"]["cases"]
        # A case whose request type is no number (a WebRTC-only state) sends no P2P frame.
        msg_types = {
            int(c): case["msgType"] for c, case in cases.items() if type(case["msgType"]) is int
        }
        fields = {int(c): (str(case["reader"]), case.get("field")) for c, case in cases.items()}
        screen_forms = {int(c): f for c, f in doc["screens"]["forms"].items()}
        senders = {
            int(c): frozenset(s.get("msgType") for s in rows)
            for c, rows in doc["screens"]["senders"].items()
        }
    except (KeyError, TypeError, ValueError, AttributeError) as err:
        raise GeneratorError(f"routing input: malformed ({err!r})") from err
    for cmd, form in screen_forms.items():
        if forms.get(cmd) != form.get("form") or not isinstance(form.get("params"), dict):
            raise GeneratorError(f"routing input: screen form {cmd} does not match its frame form")
    return Routing(forms, caller, msg_types, fields, screen_forms, senders)


def load(path: Path) -> Routing:
    """The routing file at ``path``, checked against the library (:func:`drift`)."""
    routing = parse(json.loads(path.read_text(encoding="utf-8")))
    found = drift(routing)
    if found:
        raise GeneratorError("routing input and library differ: " + "; ".join(found))
    return routing


def drift(routing: Routing) -> list[str]:
    """Where the library's frame-form tables and per-command value fields differ from the
    routing input."""
    out: list[str] = []
    for name, cmds in LIBRARY_FORMS.items():
        app = {c for c, f in routing.forms.items() if f == name}
        if app != set(cmds):
            out.append(f"{name}: app only {sorted(app - cmds)}, library only {sorted(cmds - app)}")
    if routing.caller_channel != messages.JSON_TEXT_CALLER_CHANNEL_CMDS:
        out.append(f"JSON-text caller channel: app {sorted(routing.caller_channel)}")
    scalar = {c for c, f in routing.forms.items() if f in SCALAR_FORMS}
    app_fields = {  # the one-int request (type 10) of a scalar frame
        cmd: messages.EcbValueField(field, flag=_FIELD_READERS[reader])
        for cmd, (reader, field) in routing.fields.items()
        if cmd in scalar
        and routing.msg_types.get(cmd) == _INT_REQUEST
        and reader in _FIELD_READERS
        and isinstance(field, str)
    }
    if app_fields != messages.ECB_VALUE_FIELDS:
        keys = set(app_fields) | set(messages.ECB_VALUE_FIELDS)
        diff = sorted(k for k in keys if app_fields.get(k) != messages.ECB_VALUE_FIELDS.get(k))
        out.append(f"ECB value fields differ for {diff}")
    return out


@dataclass(frozen=True)
class Route:
    """How the app sends one write template: ``template`` as sent (the native screen's
    when ``screen``), or None when it sends nothing."""

    template: Mapping[str, Any] | None
    screen: bool = False
    note: str = NOT_SENT_NOTE
    """Why the app sends nothing (``template`` None)."""


def route(template: Any, routing: Routing, *, native_screens: bool, kind: str = "object") -> Route:
    """The app's route of a handler write template (module docstring) for a setting of
    ``kind``: a screen form that reads members of the value needs an object setting."""
    if not isinstance(template, dict) or any(k in template for k in _TRANSPORT_KEYS):
        return Route(template)  # no P2P frame: the library names why
    cmd, sub, params = template.get("cmd"), template.get("subCmd"), template.get("params")
    if isinstance(cmd, bool) or not isinstance(cmd, int):
        return Route(template)
    if cmd in WRAPPERS:
        sent = (
            isinstance(sub, int)
            and not isinstance(sub, bool)
            and routing.msg_types.get(cmd, 0) != 0
            and routing.forms.get(cmd) == WRAPPERS[cmd]
        )
        return Route(template if sent else None)
    msg_type = params.get("msgType") if isinstance(params, dict) else None
    if isinstance(msg_type, bool) or not isinstance(msg_type, int):
        msg_type = routing.msg_types.get(cmd, 0)
    form = routing.forms.get(cmd)
    if msg_type != 0 and form in SENT_FORMS:
        if form == "json_text" and isinstance(params, dict) and _adds_owner(routing, cmd):
            return Route({**template, "params": {**params, "account_id": ACCOUNT_SLOT}})
        return Route(template)
    if native_screens and cmd in routing.screen_forms:
        params = routing.screen_forms[cmd]["params"]
        if kind == "object" or "$v." not in json.dumps(params):
            return Route({**template, "params": params}, screen=True)
        return Route(None, note=SCREEN_OBJECT_NOTE)
    senders = routing.screen_senders.get(cmd, frozenset())
    if native_screens and form in SCALAR_FORMS and senders - {0, None}:
        return Route(template, screen=True)
    return Route(None)


def _adds_owner(routing: Routing, cmd: int) -> bool:
    """The request builder puts the owner's id into the command's JSON text as
    ``account_id`` (replacing a member of that name in place, else appending it)."""
    return routing.fields.get(cmd, ("", None))[0] == OWNER_JSON_READER


def apply(
    settings: dict[str, Any], routing: Routing, *, native_screens: bool, counts: dict[str, int]
) -> None:
    """Route every write of a model's settings in one context: a template the app sends
    another way becomes that way, a setting with a template the app does not send becomes
    read-only with :data:`NOT_SENT_NOTE` or :data:`SCREEN_OBJECT_NOTE` (its read kept)."""
    for entry in settings.values():
        if entry.get("access") != "rw":
            continue
        table = entry.get("write_table") or {}
        kind = str(entry.get("kind"))
        routes = {
            k: route(t, routing, native_screens=native_screens, kind=kind) for k, t in table.items()
        }
        write = route(entry.get("write"), routing, native_screens=native_screens, kind=kind)
        if write.template is None and entry.get("write") is None and not table:
            continue
        unsent = [r for r in (write, *routes.values()) if r.template is None]
        if entry.get("write") is None:
            unsent = [r for r in routes.values() if r.template is None]
        if unsent:
            entry["access"] = "ro"
            entry.pop("write", None)
            entry.pop("write_table", None)
            note, why = entry.get("note"), unsent[0].note
            entry["note"] = f"{note}; {why}" if note else why
            counts[f"ro:{why}"] = counts.get(f"ro:{why}", 0) + 1
            continue
        if entry.get("write") is not None:
            entry["write"] = write.template
        for key, r in routes.items():
            table[key] = r.template
        if write.screen or any(r.screen for r in routes.values()):
            counts["routing:screen"] = counts.get("routing:screen", 0) + 1
