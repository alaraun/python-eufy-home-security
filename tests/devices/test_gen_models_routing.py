"""The settings generator emits a write only in the frame form the eufy app's routing gives it
(scripts/gen_models_routing.py). The routing input here is synthetic: built from the
library's own frame-form tables, so the tests carry no app data."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from .routing_input import FORMS, library_routing

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
routing = _load("gen_models_routing")

SCREEN_1414 = {"msgType": 16, "mValue": "$v.enable:flag", "mValueStr": "$v.lat:str"}


def _doc() -> dict[str, Any]:
    """A routing input that agrees with the library, plus the commands the rule tests use."""
    doc = library_routing()
    doc["native"]["forms"]["bare_channel"] = {"cmds": [1004]}
    doc["executor"]["cases"] |= {
        "1271": {"msgType": 6, "reader": "json"},
        "1004": {"msgType": 10, "reader": "none"},
        "9258": {"msgType": 10, "reader": "int", "field": "interval"},
        "-100": {"msgType": "Unknown.STATE", "reader": "none"},
    }
    doc["screens"] = {
        "senders": {"1408": [{"msgType": 10}], "1409": [{"msgType": None}]},
        "forms": {"1414": {"form": "string_int", "params": SCREEN_1414}},
    }
    return doc


ROUTES = routing.parse(_doc())


def test_an_input_that_agrees_with_the_library_has_no_drift() -> None:
    assert routing.LIBRARY_FORMS == FORMS
    assert routing.drift(ROUTES) == []
    assert ROUTES.msg_types.get(-100) is None  # a request type that is no number


@pytest.mark.parametrize(
    ("edit", "found"),
    [
        (lambda d: d["native"]["forms"]["ecb_station"]["cmds"].append(1999), "ecb_station"),
        (lambda d: d["native"]["forms"]["channel_value"]["cmds"].remove(1205), "channel_value"),
        (lambda d: d["native"]["forms"]["json_text"]["caller_channel_cmds"].pop(), "caller"),
        (lambda d: d["executor"]["cases"]["1400"].update(field="on"), "[1400]"),
        (lambda d: d["executor"]["cases"]["1403"].update(reader="int"), "[1403]"),
        (lambda d: d["executor"]["cases"].pop("1230"), "[1230]"),
    ],
)
def test_a_moved_command_or_field_is_drift(edit: Any, found: str) -> None:
    doc = _doc()
    edit(doc)
    (problem,) = routing.drift(routing.parse(doc))
    assert found in problem


def test_a_two_int_request_is_no_value_field() -> None:
    """A scalar command whose request carries two ints (type 4) has no one value field."""
    doc = _doc()
    doc["executor"]["cases"]["1202"] = {"msgType": 4, "reader": "int", "field": "time_out"}
    assert routing.drift(routing.parse(doc)) == []


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["native"].pop("forms"),
        lambda d: d["executor"]["cases"].update({"x": {"msgType": 1}}),
        lambda d: d["screens"]["forms"]["1414"].update(form="json_text"),
        lambda d: d["screens"]["forms"]["1414"].update(params="$v"),
    ],
)
def test_a_malformed_input_is_refused(edit: Any) -> None:
    doc = _doc()
    edit(doc)
    with pytest.raises(codec.GeneratorError, match="routing input"):
        routing.parse(doc)


def test_load_refuses_an_input_the_library_disagrees_with(tmp_path: Path) -> None:
    doc = _doc()
    doc["native"]["forms"]["string_int"]["cmds"].append(1999)
    path = tmp_path / "routing.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(codec.GeneratorError, match="string_int"):
        routing.load(path)


@pytest.mark.parametrize(
    ("template", "native", "sent"),
    [
        ({"cmd": 1271, "params": {"snooze_time": "$v"}}, False, True),  # JSON text
        ({"cmd": 1013, "params": {"value": "$v"}}, False, True),  # channel + value
        ({"cmd": 1400, "params": {"open": "$v"}}, True, True),
        ({"cmd": 1350, "subCmd": 1277, "params": {}}, False, True),
        ({"cmd": 1700, "subCmd": 6014, "params": {}}, False, True),
        ({"cmd": 1350, "params": {}}, False, False),  # a transfer needs its sub-command
        ({"cmd": 1700, "subCmd": True, "params": {}}, False, False),
        ({"cmd": 1507, "params": {"msgType": 10, "mValue": "$v"}}, False, True),  # override
        ({"cmd": 1507, "params": {"msgType": 0, "mValue": "$v"}}, True, False),
        ({"cmd": 9258, "params": {"interval": "$v"}}, True, False),  # no frame form
        ({"cmd": 1004, "params": {}}, False, False),  # a form the library does not send
        ({"cmd": 1408, "params": {"on": "$v"}}, False, False),  # app-drawn settings only
        ({"cmd": 1409, "params": {"on": "$v"}}, True, False),  # no screen request type
        ({"cmd": 1414, "params": {"value": "$v"}}, False, False),
    ],
)
def test_a_template_is_kept_only_where_the_app_sends_it(
    template: dict[str, Any], native: bool, sent: bool
) -> None:
    found = routing.route(template, ROUTES, native_screens=native)
    assert (found.template == template, found.screen) == (sent, False)


def test_a_native_screen_sends_its_own_form_or_the_same_scalar() -> None:
    handler = {"cmd": 1414, "params": {"value": "$v"}, "update": {"cmd": 1414, "paramValue": "x"}}
    found = routing.route(handler, ROUTES, native_screens=True)
    assert found.screen
    assert found.template == {**handler, "params": SCREEN_1414}
    scalar = {"cmd": 1408, "params": {"on": "$v"}}
    assert routing.route(scalar, ROUTES, native_screens=True) == routing.Route(scalar, True)
    text = routing.route(handler, ROUTES, native_screens=True, kind="string")
    # the screen form reads members a text does not have
    assert text == routing.Route(None, note=routing.SCREEN_OBJECT_NOTE)


@pytest.mark.parametrize(
    "template",
    [
        None,
        "x",
        {"cmd": "1013"},
        {"cmd": 1013, "sendRequestUrl": "/x"},
        {"cmd": 9258, "params": {}, "sendRequestUrl": "/x"},  # the library names the cloud
    ],
)
def test_a_template_with_no_p2p_command_is_left_to_the_library(template: Any) -> None:
    assert routing.route(template, ROUTES, native_screens=False).template == template


@pytest.mark.parametrize(
    ("params", "sent"),
    [
        ({"mode": "$v"}, {"mode": "$v", "account_id": "$account_id"}),
        ({"account_id": "", "mode": "$v"}, {"account_id": "$account_id", "mode": "$v"}),
    ],
)
def test_a_json_text_case_that_adds_the_owner_id_gets_its_slot(
    params: dict[str, Any], sent: dict[str, Any]
) -> None:
    """Appended, or in place of a member of that name, as a map put does."""
    doc = _doc()
    doc["executor"]["cases"]["1255"] = {"msgType": 6, "reader": "json+account"}
    found = routing.route({"cmd": 1255, "params": params}, routing.parse(doc), native_screens=False)
    assert found.template is not None
    assert list(found.template["params"].items()) == list(sent.items())
    plain = routing.route({"cmd": 1271, "params": params}, ROUTES, native_screens=False)
    assert plain.template == {"cmd": 1271, "params": params}


def _settings() -> dict[str, Any]:
    read = {"param": 9258, "map": None}
    return {
        "sent": {"access": "rw", "write": {"cmd": 1271, "params": {"snooze_time": "$v"}}},
        "unsent": {"access": "rw", "write": {"cmd": 9258, "params": {}}, "read": read},
        "noted": {"access": "rw", "write": {"cmd": 9258, "params": {}}, "note": "n"},
        "table": {
            "access": "rw",
            "write_table": {
                "0": {"cmd": 1271, "params": {}},
                "1": {"cmd": 9258, "params": {}},
            },
        },
        "screen": {"access": "rw", "kind": "object", "write": {"cmd": 1414, "params": {}}},
        "text": {"access": "rw", "kind": "string", "write": {"cmd": 1414, "params": {}}},
        "screen_table": {"access": "rw", "write_table": {"0": {"cmd": 1408, "params": {}}}},
        "ro": {"access": "ro", "note": "no handler write path"},
    }


def test_apply_makes_a_write_the_app_does_not_send_read_only() -> None:
    settings, counts = _settings(), dict[str, int]()
    before = copy.deepcopy(settings)
    screens = routing.apply(settings, ROUTES, native_screens=True, counts=counts)
    assert screens == {"screen": {None}, "screen_table": {"0"}}  # the screens' templates
    assert settings["sent"] == before["sent"]
    assert settings["unsent"] == {
        "access": "ro",
        "read": {"param": 9258, "map": None},  # the read stays
        "note": routing.NOT_SENT_NOTE,
    }
    assert settings["noted"]["note"] == f"n; {routing.NOT_SENT_NOTE}"
    assert settings["table"] == {"access": "ro", "note": routing.NOT_SENT_NOTE}
    assert settings["screen"]["write"]["params"] == SCREEN_1414
    assert settings["text"] == {
        "access": "ro",
        "kind": "string",
        "note": routing.SCREEN_OBJECT_NOTE,
    }
    assert settings["screen_table"] == before["screen_table"]
    assert settings["ro"] == before["ro"]
    assert counts == {
        f"ro:{routing.NOT_SENT_NOTE}": 3,
        f"ro:{routing.SCREEN_OBJECT_NOTE}": 1,
        "routing:screen": 2,
    }


def test_apply_on_a_model_the_rn_bundle_draws_sends_no_screen_form() -> None:
    settings, counts = _settings(), dict[str, int]()
    assert routing.apply(settings, ROUTES, native_screens=False, counts=counts) == {}
    assert settings["screen"]["access"] == "ro"
    assert settings["screen_table"]["access"] == "ro"
    assert counts == {f"ro:{routing.NOT_SENT_NOTE}": 6}
