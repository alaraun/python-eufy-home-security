"""``scripts/gen_device_alarm.py``: which alarm property the app reads, and the request form."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = _load("gen_device_alarm")


def _prop(ident: str, *groups: list[tuple[str, str, str]]) -> dict[str, Any]:
    conditions = [
        {"conditions": [{"type": t, "qualifier": q, "value": v} for t, q, v in g]} for g in groups
    ]
    return {"identifier": ident, "read_conditions": {"condition_list": conditions}}


BASE = _prop("set_alarm_type")
BEHIND_A_STATION = _prop("set_alarm_type__v1", [("parent_sn", "RE", "^(?!T9ZZ9|T8N00).*$")])


def test_the_variant_applies_where_its_parent_pattern_passes() -> None:
    props = [BASE, BEHIND_A_STATION]
    assert gen.resolve(props, "T9ZZ9P0000000002", "T8030P0000000001") is BEHIND_A_STATION
    assert gen.resolve(props, "T9ZZ9P0000000002", "T9ZZ9P0000000002") is BASE


def test_the_variant_with_more_passing_conditions_wins() -> None:
    narrow = _prop(
        "set_alarm_type__v2",
        [("parent_sn", "RE", "^T8030"), ("device_sn", "RE", "^T9ZZ9")],
    )
    props = [BASE, BEHIND_A_STATION, narrow]
    assert gen.resolve(props, "T9ZZ9P0000000002", "T8030P0000000001") is narrow


def test_of_two_variants_with_as_many_conditions_the_first_wins() -> None:
    later = _prop("set_alarm_type__v2", [("parent_sn", "RE", "^T8030")])
    props = [BASE, BEHIND_A_STATION, later]
    assert gen.resolve(props, "T9ZZ9P0000000002", "T8030P0000000001") is BEHIND_A_STATION


def test_a_serial_condition_that_is_no_pattern_match_keeps_the_base() -> None:
    other = _prop("set_alarm_type__v1", [("parent_sn", "SE", ".*")])
    assert gen.resolve([BASE, other], "T9ZZ9P0000000002", "T8030P0000000001") is BASE


def test_a_condition_on_a_device_value_keeps_the_base() -> None:
    gated = _prop(
        "set_alarm_type__v1",
        [("parent_sn", "RE", ".*"), ("associated_field", "=", "1")],
    )
    assert gen.resolve([BASE, gated], "T9ZZ9P0000000002", "T8030P0000000001") is BASE


def test_a_request_slots_the_channel_and_the_nickname() -> None:
    def recipe(channel: int) -> dict[str, Any]:
        params = {"channel": channel, "type": 10, "time_out": 30, "user_name": gen.NICKNAME}
        return {"cmd": 1350, "subCmd": 1202, "params": params}

    assert gen.request(recipe(3), recipe(5), (3, 5)) == [
        1202,
        {"channel": "$channel", "type": 10, "time_out": 30, "user_name": "$user_name"},
    ]


def test_a_value_equal_to_the_channel_on_one_channel_only_stays() -> None:
    """Only a field that follows the channel on both probes is the channel slot."""

    def recipe(channel: int) -> dict[str, Any]:
        return {"cmd": 1202, "params": {"channel": channel, "type": 3, "time_out": 30}}

    assert gen.request(recipe(3), recipe(5), (3, 5)) == [
        1202,
        {"channel": "$channel", "type": 3, "time_out": 30},
    ]


def test_a_request_the_station_does_not_confirm_is_none() -> None:
    sensor = {"cmd": 1350, "subCmd": 1826, "params": {}}
    assert gen.request(sensor, sensor, (3, 5)) is None
    assert gen.request(None, None, (3, 5)) is None


def test_the_choices_leave_out_the_homebase_alarm() -> None:
    rows = [
        {"value": "0", "desc": "sound"},
        {"value": "1", "desc": "light"},
        {"value": "2", "desc": "both", "isDefault": "1"},
        {"value": "3", "desc": "homebase"},
    ]
    prop = {"identifier": "set_alarm_type", "data_type": {"specs": {"eunmList": rows}}}
    assert gen._choices(prop) == ([0, 1, 2], 2)


START = [1202, {"channel": "$channel", "type": 10, "time_out": 30}]
STOP = [1201, {"channel": "$channel", "type": 10, "time_out": 0}]


def test_a_choice_needs_a_start_and_a_stop_with_the_same_fields() -> None:
    assert gen.start_stop(START, STOP) == [START, STOP]
    assert gen.start_stop(START, [1202, {"time_out": 0}]) is None
    assert gen.start_stop(START, None) is None
    assert gen.start_stop(None, STOP) is None
