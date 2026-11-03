from __future__ import annotations

import json
from typing import Any

import pytest

from eufy_home_security.p2p.param_notify import ParamNotify, decode_param_notify


def test_a_sensor_status_list_sets_each_listed_parameter() -> None:
    """1829: every ``{param_type, param_value}`` of the list, an int value as its decimal."""
    obj = {
        "cmd": 1829,
        "payload": {
            "params": [
                {"param_type": 1550, "param_value": 1},
                {"param_type": "61015", "param_value": "0"},
            ]
        },
    }
    assert decode_param_notify(obj) == ParamNotify(values={1550: "1", 61015: "0"}, skipped=0)


@pytest.mark.parametrize(
    "params",
    [
        json.dumps([{"param_type": 1550, "param_value": 0}]),
        "[{param_type=1550, param_value=0}]",
    ],
    ids=["json-string", "key-equals"],
)
def test_a_sensor_status_list_written_as_text_is_read(params: str) -> None:
    """``params`` as a JSON string, or the same list written ``key=value``."""
    notify = decode_param_notify({"cmd": 1829, "payload": {"params": params}})
    assert notify == ParamNotify(values={1550: "0"}, skipped=0)


def test_an_entry_sensor_status_sets_its_door_parameter() -> None:
    """1550 ``status``: the door state, filed as parameter 1550."""
    assert decode_param_notify({"cmd": 1550, "payload": {"status": 1}}) == ParamNotify(
        values={1550: "1"}, skipped=0
    )
    assert decode_param_notify({"cmd": "1550", "payload": json.dumps({"status": "0"})}) == (
        ParamNotify(values={1550: "0"}, skipped=0)
    )


def test_an_update_camera_info_sets_the_parameter_its_cmd_names() -> None:
    """``updateCameraInfo``: parameter ``cmd`` takes ``value``, whatever the id."""
    value = json.dumps({"mb_switch": 0})
    obj = {"cmd": 60012, "payload": {"type": "updateCameraInfo", "value": value}}
    assert decode_param_notify(obj) == ParamNotify(values={60012: value}, skipped=0)
    numeric = {"cmd": 1550, "payload": {"type": "updateCameraInfo", "value": 1}}
    assert decode_param_notify(numeric) == ParamNotify(values={1550: "1"}, skipped=0)


@pytest.mark.parametrize(
    "obj",
    [
        {"cmd": 2037, "payload": json.dumps({"event_type": 3101})},  # a camera push
        {"cmd": 1224, "code": 0},  # a command result
        {"cmd": 6246, "payload": {"num": 1}},  # another notify
        {"cmd": "x", "payload": {"type": "updateCameraInfo", "value": "1"}},
        {"payload": {"status": 1}},
        {"cmd": 6246, "payload": "not json"},
    ],
)
def test_other_frames_are_no_parameter_notify(obj: dict[str, Any]) -> None:
    assert decode_param_notify(obj) is None


@pytest.mark.parametrize(
    ("payload", "values", "skipped"),
    [
        (
            {
                "params": [
                    {"param_type": 1550, "param_value": 1},
                    {"param_type": "x", "param_value": 1},
                    {"param_value": 1},
                    {"param_type": 61015, "param_value": None},
                    {"param_type": 61015, "param_value": True},
                    {"param_type": 61015, "param_value": 1.5},
                    "not an object",
                ]
            },
            {1550: "1"},
            6,
        ),
        ({"params": "[not a list"}, {}, 1),
        ({"params": json.dumps({"param_type": 1550})}, {}, 1),
        ({"params": 7}, {}, 1),
        ({}, {}, 1),
    ],
    ids=["bad-items", "unparsable-text", "not-a-list", "number", "absent"],
)
def test_malformed_status_items_are_skipped_and_counted(
    payload: dict[str, Any], values: dict[int, str], skipped: int
) -> None:
    assert decode_param_notify({"cmd": 1829, "payload": payload}) == ParamNotify(
        values=values, skipped=skipped
    )


@pytest.mark.parametrize(
    "obj",
    [
        {"cmd": 1550, "payload": {"status": "open"}},
        {"cmd": 1550, "payload": {"status": True}},
        {"cmd": 1550, "payload": {}},
        {"cmd": 60012, "payload": {"type": "updateCameraInfo", "value": {"a": 1}}},
        {"cmd": 60012, "payload": {"type": "updateCameraInfo"}},
        {"cmd": 1550},
        {"cmd": 1829, "payload": "not json"},
        {"cmd": 1829, "payload": ["not", "an", "object"]},
    ],
)
def test_a_notify_without_a_usable_value_is_counted_as_skipped(obj: dict[str, Any]) -> None:
    assert decode_param_notify(obj) == ParamNotify(values={}, skipped=1)
