import json
from collections.abc import Mapping

import pytest

from eufy_home_security.devices.recipes import (
    MAX_PRESET_SLOTS,
    PARENT_CONNECT_TYPES,
    ConnectType,
    PanTilt,
    PresetPosition,
    Recipe,
    RecipeCommand,
    ResultFrom,
    SubCommand,
    close_live_stream,
    connect_type,
    free_preset_slot,
    goto_preset,
    open_live_stream_nvr,
    parse_preset_positions,
    ptz_rotate,
    query_preset_positions,
    set_default_preset,
    set_picture_zoom,
)
from eufy_home_security.exceptions import ProtocolError, UnsupportedError


@pytest.mark.parametrize(("prefix", "expected"), PARENT_CONNECT_TYPES.items())
def test_connect_type_maps_known_prefixes(prefix: str, expected: ConnectType) -> None:
    assert connect_type(f"{prefix}12345", "T816012345") == expected


def test_connect_type_standalone_is_single() -> None:
    assert connect_type("T817012345", "T817012345") == ConnectType.SINGLE


def test_connect_type_unknown_prefix_is_single() -> None:
    assert connect_type("T000012345", "T816012345") == ConnectType.SINGLE


def test_connect_type_none_is_single() -> None:
    assert connect_type(None, "T816012345") == ConnectType.SINGLE
    assert connect_type("T803012345", None) == ConnectType.SINGLE


def test_recipe_plaintext() -> None:
    assert goto_preset(1).plaintext() == b'{"commandType":6035,"data":{"value":1}}'
    assert Recipe(identifier="test", cmd=1700, sub_cmd=1700).plaintext() == b'{"commandType":1700}'
    assert close_live_stream().plaintext() == b"\x00\x00\x00\x00"
    assert close_live_stream().plaintext(channel=3) == b"\x03\x00\x00\x00"

    with pytest.raises(UnsupportedError):
        Recipe(identifier="test", cmd=1350).plaintext()


def test_recipe_answer_cmd() -> None:
    assert query_preset_positions().answer_cmd == 6034
    assert (
        Recipe(
            identifier="test",
            cmd=1700,
            sub_cmd=1700,
            notify_sub_cmd=1701,
            result_from=ResultFrom.NOTIFY,
        ).answer_cmd
        == 1701
    )
    assert (
        Recipe(
            identifier="test", cmd=1700, sub_cmd=1700, result_from=ResultFrom.CALLBACK
        ).answer_cmd
        is None
    )


def test_ptz_rotate_zoom_type() -> None:
    assert b'"zoom":1,' in ptz_rotate(cmd_type=0, rotate_type=1, zoom=1.0).plaintext()
    assert b'"zoom":1.5,' in ptz_rotate(cmd_type=0, rotate_type=1, zoom=1.5).plaintext()


def test_parse_preset_positions() -> None:
    payload = {
        "points": [
            {"index": 2},
            {"index": 1},
        ]
    }
    slots = parse_preset_positions(payload)
    assert len(slots) == 2
    assert slots[0].index == 1
    assert slots[1].index == 2

    with pytest.raises(ProtocolError):
        parse_preset_positions({})

    with pytest.raises(ProtocolError):
        parse_preset_positions({"points": "bad"})

    with pytest.raises(ProtocolError):
        parse_preset_positions({"points": [{"name": "A"}]})


def _slots(enabled: set[int], count: int = 10) -> tuple[PresetPosition, ...]:
    return tuple(
        PresetPosition(index=i, enabled=i in enabled, zoom=1, is_default=False)
        for i in range(count)
    )


def test_free_preset_slot_is_the_lowest_empty_index() -> None:
    assert free_preset_slot(_slots({0, 1, 2})) == 3
    assert free_preset_slot(_slots({1, 4})) == 0
    assert free_preset_slot(tuple(reversed(_slots({0, 2})))) == 1


def test_free_preset_slot_none_when_the_camera_is_full() -> None:
    assert free_preset_slot(_slots(set(range(MAX_PRESET_SLOTS)))) is None
    assert free_preset_slot(_slots({1, 3, 5, 7, 9})) is None
    assert free_preset_slot(_slots({0, 1}, count=2)) is None
    assert free_preset_slot(()) is None


def test_set_default_preset_returns_the_default_slot_recipe() -> None:
    recipe = set_default_preset(2)
    assert recipe.identifier == "default_preset_positions"
    assert recipe.cmd == RecipeCommand.SET_PAYLOAD
    assert recipe.sub_cmd == SubCommand.COMMAND_APP_SET_DEFAULT_POSITION
    assert recipe.params == {"index": 2, "settingstate": 0}


def test_set_default_preset_passes_confirm_flag() -> None:
    recipe = set_default_preset(1, confirm=True)
    assert recipe.params == {"index": 1, "settingstate": 1}


def test_set_default_preset_as_handler_dict_has_expected_format() -> None:
    recipe = set_default_preset(0)
    handler_dict = recipe.as_handler_dict()
    assert handler_dict == {
        "cmd": 1350,
        "subCmd": 6242,
        "params": {"index": 0, "settingstate": 0},
    }

    with pytest.raises(UnsupportedError):
        recipe.plaintext()


def test_set_picture_zoom_is_the_handlers_1350_6203_with_no_window() -> None:
    recipe = set_picture_zoom(2)
    assert recipe.as_handler_dict() == {
        "cmd": 1350,
        "subCmd": 6203,
        "params": {"x": 0, "y": 0, "w": 0, "h": 0, "offset": False, "orgZoom": 0, "dstZoom": 2},
    }
    params = set_picture_zoom(2.5).params
    assert params is not None
    assert params["dstZoom"] == 2.5


def test_pan_tilt_directions_are_the_cameras() -> None:
    """``rotate_type`` 1 turns the camera left, 2 right, 3 up, 4 down (the picture's
    directions; see docs/reference/hardware-verification.md)."""
    assert [(d.name, int(d)) for d in PanTilt] == [
        ("LEFT", 1),
        ("RIGHT", 2),
        ("UP", 3),
        ("DOWN", 4),
    ]


def test_the_plain_preset_query_sends_no_data_and_names_its_notify() -> None:
    plain = query_preset_positions(value=False)
    assert plain.plaintext() == b'{"commandType":6034}'
    assert plain.as_handler_dict()["notifySubCmd"] == 6034
    assert plain.answer_cmd == query_preset_positions().answer_cmd == 6034
    assert b'"data":{"value":0}' in query_preset_positions().plaintext()


def _nvr_payload(player: Mapping[str, object], **kwargs: bool) -> dict[str, object]:
    params = open_live_stream_nvr(channel=3, player=player, **kwargs).params
    assert params is not None
    payload = params["payload"]
    assert isinstance(payload, dict)
    return payload


def test_the_multi_camera_open_defaults_as_the_handler_does() -> None:
    recipe = open_live_stream_nvr(channel=3, player={"userId": "u"})
    assert recipe.as_handler_dict() == {
        "cmd": 1350,
        "subCmd": 1003,
        "timeout": 15000,
        "params": {
            "cmd": 1003,
            "mChannel": 3,
            "account_id": "u",
            "mValue3": 1003,
            "mValue5": 0,
            "payload": {
                "accountId": "u",
                "streamtype": 2,
                "camera_type": 0,
                "entrytype": 0,
                "stitch_mode": 1,
                "chn_list": [],
            },
        },
    }


def test_the_multi_camera_open_takes_a_page_channel_from_the_player() -> None:
    params = open_live_stream_nvr(channel=3, player={"mChannel": 21}).params
    assert params is not None
    assert params["mChannel"] == 21
    assert "mChannel" not in params["payload"]


def test_the_multi_camera_open_keeps_the_players_other_keys_but_not_the_mapped_ones() -> None:
    player = {
        "userId": "u",
        "streamType": 0,
        "entryType": 0,
        "chn_list": "",
        "stitch_mode": 5,
        "station_video_type": 0,
        "key": "k",
        "extValue": 1000,
    }
    payload = _nvr_payload(player)
    assert {"userId", "streamType", "entryType", "station_video_type"}.isdisjoint(payload)
    assert (payload["key"], payload["extValue"], payload["stitch_mode"]) == ("k", 1000, 5)


@pytest.mark.parametrize(
    ("entry", "from_lens", "camera_type"),
    [
        ({"cameraType": 0, "sensor": 1}, False, 0),
        ({"cameraType": 0, "sensor": 1}, True, 1),
        ({"cameraType": 0, "sensor": 0}, True, 0),
        ({"sensor": 1}, False, 1),
        ({"cameraType": 2, "sensor": 0}, True, 2),
    ],
)
def test_the_multi_camera_open_names_the_camera_type_of_a_one_lens_view(
    entry: dict[str, int], from_lens: bool, camera_type: int
) -> None:
    player = {"chn_list": json.dumps([entry])}
    assert _nvr_payload(player, camera_type_from_lens=from_lens)["camera_type"] == camera_type


def test_the_multi_camera_open_names_no_camera_type_for_several_lenses() -> None:
    player = {"chn_list": json.dumps([{"cameraType": 0, "sensor": 1}] * 2)}
    assert _nvr_payload(player, camera_type_from_lens=True)["camera_type"] == 0


_CORD = json.dumps({"x1": 0.0005, "y1": 0.7, "x2": 0.9994, "y2": 0.9})


def test_a_picture_in_picture_open_rounds_the_inset_to_thousandths() -> None:
    payload = _nvr_payload({"stitch_mode": 7, "station_video_type": 9, "pip_cord": _CORD})
    assert payload["station_video_type"] == 9
    assert payload["pip_cord"] == {"x1": 1, "y1": 700, "x2": 999, "y2": 900}


@pytest.mark.parametrize("video_type", [0, 1])
def test_a_picture_in_picture_open_of_one_lens_keeps_the_inset_as_given(video_type: int) -> None:
    payload = _nvr_payload({"stitch_mode": 7, "station_video_type": video_type, "pip_cord": _CORD})
    assert payload["station_video_type"] == video_type
    assert payload["pip_cord"] == _CORD


def test_only_a_picture_in_picture_open_names_the_station_video_type() -> None:
    payload = _nvr_payload({"stitch_mode": 5, "station_video_type": 9, "pip_cord": ""})
    assert "station_video_type" not in payload
    assert payload["pip_cord"] == ""
