from __future__ import annotations

import json
from typing import Any

import pytest

from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.mode_actions import (
    ACTION_FLAGS,
    FIELD_PARAMS,
    MODE_TABLE_MODES,
    MODE_TABLE_PARAMS,
    CountDown,
    ModeTable,
    ModeTableField,
    applied_params,
    mode_table_from_params,
)

ALARM = ModeTableField.ALARM_DELAY
LEAVING = ModeTableField.LEAVING_DELAY
ACCOUNT = "synthetic-account"

# A synthetic dump shaped like a HomeBase 3 with two cameras (0, 1) and a motion
# sensor (16): Home actions 1/1/0, every delay 0, plus a station block and a keypad-like
# block that reports no action.
HOME_DUMP: dict[int, dict[int, str | None]] = {
    0: {1225: "1", 1166: "0", 1171: "0", 1239: "9"},
    1: {1225: "1", 1166: "0", 1171: "0", 1239: "143"},
    16: {1225: "0", 1166: "0", 1171: "0", 1239: "8"},
    255: {1224: "1", 1225: "7"},
    40: {1101: "90"},
}


def _home() -> ModeTable:
    return mode_table_from_params(HOME_DUMP, GuardMode.HOME)


def test_param_ids_follow_the_apk_mode_order() -> None:
    """Actions are Away-first ids, the delays Home-first (ArmingManager.c/d)."""
    assert FIELD_PARAMS[ModeTableField.ACTION] == {
        GuardMode.AWAY: 1239,
        GuardMode.HOME: 1225,
        GuardMode.CUSTOM_1: 1148,
        GuardMode.CUSTOM_2: 1149,
        GuardMode.CUSTOM_3: 1150,
    }
    assert [FIELD_PARAMS[ALARM][m] for m in MODE_TABLE_MODES] == [1167, 1166, 1168, 1169, 1170]
    assert [FIELD_PARAMS[LEAVING][m] for m in MODE_TABLE_MODES] == [1172, 1171, 1173, 1174, 1175]
    assert len(MODE_TABLE_PARAMS) == 15
    assert [int(m) for m in MODE_TABLE_MODES] == [0, 1, 3, 4, 5]
    assert ACTION_FLAGS["camera_siren"] == 2
    assert ACTION_FLAGS["light_alarm"] == 128


def test_from_params_takes_every_block_with_the_action() -> None:
    table = _home()
    assert table.actions == {0: 1, 1: 1, 16: 0}  # not the station, not the keypad
    assert table.alarm_delays == {0: 0, 1: 0, 16: 0}
    assert mode_table_from_params({0: {1239: "143"}}, GuardMode.AWAY).alarm_delays == {0: 0}


def test_an_unchanged_table_is_the_apps_away_table() -> None:
    """The app's Away table: every device, empty count-downs at 0, sirens all 0."""
    table = mode_table_from_params(HOME_DUMP, GuardMode.AWAY)
    assert table.request(ACCOUNT) == {
        "account_id": ACCOUNT,
        "mode_id": 0,
        "devices": [
            {"device_channel": 16, "action": 8},
            {"device_channel": 1, "action": 143},
            {"device_channel": 0, "action": 9},
        ],
        "count_down_alarm": {"channel_list": [], "delay_time": 0},
        "count_down_arm": {"channel_list": [], "delay_time": 0},
        "siren_sensor_action": [
            {"device_channel": 16, "action": 0},
            {"device_channel": 1, "action": 0},
            {"device_channel": 0, "action": 0},
        ],
    }
    assert json.loads(table.encode(ACCOUNT)) == table.request(ACCOUNT)


def test_with_action_changes_one_device_only() -> None:
    table = mode_table_from_params(HOME_DUMP, GuardMode.AWAY).with_action(1, 9)
    assert table.actions == {0: 9, 1: 9, 16: 8}
    assert table.params() == {0: {1239: 9}, 1: {1239: 9}, 16: {1239: 8}}  # delays all off
    assert not table.same_values(mode_table_from_params(HOME_DUMP, GuardMode.AWAY))
    assert table.same_values(table.with_delay(ALARM, 0, 0))  # already off: nothing to write


def test_delays_reproduce_the_apps_home_write() -> None:
    """Home, 30 s alarm delay on both cameras and leaving delay on channel 1."""
    table = _home().with_delay(ALARM, 1, 30).with_delay(ALARM, 0, 30).with_delay(LEAVING, 1, 30)
    request = table.request(ACCOUNT)
    assert request["count_down_alarm"] == {"channel_list": [1, 0], "delay_time": 30}
    assert request["count_down_arm"] == {"channel_list": [1], "delay_time": 30}
    assert table.params() == {
        0: {1225: 1, 1166: 30},
        1: {1225: 1, 1166: 30, 1171: 30},
        16: {1225: 0},  # its delays stay off and are not read back
    }


def test_a_non_zero_delay_moves_every_device_that_has_it_on() -> None:
    table = mode_table_from_params(
        {0: {1225: "1", 1166: "30"}, 1: {1225: "1", 1166: "0"}, 16: {1225: "0", 1166: "30"}},
        GuardMode.HOME,
    )
    assert table.with_delay(ALARM, 1, 45).count_down(ALARM) == CountDown((16, 1, 0), 45)


def test_a_zero_delay_turns_off_one_device_and_keeps_the_rest() -> None:
    table = mode_table_from_params(
        {0: {1225: "1", 1166: "30"}, 1: {1225: "1", 1166: "30"}}, GuardMode.HOME
    )
    off = table.with_delay(ALARM, 0, 0)
    assert off.count_down(ALARM) == CountDown((1,), 30)  # 0 left out of the list
    assert off.params()[0][1166] == 0
    # The last one off: listed with delay 0, so the station writes the 0.
    assert off.with_delay(ALARM, 1, 0).count_down(ALARM) == CountDown((1, 0), 0)


def test_a_delay_that_differs_between_devices_is_refused() -> None:
    table = mode_table_from_params(
        {0: {1225: "1", 1171: "30"}, 1: {1225: "1", 1171: "60"}}, GuardMode.HOME
    )
    with pytest.raises(UnsupportedError, match="channel 0 = 30 s, channel 1 = 60 s"):
        table.with_action(0, 3).request(ACCOUNT)  # the leaving delay cannot ride unchanged
    # Setting it moves both to one value, which a table can carry.
    assert table.with_delay(LEAVING, 0, 20).count_down(LEAVING) == CountDown((1, 0), 20)


@pytest.mark.parametrize(
    ("dump", "mode", "match"),
    [
        ({0: {1225: "x"}}, GuardMode.HOME, "not a non-negative integer"),
        ({0: {1225: "-1"}}, GuardMode.HOME, "not a non-negative integer"),
        ({0: {1225: "1"}}, GuardMode.SCHEDULE, "no action table"),
        ({0: {1225: "1"}}, GuardMode.DISARMED, "no action table"),
    ],
)
def test_from_params_refuses(
    dump: dict[int, dict[int, str | None]], mode: GuardMode, match: str
) -> None:
    with pytest.raises(UnsupportedError, match=match):
        mode_table_from_params(dump, mode)


def test_changes_refuse_devices_outside_the_table_and_bad_values() -> None:
    table = _home()
    with pytest.raises(UnsupportedError, match="channel 5 does not report its home action"):
        table.with_action(5, 1)
    with pytest.raises(UnsupportedError, match="param 1225"):
        table.with_delay(ALARM, 40, 30)
    with pytest.raises(ValueError, match="non-negative"):
        table.with_action(0, -1)
    with pytest.raises(ValueError, match="non-negative"):
        table.with_delay(ALARM, 0, True)
    with pytest.raises(ValueError, match="not a sub-device channel"):
        ModeTable(mode=GuardMode.HOME, actions={255: 1})
    with pytest.raises(ValueError, match="no action in the table"):
        ModeTable(mode=GuardMode.HOME, actions={0: 1}, alarm_delays={1: 30})


def test_applied_params_are_what_the_station_was_seen_to_write() -> None:
    request: dict[str, Any] = {
        "mode_id": 1,
        "devices": [{"device_channel": 16, "action": 0}, {"device_channel": 1, "action": 1}, "x"],
        "count_down_alarm": {"channel_list": [1, 0], "delay_time": 30},
        "count_down_arm": {"channel_list": [1], "delay_time": 30},
    }
    assert applied_params(request) == {
        16: {1225: 0, 1166: 0, 1171: 0},  # in devices, in no list: the station writes 0
        1: {1225: 1, 1166: 30, 1171: 30},
        0: {1166: 30},  # listed for the alarm delay, not in devices
    }
    with pytest.raises(UnsupportedError, match="mode_id 2"):
        applied_params({"mode_id": 2})
