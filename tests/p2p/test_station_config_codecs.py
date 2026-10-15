"""Station configuration codecs: 1256 modes, 1254/1257 schedule, stored mode tables, 1072/1073."""

from __future__ import annotations

import base64
import json
from datetime import time, timedelta, timezone
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from eufy_home_security.exceptions import ProtocolError, UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.mode_actions import MODE_TABLE_MODES, CountDown, ModeTable
from eufy_home_security.p2p.station_config_codecs import (
    BUILT_IN_MODE_TITLES,
    CUSTOM_MODES,
    MAX_DETAIL_LENGTH,
    MAX_TITLE_LENGTH,
    MODE_ICONS,
    PRO_ALARM_MODE_TABLE_PARAMS,
    SCHEDULE_MODES,
    STORED_MODE_TABLE_PARAMS,
    CustomModes,
    ModeDefinition,
    ModeOperation,
    Schedule,
    ScheduleSlot,
    StoredModeTable,
    Weekday,
    add_custom_mode,
    decode_custom_modes,
    decode_pro_alarm_mode_table,
    decode_schedule,
    decode_schedule_default,
    decode_stored_mode_table,
    decode_tracking_cameras,
    decode_tracking_groups,
    delete_custom_mode,
    encode_schedule_default,
    encode_stored_mode_table,
    encode_tracking_cameras,
    encode_tracking_groups,
    modify_custom_mode,
)
from eufy_home_security.testing import SYNTHETIC

ACCOUNT = SYNTHETIC.account_id
CAMERAS = tuple(SYNTHETIC.camera_sn[:-1] + str(n) for n in range(3))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _value(obj: object) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")))


# The app's style: compact, sorted keys, apostrophe escaped.
MODES_JSON = (
    '{"account_id":"' + ACCOUNT + '","mode_id":3,"modes":['
    '{"detail":"Enable when you\\u0027re at home","iconType":0,"mode":1,"mode_action":0,'
    '"title":"Home"},'
    '{"detail":"Enable when you leave your home","iconType":1,"mode":0,"mode_action":0,'
    '"title":"Away"},'
    '{"detail":"","iconType":6,"mode":3,"mode_action":50331657,"title":"Night"}'
    '],"operate_type":100}'
)
MODES_RAW = _b64(MODES_JSON)


def _modes() -> CustomModes:
    modes = decode_custom_modes(MODES_RAW)
    assert modes is not None
    return modes


# --- 1256 -------------------------------------------------------------------


def test_custom_modes_decode_and_round_trip() -> None:
    modes = _modes()
    assert modes.account_id == ACCOUNT
    assert modes.mode_id is GuardMode.CUSTOM_1
    assert modes.operate_type == ModeOperation.ADD
    assert modes.modes[0] == ModeDefinition(
        mode=GuardMode.HOME,
        title="Home",
        icon_type=0,
        detail="Enable when you're at home",
        mode_action=0,
    )
    assert modes.get(GuardMode.CUSTOM_2) is None
    assert modes.param_value() == MODES_RAW
    assert decode_custom_modes(f"\n {MODES_RAW}\t") == modes


def test_titles_fix_built_ins_and_list_only_existing_custom_modes() -> None:
    doc = json.loads(MODES_JSON)
    doc["modes"][0]["title"] = "Renamed"
    del doc["modes"][1]  # Away absent: still offered
    modes = decode_custom_modes(_value(doc))
    assert modes is not None
    assert modes.titles() == {
        GuardMode.HOME: "Home",
        GuardMode.AWAY: "Away",
        GuardMode.CUSTOM_1: "Night",
        GuardMode.DISARMED: "Disarmed",
    }
    assert modes.custom_modes() == (GuardMode.CUSTOM_1,)
    assert modes.defined_modes() == {*BUILT_IN_MODE_TITLES, GuardMode.CUSTOM_1}


def test_custom_modes_keep_absent_and_unknown_keys() -> None:
    text = '{"modes":[{"iconType":2,"mode":4,"title":"Shed","zone":[1,2]}]}'
    modes = decode_custom_modes(_b64(text))
    assert modes is not None
    assert (modes.account_id, modes.mode_id, modes.operate_type) == (None, None, None)
    entry = modes.modes[0]
    assert (entry.detail, entry.mode_action, dict(entry.extra)) == (None, None, {"zone": [1, 2]})
    assert modes.param_value() == _b64(text)


@pytest.mark.parametrize("raw", [None, "", "  \n"])
def test_absent_values_decode_to_none(raw: str | None) -> None:
    assert decode_custom_modes(raw) is None
    assert decode_schedule(raw) is None
    assert decode_schedule_default(raw) is None
    assert decode_stored_mode_table(raw) is None
    assert decode_tracking_cameras(raw) is None
    assert decode_tracking_groups(raw) == ()


@pytest.mark.parametrize(
    "raw",
    [
        "not base64!",
        "QUJD",  # "ABC": not JSON
        _b64("[]"),
        _b64('{"account_id":"a"}'),
        _value({"modes": [{"mode": 9, "title": "x", "iconType": 0}]}),
        _value({"modes": [{"mode": 3, "title": "x", "iconType": 0}] * 2}),
        _value({"modes": [{"mode": 3, "title": 5, "iconType": 0}]}),
        _value({"modes": [{"mode": 3, "title": "x"}]}),
        _value({"modes": [{"mode": 3, "title": "x", "iconType": 0, "mode_action": 1.5}]}),
        _value({"modes": [], "mode_id": 99}),
    ],
)
def test_custom_modes_reject_undecodable_input(raw: str) -> None:
    with pytest.raises(ProtocolError):
        decode_custom_modes(raw)


def test_non_string_value_is_a_protocol_error() -> None:
    with pytest.raises(ProtocolError):
        decode_custom_modes(5)  # type: ignore[arg-type]


def test_add_takes_the_first_free_custom_mode_and_builds_the_app_body() -> None:
    doc = json.loads(MODES_JSON)
    doc["modes"].append({"iconType": 9, "mode": 63, "title": "Disarmed"})
    current = decode_custom_modes(_value(doc))
    assert current is not None
    added = add_custom_mode(current, account_id=ACCOUNT, title="  Garden ", icon_type=4)
    assert added.operate_type == ModeOperation.ADD
    assert added.mode_id is GuardMode.CUSTOM_2
    assert [m.mode for m in added.modes] == [
        GuardMode.HOME,
        GuardMode.AWAY,
        GuardMode.CUSTOM_1,
        GuardMode.CUSTOM_2,
    ]
    assert added.body() == (
        MODES_JSON.replace('"mode_id":3', '"mode_id":4')
        .replace(
            "}],",
            '},{"detail":"","iconType":4,"mode":4,"mode_action":67108873,"title":"Garden"}],',
        )
        .encode()
    )
    assert added.param_value() == base64.b64encode(added.body()).decode()


def test_add_to_an_absent_list_and_to_a_chosen_mode() -> None:
    added = add_custom_mode(
        None, account_id=ACCOUNT, title="Lake", icon_type=1, mode=GuardMode.CUSTOM_3
    )
    assert added.modes == (
        ModeDefinition(
            mode=GuardMode.CUSTOM_3,
            title="Lake",
            icon_type=1,
            detail="",
            mode_action=5 << 24 | 9,
        ),
    )
    assert added.titles()[GuardMode.CUSTOM_3] == "Lake"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"title": ""}, "empty"),
        ({"title": "   "}, "empty"),
        ({"title": "x" * (MAX_TITLE_LENGTH + 1)}, "at most"),
        ({"title": "Night"}, "already used"),
        ({"title": "Away"}, "already used"),
        ({"title": "Disarmed"}, "already used"),
        ({"detail": "d" * (MAX_DETAIL_LENGTH + 1)}, "at most"),
        ({"icon_type": -1}, "icon is 0 to 7"),
        ({"icon_type": MODE_ICONS}, "icon is 0 to 7"),
        ({"mode": GuardMode.CUSTOM_1}, "already exists"),
        ({"mode": GuardMode.HOME}, "only custom modes"),
        ({"mode": 2}, "only custom modes"),
        ({"mode": 8}, "unknown guard mode"),
    ],
)
def test_add_refuses(kwargs: dict[str, Any], match: str) -> None:
    args: dict[str, Any] = {"account_id": ACCOUNT, "title": "Garden", "icon_type": 0, **kwargs}
    with pytest.raises(ValueError, match=match):
        add_custom_mode(_modes(), **args)


def test_add_refuses_beyond_custom_3() -> None:
    full = _modes()
    for title in ("B", "C"):
        full = add_custom_mode(full, account_id=ACCOUNT, title=title, icon_type=0)
    assert full.custom_modes() == CUSTOM_MODES
    with pytest.raises(ValueError, match="all three"):
        add_custom_mode(full, account_id=ACCOUNT, title="D", icon_type=0)


def test_modify_replaces_only_the_given_fields() -> None:
    changed = modify_custom_mode(_modes(), GuardMode.CUSTOM_1, account_id=ACCOUNT, title="Late")
    assert changed.operate_type == ModeOperation.MODIFY
    assert changed.mode_id is GuardMode.CUSTOM_1
    entry = changed.get(GuardMode.CUSTOM_1)
    assert entry is not None
    assert (entry.title, entry.icon_type, entry.detail, entry.mode_action) == (
        "Late",
        6,
        "",
        50331657,
    )
    assert changed.modes[:2] == _modes().modes[:2]
    same = modify_custom_mode(_modes(), 3, account_id=ACCOUNT, title="Night", icon_type=2)
    assert same.titles()[GuardMode.CUSTOM_1] == "Night"


@pytest.mark.parametrize(
    ("mode", "title", "match"),
    [
        (GuardMode.HOME, "x", "only custom modes"),
        (GuardMode.CUSTOM_2, "x", "does not exist"),
        (GuardMode.CUSTOM_1, " ", "empty"),
        (GuardMode.CUSTOM_1, "Home", "already used"),
    ],
)
def test_modify_refuses(mode: GuardMode, title: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        modify_custom_mode(_modes(), mode, account_id=ACCOUNT, title=title)


def test_delete_writes_the_list_without_the_mode() -> None:
    deleted = delete_custom_mode(_modes(), GuardMode.CUSTOM_1, account_id=ACCOUNT)
    assert deleted.operate_type == ModeOperation.DELETE
    assert deleted.mode_id is GuardMode.CUSTOM_1
    assert deleted.modes == _modes().modes[:2]
    assert json.loads(deleted.body())["operate_type"] == 101


@pytest.mark.parametrize(
    ("mode", "match"),
    [
        (GuardMode.HOME, "only custom modes"),
        (GuardMode.AWAY, "only custom modes"),
        (GuardMode.DISARMED, "only custom modes"),
        (GuardMode.CUSTOM_3, "does not exist"),
    ],
)
def test_delete_refuses(mode: GuardMode, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        delete_custom_mode(_modes(), mode, account_id=ACCOUNT)


def test_delete_refuses_a_mode_the_schedule_uses() -> None:
    schedule = Schedule(
        account_id=ACCOUNT,
        slots=(ScheduleSlot(Weekday.MONDAY, time(8), time(9), GuardMode.CUSTOM_1),),
    )
    with pytest.raises(ValueError, match="schedule"):
        delete_custom_mode(_modes(), GuardMode.CUSTOM_1, account_id=ACCOUNT, schedule=schedule)


def test_body_escapes_like_the_app_and_keeps_utf8() -> None:
    added = add_custom_mode(None, account_id=ACCOUNT, title="A<b>&c='d' ü", icon_type=0)
    body = added.body()
    assert b'"title":"A\\u003cb\\u003e\\u0026c\\u003d\\u0027d\\u0027 \xc3\xbc"' in body
    assert decode_custom_modes(added.param_value()) == added


_titles = st.text(st.characters(codec="utf-8"), min_size=1, max_size=30).filter(
    lambda t: t.strip() == t and t not in BUILT_IN_MODE_TITLES.values()
)


@given(
    st.dictionaries(st.sampled_from(CUSTOM_MODES), st.tuples(_titles, st.integers(0, 20))),
    st.text(max_size=60),
)
def test_custom_modes_round_trip(entries: dict[GuardMode, tuple[str, int]], detail: str) -> None:
    modes = CustomModes(
        account_id=ACCOUNT,
        mode_id=GuardMode.HOME,
        operate_type=ModeOperation.MODIFY,
        modes=tuple(
            ModeDefinition(mode=m, title=t, icon_type=i, detail=detail)
            for m, (t, i) in entries.items()
        ),
    )
    raw = modes.param_value()
    decoded = decode_custom_modes(raw)
    assert decoded is not None
    assert decoded == modes
    assert decoded.param_value() == raw


# --- 1254 / 1257 --------------------------------------------------------------

SCHEDULE_JSON = (
    '{"account_id":"' + ACCOUNT + '","schedules":['
    '{"end_h":17,"end_m":10,"mode_id":0,"start_h":7,"start_m":50,"week":1},'
    '{"end_h":23,"end_m":59,"mode_id":1,"start_h":17,"start_m":10,"week":1},'
    '{"end_h":12,"end_m":0,"mode_id":3,"start_h":0,"start_m":0,"week":0}]}'
)


def test_schedule_decode_and_round_trip() -> None:
    raw = _b64(SCHEDULE_JSON)
    schedule = decode_schedule(raw)
    assert schedule is not None
    assert schedule.account_id == ACCOUNT
    assert schedule.slots == (
        ScheduleSlot(Weekday.MONDAY, time(7, 50), time(17, 10), GuardMode.AWAY),
        ScheduleSlot(Weekday.MONDAY, time(17, 10), time(23, 59), GuardMode.HOME),
        ScheduleSlot(Weekday.SUNDAY, time(0), time(12), GuardMode.CUSTOM_1),
    )
    assert schedule.modes() == {GuardMode.AWAY, GuardMode.HOME, GuardMode.CUSTOM_1}
    assert schedule.param_value() == raw
    assert schedule.body() == SCHEDULE_JSON.encode()


def test_slot_converts_integer_codes() -> None:
    slot = ScheduleSlot(6, time(1), time(2), 63)  # type: ignore[arg-type]
    assert (slot.weekday, slot.mode) == (Weekday.SATURDAY, GuardMode.DISARMED)


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ((1, time(9), time(9), 0), "start before"),
        ((1, time(10), time(9), 0), "start before"),
        ((1, time(8), time(9), GuardMode.SCHEDULE), "cannot use"),
        ((1, time(8), time(9), GuardMode.GEOFENCE), "cannot use"),
        ((1, time(8), time(9), GuardMode.OFF), "cannot use"),
        ((1, time(8), time(9), 99), "unknown guard mode"),
        ((7, time(8), time(9), 0), "weekday"),
        ((True, time(8), time(9), 0), "weekday"),
        ((1, time(8, 0, 30), time(9), 0), "whole minute"),
        ((1, time(8, tzinfo=timezone(timedelta(hours=3))), time(9), 0), "whole minute"),
        ((1, "08:00", time(9), 0), "datetime.time"),
    ],
)
def test_slot_refuses(args: tuple[Any, ...], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        ScheduleSlot(*args)


def test_schedule_refuses_overlapping_slots_of_a_weekday() -> None:
    first = ScheduleSlot(Weekday.TUESDAY, time(8), time(12), GuardMode.AWAY)
    touching = ScheduleSlot(Weekday.TUESDAY, time(12), time(13), GuardMode.HOME)
    other_day = ScheduleSlot(Weekday.WEDNESDAY, time(9), time(10), GuardMode.HOME)
    Schedule(account_id=ACCOUNT, slots=(first, touching, other_day))
    overlap = ScheduleSlot(Weekday.TUESDAY, time(11, 59), time(14), GuardMode.HOME)
    with pytest.raises(ValueError, match="overlap on tuesday"):
        Schedule(account_id=ACCOUNT, slots=(first, overlap))


def test_schedule_require_defined() -> None:
    schedule = decode_schedule(_b64(SCHEDULE_JSON))
    assert schedule is not None
    schedule.require_defined(_modes().defined_modes())
    without_custom = delete_custom_mode(_modes(), GuardMode.CUSTOM_1, account_id=ACCOUNT)
    with pytest.raises(ValueError, match="custom_1"):
        schedule.require_defined(without_custom.defined_modes())


@pytest.mark.parametrize(
    "slot",
    [
        {"end_h": 24, "end_m": 0, "mode_id": 0, "start_h": 8, "start_m": 0, "week": 1},
        {"end_h": 9, "end_m": 0, "mode_id": 0, "start_h": 8, "start_m": 0, "week": 7},
        {"end_h": 9, "end_m": 0, "mode_id": 47, "start_h": 8, "start_m": 0, "week": 1},
        {"end_h": 8, "end_m": 0, "mode_id": 0, "start_h": 9, "start_m": 0, "week": 1},
        {"end_h": 9, "end_m": 0, "start_h": 8, "start_m": 0, "week": 1},
        "slot",
    ],
)
def test_schedule_rejects_bad_slots(slot: object) -> None:
    with pytest.raises(ProtocolError):
        decode_schedule(_value({"account_id": ACCOUNT, "schedules": [slot]}))


def test_schedule_rejects_overlapping_slots_in_data() -> None:
    slot = {"end_h": 9, "end_m": 0, "mode_id": 0, "start_h": 8, "start_m": 0, "week": 1}
    with pytest.raises(ProtocolError, match="overlap"):
        decode_schedule(_value({"schedules": [slot, slot]}))


@given(
    st.lists(
        st.tuples(
            st.sampled_from(list(Weekday)),
            st.integers(0, 1438),
            st.integers(1, 1439),
            st.sampled_from(SCHEDULE_MODES),
        ),
        max_size=12,
    )
)
def test_schedule_round_trip(raw_slots: list[tuple[Weekday, int, int, GuardMode]]) -> None:
    slots: list[ScheduleSlot] = []
    for day, start, length, mode in raw_slots:
        end = min(start + length, 1439)
        slot = ScheduleSlot(day, time(*divmod(start, 60)), time(*divmod(end, 60)), mode)
        if not any(slot.overlaps(other) for other in slots):
            slots.append(slot)
    schedule = Schedule(account_id=ACCOUNT, slots=tuple(slots))
    raw = schedule.param_value()
    decoded = decode_schedule(raw)
    assert decoded is not None
    assert decoded == schedule
    assert decoded.param_value() == raw


@pytest.mark.parametrize(
    ("raw", "mode"), [("63", GuardMode.DISARMED), (" 3 ", GuardMode.CUSTOM_1), (0, GuardMode.AWAY)]
)
def test_schedule_default_decodes(raw: str | int, mode: GuardMode) -> None:
    assert decode_schedule_default(raw) is mode
    assert encode_schedule_default(mode) == int(mode)


@pytest.mark.parametrize("raw", ["x", "2", "47", "1.0", "99"])
def test_schedule_default_rejects(raw: str) -> None:
    with pytest.raises(ProtocolError):
        decode_schedule_default(raw)


@pytest.mark.parametrize("mode", [GuardMode.SCHEDULE, GuardMode.GEOFENCE, GuardMode.OFF, 9])
def test_schedule_default_refuses_to_encode(mode: GuardMode | int) -> None:
    with pytest.raises(ValueError, match="schedule default"):
        encode_schedule_default(mode)


# --- stored mode tables -------------------------------------------------------

# Shaped like the 1255 body: two cameras (1, 0) and a sensor (16), channels highest first.
TABLE: dict[str, Any] = {
    "account_id": ACCOUNT,
    "mode_id": 1,
    "devices": [
        {"device_channel": 16, "action": 8},
        {"device_channel": 1, "action": 9},
        {"device_channel": 0, "action": 143},
    ],
    "count_down_alarm": {"channel_list": [1, 0], "delay_time": 30},
    "count_down_arm": {"channel_list": [], "delay_time": 0},
    "siren_sensor_action": [
        {"device_channel": 16, "action": 0},
        {"device_channel": 1, "action": 0},
        {"device_channel": 0, "action": 0},
    ],
}


def _table(**changes: Any) -> str:
    return _value({**TABLE, **changes})


def test_stored_table_params_cover_every_writable_mode_and_disarmed() -> None:
    assert set(STORED_MODE_TABLE_PARAMS) == {*MODE_TABLE_MODES, GuardMode.DISARMED}
    assert len(set(STORED_MODE_TABLE_PARAMS.values())) == len(STORED_MODE_TABLE_PARAMS)


def test_stored_table_decodes_round_trips_and_matches_the_1255_body() -> None:
    raw = _table()
    table = decode_stored_mode_table(raw, GuardMode.HOME)
    assert table is not None
    assert table == StoredModeTable(
        account_id=ACCOUNT,
        mode=GuardMode.HOME,
        actions={16: 8, 1: 9, 0: 143},
        alarm=CountDown((1, 0), 30),
        arm=CountDown((), 0),
        siren_actions={16: 0, 1: 0, 0: 0},
    )
    assert table.param == 1157
    assert table.param_value() == raw
    assert table.alarm_delays() == {16: 0, 1: 30, 0: 30}
    assert table.leaving_delays() == {16: 0, 1: 0, 0: 0}
    mode_table = table.to_mode_table()
    assert mode_table.same_values(
        ModeTable(
            mode=GuardMode.HOME,
            actions={16: 8, 1: 9, 0: 143},
            alarm_delays={16: 0, 1: 30, 0: 30},
            leaving_delays={16: 0, 1: 0, 0: 0},
        )
    )
    assert mode_table.request(ACCOUNT) == TABLE


def test_disarmed_table_reads_but_has_no_1255_table() -> None:
    table = decode_stored_mode_table(_table(mode_id=63), GuardMode.DISARMED)
    assert table is not None
    assert table.param == 1177
    with pytest.raises(UnsupportedError):
        table.to_mode_table()


def test_stored_table_without_account_or_siren_list() -> None:
    doc = {k: v for k, v in TABLE.items() if k not in ("account_id", "siren_sensor_action")}
    table = decode_stored_mode_table(_value(doc))
    assert table is not None
    assert (table.account_id, dict(table.siren_actions)) == (None, {})


@pytest.mark.parametrize(
    "raw",
    [
        _table(mode_id=0),  # expected Home
        _table(mode_id=2),
        _table(mode_id="x"),
        _table(devices=[{"device_channel": 1, "action": 1}] * 2),
        _table(devices=[{"device_channel": -1, "action": 1}]),
        _table(devices={"device_channel": 1}),
        _table(count_down_alarm={"channel_list": [1], "delay_time": -5}),
        _table(count_down_arm={"channel_list": ["a"], "delay_time": 0}),
        _table(count_down_arm=None),
        _b64("{"),
    ],
)
def test_stored_table_rejects(raw: str) -> None:
    with pytest.raises(ProtocolError):
        decode_stored_mode_table(raw, GuardMode.HOME)


# --- 61300-61309: pro-alarm stored mode tables --------------------------------

HANDLER_BODY: dict[str, Any] = {
    "account_id": ACCOUNT,
    "devices": [{"device_channel": 1, "action": 9}, {"device_channel": 0, "action": 143}],
    "count_down_alarm": {"channel_list": [0], "delay_time": 30},
    "count_down_arm": {"channel_list": [1, 0], "delay_time": 60},
    "siren_sensor_action": [
        {"device_channel": 1, "action": 0},
        {"device_channel": 0, "action": 0},
    ],
}
"""The ``arming_config`` payload sent to the handler; ``mode_id`` is added per mode."""

# The 61300-61309 values a T8024 handler files after an `arming_config` write of
# HANDLER_BODY (mode_id set per mode), for each mode.
HANDLER_STORED: dict[int, str] = {
    61301: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjAsImRldmljZXMiOlt7ImRldmljZV9jaGFubmVsIjoxLCJhY3Rpb24iOjl9LHsi"
        "ZGV2aWNlX2NoYW5uZWwiOjAsImFjdGlvbiI6MTQzfV0sImNvdW50X2Rvd25fYWxhcm0iOnsiY2hh"
        "bm5lbF9saXN0IjpbMF0sImRlbGF5X3RpbWUiOjMwfSwiY291bnRfZG93bl9hcm0iOnsiY2hhbm5l"
        "bF9saXN0IjpbMSwwXSwiZGVsYXlfdGltZSI6NjB9LCJzaXJlbl9zZW5zb3JfYWN0aW9uIjpbeyJk"
        "ZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjowfSx7ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24i"
        "OjB9XX0="
    ),
    61300: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjEsImRldmljZXMiOlt7ImRldmljZV9jaGFubmVsIjoxLCJhY3Rpb24iOjl9LHsi"
        "ZGV2aWNlX2NoYW5uZWwiOjAsImFjdGlvbiI6MTQzfV0sImNvdW50X2Rvd25fYWxhcm0iOnsiY2hh"
        "bm5lbF9saXN0IjpbMF0sImRlbGF5X3RpbWUiOjMwfSwiY291bnRfZG93bl9hcm0iOnsiY2hhbm5l"
        "bF9saXN0IjpbMSwwXSwiZGVsYXlfdGltZSI6NjB9LCJzaXJlbl9zZW5zb3JfYWN0aW9uIjpbeyJk"
        "ZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjowfSx7ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24i"
        "OjB9XX0="
    ),
    61307: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjMsImRldmljZXMiOlt7ImRldmljZV9jaGFubmVsIjoxLCJhY3Rpb24iOjl9LHsi"
        "ZGV2aWNlX2NoYW5uZWwiOjAsImFjdGlvbiI6MTQzfV0sImNvdW50X2Rvd25fYWxhcm0iOnsiY2hh"
        "bm5lbF9saXN0IjpbMF0sImRlbGF5X3RpbWUiOjMwfSwiY291bnRfZG93bl9hcm0iOnsiY2hhbm5l"
        "bF9saXN0IjpbMSwwXSwiZGVsYXlfdGltZSI6NjB9LCJzaXJlbl9zZW5zb3JfYWN0aW9uIjpbeyJk"
        "ZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjowfSx7ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24i"
        "OjB9XX0="
    ),
    61308: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjQsImRldmljZXMiOlt7ImRldmljZV9jaGFubmVsIjoxLCJhY3Rpb24iOjl9LHsi"
        "ZGV2aWNlX2NoYW5uZWwiOjAsImFjdGlvbiI6MTQzfV0sImNvdW50X2Rvd25fYWxhcm0iOnsiY2hh"
        "bm5lbF9saXN0IjpbMF0sImRlbGF5X3RpbWUiOjMwfSwiY291bnRfZG93bl9hcm0iOnsiY2hhbm5l"
        "bF9saXN0IjpbMSwwXSwiZGVsYXlfdGltZSI6NjB9LCJzaXJlbl9zZW5zb3JfYWN0aW9uIjpbeyJk"
        "ZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjowfSx7ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24i"
        "OjB9XX0="
    ),
    61309: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjUsImRldmljZXMiOlt7ImRldmljZV9jaGFubmVsIjoxLCJhY3Rpb24iOjl9LHsi"
        "ZGV2aWNlX2NoYW5uZWwiOjAsImFjdGlvbiI6MTQzfV0sImNvdW50X2Rvd25fYWxhcm0iOnsiY2hh"
        "bm5lbF9saXN0IjpbMF0sImRlbGF5X3RpbWUiOjMwfSwiY291bnRfZG93bl9hcm0iOnsiY2hhbm5l"
        "bF9saXN0IjpbMSwwXSwiZGVsYXlfdGltZSI6NjB9LCJzaXJlbl9zZW5zb3JfYWN0aW9uIjpbeyJk"
        "ZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjowfSx7ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24i"
        "OjB9XX0="
    ),
    61306: (
        "eyJhY2NvdW50X2lkIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIs"
        "Im1vZGVfaWQiOjYzLCJkZXZpY2VzIjpbeyJkZXZpY2VfY2hhbm5lbCI6MSwiYWN0aW9uIjo5fSx7"
        "ImRldmljZV9jaGFubmVsIjowLCJhY3Rpb24iOjE0M31dLCJjb3VudF9kb3duX2FsYXJtIjp7ImNo"
        "YW5uZWxfbGlzdCI6WzBdLCJkZWxheV90aW1lIjozMH0sImNvdW50X2Rvd25fYXJtIjp7ImNoYW5u"
        "ZWxfbGlzdCI6WzEsMF0sImRlbGF5X3RpbWUiOjYwfSwic2lyZW5fc2Vuc29yX2FjdGlvbiI6W3si"
        "ZGV2aWNlX2NoYW5uZWwiOjEsImFjdGlvbiI6MH0seyJkZXZpY2VfY2hhbm5lbCI6MCwiYWN0aW9u"
        "IjowfV19"
    ),
}


def test_pro_alarm_params_cover_every_writable_mode_and_disarmed() -> None:
    assert set(PRO_ALARM_MODE_TABLE_PARAMS) == set(STORED_MODE_TABLE_PARAMS)
    assert sorted(PRO_ALARM_MODE_TABLE_PARAMS.values()) == sorted(HANDLER_STORED)
    assert not set(PRO_ALARM_MODE_TABLE_PARAMS.values()) & set(STORED_MODE_TABLE_PARAMS.values())


@pytest.mark.parametrize("mode", list(PRO_ALARM_MODE_TABLE_PARAMS))
def test_pro_alarm_table_decodes_the_handlers_value(mode: GuardMode) -> None:
    """Each value the app files is the base64 of the compact 1255 body; it decodes to the
    table, re-encodes byte for byte and is what the library's own write of it stores."""
    param = PRO_ALARM_MODE_TABLE_PARAMS[mode]
    raw = HANDLER_STORED[param]
    table = decode_pro_alarm_mode_table(raw, mode)
    assert table is not None
    assert (table.param, table.account_id, dict(table.actions)) == (param, ACCOUNT, {1: 9, 0: 143})
    assert table.alarm_delays() == {1: 0, 0: 30}
    assert table.leaving_delays() == {1: 60, 0: 60}
    assert table.param_value() == raw
    body = {"account_id": ACCOUNT, "mode_id": int(mode), **HANDLER_BODY}
    assert encode_stored_mode_table(json.dumps(body, separators=(",", ":")).encode()) == raw
    if mode in MODE_TABLE_MODES:
        assert encode_stored_mode_table(table.to_mode_table().encode(ACCOUNT)) == raw


def test_pro_alarm_table_ignores_the_apps_extra_keys() -> None:
    doc = {
        **HANDLER_BODY,
        "mode_id": 0,
        "auto_camera_action": [],
        "count_down_pro_alarm": {"channel_list": [], "delay_time": 0},
        "method": 0,
    }
    table = decode_pro_alarm_mode_table(_value(doc), GuardMode.AWAY)
    assert table is not None
    assert (table.param, dict(table.actions)) == (61301, {1: 9, 0: 143})


@pytest.mark.parametrize(
    ("raw", "mode"),
    [
        (_value({**HANDLER_BODY, "mode_id": 1}), GuardMode.AWAY),
        (_value({**HANDLER_BODY, "mode_id": 6}), None),
        (_value({**HANDLER_BODY, "mode_id": 1, "count_down_arm": None}), None),
        (_b64("[]"), None),
    ],
)
def test_pro_alarm_table_rejects(raw: str, mode: GuardMode | None) -> None:
    with pytest.raises(ProtocolError):
        decode_pro_alarm_mode_table(raw, mode)


# --- 1072 / 1073 -------------------------------------------------------------


def test_tracking_cameras_round_trip() -> None:
    raw = _b64('["' + '","'.join(CAMERAS) + '"]')
    assert decode_tracking_cameras(f" {raw}\n") == CAMERAS
    assert encode_tracking_cameras(CAMERAS) == raw
    assert decode_tracking_cameras(encode_tracking_cameras([])) == ()


def test_tracking_groups_round_trip() -> None:
    raw = _b64('[{"value":["' + '","'.join(CAMERAS) + '"]},{"value":["' + CAMERAS[0] + '"]}]')
    groups = decode_tracking_groups(raw)
    assert groups == (CAMERAS, (CAMERAS[0],))
    assert encode_tracking_groups(groups) == raw


@pytest.mark.parametrize("doc", [{"value": CAMERAS}, [1, 2], [""], ["a", None], "x"], ids=repr)
def test_tracking_cameras_reject(doc: object) -> None:
    with pytest.raises(ProtocolError):
        decode_tracking_cameras(_value(doc))


@pytest.mark.parametrize("doc", [CAMERAS, [{"members": []}], [{"value": [3]}], {}], ids=repr)
def test_tracking_groups_reject(doc: object) -> None:
    with pytest.raises(ProtocolError):
        decode_tracking_groups(_value(doc))


@pytest.mark.parametrize(
    ("serials", "match"),
    [(CAMERAS[0], "not one string"), ([CAMERAS[0]] * 2, "twice"), ([""], "non-empty")],
)
def test_tracking_encoders_refuse(serials: Any, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        encode_tracking_cameras(serials)
    with pytest.raises(ValueError, match=match):
        encode_tracking_groups([serials])


@given(st.lists(st.lists(st.text(min_size=1).filter(str.strip), unique=True), max_size=4))
def test_tracking_round_trip(groups: list[list[str]]) -> None:
    raw = encode_tracking_groups(groups)
    assert decode_tracking_groups(raw) == tuple(tuple(g) for g in groups)
    assert encode_tracking_groups(decode_tracking_groups(raw)) == raw
    flat = list(dict.fromkeys(s for g in groups for s in g))
    assert decode_tracking_cameras(encode_tracking_cameras(flat)) == tuple(flat)
