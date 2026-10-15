from __future__ import annotations

import base64
import dataclasses
import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import Event, StationConfigChanged, StationStateChanged
from eufy_home_security.exceptions import ConfigChangedError, UnsupportedError
from eufy_home_security.models import GUARD_MODE_LABELS, GuardMode, ValueSource
from eufy_home_security.p2p.params import ParamDump
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station, StationState
from eufy_home_security.station_config import (
    MODE_ORDER,
    ModeDeviceAction,
    StationConfig,
    build_station_config,
    changed_fields,
    check_revision,
    guard_mode_label,
)
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)
CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    channel=0,
)


def b64(obj: object) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def mode_list(*entries: tuple[int, str, int]) -> str:
    """A 1256 value listing ``(mode, title, icon)`` entries."""
    modes = [{"iconType": icon, "mode": mode, "title": title} for mode, title, icon in entries]
    return b64({"account_id": SYNTHETIC.account_id, "mode_id": 3, "modes": modes})


def schedule(*slots: tuple[int, int, int, int]) -> str:
    """A 1254 value of ``(weekday, start hour, end hour, mode)`` slots."""
    return b64(
        {
            "account_id": SYNTHETIC.account_id,
            "schedules": [
                {"week": w, "start_h": s, "start_m": 0, "end_h": e, "end_m": 0, "mode_id": m}
                for w, s, e, m in slots
            ],
        }
    )


def _offline_station(
    sub_devices: tuple[CloudDevice, ...] = (CAMERA,), *, pn: str | None = None
) -> Station:
    async def no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("not connecting")

    session = StationSession(SYNTHETIC.station_sn, no_credentials, host=None)
    hub = STATION if pn is None else dataclasses.replace(STATION, raw={"device_new_pn": pn})
    return Station(hub, session, sub_devices=sub_devices)


def _cloud_entry(params: dict[int, str], *, pn: str | None = None) -> CloudDevice:
    """The hub's cloud device with ``params``; ``pn`` sets its product code."""
    raw: dict[str, Any] = {
        "params": [
            {"param_type": pid, "param_value": value, "update_time": 1.7e9}
            for pid, value in params.items()
        ]
    }
    if pn is not None:
        raw["device_new_pn"] = pn
    return dataclasses.replace(STATION, raw=raw)


def state_of(
    station: dict[int, str],
    *,
    cloud: dict[int, str] | None = None,
    blocks: dict[int, dict[int, str]] | None = None,
    pn: str | None = None,
) -> StationState:
    """The state of the synthetic hub from its own block, a cloud copy and device blocks;
    ``pn`` makes it a station of that product code."""
    st = _offline_station(pn=pn)
    if cloud is not None:
        st.apply_cloud_device(_cloud_entry(cloud, pn=pn))
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": dev, "param_type": pid, "param_value": value}
                for dev, params in {255: station, **(blocks or {})}.items()
                for pid, value in params.items()
            ]
        }
    )
    return st._state(dump)


def config_of(station: dict[int, str], **kwargs: Any) -> StationConfig:
    return build_station_config(state_of(station, **kwargs))


def names(config: StationConfig) -> list[tuple[GuardMode | int, str]]:
    return [(m.code, m.name) for m in config.modes]


# ── modes ────────────────────────────────────────────────────────────────────


def test_without_a_mode_list_the_station_has_the_built_in_modes() -> None:
    config = config_of({1224: "0"})
    assert names(config) == [
        (GuardMode.HOME, "Home"),
        (GuardMode.AWAY, "Away"),
        (GuardMode.DISARMED, "Disarmed"),
    ]
    assert config.settable_modes == (GuardMode.HOME, GuardMode.AWAY, GuardMode.DISARMED)
    assert config.sources["modes"] is ValueSource.APP_DEFAULT
    assert not config.is_defined(GuardMode.CUSTOM_2)


def test_a_custom_mode_is_defined_only_when_the_mode_list_names_it() -> None:
    """The cloud's 1256 lists Home, Away and Custom 1 with the user's title: Custom 2 and
    3 do not exist, and Custom 1 is set through 1224 like a built-in mode."""
    modes = mode_list((1, "Home", 1), (0, "Away", 0), (3, "Night watch", 6))
    config = config_of({1224: "1"}, cloud={1256: modes})

    assert names(config) == [
        (GuardMode.HOME, "Home"),
        (GuardMode.AWAY, "Away"),
        (GuardMode.CUSTOM_1, "Night watch"),
        (GuardMode.DISARMED, "Disarmed"),
    ]
    custom = config.mode(GuardMode.CUSTOM_1)
    assert custom is not None
    assert (custom.icon, custom.custom) == (6, True)
    home = config.mode(GuardMode.HOME)
    assert home is not None
    assert (home.icon, home.custom) == (1, False)
    assert config.mode(GuardMode.DISARMED) is not None
    assert config.mode(GuardMode.DISARMED).icon is None  # type: ignore[union-attr]
    assert GuardMode.CUSTOM_1 in config.settable_modes
    assert not config.is_defined(GuardMode.CUSTOM_2)
    assert not config.is_defined(GuardMode.CUSTOM_3)
    assert config.sources["modes"] is ValueSource.CLOUD
    assert config.mode_name(GuardMode.CUSTOM_1) == "Night watch"
    assert config.mode_name(GuardMode.CUSTOM_2) == "Custom 2"


def test_built_in_titles_are_fixed_and_an_untitled_custom_mode_gets_its_label() -> None:
    modes = mode_list((1, "Casa", 1), (4, "  ", 2))
    config = config_of({1224: "0", 1256: modes})
    assert names(config)[0] == (GuardMode.HOME, "Home")
    assert (GuardMode.CUSTOM_2, "Custom 2") in names(config)
    assert config.sources["modes"] is ValueSource.P2P


def test_a_custom_mode_the_station_is_in_is_defined_without_a_list() -> None:
    config = config_of({1224: "5"})
    assert config.mode_name(GuardMode.CUSTOM_3) == "Custom 3"
    assert GuardMode.CUSTOM_3 in config.settable_modes


@pytest.mark.parametrize(
    ("params", "defined"),
    [
        ({1224: "0"}, False),
        ({1224: "0", 1254: schedule()}, False),  # a schedule without a slot
        ({1224: "0", 1254: schedule((1, 8, 17, 0))}, True),
        ({1224: "2", 1151: "1"}, True),  # Schedule selected
    ],
)
def test_schedule_is_defined_by_a_slot_or_the_selection(
    params: dict[int, str], defined: bool
) -> None:
    config = config_of(params)
    assert config.is_defined(GuardMode.SCHEDULE) is defined
    assert (GuardMode.SCHEDULE in config.settable_modes) is defined


def test_geofencing_and_off_are_defined_only_while_reported_and_never_settable() -> None:
    assert not config_of({1224: "0"}).is_defined(GuardMode.GEOFENCE)
    assert not config_of({1224: "0"}).is_defined(GuardMode.OFF)

    geofence = config_of({1224: "47", 1151: "1"})
    assert geofence.mode_name(GuardMode.GEOFENCE) == "Geofencing"
    assert GuardMode.GEOFENCE not in geofence.settable_modes

    off = config_of({1224: "6"})
    assert off.is_defined(GuardMode.OFF)
    assert GuardMode.OFF not in off.settable_modes


def test_modes_follow_the_app_order() -> None:
    modes = mode_list((5, "C", 1), (3, "A", 1), (4, "B", 1))
    config = config_of({1224: "47", 1151: "6", 1256: modes, 1254: schedule((0, 1, 2, 1))})
    assert [m.code for m in config.modes] == list(MODE_ORDER)


def test_an_unknown_reported_code_is_listed_by_number_and_not_settable() -> None:
    config = config_of({1224: "9"})
    assert (9, "Mode 9") in names(config)
    assert 9 not in config.settable_modes


def test_an_undecodable_mode_list_leaves_the_built_ins_and_says_why() -> None:
    config = config_of({1224: "0", 1256: "not base64!"})
    assert [m.code for m in config.modes] == [GuardMode.HOME, GuardMode.AWAY, GuardMode.DISARMED]
    assert "1256" in config.unreadable["modes"]


def test_every_guard_mode_has_a_sentence_case_label() -> None:
    assert set(GUARD_MODE_LABELS) == set(GuardMode)
    assert GuardMode.GEOFENCE.label == "Geofencing"
    assert GuardMode.CUSTOM_1.label == "Custom 1"
    assert guard_mode_label(63) == "Disarmed"
    assert guard_mode_label(9) == "Mode 9"


# ── guard-mode writes ────────────────────────────────────────────────────────


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    await station.start()
    yield station
    station.stop()


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])
    yield st
    await st.async_close()


@pytest.mark.parametrize("mode", [GuardMode.CUSTOM_1, GuardMode.CUSTOM_2, GuardMode.CUSTOM_3])
async def test_a_custom_mode_is_set_through_1224(
    station: Station, fake: FakeStation, mode: GuardMode
) -> None:
    assert await station.async_set_guard_mode(mode.name.lower()) == mode
    assert fake.guard_mode == mode


# ── mode tables ──────────────────────────────────────────────────────────────


def stored_table(mode: int, actions: dict[int, int], *, alarm: tuple[list[int], int]) -> str:
    """A stored mode table (1157-1161, 1177) of ``actions`` with an alarm count-down."""
    devices = [{"device_channel": ch, "action": a} for ch, a in actions.items()]
    return b64(
        {
            "account_id": SYNTHETIC.account_id,
            "mode_id": mode,
            "devices": devices,
            "count_down_alarm": {"channel_list": alarm[0], "delay_time": alarm[1]},
            "count_down_arm": {"channel_list": [], "delay_time": 0},
            "siren_sensor_action": [{"device_channel": ch, "action": 0} for ch in actions],
        }
    )


CUSTOM_1_LISTED = mode_list((1, "Home", 1), (0, "Away", 0), (3, "Night watch", 6))


@pytest.mark.parametrize(
    ("serial", "action", "flags"),
    [
        ("T8910P0000000001", 8, {"notification", "motion_sensor_respond"}),
        ("T8910P0000000001", 32, set()),
        (SYNTHETIC.camera_sn, 33, {"record"}),
        (None, 40, {"notification"}),
    ],
)
def test_a_mode_entry_lists_react_to_motion_while_bit_32_is_clear(
    serial: str | None, action: int, flags: set[str]
) -> None:
    """Only a catalogued motion sensor reacts to motion; bit 32 set means it ignores it."""
    entry = ModeDeviceAction(
        channel=16, device_sn=serial, action=action, alarm_delay=0, leaving_delay=0
    )
    assert entry.flags == flags


def test_mode_tables_come_from_the_dump_else_the_stored_table() -> None:
    config = config_of(
        {1224: "0"},
        cloud={1256: CUSTOM_1_LISTED, 1157: stored_table(1, {0: 9}, alarm=([0], 30))},
        blocks={0: {1239: "5", 1167: "10", 1172: "0"}},
    )
    home = config.mode_tables[GuardMode.HOME]
    assert home is not None
    entry = home.device(SYNTHETIC.camera_sn)
    assert entry is not None
    assert (entry.channel, entry.action, entry.alarm_delay, entry.leaving_delay) == (0, 9, 30, 0)
    assert entry.flags == {"record", "notification"}
    assert config.sources["mode_tables.home"] is ValueSource.CLOUD

    away = config.mode_tables[GuardMode.AWAY]
    assert away is not None
    assert [(d.device_sn, d.action, d.alarm_delay) for d in away.devices] == [
        (SYNTHETIC.camera_sn, 5, 10)
    ]
    assert config.sources["mode_tables.away"] is ValueSource.P2P

    # Defined but never configured: no table, never an invented one.
    assert config.mode_tables[GuardMode.CUSTOM_1] is None
    assert config.mode_tables[GuardMode.DISARMED] is None
    assert "mode_tables.custom_1" not in config.sources
    # An undefined mode has no entry at all.
    assert set(config.mode_tables) == {
        GuardMode.HOME,
        GuardMode.AWAY,
        GuardMode.CUSTOM_1,
        GuardMode.DISARMED,
    }


def test_the_disarmed_table_comes_from_its_stored_param_only() -> None:
    config = config_of({1224: "63", 1177: stored_table(63, {0: 0}, alarm=([], 0))})
    disarmed = config.mode_tables[GuardMode.DISARMED]
    assert disarmed is not None
    assert [d.action for d in disarmed.devices] == [0]


def test_the_dump_table_wins_over_a_stale_stored_copy() -> None:
    """After a write the devices' parameters already hold the new mask; the stored copy
    in the cloud list still holds the old one."""
    config = config_of(
        {1224: "0"},
        cloud={1157: stored_table(1, {0: 9}, alarm=([0], 30))},
        blocks={0: {1225: "1"}},
    )
    home = config.mode_tables[GuardMode.HOME]
    assert home is not None
    assert [d.action for d in home.devices] == [1]
    assert config.sources["mode_tables.home"] is ValueSource.P2P


def test_an_undecodable_stored_table_without_a_dump_table_is_none_and_says_why() -> None:
    config = config_of({1224: "0", 1157: b64({"mode_id": 0})})
    assert config.mode_tables[GuardMode.HOME] is None
    assert "mode_tables.home" in config.unreadable


@pytest.mark.parametrize(
    "blocks",
    [
        {0: {1225: "-1"}},  # not a mask
        {300: {1225: "1"}},  # not a sub-device channel
    ],
)
def test_a_dump_table_that_cannot_be_built_is_none_and_says_why(
    blocks: dict[int, dict[int, str]],
) -> None:
    config = config_of({1224: "0"}, blocks=blocks)
    assert config.mode_tables[GuardMode.HOME] is None
    assert "mode_tables.home" in config.unreadable


def pro_alarm_table(mode: int, actions: dict[int, int], *, alarm: tuple[list[int], int]) -> str:
    """A pro-alarm station's stored table (61300-61309): the same document as
    :func:`stored_table`."""
    return stored_table(mode, actions, alarm=alarm)


def test_a_pro_alarm_station_reads_its_stored_tables_dump_first() -> None:
    """A T8024 whose devices report no per-mode params: Away from the dump's 61301, Home
    from the cloud's 61300; a HomeBase 3 copy (1157) is not its layout."""
    state = state_of(
        {1224: "0", 61301: pro_alarm_table(0, {0: 9}, alarm=([0], 30))},
        cloud={
            61301: pro_alarm_table(0, {0: 1}, alarm=([], 0)),
            61300: pro_alarm_table(1, {0: 143}, alarm=([], 0)),
            1157: stored_table(1, {0: 8}, alarm=([], 0)),
        },
        blocks={0: {1101: "87"}},
        pn="T8024",
    )
    config = build_station_config(state)
    away, home = config.mode_tables[GuardMode.AWAY], config.mode_tables[GuardMode.HOME]
    assert away is not None
    assert home is not None
    assert [(d.device_sn, d.action, d.alarm_delay) for d in away.devices] == [
        (SYNTHETIC.camera_sn, 9, 30)
    ]
    assert [d.action for d in home.devices] == [143]
    assert config.sources["mode_tables.away"] is ValueSource.P2P
    assert config.sources["mode_tables.home"] is ValueSource.CLOUD
    camera = SYNTHETIC.camera_sn
    assert state.setting("camera_action_away", device_sn=camera) == 9
    assert state.setting("camera_action_home", device_sn=camera) == 143
    with pytest.raises(UnsupportedError, match="alarm_delay_away"):
        state.setting("alarm_delay_away", device_sn=camera)  # the app offers no delays here
    assert state.setting("camera_action_custom_1", device_sn=camera) is None
    assert state.devices[0].params == {1101: "87"}  # the block itself is as reported


def test_a_pro_alarm_station_whose_devices_report_their_params_reads_those() -> None:
    """The layout the eufy app reads these models from: the devices' own params win."""
    state = state_of(
        {1224: "0", 61301: pro_alarm_table(0, {0: 9}, alarm=([0], 30))},
        blocks={0: {1239: "5", 1167: "10"}},
        pn="T8024",
    )
    away = build_station_config(state).mode_tables[GuardMode.AWAY]
    assert away is not None
    assert [(d.action, d.alarm_delay) for d in away.devices] == [(5, 10)]
    assert state.devices[0].stored_mode_params == {}
    assert state.setting("camera_action_away", device_sn=SYNTHETIC.camera_sn) == 5


def test_a_homebase_3_does_not_read_the_pro_alarm_params() -> None:
    """Its own stored copy (1158) gives the configuration's table, as before, but never
    the per-mode settings; 61301 is not its layout."""
    state = state_of(
        {1224: "0", 61301: pro_alarm_table(0, {0: 9}, alarm=([0], 30))},
        cloud={1158: stored_table(0, {0: 1}, alarm=([], 0))},
        blocks={0: {1101: "87"}},
    )
    away = build_station_config(state).mode_tables[GuardMode.AWAY]
    assert away is not None
    assert [d.action for d in away.devices] == [1]
    assert state.devices[0].stored_mode_params == {}
    assert state.setting("camera_action_away", device_sn=SYNTHETIC.camera_sn) is None


def test_an_undecodable_pro_alarm_table_is_none_and_says_why() -> None:
    state = state_of({1224: "0", 61301: b64({"mode_id": 0})}, blocks={0: {1101: "87"}}, pn="T8020")
    config = build_station_config(state)
    assert config.mode_tables[GuardMode.AWAY] is None
    assert "mode_tables.away" in config.unreadable
    assert state.setting("camera_action_away", device_sn=SYNTHETIC.camera_sn) is None


# ── schedule, cross-camera, settings ─────────────────────────────────────────


def test_schedule_and_its_default_mode() -> None:
    config = config_of({1224: "2", 1151: "0", 1257: "63"}, cloud={1254: schedule((1, 8, 17, 0))})
    assert config.schedule is not None
    assert [(s.weekday, s.mode) for s in config.schedule.slots] == [(1, GuardMode.AWAY)]
    assert config.schedule_default is GuardMode.DISARMED
    assert (config.guard_mode, config.effective_mode) == (GuardMode.SCHEDULE, GuardMode.AWAY)
    assert config.sources["schedule"] is ValueSource.CLOUD
    assert config.sources["schedule_default"] is ValueSource.P2P


def test_cross_camera_reads_the_settings_and_the_lists() -> None:
    other = "T8160P2000067891"
    config = config_of(
        {1224: "0", 1072: b64([SYNTHETIC.camera_sn]), 1073: b64([{"value": [other]}])},
        cloud={1065: "1"},
    )
    cross = config.cross_camera
    assert cross is not None
    assert (cross.enabled, cross.assistance) == (True, True)
    assert cross.cameras == (SYNTHETIC.camera_sn,)
    assert cross.groups == ((other,),)
    assert config.sources["cross_camera.enabled"] is ValueSource.CLOUD
    assert config.sources["cross_camera.assistance"] is ValueSource.APP_DEFAULT
    assert config.sources["cross_camera.cameras"] is ValueSource.P2P
    assert config.setting_keys["cross_camera.enabled"] == "device_cross_cam_tracking_swtich"


def test_cross_camera_lists_the_cameras_and_doorbells_tracking_can_follow() -> None:
    """By channel; a sensor, a keypad and a device of no catalogued model are left out."""
    doorbell = dataclasses.replace(CAMERA, device_sn="T8210P0000000001", device_type=7, channel=1)
    keypad = dataclasses.replace(CAMERA, device_sn="T8960P0000000001", device_type=4, channel=2)
    unknown = dataclasses.replace(CAMERA, device_sn="T0000P0000000001", device_type=0, channel=3)
    sensor = dataclasses.replace(CAMERA, device_sn="T8910P0000000001", device_type=10, channel=16)
    st = _offline_station((sensor, doorbell, unknown, CAMERA, keypad))
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": dev, "param_type": 1101, "param_value": "90"}
                for dev in (0, 1, 2, 3, 16)
            ]
            + [{"dev_type": 255, "param_type": 1224, "param_value": "0"}]
        }
    )
    cross = build_station_config(st._state(dump)).cross_camera
    assert cross is not None
    assert cross.eligible == (SYNTHETIC.camera_sn, doorbell.device_sn)
    assert st.cross_camera_eligible() == cross.eligible


@pytest.mark.parametrize(
    ("cloud", "option", "seconds"),
    [
        ({1070: "180"}, 1, 180),  # a HomeBase 3's cloud copy: option 1, the app's "3 min"
        ({1070: "1800"}, 6, 1800),
        ({}, 0, 120),  # unreported: the app's default, 2 min
        ({1070: "7"}, None, None),  # not an interval the model offers
    ],
)
def test_the_continuous_tracking_time_reads_as_its_option_and_in_seconds(
    cloud: dict[int, str], option: int | None, seconds: int | None
) -> None:
    state = state_of({1224: "0"}, cloud=cloud)
    config = build_station_config(state)
    cross = config.cross_camera
    assert cross is not None
    assert (cross.continuous_time, cross.continuous_time_s) == (option, seconds)
    setting = state.settings[config.setting_keys["cross_camera.continuous_time"]]
    if option is not None and seconds is not None:
        assert setting.label(option) == f"{seconds // 60} min"


def test_alarm_and_time_values_reuse_the_station_settings() -> None:
    config = config_of({1224: "0", 1235: "20", 1281: "2"})
    assert (config.alarm_volume, config.alarm_tone) == (20, 2)
    assert config.sources["alarm_volume"] is ValueSource.P2P
    assert config.setting_keys["alarm_tone"] == "alarm_tones_mode"
    assert config.setting_keys["time_zone"] == "timezone_set"
    assert config.time_format is None  # not reported and no default
    assert "time_format" not in config.sources


# ── revision ─────────────────────────────────────────────────────────────────


def test_the_revision_follows_the_content() -> None:
    params = {1224: "0", 1254: schedule((1, 8, 17, 0)), 1256: CUSTOM_1_LISTED}
    first, again = config_of(params), config_of(dict(params))
    assert first.revision == again.revision
    assert 0 <= first.revision < 2**53  # exact as a JSON number

    changed = config_of({**params, 1254: schedule((1, 8, 18, 0))})
    assert changed.revision != first.revision
    assert changed_fields(first, changed) == {"schedule"}
    assert changed_fields(None, first) >= {"modes", "schedule", "sources"}
    assert "revision" not in changed_fields(None, first)


def test_the_revision_is_the_same_in_another_process() -> None:
    """A revision survives a restart: no per-process hash seed goes into it."""
    code = (
        "import tests.test_station_config as t;"
        "print(t.config_of({1224: '0', 1256: t.CUSTOM_1_LISTED}).revision)"
    )
    revisions = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout.strip()
        for seed in ("1", "2")
    }
    assert revisions == {str(config_of({1224: "0", 1256: CUSTOM_1_LISTED}).revision)}


def test_check_revision_raises_with_the_fresh_config() -> None:
    config = config_of({1224: "0"})
    check_revision(config, None)
    check_revision(config, config.revision)
    with pytest.raises(ConfigChangedError) as caught:
        check_revision(config, config.revision + 1)
    assert caught.value.config is config
    assert caught.value.expected == config.revision + 1


# ── Station.async_get_config ─────────────────────────────────────────────────


async def test_get_config_reads_a_station_without_state_first(
    station: Station, fake: FakeStation
) -> None:
    fake.params[255][1256] = CUSTOM_1_LISTED
    assert station.config is None
    config = await station.async_get_config()
    assert config.guard_mode is GuardMode.DISARMED
    assert config.mode_name(GuardMode.CUSTOM_1) == "Night watch"
    assert station.config == config


async def test_get_config_refresh_reads_the_station_and_the_cloud_once(
    fake: FakeStation,
) -> None:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    calls: list[str] = []

    async def cloud_refresh() -> int:
        calls.append("cloud")
        st.apply_cloud_device(_cloud_entry({1254: schedule((2, 9, 10, 1))}))
        return 1

    st = Station(STATION, session, sub_devices=[CAMERA], cloud_refresh=cloud_refresh)
    try:
        before = await st.async_get_config()
        assert calls == []
        fake.params[255][1224] = "1"
        config = await st.async_get_config(refresh=True)
        assert calls == ["cloud"]
        assert config.guard_mode is GuardMode.HOME
        assert config.is_defined(GuardMode.SCHEDULE)
        assert config.revision != before.revision
    finally:
        await st.async_close()


async def test_a_write_s_revision_check_reads_fresh(station: Station, fake: FakeStation) -> None:
    assert await station._check_revision(None) is None
    config = await station.async_get_config()
    assert await station._check_revision(config.revision) == config

    fake.params[255][1254] = schedule((3, 6, 7, 0))  # changed elsewhere
    with pytest.raises(ConfigChangedError) as caught:
        await station._check_revision(config.revision)
    assert caught.value.config.is_defined(GuardMode.SCHEDULE)


# ── StationConfigChanged ─────────────────────────────────────────────────────


def _config_events(events: list[Event]) -> list[StationConfigChanged]:
    return [e for e in events if isinstance(e, StationConfigChanged)]


async def test_a_dump_that_changes_the_config_emits_once(
    station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    station.subscribe(events.append)
    first = await station.async_get_config()
    [initial] = _config_events(events)
    assert initial.revision == first.revision
    assert {"modes", "guard_mode"} <= initial.fields

    await station.async_update()  # nothing changed
    fake.params[0][1101] = "12"  # a battery level: state, not configuration
    await station.async_update()
    assert len(_config_events(events)) == 1
    assert len([e for e in events if isinstance(e, StationStateChanged)]) == 2

    fake.params[255][1256] = CUSTOM_1_LISTED
    await station.async_update()
    changed = _config_events(events)[-1]
    assert changed.fields == {"modes", "settable_modes", "mode_tables", "sources"}
    config = station.config
    assert config is not None
    assert changed.revision == config.revision != first.revision


async def test_a_cloud_refresh_that_changes_the_config_emits(station: Station) -> None:
    await station.async_update()
    events: list[Event] = []
    station.subscribe(events.append)

    station.apply_cloud_device(_cloud_entry({1254: schedule((0, 1, 2, 0))}))
    station.apply_cloud_device(_cloud_entry({1254: schedule((0, 1, 2, 0))}))  # no news
    assert [e.fields for e in _config_events(events)] == [
        {"modes", "settable_modes", "schedule", "sources"}
    ]
