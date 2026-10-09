from __future__ import annotations

import base64
import json

import pytest

from eufy_home_security.devices.settings import (
    DUAL_VIEW,
    MODE_ACTION_FLAGS,
    MODE_TABLE_SETTINGS,
    SCOPE_DEFAULT_CHANNEL,
    Scope,
    SettingKind,
    SettingUnit,
    mode_action_flags,
    mode_action_key,
    mode_delay_key,
    mode_table_setting,
    report_value,
    scope_for_kind,
)
from eufy_home_security.devices.types import DeviceKind
from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.mode_actions import (
    ACTION_FLAGS,
    FIELD_PARAMS,
    MODE_TABLE_MODES,
    MODE_TABLE_PARAMS,
    ModeTableField,
)

MODES = ("home", "away", "custom_1", "custom_2", "custom_3")
DELAY_KEYS = {f"{kind}_delay_{mode}" for kind in ("alarm", "leaving") for mode in MODES}
ACTION_KEYS = {f"{kind}_action_{mode}" for kind in ("camera", "sensor") for mode in MODES}


def test_the_mode_table_settings_are_every_mode_table_param() -> None:
    """Ten delays per sub-device, and one action mask per mode for each kind with named
    action bits; each read back from its own parameter."""
    table = {s.key: s for s in MODE_TABLE_SETTINGS}
    assert len(table) == len(MODE_TABLE_SETTINGS)
    assert set(table) == DELAY_KEYS | ACTION_KEYS
    assert {s.command_id for s in table.values()} == set(MODE_TABLE_PARAMS)
    for key, setting in table.items():
        mode, table_field = MODE_TABLE_PARAMS[setting.command_id]
        assert setting.read_param == setting.command_id, key
        if table_field is ModeTableField.ACTION:
            assert key == mode_action_key(mode, setting.scope)
            assert setting.flags == MODE_ACTION_FLAGS[setting.scope]
            assert setting.kind is SettingKind.FLAGS
            assert setting.unit is SettingUnit.NONE
        else:
            assert key == mode_delay_key(table_field, mode)
            assert setting.scope is Scope.SUB_DEVICE
            assert setting.kind is SettingKind.NUMBER
            assert (setting.value_range, setting.unit) == ((0, 300), SettingUnit.SECONDS)


def test_mode_table_names() -> None:
    assert mode_table_setting("alarm_delay_custom_1").name == "Alarm delay (Custom 1)"
    assert mode_table_setting("leaving_delay_away").name == "Leaving delay (Away)"
    assert mode_table_setting("camera_action_away").name == "Camera actions (Away)"
    assert mode_table_setting("sensor_action_home").name == "Sensor actions (Home)"


def test_action_flags_per_kind_are_the_apk_bits() -> None:
    assert dict(MODE_ACTION_FLAGS[Scope.CAMERA]) == {
        "record": 1,
        "camera_siren": 2,
        "station_alarm": 4,
        "notification": 8,
        "report_monitor_center": 64,
        "light_alarm": 128,
    }
    assert dict(MODE_ACTION_FLAGS[Scope.SENSOR]) == {
        "station_alarm": 4,
        "notification": 8,
        "motion_sensor_respond": 32,
        "report_monitor_center": 64,
    }
    assert all(ACTION_FLAGS[n] == b for f in MODE_ACTION_FLAGS.values() for n, b in f.items())
    away = mode_table_setting("camera_action_away")
    # 143, a mask a station reported: record, camera siren, HomeBase alarm, notification, light.
    assert away.decode_flags(143) == (
        frozenset({"record", "camera_siren", "station_alarm", "notification", "light_alarm"}),
        0,
    )
    assert away.with_flag(143, "camera_siren", False) == 141
    assert mode_table_setting("sensor_action_away").decode_flags(8) == (
        frozenset({"notification"}),
        0,
    )


def test_mode_keys() -> None:
    assert mode_action_key(GuardMode.CUSTOM_2, Scope.SENSOR) == "sensor_action_custom_2"
    assert mode_delay_key(ModeTableField.LEAVING_DELAY, GuardMode.AWAY) == "leaving_delay_away"
    assert (
        mode_table_setting("leaving_delay_away").command_id
        == FIELD_PARAMS[ModeTableField.LEAVING_DELAY][GuardMode.AWAY]
    )
    with pytest.raises(UnsupportedError, match="no per-device actions"):
        mode_action_key(GuardMode.OFF, Scope.CAMERA)
    with pytest.raises(UnsupportedError, match="no catalogued per-mode actions"):
        mode_action_key(GuardMode.AWAY, Scope.SUB_DEVICE)
    with pytest.raises(UnsupportedError, match="no action delay"):
        mode_delay_key(ModeTableField.ACTION, GuardMode.AWAY)
    assert len(MODE_TABLE_MODES) == 5


def test_delay_scopes_follow_the_parameter_dump() -> None:
    """The ten per-mode alarm/leaving delays sit on every sub-device block, never the
    station's."""
    delays = {s.command_id: s for s in MODE_TABLE_SETTINGS if s.key in DELAY_KEYS}
    assert sorted(delays) == list(range(1166, 1176))
    for setting in delays.values():
        assert setting.applies_to(Scope.CAMERA)
        assert setting.applies_to(Scope.SENSOR)
        assert not setting.applies_to(Scope.STATION)


def test_an_action_mask_applies_to_its_own_scope() -> None:
    camera = mode_table_setting("camera_action_home")
    assert camera.applies_to(Scope.CAMERA)
    assert not camera.applies_to(Scope.SENSOR)
    assert not camera.applies_to(Scope.STATION)


def test_decode() -> None:
    delay = mode_table_setting("alarm_delay_home")
    assert delay.decode("60") == 60
    assert delay.decode("n/a") == "n/a"


def test_scope_default_channel() -> None:
    assert SCOPE_DEFAULT_CHANNEL == {
        Scope.STATION: 255,
        Scope.CAMERA: 0,
        Scope.SENSOR: 0,
        Scope.SUB_DEVICE: 0,
    }


@pytest.mark.parametrize(
    ("device_type", "respond"), [(10, True), (127, True), (None, True), (2, False)]
)
def test_only_a_motion_sensor_s_actions_name_respond(
    device_type: int | None, respond: bool
) -> None:
    flags = mode_action_flags(Scope.SENSOR, device_type)
    assert ("motion_sensor_respond" in flags) is respond
    assert {"notification", "station_alarm", "report_monitor_center"} <= set(flags)
    action = mode_table_setting("sensor_action_away").for_device_type(device_type)
    assert action.flags == flags
    camera = mode_table_setting("camera_action_away")
    assert camera.for_device_type(2) is camera
    assert mode_action_flags(Scope.CAMERA, 2) == MODE_ACTION_FLAGS[Scope.CAMERA]
    assert dict(mode_action_flags(Scope.SUB_DEVICE)) == {}


def test_with_flag_keeps_every_other_bit() -> None:
    action = mode_table_setting("camera_action_away")
    assert action.with_flag(0x300, "notification", True) == 0x308
    assert action.with_flag(0x30F, "record", False) == 0x30E
    assert action.with_flag(0x301, "record", True) == 0x301
    assert action.decode_flags(0x309) == (frozenset({"record", "notification"}), 0x300)


def test_flags_refuse_unknown_names_other_kinds_and_negatives() -> None:
    action = mode_table_setting("camera_action_away")
    delay = mode_table_setting("alarm_delay_home")
    with pytest.raises(UnsupportedError, match="known flags: record, camera_siren"):
        action.with_flag(1, "motion_sensor_respond", True)
    with pytest.raises(UnsupportedError, match="not a bitmask of flags"):
        delay.decode_flags(1)
    with pytest.raises(UnsupportedError, match="not a bitmask of flags"):
        delay.with_flag(1, "record", True)
    with pytest.raises(ValueError, match="not a bitmask"):
        action.decode_flags(-1)
    with pytest.raises(ValueError, match="not a bitmask"):
        action.with_flag(-1, "record", True)


def test_scope_for_kind() -> None:
    assert scope_for_kind(DeviceKind.STATION) is Scope.STATION
    assert scope_for_kind(DeviceKind.CAMERA) is Scope.CAMERA
    assert scope_for_kind(DeviceKind.SENSOR) is Scope.SENSOR
    # Only known to be some sub-device: just the settings every sub-device carries.
    assert scope_for_kind(DeviceKind.KEYPAD) is Scope.SUB_DEVICE
    assert scope_for_kind(None) is Scope.SUB_DEVICE
    assert mode_table_setting("alarm_delay_home").applies_to(scope_for_kind(None))
    assert not mode_table_setting("camera_action_home").applies_to(scope_for_kind(None))


def _per_view(single: object, dual: object) -> str:
    report = {"mode_0": {"quality": single}, "mode_1": {"quality": dual}, "cur_mode": 0}
    return base64.b64encode(json.dumps(report).encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    ("raw", "view_mode", "value"),
    [
        (None, None, None),
        ("42", None, 42),
        ("-1", None, -1),
        (_per_view(3, 5), None, 3),
        (_per_view(3, 5), "0", 3),
        (_per_view(3, 5), str(DUAL_VIEW), 5),
        (_per_view("4", 5), "x", 4),
        (_per_view(True, 5), None, None),
        (_per_view("high", 5), None, None),
        ("not base64!", None, None),
        (base64.b64encode(b"[1, 2]").decode(), None, None),
    ],
)
def test_report_value(raw: str | None, view_mode: str | None, value: int | None) -> None:
    assert report_value(raw, view_mode) == value


def test_mode_table_setting_looks_up_a_mode_table_key() -> None:
    assert mode_table_setting("camera_action_away").command_id == 1239
    with pytest.raises(UnsupportedError, match=r"known: .*alarm_delay_home"):
        mode_table_setting("mirror")


def test_settings_carry_no_tiers_or_catalogue() -> None:
    from eufy_home_security.devices import settings, support  # noqa: PLC0415

    for name in ("Tier", "TIER_ORDER", "rank", "tier_for_support"):
        assert not hasattr(support, name), name
    for name in ("SETTINGS", "get_setting", "check_shape", "check_applies_when"):
        assert not hasattr(settings, name), name
