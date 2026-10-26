from __future__ import annotations

import base64
import json

import pytest

from eufy_home_security.devices import settings
from eufy_home_security.devices._device_alarm_data import DEVICE_ALARMS
from eufy_home_security.devices.device_alarm import device_alarms
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.devices.settings import (
    DOORBELL_TYPE_ACTIONS,
    DUAL_VIEW,
    MODE_ACTION_ALARM_AFFECTING,
    MODE_ACTION_FLAGS,
    MODE_ACTION_LABELS,
    MODE_TABLE_SETTINGS,
    SCOPE_DEFAULT_CHANNEL,
    Scope,
    SettingKind,
    SettingUnit,
    mode_action_flags,
    mode_action_key,
    mode_action_label,
    mode_delay_key,
    mode_table_setting,
    report_value,
    scope_for_kind,
)
from eufy_home_security.devices.types import MODELS, DeviceKind
from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.mode_actions import (
    ACTION_FLAGS,
    FIELD_PARAMS,
    MODE_ACTION_CLEARS,
    MODE_ACTION_INVERTED,
    MODE_DELAY_CHOICES,
    MODE_TABLE_MODES,
    MODE_TABLE_PARAMS,
    ModeTableField,
    mode_action_on,
)

MODES = ("home", "away", "custom_1", "custom_2", "custom_3")
DELAY_KEYS = {f"{kind}_delay_{mode}" for kind in ("alarm", "leaving") for mode in MODES}
ACTION_KEYS = {
    f"{kind}_action_{mode}" for kind in ("camera", "doorbell", "sensor") for mode in MODES
}


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
            assert setting.values == MODE_DELAY_CHOICES == (0, 15, 30, 45, 60, 180, 300)


def test_mode_table_names() -> None:
    assert mode_table_setting("alarm_delay_custom_1").name == "Alarm delay (Custom 1)"
    assert mode_table_setting("leaving_delay_away").name == "Leaving delay (Away)"
    assert mode_table_setting("camera_action_away").name == "Camera actions (Away)"
    assert mode_table_setting("sensor_action_home").name == "Sensor actions (Home)"
    assert mode_table_setting("doorbell_action_away").name == "Doorbell actions (Away)"


def test_action_flags_per_kind_are_the_apk_bits() -> None:
    assert dict(MODE_ACTION_FLAGS[Scope.CAMERA]) == {
        "record": 1,
        "camera_siren": 2,
        "station_alarm": 4,
        "notification": 8,
        "report_monitor_center": 64,
        "light_alarm": 128,
    }
    assert MODE_ACTION_FLAGS[Scope.DOORBELL] == MODE_ACTION_FLAGS[Scope.CAMERA]
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
    assert mode_table_setting("sensor_action_away").decode_flags(40) == (
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
        Scope.DOORBELL: 0,
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


_FULL_DOORBELL = [
    "record",
    "camera_siren",
    "station_alarm",
    "notification",
    "report_monitor_center",
    "light_alarm",
]


@pytest.mark.parametrize(
    ("device_type", "flags"),
    [
        (5, ["record", "notification", "report_monitor_center"]),
        (93, ["record", "notification", "report_monitor_center"]),
        *(
            (t, ["record", "station_alarm", "notification", "report_monitor_center"])
            for t in (7, 16, 91, 94, 95, 96)
        ),
        (312, _FULL_DOORBELL),  # its product has a siren and light of its own
        (97, _FULL_DOORBELL),
        (None, _FULL_DOORBELL),  # type unknown: the whole row
        (1, []),  # a type no catalogued doorbell has
    ],
)
def test_a_doorbell_s_actions_follow_its_cloud_type(
    device_type: int | None, flags: list[str]
) -> None:
    assert list(mode_action_flags(Scope.DOORBELL, device_type)) == flags
    action = mode_table_setting("doorbell_action_home").for_device_type(device_type)
    assert list(action.flags or {}) == flags


def test_an_untabled_doorbell_type_has_the_whole_row_iff_it_has_its_own_alarm() -> None:
    """Decided from the generated device-alarm data, per catalogued doorbell."""
    assert {
        model.cloud_device_type
        for model in MODELS.values()
        if model.kind is DeviceKind.DOORBELL
        and device_alarms(model.model, ConnectType.HB3) is not None
    } == settings._DEVICE_ALARM_DOORBELL_TYPES
    seen = set()
    for model in MODELS.values():
        device_type = model.cloud_device_type
        if model.kind is not DeviceKind.DOORBELL or device_type is None:
            continue
        if device_type in DOORBELL_TYPE_ACTIONS:
            continue
        seen.add(model.model)
        full = device_alarms(model.model, ConnectType.HB3) is not None
        assert dict(mode_action_flags(Scope.DOORBELL, device_type)) == (
            dict(MODE_ACTION_FLAGS[Scope.DOORBELL]) if full else {}
        )
    assert seen


def test_an_alarm_only_without_a_station_is_no_alarm_behind_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    single = DEVICE_ALARMS["T8217"][0]
    assert single[0] == ("SINGLE",)
    monkeypatch.setitem(DEVICE_ALARMS, "T0001", [single])
    assert not settings._alarm_behind_station("T0001")
    assert settings._alarm_behind_station("t8217")
    assert not settings._alarm_behind_station("T8210")  # no alarm of its own


def test_a_doorbell_refuses_an_action_its_type_does_not_have() -> None:
    action = mode_table_setting("doorbell_action_away").for_device_type(93)
    assert action.with_flag(0, "record", True) == 1
    assert action.decode_flags(4 | 8) == (frozenset({"notification"}), 4)
    with pytest.raises(UnsupportedError, match="known flags: record, notification"):
        action.with_flag(0, "station_alarm", True)


def test_with_flag_keeps_every_other_bit() -> None:
    action = mode_table_setting("camera_action_away")
    assert action.with_flag(0x300, "notification", True) == 0x308
    assert action.with_flag(0x30F, "record", False) == 0x30E
    assert action.with_flag(0x301, "record", True) == 0x301
    assert action.decode_flags(0x309) == (frozenset({"record", "notification"}), 0x300)


def test_motion_sensor_respond_is_on_while_its_bit_is_clear() -> None:
    """The app's "React to motion" is ticked while bit 32 is clear."""
    assert {"motion_sensor_respond"} == MODE_ACTION_INVERTED
    assert mode_action_on("motion_sensor_respond", 8)
    assert not mode_action_on("motion_sensor_respond", 40)
    assert mode_action_on("notification", 40)
    sensor = mode_table_setting("sensor_action_away").for_device_type(10)
    assert sensor.decode_flags(0) == (frozenset({"motion_sensor_respond"}), 0)
    assert sensor.decode_flags(32) == (frozenset(), 0)
    assert sensor.with_flag(8, "motion_sensor_respond", False) == 40
    assert sensor.with_flag(40, "motion_sensor_respond", True) == 8
    assert mode_action_label("motion_sensor_respond") == "React to motion"


def test_ignoring_motion_also_clears_notification_and_homebase_alarm() -> None:
    assert {"motion_sensor_respond": {"notification", "station_alarm"}} == MODE_ACTION_CLEARS
    sensor = mode_table_setting("sensor_action_away").for_device_type(10)
    assert sensor.with_flags(76, {"motion_sensor_respond": False}) == 96
    assert sensor.with_flags(96, {"motion_sensor_respond": True}) == 64  # restores nothing
    assert sensor.with_flags(12, {"notification": False}) == 4  # only the coupled flag clears
    with pytest.raises(ValueError, match="station_alarm cannot be turned on"):
        sensor.with_flags(0, {"motion_sensor_respond": False, "station_alarm": True})
    door = mode_table_setting("sensor_action_away").for_device_type(2)
    assert door.with_flags(12, {"station_alarm": False}) == 8


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


def test_every_action_flag_has_a_sentence_case_label() -> None:
    assert MODE_ACTION_LABELS.keys() == ACTION_FLAGS.keys()
    assert len(set(MODE_ACTION_LABELS.values())) == len(MODE_ACTION_LABELS)
    for label in MODE_ACTION_LABELS.values():
        assert label[0].isupper()
        rest = label.replace("HomeBase", "homebase")[1:]  # the product name keeps its case
        assert rest == rest.lower()
    assert mode_action_label("camera_siren") == "Camera alarm"
    assert mode_action_label("station_alarm") == "HomeBase alarm"
    with pytest.raises(UnsupportedError, match="unknown action flag 'siren'; known: record"):
        mode_action_label("siren")


def test_the_sounding_flags_and_their_clearer_are_alarm_affecting() -> None:
    assert {"camera_siren", "station_alarm", "light_alarm", "motion_sensor_respond"} == (
        MODE_ACTION_ALARM_AFFECTING
    )


def test_scope_for_kind() -> None:
    assert scope_for_kind(DeviceKind.STATION) is Scope.STATION
    assert scope_for_kind(DeviceKind.CAMERA) is Scope.CAMERA
    assert scope_for_kind(DeviceKind.SENSOR) is Scope.SENSOR
    assert scope_for_kind(DeviceKind.DOORBELL) is Scope.DOORBELL
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
