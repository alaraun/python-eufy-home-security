"""Loading, validating, encoding and decoding the per-model settings."""

from __future__ import annotations

import base64
import functools
import json
import operator
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    Setting,
    SettingControl,
    SettingKind,
    WriteContext,
    WritePath,
    bundled_codes,
    mode_table_settings,
    product_code_of,
    settings_of,
)
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.devices.settings import Scope, SettingUnit, mode_table_setting
from eufy_home_security.exceptions import ModelDataError, UnsupportedError
from eufy_home_security.p2p.mode_actions import ACTION_FLAGS

CHILD = WriteContext(
    standalone=False, channel=3, device_sn="T0000CHILDSN0001", station_sn="T0000STATION0001"
)
ALONE = WriteContext(
    standalone=True, channel=0, device_sn="T0000ALONESN0001", station_sn="T0000ALONESN0001"
)


def _setting(product_code: str, key: str) -> Setting:
    return settings_of(product_code)[key]


def test_power_manager_mode_round_trip() -> None:
    """T8160 power_manager_mode 3 is ECB 1246 value 2; parameter "2" reads back as 3."""
    setting = _setting("T8160", "power_manager_mode")
    assert setting.kind is SettingKind.ENUM
    wire = setting.encode(3, CHILD)
    assert wire.path is WritePath.ECB
    assert wire.cmd == 1246
    assert wire.value == 2
    assert wire.updates == ((1246, "2"),)
    assert setting.decode("2") == 3


def test_setting_has_no_evidence_fields() -> None:
    fields = set(Setting.__dataclass_fields__)
    assert not fields & {"evidence", "tier", "support", "verified"}


def test_product_codes_match_case_insensitively() -> None:
    assert settings_of("t8160") is settings_of("T8160")
    assert _setting("t8160", "power_manager_mode").product_code == "T8160"


@pytest.mark.parametrize("code", ["T0000", "", "../T8160", "T8160.json"])
def test_unknown_or_invalid_code_has_no_settings(code: str) -> None:
    assert dict(settings_of(code)) == {}


@pytest.mark.parametrize(
    ("serial", "code"),
    [
        ("T8410X5000000001", "T8410C"),
        ("t8410x5000000001", "T8410C"),
        ("T8410X4000000001", "T8410"),
        ("T8420X6000000001", "T8420X"),
        ("T8420X5000000001", "T8420"),
        ("T8210X8000000001", "T8210C"),
        ("T8210X7000000001", "T8210"),
        ("T8520X8000000001", "T8510P"),
        ("T8520X9000000001", "T8520P"),
        ("T8520X7000000001", "T8520"),
        ("T8W11P0000000001", "T8W11C"),
        ("T8W11X0000000001", "T8W11"),
        ("T8160X5000000001", "T8160"),
        ("T8410X", "T8410"),
        ("T0000X0000000001", None),
    ],
)
def test_without_a_cloud_code_the_serial_names_the_product(serial: str, code: str | None) -> None:
    assert product_code_of(None, serial) == code


def test_the_cloud_code_wins_over_the_serial() -> None:
    assert product_code_of("t8410", "T8410X5000000001") == "T8410"


# ── decode ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("key", "raw", "value"),
    [
        ("power_manager_mode", "2", 3),
        ("power_manager_mode", "7", None),
        ("motion_stop_end_early", "0", True),
        ("motion_stop_end_early", "1", False),
        ("speaker_volume", "90", 0),
        ("nightvision_type", "2", 2),
        ("nightvision_type", "9", None),
        ("video_clip_length", "30", 30),
        ("power_manager_mode", None, None),
    ],
)
def test_t8160_decode(key: str, raw: str | None, value: object) -> None:
    decoded = _setting("T8160", key).decode(raw)
    assert decoded == value
    assert type(decoded) is type(value)


def test_unreadable_setting_decodes_to_none() -> None:
    setting = _setting("T8160", "device_name")
    assert not setting.readable
    assert setting.decode("x") is None


# ── encode paths ────────────────────────────────────────────────────────────


def test_recipe_1700_path() -> None:
    wire = _setting("T8170", "ptz_turn_speed").encode(5, ALONE)
    assert wire.path is WritePath.RECIPE_1700
    assert wire.cmd == 6015
    assert wire.params is not None
    assert wire.params["value"] == 5
    assert wire.updates == ((6015, "5"),)


def test_sub_1350_path_carries_the_channel() -> None:
    wire = _setting("T8170", "nightvision_type").encode(1, CHILD)
    assert wire.path is WritePath.SUB_1350
    assert wire.cmd == 1277
    assert wire.params == {"night_sion": 1, "channel": 3}
    assert wire.value is None


def test_direct_path() -> None:
    wire = _setting("T8170", "device_snooze_time").encode(5, ALONE)
    assert wire.path is WritePath.DIRECT
    assert wire.cmd == 1271
    assert wire.params == {"snooze_time": 900}
    assert wire.value is None


def test_a_time_zone_is_written_as_the_app_s_string_frame() -> None:
    """``timezone_set`` takes an IANA id and sends the device form ``<rule>|1.<sn>``."""
    setting = _setting("T8170", "timezone_set")
    wire = setting.encode("Europe/Helsinki", ALONE)
    assert wire.path is WritePath.STRING
    assert wire.cmd == 1215
    assert wire.text == "EET-2EEST,M3.5.0/3,M10.5.0/4|1.1386"
    assert (wire.params, wire.value) == (None, None)
    assert wire.updates == ((1215, wire.text),)


def test_ecb_command_with_a_numeric_string_value_goes_ecb() -> None:
    """A handler that writes an ECB command's value as a digit string still uses ECB."""
    wire = _setting("T8160", "detection_sensitivity").encode(3, CHILD)
    assert wire.path is WritePath.ECB
    assert (wire.cmd, wire.value) == (1210, 3)
    assert wire.updates == ((1210, "3"),)


@pytest.mark.parametrize("value", [1, "1"])
def test_ecb_path_does_not_depend_on_the_caller_type(value: object) -> None:
    wire = _setting("T8030", "time_format_set").encode(value, ALONE)
    assert wire.path is WritePath.ECB
    assert (wire.cmd, wire.value) == (1253, 1)


def test_ecb_command_with_a_non_numeric_value_is_refused() -> None:
    with pytest.raises(ValueError, match="1253"):
        _setting("T8030", "time_format_set").encode("abc", ALONE)


def test_ecb_value_repeated_under_two_names_goes_ecb() -> None:
    wire = _setting("T8172", "video_clip_length").encode(30, CHILD)
    assert wire.path is WritePath.ECB
    assert (wire.cmd, wire.value) == (1249, 30)


def test_bool_ecb_value_is_zero_or_one() -> None:
    wire = _setting("T8160", "motion_stop_end_early").encode(True, CHILD)
    assert wire.path is WritePath.ECB
    assert (wire.cmd, wire.value) == (1251, 0)


def test_ext_updates_follow_the_main_update() -> None:
    wire = _setting("T8162", "speaker_volume").encode(60, CHILD)
    assert wire.path is WritePath.ECB
    assert wire.updates == ((2003, "60"), (1230, "60"), (2003, "60"))


# ── refusals ────────────────────────────────────────────────────────────────


def _find(transport: str) -> Setting:
    """The first setting in the bundled files whose child write template carries ``transport``."""
    root = Path(model_settings.__file__).parent / "data" / "models"
    for path in sorted(root / f"{code}.json" for code in bundled_codes()):
        entries = json.loads(path.read_text(encoding="utf-8"))["settings"]
        for key, entry in entries.items():
            if key == "arming_selected_mode" or entry["access"] != "rw":
                continue
            templates = [entry.get("write"), *(entry.get("write_table") or {}).values()]
            if any(isinstance(t, dict) and _carries(t, transport) for t in templates):
                return settings_of(path.stem)[key]
    raise AssertionError(transport)


def _carries(template: dict[str, object], transport: str) -> bool:
    if transport == "param_data":
        return template.get("cmd") == 1700 and "param_data" in template
    if transport == "scalar":
        return "subCmd" not in template and template.get("cmd") == 1254
    return transport in template


@pytest.mark.parametrize(
    ("transport", "note"),
    [
        ("sendRequestUrl", "cloud request"),
        ("multipleRequest", "multi-command write"),
        ("localParams", "app-local"),
        ("http", "cloud request"),
        ("ble", "Bluetooth"),
        ("param_data", "1700 data body not supported"),
        ("scalar", "scalar body on a non-ECB command"),
    ],
)
def test_unsent_transports_are_not_writable(transport: str, note: str) -> None:
    setting = _find(transport)
    assert not setting.writable
    assert setting.note is not None
    assert setting.note.endswith(note)
    with pytest.raises(UnsupportedError, match=note):
        setting.encode(setting.values[0] if setting.values else False, CHILD)


def test_existing_note_is_kept_before_the_refusal() -> None:
    setting = _setting("T8160", "device_name")
    assert setting.note == "round trip does not return the written value; cloud request"


@pytest.mark.parametrize("code", ["T8001", "T8111"])
def test_guard_mode_is_not_a_writable_setting(code: str) -> None:
    setting = _setting(code, "arming_selected_mode")
    assert not setting.writable
    assert setting.note == "guard mode: use Station.async_set_guard_mode"


def test_a_write_the_standalone_handler_sends_by_mqtt_is_refused_standalone_only() -> None:
    child = settings_of("T85V0")["device_rain_mode"]
    assert child.writable
    assert child.encode(True, CHILD).path is WritePath.SUB_1350
    alone = settings_of("T85V0", standalone=True)["device_rain_mode"]
    assert not alone.writable
    assert alone.note is not None
    assert alone.note.endswith("MQTT")
    with pytest.raises(UnsupportedError, match="MQTT"):
        alone.encode(True, ALONE)


def test_read_only_setting_refuses_encode() -> None:
    setting = next(s for s in settings_of("T8160").values() if not s.writable and s.note is None)
    with pytest.raises(UnsupportedError):
        setting.encode(0, CHILD)


# ── validate ────────────────────────────────────────────────────────────────


def test_enum_accepts_values_numbers_as_text_and_labels() -> None:
    setting = _setting("T8160", "power_manager_mode")
    assert setting.validate(3) == 3
    assert setting.validate("3") == 3
    assert setting.validate("Custom recording") == 3
    assert setting.validate("custom RECORDING") == 3
    assert setting.label(3) == "Custom recording"
    assert setting.label(9) is None
    with pytest.raises(ValueError, match="not one of"):
        setting.validate(2)
    with pytest.raises(ValueError, match="not one of"):
        setting.validate(True)


@pytest.mark.parametrize(
    ("raw", "value"),
    [("on", True), ("off", False), ("true", True), ("false", False), (0, False), (1, True)],
)
def test_bool_accepts_text_and_zero_one(raw: object, value: bool) -> None:
    assert _setting("T8160", "motion_stop_end_early").validate(raw) is value


@pytest.mark.parametrize("raw", [2, "maybe", None, 0.5])
def test_bool_rejects_other_values(raw: object) -> None:
    with pytest.raises(ValueError, match="not a bool"):
        _setting("T8160", "motion_stop_end_early").validate(raw)


def test_range_checks_bounds_and_step() -> None:
    setting = _setting("T8160", "video_clip_length")
    assert (setting.minimum, setting.maximum, setting.step) == (5, 120, 1)
    assert setting.validate(30) == 30
    assert setting.validate("30") == 30
    with pytest.raises(ValueError, match="outside"):
        setting.validate(121)
    with pytest.raises(ValueError, match="step"):
        setting.validate(30.5)
    with pytest.raises(ValueError, match="number"):
        setting.validate(True)


def test_string_accepts_str_only() -> None:
    setting = _setting("T8030", "device_name")
    assert setting.validate("Home") == "Home"
    with pytest.raises(ValueError, match="string"):
        setting.validate(2)


def test_a_time_zone_setting_offers_the_app_s_zones_and_reads_back_the_id() -> None:
    setting = _setting("T8170", "timezone_set")
    assert (setting.control, setting.domain) == (SettingControl.SELECT, "timezone")
    assert "Europe/Tallinn" in setting.values
    assert len(setting.values) == len(set(setting.values)) > 400
    assert setting.validate("Europe/Tallinn") == "Europe/Tallinn"
    for wrong in ("GMT+2", "EET-2EEST,M3.5.0/3,M10.5.0/4|1.1416", "Mars/Olympus"):
        with pytest.raises(ValueError, match="timezone ids"):
            setting.validate(wrong)
    assert setting.decode("EET-2EEST,M3.5.0/3,M10.5.0/4|1.1416") == "Europe/Tallinn"
    # The device form without a row number, or with an unknown one, is not placed.
    for raw in ("Europe/Tokyo", "EET-2EEST,M3.5.0/3,M10.5.0/4", "GMT0|1.9999", "x|1.abc", "0"):
        assert setting.decode(raw) is None


def test_labels_are_keyed_by_public_value() -> None:
    setting = _setting("T8160", "power_manager_mode")
    assert dict(setting.labels) == {
        0: "Optimal battery life",
        1: "Optimal surveillance",
        3: "Custom recording",
    }
    assert setting.applies_when is None
    assert _setting("T8160", "video_clip_length").applies_when == ("power_manager_mode", 3)


def test_file_units_map_to_setting_units() -> None:
    assert _setting("T8222", "video_clip_length").unit is SettingUnit.SECONDS
    assert _setting("T8160", "video_clip_length").unit is SettingUnit.SECONDS
    assert SettingUnit("ms") is SettingUnit.MILLISECONDS
    assert SettingUnit("d") is SettingUnit.DAYS
    units = {s.unit for code in ("T8172", "T8222") for s in settings_of(code).values()}
    assert {SettingUnit.PERCENT, SettingUnit.MILLISECONDS} <= units


@pytest.mark.parametrize("code", ["T8160", "T8170"])
def test_custom_recording_settings_carry_app_titles_and_seconds(code: str) -> None:
    names = {k: _setting(code, k).name for k in ("video_clip_length", "trigger_interval_time")}
    assert names == {
        "video_clip_length": "Clip length",
        "trigger_interval_time": "Intervals between triggers",
    }
    assert _setting(code, "motion_stop_end_early").name == "End clip early if motion stops"
    assert _setting(code, "trigger_interval_time").unit is SettingUnit.SECONDS


@pytest.mark.parametrize(
    ("code", "key", "primary"),
    [
        ("T8170", "record_resolution__v1", "record_resolution"),
        ("T8170", "detection_type_set__v2", "detection_type_set"),
        ("T8160", "nightvision_type", "nightvision_type_new"),
    ],
)
def test_bundled_variants_name_their_primary(code: str, key: str, primary: str) -> None:
    assert _setting(code, key).variant_of == primary
    assert _setting(code, primary).variant_of is None


def test_spotlight_switches_are_not_variants() -> None:
    assert _setting("T8170", "spotlight_status").variant_of is None
    assert _setting("T8170", "spotlight_switch").variant_of is None


# ── malformed files ─────────────────────────────────────────────────────────


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A temporary models directory the loader reads from, indexing ``T0001``."""
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    _write_index(tmp_path, ["T0001"])
    yield tmp_path
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


def _write_index(root: Path, codes: object, schema_version: int = 3) -> None:
    index = {"schema_version": schema_version, "codes": codes}
    (root / "INDEX.json").write_text(json.dumps(index), encoding="utf-8")
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


GOOD_ENTRY = {"access": "ro", "kind": "bool", "read": None}


@pytest.mark.parametrize(
    "doc",
    [
        "{not json",
        json.dumps([]),
        json.dumps({"schema_version": 1, "product_code": "T0001", "settings": {}}),
        json.dumps({"schema_version": 2, "product_code": "T0001", "settings": {}}),
        json.dumps({"schema_version": 3, "product_code": "T0002", "settings": {}}),
        json.dumps({"schema_version": 3, "product_code": "T0001"}),
        json.dumps(
            {"schema_version": 3, "product_code": "T0001", "settings": {"x": {"kind": "bool"}}}
        ),
        json.dumps(
            {
                "schema_version": 3,
                "product_code": "T0001",
                "settings": {"x": {**GOOD_ENTRY, "kind": "colour"}},
            }
        ),
        json.dumps(
            {
                "schema_version": 3,
                "product_code": "T0001",
                "settings": {"x": {**GOOD_ENTRY, "access": "rw", "write": "1350"}},
            }
        ),
    ],
)
def test_malformed_file_names_the_file(data_root: Path, doc: str) -> None:
    (data_root / "T0001.json").write_text(doc, encoding="utf-8")
    with pytest.raises(ModelDataError, match=r"T0001\.json"):
        settings_of("T0001")


def _write_model(root: Path, settings: dict[str, object]) -> None:
    doc = {"schema_version": 3, "product_code": "T0001", "settings": settings}
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")


def test_name_and_variant_of_come_from_the_file(data_root: Path) -> None:
    _write_model(
        data_root,
        {
            "mode": GOOD_ENTRY,
            "mode__v1": {**GOOD_ENTRY, "name": "App Title", "variant_of": "mode"},
        },
    )
    loaded = settings_of("T0001")
    assert (loaded["mode__v1"].name, loaded["mode__v1"].variant_of) == ("App Title", "mode")
    assert (loaded["mode"].name, loaded["mode"].variant_of) == ("Mode", None)


@pytest.mark.parametrize("target", ["gone", "mode", "Bad-Key"])
def test_variant_of_must_name_another_setting(data_root: Path, target: str) -> None:
    _write_model(data_root, {"mode": {**GOOD_ENTRY, "variant_of": target}})
    with pytest.raises(ModelDataError, match=r"T0001\.json.*variant_of"):
        settings_of("T0001")


def test_identifiers_outside_the_pattern_are_skipped(data_root: Path) -> None:
    doc = {
        "schema_version": 3,
        "product_code": "T0001",
        "settings": {"ok_1": GOOD_ENTRY, "Bad-Key": GOOD_ENTRY},
    }
    (data_root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")
    assert list(settings_of("T0001")) == ["ok_1"]


def _b64_json(obj: object) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _report(first: int, second: int, cur_mode: int) -> str:
    return _b64_json(
        {"mode_0": {"quality": first}, "mode_1": {"quality": second}, "cur_mode": cur_mode}
    )


_QUALITY = {
    "kind": "enum",
    "values": [1, 2],
    "access": "rw",
    "control": "select",
    "write": {
        "cmd": 1350,
        "subCmd": 2731,
        "params": {"quality": {"$map": {"1": 3, "2": 2}}, "mode": "$param:6243:int"},
    },
    "read": {"param": 2731, "map": {}, "view": {"by": 6243, "map": {"2": 2, "3": 1}}},
}


def test_a_context_replaces_the_fields_it_names_and_null_removes_one(data_root: Path) -> None:
    base = {**GOOD_ENTRY, "read": {"param": 6020, "map": None}, "note": "base note"}
    hb = {"read": {"param": 1289, "map": None}, "note": None}
    alone = {"read": None}
    _write_model(
        data_root,
        {
            "x": {
                **base,
                "contexts": [
                    {"names": ["HB2", "HB3"], "entry": hb},
                    {"names": ["standalone"], "entry": alone},
                ],
            }
        },
    )
    assert (settings_of("T0001")["x"].read_param, settings_of("T0001")["x"].note) == (
        6020,
        "base note",
    )
    behind = settings_of("T0001", ConnectType.HB3)["x"]
    assert (behind.read_param, behind.note) == (1289, None)
    assert settings_of("T0001", ConnectType.HB1)["x"].read_param == 6020
    assert settings_of("T0001", ConnectType.SINGLE)["x"].read_param == 6020
    assert settings_of("T0001", standalone=True)["x"].read_param is None


@pytest.mark.parametrize(
    ("by", "raw", "view_mode", "value"),
    [
        (6243, _report(3, 2, 0), "0", 1),
        (6243, _report(3, 2, 0), "12", 2),
        (6243, _report(3, 2, 2), None, 1),
        ("cur_mode", _report(3, 2, 0), "12", 1),
        ("cur_mode", _report(3, 2, 1), None, 1),
        ("cur_mode", _report(3, 2, 2), "0", 2),
        (None, _report(3, 2, 2), "12", 1),
        (None, _b64_json({"mode_1": {"quality": 2}}), None, None),
        (None, _b64_json({"mode_0": {"quality": 7}}), None, None),
        (6243, "not base64!", "0", None),
    ],
)
def test_a_per_view_read_takes_the_current_view_s_quality(
    data_root: Path, by: object, raw: str, view_mode: str | None, value: int | None
) -> None:
    read = {"param": 2731, "map": {}, "view": {"by": by, "map": {"2": 2, "3": 1}}}
    _write_model(data_root, {"q": {**_QUALITY, "read": read}})
    block = {} if view_mode is None else {6243: view_mode}
    assert settings_of("T0001")["q"].decode(raw, block) == value


def test_a_per_view_read_comes_after_the_map(data_root: Path) -> None:
    read = {"param": 2730, "map": {"Mw==": 2}, "view": {"by": None, "map": {"3": 1}}}
    _write_model(data_root, {"q": {**_QUALITY, "read": read}})
    setting = settings_of("T0001")["q"]
    assert setting.decode("Mw==") == 2
    assert setting.decode(_report(3, 3, 0)) == 1


def test_a_param_leaf_takes_the_device_s_current_value(data_root: Path) -> None:
    _write_model(data_root, {"q": _QUALITY})
    setting = settings_of("T0001")["q"]
    assert setting.write_params == {6243}
    wire = setting.encode(1, replace(CHILD, params={6243: "12"}))
    assert (wire.cmd, wire.params) == (2731, {"quality": 3, "mode": 12})
    with pytest.raises(ValueError, match="6243 is not reported"):
        setting.encode(1, CHILD)
    with pytest.raises(ValueError, match="6243 is not an int"):
        setting.encode(1, replace(CHILD, params={6243: "dual"}))


@pytest.mark.parametrize(
    "view",
    [{"by": "mode_1", "map": {}}, {"by": True, "map": {}}, {"by": None}, "6243"],
)
def test_a_malformed_view_names_the_file(data_root: Path, view: object) -> None:
    read = {"param": 2731, "map": {}, "view": view}
    _write_model(data_root, {"q": {**_QUALITY, "read": read}})
    with pytest.raises(ModelDataError, match=r"T0001\.json"):
        settings_of("T0001")


_MODES = ("away", "home", "custom_1", "custom_2", "custom_3")
_DELAY_PIN = tuple(
    (f"{kind}_delay_{mode}", 0, 300, param)
    for kind, first in (("alarm", 1166), ("leaving", 1171))
    for param, mode in enumerate(("home", "away", "custom_1", "custom_2", "custom_3"), first)
)
_ACTION_PARAMS = (1239, 1225, 1148, 1149, 1150)


@pytest.mark.parametrize("scope", [Scope.CAMERA, Scope.SENSOR])
def test_mode_table_settings_keys_ranges_and_read_params(scope: Scope) -> None:
    actions = tuple(
        (f"{scope}_action_{mode}", 0, 511, param)
        for mode, param in zip(_MODES, _ACTION_PARAMS, strict=True)
    )
    pinned = tuple((s.key, s.minimum, s.maximum, s.read_param) for s in mode_table_settings(scope))
    assert pinned == _DELAY_PIN + actions


def test_mode_table_settings_wrap_the_hand_written_entries() -> None:
    camera = {s.key: s for s in mode_table_settings(Scope.CAMERA)}
    sensor = {s.key for s in mode_table_settings(Scope.SENSOR)}
    assert "camera_action_away" in camera
    assert "sensor_action_away" in sensor - set(camera)
    assert mode_table_settings(Scope.STATION) == ()
    delay = camera["alarm_delay_home"]
    assert (delay.kind, delay.minimum, delay.maximum, delay.step) == (SettingKind.RANGE, 0, 300, 1)
    assert delay.unit is SettingUnit.SECONDS
    assert delay.read_param == mode_table_setting("alarm_delay_home").read_param
    action = camera["camera_action_away"]
    assert (action.minimum, action.maximum, action.unit) == (
        0,
        functools.reduce(operator.or_, ACTION_FLAGS.values()),
        None,
    )
    assert action.writable
    assert not action.labels
    assert action.validate(3) == 3
    with pytest.raises(ValueError, match=r"outside 0\.\.300"):
        delay.validate(301)


def test_bundled_td_version_comes_from_the_files_source_block() -> None:
    version = model_settings.bundled_td_version("t8160")
    assert isinstance(version, int)
    assert version > 0
    assert model_settings.bundled_td_version("T9999") is None
    assert model_settings.bundled_td_version("bad code!") is None


def test_a_code_missing_from_the_index_has_no_settings(data_root: Path) -> None:
    doc = {"schema_version": 3, "product_code": "T0002", "settings": {"ok_1": GOOD_ENTRY}}
    (data_root / "T0002.json").write_text(json.dumps(doc), encoding="utf-8")
    assert settings_of("T0002") == {}
    assert bundled_codes() == ("T0001",)


def test_an_indexed_code_without_a_file_names_the_file(data_root: Path) -> None:
    with pytest.raises(ModelDataError, match=r"T0001\.json: listed in INDEX\.json but missing"):
        settings_of("T0001")


@pytest.mark.parametrize(
    ("codes", "schema_version"),
    [(["T0001"], 1), ("T0001", 2), (["t0001"], 2), ([1], 2)],
)
def test_a_malformed_index_names_the_index(
    data_root: Path, codes: object, schema_version: int
) -> None:
    _write_index(data_root, codes, schema_version)
    with pytest.raises(ModelDataError, match=r"INDEX\.json"):
        bundled_codes()
