"""Settings that share a bitmask parameter, multi-choice flags, and the control a UI shows."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    Setting,
    SettingControl,
    SettingKind,
    SettingMeaning,
    WriteContext,
    settings_of,
)
from eufy_home_security.exceptions import ModelDataError

CHILD = WriteContext(
    standalone=False, channel=3, device_sn="T0000CHILDSN0001", station_sn="T0000STATION0001"
)


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    (tmp_path / "INDEX.json").write_text(
        json.dumps({"schema_version": 3, "codes": ["T0001"]}), encoding="utf-8"
    )
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()
    yield tmp_path
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


def _load(root: Path, settings: Mapping[str, Mapping[str, object]]) -> dict[str, Setting]:
    entries = {k: {"section": "other", "role": "setting", **e} for k, e in settings.items()}
    doc = {"schema_version": 3, "product_code": "T0001", "settings": entries}
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    return dict(settings_of("T0001"))


BIT_SWITCH = {
    "access": "rw",
    "kind": "bool",
    "bit": 256,
    "control": "switch",
    "read": {"param": 1283, "map": None},
    "write": {
        "cmd": 1350,
        "subCmd": 1283,
        "params": {"arm_push_mode": "$v:int"},
        "update": {"needUpdate": True, "cmd": 1283, "paramValue": "$v:str"},
    },
}

DETECTION = {
    "access": "rw",
    "kind": "flags",
    "control": "toggles",
    "flags": {"1": 3, "2": 4, "3": 8, "4": 32768},
    "labels": {"1": "Human", "2": "Vehicle", "3": "Pet", "4": "All Other Motions"},
    "read": {"param": 1298, "map": None},
    "write": {
        "cmd": 1350,
        "subCmd": 1298,
        "params": {"ai_detect_type": "$v:int", "channel": "$channel"},
    },
}


def test_a_bit_switch_reads_its_bit_only(data_root: Path) -> None:
    s = _load(data_root, {"notification_ignore_switch": BIT_SWITCH})["notification_ignore_switch"]
    assert (s.kind, s.bit) == (SettingKind.BOOL, 256)
    assert s.decode("464") is True  # 256 set among other bits
    assert s.decode("208") is False
    assert s.decode("x") is None


def test_a_bit_switch_writes_the_whole_mask_it_is_given(data_root: Path) -> None:
    s = _load(data_root, {"k": BIT_SWITCH})["k"]
    assert s.mask_with(208, True) == 464
    assert s.mask_with(464, False) == 208
    wire = s.encode_mask(464, CHILD)
    assert (wire.cmd, dict(wire.params or {})) == (1283, {"arm_push_mode": 464})
    with pytest.raises(ValueError, match="current mask"):
        s.encode(True, CHILD)


def test_flags_decode_to_the_set_keys_and_keep_other_bits(data_root: Path) -> None:
    s = _load(data_root, {"detection_type_set": DETECTION})["detection_type_set"]
    assert s.kind is SettingKind.FLAGS
    assert s.decode_flags("196623") == (frozenset({"1", "2", "3"}), 196608)
    assert s.decode("196623") == 196623
    assert s.flag_label("1") == "Human"


def test_a_flag_change_keeps_every_other_bit(data_root: Path) -> None:
    s = _load(data_root, {"d": DETECTION})["d"]
    assert s.with_flag(196623, "3", on=False) == 196615
    assert s.with_flag(196615, "4", on=True) == 196615 | 32768
    with pytest.raises(ValueError, match="flag"):
        s.with_flag(0, "9", on=True)
    wire = s.encode(196615, CHILD)
    assert dict(wire.params or {}) == {"ai_detect_type": 196615, "channel": 3}


def test_a_multi_bit_flag_is_on_only_when_all_its_bits_are(data_root: Path) -> None:
    s = _load(data_root, {"d": {**DETECTION, "flags": {"1": 3, "2": 4}}})["d"]
    assert s.decode_flags("1")[0] == frozenset()  # 3 needs both bits
    assert s.decode_flags("3")[0] == frozenset({"1"})


@pytest.mark.parametrize(
    ("entry", "control"),
    [
        ({"access": "rw", "kind": "bool", "control": "switch"}, SettingControl.SWITCH),
        (
            {"access": "rw", "kind": "range", "min": 1, "max": 100, "step": 1, "control": "slider"},
            SettingControl.SLIDER,
        ),
        ({"access": "ro", "kind": "range", "min": 1, "max": 100, "step": 1}, None),
    ],
)
def test_control_comes_from_the_file(
    data_root: Path, entry: dict[str, object], control: object
) -> None:
    write = {"cmd": 1230, "params": {"volume": "$v"}} if entry["access"] == "rw" else None
    full = {**entry, "read": None, **({"write": write} if write else {})}
    assert _load(data_root, {"k": full})["k"].control is control


@pytest.mark.parametrize(
    "entry",
    [
        {"access": "rw", "kind": "bool", "control": "slider"},  # wrong control for the kind
        {"access": "rw", "kind": "enum", "values": [0, 1]},  # writable without a control
        {**DETECTION, "flags": {}},  # flags without names
        {**DETECTION, "flags": {"1": 0}},  # a flag with no bit
        {**BIT_SWITCH, "kind": "enum", "values": [0, 1], "control": "select"},  # bit on an enum
    ],
)
def test_inconsistent_control_or_flags_name_the_file(
    data_root: Path, entry: dict[str, object]
) -> None:
    full = {"read": None, "write": {"cmd": 1, "params": {"v": "$v"}}, **entry}
    with pytest.raises(ModelDataError, match=r"T0001\.json"):
        _load(data_root, {"k": full})


# A read-only status mask, as a smoke sensor's handler reads it from one parameter.
SMOKE_FLAGS = {
    "alarm": 1,
    "localTesting": 2,
    "remotingTesting": 4,
    "battery": 8,
    "trouble": 16,
    "muting": 32,
    "endoflife": 64,
    "highAlarm": 128,
}
SMOKE_STATUS = {
    "access": "ro",
    "kind": "flags",
    "role": "status",
    "flags": SMOKE_FLAGS,
    "flag_meanings": {
        "alarm": "smoke",
        "highAlarm": "smoke",
        "localTesting": "testing",
        "remotingTesting": "testing",
        "battery": "low_battery",
        "trouble": "problem",
        "muting": "muted",
        "endoflife": "end_of_life",
    },
    "read": {"param": 1823, "map": None, "no_default": True},
}


def test_a_read_only_flags_status_reads_its_mask(data_root: Path) -> None:
    s = _load(data_root, {"sensor_smoke_status": SMOKE_STATUS})["sensor_smoke_status"]
    assert (s.kind, s.writable, s.readable, s.control) == (SettingKind.FLAGS, False, True, None)
    assert s.read_param == 1823
    assert s.decode("3") == 3
    assert s.decode("x") is None


def test_flag_values_give_every_member_on_or_off(data_root: Path) -> None:
    s = _load(data_root, {"k": SMOKE_STATUS})["k"]
    on = {"alarm", "localTesting"}
    assert s.flag_values("3") == {m: m in on for m in SMOKE_FLAGS}
    assert s.flag_values(3) == s.flag_values("3")
    assert s.flag_values(0) == dict.fromkeys(SMOKE_FLAGS, False)


@pytest.mark.parametrize("raw", [None, "", "x", "-1", True, 1.5])
def test_flag_values_of_an_unreported_or_malformed_value_are_none(
    data_root: Path, raw: object
) -> None:
    assert _load(data_root, {"k": SMOKE_STATUS})["k"].flag_values(raw) is None


def test_flag_meanings_load_as_meanings(data_root: Path) -> None:
    s = _load(data_root, {"k": SMOKE_STATUS})["k"]
    assert s.flag_meanings["highAlarm"] is SettingMeaning.SMOKE
    assert s.flag_meanings["muting"] is SettingMeaning.MUTED
    assert s.flag_meanings["endoflife"] is SettingMeaning.END_OF_LIFE
    assert s.flag_meanings["trouble"] is SettingMeaning.PROBLEM
    assert s.flag_meanings["remotingTesting"] is SettingMeaning.TESTING
    assert s.flag_meanings["battery"] is SettingMeaning.LOW_BATTERY
    assert s.meaning is None  # the mask itself names no state


@pytest.mark.parametrize(
    ("raw", "smoke"),
    [
        ("1", True),  # alarm
        ("128", True),  # high alarm
        ("129", True),
        ("3", True),  # alarm while testing
        ("0", False),
        ("2", False),  # a test press alone
        ("4", False),
        ("126", False),  # every other member
        ("256", False),  # a bit no member names
        (None, None),  # not reported
        ("", None),
        ("x", None),
        ("-1", None),
    ],
)
def test_meaning_on_is_any_member_of_that_meaning(
    data_root: Path, raw: str | None, smoke: bool | None
) -> None:
    s = _load(data_root, {"k": SMOKE_STATUS})["k"]
    assert s.meaning_on(raw, SettingMeaning.SMOKE) is smoke


def test_meaning_on_takes_the_decoded_mask_too(data_root: Path) -> None:
    s = _load(data_root, {"k": SMOKE_STATUS})["k"]
    assert s.meaning_on(s.decode("8"), SettingMeaning.LOW_BATTERY) is True
    assert s.meaning_on(s.decode("8"), SettingMeaning.SMOKE) is False


def test_meaning_on_refuses_a_meaning_no_member_carries(data_root: Path) -> None:
    s = _load(data_root, {"k": SMOKE_STATUS})["k"]
    with pytest.raises(ValueError, match="moisture"):
        s.meaning_on("1", SettingMeaning.MOISTURE)
    with pytest.raises(ValueError, match="flags"):
        _load(data_root, {"b": BIT_SWITCH})["b"].meaning_on("1", SettingMeaning.SMOKE)


def test_a_flags_setting_without_flag_meanings_has_none(data_root: Path) -> None:
    s = _load(data_root, {"d": DETECTION})["d"]
    assert dict(s.flag_meanings) == {}
    assert s.flag_values("4") == {"1": False, "2": True, "3": False, "4": False}


def test_a_multi_bit_member_is_on_only_when_all_its_bits_are(data_root: Path) -> None:
    s = _load(data_root, {"d": DETECTION})["d"]
    assert s.flag_values("1") == {"1": False, "2": False, "3": False, "4": False}  # 3 needs 1|2
    assert s.flag_values("3") == {"1": True, "2": False, "3": False, "4": False}


def test_flag_values_of_a_setting_that_is_no_flags_mask_are_none(data_root: Path) -> None:
    assert _load(data_root, {"b": BIT_SWITCH})["b"].flag_values("256") is None


@pytest.mark.parametrize(
    "meanings",
    [
        {"alarm": "duration"},  # not a binary meaning
        {"alarm": "no_such_meaning"},
        {"siren": "smoke"},  # not a member
        {},  # names nothing
        ["smoke"],  # not an object
    ],
)
def test_bad_flag_meanings_name_the_file(data_root: Path, meanings: object) -> None:
    with pytest.raises(ModelDataError, match=r"T0001\.json"):
        _load(data_root, {"k": {**SMOKE_STATUS, "flag_meanings": meanings}})


def test_flag_meanings_on_a_setting_that_is_no_flags_name_the_file(data_root: Path) -> None:
    entry = {**BIT_SWITCH, "flag_meanings": {"x": "smoke"}}
    with pytest.raises(ModelDataError, match=r"T0001\.json"):
        _load(data_root, {"k": entry})
