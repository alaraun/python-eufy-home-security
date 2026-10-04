"""Settings that share a bitmask parameter, multi-choice flags, and the control a UI shows."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    Setting,
    SettingControl,
    SettingKind,
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
        json.dumps({"schema_version": 2, "codes": ["T0001"]}), encoding="utf-8"
    )
    model_settings._load.cache_clear()
    model_settings.bundled_codes.cache_clear()
    yield tmp_path
    model_settings._load.cache_clear()
    model_settings.bundled_codes.cache_clear()


def _load(root: Path, settings: dict[str, object]) -> dict[str, Setting]:
    doc = {"schema_version": 2, "product_code": "T0001", "settings": settings}
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")
    model_settings._load.cache_clear()
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
    write = {"cmd": 1, "params": {"v": "$v"}} if entry["access"] == "rw" else None
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
