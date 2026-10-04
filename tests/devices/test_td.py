"""``devices/td.py``: a vendor thing description as read-only settings."""

from __future__ import annotations

from typing import Any

import pytest

from eufy_home_security.devices.model_settings import SettingKind
from eufy_home_security.devices.settings import SettingUnit
from eufy_home_security.devices.td import (
    LISTED_NOTE,
    normalise_unit,
    parse_thing_description,
    td_version,
)
from eufy_home_security.testing.cloud import enum_property, range_property, thing_description

CODE = "T9999"  # no bundled file


def parse(*props: dict[str, Any]) -> dict[str, Any]:
    return dict(parse_thing_description(CODE, thing_description(CODE, list(props))))


def test_enum_lists_values_labels_and_default_read_only() -> None:
    (s,) = parse(
        enum_property("motion_sensitivity", {1: "low", 2: "中", 3: "高"}, default=2)
    ).values()
    assert s.kind is SettingKind.ENUM
    assert s.values == (1, 2, 3)
    assert dict(s.labels) == {1: "Low", 2: "Medium", 3: "High"}
    assert s.default == 2
    assert (s.writable, s.readable, s.note) == (False, False, LISTED_NOTE)
    assert s.name == "Motion sensitivity"
    assert s.product_code == CODE


def test_an_enum_without_a_usable_desc_falls_back_to_the_value() -> None:
    (s,) = parse(enum_property("mode_x", {4: "", "auto": ""})).values()
    assert dict(s.labels) == {4: "Value 4", "auto": "auto"}


def test_range_with_step_unit_and_default() -> None:
    (s,) = parse(range_property("record_time", 10, 120, step=5, unit="秒", default=60)).values()
    assert s.kind is SettingKind.RANGE
    assert (s.minimum, s.maximum, s.step) == (10, 120, 5)
    assert s.unit is SettingUnit.SECONDS
    assert s.default == 60


@pytest.mark.parametrize(
    ("lo", "hi", "unit"), [(0, 100, SettingUnit.PERCENT), (1, 100, SettingUnit.PERCENT)]
)
def test_volume_is_a_percentage_on_a_hundred_scale(lo: int, hi: int, unit: SettingUnit) -> None:
    (s,) = parse(range_property("speaker_volume", lo, hi, unit="音量")).values()
    assert s.unit is unit


@pytest.mark.parametrize("raw", ["lux", "音量"])
def test_an_unmapped_unit_is_dropped_not_raised(raw: str) -> None:
    (s,) = parse(range_property("speaker_volume", 0, 10, unit=raw)).values()
    assert s.unit is None


def test_normalise_unit_raises_value_error_when_unmapped() -> None:
    assert normalise_unit("个", 0, 3) is None
    assert normalise_unit("day", None, None) is SettingUnit.DAYS
    with pytest.raises(ValueError, match="lux"):
        normalise_unit("lux", 0, 100)


def test_bool_string_and_other_kinds() -> None:
    settings = parse(
        {"identifier": "led_on", "data_type": {"type": "bool", "specs": {"defaultValue": "1"}}},
        {"identifier": "nick", "data_type": {"type": "string", "specs": {}}},
        {"identifier": "blob", "data_type": {"type": "struct"}},
    )
    assert settings["led_on"].kind is SettingKind.BOOL
    assert settings["led_on"].default is True
    assert settings["nick"].kind is SettingKind.STRING
    assert settings["blob"].kind is SettingKind.OTHER


def test_identifiers_outside_the_key_alphabet_and_malformed_entries_are_skipped() -> None:
    settings = parse(
        range_property("ok_1", 0, 1),
        range_property("Bad-Id", 0, 1),
        {"identifier": 7},
        "not an object",  # type: ignore[arg-type]
        {"identifier": "no_type"},
    )
    assert sorted(settings) == ["no_type", "ok_1"]
    assert settings["no_type"].kind is SettingKind.OTHER


@pytest.mark.parametrize("td", [{}, {"properties": None}, {"properties": {}}])
def test_a_td_without_a_properties_list_raises(td: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=CODE):
        parse_thing_description(CODE, td)


def test_td_version_is_large_version() -> None:
    assert td_version(thing_description(CODE, [], large_version=124)) == 124
    assert td_version({}) is None
    assert td_version({"large_version": True}) is None
