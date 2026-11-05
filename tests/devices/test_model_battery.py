"""A device's battery level from the parameters its model's file names
(``devices.model_settings.battery_level``)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    DEFAULT_BATTERY_READS,
    BatteryRead,
    battery_level,
    battery_reads,
)
from eufy_home_security.exceptions import ModelDataError

GOOD_ENTRY = {"access": "ro", "kind": "bool", "read": None, "section": "other", "role": "status"}


def _clear() -> None:
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A temporary models directory the loader reads from, indexing ``T0001``."""
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    index = {"schema_version": 3, "codes": ["T0001"]}
    (tmp_path / "INDEX.json").write_text(json.dumps(index), encoding="utf-8")
    _clear()
    yield tmp_path
    _clear()


def _write(root: Path, battery: object) -> None:
    doc = {"schema_version": 3, "product_code": "T0001", "settings": {"mode": GOOD_ENTRY}}
    if battery is not None:
        doc["battery"] = battery
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")


def test_the_file_names_the_battery_parameters_in_order(data_root: Path) -> None:
    _write(data_root, [{"param": 1101, "levels": {"0": None, "200": 100}}, {"param": 6001}])
    assert battery_reads("t0001") == (
        BatteryRead(1101, {"0": None, "200": 100}),
        BatteryRead(6001),
    )


@pytest.mark.parametrize(
    ("params", "level"),
    [
        ({1101: "57"}, 57),
        ({1101: "0"}, None),  # a raw value the file reads as no level
        ({1101: "200"}, 100),  # a raw value the file reads as another level
        ({1101: "abc"}, None),
        ({1101: "-1"}, None),  # the app's no-level value
        ({1101: "", 6001: "40"}, None),  # the first listed one decides, even when empty
        ({6001: "40"}, 40),  # the second parameter when the first is not reported
        ({1101: "30", 6001: "40"}, 30),  # the first one listed wins
        ({1101: "0", 6001: "40"}, None),  # even when it reads as no level
        ({6001: "0"}, 0),  # levels belong to their own parameter
        ({1102: "40"}, None),
        ({}, None),
    ],
)
def test_the_level_is_the_first_listed_parameter_the_device_reports(
    data_root: Path, params: dict[int, str], level: int | None
) -> None:
    _write(data_root, [{"param": 1101, "levels": {"0": None, "200": 100}}, {"param": 6001}])
    assert battery_level("T0001", params) == level


@pytest.mark.parametrize("code", [None, "T9ZZ9", "not a code!"])
def test_a_model_without_a_file_reads_1101_as_reported(code: str | None) -> None:
    assert battery_reads(code) == DEFAULT_BATTERY_READS == (BatteryRead(1101),)
    assert battery_level(code, {1101: "255", 6001: "40"}) == 255
    assert battery_level(code, {1101: "-1"}) is None


def test_a_file_without_a_battery_reads_1101_as_reported(data_root: Path) -> None:
    _write(data_root, None)
    assert battery_level("T0001", {1101: "0", 6001: "40"}) == 0


@pytest.mark.parametrize(
    ("code", "params", "level"),
    [
        ("T85P1", {1101: "255"}, None),  # its handler reads 0 and 255 as no level
        ("T85P1", {1101: "0"}, None),
        ("T85P1", {1101: "57"}, 57),
        ("T8503", {6001: "40"}, 40),  # its handler reads 1101 and 6001
        ("T8503", {1101: "30", 6001: "40"}, 30),
        ("T8160", {1101: "255"}, 255),  # 1101 as reported
        ("T8160", {6001: "40"}, None),
    ],
)
def test_bundled_models_read_their_battery_as_their_file_says(
    code: str, params: dict[int, str], level: int | None
) -> None:
    assert battery_level(code, params) == level


@pytest.mark.parametrize(
    ("battery", "match"),
    [
        ({"param": 1101}, "not a list"),
        ([1101], r"\{param, levels\}"),
        ([{"param": 1101, "map": {}}], r"\{param, levels\}"),
        ([{"levels": {}}], "no parameter id"),
        ([{"param": "1101"}], "no parameter id"),
        ([{"param": True}], "no parameter id"),
        ([{"param": 0}], "no parameter id"),
        ([{"param": 65536}], "no parameter id"),
        ([{"param": 1101, "levels": [0]}], "text -> level"),
        ([{"param": 1101, "levels": {"0": "1"}}], "text -> level"),
        ([{"param": 1101, "levels": {"0": False}}], "text -> level"),
        ([{"param": 1101}, {"param": 1101}], "listed twice"),
    ],
)
def test_a_malformed_battery_names_the_file(data_root: Path, battery: object, match: str) -> None:
    _write(data_root, battery)
    with pytest.raises(ModelDataError, match=rf"T0001\.json.*{match}"):
        battery_reads("T0001")


def test_the_boundary_parameter_ids_load(data_root: Path) -> None:
    _write(data_root, [{"param": 1}, {"param": 65535}])
    assert [r.param for r in battery_reads("T0001")] == [1, 65535]
