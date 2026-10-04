"""The device time-zone table: ids, the device form and reading it back."""

from __future__ import annotations

import importlib.util
import json
import sys
import zoneinfo
from pathlib import Path
from types import ModuleType

import pytest

from eufy_home_security.devices.timezones import (
    decode_zone,
    encode_zone,
    time_zones,
    zone_ids,
)

ROOT = Path(__file__).resolve().parents[2]
TABLE = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "timezones.json"


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_timezones", ROOT / "scripts" / "gen_timezones.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_every_zone_is_a_zoneinfo_key_with_a_unique_row_number() -> None:
    zones = time_zones()
    assert len(zones) > 400
    assert zone_ids() == tuple(z.id for z in zones)
    assert len({z.id for z in zones}) == len({z.sn for z in zones}) == len(zones)
    assert not {z.id for z in zones} - zoneinfo.available_timezones()
    assert all(z.posix and "|" not in z.posix for z in zones)


@pytest.mark.parametrize(
    ("zone_id", "device"),
    [
        ("Europe/Tallinn", "EET-2EEST,M3.5.0/3,M10.5.0/4|1.1416"),
        ("Europe/London", "GMT0BST,M3.5.0/1,M10.5.0|1.1394"),
        ("Asia/Tokyo", "JST-9|1.1307"),
    ],
)
def test_a_zone_round_trips_through_the_device_form(zone_id: str, device: str) -> None:
    assert encode_zone(zone_id) == device
    assert decode_zone(device) == zone_id


def test_an_id_outside_the_table_is_refused() -> None:
    with pytest.raises(ValueError, match="not a zone"):
        encode_zone("Mars/Olympus")


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "Europe/Tallinn",
        "EET-2EEST,M3.5.0/3,M10.5.0/4",
        "GMT0|1.",
        "GMT0|1.x",
        "GMT0|1.99999",
    ],
)
def test_a_device_value_without_a_known_row_number_is_not_placed(raw: str | None) -> None:
    assert decode_zone(raw) is None


def test_a_row_number_wins_over_the_rule_beside_it() -> None:
    """The rule is the device clock's; the row number names the zone (one rule, many zones)."""
    assert decode_zone("GMT0|1.1416") == "Europe/Tallinn"
    assert decode_zone("EET-2EEST,M3.5.0/3,M10.5.0/4|1.1386|extra") == "Europe/Helsinki"


def test_the_generator_builds_the_shipped_layout_and_refuses_bad_rows() -> None:
    gen = _generator()
    rows = [
        {"timeZoneName": "A", "timeId": "Europe/Tallinn", "timeSn": "1416", "timeZoneGMT": "EET-2"},
        {"timeZoneName": "B", "timeId": "Asia/Tokyo", "timeSn": "1307", "timeZoneGMT": "JST-9"},
    ]
    text = gen.render(gen.build(rows, "1.0"))
    data = json.loads(text)
    assert data["zones"] == [
        {"id": "Europe/Tallinn", "posix": "EET-2", "sn": 1416},
        {"id": "Asia/Tokyo", "posix": "JST-9", "sn": 1307},
    ]
    assert data["source"]["app_version"] == "1.0"
    shipped = json.loads(TABLE.read_text(encoding="utf-8"))
    assert TABLE.read_text(encoding="utf-8") == gen.render(shipped)
    for bad in (
        [rows[0], {**rows[1], "timeSn": "1416"}],
        [rows[0], {**rows[1], "timeId": "Europe/Tallinn"}],
        [{**rows[0], "timeZoneGMT": "a|b"}],
        [{**rows[0], "timeSn": "x"}],
    ):
        with pytest.raises(ValueError, match=r"row|duplicate|separator"):
            gen.build(bad, "1.0")
