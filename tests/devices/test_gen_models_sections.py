"""``scripts/gen_models_sections.py``: the page table, the identifier rules and variants."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.devices.sections import OTHER_SECTION, SETTING_SECTIONS

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
sections = _load("gen_models_sections")
IDS = {s.id for s in SETTING_SECTIONS}


def _committed_pages() -> set[str]:
    pages: set[str] = set()
    for path in MODELS.glob("T*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        pages |= {e["page"] for e in doc["settings"].values() if "page" in e}
    return pages


def test_every_page_of_the_bundled_files_is_in_the_page_table() -> None:
    assert _committed_pages() <= set(sections.PAGE_SECTIONS)


def test_the_tables_name_catalogue_sections_and_compile() -> None:
    named = {s for s in sections.PAGE_SECTIONS.values() if s is not None}
    named |= {s for _, s in (*sections.STATION_RULES, *sections.KEY_RULES)}
    assert named <= IDS - {OTHER_SECTION}
    for pattern, _ in (*sections.STATION_RULES, *sections.KEY_RULES):
        re.compile(pattern)


def _entry(**fields: Any) -> dict[str, Any]:
    return {"kind": "bool", "access": "rw", **fields}


def test_a_page_decides_then_the_station_rules_then_the_key_rules() -> None:
    settings = {
        "video_clip_length": _entry(page="PanTiltSettings"),  # the page wins
        "power_manager_mode": _entry(page="MotionDetection"),  # a mixed page defers
        "led_on_off": _entry(),
        "speaker_volume": _entry(),
        "unheard_of": _entry(),
    }
    counts = sections.assign(settings, station=False)
    got = {k: e["section"] for k, e in settings.items()}
    assert got == {
        "video_clip_length": "ptz",
        "power_manager_mode": "power",
        "led_on_off": "picture",
        "speaker_volume": "audio",
        "unheard_of": OTHER_SECTION,
    }
    assert counts == {"section:page": 1, "section:key": 3, "section:none": 1}
    station = {"led_on_off": _entry()}
    assert sections.assign(station, station=True) == {"section:station": 1}
    assert station["led_on_off"]["section"] == "system"


@pytest.mark.parametrize(
    ("ident", "section"),
    [
        ("device_monitor_indoor_temperature_switch", "alarm"),
        ("device_indoor_temperatur_alarm_max_value", "alarm"),
        ("device_indoor_temperature_unit", "system"),
        ("device_white_noise_volume", "audio"),
        ("daily_highlight_switch", "recording"),
        ("breathing_light_schedule_config", "picture"),
        ("zoom_spotlight_switch", "picture"),
        ("radar_test_mode_on_off", "detection"),
    ],
)
def test_an_identifier_rule_places_the_setting(ident: str, section: str) -> None:
    assert sections.section_of(ident, {}, station=False) == (section, "key")


def test_a_variant_takes_its_primary_s_section() -> None:
    settings = {
        "spotlight_status": _entry(),
        "enable_floodlights_status": _entry(variant_of="spotlight_status"),
        "record_resolution__v1": _entry(variant_of="spotlight_status"),
    }
    counts = sections.assign(settings, station=False)
    assert {e["section"] for e in settings.values()} == {"picture"}
    assert counts["section:variant"] == 2


def test_an_unlisted_page_is_an_error() -> None:
    with pytest.raises(codec.GeneratorError, match="NewScreen"):
        sections.assign({"x": _entry(page="NewScreen")}, station=False)
