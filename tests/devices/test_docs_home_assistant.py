"""The Home Assistant guide's settings sections match the code.

``docs/how-to/home-assistant.md`` explains the per-model settings, their counts and
``applies_when`` under ``## Entities``. The counts table is recomputed here from the
bundled settings files, so the guide cannot drift from the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from eufy_home_security.devices.model_settings import settings_of
from eufy_home_security.devices.td import LISTED_NOTE

DOC = Path(__file__).resolve().parents[2] / "docs" / "how-to" / "home-assistant.md"
TEXT = DOC.read_text(encoding="utf-8")
ENTITIES = TEXT.split("\n## Entities\n", 1)[1].split("\n## ", 1)[0]
MODELS = ("T8030", "T8160", "T8170", "T8910")
ROW = re.compile(r"^\| (T\d{4}) \| (\d+) \| (\d+) \| (\d+) \|$", re.MULTILINE)
HEADINGS = ("### Settings per model", "### `applies_when`", "### Models without a settings file")
RETIRED_NAMES = (
    "### Evidence tiers",
    "### Settings from the model registry",
    "### The override file",
    "locally_unreliable",
    "setting_note",
    "setting_def",
    "async_set_setting_flag",
    "SettingDef",
    "registry_override",
    "`tier`",
    "catalogue",
)


def _section(heading: str) -> str:
    return ENTITIES.split(f"\n{heading}\n", 1)[1].split("\n### ", 1)[0]


@pytest.mark.parametrize("heading", HEADINGS)
def test_the_subsections_are_under_entities(heading: str) -> None:
    assert f"\n{heading}\n" in ENTITIES


@pytest.mark.parametrize("name", RETIRED_NAMES)
def test_the_section_names_no_retired_api(name: str) -> None:
    assert name not in ENTITIES


def test_the_section_names_the_settings_api() -> None:
    for phrase in (
        "station.settings_for(device_sn)",
        "station.setting(key, device_sn=…)",
        "state.setting(key, device_sn=…)",
        "station.async_set_setting(key, value, device_sn=…, channel=…)",
        "station.async_set_mode_action(",
        "CommandOutcome",
        "(group, page, order, key)",
    ):
        assert phrase in ENTITIES, phrase


def test_the_unknown_model_section_names_the_listing_and_its_status() -> None:
    section = _section(HEADINGS[2])
    for phrase in (
        f'`"{LISTED_NOTE}"`',
        "async_discover(refresh=True)",
        "eufy.model_status()",
        '"cloud-listed"',
        "newer_vendor_data",
        "UnsupportedError",
    ):
        assert phrase in section, phrase


def test_the_counts_table_is_the_computed_one() -> None:
    rows = {m[0]: tuple(int(n) for n in m[1:]) for m in ROW.findall(_section(HEADINGS[0]))}
    assert set(rows) == set(MODELS)
    for code in MODELS:
        settings = settings_of(code).values()
        writable = sum(1 for s in settings if s.writable)
        assert rows[code] == (len(settings), writable, len(settings) - writable), code


def test_applies_when_names_the_settings_that_carry_it() -> None:
    section = _section(HEADINGS[1])
    carrying = {k: s.applies_when for k, s in settings_of("T8160").items() if s.applies_when}
    assert carrying
    for key, (other, value) in carrying.items():
        assert f"`{key}`" in section
        assert f"`{other}` is `{value}`" in section


def test_the_guide_has_no_uncatalogued_model_sentence() -> None:
    assert "an uncatalogued model gives `()`" not in TEXT
    assert "Until the catalog has a profile for the model" not in TEXT
