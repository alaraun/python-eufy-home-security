from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

from eufy_home_security.devices.matrix import render_support_matrix
from eufy_home_security.devices.model_settings import bundled_codes, settings_of
from eufy_home_security.devices.types import MODELS

ROOT = Path(__file__).resolve().parents[2]


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_device_matrix", ROOT / "scripts" / "gen_device_matrix.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_render_is_deterministic_and_complete() -> None:
    text = render_support_matrix()
    assert text == render_support_matrix()
    assert all(f"| {model} |" in text for model in MODELS)
    assert "**verified**" in text
    assert "| tier |" not in text
    assert "| support | source |" not in text.split("\n## Settings\n", 1)[1]


def test_docs_are_up_to_date() -> None:
    assert _generator().main(["--check"]) == 0


def test_check_detects_stale_file(tmp_path: Path) -> None:
    stale = tmp_path / "devices.md"
    stale.write_text("old\n", encoding="utf-8")
    generator = _generator()
    assert generator.main(["--check", "--output", str(stale)]) == 1
    assert generator.main(["--output", str(stale)]) == 0
    assert generator.main(["--check", "--output", str(stale)]) == 0
    sys.stdout.flush()


def _settings_block(text: str, code: str) -> str:
    """The ``### Settings of <code>`` part of ``## Settings``, heading line excluded."""
    section = text.split("\n## Settings\n", 1)[1]
    heading = re.search(rf"^### Settings of {code}( .*)?$", section, re.MULTILINE)
    assert heading is not None, code
    return section[heading.end() :].split("\n### ", 1)[0]


def _settings_rows(text: str, code: str) -> dict[str, list[str]]:
    """The settings table of ``code`` under ``## Settings``: key → cells."""
    rows = {}
    for line in _settings_block(text, code).splitlines():
        if line.startswith("| `"):
            cells = [cell.strip() for cell in line.strip("|").split(" | ")]
            rows[cells[0].strip("`")] = cells
    return rows


def test_a_models_settings_table_shows_values_labels_and_writable() -> None:
    row = _settings_rows(render_support_matrix(), "T8160")["power_manager_mode"]
    assert row[1:6] == ["enum", "0, 1, 3", "-", "yes", "select"]
    assert "0=Optimal battery life" in row[6]


def test_a_models_settings_table_names_each_control() -> None:
    rows = _settings_rows(render_support_matrix(), "T8160")
    assert rows["detection_sensitivity"][1:6] == ["range", "1..7 step 1", "-", "yes", "slider"]
    assert rows["detection_type_set"][1] == "flags"
    assert rows["detection_type_set"][5] == "toggles"
    assert rows["led_on_off"][5] == "switch"
    assert rows["battery_value"][4:6] == ["no", "-"]


def test_every_bundled_model_has_a_section_with_the_files_counts() -> None:
    text = render_support_matrix()
    codes = bundled_codes()
    assert len(codes) == 107
    assert text.count("\n### Settings of ") == len(codes)
    for code in codes:
        settings = settings_of(code)
        rw = sum(1 for s in settings.values() if s.writable)
        assert (
            _settings_block(text, code).split("\n\n", 2)[1] == f"rw {rw} / ro {len(settings) - rw}"
        )
        assert sorted(_settings_rows(text, code)) == sorted(settings), code


def test_a_profile_links_its_models_settings_section() -> None:
    text = render_support_matrix()
    profile = text.split("\n## T8160 ", 1)[1].split("\n## ", 1)[0]
    assert "Settings: rw 31 / ro 72, see [Settings of T8160 " in profile
    assert "(#settings-of-t8160-eufycam-3-s330)" in profile


def test_a_range_renders_min_max_and_step() -> None:
    row = _settings_rows(render_support_matrix(), "T8030")["alarm_volume_value"]
    assert row[1:5] == ["range", "1..26 step 1", "-", "yes"]
