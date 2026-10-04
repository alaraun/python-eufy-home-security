"""Setting meanings and evidence, as the capability evidence, the protocol doc and the
verification log state them.

- ``time_system`` (1253) reads 0 = 12 h, 1 = 24 h; the T8030 ``SETTINGS_WRITE`` evidence
  rests on it and is verified by the app-display check.
- ``night_vision`` (1277) carries the vendor's 0/1/2 and keeps 3 as undocumented.
- The round-trip-only settings are marked declared; the T8160 ``SETTINGS_WRITE`` note
  names the numeric settings and the power_mode codes it rests on.
"""

from __future__ import annotations

import re
from pathlib import Path

from eufy_home_security.devices.capabilities import PROFILES, Capability
from eufy_home_security.devices.support import Support

from .verification_log import VERIFIED_MARK, backticked, log_rows

ROOT = Path(__file__).resolve().parents[2]

# The five settings whose ``verified`` mark would rest only on a write round-trip.
ROUND_TRIP_ONLY = ("detection_type", "mirror", "power_mode", "record_autostop", "status_led")
# power_mode is verified by the app-display check; these four are declared.
DECLARED_MEANINGS = tuple(key for key in ROUND_TRIP_ONLY if key != "power_mode")
# The T8160 numeric settings its verified SETTINGS_WRITE claim rests on.
CAM3_NUMERIC = (
    "pir_sensitivity",
    "motion_sensitivity",
    "retrigger_interval",
    "clip_length",
    "speaker_volume",
)
# The protocol doc's command id of each setting it describes.
COMMAND_IDS = {
    "time_system": 1253,
    "night_vision": 1277,
    "power_mode": 1246,
    "detection_type": 1298,
    "mirror": 1207,
    "record_autostop": 1251,
    "status_led": 1045,
}


# ── capability evidence ───────────────────────────────────────────────────────────────


def test_t8030_settings_write_is_verified_by_the_app_display() -> None:
    evidence = PROFILES["T8030"].capabilities[Capability.SETTINGS_WRITE]
    # Verified by an app-display observation.
    assert evidence.support is Support.VERIFIED
    assert "seen in the eufy app" in evidence.note
    assert "1253 = 1" in evidence.note


# ── round-trip-only settings ───────────────────────────────────────────────────────────


def test_round_trip_only_keys_sit_in_a_non_verified_log_row() -> None:
    """Each round-trip-only key is named in a ``Settings…`` row that is not marked
    verified."""
    rows = log_rows()
    logged: set[str] = set()
    for area, (mark, notes) in rows.items():
        if area.startswith("Settings") and mark != VERIFIED_MARK:
            logged |= backticked(notes)
    assert set(DECLARED_MEANINGS) <= logged, sorted(set(DECLARED_MEANINGS) - logged)
    # Each declared key's own row states what the write did not prove.
    for key in DECLARED_MEANINGS:
        mark, notes = rows[f"Settings, camera: {key}"]
        assert mark != VERIFIED_MARK, key
        assert "did not establish the value-to-label meaning" in notes, key


def test_cam3_settings_write_names_the_numeric_settings() -> None:
    evidence = PROFILES["T8160"].capabilities[Capability.SETTINGS_WRITE]
    assert evidence.support is Support.VERIFIED
    for key in CAM3_NUMERIC:
        assert key in evidence.note, key


# ── the protocol doc ───────────────────────────────────────────────────────────────────


def _commands_row(command_id: int) -> str:
    """The one ``docs/protocol/commands.md`` settings-table row whose cmd cell is
    ``command_id``."""
    text = (ROOT / "docs" / "protocol" / "commands.md").read_text("utf-8")
    rows = []
    for line in text.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) > 1 and cells[1] == str(command_id):
            rows.append(line)
    assert len(rows) == 1, (command_id, rows)
    return rows[0]


def test_commands_doc_states_the_clock_and_night_vision_meanings() -> None:
    """The protocol doc: clock format reads 0 = 12 h, 1 = 24 h; night vision carries 0..3
    with the vendor meanings of 0/1/2 and no meaning for 3."""
    clock = _commands_row(COMMAND_IDS["time_system"])
    assert "0 = 12 h, 1 = 24 h" in clock
    assert "vendor corpus" in clock
    night = _commands_row(COMMAND_IDS["night_vision"])
    assert r"<0\|1\|2\|3>" in night
    assert "0 off, 1 black & white, 2 color" in night
    assert "3's meaning is unknown" in night
    assert "infrared" not in night.lower()


def test_commands_doc_marks_the_round_trip_only_meanings_declared() -> None:
    """The protocol doc: each round-trip-only setting's row says the wire is verified and the
    meaning declared, and never grades the row plainly ``[verified]``."""
    for key in DECLARED_MEANINGS:
        row = _commands_row(COMMAND_IDS[key])
        assert "**[wire verified]**" in row, key
        assert "meaning **[declared]**" in row, key
        assert "**[verified]**" not in row, key
    # The power_mode row's labels are settled, not disputed.
    assert "labels disputed" not in _commands_row(COMMAND_IDS["power_mode"])


# ── power_mode ─────────────────────────────────────────────────────────────────────────


def test_power_mode_verification_log_row() -> None:
    mark, notes = log_rows()["Settings, camera: power_mode"]
    assert mark == VERIFIED_MARK
    assert "`power_mode`" in notes
    for fact in (
        "T8160",
        "fw 3.4.3.0",
        "seen in the eufy app",
        'both are showing "Optimal Surveillance"',
        '"Custom"',
        '"Optimal Battery Life"',
        "never acted on",
    ):
        assert fact in notes, fact


def test_power_mode_commands_row() -> None:
    row = _commands_row(COMMAND_IDS["power_mode"])
    assert r"<0\|1\|2\|3>" in row
    assert "0 optimal battery life, 1 optimal surveillance, 2 custom" in row
    assert "3 undocumented" in row
    assert "**[verified]**" in row


def test_cam3_settings_write_names_power_mode() -> None:
    """power_mode is verified, so the T8160 settings-write claim names it."""
    note = PROFILES["T8160"].capabilities[Capability.SETTINGS_WRITE].note
    assert "power_mode codes 0-3" in note
    for key in DECLARED_MEANINGS:
        assert key not in note, key
