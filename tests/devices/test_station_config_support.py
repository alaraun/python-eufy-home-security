"""The generated station configuration support table (devices/_station_config_data.py)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from eufy_home_security.devices import station_config_support as scs
from eufy_home_security.devices._station_config_data import FEATURES
from eufy_home_security.devices.model_settings import settings_of
from eufy_home_security.devices.station_config_support import (
    ALARM_AFFECTING,
    ModeTableStorage,
    StationFeature,
    config_support,
    cross_camera_intervals,
    max_custom_modes,
    min_firmware,
    mode_table_params,
    mode_table_storage,
    restart_command,
    station_config_models,
    stored_mode_table_params,
)
from eufy_home_security.devices.support import Support
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.station_config_codecs import (
    PRO_ALARM_MODE_TABLE_PARAMS,
    STORED_MODE_TABLE_PARAMS,
)

from .verification_log import VERIFIED_MARK, log_rows

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"
DATA = ROOT / ".work" / "notes" / "hb-config" / "data"

#: Station models with a thing description and handler on record.
ON_RECORD = (
    "T8001",
    "T8002",
    "T8010",
    "T8020",
    "T8023",
    "T8024",
    "T8025",
    "T8026",
    "T8030",
    "T8N00",
    "T9000",
)
#: Station models the app names without a thing description on record.
NOT_ON_RECORD = ("T7000", "T8021", "T8028", "T8040")

# The hardware-verification row that traces each verified (model, feature).
LOG_AREA: dict[tuple[str, StationFeature], str] = {
    ("T8030", StationFeature.GUARD_MODE): "Guard mode write",
    ("T8030", StationFeature.CUSTOM_MODES): "Custom modes (1256) library write",
    ("T8030", StationFeature.SCHEDULE): "Schedule (1254) library write",
    ("T8030", StationFeature.CROSS_CAMERA): "Cross-camera tracking cameras (1072) library write",
    (
        "T8030",
        StationFeature.CROSS_CAMERA_GROUPS,
    ): "Cross-camera tracking groups (1073) library write",
    ("T8030", StationFeature.MODE_TABLES): "Settings, mode table (1255) library write",
    ("T8030", StationFeature.MODE_DELAYS): "Settings, mode table (1255) library write",
    ("T8030", StationFeature.RESTART): "Station restart (1034) library call",
    ("T8030", StationFeature.SOUND_ALARM): "Station siren sound and stop (1201) library call",
}


def test_every_station_model_has_every_feature() -> None:
    assert station_config_models() == tuple(sorted(ON_RECORD + NOT_ON_RECORD))
    for code in station_config_models():
        assert set(FEATURES[code]) == {f.value for f in StationFeature}, code
        for feature in StationFeature:
            evidence = config_support(code, feature)
            assert evidence.source, (code, feature)


def test_a_model_without_a_thing_description_is_unknown_throughout() -> None:
    for code in NOT_ON_RECORD:
        for feature in StationFeature:
            evidence = config_support(code, feature)
            assert evidence.support is Support.UNKNOWN
            assert "no thing description" in evidence.source
        assert mode_table_storage(code) is None
        assert max_custom_modes(code) == 0


def test_homebase_3_grades_follow_the_hardware_checks() -> None:
    verified = {
        StationFeature.GUARD_MODE,
        StationFeature.MODE_TABLES,
        StationFeature.MODE_DELAYS,
        StationFeature.RESTART,
        StationFeature.SOUND_ALARM,
        StationFeature.CUSTOM_MODES,
        StationFeature.SCHEDULE,
        StationFeature.CROSS_CAMERA,
        StationFeature.CROSS_CAMERA_GROUPS,
    }
    for feature in StationFeature:
        expected = Support.VERIFIED if feature in verified else Support.DECLARED
        assert config_support("T8030", feature).support is expected, feature
    assert "not written" in config_support("T8030", StationFeature.ARMING_GROUPS).note


def test_every_verified_entry_is_in_the_verification_log() -> None:
    assert set(LOG_AREA) == set(scs._VERIFIED)
    rows = log_rows()
    for key, evidence in scs._VERIFIED.items():
        assert evidence.support is Support.VERIFIED
        assert rows[LOG_AREA[key]][0] == VERIFIED_MARK, key


def test_alarm_affecting_features() -> None:
    assert {
        StationFeature.GUARD_MODE,
        StationFeature.SCHEDULE,
        StationFeature.MODE_TABLES,
        StationFeature.MODE_DELAYS,
        StationFeature.ARMING_GROUPS,
        StationFeature.RESTART,
        StationFeature.SOUND_ALARM,
    } == ALARM_AFFECTING
    assert StationFeature.MODE_TABLES.alarm_affecting
    assert not StationFeature.CROSS_CAMERA.alarm_affecting
    assert not StationFeature.WORKING_MODE.alarm_affecting


@pytest.mark.parametrize(
    ("code", "storage"),
    [
        ("T8030", ModeTableStorage.HB3_TABLES),
        ("T8001", ModeTableStorage.ACTION_PARAMS),
        ("T8025", ModeTableStorage.ACTION_PARAMS),
        ("T8020", ModeTableStorage.PRO_ALARM),
        ("T8N00", ModeTableStorage.PRO_ALARM),
        ("t9000", ModeTableStorage.PRO_ALARM),
    ],
)
def test_mode_table_storage(code: str, storage: ModeTableStorage) -> None:
    assert mode_table_storage(code) is storage
    params = mode_table_params(code)
    assert set(params) == {
        GuardMode.AWAY,
        GuardMode.HOME,
        GuardMode.CUSTOM_1,
        GuardMode.CUSTOM_2,
        GuardMode.CUSTOM_3,
        GuardMode.DISARMED,
    }
    if storage is ModeTableStorage.HB3_TABLES:
        assert params == STORED_MODE_TABLE_PARAMS
    if storage is ModeTableStorage.PRO_ALARM:
        assert params == PRO_ALARM_MODE_TABLE_PARAMS
        assert stored_mode_table_params(code) == PRO_ALARM_MODE_TABLE_PARAMS
    else:
        assert stored_mode_table_params(code) == STORED_MODE_TABLE_PARAMS
    if storage is ModeTableStorage.ACTION_PARAMS:
        assert params[GuardMode.AWAY] == 1239
        assert params[GuardMode.HOME] == 1225


def test_every_model_on_record_names_its_mode_table_storage() -> None:
    for code in ON_RECORD:
        assert mode_table_storage(code) is not None, code


def test_cross_camera_intervals_match_the_settings_file() -> None:
    for code in ON_RECORD:
        intervals = cross_camera_intervals(code)
        if config_support(code, StationFeature.CROSS_CAMERA).support is Support.UNKNOWN:
            assert intervals == (), code
            continue
        setting = settings_of(code)["device_cross_cam_interval"]
        assert [setting.decode(str(s)) for s in intervals] == list(setting.values), code
    assert cross_camera_intervals("T8030")[0] == 120


def test_a_station_below_the_apps_firmware_gate_is_unknown() -> None:
    """A verified feature too: the hardware check ran above the gate."""
    gate = min_firmware("T8030", StationFeature.CROSS_CAMERA)
    assert gate is not None
    old = config_support("T8030", StationFeature.CROSS_CAMERA, firmware="3.3.0.0")
    assert old.support is Support.UNKNOWN
    assert gate in old.source
    new = config_support("T8030", StationFeature.CROSS_CAMERA, firmware="3.8.7.4")
    assert new == config_support("T8030", StationFeature.CROSS_CAMERA)
    assert new.support is Support.VERIFIED
    assert new.note.endswith(
        f"settings, not written here; the eufy app offers it from firmware {gate}"
    )
    odd = config_support("T8030", StationFeature.CROSS_CAMERA, firmware="3.3.1.5m_2.6")
    assert odd.support is Support.VERIFIED
    assert min_firmware("T8030", StationFeature.SCHEDULE) is None


@pytest.mark.parametrize(
    ("code", "feature", "reason"),
    [
        ("T8N00", StationFeature.CUSTOM_MODES, "WebRTC"),
        ("T9000", StationFeature.ARMING_GROUPS, "professional arming"),
        ("T8023", StationFeature.MODE_DELAYS, "arming_support_arm_delay false"),
        ("T8026", StationFeature.MODE_DELAYS, "arming_support_arm_delay false"),
        ("T8020", StationFeature.MODE_DELAYS, "arming_support_arm_delay false"),
        ("T8001", StationFeature.CROSS_CAMERA, "declares no"),
        ("T8024", StationFeature.RESTART, "declares no restart_device"),
    ],
)
def test_unknown_carries_the_reason(code: str, feature: StationFeature, reason: str) -> None:
    evidence = config_support(code, feature)
    assert evidence.support is Support.UNKNOWN
    assert reason in evidence.source


def test_lookups_for_a_model_not_on_record() -> None:
    for code in (None, "T8170"):
        assert config_support(code, StationFeature.SCHEDULE).support is Support.UNKNOWN
        assert mode_table_storage(code) is None
        assert mode_table_params(code) == {}
        assert stored_mode_table_params(code) == STORED_MODE_TABLE_PARAMS
        assert cross_camera_intervals(code) == ()
        assert restart_command(code) is None
        assert max_custom_modes(code) == 0
    assert scs.app_version()
    assert scs.remote_config_template() > 0


def test_custom_modes_and_restart() -> None:
    assert max_custom_modes("T8030") == 3
    assert max_custom_modes("T8N00") == 0
    assert restart_command("t8030") == (1034, None)
    assert restart_command("T8023") is None


@pytest.mark.skipif(
    not CACHE.is_dir() or not DATA.is_dir() or shutil.which("node") is None,
    reason="needs the private thing-model cache, the app data and Node",
)
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_station_config.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
