from collections.abc import Iterator

import pytest

from eufy_home_security._logging import set_secret_logging
from eufy_home_security.devices.param_info import param_info
from eufy_home_security.devices.settings import Scope
from eufy_home_security.models import PARAM_DEVICE_NAME, STATION_CHANNEL


@pytest.fixture
def _secrets_restored() -> Iterator[None]:
    set_secret_logging(False)
    yield
    set_secret_logging(False)


@pytest.mark.parametrize(
    (
        "param_id",
        "channel",
        "scope",
        "old",
        "new",
        "expected_change",
        "expected_desc",
        "expected_desc_val",
    ),
    [
        # a mode-table delay, with its unit
        (
            1167,
            0,
            Scope.CAMERA,
            10,
            15,
            "alarm_delay_away (Alarm (entry) delay after this device triggers, Away mode): 10 s → 15 s",
            "alarm_delay_away (Alarm (entry) delay after this device triggers, Away mode)",
            "alarm_delay_away (Alarm (entry) delay after this device triggers, Away mode) = 15 s",
        ),
        # '|' join for unknown kind
        (
            1239,
            0,
            None,
            1,
            2,
            "camera_action_away|doorbell_action_away|sensor_action_away (What this camera does when it triggers in Away mode): +camera_siren -record (1 → 2)",
            "camera_action_away|doorbell_action_away|sensor_action_away (What this camera does when it triggers in Away mode)",
            "camera_action_away|doorbell_action_away|sensor_action_away (What this camera does when it triggers in Away mode) = camera_siren",
        ),
        # single key with Scope.CAMERA
        (
            1239,
            0,
            Scope.CAMERA,
            1,
            2,
            "camera_action_away (What this camera does when it triggers in Away mode): +camera_siren -record (1 → 2)",
            "camera_action_away (What this camera does when it triggers in Away mode)",
            "camera_action_away (What this camera does when it triggers in Away mode) = camera_siren",
        ),
        # guard_mode
        (
            1224,
            255,
            None,
            0,
            1,
            "guard_mode (selected guard mode): away → home",
            "guard_mode (selected guard mode)",
            "guard_mode (selected guard mode) = home",
        ),
        (
            1224,
            255,
            None,
            0,
            63,
            "guard_mode (selected guard mode): away → disarmed",
            "guard_mode (selected guard mode)",
            "guard_mode (selected guard mode) = disarmed",
        ),
        # battery
        (
            1101,
            0,
            None,
            50,
            60,
            "battery (battery level): 50 % → 60 %",
            "battery (battery level)",
            "battery (battery level) = 60 %",
        ),
        # online with an offline code
        (
            1131,
            0,
            None,
            1,
            0,
            "online (online status): online → offline",
            "online (online status)",
            "online (online status) = offline",
        ),
        (
            1131,
            0,
            None,
            1,
            2,
            "online (online status): online → offline (code 2)",
            "online (online status)",
            "online (online status) = offline (code 2)",
        ),
        # an id outside the mode tables and device state: the app's name only
        (
            1210,
            0,
            Scope.CAMERA,
            3,
            4,
            "SET_PIRSENSITIVITY? (the app's name, meaning unknown)",
            "SET_PIRSENSITIVITY? (the app's name, meaning unknown)",
            "SET_PIRSENSITIVITY? (the app's name, meaning unknown)",
        ),
        # app-name-only id
        (
            900,
            0,
            None,
            1,
            2,
            "START_REC_BROADCASE? (the app's name, meaning unknown)",
            "START_REC_BROADCASE? (the app's name, meaning unknown)",
            "START_REC_BROADCASE? (the app's name, meaning unknown)",
        ),
        # unknown id
        (999999, 0, None, 1, 2, "unknown", "unknown", "unknown"),
    ],
)
def test_param_info_formatting(  # noqa: PLR0917
    param_id: int,
    channel: int,
    scope: Scope | None,
    old: int,
    new: int,
    expected_change: str,
    expected_desc: str,
    expected_desc_val: str,
) -> None:
    info = param_info(param_id, channel, scope)
    assert info.change(old, new) == expected_change
    assert info.describe() == expected_desc
    assert info.describe(new) == expected_desc_val


@pytest.mark.usefixtures("_secrets_restored")
def test_param_info_identifying() -> None:
    info = param_info(PARAM_DEVICE_NAME, 0)
    assert info.identifying is True
    assert info.change("OldName", "NewName") == "device_name (device name): ******* → *******"
    assert info.describe("NewName") == "device_name (device name) = *******"
    assert info.raw("NewName") == "'*******'"

    set_secret_logging(True)
    assert info.change("OldName", "NewName") == "device_name (device name): OldName → NewName"
    assert info.describe("NewName") == "device_name (device name) = NewName"
    assert info.raw("NewName") == "'NewName'"


@pytest.mark.usefixtures("_secrets_restored")
def test_a_json_value_is_shown_with_its_identifying_fields_masked() -> None:
    """A value holding a JSON object (an access point's name and address) is logged with
    its identifying fields redacted, in full only with secret logging on."""
    value = '{"mode": 2, "ap_info": {"ssid": "Example-Net", "ip_addr": "192.0.2.10"}}'
    info = param_info(60012, 0)
    shown = info.raw(value)
    assert "Example-Net" not in shown
    assert "192.0.2.10" not in shown
    assert '"mode": 2' in shown
    assert info.raw("7") == "'7'"
    set_secret_logging(True)
    assert "Example-Net" in info.raw(value)


def test_sub_device_settings_never_match_the_station_channel() -> None:
    assert param_info(1167, 0).label == "alarm_delay_away"
    assert param_info(1167, STATION_CHANNEL).label == "ALARM_DELAY_AWAY?"


@pytest.mark.parametrize(
    ("param_id", "channel", "label"),
    [(1134, 0, "upgrading"), (1133, STATION_CHANNEL, "hub_upgrading"), (1103, 0, "camera_info")],
)
def test_a_param_the_library_reports_elsewhere_is_named_by_its_field(
    param_id: int, channel: int, label: str
) -> None:
    assert param_info(param_id, channel).label == label


def test_a_station_param_outside_the_mode_tables_has_the_apps_name() -> None:
    assert param_info(1235, STATION_CHANNEL).label == "SET_HUB_SPK_VOLUME?"
