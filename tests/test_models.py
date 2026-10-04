from __future__ import annotations

import pytest

from eufy_home_security.models import PARAM_WIFI_RSSI, GuardMode


@pytest.mark.parametrize(
    ("text", "mode"),
    [
        ("away", GuardMode.AWAY),
        ("Armed Home", GuardMode.HOME),
        ("custom2", GuardMode.CUSTOM_2),
        ("off", GuardMode.DISARMED),
        ("63", GuardMode.DISARMED),
        (47, GuardMode.GEOFENCE),
    ],
)
def test_parse(text: str | int, mode: GuardMode) -> None:
    assert GuardMode.parse(text) is mode


def test_parse_rejects_unknown_without_listing_the_off_alias() -> None:
    with pytest.raises(ValueError, match="invalid guard mode") as info:
        GuardMode.parse("bogus")
    valid = str(info.value).split("valid: ", 1)[1].split(", ")
    assert "off" not in valid
    assert "disarmed" in valid


@pytest.mark.parametrize(
    ("mode", "disarmed"),
    [(GuardMode.DISARMED, True), (GuardMode.OFF, True), (GuardMode.AWAY, False)],
)
def test_is_disarmed(mode: GuardMode, disarmed: bool) -> None:
    assert mode.is_disarmed is disarmed


@pytest.mark.parametrize("value", [True, False, 99, "99", 1.0])
def test_parse_rejects_bools_and_unknown_codes_with_the_formatted_error(value: object) -> None:
    with pytest.raises(ValueError, match=r"invalid guard mode .*; valid: away"):
        GuardMode.parse(value)  # type: ignore[arg-type]


def test_rssi_param_alias_names_the_wifi_signal() -> None:
    assert PARAM_WIFI_RSSI == 1142
