from __future__ import annotations

import pytest

from eufy_home_security.models import PARAM_WIFI_RSSI, E2EKey, E2EKeyType, GuardMode


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


@pytest.mark.parametrize(
    ("cipher_id", "key"),
    [
        (0x0400000A, E2EKey(E2EKeyType.PIN, 10)),
        (0x05000007, E2EKey(E2EKeyType.CIPHER, 7)),
        (0x050012FF, E2EKey(E2EKeyType.CIPHER, 0xFF)),
        (84, None),  # a P2P cipher id: no end-to-end encryption
        (0x00FFFFFF, None),
        (0x01000002, None),  # a type the app does not know
        (0x0900000C, E2EKey(E2EKeyType.PIN, 12)),  # type 9: the PIN key, as type 4
        (0x09000002, E2EKey(E2EKeyType.PIN, 2)),
        (0x0800000C, None),  # type 8: the owner's cipher, which the station names per record
        (-1, None),
        (None, None),
    ],
)
def test_a_cipher_id_names_its_e2e_key_as_the_app_reads_it(
    cipher_id: int | None, key: E2EKey | None
) -> None:
    assert E2EKey.from_cipher_id(cipher_id) == key
