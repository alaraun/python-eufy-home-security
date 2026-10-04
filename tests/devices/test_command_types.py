from __future__ import annotations

from eufy_home_security.devices.command_types import (
    APK_COMMAND_TYPES,
    COMMAND_NAMES,
    WIRE_EXTRAS,
    command_name,
)

_STRIPPED_PREFIXES = ("APP_CMD_", "APP_", "COMMAND_", "COMMAMD_", "CMD_")


def test_catalog_is_the_merge_of_disjoint_sources() -> None:
    assert not set(APK_COMMAND_TYPES) & set(WIRE_EXTRAS)
    assert len(COMMAND_NAMES) == len(APK_COMMAND_TYPES) + len(WIRE_EXTRAS)
    assert len(APK_COMMAND_TYPES) == 492


def test_enum_names_are_prefix_stripped() -> None:
    for command_id, joined in APK_COMMAND_TYPES.items():
        for name in joined.split(" / "):
            assert not name.startswith(_STRIPPED_PREFIXES), (command_id, name)


def test_small_ids_from_unrelated_enums_are_not_named() -> None:
    assert min(APK_COMMAND_TYPES) >= 900
    assert command_name(1) == "param 1"


def test_command_name_known_and_fallback() -> None:
    assert command_name(1224) == "SET_ARMING"
    assert command_name(1421) == "AMBIENT_LIGHT"
    assert command_name(7013) == WIRE_EXTRAS[7013]
    assert command_name(99999) == "param 99999"
