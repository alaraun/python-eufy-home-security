"""The lamps of each model: which settings make each lamp, their scales and grades."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from eufy_home_security.devices import lights
from eufy_home_security.devices.lights import LAMP_SPECS, LightBrightness, lights_from, lights_of
from eufy_home_security.devices.model_settings import (
    STANDALONE_CONTEXT,
    SettingKind,
    bundled_codes,
    settings_of,
)
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.devices.support import Support

_CONTEXTS: list[tuple[ConnectType | None, bool]] = [
    (None, True),
    (None, False),
    *((connect, False) for connect in ConnectType),
]


def _lamp_models() -> set[str]:
    """Bundled models whose lamp switch is a readable or writable bool."""
    found = set()
    for code in bundled_codes():
        for spec in LAMP_SPECS:
            switch = settings_of(code).get(spec.switch)
            if (
                switch is not None
                and switch.kind is SettingKind.BOOL
                and (switch.readable or switch.writable)
            ):
                found.add(code)
    return found


@pytest.mark.parametrize(("connect", "standalone"), _CONTEXTS)
def test_every_model_with_a_lamp_switch_lists_its_lamps(
    connect: ConnectType | None, standalone: bool
) -> None:
    with_lights = {
        code for code in bundled_codes() if lights_of(code, connect, standalone=standalone)
    }
    assert with_lights == _lamp_models()
    assert len(with_lights) == 45
    assert not {code for code in with_lights if code.startswith("T8L") and code != "T8L60"}


def test_the_light_products_without_a_usable_switch_have_no_lamp() -> None:
    lights = [code for code in bundled_codes() if code.startswith("T8L") and code != "T8L60"]
    assert len(lights) == 8
    for code in lights:
        assert "spotlight_switch" in settings_of(code)
        assert lights_of(code) == ()


def test_a_lamp_read_only_behind_a_station_is_listed_unwritable() -> None:
    (alone,) = lights_of("T84A1", standalone=True)
    (paired,) = lights_of("T84A1", ConnectType.HB3)
    assert alone.on_off_writable
    assert not paired.on_off_writable
    assert paired.on_off_readable


def test_a_doorbell_bottom_lamp_is_on_off_only() -> None:
    main, bottom = lights_of("T8214", ConnectType.HB3)
    assert (main.id, bottom.id) == ("spotlight", "bottom_spotlight")
    assert main.brightness is not None
    assert main.brightness.key == "spotlight_brightness_level"
    assert main.color_temp is not None
    assert main.color_temp.key == "light_color_temperature"
    assert main.color_temp.kelvin is None
    assert bottom.brightness is None
    assert bottom.color_temp is None
    assert bottom.name == "Bottom spotlight"
    assert bottom.keys == ("bottom_spotlight_switch",)


def test_a_track_light_pairs_each_lamp_with_its_own_brightness() -> None:
    main, zoom = lights_of("T8L60", ConnectType.HB3)
    assert main.brightness is not None
    assert main.brightness.key == "spotlight_brightness_level"
    assert not main.brightness.writable  # read-only on this model
    # The zoom brightness is neither readable nor writable: no scale to offer.
    assert zoom.id == "zoom_spotlight"
    assert zoom.brightness is None
    assert "zoom_spotlight_brightness_level" not in zoom.keys


def test_an_enum_brightness_maps_each_level_to_its_percent() -> None:
    (light,) = lights_of("T8160", ConnectType.HB3)
    brightness = light.brightness
    assert brightness is not None
    assert dict(brightness.levels) == {0: 40, 1: 70, 2: 100}
    assert (brightness.minimum, brightness.maximum, brightness.step) == (40, 100, None)
    assert [brightness.percent(v) for v in (0, 1, 2, 3, None, True)] == [
        40,
        70,
        100,
        None,
        None,
        None,
    ]
    assert [brightness.value_for(p) for p in (0, 54, 55, 56, 85, 86, 100)] == [0, 0, 0, 1, 1, 2, 2]


def test_a_range_brightness_is_the_percent() -> None:
    brightness = LightBrightness(
        key="b", writable=True, readable=True, minimum=10, maximum=100, step=5
    )
    assert [brightness.percent(v) for v in (9, 10, 55, 100, 101, "x")] == [
        None,
        10,
        55,
        100,
        None,
        None,
    ]
    assert [brightness.value_for(p) for p in (0, 10, 12, 13, 99, 100, 150)] == [
        10,
        10,
        10,
        15,
        100,
        100,
        100,
    ]
    unstepped = LightBrightness(
        key="b", writable=True, readable=True, minimum=1, maximum=100, step=None
    )
    assert unstepped.value_for(42.4) == 42
    odd = LightBrightness(key="b", writable=True, readable=True, minimum=1, maximum=100, step=2)
    assert odd.value_for(100) == 100  # the step grid ends at 99 and 101: capped


def test_an_enum_without_a_device_value_for_every_level_has_no_scale() -> None:
    settings = dict(settings_of("T8160"))
    brightness = settings["spotlight_brightness_level"]
    trimmed = dict(brightness._read_map or {})
    trimmed.pop("70")
    settings["spotlight_brightness_level"] = dataclasses.replace(brightness, _read_map=trimmed)
    (light,) = lights_from(settings, "T8160", ConnectType.HB3)
    assert light.brightness is None


def test_the_master_enable_and_config_keys_belong_to_the_main_lamp() -> None:
    (light,) = lights_of("T8422", ConnectType.HB3)
    assert light.enabled_by == "spotlight_status"
    assert "spotlight_status" in light.config
    variants = [s.key for s in settings_of("T8422").values() if s.variant_of == "spotlight_status"]
    assert variants
    assert set(variants) <= set(light.keys)
    (plain,) = lights_of("T8160", ConnectType.HB3)
    assert plain.enabled_by is None
    assert plain.config == ()
    assert plain.keys == ("spotlight_switch", "spotlight_brightness_level")


@pytest.mark.parametrize(
    ("code", "connect", "standalone", "support"),
    [
        ("T8160", ConnectType.HB3, False, Support.VERIFIED),
        ("t8160", ConnectType.HB3, False, Support.VERIFIED),
        ("T8160", ConnectType.HB2, False, Support.DECLARED),
        ("T8160", None, True, Support.DECLARED),
        ("T8170", None, True, Support.VERIFIED),
        ("T8170", ConnectType.HB3, False, Support.DECLARED),
        ("T8423", ConnectType.HB3, False, Support.DECLARED),
    ],
)
def test_only_the_hardware_proven_switches_are_verified(
    code: str, connect: ConnectType | None, standalone: bool, support: Support
) -> None:
    (light,) = lights_of(code, connect, standalone=standalone)
    assert light.evidence.support is support
    assert light.product_code == code.upper()


def test_the_verified_switches_have_their_hardware_rows() -> None:
    doc = (Path(__file__).parents[2] / "docs/reference/hardware-verification.md").read_text()
    rows = [line for line in doc.splitlines() if "| ✓ |" in line and "spotlight_switch" in line]
    for code, context in lights._VERIFIED_SWITCHES:
        assert context in (ConnectType.HB3.value, STANDALONE_CONTEXT)
        assert any(code in row for row in rows), code


@pytest.mark.parametrize(
    ("code", "reported"),
    [("T8160", True), ("T8442", False), ("T870G", False), ("T8L60", False)],
)
def test_the_state_is_reported_where_the_light_frame_carries_it(code: str, reported: bool) -> None:
    """The station's light frame reports param 1400; another read param (6083, 1398) is
    refreshed only by reads, and a write-only switch has no read."""
    lights = lights_of(code, ConnectType.HB3)
    assert lights[0].state_reported is reported
    assert all(not light.state_reported for light in lights[1:])


def test_a_switch_that_is_no_usable_bool_makes_no_lamp() -> None:
    settings = dict(settings_of("T8160"))
    switch = settings["spotlight_switch"]
    settings["spotlight_switch"] = dataclasses.replace(switch, kind=SettingKind.OTHER)
    assert lights_from(settings, "T8160", ConnectType.HB3) == ()
    settings["spotlight_switch"] = dataclasses.replace(switch, readable=False, writable=False)
    assert lights_from(settings, "T8160", ConnectType.HB3) == ()


def test_a_variant_of_a_covered_setting_is_covered() -> None:
    settings = dict(settings_of("T8214"))
    variant = dataclasses.replace(
        settings["light_color_temperature"],
        key="light_color_temperature__v1",
        variant_of="light_color_temperature",
    )
    settings[variant.key] = variant
    main, bottom = lights_from(settings, "T8214", ConnectType.HB3)
    assert "light_color_temperature__v1" in main.keys
    assert "light_color_temperature__v1" not in bottom.keys


def test_a_brightness_range_without_whole_bounds_has_no_scale() -> None:
    settings = dict(settings_of("T8170"))
    brightness = settings["spotlight_brightness_level"]
    settings[brightness.key] = dataclasses.replace(brightness, minimum=0.5)
    (light,) = lights_from(settings, "T8170", standalone=True)
    assert light.brightness is None


def test_an_enum_level_takes_its_first_numeric_device_value() -> None:
    settings = dict(settings_of("T8160"))
    brightness = settings["spotlight_brightness_level"]
    read_map = {"x": 0, "": 2, "40": 0, "45": 0, "70": 1, "100": 2}
    settings[brightness.key] = dataclasses.replace(brightness, _read_map=read_map)
    (light,) = lights_from(settings, "T8160", ConnectType.HB3)
    assert light.brightness is not None
    assert dict(light.brightness.levels) == {0: 40, 1: 70, 2: 100}


def test_a_colour_temperature_without_a_range_is_not_offered() -> None:
    (light,) = lights_of("T8423", ConnectType.HB3)
    assert settings_of("T8423")["light_color_temperature"].kind is SettingKind.OTHER
    assert light.color_temp is None
    assert "light_color_temperature" not in light.keys


def test_a_colour_temperature_neither_readable_nor_writable_is_not_offered() -> None:
    settings = dict(settings_of("T8214"))
    color = settings["light_color_temperature"]
    settings[color.key] = dataclasses.replace(color, readable=False, writable=False)
    main, _ = lights_from(settings, "T8214", ConnectType.HB3)
    assert main.color_temp is None


def test_an_unknown_code_has_no_lamp() -> None:
    assert lights_of("T0000") == ()
    assert lights_of("not a code") == ()
