"""``devices/sections.py``: the catalogue, and the section every bundled setting carries."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.model_settings import (
    Setting,
    SettingKind,
    bundled_codes,
    mode_table_settings,
    settings_of,
    sort_settings,
)
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.devices.sections import (
    MODES_SECTION,
    OTHER_SECTION,
    SETTING_SECTIONS,
    SettingSection,
    setting_section,
)
from eufy_home_security.devices.settings import Scope
from eufy_home_security.exceptions import UnsupportedError

IDS = {s.id for s in SETTING_SECTIONS}
# The Home Assistant camera card's tab ids and some keys each tab holds.
CARD_GROUPS = {
    "picture": {"nightvision_type_new", "nightvision_type", "spotlight_switch", "watermark_set"},
    "detection": {"motion_detection_status", "detection_sensitivity", "detection_type_set"},
    "recording": {"live_streaming_resolution", "record_resolution", "audio_recording_on_off"},
    "power": {"power_manager_mode", "power_charge_mode"},
    "ptz": {"ai_tracking_status", "ptz_turn_speed"},
    "other": set(),
}


def test_ids_are_unique_lower_case_and_the_order_ascends() -> None:
    ids = [s.id for s in SETTING_SECTIONS]
    assert len(ids) == len(set(ids))
    assert all(i.isascii() and i.islower() and i.isidentifier() for i in ids)
    orders = [s.order for s in SETTING_SECTIONS]
    assert orders == sorted(set(orders))
    assert SETTING_SECTIONS[-1].id == OTHER_SECTION
    assert {OTHER_SECTION, MODES_SECTION} <= IDS
    assert len(SETTING_SECTIONS) <= 14


def test_headings_are_sentence_case() -> None:
    for section in SETTING_SECTIONS:
        first, *rest = section.heading.split()
        assert first[0].isupper(), section
        assert all(w == "&" or w.islower() for w in rest), section


def test_the_camera_card_ids_keep_their_headings() -> None:
    headings = {s.id: s.heading for s in SETTING_SECTIONS}
    assert set(CARD_GROUPS) <= IDS
    assert headings["ptz"] == "Pan & tilt"
    assert [i for i in headings if i in CARD_GROUPS] == list(CARD_GROUPS)  # the card's order


def test_lookup_by_id() -> None:
    assert setting_section("ptz") == SettingSection("ptz", "Pan & tilt", 60)
    with pytest.raises(UnsupportedError, match="unknown setting section 'lights'"):
        setting_section("lights")


def _bundled() -> list[tuple[str, dict[str, Setting]]]:
    return [(code, dict(settings_of(code))) for code in bundled_codes()]


@pytest.mark.parametrize("connect", [None, ConnectType.HB3])
def test_every_bundled_setting_has_a_known_section_and_a_variant_its_primary_s(
    connect: ConnectType | None,
) -> None:
    for code, settings in _bundled():
        for key, setting in settings.items():
            assert setting.section in IDS, (code, key)
            assert setting.section_info.id == setting.section
            if setting.variant_of is not None:
                assert setting.section == settings[setting.variant_of].section, (code, key)
        assert settings_of(code, connect).keys() == settings.keys()
        for key, setting in settings_of(code, connect).items():
            assert setting.section == settings[key].section, (code, key)


def test_the_camera_card_keys_sit_in_their_card_tab() -> None:
    seen: dict[str, set[str]] = {group: set() for group in CARD_GROUPS}
    for code, settings in _bundled():
        for group, keys in CARD_GROUPS.items():
            for key in keys & settings.keys():
                assert settings[key].section == group, (code, key)
                seen[group].add(key)
    assert seen == CARD_GROUPS


def test_writable_camera_and_station_settings_avoid_other() -> None:
    """Only the garage-door controller's door switches fit no section."""
    left = {
        (code, key)
        for code, settings in _bundled()
        for key, s in settings.items()
        if s.section == OTHER_SECTION and (s.writable or s.readable)
    }
    assert {key for _, key in left} <= {"garage_door_on_off", "garage_door_binding_status"}


def test_station_settings_take_station_sections() -> None:
    hb3 = settings_of("T8030")
    assert {k: hb3[k].section for k in ("alarm_volume_value", "prompt_volume_value")} == {
        "alarm_volume_value": "alarm",
        "prompt_volume_value": "alarm",
    }
    assert hb3["device_cross_cam_tracking_swtich"].section == "detection"
    assert hb3["working_mode_value"].section == "system"
    assert hb3["switching_notification"].section == "notifications"
    assert hb3["arming_selected_mode"].section == MODES_SECTION


@pytest.mark.parametrize("scope", [Scope.CAMERA, Scope.SENSOR])
def test_per_mode_delays_and_actions_are_in_modes(scope: Scope) -> None:
    assert {s.section for s in mode_table_settings(scope)} == {MODES_SECTION}


def test_the_alarm_and_modes_sections_are_alarm_affecting() -> None:
    assert {s.id for s in SETTING_SECTIONS if s.alarm_affecting} == {"alarm", MODES_SECTION}


@pytest.mark.parametrize(
    ("key", "affecting"),
    [
        ("alarm_volume_value", True),  # a change sounds the HomeBase
        ("alarm_tones_mode", True),
        ("arming_selected_mode", True),
        ("device_cross_cam_interval", False),
        ("working_mode_value", False),
    ],
)
def test_a_setting_is_alarm_affecting_by_its_section(key: str, affecting: bool) -> None:
    assert settings_of("T8030", standalone=True)[key].alarm_affecting is affecting


def test_every_per_mode_setting_is_alarm_affecting() -> None:
    settings = (*mode_table_settings(Scope.CAMERA), *mode_table_settings(Scope.SENSOR))
    assert all(s.alarm_affecting for s in settings)


def _make(key: str, section: str = "picture", **fields: object) -> Setting:
    return Setting(
        key=key,
        product_code="",
        name=str(fields.pop("name", key)),
        kind=SettingKind.BOOL,
        section=section,
        **fields,  # type: ignore[arg-type]
    )


def test_sort_by_section_then_the_app_placement_then_the_name() -> None:
    settings = [
        _make("z", "other"),
        _make("n2", name="beta"),
        _make("n1", name="Alpha"),
        _make("v", page="Video"),
        _make("g2", page="Audio", group="B", order=0),
        _make("g1", page="Audio", group="A", order=5),
        _make("o2", page="Audio", order=2),
        _make("o1", page="Audio", order=1),
        _make("p", page="Audio"),
        _make("d", "detection"),
        _make("n1__v1", name="Alpha", variant_of="n1"),
    ]
    # picture before detection before other; within picture the placed settings first
    # (page name, group, order), then by name; a variant right after its primary
    keys = [s.key for s in sort_settings(settings)]
    assert keys == ["g1", "g2", "o1", "o2", "p", "v", "n1", "n1__v1", "n2", "d", "z"]
    assert sort_settings(reversed(settings)) == sort_settings(settings)


def test_a_bundled_list_sorts_by_section_order() -> None:
    order = {s.id: s.order for s in SETTING_SECTIONS}
    listed = sort_settings(settings_of("T8170").values())
    ranks = [order[s.section] for s in listed]
    assert ranks == sorted(ranks)
