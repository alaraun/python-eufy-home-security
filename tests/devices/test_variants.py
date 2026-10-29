"""Which member of a variant group the eufy app uses for a unit (devices/variants.py)."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.conditions import Condition, ConditionUnit
from eufy_home_security.devices.model_settings import (
    Setting,
    SettingKind,
    VariantRule,
    bundled_codes,
    settings_of,
)
from eufy_home_security.devices.variants import setting_in_use
from eufy_home_security.testing import SYNTHETIC

TAIL = SYNTHETIC.camera_sn[5:]
HB3 = SYNTHETIC.station_sn  # a HomeBase 3 serial
DETECTION = "detection_type_set"
AI_EMPOWERED = {1299: "1"}  # the parameter the AI empowerment property reads


def unit(
    code: str,
    parent: str | None = HB3,
    *,
    params: Mapping[int, str] | None = AI_EMPOWERED,
    firmware: str | None = "1.0.0.0",
    country: str | None = "DE",
) -> ConditionUnit:
    serial = code + TAIL
    return ConditionUnit(
        serial=serial,
        parent_serial=parent or serial,
        firmware=firmware,
        parent_firmware="3.8.7.4",
        params=params,
        country=country,
    )


def in_use(code: str, members: tuple[str, ...], u: ConditionUnit) -> list[bool | None]:
    settings = settings_of(code)
    return [setting_in_use(settings, key, u) for key in members]


GROUP = (DETECTION, f"{DETECTION}__v1", f"{DETECTION}__v2")


@pytest.mark.parametrize("code", ["T8410", "T8161"])
def test_a_camera_behind_a_homebase_3_with_ai_empowerment_uses_v1(code: str) -> None:
    assert in_use(code, GROUP, unit(code)) == [False, True, False]


@pytest.mark.parametrize("code", ["T8410", "T8161"])
def test_without_ai_empowerment_the_primary(code: str) -> None:
    assert in_use(code, GROUP, unit(code, params={1299: "0"})) == [True, False, False]


def test_a_device_that_does_not_report_the_parameter_reads_its_default() -> None:
    assert in_use("T8410", GROUP, unit("T8410", params={1298: "3"})) == [True, False, False]


def test_without_the_device_s_parameters_the_client_cannot_tell() -> None:
    """``__v2`` needs a T8040 parent, so it is out either way."""
    assert in_use("T8410", GROUP, unit("T8410", params=None)) == [None, None, False]


def test_behind_a_homebase_s380_v2() -> None:
    assert in_use("T8161", GROUP, unit("T8161", "T8040" + TAIL)) == [False, False, True]


@pytest.mark.parametrize(
    ("parent", "expected"),
    [(HB3, [True, False]), (None, [True, False]), ("T8040" + TAIL, [False, True])],
)
def test_a_t8112_offers_vehicle_recognition_only_behind_a_homebase_s380(
    parent: str | None, expected: list[bool]
) -> None:
    assert in_use("T8112", (DETECTION, f"{DETECTION}__v2"), unit("T8112", parent)) == expected


@pytest.mark.parametrize(
    ("firmware", "expected"),
    [("3.1.5.8", [False, True]), ("3.1.5.7", [True, False]), ("", [True, False])],
)
def test_a_firmware_bound_and_a_missing_firmware(firmware: str, expected: list[bool]) -> None:
    """A missing firmware compares below every bound, as in the app."""
    members = ("record_resolution", "record_resolution__v1")
    assert in_use("T8162", members, unit("T8162", firmware=firmware)) == expected


def test_an_unknown_country_cannot_tell_where_it_decides() -> None:
    members = ("player_model_config", "player_model_config__v1")
    assert in_use("T814X", members, unit("T814X", country=None)) == [None, None]
    assert in_use("T814X", members, unit("T814X", country="OM")) == [False, True]


def test_a_setting_without_variants_is_in_use() -> None:
    assert setting_in_use(settings_of("T8410"), "watermark_set", unit("T8410", params=None))


def test_an_unknown_key_raises() -> None:
    with pytest.raises(KeyError):
        setting_in_use(settings_of("T8410"), "no_such_setting", unit("T8410"))


def _members(code: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for key, setting in settings_of(code).items():
        if setting.variant_of is not None:
            groups.setdefault(setting.variant_of, [setting.variant_of]).append(key)
    return groups


def _known_units(code: str) -> list[ConditionUnit]:
    """Units whose every input is known, behind each station kind's prefix and alone."""
    parents = ["T8030", "T8040", "T9000", "T8N00", "T8010", "T8025", "T7000"]
    return [unit(code, p + TAIL) for p in parents] + [unit(code, None)]


@pytest.mark.parametrize("code", bundled_codes())
def test_every_group_names_at_most_one_member_when_every_input_is_known(code: str) -> None:
    """For every bundled model, read from its data alone: one member in use, or none
    when the app reads a property the file has no setting for."""
    settings = settings_of(code)
    for primary, members in _members(code).items():
        for u in _known_units(code):
            answers = [setting_in_use(settings, key, u) for key in members]
            if None in answers:  # a property read the generator could not find
                assert any(
                    (c.param is None and c.prop) or c.kind == "parent_associated_field"
                    for rule in settings[primary]._variants
                    for group in rule.read_conditions
                    for c in group
                ), (code, primary)
                continue
            assert answers.count(True) <= 1, (code, primary, u.parent_serial)


def _setting(key: str, variant_of: str | None = None, *rules: VariantRule) -> Setting:
    return Setting(
        key=key,
        product_code="T0000",
        name=key,
        kind=SettingKind.BOOL,
        variant_of=variant_of,
        _variants=tuple(rules),
    )


PASSING = (Condition(kind="parent_sn", qualifier="RE", value="^T8030"),)


def _group(*rules: VariantRule, keys: tuple[str, ...] = ("x__v1", "x__v2")) -> dict[str, Setting]:
    out = {"x": _setting("x", None, *rules)}
    out.update({k: _setting(k, "x") for k in keys})
    return out


def _rule(identifier: str, key: str | None, *groups: tuple[Condition, ...]) -> VariantRule:
    return VariantRule(identifier=identifier, key=key, read_conditions=tuple(groups))


def test_equal_variants_keep_the_first() -> None:
    settings = _group(_rule("x__v1", "x__v1", PASSING), _rule("x__v2", "x__v2", PASSING))
    assert [setting_in_use(settings, k, unit("T0000")) for k in settings] == [False, True, False]


def test_a_variant_with_more_conditions_wins() -> None:
    settings = _group(_rule("x__v1", "x__v1", PASSING), _rule("x__v2", "x__v2", PASSING + PASSING))
    assert [setting_in_use(settings, k, unit("T0000")) for k in settings] == [False, False, True]


def test_a_variant_dropped_as_the_primary_s_equal_keeps_the_primary() -> None:
    settings = _group(_rule("x__v1", "x", PASSING), keys=("x__v2",))
    assert [setting_in_use(settings, k, unit("T0000")) for k in settings] == [True, False]


def test_a_property_the_file_has_no_setting_for_leaves_every_member_out() -> None:
    settings = _group(_rule("x__v3", None, PASSING))
    assert [setting_in_use(settings, k, unit("T0000")) for k in settings] == [False] * 3


def test_a_legacy_member_is_never_in_use() -> None:
    settings = {"x": _setting("x"), "old_x": _setting("old_x", "x")}
    assert setting_in_use(settings, "old_x", unit("T0000")) is False
    assert setting_in_use(settings, "x", unit("T0000")) is True


def test_a_member_the_unknown_input_cannot_reach_is_out() -> None:
    maybe = (Condition(kind="user_country", qualifier="RE", value="^DE"),)
    settings = _group(_rule("x__v1", "x__v1", maybe))
    nobody = dataclasses.replace(unit("T0000"), country=None)
    assert [setting_in_use(settings, k, nobody) for k in settings] == [None, None, False]


def _entries(rules: object, member: dict[str, object]) -> dict[str, dict[str, object]]:
    base = {"kind": "bool", "access": "ro", "read": None, "section": "other"}
    return {"x": {**base, "variants": rules}, "x__v1": {**base, "variant_of": "x", **member}}


@pytest.mark.parametrize(
    ("variants", "member", "error"),
    [
        ([{"id": "x__v1", "key": "y", "read_conditions": []}], {}, "not one of its variants"),
        (
            [{"id": "x__v1", "key": "x__v1", "read_conditions": []}],
            {"variants": [{"id": "x__v1__v1", "key": None, "read_conditions": []}]},
            "a variant lists variants",
        ),
        ([{"key": "x__v1", "read_conditions": []}], {}, "has no id"),
        ([{"id": "x__v1", "key": 1, "read_conditions": []}], {}, "key is not a string"),
        ({"id": "x__v1"}, {}, "variants is not a list"),
        ([{"id": "x__v1", "key": None, "read_conditions": [{}]}], {}, "not a list of lists"),
    ],
)
def test_a_malformed_variants_field_is_refused(
    variants: object, member: dict[str, object], error: str
) -> None:
    with pytest.raises((TypeError, ValueError), match=error):
        model_settings._parse("T0000", _entries(variants, member), None)


def test_a_variants_field_naming_its_members_loads() -> None:
    rules = [
        {"id": "x__v1", "key": "x__v1", "read_conditions": [[]]},
        {"id": "x__v2", "key": "x", "read_conditions": [[]]},
        {"id": "x__v3", "key": None, "read_conditions": [[]]},
    ]
    parsed = model_settings._parse("T0000", _entries(rules, {}), None)
    assert [r.key for r in parsed["x"]._variants] == ["x__v1", "x", None]
