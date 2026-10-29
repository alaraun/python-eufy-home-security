"""Thing-description conditions and variant choice (devices/conditions.py)."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.conditions import (
    Condition,
    ConditionUnit,
    Groups,
    choices,
    evaluate,
    passes,
    regex,
    variant_rest,
    version,
)
from eufy_home_security.testing import SYNTHETIC

UNIT = ConditionUnit(
    serial=SYNTHETIC.camera_sn,
    parent_serial=SYNTHETIC.station_sn,
    firmware="3.0.0.0",
    parent_firmware="3.8.0.0",
    params={1299: "1"},
    country="DE",
)


def c(kind: str, qualifier: str, value: str, **extra: object) -> Condition:
    return Condition(kind=kind, qualifier=qualifier, value=value, **extra)  # type: ignore[arg-type]


def unknown(unit: ConditionUnit = UNIT, **changes: object) -> ConditionUnit:
    fields = {f: getattr(unit, f) for f in unit.__dataclass_fields__}
    return ConditionUnit(**(fields | changes))


@pytest.mark.parametrize(
    ("current", "qualifier", "bound", "expected"),
    [
        ("2.0", ">", "1.9", True),
        ("2.0", ">", "2.0", False),
        ("1.9", "<", "2.0", True),
        ("2.0", "<", "2.0", False),
        ("2.0", "=", "2.0.0", True),
        ("2.0", "=", "2.1", False),
        ("2.0", "!=", "2.0", False),
        ("2.1", "!=", "2.0", True),
        ("2.0", ">=", "2.0", True),
        ("2.0", "<=", "2.0", True),
        ("2.1", "<=", "2.0", False),
        ("2.0.beta", "RE", "beta", True),
        ("2.0", "RE", "beta", False),
        ("2.0", "~", "2.0", False),
        ("", ">=", "0.0.0.1", False),  # a missing firmware is below every bound
    ],
)
def test_version_conditions(current: str, qualifier: str, bound: str, expected: bool) -> None:
    assert version(current, qualifier, bound) is expected


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("", "T8030", True),
        ("^T8030", "", True),
        ("^T8030", "T8030P1", True),
        ("^T8030", "T8010P1", False),
        ("x" * 512, "x" * 512, True),
        ("x" * 513, "x" * 513, False),
        ("^x", "x" * 2048, True),
        ("^x", "x" * 2049, False),
        ("^(?i)(jp).*$", "JP", True),  # an inline flag anywhere applies to the pattern
        ("(?i)^(?!(?:JP|OM)).*$", "jp", False),
        ("^(?i)(JP).*$", "DE", False),
        ("^(unclosed", "x", False),
    ],
)
def test_pattern_conditions(pattern: str, value: str, expected: bool) -> None:
    assert regex(pattern, value) is expected


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (c("device_version", ">=", "3.0.0.0"), True),
        (c("device_version", ">", "3.0.0.0"), False),
        (c("parent_version", ">=", "3.8.0.0"), True),
        (c("parent_version", ">=", ""), True),  # no bound passes
        (c("parent_version", "", "9.0"), True),  # no qualifier passes
        (c("sdk_version", ">=", "0.0.0.1"), True),
        (c("sdk_version", "<=", "0.0.0.1"), False),
        (c("device_sn", "SE", "^T8410"), False),  # the qualifier is not read
        (c("device_sn", "SE", f"^{SYNTHETIC.camera_sn[:5]}"), True),
        (c("parent_sn", "RE", f"^{SYNTHETIC.station_sn[:5]}"), True),
        (c("parent_sn", "RE", "^(?!T8030)"), False),
        (c("user_country", "RE", "^(?i)(de)$"), True),
        (c("user_country", "RE", "^JP"), False),
        (c("user_permission", "IN", "1"), False),  # a type the rule does not know
        (c("associated_field", "=", "1", prop="ai_empower", param=1299), True),
        (c("associated_field", "!=", "1", prop="ai_empower", param=1299), False),
        (c("associated_field", ">=", "0", prop="ai_empower", param=1299), True),
        (c("associated_field", "<", "1", prop="ai_empower", param=1299), False),
        (c("associated_field", ">", "0", prop="ai_empower", param=1299), True),
        (c("associated_field", "<=", "0", prop="ai_empower", param=1299), False),
        (c("associated_field", ">=", "1", prop="ai_empower", param=1299), True),  # equal
        (c("associated_field", "<=", "1", prop="ai_empower", param=1299), True),
        (c("associated_field", ">", "1", prop="ai_empower", param=1299), False),
        (c("associated_field", "~", "1", prop="ai_empower", param=1299), False),
        (c("associated_field", "RE", "^1$", prop="ai_empower", param=1299), True),
        (c("associated_field", "=", "1"), False),  # no property: its value is ""
        # a parameter the device lacks: the property's default
        (c("associated_field", "=", "0", prop="ai_empower", param=1300, default="0"), True),
        (c("associated_field", "=", "2", prop="mode", param=1299, read_map={"1": "2"}), True),
        (c("parent_associated_field", "=", "1", prop="ai_empower"), None),
    ],
)
def test_conditions(condition: Condition, expected: bool | None) -> None:
    assert evaluate(condition, UNIT) is expected


@pytest.mark.parametrize(
    ("condition", "unit"),
    [
        (c("device_version", ">=", "1.0"), unknown(firmware=None)),
        (c("parent_version", ">=", "1.0"), unknown(parent_firmware=None)),
        (c("user_country", "RE", "^DE"), unknown(country=None)),
        (c("associated_field", "=", "1", prop="ai_empower", param=1299), unknown(params=None)),
        (c("associated_field", "=", "1", prop="ai_empower"), UNIT),  # no read known
        (c("associated_field", "=", "1", prop="mode", param=1299, read_map={"2": "1"}), UNIT),
    ],
)
def test_an_input_the_client_lacks_is_unknown(condition: Condition, unit: ConditionUnit) -> None:
    assert evaluate(condition, unit) is None


def test_a_parent_associated_field_without_a_listed_parent_passes() -> None:
    condition = c("parent_associated_field", "=", "1", prop="ai_empower")
    assert evaluate(condition, unknown(parent_listed=False)) is True


YES = c("parent_sn", "RE", "")
NO = c("parent_sn", "RE", "^(?!T)")
MAYBE = c("user_country", "RE", "^DE")
NOBODY = unknown(country=None)


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        ((), True),
        (((YES, YES),), True),
        (((YES, NO),), False),
        (((NO,), (YES,)), True),
        (((),), True),  # an empty group passes
        (((YES, MAYBE),), None),
        (((NO, MAYBE),), False),  # a failing condition decides the group
        (((MAYBE,), (YES,)), True),  # a passing group decides the list
        (((MAYBE,), (NO,)), None),
    ],
)
def test_condition_lists(groups: Groups, expected: bool | None) -> None:
    assert passes(groups, NOBODY) is expected


def test_the_variant_with_the_most_passing_conditions_wins() -> None:
    candidates = [("v1", ((YES,),)), ("v2", ((YES, YES),)), ("v3", ((YES, NO, YES),))]
    assert choices(candidates, UNIT) == {"v2"}


def test_equal_variants_keep_the_first() -> None:
    candidates = [("v1", ((NO,),)), ("v2", ((YES, YES),)), ("v3", ((YES,), (YES,)))]
    assert choices(candidates, UNIT) == {"v2"}


def test_a_variant_without_read_conditions_never_competes() -> None:
    assert choices([("v1", ())], UNIT) == {None}


def test_no_passing_variant_leaves_the_base() -> None:
    assert choices([("v1", ((NO,),))], UNIT) == {None}


def test_unknown_inputs_give_every_outcome_they_allow() -> None:
    candidates = [("v1", ((YES,),)), ("v2", ((YES, MAYBE),))]
    assert choices(candidates, NOBODY) == {"v1", "v2"}


def test_an_unknown_input_that_cannot_win_does_not_matter() -> None:
    candidates = [("v1", ((YES, YES),)), ("v2", ((MAYBE,),))]
    assert choices(candidates, NOBODY) == {"v1"}


def test_an_unknown_base_or_variant() -> None:
    assert choices([("v1", ((MAYBE,),))], NOBODY) == {None, "v1"}


@pytest.mark.parametrize(
    ("identifier", "rest"),
    [
        ("speaker_volume__v1", "__v1"),
        ("speaker_volume__V2", "__V2"),
        ("speaker_volume", None),
        ("speaker_volume_level", None),
        ("other__v1", None),
    ],
)
def test_variant_identifiers(identifier: str, rest: str | None) -> None:
    assert variant_rest(identifier, "speaker_volume") == rest
