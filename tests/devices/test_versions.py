"""Firmware version comparison (devices/versions.py)."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.versions import version_bigger_than, version_equals


@pytest.mark.parametrize(
    ("a", "b", "bigger"),
    [
        ("3.8.7.4", "3.7.4.3", True),
        ("3.7.4.3", "3.8.7.4", False),
        ("3.7.4.3", "3.7.4.3", False),
        ("4.2", "4.1.9.999", True),  # a missing field counts as 0
        ("4.1.9.1000", "4.1.9.999", True),  # fields compare as numbers, not text
        ("1.x.5", "1.0.4", True),  # a non-numeric field counts as 0
        ("1.0.beta", "1.0", True),  # parts left over after the numeric run
        ("1.0", "1.0.beta", False),
        ("1.0.rc.2", "1.0.rc.1", True),  # the last integer part of the leftovers
        ("1.0.rc.1", "1.0.rc.2", False),
        ("1.0.rc.2", "1.0.beta.1", False),  # leftovers before it differ
        ("1.0.rc", "1.0.rc", False),
        (
            "1.0.rc.2a",
            "1.0.rc.1a",
            False,
        ),  # leftovers compare only parts that are integers as written
        ("2147483647", "-1", False),  # the field difference wraps as a 32-bit integer
        ("99999999999", "1", False),  # a field beyond 32 bits is not a number
        ("", "3.7.4.3", False),
        ("3.7.4.3", "", True),
    ],
)
def test_version_bigger_than(a: str, b: str, bigger: bool) -> None:
    assert version_bigger_than(a, b) is bigger


@pytest.mark.parametrize(
    ("a", "b", "equal"),
    [
        ("3.7.4.3", "3.7.4.3", True),
        ("4.2", "4.2.0.0", True),
        ("2.1.6.9h", "2.1.6.9", True),  # trailing letters are dropped
        ("+5", "5", True),
        ("", "0", True),
        ("3.7.4.3", "3.7.4.4", False),
        ("1.0.rc", "1.0.beta", False),
        ("1.0.rc", "1.0", False),
    ],
)
def test_version_equals(a: str, b: str, equal: bool) -> None:
    assert version_equals(a, b) is equal
