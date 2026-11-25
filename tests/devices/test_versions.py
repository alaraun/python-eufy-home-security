"""Firmware version comparison (devices/versions.py)."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.versions import (
    remote_version_at_least,
    version_bigger_than,
    version_equals,
)


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


@pytest.mark.parametrize(
    ("device", "threshold", "expected"),
    [
        ("2.2.0.0", "2.2.0.0", True),
        ("2.2.0.1", "2.2.0.0", True),
        ("2.1.9.9", "2.2.0.0", False),
        ("2.10", "2.9.9", True),
        ("2.2", "2.2.0.0", True),  # missing fields count as 0
        ("2.2.0.0", "2.2", True),
        ("v2.2.0.0b", "2.2.0.0", True),  # every character but digits and dots is dropped
        ("2.2.0.0.", "2.2.0.0", True),  # a trailing dot splits off nothing
        ("2..2", "2.2", False),  # an empty field does not parse
        (".2", "0.2", False),
        ("", "0.3.0.0", False),  # no version reaches no threshold
        ("abc", "0.3.0.0", False),
        ("0.3.0.0", "", False),
        ("99999999999.0", "1.0", False),  # a field over 32 bits does not parse
    ],
)
def test_remote_version_at_least(device: str, threshold: str, expected: bool) -> None:
    assert remote_version_at_least(device, threshold) is expected
