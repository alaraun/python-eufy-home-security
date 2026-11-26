"""What every lock command path decides before and after it sends."""

from __future__ import annotations

from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.locks import LockState
from eufy_home_security.lock_commands.control import ends_wait, is_guest


@pytest.mark.parametrize("target", [LockState.LOCKED, LockState.UNLOCKED])
@pytest.mark.parametrize("reading", list(LockState))
def test_only_the_asked_state_or_a_fault_ends_the_wait(
    reading: LockState, target: LockState
) -> None:
    expected = reading is target or reading in (LockState.JAMMED, LockState.INTERMEDIATE)
    assert ends_wait(reading, target) is expected


@pytest.mark.parametrize(
    ("member", "guest"),
    [
        ({"admin_user_id": "a" * 40, "member_type": 0}, True),
        ({"admin_user_id": "a" * 40}, True),  # no member_type: read as 0, as the app reads it
        ({"admin_user_id": "a" * 40, "member_type": 1}, False),
        ({"admin_user_id": "a" * 40, "member_type": 2}, False),
        ({}, False),
        (None, False),
    ],
)
def test_a_guest_is_a_member_record_of_type_0(member: dict[str, Any] | None, guest: bool) -> None:
    device = CloudDevice.from_api(
        {"device_sn": "T85D0P2000000001", "device_type": 0}
        | ({} if member is None else {"member": member})
    )
    assert is_guest(device) is guest
