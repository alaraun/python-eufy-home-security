"""What every lock command path decides before and after it sends."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.locks import LockState
from eufy_home_security.lock_commands.control import ends_wait


@pytest.mark.parametrize("target", [LockState.LOCKED, LockState.UNLOCKED])
@pytest.mark.parametrize("reading", list(LockState))
def test_only_the_asked_state_or_a_fault_ends_the_wait(
    reading: LockState, target: LockState
) -> None:
    expected = reading is target or reading in (LockState.JAMMED, LockState.INTERMEDIATE)
    assert ends_wait(reading, target) is expected
