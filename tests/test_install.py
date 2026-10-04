"""InstallState: the in-process request hold-off shared between accounts."""

from __future__ import annotations

import time

import pytest

from eufy_home_security.install import InstallState


def test_a_request_hold_off_runs_out_and_is_never_shortened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    state = InstallState()
    assert state.request_held_off_for() is None
    state.hold_off_requests(0)
    assert state.request_held_off_for() is None
    state.hold_off_requests(3600)
    state.hold_off_requests(60)  # a shorter one keeps the longer
    assert state.request_held_off_for() == pytest.approx(3600)
    now[0] += 3600
    assert state.request_held_off_for() is None
