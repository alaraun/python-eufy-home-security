"""short_timeouts and the library waits it shortens, read at call time."""

from __future__ import annotations

import importlib
import time
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import CommandNotAppliedError, DeviceTimeoutError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p import broadcast, pppp
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.discovery import discover_stations
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.testing import SYNTHETIC, FakeStation, short_timeouts
from eufy_home_security.testing.timeouts import SHORT_TIMEOUTS


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    await station.start()
    yield station
    station.stop()


def _session(fake: FakeStation, *, account_id: str = SYNTHETIC.account_id) -> StationSession:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(account_id, "user", fake.ecc_private_key_hex)

    return StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=fake.discovery_port
    )


def test_short_timeouts_sets_each_wait_and_restores_it() -> None:
    before = {
        name: getattr(session_module, name) for name in ("COMMAND_TIMEOUT", "DISCOVERY_ATTEMPTS")
    }
    with short_timeouts(COMMAND_TIMEOUT=0.2):
        assert session_module.COMMAND_TIMEOUT == 0.2  # an override wins
        assert SHORT_TIMEOUTS["DISCOVERY_ATTEMPTS"][1] == session_module.DISCOVERY_ATTEMPTS
        assert SHORT_TIMEOUTS["CAPTURE_START_TIMEOUT"][1] == broadcast.CAPTURE_START_TIMEOUT
    assert {name: getattr(session_module, name) for name in before} == before


def test_short_timeouts_sets_every_listed_wait_on_its_module() -> None:
    def current() -> dict[str, object]:
        return {
            name: getattr(importlib.import_module(f"eufy_home_security.{module}"), name)
            for name, (module, _value) in SHORT_TIMEOUTS.items()
        }

    before = current()
    with short_timeouts():
        assert current() == {name: value for name, (_module, value) in SHORT_TIMEOUTS.items()}
    assert current() == before


@pytest.mark.parametrize(
    "name",
    [
        "PRESET_SETTLE_SECONDS",
        "PTZ_SETTLE_SECONDS",
        "PTZ_BUSY_DELAY",
        "DEFAULT_PRESET_RESULT_WAIT",
        "FULL_RESOLUTION_TIMEOUT",
        "LIVE_OPEN_TIMEOUT",
    ],
)
def test_the_camera_motion_and_live_image_waits_are_shortened(name: str) -> None:
    module, value = SHORT_TIMEOUTS[name]
    assert value < getattr(importlib.import_module(f"eufy_home_security.{module}"), name)


def test_short_timeouts_refuses_an_unknown_name() -> None:
    with pytest.raises(KeyError, match="PARAM_SETTLE"), short_timeouts(PARAM_SETTLE=0.1):
        pass


async def test_a_patched_command_timeout_bounds_a_call_without_a_timeout(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "COMMAND_TIMEOUT", 0.3)
    session = _session(fake, account_id="f" * 40)  # the station ignores this account's arm
    try:
        await session.async_connect()
        started = time.monotonic()
        with pytest.raises(CommandNotAppliedError):
            await session.async_set_guard_mode(GuardMode.HOME)
        assert time.monotonic() - started < 2.0  # not the 6 s default
    finally:
        await session.async_close()


async def test_a_patched_still_timeout_bounds_a_fetch_without_a_timeout(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "STILL_FETCH_TIMEOUT", 0.3)
    session = _session(fake)
    try:
        await session.async_connect()
        started = time.monotonic()
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/missing.jpg")  # the fake never answers it
        assert time.monotonic() - started < 2.0  # not the 12 s default
    finally:
        await session.async_close()


async def test_a_patched_lan_discovery_timeout_bounds_a_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pppp, "LAN_DISCOVERY_TIMEOUT", 0.2)
    started = time.monotonic()
    assert await discover_stations(port=9, target="127.0.0.1") == []
    assert time.monotonic() - started < 1.0
