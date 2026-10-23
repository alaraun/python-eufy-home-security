"""Station actions against the fake station: restart, sound and stop the alarm."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices import station_config_support as scs
from eufy_home_security.devices._station_config_data import RESTART_COMMAND
from eufy_home_security.devices.station_config_support import (
    StationFeature,
    config_support,
    restart_command,
    station_config_models,
)
from eufy_home_security.devices.support import Support
from eufy_home_security.events import AlarmChanged, AlarmStopSource, Event
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    UnsupportedError,
)
from eufy_home_security.p2p.messages import ECB_STATION_CMDS
from eufy_home_security.p2p.session import CommandOutcome, P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

HB3 = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)

#: Models whose restart the library sends.
RESTART_MODELS = tuple(sorted(RESTART_COMMAND))


def _as(pn: str) -> CloudDevice:
    """The fake's station listed under product code ``pn``."""
    return dataclasses.replace(HB3, raw={"device_new_pn": pn})


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    station.reply_to_settings = True
    await station.start()
    yield station
    station.stop()


def _station(fake: FakeStation, device: CloudDevice = HB3) -> Station:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    return Station(device, session)


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    st = _station(fake)
    yield st
    await st.async_close()


def _sent(fake: FakeStation, cmd: int) -> list[dict[str, Any]]:
    """Every ``cmd`` command the fake received, without its time-stamp transaction."""
    return [
        {k: v for k, v in obj.items() if k != "transaction"}
        for obj in fake.received
        if obj.get("cmd") == cmd
    ]


def test_every_restart_request_is_an_ecb_station_scalar() -> None:
    assert RESTART_MODELS == ("T8001", "T8002", "T8010", "T8020", "T8025", "T8026", "T8030")
    for pn in station_config_models():
        command = restart_command(pn)
        declared = config_support(pn, StationFeature.RESTART).support is not Support.UNKNOWN
        assert declared is (command is not None), pn
        if command is not None:
            assert command == (1034, None)
            assert command[0] in ECB_STATION_CMDS


@pytest.mark.parametrize("pn", RESTART_MODELS)
async def test_restart_sends_the_models_restart_request(fake: FakeStation, pn: str) -> None:
    station = _station(fake, _as(pn))
    try:
        assert await station.async_restart() is CommandOutcome.APPLIED
    finally:
        await station.async_close()
    assert fake.ecb_received == [(1034, 255, 0)]
    assert fake.received == []


async def test_a_rejected_restart_raises(station: Station, fake: FakeStation) -> None:
    fake.account_id = "another-account"  # the ECB result code is then -104
    with pytest.raises(CommandRejectedError) as err:
        await station.async_restart()
    assert (err.value.command, err.value.code) == (1034, -104)


async def test_an_unanswered_restart_is_not_success(station: Station, fake: FakeStation) -> None:
    fake.ecb_apply_late = True  # taken, never answered
    with pytest.raises(CommandNotAppliedError):
        await station.async_restart(timeout=0.5)


@pytest.mark.parametrize(
    ("pn", "reason"),
    [
        ("T8023", "declares no restart_device"),
        ("T8024", "declares no restart_device"),
        ("T8N00", "WebRTC"),
        ("T9000", "WebRTC"),
        ("T8028", "builds restart_device as None"),
    ],
)
async def test_restart_is_refused_without_sending_on_a_model_without_it(
    fake: FakeStation, pn: str, reason: str
) -> None:
    station = _station(fake, _as(pn))
    assert station.config_support(StationFeature.RESTART).support is Support.UNKNOWN
    with pytest.raises(UnsupportedError, match=reason):
        await station.async_restart()
    assert fake.ecb_received == []
    assert fake.received == []


async def test_restart_is_refused_below_a_firmware_gate(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A *declared* model below the app's gate is refused (a *verified* one is not gated)."""
    monkeypatch.setattr(scs, "MIN_FIRMWARE", {"T8010": {"restart": "9.0"}})
    station = _station(fake, _as("T8010"))
    try:
        with pytest.raises(UnsupportedError, match=r"from firmware 9\.0"):
            await station.async_restart()
    finally:
        await station.async_close()
    assert fake.ecb_received == []


# ── sound / stop the alarm ────────────────────────────────────────────────────────


def _tone_file(seconds: int) -> dict[str, Any]:
    return {
        "account_id": SYNTHETIC.account_id,
        "cmd": 1201,
        "mChannel": 0,
        "mValue3": 0,
        "payload": {"time_out": seconds, "user_name": "user"},
    }


def test_sound_alarm_is_declared_where_the_library_sends_it() -> None:
    declared = {
        pn
        for pn in station_config_models()
        if config_support(pn, StationFeature.SOUND_ALARM).support is not Support.UNKNOWN
    }
    assert declared == {"T8001", "T8002", "T8010", "T8020", "T8021", "T8023", "T8025", "T8030"}


async def test_trigger_and_stop_send_the_tone_file_body(
    station: Station, fake: FakeStation
) -> None:
    assert await station.async_trigger_alarm(30) is CommandOutcome.APPLIED
    assert await station.async_stop_alarm() is CommandOutcome.APPLIED
    assert _sent(fake, 1201) == [_tone_file(30), _tone_file(0)]
    assert fake.received_header_channels == [0, 0]


async def test_trigger_defaults_to_the_apps_30_seconds(station: Station, fake: FakeStation) -> None:
    await station.async_trigger_alarm()
    assert _sent(fake, 1201) == [_tone_file(30)]


@pytest.mark.parametrize("seconds", [0, 2, 29, 60, -1])
async def test_seconds_outside_the_apps_options_send_nothing(
    station: Station, fake: FakeStation, seconds: int
) -> None:
    with pytest.raises(ValueError, match="alarm seconds"):
        await station.async_trigger_alarm(seconds)
    assert fake.received == []


async def test_a_rejected_alarm_raises(station: Station, fake: FakeStation) -> None:
    fake.reply_codes[1201] = -1
    with pytest.raises(CommandRejectedError) as err:
        await station.async_trigger_alarm(30)
    assert (err.value.command, err.value.code) == (1201, -1)
    with pytest.raises(CommandRejectedError):
        await station.async_stop_alarm()


async def test_an_unanswered_alarm_is_not_success(station: Station, fake: FakeStation) -> None:
    fake.reply_to_settings = False
    with pytest.raises(CommandNotAppliedError):
        await station.async_trigger_alarm(30, timeout=0.5)
    with pytest.raises(CommandNotAppliedError):
        await station.async_stop_alarm(timeout=0.5)


async def test_the_alarm_tone_frame_confirms_an_unanswered_alarm(
    station: Station, fake: FakeStation
) -> None:
    """A HomeBase 3 acknowledges 1201 without a result and reports the siren in its
    alarm-tone frame: on for a trigger, stopped from the app for a stop. Each call returns
    on the frame, well inside the default command timeout, and leaves no waiter or lock."""
    fake.reply_to_settings = False
    fake.tone_frames = True
    session = station.session
    calls: tuple[Callable[[], Awaitable[CommandOutcome]], ...] = (
        lambda: station.async_trigger_alarm(30),
        station.async_stop_alarm,
    )
    for call in calls:
        started = time.monotonic()
        assert await call() is CommandOutcome.APPLIED
        assert time.monotonic() - started < 2.0
        assert not session._waiters
        assert not session._tone_waiters
        assert not session._op_lock.locked()
    assert _sent(fake, 1201) == [_tone_file(30), _tone_file(0)]


async def test_the_station_says_whether_its_alarm_sounds(
    station: Station, fake: FakeStation
) -> None:
    """``alarming`` follows the alarm-tone frames and is already set when a subscriber
    receives the AlarmChanged; ``last_alarm`` is that event."""
    fake.tone_frames = True
    seen: list[tuple[bool, bool]] = []

    def on_event(event: Event) -> None:
        if isinstance(event, AlarmChanged):
            seen.append((event.alarming, station.alarming))

    station.subscribe(on_event)
    assert (station.alarming, station.last_alarm) == (False, None)
    await station.async_trigger_alarm(30)
    started = station.last_alarm
    assert started is not None
    assert (station.alarming, started.event_type, started.duration_s) == (True, 3, 30)
    await station.async_stop_alarm()
    stopped = station.last_alarm
    assert stopped is not None
    assert (station.alarming, stopped.stop_source) == (False, AlarmStopSource.APP)
    assert seen == [(True, True), (False, False)]


@pytest.mark.parametrize(
    ("pn", "reason"),
    [
        ("T8024", "declares no set_alarm_type"),
        ("T8026", "declares no set_alarm_type"),
        ("T8N00", "declares no set_alarm_type"),
        ("T9000", "WebRTC"),
    ],
)
async def test_the_alarm_is_refused_without_sending_on_a_model_without_it(
    fake: FakeStation, pn: str, reason: str
) -> None:
    station = _station(fake, _as(pn))
    try:
        assert station.config_support(StationFeature.SOUND_ALARM).support is Support.UNKNOWN
        with pytest.raises(UnsupportedError, match=reason):
            await station.async_trigger_alarm(30)
        with pytest.raises(UnsupportedError, match=reason):
            await station.async_stop_alarm()
    finally:
        await station.async_close()
    assert fake.received == []
