"""A device's own siren and light (Station.async_trigger_device_alarm) against the fake station."""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices import device_alarm
from eufy_home_security.devices.device_alarm import DeviceAlarm
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    UnsupportedError,
)
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
CHANNEL = 3
CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    channel=CHANNEL,
)


def _camera(pn: str) -> CloudDevice:
    return dataclasses.replace(CAMERA, raw={"device_new_pn": pn})


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.siren_frames = True  # a HomeBase 3 answers 1202 with the siren frame only
    await station.start()
    yield station
    station.stop()


def _station(fake: FakeStation, cameras: Sequence[CloudDevice] = (CAMERA,)) -> Station:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    return Station(HB3, session, sub_devices=cameras)


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    st = _station(fake)
    yield st
    await st.async_close()


def _sent(fake: FakeStation, cmd: int) -> list[dict[str, Any]]:
    return [
        {k: v for k, v in obj.items() if k != "transaction"}
        for obj in fake.received
        if obj.get("cmd") == cmd
    ]


def _siren(seconds: int, kind: int = 10) -> dict[str, Any]:
    return {
        "account_id": SYNTHETIC.account_id,
        "cmd": 1202,
        "mChannel": CHANNEL,
        "mValue3": 0,
        "payload": {"channel": CHANNEL, "type": kind, "time_out": seconds, "user_name": "user"},
    }


async def test_the_camera_siren_is_sent_as_its_handler_does_and_confirmed_by_its_frame(
    station: Station, fake: FakeStation
) -> None:
    """A T8160 behind a HomeBase 3: SET_DEVS_TONE_FILE on its channel, 30 s then 0; the
    station sends no result, the device-siren frame on that channel confirms each."""
    session = station.session
    assert station.device_alarms(CAMERA.device_sn) == (
        DeviceAlarm.SOUND,
        DeviceAlarm.SOUND_AND_LIGHT,
    )
    assert station.device_alarm_default(CAMERA.device_sn) is DeviceAlarm.SOUND
    assert await station.async_trigger_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED
    assert await station.async_stop_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED
    assert _sent(fake, 1202) == [_siren(30), _siren(0)]
    assert fake.received_header_channels == [CHANNEL, CHANNEL]
    assert session.params[(CHANNEL, 1202)] == "0"
    assert not session._siren_waiters
    assert not session._op_lock.locked()


async def test_an_acknowledged_siren_without_its_frame_is_not_success(
    station: Station, fake: FakeStation
) -> None:
    fake.siren_frames = False
    with pytest.raises(CommandNotAppliedError):
        await station.async_trigger_device_alarm(CAMERA.device_sn, timeout=0.5)
    with pytest.raises(CommandNotAppliedError):
        await station.async_stop_device_alarm(CAMERA.device_sn, timeout=0.5)
    assert not station.session._siren_waiters


async def test_a_siren_frame_of_another_channel_confirms_nothing(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    send = fake.send_alarm_frame

    def elsewhere(ftype: int, *values: int, channel: int, cipher: int) -> None:
        send(ftype, *values, channel=channel + 1, cipher=cipher)

    monkeypatch.setattr(fake, "send_alarm_frame", elsewhere)
    with pytest.raises(CommandNotAppliedError):
        await station.async_trigger_device_alarm(CAMERA.device_sn, timeout=0.5)


async def test_a_siren_frame_in_the_other_state_confirms_nothing(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A trigger answered by an off frame (an arm sends ``[0, 0]`` on every channel)."""
    send = fake.send_alarm_frame

    def off(ftype: int, *values: int, channel: int, cipher: int) -> None:
        send(ftype, 0, 0, channel=channel, cipher=cipher)

    monkeypatch.setattr(fake, "send_alarm_frame", off)
    with pytest.raises(CommandNotAppliedError):
        await station.async_trigger_device_alarm(CAMERA.device_sn, timeout=0.5)


async def test_a_refused_siren_raises_the_stations_code(
    station: Station, fake: FakeStation
) -> None:
    fake.reply_to_settings = True
    fake.reply_codes[1202] = -1
    with pytest.raises(CommandRejectedError) as err:
        await station.async_trigger_device_alarm(CAMERA.device_sn)
    assert (err.value.command, err.value.code) == (1202, -1)


async def test_a_choice_the_app_does_not_offer_there_is_refused_unsent(
    station: Station, fake: FakeStation
) -> None:
    """A T8160 behind a HomeBase 3 offers no light-only alarm (the app reads its
    ``set_alarm_type__v1`` there)."""
    with pytest.raises(UnsupportedError, match="LIGHT"):
        await station.async_trigger_device_alarm(CAMERA.device_sn, DeviceAlarm.LIGHT)
    assert fake.received == []


async def test_a_model_the_app_offers_no_alarm_is_refused_unsent(fake: FakeStation) -> None:
    station = _station(fake, [_camera("T8210")])
    try:
        assert station.device_alarms(CAMERA.device_sn) == ()
        assert station.device_alarm_default(CAMERA.device_sn) is None
        with pytest.raises(UnsupportedError, match="no alarm"):
            await station.async_trigger_device_alarm(CAMERA.device_sn)
        with pytest.raises(UnsupportedError, match="no alarm"):
            await station.async_stop_device_alarm(CAMERA.device_sn)
    finally:
        await station.async_close()
    assert fake.received == []


async def test_the_default_choice_is_the_one_the_app_preselects(fake: FakeStation) -> None:
    """A T8162 behind a HomeBase 3 preselects light only: type 22."""
    station = _station(fake, [_camera("T8162")])
    try:
        assert station.device_alarm_default(CAMERA.device_sn) is DeviceAlarm.LIGHT
        await station.async_trigger_device_alarm(CAMERA.device_sn)
    finally:
        await station.async_close()
    assert _sent(fake, 1202) == [_siren(30, 22)]


async def test_a_product_named_nowhere_in_code_takes_its_alarm_from_the_data(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = {
        "default": 0,
        "choices": {
            0: (
                (
                    1202,
                    {"channel": "$channel", "type": 4, "time_out": 30, "user_name": "$user_name"},
                ),
                (
                    1202,
                    {"channel": "$channel", "type": 0, "time_out": 0, "user_name": "$user_name"},
                ),
            )
        },
    }
    table = {"T9ZZ9": {ConnectType.HB3: device_alarm._alarms(raw)}}
    monkeypatch.setattr(device_alarm, "_TABLE", table)
    station = _station(fake, [_camera("T9ZZ9")])
    try:
        assert station.device_alarms(CAMERA.device_sn) == (DeviceAlarm.SOUND,)
        await station.async_trigger_device_alarm(CAMERA.device_sn)
        await station.async_stop_device_alarm(CAMERA.device_sn)
    finally:
        await station.async_close()
    assert _sent(fake, 1202) == [_siren(30, 4), _siren(0, 0)]


async def test_the_station_itself_sounds_through_its_own_handlers_request(
    station: Station, fake: FakeStation
) -> None:
    """The HomeBase's own entry: SET_TONE_FILE on channel 0, confirmed by its alarm-tone
    frame, as :meth:`Station.async_trigger_alarm`."""
    fake.tone_frames = True
    assert DeviceAlarm.SOUND in station.device_alarms(HB3.device_sn)
    await station.async_trigger_device_alarm(HB3.device_sn, DeviceAlarm.SOUND)
    await station.async_stop_device_alarm(HB3.device_sn, DeviceAlarm.SOUND)
    payloads = [obj["payload"] for obj in _sent(fake, 1201)]
    assert payloads == [{"time_out": 30, "user_name": "user"}, {"time_out": 0, "user_name": "user"}]
    assert not station.session._tone_waiters
