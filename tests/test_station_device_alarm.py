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
from eufy_home_security.devices.support import Evidence, Support
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    UnsupportedError,
)
from eufy_home_security.p2p.session import CommandOutcome, P2PCredentials, StationSession
from eufy_home_security.p2p.xzyh import FrameType
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


async def test_the_event_type_alone_gives_the_sirens_state(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start frame ``[type, 0]`` and a stop frame ``[0, seconds]`` confirm each."""
    send = fake.send_alarm_frame

    def type_only(ftype: int, *values: int, channel: int, cipher: int) -> None:
        send(ftype, values[0], 0 if values[0] else 30, channel=channel, cipher=cipher)

    monkeypatch.setattr(fake, "send_alarm_frame", type_only)
    assert await station.async_trigger_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED
    assert await station.async_stop_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED


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


@pytest.mark.parametrize("alarm", [3, 5])
async def test_an_int_that_is_no_offered_choice_is_refused_unsent(
    station: Station, fake: FakeStation, alarm: int
) -> None:
    with pytest.raises(UnsupportedError, match=f"no {alarm} alarm"):
        await station.async_trigger_device_alarm(CAMERA.device_sn, alarm)
    with pytest.raises(UnsupportedError, match=f"no {alarm} alarm"):
        await station.async_stop_device_alarm(CAMERA.device_sn, alarm)
    assert fake.received == []


async def test_a_serial_not_paired_here_has_no_alarm_and_is_refused_unsent(
    station: Station, fake: FakeStation
) -> None:
    """A serial of a model with an alarm, neither the station nor one of its devices."""
    stranger = SYNTHETIC.camera_sn[:-1] + "9"
    assert stranger != CAMERA.device_sn
    assert station.device_alarms(stranger) == ()
    assert station.device_alarm_default(stranger) is None
    with pytest.raises(UnsupportedError, match="not paired"):
        await station.async_trigger_device_alarm(stranger)
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


def _only_product(
    monkeypatch: pytest.MonkeyPatch, start: tuple[int, int], stop: tuple[int, int]
) -> None:
    """Make T9ZZ9 behind a HomeBase 3 the only product with an alarm: one choice whose
    start and stop requests are ``(command, type)``."""

    def req(command_type: tuple[int, int], seconds: int) -> tuple[int, dict[str, Any]]:
        command, kind = command_type
        params = {"channel": "$channel", "type": kind, "time_out": seconds}
        return command, params | {"user_name": "$user_name"}

    raw = {"default": 0, "choices": {0: (req(start, 30), req(stop, 0))}}
    table = {"T9ZZ9": {ConnectType.HB3: device_alarm._alarms(raw)}}
    monkeypatch.setattr(device_alarm, "_TABLE", table)


async def test_a_product_named_nowhere_in_code_takes_its_alarm_from_the_data(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    _only_product(monkeypatch, (1202, 4), (1202, 0))
    station = _station(fake, [_camera("T9ZZ9")])
    try:
        assert station.device_alarms(CAMERA.device_sn) == (DeviceAlarm.SOUND,)
        await station.async_trigger_device_alarm(CAMERA.device_sn)
        await station.async_stop_device_alarm(CAMERA.device_sn)
    finally:
        await station.async_close()
    assert _sent(fake, 1202) == [_siren(30, 4), _siren(0, 0)]


async def test_each_request_is_confirmed_by_the_frame_of_its_own_command(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start with SET_TONE_FILE on the device's channel is confirmed by the alarm-tone
    frame (sent on 255), its stop with SET_DEVS_TONE_FILE by the siren frame."""
    _only_product(monkeypatch, (1201, 10), (1202, 10))
    fake.tone_frames = True
    station = _station(fake, [_camera("T9ZZ9")])
    try:
        assert await station.async_trigger_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED
        assert await station.async_stop_device_alarm(CAMERA.device_sn) is CommandOutcome.APPLIED
        assert not station.session._tone_waiters
        assert not station.session._siren_waiters
    finally:
        await station.async_close()
    assert [obj["cmd"] for obj in fake.received] == [1201, 1202]
    assert fake.received_header_channels == [CHANNEL, CHANNEL]


async def test_a_tone_request_without_its_alarm_tone_frame_is_not_success(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SET_TONE_FILE start is not confirmed by a siren frame on the device's channel."""
    _only_product(monkeypatch, (1201, 10), (1202, 10))
    send = fake.send_alarm_frame

    def siren_instead(ftype: int, *values: int, channel: int, cipher: int) -> None:
        send(FrameType.SIREN_NOTIFY, 10, 30, channel=CHANNEL, cipher=cipher)

    monkeypatch.setattr(fake, "send_alarm_frame", siren_instead)
    fake.tone_frames = True
    station = _station(fake, [_camera("T9ZZ9")])
    try:
        with pytest.raises(CommandNotAppliedError):
            await station.async_trigger_device_alarm(CAMERA.device_sn, timeout=0.5)
    finally:
        await station.async_close()


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
    assert [obj["mChannel"] for obj in _sent(fake, 1201)] == [0, 0]
    assert fake.received_header_channels == [0, 0]
    assert not station.session._tone_waiters


async def test_the_stations_own_alarm_is_refused_where_its_siren_is(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HomeBase's own serial is its station siren: refused like async_trigger_alarm."""
    unknown = Evidence(Support.UNKNOWN, "no siren here")
    monkeypatch.setattr(Station, "config_support", lambda self, feature: unknown)
    assert DeviceAlarm.SOUND in station.device_alarms(HB3.device_sn)
    with pytest.raises(UnsupportedError, match="no siren here"):
        await station.async_trigger_device_alarm(HB3.device_sn)
    with pytest.raises(UnsupportedError, match="no siren here"):
        await station.async_stop_device_alarm(HB3.device_sn)
    assert fake.received == []
