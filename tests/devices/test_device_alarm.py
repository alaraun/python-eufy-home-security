"""The device-alarm lookups over the generated data."""

from __future__ import annotations

import pytest

from eufy_home_security.devices import device_alarm
from eufy_home_security.devices.device_alarm import DeviceAlarm, DeviceAlarms, device_alarms
from eufy_home_security.devices.recipes import ConnectType


def _alarms(code: str, connect: ConnectType = ConnectType.HB3) -> DeviceAlarms:
    alarms = device_alarms(code, connect)
    assert alarms is not None
    return alarms


@pytest.mark.parametrize(
    ("code", "connect", "tone"),
    [
        ("T8160", ConnectType.HB3, False),  # SET_DEVS_TONE_FILE on its channel
        ("T8150", ConnectType.HB3, True),  # SET_TONE_FILE behind a HomeBase
        ("T8030", ConnectType.HB3, True),  # a HomeBase's own
        ("T8170", ConnectType.SINGLE, True),  # starts with 1201, stops with 1202
    ],
)
def test_an_alarm_started_with_set_tone_file_is_the_station_tone(
    code: str, connect: ConnectType, tone: bool
) -> None:
    assert _alarms(code, connect).station_tone is tone


def test_the_choice_is_the_one_whose_start_sends_the_event_type() -> None:
    alarms = _alarms("T8160")
    assert alarms.choice_for(10) is DeviceAlarm.SOUND
    assert alarms.choice_for(23) is DeviceAlarm.SOUND_AND_LIGHT
    assert alarms.choice_for(25) is None  # a detection's siren
    assert alarms.choice_for(None) is None


def test_no_choice_is_named_where_several_send_the_type() -> None:
    def req(kind: int) -> tuple[int, dict[str, int]]:
        return 1202, {"type": kind}

    raw = {"default": 0, "choices": {c: (req(kind), req(0)) for c, kind in enumerate((10, 10, 23))}}
    alarms = device_alarm._alarms(raw)
    assert alarms.choice_for(10) is None
    assert alarms.choice_for(23) is DeviceAlarm.SOUND_AND_LIGHT


def test_a_request_without_a_type_names_no_choice() -> None:
    """A HomeBase's own alarm sends no type: no event type names its choice."""
    alarms = _alarms("T8010")
    assert alarms.choices == (DeviceAlarm.SOUND,)
    assert alarms.choice_for(None) is None


def test_an_alarm_with_any_siren_start_is_not_the_station_tone() -> None:
    """One choice starts with SET_TONE_FILE, another with SET_DEVS_TONE_FILE."""
    raw = {"default": 0, "choices": {0: ((1201, {}), (1201, {})), 1: ((1202, {}), (1202, {}))}}
    assert device_alarm._alarms(raw).station_tone is False
