"""Lock state and garage doors on a station (``Station.lock_state``,
``Station.garage_doors``, ``Station.async_open_garage_door`` / ``async_close_garage_door``)
against the fake station, with model files that carry ``lock`` and ``garage`` blocks."""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.garage import GarageDoor, GarageDoorSource, GarageDoorState
from eufy_home_security.devices.locks import LockReading, LockState, LockStateSource
from eufy_home_security.events import (
    Event,
    EventSource,
    GarageDoorChanged,
    LockStateChanged,
    SecurityEvent,
)
from eufy_home_security.exceptions import (
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    DoorNotMovedError,
    DoorStateUnknownError,
    UnsupportedError,
)
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.p2p.session.param_state import ParamOrigin
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.station import Station
from eufy_home_security.station.locks import LOCK_PUSH_MAX_AGE_SECONDS, LOCK_REPORT_SLACK_SECONDS
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

pytestmark = pytest.mark.usefixtures("door_models")

LOCK_SN = "T8502P2000000001"
GARAGE_SN = "T8453P2000000001"
STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=0,
    name="Home Base",
    station_sn=SYNTHETIC.station_sn,
    p2p_did=SYNTHETIC.did,
)
LOCK = CloudDevice(
    device_sn=LOCK_SN, device_type=52, name="Front", station_sn=SYNTHETIC.station_sn, channel=1
)
CLOSED_BOTH = "10"  # door 1 closed (2), door 2 closed (8)


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    await station.start()
    yield station
    station.stop()


def _session(fake: FakeStation, serial: str) -> StationSession:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "Nick", fake.ecc_private_key_hex)

    return StationSession(serial, credentials, host="127.0.0.1", port=fake.discovery_port)


def _events(station: Station) -> list[Event]:
    seen: list[Event] = []
    station.subscribe(seen.append)
    return seen


def _locks(events: list[Event]) -> list[tuple[LockState, LockStateSource, str | None]]:
    return [(e.state, e.source, e.raw) for e in events if isinstance(e, LockStateChanged)]


def _doors(events: list[Event]) -> list[tuple[int, GarageDoorState, GarageDoorSource]]:
    return [(e.door, e.state, e.source) for e in events if isinstance(e, GarageDoorChanged)]


# ── locks ────────────────────────────────────────────────────────────────────


@pytest.fixture
async def hub(fake: FakeStation) -> AsyncIterator[Station]:
    """A HomeBase with the lock on channel 1 reporting 1912 locked."""
    fake.params[1] = {1912: "4"}
    station = Station(STATION, _session(fake, SYNTHETIC.station_sn), sub_devices=[LOCK])
    yield station
    await station.async_close()


async def test_a_lock_behind_a_station_reads_its_1912(hub: Station, fake: FakeStation) -> None:
    events = _events(hub)
    assert hub.lock_state(LOCK_SN) is None
    await hub.async_update()
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.LOCKED, source=LockStateSource.P2P, raw="4"
    )
    fake.params[1][1912] = "3"
    await hub.async_update()
    fake.params[1][1912] = " 3 "  # another value of the same state: no event
    await hub.async_update()
    assert _locks(events) == [
        (LockState.LOCKED, LockStateSource.P2P, "4"),
        (LockState.UNLOCKED, LockStateSource.P2P, "3"),
    ]
    first = next(e for e in events if isinstance(e, LockStateChanged))
    assert (first.device_sn, first.station_sn) == (LOCK_SN, SYNTHETIC.station_sn)
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNLOCKED, source=LockStateSource.P2P, raw=" 3 "
    )
    assert hub.lock_state(SYNTHETIC.station_sn) is None  # no lock
    with pytest.raises(UnsupportedError, match="not paired"):
        hub.lock_state("T8502P2000099999")


def _push(event_type: int, at: int, device_sn: str = LOCK_SN) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.CLOUD, device_sn=device_sn, event_type=event_type, event_time_ms=at
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _reported_ms(station: Station) -> int:
    """When the held lock-state value of the lock on channel 1 arrived (epoch ms)."""
    at = station.session.param_time((1, 1912))
    assert at is not None
    return int(at * 1000)


async def test_lock_pushes_set_the_state_in_event_time_order(
    hub: Station, fake: FakeStation
) -> None:
    events = _events(hub)
    await hub.async_update()
    now = _now_ms()
    assert hub.note_lock_push(_push(259, now)) is True  # unlocked by code
    assert hub.note_lock_push(_push(262, now - 1)) is False  # older than the last push
    assert hub.note_lock_push(_push(262, now)) is True  # as old as the last push: taken
    assert hub.note_lock_push(_push(513, now)) is False  # low battery: no state
    assert hub.note_lock_push(_push(262, now, "T8502P2000099999")) is False
    undated = SecurityEvent(source=EventSource.CLOUD, device_sn=LOCK_SN, event_type=259)
    assert hub.note_lock_push(undated) is True  # dated on arrival
    assert hub.note_lock_push(_push(516, now - 1)) is False  # older than that arrival
    assert hub.note_lock_push(_push(516, _now_ms() + 1)) is True  # offline
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNKNOWN, source=LockStateSource.PUSH, event_type=516
    )
    assert _locks(events) == [
        (LockState.LOCKED, LockStateSource.P2P, "4"),
        (LockState.UNLOCKED, LockStateSource.PUSH, None),
        (LockState.LOCKED, LockStateSource.PUSH, None),
        (LockState.UNLOCKED, LockStateSource.PUSH, None),
        (LockState.UNKNOWN, LockStateSource.PUSH, None),
    ]
    pushed = [e for e in events if isinstance(e, LockStateChanged) and e.event_type]
    assert [e.event_type for e in pushed] == [259, 262, 259, 516]


async def test_a_lock_push_older_than_the_last_report_is_dropped(
    hub: Station, fake: FakeStation
) -> None:
    """A push about an earlier change (a redelivery, a late one) cannot move the state the
    station reported since; one up to the slack before the report still can."""
    fake.params[1][1912] = "3"
    await hub.async_update()
    assert hub.note_lock_push(_push(262, _now_ms() - 3_600_000)) is False  # an hour old
    slack = LOCK_REPORT_SLACK_SECONDS * 1000
    assert hub.note_lock_push(_push(262, _reported_ms(hub) - slack - 1)) is False
    await hub.async_update()  # the station still reports unlocked
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNLOCKED, source=LockStateSource.P2P, raw="3"
    )
    assert hub.note_lock_push(_push(262, _reported_ms(hub) - slack)) is True
    assert hub.lock_state(LOCK_SN).state is LockState.LOCKED  # type: ignore[union-attr]


async def test_a_lock_push_older_than_the_bound_is_dropped(hub: Station) -> None:
    now = _now_ms()
    hub._locks._now_ms = lambda: now
    bound = LOCK_PUSH_MAX_AGE_SECONDS * 1000
    assert hub.note_lock_push(_push(262, now - bound - 1)) is False
    assert hub.lock_state(LOCK_SN) is None
    assert hub.note_lock_push(_push(262, now - bound)) is True


async def test_a_report_after_a_push_replaces_it_when_its_value_repeats(
    hub: Station, fake: FakeStation
) -> None:
    """A push-only state (jammed) lasts until the station's next report: a dump taken after
    the push gives the lock-state code again, though it did not move."""
    events = _events(hub)
    await hub.async_update()
    assert hub.note_lock_push(_push(517, _now_ms() - 1_000)) is True  # mechanical fault
    assert hub.lock_state(LOCK_SN).state is LockState.JAMMED  # type: ignore[union-attr]
    await hub.async_update()  # still "4"
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.LOCKED, source=LockStateSource.P2P, raw="4"
    )
    assert _locks(events) == [
        (LockState.LOCKED, LockStateSource.P2P, "4"),
        (LockState.JAMMED, LockStateSource.PUSH, None),
        (LockState.LOCKED, LockStateSource.P2P, "4"),
    ]


def _listed(device: CloudDevice, param: int, updated_ms: int | None) -> CloudDevice:
    entry: dict[str, object] = {"param_type": param, "param_value": "4"}
    if updated_ms is not None:
        entry["update_time"] = updated_ms // 1000
    return dataclasses.replace(device, raw={**device.raw, "params": [entry]})


async def test_a_cloud_copy_replaces_a_push_only_when_dated_after_it(fake: FakeStation) -> None:
    station = Station(STATION, _session(fake, SYNTHETIC.station_sn))
    pushed = (_now_ms() // 1000 - 60) * 1000  # cloud times are whole seconds
    station.update_sub_devices([_listed(LOCK, 1912, pushed - 10_000)])
    assert station.note_lock_push(_push(259, pushed)) is True
    for updated in (pushed - 10_000, pushed, None):  # older, as old, undated
        station.update_sub_devices([_listed(LOCK, 1912, updated)])
        assert station.lock_state(LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]
    station.update_sub_devices([_listed(LOCK, 1912, pushed + 60_000)])
    assert station.lock_state(LOCK_SN) == LockReading(
        state=LockState.LOCKED, source=LockStateSource.CLOUD, raw="4"
    )
    station.update_sub_devices([_listed(LOCK, 1912, pushed - 100_000)])  # an older copy
    slack = LOCK_REPORT_SLACK_SECONDS * 1000
    assert station.note_lock_push(_push(259, pushed + 60_000 - slack - 1)) is False


async def test_a_lock_without_a_dump_reads_the_cloud_copy(fake: FakeStation) -> None:
    station = Station(STATION, _session(fake, SYNTHETIC.station_sn))
    events = _events(station)
    listed = dataclasses.replace(LOCK, raw={"params": [{"param_type": 1912, "param_value": "7"}]})
    station.update_sub_devices([listed])
    assert station.lock_state(LOCK_SN) == LockReading(
        state=LockState.LOCKING, source=LockStateSource.CLOUD, raw="7"
    )
    station.update_sub_devices([listed])
    assert len(_locks(events)) == 1


async def test_a_parameter_notify_names_its_source(hub: Station, fake: FakeStation) -> None:
    events = _events(hub)
    await hub.async_update()
    hub.session._param_state._param_origin[(1, 1912)] = ParamOrigin.NOTIFY
    hub.session._param_state._params[(1, 1912)] = "6"
    hub._refresh_doors()
    assert _locks(events)[-1] == (LockState.UNLOCKING, LockStateSource.NOTIFY, "6")


async def test_a_lock_that_is_its_own_station_reads_6000(fake: FakeStation) -> None:
    fake.serial = "T8502P2000000002"
    fake.static_key = static_key(fake.serial, fake.did)
    device = CloudDevice(
        device_sn="T8502P2000000002",
        device_type=52,
        name="Back",
        p2p_did=SYNTHETIC.did,
        station_sn="T8502P2000000002",
    )
    station = Station(device, _session(fake, device.device_sn))
    fake.params[0] |= {1912: "3", 6000: "4"}
    fake.params[255] |= {1912: "3", 6000: "4"}
    try:
        await station.async_update()
        reading = station.lock_state(device.device_sn)
        assert station.note_lock_push(_push(259, _now_ms() - 1_000, device.device_sn))
        await station.async_update()  # a dump after the push, the same value
        again = station.lock_state(device.device_sn)
    finally:
        await station.async_close()
    assert reading is not None
    assert (reading.state, reading.raw) == (LockState.LOCKED, "4")
    assert again == reading


async def test_a_lock_that_is_its_own_station_dates_its_cloud_copy(fake: FakeStation) -> None:
    fake.serial = "T8502P2000000002"
    fake.static_key = static_key(fake.serial, fake.did)
    device = CloudDevice(
        device_sn="T8502P2000000002",
        device_type=52,
        name="Back",
        p2p_did=SYNTHETIC.did,
        station_sn="T8502P2000000002",
    )
    station = Station(device, _session(fake, device.device_sn))
    pushed = (_now_ms() // 1000 - 60) * 1000
    try:
        await station.async_update()  # no 6000 in the dump: the cloud's copy
        station.apply_cloud_device(_listed(device, 6000, pushed - 10_000))
        assert station.note_lock_push(_push(259, pushed, device.device_sn))
        station.apply_cloud_device(_listed(device, 6000, pushed - 10_000))
        unchanged = station.lock_state(device.device_sn)
        station.apply_cloud_device(_listed(device, 6000, pushed + 10_000))
        replaced = station.lock_state(device.device_sn)
    finally:
        await station.async_close()
    assert unchanged is not None
    assert unchanged.state is LockState.UNLOCKED
    assert replaced == LockReading(state=LockState.LOCKED, source=LockStateSource.CLOUD, raw="4")


# ── garage doors ─────────────────────────────────────────────────────────────


@pytest.fixture
async def garage(fake: FakeStation) -> AsyncIterator[Station]:
    """A standalone T8453 with both doors bound and closed, door commands moving them."""
    fake.serial = GARAGE_SN
    fake.static_key = static_key(GARAGE_SN, fake.did)
    fake.garage_moves = True
    for block in (fake.params[0], fake.params[255]):
        block |= {7500: CLOSED_BOTH, 7501: "3", 7502: "15"}
    device = CloudDevice(
        device_sn=GARAGE_SN,
        device_type=133,
        name="Garage",
        p2p_did=SYNTHETIC.did,
        station_sn=GARAGE_SN,
    )
    station = Station(device, _session(fake, GARAGE_SN))
    await station.async_update()
    yield station
    await station.async_close()


def _door(door: int, state: GarageDoorState, *, motor: bool = True) -> GarageDoor:
    return GarageDoor(
        device_sn=GARAGE_SN,
        door=door,
        motor_bound=motor,
        sensor_bound=True,
        sensor_calibrated=True,
        state=state,
    )


async def test_the_doors_a_unit_reports_and_their_state(garage: Station) -> None:
    closed = GarageDoorState.CLOSED
    assert garage.garage_doors() == (_door(1, closed), _door(2, closed))
    assert garage.garage_doors(GARAGE_SN) == garage.garage_doors()


async def test_open_sends_the_apps_body_and_waits_for_the_door(
    garage: Station, fake: FakeStation
) -> None:
    fake.garage_report_delay = 0.2
    events = _events(garage)
    assert await garage.async_open_garage_door(GARAGE_SN, 2) is GarageDoorState.OPEN
    assert fake.doorbell_payloads[-1] == {
        "commandType": 7500,
        "data": {"type": 3, "user_name": "Nick", "source": 0, "disable_push": 0, "cmdType": 0},
    }
    assert _doors(events) == [
        (2, GarageDoorState.OPENING, GarageDoorSource.COMMAND),
        (2, GarageDoorState.OPEN, GarageDoorSource.NOTIFY),
    ]
    assert garage.garage_doors()[1].state is GarageDoorState.OPEN
    assert await garage.async_close_garage_door(GARAGE_SN, 2) is GarageDoorState.CLOSED
    assert fake.doorbell_payloads[-1]["data"]["type"] == 2


async def test_a_door_in_the_asked_state_sends_nothing(garage: Station, fake: FakeStation) -> None:
    assert await garage.async_close_garage_door(GARAGE_SN, 1) is GarageDoorState.CLOSED
    assert fake.doorbell_payloads == []


async def test_an_unknown_door_needs_operate(garage: Station, fake: FakeStation) -> None:
    fake.params[0][7500] = fake.params[255][7500] = "16"  # door 1 unknown
    await garage.async_update()
    with pytest.raises(DoorStateUnknownError, match="operate=True"):
        await garage.async_open_garage_door(GARAGE_SN, 1)
    assert fake.doorbell_payloads == []
    assert await garage.async_open_garage_door(GARAGE_SN, 1, operate=True) is (GarageDoorState.OPEN)
    assert fake.doorbell_payloads[-1]["data"]["type"] == 4


async def test_operate_waits_past_an_unknown_report_for_a_known_state(
    garage: Station, fake: FakeStation
) -> None:
    fake.params[0][7500] = fake.params[255][7500] = "16"  # door 1 unknown
    await garage.async_update()
    fake.garage_moves = False
    task = asyncio.create_task(garage.async_open_garage_door(GARAGE_SN, 1, operate=True))
    async with asyncio.timeout(3):
        while not fake.doorbell_payloads:
            await asyncio.sleep(0.01)
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 1, "type": 16 | 8}})
    await asyncio.sleep(0.2)
    assert not task.done()
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 1, "type": 2 | 8}})
    assert await task is GarageDoorState.CLOSED


async def test_only_doors_with_a_motor_or_sensor_are_listed(
    garage: Station, fake: FakeStation
) -> None:
    fake.params[0][7501] = fake.params[255][7501] = "1"
    fake.params[0][7502] = fake.params[255][7502] = "1"
    await garage.async_update()
    assert [d.door for d in garage.garage_doors()] == [1]


async def test_a_door_without_a_motor_or_another_number_is_refused(
    garage: Station, fake: FakeStation
) -> None:
    fake.params[0][7501] = fake.params[255][7501] = "1"
    await garage.async_update()
    assert garage.garage_doors()[1] == _door(2, GarageDoorState.CLOSED, motor=False)
    with pytest.raises(UnsupportedError, match="no motor bound to door 2"):
        await garage.async_open_garage_door(GARAGE_SN, 2)
    with pytest.raises(ValueError, match="door 3"):
        await garage.async_open_garage_door(GARAGE_SN, 3)
    assert fake.doorbell_payloads == []


async def test_a_second_command_while_one_waits_is_busy(garage: Station, fake: FakeStation) -> None:
    fake.garage_report_delay = 0.5
    first = asyncio.create_task(garage.async_open_garage_door(GARAGE_SN, 1))
    async with asyncio.timeout(3):
        while not fake.doorbell_payloads:
            await asyncio.sleep(0.01)
    with pytest.raises(DeviceBusyError):
        await garage.async_open_garage_door(GARAGE_SN, 2)
    assert await first is GarageDoorState.OPEN
    assert len(fake.doorbell_payloads) == 1


async def test_no_report_times_out_and_restores_the_state(
    garage: Station, fake: FakeStation
) -> None:
    fake.garage_moves = False
    events = _events(garage)
    with pytest.raises(DeviceTimeoutError, match="door 1 reported no open"):
        await garage.async_open_garage_door(GARAGE_SN, 1, timeout=0.3)
    assert _doors(events) == [
        (1, GarageDoorState.OPENING, GarageDoorSource.COMMAND),
        (1, GarageDoorState.CLOSED, GarageDoorSource.P2P),
    ]
    assert garage.garage_doors()[0].state is GarageDoorState.CLOSED


async def test_a_refused_command_leaves_the_door_as_reported(
    garage: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fake, "doorbell_receipt_code", lambda: -1)
    events = _events(garage)
    with pytest.raises(CommandRejectedError):
        await garage.async_open_garage_door(GARAGE_SN, 1)
    assert _doors(events) == []


async def test_an_unsolicited_notify_moves_the_door(garage: Station, fake: FakeStation) -> None:
    events = _events(garage)
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 1, "type": 9}})
    async with asyncio.timeout(3):
        while not _doors(events):
            await asyncio.sleep(0.01)
    assert _doors(events) == [(1, GarageDoorState.OPEN, GarageDoorSource.NOTIFY)]


async def _notified(events: list[Event], count: int) -> None:
    async with asyncio.timeout(3):
        while len(_doors(events)) < count:
            await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    "case",
    [
        (CLOSED_BOTH, 9, GarageDoorState.CLOSED, GarageDoorState.OPEN),
        ("9", 10, GarageDoorState.OPEN, GarageDoorState.CLOSED),
    ],
)
async def test_a_dump_after_a_door_notify_restores_the_value_the_notify_replaced(
    garage: Station,
    fake: FakeStation,
    case: tuple[str, int, GarageDoorState, GarageDoorState],
) -> None:
    """The notify's bits become the held door-state parameter, so a later dump that still
    carries the value from before the notify (a later notify missed) is news again."""
    dumped, notified, before, after = case
    fake.params[0][7500] = fake.params[255][7500] = dumped
    await garage.async_update()
    assert garage.garage_doors()[0].state is before
    events = _events(garage)
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 1, "type": notified}})
    await _notified(events, 1)
    assert garage.garage_doors()[0].state is after
    assert garage.state is not None
    assert garage.state.setting_params[7500] == str(notified)
    garage.update_sub_devices([])  # a device-list refresh re-reads the held value
    assert garage.garage_doors()[0].state is after
    await garage.async_update()  # the station still reports ``dumped``
    assert garage.garage_doors()[0].state is before
    assert _doors(events) == [
        (1, after, GarageDoorSource.NOTIFY),
        (1, before, GarageDoorSource.P2P),
    ]


async def _sent(fake: FakeStation) -> None:
    async with asyncio.timeout(3):
        while not fake.doorbell_payloads:
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("door_id", [{"door_id": 1}, {}])
async def test_a_report_of_another_state_ends_the_wait_at_once(
    garage: Station, fake: FakeStation, door_id: dict[str, int]
) -> None:
    """The door's report ends a command's wait whatever it says, as the app ends its wait:
    the reported state is shown at once and the call raises. A report of the other door
    (``door_id`` 2) is shown and the wait goes on; one without ``door_id`` names both."""
    fake.garage_moves = False
    events = _events(garage)
    task = asyncio.create_task(garage.async_open_garage_door(GARAGE_SN, 1))
    await _sent(fake)
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 2, "type": 2 | 4}})
    await _notified(events, 2)
    assert [d.state for d in garage.garage_doors()] == [
        GarageDoorState.OPENING,
        GarageDoorState.OPEN,
    ]
    assert not task.done()
    fake.send_json(0x0547, {"cmd": 7500, "payload": {**door_id, "type": 2 | 8}})
    async with asyncio.timeout(1):
        with pytest.raises(DoorNotMovedError, match="door 1 reported closed") as err:
            await task
    assert (err.value.door, err.value.state, err.value.device_sn) == (
        1,
        GarageDoorState.CLOSED,
        GARAGE_SN,
    )
    assert _doors(events) == [
        (1, GarageDoorState.OPENING, GarageDoorSource.COMMAND),
        (2, GarageDoorState.OPEN, GarageDoorSource.NOTIFY),
        (1, GarageDoorState.CLOSED, GarageDoorSource.NOTIFY),
        (2, GarageDoorState.CLOSED, GarageDoorSource.NOTIFY),
    ]
    fake.garage_moves = True  # the camera takes the next command
    assert await garage.async_open_garage_door(GARAGE_SN, 1) is GarageDoorState.OPEN


async def test_an_unknown_report_ends_an_open_or_close(garage: Station, fake: FakeStation) -> None:
    fake.params[0][7500] = fake.params[255][7500] = "6"  # door 1 closed, door 2 open
    await garage.async_update()
    fake.garage_moves = False
    events = _events(garage)
    task = asyncio.create_task(garage.async_close_garage_door(GARAGE_SN, 2))
    await _sent(fake)
    fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 2, "type": 2 | 32}})
    async with asyncio.timeout(1):
        with pytest.raises(DoorNotMovedError, match="door 2 reported unknown"):
            await task
    assert garage.garage_doors()[1].state is GarageDoorState.UNKNOWN
    assert _doors(events) == [
        (2, GarageDoorState.CLOSING, GarageDoorSource.COMMAND),
        (2, GarageDoorState.UNKNOWN, GarageDoorSource.NOTIFY),
    ]


async def test_a_report_before_the_receipt_shows_no_movement(
    garage: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A door that reports the asked state before the command's receipt is handled reads
    that state, never opening after it."""
    fake.garage_moves = False
    events = _events(garage)
    run = garage.session.async_run_recipe

    async def run_then_report(*args: Any, **kwargs: Any) -> Any:
        result = await run(*args, **kwargs)
        fake.send_json(0x0547, {"cmd": 7500, "payload": {"door_id": 1, "type": 1 | 8}})
        await _notified(events, 1)
        return result

    monkeypatch.setattr(garage.session, "async_run_recipe", run_then_report)
    assert await garage.async_open_garage_door(GARAGE_SN, 1) is GarageDoorState.OPEN
    assert _doors(events) == [(1, GarageDoorState.OPEN, GarageDoorSource.NOTIFY)]


async def test_a_pushed_dump_block_moves_the_lock_before_the_dump_completes(
    hub: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parameter change is taken when it arrives, not when the dump it rides settles."""
    await hub.async_update()
    monkeypatch.setattr(session_module, "PARAM_SETTLE", 30.0)
    events = _events(hub)
    block = {"params": [{"dev_type": 1, "param_type": 1912, "param_value": "3"}]}
    fake.send_json(FrameType.PARAM_NOTIFY, block)
    async with asyncio.timeout(3):
        while not _locks(events):
            await asyncio.sleep(0.01)
    assert _locks(events) == [(LockState.UNLOCKED, LockStateSource.P2P, "3")]


async def test_a_pushed_dump_block_moves_the_door_before_the_dump_completes(
    garage: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "PARAM_SETTLE", 30.0)
    events = _events(garage)
    block = {"params": [{"dev_type": 255, "param_type": 7500, "param_value": "9"}]}
    fake.send_json(FrameType.PARAM_NOTIFY, block)
    await _notified(events, 1)
    assert _doors(events) == [(1, GarageDoorState.OPEN, GarageDoorSource.P2P)]


async def test_a_garage_camera_behind_a_station_takes_the_notify_on_its_channel(
    fake: FakeStation,
) -> None:
    device = CloudDevice(
        device_sn="T8453P2000000002",
        device_type=133,
        name="Garage",
        station_sn=SYNTHETIC.station_sn,
        channel=2,
    )
    fake.params[2] = {7500: CLOSED_BOTH, 7501: "3", 7502: "15"}
    station = Station(STATION, _session(fake, SYNTHETIC.station_sn), sub_devices=[device])
    try:
        await station.async_update()
        events = _events(station)
        for other in ({"mChannel": 3}, {}):  # another channel, none on a HomeBase
            fake.send_json(0x0547, {"cmd": 7500, **other, "payload": {"door_id": 1, "type": 9}})
        fake.send_json(0x0547, {"cmd": 7500, "mChannel": 2, "payload": {"door_id": 2, "type": 6}})
        await _notified(events, 1)
        station.update_sub_devices([device])
        states = [d.state for d in station.garage_doors(device.device_sn)]
    finally:
        await station.async_close()
    assert _doors(events) == [(2, GarageDoorState.OPEN, GarageDoorSource.NOTIFY)]
    assert states == [GarageDoorState.CLOSED, GarageDoorState.OPEN]


async def test_a_garage_camera_without_a_dump_reads_the_cloud_copy(fake: FakeStation) -> None:
    listed = {7500: "9", 7501: "3", 7502: "15"}
    device = CloudDevice(
        device_sn=GARAGE_SN,
        device_type=133,
        name="Garage",
        p2p_did=SYNTHETIC.did,
        station_sn=GARAGE_SN,
        raw={"params": [{"param_type": k, "param_value": v} for k, v in listed.items()]},
    )
    station = Station(device, _session(fake, GARAGE_SN))
    events = _events(station)
    station.update_sub_devices([])
    assert _doors(events) == [
        (1, GarageDoorState.OPEN, GarageDoorSource.CLOUD),
        (2, GarageDoorState.CLOSED, GarageDoorSource.CLOUD),
    ]


@pytest.mark.parametrize("product", ["T8502", "T8453"])
async def test_a_device_whose_serial_is_graded_neither_has_no_lock_or_doors(
    fake: FakeStation, product: str
) -> None:
    """The grade of the device's serial decides, even where the cloud lists another
    product code whose file has a ``lock`` or ``garage`` block."""
    device = CloudDevice(
        device_sn=SYNTHETIC.camera_sn,
        device_type=52,
        name="Odd",
        station_sn=SYNTHETIC.station_sn,
        channel=3,
        raw={"device_new_pn": product},
    )
    fake.params[3] = {1912: "4", 7500: CLOSED_BOTH, 7501: "3", 7502: "15"}
    station = Station(STATION, _session(fake, SYNTHETIC.station_sn), sub_devices=[device])
    try:
        await station.async_update()
        assert station.state is not None
        assert station.state.devices[3].params[1912] == "4"  # reported, not read
        assert station.lock_state(device.device_sn) is None
        assert station.garage_doors(device.device_sn) == ()
    finally:
        await station.async_close()


async def test_a_device_without_doors_is_refused(hub: Station) -> None:
    await hub.async_update()
    assert hub.garage_doors(LOCK_SN) == ()
    with pytest.raises(UnsupportedError, match="no garage doors"):
        await hub.async_open_garage_door(LOCK_SN, 1)
