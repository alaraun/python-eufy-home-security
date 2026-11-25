"""Lock state and garage doors on a station (``Station.lock_state``,
``Station.garage_doors``, ``Station.async_open_garage_door`` / ``async_close_garage_door``)
against the fake station, with model files that carry ``lock`` and ``garage`` blocks."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator

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
    DoorStateUnknownError,
    UnsupportedError,
)
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.p2p.session.param_state import ParamOrigin
from eufy_home_security.station import Station
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
    fake.params[1][1912] = "8"  # another unlocked code: no event
    await hub.async_update()
    assert _locks(events) == [
        (LockState.LOCKED, LockStateSource.P2P, "4"),
        (LockState.UNLOCKED, LockStateSource.P2P, "3"),
    ]
    first = next(e for e in events if isinstance(e, LockStateChanged))
    assert (first.device_sn, first.station_sn) == (LOCK_SN, SYNTHETIC.station_sn)
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNLOCKED, source=LockStateSource.P2P, raw="8"
    )
    assert hub.lock_state(SYNTHETIC.station_sn) is None  # no lock
    with pytest.raises(UnsupportedError, match="not paired"):
        hub.lock_state("T8502P2000099999")


def _push(event_type: int, at: int, device_sn: str = LOCK_SN) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.CLOUD, device_sn=device_sn, event_type=event_type, event_time_ms=at
    )


async def test_a_lock_push_sets_the_state_until_the_parameter_moves(
    hub: Station, fake: FakeStation
) -> None:
    events = _events(hub)
    await hub.async_update()
    assert hub.note_lock_push(_push(259, 2_000)) is True  # unlocked by code
    assert hub.note_lock_push(_push(262, 1_000)) is False  # older than the last: ignored
    assert hub.note_lock_push(_push(513, 3_000)) is False  # low battery: no state
    assert hub.note_lock_push(_push(262, 3_000, "T8502P2000099999")) is False
    await hub.async_update()  # 1912 still "4": the push stands
    assert hub.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNLOCKED, source=LockStateSource.PUSH, event_type=259
    )
    fake.params[1][1912] = "2"
    await hub.async_update()
    assert hub.note_lock_push(_push(516, 4_000)) is True  # offline
    assert _locks(events) == [
        (LockState.LOCKED, LockStateSource.P2P, "4"),
        (LockState.UNLOCKED, LockStateSource.PUSH, None),
        (LockState.JAMMED, LockStateSource.P2P, "2"),
        (LockState.UNKNOWN, LockStateSource.PUSH, None),
    ]
    pushed = [e for e in events if isinstance(e, LockStateChanged) and e.event_type]
    assert [e.event_type for e in pushed] == [259, 516]


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
    finally:
        await station.async_close()
    assert reading is not None
    assert (reading.state, reading.raw) == (LockState.LOCKED, "4")


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


async def test_a_device_without_doors_is_refused(hub: Station) -> None:
    await hub.async_update()
    assert hub.garage_doors(LOCK_SN) == ()
    with pytest.raises(UnsupportedError, match="no garage doors"):
        await hub.async_open_garage_door(LOCK_SN, 1)
