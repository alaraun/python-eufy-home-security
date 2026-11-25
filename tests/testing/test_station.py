"""The fake garage-door camera of ``FakeStation``: door commands and the storage query."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.garage import GarageDoorState
from eufy_home_security.exceptions import DeviceTimeoutError
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

GARAGE_SN = "T8453P2000000001"
CLOSED_BOTH = "10"  # door 1 closed (2), door 2 closed (8)


def _fake(serial: str) -> FakeStation:
    fake = FakeStation(serial=serial)
    fake.static_key = static_key(serial, fake.did)
    return fake


def _session(fake: FakeStation) -> StationSession:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "Nick", fake.ecc_private_key_hex)

    return StationSession(fake.serial, credentials, host="127.0.0.1", port=fake.discovery_port)


@pytest.fixture
async def garage_fake() -> AsyncIterator[FakeStation]:
    """A standalone T8453 with both doors bound and closed."""
    fake = _fake(GARAGE_SN)
    for block in (fake.params[0], fake.params[255]):
        block |= {7500: CLOSED_BOTH, 7501: "3", 7502: "15"}
    await fake.start()
    yield fake
    fake.stop()


@pytest.mark.usefixtures("door_models")
async def test_a_door_command_while_the_doors_hold_still_is_dropped(
    garage_fake: FakeStation,
) -> None:
    """With ``garage_moves`` off a door command gets its receipt only: nothing is applied,
    then or at a later command."""
    device = CloudDevice(
        device_sn=GARAGE_SN,
        device_type=133,
        name="Garage",
        p2p_did=SYNTHETIC.did,
        station_sn=GARAGE_SN,
    )
    station = Station(device, _session(garage_fake))
    try:
        await station.async_update()
        with pytest.raises(DeviceTimeoutError):
            await station.async_open_garage_door(GARAGE_SN, 1, timeout=0.2)
        assert [p["data"]["type"] for p in garage_fake.doorbell_payloads] == [1]
        assert garage_fake.params[0][7500] == CLOSED_BOTH
        garage_fake.garage_moves = True
        assert await station.async_open_garage_door(GARAGE_SN, 2) is GarageDoorState.OPEN
        states = [d.state for d in station.garage_doors()]
    finally:
        await station.async_close()
    assert states == [GarageDoorState.CLOSED, GarageDoorState.OPEN]
    assert garage_fake.params[0][7500] == "6"  # door 1 closed (2), door 2 open (4)


@pytest.mark.parametrize(
    ("serial", "answered"),
    [(GARAGE_SN, True), (SYNTHETIC.station_sn, False)],
    ids=["garage-door camera", "homebase"],
)
async def test_a_garage_door_camera_answers_the_storage_query_by_default(
    serial: str, answered: bool
) -> None:
    """``sd_info`` left at None: a garage-door camera answers ``SDINFO_EX`` with a
    synthetic half-full medium, every other model ignores it."""
    fake = _fake(serial)
    await fake.start()
    session = _session(fake)
    try:
        await session.async_connect()
        if answered:
            info = await session.async_get_sd_info(timeout=3)
            assert info.emmc is not None
            assert info.emmc.used_percent == 50.0
        else:
            with pytest.raises(DeviceTimeoutError):
                await session.async_get_sd_info(timeout=0.3)
    finally:
        await session.async_close()
        fake.stop()
    assert fake.sd_info_queries >= 1
