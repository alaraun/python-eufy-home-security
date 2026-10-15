"""``testing.station_config``: a station's mode list and schedule seeded through the fakes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import time

import pytest

from eufy_home_security.models import GuardMode, ValueSource
from eufy_home_security.p2p.station_config_codecs import (
    Schedule,
    ScheduleSlot,
    Weekday,
    decode_custom_modes,
    decode_schedule,
)
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    mode_list_params,
    schedule_params,
    station_device,
    warm_store,
)

AWAY_AT_WORK = ScheduleSlot(Weekday.MONDAY, time(8), time(17, 30), GuardMode.AWAY)
NIGHT = ScheduleSlot(Weekday.FRIDAY, time(22), time(0), GuardMode.CUSTOM_1)


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    await station.start()
    yield station
    station.stop()


def test_a_mode_list_lists_home_and_away_then_the_named_custom_modes() -> None:
    params = mode_list_params({GuardMode.CUSTOM_2: "Yard", 3: "Garden"}, icons={3: 2})
    modes = decode_custom_modes(params[1256])
    assert modes is not None
    assert modes.account_id == SYNTHETIC.account_id
    assert [(m.mode, m.title, m.icon_type) for m in modes.modes] == [
        (GuardMode.HOME, "Home", 1),
        (GuardMode.AWAY, "Away", 0),
        (GuardMode.CUSTOM_1, "Garden", 2),
        (GuardMode.CUSTOM_2, "Yard", 7),
    ]


def test_a_mode_list_names_custom_modes_only() -> None:
    with pytest.raises(ValueError, match="only custom modes"):
        mode_list_params({GuardMode.HOME: "Inside"})


def test_a_schedule_is_its_slots_and_the_default() -> None:
    params = schedule_params([AWAY_AT_WORK, NIGHT], default=GuardMode.DISARMED)
    schedule = decode_schedule(params[1254])
    assert schedule is not None
    assert (schedule.account_id, schedule.slots) == (SYNTHETIC.account_id, (AWAY_AT_WORK, NIGHT))
    assert params[1257] == "63"
    for owner, stored in ((None, SYNTHETIC.account_id), ("other", "other")):
        built = schedule_params(Schedule(account_id=owner, slots=(NIGHT,)))
        assert 1257 not in built
        decoded = decode_schedule(built[1254])
        assert decoded is not None
        assert decoded.account_id == stored
    with pytest.raises(ValueError, match="overlap"):
        schedule_params([AWAY_AT_WORK, AWAY_AT_WORK])


async def test_the_fake_station_reports_the_seeded_mode_list_and_schedule(
    fake: FakeStation,
) -> None:
    fake.set_mode_list({GuardMode.CUSTOM_1: "Night watch"})
    fake.set_schedule([AWAY_AT_WORK, NIGHT], default=GuardMode.HOME)
    cloud = FakeCloud.for_stations(fake)
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=warm_store(email=SYNTHETIC.email, cloud=cloud),
        cloud=cloud,
        stations={fake.serial: fake},
    )
    try:
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        config = await eufy.stations[fake.serial].async_get_config(refresh=True)
    finally:
        await eufy.async_close()
    assert config.mode_name(GuardMode.CUSTOM_1) == "Night watch"
    assert config.schedule is not None
    assert config.schedule.slots == (AWAY_AT_WORK, NIGHT)
    assert config.schedule_default is GuardMode.HOME
    assert config.sources["schedule"] is ValueSource.P2P


async def test_the_fake_cloud_carries_the_seeded_mode_list_as_the_stations_copy(
    fake: FakeStation,
) -> None:
    cloud = FakeCloud.for_stations(fake)
    cloud.set_station_params(fake.serial, mode_list_params({3: "Night watch"}))
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=warm_store(email=SYNTHETIC.email, cloud=cloud),
        cloud=cloud,
        stations={fake.serial: fake},
    )
    try:
        await eufy.async_discover(refresh=True)
        assert await eufy.async_start(push=False) == {}
        config = await eufy.stations[fake.serial].async_get_config()
    finally:
        await eufy.async_close()
    assert config.mode_name(GuardMode.CUSTOM_1) == "Night watch"
    assert config.sources["modes"] is ValueSource.CLOUD


def test_cloud_params_go_into_the_stations_entry() -> None:
    entry = station_device(params=schedule_params([NIGHT]))
    assert {p["param_type"] for p in entry["params"]} == {1140, 1254}
    cloud = FakeCloud(devices=[entry])
    cloud.set_station_params(SYNTHETIC.station_sn, {1140: "1"})
    assert {p["param_type"]: p["param_value"] for p in entry["params"]}[1140] == "1"
    with pytest.raises(KeyError, match="no station"):
        cloud.set_station_params(SYNTHETIC.camera_sn, {1254: ""})
