"""EufySecurity's arming groups: which house, the bodies sent, the refusals before any
write, and activation (the cloud record first, then one guard-mode write per member)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast

import pytest

from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud import const
from eufy_home_security.cloud.arming import ArmingOutcome
from eufy_home_security.exceptions import (
    CloudApiError,
    CommandNotAppliedError,
    EufySecurityError,
    UnsupportedError,
)
from eufy_home_security.inclusion import Reach
from eufy_home_security.models import GuardMode
from eufy_home_security.station import Station
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    warm_store,
)
from eufy_home_security.testing.cloud import camera_device, station_device

OTHER_STATION_SN = "T8030P2000054321"
OTHER_DID = "EUPRAMA-654321-ABCDE"
THIRD_STATION_SN = "T8030P2000011111"
FOURTH_STATION_SN = "T8030P2000022222"
UNSERVED_STATION_SN = "T8030P2000033333"
HOUSE = "house-1"
COTTAGE = "house-2"
GROUP = "group-1"


def _member(serial: str, mode: int, title: str = "") -> dict[str, Any]:
    return {"device_sn": serial, "mode": title or str(mode), "mode_id": mode}


def _group(group_id: str = GROUP, name: str = "Night", *members: dict[str, Any]) -> dict[str, Any]:
    return {
        "group_id": group_id,
        "group_name": name,
        "status": "0",
        "default": 0,
        "devices": list(members) or [_member(SYNTHETIC.station_sn, 0, "Away")],
    }


def _cloud(*, cottage: list[dict[str, Any]] | None = None) -> FakeCloud:
    """Two stations (and a camera) in one house; ``cottage`` lists the second house."""
    devices = [
        station_device(),
        camera_device(),
        station_device(OTHER_STATION_SN, did=OTHER_DID, name="Garage"),
    ]
    cloud = FakeCloud(devices=devices)
    cloud.houses = [
        {"house_id": HOUSE, "house_name": "Home"},
        {"house_id": COTTAGE, "house_name": "Cottage"},
    ]
    cloud.house_devices = {HOUSE: devices, COTTAGE: cottage or []}
    cloud.arming_groups = {HOUSE: [_group()]}
    return cloud


def _client(cloud: FakeCloud) -> EufySecurity:
    return build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )


def _arming_bodies(cloud: FakeCloud, path: str) -> list[dict[str, Any]]:
    return [body for sent, body in cloud.arming_requests if sent == path]


# ── which house ──────────────────────────────────────────────────────────────


async def test_the_groups_of_the_house_holding_the_accounts_stations() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    listing = await eufy.async_arming_groups()
    assert listing.house_id == HOUSE
    assert listing.guided == 2
    assert [(g.group_id, g.name, g.members[0].mode) for g in listing.groups] == [
        (GROUP, "Night", GuardMode.AWAY)
    ]
    assert cloud.calls == ["houses", f"house:{HOUSE}", f"house:{COTTAGE}", "arming:guard_list"]
    assert cloud.arming_requests == [(const.ARMING_GROUPS_PATH, {"house_id": HOUSE})]


async def test_a_house_id_names_the_house_and_lists_only_its_devices() -> None:
    cloud = _cloud()
    cloud.arming_groups[COTTAGE] = []
    eufy = _client(cloud)
    listing = await eufy.async_arming_groups(COTTAGE)
    assert (listing.house_id, listing.groups) == (COTTAGE, ())
    assert cloud.calls == ["houses", f"house:{COTTAGE}", "arming:guard_list"]


async def test_stations_in_two_houses_need_a_house_id() -> None:
    cloud = _cloud(cottage=[station_device(OTHER_STATION_SN, did=OTHER_DID)])
    eufy = _client(cloud)
    with pytest.raises(ValueError, match="2 houses; pass house_id"):
        await eufy.async_arming_groups()
    assert cloud.arming_requests == []


@pytest.mark.parametrize("house_id", ["", "shared.devices"])
async def test_shared_devices_have_no_groups_and_nothing_is_asked(house_id: str) -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    with pytest.raises(UnsupportedError, match="not to shared devices"):
        await eufy.async_arming_groups(house_id)
    assert cloud.calls == []


async def test_an_unlisted_house_or_a_professional_arming_house_is_refused() -> None:
    cloud = _cloud()
    cloud.house_devices[COTTAGE] = [station_device("T9000P1000000001", did=OTHER_DID)]
    eufy = _client(cloud)
    with pytest.raises(UnsupportedError, match="no login scope lists the house"):
        await eufy.async_arming_groups("house-9")
    with pytest.raises(UnsupportedError, match="professional arming"):
        await eufy.async_arming_groups(COTTAGE)
    assert cloud.arming_requests == []


# ── create, update, delete, logs ─────────────────────────────────────────────


async def test_create_sends_the_apps_body_and_returns_the_listed_group() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    group = await eufy.async_create_arming_group(
        " Leaving ", {SYNTHETIC.station_sn: "away", OTHER_STATION_SN: GuardMode.CUSTOM_1}
    )
    assert _arming_bodies(cloud, const.ARMING_GROUP_ADD_PATH) == [
        {
            "house_id": HOUSE,
            "group_name": "Leaving",
            "devices": [
                {"device_sn": SYNTHETIC.station_sn, "mode": "Away", "mode_id": 0},
                {"device_sn": OTHER_STATION_SN, "mode": "Custom 1", "mode_id": 3},
            ],
            "default": 0,
        }
    ]
    assert group.name == "Leaving"
    assert group.group_id != GROUP
    assert [(m.device_sn, m.mode) for m in group.members] == [
        (SYNTHETIC.station_sn, GuardMode.AWAY),
        (OTHER_STATION_SN, GuardMode.CUSTOM_1),
    ]
    assert cloud.calls[-2:] == ["arming:add_guard", "arming:guard_list"]


@pytest.mark.parametrize(
    ("name", "members", "reason"),
    [
        ("Night!", {SYNTHETIC.station_sn: "away"}, "special characters"),
        ("x" * 32, {SYNTHETIC.station_sn: "away"}, "at most 31"),
        ("Leaving", {}, "at least one member"),
        ("Leaving", {SYNTHETIC.station_sn: GuardMode.OFF}, "cannot be a group target"),
        ("Leaving", {SYNTHETIC.station_sn: 7}, "invalid guard mode"),
    ],
)
async def test_an_invalid_name_or_mode_is_refused_before_any_request(
    name: str, members: dict[str, Any], reason: str
) -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    with pytest.raises(ValueError, match=reason):
        await eufy.async_create_arming_group(name, members)
    assert cloud.calls == []


async def test_house_rules_are_checked_before_the_write() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    with pytest.raises(ValueError, match="already has an arming group of that name"):
        await eufy.async_create_arming_group("Night", {SYNTHETIC.station_sn: "home"})
    with pytest.raises(UnsupportedError, match="not a station or standalone device"):
        await eufy.async_create_arming_group("Porch", {SYNTHETIC.camera_sn: "home"})
    cloud.arming_groups[HOUSE] = [_group(f"g{i}", f"Group {i}") for i in range(20)]
    with pytest.raises(UnsupportedError, match="at most 20"):
        await eufy.async_create_arming_group("Porch", {SYNTHETIC.station_sn: "home"})
    assert _arming_bodies(cloud, const.ARMING_GROUP_ADD_PATH) == []


async def test_update_sends_only_what_changes_and_keeps_a_stored_mode_name() -> None:
    cloud = _cloud()
    cloud.arming_groups[HOUSE] = [
        _group(GROUP, "Night", _member(SYNTHETIC.station_sn, 4, "Porch")),
        _group("group-2", "Day"),
    ]
    eufy = _client(cloud)
    renamed = await eufy.async_update_arming_group(GROUP, name="Late")
    moved = await eufy.async_update_arming_group(
        GROUP, members={SYNTHETIC.station_sn: GuardMode.CUSTOM_2, OTHER_STATION_SN: "home"}
    )
    assert _arming_bodies(cloud, const.ARMING_GROUP_UPDATE_PATH) == [
        {"house_id": HOUSE, "group_id": GROUP, "group_name": "Late"},
        {
            "house_id": HOUSE,
            "group_id": GROUP,
            "devices": [
                {"device_sn": SYNTHETIC.station_sn, "mode": "Porch", "mode_id": 4},
                {"device_sn": OTHER_STATION_SN, "mode": "Home", "mode_id": 1},
            ],
        },
    ]
    assert renamed.name == moved.name == "Late"
    assert [m.title for m in moved.members] == ["Porch", "Home"]
    with pytest.raises(ValueError, match="already has"):
        await eufy.async_update_arming_group(GROUP, name="Day")
    with pytest.raises(UnsupportedError, match="no arming group"):
        await eufy.async_update_arming_group("group-9", name="Other")
    with pytest.raises(ValueError, match="name or members"):
        await eufy.async_update_arming_group(GROUP)
    assert len(_arming_bodies(cloud, const.ARMING_GROUP_UPDATE_PATH)) == 2


async def test_delete_and_logs() -> None:
    cloud = _cloud()
    cloud.arming_logs[GROUP] = [{"group_id": GROUP, "user_name": "kim", "create_time": 9}]
    eufy = _client(cloud)
    logs = await eufy.async_arming_group_logs(GROUP)
    with pytest.raises(UnsupportedError, match="no arming group"):
        await eufy.async_delete_arming_group("group-9")
    await eufy.async_delete_arming_group(GROUP)
    assert [(log.user_name, log.create_time) for log in logs] == [("kim", 9)]
    assert _arming_bodies(cloud, const.ARMING_GROUP_LOGS_PATH) == [
        {"house_id": HOUSE, "group_id": GROUP}
    ]
    assert _arming_bodies(cloud, const.ARMING_GROUP_DELETE_PATH) == [
        {"house_id": HOUSE, "group_id": GROUP}
    ]
    assert cloud.arming_groups[HOUSE] == []


# ── activation ───────────────────────────────────────────────────────────────


@dataclass
class StubStation:
    """The part of a :class:`Station` an activation uses; writes are recorded with the
    number of arming-group requests the cloud had seen by then."""

    serial: str
    cloud: FakeCloud
    connected: bool = True
    connects_on_demand: bool = False
    mode: int | None = GuardMode.HOME
    error: EufySecurityError | None = None
    writes: list[tuple[GuardMode, int]] = field(default_factory=list)

    @property
    def state(self) -> Any:
        return None if self.mode is None else SimpleNamespace(guard_mode=self.mode)

    async def async_set_guard_mode(self, mode: GuardMode) -> GuardMode:
        self.writes.append((mode, len(self.cloud.arming_requests)))
        if self.error is not None:
            raise self.error
        self.mode = mode
        return mode


def _install(eufy: EufySecurity, *stubs: StubStation) -> None:
    for stub in stubs:
        eufy.stations[stub.serial] = cast("Station", stub)


async def test_activation_records_first_then_sets_each_member_once() -> None:
    cloud = _cloud()
    cloud.arming_groups[HOUSE] = [
        _group(
            GROUP,
            "Leaving",
            _member(SYNTHETIC.station_sn, 0),
            _member(OTHER_STATION_SN, 0),
            _member(THIRD_STATION_SN, 0),
            _member(FOURTH_STATION_SN, 0),
            _member(UNSERVED_STATION_SN, 0),
            _member("T8170P2000013579", 99),
        )
    ]
    eufy = _client(cloud)
    changed = StubStation(SYNTHETIC.station_sn, cloud)
    offline = StubStation(OTHER_STATION_SN, cloud, connected=False)
    already = StubStation(THIRD_STATION_SN, cloud, mode=GuardMode.AWAY)
    refused = CommandNotAppliedError(1224)
    failing = StubStation(FOURTH_STATION_SN, cloud, error=refused)
    _install(eufy, changed, offline, already, failing)

    activation = await eufy.async_activate_arming_group(GROUP)

    outcomes = {r.device_sn: (r.outcome, r.applied, type(r.error)) for r in activation.results}
    assert outcomes == {
        SYNTHETIC.station_sn: (ArmingOutcome.CHANGED, GuardMode.AWAY, type(None)),
        OTHER_STATION_SN: (ArmingOutcome.SKIPPED_OFFLINE, None, type(None)),
        THIRD_STATION_SN: (ArmingOutcome.ALREADY, None, type(None)),
        FOURTH_STATION_SN: (ArmingOutcome.FAILED, None, CommandNotAppliedError),
        UNSERVED_STATION_SN: (ArmingOutcome.FAILED, None, UnsupportedError),
        "T8170P2000013579": (ArmingOutcome.FAILED, None, UnsupportedError),
    }
    assert next(r for r in activation.results if r.device_sn == FOURTH_STATION_SN).error is refused
    assert not activation.complete
    assert activation.group.name == "Leaving"
    # setup_guard (the second arming request, after guard_list) went out before any write.
    assert _arming_bodies(cloud, const.ARMING_GROUP_ACTIVATE_PATH) == [
        {"house_id": HOUSE, "group_id": GROUP, "user_name": "user", "enable": True}
    ]
    assert changed.writes == [(GuardMode.AWAY, 2)]
    assert failing.writes == [(GuardMode.AWAY, 2)]
    assert offline.writes == already.writes == []


async def test_an_on_demand_station_is_woken_and_a_full_activation_is_complete() -> None:
    cloud = _cloud()
    cloud.arming_groups[HOUSE] = [_group(GROUP, "Night", _member(SYNTHETIC.station_sn, 63))]
    eufy = _client(cloud)
    battery = StubStation(SYNTHETIC.station_sn, cloud, connected=False, connects_on_demand=True)
    _install(eufy, battery)
    activation = await eufy.async_activate_arming_group(GROUP)
    assert [r.outcome for r in activation.results] == [ArmingOutcome.CHANGED]
    assert activation.complete
    assert battery.writes == [(GuardMode.DISARMED, 2)]


async def test_a_refused_activation_record_touches_no_station() -> None:
    cloud = _cloud()
    cloud.arming_errors["setup_guard"] = CloudApiError(31001, "refused")
    eufy = _client(cloud)
    stub = StubStation(SYNTHETIC.station_sn, cloud)
    _install(eufy, stub)
    with pytest.raises(CloudApiError):
        await eufy.async_activate_arming_group(GROUP)
    assert stub.writes == []
    assert cloud.arming_groups[HOUSE][0]["status"] == "0"


async def wait_for(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.02)


async def test_activation_arms_a_real_station_session() -> None:
    fake = FakeStation()
    await fake.start()
    cloud = FakeCloud.for_stations(fake)
    cloud.houses = [{"house_id": HOUSE, "house_name": "Home"}]
    cloud.house_devices = {HOUSE: list(cloud.devices)}
    cloud.arming_groups = {HOUSE: [_group(GROUP, "Staying", _member(fake.serial, 1, "Home"))]}
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email,
            store=warm_store(email=SYNTHETIC.email, cloud=cloud),
            cloud=cloud,
            stations={fake.serial: fake},
            include={fake.serial: Reach.LOCAL},
        )
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.stations[fake.serial].connected)
        await eufy.stations[fake.serial].async_update()

        first = await eufy.async_activate_arming_group(GROUP)
        again = await eufy.async_activate_arming_group(GROUP)
        await eufy.async_close()
    finally:
        fake.stop()
    assert [(r.outcome, r.applied) for r in first.results] == [
        (ArmingOutcome.CHANGED, GuardMode.HOME)
    ]
    assert fake.guard_mode == GuardMode.HOME
    assert [r.outcome for r in again.results] == [ArmingOutcome.ALREADY]
    assert cloud.arming_groups[HOUSE][0]["status"] == "1"
    assert [log["user_name"] for log in cloud.arming_logs[GROUP]] == ["user", "user"]


@dataclass
class ModesStation:
    """A local station whose mode list is known: Custom 1 is "Night watch"."""

    serial: str

    def target_mode_name(self, mode: GuardMode) -> str | None:
        if mode is GuardMode.CUSTOM_2:
            raise UnsupportedError("no Custom 2")
        return "Night watch" if mode is GuardMode.CUSTOM_1 else mode.label


async def test_member_modes_are_checked_and_named_by_their_station() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    eufy.stations[SYNTHETIC.station_sn] = cast("Station", ModesStation(SYNTHETIC.station_sn))
    with pytest.raises(UnsupportedError, match="no Custom 2"):
        await eufy.async_create_arming_group("Porch", {SYNTHETIC.station_sn: "custom_2"})
    with pytest.raises(UnsupportedError, match="no Custom 2"):
        await eufy.async_update_arming_group(GROUP, members={SYNTHETIC.station_sn: "custom_2"})
    await eufy.async_update_arming_group(
        GROUP, members={SYNTHETIC.station_sn: "custom_1", OTHER_STATION_SN: "custom_1"}
    )
    assert _arming_bodies(cloud, const.ARMING_GROUP_ADD_PATH) == []
    assert _arming_bodies(cloud, const.ARMING_GROUP_UPDATE_PATH) == [
        {
            "house_id": HOUSE,
            "group_id": GROUP,
            "devices": [
                {"device_sn": SYNTHETIC.station_sn, "mode": "Night watch", "mode_id": 3},
                {"device_sn": OTHER_STATION_SN, "mode": "Custom 1", "mode_id": 3},
            ],
        }
    ]
