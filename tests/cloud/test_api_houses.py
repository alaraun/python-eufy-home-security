"""EufyCloudApi's device list across the account's houses: the account-wide list, the house
list and each house's own list, merged as the eufy app merges them."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FAKE_OWNER_ID, FakeMega

OWN_HOUSE = "house-own"
SHARED_HOUSE = "house-shared"
OTHER_STATION_SN = "T8030P2000099999"
OTHER_CAMERA_SN = "T8113P2000099999"


def _station(serial: str, house_id: str = "", **fields: Any) -> dict[str, Any]:
    return {"device_sn": serial, "device_type": 18, "house_id": house_id, **fields}


def _camera(serial: str, station_sn: str, house_id: str = "") -> dict[str, Any]:
    return {"device_sn": serial, "device_type": 9, "station_sn": station_sn, "house_id": house_id}


def _house(house_id: str, owner: str) -> dict[str, Any]:
    return {"house_id": house_id, "house_name": "Home", "admin_user_id": owner, "member_type": 1}


@pytest.fixture
async def http() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


def _api(http: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    return EufyCloudApi(http, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


def _list_requests(fake_mega: FakeMega) -> list[tuple[str, dict[str, Any]]]:
    """The device-list and house-list requests, with their bodies, in order."""
    return [(name, body) for name, body in fake_mega.calls if name in {"devices", "houses"}]


def _all(house_id: str) -> tuple[str, dict[str, Any]]:
    return ("devices", {"house_id": house_id, "device_sns": {}})


async def test_a_shared_home_listed_only_by_its_house_is_served(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.houses = [_house(SHARED_HOUSE, FAKE_OWNER_ID)]
    fake_mega.house_devices = {
        SHARED_HOUSE: [
            _station(OTHER_STATION_SN, SHARED_HOUSE),
            _camera(OTHER_CAMERA_SN, OTHER_STATION_SN, SHARED_HOUSE),
        ]
    }  # the account-wide list (fake_mega.devices) names none of them
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        devices = await api.async_get_devices()
    assert [(d.device_sn, d.region) for d in devices] == [
        (OTHER_STATION_SN, "eu"),
        (OTHER_CAMERA_SN, "eu"),
    ]
    assert api.suspended_regions() == []
    assert api.regions_to_list() == ["eu"]
    assert _list_requests(fake_mega) == [_all(""), ("houses", {}), _all(SHARED_HOUSE)]


async def test_every_house_is_asked_and_the_lists_merge(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    own = _station(SYNTHETIC.station_sn, OWN_HOUSE)
    fake_mega.devices = [own]
    fake_mega.houses = [
        _house(OWN_HOUSE, SYNTHETIC.account_id),
        _house(SHARED_HOUSE, FAKE_OWNER_ID),
    ]
    fake_mega.house_devices = {
        OWN_HOUSE: [own],
        SHARED_HOUSE: [_station(OTHER_STATION_SN, SHARED_HOUSE)],
    }
    with aioresponses() as mock:
        fake_mega.install(mock)
        devices = await _api(http, cache).async_get_devices()
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn, OTHER_STATION_SN]
    assert _list_requests(fake_mega) == [
        _all(""),
        ("houses", {}),
        _all(OWN_HOUSE),
        _all(SHARED_HOUSE),
    ]


async def test_a_house_answer_replaces_that_house_s_entries(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_mega.devices = [
        _station(SYNTHETIC.station_sn, device_name="account-wide"),  # no house named here
        _camera(SYNTHETIC.camera_sn, SYNTHETIC.station_sn, SHARED_HOUSE),  # not in its house
    ]
    fake_mega.houses = [_house(SHARED_HOUSE, FAKE_OWNER_ID)]
    fake_mega.house_devices = {
        SHARED_HOUSE: [_station(SYNTHETIC.station_sn, SHARED_HOUSE, device_name="house")]
    }
    with caplog.at_level(logging.WARNING), aioresponses() as mock:
        fake_mega.install(mock)
        devices = await _api(http, cache).async_get_devices()
    assert [(d.device_sn, d.raw["device_name"]) for d in devices] == [
        (SYNTHETIC.station_sn, "house")
    ]
    assert "listed by" not in caplog.text  # one region: no duplicate to warn about


async def test_an_account_whose_lists_are_all_empty_is_suspended(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_mega.houses = [_house(SHARED_HOUSE, FAKE_OWNER_ID)]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with caplog.at_level(logging.WARNING, logger="eufy_home_security.cloud.api"):
            assert await api.async_get_devices() == []
        assert api.suspended_regions() == ["eu"]
        assert "the account lists no devices in the eu region(s)" in caplog.text
        assert _list_requests(fake_mega) == [_all(""), ("houses", {}), _all(SHARED_HOUSE)]
        fake_mega.calls.clear()
        assert await api.async_get_devices(refresh=True) == []
    assert _list_requests(fake_mega) == []  # suspended: not asked again until a rescan
