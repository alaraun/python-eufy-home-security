"""EufyCloudApi across the cloud regions: listing, suspension, per-device routing."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.exceptions import LoginChallengeError, LoginLimitedError, ProtocolError
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FAKE_ECC_KEY, FakeMega

US_STATION_SN = "T8030P2000099999"


def _station(serial: str) -> dict[str, Any]:
    return {"device_sn": serial, "device_type": 18, "p2p_did": SYNTHETIC.did}


@pytest.fixture
async def http() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


def _api(http: aiohttp.ClientSession, cache: SessionCache, **kwargs: Any) -> EufyCloudApi:
    return EufyCloudApi(http, cache, SYNTHETIC.email, SYNTHETIC.password, **kwargs)


def _requests(fake_mega: FakeMega, endpoint: str) -> list[str]:
    return [region for name, region in fake_mega.region_calls if name == endpoint]


def test_each_region_has_its_own_security_host() -> None:
    assert const.security_host("eu") == "security-app-eu.eufylife.com"
    assert const.security_host("us") == "security-app.eufylife.com"
    with pytest.raises(ValueError, match="unknown region"):
        const.security_host("ap")


def test_an_unknown_region_override_is_refused(
    http: aiohttp.ClientSession, cache: SessionCache
) -> None:
    with pytest.raises(ValueError, match="unknown region"):
        _api(http, cache, region="ap")


async def test_the_first_list_asks_every_region_and_tags_each_device(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    fake_mega.region_devices = {"us": [_station(US_STATION_SN)]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
        devices = await api.async_get_devices()
    assert [fake_mega.logins_in(r) for r in const.REGIONS] == [1, 1]
    assert {d.device_sn: d.region for d in devices} == {
        SYNTHETIC.station_sn: "eu",
        US_STATION_SN: "us",
    }
    assert api.regions_with_devices() == ["eu", "us"]
    assert api.device_region(US_STATION_SN) == "us"
    # The login names its region as ``ab``.
    assert [p["ab"] for name, p in fake_mega.calls if name == "login"] == ["eu", "us"]


async def test_an_empty_region_is_suspended_until_a_rescan(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_get_devices()
        assert api.suspended_regions() == ["us"]
        assert api.regions_to_list() == ["eu"]
        fake_mega.region_calls.clear()

        await api.async_get_devices(refresh=True)
        await api.async_login(force=True)
        assert _requests(fake_mega, "devices") == ["eu"]
        assert _requests(fake_mega, "login") == ["eu"]  # never the suspended region

        fake_mega.region_devices = {"us": [_station(US_STATION_SN)]}
        with caplog.at_level(logging.INFO, logger="eufy_home_security.cloud.api"):
            devices = await api.async_get_devices(rescan_regions=True)
    assert {d.region for d in devices} == {"eu", "us"}
    assert api.suspended_regions() == []
    assert "the us region lists 1 device(s)" in caplog.text


async def test_scan_regions_asks_every_region_on_every_fetch(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, scan_regions=True)
        await api.async_get_devices()
        fake_mega.region_calls.clear()
        await api.async_get_devices(refresh=True)
    assert _requests(fake_mega, "devices") == ["eu", "us"]
    assert _requests(fake_mega, "login") == []  # both sessions were cached


async def test_an_account_with_no_devices_anywhere_is_not_asked_again(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with caplog.at_level(logging.WARNING, logger="eufy_home_security.cloud.api"):
            assert await api.async_get_devices() == []
        assert "lists no devices in the eu, us region(s)" in caplog.text
        assert api.regions_to_list() == []
        fake_mega.region_calls.clear()

        assert await api.async_get_devices(refresh=True) == []
        await api.async_login()
    assert fake_mega.region_calls == []  # no list, no login


async def test_devices_only_in_the_us_region_are_served_there(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.region_devices = {"us": [_station(US_STATION_SN)]}
    fake_mega.cipher_objects = [{"cipher_id": const.CIPHER_ID_P2P, "ecc_private_key": FAKE_ECC_KEY}]
    fake_mega.dsk_objects = [{"dsk_key": "k" * 32, "expiration": 9e9}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_get_devices()
        assert api.region == "us"
        fake_mega.region_calls.clear()
        assert await api.async_get_cipher_key(US_STATION_SN) == FAKE_ECC_KEY
        await api.async_get_dsk_key(US_STATION_SN)
        await api.async_register_push_token("fcm-token")
    assert {r for _, r in fake_mega.region_calls} == {"us"}
    assert {"ciphers", "dsk", "push"} <= {name for name, _ in fake_mega.region_calls}


async def test_push_is_registered_in_every_region_with_devices(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    fake_mega.region_devices = {"us": [_station(US_STATION_SN)]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_get_devices()
        await api.async_register_push_token("fcm-token")
    assert _requests(fake_mega, "push") == ["eu", "us"]


async def test_a_serial_two_regions_list_keeps_the_first_entry(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    fake_mega.region_devices = {"us": [_station(SYNTHETIC.station_sn)]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        devices = await _api(http, cache).async_get_devices()
    assert [d.region for d in devices] == ["eu"]
    assert "listed by the eu and the us region; using the eu entry" in caplog.text


async def test_a_failing_region_caches_nothing(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, scan_regions=True)
        await api.async_get_devices()
        fake_mega.devices = [_station(SYNTHETIC.station_sn), _station(US_STATION_SN)]
        fake_mega.region_devices = {"us": "not a list"}  # type: ignore[dict-item]
        with pytest.raises(ProtocolError):
            await api.async_fetch_devices()  # eu answered, us did not
    assert [d["device_sn"] for d in cache.cached_devices() or []] == [SYNTHETIC.station_sn]


async def test_a_region_override_asks_only_that_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.region_devices = {"us": [_station(US_STATION_SN)]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, region="us")
        await api.async_login()
        devices = await api.async_get_devices(rescan_regions=True)
    assert [d.region for d in devices] == ["us"]
    assert {r for _, r in fake_mega.region_calls} == {"us"}


async def test_a_challenge_is_answered_in_the_region_that_asked(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.region_login_code = {"us": int(const.CloudCode.NEED_VERIFY_CODE)}
    fake_mega.login_extra = {"login_id": "lid-us"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginChallengeError) as exc:
            await api.async_login()
        assert exc.value.region == "us"
        fake_mega.region_login_code = {}
        fake_mega.region_calls.clear()
        await api.async_login(verify_code="123456", login_id="lid-us")
    assert _requests(fake_mega, "login") == ["us"]  # eu kept the session it got first
    answer = [p for name, p in fake_mega.calls if name == "login"][-1]
    assert (answer["ab"], answer["verify_code"]) == ("us", "123456")


async def test_cloud_status_reports_each_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    fake_mega.login_data["country_code"] = "US"
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_get_devices()
    status = api.cloud_status()
    eu, us = status.regions["eu"], status.regions["us"]
    assert (eu.devices, eu.in_use, eu.suspended, eu.country_code) == (1, True, False, "US")
    assert (us.devices, us.in_use, us.suspended) == (0, False, True)
    assert eu.listed_age is not None
    assert eu.session_expires_in
    assert us.session_expires_in  # its session stays cached for a rescan


async def test_a_login_count_throttle_holds_off_only_its_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.region_login_code = {"eu": int(const.CloudCode.MAX_LOGIN_LIMIT)}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginLimitedError):
            await api.async_login()
        fake_mega.region_login_code = {}
        with pytest.raises(LoginLimitedError, match="eu logins"):
            await api.async_login()  # refused locally
        await _api(http, cache, region="us").async_login()
    assert _requests(fake_mega, "login") == ["eu", "us"]


async def test_a_credential_lock_holds_off_every_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.region_login_code = {"eu": int(const.CloudCode.PASSWORD_ERROR_MUCH)}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginLimitedError):
            await api.async_login()
        fake_mega.region_login_code = {}
        with pytest.raises(LoginLimitedError):
            await _api(http, cache, region="us").async_login()  # refused locally
    assert _requests(fake_mega, "login") == ["eu"]


async def test_the_login_budget_is_counted_per_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    for _ in range(const.LOGIN_BUDGET):
        cache.note_login(const.LOGIN_BUDGET_WINDOW_SECONDS, "eu")
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, region="us")
        await api.async_login()
    assert _requests(fake_mega, "login") == ["us"]


async def test_push_is_not_registered_once_every_region_is_suspended(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_get_devices()
        await api.async_register_push_token("fcm-token")
    assert _requests(fake_mega, "push") == []
