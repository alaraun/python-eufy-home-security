"""EufyCloudApi login country: lookup, ``ab`` and headers, home region first, re-login once."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.models import LoginCountry
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FakeMega

# A body code the cloud refuses a login with, outside every typed family.
_PLAIN_REFUSAL = 26502


@pytest.fixture
async def http() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


def _api(http: aiohttp.ClientSession, cache: SessionCache, **kwargs: Any) -> EufyCloudApi:
    kwargs.setdefault("password", SYNTHETIC.password)
    return EufyCloudApi(http, cache, SYNTHETIC.email, **kwargs)


def _login_abs(fake_mega: FakeMega) -> list[str]:
    return [p["ab"] for name, p in fake_mega.calls if name == "login"]


def _sent(fake_mega: FakeMega, name: str) -> list[dict[str, Any]]:
    return [p for n, p in fake_mega.calls if n == name]


def _requests(fake_mega: FakeMega, endpoint: str) -> list[str]:
    return [region for name, region in fake_mega.region_calls if name == endpoint]


async def _logged_in_by_region(fake_mega: FakeMega, cache: SessionCache, http: Any) -> None:
    """Sessions in both regions made with the region as ``ab`` (no country known)."""
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
    assert [cache.cloud_session(r).get("ab") for r in const.REGIONS] == ["eu", "us"]
    fake_mega.calls.clear()
    fake_mega.region_calls.clear()


def test_a_country_that_is_no_iso_code_is_refused(
    http: aiohttp.ClientSession, cache: SessionCache
) -> None:
    with pytest.raises(ValueError, match="ISO 3166"):
        _api(http, cache, country="Estonia")


async def test_the_country_option_is_the_login_ab_and_the_country_header(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country="ee", timezone="Europe/Tallinn")
        await api.async_login()
    assert _sent(fake_mega, "estimate_domain") == [{"ab": "EE", "mode": 1}]
    assert _sent(fake_mega, "client_country") == []  # an option needs no IP lookup
    assert _login_abs(fake_mega) == ["EE", "EE"]
    headers = fake_mega.headers["login"][0]
    assert (headers["country"], headers["timezone"]) == ("EE", "Europe/Tallinn")
    assert api.login_country == LoginCountry(
        code="EE", source=const.COUNTRY_SOURCE_OPTION, home_region="eu"
    )
    assert cache.section("cloud")["country"] == {
        "code": "EE",
        "source": const.COUNTRY_SOURCE_OPTION,
        "home_region": "eu",
    }
    assert [api.session_ab(r) for r in const.REGIONS] == ["EE", "EE"]


async def test_the_ip_country_is_used_and_its_home_region_logs_in_first(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "US"
    fake_mega.country_regions = {"US": "us"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
    assert _requests(fake_mega, "login") == ["us", "eu"]
    assert _login_abs(fake_mega) == ["US", "US"]
    assert api.region == "us"
    assert api.login_country == LoginCountry(
        code="US", source=const.COUNTRY_SOURCE_IP, home_region="us"
    )


async def test_a_cached_ip_country_is_not_looked_up_again(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
        fake_mega.calls.clear()
        api = _api(http, cache)
        await api.async_login()
        await api.async_login(force=True)
    assert _sent(fake_mega, "client_country") == []
    assert _sent(fake_mega, "estimate_domain") == []
    assert _login_abs(fake_mega) == ["EE"]


async def test_without_a_known_country_the_region_is_the_ab(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
    assert len(_sent(fake_mega, "client_country")) == 1
    assert _sent(fake_mega, "estimate_domain") == []
    assert _login_abs(fake_mega) == ["eu", "us"]
    headers = fake_mega.headers["login"][0]
    assert (headers["country"], headers["timezone"]) == (const.DEFAULT_COUNTRY, "UTC")
    assert api.login_country is None
    assert "country" not in cache.section("cloud")


async def test_a_country_eufy_names_no_cluster_for_keeps_the_region_as_ab(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country="AQ")
        await api.async_login()
    assert _login_abs(fake_mega) == ["eu", "us"]
    assert fake_mega.headers["login"][0]["country"] == "AQ"
    assert api.login_country is None


async def test_a_session_made_with_another_ab_logs_in_again_once(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    await _logged_in_by_region(fake_mega, cache, http)
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
        assert _login_abs(fake_mega) == ["EE", "EE"]
        assert [cache.cloud_session(r)["ab"] for r in const.REGIONS] == ["EE", "EE"]
        fake_mega.calls.clear()
        await _api(http, cache).async_login()  # a restart: settled, nothing sent
    assert _login_abs(fake_mega) == []


async def test_a_refused_re_login_keeps_the_session_and_is_not_asked_again(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    await _logged_in_by_region(fake_mega, cache, http)
    token = cache.cloud_session("eu")["auth_token"]
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.code_once["login"] = _PLAIN_REFUSAL
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()  # no error: the region-token session stays in use
        assert cache.cloud_session("eu")["auth_token"] == token
        assert (api.session_ab("eu"), cache.cloud_session("eu")["ab_wanted"]) == ("eu", "EE")
        assert _login_abs(fake_mega) == ["EE", "EE"]  # eu refused (no fallback), us re-made
        fake_mega.calls.clear()
        await _api(http, cache).async_login()
    assert _login_abs(fake_mega) == []


async def test_no_re_login_while_the_budget_is_spent_or_without_a_password(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    await _logged_in_by_region(fake_mega, cache, http)
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    spent = cache.section("throttle")["logins"]
    with aioresponses() as mock:
        fake_mega.install(mock)
        spent["eu"] = spent["us"] = [time.time() - 60] * const.LOGIN_BUDGET
        await _api(http, cache).async_login()
        assert _login_abs(fake_mega) == []
        assert fake_mega.calls == []  # nothing looked up either

        spent["eu"] = spent["us"] = []
        cache.drop_password()
        await _api(http, cache, password=None).async_login()
        assert fake_mega.calls == []
        await _api(http, cache, password=_never).async_login()  # never a prompt
        assert fake_mega.calls == []

        await _api(http, cache).async_login()  # a password at hand again
    assert _login_abs(fake_mega) == ["EE", "EE"]


async def _never() -> str:
    raise AssertionError("prompted for a password")


async def test_a_refused_country_login_falls_back_to_the_region_once(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.code_once["login"] = _PLAIN_REFUSAL
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
        assert _login_abs(fake_mega) == ["EE", "eu", "EE"]
        assert (api.session_ab("eu"), cache.cloud_session("eu")["ab_wanted"]) == ("eu", "EE")
        assert api.session_ab("us") == "EE"
        assert len(cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS, "eu")) == 2
        fake_mega.calls.clear()
        await _api(http, cache).async_login()
    assert _login_abs(fake_mega) == []


async def test_the_last_login_code_and_the_ip_country_are_read_on_a_session(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
        assert await api.async_last_login_code("eu", login=False) == "EE"
        assert await api.async_client_country("us", login=False) == "EE"
    assert _sent(fake_mega, "last_login_code") == [{"email": SYNTHETIC.email}]
