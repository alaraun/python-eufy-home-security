"""EufyCloudApi login country: lookup, ``ab`` and headers, home region first, re-login once."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.models import LoginCountry
from eufy_home_security.exceptions import CommunicationError, LoginChallengeError, RateLimitedError
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FAKE_AUTH_TOKEN, FakeMega

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


async def _reloaded(store: MemoryStore) -> SessionCache:
    """The cache as a new instance (a restart) reads it from ``store``."""
    cache = SessionCache(store, SYNTHETIC.email)
    await cache.async_load()
    return cache


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
    assert _login_abs(fake_mega) == ["EE"]  # the home region only
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
    assert [api.session_ab(r) for r in const.REGIONS] == ["EE", None]
    assert api.regions_with_session() == ["eu"]


async def test_the_ip_country_is_used_and_only_its_home_region_logs_in(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "US"
    fake_mega.country_regions = {"US": "us"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
    assert _requests(fake_mega, "login") == ["us"]
    assert _login_abs(fake_mega) == ["US"]
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


@pytest.mark.parametrize(
    ("endpoint", "country", "domain_lookups"),
    [("estimate_domain", "EE", 2), ("client_country", "", 1)],
)
async def test_no_login_while_the_login_country_lookup_does_not_answer(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    *,
    endpoint: str,
    country: str,
    domain_lookups: int,
) -> None:
    """A lookup that fails on the network is asked again before the next login, and
    no login is spent meanwhile."""
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.error_bodies[endpoint] = [(503, {})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=country)
        with pytest.raises(CommunicationError):
            await api.async_login()
        assert _login_abs(fake_mega) == []
        await api.async_login()
    assert len(_sent(fake_mega, "estimate_domain")) == domain_lookups
    assert _login_abs(fake_mega) == ["EE"]
    assert api.login_country is not None
    assert api.login_country.home_region == "eu"


_ESTIMATE_DOMAIN_URL = f"https://{const.mega_host('eu')}{const.ESTIMATE_DOMAIN_PATH}"


@pytest.mark.parametrize(
    ("answer", "error"),
    [
        ({"exception": aiohttp.ClientConnectionError("down")}, CommunicationError),
        ({"status": 503, "body": ""}, CommunicationError),
        ({"status": 200, "body": "<html>blocked</html>"}, CommunicationError),
        ({"status": 200, "body": b"\xff\xfe\xfa"}, CommunicationError),
        ({"status": 429, "body": "", "headers": {"Retry-After": "120"}}, RateLimitedError),
        (
            {"status": 200, "body": json.dumps({"code": int(const.CloudCode.API_REQUEST_LIMIT)})},
            RateLimitedError,
        ),
    ],
    ids=["network", "http-503", "not-json", "not-text", "http-429", "throttle-code"],
)
async def test_a_home_region_lookup_without_an_answer_spends_no_login(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    answer: dict[str, Any],
    error: type[Exception],
) -> None:
    """A throttle starts the request hold-off, as on any other call."""
    with aioresponses() as mock:
        mock.post(_ESTIMATE_DOMAIN_URL, **answer)
        fake_mega.install(mock)
        api = _api(http, cache, country="EE")
        with pytest.raises(error):
            await api.async_login()
    assert _login_abs(fake_mega) == []
    assert (api.cloud_status().request_hold_off is not None) is (error is RateLimitedError)


async def test_a_home_region_lookup_refused_with_a_body_code_keeps_the_option_without_a_home(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.error_bodies["estimate_domain"] = [(200, {"code": _PLAIN_REFUSAL, "msg": "error"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country="EE")
        await api.async_login()
    assert api.login_country == LoginCountry(
        code="EE", source=const.COUNTRY_SOURCE_OPTION, home_region=None
    )
    assert list(zip(_requests(fake_mega, "login"), _login_abs(fake_mega), strict=True)) == [
        ("eu", "EE"),
        ("us", "EE"),
    ]


async def test_a_reauthentication_logs_in_on_the_home_region_of_a_country_not_yet_known(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "US"
    fake_mega.country_regions = {"US": "us"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_reauthenticate(SYNTHETIC.password)
    assert (_requests(fake_mega, "login"), _login_abs(fake_mega)) == (["us"], ["US"])
    assert api.login_scopes() == api.regions_with_session() == ["us"]


async def test_a_login_held_off_on_one_region_logs_in_no_region_the_country_leaves_out(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """The country is looked up before the scopes to log in to are chosen, even while
    the first region's logins are held off."""
    await _logged_in_by_region(fake_mega, cache, http)
    del cache.section("cloud")["sessions"]["us"]
    cache.hold_off("login", 3600, region="eu")
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
    assert _login_abs(fake_mega) == []
    assert api.login_scopes() == ["eu"]


async def test_a_device_list_on_a_cold_cache_logs_in_on_the_home_region_only(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country="EE")
        devices = await api.async_get_devices()
    assert (_requests(fake_mega, "login"), _login_abs(fake_mega)) == (["eu"], ["EE"])
    assert [d.region for d in devices] == ["eu"]


async def test_a_session_made_with_another_ab_logs_in_again_once(
    fake_mega: FakeMega, http: aiohttp.ClientSession
) -> None:
    store = MemoryStore()
    cache = await _reloaded(store)
    await _logged_in_by_region(fake_mega, cache, http)
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
        assert _login_abs(fake_mega) == ["EE"]  # the other region is no scope any more
        assert [cache.cloud_session(r)["ab"] for r in const.REGIONS] == ["EE", "us"]
        fake_mega.calls.clear()
        await _api(http, await _reloaded(store)).async_login()  # a restart: settled, nothing sent
    assert _login_abs(fake_mega) == []


async def test_a_refused_re_login_keeps_the_session_and_is_not_asked_again(
    fake_mega: FakeMega, http: aiohttp.ClientSession
) -> None:
    store = MemoryStore()
    cache = await _reloaded(store)
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
        assert _login_abs(fake_mega) == ["EE"]  # refused, no fallback
        fake_mega.calls.clear()
        await _api(http, await _reloaded(store)).async_login()
    assert _login_abs(fake_mega) == []


@pytest.mark.parametrize(
    "failure",
    [(503, {}), (200, {"code": int(const.CloudCode.MAX_LOGIN_LIMIT), "msg": "too many"})],
    ids=["unreachable", "throttled"],
)
async def test_a_re_login_that_does_not_get_through_keeps_the_session_and_asks_again(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    failure: tuple[int, dict[str, Any]],
) -> None:
    await _logged_in_by_region(fake_mega, cache, http)
    token = cache.cloud_session("eu")["auth_token"]
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.error_bodies["login"] = [failure]
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
    assert _login_abs(fake_mega) == ["EE"]
    assert cache.cloud_session("eu")["auth_token"] == token
    assert cache.cloud_session("eu")["ab_wanted"] == "eu"  # not settled: asked again later


async def test_a_re_login_that_meets_a_challenge_asks_for_no_code(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """The one-time country re-login runs unattended: a challenge keeps the session
    and e-mails nothing."""
    await _logged_in_by_region(fake_mega, cache, http)
    token = cache.cloud_session("eu")["auth_token"]
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.two_step = {"eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
    assert _login_abs(fake_mega) == ["EE"]
    assert fake_mega.code_requests == []
    assert cache.cloud_session("eu")["auth_token"] == token
    assert cache.cloud_session("eu")["ab_wanted"] == "EE"


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
    assert _login_abs(fake_mega) == ["EE"]


async def _never() -> str:
    raise AssertionError("prompted for a password")


async def test_a_refused_country_login_falls_back_to_the_region_once(
    fake_mega: FakeMega, http: aiohttp.ClientSession
) -> None:
    store = MemoryStore()
    cache = await _reloaded(store)
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.code_once["login"] = _PLAIN_REFUSAL
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        await api.async_login()
        assert _login_abs(fake_mega) == ["EE", "eu"]
        assert (api.session_ab("eu"), cache.cloud_session("eu")["ab_wanted"]) == ("eu", "EE")
        assert len(cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS, "eu")) == 2
        fake_mega.calls.clear()
        await _api(http, await _reloaded(store)).async_login()
    assert _login_abs(fake_mega) == []


async def test_a_refused_country_is_not_sent_again_when_the_session_lapses(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.client_country = "EE"
    fake_mega.country_regions = {"EE": "eu"}
    fake_mega.code_once["login"] = _PLAIN_REFUSAL
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
        cache.cloud_session("eu")["expires_at"] = time.time() - 10
        fake_mega.calls.clear()
        await _api(http, cache).async_login()
    assert _login_abs(fake_mega) == ["eu"]  # the settled ab, one login
    assert (cache.cloud_session("eu")["ab"], cache.cloud_session("eu")["ab_wanted"]) == ("eu", "EE")


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
        assert await api.async_client_country("eu", login=False) == "EE"
    assert _sent(fake_mega, "last_login_code") == [{"email": SYNTHETIC.email}]


# ── extra countries ───────────────────────────────────────────────────────────

_EXTRA_STATION_SN = "T8010P2000099998"


def _station(serial: str) -> dict[str, Any]:
    return {"device_sn": serial, "device_type": 0, "p2p_did": SYNTHETIC.did}


def _with_an_extra_country(fake_mega: FakeMega) -> None:
    """The account's own station under EE, a shared one listed only under CH."""
    fake_mega.country_regions = {"EE": "eu", "CH": "eu"}
    fake_mega.devices = [_station(SYNTHETIC.station_sn)]
    fake_mega.country_devices = {"CH": [_station(_EXTRA_STATION_SN)]}


@pytest.mark.parametrize(
    ("region", "country", "scope"), [("eu", None, "eu"), ("us", None, "us"), ("eu", "CH", "eu:CH")]
)
def test_a_login_scope_names_its_region_and_country(
    region: str, country: str | None, scope: str
) -> None:
    assert const.scope(region, country) == scope
    assert (const.scope_region(scope), const.scope_country(scope)) == (region, country)


def test_a_country_list_with_a_non_iso_code_is_refused(
    http: aiohttp.ClientSession, cache: SessionCache
) -> None:
    with pytest.raises(ValueError, match="ISO 3166"):
        _api(http, cache, country=["EE", "Switzerland"])


async def test_an_extra_country_logs_in_on_its_home_region_and_its_devices_join_the_list(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["ee", "CH", "ee"])
        await api.async_login()
        devices = await api.async_fetch_devices()
    assert sorted(p["ab"] for p in _sent(fake_mega, "estimate_domain")) == ["CH", "EE"]
    assert _login_abs(fake_mega) == ["EE", "CH"]
    assert _requests(fake_mega, "login") == ["eu", "eu"]
    assert fake_mega.headers["login"][1]["country"] == "CH"
    assert {d.device_sn: d.region for d in devices} == {
        SYNTHETIC.station_sn: "eu",
        _EXTRA_STATION_SN: "eu:CH",
    }
    assert api.device_region(_EXTRA_STATION_SN) == "eu:CH"
    assert api.session_ab("eu:CH") == "CH"
    assert api.suspended_regions() == []
    assert api.regions_to_list() == ["eu", "eu:CH"]
    assert api.regions_with_session() == ["eu", "eu:CH"]
    assert cache.section("cloud")["extra_countries"] == {"CH": "eu"}
    # The login budget counts per cluster: both eu logins.
    assert len(cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS, "eu")) == 2


async def test_a_restart_reuses_the_extra_country_session_without_a_lookup(
    fake_mega: FakeMega, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    store = MemoryStore()
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, await _reloaded(store), country=["EE", "CH"]).async_login()
        fake_mega.calls.clear()
        api = _api(http, await _reloaded(store), country=["EE", "CH"])
        await api.async_login()
        devices = await api.async_fetch_devices()
    assert _sent(fake_mega, "estimate_domain") == []
    assert _login_abs(fake_mega) == []
    assert _EXTRA_STATION_SN in {d.device_sn for d in devices}


async def test_calls_about_an_extra_country_go_to_its_session_on_its_cluster(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    fake_mega.security_stations = [{"station_sn": _EXTRA_STATION_SN, "device_type": 0}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["EE", "CH"])
        await api.async_login()
        stations = await api.async_list_security_devices("eu:CH", stations=True, login=False)
    assert [(s.device_sn, s.region) for s in stations] == [(_EXTRA_STATION_SN, "eu:CH")]
    headers = fake_mega.headers["security_stations"][0]
    assert (headers["country"], headers["x-auth-token"]) == ("CH", f"{FAKE_AUTH_TOKEN}-CH")
    assert _requests(fake_mega, "security_stations") == ["eu"]


async def test_cipher_dsk_and_firmware_of_an_extra_country_station_use_its_session(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    fake_mega.cipher_objects = [{"cipher_id": const.CIPHER_ID_P2P, "ecc_private_key": "ab" * 32}]
    fake_mega.dsk_objects = [{"dsk_key": "dsk-0123", "expiration": time.time() + 3600}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["EE", "CH"])
        await api.async_login()
        await api.async_fetch_devices()
        fake_mega.region_calls.clear()
        await api.async_get_cipher_key(_EXTRA_STATION_SN)
        await api.async_get_dsk_key(_EXTRA_STATION_SN)
        await api.async_check_firmware(
            _EXTRA_STATION_SN, ota_type="T8010", current_version_name="1.0.0"
        )
    for endpoint in ("ciphers", "dsk", "ota"):
        (headers,) = fake_mega.headers[endpoint]
        assert (headers["country"], headers["x-auth-token"]) == ("CH", f"{FAKE_AUTH_TOKEN}-CH")
        assert _requests(fake_mega, endpoint) == ["eu"]


async def test_an_extra_country_eufy_names_no_cluster_for_gets_no_session(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.country_regions = {"EE": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["EE", "AQ"])
        await api.async_login()
    assert _login_abs(fake_mega) == ["EE"]
    assert api.regions_with_session() == ["eu"]
    assert "extra_countries" not in cache.section("cloud")


async def test_an_extra_country_lookup_that_failed_is_asked_again_by_the_next_fetch(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country="EE").async_login()
        fake_mega.calls.clear()
        fake_mega.error_bodies["estimate_domain"] = [(503, {})]
        api = _api(http, cache, country=["EE", "CH"])
        await api.async_login()
        assert api.login_scopes() == ["eu"]
        devices = await api.async_fetch_devices()
    assert [p["ab"] for p in _sent(fake_mega, "estimate_domain")] == ["CH", "CH"]
    assert _login_abs(fake_mega) == ["CH"]
    assert api.login_scopes() == ["eu", "eu:CH"]
    assert _EXTRA_STATION_SN in {d.device_sn for d in devices}


@pytest.mark.parametrize("asked_again_by", ["rescan", "country list change"])
async def test_a_refused_extra_country_is_skipped_until_asked_again(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
    asked_again_by: str,
) -> None:
    """A plain refusal of an extra country's login is not retried with the region and
    blocks neither the other scopes nor the device list."""
    _with_an_extra_country(fake_mega)
    countries = ["EE", "CH"]
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country="EE").async_get_devices()
        fake_mega.calls.clear()
        fake_mega.code_once["login"] = _PLAIN_REFUSAL
        with caplog.at_level(logging.WARNING, logger="eufy_home_security.cloud.api"):
            await _api(http, cache, country=countries).async_login()
            api = _api(http, cache, country=countries)
            await api.async_login()
            devices = await api.async_get_devices(refresh=True)
        assert _login_abs(fake_mega) == ["CH"]  # once, no fallback, not asked again
        assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
        status = api.cloud_status().regions["eu:CH"]
        assert (status.login_refused, status.in_use) == (True, False)
        assert sum("eu:CH" in r.getMessage() for r in caplog.records) == 1
        if asked_again_by == "rescan":
            devices = await api.async_fetch_devices(rescan_regions=True)
        else:
            countries = ["EE", "CH", "AQ"]
            api = _api(http, cache, country=countries)
            devices = await api.async_get_devices(refresh=True)
    assert _login_abs(fake_mega) == ["CH", "CH"]
    assert _EXTRA_STATION_SN in {d.device_sn for d in devices}
    assert not api.cloud_status().regions["eu:CH"].login_refused


async def test_a_refused_extra_scope_keeps_the_devices_it_listed_last(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    _with_an_extra_country(fake_mega)
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["EE", "CH"])
        await api.async_get_devices()
        cache.cloud_session("eu:CH")["expires_at"] = time.time() - 10
        fake_mega.code_once["login"] = _PLAIN_REFUSAL
        api = _api(http, cache, country=["EE", "CH"])
        devices = await api.async_get_devices(refresh=True)
    assert {d.device_sn: d.region for d in devices} == {
        SYNTHETIC.station_sn: "eu",
        _EXTRA_STATION_SN: "eu:CH",
    }
    assert api.refused_regions() == ["eu:CH"]


async def test_a_challenge_from_an_extra_scope_is_answered_there_after_a_restart(
    fake_mega: FakeMega, http: aiohttp.ClientSession
) -> None:
    """Each scope of a two-step account asks in turn; an answer given on a new
    instance goes to the scope that asked, which ends the flow."""
    _with_an_extra_country(fake_mega)
    fake_mega.two_step = {"eu"}
    store = MemoryStore()
    countries = ["EE", "CH"]
    with aioresponses() as mock:
        fake_mega.install(mock)
        with pytest.raises(LoginChallengeError) as first:
            await _api(http, await _reloaded(store), country=countries).async_login()
        with pytest.raises(LoginChallengeError) as second:
            await _api(http, await _reloaded(store), country=countries).async_login(
                verify_code="123456", login_id=first.value.login_id
            )
        cache = await _reloaded(store)
        cache.section("throttle")["logins"] = {}  # the budget is not under test here
        await cache.async_save()
        fake_mega.calls.clear()
        fake_mega.region_calls.clear()
        api = _api(http, await _reloaded(store), country=countries)
        await api.async_login(verify_code="654321", login_id=second.value.login_id)
    assert (first.value.region, second.value.region) == ("eu", "eu:CH")
    answers = [(p["ab"], p["verify_code"]) for p in _sent(fake_mega, "login")]
    assert answers == [("CH", "654321")]
    assert api.regions_with_session() == ["eu", "eu:CH"]
    assert not (await _reloaded(store)).section("cloud").get("challenges")


async def test_an_extra_country_logs_in_under_its_own_install_id(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """eufy keeps one session per install id and cluster: a second country's login
    under the install's own id would end the first's session."""
    _with_an_extra_country(fake_mega)
    fake_mega.one_session_per_install = True
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=["EE", "CH"])
        await api.async_login()
        devices = await api.async_fetch_devices()
    install_ids = [h["openudid"] for h in fake_mega.headers["login"]]
    assert _login_abs(fake_mega) == ["EE", "CH"]  # nothing ended, nothing re-made
    assert install_ids[0] == cache.openudid != install_ids[1]
    assert cache.section("cloud")["install_ids"] == {"eu:CH": install_ids[1]}
    assert {d.device_sn for d in devices} == {SYNTHETIC.station_sn, _EXTRA_STATION_SN}


@pytest.mark.parametrize(
    ("before", "after"), [(["EE"], ["EE", "CH"]), (["EE", "CH"], ["EE"])], ids=["added", "removed"]
)
async def test_a_cached_list_that_misses_or_outlives_a_scope_is_fetched_again(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    before: list[str],
    after: list[str],
) -> None:
    """A cached list is served only when it covers every scope to list and no other."""
    _with_an_extra_country(fake_mega)
    listed = {SYNTHETIC.station_sn} | ({_EXTRA_STATION_SN} if "CH" in after else set())
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country=before)
        await api.async_login()
        await api.async_get_devices()
        fake_mega.region_calls.clear()
        api = _api(http, cache, country=after)
        await api.async_login()
        devices = await api.async_get_devices()
        assert {d.device_sn for d in devices} == listed
        assert len(_requests(fake_mega, "devices")) == len(after)
        fake_mega.region_calls.clear()
        assert {d.device_sn for d in await api.async_get_devices()} == listed
    assert _requests(fake_mega, "devices") == []  # the refetched list is a hit
