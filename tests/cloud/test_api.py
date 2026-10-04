"""EufyCloudApi: login, devices, owner id, cipher, push token."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security._logging import set_secret_logging
from eufy_home_security.cloud import const, crypto
from eufy_home_security.cloud.api import EufyCloudApi, _check_owner_id, _Identity
from eufy_home_security.cloud.status import LoginNeed
from eufy_home_security.exceptions import (
    AuthenticationError,
    CloudApiError,
    CommunicationError,
    EmptyResponseError,
    EufySecurityError,
    KeyExchangeRefusedError,
    LoginChallengeError,
    LoginLimitedError,
    ProtocolError,
    RateLimitedError,
    RefreshCooldownError,
    SessionReplacedError,
)
from eufy_home_security.install import InstallState
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FAKE_AUTH_TOKEN, FAKE_ECC_KEY, FAKE_OWNER_ID, FakeMega


def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password)


def _devices_url(fake_mega: FakeMega) -> str:
    return f"https://{const.cluster_host('house', fake_mega.region)}{const.DEVICES_PATH}"


async def test_login_happy_path_caches_session(fake_mega: FakeMega, cache: SessionCache) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert api.user_id == SYNTHETIC.account_id
            assert api.user_name == "user"
            # A second login reuses the cached session — no new login round trip.
            await api.async_login()
    assert fake_mega.login_calls == 1
    assert cache.section("cloud")["auth_token"]
    assert cache.section("cloud")["mega_domain"] == "mega-eu-pr.eufy.com"


async def test_password_callable_is_awaited_only_for_a_real_login(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    asked = 0

    async def ask() -> str:
        nonlocal asked
        asked += 1
        return SYNTHETIC.password

    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, ask)
            await api.async_login()
            await api.async_login()  # cached: the password is not needed again
    assert fake_mega.login_calls == 1
    assert asked == 1


async def test_a_cache_layout_change_logs_in_again_with_the_cached_password(
    fake_mega: FakeMega,
) -> None:
    store = MemoryStore()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            cache = SessionCache(store, SYNTHETIC.email)
            await _api(session, cache).async_login()
            assert cache.password == SYNTHETIC.password
            doc = await store.async_load()
            assert doc is not None
            await store.async_save({**doc, "version": 0})  # a library update changed the layout

            upgraded = SessionCache(store, SYNTHETIC.email)
            await upgraded.async_load()
            assert upgraded.section("cloud") == {}
            await EufyCloudApi(session, upgraded, SYNTHETIC.email, None).async_get_devices()
    assert fake_mega.login_calls == 2  # one login cycle, nobody asked


async def test_without_a_password_or_a_cached_one_nothing_is_sent(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(AuthenticationError, match="no password"):
                await EufyCloudApi(session, cache, SYNTHETIC.email, None).async_login()
        assert not mock.requests


async def test_a_given_password_wins_over_the_cached_one_and_replaces_it(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    cache.set_password("old-password")
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await EufyCloudApi(session, cache, SYNTHETIC.email, "new-password").async_login()
    assert cache.password == "new-password"


async def test_a_cached_password_spares_the_prompt(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    cache.set_password(SYNTHETIC.password)

    async def ask() -> str:
        raise AssertionError("prompted although a password is cached")

    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await EufyCloudApi(session, cache, SYNTHETIC.email, ask).async_login()
    assert fake_mega.login_calls == 1


@pytest.mark.parametrize(
    ("given", "kept"),
    [(None, None), ("typo", SYNTHETIC.password)],  # only a rejected *cached* password is dropped
)
async def test_a_rejected_cached_password_is_forgotten(
    fake_mega: FakeMega, cache: SessionCache, given: str | None, kept: str | None
) -> None:
    cache.set_password(SYNTHETIC.password)
    fake_mega.login_code = int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(AuthenticationError):
                await EufyCloudApi(session, cache, SYNTHETIC.email, given).async_login()
    assert cache.password == kept


async def test_a_login_challenge_keeps_the_cached_password(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    cache.set_password(SYNTHETIC.password)
    fake_mega.login_code = int(const.CloudCode.NEED_VERIFY_CODE)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(LoginChallengeError):
                await EufyCloudApi(session, cache, SYNTHETIC.email, None).async_login()
    assert cache.password == SYNTHETIC.password


async def test_cached_session_survives_a_fresh_instance(fake_mega: FakeMega) -> None:
    store = MemoryStore()
    cache = SessionCache(store, SYNTHETIC.email)
    await cache.async_load()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await _api(session, cache).async_login()
            await cache.async_save()

            cache2 = SessionCache(store, SYNTHETIC.email)
            await cache2.async_load()
            await _api(session, cache2).async_login()
    assert fake_mega.login_calls == 1  # the second instance read the cache


async def test_verify_code_challenge(fake_mega: FakeMega, cache: SessionCache) -> None:
    fake_mega.login_code = int(const.CloudCode.NEED_VERIFY_CODE)
    fake_mega.login_extra = {"login_id": "lid-42"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(LoginChallengeError) as exc:
                await _api(session, cache).async_login()
    assert exc.value.kind == "verify_code"
    assert exc.value.login_id == "lid-42"


async def test_captcha_challenge_fetches_an_image(fake_mega: FakeMega, cache: SessionCache) -> None:
    fake_mega.login_code = int(const.CloudCode.LOGIN_NEED_CAPTCHA)
    fake_mega.login_extra = {"login_id": "lid-7"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(LoginChallengeError) as exc:
                await _api(session, cache).async_login()
    assert exc.value.kind == "captcha"
    assert exc.value.captcha_id == "cap-123"
    assert exc.value.captcha_image.startswith("data:image/png;base64,")
    assert exc.value.login_id == "lid-7"


async def test_answering_a_challenge_sends_the_answer(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await _api(session, cache).async_login(
                captcha_id="cap-123", captcha_answer="WXYZ", login_id="lid-7"
            )
    login = next(payload for name, payload in fake_mega.calls if name == "login")
    assert login["captcha_id"] == "cap-123"
    assert login["answer"] == "WXYZ"
    assert login["login_id"] == "lid-7"  # carried from the challenge into the answer


async def test_bad_credentials_raise_authentication_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.login_code = int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(AuthenticationError):
                await _api(session, cache).async_login()


@pytest.mark.parametrize(
    ("code", "hours"),
    [
        (const.CloudCode.MAX_LOGIN_LIMIT, 2),
        (const.CloudCode.PASSWORD_ERROR_MUCH, 24),
        (const.CloudCode.PASSWORD_ERROR_5, 24),
        (const.CloudCode.VERIFY_CODE_MAX, 24),
    ],
)
async def test_login_throttle_holds_off_logins_across_instances(
    fake_mega: FakeMega, code: int, hours: int
) -> None:
    store = MemoryStore()
    fake_mega.login_code = int(code)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            cache = SessionCache(store, SYNTHETIC.email)
            with pytest.raises(LoginLimitedError) as caught:
                await _api(session, cache).async_login()
            assert caught.value.code == code
            assert caught.value.retry_after == pytest.approx(hours * 3600, abs=5)

            fake_mega.login_code = 0  # the block is lifted server-side: still not asked
            restarted = SessionCache(store, SYNTHETIC.email)
            await restarted.async_load()
            with pytest.raises(LoginLimitedError):
                await _api(session, restarted).async_login()
    assert fake_mega.login_calls == 1


@pytest.mark.parametrize(
    "code", [const.CloudCode.API_REQUEST_LIMIT, const.CloudCode.REQUEST_TOO_FAST]
)
async def test_request_throttle_holds_off_every_cloud_call(
    fake_mega: FakeMega, cache: SessionCache, code: int
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            fake_mega.code_once["devices"] = int(code)
            with pytest.raises(RateLimitedError) as caught:
                await api.async_get_devices(refresh=True)
            assert not isinstance(caught.value, LoginLimitedError)
            assert caught.value.retry_after == pytest.approx(3600, abs=5)
            sent = len(mock.requests)
            with pytest.raises(RateLimitedError):
                await api.async_register_push_token("token")
            with pytest.raises(RateLimitedError):
                await api.async_login(force=True)
            assert len(mock.requests) == sent  # refused locally: nothing reached the cloud


async def test_login_hold_off_leaves_a_valid_session_working(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            cache.hold_off("login", 3600)
            assert await api.async_get_devices(refresh=True) == []


async def test_an_expired_hold_off_lets_calls_through(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            cache.hold_off("requests", 3600)
            with pytest.raises(RateLimitedError):
                await api.async_get_devices(refresh=True)
            cache.section("throttle")["requests"] = time.time() - 1
            assert await api.async_get_devices(refresh=True) == []


@pytest.mark.parametrize(
    ("headers", "expected"),
    [({}, 3600), ({"Retry-After": "7200"}, 7200), ({"Retry-After": "60"}, 3600)],
)
async def test_http_429_is_a_request_throttle(
    fake_mega: FakeMega, cache: SessionCache, headers: dict[str, str], expected: int
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            fake_mega.status_once["devices"] = (429, headers)
            with pytest.raises(RateLimitedError) as caught:
                await api.async_get_devices(refresh=True)
    assert caught.value.code == 429
    assert caught.value.retry_after == pytest.approx(expected, abs=5)


async def test_logins_are_capped_per_window(fake_mega: FakeMega, cache: SessionCache) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            for _ in range(const.LOGIN_BUDGET):
                await api.async_login(force=True)
            with pytest.raises(LoginLimitedError) as caught:
                await api.async_login(force=True)
    assert fake_mega.login_calls == const.LOGIN_BUDGET
    assert caught.value.code == 0
    assert caught.value.retry_after == pytest.approx(const.LOGIN_BUDGET_WINDOW_SECONDS, abs=5)


async def test_http_200_with_error_code_on_devices(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.code_once["devices"] = int(const.CloudCode.INPUT_PARAM_INVALID)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(CloudApiError) as exc:
                await api.async_get_devices()
    assert exc.value.code == int(const.CloudCode.INPUT_PARAM_INVALID)


def _device_fetches(fake_mega: FakeMega) -> int:
    return sum(1 for kind, _ in fake_mega.calls if kind == "devices")


async def test_device_list_is_cached_and_refresh_forces_a_fetch(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_name": "Home Base",
            "member": {"admin_user_id": SYNTHETIC.account_id},
            "params": [{"param_type": 1101, "param_value": "87"}] * 50,  # the heavy snapshot
        }
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            first = await api.async_get_devices()
            assert first[0].raw["params"]  # the live fetch keeps everything
            assert _device_fetches(fake_mega) == 1
            # A warm read comes from the cache — no second network call.
            again = await api.async_get_devices()
            assert _device_fetches(fake_mega) == 1
            assert [d.device_sn for d in again] == [d.device_sn for d in first]
            # refresh forces a fetch and rewrites the cache.
            await api.async_get_devices(refresh=True)
            assert _device_fetches(fake_mega) == 2
    stored = cache.cached_devices()
    assert stored
    assert "params" not in stored[0]  # the snapshot is not persisted
    assert stored[0]["member"]  # but device metadata is kept, incl. the owner relation
    assert again[0].has_member_relation  # a cache-loaded device still resolves its owner


async def test_refresh_falls_back_to_the_cache_when_the_cloud_is_unreachable(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_name": "Home Base"}]
            await api.async_login()
            fresh = await api.async_get_devices()

    with aioresponses() as mock:
        mock.post(
            _devices_url(fake_mega),
            exception=aiohttp.ClientConnectionError("no route"),
            repeat=True,
        )
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            cached = await api.async_get_devices(refresh=True)
    assert [d.device_sn for d in cached] == [d.device_sn for d in fresh]


async def test_refresh_during_a_hold_off_uses_the_cached_list(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_devices(refresh=True)
            cache.hold_off("requests", 3600)
            devices = await api.async_get_devices(refresh=True)
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]


async def test_refresh_without_a_cache_propagates_the_outage(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        mock.post(
            _devices_url(fake_mega),
            exception=aiohttp.ClientConnectionError("no route"),
            repeat=True,
        )
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            with pytest.raises(CommunicationError):
                await api.async_get_devices(refresh=True)


async def test_an_expired_token_triggers_a_single_relogin(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    fake_mega.code_once["devices"] = int(const.CloudCode.SESSION_TIMEOUT)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            devices = await api.async_get_devices()
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
    assert fake_mega.login_calls == 2  # initial + one automatic re-login


_REKEY_ANSWERS = {
    # the gateway's answer once the key identity has lapsed (verified on hardware)
    "http-463-body-4404": (463, {"code": 4404, "msg": "get identity error"}),
    "http-463-no-code": (463, {}),
    "http-200-body-463": (200, {"code": 463, "msg": "error"}),
    "http-200-body-4404": (200, {"code": 4404, "msg": "error"}),
}


@pytest.mark.parametrize("answer", list(_REKEY_ANSWERS.values()), ids=list(_REKEY_ANSWERS))
async def test_a_rekey_answer_runs_a_key_exchange_and_keeps_the_token(
    fake_mega: FakeMega, cache: SessionCache, answer: tuple[int, dict[str, Any]]
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            old_ident = cache.section("cloud")["key_ident"]
            fake_mega.error_bodies["devices"] = [answer]
            devices = await api.async_get_devices(refresh=True)
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
    assert fake_mega.login_calls == 1  # a re-key is never a login
    cloud = cache.section("cloud")
    assert cloud["key_ident"] != old_ident
    assert cloud["auth_token"] == FAKE_AUTH_TOKEN


async def test_a_second_rekey_refusal_raises_instead_of_serving_the_cached_list(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    refusal = (463, {"code": 4404, "msg": "get identity error"})
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_devices(refresh=True)  # a cached list exists
            fake_mega.error_bodies["devices"] = [refusal, refusal]
            with pytest.raises(KeyExchangeRefusedError) as caught:
                await api.async_get_devices(refresh=True)
    assert (caught.value.code, caught.value.status) == (4404, 463)
    assert fake_mega.login_calls == 1
    assert not api.session_replaced


async def test_other_non_200_answers_name_their_body_code(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            fake_mega.error_bodies["devices"] = [(503, {"code": 12345})]
            with pytest.raises(CommunicationError, match=r"HTTP 503 \(code 12345\)"):
                await api.async_get_devices(refresh=True)


async def test_concurrent_rekey_answers_share_one_key_exchange(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    fake_mega.latency = 0.01
    refusal = (463, {"code": 4404, "msg": "get identity error"})
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            fake_mega.error_bodies["devices"] = [refusal, refusal]
            exchanges = len(fake_mega._shared)
            await asyncio.gather(*(api.async_get_devices(refresh=True) for _ in range(2)))
    assert len(fake_mega._shared) == exchanges + 1
    assert fake_mega.login_calls == 1


@pytest.mark.parametrize("answer", ["code 26084", "HTTP 401"])
async def test_a_replaced_session_latches_until_a_forced_login(
    fake_mega: FakeMega, answer: str
) -> None:
    store = MemoryStore()
    cache = SessionCache(store, SYNTHETIC.email)
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_devices()  # a cached list must not hide the kick-out
            if answer == "HTTP 401":
                fake_mega.status_once["devices"] = (401, {})
            else:
                fake_mega.code_once["devices"] = int(const.CloudCode.SESSION_REPLACED)
            with pytest.raises(SessionReplacedError):
                await api.async_get_devices(refresh=True)
            latched = api.session_replaced
            assert latched
            assert "auth_token" not in cache.section("cloud")
            assert cache.password == SYNTHETIC.password  # the credentials were never wrong

            # Nothing logs in again or reaches the cloud by itself, after a restart too.
            sent = len(fake_mega.calls)
            reloaded = SessionCache(store, SYNTHETIC.email)
            await reloaded.async_load()
            for client in (api, _api(session, reloaded)):
                with pytest.raises(SessionReplacedError):
                    await client.async_get_devices(refresh=True)
                with pytest.raises(SessionReplacedError):
                    await client.async_login()
            assert len(fake_mega.calls) == sent
            assert fake_mega.login_calls == 1

            await api.async_login(force=True)  # the user takes the session back
            taken_back = api.session_replaced
            devices = await api.async_get_devices(refresh=True)
            assert not taken_back
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
    assert fake_mega.login_calls == 2


_FAILED_TAKE_OVERS = {
    "challenge": lambda mega: setattr(mega, "login_code", int(const.CloudCode.NEED_VERIFY_CODE)),
    "rejected": lambda mega: setattr(
        mega, "login_code", int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    ),
    "unreachable": lambda mega: mega.error_bodies.__setitem__("login", [(502, {})]),
}


@pytest.mark.parametrize("take_over", ["force", "reauthenticate"])
@pytest.mark.parametrize("fail", list(_FAILED_TAKE_OVERS.values()), ids=list(_FAILED_TAKE_OVERS))
async def test_a_failed_take_over_leaves_the_latch_set(
    fake_mega: FakeMega, take_over: str, fail: Callable[[FakeMega], None]
) -> None:
    store = MemoryStore()
    cache = SessionCache(store, SYNTHETIC.email)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            fake_mega.code_once["devices"] = int(const.CloudCode.SESSION_REPLACED)
            with pytest.raises(SessionReplacedError):
                await api.async_get_devices(refresh=True)
            fail(fake_mega)
            take_back = (
                api.async_login(force=True)
                if take_over == "force"
                else api.async_reauthenticate(SYNTHETIC.password, take_over=True)
            )
            with pytest.raises(EufySecurityError):
                await take_back
            reloaded = SessionCache(store, SYNTHETIC.email)
            await reloaded.async_load()
            assert api.session_replaced
            assert reloaded.replaced_at is not None  # persisted: a restart still refuses
            with pytest.raises(SessionReplacedError):
                await _api(session, reloaded).async_login()


async def test_owner_id_prefers_member_admin_id(fake_mega: FakeMega, cache: SessionCache) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 18,
            "member": {"admin_user_id": FAKE_OWNER_ID, "member_user_id": SYNTHETIC.account_id},
        },
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            owner = await api.async_get_station_owner_id(SYNTHETIC.station_sn)
    assert owner == FAKE_OWNER_ID
    assert cache.station_account_id(SYNTHETIC.station_sn) == FAKE_OWNER_ID


async def test_owner_id_falls_back_to_own_id_without_a_member_relation(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]  # no member
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            owner = await api.async_get_station_owner_id(SYNTHETIC.station_sn)
    assert owner == SYNTHETIC.account_id  # the literal owner uses its own id


async def test_owner_id_for_an_unknown_station_is_an_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(CloudApiError):
                await api.async_get_station_owner_id(SYNTHETIC.station_sn)


@pytest.mark.parametrize(
    ("owner", "accepted"),
    [
        ("abc\x01def", False),  # a control character
        ("a" * 200, False),  # does not fit the char[128] account field
        ("a" * 128, False),  # no room for the NUL
        ("ö" * 10, False),  # not ASCII
        ("0123456789abcdefABCDEF0123456789", True),  # 32 alphanumerics: no 40-hex rule
        ("a" * 127, True),
    ],
)
async def test_an_owner_id_that_cannot_fit_a_command_is_refused_and_not_cached(
    fake_mega: FakeMega, cache: SessionCache, owner: str, accepted: bool
) -> None:
    fake_mega.devices = [
        {"device_sn": SYNTHETIC.station_sn, "device_type": 18, "member": {"admin_user_id": owner}}
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            if accepted:
                assert await api.async_get_station_owner_id(SYNTHETIC.station_sn) == owner
            else:
                with pytest.raises(ProtocolError, match="not printable ASCII"):
                    await api.async_get_station_owner_id(SYNTHETIC.station_sn)
    assert cache.station_account_id(SYNTHETIC.station_sn) == (owner if accepted else None)


def test_the_owner_id_check_refuses_an_empty_id() -> None:
    # Unreachable through the device list ("" becomes None there, "has no owner id").
    with pytest.raises(ProtocolError):
        _check_owner_id("", SYNTHETIC.station_sn)


OTHER_EMAIL = "other@example.com"


def _sent(mock: aioresponses) -> int:
    return sum(len(calls) for calls in mock.requests.values())


async def test_a_request_throttle_holds_off_every_account_sharing_the_install(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 18,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        }
    ]
    install = InstallState()
    other = SessionCache(MemoryStore(), OTHER_EMAIL)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            a = EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, install=install)
            b = EufyCloudApi(session, other, OTHER_EMAIL, SYNTHETIC.password, install=install)
            await b.async_login()
            await b.async_get_station_owner_id(SYNTHETIC.station_sn)  # caches B's device list
            await a.async_login()
            fake_mega.code_once["devices"] = int(const.CloudCode.API_REQUEST_LIMIT)
            with pytest.raises(RateLimitedError):
                await a.async_get_devices(refresh=True)
            sent = _sent(mock)

            devices = await b.async_get_devices(refresh=True)  # falls back to B's cache
            assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
            with pytest.raises(RateLimitedError) as caught:
                await b.async_get_cipher_key(SYNTHETIC.station_sn, refresh=True)
            assert caught.value.retry_after == pytest.approx(3600, abs=5)
            assert b.cloud_status().request_hold_off == pytest.approx(3600, abs=5)
            assert _sent(mock) == sent  # refused locally: nothing reached the cloud
            assert other.held_off_for("requests", longest=const.LOCKOUT_HOLD_OFF_SECONDS) is None

            # A restart: a new InstallState shares nothing, A's own store still holds off.
            restarted = EufyCloudApi(
                session, other, OTHER_EMAIL, SYNTHETIC.password, install=InstallState()
            )
            await restarted.async_get_devices(refresh=True)
            assert _sent(mock) > sent
    assert cache.held_off_for("requests", longest=const.LOCKOUT_HOLD_OFF_SECONDS) is not None


async def test_a_login_hold_off_is_not_shared_with_the_install(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    install = InstallState()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            a = EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, install=install)
            fake_mega.login_code = int(const.CloudCode.PASSWORD_ERROR_MUCH)
            with pytest.raises(LoginLimitedError):
                await a.async_login()
            fake_mega.login_code = 0
            other = SessionCache(MemoryStore(), OTHER_EMAIL)
            b = EufyCloudApi(session, other, OTHER_EMAIL, SYNTHETIC.password, install=install)
            await b.async_login()
    assert install.request_held_off_for() is None
    assert fake_mega.login_calls == 2


async def test_cipher_fetch_uses_the_owner_id_and_caches(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 18,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.cipher_objects = [{"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            key = await api.async_get_cipher_key(SYNTHETIC.station_sn)
            assert key == FAKE_ECC_KEY
            # Cached: a second call makes no request.
            calls_before = len(fake_mega.calls)
            assert await api.async_get_cipher_key(SYNTHETIC.station_sn) == FAKE_ECC_KEY
            assert len(fake_mega.calls) == calls_before
    cipher_body = next(payload for name, payload in fake_mega.calls if name == "ciphers")
    assert cipher_body["user_id"] == FAKE_OWNER_ID  # never the caller's own id
    assert cipher_body["station_sn"] == SYNTHETIC.station_sn


async def test_empty_cipher_success_is_an_empty_response_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 18,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.cipher_objects = None  # code 0, no data — the "wrong user_id" answer
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(EmptyResponseError):
                await api.async_get_cipher_key(SYNTHETIC.station_sn)


async def test_cipher_refresh_honours_the_cooldown(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 18,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.cipher_objects = [{"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_cipher_key(SYNTHETIC.station_sn, refresh=True)
            # A second forced refresh immediately after is inside the cooldown: a local
            # refusal, not a eufy throttle.
            with pytest.raises(RefreshCooldownError) as caught:
                await api.async_get_cipher_key(SYNTHETIC.station_sn, refresh=True)
    assert caught.value.code == 0
    assert caught.value.retry_after is not None


async def test_register_push_token(fake_mega: FakeMega, cache: SessionCache) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_register_push_token("fid:APA91btoken")
    push = next(payload for name, payload in fake_mega.calls if name == "push")
    assert push == {
        "token": "fid:APA91btoken",
        "is_notification_enable": True,
        "voip_token": "fid:APA91btoken",
    }


_STATION_OF_OWNER = {
    "device_sn": SYNTHETIC.station_sn,
    "device_type": 18,
    "member": {"admin_user_id": FAKE_OWNER_ID},
}


async def test_login_is_persisted_to_the_store(fake_mega: FakeMega) -> None:
    store = MemoryStore()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await _api(session, SessionCache(store, SYNTHETIC.email)).async_login()
    assert store.data is not None  # no explicit save: HA never unloads on shutdown
    assert store.data["cloud"]["auth_token"] == FAKE_AUTH_TOKEN


async def test_concurrent_calls_on_a_cold_cache_share_one_login(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    async def slow_password() -> str:
        await asyncio.sleep(0.01)  # widen the window two logins would race through
        return SYNTHETIC.password

    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, slow_password)
            await asyncio.gather(api.async_get_devices(), api.async_register_push_token("tok"))
    assert fake_mega.login_calls == 1


async def test_concurrent_expiries_relogin_once(fake_mega: FakeMega, cache: SessionCache) -> None:
    """The second failing task must not drop the session the first just re-established."""
    fake_mega.code_once = {"devices": 401, "push": 401}
    fake_mega.latency = 0.01  # both calls are in flight when the token is refused …
    fake_mega.slow["push"] = 0.2  # … but push hears so only after the re-login finished
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await asyncio.gather(api.async_get_devices(), api.async_register_push_token("tok"))
    assert fake_mega.login_calls == 2  # initial + exactly one re-login


async def test_cipher_fetch_relogins_once_on_a_revoked_token(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [_STATION_OF_OWNER]
    fake_mega.cipher_objects = [{"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY}]
    fake_mega.code_once["ciphers"] = int(const.CloudCode.SESSION_TIMEOUT)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_get_cipher_key(SYNTHETIC.station_sn) == FAKE_ECC_KEY
    assert fake_mega.login_calls == 2


async def test_credential_rejection_on_a_call_is_never_retried_with_a_login(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.code_once["devices"] = int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(AuthenticationError):
                await api.async_get_devices()
    assert fake_mega.login_calls == 1


async def test_rejected_login_behind_a_call_is_attempted_once(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.login_code = int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(AuthenticationError):
                await _api(session, cache).async_get_devices()
    assert fake_mega.login_calls == 1


@pytest.mark.parametrize(
    "body",
    [
        lambda shared: json.dumps({"code": "not-a-number"}),
        lambda shared: json.dumps({"code": None}),
        lambda shared: json.dumps({"code": 0, "data": crypto.body_encrypt("not json", shared)}),
        lambda shared: json.dumps({"code": 0, "data": 5}),
    ],
    ids=["code-text", "code-null", "data-not-json", "data-scalar"],
)
async def test_malformed_bodies_are_protocol_errors(
    fake_mega: FakeMega, cache: SessionCache, body: Callable[[str], str]
) -> None:
    fake_mega.devices = [_STATION_OF_OWNER]
    fake_mega.body_once["ciphers"] = body
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(ProtocolError):
                await api.async_get_cipher_key(SYNTHETIC.station_sn)


async def test_device_success_without_devices_keeps_the_cache(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [_STATION_OF_OWNER]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_devices()
            fake_mega.data_override["devices"] = {"unexpected": True}
            with pytest.raises(ProtocolError):
                await api.async_get_devices(refresh=True)
    assert [d["device_sn"] for d in cache.cached_devices() or []] == [SYNTHETIC.station_sn]


async def test_owner_id_refresh_rereads_the_device_list_once_per_cooldown(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [_STATION_OF_OWNER]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_get_station_owner_id(SYNTHETIC.station_sn) == FAKE_OWNER_ID
            fake_mega.devices = [{**_STATION_OF_OWNER, "member": {"admin_user_id": "new-owner"}}]
            owner = await api.async_get_station_owner_id(SYNTHETIC.station_sn, refresh=True)
            assert owner == "new-owner"
            fetches = _device_fetches(fake_mega)
            # A handshake loop asking again inside the cooldown gets the cache, no fetch.
            again = await api.async_get_station_owner_id(SYNTHETIC.station_sn, refresh=True)
            assert again == "new-owner"
            assert _device_fetches(fake_mega) == fetches


async def test_region_override_wins_over_a_cached_mega_domain(cache: SessionCache) -> None:
    fake_mega = FakeMega(region="eu")
    fake_mega.login_data["mega_domain"] = "mega-us-pr.eufy.com"  # disagrees with the override
    fake_mega.devices = [_STATION_OF_OWNER]
    fake_mega.cipher_objects = [{"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY}]
    with aioresponses() as mock:
        fake_mega.install(mock)  # only eu hosts exist: a us host would fail to connect
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")
            await api.async_login()
            await api.async_get_devices(refresh=True)
            assert await api.async_get_cipher_key(SYNTHETIC.station_sn) == FAKE_ECC_KEY


async def test_login_logs_the_auth_flow_with_secrets_only_when_enabled(
    fake_mega: FakeMega, caplog: pytest.LogCaptureFixture
) -> None:
    async def login() -> str:
        caplog.clear()
        with aioresponses() as mock:
            fake_mega.install(mock)
            async with aiohttp.ClientSession() as session:
                api = _api(session, SessionCache(MemoryStore(), SYNTHETIC.email))
                await api.async_login()
        return caplog.text

    with caplog.at_level(logging.DEBUG, logger="eufy_home_security"):
        text = await login()
        assert "logging in to the eufy cloud" in text
        assert const.LOGIN_PATH in text
        assert "shared_key" in text
        assert FAKE_AUTH_TOKEN not in text
        assert SYNTHETIC.password not in text
        assert "login: password ***," in text  # no tail, no length: either leaks part of it
        set_secret_logging(True)
        try:
            text = await login()
        finally:
            set_secret_logging(False)
        assert f"auth_token {FAKE_AUTH_TOKEN}" in text
        assert f"password {SYNTHETIC.password}" in text


def test_identity_repr_hides_the_key_and_token() -> None:
    text = repr(_Identity(key_ident="k" * 32, shared_key="s" * 64, auth_token="tok-secret"))
    assert "s" * 64 not in text
    assert "tok-secret" not in text


# ── cloud status ─────────────────────────────────────────────────────────────


def _warm_session(cache: SessionCache, *, expires_in: float) -> None:
    cache.section("cloud").update(
        {
            "auth_token": "old-token",
            "key_ident": "old-ident",
            "shared_key": "00" * 32,
            "expires_at": time.time() + expires_in,
        }
    )


@pytest.mark.parametrize(
    ("expires_in", "cached_password", "latched", "need"),
    [
        (7 * 86400, None, False, LoginNeed.NONE),
        (60, SYNTHETIC.password, False, LoginNeed.CACHED_PASSWORD),  # inside the expiry margin
        (-60, None, False, LoginNeed.PASSWORD_REQUIRED),
        (7 * 86400, SYNTHETIC.password, True, LoginNeed.REPLACED),  # REPLACED wins over NONE
    ],
)
async def test_cloud_status_login_need_never_contacts_the_cloud(
    cache: SessionCache,
    expires_in: float,
    cached_password: str | None,
    latched: bool,
    need: LoginNeed,
) -> None:
    _warm_session(cache, expires_in=expires_in)
    if cached_password:
        cache.set_password(cached_password)
    if latched:
        cache.set_replaced()
    with aioresponses() as mock:
        async with aiohttp.ClientSession() as session:
            status = EufyCloudApi(session, cache, SYNTHETIC.email, None).cloud_status()
        assert not mock.requests
    assert status.login_need is need
    assert status.password_cached is (cached_password is not None)
    assert status.session_expires_in == pytest.approx(max(expires_in, 0.0), abs=5)
    assert status.logins_in_window == 0
    assert status.next_login_allowed_in == 0.0
    assert status.last_login_attempt_age is None


async def test_cloud_status_next_login_matches_the_budget_refusal(cache: SessionCache) -> None:
    cache.section("throttle")["logins"] = [time.time() - 3000, time.time() - 2000, time.time() - 10]
    with aioresponses() as mock:
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            status = api.cloud_status()
            with pytest.raises(LoginLimitedError) as caught:
                await api.async_login()
        assert not mock.requests
    assert status.logins_in_window == 3
    assert (status.login_budget, status.login_window) == (
        const.LOGIN_BUDGET,
        const.LOGIN_BUDGET_WINDOW_SECONDS,
    )
    assert caught.value.retry_after is not None
    assert status.next_login_allowed_in == pytest.approx(caught.value.retry_after, abs=1)
    assert status.last_login_attempt_age == pytest.approx(10, abs=5)
    assert status.login_hold_off is None
    assert status.request_hold_off is None


@pytest.mark.parametrize(("failing", "spent"), [("login", 1), ("exchange", 0)])
async def test_a_login_is_counted_once_it_is_sent(
    fake_mega: FakeMega, cache: SessionCache, failing: str, spent: int
) -> None:
    host, path = {
        "login": (const.cluster_host("passport", "eu"), const.LOGIN_PATH),
        "exchange": (const.cluster_host("openapi", "eu"), const.KEY_EXCHANGE_PATH),
    }[failing]
    with aioresponses() as mock:
        mock.post(f"https://{host}{path}", exception=aiohttp.ClientConnectionError("down"))
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            before = api.cloud_status().logins_in_window
            with pytest.raises(CommunicationError):
                await api.async_login()
            after = api.cloud_status().logins_in_window
    assert after - before == spent


async def test_cloud_status_reports_refresh_state_per_station(cache: SessionCache) -> None:
    other_sn = "T8030P2000067890"
    cache.set_cipher_key(SYNTHETIC.station_sn, 40, FAKE_ECC_KEY)
    cache.set_cipher_key(other_sn, 40, FAKE_ECC_KEY)
    cache.note_refresh("cipher", SYNTHETIC.station_sn)
    cache.note_key_refresh(other_sn)
    cache.note_refresh("owner")
    async with aiohttp.ClientSession() as session:
        status = _api(session, cache).cloud_status()
    a, b = status.stations[SYNTHETIC.station_sn], status.stations[other_sn]
    assert a.cipher_refresh_age == pytest.approx(0, abs=5)
    assert not a.key_refresh_outstanding
    assert a.next_automatic_refresh_in == pytest.approx(const.FORCED_REFRESH_COOLDOWN, abs=5)
    assert b.cipher_refresh_age is None
    assert b.key_refresh_outstanding
    assert b.next_automatic_refresh_in == pytest.approx(const.KEY_REFRESH_SLOW_RETRY, abs=5)
    assert status.device_list_refresh_age == pytest.approx(0, abs=5)


async def test_a_cipher_cooldown_does_not_block_another_station(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    other_sn = "T8030P2000067890"
    fake_mega.devices = [
        {"device_sn": sn, "device_type": 18, "member": {"admin_user_id": FAKE_OWNER_ID}}
        for sn in (SYNTHETIC.station_sn, other_sn)
    ]
    fake_mega.cipher_objects = [{"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_cipher_key(SYNTHETIC.station_sn, refresh=True)
            assert await api.async_get_cipher_key(other_sn, refresh=True) == FAKE_ECC_KEY


# ── reauthenticate ───────────────────────────────────────────────────────────


def _warm_with_old_password(cache: SessionCache) -> None:
    _warm_session(cache, expires_in=7 * 86400)
    cache.set_password("old")


async def test_reauthenticate_logs_in_on_a_warm_cache_and_replaces_the_password(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    _warm_with_old_password(cache)
    cache.note_key_refresh(SYNTHETIC.station_sn)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, "old")
            await api.async_reauthenticate("new")
            await api.async_login()  # the new session is reused
    assert fake_mega.login_calls == 1
    assert cache.password == "new"
    assert cache.section("cloud")["auth_token"] == FAKE_AUTH_TOKEN
    assert cache.key_refresh_outstanding(SYNTHETIC.station_sn) is None
    assert api._password == "new"  # a given password does not outlive the change


async def test_a_rejected_reauthentication_keeps_the_cached_password(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    _warm_with_old_password(cache)
    fake_mega.login_code = int(const.CloudCode.EMAIL_OR_PASSWORD_ERROR)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, None)
            before = api.cloud_status().logins_in_window
            with pytest.raises(AuthenticationError):
                await api.async_reauthenticate("new")
            assert api.cloud_status().logins_in_window == before + 1
    assert cache.password == "old"
    assert cache.section("cloud")["auth_token"] == "old-token"


async def test_reauthenticate_honours_the_login_budget(cache: SessionCache) -> None:
    _warm_with_old_password(cache)
    cache.section("throttle")["logins"] = [time.time() - 60] * const.LOGIN_BUDGET
    with aioresponses() as mock:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(LoginLimitedError):
                await EufyCloudApi(session, cache, SYNTHETIC.email, None).async_reauthenticate(
                    "new"
                )
        assert not mock.requests
    assert cache.password == "old"


async def test_reauthenticate_respects_the_replaced_latch_unless_taking_over(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    _warm_with_old_password(cache)
    cache.set_replaced()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, None)
            with pytest.raises(SessionReplacedError):
                await api.async_reauthenticate("new")
            assert not mock.requests
            await api.async_reauthenticate("new", take_over=True)
    assert fake_mega.login_calls == 1
    assert not api.session_replaced
    assert cache.password == "new"


async def test_a_reauthentication_challenge_stores_the_password_only_once_answered(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    _warm_with_old_password(cache)
    fake_mega.login_code = int(const.CloudCode.NEED_VERIFY_CODE)
    fake_mega.login_extra = {"login_id": "login-1"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, None)
            with pytest.raises(LoginChallengeError) as caught:
                await api.async_reauthenticate("new")
            assert cache.password == "old"
            fake_mega.login_code = 0
            await api.async_reauthenticate(
                "new", verify_code="123456", login_id=caught.value.login_id
            )
    assert caught.value.login_id == "login-1"
    assert fake_mega.calls[-1] == ("login", fake_mega.calls[-1][1])
    assert fake_mega.calls[-1][1]["verify_code"] == "123456"
    assert fake_mega.calls[-1][1]["login_id"] == "login-1"
    assert cache.password == "new"


async def test_device_list_cache_keeps_params_for_on_demand_and_drops_for_homebase(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": "T8170P0000000000",
            "device_name": "SoloCam",
            "params": [{"param_type": 1101, "param_value": "87"}],
        },
        {
            "device_sn": "T8030P0000000000",
            "device_name": "HomeBase",
            "params": [{"param_type": 1101, "param_value": "87"}],
        },
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_get_devices()

    stored = cache.cached_devices()
    assert stored is not None
    assert len(stored) == 2

    # T8170 is on-demand, should have params
    on_demand = next(d for d in stored if d["device_sn"] == "T8170P0000000000")
    assert "params" in on_demand

    # T8030 is HomeBase, should not have params
    homebase = next(d for d in stored if d["device_sn"] == "T8030P0000000000")
    assert "params" not in homebase


async def test_dsk_fetch_caches_until_it_expires(fake_mega: FakeMega, cache: SessionCache) -> None:

    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 48,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.dsk_objects = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "dsk_key": "the-dsk-value",
            "expiration": time.time() + 3600,
        }
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_get_dsk_key(SYNTHETIC.station_sn) == "the-dsk-value"
            calls_before = len(fake_mega.calls)
            # Cached: a second call makes no request, and it lands in the store.
            assert await api.async_get_dsk_key(SYNTHETIC.station_sn) == "the-dsk-value"
            assert len(fake_mega.calls) == calls_before
    cached = cache.dsk_key(SYNTHETIC.station_sn)
    assert cached is not None
    assert cached[0] == "the-dsk-value"
    dsk_body = next(payload for name, payload in fake_mega.calls if name == "dsk")
    assert dsk_body["station_sns"] == [SYNTHETIC.station_sn]
    assert dsk_body["device_dsks"][0]["device_sn"] == SYNTHETIC.station_sn


async def test_dsk_refresh_passes_the_stale_key_as_invalid(
    fake_mega: FakeMega, cache: SessionCache
) -> None:

    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 48,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.dsk_objects = [
        {"device_sn": SYNTHETIC.station_sn, "dsk_key": "first", "expiration": time.time() + 3600}
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_get_dsk_key(SYNTHETIC.station_sn) == "first"
            fake_mega.dsk_objects = [
                {
                    "device_sn": SYNTHETIC.station_sn,
                    "dsk_key": "second",
                    "expiration": time.time() + 3600,
                }
            ]
            assert await api.async_get_dsk_key(SYNTHETIC.station_sn, refresh=True) == "second"
    refresh_body = [payload for name, payload in fake_mega.calls if name == "dsk"][-1]
    assert refresh_body["device_dsks"][0]["invalid_dsk"] == "first"


async def test_dsk_expired_cache_is_refetched(fake_mega: FakeMega, cache: SessionCache) -> None:

    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 48,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    cache.set_dsk_key(SYNTHETIC.station_sn, "stale", time.time() + 60)  # inside the margin
    fake_mega.dsk_objects = [
        {"device_sn": SYNTHETIC.station_sn, "dsk_key": "fresh", "expiration": time.time() + 3600}
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_get_dsk_key(SYNTHETIC.station_sn) == "fresh"


async def test_empty_dsk_response_is_an_empty_response_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [
        {
            "device_sn": SYNTHETIC.station_sn,
            "device_type": 48,
            "member": {"admin_user_id": FAKE_OWNER_ID},
        },
    ]
    fake_mega.dsk_objects = None  # code 0, empty device_dsks
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(EmptyResponseError):
                await api.async_get_dsk_key(SYNTHETIC.station_sn)


# ── firmware (OTA) ───────────────────────────────────────────────────────────

_ROM_UPDATE = {
    "device_type": "T8030_Kit",
    "rom_version": 700,
    "rom_version_name": "3.9.0.0",
    "force_upgrade": False,
    "introduction": "Stability fixes.",
    "full_package": {
        "file_md5": "0123456789abcdef0123456789abcdef",
        "file_name": "T8030_3.9.0.0.bin",
        "file_path": "https://cdn.eufylife.com/fw/T8030_3.9.0.0.bin",
        "file_size": 12345678,
    },
}


async def test_check_firmware_up_to_date_is_none(fake_mega: FakeMega, cache: SessionCache) -> None:
    fake_mega.rom_version_data = None  # the OTA "up to date" answer (code 20004 in data)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            update = await api.async_check_firmware(
                SYNTHETIC.station_sn, ota_type="T8030_Kit", current_version_name="3.8.7.4"
            )
    assert update is None
    body = next(payload for name, payload in fake_mega.calls if name == "ota")
    assert body["device_sn"] == SYNTHETIC.station_sn
    assert body["sn"] == SYNTHETIC.station_sn
    assert body["device_type"] == "T8030_Kit"
    assert body["current_version_name"] == "3.8.7.4"
    assert body["transaction"]


async def test_check_firmware_parses_available_update(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.rom_version_data = _ROM_UPDATE
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            update = await api.async_check_firmware(
                SYNTHETIC.station_sn, ota_type="T8030_Kit", current_version_name="3.8.7.4"
            )
    assert update is not None
    assert update.device_sn == SYNTHETIC.station_sn
    assert update.version_name == "3.9.0.0"
    assert update.rom_version == 700
    assert update.download_url == "https://cdn.eufylife.com/fw/T8030_3.9.0.0.bin"
    assert update.md5 == "0123456789abcdef0123456789abcdef"
    assert update.size_bytes == 12345678
    assert update.notes == "Stability fixes."
    assert update.forced is False
    # The serial is redacted out of the repr (it lands in logs / HA diagnostics).
    assert SYNTHETIC.station_sn not in repr(update)


async def test_check_firmware_without_full_package_is_none(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    # A code-0 answer that names a version but carries no downloadable package is not an update.
    fake_mega.rom_version_data = {"rom_version_name": "3.9.0.0", "upgrade_flag": 0}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            update = await api.async_check_firmware(
                SYNTHETIC.station_sn, ota_type="T8030_Kit", current_version_name="3.8.7.4"
            )
    assert update is None
