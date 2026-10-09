"""EufyCloudApi.async_get_thing_descriptions: the cached session only, never a login.

Every scenario seeds a session with one ordinary login, then arms a guard that makes
every login-capable method raise. From then on no failure — no session, an expired or
re-keyed session, 401, 429, a throttle code, a hold-off, the replaced latch — may
reach a login: ``FakeMega.login_calls`` stays at the seeding login and the guard
never fires.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import time
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.exceptions import (
    AuthenticationError,
    CloudError,
    NoCachedSessionError,
    ProtocolError,
    RateLimitedError,
    SessionReplacedError,
)
from eufy_home_security.install import InstallState
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.cloud import enum_property, thing_description

from .conftest import FakeMega

#: Every method of EufyCloudApi that can send a login.
_LOGIN_PATHS = ("_do_login", "async_login", "async_reauthenticate", "_ensure_session")
#: Names the fetch's source must never mention: the login paths, the re-login
#: wrappers, and the session drop.
_FORBIDDEN = frozenset(
    {*_LOGIN_PATHS, "_with_session", "_authenticated_call", "_drop_session_if_current"}
)


def _thing(product_code: str) -> dict[str, Any]:
    """A synthetic thing description of ``product_code``."""
    return thing_description(product_code, [enum_property("power_mode", {0: "Off", 1: "On"})])


def _sent(mock: aioresponses) -> int:
    return sum(len(calls) for calls in mock.requests.values())


class _LoginGuard:
    """Once armed, every login-capable method raises and is recorded."""

    def __init__(self) -> None:
        self.armed = False
        self.hits: list[str] = []


def _guarded(
    guard: _LoginGuard, name: str, original: Callable[..., Awaitable[Any]]
) -> Callable[..., Awaitable[Any]]:
    async def patched(self: EufyCloudApi, *args: Any, **kwargs: Any) -> Any:
        if guard.armed:
            guard.hits.append(name)
            raise AssertionError(f"login path reached: {name}")
        return await original(self, *args, **kwargs)

    return patched


@pytest.fixture(autouse=True)
def login_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LoginGuard]:
    guard = _LoginGuard()
    for name in _LOGIN_PATHS:
        monkeypatch.setattr(EufyCloudApi, name, _guarded(guard, name, getattr(EufyCloudApi, name)))
    yield guard
    assert guard.hits == [], f"a login path ran: {guard.hits}"


async def _seeded(
    session: aiohttp.ClientSession,
    guard: _LoginGuard,
    *,
    install: InstallState | None = None,
    load: bool = True,
) -> tuple[EufyCloudApi, SessionCache]:
    """A fresh client over a cache one ordinary login filled; logins are forbidden after."""
    store = MemoryStore()
    first = SessionCache(store, SYNTHETIC.email)
    await first.async_load()
    await EufyCloudApi(
        session, first, SYNTHETIC.email, SYNTHETIC.password, region="eu"
    ).async_login()
    await first.async_save()
    cache = SessionCache(store, SYNTHETIC.email)
    if load:
        await cache.async_load()
    guard.armed = True
    api = EufyCloudApi(
        session, cache, SYNTHETIC.email, SYNTHETIC.password, install=install, region="eu"
    )
    return api, cache


# ── the happy path ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("source", ["cached", "held"])
async def test_fetches_on_the_existing_session_without_a_login(
    fake_mega: FakeMega, login_guard: _LoginGuard, source: str
) -> None:
    fake_mega.things = [_thing("TX0001"), _thing("TX0002")]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            if source == "cached":  # a fresh instance reads the session from the cache
                api, _cache = await _seeded(session, login_guard)
            else:  # the instance that logged in keeps its session in memory
                cache = SessionCache(MemoryStore(), SYNTHETIC.email)
                await cache.async_load()
                api = EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")
                await api.async_login()
                login_guard.armed = True
            things = await api.async_get_thing_descriptions(["TX0001", "TX9999"])
    # The reply omits the code the cloud does not know; the caller matches by code.
    assert [t["profile"]["product_code"] for t in things] == ["TX0001"]
    assert fake_mega.things_calls == 1
    assert [p for name, p in fake_mega.calls if name == "things"] == [
        {"product_codes": ["TX0001", "TX9999"], "code_time_map": {}, "use_network_version": True}
    ]
    assert fake_mega.login_calls == 1  # the seeding login only


async def test_no_product_codes_sends_nothing(
    fake_mega: FakeMega, login_guard: _LoginGuard
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, _cache = await _seeded(session, login_guard)
            assert await api.async_get_thing_descriptions([]) == []
    assert fake_mega.things_calls == 0


# ── refused locally: nothing is sent ─────────────────────────────────────────


def _no_session(cache: SessionCache, install: InstallState) -> None:
    for key in ("auth_token", "key_ident", "shared_key", "expires_at"):
        cache.cloud_session("eu").pop(key, None)


def _expired(cache: SessionCache, install: InstallState) -> None:
    cache.cloud_session("eu")["expires_at"] = time.time() + 10  # inside SESSION_EXPIRY_MARGIN


def _request_hold_off(cache: SessionCache, install: InstallState) -> None:
    cache.hold_off("requests", 3600)


def _install_hold_off(cache: SessionCache, install: InstallState) -> None:
    install.hold_off_requests(3600)


def _replaced(cache: SessionCache, install: InstallState) -> None:
    cache.set_replaced()


@pytest.mark.parametrize(
    ("setup", "error"),
    [
        (None, NoCachedSessionError),  # the session cache was never loaded
        (_no_session, NoCachedSessionError),
        (_expired, NoCachedSessionError),
        (_request_hold_off, RateLimitedError),
        (_install_hold_off, RateLimitedError),
        (_replaced, SessionReplacedError),
    ],
    ids=[
        "cache-not-loaded",
        "no-session",
        "expired",
        "request-hold-off",
        "install-hold-off",
        "replaced-latch",
    ],
)
async def test_refused_locally_without_a_request_or_login(
    fake_mega: FakeMega,
    login_guard: _LoginGuard,
    setup: Callable[[SessionCache, InstallState], None] | None,
    error: type[CloudError],
) -> None:
    fake_mega.things = [_thing("TX0001")]
    install = InstallState()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, cache = await _seeded(
                session, login_guard, install=install, load=setup is not None
            )
            if setup is not None:
                setup(cache, install)
            token = cache.cloud_session("eu").get("auth_token")
            sent = _sent(mock)
            with pytest.raises(error):
                await api.async_get_thing_descriptions(["TX0001"])
            assert _sent(mock) == sent
            assert cache.cloud_session("eu").get("auth_token") == token  # nothing dropped
    assert fake_mega.things_calls == 0
    assert fake_mega.login_calls == 1
    assert not issubclass(NoCachedSessionError, AuthenticationError)  # never a reauth


# ── the cloud refuses the session: propagate, never re-login ─────────────────


@pytest.mark.parametrize("code", [int(const.CloudCode.SESSION_TIMEOUT), *sorted(const.REKEY_CODES)])
async def test_an_expired_or_rekey_answer_propagates_and_keeps_the_session(
    fake_mega: FakeMega, login_guard: _LoginGuard, code: int
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, cache = await _seeded(session, login_guard)
            token = cache.cloud_session("eu")["auth_token"]
            fake_mega.code_once["things"] = code
            with pytest.raises(CloudError):
                await api.async_get_thing_descriptions(["TX0001"])
            assert cache.cloud_session("eu")["auth_token"] == token  # a guest never drops it
            assert api.session_replaced is False
    assert fake_mega.things_calls == 1
    assert fake_mega.login_calls == 1


@pytest.mark.parametrize("answer", ["HTTP 401", "code 26084"])
async def test_a_replaced_session_latches_without_a_login(
    fake_mega: FakeMega, login_guard: _LoginGuard, answer: str
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, cache = await _seeded(session, login_guard)
            if answer == "HTTP 401":
                replaced = {"code": int(const.CloudCode.SESSION_REPLACED), "msg": "replaced"}
                fake_mega.error_bodies["things"] = [(401, replaced)]
            else:
                fake_mega.code_once["things"] = int(const.CloudCode.SESSION_REPLACED)
            with pytest.raises(SessionReplacedError):
                await api.async_get_thing_descriptions(["TX0001"])
            assert api.session_replaced is True
            # The one session mutation on this path, exactly as _with_session does it.
            assert "auth_token" not in cache.cloud_session("eu")
            sent = _sent(mock)
            with pytest.raises(SessionReplacedError):
                await api.async_get_thing_descriptions(["TX0001"])
            assert _sent(mock) == sent
    assert fake_mega.login_calls == 1


async def test_http_401_without_the_takeover_code_neither_latches_nor_logs_in(
    fake_mega: FakeMega, login_guard: _LoginGuard
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, _cache = await _seeded(session, login_guard)
            fake_mega.error_bodies["things"] = [(401, {"code": 401, "msg": "expired"})]
            with pytest.raises(NoCachedSessionError):  # no login was tried: never a reauth
                await api.async_get_thing_descriptions(["TX0001"])
            assert api.session_replaced is False
    assert fake_mega.login_calls == 1


# ── throttles: the shared hold-off budget ────────────────────────────────────


@pytest.mark.parametrize(
    "throttle",
    ["HTTP 429", int(const.CloudCode.API_REQUEST_LIMIT), int(const.CloudCode.REQUEST_TOO_FAST)],
)
async def test_a_throttle_holds_off_every_cloud_call(
    fake_mega: FakeMega, login_guard: _LoginGuard, throttle: str | int
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, _cache = await _seeded(session, login_guard)
            if throttle == "HTTP 429":
                fake_mega.status_once["things"] = (429, {"Retry-After": "7200"})
                expected = 7200
            else:
                fake_mega.code_once["things"] = int(throttle)
                expected = 3600
            with pytest.raises(RateLimitedError) as caught:
                await api.async_get_thing_descriptions(["TX0001"])
            assert caught.value.retry_after == pytest.approx(expected, abs=5)
            assert api.cloud_status().request_hold_off == pytest.approx(expected, abs=5)
            sent = _sent(mock)
            with pytest.raises(RateLimitedError):
                await api.async_get_thing_descriptions(["TX0001"])
            # An ordinary call may pass through _ensure_session (which finds the session
            # in memory); disarm the guard for it and count logins on the wire instead.
            login_guard.armed = False
            with pytest.raises(RateLimitedError):
                await api.async_get_devices(refresh=True)  # the same budget
            assert _sent(mock) == sent  # refused locally: nothing reached the cloud
    assert fake_mega.things_calls == 1
    assert fake_mega.login_calls == 1


# ── untrusted reply ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "data",
    [{}, {"things_list": {"TX0001": {}}}, {"things_list": None}, [], None],
    ids=["no-things-list", "things-list-not-a-list", "things-list-null", "a-list", "no-data"],
)
async def test_a_malformed_reply_is_a_protocol_error(
    fake_mega: FakeMega, login_guard: _LoginGuard, data: Any
) -> None:
    fake_mega.data_override["things"] = data
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, _cache = await _seeded(session, login_guard)
            with pytest.raises(ProtocolError, match="things_list"):
                await api.async_get_thing_descriptions(["TX0001"])


async def test_non_mapping_items_are_dropped(fake_mega: FakeMega, login_guard: _LoginGuard) -> None:
    thing = _thing("TX0001")
    fake_mega.data_override["things"] = {"things_list": ["TX0001", 3, None, thing]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api, _cache = await _seeded(session, login_guard)
            assert await api.async_get_thing_descriptions(["TX0001"]) == [thing]


# ── structural: no login-capable name in the source ──────────────────────────


def _names(source: str) -> set[str]:
    tree = ast.parse(textwrap.dedent(source))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def test_structural_scan_finds_no_login_path() -> None:
    names = _names(inspect.getsource(EufyCloudApi.async_get_thing_descriptions))
    assert "_call" in names  # the scan sees the call it makes (not a vacuous pass)
    assert "_mark_replaced" in names
    assert names.isdisjoint(_FORBIDDEN), sorted(names & _FORBIDDEN)
