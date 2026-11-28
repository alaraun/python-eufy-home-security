"""EufyCloudApi: the account check before every login and the password it decides on."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import AsyncIterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.exceptions import (
    AuthenticationError,
    CloudApiError,
    CommunicationError,
    LoginChallengeError,
    LoginLimitedError,
    RateLimitedError,
    SessionRejectedError,
)
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FAKE_PENDING_TOKEN, FakeMega

_SHA256 = hashlib.sha256(SYNTHETIC.password.encode()).hexdigest()
_MISMATCH = int(const.CloudCode.DOMAIN_MISMATCH)
# A second cluster domain of the eu cluster.
_EU_DOMAIN_2 = "mega-eu-pr-2.eufy.com"


@pytest.fixture
async def http() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


def _api(http: aiohttp.ClientSession, cache: SessionCache, **kwargs: Any) -> EufyCloudApi:
    kwargs.setdefault("region", "eu")
    return EufyCloudApi(http, cache, SYNTHETIC.email, SYNTHETIC.password, **kwargs)


def _endpoints(fake_mega: FakeMega) -> list[str]:
    """The login-path requests in order, with the region label of the host they reached."""
    names = {"validate_email", "login", "estimate_domain"}
    return [f"{name}@{region}" for name, region in fake_mega.region_calls if name in names]


def _sent(fake_mega: FakeMega, name: str) -> list[dict[str, Any]]:
    return [payload for n, payload in fake_mega.calls if n == name]


def _budget(cache: SessionCache) -> int:
    return len(cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS, "eu"))


@pytest.mark.parametrize(
    ("enc_text", "wrapped"),
    [
        ("sha2", _SHA256),
        (None, SYNTHETIC.password),
        ("", SYNTHETIC.password),
        ("SHA2", SYNTHETIC.password),  # the app compares exactly
    ],
    ids=["sha2", "no-enc-text", "empty", "other-case"],
)
async def test_the_account_check_decides_what_the_login_wraps(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    enc_text: str | None,
    wrapped: str,
) -> None:
    """The fake accepts only the password the account check asks for: its SHA-256 for
    ``enc_text`` ``sha2``, else the password itself."""
    fake_mega.enc_text = enc_text
    fake_mega.account_password = SYNTHETIC.password
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache).async_login()
    assert fake_mega.login_passwords == [wrapped]
    assert _endpoints(fake_mega) == ["validate_email@eu", "login@eu"]
    assert _sent(fake_mega, "validate_email") == [{"email": SYNTHETIC.email}]
    check, login = fake_mega.headers["validate_email"][0], fake_mega.headers["login"][0]
    assert check["x-key-ident"] == login["x-key-ident"]  # under the login's own identity
    assert check["x-encryption-info"] == "algo_ecdh"  # an encrypted body, as the app sends
    assert "x-auth-token" not in check
    assert cache.cloud_session("eu")["auth_token"]
    assert cache.password == SYNTHETIC.password
    assert _budget(cache) == 1  # the check and its login are one attempt


@pytest.mark.parametrize(
    ("enc_text", "accepted", "refused"),
    [("sha2", _SHA256, SYNTHETIC.password), (None, SYNTHETIC.password, _SHA256)],
    ids=["sha2", "plain"],
)
def test_the_fake_takes_only_the_form_its_check_asks_for(
    fake_mega: FakeMega, enc_text: str | None, accepted: str, refused: str
) -> None:
    fake_mega.enc_text = enc_text
    fake_mega.account_password = f" {SYNTHETIC.password}\t"  # trimmed before hashing
    if enc_text is None:
        fake_mega.account_password = SYNTHETIC.password
    assert fake_mega._password_accepted(accepted)
    assert not fake_mega._password_accepted(refused)
    assert not fake_mega._password_accepted(None)


async def test_the_answer_to_a_two_step_code_checks_the_account_again(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """The answer repeats the check inside the pending login and wraps the SHA-256 under
    the challenge's key: the same ciphertext as the challenge's login."""
    fake_mega.two_step = {"eu"}
    fake_mega.enc_text = "sha2"
    fake_mega.account_password = SYNTHETIC.password
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginChallengeError):
            await api.async_login()
        await api.async_login(verify_code="123456")
    assert _endpoints(fake_mega) == ["validate_email@eu", "login@eu"] * 2
    first, second = fake_mega.headers["validate_email"]
    first_login, answer_login = fake_mega.headers["login"]
    assert second["x-key-ident"] == answer_login["x-key-ident"] == first_login["x-key-ident"]
    assert "x-auth-token" not in first
    assert second["x-auth-token"] == FAKE_PENDING_TOKEN
    assert fake_mega.login_passwords == [_SHA256, _SHA256]
    first_body, answer_body = _sent(fake_mega, "login")
    assert answer_body["password"] == first_body["password"]
    assert cache.cloud_session("eu")["auth_token"]
    assert _budget(cache) == 2


async def test_a_new_login_answering_a_code_checks_the_account_too(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.two_step = {"eu"}
    fake_mega.enc_text = "sha2"
    fake_mega.account_password = SYNTHETIC.password
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginChallengeError):
            await api.async_login()
        cache.section("cloud")["pending_logins"].clear()
        await api.async_login(verify_code="123456")
    assert _endpoints(fake_mega) == ["validate_email@eu", "login@eu"] * 2
    assert fake_mega.login_passwords == [_SHA256, _SHA256]


async def test_a_domain_mismatch_is_followed_on_the_same_cluster(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """26502: the login country's domain is looked up again and the check repeated
    there once; the login follows to that domain."""
    fake_mega.country_regions = {"DE": "eu"}
    fake_mega.error_bodies["validate_email"] = [(200, {"code": _MISMATCH, "msg": "x"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        fake_mega.install_domain(mock, _EU_DOMAIN_2, "eu2")
        api = _api(http, cache, country="DE", region=None)
        await api.async_login()
        fake_mega.country_domains = {"DE": _EU_DOMAIN_2}
        fake_mega.region_calls.clear()
        fake_mega.calls.clear()
        fake_mega.error_bodies["validate_email"] = [(200, {"code": _MISMATCH, "msg": "x"})]
        await api.async_reauthenticate(SYNTHETIC.password)
    assert _endpoints(fake_mega) == [
        "validate_email@eu",
        "estimate_domain@eu",
        "validate_email@eu2",
        "login@eu2",
    ]
    assert _sent(fake_mega, "estimate_domain") == [{"ab": "DE", "mode": 1}]
    assert cache.cloud_session("eu")["auth_token"]


@pytest.mark.parametrize(
    "domain", ["mega-us-pr.eufy.com", "aiot-api-eu.eufylife.com"], ids=["us", "no-cluster"]
)
async def test_a_domain_mismatch_naming_another_cluster_is_not_followed(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession, domain: str
) -> None:
    await cache.async_load()
    cache.section("cloud")["country"] = {"code": "DE", "source": "option", "home_region": "eu"}
    fake_mega.country_domains = {"DE": domain}
    fake_mega.error_bodies["validate_email"] = [(200, {"code": _MISMATCH, "msg": "x"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        with pytest.raises(CloudApiError) as exc:
            await _api(http, cache, country="DE", region=None).async_login()
    assert type(exc.value) is CloudApiError
    assert exc.value.code == _MISMATCH
    assert _endpoints(fake_mega) == [
        "validate_email@eu",
        "estimate_domain@eu",
    ]
    assert fake_mega.login_calls == 0
    assert "mega_domain" not in cache.cloud_session("eu")


async def test_a_second_domain_mismatch_is_not_followed_again(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    await cache.async_load()
    cache.section("cloud")["country"] = {"code": "DE", "source": "option", "home_region": "eu"}
    fake_mega.country_regions = {"DE": "eu"}
    mismatch = (200, {"code": _MISMATCH, "msg": "x"})
    fake_mega.error_bodies["validate_email"] = [mismatch, mismatch]
    with aioresponses() as mock:
        fake_mega.install(mock)
        with pytest.raises(CloudApiError) as exc:
            await _api(http, cache, country="DE", region=None).async_login()
    assert exc.value.code == _MISMATCH
    assert _endpoints(fake_mega) == [
        "validate_email@eu",
        "estimate_domain@eu",
        "validate_email@eu",
    ]
    assert fake_mega.login_calls == 0


_THROTTLE = int(const.CloudCode.MAX_LOGIN_LIMIT)
_TOO_FAST = int(const.CloudCode.REQUEST_TOO_FAST)
_NOT_REGISTERED = int(const.CloudCode.EMAIL_NOT_REGISTERED)


@pytest.mark.parametrize(
    "case",
    [
        ((200, {"code": _THROTTLE, "msg": "x"}), LoginLimitedError, True),
        ((200, {"code": _TOO_FAST, "msg": "x"}), RateLimitedError, True),
        ((429, {"msg": "x"}), RateLimitedError, True),
        ((200, {"code": _NOT_REGISTERED, "msg": "x"}), AuthenticationError, False),
        ((502, {"msg": "bad gateway"}), CommunicationError, True),
        ((401, {"code": 401, "msg": "expired"}), SessionRejectedError, True),
        ((200, {"code": 26501, "msg": "x"}), CloudApiError, True),
    ],
    ids=[
        "login-throttle",
        "request-throttle",
        "http-429",
        "credential",
        "transient",
        "401",
        "plain",
    ],
)
async def test_a_refused_account_check_stops_the_login(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    case: tuple[tuple[int, dict[str, Any]], type[Exception], bool],
) -> None:
    """Classified as the login's own answer would be; no login is sent."""
    answer, error, password_kept = case
    cache.set_password(SYNTHETIC.password)
    fake_mega.error_bodies["validate_email"] = [answer]
    with aioresponses() as mock:
        fake_mega.install(mock)
        with pytest.raises(error) as exc:
            await EufyCloudApi(http, cache, SYNTHETIC.email, None, region="eu").async_login()
    assert isinstance(exc.value, error)
    assert not isinstance(exc.value, LoginChallengeError)
    if error is CloudApiError:
        assert type(exc.value) is CloudApiError
    assert fake_mega.login_calls == 0
    assert (cache.password == SYNTHETIC.password) is password_kept
    assert _budget(cache) == 1
    held = cache.held_off_for("login", longest=const.LOCKOUT_HOLD_OFF_SECONDS, region="eu")
    assert (held is not None) is (error is LoginLimitedError)


async def test_a_captcha_answer_to_the_account_check_is_a_challenge(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    cache.set_password(SYNTHETIC.password)
    captcha = int(const.CloudCode.LOGIN_NEED_CAPTCHA)
    fake_mega.error_bodies["validate_email"] = [(200, {"code": captcha, "login_id": "lid-3"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = EufyCloudApi(http, cache, SYNTHETIC.email, None, region="eu")
        with pytest.raises(LoginChallengeError) as exc:
            await api.async_login()
    assert (exc.value.kind, exc.value.code, exc.value.region) == ("captcha", captcha, "eu")
    assert (exc.value.captcha_id, exc.value.login_id) == ("cap-123", "lid-3")
    assert api._challenge_region == "eu"
    assert fake_mega.login_calls == 0
    assert cache.password == SYNTHETIC.password


async def test_a_code_answer_to_the_account_check_is_a_challenge(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    cache.set_password(SYNTHETIC.password)
    code = int(const.CloudCode.NEED_VERIFY_CODE)
    fake_mega.error_bodies["validate_email"] = [(200, {"code": code, "msg": "x"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        with pytest.raises(LoginChallengeError) as exc:
            await EufyCloudApi(http, cache, SYNTHETIC.email, None, region="eu").async_login()
    assert (exc.value.kind, exc.value.code) == ("verify_code", code)
    assert fake_mega.login_calls == 0
    assert cache.password == SYNTHETIC.password


async def test_a_refused_check_of_an_extra_country_skips_only_that_scope(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    fake_mega.country_regions = {"DE": "eu", "FR": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country="DE", region=None).async_login()
        fake_mega.error_bodies["validate_email"] = [(200, {"code": 26501, "msg": "x"})]
        api = _api(http, cache, country=("DE", "FR"), region=None)
        await api.async_login()  # the extra scope is skipped, the home session stays
    assert api.refused_regions() == ["eu:FR"]
    assert fake_mega.login_calls == 1


async def test_a_lapsed_key_on_an_extra_country_check_is_no_refusal(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """Only a plain body code records the scope as refused, as for its login."""
    fake_mega.country_regions = {"DE": "eu", "FR": "eu"}
    rekey = int(const.CloudCode.NEED_NEGOTIATE_KEY)
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country="DE", region=None).async_login()
        fake_mega.error_bodies["validate_email"] = [(463, {"code": rekey, "msg": "x"})]
        api = _api(http, cache, country=("DE", "FR"), region=None)
        with pytest.raises(CloudApiError) as exc:
            await api.async_login()
    assert exc.value.code == rekey
    assert api.refused_regions() == []
    assert fake_mega.login_calls == 1


async def _logged_in_by_region(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """Sessions in both regions made with the region as ``ab`` (no country known)."""
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, region=None).async_login()
    assert cache.cloud_session("eu")["ab"] == "eu"
    fake_mega.calls.clear()
    fake_mega.region_calls.clear()


@pytest.mark.parametrize(
    "challenge",
    [int(const.CloudCode.NEED_VERIFY_CODE), int(const.CloudCode.LOGIN_NEED_CAPTCHA)],
    ids=["verify-code", "captcha"],
)
async def test_an_unattended_re_login_asks_for_nothing_when_the_check_is_challenged(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    challenge: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The one-time country re-login: a challenge on its account check e-mails no code,
    fetches no captcha, records no challenge and keeps the session."""
    await _logged_in_by_region(fake_mega, cache, http)
    token = cache.cloud_session("eu")["auth_token"]
    logins = fake_mega.login_calls
    fake_mega.country_regions = {"DE": "eu"}
    # A pending token in the answer: an interactive login would ask for the code with it.
    pending = {"auth_token": FAKE_PENDING_TOKEN, "user_id": SYNTHETIC.account_id}
    fake_mega.error_bodies["validate_email"] = [
        (200, {"code": challenge, "msg": "x", "login_id": "lid-9", "data": pending})
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache, country="DE", region=None)
        with caplog.at_level(logging.INFO, logger="eufy_home_security.cloud.api"):
            await api.async_login()
    assert f"account check needs a challenge answer (code {challenge})" in caplog.text
    assert len(_sent(fake_mega, "validate_email")) == 1
    assert fake_mega.login_calls == logins
    assert fake_mega.code_requests == []
    assert [name for name, _ in fake_mega.region_calls if name == "captcha"] == []
    assert api._challenge_region is None
    assert not cache.section("cloud").get("challenges")
    assert cache.cloud_session("eu")["auth_token"] == token
    assert cache.cloud_session("eu")["ab_wanted"] == "DE"  # not asked again for DE


async def test_an_unattended_re_login_of_an_extra_country_records_no_refusal(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """A plain body code on the re-login's check keeps the extra scope's session and does
    not skip the scope until a rescan."""
    fake_mega.country_regions = {"DE": "eu", "FR": "eu"}
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country=("DE", "FR"), region=None).async_login()
        session = cache.cloud_session("eu:FR")
        session["ab"] = session["ab_wanted"] = "XX"  # made with another ab
        token = session["auth_token"]
        fake_mega.calls.clear()
        logins = fake_mega.login_calls
        fake_mega.error_bodies["validate_email"] = [(200, {"code": 26501, "msg": "x"})]
        api = _api(http, cache, country=("DE", "FR"), region=None)
        await api.async_login()
    assert len(_sent(fake_mega, "validate_email")) == 1
    assert fake_mega.login_calls == logins
    assert api.refused_regions() == []
    assert cache.cloud_session("eu:FR")["auth_token"] == token
    assert cache.cloud_session("eu:FR")["ab_wanted"] == "FR"


async def test_a_country_fallback_login_reuses_the_check(
    fake_mega: FakeMega, cache: SessionCache, http: aiohttp.ClientSession
) -> None:
    """The region-``ab`` re-send is the same attempt: one check, two logins counted."""
    fake_mega.country_regions = {"DE": "eu"}
    fake_mega.enc_text = "sha2"
    fake_mega.account_password = SYNTHETIC.password
    fake_mega.error_bodies["login"] = [(200, {"code": 26501, "msg": "x"})]
    with aioresponses() as mock:
        fake_mega.install(mock)
        await _api(http, cache, country="DE", region=None).async_login()
    assert [body["ab"] for body in _sent(fake_mega, "login")] == ["DE", "eu"]
    assert len(_sent(fake_mega, "validate_email")) == 1
    assert fake_mega.login_passwords == [_SHA256]  # the refused one is not unwrapped
    assert _budget(cache) == 2


async def test_neither_the_password_nor_its_hash_is_logged(
    fake_mega: FakeMega,
    cache: SessionCache,
    http: aiohttp.ClientSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    fake_mega.two_step = {"eu"}
    fake_mega.enc_text = "sha2"
    fake_mega.account_password = SYNTHETIC.password
    with aioresponses() as mock:
        fake_mega.install(mock)
        api = _api(http, cache)
        with pytest.raises(LoginChallengeError):
            await api.async_login()
        await api.async_login(verify_code="123456")
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "the password's SHA-256 (enc_text sha2)" in logged
    assert SYNTHETIC.password not in logged
    assert _SHA256 not in logged
    assert SYNTHETIC.email not in logged
