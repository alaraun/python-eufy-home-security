"""EufyCloudApi's MQTT certificate: the request, the answer, the cache rules."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.models import MqttCertificate
from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.mqtt import MqttTestPki, make_mqtt_pki

from .conftest import FakeMega


@pytest.fixture(scope="module")
def pki() -> MqttTestPki:
    return make_mqtt_pki()


async def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    await cache.async_load()
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


def _registers(fake: FakeMega) -> list[dict[str, Any]]:
    return [body for name, body in fake.calls if name == "mqtt_register"]


# ── the request ──────────────────────────────────────────────────────────────


async def test_register_posts_an_empty_body_to_the_mega_domain_with_the_app_tab(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            certificate = await api.async_register_iot()
    assert _registers(fake_mega) == [{}]
    headers = fake_mega.headers["mqtt_register"][0]
    assert headers["host"] == const.mega_host("eu")
    assert headers["app-tab"] == "eufy_security"
    assert headers["x-auth-token"]
    assert certificate.endpoint == "127.0.0.1"
    assert certificate.certificate_pem == pki.client_cert_pem
    assert certificate.private_key == pki.client_key_pem
    assert certificate.user_id == SYNTHETIC.account_id
    assert certificate.app_name == "eufy_security"
    assert certificate.thing_name == "synthetic-thing"


async def test_register_goes_to_the_sessions_own_mega_domain(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    own = "mega-eu-pr2.eufy.com"
    fake_mega.login_data["mega_domain"] = own
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        fake_mega.install_mqtt_register(mock, own, "eu")
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            await api.async_register_iot()
    assert [h["host"] for h in fake_mega.headers["mqtt_register"]] == [own]


async def test_a_session_domain_of_another_cluster_is_not_used(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.login_data["mega_domain"] = "mega-us-pr.eufy.com"
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            await api.async_register_iot()
    assert [h["host"] for h in fake_mega.headers["mqtt_register"]] == [const.mega_host("eu")]


@pytest.mark.parametrize(
    "missing", ["certificate_pem", "private_key", "endpoint_addr", "user_id", "app_name"]
)
async def test_an_answer_without_a_needed_field_is_a_protocol_error(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki, missing: str
) -> None:
    fake_mega.mqtt_answer = pki.register_answer(**{missing: ""})
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            with pytest.raises(ProtocolError, match=missing):
                await api.async_register_iot()


async def test_an_answer_without_data_is_a_protocol_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.mqtt_answer = None
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            with pytest.raises(ProtocolError):
                await api.async_register_iot()


# ── secrets ──────────────────────────────────────────────────────────────────


async def test_the_secrets_never_reach_the_debug_log_or_the_repr(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki, caplog: pytest.LogCaptureFixture
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    caplog.set_level(logging.DEBUG)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            certificate = await api.async_register_iot()
    assert certificate.endpoint not in repr(certificate)
    text = caplog.text + repr(certificate)
    assert "/app/mqtt/register/iot" in caplog.text  # the answer was logged
    for secret in (
        pki.client_key_pem.splitlines()[1],
        pki.client_cert_pem.splitlines()[1],
        "synthetic-pkcs12",
        "synthetic-public-key",
    ):
        assert secret not in text


def test_the_client_id_is_the_apps_shape_with_the_given_install_id(pki: MqttTestPki) -> None:
    certificate = MqttCertificate.from_api(pki.register_answer(app_name="eufy_security"))
    assert certificate.client_id("0011223344556677") == (
        f"android-eufy_security-{SYNTHETIC.account_id}-0011223344556677"
    )


async def test_the_api_names_the_client_id_with_its_own_install_id(
    pki: MqttTestPki,
) -> None:
    cache = SessionCache(MemoryStore(), SYNTHETIC.email)
    await cache.async_load()
    async with aiohttp.ClientSession() as session:
        api = EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")
        certificate = MqttCertificate.from_api(pki.register_answer())
        assert api.mqtt_client_id(certificate) == certificate.client_id(cache.openudid)
        # An extra country's scope has an install id of its own.
        scope = f"eu{const.SCOPE_SEPARATOR}FR"
        other = api.mqtt_client_id(certificate, scope)
        assert other == certificate.client_id(api._install_id(scope))
        assert other != api.mqtt_client_id(certificate)


# ── the cached certificate (the app's reuse and re-issue rules) ──────────────

_KEYS = ("T85D0P2000054321-1700000000",)


async def _issue_count(fake: FakeMega) -> int:
    return len(_registers(fake))


async def test_the_first_certificate_is_fetched_and_kept_with_the_device_set(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            first = await api.async_mqtt_certificate(_KEYS)
            again = await api.async_mqtt_certificate(list(reversed(_KEYS)))
    assert first == again
    assert await _issue_count(fake_mega) == 1
    assert cache.mqtt_devices("eu") == frozenset(_KEYS)
    assert cache.mqtt_certificate("eu") == first.as_cache()


async def test_a_restart_reuses_the_stored_certificate_without_a_request(
    fake_mega: FakeMega, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    store = MemoryStore()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            first = await (
                await _api(session, SessionCache(store, SYNTHETIC.email))
            ).async_mqtt_certificate(_KEYS)
            later = await (
                await _api(session, SessionCache(store, SYNTHETIC.email))
            ).async_mqtt_certificate(_KEYS)
    assert first == later
    assert await _issue_count(fake_mega) == 1


async def test_a_changed_device_set_issues_a_new_certificate(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer(certificate_id="1" * 64)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            await api.async_mqtt_certificate(_KEYS)
            fake_mega.mqtt_answer = pki.register_answer(certificate_id="2" * 64)
            # A re-paired lock keeps its serial and gets a new bind time.
            rebound = ("T85D0P2000054321-1700000999",)
            second = await api.async_mqtt_certificate(rebound)
    assert second.certificate_id == "2" * 64
    assert await _issue_count(fake_mega) == 2
    assert cache.mqtt_devices("eu") == frozenset(rebound)
    assert cache.mqtt_certificate("eu") == second.as_cache()


async def test_a_failed_reissue_keeps_the_cached_certificate_and_the_new_set(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    more = (*_KEYS, "T85L0P2000054322-1700000001")
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            first = await api.async_mqtt_certificate(_KEYS)
            fake_mega.code_once["mqtt_register"] = 10000
            kept = await api.async_mqtt_certificate(more)
            # The set was stored before the refresh: the same set asks nothing again.
            again = await api.async_mqtt_certificate(more)
    assert kept == first == again
    assert await _issue_count(fake_mega) == 2
    assert cache.mqtt_devices("eu") == frozenset(more)


async def test_a_failed_first_fetch_raises(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer(private_key="")
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            with pytest.raises(ProtocolError):
                await api.async_mqtt_certificate(_KEYS)
    assert cache.mqtt_certificate("eu") is None


async def test_a_dropped_certificate_is_fetched_again_for_the_same_set(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            await api.async_mqtt_certificate(_KEYS)
            await api.async_drop_mqtt_certificate()
            assert cache.mqtt_certificate("eu") is None
            await api.async_mqtt_certificate(_KEYS)
    assert await _issue_count(fake_mega) == 2


async def test_a_refresh_fetches_for_the_same_set_and_falls_back_on_failure(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer(certificate_id="1" * 64)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            first = await api.async_mqtt_certificate(_KEYS)
            fake_mega.mqtt_answer = pki.register_answer(certificate_id="2" * 64)
            fresh = await api.async_mqtt_certificate(_KEYS, refresh=True)
            fake_mega.code_once["mqtt_register"] = 10000
            kept = await api.async_mqtt_certificate(_KEYS, refresh=True)
    assert first.certificate_id == "1" * 64
    assert fresh.certificate_id == kept.certificate_id == "2" * 64
    assert await _issue_count(fake_mega) == 3


async def test_a_malformed_cached_certificate_is_fetched_again(
    fake_mega: FakeMega, cache: SessionCache, pki: MqttTestPki
) -> None:
    fake_mega.mqtt_answer = pki.register_answer()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            await api.async_mqtt_certificate(_KEYS)
            cache.set_mqtt_certificate("eu", {"user_id": SYNTHETIC.account_id})
            await api.async_mqtt_certificate(_KEYS)
    assert await _issue_count(fake_mega) == 2


def test_the_cache_summary_names_no_certificate_value(pki: MqttTestPki) -> None:
    cache = SessionCache(MemoryStore(), SYNTHETIC.email)
    certificate = MqttCertificate.from_api(pki.register_answer())
    cache.set_mqtt_certificate("eu", certificate.as_cache())
    cache.set_mqtt_devices("eu", _KEYS)
    text = repr(cache.redacted_summary())
    assert "mqtt" in text
    for value in (pki.client_key_pem.splitlines()[1], SYNTHETIC.account_id, _KEYS[0]):
        assert value not in text
