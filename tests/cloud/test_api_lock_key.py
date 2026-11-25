"""EufyCloudApi's lock public key (``app/public_key/query``): a signed GET, cached."""

from __future__ import annotations

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.exceptions import EmptyResponseError, ProtocolError
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FakeMega

LOCK = "T8520P2000000001"
KEY = bytes(range(64))


async def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    await cache.async_load()
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


def _queries(fake: FakeMega) -> list[dict[str, object]]:
    return [dict(body) for name, body in fake.calls if name == "public_key"]


async def test_public_key_is_a_signed_get_on_the_security_host(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.lock_public_keys[(LOCK, 2)] = KEY.hex()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            key = await api.async_get_lock_public_key(LOCK, 2)
    assert key == KEY
    assert _queries(fake_mega) == [{"device_sn": LOCK, "type": "2"}]
    headers = fake_mega.headers["public_key"][0]
    assert headers["host"] == const.security_host("eu")
    assert headers["category"] == headers["app-tab"] == "eufy_security"
    assert fake_mega.refused == []


async def test_public_key_is_asked_once_per_lock_and_type(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.lock_public_keys[(LOCK, 2)] = KEY.hex()
    fake_mega.lock_public_keys[(LOCK, 3)] = ("04" + KEY.hex()).upper()
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            first = await api.async_get_lock_public_key(LOCK, 2)
            again = await api.async_get_lock_public_key(LOCK, 2)
            ecdh = await api.async_get_lock_public_key(LOCK, 3)
    assert first == again == KEY
    assert ecdh == b"\x04" + KEY
    assert [q["type"] for q in _queries(fake_mega)] == ["2", "3"]


async def test_no_public_key_raises_empty_response_and_is_not_cached(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            with pytest.raises(EmptyResponseError, match="public key"):
                await api.async_get_lock_public_key(LOCK, 2)
            fake_mega.lock_public_keys[(LOCK, 2)] = KEY.hex()
            assert await api.async_get_lock_public_key(LOCK, 2) == KEY
    assert len(_queries(fake_mega)) == 2


@pytest.mark.parametrize("answer", ["", "zz", "abc"])
async def test_a_public_key_that_is_no_hex_raises(
    fake_mega: FakeMega, cache: SessionCache, answer: str
) -> None:
    fake_mega.lock_public_keys[(LOCK, 2)] = answer
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = await _api(session, cache)
            with pytest.raises((ProtocolError, EmptyResponseError)):
                await api.async_get_lock_public_key(LOCK, 2)
