"""EufyCloudApi's read-only lists: houses, house-scoped devices, pending invitations, the
security realm's station and device lists, the cipher-table sweep, and ``login=False``."""

from __future__ import annotations

import logging
import time

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.exceptions import NoCachedSessionError, SessionRejectedError
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC, security_device, security_station

from .conftest import FAKE_ECC_KEY, FAKE_OWNER_ID, FakeMega


def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


def _bodies(fake_mega: FakeMega, endpoint: str) -> list[dict[str, object]]:
    return [payload for name, payload in fake_mega.calls if name == endpoint]


async def test_house_list_and_a_house_scoped_device_list(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.houses = [
        {"house_id": "house-1", "house_name": "Home", "admin_user_id": FAKE_OWNER_ID,
         "member_type": 1, "is_default": 1},
    ]  # fmt: skip
    fake_mega.house_devices = {"house-1": [{"device_sn": SYNTHETIC.camera_sn, "device_type": 9}]}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            houses = await api.async_list_houses("eu")
            devices = await api.async_list_house_devices("eu", houses[0].house_id)
    assert [(h.house_id, h.owner_user_id, h.member_type, h.is_default) for h in houses] == [
        ("house-1", FAKE_OWNER_ID, 1, True)
    ]
    assert "house-1" not in repr(houses[0])
    assert [(d.device_sn, d.region, d.source) for d in devices] == [
        (SYNTHETIC.camera_sn, "eu", "house")
    ]
    assert _bodies(fake_mega, "devices") == [
        {"house_id": "house-1", "categories": [], "add_pns": []}
    ]
    assert cache.cached_devices() is None  # a listing is never cached


async def test_the_account_wide_house_list_sends_the_librarys_body(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.devices = [{"device_sn": SYNTHETIC.station_sn, "device_type": 18}]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            devices = await api.async_list_house_devices("eu")
    assert [d.device_sn for d in devices] == [SYNTHETIC.station_sn]
    assert _bodies(fake_mega, "devices") == [{"device_sn": ""}]


async def test_pending_invitations_of_homes_and_devices(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.invite_data = {
        "house_invites": {"house_invite_records": [
            {"id": 7, "house_id": "house-9", "house_name": "Cottage", "action_user_nick": "Kim"},
        ]},
        "device_invites": {"invites": [
            {"id": 3, "device_sn": SYNTHETIC.camera_sn, "product_code": "T8160",
             "action_user_email": "kim@example.invalid", "create_time": 1700000000},
        ]},
    }  # fmt: skip
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            home, device = await api.async_list_invites("eu")
    assert (home.kind, home.invite_id, home.house_id, home.house_name, home.inviter) == (
        "house",
        7,
        "house-9",
        "Cottage",
        "Kim",
    )
    assert (device.kind, device.device_sn, device.product_code, device.inviter) == (
        "device",
        SYNTHETIC.camera_sn,
        "T8160",
        "kim@example.invalid",
    )
    assert device.as_redacted_dict() == {
        "kind": "device",
        "region": "eu",
        "device_sn": "T8160***7890",
        "product_code": "T8160",
        "created_at": 1700000000,
    }
    for secret in ("house-9", "Cottage", "Kim", "kim@", SYNTHETIC.camera_sn):
        assert secret not in repr([home, device])
    for endpoint in ("house_invites", "device_invites"):
        (body,) = _bodies(fake_mega, endpoint)
        assert body["is_inviter"] == const.INVITES_RECEIVED
        assert body["transaction"]
    assert _bodies(fake_mega, "device_invites")[0]["categories"] == []


async def test_house_and_invitation_answers_are_logged_as_counts(
    fake_mega: FakeMega, cache: SessionCache, caplog: pytest.LogCaptureFixture
) -> None:
    """Names, nicknames and locations stay out of the debug log; the wire dump has them."""
    fake_mega.houses = [{"house_id": "house-1", "house_name": "Cottage", "latitude": 59.4372}]
    fake_mega.invite_data = {
        "house_invites": {"house_invite_records": [
            {"id": 7, "house_id": "house-9", "house_name": "Lakeside", "action_user_nick": "Kim"},
        ]},
        "device_invites": {"invites": [
            {"id": 3, "action_user_nick": "Robin", "action_user_email": "kim@example.invalid"},
        ]},
    }  # fmt: skip
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.cloud.api")
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_list_houses("eu")
            await api.async_list_invites("eu")
    logged = "\n".join(
        r.getMessage() for r in caplog.records if r.name == "eufy_home_security.cloud.api"
    )
    for private in ("Cottage", "Lakeside", "Kim", "Robin", "59.4372", "kim@"):
        assert private not in logged
    for summary in ("<1 house_infos>", "<1 house_invite_records>", "<1 invites>"):
        assert summary in logged


@pytest.mark.parametrize("data", [None, {"house_invite_records": None}, {}])
async def test_no_invitation_list_is_no_invitations(
    fake_mega: FakeMega, cache: SessionCache, data: object
) -> None:
    fake_mega.invite_data = {"house_invites": data, "device_invites": {"invites": None}}
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_list_invites("eu") == []


async def test_security_lists_map_to_house_shaped_devices(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.security_stations = [security_station(params={1103: "5"})]
    fake_mega.security_devices = [security_device()]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            stations = await api.async_list_security_devices("eu", stations=True)
            devices = await api.async_list_security_devices("eu", stations=False)
    (station,) = stations
    assert (station.device_sn, station.name, station.station_sn, station.source) == (
        SYNTHETIC.station_sn,
        "Home Base",
        None,
        "security",
    )
    assert station.is_station
    assert [(p.param_id, p.value) for p in station.cloud_params] == [(1103, "5")]
    (camera,) = devices
    assert (camera.device_sn, camera.station_sn, camera.channel, camera.region) == (
        SYNTHETIC.camera_sn,
        SYNTHETIC.station_sn,
        0,
        "eu",
    )
    body = _bodies(fake_mega, "security_stations")[0]
    assert {k: body[k] for k in ("device_sn", "station_sn", "num", "page", "orderby")} == {
        "device_sn": "",
        "station_sn": "",
        "num": const.SECURITY_LIST_PAGE,
        "page": 0,
        "orderby": "",
    }
    assert body["event_num_type"] == 1
    assert body["transaction"]
    for endpoint in ("security_stations", "security_devices"):
        assert fake_mega.headers[endpoint][0]["category"] == const.CATEGORY


async def test_an_empty_security_list_is_no_devices(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_list_security_devices("eu", stations=True) == []
            assert await api.async_list_houses("eu") == []


async def test_cipher_sweep_reads_the_whole_table_without_caching(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.cipher_objects = [
        {"cipher_id": 13, "ecc_private_key": "", "private_key": "x"},
        {"cipher_id": 40, "ecc_private_key": FAKE_ECC_KEY},
        {"no_cipher_id": True},
    ]
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            records = await api.async_list_ciphers(SYNTHETIC.station_sn, FAKE_OWNER_ID)
    assert [(r.cipher_id, r.ecc_state) for r in records] == [(13, "absent"), (40, "usable")]
    (body,) = _bodies(fake_mega, "ciphers")
    assert body == {
        "cipher_ids": list(const.CIPHER_ID_SWEEP),
        "user_id": FAKE_OWNER_ID,
        "station_sn": SYNTHETIC.station_sn,
    }
    assert cache.cipher_key(SYNTHETIC.station_sn, 40) is None
    assert FAKE_ECC_KEY not in repr(records)


async def test_an_empty_cipher_answer_is_an_empty_table(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert await api.async_list_ciphers(SYNTHETIC.station_sn, FAKE_OWNER_ID, [41]) == []


async def test_without_login_no_session_refuses_before_sending(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await cache.async_load()
            assert api.regions_with_session() == []
            with pytest.raises(NoCachedSessionError):
                await api.async_list_houses("eu", login=False)
            with pytest.raises(NoCachedSessionError):
                await api.async_list_security_devices("eu", stations=True, login=False)
    assert fake_mega.login_calls == 0
    assert fake_mega.calls == []


async def test_without_login_an_expired_token_is_not_logged_in_again(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.code_once["houses"] = int(const.CloudCode.SESSION_TIMEOUT)
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            assert api.regions_with_session() == ["eu"]
            with pytest.raises(SessionRejectedError):
                await api.async_list_houses("eu", login=False)
    assert fake_mega.login_calls == 1


async def test_a_cached_session_counts_until_it_expires(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            await _api(session, cache).async_login()
            fresh = _api(session, cache)
            assert fresh.regions_with_session() == ["eu"]
            cache.cloud_session("eu")["expires_at"] = time.time()
            assert fresh.regions_with_session() == []
