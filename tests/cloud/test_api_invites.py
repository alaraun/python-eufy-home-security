"""EufyCloudApi.async_accept_invite: the eufy app's accept requests and its code check."""

from __future__ import annotations

from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import const, crypto
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.models import CloudInvite
from eufy_home_security.exceptions import CloudApiError, InviteCodeError, UnsupportedError
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import FakeMega

CODE = "482913"
OWNER = "owner-user-1"
SUB_SNS = "sub-sn-1"


def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


def _bodies(fake_mega: FakeMega, endpoint: str) -> list[dict[str, Any]]:
    return [payload for name, payload in fake_mega.calls if name == endpoint]


def _device_entry(invite_id: int = 3, **extra: Any) -> dict[str, Any]:
    return {
        "id": invite_id,
        "device_sn": SYNTHETIC.camera_sn,
        "product_code": "T8160",
        "user_id": OWNER,
        "category": "eufy_security",
        "sub_sns": "",
        **extra,
    }


async def _listed(
    fake_mega: FakeMega, cache: SessionCache, *, houses: list[Any], devices: list[Any]
) -> list[CloudInvite]:
    fake_mega.invite_data = {
        "house_invites": {"house_invite_records": houses},
        "device_invites": {"invites": devices},
    }
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            return await api.async_list_invites("eu")


async def _accept(
    fake_mega: FakeMega, cache: SessionCache, invite: CloudInvite, code: str | None = None
) -> None:
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            await api.async_accept_invite(invite, code=code)


def _accepts(fake_mega: FakeMega) -> list[dict[str, Any]]:
    return _bodies(fake_mega, "accept_house_invite") + _bodies(fake_mega, "accept_device_invite")


async def test_a_home_invitation_is_accepted_with_the_apps_body(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    (home,) = await _listed(
        fake_mega,
        cache,
        houses=[{"id": 7, "house_id": "house-9", "house_name": "Cottage", "user_id": OWNER}],
        devices=[],
    )
    await _accept(fake_mega, cache, home)
    (body,) = _bodies(fake_mega, "accept_house_invite")
    assert body.pop("transaction")
    assert body == {
        "categories": [],
        "add_pns": [],
        "house_id": "house-9",
        "invite_id": 7,
        "is_inviter": const.INVITES_RECEIVED,
    }
    assert _bodies(fake_mega, "accept_device_invite") == []


async def test_a_device_invitation_is_accepted_with_the_apps_body(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    (device,) = await _listed(
        fake_mega,
        cache,
        houses=[],
        devices=[_device_entry(sub_sns=SUB_SNS, category="eufy_care")],
    )
    await _accept(fake_mega, cache, device)
    (body,) = _bodies(fake_mega, "accept_device_invite")
    assert body.pop("transaction")
    assert body == {
        "invites": [
            {
                "category": "eufy_care",
                "device_sn": SYNTHETIC.camera_sn,
                "invite_id": 3,
                "owner_user_id": OWNER,
                "sub_sns": SUB_SNS,
            }
        ]
    }


async def test_a_device_invitation_without_category_or_owner_sends_the_apps_defaults(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    entry = {"id": 3, "device_sn": SYNTHETIC.camera_sn}
    (device,) = await _listed(fake_mega, cache, houses=[], devices=[entry])
    await _accept(fake_mega, cache, device)
    ((sent,),) = [b["invites"] for b in _bodies(fake_mega, "accept_device_invite")]
    assert sent == {
        "category": const.INVITE_CATEGORY_DEFAULT,
        "device_sn": SYNTHETIC.camera_sn,
        "invite_id": 3,
        "owner_user_id": "",
        "sub_sns": "",
    }


async def test_a_code_invitation_is_accepted_with_its_code_which_is_not_sent(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    sealed = crypto.invite_seal(CODE, "share")
    (home,) = await _listed(
        fake_mega,
        cache,
        houses=[{"id": 7, "house_id": "house-9", "encrypted_data": sealed}],
        devices=[],
    )
    assert home.needs_code
    await _accept(fake_mega, cache, home, CODE)
    (body,) = _bodies(fake_mega, "accept_house_invite")
    assert CODE not in str(body)
    assert sealed not in str(body)


@pytest.mark.parametrize(("code", "missing"), [(None, True), ("", True), ("482914", False)])
async def test_a_code_invitation_without_the_right_code_sends_nothing(
    fake_mega: FakeMega, cache: SessionCache, code: str | None, missing: bool
) -> None:
    (device,) = await _listed(
        fake_mega,
        cache,
        houses=[],
        devices=[_device_entry(encrypted_data=crypto.invite_seal(CODE, "share"))],
    )
    with pytest.raises(InviteCodeError) as caught:
        await _accept(fake_mega, cache, device, code)
    assert caught.value.missing is missing
    assert _accepts(fake_mega) == []


async def test_an_owners_code_covers_each_of_that_owners_device_invitations(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    """The app asks one code for every pending invitation of the owner that set it."""
    sealed = crypto.invite_seal(CODE, "share")
    other = crypto.invite_seal("111111", "share")
    first, coded, plain, second_code = await _listed(
        fake_mega,
        cache,
        houses=[],
        devices=[
            _device_entry(1),
            _device_entry(2, encrypted_data=sealed),
            _device_entry(3, user_id="owner-user-2"),
            _device_entry(4, encrypted_data=other),
        ],
    )
    assert (first.encrypted_data, coded.encrypted_data) == (sealed, sealed)
    assert not plain.needs_code
    assert second_code.encrypted_data == other
    with pytest.raises(InviteCodeError):
        await _accept(fake_mega, cache, first)
    await _accept(fake_mega, cache, first, CODE)
    assert [b["invites"][0]["invite_id"] for b in _accepts(fake_mega)] == [1]


async def test_an_invitation_without_an_owner_takes_no_other_code(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    sealed = crypto.invite_seal(CODE, "share")
    coded, plain = await _listed(
        fake_mega,
        cache,
        houses=[],
        devices=[
            _device_entry(1, user_id=None, encrypted_data=sealed),
            _device_entry(2, user_id=None),
        ],
    )
    assert coded.needs_code
    assert not plain.needs_code


@pytest.mark.parametrize("category", sorted(const.INVITE_CATEGORIES_OTHER_SDK))
async def test_an_appliance_invitation_is_left_to_the_app(
    fake_mega: FakeMega, cache: SessionCache, category: str
) -> None:
    (device,) = await _listed(
        fake_mega, cache, houses=[], devices=[_device_entry(category=category)]
    )
    with pytest.raises(UnsupportedError):
        await _accept(fake_mega, cache, device)
    assert _accepts(fake_mega) == []


@pytest.mark.parametrize(
    "invite",
    [
        CloudInvite(kind="house", region="eu", house_id="house-9"),
        CloudInvite(kind="house", region="eu", invite_id=7),
        CloudInvite(kind="device", region="eu", device_sn=SYNTHETIC.camera_sn),
        CloudInvite(kind="device", region="eu", invite_id=3, device_sn=""),
    ],
)
async def test_an_invitation_without_its_ids_sends_nothing(
    fake_mega: FakeMega, cache: SessionCache, invite: CloudInvite
) -> None:
    with pytest.raises(UnsupportedError):
        await _accept(fake_mega, cache, invite)
    assert _accepts(fake_mega) == []


async def test_a_refused_accept_raises(fake_mega: FakeMega, cache: SessionCache) -> None:
    (device,) = await _listed(fake_mega, cache, houses=[], devices=[_device_entry()])
    fake_mega.code_once["accept_device_invite"] = 10000
    with pytest.raises(CloudApiError):
        await _accept(fake_mega, cache, device)
