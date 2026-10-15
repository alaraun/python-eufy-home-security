"""Arming groups: the cloud models, the request bodies, the parsing and name rules, and
EufyCloudApi's six calls on the security realm."""

from __future__ import annotations

from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security.cloud import arming, const
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.arming import (
    ArmingGroup,
    ArmingGroupList,
    ArmingGroupLog,
    ArmingGroupMember,
    ArmingGroupPreset,
    ArmingHouse,
)
from eufy_home_security.exceptions import CloudApiError, ProtocolError, UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.storage import SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import ARMING_ENDPOINTS, FakeMega

HOUSE = "house-1"
GROUP = "group-7"
PATH = const.ARMING_GROUPS_PATH


def _raw_group(**overrides: Any) -> dict[str, Any]:
    group = {
        "group_id": GROUP,
        "group_name": "Night",
        "status": "1",
        "default": 2,
        "devices": [
            {"device_sn": SYNTHETIC.station_sn, "mode": "Home", "mode_id": 1, "isBypass": False},
            {"device_sn": SYNTHETIC.camera_sn, "mode": "Porch", "mode_id": 4, "isBypass": True},
        ],
        "extra_key": "ignored",
    }
    return group | overrides


# ── parsing ──────────────────────────────────────────────────────────────────


def test_a_group_list_parses_members_modes_and_presets_and_ignores_unknown_keys() -> None:
    data = {"guided": 2, "groups": [_raw_group()], "new_field": []}
    listing = arming.parse_group_list(data, HOUSE, PATH)
    assert listing == ArmingGroupList(
        house_id=HOUSE,
        guided=2,
        groups=(
            ArmingGroup(
                group_id=GROUP,
                name="Night",
                status="1",
                preset=ArmingGroupPreset.STAYING,
                members=(
                    ArmingGroupMember(
                        device_sn=SYNTHETIC.station_sn, mode=GuardMode.HOME, title="Home"
                    ),
                    ArmingGroupMember(
                        device_sn=SYNTHETIC.camera_sn,
                        mode=GuardMode.CUSTOM_2,
                        title="Porch",
                        bypass=True,
                    ),
                ),
            ),
        ),
    )
    assert listing.groups[0].active
    assert SYNTHETIC.station_sn not in repr(listing.groups[0])
    assert "Night" not in repr(listing.groups[0])


def test_codes_the_library_does_not_name_stay_ints_and_absent_fields_default() -> None:
    entry = {
        "group_id": 12,
        "group_name": "",
        "default": 9,
        "devices": [{"device_sn": SYNTHETIC.station_sn, "mode_id": "99"}],
    }
    group = arming.parse_group(entry, PATH)
    assert (group.group_id, group.status, group.active, group.preset) == ("12", "0", False, 9)
    assert group.members == (ArmingGroupMember(device_sn=SYNTHETIC.station_sn, mode=99),)
    assert arming.parse_group({"group_id": "g", "group_name": "x"}, PATH).members == ()


@pytest.mark.parametrize(
    ("data", "listed"),
    [(None, ()), ({"guided": 0, "groups": None}, ()), ({"groups": []}, ())],
)
def test_no_data_or_no_groups_is_an_empty_list(data: object, listed: tuple[()]) -> None:
    assert arming.parse_group_list(data, HOUSE, PATH).groups == listed


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"guided": 2},
        {"groups": {}},
        {"groups": [{"group_name": "x"}]},
        {"groups": [{"group_id": "", "group_name": "x"}]},
        {"groups": [{"group_id": "g"}]},
        {"groups": [{"group_id": "g", "group_name": "x", "devices": {}}]},
        {"groups": [{"group_id": "g", "group_name": "x", "devices": [{"mode_id": 1}]}]},
        {"groups": [{"group_id": "g", "group_name": "x", "devices": [{"device_sn": "s"}]}]},
        {"groups": ["g"]},
    ],
)
def test_a_missing_required_key_is_a_protocol_error(data: object) -> None:
    with pytest.raises(ProtocolError):
        arming.parse_group_list(data, HOUSE, PATH)


def test_logs_keep_the_clouds_order_and_need_a_group_and_a_time() -> None:
    raw = {
        "logs": [
            {"group_id": GROUP, "group_name": "Night", "user_id": "u1", "user_name": "kim",
             "create_time": 1_700_000_100, "more": 1},
            {"group_id": GROUP, "create_time": "1700000000"},
        ]
    }  # fmt: skip
    assert arming.parse_logs(raw, PATH) == (
        ArmingGroupLog(
            group_id=GROUP,
            group_name="Night",
            user_id="u1",
            user_name="kim",
            create_time=1_700_000_100,
        ),
        ArmingGroupLog(group_id=GROUP, create_time=1_700_000_000),
    )
    assert arming.parse_logs(None, PATH) == arming.parse_logs({"logs": None}, PATH) == ()
    bad_logs: list[object] = [
        {"logs": {}},
        {"logs": [{"group_id": GROUP}]},
        {"logs": [{"create_time": 1}]},
    ]
    for bad in bad_logs:
        with pytest.raises(ProtocolError):
            arming.parse_logs(bad, PATH)


# ── names, modes, members ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "sent"),
    [
        ("  Night  ", "Night"),
        ("a" * 31, "a" * 31),
        ("Ö" * 31, "Ö" * 31),  # U+00D6 counts one
        ("夜" * 15 + "a", "夜" * 15 + "a"),  # 15 x 2 + 1
        ("Away (all) #1 @home.", "Away (all) #1 @home."),
    ],
)
def test_a_name_the_app_accepts_is_sent_trimmed(name: str, sent: str) -> None:
    assert arming.check_group_name(name) == sent


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        "a" * 32,
        "夜" * 16,
        "Night!",
        "a/b",
        "it's",
        "x\uff01",
        "Home \U0001f3e0",
        "\u2600",
    ],
)
def test_a_name_the_app_refuses_is_a_value_error(name: str) -> None:
    with pytest.raises(ValueError, match="arming group name"):
        arming.check_group_name(name)


def test_every_writable_mode_can_be_a_target_and_off_cannot() -> None:
    assert arming.target_modes({SYNTHETIC.station_sn: "away", SYNTHETIC.camera_sn: 63}) == {
        SYNTHETIC.station_sn: GuardMode.AWAY,
        SYNTHETIC.camera_sn: GuardMode.DISARMED,
    }
    for bad in (GuardMode.OFF, 7, "armed", True):
        with pytest.raises(ValueError, match="guard mode"):
            arming.target_mode(bad)
    with pytest.raises(ValueError, match="at least one member"):
        arming.target_modes({})


def test_members_must_be_stations_of_the_house_and_keep_a_stored_title() -> None:
    house = ArmingHouse(house_id=HOUSE, region="eu", stations=frozenset({SYNTHETIC.station_sn}))
    previous = arming.parse_group(
        _raw_group(devices=[{"device_sn": SYNTHETIC.station_sn, "mode": "Porch", "mode_id": 4}]),
        PATH,
    )
    assert arming.build_members(house, {SYNTHETIC.station_sn: GuardMode.CUSTOM_2}, previous) == (
        ArmingGroupMember(device_sn=SYNTHETIC.station_sn, mode=GuardMode.CUSTOM_2, title="Porch"),
    )
    assert arming.build_members(house, {SYNTHETIC.station_sn: GuardMode.AWAY}, previous) == (
        ArmingGroupMember(device_sn=SYNTHETIC.station_sn, mode=GuardMode.AWAY, title="Away"),
    )
    with pytest.raises(UnsupportedError, match="not a station"):
        arming.build_members(house, {SYNTHETIC.camera_sn: GuardMode.AWAY})


def test_house_rules_unique_names_known_groups_and_professional_arming() -> None:
    listing = arming.parse_group_list({"groups": [_raw_group()]}, HOUSE, PATH)
    with pytest.raises(ValueError, match="already has"):
        arming.check_unique_name(listing, "Night")
    arming.check_unique_name(listing, "Night", group_id=GROUP)  # its own name
    arming.check_unique_name(listing, "night")
    assert arming.find_group(listing, GROUP).name == "Night"
    with pytest.raises(UnsupportedError, match="no arming group"):
        arming.find_group(listing, "other")
    assert arming.uses_professional_arming(["T9000P1000000001", SYNTHETIC.station_sn])
    assert not arming.uses_professional_arming([SYNTHETIC.station_sn, SYNTHETIC.camera_sn])


def test_every_writable_guard_mode_has_a_title() -> None:
    assert set(arming.MODE_TITLES) == set(GuardMode) - {GuardMode.OFF}
    assert arming.mode_title(GuardMode.GEOFENCE) == "Geofencing"
    assert arming.mode_title(99) == "99"


# ── the calls on the security realm ──────────────────────────────────────────


def _api(session: aiohttp.ClientSession, cache: SessionCache) -> EufyCloudApi:
    return EufyCloudApi(session, cache, SYNTHETIC.email, SYNTHETIC.password, region="eu")


_MEMBERS = (
    ArmingGroupMember(device_sn=SYNTHETIC.station_sn, mode=GuardMode.AWAY),
    ArmingGroupMember(device_sn=SYNTHETIC.camera_sn, mode=GuardMode.CUSTOM_1, title="Porch"),
)
_SENT_MEMBERS = [
    {"device_sn": SYNTHETIC.station_sn, "mode": "Away", "mode_id": 0},
    {"device_sn": SYNTHETIC.camera_sn, "mode": "Porch", "mode_id": 3},
]


async def test_the_six_calls_send_the_apps_bodies_on_the_security_realm(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.arming_data = {
        "guard_list": {"guided": 2, "groups": [_raw_group()]},
        "get_guard_logs": {"logs": [{"group_id": GROUP, "create_time": 5}]},
    }
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            listing = await api.async_list_arming_groups(HOUSE, region="eu")
            await api.async_add_arming_group(HOUSE, "Night", _MEMBERS, region="eu")
            await api.async_update_arming_group(HOUSE, GROUP, region="eu", name="Late")
            await api.async_update_arming_group(HOUSE, GROUP, region="eu", members=_MEMBERS)
            await api.async_delete_arming_group(HOUSE, GROUP, region="eu")
            await api.async_activate_arming_group(HOUSE, GROUP, region="eu")
            logs = await api.async_arming_group_logs(HOUSE, GROUP, region="eu")
            with pytest.raises(ValueError, match="name or members"):
                await api.async_update_arming_group(HOUSE, GROUP, region="eu")
    endpoints = set(ARMING_ENDPOINTS.values())
    sent = [(name, body) for name, body in fake_mega.calls if name in endpoints]
    assert sent == [
        ("guard_list", {"house_id": HOUSE}),
        ("add_guard", {"house_id": HOUSE, "group_name": "Night", "devices": _SENT_MEMBERS,
                       "default": 0}),
        ("update_guard", {"house_id": HOUSE, "group_id": GROUP, "group_name": "Late"}),
        ("update_guard", {"house_id": HOUSE, "group_id": GROUP, "devices": _SENT_MEMBERS}),
        ("delete_guard", {"house_id": HOUSE, "group_id": GROUP}),
        ("setup_guard", {"house_id": HOUSE, "group_id": GROUP,
                         "user_name": SYNTHETIC.email.split("@")[0], "enable": True}),
        ("get_guard_logs", {"house_id": HOUSE, "group_id": GROUP}),
    ]  # fmt: skip
    assert fake_mega.refused == []  # a security-realm identity on every call
    assert all(
        h["category"] == const.CATEGORY
        for name in endpoints
        for h in fake_mega.headers.get(name, [])
    )
    assert listing.house_id == HOUSE
    assert [g.group_id for g in listing.groups] == [GROUP]
    assert logs == (ArmingGroupLog(group_id=GROUP, create_time=5),)


async def test_a_refused_activation_raises_the_clouds_error(
    fake_mega: FakeMega, cache: SessionCache
) -> None:
    fake_mega.code_once["setup_guard"] = 31001
    with aioresponses() as mock:
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as session:
            api = _api(session, cache)
            await api.async_login()
            with pytest.raises(CloudApiError) as caught:
                await api.async_activate_arming_group(HOUSE, GROUP, region="eu", user_name="kim")
    assert caught.value.code == 31001
    assert [body for name, body in fake_mega.calls if name == "setup_guard"] == [
        {"house_id": HOUSE, "group_id": GROUP, "user_name": "kim", "enable": True}
    ]
