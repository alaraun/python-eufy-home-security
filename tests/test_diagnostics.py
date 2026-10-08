"""The account report: every list, merged per device, cipher state without keys; the
client's login-free pending-invitations read."""

from __future__ import annotations

import json
from typing import Any

from eufy_home_security import EufySecurity, redact_serial
from eufy_home_security.cloud import const
from eufy_home_security.diagnostics import (
    CAMERA_INFO_PARAM,
    HOUSE,
    INVITES,
    SECURITY_DEVICES,
    SECURITY_STATIONS,
    house_source,
)
from eufy_home_security.exceptions import RateLimitedError
from eufy_home_security.storage import MemoryStore
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    camera_device,
    security_device,
    security_station,
    station_device,
    warm_store,
)

# A HomeBase 2 and its camera that only the security realm lists, owned by another
# account; synthetic serials.
_HB2_SN = "T8010P2000054321"
_HB2_CAMERA_SN = "T8114P2000054321"
_OTHER_OWNER = "fedcba9876543210fedcba9876543210fedcba98"
_ECC = "ab" * 32


def _cloud() -> FakeCloud:
    pem = FakeStation(SYNTHETIC.station_sn).rsa_private_key_pem
    return FakeCloud(
        devices=[station_device(), camera_device()],
        owner_ids={SYNTHETIC.station_sn: SYNTHETIC.account_id, _HB2_SN: _OTHER_OWNER},
        houses=[{"house_id": "house-1", "admin_user_id": _OTHER_OWNER, "member_type": 1}],
        house_devices={"house-1": [security_device(_HB2_CAMERA_SN, station_sn=_HB2_SN)]},
        house_invites=[
            {"id": 4, "house_id": "house-2", "house_name": "Cottage", "action_user_nick": "Kim"}
        ],
        security_stations=[
            security_station(_HB2_SN, did="EUPRAMA-654321-ABCDE", params={CAMERA_INFO_PARAM: "5"})
        ],
        security_devices=[
            security_device(_HB2_CAMERA_SN, station_sn=_HB2_SN),
            {**camera_device(), "main_hw_version": "H2", "device_model": "T8160"},
        ],
        cipher_records={
            40: {"ecc_private_key": _ECC, "private_key": pem.lower()},
            98: {"ecc_private_key": _ECC, "private_key": pem},
            13: {"private_key": pem.lower()},
        },
        cipher_ids_held=set(),
    )


def _client(cloud: FakeCloud, store: MemoryStore | None = None) -> EufySecurity:
    store = store or warm_store(email=SYNTHETIC.email, cloud=cloud)
    return build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud)


def _by_serial(report: dict[str, Any], serial: str) -> dict[str, Any]:
    devices: list[dict[str, Any]] = report["devices"]
    (device,) = (d for d in devices if d["device_sn"] == redact_serial(serial))
    return device


async def test_every_list_is_asked_and_merged_per_device() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    report = (await eufy.async_account_report()).as_dict()

    assert report["regions"] == ["eu", "us"]
    assert report["regions_without_session"] == []
    assert report["stopped"] is None
    eu = {(r["source"], r["entries"]) for r in report["listings"] if r["region"] == "eu"}
    assert eu == {
        (HOUSE, 2),
        ("houses", 1),
        (INVITES, 1),
        (SECURITY_STATIONS, 1),
        (SECURITY_DEVICES, 2),
    }
    assert report["invites"] == [
        {
            "region": "eu",
            "kind": "house",
            "device_sn": None,
            "product_code": None,
            "created_at": None,
        }
    ]
    assert report["houses"] == [
        {
            "region": "eu",
            "index": 1,
            "is_default": False,
            "member_type": 1,
            "account_is_owner": False,
            "devices": 1,
            "error": None,
        }
    ]

    camera = _by_serial(report, SYNTHETIC.camera_sn)
    assert camera["listed_by"] == [HOUSE, SECURITY_DEVICES]
    assert camera["main_hw_version"] == "H2"  # only the security list carries it
    assert camera["connect_type"] == "HB3"
    assert camera["model_support"] is not None

    hb2 = _by_serial(report, _HB2_SN)
    assert hb2["listed_by"] == [SECURITY_STATIONS]
    assert hb2["is_station"]
    assert hb2["camera_info"] == 5
    assert hb2["param_ids"] == [CAMERA_INFO_PARAM]
    assert (hb2["main_sw_version"], hb2["main_hw_version"]) == ("2.1.6.9h", "P1")
    assert hb2["owner"] == "owner 1"
    assert hb2["cloud_model"] is None
    assert camera["cloud_model"] == "T8160"
    assert not hb2["account_is_owner"]
    hb2_camera = _by_serial(report, _HB2_CAMERA_SN)
    assert hb2_camera["listed_by"] == [house_source(1), SECURITY_DEVICES]
    assert hb2_camera["connect_type"] == "HB2"
    assert hb2_camera["station_sn"] == "T8010***4321"


async def test_one_cipher_sweep_per_owner_reports_key_state_only() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    await eufy.cache.async_load()
    eufy.cache.set_station_cipher_id(SYNTHETIC.station_sn, 40)
    cloud.calls.clear()
    cloud.cipher_ids_requested.clear()

    report = (await eufy.async_account_report()).as_dict()

    sweeps = [c for c in cloud.calls if c.startswith("cipher:")]
    assert sweeps == ["cipher:T8030***2345", "cipher:T8010***4321"]
    assert cloud.cipher_ids_requested == list(const.CIPHER_ID_SWEEP) * 2
    own, other = report["ciphers"]
    assert (own["owner"], own["station_sn"], own["region"]) == ("own", "T8030***2345", "eu")
    assert other["owner"] == "owner 1"
    table = {c["cipher_id"]: c for c in own["ciphers"]}
    assert set(table) == {13, 40, 98}
    assert table[40] == {
        "cipher_id": 40,
        "ecc": "usable",
        "rsa": "unusable",
        "rsa_case": "lower",
        "rsa_bits": None,
        "rsa_reason": "rsa_unparsable",
        "named_by": ["T8030***2345"],
    }
    assert (table[98]["rsa"], table[98]["rsa_case"], table[98]["rsa_bits"]) == (
        "usable",
        "mixed",
        1024,
    )
    assert table[13]["ecc"] == "absent"
    assert _by_serial(report, SYNTHETIC.station_sn)["named_cipher_id"] == 40


async def test_the_report_is_json_safe_and_secret_free() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    dumped = json.dumps((await eufy.async_account_report()).as_dict())
    pem = cloud.cipher_records[98]["private_key"]
    for secret in (
        SYNTHETIC.station_sn,
        SYNTHETIC.camera_sn,
        _HB2_SN,
        _HB2_CAMERA_SN,
        SYNTHETIC.account_id,
        _OTHER_OWNER,
        SYNTHETIC.did,
        SYNTHETIC.station_ip,
        "house-1",
        "house-2",
        "Cottage",
        "Kim",
        "Home Base",
        _ECC,
        pem.splitlines()[1],
        pem.lower().splitlines()[1],
    ):
        assert secret not in dumped


async def test_pending_invites_are_read_without_a_login() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    cloud.calls.clear()
    (invite,) = await eufy.async_pending_invites()
    assert (invite.kind, invite.region, invite.house_name, invite.inviter) == (
        "house",
        "eu",
        "Cottage",
        "Kim",
    )
    assert "login" not in cloud.calls
    assert {c.split("@")[0] for c in cloud.calls} == {"house_invites", "device_invites"}

    cold = FakeCloud()
    assert await _client(cold, MemoryStore()).async_pending_invites() == []
    assert cold.calls == []


async def test_without_a_session_nothing_is_sent() -> None:
    cloud = _cloud()
    eufy = _client(cloud, MemoryStore())
    report = await eufy.async_account_report()
    assert report.regions == ()
    assert report.regions_without_session == const.REGIONS
    assert report.devices == ()
    assert cloud.calls == []


async def test_a_throttle_stops_every_later_request() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    cloud.call_errors = [RateLimitedError("throttled", retry_after=60.0, code=26145)]
    cloud.calls.clear()
    report = await eufy.async_account_report()
    assert report.stopped is not None
    assert report.stopped.startswith(RateLimitedError.__name__)
    assert cloud.calls == ["devices"]
    first, *rest = report.listings
    assert first.error == report.stopped
    assert rest
    assert all(r.error is not None and r.error.startswith("not asked") for r in rest)
    assert report.ciphers == ()


async def test_ciphers_off_sends_no_sweep() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    cloud.calls.clear()
    report = await eufy.async_account_report(ciphers=False)
    assert report.ciphers == ()
    assert not any(c.startswith("cipher:") for c in cloud.calls)


async def test_served_is_known_only_after_a_discovery() -> None:
    cloud = _cloud()
    eufy = _client(cloud)
    before = await eufy.async_account_report(ciphers=False)
    assert {d.served for d in before.devices} == {None}
    await eufy.async_discover()
    after = {d.device_sn: d.served for d in (await eufy.async_account_report()).devices}
    await eufy.async_close()
    assert after["T8030***2345"] is True
    assert after["T8160***7890"] is True
    assert after["T8010***4321"] is False
