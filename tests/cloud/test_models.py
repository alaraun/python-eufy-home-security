"""CloudDevice.from_api and the cache allowlist."""

from __future__ import annotations

import json

from eufy_home_security.cloud.const import firmware_ota_type
from eufy_home_security.cloud.models import (
    CACHED_DEVICE_FIELDS,
    CACHED_MEMBER_FIELDS,
    CloudDevice,
    CloudParam,
    FirmwareUpdate,
    device_cache_entry,
)


def test_from_api_lifts_the_owner_id_out_of_member() -> None:
    device = CloudDevice.from_api(
        {
            "device_sn": "T8030P2000012345",
            "device_type": 18,
            "device_name": "HomeBase",
            "device_channel": 0,
            "p2p_did": "EUPRAMA-123456-ABCDE",
            "local_ip": "192.0.2.10",
            "member": {"admin_user_id": "owner-id", "member_user_id": "mine", "member_type": 1},
            "main_sw_version": "1.2.3",
        }
    )
    assert device.owner_user_id == "owner-id"
    assert device.member_type == 1
    assert device.is_station
    assert device.has_member_relation
    assert device.channel == 0  # a real slot, not falsy-tested away


def test_from_api_marks_a_sub_device_and_tolerates_missing_fields() -> None:
    device = CloudDevice.from_api(
        {"device_sn": "T8160CAM", "device_type": 3, "parent_sn": "T8030HB"}
    )
    assert not device.is_station
    assert device.station_sn == "T8030HB"
    assert device.owner_user_id is None
    assert not device.has_member_relation
    assert device.name == ""


def test_from_api_keeps_raw_readonly() -> None:
    device = CloudDevice.from_api({"device_sn": "x", "device_type": 1, "extra": {"k": "v"}})
    assert device.raw["extra"] == {"k": "v"}


def test_a_device_without_p2p_identity_is_not_a_station() -> None:
    """A robot vacuum on the same account is its own parent but has no p2p_did."""
    vacuum = CloudDevice.from_api({"device_sn": "ebcfe0000000000e8n7", "device_type": 0})
    assert not vacuum.is_station
    standalone = CloudDevice.from_api(
        {"device_sn": "T8400P2000000001", "device_type": 30, "p2p_did": "EUPRAMA-123456-ABCDE"}
    )
    assert standalone.is_station


def test_model_of_a_catalogued_camera() -> None:
    camera = CloudDevice.from_api(
        {"device_sn": "t8160P2000067890", "device_type": 19, "parent_sn": "T8030P2000012345"}
    )
    assert camera.model is not None
    assert camera.model.model == "T8160"
    assert camera.model_id == "T8160"
    assert camera.model_name == "eufyCam 3 (S330)"


def test_model_of_an_uncatalogued_device_keeps_the_prefix() -> None:
    device = CloudDevice.from_api({"device_sn": "T8400P2000000001", "device_type": 30})
    assert device.model is None
    assert device.model_id == "T8400"
    assert device.model_name is None


def test_model_id_is_none_without_a_full_prefix() -> None:
    device = CloudDevice.from_api({"device_sn": "T80", "device_type": 0})
    assert (device.model, device.model_id, device.model_name) == (None, None, None)


def test_repr_redacts_identifiers() -> None:
    device = CloudDevice.from_api(
        {
            "device_sn": "T8030P2000012345",
            "device_type": 18,
            "p2p_did": "EUPRAMA-123456-ABCDE",
            "local_ip": "192.0.2.10",
            "member": {"admin_user_id": "0123456789abcdef0123456789abcdef01234567"},
        }
    )
    text = repr(device)
    for secret in ("T8030P2000012345", "EUPRAMA-123456-ABCDE", "192.0.2.10", "0123456789abcdef01"):
        assert secret not in text
    assert "T8030***2345" in text


def test_account_is_owner_without_a_member_relation_or_as_member_type_2() -> None:
    base = {"device_sn": "T8030P2000012345", "device_type": 18, "p2p_did": "EUPRAMA-123456-ABCDE"}
    assert CloudDevice.from_api(base).account_is_owner
    owner = {"admin_user_id": "me", "member_type": 2}
    assert CloudDevice.from_api({**base, "member": owner}).account_is_owner
    for member_type in (0, 1):
        shared = {"admin_user_id": "owner-id", "member_type": member_type}
        assert not CloudDevice.from_api({**base, "member": shared}).account_is_owner


def test_redacted_dict_is_json_safe_and_carries_no_identifier() -> None:
    owner = "0123456789abcdef0123456789abcdef01234567"
    station = CloudDevice.from_api(
        {
            "device_sn": "T8030P2000012345",
            "device_type": 18,
            "device_name": "HomeBase",
            "p2p_did": "EUPRAMA-123456-ABCDE",
            "local_ip": "192.0.2.10",
            "member": {"admin_user_id": owner, "member_type": 1},
            "main_sw_version": "3.8.7.4",
            "cloud_region": "us",
        }
    )
    camera = CloudDevice.from_api(
        {
            "device_sn": "T8160P2000067890",
            "device_type": 7,
            "device_name": "Front",
            "parent_sn": "T8030P2000012345",
            "device_channel": 0,
        }
    )
    dumped = json.dumps([station.as_redacted_dict(), camera.as_redacted_dict()], sort_keys=True)
    for secret in (
        "T8030P2000012345",
        "T8160P2000067890",
        "EUPRAMA-123456-ABCDE",
        "192.0.2.10",
        owner,
        "123456",
        "2.10",
    ):
        assert secret not in dumped
    assert station.as_redacted_dict() == {
        "device_sn": "T8030***2345",
        "station_sn": None,
        "device_type": 18,
        "name": "HomeBase",
        "channel": None,
        "is_station": True,
        "member_type": 1,
        "account_is_owner": False,
        "main_sw_version": "3.8.7.4",
        "sec_sw_version": None,
        "region": "us",
        "has_p2p_did": True,
        "has_local_ip": True,
        "has_owner_user_id": True,
        "model_id": "T8030",
        "model_name": "HomeBase 3 (S380)",
    }
    assert camera.as_redacted_dict()["station_sn"] == "T8030***2345"
    assert camera.as_redacted_dict()["channel"] == 0


def test_only_an_own_parent_station_is_standalone() -> None:
    # True for own-parent devices with a DID
    assert (
        CloudDevice(
            device_sn="T8170X",
            station_sn="T8170X",
            p2p_did="TST-123",
            device_type=48,
            channel=0,
            name="standalone",
        ).is_standalone
        is True
    )

    # False for hub (parent_sn None)
    assert (
        CloudDevice(
            device_sn="T8030X",
            station_sn=None,
            p2p_did="TST-456",
            device_type=0,
            channel=None,
            name="hub",
        ).is_standalone
        is False
    )

    # False for paired camera
    assert (
        CloudDevice(
            device_sn="T8111X",
            station_sn="T8030X",
            p2p_did="TST-789",
            device_type=1,
            channel=0,
            name="paired",
        ).is_standalone
        is False
    )

    # False for an own-parent device without a DID
    assert (
        CloudDevice(
            device_sn="T8999X",
            station_sn="T8999X",
            p2p_did=None,
            device_type=48,
            channel=0,
            name="no did",
        ).is_standalone
        is False
    )


def test_cloud_params_parses_params() -> None:
    device = CloudDevice.from_api(
        {
            "device_sn": "T8030P2000012345",
            "device_type": 18,
            "params": [
                {"param_type": 100, "param_value": 1, "update_time": 1600000000},
                {"param_type": "101", "param_value": "value", "update_time": 1600000001},
                {"param_type": 102, "param_value": True, "update_time": 1600000002},
                {"param_type": 103, "param_value": None, "update_time": 1600000003},
                {"param_type": 104, "param_value": {}, "update_time": 1600000004},
                {"param_type": 105, "param_value": "no-time"},
                {"param_type": 106, "param_value": "bool-time", "update_time": False},
                {"param_value": "no-type", "update_time": 1600000005},
                "not-a-mapping",
            ],
        }
    )
    assert device.cloud_params == (
        CloudParam(param_id=100, value="1", updated_at=1600000000.0),
        CloudParam(param_id=101, value="value", updated_at=1600000001.0),
        CloudParam(param_id=105, value="no-time", updated_at=None),
        CloudParam(param_id=106, value="bool-time", updated_at=None),
    )


def test_cloud_params_no_params_key() -> None:
    device = CloudDevice.from_api({"device_sn": "T8030P2000012345", "device_type": 18})
    assert device.cloud_params == ()


# A get_devs_list entry: everything CloudDevice reads, plus the kind of thing it never
# does (the member's contact details, radio MACs, MQTT/WebRTC details, cover images).
_FULL_ENTRY = {
    "cloud_region": "eu",
    "device_sn": "T8170P2000012345",
    "device_type": 48,
    "device_name": "SoloCam",
    "parent_sn": "T8170P2000012345",
    "device_channel": 0,
    "p2p_did": "EUPRAMA-123456-ABCDE",
    "local_ip": "192.0.2.10",
    "main_sw_version": "1.2.3",
    "sec_sw_version": "4.5.6",
    "app_conn": "EBGCEBGCEBGC",
    "device_new_pn": "T8170",
    "member": {
        "admin_user_id": "owner-id",
        "member_type": 2,
        "email": "owner@example.com",
        "nick_name": "Owner",
        "mobile": "+000000",
        "avatar": "https://cdn.example/avatar.png",
    },
    "params": [
        {"param_type": 1101, "param_value": "87", "update_time": 1600000000, "status": 1},
    ],
    "wifi_mac": "00:00:5E:00:53:01",
    "bt_mac": "00:00:5E:00:53:02",
    "p2p_conn": "EBGCEBGC",
    "mqtt_info": {"host": "mqtt.example"},
    "cover_path": "https://cdn.example/cover.jpg",
}


def test_device_cache_entry_keeps_exactly_what_the_model_reads() -> None:
    slim = device_cache_entry(_FULL_ENTRY, keep_params=True)
    assert set(slim) == {*CACHED_DEVICE_FIELDS, "member", "params"}
    assert set(slim["member"]) == set(CACHED_MEMBER_FIELDS)
    assert slim["params"] == [{"param_type": 1101, "param_value": "87", "update_time": 1600000000}]
    text = json.dumps(slim)
    for gone in ("owner@example.com", "Owner", "+000000", "avatar", "00:00:5E", "mqtt", "cover"):
        assert gone not in text
    # Nothing the model reads is lost: fields and derived properties agree.
    full, cached = CloudDevice.from_api(_FULL_ENTRY), CloudDevice.from_api(slim)
    assert full == cached
    for prop in (
        "is_station",
        "is_standalone",
        "has_member_relation",
        "account_is_owner",
        "cloud_params",
        "rendezvous_servers",
        "model_id",
        "model_name",
    ):
        assert getattr(full, prop) == getattr(cached, prop), prop
    assert cached.raw["app_conn"] == _FULL_ENTRY["app_conn"]
    assert cached.raw["device_new_pn"] == _FULL_ENTRY["device_new_pn"]
    assert cached.region == "eu"


def test_device_cache_entry_drops_the_params_snapshot_unless_asked() -> None:
    slim = device_cache_entry(_FULL_ENTRY, keep_params=False)
    assert "params" not in slim
    assert CloudDevice.from_api(slim).cloud_params == ()
    # An empty or missing member is not stored either; malformed ones are skipped.
    assert "member" not in device_cache_entry(
        {"device_sn": "T8030X", "member": {}}, keep_params=False
    )
    assert device_cache_entry(
        {"device_sn": "T8170X", "member": "nope", "params": ["x", {"param_type": 1}]},
        keep_params=True,
    ) == {"device_sn": "T8170X", "params": [{"param_type": 1}]}


def test_firmware_update_from_api_up_to_date_is_none() -> None:
    # The OTA "already newest" answer: an error object, not a version with a package.
    reason = {"reason": "error: code = 20004 reason =  message = "}
    assert FirmwareUpdate.from_api("T8030P2000012345", reason) is None
    assert FirmwareUpdate.from_api("T8030P2000012345", None) is None
    assert FirmwareUpdate.from_api("T8030P2000012345", {"rom_version_name": "3.9.0.0"}) is None


def test_firmware_update_from_api_parses_the_package() -> None:
    update = FirmwareUpdate.from_api(
        "T8030P2000012345",
        {
            "rom_version_name": "3.9.0.0",
            "rom_version": 700,
            "up_forced": True,
            "full_package": {
                "file_path": "https://cdn.eufylife.com/fw/x.bin",
                "file_md5": "abc",
                "file_size": 42,
            },
        },
    )
    assert update is not None
    assert update.version_name == "3.9.0.0"
    assert update.download_url == "https://cdn.eufylife.com/fw/x.bin"
    assert update.size_bytes == 42
    assert update.forced is True


def test_firmware_ota_type_is_the_station_kit() -> None:
    assert firmware_ota_type("T8030P2000012345") == "T8030_Kit"
    assert firmware_ota_type("T7000P1000000001") == "T7000_Kit"
