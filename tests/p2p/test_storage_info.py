from __future__ import annotations

import dataclasses
import json
import struct
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.p2p.storage_info import (
    CMD_SD_INFO,
    CMD_STORAGE,
    STORAGE_QUERY_INFO,
    DiskInfo,
    EmmcInfo,
    StorageInfo,
    StorageMedium,
    parse_sd_card_info,
    parse_storage_info,
    storage_query_payload,
    storage_record,
)
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import synthetic_storage_body


def test_query_payload_is_the_apps() -> None:
    assert storage_query_payload() == {"version": 1, "cmd": 11001}
    assert (CMD_STORAGE, STORAGE_QUERY_INFO) == (1307, 11001)


def test_a_full_record_parses_into_the_apps_figures() -> None:
    info = parse_storage_info(synthetic_storage_body())
    assert (info.storage_days, info.storage_events, info.body_version) == (30, 120, 2)
    assert (info.format_transaction, info.format_error, info.formatting) == (None, 0, False)
    assert info.external is None
    disk = info.disk
    assert disk is not None
    assert (disk.model, disk.disk_type, disk.path) == ("ExampleSSD256GB", 1, "/dev/sda")
    assert (disk.size_mib, disk.nominal_size_mib) == (238475, 256000)
    assert (disk.system_mib, disk.recordings_used_mib, disk.used_mib) == (13000, 1500, 14500)
    assert (disk.recordings_capacity_mib, disk.filesystem_used_mib) == (220000, 2100)
    assert (disk.used_gib, disk.size_gib) == (14.16, 232.89)
    assert (disk.free_mib, disk.free_gib, disk.used_percent) == (223975, 218.73, 6.1)
    assert (disk.temperature_c, disk.healthy, disk.ready, disk.formatting) == (
        38,
        True,
        True,
        False,
    )
    assert (disk.serial, disk.label) == (SYNTHETIC.disk_serial, SYNTHETIC.disk_label)
    emmc = info.emmc
    assert emmc is not None
    assert (
        emmc.size_mib,
        emmc.used_mib,
        emmc.filesystem_used_mib,
        emmc.free_mib,
    ) == (16000, 3000, 3000, 13000)
    assert (emmc.used_gib, emmc.size_gib) == (2.93, 15.62)
    assert (emmc.used_percent, emmc.station_used_percent, emmc.wear_percent) == (25.0, 25, 2)
    assert (emmc.swap_mib, emmc.data_partition_mib, emmc.healthy) == (2048, 12000, True)


def test_used_is_the_app_formula() -> None:
    """The documented app figures: 8065 + 18819 + 2237 MiB shown as 28.44 of 465.76 GB."""
    body = synthetic_storage_body()
    body["hdd_info"].update(
        system_size=8065, system_size_data=18819, video_used=2237, disk_size_1024=476940
    )
    disk = parse_storage_info(body).disk
    assert disk is not None
    assert (disk.used_mib, disk.used_gib, disk.size_gib) == (29121, 28.44, 465.76)


def test_disk_serial_and_label_stay_out_of_repr() -> None:
    info = parse_storage_info(synthetic_storage_body())
    assert SYNTHETIC.disk_serial not in repr(info)
    assert SYNTHETIC.disk_label not in repr(info)
    # still part of equality: a format (new label) is a change
    relabelled = parse_storage_info(synthetic_storage_body(label="hdd_other"))
    assert relabelled != info


def test_formatting_is_parted_status_2() -> None:
    body = synthetic_storage_body()
    body["hdd_info"]["parted_status"] = 2
    info = parse_storage_info(body)
    assert info.disk is not None
    assert (info.disk.formatting, info.disk.ready, info.formatting) == (True, False, True)


@pytest.mark.parametrize(
    "hdd",
    [
        None,
        "not an object",
        {},
        {"disk_size_1024": 0, "disk_size": 0, "disk_path": ""},
    ],
)
def test_no_internal_disk(hdd: Any) -> None:
    body = synthetic_storage_body()
    if hdd is None:
        del body["hdd_info"]
    else:
        body["hdd_info"] = hdd
    info = parse_storage_info(body)
    assert info.disk is None
    assert info.emmc is not None


def test_an_external_disk_carries_path_size_and_use() -> None:
    body = synthetic_storage_body()
    body["move_disk_info"] = {"disk_path": "/dev/sdb1", "disk_size": 100000, "disk_used": 2500}
    external = parse_storage_info(body).external
    assert external == DiskInfo(
        path="/dev/sdb1", size_mib=100000, used_mib=2500, filesystem_used_mib=2500
    )
    assert (external.used_percent, external.free_mib, external.healthy) == (2.5, 97500, None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("video_used", "12x"),
        ("video_used", -5),
        ("video_used", 1.5),
        ("video_used", True),
        ("video_used", 1 << 50),
        ("system_size_data", None),
        ("cur_temperate", 900),
        ("hdd_label", 42),
        ("hdd_label", "bad\x00label"),
        ("device_module", "   "),
    ],
)
def test_a_bad_field_becomes_none_alone(field: str, value: Any) -> None:
    body = synthetic_storage_body()
    body["hdd_info"][field] = value
    disk = parse_storage_info(body).disk
    assert disk is not None
    assert disk.size_mib == 238475  # the rest still parses
    derived = {
        "video_used": (disk.recordings_used_mib, disk.used_mib),
        "system_size_data": (disk.system_mib, disk.used_mib),
        "cur_temperate": (disk.temperature_c,),
        "hdd_label": (disk.label,),
        "device_module": (disk.model,),
    }[field]
    assert all(v is None for v in derived)
    if field in ("video_used", "system_size_data"):
        assert (disk.free_mib, disk.used_percent, disk.used_gib) == (None, None, None)


def test_decimal_strings_are_numbers() -> None:
    body = synthetic_storage_body()
    body["emmc_info"]["eol_percent"] = "7"
    body["emmc_info"]["data_used_percent"] = 101
    emmc = parse_storage_info(body).emmc
    assert emmc is not None
    assert (emmc.wear_percent, emmc.station_used_percent, emmc.used_percent) == (7, None, 18.8)


def _reply(payload: object) -> dict[str, Any]:
    return {"cmd": 1307, "payload": payload}


def test_storage_record_recognises_the_reply() -> None:
    body = synthetic_storage_body()
    record = storage_record(_reply({"cmd": 11001, "mIntRet": 0, "body": body}))
    assert record is not None
    assert (record.code, record.body) == (0, body)
    as_text = storage_record(_reply(json.dumps({"cmd": "11001", "body": body})))
    assert as_text is not None
    assert as_text.body == body
    rejected = storage_record(_reply({"cmd": 11001, "mIntRet": -104}))
    assert rejected is not None
    assert (rejected.code, rejected.body) == (-104, None)
    odd = storage_record(_reply({"cmd": 11001, "mIntRet": "x", "body": []}))
    assert odd is not None
    assert (odd.code, odd.body) == (-1, None)


@pytest.mark.parametrize(
    "obj",
    [
        {"cmd": 1306, "payload": {"cmd": 11001, "body": {}}},
        _reply({"cmd": 11003, "body": {"media_type": "hdd"}}),
        _reply("{not json"),
        _reply(None),
        {"cmd": 2037, "payload": "{}"},
    ],
)
def test_storage_record_ignores_everything_else(obj: dict[str, Any]) -> None:
    assert storage_record(obj) is None


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=40,
)
_SECTION = st.dictionaries(
    st.sampled_from(
        sorted({*synthetic_storage_body()["hdd_info"], *synthetic_storage_body()["emmc_info"]})
    ),
    _JSON,
)


@given(
    top=st.dictionaries(st.text(max_size=12), _JSON, max_size=4),
    hdd=_SECTION | _JSON,
    move=_SECTION | _JSON,
    emmc=_SECTION | _JSON,
)
@settings(max_examples=200)
def test_any_record_parses_without_raising(
    top: dict[str, Any], hdd: Any, move: Any, emmc: Any
) -> None:
    body = {**top, "hdd_info": hdd, "move_disk_info": move, "emmc_info": emmc}
    info = parse_storage_info(body)
    assert isinstance(info, StorageInfo)
    for disk in (info.disk, info.external, info.emmc):
        if disk is not None:
            _ = (
                disk.free_mib,
                disk.used_percent,
                disk.used_gib,
                disk.size_gib,
                disk.free_gib,
                disk.recordings_used_gib,
                disk.recordings_capacity_gib,
                disk.healthy,
                disk.formatting,
                disk.ready,
            )
    assert storage_record(_reply({"cmd": 11001, "body": body})) is not None


def test_disk_and_emmc_share_one_shape() -> None:
    assert issubclass(DiskInfo, StorageMedium)
    assert issubclass(EmmcInfo, StorageMedium)
    assert {f.name for f in dataclasses.fields(DiskInfo)} == {
        f.name for f in dataclasses.fields(EmmcInfo)
    }

    def public_properties(cls: type) -> set[str]:
        return {
            name
            for name in dir(cls)
            if not name.startswith("_") and isinstance(getattr(cls, name), property)
        }

    assert public_properties(DiskInfo) == public_properties(EmmcInfo)


def test_a_field_the_other_record_carries_is_parsed_on_either() -> None:
    body = synthetic_storage_body()
    body["emmc_info"]["cur_temperate"] = 42
    body["emmc_info"]["parted_status"] = 2
    body["emmc_info"]["device_module"] = "EMMC-TEST"
    body["hdd_info"]["eol_percent"] = 5
    body["hdd_info"]["data_used_percent"] = 60
    body["hdd_info"]["swap_size"] = 1024
    body["hdd_info"]["data_partition_size"] = 8000

    info = parse_storage_info(body)
    assert info.emmc is not None
    assert (info.emmc.temperature_c, info.emmc.parted_status, info.emmc.model) == (
        42,
        2,
        "EMMC-TEST",
    )

    assert info.disk is not None
    assert (
        info.disk.wear_percent,
        info.disk.station_used_percent,
        info.disk.swap_mib,
        info.disk.data_partition_mib,
    ) == (5, 60, 1024, 8000)


def test_used_percent_is_computed_without_a_station_figure() -> None:
    body = synthetic_storage_body()
    body["hdd_info"].update(
        video_used=25000, system_size=0, system_size_data=0, disk_size_1024=100000
    )
    del body["emmc_info"]["data_used_percent"]
    body["emmc_info"].update(disk_used=1000, disk_size=10000)
    info = parse_storage_info(body)
    assert info.disk is not None
    assert info.emmc is not None
    assert (info.disk.station_used_percent, info.disk.used_percent) == (None, 25.0)
    assert (info.emmc.station_used_percent, info.emmc.used_percent) == (None, 10.0)


def test_the_emmc_prefers_the_stations_used_percent() -> None:
    body = synthetic_storage_body()
    body["emmc_info"] = {
        "disk_nominal": 15974,
        "disk_size": 16000,
        "system_size": 5206,
        "disk_used": 3067,
        "data_used_percent": 20,
        "swap_size": 2048,
        "video_size": 10364,
        "video_used": 201,
        "data_partition_size": 12816,
        "eol_percent": 1,
        "work_status": 0,
        "health": 0,
    }

    emmc = parse_storage_info(body).emmc
    assert emmc is not None
    assert (
        emmc.used_percent,
        emmc.free_mib,
        emmc.used_gib,
        emmc.size_gib,
        emmc.recordings_used_gib,
        emmc.healthy,
        emmc.formatting,
        emmc.temperature_c,
    ) == (20.0, 12933, 3.0, 15.62, 0.2, True, None, None)


def test_parse_sd_card_info_parses_the_binary_triple() -> None:
    # status 0, total 7140 MB, free 7108 MB (the live T8170 reply: 0.4% used).
    info = parse_sd_card_info(struct.pack("<3i", 0, 7140, 7108))
    assert isinstance(info, EmmcInfo)
    assert info.size_mib == 7140
    assert info.free_mib == 7108
    assert info.used_mib == 32
    assert info.work_status == 0
    assert info.used_percent == 0.4


def test_parse_sd_card_info_used_percent_exact() -> None:
    info = parse_sd_card_info(struct.pack("<3i", 0, 8000, 3000))
    assert info is not None
    assert info.used_mib == 5000
    assert info.used_percent == 62.5


def test_parse_sd_card_info_clamps_free_to_total() -> None:
    # free above total (a transient reading) clamps: used 0, not negative.
    info = parse_sd_card_info(struct.pack("<3i", 0, 100, 200))
    assert info is not None
    assert info.free_mib == 100
    assert info.used_mib == 0
    assert info.used_percent == 0.0


def test_parse_sd_card_info_none_for_short_or_no_emmc() -> None:
    assert parse_sd_card_info(b"") is None
    assert parse_sd_card_info(struct.pack("<2i", 0, 7140)) is None  # under 12 bytes
    assert parse_sd_card_info(struct.pack("<3i", 0, 0, 0)) is None  # total 0: no eMMC
    assert parse_sd_card_info(struct.pack("<3i", 0, -1, 3000)) is None  # negative total


def test_cmd_sd_info_is_1144() -> None:
    assert CMD_SD_INFO == 1144
