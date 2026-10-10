"""Parameter-dump accumulation."""

from __future__ import annotations

import base64
import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.params import ParamDump, standalone_aliases
from eufy_home_security.testing import SYNTHETIC


def _param(dev: int, pid: int, value: str) -> dict[str, object]:
    return {"dev_type": dev, "param_type": pid, "param_value": value}


def test_ingest_groups_by_dev_type_and_keeps_meta() -> None:
    dump = ParamDump()
    merged = dump.ingest(
        {
            "main_sw_version": "3.8.6.0",
            "sec_sw_version": "1.4.0.8",
            "params": [
                _param(255, 1224, "0"),
                _param(255, 1176, "192.0.2.10"),
                _param(0, 1101, "93"),
                _param(1, 1101, "98"),  # a second device's battery, not collapsed
                {"param_type": None},  # skipped
            ],
        }
    )
    assert merged == 4
    assert dump.station[1224] == "0"
    assert dump.devices[0][1101] == "93"  # a second device's battery, not collapsed
    assert dump.devices[1][1101] == "98"
    assert dump.meta["main_sw_version"] == "3.8.6.0"


def test_ingest_aliases_and_standalone_aliases() -> None:
    dump = ParamDump()
    merged = dump.ingest(
        {
            "params": [
                _param(48, 1224, "1"),
                _param(48, 1101, "99"),
                _param(1, 1101, "98"),
            ]
        },
        aliases={48: (255, 0)},
    )
    assert merged == 3
    assert dump.devices[255] == {1224: "1", 1101: "99"}
    assert dump.devices[0] == {1224: "1", 1101: "99"}
    assert dump.devices[1] == {1101: "98"}
    assert 48 not in dump.devices
    assert dump.guard_mode == GuardMode.HOME
    assert standalone_aliases(48, 0) == {48: (255, 0)}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _bypass(channel: int, pid: int, value: str) -> dict[str, object]:
    return {
        "channel": channel,
        "device_sn": SYNTHETIC.camera_sn,
        "param_type": pid,
        "param_value": _b64(value),
    }


def test_ingest_files_bypass_entries_under_their_channel_decoded() -> None:
    """``db_bypass_str`` adds a paired device's own params, base64-decoded once."""
    quality = _b64(json.dumps({"mode_0": {"quality": 2}, "mode_1": {"quality": 0}, "cur_mode": 0}))
    dump = ParamDump()
    merged = dump.ingest(
        {
            "params": [_param(255, 1224, "1"), _param(2, 1705, "3")],
            "db_bypass_str": [
                _bypass(2, 2730, quality),
                _bypass(2, 6243, "0"),
                {"channel": 2, "param_type": 6015, "param_value": "not base64!"},
                {"channel": None, "param_type": 6248, "param_value": _b64("0")},
                "junk",
            ],
        }
    )
    assert merged == 4
    assert dump.devices[2] == {1705: "3", 2730: quality, 6243: "0"}
    assert dump.station == {1224: "1"}


def test_bypass_entry_keeps_the_params_value_of_the_same_id() -> None:
    dump = ParamDump()
    dump.ingest(
        {"params": [_param(2, 1019, "1")], "db_bypass_str": [_bypass(2, 1019, "0")]},
        aliases={2: (2, 7)},
    )
    assert dump.devices[2] == {1019: "1"}
    assert dump.devices[7] == {1019: "1"}
    later = ParamDump()
    later.ingest({"params": [_param(2, 1019, "1")]})
    later.ingest({"db_bypass_str": [_bypass(2, 1019, "0")]})
    assert later.devices[2] == {1019: "0"}


def test_ingest_keeps_the_objects_and_the_keys_it_does_not_read() -> None:
    first = {"params": [_param(255, 1224, "1")], "main_sw_version": "3.8.7.4", "new_key": {"a": 1}}
    second = {"params": [], "new_key": {"a": 2}, "db_bypass_str": []}
    dump = ParamDump()
    dump.ingest(first)
    dump.ingest(second)
    assert dump.received == [first, second]
    assert dump.unread == {"new_key": {"a": 2}}


def test_guard_mode_property() -> None:
    dump = ParamDump()
    dump.ingest({"params": [_param(255, 1224, "1")]})
    assert dump.guard_mode is GuardMode.HOME
    # an unknown code degrades to the raw int
    other = ParamDump()
    other.ingest({"params": [_param(255, 1224, "99")]})
    assert other.guard_mode == 99
    # no guard-mode param anywhere
    empty = ParamDump()
    empty.ingest({"params": [_param(0, 1101, "50")]})
    assert empty.guard_mode is None
    # 1224 on a sub-device is found as a fallback
    fallback = ParamDump()
    fallback.ingest({"params": [_param(0, 1224, "63")]})
    assert fallback.guard_mode is GuardMode.DISARMED


def test_active_mode_is_param_1151() -> None:
    dump = ParamDump()
    dump.ingest({"params": [_param(255, 1224, "2"), _param(255, 1151, "0")]})
    assert (dump.guard_mode, dump.active_mode) == (GuardMode.SCHEDULE, GuardMode.AWAY)
    assert ParamDump().active_mode is None


def test_flatten_and_sub_device_serials() -> None:
    dump = ParamDump()
    serials = base64.b64encode(json.dumps(["T8160P2000067890"]).encode()).decode()
    dump.ingest({"params": [_param(255, 1072, serials), _param(0, 1101, "12")]})
    assert dump.flatten()[(0, 1101)] == "12"
    assert dump.sub_device_serials() == ["T8160P2000067890"]
    # a bad blob yields no serials, never raises
    bad = ParamDump()
    bad.ingest({"params": [_param(255, 1072, "!!!not base64!!!")]})
    assert bad.sub_device_serials() == []
    assert ParamDump().sub_device_serials() == []


def test_sub_device_serials_keep_the_positions_of_rejected_entries() -> None:
    station, camera, other = "T8030P2000012345", "T8160P2000067890", "T8160P2000067892"
    listed = [camera, station, camera.lower(), "T8160-BAD", 7, camera, other]
    dump = ParamDump()
    blob = base64.b64encode(json.dumps(listed).encode()).decode()
    dump.ingest({"params": [_param(255, 1072, blob)]})
    assert dump.sub_device_serials(station_sn=station) == [
        camera,
        None,  # the station itself
        None,  # not uppercase
        None,  # not serial-shaped
        None,  # not a string
        None,  # a repeat
        other,
    ]
    assert dump.sub_device_serials()[1] == station  # only a named station serial is dropped


def test_malformed_params_are_skipped_not_raised() -> None:
    for params in ("abc", {"param_type": 1224}, [None], 7):
        assert ParamDump().ingest({"params": params}) == 0
    dump = ParamDump()
    merged = dump.ingest(
        {
            "params": [
                {"dev_type": 255, "param_type": float("inf"), "param_value": "1"},
                {"dev_type": 1.9, "param_type": 1101, "param_value": "1"},
                {"dev_type": True, "param_type": 1101, "param_value": "1"},
                {"dev_type": "0", "param_type": "1101", "param_value": 55},  # decimal strs ok
                {"dev_type": 0, "param_type": 1102, "param_value": {"x": 1}},  # not a scalar
            ]
        }
    )
    assert merged == 1
    assert dump.devices == {0: {1101: "55"}}


def test_guard_mode_rejects_non_integer_codes() -> None:
    for raw in ("1.9", "Infinity", " 1", "", "0x3f"):
        dump = ParamDump()
        dump.devices[255] = {1224: raw}
        assert dump.guard_mode is None, raw


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=30,
)
_PARAM = st.fixed_dictionaries(
    {},
    optional={"dev_type": _JSON, "param_type": _JSON, "param_value": _JSON},
)


@given(params=st.one_of(_JSON, st.lists(st.one_of(_PARAM, _JSON), max_size=6)))
@settings(max_examples=200)
def test_any_json_ingests_and_reads_without_raising(params: Any) -> None:
    dump = ParamDump()
    dump.ingest({"params": params, "main_sw_version": params})
    _ = dump.guard_mode
    dump.flatten()
    dump.sub_device_serials()
    assert all(isinstance(v, str) for p in dump.devices.values() for v in p.values())
