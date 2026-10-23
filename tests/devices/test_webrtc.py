"""Whether the eufy app reaches a device over WebRTC or P2P (devices/webrtc.py)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices import webrtc
from eufy_home_security.devices.webrtc import (
    RouteDevice,
    app_uses_webrtc,
    app_webrtc_only,
    route_device,
)
from eufy_home_security.testing import SYNTHETIC

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"
TAIL = SYNTHETIC.camera_sn[5:]  # "P2000067890": serial character 7 is "2"
OTHER_TAIL = "P0000067890"  # serial character 7 is "0"


def station(code: str, firmware: str | None) -> RouteDevice:
    serial = code + SYNTHETIC.station_sn[5:]
    return RouteDevice(serial=serial, product_code=code, station_serial=serial, firmware=firmware)


def child(
    code: str, hub: RouteDevice | None, firmware: str | None = "1.0.0.0", tail: str = TAIL
) -> RouteDevice:
    serial = code + tail
    return RouteDevice(
        serial=serial,
        product_code=code,
        station_serial=serial if hub is None else hub.serial,
        firmware=firmware,
    )


def routed(device: RouteDevice, *others: RouteDevice) -> bool:
    return app_uses_webrtc(device.serial, (device, *others))


@pytest.mark.parametrize(
    ("firmware", "expected"),
    [
        ("3.7.4.2", False),
        ("3.7.4.3", True),  # both bounds of the HomeBase 3's value 1 are inclusive
        ("3.8.7.4", True),
        ("4.1.9.999", True),
        ("4.1.9.1000", False),
        ("4.2.0.0", False),  # its 2 needs an app SDK version the app does not have
        ("", False),
        (None, False),  # no firmware compares below every bound
    ],
)
@pytest.mark.parametrize("code", ["T8223", "T8224"])
def test_a_doorbell_behind_a_homebase_3_inside_its_firmware_range(
    code: str, firmware: str | None, expected: bool
) -> None:
    hub = station("T8030", firmware)
    doorbell = child(code, hub)
    assert routed(doorbell, hub) is expected
    assert routed(hub, doorbell) is expected  # the listed child routes the station too


def test_a_homebase_3_routes_only_what_its_sub_device_list_lets_through() -> None:
    hub = station("T8030", "3.8.7.4")
    camera = child("T8160", hub)
    assert not routed(hub, camera)  # no listed product paired: the station is P2P
    doorbell = child("T8224", hub, tail=OTHER_TAIL)
    assert not routed(camera, hub, doorbell)  # no property of its own
    # its own value is read only away from a HomeBase 3, its variant needs an old app SDK
    assert not routed(child("T8170", hub, "3.4.0.0", OTHER_TAIL), hub, doorbell)


def test_a_product_routed_by_its_own_thing_description_behind_a_homebase_3() -> None:
    hub = station("T8030", "3.7.4.3")
    doorbell = child("T8215", hub)
    assert routed(doorbell, hub)  # its variant reads the station's serial and firmware
    assert not routed(doorbell, station("T8030", "3.7.4.2"))


@pytest.mark.parametrize(
    ("hub_firmware", "lock_firmware", "expected"),
    [
        ("3.8.5.1", "2.0.0.0", True),  # the wider sub-device list from 3.8.5.1
        ("3.8.5.0", "2.0.0.0", False),  # the base list does not name it
        ("3.8.5.1", "1.9.9.9", False),  # its own property is not available below 2.0.0.0
    ],
)
def test_the_variant_with_the_most_passing_conditions_is_read(
    hub_firmware: str, lock_firmware: str, expected: bool
) -> None:
    hub = station("T8030", hub_firmware)
    assert routed(child("T85M1", hub, lock_firmware), hub) is expected


@pytest.mark.parametrize(
    ("firmware", "code", "expected"),
    [
        ("4.0.7.9", "T8224", False),
        ("4.0.8.0", "T8224", True),
        ("4.0.8.2", "T8215", True),  # the base list
        ("4.0.8.3", "T8532", True),  # its variant list
        ("4.0.8.2", "T8532", False),
        (None, "T8224", False),
    ],
)
def test_a_homebase_mini_child(firmware: str | None, code: str, expected: bool) -> None:
    hub = station("T8025", firmware)
    assert routed(child(code, hub, "2.0.0.0"), hub) is expected


@pytest.mark.parametrize("code", ["T9000", "T8N00", "T7000", "T8040"])
def test_a_webrtc_only_station_routes_itself_and_every_child(code: str) -> None:
    hub = station(code, None)
    camera = child("T8160", hub)
    assert routed(camera, hub)
    assert routed(hub, camera)
    assert app_webrtc_only(hub)


@pytest.mark.parametrize(
    "hub", [station("T8030", "3.8.7.4"), station("T8030", "4.2.0.0"), station("T8010", "3.2.0.0")]
)
def test_other_stations_are_not_webrtc_only(hub: RouteDevice) -> None:
    assert not app_webrtc_only(hub)


@pytest.mark.parametrize(
    ("code", "firmware", "tail", "expected"),
    [
        ("T8224", None, TAIL, True),
        ("T8170", "3.4.0.0", OTHER_TAIL, True),
        ("T8170", "3.3.9.9", OTHER_TAIL, False),  # below its firmware condition
        ("T8170", "3.4.0.0", TAIL, False),  # its serial condition
        ("T8170", None, OTHER_TAIL, False),
        ("T8160", "9.9.9.9", OTHER_TAIL, False),
    ],
)
def test_a_standalone_device(code: str, firmware: str | None, tail: str, expected: bool) -> None:
    assert routed(child(code, None, firmware, tail)) is expected


def test_a_device_whose_station_is_not_listed_reads_only_its_own_value() -> None:
    hub = station("T8030", "3.7.4.2")
    assert routed(child("T8224", hub))
    assert not routed(child("T8224", hub), hub)


def test_unknown_devices_are_p2p() -> None:
    hub = station("T8030", "3.8.7.4")
    assert not app_uses_webrtc("T8224" + TAIL, [hub])
    nameless = RouteDevice(serial="T8224" + TAIL, product_code=None, station_serial=hub.serial)
    assert not routed(nameless, hub)


def test_a_station_cycle_ends() -> None:
    doorbell = RouteDevice(serial="T8224P1", product_code="T8224", station_serial="T8030P2")
    hub = RouteDevice(
        serial="T8030P2", product_code="T8030", station_serial="T8224P1", firmware="3.8.7.4"
    )
    assert not routed(doorbell, hub)


def test_equal_variants_keep_the_first(monkeypatch: pytest.MonkeyPatch) -> None:
    passing = (("device_version", ">=", "1.0.0.0"),)
    variants = (
        webrtc._Property("is_connect_webrtc", "0", (), ((),)),
        webrtc._Property("is_connect_webrtc__V1", "2", (), (passing,)),  # any case
        webrtc._Property("is_connect_webrtc__v2", "0", (), (passing,)),
    )
    monkeypatch.setattr(webrtc, "_PROPERTIES", {"T0000": variants})
    assert app_webrtc_only(child("T0000", None, "1.0.0.0"))


def test_a_variant_without_read_conditions_is_never_chosen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    props = (
        webrtc._Property("is_connect_webrtc", "2", (), ()),
        webrtc._Property("is_connect_webrtc__v1", "0", (), ()),
    )
    monkeypatch.setattr(webrtc, "_PROPERTIES", {"T0000": props})
    assert app_webrtc_only(child("T0000", None))


def test_only_a_variant_is_no_property(monkeypatch: pytest.MonkeyPatch) -> None:
    readable = ((("device_version", ">=", "1.0.0.0"),),)
    props = (webrtc._Property("is_connect_webrtc__v1", "2", (), readable),)
    monkeypatch.setattr(webrtc, "_PROPERTIES", {"T0000": props})
    assert not app_webrtc_only(child("T0000", None, "1.0.0.0"))


def test_a_station_value_that_is_not_available_is_no_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    later = ((("device_version", ">=", "9.0.0.0"),),)
    props = (webrtc._Property("is_connect_webrtc", "2", later, ()),)
    monkeypatch.setattr(webrtc, "_PROPERTIES", {"T0000": props})
    hub = station("T0000", "1.0.0.0")
    assert not routed(child("T8160", hub), hub)


@pytest.mark.parametrize(
    ("version", "qualifier", "bound", "expected"),
    [
        ("2.0", ">", "1.9", True),
        ("2.0", ">", "2.0", False),
        ("1.9", "<", "2.0", True),
        ("2.0", "<", "2.0", False),
        ("2.0", "=", "2.0.0", True),
        ("2.0", "=", "2.1", False),
        ("2.0", "!=", "2.0", False),
        ("2.1", "!=", "2.0", True),
        ("2.0", ">=", "2.0", True),
        ("2.0", "<=", "2.0", True),
        ("2.1", "<=", "2.0", False),
        ("2.0.beta", "RE", "beta", True),
        ("2.0", "RE", "beta", False),
        ("2.0", "~", "2.0", False),
    ],
)
def test_version_conditions(version: str, qualifier: str, bound: str, expected: bool) -> None:
    assert webrtc._version(version, qualifier, bound) is expected


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("", "T8030", True),
        ("^T8030", "", True),
        ("^T8030", "T8030P1", True),
        ("^T8030", "T8010P1", False),
        ("x" * 512, "x" * 512, True),
        ("x" * 513, "x" * 513, False),
        ("^x", "x" * 2048, True),
        ("^x", "x" * 2049, False),
    ],
)
def test_pattern_conditions(pattern: str, value: str, expected: bool) -> None:
    assert webrtc._regex(pattern, value) is expected


@pytest.mark.parametrize(
    ("text", "number"),
    [
        ("true", 1),
        ("FALSE", 0),
        ("2", 2),
        ("+1", 1),
        (" 0", 0),
        (" 2", 0),
        ("", 0),
        ("2147483647", 2**31 - 1),
        ("2147483648", 0),
        ("-2147483648", -(2**31)),
        ("-2147483649", 0),
    ],
)
def test_values_read_as_numbers(text: str, number: int) -> None:
    assert webrtc._as_int(text) == number


@pytest.mark.parametrize(
    ("text", "codes"),
    [('["T8223","T8224"]', ["T8223", "T8224"]), ("", []), ('{"a": 1}', []), ("[1]", [])],
)
def test_sub_device_lists(text: str, codes: list[str]) -> None:
    assert webrtc._code_list(text) == codes


def test_parent_version_without_a_bound_passes() -> None:
    graph = webrtc._Graph(())
    device = child("T8170", None)
    assert graph.condition(device, "parent_version", ">=", "")
    assert not graph.condition(device, "parent_version", ">=", "1.0")  # no parent listed
    assert not graph.condition(device, "user_country", "=", "DE")


def test_a_cloud_device_as_the_rule_reads_it() -> None:
    device = CloudDevice(
        device_sn=SYNTHETIC.camera_sn,
        device_type=7,
        name="Camera",
        station_sn=SYNTHETIC.station_sn,
        main_sw_version="3.4.3.0",
        raw={"device_new_pn": "T8160"},
    )
    assert route_device(device) == RouteDevice(
        serial=SYNTHETIC.camera_sn,
        product_code="T8160",
        station_serial=SYNTHETIC.station_sn,
        firmware="3.4.3.0",
    )


@pytest.mark.skipif(not CACHE.is_dir(), reason="needs the private thing-model cache")
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_webrtc_routing.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def gen(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """``scripts/gen_webrtc_routing.py``, registered in ``sys.modules`` for this test only."""
    spec = importlib.util.spec_from_file_location(
        "gen_webrtc_routing", ROOT / "scripts" / "gen_webrtc_routing.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_the_generator_refuses_a_condition_the_rule_does_not_evaluate(gen: ModuleType) -> None:
    prop = {
        "identifier": "is_connect_webrtc",
        "read_conditions": {"condition_list": [{"conditions": [{"type": "user_country"}]}]},
    }
    with pytest.raises(SystemExit, match="user_country"):
        gen.conditions("T0000", prop, "read_conditions")


def test_the_generator_reads_an_enum_default(gen: ModuleType) -> None:
    enum = [{"value": "1", "isDefault": 0}, {"value": "2", "isDefault": 1}]
    assert gen.default_value({"data_type": {"specs": {"eunmList": enum}}}) == "2"
    assert gen.default_value({"data_type": {"specs": {"defaultValue": None}}}) == ""
