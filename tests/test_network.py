"""LAN paths, local ports, and the cloud's LAN address."""

from __future__ import annotations

from dataclasses import replace

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.models import PARAM_LAN_IP
from eufy_home_security.network import (
    FIRST_SUGGESTED_LOCAL_PORT,
    HostSource,
    LanPath,
    PathWarning,
    check_local_ports,
    extra_search_hosts,
    lan_address,
    lan_path_for,
    suggest_local_ports,
    with_discovery,
)
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.cloud import station_device

OTHER_DID = "EUPRAMA-654321-ABCDE"


def _path(**overrides: object) -> LanPath:
    fields: dict[str, object] = {
        "serial": SYNTHETIC.station_sn,
        "name": "Home Base",
        "host": SYNTHETIC.station_ip,
        "host_source": HostSource.CLOUD,
        "cloud_ip": SYNTHETIC.station_ip,
        "observed_ip": None,
        "local_port": 32109,
    }
    fields.update(overrides)
    return LanPath(**fields)  # type: ignore[arg-type]


def test_public_local_ip_is_not_used_for_lan_discovery() -> None:
    assert lan_address(SYNTHETIC.station_ip) == SYNTHETIC.station_ip  # 192.0.2.x counts as private
    assert lan_address("192.168.1.20") == "192.168.1.20"
    assert lan_address("10.0.0.5") == "10.0.0.5"
    assert lan_address("88.196.8.222") is None
    assert lan_address("not an ip") is None
    assert lan_address(None) is None


@pytest.mark.parametrize(
    ("value", "lan"),
    [
        ("192.168.7.21", True),
        ("172.16.0.9", True),
        ("0.0.0.0", False),  # noqa: S104 - names no host
        ("255.255.255.255", False),
        ("127.0.0.1", False),
        ("169.254.3.4", False),
        ("224.0.0.251", False),
        ("240.0.0.1", False),
        ("100.64.0.9", True),  # shared address space
        ("192.88.99.9", False),  # public
        ("fd00::21", False),  # IPv6: discovery is IPv4 only
        ("fe80::1", False),
        ("::1", False),
    ],
)
def test_only_an_ipv4_unicast_lan_address_is_searched(value: str, lan: bool) -> None:
    """The cloud's ``local_ip`` and the address a station reports pass one rule."""
    want = value if lan else None
    assert lan_address(value) == want
    assert extra_search_hosts(_device(None, value), None) == ((value,) if lan else ())
    assert lan_path_for(_device(value, None), search_host=None, local_port=0).cloud_ip == want


def test_a_pinned_cloud_addressed_path_needs_nothing() -> None:
    assert _path().warnings == ()
    assert _path().station_ip == SYNTHETIC.station_ip


def test_path_warnings() -> None:
    broadcast = _path(host=None, host_source=HostSource.BROADCAST, cloud_ip=None, local_port=0)
    assert broadcast.warnings == (PathWarning.BROADCAST_ONLY, PathWarning.EPHEMERAL_PORT)
    assert broadcast.station_ip is None
    assert _path(observed_ip="192.168.1.30", host=None).station_ip == "192.168.1.30"

    configured_elsewhere = _path(host="192.168.1.40", host_source=HostSource.CONFIGURED)
    assert configured_elsewhere.warnings == (PathWarning.ADDRESS_CHANGED,)
    answered_elsewhere = _path(observed_ip="192.168.1.50", answered=True)
    assert answered_elsewhere.warnings == (PathWarning.ADDRESS_CHANGED,)
    assert _path(answered=False).warnings == (PathWarning.NO_LAN_REPLY,)
    assert _path(lan_reply_blocked=True).warnings == (PathWarning.LAN_REPLY_BLOCKED,)
    # A probe the station answered proves its LAN replies arrive.
    assert _path(lan_reply_blocked=True, answered=True).warnings == ()


def test_a_path_carries_whether_the_stations_lan_reply_is_blocked() -> None:
    device = _device(SYNTHETIC.station_ip, None)
    assert lan_path_for(device, search_host=None, local_port=0).lan_reply_blocked is False
    blocked = lan_path_for(device, search_host=None, local_port=0, lan_reply_blocked=True)
    assert PathWarning.LAN_REPLY_BLOCKED in blocked.warnings


def _reply(ip: str, did: str = SYNTHETIC.did) -> DiscoveredStation:
    return DiscoveredStation(ip=ip, port=40000, did=Did.parse(did))


def test_discovery_records_where_the_station_answered() -> None:
    unaddressed = _path(host=None, host_source=HostSource.BROADCAST, cloud_ip=None)
    found = with_discovery(
        unaddressed, SYNTHETIC.did, [_reply("192.168.1.7", OTHER_DID), _reply("192.168.1.9")]
    )
    assert found.answered is True
    assert found.station_ip == "192.168.1.9"  # its own reply, not the neighbour's

    two_interfaces = with_discovery(
        _path(), SYNTHETIC.did, [_reply("10.0.0.9"), _reply(SYNTHETIC.station_ip)]
    )
    assert two_interfaces.observed_ip == SYNTHETIC.station_ip  # the configured one wins
    assert two_interfaces.warnings == ()

    silent = with_discovery(_path(), SYNTHETIC.did, [_reply("192.168.1.7", OTHER_DID)])
    assert silent.answered is False
    assert with_discovery(_path(), None, [_reply(SYNTHETIC.station_ip)]).answered is False


def test_local_ports_are_one_per_station() -> None:
    check_local_ports({SYNTHETIC.station_sn: 32109, SYNTHETIC.camera_sn: 0, "T8400P0000000001": 0})
    with pytest.raises(ValueError, match="two stations"):
        check_local_ports({SYNTHETIC.station_sn: 32109, SYNTHETIC.camera_sn: 32109})
    with pytest.raises(ValueError, match="not 0-65535"):
        check_local_ports({SYNTHETIC.station_sn: 70000})


def test_suggestions_are_stable_and_skip_taken_ports() -> None:
    serials = ["T8400P0000000001", SYNTHETIC.station_sn, "T8030P0000000009"]
    first = suggest_local_ports(serials, taken={FIRST_SUGGESTED_LOCAL_PORT + 1})
    assert first == suggest_local_ports(reversed(serials), taken={FIRST_SUGGESTED_LOCAL_PORT + 1})
    assert sorted(first.values()) == [32109, 32111, 32112]
    assert first["T8030P0000000009"] == FIRST_SUGGESTED_LOCAL_PORT  # serial order
    with pytest.raises(ValueError, match="no free local port"):
        suggest_local_ports(["A", "B"], start=65535)


def _device(local_ip: str | None, lan_ip: str | None) -> CloudDevice:
    entry = station_device(params={PARAM_LAN_IP: lan_ip} if lan_ip is not None else None)
    entry["local_ip"] = local_ip
    return CloudDevice.from_api(entry)


@pytest.mark.parametrize(
    ("given", "want"),
    [
        # No address configured or reported by the cloud: the station's own one is
        # searched beside the broadcast.
        ((None, "192.168.7.21", None), ("192.168.7.21", HostSource.DEVICE, ("192.168.7.21",))),
        (("", "192.168.7.21", None), ("192.168.7.21", HostSource.DEVICE, ("192.168.7.21",))),
        (
            ("192.88.99.9", "192.168.7.21", None),
            ("192.168.7.21", HostSource.DEVICE, ("192.168.7.21",)),
        ),
        # A private cloud address or a configured one is searched instead, alone.
        (("192.168.1.20", "192.168.7.21", None), ("192.168.1.20", HostSource.CLOUD, ())),
        ((None, "192.168.7.21", "192.168.1.40"), ("192.168.1.40", HostSource.CONFIGURED, ())),
        # A reported address that is public or no address at all is not searched.
        ((None, "192.88.99.9", None), (None, HostSource.BROADCAST, ())),
        ((None, "not an ip", None), (None, HostSource.BROADCAST, ())),
        ((None, None, None), (None, HostSource.BROADCAST, ())),
    ],
)
def test_the_station_reported_address_is_searched_when_nothing_else_names_one(
    given: tuple[str | None, str | None, str | None],
    want: tuple[str | None, HostSource, tuple[str, ...]],
) -> None:
    local_ip, lan_ip, configured = given
    host, source, extra = want
    device = _device(local_ip, lan_ip)
    search_host = configured or lan_address(device.local_ip)
    assert extra_search_hosts(device, search_host) == extra
    path = lan_path_for(device, search_host=search_host, local_port=0)
    assert (path.host, path.host_source) == (host, source)


def test_a_path_through_the_reported_address_warns_it_is_not_fixed() -> None:
    """The address a station reports follows its lease: a firewall rule cannot rely on
    it until it is fixed, as for a broadcast."""
    path = lan_path_for(_device(None, "192.168.7.21"), search_host=None, local_port=32109)
    assert path.warnings == (PathWarning.BROADCAST_ONLY,)
    moved = replace(path, observed_ip="192.168.7.99")
    assert moved.warnings == (PathWarning.BROADCAST_ONLY, PathWarning.ADDRESS_CHANGED)
