"""LAN paths, local ports, and the cloud's LAN address."""

from __future__ import annotations

import pytest

from eufy_home_security.network import (
    FIRST_SUGGESTED_LOCAL_PORT,
    HostSource,
    LanPath,
    PathWarning,
    check_local_ports,
    lan_address,
    suggest_local_ports,
    with_discovery,
)
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation
from eufy_home_security.testing import SYNTHETIC

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
