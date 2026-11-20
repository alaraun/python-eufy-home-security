"""Which stations a setup step offers, and how."""

from __future__ import annotations

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.inclusion import Reach, StationChoice
from eufy_home_security.network import HostSource, LanPath
from eufy_home_security.p2p.transport import ConnectPath
from eufy_home_security.testing import SYNTHETIC

UNKNOWN_MODEL_SN = "T9999P0000000001"


def _choice(serial: str, *, answered: bool, rendezvous: bool | None = None) -> StationChoice:
    device = CloudDevice(device_sn=serial, device_type=18, name="HB", p2p_did=SYNTHETIC.did)
    camera = CloudDevice(
        device_sn=SYNTHETIC.camera_sn, device_type=19, name="Cam", station_sn=serial, channel=0
    )
    path = LanPath(
        serial=serial,
        name="HB",
        host=None,
        host_source=HostSource.BROADCAST,
        cloud_ip=None,
        observed_ip="192.168.1.5" if answered else None,
        local_port=0,
        answered=answered,
    )
    return StationChoice(
        device=device,
        sub_devices=(camera,),
        path=path,
        rendezvous=rendezvous,
        connects_on_demand=False,
    )


@pytest.mark.parametrize(
    ("serial", "answered", "reach", "default"),
    [
        (SYNTHETIC.station_sn, True, Reach.LOCAL, True),
        (SYNTHETIC.station_sn, False, Reach.REMOTE, False),  # offered, but the user enables it
        (UNKNOWN_MODEL_SN, True, Reach.LOCAL, False),  # reachable, but not in the catalog
    ],
)
def test_a_station_is_enabled_by_default_only_when_local_and_supported(
    serial: str, answered: bool, reach: Reach, default: bool
) -> None:
    choice = _choice(serial, answered=answered)
    assert choice.reach is reach
    assert choice.enabled_by_default is default
    assert choice.supported is (serial == SYNTHETIC.station_sn)
    assert [d.device_sn for d in choice.sub_devices] == [SYNTHETIC.camera_sn]


@pytest.mark.parametrize(
    ("answered", "rendezvous", "via"),
    [
        (True, None, ConnectPath.LAN),
        (False, True, ConnectPath.RENDEZVOUS),  # only its servers reach it
        (True, True, ConnectPath.RENDEZVOUS),  # a connected session whose link came that way
        (True, False, ConnectPath.LAN),
        (False, False, None),
        (False, None, None),  # not probed through the servers (on demand, no DSK)
    ],
)
def test_a_station_any_path_reaches_is_local(
    answered: bool, rendezvous: bool | None, via: ConnectPath | None
) -> None:
    choice = _choice(SYNTHETIC.station_sn, answered=answered, rendezvous=rendezvous)
    assert choice.reachable_via is via
    assert choice.reach is (Reach.REMOTE if via is None else Reach.LOCAL)
    assert choice.enabled_by_default is (via is not None)
