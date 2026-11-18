"""Which stations to include, and how: for a setup step that asks the user.

A station that answers LAN discovery, or a punch through its rendezvous servers, can
be served **locally**: its P2P session gives full control (state, commands,
settings, media) and its own event stream. A station that answers neither (another
site, offline, a battery station off the LAN, which is not probed through the servers)
can still be included **remotely**: its devices and the cloud push events for them
(detections, guard-mode changes as they happen), but nothing that needs the P2P
session: no commands, no settings, no state dumps, no media. The library has no
cloud command path, so a remote station is monitor-only.

:meth:`EufySecurity.async_station_choices` lists every station on the account with
its reach; the chosen ones go back as ``EufySecurity(stations={serial: Reach})``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .cloud.models import CloudDevice
from .devices.types import DeviceModel, connects_on_demand, model_for_serial
from .network import LanPath
from .p2p.transport import ConnectPath


class Reach(StrEnum):
    """How an included station is served."""

    LOCAL = "local"
    """Over LAN P2P: full control."""
    REMOTE = "remote"
    """From the cloud: its devices and push events only."""


@dataclass(frozen=True, slots=True, kw_only=True)
class StationChoice:
    """One station on the account, as a setup step offers it."""

    device: CloudDevice
    sub_devices: tuple[CloudDevice, ...]
    """The cameras and sensors paired to it; they are included with it."""
    path: LanPath
    """Its LAN path after a discovery probe."""
    rendezvous: bool | None = None
    """Whether a punch through its rendezvous servers reached it (a probe, or the link
    of its connected session); None when that was not tried: it answered the LAN probe,
    it is reached on demand, it lists no servers, or its DSK could not be fetched."""

    @property
    def serial(self) -> str:
        return self.device.device_sn

    @property
    def name(self) -> str:
        return self.device.name

    @property
    def model(self) -> DeviceModel | None:
        return model_for_serial(self.serial)

    @property
    def reachable_via(self) -> ConnectPath | None:
        """How a session reaches it: through its rendezvous servers, over the LAN, or
        None when neither answered."""
        if self.rendezvous:
            return ConnectPath.RENDEZVOUS
        return ConnectPath.LAN if self.path.answered else None

    @property
    def reach(self) -> Reach:
        """Local when a session reaches it (:attr:`reachable_via`), remote otherwise."""
        return Reach.REMOTE if self.reachable_via is None else Reach.LOCAL

    @property
    def connects_on_demand(self) -> bool:
        """Whether it is a battery station reached on demand
        (:func:`~.devices.types.connects_on_demand`): one that did not answer the LAN
        probe is not probed through its servers, which would wake it."""
        return connects_on_demand(self.serial)

    @property
    def supported(self) -> bool:
        """Whether the device catalog knows the station's model."""
        return self.model is not None

    @property
    def enabled_by_default(self) -> bool:
        """Local and supported. A remote station is offered, but left for the user to enable."""
        return self.reach is Reach.LOCAL and self.supported
