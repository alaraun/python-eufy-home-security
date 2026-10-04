"""Which stations to include, and how: for a setup step that asks the user.

A station that answers LAN discovery can be served **locally**: its P2P session
gives full control (state, commands, settings, media) and its own event stream.
A station that does not answer (another site, another network, offline) can still
be included **remotely**: its devices and the cloud push events for them
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
from .devices.types import DeviceModel, model_for_serial
from .network import LanPath


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
    """Its LAN path after a discovery probe (``path.answered`` decides the reach)."""

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
    def reach(self) -> Reach:
        """Local when it answered the LAN probe, remote otherwise."""
        return Reach.LOCAL if self.path.answered else Reach.REMOTE

    @property
    def supported(self) -> bool:
        """Whether the device catalog knows the station's model."""
        return self.model is not None

    @property
    def enabled_by_default(self) -> bool:
        """Local and supported. A remote station is offered, but left for the user to enable."""
        return self.reach is Reach.LOCAL and self.supported
