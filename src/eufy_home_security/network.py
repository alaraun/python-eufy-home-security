"""What the network between this host and a station must allow, for setup-time advice.

The station answers from a random high port that changes every session, so a
firewall cannot match its side. A host or network firewall that filters inbound UDP
has two ways to admit a station's replies, and both name the station's address, so
the station needs a fixed IP (a DHCP reservation):

* allow all UDP from the station's address; or
* pin **one local UDP port per station** (``EufySecurity(local_ports=…)``) and allow
  UDP from the station's address to that port.

Discovery is a broadcast unless the station's address is known (configured, or a
private address from the cloud), and a broadcast only reaches the station's own
network. The cloud's device list often carries no LAN address for a station, or a
public one, so the address worth advising on is where the station *answers* from:
``EufySecurity.async_probe_lan()`` runs one discovery and records it. Nothing in this
module does I/O: :attr:`Station.lan_path` describes one station, :func:`with_discovery`
folds a probe's replies in, and a consumer (the CLI, a config flow) turns the result
into advice.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from .p2p.pppp import DISCOVERY_PORT

if TYPE_CHECKING:
    from .cloud.models import CloudDevice
    from .p2p.discovery import DiscoveredStation

#: Where :func:`suggest_local_ports` starts: the port after the station's discovery port.
FIRST_SUGGESTED_LOCAL_PORT: Final = DISCOVERY_PORT + 1
_MAX_PORT: Final = 65535


class HostSource(StrEnum):
    """Where the address a session searches comes from."""

    CONFIGURED = "configured"
    """Set by the user (``station_hosts``)."""
    CLOUD = "cloud"
    """The private ``local_ip`` the cloud reports for the station."""
    BROADCAST = "broadcast"
    """No address: discovery broadcasts on this host's networks."""


class PathWarning(StrEnum):
    """Something about a station's network path the user should act on."""

    BROADCAST_ONLY = "broadcast_only"
    """No address is configured or reported: discovery is a broadcast, so this host
    must share the station's network, and a firewall rule cannot rely on the address
    the station answers from until that address is fixed."""
    EPHEMERAL_PORT = "ephemeral_port"
    """No local port is pinned: a firewall that filters inbound UDP must allow all
    UDP from the station, or a local port must be pinned for it."""
    ADDRESS_CHANGED = "address_changed"
    """The configured address is not where the station answered from, or not the one
    the cloud reports: its IP changed (give it a fixed lease) or the setting is stale."""
    NO_LAN_REPLY = "no_lan_reply"
    """The station did not answer LAN discovery: it is offline, on another network,
    or a firewall drops its replies."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LanPath:
    """How this host reaches one station over the LAN."""

    serial: str
    name: str
    host: str | None
    """The address discovery is sent to; None broadcasts."""
    host_source: HostSource
    cloud_ip: str | None
    """The private LAN address the cloud reports, if any."""
    observed_ip: str | None
    """The address the station answered from, once a session was established."""
    local_port: int
    """The pinned local UDP port; 0 is an ephemeral port chosen per session."""
    answered: bool | None = None
    """Whether the station answered a discovery probe; None when none was run."""

    @property
    def station_ip(self) -> str | None:
        """The best-known address of the station, for a firewall rule."""
        return self.observed_ip or self.host or self.cloud_ip

    @property
    def warnings(self) -> tuple[PathWarning, ...]:
        found: list[PathWarning] = []
        if self.host is None:
            found.append(PathWarning.BROADCAST_ONLY)
        if not self.local_port:
            found.append(PathWarning.EPHEMERAL_PORT)
        if self.answered is False:
            found.append(PathWarning.NO_LAN_REPLY)
        if self.host is not None and (
            (self.observed_ip is not None and self.observed_ip != self.host)
            or (
                self.host_source is HostSource.CONFIGURED and self.cloud_ip not in (None, self.host)
            )
        ):
            found.append(PathWarning.ADDRESS_CHANGED)
        return tuple(found)


def with_discovery(path: LanPath, did: str | None, replies: Iterable[DiscoveredStation]) -> LanPath:
    """``path`` with a discovery probe folded in: where the station with ``did`` answered.

    A station answering from several addresses (several interfaces) keeps the
    configured one when it is among them.
    """
    addresses = [reply.ip for reply in replies if did is not None and str(reply.did) == did]
    if not addresses:
        return replace(path, answered=False)
    observed = path.host if path.host in addresses else addresses[0]
    return replace(path, answered=True, observed_ip=observed)


def lan_path_for(
    device: CloudDevice,
    *,
    search_host: str | None,
    local_port: int,
    learned_host: str | None = None,
) -> LanPath:
    """The :class:`LanPath` of ``device`` when discovery searches ``search_host``.

    ``learned_host`` is where an established session found the station.
    """
    cloud_ip = lan_address(device.local_ip)
    if search_host is None:
        source = HostSource.BROADCAST
    elif search_host == cloud_ip:
        source = HostSource.CLOUD
    else:
        source = HostSource.CONFIGURED
    return LanPath(
        serial=device.device_sn,
        name=device.name,
        host=search_host,
        host_source=source,
        cloud_ip=cloud_ip,
        observed_ip=learned_host if learned_host != search_host else None,
        local_port=local_port,
    )


def lan_address(local_ip: str | None) -> str | None:
    """The cloud's ``local_ip`` when it is a private address, else None.

    For some devices the field carries the home's public WAN address, which a LAN
    discovery must not be pointed at.
    """
    if not local_ip:
        return None
    try:
        return local_ip if ipaddress.ip_address(local_ip).is_private else None
    except ValueError:
        return None


def check_local_ports(ports: Mapping[str, int]) -> None:
    """Raise ValueError unless every port is 0-65535 and each non-zero one is used once.

    One UDP socket per station: two stations on one pinned port cannot both bind.
    """
    seen: dict[int, str] = {}
    for serial, port in ports.items():
        if not 0 <= port <= _MAX_PORT:
            raise ValueError(f"local port {port} is not 0-{_MAX_PORT}")
        if port and port in seen:
            raise ValueError(f"local port {port} is pinned for two stations; use one per station")
        if port:
            seen[port] = serial


def suggest_local_ports(
    serials: Iterable[str],
    *,
    taken: Collection[int] = (),
    start: int = FIRST_SUGGESTED_LOCAL_PORT,
) -> dict[str, int]:
    """One free local port per serial, counting up from ``start`` in serial order.

    Deterministic for the same input, so a suggestion shown at setup is the one a
    later run would make — but store what the user accepts: adding a station can
    shift the suggestions after it.
    """
    suggested: dict[str, int] = {}
    port = start
    for serial in sorted(set(serials)):
        while port in taken or port == DISCOVERY_PORT:
            port += 1
        if port > _MAX_PORT:
            raise ValueError("no free local port left to suggest")
        suggested[serial] = port
        port += 1
    return suggested
