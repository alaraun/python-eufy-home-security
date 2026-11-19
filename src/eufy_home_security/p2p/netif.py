"""This host's directly connected IPv4 networks, for classifying how a station answered.

A station whose ``PUNCH_PKT`` comes from an address in one of these networks is on a
network this host is attached to, however the punch arrived (see
``docs/protocol/p2p-transport.md`` § Rendezvous connect).

Linux only: each interface's primary IPv4 address and netmask are read with the
``SIOCGIFADDR`` / ``SIOCGIFNETMASK`` ioctls. Secondary addresses (aliases) are not
read, so a station on such a subnet is classified as one outside these networks.
An interface counts whether it is up or down, and a tunnel interface (WireGuard,
tun) counts like any other. Elsewhere, or when the interfaces cannot be read, the
networks are unknown (None). The read is blocking system calls: call
:func:`async_local_networks` from the event loop.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import sys
from ipaddress import IPv4Interface, IPv4Network
from typing import Final

if sys.platform == "linux":
    import fcntl

SIOCGIFADDR: Final = 0x8915
SIOCGIFNETMASK: Final = 0x891B
_IFREQ_SIZE: Final = 40
"""``struct ifreq``: a 16-byte name, then a union whose ``sockaddr_in`` holds the
IPv4 address at bytes 20-23."""
_IFNAMSIZ: Final = 16
_SKIPPED_ERRNOS: Final = frozenset({errno.EADDRNOTAVAIL, errno.ENODEV})
"""An interface without an IPv4 address, or gone since it was listed."""


def local_networks() -> tuple[IPv4Network, ...] | None:
    """The IPv4 networks of this host's interfaces (primary address and netmask),
    loopback left out, each once in interface order; None when they cannot be read
    (not Linux, or an interface error other than :data:`_SKIPPED_ERRNOS`). An
    interface whose request the ioctl refuses as a value is skipped like one
    without IPv4."""
    if sys.platform != "linux":
        return None
    found: dict[IPv4Network, None] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _index, name in socket.if_nameindex():
                try:
                    address = _ioctl_ipv4(sock, SIOCGIFADDR, name)
                    netmask = _ioctl_ipv4(sock, SIOCGIFNETMASK, name)
                except ValueError:
                    continue
                except OSError as err:
                    if err.errno in _SKIPPED_ERRNOS:
                        continue
                    raise
                network = IPv4Interface(f"{address}/{netmask}").network
                if not network.is_loopback:
                    found[network] = None
    except OSError:
        return None
    return tuple(found)


async def async_local_networks() -> tuple[IPv4Network, ...] | None:
    """:func:`local_networks`, read off the event loop."""
    return await asyncio.to_thread(local_networks)


def _ioctl_ipv4(sock: socket.socket, request: int, name: str) -> str:
    """The IPv4 address an ``ifreq`` ioctl returns for interface ``name``, sent as the
    bytes the kernel listed (``os.fsencode``) and cut to its 15-byte limit."""
    request_buffer = os.fsencode(name)[: _IFNAMSIZ - 1].ljust(_IFREQ_SIZE, b"\0")
    reply = fcntl.ioctl(sock.fileno(), request, request_buffer)
    return socket.inet_ntoa(reply[20:24])
