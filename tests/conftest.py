"""Shared fixtures.

Every identity the tests use is synthetic and defined once, in
:data:`eufy_home_security.testing.SYNTHETIC`; a test that needs a second identity (another
account, another station) defines it locally. Real serials, P2P ids, account ids and LAN
addresses must never appear in this repository (``scripts/check_denylist.py``).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from typing import Any

import pytest

from eufy_home_security.testing import SYNTHETIC


def _loopback(address: object) -> bool:
    """True for a loopback (or non-IP, e.g. AF_UNIX) socket address."""
    if not isinstance(address, tuple) or not address:
        return True
    host = address[0]
    if host in ("", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Refuse any non-loopback packet or TCP connect outside tests marked ``live``.

    A UDP ``connect`` sends nothing (route lookup), so it passes; a later ``send`` on that
    socket is checked against its peer.
    """
    if request.node.get_closest_marker("live"):
        yield
        return

    def refuse(address: object) -> None:
        if not _loopback(address):
            raise RuntimeError(f"test tried to reach {address!r}; mark it live or use a fake")

    connect, connect_ex = socket.socket.connect, socket.socket.connect_ex
    sendto, send = socket.socket.sendto, socket.socket.send

    def checked_connect(self: socket.socket, address: Any) -> None:
        if self.type != socket.SOCK_DGRAM:
            refuse(address)
        connect(self, address)

    def checked_connect_ex(self: socket.socket, address: Any) -> int:
        if self.type != socket.SOCK_DGRAM:
            refuse(address)
        return connect_ex(self, address)

    def checked_sendto(self: socket.socket, *args: Any) -> int:
        refuse(args[-1])
        return sendto(self, *args)

    def checked_send(self: socket.socket, *args: Any) -> int:
        if self.type == socket.SOCK_DGRAM:
            refuse(self.getpeername())
        return send(self, *args)

    monkeypatch.setattr(socket.socket, "connect", checked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", checked_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", checked_sendto)
    monkeypatch.setattr(socket.socket, "send", checked_send)
    yield


@pytest.fixture
def station_sn() -> str:
    return SYNTHETIC.station_sn
