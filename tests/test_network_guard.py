"""The suite-wide network guard in ``tests/conftest.py``."""

from __future__ import annotations

import re
import socket

import pytest


def test_a_non_loopback_tcp_connect_is_refused() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(RuntimeError, match=re.escape("192.0.2.1")),
    ):
        sock.connect(("192.0.2.1", 443))


def test_a_non_loopback_datagram_is_refused() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        pytest.raises(RuntimeError, match=re.escape("255.255.255.255")),
    ):
        sock.sendto(b"x", ("255.255.255.255", 32108))


def test_a_udp_route_lookup_passes_but_its_send_is_refused() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))
        except OSError:
            pytest.skip("no route on this host")
        with pytest.raises(RuntimeError, match=re.escape("192.0.2.1")):
            sock.send(b"x")


def test_loopback_is_allowed() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.sendto(b"x", sock.getsockname())
        assert sock.recv(1) == b"x"
