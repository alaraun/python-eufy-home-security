"""This host's directly connected IPv4 networks, read from its interfaces."""

from __future__ import annotations

import errno
import fcntl
import os
import socket
import sys
import threading
from ipaddress import IPv4Network

import pytest

from eufy_home_security.p2p import netif

_ADDR = {
    "lo": ("127.0.0.1", "255.0.0.0"),
    "eth0": ("192.0.2.17", "255.255.255.0"),
    "br0": ("198.51.100.1", "255.255.0.0"),
    "eth1": ("192.0.2.18", "255.255.255.0"),  # a second address on the same /24
}


def _ifreq_reply(name: bytes, address: str) -> bytes:
    """An ``ifreq`` as the kernel returns it: the name, then a ``sockaddr_in``."""
    return name.ljust(16, b"\0") + b"\x02\x00\x00\x00" + socket.inet_aton(address) + bytes(16)


def _fake_ioctl(table: dict[str, tuple[str, str] | int]) -> object:
    """An ``ioctl`` answering SIOCGIFADDR / SIOCGIFNETMASK from ``table``; an int entry
    is the errno the interface raises."""

    def ioctl(_fd: int, request: int, arg: bytes) -> bytes:
        assert len(arg) == 40  # a whole ifreq
        name = arg[:16].rstrip(b"\0")
        entry = table[os.fsdecode(name)]
        if isinstance(entry, int):
            raise OSError(entry, "fake")
        address, mask = entry
        if request == netif.SIOCGIFADDR:
            return _ifreq_reply(name, address)
        assert request == netif.SIOCGIFNETMASK
        return _ifreq_reply(name, mask)

    return ioctl


def _patch(monkeypatch: pytest.MonkeyPatch, table: dict[str, tuple[str, str] | int]) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        socket, "if_nameindex", lambda: [(i, name) for i, name in enumerate(table, 1)]
    )
    monkeypatch.setattr(fcntl, "ioctl", _fake_ioctl(table))


def test_the_networks_of_every_ipv4_interface_but_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, dict(_ADDR))
    assert netif.local_networks() == (
        IPv4Network("192.0.2.0/24"),
        IPv4Network("198.51.0.0/16"),
    )


@pytest.mark.parametrize("error", [errno.EADDRNOTAVAIL, errno.ENODEV])
def test_an_interface_without_ipv4_or_gone_is_skipped(
    monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    _patch(monkeypatch, {"wg0": error, "eth0": _ADDR["eth0"]})
    assert netif.local_networks() == (IPv4Network("192.0.2.0/24"),)


def test_no_ipv4_interface_but_loopback_is_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"lo": _ADDR["lo"], "wg0": errno.EADDRNOTAVAIL})
    assert netif.local_networks() == ()


def test_an_interface_name_that_is_not_utf8_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name the kernel lists with bytes that are not UTF-8 (surrogate-escaped by
    ``if_nameindex``) goes to the ioctl as those bytes."""
    _patch(monkeypatch, {"\udcff": _ADDR["eth0"]})
    assert netif.local_networks() == (IPv4Network("192.0.2.0/24"),)


def test_an_interface_the_ioctl_refuses_as_a_value_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, {"bad0": _ADDR["br0"], "eth0": _ADDR["eth0"]})
    ioctl = fcntl.ioctl

    def refusing(fd: int, request: int, arg: bytes) -> bytes:
        if arg.startswith(b"bad0\0"):
            raise ValueError("fake")
        return ioctl(fd, request, arg)

    monkeypatch.setattr(fcntl, "ioctl", refusing)
    assert netif.local_networks() == (IPv4Network("192.0.2.0/24"),)


def test_a_long_interface_name_is_cut_to_the_kernels_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ifreq`` holds 15 name bytes and a NUL: a longer listed name is sent cut."""
    long_name = "veth0123456789abcdef"
    _patch(monkeypatch, {long_name[:15]: _ADDR["eth0"]})
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, long_name)])
    assert netif.local_networks() == (IPv4Network("192.0.2.0/24"),)


def test_any_other_interface_error_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {"eth0": _ADDR["eth0"], "eth1": errno.EPERM})
    assert netif.local_networks() is None


def test_interfaces_that_cannot_be_listed_are_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, dict(_ADDR))

    def unlisted() -> list[tuple[int, str]]:
        raise OSError(errno.ENOSYS, "fake")

    monkeypatch.setattr(socket, "if_nameindex", unlisted)
    assert netif.local_networks() is None


def test_another_platform_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, dict(_ADDR))
    monkeypatch.setattr(sys, "platform", "darwin")
    assert netif.local_networks() is None


async def test_the_async_reader_runs_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    threads: list[threading.Thread] = []

    def reader() -> tuple[IPv4Network, ...]:
        threads.append(threading.current_thread())
        return (IPv4Network("192.0.2.0/24"),)

    monkeypatch.setattr(netif, "local_networks", reader)
    assert await netif.async_local_networks() == (IPv4Network("192.0.2.0/24"),)
    assert threads
    assert threads[0] is not threading.current_thread()


def test_the_real_reader_answers_on_this_host() -> None:
    """Whatever this host has: a tuple of non-loopback IPv4 networks, or unknown."""
    networks = netif.local_networks()
    assert networks is None or all(not net.is_loopback for net in networks)
