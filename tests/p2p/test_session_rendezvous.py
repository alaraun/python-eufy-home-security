"""When a station session runs the rendezvous connect beside LAN discovery."""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from ipaddress import IPv4Network
from typing import Any

import pytest

import eufy_home_security.p2p.session as session_module
from eufy_home_security.exceptions import (
    CommunicationError,
    SessionReplacedError,
    StationUnreachableError,
)
from eufy_home_security.p2p import netif
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.p2p.transport import ConnectPath, PPPPTransport, Wake
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

WAKE = Wake(servers=("192.0.2.1",), dsk="x" * 8)


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


class Attempts:
    """Stands in for :meth:`PPPPTransport.connect`: records what each attempt was
    given, fails the first ``fail`` attempts as unanswered, and connects the rest over
    LAN discovery to the fake station, reporting ``path`` as how the link came up."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, fail: int = 0) -> None:
        self.fail = fail
        self.reach: str | None = None
        """Where the fake station is when the session searches no host (a broadcast)."""
        self.redirect: dict[str, str] = {}
        """Searched host -> where the fake station answers from instead (a punched path)."""
        self.path = ConnectPath.LAN
        self.blocked = False
        """Reported as the link's ``lan_reply_blocked``."""
        self.calls: list[dict[str, Any]] = []
        connect = PPPPTransport.connect

        async def recording(transport: PPPPTransport, host: str | None, **kwargs: Any) -> Any:
            self.calls.append({"host": host, **kwargs})
            if len(self.calls) <= self.fail:
                raise StationUnreachableError("no LAN discovery reply")
            kwargs.pop("wake", None)
            kwargs.pop("extra_hosts", None)
            did = await connect(
                transport, self.redirect.get(host or "", host) or self.reach, **kwargs
            )
            transport._path = self.path
            transport._lan_reply_blocked = self.blocked
            return did

        monkeypatch.setattr(PPPPTransport, "connect", recording)
        monkeypatch.setattr(session_module, "DISCOVERY_RETRY_DELAY", 0)

    @property
    def wakes(self) -> list[bool]:
        return [call.get("wake") is not None for call in self.calls]


class WakeSource:
    """A wake provider holding a DSK when ``cached``; any other ask fetches one (a
    cloud call), failing with ``error`` when set."""

    def __init__(self, error: Exception | None = None, *, cached: bool = False) -> None:
        self.asks: list[bool] = []
        """``cached_only`` of each call, in order."""
        self.fetches = 0
        self.error = error
        self.cached = cached

    async def __call__(self, *, cached_only: bool = False) -> Wake | None:
        self.asks.append(cached_only)
        if self.cached:
            return WAKE
        if cached_only:
            return None
        self.fetches += 1
        if self.error is not None:
            raise self.error
        return WAKE


def _session(
    station: FakeStation, wake: WakeSource | None, *, on_demand: bool = False, **kwargs: Any
) -> StationSession:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    return StationSession(
        SYNTHETIC.station_sn,
        credentials,
        host="127.0.0.1",
        port=station.discovery_port,
        did=SYNTHETIC.did,
        on_demand=on_demand,
        wake_provider=wake,
        **kwargs,
    )


async def test_a_held_station_without_a_cached_dsk_searches_the_lan_first(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    wake = WakeSource()
    session = _session(station, wake)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [False]
    assert wake.asks == [True]  # a cached DSK only
    assert wake.fetches == 0  # no cloud call for a station the LAN reaches


async def test_a_held_station_with_a_cached_dsk_runs_the_rendezvous_from_the_first_attempt(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both searches from the start, as the eufy app runs them, when that needs no cloud
    call; the LAN answering first makes the link a LAN one."""
    attempts = Attempts(monkeypatch)
    wake = WakeSource(cached=True)
    session = _session(station, wake)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [True]
    assert wake.asks == [True]
    assert wake.fetches == 0
    assert session.connect_path is ConnectPath.LAN


async def test_a_held_station_adds_the_rendezvous_after_a_lan_attempt_fails(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch, fail=2)
    wake = WakeSource()
    session = _session(station, wake)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, True, True]
    assert wake.asks == [True, False, False]
    assert wake.fetches == 2


async def test_an_on_demand_station_runs_the_rendezvous_from_the_first_attempt(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    wake = WakeSource()
    session = _session(station, wake, on_demand=True)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [True]
    assert wake.asks == [False]  # fetched when not cached: it is what wakes the station


async def test_a_station_last_reached_through_the_servers_goes_there_at_once(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch, fail=1)
    attempts.path = ConnectPath.RENDEZVOUS
    wake = WakeSource()
    session = _session(station, wake)
    try:
        paths = []
        await session.async_connect()
        paths.append(session.connect_path)
        session._teardown("test")
        attempts.path = ConnectPath.LAN
        await session.async_connect()
        paths.append(session.connect_path)
        session._teardown("test")
        await session.async_connect()
    finally:
        await session.async_close()
    assert paths == [ConnectPath.RENDEZVOUS, ConnectPath.LAN]
    # LAN first; then straight to the servers after the rendezvous link; LAN first again.
    assert attempts.wakes == [False, True, True, False]
    assert wake.asks == [True, False, False, True]  # fetched when it was the last path
    stats = session.stats()
    assert stats.connect_path == "lan"
    assert stats.connects_by_path == {"rendezvous": 1, "lan": 2}


async def test_a_session_given_the_rendezvous_path_fetches_its_dsk_on_the_first_attempt(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last link path an owner kept from an earlier run (``connect_path``) is read
    as the session's own: the servers at once, the DSK fetched when none is cached."""
    attempts = Attempts(monkeypatch)
    wake = WakeSource()
    session = _session(station, wake, connect_path=ConnectPath.RENDEZVOUS)
    assert session.stats().connect_path == "rendezvous"
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [True]
    assert wake.asks == [False]
    assert wake.fetches == 1
    assert session.connect_path is ConnectPath.LAN  # the LAN answered: lan from now on


async def test_a_rendezvous_attempt_classifies_by_this_hosts_networks(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An attempt with the rendezvous gives the transport this host's networks, read
    off the event loop; a LAN-only attempt reads none."""
    attempts = Attempts(monkeypatch, fail=1)
    networks = (IPv4Network("192.0.2.0/24"),)
    reads: list[threading.Thread] = []

    def reader() -> tuple[IPv4Network, ...]:
        reads.append(threading.current_thread())
        return networks

    monkeypatch.setattr(netif, "local_networks", reader)
    session = _session(station, WakeSource())
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, True]
    assert [call["local_networks"] for call in attempts.calls] == [None, networks]
    assert len(reads) == 1
    assert reads[0] is not threading.current_thread()


async def test_given_host_networks_are_used_instead_of_the_interfaces(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``local_networks`` given to the session replace the interface reader, for its
    own attempts and for its short-lived sessions."""
    attempts = Attempts(monkeypatch)
    given = (IPv4Network("198.51.100.0/24"),)

    def unread() -> tuple[IPv4Network, ...]:
        raise AssertionError("the interfaces were read")

    monkeypatch.setattr(netif, "local_networks", unread)
    session = _session(station, WakeSource(cached=True), local_networks=given)
    try:
        await session.async_connect()
        extra = session._short_lived_session()
        try:
            await extra.async_connect()
        finally:
            await extra.async_close()
    finally:
        await session.async_close()
    assert [call["local_networks"] for call in attempts.calls] == [given, given]


@pytest.mark.parametrize(("on_demand", "grace"), [(False, True), (True, False)])
async def test_only_a_held_station_holds_its_on_link_punch_for_the_grace(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, on_demand: bool, grace: bool
) -> None:
    """A held station's LAN search gets the on-link grace; a station reached on demand
    is punched at once, as its wake needs."""
    attempts = Attempts(monkeypatch)
    session = _session(station, WakeSource(cached=True), on_demand=on_demand)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert [call["on_link_grace"] for call in attempts.calls] == [grace]


async def test_a_blocked_lan_reply_is_reported_until_a_link_comes_up_without_it(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each link sets ``lan_reply_blocked`` (stats too); while it is set, a reconnect
    runs the rendezvous from its first attempt, its DSK fetched when none is cached."""
    attempts = Attempts(monkeypatch)
    attempts.blocked = True
    wake = WakeSource()
    session = _session(station, wake)
    assert session.lan_reply_blocked is False
    try:
        await session.async_connect()
        seen = [session.lan_reply_blocked, session.stats().lan_reply_blocked]
        session._teardown("test")
        attempts.blocked = False
        await session.async_connect()
        seen += [session.lan_reply_blocked, session.stats().lan_reply_blocked]
        session._teardown("test")
        await session.async_connect()
    finally:
        await session.async_close()
    assert seen == [True, True, False, False]
    # LAN first; at once through the servers while blocked; LAN first again.
    assert attempts.wakes == [False, True, False]
    assert wake.asks == [True, False, True]


async def test_a_held_station_without_rendezvous_material_logs_a_lan_only_attempt(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    Attempts(monkeypatch)
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.p2p.session")
    session = _session(station, WakeSource())
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert any(
        "LAN discovery only on this attempt (no rendezvous servers, or no DSK held)"
        in record.getMessage()
        for record in caplog.records
    )


def test_no_connect_path_before_the_first_link(station: FakeStation) -> None:
    stats = _session(station, WakeSource()).stats()
    assert stats.connect_path is None
    assert stats.connects_by_path == {}


async def test_a_held_station_without_cloud_session_keeps_searching_the_lan(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replaced cloud session costs a held station its rendezvous, not its LAN path."""
    attempts = Attempts(monkeypatch, fail=1)
    wake = WakeSource(SessionReplacedError())
    session = _session(station, wake)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, False]
    assert wake.fetches == 1


async def test_an_on_demand_station_without_cloud_session_fails_at_once(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    session = _session(station, WakeSource(SessionReplacedError()), on_demand=True)
    try:
        with pytest.raises(SessionReplacedError):
            await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.calls == []


async def test_a_cloud_error_leaves_a_held_station_on_the_lan(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch, fail=1)
    session = _session(station, WakeSource(CommunicationError("no route")))
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, False]


async def test_extra_search_hosts_reach_the_transport(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    session = _session(station, None, extra_hosts=("192.0.2.33",))
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.calls[0]["extra_hosts"] == ("192.0.2.33",)
    assert session.extra_hosts == ("192.0.2.33",)


async def test_a_short_lived_session_connects_the_way_the_station_was_reached(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    attempts.path = ConnectPath.RENDEZVOUS
    wake = WakeSource()
    session = _session(station, wake, extra_hosts=("192.0.2.33",))
    try:
        await session.async_connect()
        extra = session._short_lived_session()
        assert extra.connect_path is ConnectPath.RENDEZVOUS
        assert extra.extra_hosts == ("192.0.2.33",)
        try:
            await extra.async_connect()
        finally:
            await extra.async_close()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, True]


async def test_a_short_lived_session_of_a_blocked_station_runs_the_rendezvous_at_once(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    attempts.blocked = True
    session = _session(station, WakeSource())
    try:
        await session.async_connect()
        extra = session._short_lived_session()
        assert extra.lan_reply_blocked is True
        try:
            await extra.async_connect()
        finally:
            await extra.async_close()
    finally:
        await session.async_close()
    assert attempts.wakes == [False, True]


@pytest.mark.parametrize(
    ("peer", "searched", "learned"),
    [
        ("192.0.2.50", (), True),
        ("100.64.0.50", (), True),  # shared address space
        ("192.88.99.50", (), False),
        ("192.88.99.50", ("192.88.99.50",), True),
        ("127.0.0.1", (), False),
        ("not-an-address", (), False),
    ],
)
def test_which_peer_address_is_kept_as_the_station_host(
    peer: str, searched: tuple[str, ...], learned: bool
) -> None:
    """Only a LAN address, or one discovery already searches by unicast, is searched
    next: a station punching from a public address is not looked for there."""
    assert session_module._learns_host(peer, searched) is learned


@pytest.mark.parametrize(
    ("searched", "extra", "learned"),
    [
        ("127.0.0.1", (), "127.0.0.1"),
        (None, ("127.0.0.1",), "127.0.0.1"),
        (None, (), None),
    ],
)
async def test_the_link_address_is_searched_next_only_when_it_may_be(
    station: FakeStation,
    monkeypatch: pytest.MonkeyPatch,
    searched: str | None,
    extra: tuple[str, ...],
    learned: str | None,
) -> None:
    """The station answers from loopback, no LAN address: it is kept as the host only
    when the session searches it by unicast (configured or an extra host)."""
    attempts = Attempts(monkeypatch)
    attempts.reach = "127.0.0.1"
    session = _session(station, None, extra_hosts=extra)
    session._host = session._search_host = searched
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert session.host == learned


async def test_a_link_from_the_configured_host_is_searched_again_after_the_host_moved(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host moved to another address since it was configured; a link that comes
    from the configured (not LAN) address makes it the host again."""
    attempts = Attempts(monkeypatch)
    attempts.redirect = {"192.0.2.99": "127.0.0.1"}
    session = _session(station, None)
    session._search_host = "127.0.0.1"
    session._host = "192.0.2.99"
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.calls[0]["host"] == "192.0.2.99"
    assert session.host == "127.0.0.1"


async def test_the_link_log_names_the_peer_and_the_path(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A link whose peer is not kept as the search host still logs where it came from."""
    attempts = Attempts(monkeypatch)
    attempts.reach = "127.0.0.1"
    attempts.path = ConnectPath.RENDEZVOUS

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn,
        credentials,
        host=None,
        port=station.discovery_port,
        did=SYNTHETIC.did,
        wake_provider=WakeSource(),
    )
    caplog.set_level(logging.INFO, logger="eufy_home_security.p2p.session")
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert session.host is None
    assert any(
        "P2P session established via 127.0.0.1 (rendezvous)" in record.getMessage()
        for record in caplog.records
    )
