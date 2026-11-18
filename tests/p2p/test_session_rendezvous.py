"""When a station session runs the rendezvous connect beside LAN discovery."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

import eufy_home_security.p2p.session as session_module
from eufy_home_security.exceptions import (
    CommunicationError,
    SessionReplacedError,
    StationUnreachableError,
)
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
        self.path = ConnectPath.LAN
        self.calls: list[dict[str, Any]] = []
        connect = PPPPTransport.connect

        async def recording(transport: PPPPTransport, host: str | None, **kwargs: Any) -> Any:
            self.calls.append({"host": host, **kwargs})
            if len(self.calls) <= self.fail:
                raise StationUnreachableError("no LAN discovery reply")
            kwargs.pop("wake", None)
            kwargs.pop("extra_hosts", None)
            did = await connect(transport, host or self.reach, **kwargs)
            transport._path = self.path
            return did

        monkeypatch.setattr(PPPPTransport, "connect", recording)
        monkeypatch.setattr(session_module, "DISCOVERY_RETRY_DELAY", 0)

    @property
    def wakes(self) -> list[bool]:
        return [call.get("wake") is not None for call in self.calls]


class WakeSource:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    async def __call__(self) -> Wake | None:
        self.calls += 1
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


async def test_a_held_station_the_lan_reaches_never_asks_for_a_rendezvous(
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
    assert wake.calls == 0  # no cloud call for a station the LAN reaches


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
    assert wake.calls == 2


async def test_an_on_demand_station_runs_the_rendezvous_from_the_first_attempt(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch)
    session = _session(station, WakeSource(), on_demand=True)
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert attempts.wakes == [True]


async def test_a_station_last_reached_through_the_servers_goes_there_at_once(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = Attempts(monkeypatch, fail=1)
    attempts.path = ConnectPath.RENDEZVOUS
    session = _session(station, WakeSource())
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
    stats = session.stats()
    assert stats.connect_path == "lan"
    assert stats.connects_by_path == {"rendezvous": 1, "lan": 2}


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
    assert wake.calls == 1


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
