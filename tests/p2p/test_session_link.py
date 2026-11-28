"""The seam between StationSession's protocol half and its link (StationLink).

A fake link that speaks clear JSON stands in for the P2P one: the session's requests,
reply matching, notify dispatch and link-loss handling must work through the
StationLink members alone. The P2P link's own duties toward the session (a reconnect
tears the session down, a teardown closes the transport, a lost transport keeps its
counters) are checked against a fake station.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest

import eufy_home_security.p2p.session as session_module
from eufy_home_security._logging import redact_serial
from eufy_home_security.events import ConnectionChanged, DisconnectCause, Event
from eufy_home_security.exceptions import CloudError, StationUnreachableError
from eufy_home_security.p2p.pppp import MsgType, encode_packet
from eufy_home_security.p2p.session import CommandOutcome, P2PCredentials, StationSession
from eufy_home_security.p2p.session.core import Inbound
from eufy_home_security.p2p.session.link import LinkTuning, StationLink
from eufy_home_security.p2p.transport import SilentLinkError, Wake
from eufy_home_security.p2p.xzyh import Frame, FrameCipher, FrameType
from eufy_home_security.testing import SYNTHETIC, FakeStation

CREDS = P2PCredentials(SYNTHETIC.account_id, "user", "")


class FakeLink:
    """A StationLink over clear JSON: records what the session sends, answers on demand."""

    def __init__(self, session: StationSession, *, answer: bool = True) -> None:
        self._session = session
        self.answer = answer
        self.up = False
        self.generation = 0
        self.sent: list[tuple[int, dict[str, Any]]] = []
        self.drops: list[str] = []
        self.losses = 0

    @property
    def connected(self) -> bool:
        return self.up

    @property
    def link_generation(self) -> int:
        return self.generation

    async def connect(self) -> P2PCredentials:
        self.up = True
        self.generation += 1
        return CREDS

    def drop(self, reason: str) -> None:
        self.up = False
        self.drops.append(reason)

    def lost(self) -> None:
        self.up = False
        self.losses += 1

    def send_command(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int:
        if not self.up:
            raise StationUnreachableError("no link")
        obj = json.loads(plaintext)
        self.sent.append((frame_type, obj))
        if self.answer:
            reply = {"cmd": obj["cmd"], "code": 0}
            asyncio.get_running_loop().call_soon(self.deliver, reply)
        return len(self.sent)

    def acked(self, indices: Sequence[int], channel: int = 0) -> bool:
        return bool(indices)

    def decode_receipt(self, channel: int, frame: Frame) -> tuple[int, int | None] | None:
        return None

    def decode_json(self, frame: Frame, *, plain_rsa: bool) -> dict[str, Any] | None:
        obj = json.loads(frame.payload)
        return obj if isinstance(obj, dict) else None

    def deliver(self, obj: dict[str, Any], channel: int = 0) -> None:
        """Hand the session a notify frame (0x0547) carrying ``obj``."""
        subheader = bytes([FrameCipher.GCM, 0, 0, 0, 0, 0])
        frame = Frame(FrameType.NOTIFY_PAYLOAD, subheader, json.dumps(obj).encode())
        self._session._dispatch(Inbound(channel, frame, self._session))


def _session(*, answer: bool = True) -> tuple[StationSession, FakeLink]:
    async def provider(**_: object) -> P2PCredentials:
        raise AssertionError("the fake link loads no credentials")

    session = StationSession(SYNTHETIC.station_sn, provider)
    link = FakeLink(session, answer=answer)
    session._link = link
    return session, link


def test_the_fake_link_is_a_station_link() -> None:
    session, link = _session()
    as_link: StationLink = link
    assert session._link is as_link


async def test_a_command_goes_out_through_the_link_and_its_reply_applies_it() -> None:
    session, link = _session()

    outcome = await session.async_send_command(1234, channel=0, value3=5)

    assert outcome is CommandOutcome.APPLIED
    assert link.generation == 1
    assert len(link.sent) == 1
    frame_type, sent = link.sent[0]
    assert (frame_type, sent["cmd"], sent["account_id"]) == (
        FrameType.CMD_TRANSFER,
        1234,
        SYNTHETIC.account_id,
    )
    assert session.connected
    assert session._p2p._transport is None  # the P2P link was never used


async def test_a_notification_reaches_the_listeners_through_the_link() -> None:
    session, link = _session()
    await session.async_connect()
    seen: list[tuple[dict[str, Any], FrameCipher]] = []
    session.add_notify_listener(lambda obj, cipher: seen.append((dict(obj), cipher)))

    link.deliver({"cmd": 9999, "payload": {"x": 1}})

    assert seen == [({"cmd": 9999, "payload": {"x": 1}}, FrameCipher.GCM)]


async def test_a_lost_link_fails_the_waiting_request_and_reports_the_outage() -> None:
    session, link = _session(answer=False)
    events: list[Event] = []
    session.subscribe(events.append)
    await session.async_connect()
    session._announce_connected()

    task = asyncio.create_task(session.async_send_command(1234, channel=0, timeout=5.0))
    async with asyncio.timeout(3):
        while not link.sent:
            await asyncio.sleep(0)
    session._on_lost(SilentLinkError("no datagram from the station for 15s"))

    with pytest.raises(StationUnreachableError):
        async with asyncio.timeout(3):
            await task
    assert link.losses == 1
    assert not session.connected
    down = [e for e in events if isinstance(e, ConnectionChanged) and not e.connected]
    assert [(e.cause, e.reason) for e in down] == [
        (DisconnectCause.LINK_SILENT, "no datagram from the station for 15s")
    ]


async def test_closing_the_session_drops_the_link() -> None:
    session, link = _session()
    await session.async_connect()

    await session.async_close()

    assert link.drops == ["closed by the client"]
    assert not session.connected


def test_the_link_reads_the_session_constants_at_their_current_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, _ = _session()
    values = {
        "DISCOVERY_ATTEMPTS": 7,
        "DISCOVERY_TIMEOUT": 1.25,
        "DISCOVERY_RETRY_DELAY": 0.125,
        "HANDSHAKE_TIMEOUT": 2.5,
        "CONN_INIT_MIN_LEN": 11,
        "CONN_INIT_MAX_LEN": 99,
        "RSA_RESULT_WINDOW": 3.5,
    }
    for name, value in values.items():
        monkeypatch.setattr(session_module, name, value)

    assert session._link_tuning() == LinkTuning(
        discovery_attempts=7,
        discovery_timeout=1.25,
        discovery_retry_delay=0.125,
        handshake_timeout=2.5,
        conn_init_min_len=11,
        conn_init_max_len=99,
        rsa_result_window=3.5,
    )


async def test_the_p2p_link_logs_under_the_sessions_redacted_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def provider(**_: object) -> P2PCredentials:
        raise AssertionError("not called")

    async def wake(*, cached_only: bool = False) -> Wake | None:
        raise CloudError("cloud down")

    session = StationSession(SYNTHETIC.station_sn, provider, wake_provider=wake)
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.p2p.session")

    assert await session._p2p._wake(cached_only=False) is None

    lines = [
        r.getMessage() for r in caplog.records if r.name == "eufy_home_security.p2p.session.link"
    ]
    assert lines == [
        f"{redact_serial(SYNTHETIC.station_sn)}: no wake material (cloud down); "
        "trying LAN discovery only"
    ]


# ── the P2P link against a fake station ───────────────────────────────────────


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


def _p2p_session(station: FakeStation) -> StationSession:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    return StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )


async def _wait_until(predicate: Any) -> None:
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0.01)


async def test_a_p2p_reconnect_ends_the_old_connections_requests_and_announcement(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "PARAM_SETTLE", 0.05)
    station.unanswered_commands = {1234}
    session = _p2p_session(station)
    try:
        await session.async_get_params()  # announced: a parameter read answered
        assert session.stats().connected
        session._still_owed.append(("/a/late/still.jpg", time.monotonic() + 60))
        task = asyncio.create_task(session.async_send_command(1234, channel=0, timeout=5.0))
        await _wait_until(lambda: session._waiters)

        await session._p2p.connect()

        with pytest.raises(StationUnreachableError, match="reconnecting"):
            async with asyncio.timeout(3):
                await task
        assert not session._still_owed
        assert session.connected
        assert not session.announced  # until an application reply on the new link
        assert station.conn_inits == 2
    finally:
        await session.async_close()


async def test_a_session_teardown_closes_the_p2p_transport(station: FakeStation) -> None:
    session = _p2p_session(station)
    try:
        await session.async_connect()
        transport = session._p2p._transport
        assert transport is not None
        assert session.connected

        session._teardown("parameter probe unanswered", cause=DisconnectCause.PROBE_UNANSWERED)

        assert not transport.is_open
        assert session._p2p._transport is None
    finally:
        await session.async_close()


async def test_a_lost_transports_wrong_port_drops_stay_counted(station: FakeStation) -> None:
    session = _p2p_session(station)
    loop = asyncio.get_running_loop()
    other, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    try:
        await session.async_connect()
        transport = session._p2p._transport
        assert transport is not None
        assert transport.local_port is not None
        # The station's host, another port: not this session's traffic.
        other.sendto(encode_packet(MsgType.CLOSE), ("127.0.0.1", transport.local_port))
        await _wait_until(lambda: transport.wrong_port_drops == 1)
        assert session.stats().wrong_port_drops == 1

        station.send_close()
        await _wait_until(lambda: session._p2p._transport is None)

        assert session.stats().wrong_port_drops == 1
    finally:
        other.close()
        await session.async_close()
