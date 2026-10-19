"""``rtc/session.py``: the live-call sequence over a fake server and media plane."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, ClassVar

import pytest

from eufy_home_security.exceptions import CallRefusedError, SignalingError, UnsupportedError
from eufy_home_security.rtc.codec import CallBody, MessageType
from eufy_home_security.rtc.config import QuickLogin
from eufy_home_security.rtc.media import CommandRoute
from eufy_home_security.rtc.sdp import CompactOffer, SdpInfo
from eufy_home_security.rtc.session import RtcSession, UnavailableMediaPlane, compact_offer
from eufy_home_security.rtc.signaling import SignalingClient

from .fakes import CONTACT, SESSION_KEY, FakeCrypto, config, start_server, unseal


class FakeMedia:
    instances: ClassVar[list[FakeMedia]] = []

    def __init__(self) -> None:
        self.offer: CompactOffer | None = None
        self.turn: Mapping[str, Any] | None = None
        self.candidates: list[str] = []
        self.commands: list[bytes] = []
        self.closed = False
        FakeMedia.instances.append(self)

    async def start(
        self, offer: CompactOffer, info: SdpInfo, turn: Mapping[str, Any] | None
    ) -> str:
        self.offer, self.turn = offer, turn
        return f"a=ice-ufrag:{info.ice_ufrag}\r\n"

    def add_remote_candidate(self, candidate: str) -> None:
        self.candidates.append(candidate)

    async def send_command(self, data: bytes) -> None:
        self.commands.append(data)

    async def close(self) -> None:
        self.closed = True


class FakeDataChannel:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def recv(self) -> bytes:
        return b""

    async def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _sdp_info_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SdpInfo, "encode", lambda self: bytes(86))


async def _session(**kwargs: Any) -> tuple[Any, RtcSession]:
    server, port = await start_server(**kwargs.pop("server", {}))
    crypto = FakeCrypto()
    cfg = config(**kwargs.pop("cfg", {}))
    session = RtcSession(cfg, crypto, signaling=SignalingClient(cfg, crypto, port=port), **kwargs)
    return server, session


async def test_start_discovers_logs_in_and_pings() -> None:
    server, session = await _session()
    try:
        record = await session.start()
        assert record.contact_id == CONTACT
        async with asyncio.timeout(5):
            while MessageType.MESSAGE not in server.kinds():
                await asyncio.sleep(0.01)
        assert server.kinds()[:3] == [MessageType.DISCOVER, MessageType.LOGIN, MessageType.LOGIN]
    finally:
        await session.close()


async def test_a_quick_login_skips_discover() -> None:
    server, session = await _session(
        cfg={"quick_login": QuickLogin(SESSION_KEY, CONTACT, "127.0.0.1", 9e12)}
    )
    try:
        await session.start()
        assert MessageType.DISCOVER not in server.kinds()
    finally:
        await session.close()


async def test_open_live_answers_the_offer_and_relays_candidates() -> None:
    FakeMedia.instances.clear()
    server, session = await _session(media_factory=FakeMedia)
    try:
        await session.start()
        live = await session.open_live(2, timeout=2)
        media = FakeMedia.instances[-1]
        assert media.offer is not None
        assert media.offer.ice_ufrag == "dev"
        assert media.turn is not None
        assert media.turn["port"] == 3478
        async with asyncio.timeout(2):
            while MessageType.INFO not in server.kinds():
                await asyncio.sleep(0.01)
        info = next(r for r in server.received if r.header.message_type == MessageType.INFO)
        answer = unseal(CallBody.decode(info.body).attachment)
        assert answer == {"request_id": "r1", "sdp": f"a=ice-ufrag:{live.info.ice_ufrag}\r\n"}
        caller = info.addr
        server.device_packet(
            MessageType.INFO,
            CallBody(2, live.call.uuid, CONTACT),
            {"candidate": "candidate:9"},
            caller,
        )
        async with asyncio.timeout(2):
            while not media.candidates:
                await asyncio.sleep(0.01)
        assert media.candidates == ["candidate:9"]
        assert await session.open_live(2) is live
        await session.close_live(2)
        assert media.closed
        assert live.call.ended
    finally:
        await session.close()


async def test_a_refused_call_closes_the_media_plane_and_hangs_up() -> None:
    FakeMedia.instances.clear()
    _server, session = await _session(media_factory=FakeMedia, server={"call_reply": "busy"})
    try:
        await session.start()
        with pytest.raises(CallRefusedError):
            await session.open_live(1, timeout=2)
        assert FakeMedia.instances[-1].closed
    finally:
        await session.close()


async def test_the_unavailable_media_plane_refuses_and_hangs_up() -> None:
    server, session = await _session()
    try:
        await session.start()
        with pytest.raises(UnsupportedError):
            await session.open_live(1, timeout=2)
        async with asyncio.timeout(2):
            while MessageType.HANGUP not in server.kinds():
                await asyncio.sleep(0.01)
    finally:
        await session.close()


async def test_commands_follow_their_route() -> None:
    FakeMedia.instances.clear()
    channel = FakeDataChannel()
    _, session = await _session(media_factory=FakeMedia, data_channel=channel)
    try:
        await session.start()
        with pytest.raises(SignalingError):
            await session.send_command(2, CommandRoute.RTCP, b"open")
        await session.open_live(2, timeout=2)
        await session.send_command(2, CommandRoute.RTCP, b"open")
        await session.send_command(2, CommandRoute.DATA_CHANNEL, b"guard")
        assert FakeMedia.instances[-1].commands == [b"open"]
        assert channel.sent == [b"guard"]
    finally:
        await session.close()
    assert channel.closed


async def test_without_a_data_channel_a_data_command_is_unsupported() -> None:
    _, session = await _session()
    try:
        with pytest.raises(UnsupportedError):
            await session.send_command(0, CommandRoute.DATA_CHANNEL, b"x")
    finally:
        await session.close()


def test_the_offer_must_carry_a_compact_sdp() -> None:
    assert compact_offer({"sdp": {"ice-u": "u"}}).ice_ufrag == "u"
    with pytest.raises(Exception, match="compact SDP"):
        compact_offer({"sdp": "v=0"})


async def test_the_unavailable_media_plane_closes_quietly() -> None:
    plane = UnavailableMediaPlane()
    await plane.close()
    with pytest.raises(UnsupportedError):
        plane.add_remote_candidate("c")
    with pytest.raises(UnsupportedError):
        await plane.send_command(b"x")


async def test_the_session_hands_every_login_record_on() -> None:
    _, port = await start_server()
    records: list[QuickLogin] = []
    session = RtcSession(config(), FakeCrypto(), on_login=records.append)
    session.signaling._port = port
    try:
        await session.start()
        assert [r.contact_id for r in records] == [CONTACT]
    finally:
        await session.close()
