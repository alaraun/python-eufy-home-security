"""``rtc/signaling.py`` against a fake signaling server on localhost."""

from __future__ import annotations

import asyncio
import base64
import itertools
import json
import random
from typing import Any

import pytest

from eufy_home_security.exceptions import (
    CallRefusedError,
    DeviceTimeoutError,
    SignalingError,
    UnsupportedError,
)
from eufy_home_security.rtc import codec, signaling
from eufy_home_security.rtc.codec import BodyType, CallBody, CallKind, MessageBody, MessageType
from eufy_home_security.rtc.config import QuickLogin
from eufy_home_security.rtc.crypto import UnavailableCrypto
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.rtc.signaling import CallEventKind, SignalingClient
from eufy_home_security.testing import SYNTHETIC

from .fakes import (
    APP_ID,
    CONTACT,
    LICENSE,
    PUBLIC_KEY,
    SESSION_KEY,
    USER_ID,
    FakeCrypto,
    FakeServer,
    Received,
    config,
    start_server,
    unseal,
)

NOW = 1_789_000_000.0


async def _client(
    server_kwargs: dict[str, Any] | None = None,
    client_kwargs: dict[str, Any] | None = None,
    **cfg: Any,
) -> tuple[FakeServer, SignalingClient, FakeCrypto]:
    server, port = await start_server(**(server_kwargs or {}))
    crypto = FakeCrypto()
    client = SignalingClient(
        config(**cfg),
        crypto,
        port=port,
        tcp_ports=(server.tcp_port,),
        clock=lambda: NOW,
        **(client_kwargs or {}),
    )
    await client.open()
    return server, client, crypto


async def _logged_in(
    client_kwargs: dict[str, Any] | None = None, **server_kwargs: object
) -> tuple[FakeServer, SignalingClient, FakeCrypto]:
    server, client, crypto = await _client(server_kwargs, client_kwargs)
    await client.discover()
    await client.login()
    return server, client, crypto


async def _until(predicate: object, timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():  # type: ignore[operator]
            await asyncio.sleep(0.01)


async def test_discover_then_login_with_the_key_exchange() -> None:
    server, port = await start_server()
    crypto = FakeCrypto()
    ticks = iter(range(int(NOW), int(NOW) + 100))
    client = SignalingClient(config(), crypto, port=port, clock=lambda: float(next(ticks)))
    await client.open()
    try:
        assert await client.discover() == "127.0.0.1"
        record = await client.login()
        assert (record.session_key, record.contact_id) == (SESSION_KEY, CONTACT)
        assert client.logged_in
        assert client.contact_id == CONTACT
        assert server.kinds() == [MessageType.DISCOVER, MessageType.LOGIN, MessageType.LOGIN]
        reg, exchange = server.received[1], server.received[2]
        assert (reg.header.mode, reg.body) == (codec.WORK_PROTOCOL, b"")
        assert exchange.header.body_type == BodyType.KEY_EXCHANGE
        # The key exchange reuses the challenge's packet id with a new counter.
        assert exchange.header.packet_id == reg.header.packet_id
        assert exchange.header.counter != reg.header.counter
        assert ("seal_session_key", PUBLIC_KEY) in crypto.calls
    finally:
        await client.close()


async def test_every_header_names_the_station_and_one_route() -> None:
    server, client, _ = await _logged_in()
    try:
        assert {r.header.serial for r in server.received} == {SYNTHETIC.station_sn}
        assert len({r.header.route for r in server.received}) == 1
        assert {r.header.sender for r in server.received} == {codec.Endpoint.ANDROID}
    finally:
        await client.close()


async def test_a_refused_key_exchange_raises_with_the_code() -> None:
    _, client, _ = await _client({"refuse_login": True})
    try:
        await client.discover()
        with pytest.raises(SignalingError) as err:
            await client.login()
        assert err.value.code == 401
        assert not client.logged_in
    finally:
        await client.close()


async def test_a_usable_quick_login_takes_one_request() -> None:
    record = QuickLogin(SESSION_KEY, CONTACT, "127.0.0.1", NOW - 3600)
    server, client, crypto = await _client(quick_login=record)
    try:
        assert (await client.login()).contact_id == CONTACT
        assert server.kinds() == [MessageType.LOGIN]
        assert server.received[0].header.body_type == BodyType.CONTACT
        assert server.received[0].header.mode == 0
        assert ("new_session_key", None) not in crypto.calls
    finally:
        await client.close()


async def test_a_refused_quick_login_falls_back_to_the_key_exchange() -> None:
    record = QuickLogin(SESSION_KEY, "x" * 32, "127.0.0.1", NOW)
    server, client, _ = await _client(quick_login=record)
    try:
        assert (await client.login()).contact_id == CONTACT
        assert [r.header.body_type for r in server.received] == [
            BodyType.CONTACT,
            BodyType.KEY_EXCHANGE,
        ]
    finally:
        await client.close()


def test_a_quick_login_record_expires_after_23_hours() -> None:
    record = QuickLogin(SESSION_KEY, CONTACT, "h", NOW)
    assert record.usable(NOW + 82800)
    assert not record.usable(NOW + 82801)
    assert not QuickLogin("short", CONTACT, "h", NOW).usable(NOW)


async def test_discover_retries_then_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signaling, "DISCOVER_TIMEOUT", 0.05)
    server, client, _ = await _client()
    seen: list[bytes] = []
    server.datagram_received = lambda data, addr: seen.append(data)  # type: ignore[method-assign]
    try:
        with pytest.raises(DeviceTimeoutError):
            await client.discover()
        assert len(seen) == signaling.DISCOVER_ATTEMPTS
    finally:
        await client.close()


async def test_the_crypto_placeholder_refuses_at_login() -> None:
    _server, port = await start_server()
    client = SignalingClient(config(), UnavailableCrypto(), port=port, clock=lambda: NOW)
    await client.open()
    try:
        await client.discover()
        with pytest.raises(UnsupportedError):
            await client.login()
    finally:
        await client.close()


async def test_a_call_gets_trying_with_turn_then_the_offer_and_is_acknowledged() -> None:
    server, client, _ = await _logged_in()
    try:
        call = await client.call(CallKind.CHANNEL_P2P, channel=2)
        offer = await call.wait_offer(2)
        assert offer["request_id"] == "r1"
        assert call.device_request_id == "r1"
        assert call.turn is not None
        assert call.turn["port"] == 3478
        sent = next(r for r in server.received if r.header.message_type == MessageType.CALL)
        body = CallBody.decode(sent.body)
        assert (body.channel, body.uuid, body.contact_id) == (2, "", CONTACT)
        assert sent.header.encrypted
        assert sent.header.mode == 0
        attachment = unseal(body.attachment)
        assert attachment["call_type"] == "call"
        assert attachment["eufy_p2p_type"] == "channel_p2p"
        assert attachment["account"] == signaling.md5_hex(f"2{USER_ID}{int(NOW)}")
        assert attachment["eufy_app_id"] == APP_ID
        assert "token" not in attachment
        await _until(lambda: MessageType.ACK in server.kinds())
        ack = next(r for r in server.received if r.header.message_type == MessageType.ACK)
        assert CallBody.decode(ack.body).attachment == b""
    finally:
        await client.close()


async def test_a_busy_device_refuses_the_call() -> None:
    _, client, _ = await _logged_in(call_reply="busy")
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        with pytest.raises(CallRefusedError) as err:
            await call.wait_offer(2)
        assert err.value.code == 486
        assert call.ended
    finally:
        await client.close()


async def test_a_hangup_before_the_offer_refuses_the_call() -> None:
    server, client, _ = await _logged_in(call_reply="trying")
    try:
        call = await client.call(CallKind.CHANNEL_P2P, channel=1)
        caller = server.received[-1].addr
        server.device_packet(MessageType.HANGUP, CallBody(1, "", CONTACT), None, caller)
        with pytest.raises(CallRefusedError, match="hung up"):
            await call.wait_offer(2)
    finally:
        await client.close()


async def test_a_silent_device_times_out() -> None:
    _, client, _ = await _logged_in(call_reply="silent")
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        with pytest.raises(TimeoutError):
            await call.wait_offer(0.1)
    finally:
        await client.close()


async def test_device_info_is_answered_and_delivered() -> None:
    server, client, _ = await _logged_in()
    try:
        call = await client.call(CallKind.CHANNEL_P2P, channel=3)
        await call.wait_offer(2)
        caller = server.received[-1].addr
        server.device_packet(
            MessageType.INFO, CallBody(3, "", CONTACT), {"candidate": "candidate:1"}, caller
        )
        async with asyncio.timeout(2):
            while (event := await call.events.get()).kind is not CallEventKind.INFO:
                pass
        assert event.payload["candidate"] == "candidate:1"
        await _until(
            lambda: any(
                r.header.message_type == MessageType.INFO and r.header.is_response
                for r in server.received
            )
        )
    finally:
        await client.close()


async def test_send_info_carries_the_device_request_id() -> None:
    server, client, _ = await _logged_in()
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        await call.wait_offer(2)
        client.send_info(call, {"sdp": "a=ice-ufrag:x"})
        await _until(lambda: MessageType.INFO in server.kinds())
        info = next(r for r in server.received if r.header.message_type == MessageType.INFO)
        assert info.header.sub_id == 1
        assert info.header.encrypted
        assert unseal(CallBody.decode(info.body).attachment) == {
            "request_id": "r1",
            "sdp": "a=ice-ufrag:x",
        }
    finally:
        await client.close()


async def test_hangup_is_sent_once() -> None:
    server, client, _ = await _logged_in()
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        client.hangup(call)
        client.hangup(call)
        await _until(lambda: MessageType.HANGUP in server.kinds())
        await asyncio.sleep(0.05)
        assert server.kinds().count(MessageType.HANGUP) == 1
    finally:
        await client.close()


async def test_a_private_call_carries_token_and_sdp_info_on_its_own_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SdpInfo, "encode", lambda self: b"\x01" * 86)
    server, client, _ = await _logged_in()
    try:
        info = SdpInfo.generate("k" * 16, "i" * 16)
        call = await client.call(CallKind.PRIV_MEDIA, channel=2, sdp_info=info, boot_action=1)
        await call.wait_offer(2)
        sent = next(r for r in server.received if r.header.message_type == MessageType.CALL)
        body = CallBody.decode(sent.body)
        assert body.uuid.startswith("FF006")
        assert len(body.uuid) == codec.UUID_LEN
        assert sent.header.mode == codec.WORK_PROTOCOL
        attachment = unseal(body.attachment)
        assert (attachment["call_type"], attachment["eufy_p2p_type"]) == ("scall", "priv_p2p")
        assert base64.b64decode(attachment["sdp_info"]) == b"\x01" * 86
        token = base64.b64decode(attachment["token"])
        assert FakeCrypto().open(SESSION_KEY, 0, token) == f"{SYNTHETIC.did}:{LICENSE}".encode()
        assert attachment["boot_action"] == 1
        login_port = server.received[1].addr[1]
        assert sent.addr[1] != login_port
    finally:
        await client.close()


async def test_a_private_call_needs_sdp_info() -> None:
    _, client, _ = await _logged_in()
    try:
        with pytest.raises(ValueError, match="sdp_info"):
            await client.call(CallKind.PRIV_MEDIA)
        with pytest.raises(UnsupportedError):
            await client.call(CallKind.PRIV_MEDIA, sdp_info=SdpInfo.generate("k", "i"))
    finally:
        await client.close()


async def test_a_call_before_login_is_refused() -> None:
    _, client, _ = await _client()
    try:
        with pytest.raises(SignalingError):
            await client.call(CallKind.CHANNEL_P2P)
    finally:
        await client.close()


async def test_the_ping_is_a_sealed_message_with_the_contact() -> None:
    server, client, _ = await _logged_in()
    try:
        client.start_ping(interval=0.02)
        await _until(lambda: server.kinds().count(MessageType.MESSAGE) >= 2)
        ping = next(r for r in server.received if r.header.message_type == MessageType.MESSAGE)
        body = MessageBody.decode(ping.body)
        assert body.is_ping
        assert body.contact_id == CONTACT
        assert ping.header.encrypted
        wrapper = unseal(body.data)
        assert wrapper["to"] == "device"
        content = json.loads(base64.b64decode(wrapper["content"]))
        assert content == {
            "eufy_contact_id": CONTACT,
            "eufy_network_type": 1,
            "eufy_app_id": APP_ID,
        }
    finally:
        await client.close()


async def test_a_device_message_is_answered_200_with_its_ids() -> None:
    server, client, _ = await _logged_in()
    try:
        server.device_message(server.received[-1].addr)
        await _until(
            lambda: any(
                r.header.message_type == MessageType.MESSAGE and r.header.is_response
                for r in server.received
            )
        )
        answer = next(r for r in server.received if r.header.is_response)
        assert (
            answer.header.code,
            answer.header.packet_id,
            answer.header.counter,
            answer.header.route,
        ) == (200, 77, 4, 1)
        assert MessageBody.decode(answer.body).sub_type == 0x66
    finally:
        await client.close()


async def test_garbage_and_unknown_packets_are_dropped() -> None:
    server, client, _ = await _logged_in()
    try:
        addr = server.received[-1].addr
        assert server.transport is not None
        server.transport.sendto(b"\x08\x00garbage", addr)
        server.transport.sendto(b"\x01" * 80, addr)
        await asyncio.sleep(0.05)
        assert client.logged_in
    finally:
        await client.close()


def test_private_call_uuid_is_36_characters() -> None:
    uuid = signaling.private_call_uuid(config(), CallKind.PRIV_MEDIA, 123)
    assert uuid.startswith("FF006")
    assert len(uuid) == 36


def test_license_stays_out_of_the_config_repr() -> None:
    assert LICENSE not in repr(config())


# ── LOGIN retries ────────────────────────────────────────────────────────────


def test_login_waits_grow_threefold_up_to_270_s() -> None:
    for seed in range(20):
        delays = signaling.login_retry_delays(random.Random(seed))
        assert len(delays) == signaling.LOGIN_ATTEMPTS
        assert 11 <= delays[0] <= 20
        for before, after in itertools.pairwise(delays):
            assert after == min(before * 3, 270)
    assert signaling.login_retry_delays(random.Random(0))[-1] <= 270


@pytest.fixture
def short_login_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signaling, "login_retry_delays", lambda rng: [0.05] * 3)


@pytest.mark.usefixtures("short_login_waits")
async def test_an_unanswered_login_is_sent_again() -> None:
    server, client, _ = await _client({"drop_logins": 2})
    try:
        await client.discover()
        assert (await client.login()).contact_id == CONTACT
        regs = [r for r in server.received if r.header.message_type == MessageType.LOGIN]
        assert [r.header.body_type for r in regs] == [BodyType.NONE] * 3 + [BodyType.KEY_EXCHANGE]
        assert len({r.header.counter for r in regs}) == 4
    finally:
        await client.close()


@pytest.mark.usefixtures("short_login_waits")
async def test_a_lost_key_exchange_answer_resends_it_with_the_challenge_id() -> None:
    server, client, _ = await _client()
    seen: list[int] = []

    def drop_first_exchange(item: Received) -> None:
        if item.header.body_type == BodyType.KEY_EXCHANGE and not seen:
            seen.append(1)
            server.drop_logins = 1

    server.on_packet = drop_first_exchange
    try:
        await client.discover()
        await client.login()
        exchanges = [r for r in server.received if r.header.body_type == BodyType.KEY_EXCHANGE]
        assert len(exchanges) == 2
        assert exchanges[0].header.packet_id == exchanges[1].header.packet_id
    finally:
        await client.close()


@pytest.mark.usefixtures("short_login_waits")
async def test_a_login_unanswered_every_time_times_out() -> None:
    server, client, _ = await _client({"drop_logins": 99})
    try:
        with pytest.raises(DeviceTimeoutError):
            await client.login()
        assert server.kinds().count(MessageType.LOGIN) == 3
        assert not client.logged_in
    finally:
        await client.close()


# ── re-discover flag ─────────────────────────────────────────────────────────


async def test_the_rediscover_flag_runs_discover_and_a_quick_relogin() -> None:
    records: list[QuickLogin] = []
    server, client, _ = await _logged_in({"on_login": records.append})
    try:
        assert len(records) == 1
        before = len(server.received)
        server.device_message(server.received[-1].addr, flags=codec.FLAG_REDISCOVER)
        await _until(lambda: len(records) == 2)
        later = [r.header for r in server.received[before:] if not r.header.is_response]
        assert [h.message_type for h in later] == [MessageType.DISCOVER, MessageType.LOGIN]
        assert later[1].body_type == BodyType.CONTACT
        assert records[1].contact_id == CONTACT
        assert records[1].logged_in_at == records[0].logged_in_at == NOW
    finally:
        await client.close()


async def test_the_rediscover_flag_before_login_is_ignored() -> None:
    server, client, _ = await _client()
    try:
        await client.discover()
        server.device_message(server.received[-1].addr, flags=codec.FLAG_REDISCOVER)
        await asyncio.sleep(0.05)
        assert server.kinds() == [MessageType.DISCOVER]
    finally:
        await client.close()


# ── CALL wake over TCP ───────────────────────────────────────────────────────


@pytest.fixture
def short_call_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signaling, "CALL_REPLY_TIMEOUT", 0.05)


@pytest.mark.usefixtures("short_call_reply")
async def test_an_unanswered_call_is_sent_plain_over_tcp_and_answered_there() -> None:
    server, client, _ = await _logged_in(udp_calls=False)
    try:
        call = await client.call(CallKind.CHANNEL_P2P, channel=2)
        offer = await call.wait_offer(2)
        assert offer["request_id"] == "r1"
        calls = [r for r in server.received if r.header.message_type == MessageType.CALL]
        assert [r.via for r in calls] == ["udp", "tcp"]
        assert calls[1].header.transport_flag == 0
        assert calls[1].header.request_id == calls[0].header.request_id
        assert calls[1].body == calls[0].body
        await _until(lambda: MessageType.ACK in server.kinds())
        ack = next(r for r in server.received if r.header.message_type == MessageType.ACK)
        assert ack.via == "udp"
    finally:
        await client.close()


@pytest.mark.usefixtures("short_call_reply")
async def test_an_answered_call_is_not_sent_over_tcp() -> None:
    server, client, _ = await _logged_in(call_reply="trying")
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        await _until(call.answered.is_set)
        await asyncio.sleep(0.2)
        assert all(r.via == "udp" for r in server.received)
    finally:
        await client.close()


@pytest.mark.usefixtures("short_call_reply")
async def test_the_tcp_wake_gives_up_after_its_attempts() -> None:
    server, client, _ = await _logged_in(call_reply="silent")
    try:
        await client.call(CallKind.CHANNEL_P2P)
        await _until(lambda: not client._wake_tasks)
        tcp = [r for r in server.received if r.via == "tcp"]
        assert len(tcp) == signaling.WAKE_ATTEMPTS
    finally:
        await client.close()


@pytest.mark.usefixtures("short_call_reply")
async def test_no_tcp_wake_when_disabled_or_hung_up() -> None:
    server, client, _ = await _logged_in(call_reply="silent")
    try:
        await client.call(CallKind.CHANNEL_P2P, wake=False)
        client.hangup(await client.call(CallKind.CHANNEL_P2P))
        await asyncio.sleep(0.2)
        assert all(r.via == "udp" for r in server.received)
    finally:
        await client.close()


@pytest.mark.usefixtures("short_call_reply")
async def test_a_refused_tcp_connection_is_survived() -> None:
    server, client, _ = await _logged_in(call_reply="silent")
    assert server.tcp is not None
    server.tcp.close()
    await server.tcp.wait_closed()
    try:
        call = await client.call(CallKind.CHANNEL_P2P)
        await _until(lambda: not client._wake_tasks)
        assert not call.answered.is_set()
    finally:
        await client.close()


async def test_the_quick_login_record_keeps_the_login_time() -> None:
    _, port = await start_server()
    now = [NOW]
    client = SignalingClient(config(), FakeCrypto(), port=port, clock=lambda: now[0])
    await client.open()
    try:
        await client.login()
        now[0] += 600
        record = client.quick_login()
        assert record is not None
        assert record.logged_in_at == NOW
    finally:
        await client.close()
