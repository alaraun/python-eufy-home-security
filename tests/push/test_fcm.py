"""PushListener: Android registration shape, token re-upload, dedupe, isolation."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
import ssl
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import aiohttp
import pytest
from aioresponses import CallbackResult, aioresponses
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from firebase_messaging.const import FCM_INSTALLATION, GCM_CHECKIN_URL, GCM_REGISTER_URL
from firebase_messaging.proto.checkin_pb2 import AndroidCheckinRequest

from eufy_home_security._logging import set_secret_logging
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.events import EventSource, SecurityEvent
from eufy_home_security.exceptions import (
    CloudApiError,
    CloudError,
    CommunicationError,
    EufySecurityError,
    RateLimitedError,
    SessionReplacedError,
)
from eufy_home_security.push import const as push_const
from eufy_home_security.push import fcm as fcm_module
from eufy_home_security.push.fcm import PushListener, _EufyFcmPushClient, _fcm_config
from eufy_home_security.storage import CACHE_VERSION, MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC

from .conftest import (
    FAKE_ANDROID_ID,
    FAKE_FCM_TOKEN,
    FAKE_SECURITY_TOKEN,
    FakeCloud,
    checkin_body,
    install_google_mocks,
)

_INSTALL_URL = f"{FCM_INSTALLATION}projects/{push_const.FCM_PROJECT_ID}/installations"
_real_sleep = asyncio.sleep


def _ignore_event(event: SecurityEvent) -> None:
    """An event sink for a listener whose events a test does not look at."""


def _listener(
    cloud: FakeCloud,
    cache: SessionCache,
    session: aiohttp.ClientSession,
    events: list[SecurityEvent],
) -> PushListener:
    return PushListener(cast(EufyCloudApi, cloud), cache, events.append, session=session)


@pytest.fixture(autouse=True)
def _no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never open a real MCS socket in these tests."""

    async def fake_start(self: Any) -> None:
        self.do_listen = True

    async def fake_stop(self: Any) -> None:
        self.do_listen = False

    monkeypatch.setattr("firebase_messaging.FcmPushClient.start", fake_start)
    monkeypatch.setattr("firebase_messaging.FcmPushClient.stop", fake_stop)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Make the module's retry/backoff/supervision sleeps instant, and record them."""
    recorded: list[float] = []

    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)
        await _real_sleep(0)

    monkeypatch.setattr(fcm_module, "_sleep", fake_sleep)
    return recorded


async def test_start_registers_android_flavour_and_uploads_token(
    fake_cloud: FakeCloud, cache: SessionCache
) -> None:
    register_body: dict[str, Any] = {}
    with aioresponses() as mock:
        install_google_mocks(mock, register_body)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            assert listener.running
            assert listener.token == FAKE_FCM_TOKEN
            await listener.async_stop()

    # The c2dm/register3 form is the app's Android shape.
    assert register_body["app"] == push_const.APP_PACKAGE
    assert register_body["cert"] == push_const.APP_CERT_SHA1
    assert register_body["sender"] == push_const.FCM_SENDER_ID
    # And the token was uploaded to eufy.
    assert fake_cloud.registered == [FAKE_FCM_TOKEN]
    # Credentials were cached for reuse.
    assert (
        cache.section("push")["fcm_credentials"]["fcm"]["registration"]["token"] == FAKE_FCM_TOKEN
    )


async def test_credentials_are_logged_in_clear_only_with_secret_logging(
    fake_cloud: FakeCloud, cache: SessionCache, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.push")
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            await listener.async_stop()
            assert FAKE_FCM_TOKEN[-4:] in caplog.text
            assert FAKE_FCM_TOKEN not in caplog.text
            assert str(FAKE_SECURITY_TOKEN) not in caplog.text
            caplog.clear()
            set_secret_logging(True)
            try:
                await listener.async_start()
                await listener.async_stop()
            finally:
                set_secret_logging(False)
    assert FAKE_FCM_TOKEN in caplog.text
    assert str(FAKE_SECURITY_TOKEN) in caplog.text


async def test_token_is_reregistered_on_every_start(
    fake_cloud: FakeCloud, cache: SessionCache
) -> None:
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            await listener.async_stop()
            # A restart reuses the cached device but re-uploads the token.
            await listener.async_start()
            await listener.async_stop()
    assert fake_cloud.registered == [FAKE_FCM_TOKEN, FAKE_FCM_TOKEN]


async def test_incoming_message_becomes_an_event() -> None:
    events: list[SecurityEvent] = []
    listener = PushListener(
        cast(EufyCloudApi, FakeCloud()),
        _throwaway_cache(),
        events.append,
        session=cast(aiohttp.ClientSession, object()),
    )
    listener._on_message(
        {"type": "30", "span_id": "s1", "payload": _arming_payload()}, "pid-1", None
    )
    assert len(events) == 1
    assert events[0].source is EventSource.CLOUD
    assert events[0].guard_mode == 1


async def test_span_id_dedupe() -> None:
    events: list[SecurityEvent] = []
    listener = PushListener(
        cast(EufyCloudApi, FakeCloud()),
        _throwaway_cache(),
        events.append,
        session=cast(aiohttp.ClientSession, object()),
    )
    msg = {"type": "30", "span_id": "dup", "payload": _arming_payload()}
    listener._on_message(msg, "pid-1", None)
    listener._on_message(msg, "pid-2", None)  # redelivered
    assert len(events) == 1


async def test_a_raising_callback_does_not_propagate() -> None:
    def boom(_event: SecurityEvent) -> None:
        raise RuntimeError("subscriber blew up")

    listener = PushListener(
        cast(EufyCloudApi, FakeCloud()),
        _throwaway_cache(),
        boom,
        session=cast(aiohttp.ClientSession, object()),
    )
    # Must not raise out of the socket handler.
    listener._on_message({"type": "30", "span_id": "x", "payload": _arming_payload()}, "pid", None)


@pytest.mark.parametrize(
    ("setup", "error"),
    [
        (lambda m: m.post(_INSTALL_URL, status=403, repeat=True), CloudApiError),
        (
            lambda m: m.post(
                GCM_CHECKIN_URL, exception=aiohttp.ClientConnectionError("down"), repeat=True
            ),
            CommunicationError,
        ),
        (lambda m: m.post(_INSTALL_URL, payload={"nope": 1}, repeat=True), CloudApiError),
        (lambda m: m.post(_INSTALL_URL, body="not json", repeat=True), CloudApiError),
        (
            lambda m: m.post(GCM_REGISTER_URL, body="Error=AUTHENTICATION_FAILED", repeat=True),
            CloudApiError,
        ),
        (lambda m: m.post(GCM_REGISTER_URL, status=503, repeat=True), CommunicationError),
    ],
)
async def test_registration_failures_are_typed(
    fake_cloud: FakeCloud,
    cache: SessionCache,
    sleeps: list[float],
    setup: Any,
    error: type[EufySecurityError],
) -> None:
    with aioresponses() as mock:
        setup(mock)  # registered first, so it wins over the working mocks
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            with pytest.raises(error):
                await listener.async_start()
            assert not listener.running
            await listener.async_stop()
    assert fake_cloud.registered == []


async def test_token_upload_outcome_is_reported(fake_cloud: FakeCloud, cache: SessionCache) -> None:
    outcomes: list[CloudError | None] = []
    kicked = SessionReplacedError()
    fake_cloud.failures = [kicked]
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = PushListener(
                cast(EufyCloudApi, fake_cloud),
                cache,
                _ignore_event,
                session=session,
                on_token_upload=outcomes.append,
            )
            with pytest.raises(SessionReplacedError):
                await listener.async_start()
            await listener.async_start()
            await listener.async_stop()
    assert outcomes == [kicked, None]


async def test_unexpected_start_error_is_wrapped(
    cache: SessionCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenCloud(FakeCloud):
        async def async_register_push_token(self, token: str) -> None:
            raise KeyError("token")

    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(BrokenCloud(), cache, session, [])
            with pytest.raises(CommunicationError) as info:
                await listener.async_start()
    assert isinstance(info.value.__cause__, KeyError)


async def test_retries_do_not_sleep_after_the_last_attempt(
    fake_cloud: FakeCloud, cache: SessionCache, sleeps: list[float]
) -> None:
    with aioresponses() as mock:
        mock.post(GCM_REGISTER_URL, status=400, body="Error=X", repeat=True)
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(CloudApiError):
                await _listener(fake_cloud, cache, session, []).async_start()
    assert sleeps == [2 * n for n in range(1, push_const.REGISTER_RETRIES)]


async def test_start_has_an_overall_deadline(
    cache: SessionCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    class HangingCloud(FakeCloud):
        async def async_register_push_token(self, token: str) -> None:
            await _real_sleep(30)

    monkeypatch.setattr(push_const, "START_DEADLINE_SECONDS", 0.05)
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(HangingCloud(), cache, session, [])
            with pytest.raises(CommunicationError, match="within"):
                await listener.async_start()


async def test_second_start_is_a_noop(fake_cloud: FakeCloud, cache: SessionCache) -> None:
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await asyncio.gather(listener.async_start(), listener.async_start())
            first = listener._client
            await listener.async_start()
            assert listener._client is first
            await listener.async_stop()
            assert listener._client is None
            assert not listener.running
    assert fake_cloud.registered == [FAKE_FCM_TOKEN]


def _checkin_recorder(mock: aioresponses, requests: list[AndroidCheckinRequest]) -> None:
    """Record each checkin request; register before install_google_mocks (first match wins)."""

    def record(url: Any, **kwargs: Any) -> CallbackResult:
        req = AndroidCheckinRequest()
        req.ParseFromString(kwargs["data"])
        requests.append(req)
        return CallbackResult(status=200, body=checkin_body())

    mock.post(GCM_CHECKIN_URL, callback=record, repeat=True)


async def test_restart_reuses_the_stored_device(fake_cloud: FakeCloud, cache: SessionCache) -> None:
    requests: list[AndroidCheckinRequest] = []
    with aioresponses() as mock:
        _checkin_recorder(mock, requests)
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            await listener.async_stop()
            await listener.async_start()
            await listener.async_stop()
    assert len(requests) == 2
    assert not requests[0].HasField("id")  # first start: a new device
    assert requests[1].id == FAKE_ANDROID_ID  # restart: "this device again"
    assert requests[1].security_token == FAKE_SECURITY_TOKEN


def _stored_credentials(cache: SessionCache, android_id: int = 42) -> None:
    cache.section("push")["fcm_credentials"] = {
        "gcm": {"android_id": android_id, "security_token": 7, "token": "old"},
        "fcm": {"registration": {"token": "old-token"}},
    }


async def test_checkin_outage_keeps_the_stored_device(
    fake_cloud: FakeCloud, cache: SessionCache, sleeps: list[float]
) -> None:
    _stored_credentials(cache)
    with aioresponses() as mock:
        mock.post(GCM_CHECKIN_URL, status=503, repeat=True)
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(CommunicationError):
                await _listener(fake_cloud, cache, session, []).async_start()
    assert cache.section("push")["fcm_credentials"]["gcm"]["android_id"] == 42
    assert sleeps == [1, 2]  # CHECKIN_RETRIES tries, no sleep after the last


async def test_checkin_rejection_registers_a_new_device(
    fake_cloud: FakeCloud, cache: SessionCache
) -> None:
    _stored_credentials(cache)
    with aioresponses() as mock:
        mock.post(GCM_CHECKIN_URL, status=403)  # once: the stored device is rejected
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            await listener.async_stop()
    gcm = cache.section("push")["fcm_credentials"]["gcm"]
    assert gcm["android_id"] == str(FAKE_ANDROID_ID)
    assert listener.token == FAKE_FCM_TOKEN


async def test_supervisor_restarts_a_dead_client_with_growing_backoff(
    fake_cloud: FakeCloud,
    cache: SessionCache,
    sleeps: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts: list[object] = []

    async def dies_at_once(self: Any) -> None:
        starts.append(self)
        self.do_listen = False  # what firebase-messaging's _terminate leaves behind

    monkeypatch.setattr("firebase_messaging.FcmPushClient.start", dies_at_once)
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            assert not listener.running  # the real client state, not "start was called"
            for _ in range(5000):
                if len(starts) >= 11:
                    break
                await _real_sleep(0)
            await listener.async_stop()
            assert listener._supervisor is None

    assert len(starts) >= 11
    assert len(set(map(id, starts))) == len(starts)  # a fresh client each time
    backoff = [d for d in sleeps if d != push_const.SUPERVISE_INTERVAL]
    assert backoff[:9] == [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 320.0, 600.0, 600.0]
    assert len(fake_cloud.registered) == len(starts)  # the token is re-uploaded per restart


async def test_supervisor_waits_out_a_cloud_hold_off(
    fake_cloud: FakeCloud,
    cache: SessionCache,
    sleeps: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts: list[object] = []

    async def dies_once(self: Any) -> None:
        starts.append(self)
        if len(starts) == 1:
            self.do_listen = False

    monkeypatch.setattr("firebase_messaging.FcmPushClient.start", dies_once)
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            fake_cloud.failures = [
                RateLimitedError("held off", retry_after=1800.0),
                CommunicationError("down"),
            ]
            for _ in range(5000):
                if len(starts) >= 2:
                    break
                await _real_sleep(0)
            await listener.async_stop()

    backoff = [d for d in sleeps if d != push_const.SUPERVISE_INTERVAL]
    # The hold-off replaces the 5 s step; the backoff itself keeps doubling.
    assert backoff[:2] == [1800.0, 10.0]
    assert len(starts) == 2


async def test_listening_transitions_are_reported(
    fake_cloud: FakeCloud,
    cache: SessionCache,
    sleeps: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts: list[object] = []
    reports: list[tuple[bool, EufySecurityError | None]] = []

    async def dies_once(self: Any) -> None:
        starts.append(self)
        self.do_listen = len(starts) > 1

    monkeypatch.setattr("firebase_messaging.FcmPushClient.start", dies_once)
    down = CommunicationError("down")
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = PushListener(
                cast(EufyCloudApi, fake_cloud),
                cache,
                lambda _event: None,
                session=session,
                on_listening=lambda running, error: reports.append((running, error)),
            )
            await listener.async_start()
            fake_cloud.failures = [down]  # the first restart fails at the token upload
            for _ in range(5000):
                if len(reports) >= 4:
                    break
                await _real_sleep(0)
            assert listener.running
            await listener.async_stop()

    assert [running for running, _ in reports] == [True, False, False, True, False]
    assert reports[0][1] is None
    assert isinstance(reports[1][1], CommunicationError)  # found stopped listening
    assert reports[2][1] is down  # the failed restart
    assert reports[3][1] is None
    assert reports[4][1] is None
    assert len(starts) == 2


async def test_supervisor_leaves_a_healthy_client_alone(
    fake_cloud: FakeCloud, cache: SessionCache, sleeps: list[float]
) -> None:
    with aioresponses() as mock:
        install_google_mocks(mock)
        async with aiohttp.ClientSession() as session:
            listener = _listener(fake_cloud, cache, session, [])
            await listener.async_start()
            client = listener._client
            for _ in range(50):
                await _real_sleep(0)
            assert listener._client is client
            assert listener.running
            await listener.async_stop()
    assert set(sleeps) == {push_const.SUPERVISE_INTERVAL}


async def test_dedupe_ring_survives_a_restart() -> None:
    store = MemoryStore()
    first: list[SecurityEvent] = []
    cache = SessionCache(store, SYNTHETIC.email)
    await cache.async_load()
    listener = _bare_listener(cache, first)
    msg = {"type": "30", "span_id": "persisted", "payload": _arming_payload()}
    listener._on_message(msg, "pid-1", None)
    await listener.async_stop()  # persists the ring

    again: list[SecurityEvent] = []
    reloaded = SessionCache(store, SYNTHETIC.email)
    await reloaded.async_load()
    _bare_listener(reloaded, again)._on_message(msg, "pid-2", None)  # redelivered
    assert len(first) == 1
    assert again == []


async def test_the_ring_is_stored_compact_and_an_older_list_migrates() -> None:
    now = int(time.time())
    store = MemoryStore(
        {
            "version": CACHE_VERSION,
            "account": SYNTHETIC.email,
            "push": {"seen_spans": [["listed", now - 60]]},  # the older shape
        }
    )
    cache = SessionCache(store, SYNTHETIC.email)
    await cache.async_load()
    events: list[SecurityEvent] = []
    listener = _bare_listener(cache, events)
    listener._on_message({"type": "30", "span_id": "listed", "payload": ""}, "p1", None)
    listener._on_message({"type": "30", "span_id": "fresh", "payload": ""}, "p2", None)
    await listener.async_stop()
    assert [e.push_id for e in events] == ["fresh"]
    assert store.data is not None
    stored = store.data["push"]["seen_spans"]
    assert isinstance(stored, dict)
    assert stored["listed"] == now - 60
    assert list(stored) == ["listed", "fresh"]


async def test_delivery_state_is_saved_later_and_on_stop() -> None:
    saves: list[dict[str, Any]] = []

    class RecordingStore(MemoryStore):
        async def async_save(self, data: dict[str, Any]) -> None:
            saves.append(data)

    cache = SessionCache(RecordingStore(), SYNTHETIC.email)
    await cache.async_load()
    listener = _bare_listener(cache, [])
    listener._on_message({"type": "30", "span_id": "s1", "payload": ""}, "p1", None)
    await _real_sleep(0)
    assert saves == []  # batched, not written per push
    await listener.async_stop()
    assert list(saves[-1]["push"]["seen_spans"]) == ["s1"]


async def test_dedupe_falls_back_to_persistent_id() -> None:
    events: list[SecurityEvent] = []
    listener = _bare_listener(_throwaway_cache(), events)
    msg = {"type": "30", "payload": _arming_payload()}  # no span_id
    listener._on_message(msg, "pid-1", None)
    listener._on_message(msg, "pid-1", None)
    listener._on_message(msg, "pid-2", None)
    assert len(events) == 2


async def test_pushes_for_other_apps_are_dropped() -> None:
    events: list[SecurityEvent] = []
    listener = _bare_listener(_throwaway_cache(), events)
    listener._on_message(
        {"app_tab": "eufy_home", "span_id": "vac", "payload": _arming_payload()}, "p", None
    )
    assert events == []


def test_deleted_messages_notice_is_ignored() -> None:
    calls: list[object] = []
    client = _EufyFcmPushClient(
        lambda *args: calls.append(args), _fcm_config(), None, None, openudid="0123456789abcdef"
    )
    kv = SimpleNamespace(key="message_type", value="deleted_messages")
    client._handle_data_message(SimpleNamespace(app_data=[kv], persistent_id="p"))
    assert calls == []


# ── helpers ──────────────────────────────────────────────────────────────────


def _bare_listener(cache: SessionCache, events: list[SecurityEvent]) -> PushListener:
    return PushListener(
        cast(EufyCloudApi, FakeCloud()),
        cache,
        events.append,
        session=cast(aiohttp.ClientSession, object()),
    )


def _arming_payload() -> str:
    return base64.b64encode(json.dumps({"arming": 1, "mode": 1}).encode()).decode()


def _throwaway_cache() -> SessionCache:
    return SessionCache(MemoryStore(), "user@example.com")


# ── stopping ─────────────────────────────────────────────────────────────────


def _self_signed() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """A server context with a throwaway certificate and a client context trusting nothing."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = Path(tmp) / "c.pem", Path(tmp) / "k.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context()
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    return server, client


async def test_the_mcs_socket_closes_at_once_when_the_server_ignores_close_notify() -> None:
    """The MCS server does not answer TLS close_notify; a graceful close waits 30 s."""
    server_ctx, client_ctx = _self_signed()
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    release = threading.Event()

    def deaf_peer() -> None:
        # Two connections: TLS handshake, then never read again (no close_notify reply).
        held = []
        for _ in range(2):
            conn, _addr = listener.accept()
            held.append(server_ctx.wrap_socket(conn, server_side=True))
        release.wait(10)
        for tls in held:
            tls.close()

    thread = threading.Thread(target=deaf_peer, daemon=True)
    thread.start()
    try:
        _, plain = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx)
        plain.close()
        with pytest.raises(TimeoutError):  # the peer really leaves the close hanging
            await asyncio.wait_for(plain.wait_closed(), 0.5)
        plain.transport.abort()

        client = _EufyFcmPushClient(
            _ignore_event, _fcm_config(), None, None, openudid="0123456789abcdef"
        )
        _, client.writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx)
        transport = client.writer.transport
        started = time.monotonic()
        await client._do_writer_close()
        assert time.monotonic() - started < 0.5
        assert transport.is_closing()
        writer: object = client.writer
        assert writer is None
    finally:
        release.set()
        await asyncio.to_thread(thread.join, 5)
        listener.close()


async def test_stopping_does_not_wait_for_a_client_task_that_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(push_const, "STOP_TIMEOUT", 0.1)
    hang = asyncio.Event()

    async def closing_forever() -> None:
        try:
            await hang.wait()
        except asyncio.CancelledError:
            await asyncio.shield(hang.wait())  # a close that never completes

    task = asyncio.create_task(closing_forever())
    await asyncio.sleep(0)

    class Client:
        tasks: ClassVar[list[asyncio.Task[None]]] = [task]

        async def stop(self) -> None:
            task.cancel()

    listener = _bare_listener(_throwaway_cache(), [])
    listener._client = cast(Any, Client())
    started = time.monotonic()
    await listener.async_stop()
    assert time.monotonic() - started < 1.0
    assert not task.done()
    hang.set()
    await task
