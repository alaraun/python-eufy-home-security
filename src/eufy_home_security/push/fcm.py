"""FCM registration and listener → :class:`SecurityEvent`.

The eufy Security app registers with Firebase as an **Android** app, not a
web-push client, and receives plain ``app_data`` messages rather than
ECE-encrypted ones. The upstream ``firebase-messaging`` library does the
web-push flavour, so two small subclasses override exactly the parts that differ:

* :class:`_EufyFcmRegister` replaces the three registration calls —
  Android checkin (``DEVICE_ANDROID_OS``, not a Chrome build), Firebase
  Installations *with* the ``X-Android-Package`` / ``X-Android-Cert`` headers the
  Android-restricted API key demands, and ``c2dm/register3`` posted as the app —
  and assembles the credentials blob the client expects.
* :class:`_EufyFcmPushClient` reads ``msg.app_data`` directly instead of trying
  the web-push decrypt, and registers through :class:`_EufyFcmRegister`.

Registration failures are typed: no answer, a timeout or a 5xx/429 raise
:class:`CommunicationError`; a rejection or an unexpected reply raises
:class:`CloudApiError` (``code`` = the HTTP status, 0 for a bad body). A stored
device is re-registered only when Google explicitly rejects its checkin — an
outage must not mint a new android id and orphan the tokens of the old one.

Nothing else — the MCS socket, acks, heartbeats and protobufs — is changed.
``firebase-messaging`` already offloads the one blocking call it makes
(``ssl.create_default_context`` runs in an executor inside ``_connect``), and
every other call is aiohttp on the injected session, so there is nothing to work
around on the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from base64 import urlsafe_b64encode
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

import aiohttp
from firebase_messaging import FcmPushClient, FcmPushClientConfig, FcmRegisterConfig
from firebase_messaging.const import (
    AUTH_VERSION,
    FCM_INSTALLATION,
    GCM_CHECKIN_URL,
    GCM_REGISTER_URL,
    MCS_HOST,
    MCS_PORT,
)
from firebase_messaging.fcmregister import FcmRegister
from firebase_messaging.proto.android_checkin_pb2 import DEVICE_ANDROID_OS
from firebase_messaging.proto.checkin_pb2 import AndroidCheckinRequest, AndroidCheckinResponse
from google.protobuf.json_format import MessageToDict  # type: ignore[import-untyped]
from google.protobuf.message import DecodeError  # type: ignore[import-untyped]

from .._logging import Identifier, Payload, Secret, redact_serial
from ..events import SecurityEvent
from ..exceptions import (
    CloudApiError,
    CloudError,
    CommunicationError,
    EufySecurityError,
    RateLimitedError,
)
from ..storage import SessionCache
from . import const
from .decode import decode_payload, decode_push, is_security_push

if TYPE_CHECKING:
    from ..cloud.api import EufyCloudApi

_LOGGER = logging.getLogger(__name__)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=const.HTTP_TIMEOUT_SECONDS)

# Indirection so tests can drive retries, backoff and supervision without waiting.
_sleep = asyncio.sleep


def _transient(status: int) -> bool:
    """An HTTP status worth retrying rather than a verdict."""
    return status >= 500 or status == 429


def _client_alive(client: FcmPushClient) -> bool:
    """Whether the MCS client is still trying to listen.

    ``firebase-messaging`` gives up silently: ``_terminate`` clears ``do_listen``
    after repeated errors, and a first connect that fails every retry just ends
    the listen task (tasks[0]) while ``do_listen`` stays set.
    """
    if not client.do_listen:
        return False
    tasks = client.tasks
    return not tasks or not tasks[0].done()


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000


def _loggable(data: Mapping[str, Any]) -> dict[str, Any]:
    """A push for a debug line, its base64 ``payload`` decoded so :class:`Payload`
    masks the secrets and identifiers inside it."""
    out = dict(data)
    if inner := decode_payload(data.get("payload")):
        out["payload"] = inner
    return out


def _fcm_config() -> FcmRegisterConfig:
    return FcmRegisterConfig(
        const.FCM_PROJECT_ID, const.FCM_APP_ID, const.FCM_API_KEY, const.FCM_SENDER_ID
    )


def _device_profile(openudid: str) -> dict[str, str]:
    """Stable per-install checkin fields derived from ``openudid``.

    Hardcoding imei/mac makes every install check in as one handset. Deriving
    them keeps them stable across restarts (checkin is identity) yet distinct.
    """
    digits = "".join(c for c in openudid if c.isdigit()).ljust(15, "7")[:15]
    return {"imei": digits, "mac": openudid[:12].upper()}


class _EufyFcmRegister(FcmRegister):
    """Register the way the eufy Android app does (see module docstring)."""

    def __init__(self, *args: Any, openudid: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._openudid = openudid

    def _checkin_payload(
        self, android_id: int | None = None, security_token: int | None = None
    ) -> AndroidCheckinRequest:
        profile = _device_profile(self._openudid)
        payload = AndroidCheckinRequest()
        payload.checkin.type = DEVICE_ANDROID_OS
        payload.checkin.last_checkin_msec = 0
        payload.imei = profile["imei"]
        payload.meid = profile["imei"]
        payload.mac_addr.append(profile["mac"])
        payload.mac_addr_type.append("wifi")
        payload.esn = const.CHECKIN_ESN
        payload.locale = "en"
        payload.time_zone = "GMT"
        payload.logging_id = const.CHECKIN_LOGGING_ID
        payload.version = 3
        payload.ota_cert.append(const.CHECKIN_OTA_CERT)
        payload.fragment = 0
        payload.user_serial_number = 0
        # An id/token pair means "this device again"; omitting it makes Google
        # issue a new device and orphan every token registered against the old one.
        if android_id and security_token:
            payload.id = int(android_id)
            payload.security_token = int(security_token)
        return payload

    async def gcm_check_in(
        self, android_id: int | None = None, security_token: int | None = None, retries: int = 3
    ) -> dict[str, Any] | None:
        """Check in; None only when Google explicitly rejects the device (4xx).

        Raises :class:`CommunicationError` when every try failed on the network, a
        timeout or a 5xx, and :class:`CloudApiError` for an undecodable reply.
        """
        payload = self._checkin_payload(android_id, security_token)
        headers = {"Content-Type": "application/x-protobuf"}
        last = ""
        for attempt in range(const.CHECKIN_RETRIES):
            if attempt:
                await _sleep(attempt)
            _LOGGER.debug(
                "gcm checkin → POST %s (try %s, android_id %s, security_token %s)",
                GCM_CHECKIN_URL,
                attempt + 1,
                Identifier(android_id) if android_id else "none: new device",
                Secret(security_token),
            )
            started = time.monotonic()
            try:
                async with self._session.post(
                    url=GCM_CHECKIN_URL,
                    headers=headers,
                    data=payload.SerializeToString(),
                    timeout=_HTTP_TIMEOUT,
                ) as resp:
                    status = resp.status
                    body = await resp.read()
            except (aiohttp.ClientError, TimeoutError) as exc:
                last = str(exc) or type(exc).__name__
                _LOGGER.warning("gcm checkin failed (try %s): %s", attempt + 1, last)
                continue
            _LOGGER.debug(
                "gcm checkin ← HTTP %s, %d bytes in %.0f ms",
                status,
                len(body),
                _elapsed_ms(started),
            )
            if status == 200:
                acir = AndroidCheckinResponse()
                try:
                    acir.ParseFromString(body)
                except DecodeError as err:
                    raise CloudApiError(
                        0, f"undecodable checkin reply: {err}", endpoint=GCM_CHECKIN_URL
                    ) from err
                result = dict(MessageToDict(acir))
                _LOGGER.debug(
                    "gcm checkin ok: android_id %s, security_token %s",
                    Identifier(result.get("androidId")),
                    Secret(result.get("securityToken")),
                )
                return result
            if not _transient(status):
                _LOGGER.warning("gcm checkin rejected: HTTP %s", status)
                return None
            last = f"HTTP {status}"
            _LOGGER.warning("gcm checkin HTTP %s (try %s)", status, attempt + 1)
        raise CommunicationError(
            f"Google checkin failed after {const.CHECKIN_RETRIES} tries: {last}"
        )

    async def fcm_install(self) -> dict[str, Any]:
        headers = {
            "X-Android-Package": const.APP_PACKAGE,
            "X-Android-Cert": const.APP_CERT_SHA1,
            "x-goog-api-key": self.config.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "fid": self._new_fid(),
            "appId": self.config.app_id,
            "authVersion": AUTH_VERSION,
            "sdkVersion": const.FIREBASE_SDK_VERSION,
        }
        url = f"{FCM_INSTALLATION}projects/{self.config.project_id}/installations"
        _LOGGER.debug(
            "firebase install → POST %s headers %s body %s", url, Payload(headers), Payload(payload)
        )
        started = time.monotonic()
        try:
            async with self._session.post(
                url=url, headers=headers, data=json.dumps(payload), timeout=_HTTP_TIMEOUT
            ) as resp:
                status = resp.status
                text = await resp.text()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise CommunicationError(f"Firebase Installations unreachable: {err}") from err
        _LOGGER.debug("firebase install ← HTTP %s in %.0f ms", status, _elapsed_ms(started))
        if status != 200:
            if _transient(status):
                raise CommunicationError(f"Firebase Installations HTTP {status}")
            raise CloudApiError(status, "Firebase Installations rejected the install", endpoint=url)
        try:
            body = json.loads(text)
            auth = body["authToken"]
            installation = {
                "token": str(auth["token"]),
                "expires_in": int(str(auth["expiresIn"]).rstrip("s") or 0),
                "refresh_token": str(body["refreshToken"]),
                "fid": str(body["fid"]),
                "created_at": time.time(),
            }
        except (KeyError, TypeError, ValueError) as err:
            raise CloudApiError(
                0, f"unexpected Firebase Installations reply: {err!r}", endpoint=url
            ) from err
        _LOGGER.debug("firebase install ok: %s", Payload(installation))
        return installation

    async def gcm_register(self, options: dict[str, Any], retries: int = 5) -> dict[str, str]:
        installation = options["installation"]
        android_id = options["androidId"]
        security_token = options["securityToken"]
        body = {
            "X-subtype": const.FCM_SENDER_ID,
            "sender": const.FCM_SENDER_ID,
            "X-app_ver": const.APP_VERSION_CODE,
            "X-osv": const.ANDROID_OS_VERSION,
            "X-cliv": const.FIID_CLIENT_VERSION,
            "X-gmsv": const.GCM_VERSION,
            "X-appid": installation["fid"],
            "X-scope": "*",
            "X-Goog-Firebase-Installations-Auth": installation["token"],
            "X-gmp_app_id": self.config.app_id,
            "X-firebase-app-name-hash": const.FIREBASE_APP_NAME_HASH,
            "X-Firebase-Client-Log-Type": "1",
            "X-app_ver_name": const.APP_VERSION_NAME,
            "app": const.APP_PACKAGE,
            "device": android_id,
            "app_ver": const.APP_VERSION_CODE,
            "gcm_ver": const.GCM_VERSION,
            "plat": "0",
            "cert": const.APP_CERT_SHA1,
            "target_ver": const.ANDROID_TARGET_VERSION,
        }
        headers = {
            "Authorization": f"AidLogin {android_id}:{security_token}",
            "app": const.APP_PACKAGE,
            "gcm_ver": const.GCM_VERSION,
            "User-Agent": const.GCM_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        failure: EufySecurityError = CommunicationError("GCM registration was not attempted")
        for attempt in range(const.REGISTER_RETRIES):
            if attempt:
                await _sleep(2 * attempt)
            _LOGGER.debug(
                "gcm register → POST %s (try %s) headers %s body %s",
                GCM_REGISTER_URL,
                attempt + 1,
                Payload(headers),
                # The installation auth header is a credential its name does not reveal.
                Payload(
                    {**body, "X-Goog-Firebase-Installations-Auth": Secret(installation["token"])}
                ),
            )
            started = time.monotonic()
            try:
                async with self._session.post(
                    url=GCM_REGISTER_URL, headers=headers, data=body, timeout=_HTTP_TIMEOUT
                ) as resp:
                    status = resp.status
                    text = (await resp.text()).strip()
            except (aiohttp.ClientError, TimeoutError) as exc:
                failure = CommunicationError(f"GCM registration failed: {exc}")
                _LOGGER.warning("gcm register failed (try %s): %s", attempt + 1, exc)
                continue
            _LOGGER.debug("gcm register ← HTTP %s in %.0f ms", status, _elapsed_ms(started))
            if status == 200 and text.startswith("token=") and len(text) > len("token="):
                _LOGGER.debug("gcm register ok: fcm token %s", Secret(text.split("=", 1)[1]))
                return {
                    "token": text.split("=", 1)[1],
                    # `subtype` on an inbound message is the sender id for an app
                    # registration; the client compares it against this.
                    "app_id": const.FCM_SENDER_ID,
                    "android_id": android_id,
                    "security_token": security_token,
                }
            if _transient(status):
                failure = CommunicationError(f"GCM registration HTTP {status}")
            else:
                failure = CloudApiError(
                    status, text[:120] or "no token in the reply", endpoint=GCM_REGISTER_URL
                )
            _LOGGER.warning("gcm register (try %s): HTTP %s %s", attempt + 1, status, text[:120])
        raise failure

    async def register(self) -> dict[str, Any]:
        """Full Android registration, shaped like the library's credentials blob."""
        checkin = await self.gcm_check_in()
        if not checkin:
            raise CloudApiError(0, "Google checkin rejected a new device", endpoint=GCM_CHECKIN_URL)
        if not checkin.get("androidId") or not checkin.get("securityToken"):
            raise CloudApiError(
                0, "Google checkin reply has no device id", endpoint=GCM_CHECKIN_URL
            )
        installation = await self.fcm_install()
        gcm = await self.gcm_register({**checkin, "installation": installation})
        credentials = {
            "keys": {},
            "gcm": gcm,
            "fcm": {"registration": {"token": gcm["token"]}, "installation": installation},
            "config": {"project_id": self.config.project_id, "flavour": "android"},
        }
        _LOGGER.debug("registered a new push device (android_id %s)", Identifier(gcm["android_id"]))
        if self.credentials_updated_callback:
            self.credentials_updated_callback(credentials)
        return credentials

    async def checkin_or_register(self) -> dict[str, Any]:
        """Reuse the stored device unless Google rejects it; an outage raises instead."""
        stored = self.credentials
        if stored and stored.get("gcm", {}).get("android_id"):
            _LOGGER.debug(
                "reusing the stored push device (android_id %s, fcm token %s)",
                Identifier(stored["gcm"]["android_id"]),
                Secret(stored["gcm"].get("token")),
            )
            if await self.gcm_check_in(
                stored["gcm"]["android_id"], stored["gcm"]["security_token"]
            ):
                return stored
            _LOGGER.warning("checkin rejected the stored device — re-registering")
        else:
            _LOGGER.debug("no stored push device; registering a new one")
        self.credentials = await self.register()
        return self.credentials

    @staticmethod
    def _new_fid() -> str:
        raw = bytearray(secrets.token_bytes(17))
        raw[0] = 0b01110000 + (raw[0] % 0b00010000)
        return urlsafe_b64encode(bytes(raw)).decode()[:22]


class _EufyFcmPushClient(FcmPushClient):
    """The library's MCS client, reading app-flavour ``app_data`` messages."""

    def __init__(self, *args: Any, openudid: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._openudid = openudid

    async def checkin_or_register(self) -> str:
        register = _EufyFcmRegister(
            self.fcm_config,
            self.credentials,
            self.credentials_updated_callback,
            http_client_session=self._http_client_session,
            openudid=self._openudid,
        )
        self.credentials = await register.checkin_or_register()
        await register.close()
        return str(self.credentials["fcm"]["registration"]["token"])

    # The overrides below only log under this module; the MCS protocol stays the
    # library's, whose own ``firebase_messaging`` logger is outside this package's tree.

    async def _connect(self) -> bool:
        _LOGGER.debug("MCS → connecting to %s:%s (TLS)", MCS_HOST, MCS_PORT)
        started = time.monotonic()
        connected = await super()._connect()
        if connected:
            _LOGGER.debug("MCS TLS connection up in %.0f ms", _elapsed_ms(started))
        return bool(connected)

    async def _login(self) -> None:
        gcm = (self.credentials or {}).get("gcm", {})
        _LOGGER.debug(
            "MCS → login (android_id %s, security_token %s, acking %d persistent ids)",
            Identifier(gcm.get("android_id")),
            Secret(gcm.get("security_token")),
            len(self.persistent_ids),
        )
        await super()._login()

    async def _handle_message(self, msg: Any) -> None:
        kind = type(msg).__name__
        if kind == "LoginResponse":
            if str(msg.error):
                _LOGGER.debug("MCS ← login rejected: %s", msg.error)
            else:
                _LOGGER.debug("MCS ← login ok")
        elif kind == "Close":
            _LOGGER.debug("MCS ← Close from the server; resetting the connection")
        elif kind == "HeartbeatPing":
            _LOGGER.debug(
                "MCS ← heartbeat ping (stream %s, last received %s)",
                msg.stream_id,
                msg.last_stream_id_received,
            )
        elif kind == "HeartbeatAck":
            _LOGGER.debug("MCS ← heartbeat ack (stream %s)", msg.stream_id)
        elif kind == "IqStanza":
            _LOGGER.debug("MCS ← iq (extension %s)", msg.extension.id)
        elif kind != "DataMessageStanza":
            _LOGGER.debug("MCS ← %s", kind)
        await super()._handle_message(msg)

    async def _send_heartbeat(self) -> None:
        _LOGGER.debug("MCS → heartbeat ping (no message for a heartbeat interval)")
        await super()._send_heartbeat()

    async def _send_selective_ack(self, persistent_id: str) -> None:
        _LOGGER.debug("MCS → ack %s", Identifier(persistent_id))
        await super()._send_selective_ack(persistent_id)

    async def _reset(self) -> None:
        _LOGGER.debug("MCS connection reset requested (state %s)", self.run_state.name)
        await super()._reset()

    def _terminate(self) -> None:
        _LOGGER.debug("MCS client stopped listening (state %s)", self.run_state.name)
        super()._terminate()

    async def _do_writer_close(self) -> None:
        """Drop the MCS socket at once: the server does not answer TLS close_notify, so
        a graceful close waits out asyncio's SSL shutdown timeout (30 s)."""
        writer, self.writer = self.writer, None
        if writer is not None:
            writer.transport.abort()

    def _handle_data_message(self, msg: Any) -> None:
        """App registrations deliver plain ``app_data`` — no ECE to decrypt."""
        data = {kv.key: kv.value for kv in msg.app_data}
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "MCS ← push %s from %s category %s (stream %s): %s",
                Identifier(msg.persistent_id),
                getattr(msg, "from"),
                msg.category,
                msg.stream_id,
                Payload(_loggable(data)),
            )
        if data.get("message_type") == "deleted_messages":
            _LOGGER.debug("ignoring a deleted_messages notice")
            return
        try:
            self.callback(data, msg.persistent_id, self.callback_context)
        except Exception:
            _LOGGER.exception("push callback raised")


class PushListener:
    """Holds an FCM socket and turns each push into a :class:`SecurityEvent`.

    The FCM credentials (Google's device identity) live in ``cache.section("push")``.
    The eufy-side token registration is re-uploaded on every (re)start, because
    there is no unregister endpoint and a token the backend has forgotten stops
    receiving.

    **Supervision.** ``firebase-messaging`` stops listening on its own after
    repeated connection or login errors. A supervisor task checks the client every
    :data:`~.const.SUPERVISE_INTERVAL` and rebuilds it (checkin with the stored
    device, token upload, start) with a doubling backoff capped at
    :data:`~.const.RESTART_BACKOFF_MAX`. :attr:`running` is the client's real state,
    so it is False while a restart is pending.

    **Delivery.** The backend redelivers on reconnect and re-registration, and does
    not keep order. Pushes are de-duplicated on ``span_id``
    (:attr:`~..events.SecurityEvent.push_id`; ``persistent_id`` when absent) against a
    ring persisted in the push section, so a restart does not replay what was already
    delivered. The same occurrence arriving over P2P as well is de-duplicated later,
    by :class:`~..client.EufySecurity`, which also drops a stale guard-mode push
    (:class:`~..events.GuardModeTracker`). Messages for another eufy app
    (``app_tab``) are dropped.
    """

    def __init__(
        self,
        cloud: EufyCloudApi,
        cache: SessionCache,
        callback: Callable[[SecurityEvent], None],
        *,
        session: aiohttp.ClientSession,
        on_token_upload: Callable[[CloudError | None], None] | None = None,
        on_listening: Callable[[bool, EufySecurityError | None], None] | None = None,
    ) -> None:
        # on_token_upload: told the outcome of every eufy token upload (None: it
        # succeeded), first start and supervisor restarts alike.
        self._on_token_upload = on_token_upload
        # on_listening: (running, error) when async_start succeeds, when the supervisor
        # finds the client stopped (with why), on each failed restart, when a restart
        # succeeds, and (False, None) from async_stop. Consumers de-duplicate.
        self._on_listening = on_listening
        self._cloud = cloud
        self._cache = cache
        self._callback = callback
        self._session = session
        self._client: FcmPushClient | None = None
        self._token: str | None = None
        self._lock = asyncio.Lock()
        self._supervisor: asyncio.Task[None] | None = None
        # span id -> first-seen epoch seconds; insertion order is age order.
        self._seen: dict[str, int] = {}
        self._state_loaded = False

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def running(self) -> bool:
        """Whether the MCS client is currently listening (False while restarting)."""
        client = self._client
        return client is not None and _client_alive(client)

    async def async_start(self) -> None:
        """Obtain (or reuse) credentials, re-register the token, and start listening.

        A no-op when already started. Raises an :class:`EufySecurityError` subclass
        on failure, after at most :data:`~.const.START_DEADLINE_SECONDS`.
        """
        async with self._lock:
            if self._supervisor is not None:
                return
            self._load_state()
            await self._start_client()
            self._supervisor = asyncio.create_task(
                self._supervise(), name="eufy-security-push-supervisor"
            )
        _LOGGER.info("push listener started (fcm token %s)", Secret(self._token))
        self._report_listening(True, None)

    async def async_stop(self) -> None:
        """Stop supervising and listening, and persist the dedupe state."""
        supervisor, self._supervisor = self._supervisor, None
        if supervisor is not None:
            supervisor.cancel()
            await asyncio.wait({supervisor})
        async with self._lock:
            await self._stop_client()
            if self._state_loaded:
                await self._save_state()
        if supervisor is not None:
            _LOGGER.info("push listener stopped")
            self._report_listening(False, None)

    # ── client lifecycle ─────────────────────────────────────────────────────

    async def _start_client(self) -> None:
        """Register and start a new MCS client; every failure is an EufySecurityError."""
        section = self._cache.section("push")
        stored = section.get("fcm_credentials")
        credentials = dict(stored) if isinstance(stored, Mapping) else None
        _LOGGER.debug(
            "starting the push client (%s)",
            "stored credentials" if credentials else "no stored credentials",
        )
        client = _EufyFcmPushClient(
            self._on_message,
            _fcm_config(),
            credentials,
            self._save_credentials,
            config=FcmPushClientConfig(
                server_heartbeat_interval=const.SERVER_HEARTBEAT_INTERVAL,
                client_heartbeat_interval=const.CLIENT_HEARTBEAT_INTERVAL,
            ),
            http_client_session=self._session,
            openudid=self._cache.openudid,
        )
        try:
            async with asyncio.timeout(const.START_DEADLINE_SECONDS):
                token = await client.checkin_or_register()
                await self._cache.async_save()
                # Re-register on every start: no unregister endpoint, and a forgotten
                # token silently stops receiving.
                _LOGGER.debug("uploading fcm token %s to the eufy cloud", Secret(token))
                try:
                    await self._cloud.async_register_push_token(token)
                except CloudError as err:
                    self._report_token_upload(err)
                    raise
                self._report_token_upload(None)
            self._token = token
            section["registered_token"] = token
            section["registered_at"] = int(time.time())
            await self._cache.async_save()
            await client.start()
        except EufySecurityError:
            raise
        except TimeoutError as err:
            raise CommunicationError(
                f"push registration did not finish within {const.START_DEADLINE_SECONDS:.0f}s"
            ) from err
        except Exception as err:
            raise CommunicationError(f"push listener did not start: {err!r}") from err
        self._client = client

    def _report_listening(self, running: bool, error: EufySecurityError | None) -> None:
        if self._on_listening is None:
            return
        try:
            self._on_listening(running, error)
        except Exception:
            _LOGGER.exception("listening callback raised")

    def _report_token_upload(self, error: CloudError | None) -> None:
        if self._on_token_upload is None:
            return
        try:
            self._on_token_upload(error)
        except Exception:
            _LOGGER.exception("token upload callback raised")

    async def _stop_client(self) -> None:
        """Stop the MCS client and wait for its tasks, at most :data:`const.STOP_TIMEOUT`."""
        client, self._client = self._client, None
        if client is None:
            return
        _LOGGER.debug("stopping the push client")
        try:
            await client.stop()
            tasks = [t for t in client.tasks if t is not asyncio.current_task()]
            if tasks:
                _done, pending = await asyncio.wait(tasks, timeout=const.STOP_TIMEOUT)
                if pending:
                    _LOGGER.debug(
                        "push client: %d task(s) still closing after %.0f s; left behind",
                        len(pending),
                        const.STOP_TIMEOUT,
                    )
        except Exception:
            _LOGGER.debug("push client stop raised", exc_info=True)

    async def _supervise(self) -> None:
        """Restart the client whenever it has given up listening."""
        delay = const.RESTART_BACKOFF_MIN
        proven = True  # the current client has logged in since it was (re)started
        while True:
            await _sleep(const.SUPERVISE_INTERVAL)
            client = self._client
            if client is not None and _client_alive(client):
                if client.is_started():
                    delay, proven = const.RESTART_BACKOFF_MIN, True
                continue
            _LOGGER.warning("push listener stopped receiving; restarting it")
            self._report_listening(False, CommunicationError("the push client stopped listening"))
            if not proven:
                # The last restart never got as far as a login: do not hammer.
                _LOGGER.debug("the last restart never logged in; backing off %.0fs", delay)
                await _sleep(delay)
                delay = min(delay * 2, const.RESTART_BACKOFF_MAX)
            while True:
                async with self._lock:
                    await self._stop_client()
                    try:
                        await self._start_client()
                    except EufySecurityError as err:
                        # A cloud hold-off refuses locally until it ends: wait it out.
                        hold_off = err.retry_after if isinstance(err, RateLimitedError) else None
                        wait = max(delay, hold_off or 0.0)
                        _LOGGER.warning(
                            "push listener restart failed, retrying in %.0fs: %s", wait, err
                        )
                        self._report_listening(False, err)
                    else:
                        _LOGGER.info("push listener restarted")
                        self._report_listening(True, None)
                        break
                await _sleep(wait)
                delay = min(delay * 2, const.RESTART_BACKOFF_MAX)
            proven = False

    def _save_credentials(self, credentials: dict[str, Any]) -> None:
        self._cache.section("push")["fcm_credentials"] = credentials

    # ── delivery ─────────────────────────────────────────────────────────────

    def _on_message(self, data: Mapping[str, Any], persistent_id: str, _ctx: object) -> None:
        if not is_security_push(data):
            _LOGGER.debug("ignoring a push for app_tab %r", data.get("app_tab"))
            return
        self._load_state()
        event = decode_push(data)
        span = event.push_id or persistent_id
        if span in self._seen:
            _LOGGER.debug("dropping a push already delivered (span %s)", span)
            return
        self._remember(span)
        _LOGGER.debug(
            "push event: station %s device %s ch %s msg_type %s event_type %s guard_mode %s",
            redact_serial(event.station_sn),
            redact_serial(event.device_sn),
            event.channel,
            event.msg_type,
            event.event_type,
            event.guard_mode,
        )
        try:
            self._callback(event)
        except Exception:
            _LOGGER.exception("push event callback raised")

    def _remember(self, span: str) -> None:
        self._seen[span] = int(time.time())
        while len(self._seen) > const.DEDUPE_RING_SIZE:
            del self._seen[next(iter(self._seen))]
        self._store_state()
        self._cache.schedule_save()

    # ── persisted delivery state ─────────────────────────────────────────────

    def _load_state(self) -> None:
        """Merge the persisted ring into memory (once).

        The ring is stored as ``{span: first-seen epoch seconds}``; a stored list of
        ``[span, seconds]`` pairs is read too and rewritten as that mapping.
        """
        if self._state_loaded:
            return
        self._state_loaded = True
        section = self._cache.section("push")
        cutoff = time.time() - const.DEDUPE_RETENTION_SECONDS
        seen = dict(self._seen)
        stored = section.get("seen_spans")
        entries: list[tuple[Any, Any]] = []
        if isinstance(stored, Mapping):
            entries = list(stored.items())
        elif isinstance(stored, list):  # a list of [span, seconds] pairs
            entries = [(e[0], e[1]) for e in stored if isinstance(e, list) and len(e) == 2]
        for span, seen_at in entries:
            if (
                isinstance(span, str)
                and isinstance(seen_at, int)
                and not isinstance(seen_at, bool)
                and seen_at >= cutoff
            ):
                seen.setdefault(span, seen_at)
        ordered = sorted(seen.items(), key=lambda item: item[1])
        self._seen = dict(ordered[-const.DEDUPE_RING_SIZE :])
        _LOGGER.debug("push delivery state loaded: %d spans", len(self._seen))

    def _store_state(self) -> None:
        """Write the in-memory ring into the push section (not the store)."""
        self._cache.section("push")["seen_spans"] = dict(self._seen)

    async def _save_state(self) -> None:
        self._store_state()
        try:
            await self._cache.async_save()
        except Exception:
            _LOGGER.warning("push delivery state not saved", exc_info=True)
        else:
            _LOGGER.debug("push delivery state saved: %d spans", len(self._seen))
