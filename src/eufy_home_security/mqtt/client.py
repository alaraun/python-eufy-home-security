"""The MQTT client of the eufy security broker (needs the ``mqtt`` extra: ``aiomqtt``).

:class:`EufyMqttClient` holds one connection per login scope, as the eufy app does: it asks
the cloud for the account's certificate (:meth:`~..cloud.api.EufyCloudApi.async_mqtt_certificate`,
which applies the app's reuse rules), connects with TLS and that client certificate,
subscribes the answer topic of every MQTT device (:mod:`.selection`) and publishes commands
(:mod:`.envelope`). The command itself is the caller's. See docs/protocol/mqtt.md.

``aiomqtt`` connects in the event loop's default executor (its name lookup, socket connect
and TLS handshake block); every read and write after that runs on the event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, Final

from .._logging import LogThrottle, redact_serial
from ..cloud.models import CloudDevice, MqttCertificate
from ..exceptions import (
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    MissingDependencyError,
    UnsupportedError,
)
from .envelope import (
    MessageSequence,
    MqttHead,
    MqttMessage,
    build_request,
    parse_message,
    request_topic,
    response_topic,
)
from .selection import device_key, mqtt_devices, topic_code
from .tls import async_tls_context

if TYPE_CHECKING:
    import aiomqtt

    from ..cloud.api import EufyCloudApi

_LOGGER = logging.getLogger(__name__)

MQTT_PORT: Final = 8883
KEEPALIVE_SECONDS: Final = 300
CONNECT_USERNAME: Final = "?SDK=Android&Version=2.81.0"
"""The CONNECT user name the eufy app sends (its MQTT SDK's tag); no password."""
RECONNECT_MIN_SECONDS: float = 4.0
"""The first wait before a reconnect; doubled per failed try up to the maximum."""
RECONNECT_MAX_SECONDS: float = 64.0
LOSSES_BEFORE_NEW_CERTIFICATE: Final = 3
"""Lost connections after which the cached certificate is dropped for a new one."""
SUBSCRIBE_RETRY_SECONDS: float = 5.0
"""The wait before a refused subscription is asked again."""
CONNECT_WAIT_SECONDS: Final = 10.0
"""How long a publish waits for a connection that is not up."""
PUBLISH_TIMEOUT_SECONDS: Final = 15.0
"""How long a publish waits for the broker's acknowledgement."""
REQUEST_TIMEOUT_SECONDS: Final = 20.0
"""How long :meth:`EufyMqttClient.async_request` waits for the device's answer."""
CONNECT_SETTLE_SECONDS: float = 30.0
"""How long a stop or restart waits for a connect step it interrupts, which normally ends
within it: the socket connect (5 s per address the endpoint resolves to), the TLS handshake
(5 s) and the CONNACK wait (15 s). The name lookup has no timeout of its own. A step still
running after it is closed when it ends."""
_QOS: Final = 1
_SUBACK_FAILURE: Final = 0x80

type Match = Callable[[MqttMessage], bool]
type Listener = Callable[[MqttMessage], None]


def next_reconnect_delay(delay: float) -> float:
    """The wait after a failed reconnect that followed a wait of ``delay`` seconds."""
    return min(delay * 2, RECONNECT_MAX_SECONDS)


def require_aiomqtt() -> Any:
    """The ``aiomqtt`` module; :class:`MissingDependencyError` without the ``mqtt`` extra."""
    try:
        import aiomqtt  # noqa: PLC0415 - optional dependency
    except ImportError as err:
        raise MissingDependencyError("the MQTT transport", extra="mqtt") from err
    return aiomqtt


def device_scope(device: CloudDevice, cloud: EufyCloudApi) -> str:
    """The login scope whose client serves ``device``: its ``region``, the cloud's
    :attr:`~..cloud.api.EufyCloudApi.region` for a device without one."""
    return device.region or cloud.region


def _refused(code: object) -> bool:
    value = getattr(code, "value", code)
    return isinstance(value, int) and value >= _SUBACK_FAILURE


class EufyMqttClient:
    """The MQTT connection of one login scope (``region``, the cloud's :attr:`region` when
    None) to the eufy security broker. It serves the MQTT devices of that scope among the
    devices it is given and ignores the others; :class:`~.account.EufyMqttAccount` runs one
    client per scope of an account.

    ``port`` and ``server_ca_pem`` exist for tests against a local broker: the client
    connects to the certificate's endpoint on :data:`MQTT_PORT` and verifies it with the
    system's trust store, as the eufy app does. Raises :class:`MissingDependencyError`
    without the ``mqtt`` extra.
    """

    def __init__(
        self,
        cloud: EufyCloudApi,
        *,
        region: str | None = None,
        port: int = MQTT_PORT,
        keepalive: int = KEEPALIVE_SECONDS,
        server_ca_pem: str | None = None,
    ) -> None:
        self._aiomqtt = require_aiomqtt()
        self._cloud = cloud
        self._region = region
        self._port = port
        self._keepalive = keepalive
        self._server_ca_pem = server_ca_pem
        self._devices: dict[str, CloudDevice] = {}
        self._subscribe: frozenset[str] | None = None
        self._sequence = MessageSequence()
        self._listeners: list[Listener] = []
        self._waiters: dict[str, list[tuple[Match, asyncio.Future[MqttMessage]]]] = {}
        self._client: aiomqtt.Client | None = None
        self._client_id: str | None = None
        self._certificate: MqttCertificate | None = None
        self._subscribed: set[str] = set()
        self._connected = asyncio.Event()
        self._wake = asyncio.Event()
        self._refresh = False
        self._losses = 0
        self._run_task: asyncio.Task[None] | None = None
        self._connection_task: asyncio.Task[bool] | None = None
        self._stopping = False
        self._lifecycle = asyncio.Lock()
        """Held by start, device update and stop, so a stop never interleaves with them."""
        self._throttle = LogThrottle()
        """Repeated lines: dropped messages, failing listeners, connect failures."""

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def devices(self) -> tuple[CloudDevice, ...]:
        """The MQTT devices this client serves, in the order they were given."""
        return tuple(self._devices.values())

    @property
    def connected(self) -> bool:
        """Whether the broker connection is up."""
        return self._connected.is_set()

    @property
    def topics(self) -> frozenset[str]:
        """The answer topics the broker accepted on the current connection."""
        return frozenset(self._subscribed)

    def add_listener(self, listener: Listener) -> Callable[[], None]:
        """Call ``listener`` with every message a device publishes; returns its remover."""
        self._listeners.append(listener)
        return lambda: self.remove_listener(listener)

    def remove_listener(self, listener: Listener) -> None:
        """Stop calling ``listener`` (once per :meth:`add_listener`); no-op when absent."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    # ── lifecycle ────────────────────────────────────────────────────────────

    @property
    def scope(self) -> str:
        """The login scope this client serves."""
        return self._cloud.region if self._region is None else self._region

    async def _select(self, devices: Iterable[CloudDevice]) -> dict[str, CloudDevice]:
        """The MQTT devices of this client's scope (:func:`device_scope`) among ``devices``."""
        # The selection reads package data on first use: off the loop.
        selected = await asyncio.to_thread(mqtt_devices, list(devices))
        scope = self.scope
        return {d.device_sn: d for d in selected if device_scope(d, self._cloud) == scope}

    def _keys(self) -> frozenset[str]:
        return frozenset(device_key(device) for device in self._devices.values())

    async def async_start(
        self,
        devices: Iterable[CloudDevice],
        *,
        subscribe: Iterable[str] | None = None,
        connect_without_devices: bool = False,
    ) -> None:
        """Serve the MQTT devices among ``devices``. With none, nothing connects, as in the
        app, unless ``connect_without_devices`` (a connection check: certificate, TLS and
        CONNECT with no subscription).

        ``subscribe`` (serials) narrows the answer topics to those devices, for a check of
        some of them; the certificate still covers every MQTT device, so the cached one
        stays valid. It holds across :meth:`async_update_devices`.

        The connection runs in a background task that reconnects by itself; use
        :meth:`async_wait_connected` to wait for it.
        """
        async with self._lifecycle:
            if self._run_task is not None:
                raise RuntimeError("the MQTT client is already started")
            self._subscribe = None if subscribe is None else frozenset(subscribe)
            self._devices = await self._select(devices)
            if not self._devices and not connect_without_devices:
                _LOGGER.debug("no MQTT device: no broker connection")
                return
            self._start_task()

    def _start_task(self) -> None:
        self._stopping = False
        self._run_task = asyncio.create_task(self._run(), name="eufy-mqtt")

    async def async_update_devices(self, devices: Iterable[CloudDevice]) -> None:
        """Follow a new device list: a changed MQTT device set asks for a new certificate
        and reconnects with it (the app's rule); an unchanged one keeps the connection."""
        async with self._lifecycle:
            selected = await self._select(devices)
            before = self._keys()
            self._devices = selected
            if self._run_task is None:
                if selected:
                    self._start_task()
                return
            if not selected:
                await self._stop()
                return
            if self._keys() != before:
                _LOGGER.debug("MQTT device set changed: reconnecting with its certificate")
                self._restart()

    async def async_stop(self) -> None:
        """Disconnect and end the background task; the waiters get a CommunicationError.
        A start or device update in progress finishes first, then is stopped."""
        async with self._lifecycle:
            await self._stop()

    async def _stop(self) -> None:
        self._stopping = True
        task, self._run_task = self._run_task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._fail_waiters("the MQTT client stopped")

    async def async_wait_connected(self, timeout: float) -> None:
        """Wait until the broker connection is up; :class:`CommunicationError` when it is
        not within ``timeout`` seconds."""
        try:
            async with asyncio.timeout(timeout):
                await self._connected.wait()
        except TimeoutError:
            raise CommunicationError(f"no MQTT broker connection within {timeout:g} s") from None

    def _restart(self) -> None:
        """End the current connection without counting a loss; the run loop reconnects."""
        self._wake.set()
        if self._connection_task is not None:
            self._connection_task.cancel()

    # ── the connection ───────────────────────────────────────────────────────

    async def _run(self) -> None:
        delay = RECONNECT_MIN_SECONDS
        while not self._stopping:
            self._wake.clear()
            connection = asyncio.create_task(self._connect_once(), name="eufy-mqtt-connection")
            self._connection_task = connection
            established = False
            try:
                established = await connection
            except asyncio.CancelledError:
                # Only a restart cancels the connection alone; a stop cancels this task.
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    raise
            except Exception:
                if self._throttle.should_log("unexpected"):
                    _LOGGER.exception("MQTT connection ended unexpectedly; reconnecting")
                else:
                    _LOGGER.debug("MQTT connection ended unexpectedly; reconnecting", exc_info=True)
            finally:
                lost = self._client is not None and not self._stopping
                self._connection_task = None
                self._client = None
                self._connected.clear()
                self._subscribed.clear()
                if lost:
                    # The answers of an ended connection never arrive.
                    self._fail_waiters("MQTT connection lost")
            if established:
                delay = RECONNECT_MIN_SECONDS
                await self._count_loss()
            if self._wake.is_set():
                continue
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(delay):
                    await self._wake.wait()
            delay = next_reconnect_delay(delay)

    def _log_repeated(self, key: str, msg: str, *args: object) -> None:
        """Log a line the retry loop repeats: a WARNING once per :class:`LogThrottle`
        interval and key, DEBUG in between."""
        if self._throttle.should_log(key):
            _LOGGER.warning(msg, *args)
        else:
            _LOGGER.debug(msg, *args)

    async def _count_loss(self) -> None:
        self._losses += 1
        if self._losses >= LOSSES_BEFORE_NEW_CERTIFICATE:
            self._losses = 0
            await self._cloud.async_drop_mqtt_certificate(self._region)

    async def _connect_once(self) -> bool:
        """One connection: certificate, TLS, connect, subscribe, read until it ends.
        True when it was established and then lost."""
        refresh, self._refresh = self._refresh, False
        try:
            certificate = await self._cloud.async_mqtt_certificate(
                self._keys(), region=self._region, refresh=refresh
            )
            context = await async_tls_context(certificate, cadata=self._server_ca_pem)
        except EufySecurityError as err:
            self._log_repeated("certificate", "MQTT certificate unavailable: %s", err)
            return False
        self._certificate = certificate
        self._client_id = self._cloud.mqtt_client_id(certificate, self._region)
        mqtt = self._aiomqtt
        client = mqtt.Client(
            certificate.endpoint,
            self._port,
            identifier=self._client_id,
            username=CONNECT_USERNAME,
            keepalive=self._keepalive,
            tls_context=context,
            protocol=mqtt.ProtocolVersion.V311,
            clean_session=True,
            timeout=PUBLISH_TIMEOUT_SECONDS,
        )
        established = False
        try:
            await _open(client)
            try:
                established = True
                self._client = client
                self._connected.set()
                _LOGGER.info("MQTT broker connected for %d device(s)", len(self._devices))
                subscriber = asyncio.create_task(
                    self._keep_subscribed(client), name="eufy-mqtt-subscribe"
                )
                try:
                    async for message in client.messages:
                        self._dispatch(str(message.topic), message.payload)
                finally:
                    subscriber.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await subscriber
            finally:
                await client.__aexit__(None, None, None)
        except mqtt.MqttError as err:
            state = "lost" if established else "failed"
            self._log_repeated(state, "MQTT broker connection %s: %s", state, err)
        return established

    async def _keep_subscribed(self, client: aiomqtt.Client) -> None:
        """Subscribe every wanted answer topic; ask again for the refused ones."""
        while True:
            wanted = {
                response_topic(topic_code(d), d.device_sn)
                for d in self._devices.values()
                if self._subscribe is None or d.device_sn in self._subscribe
            }
            missing = sorted(wanted - self._subscribed)
            try:
                for topic in self._subscribed - wanted:
                    await client.unsubscribe(topic)
                    self._subscribed.discard(topic)
                if missing:
                    codes = await client.subscribe([(topic, _QOS) for topic in missing])
                    for topic, code in zip(missing, codes, strict=False):
                        if _refused(code):
                            _LOGGER.warning(
                                "MQTT broker refused the topic of %s", _topic_device(topic)
                            )
                        else:
                            self._subscribed.add(topic)
            except self._aiomqtt.MqttError as err:
                _LOGGER.debug("MQTT subscription not answered: %s", err)
            await asyncio.sleep(SUBSCRIBE_RETRY_SECONDS)

    def _dispatch(self, topic: str, payload: Any) -> None:
        data = payload if isinstance(payload, bytes) else str(payload or "").encode()
        try:
            message = parse_message(topic, data)
        except EufySecurityError as err:
            if self._throttle.should_log(("dropped", topic)):
                _LOGGER.debug("MQTT message dropped (%s): %s", _topic_device(topic), err)
            return
        for match, future in list(self._waiters.get(message.device_sn, [])):
            if not future.done() and match(message):
                future.set_result(message)
                break
        for listener in list(self._listeners):
            try:
                listener(message)
            except Exception:
                # A consumer's bug must not end the connection nor starve the other listeners.
                if self._throttle.should_log(("listener", id(listener))):
                    _LOGGER.exception("MQTT message listener %r failed", listener)

    def _fail_waiters(self, reason: str) -> None:
        """End every pending request with a :class:`CommunicationError` naming ``reason``."""
        for device_sn, waiters in self._waiters.items():
            for _match, future in waiters:
                if not future.done():
                    future.set_exception(CommunicationError(reason, device_sn=device_sn))
        self._waiters.clear()

    # ── commands ─────────────────────────────────────────────────────────────

    async def _connected_client(self, device_sn: str) -> aiomqtt.Client:
        if not self._connected.is_set() and self._certificate is None:
            # No certificate yet: ask for a new one now, not after the back-off (the app's
            # forced refresh on a publish without connection details).
            self._refresh = True
            self._wake.set()
        try:
            async with asyncio.timeout(CONNECT_WAIT_SECONDS):
                await self._connected.wait()
        except TimeoutError:
            raise CommunicationError(
                f"no MQTT broker connection for {redact_serial(device_sn)} within "
                f"{CONNECT_WAIT_SECONDS:g} s",
                device_sn=device_sn,
            ) from None
        client = self._client
        if client is None:  # pragma: no cover - set together with the event
            raise CommunicationError("the MQTT connection ended", device_sn=device_sn)
        return client

    async def async_publish(
        self, device_sn: str, trans: str, *, need_ack: bool = False, sess_id: str | None = None
    ) -> MqttHead:
        """Publish the command ``trans`` to MQTT device ``device_sn``; returns the sent head.

        Returns once the broker acknowledged the message, which is no answer of the device
        (see :meth:`async_request`). Raises :class:`UnsupportedError` for a device this
        client does not serve and :class:`CommunicationError` when no connection is up
        within :data:`CONNECT_WAIT_SECONDS` or the broker does not take the message.
        """
        if self._run_task is None:
            raise CommunicationError("the MQTT client is not started", device_sn=device_sn)
        device = self._devices.get(device_sn)
        if device is None:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} is not an MQTT device of this client",
                device_sn=device_sn,
            )
        client = await self._connected_client(device_sn)
        head, body = build_request(
            client_id=self._client_id or "",
            account_id=device.owner_user_id or "",
            device_sn=device_sn,
            trans=trans,
            msg_seq=self._sequence.next(),
            need_ack=need_ack,
            sess_id=sess_id,
        )
        topic = request_topic(topic_code(device), device_sn)
        try:
            await client.publish(topic, body, qos=_QOS, retain=False)
        except self._aiomqtt.MqttError as err:
            raise CommunicationError(
                f"MQTT publish to {redact_serial(device_sn)} failed: {err}", device_sn=device_sn
            ) from err
        _LOGGER.debug("MQTT command %d published to %s", head.msg_seq, redact_serial(device_sn))
        return head

    async def async_request(
        self,
        device_sn: str,
        trans: str,
        *,
        match: Match | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> MqttMessage:
        """Publish ``trans`` to ``device_sn`` and return the first message of that device
        ``match`` accepts (default: the request's ``msg_seq`` or ``sess_id``, the SDK's
        correlation). Raises :class:`DeviceTimeoutError` when none arrives within
        ``timeout`` seconds, and what :meth:`async_publish` raises."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[MqttMessage] = loop.create_future()
        sent: list[MqttHead] = []

        def default(message: MqttMessage) -> bool:
            return bool(sent) and (
                message.head.msg_seq == sent[0].msg_seq or message.head.sess_id == sent[0].sess_id
            )

        entry = (match or default, future)
        self._waiters.setdefault(device_sn, []).append(entry)
        try:
            async with asyncio.timeout(timeout):
                sent.append(await self.async_publish(device_sn, trans))
                return await future
        except TimeoutError:
            raise DeviceTimeoutError(
                f"no MQTT answer from {redact_serial(device_sn)} within {timeout:g} s",
                device_sn=device_sn,
            ) from None
        finally:
            waiters = self._waiters.get(device_sn, [])
            if entry in waiters:
                waiters.remove(entry)
            if not waiters:
                self._waiters.pop(device_sn, None)


async def _open(client: aiomqtt.Client) -> None:
    """Connect ``client``. The connect step runs in an executor thread that a cancel cannot
    stop: a cancel waits for it (:data:`CONNECT_SETTLE_SECONDS` at most), closes the
    connection it opened, then propagates; a step still running then is closed when it
    ends. A connect that fails has its socket closed (:func:`_drop`)."""
    connect = asyncio.ensure_future(client.__aenter__())
    try:
        # asyncio.wait, not shield: a shield hands a step that fails after a cancel to the
        # loop's exception handler, although _settle retrieves the error.
        await asyncio.wait({connect})
    except asyncio.CancelledError:
        if await _settle(connect):
            await _close(client, connect)
        else:
            _LOGGER.warning(
                "MQTT connect step still running after %g s; closing it when it ends",
                CONNECT_SETTLE_SECONDS,
            )
            connect.add_done_callback(functools.partial(_drop_when_done, client))
        raise
    try:
        connect.result()
    except BaseException:
        _drop(client)
        raise


async def _close(client: aiomqtt.Client, connect: asyncio.Future[Any]) -> None:
    """Close what the ended connect step ``connect`` opened: a DISCONNECT when it connected
    (:data:`CONNECT_SETTLE_SECONDS` at most), else its socket."""
    if not connect.cancelled() and connect.exception() is None:
        await _settle(asyncio.ensure_future(client.__aexit__(None, None, None)))
    else:
        _drop(client)


def _drop(client: aiomqtt.Client) -> None:
    """Close the socket of a connect that failed. ``aiomqtt`` keeps it after a CONNACK
    timeout, with its reader and keepalive task, and a late CONNACK would make it a live
    session; paho's own close also ends those."""
    paho = client._client
    if paho.socket() is not None:
        paho._sock_close()


def _drop_when_done(client: aiomqtt.Client, connect: asyncio.Future[Any]) -> None:
    """Done callback of a connect step a stop stopped waiting for: close its socket,
    connected or not, and retrieve its error."""
    if not connect.cancelled():
        connect.exception()
    _drop(client)


async def _settle(future: asyncio.Future[Any]) -> bool:
    """Wait for ``future`` (:data:`CONNECT_SETTLE_SECONDS` at most, through further cancels);
    whether it ended. Its exception, if any, counts as retrieved."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + CONNECT_SETTLE_SECONDS
    while not future.done() and (remaining := deadline - loop.time()) > 0:
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait({future}, timeout=remaining)
    if future.done() and not future.cancelled():
        future.exception()
    return future.done()


def _topic_device(topic: str) -> str:
    levels = topic.split("/")
    return redact_serial(levels[3]) if len(levels) > 3 else "?"
