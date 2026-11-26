"""The MQTT connections of one account (needs the ``mqtt`` extra: ``aiomqtt``).

A login scope has its own session, certificate and client id, so the account's MQTT devices
are served by one :class:`~.client.EufyMqttClient` per scope that holds any of them.
:class:`EufyMqttAccount` keeps those clients in step with the device list and routes each
call to the client of its device's scope. See docs/protocol/mqtt.md § The client.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from .._logging import redact_serial
from ..exceptions import CloudError, CommunicationError, UnsupportedError
from .client import (
    KEEPALIVE_SECONDS,
    MQTT_PORT,
    REQUEST_TIMEOUT_SECONDS,
    EufyMqttClient,
    Listener,
    Match,
    device_scope,
    require_aiomqtt,
)
from .selection import mqtt_devices

if TYPE_CHECKING:
    from ..cloud.api import EufyCloudApi
    from ..cloud.models import CloudDevice
    from .envelope import MqttHead, MqttMessage

_LOGGER = logging.getLogger(__name__)


class EufyMqttAccount:
    """Every MQTT connection of the account behind ``cloud``: one
    :class:`~.client.EufyMqttClient` per login scope with MQTT devices.

    ``port``, ``keepalive`` and ``server_ca_pem`` are passed to each client. Raises
    :class:`MissingDependencyError` without the ``mqtt`` extra.
    """

    def __init__(
        self,
        cloud: EufyCloudApi,
        *,
        port: int = MQTT_PORT,
        keepalive: int = KEEPALIVE_SECONDS,
        server_ca_pem: str | None = None,
    ) -> None:
        require_aiomqtt()
        self._cloud = cloud
        self._port = port
        self._keepalive = keepalive
        self._server_ca_pem = server_ca_pem
        self._clients: dict[str, EufyMqttClient] = {}
        self._listeners: list[Listener] = []
        self._cloud_listeners: list[Callable[[CloudError], None]] = []
        self._subscribe: frozenset[str] | None = None
        self._stopped = False
        """Set by :meth:`async_stop`, cleared by :meth:`async_start`: device updates are ignored."""
        self._ending: set[asyncio.Task[None]] = set()
        """Client stops still running after a cancel of :meth:`async_stop`'s caller."""
        self._lifecycle = asyncio.Lock()
        """Held by start, device update and stop, so a stop never interleaves with them."""

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def clients(self) -> Mapping[str, EufyMqttClient]:
        """The running client of each login scope."""
        return MappingProxyType(self._clients)

    @property
    def devices(self) -> tuple[CloudDevice, ...]:
        """The MQTT devices served, scope by scope."""
        return tuple(d for client in self._clients.values() for d in client.devices)

    @property
    def connected(self) -> bool:
        """Whether there is a client and every client's connection is up."""
        return bool(self._clients) and all(c.connected for c in self._clients.values())

    @property
    def topics(self) -> frozenset[str]:
        """The answer topics the broker accepted, over every connection."""
        return frozenset().union(*(c.topics for c in self._clients.values()))

    def add_listener(self, listener: Listener) -> Callable[[], None]:
        """Call ``listener`` with every message any device publishes; returns its remover."""
        self._listeners.append(listener)
        for client in self._clients.values():
            client.add_listener(listener)

        def remove() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)
                for client in self._clients.values():
                    client.remove_listener(listener)

        return remove

    def add_cloud_error_listener(
        self, listener: Callable[[CloudError], None]
    ) -> Callable[[], None]:
        """Call ``listener`` with each cloud error of a client's certificate fetch (which
        never logs in: :class:`~..exceptions.NoCachedSessionError` without a usable
        session); returns its remover. :meth:`~..client.EufySecurity.use_mqtt` reports them
        as :class:`~..events.CloudProblem`."""
        self._cloud_listeners.append(listener)

        def remove() -> None:
            if listener in self._cloud_listeners:
                self._cloud_listeners.remove(listener)

        return remove

    def _cloud_error(self, error: CloudError) -> None:
        for listener in list(self._cloud_listeners):
            try:
                listener(error)
            except Exception:
                _LOGGER.exception("MQTT cloud error listener %r failed", listener)

    def client_for(self, device_sn: str) -> EufyMqttClient:
        """The client serving MQTT device ``device_sn``; :class:`UnsupportedError` for
        a serial that is none of the account's MQTT devices."""
        for client in self._clients.values():
            if any(d.device_sn == device_sn for d in client.devices):
                return client
        raise UnsupportedError(
            f"{redact_serial(device_sn)} is not an MQTT device of this account",
            device_sn=device_sn,
        )

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def _scopes(self, devices: list[CloudDevice]) -> list[str]:
        selected = await asyncio.to_thread(mqtt_devices, devices)
        return list(dict.fromkeys(device_scope(d, self._cloud) for d in selected))

    async def _start_client(
        self, scope: str, devices: list[CloudDevice], *, connect_without_devices: bool = False
    ) -> None:
        client = EufyMqttClient(
            self._cloud,
            region=scope,
            port=self._port,
            keepalive=self._keepalive,
            server_ca_pem=self._server_ca_pem,
            on_cloud_error=self._cloud_error,
        )
        for listener in self._listeners:
            client.add_listener(listener)
        self._clients[scope] = client
        await client.async_start(
            devices, subscribe=self._subscribe, connect_without_devices=connect_without_devices
        )

    async def async_start(
        self,
        devices: Iterable[CloudDevice],
        *,
        subscribe: Iterable[str] | None = None,
        connect_without_devices: bool = False,
    ) -> None:
        """Start a client for each login scope holding MQTT devices among ``devices``.

        With none, nothing connects unless ``connect_without_devices`` (a connection check
        on the cloud's :attr:`~..cloud.api.EufyCloudApi.region`). ``subscribe`` is each
        client's (:meth:`.EufyMqttClient.async_start`).
        """
        async with self._lifecycle:
            if self._clients:
                raise RuntimeError("the MQTT account is already started")
            self._stopped = False
            listed = list(devices)
            self._subscribe = None if subscribe is None else frozenset(subscribe)
            scopes = await self._scopes(listed)
            if not scopes and connect_without_devices:
                await self._start_client(self._cloud.region, listed, connect_without_devices=True)
            for scope in scopes:
                await self._start_client(scope, listed)

    async def async_update_devices(self, devices: Iterable[CloudDevice]) -> None:
        """Follow a new device list: a scope without MQTT devices left has its client
        stopped, a new one gets a client, and the others follow the list
        (:meth:`.EufyMqttClient.async_update_devices`). After :meth:`async_stop` it does
        nothing until the next :meth:`async_start`."""
        async with self._lifecycle:
            if self._stopped:
                _LOGGER.debug("MQTT account stopped: device update ignored")
                return
            listed = list(devices)
            scopes = await self._scopes(listed)
            for scope in [s for s in self._clients if s not in scopes]:
                await self._clients.pop(scope).async_stop()
            for scope in scopes:
                client = self._clients.get(scope)
                if client is None:
                    await self._start_client(scope, listed)
                else:
                    await client.async_update_devices(listed)

    async def async_stop(self) -> None:
        """Stop every client; their pending requests get a :class:`CommunicationError`.
        A start or device update in progress finishes first, then is stopped; a later
        device update is ignored until the next :meth:`async_start`. The clients stop
        together; a cancel of the caller propagates at once and they still stop. A client
        stop that fails is logged as a warning, and the first such failure is raised to a
        caller still waiting."""
        async with self._lifecycle:
            self._stopped = True
            clients, self._clients = list(self._clients.values()), {}
            # Tasks, not awaits in turn: a cancel of the caller still stops every client.
            stops = [asyncio.create_task(c.async_stop()) for c in clients]
            for stop in stops:
                self._ending.add(stop)
                stop.add_done_callback(self._stop_ended)
            if stops:
                await asyncio.wait(stops)
                for stop in stops:
                    stop.result()

    def _stop_ended(self, stop: asyncio.Task[None]) -> None:
        """Done callback of a client stop: its failure is logged here, read or not."""
        self._ending.discard(stop)
        if not stop.cancelled() and (err := stop.exception()) is not None:
            _LOGGER.warning("MQTT client stop failed: %s", err)

    async def async_wait_connected(self, timeout: float) -> None:
        """Wait until every client's connection is up; :class:`CommunicationError` when
        one is not within ``timeout`` seconds, or when there is no client."""
        if not self._clients:
            raise CommunicationError("no MQTT device: no broker connection")
        await asyncio.gather(*(c.async_wait_connected(timeout) for c in self._clients.values()))

    # ── commands ─────────────────────────────────────────────────────────────

    async def async_publish(
        self,
        device_sn: str,
        trans: str,
        *,
        need_ack: bool = False,
        sess_id: str | None = None,
        account_id: str | None = None,
        extra_fields: bool = True,
    ) -> MqttHead:
        """:meth:`.EufyMqttClient.async_publish` on the client of ``device_sn``'s scope."""
        return await self.client_for(device_sn).async_publish(
            device_sn,
            trans,
            need_ack=need_ack,
            sess_id=sess_id,
            account_id=account_id,
            extra_fields=extra_fields,
        )

    async def async_request(
        self,
        device_sn: str,
        trans: str,
        *,
        match: Match | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        publish_timeout: float | None = None,
        account_id: str | None = None,
        extra_fields: bool = True,
    ) -> MqttMessage:
        """:meth:`.EufyMqttClient.async_request` on the client of ``device_sn``'s scope."""
        return await self.client_for(device_sn).async_request(
            device_sn,
            trans,
            match=match,
            timeout=timeout,
            publish_timeout=publish_timeout,
            account_id=account_id,
            extra_fields=extra_fields,
        )
