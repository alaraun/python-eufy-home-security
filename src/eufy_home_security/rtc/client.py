"""eufy's WebRTC signaling client (asyncio, UDP with a TCP resend).

:class:`SignalingClient` runs the signaling half of a station's WebRTC session:

1. DISCOVER to the station's signaling host (UDP 5062): the answer names the server
   to log in to (an IPv4 address, or the host itself).
2. LOGIN: a request with an empty body draws a 401 challenge carrying the server's
   public key; the second request seals a fresh session key with it and proves the
   station identity; the 200 carries the client's contact id. A stored
   :class:`~.config.QuickLogin` younger than 23 h logs in with one request, and a 401 to
   it falls back to the key exchange in the same attempt.
3. A MESSAGE ping every 2 s while logged in; every MESSAGE request from the server or
   device is answered 200 carrying the client's own dynamic id.
4. CALL per channel kind (:class:`~.codec.CallKind`): the server answers 100 (with a
   TURN relay), the device 200 with its answer; the client acknowledges every 200 with
   ACK. INFO carries the ICE candidates both ways; an INFO on a private call is answered
   200 echoing its attachment. HANGUP ends a call.

A LOGIN without an answer is sent again after 11-20 s, then at three times the previous
wait, up to 270 s. A packet with the re-discover flag starts DISCOVER and a re-login. A
CALL without an answer is sent again, plain, over TCP (5061 or 15061) to wake the device.
Datagrams from any address but the signaling host and the login server are dropped.

A socket error on any of the client's sockets is reported once through ``on_lost``; the
session (:mod:`.session`) reconnects. See ``docs/protocol/rtc-signaling.md`` § Client.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from .._logging import HexDump, LogThrottle, redact, redact_serial, wire_logger
from ..exceptions import CallRefusedError, DeviceTimeoutError, ProtocolError, SignalingError
from . import codec
from .codec import (
    BodyType,
    CallBody,
    CallKind,
    ContactBody,
    DiscoverAnswer,
    Header,
    KeyExchangeBody,
    MessageBody,
    MessageType,
    ResponseCode,
)
from .config import QuickLogin, RtcConfig, ServerInfo
from .crypto import RtcSignalingCrypto
from .sdp import SdpInfo
from .signaling import (
    CallEventKind,
    call_attachment,
    call_event,
    info_payload,
    login_retry_delays,
    message_answer,
    ping_message,
    private_call_uuid,
)

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("rtc")

#: How long one DISCOVER waits for its answer, and how many are sent.
DISCOVER_TIMEOUT: Final = 4.0
DISCOVER_ATTEMPTS: Final = 3
#: How often the client pings while logged in (the eufy app's 2 s timer).
PING_INTERVAL: Final = 2.0
#: How long a CALL waits for the device's answer: a battery device wakes first.
ANSWER_TIMEOUT: Final = 60.0
#: How long a CALL waits for any answer before it is sent again over TCP.
CALL_REPLY_TIMEOUT: Final = 5.0
#: How many times an unanswered CALL is sent over TCP.
WAKE_ATTEMPTS: Final = 3
TCP_CONNECT_TIMEOUT: Final = 5.0
#: Events kept per call; the oldest is dropped when a reader falls behind.
MAX_CALL_EVENTS: Final = 64
#: The label the client gives its own UDP signaling server in :class:`~.config.ServerInfo`.
SIGNALING_SERVER_TYPE: Final = 0


@dataclass(frozen=True, slots=True)
class CallEvent:
    """One packet on a :class:`Call`: its kind, header and decrypted JSON."""

    kind: CallEventKind
    header: Header
    payload: Mapping[str, Any]


@dataclass(slots=True, eq=False)
class Call:
    """One CALL of a :class:`SignalingClient` and the events that arrive for it."""

    kind: CallKind
    channel: int
    uuid: str
    sub_id: int
    request_id: int
    private: bool
    events: asyncio.Queue[CallEvent] = field(default_factory=lambda: asyncio.Queue(MAX_CALL_EVENTS))
    turn: Mapping[str, Any] | None = None
    """The TURN relay of the CALL 100 or 200 (``turn_addr``, ``turn_port``, ...)."""
    device_request_id: Any = None
    """The ``request_id`` of the device's 200, echoed in the client's INFO."""
    answer: Mapping[str, Any] | None = None
    """The device's CALL 200 attachment."""
    ended: bool = False
    answered: asyncio.Event = field(default_factory=asyncio.Event)
    """Set by the first answer to the CALL (100, 200 or an error code)."""
    dropped: int = 0
    """Events dropped because the queue was full."""

    def push(self, event: CallEvent) -> None:
        """Queue ``event``, dropping the oldest when :data:`MAX_CALL_EVENTS` wait."""
        if self.events.full():
            self.events.get_nowait()
            self.dropped += 1
        self.events.put_nowait(event)

    async def wait_answer(self, timeout: float = ANSWER_TIMEOUT) -> Mapping[str, Any]:
        """The device's answer (the CALL 200 attachment). Raises
        :class:`~.exceptions.CallRefusedError` on an error code or a hang-up before it,
        :class:`~.exceptions.DeviceTimeoutError` after ``timeout``."""
        try:
            async with asyncio.timeout(timeout):
                while True:
                    event = await self.events.get()
                    if event.kind is CallEventKind.OFFER:
                        return event.payload
                    if event.kind is CallEventKind.REFUSED:
                        raise CallRefusedError(
                            f"RTC call refused with code {event.header.code}",
                            code=event.header.code,
                        )
                    if event.kind is CallEventKind.HANGUP:
                        raise CallRefusedError("RTC call hung up before the device's answer")
        except TimeoutError as exc:
            raise DeviceTimeoutError("the device did not answer the RTC call") from exc


class _Endpoint(asyncio.DatagramProtocol):
    def __init__(self, client: SignalingClient, name: str) -> None:
        self._client = client
        self.name = name
        self.transport: asyncio.DatagramTransport | None = None
        self.closing = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._client._received(self, data, addr)

    def error_received(self, exc: Exception) -> None:
        self._client._socket_error(self, exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None
        if not self.closing:
            self._client._socket_error(self, exc or ConnectionError("socket closed"))

    def close(self) -> None:
        self.closing = True
        if self.transport is not None:
            self.transport.close()


def _ipv4(address: str) -> str:
    """``address`` when it is an IPv4 literal; :class:`~.exceptions.ProtocolError` else
    (a host name would need a DNS lookup on the event loop)."""
    try:
        ipaddress.IPv4Address(address)
    except ValueError as exc:
        raise ProtocolError("RTC signaling server address is not an IPv4 address") from exc
    return address


class SignalingClient:
    """The signaling half of one station's WebRTC session.

    ``on_login`` receives the record of every login (re-logins after a re-discover flag
    included) for a consumer's quick-login cache; ``on_server_info`` the record of the
    server each login used (:class:`~.config.ServerInfo`); ``on_lost`` the first socket
    error. ``crypto`` and ``rng`` exist for tests.
    """

    def __init__(
        self,
        config: RtcConfig,
        *,
        crypto: RtcSignalingCrypto | None = None,
        port: int = codec.UDP_PORT,
        tcp_ports: Sequence[int] = codec.TCP_PORTS,
        clock: Callable[[], float] = time.time,
        rng: random.Random | None = None,
        on_login: Callable[[QuickLogin], None] | None = None,
        on_server_info: Callable[[ServerInfo], None] | None = None,
        on_lost: Callable[[Exception], None] | None = None,
    ) -> None:
        self._config = config
        self._rng = rng or random.SystemRandom()
        self._crypto = crypto or RtcSignalingCrypto(self._rng)
        self._port = port
        self._tcp_ports = tuple(tcp_ports)
        self._clock = clock
        self._on_login = on_login
        self._on_server_info = on_server_info
        self._on_lost = on_lost
        self._route = self._rng.getrandbits(8)
        self._counter = 0
        self._call_counter = 0
        self.dynamic_id = self._rng.getrandbits(30)
        """The client's ``eufy_client_dynamic_id``, fixed for its lifetime."""
        self._server = _ipv4(config.signaling_host)
        self._main: _Endpoint | None = None
        self._private: dict[str, _Endpoint] = {}
        self._pending: dict[tuple[int, int], asyncio.Future[tuple[Header, bytes]]] = {}
        self._calls: list[Call] = []
        self._session_key: str | None = None
        self._contact_id: str | None = None
        self._issued_at = 0.0
        self._login_sub = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._ping_task: asyncio.Task[None] | None = None
        self._rediscover_task: asyncio.Task[None] | None = None
        self._tcp: tuple[asyncio.StreamWriter, asyncio.Task[None]] | None = None
        self._lost = False
        self._closed = False
        self._throttle = LogThrottle()
        self._log_name = redact_serial(config.station_sn)

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def server(self) -> str:
        """The server this client logs in and calls through."""
        return self._server

    @property
    def contact_id(self) -> str | None:
        """The contact id of the current login; None before it."""
        return self._contact_id

    @property
    def logged_in(self) -> bool:
        return self._contact_id is not None and self._session_key is not None

    @property
    def calls(self) -> tuple[Call, ...]:
        return tuple(self._calls)

    def quick_login(self) -> QuickLogin | None:
        """The record a later client can log in with in one request."""
        if self._session_key is None or self._contact_id is None:
            return None
        return QuickLogin(self._session_key, self._contact_id, self._server, self._issued_at)

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def open(self) -> None:
        """Open the main UDP socket."""
        if self._closed:
            raise SignalingError("RTC signaling client is closed")
        if self._main is None:
            self._main = await self._open_endpoint("main")

    async def close(self) -> None:
        """Stop the ping, re-login and wake tasks, hang up open calls, close every
        socket and fail every pending request. Safe to call more than once."""
        self._closed = True
        tasks = [t for t in (self._ping_task, self._rediscover_task, *self._tasks) if t]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)
        self._ping_task = self._rediscover_task = None
        self._tasks.clear()
        self._close_tcp()
        for call in list(self._calls):
            if not call.ended:
                with contextlib.suppress(OSError, SignalingError):
                    self.hangup(call)
        for endpoint in (self._main, *self._private.values()):
            if endpoint is not None:
                endpoint.close()
        self._main = None
        self._private.clear()
        for future in self._pending.values():
            if not future.done():
                future.set_exception(SignalingError("RTC signaling client closed"))
        self._pending.clear()

    async def _open_endpoint(self, name: str) -> _Endpoint:
        loop = asyncio.get_running_loop()
        _, protocol = await loop.create_datagram_endpoint(
            lambda: _Endpoint(self, name),
            local_addr=("0.0.0.0", 0),  # noqa: S104 - answers arrive on any interface
        )
        if self._closed:  # closed while the socket opened
            protocol.close()
            raise SignalingError("RTC signaling client is closed")
        return protocol

    def _socket_error(self, endpoint: _Endpoint, exc: Exception) -> None:
        if self._closed or self._lost:
            return
        self._lost = True
        _LOGGER.debug("%s: RTC signaling %s socket error: %s", self._log_name, endpoint.name, exc)
        if self._on_lost is not None:
            self._on_lost(exc)

    def _spawn(self, coro: Any) -> asyncio.Task[None]:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ── packets ──────────────────────────────────────────────────────────────

    def _next_counter(self) -> int:
        self._counter = self._counter % 255 + 1
        return self._counter

    def _header(self, message_type: MessageType, **fields: Any) -> Header:
        fields.setdefault("packet_id", int(self._clock()))
        fields.setdefault("counter", self._next_counter())
        return Header(
            message_type=message_type,
            serial=self._config.station_sn,
            route=self._route,
            **fields,
        )

    def _send(
        self,
        header: Header,
        body: bytes = b"",
        *,
        endpoint: _Endpoint | None = None,
        address: str | None = None,
    ) -> None:
        target = endpoint or self._main
        if target is None or target.transport is None:
            raise SignalingError("RTC signaling socket is not open")
        packet = codec.encode_packet(header, body)
        _WIRE.debug(
            "%s: rtc tx %s to %s\n%s",
            self._log_name,
            MessageType(header.message_type).name,
            address or self._server,
            HexDump(packet),
        )
        target.transport.sendto(codec.obfuscate(packet), (address or self._server, self._port))

    async def _request(
        self,
        header: Header,
        body: bytes = b"",
        *,
        timeout: float,
        address: str | None = None,
    ) -> tuple[Header, bytes]:
        key = (header.message_type, header.request_id)
        future: asyncio.Future[tuple[Header, bytes]] = asyncio.get_running_loop().create_future()
        self._pending[key] = future
        try:
            self._send(header, body, address=address)
            async with asyncio.timeout(timeout):
                return await future
        except TimeoutError as exc:
            raise DeviceTimeoutError(
                f"no RTC signaling answer to {MessageType(header.message_type).name}"
            ) from exc
        finally:
            self._pending.pop(key, None)

    def _received(self, endpoint: _Endpoint, data: bytes, addr: tuple[Any, int]) -> None:
        if addr[0] not in (self._server, self._config.signaling_host):
            if self._throttle.should_log("source"):
                _LOGGER.debug("%s: RTC datagram from an unknown address dropped", self._log_name)
            return
        try:
            header, body = codec.decode_packet(codec.deobfuscate(data))
        except ProtocolError as exc:
            _LOGGER.debug("%s: dropping an RTC signaling datagram: %s", self._log_name, exc)
            return
        _WIRE.debug(
            "%s: rtc rx type %s code %s\n%s",
            self._log_name,
            header.message_type,
            header.code,
            HexDump(body),
        )
        if header.flags & codec.FLAG_REDISCOVER:
            self._schedule_rediscover()
        if header.is_response:
            future = self._pending.get((header.message_type, header.request_id))
            if future is not None and not future.done():
                future.set_result((header, body))
                return
        try:
            self._dispatch(endpoint, header, body)
        except (ProtocolError, SignalingError, OSError) as exc:
            _LOGGER.debug("%s: RTC signaling packet not handled: %s", self._log_name, exc)

    def _open_attachment(self, header: Header, data: bytes) -> Mapping[str, Any]:
        if not data:
            return {}
        if header.encrypted:
            if self._session_key is None:
                raise ProtocolError("encrypted RTC attachment before login")
            data = self._crypto.open(self._session_key, header.packet_id, data)
        return codec.json_text(data)

    def _seal(self, packet_id: int, value: Mapping[str, Any]) -> bytes:
        if self._session_key is None:
            raise SignalingError("RTC signaling is not logged in")
        return self._crypto.seal(self._session_key, packet_id, codec.json_bytes(value))

    def _dispatch(self, endpoint: _Endpoint, header: Header, body: bytes) -> None:
        mtype = header.message_type
        if mtype == MessageType.MESSAGE:
            if not header.is_response:
                self._answer_message(endpoint, header, MessageBody.decode(body))
            return
        if mtype in (MessageType.CALL, MessageType.INFO, MessageType.HANGUP):
            self._call_packet(endpoint, header, CallBody.decode(body))
            return
        _LOGGER.debug("%s: unhandled RTC signaling message type %s", self._log_name, mtype)

    # ── DISCOVER and LOGIN ───────────────────────────────────────────────────

    async def discover(self) -> str:
        """Ask the signaling host which server to log in to; returns it and keeps it
        as :attr:`server`. Raises :class:`~.exceptions.DeviceTimeoutError` when none of
        :data:`DISCOVER_ATTEMPTS` is answered, :class:`~.exceptions.SignalingError` for a
        non-200 answer and :class:`~.exceptions.ProtocolError` for an answer naming
        something other than an IPv4 address."""
        host = self._config.signaling_host
        for attempt in range(1, DISCOVER_ATTEMPTS + 1):
            try:
                header, body = await self._request(
                    self._header(MessageType.DISCOVER), timeout=DISCOVER_TIMEOUT, address=host
                )
            except DeviceTimeoutError:
                if attempt == DISCOVER_ATTEMPTS:
                    raise
                continue
            if header.code != ResponseCode.OK:
                raise SignalingError(f"RTC DISCOVER answered {header.code}", code=header.code)
            self._server = _ipv4(DiscoverAnswer.decode(body).login_address(host))
            _LOGGER.debug("%s: RTC signaling server %s", self._log_name, self._server)
            return self._server
        raise AssertionError("unreachable")  # pragma: no cover

    async def login(self, record: QuickLogin | None = None) -> QuickLogin:
        """Log in: a quick login with a usable ``record`` (default: the config's), else
        the key exchange; returns the record a later client can quick-login with.
        Raises :class:`~.exceptions.SignalingError` when the server refuses the login,
        :class:`~.exceptions.DeviceTimeoutError` when every attempt goes unanswered."""
        stored = record or self._config.quick_login
        loop = asyncio.get_running_loop()
        began = loop.time()
        try:
            if stored is not None and stored.usable(self._clock()):
                result = await self._quick_login(stored)
            else:
                result = await self._full_login()
        except (DeviceTimeoutError, SignalingError):
            self._report_server(failed=True)
            raise
        self._report_server(rtt=loop.time() - began)
        return result

    async def _quick_login(self, stored: QuickLogin) -> QuickLogin:
        self._server = _ipv4(stored.server or self._server)
        now = int(self._clock())
        body = ContactBody(
            stored.contact_id,
            self._crypto.seal(stored.session_key, now, self._config.identity),
        ).encode()
        header, answer = await self._login_request(
            lambda: self._header(
                MessageType.LOGIN,
                packet_id=now,
                mode=0,
                sub_id=self._login_sub,
                body_type=BodyType.CONTACT,
            ),
            body,
        )
        if header.code == ResponseCode.OK:
            return self._logged_in(header, answer, stored.session_key)
        if header.code != ResponseCode.UNAUTHORIZED:
            raise SignalingError(f"RTC quick LOGIN answered {header.code}", code=header.code)
        return await self._key_exchange(header, answer)

    async def _full_login(self) -> QuickLogin:
        header, answer = await self._login_request(
            lambda: self._header(
                MessageType.LOGIN, mode=codec.WORK_PROTOCOL, sub_id=self._login_sub
            )
        )
        if header.code != ResponseCode.UNAUTHORIZED:
            raise SignalingError(
                f"RTC LOGIN answered {header.code}, expected 401", code=header.code
            )
        return await self._key_exchange(header, answer)

    async def _login_request(
        self, build: Callable[[], Header], body: bytes = b""
    ) -> tuple[Header, bytes]:
        delays = login_retry_delays(self._rng)
        for attempt, delay in enumerate(delays, 1):
            try:
                return await self._request(build(), body, timeout=delay)
            except DeviceTimeoutError:
                if attempt == len(delays):
                    raise
                _LOGGER.debug(
                    "%s: RTC LOGIN unanswered after %.0f s, sending again", self._log_name, delay
                )
        raise AssertionError("unreachable")  # pragma: no cover

    async def _key_exchange(self, challenge: Header, body: bytes) -> QuickLogin:
        public_key = self._crypto.open_challenge(body, challenge.packet_id)
        session_key = self._crypto.new_session_key()
        exchange = KeyExchangeBody(
            self._crypto.seal_session_key(public_key, session_key),
            self._crypto.seal(session_key, challenge.packet_id, self._config.identity),
        )
        header, answer = await self._login_request(
            lambda: self._header(
                MessageType.LOGIN,
                packet_id=challenge.packet_id,
                mode=challenge.mode,
                sub_id=challenge.sub_id,
                body_type=BodyType.KEY_EXCHANGE,
            ),
            exchange.encode(),
        )
        if header.code != ResponseCode.OK:
            raise SignalingError(f"RTC LOGIN key exchange answered {header.code}", code=header.code)
        return self._logged_in(header, answer, session_key)

    def _logged_in(self, header: Header, body: bytes, session_key: str) -> QuickLogin:
        contact = ContactBody.decode(body).contact_id
        if not contact:
            raise ProtocolError("RTC LOGIN 200 carries no contact id")
        self._session_key = session_key
        self._contact_id = contact
        self._login_sub = header.sub_id
        self._issued_at = self._clock()
        _LOGGER.debug("%s: RTC signaling logged in, contact %s", self._log_name, redact(contact))
        record = QuickLogin(session_key, contact, self._server, self._issued_at)
        if self._on_login is not None:
            self._on_login(record)
        return record

    def _report_server(self, *, rtt: float = 0.0, failed: bool = False) -> None:
        if self._on_server_info is None:
            return
        now = int(self._clock())
        ms = round(rtt * 1000)
        self._on_server_info(
            ServerInfo(
                domain=self._config.signaling_domain or "",
                server_type=SIGNALING_SERVER_TYPE,
                ip=self._server,
                port=self._port,
                protocol=SIGNALING_SERVER_TYPE,
                last_fail_timestamp=now if failed else 0,
                last_used_timestamp=0 if failed else now,
                avg_rtt=ms,
                max_rtt=ms,
            )
        )

    def _schedule_rediscover(self) -> None:
        if not self.logged_in or self._rediscover_task is not None or self._closed:
            return
        self._rediscover_task = asyncio.get_running_loop().create_task(self._rediscover())

    async def _rediscover(self) -> None:
        """DISCOVER and a re-login with the current session, on the server's request."""
        try:
            _LOGGER.debug("%s: RTC signaling server asks for a new DISCOVER", self._log_name)
            await self.discover()
            await self.login(self.quick_login())
        except (DeviceTimeoutError, ProtocolError, SignalingError, OSError) as exc:
            _LOGGER.debug("%s: RTC re-login failed: %s", self._log_name, exc)
        finally:
            self._rediscover_task = None

    # ── ping and messages ────────────────────────────────────────────────────

    def start_ping(self, interval: float = PING_INTERVAL) -> None:
        """Send a MESSAGE ping every ``interval`` seconds until :meth:`close`."""
        if self._ping_task is None and not self._closed:
            self._ping_task = asyncio.get_running_loop().create_task(self._ping_loop(interval))

    async def _ping_loop(self, interval: float) -> None:
        while True:
            try:
                self.send_ping()
            except (OSError, SignalingError) as exc:
                if self._throttle.should_log("ping"):
                    _LOGGER.debug("%s: RTC ping not sent: %s", self._log_name, exc)
            await asyncio.sleep(interval)

    def send_ping(self) -> None:
        """One MESSAGE ping: channel 0, command type 2, sub type 0x66."""
        if self._contact_id is None:
            raise SignalingError("RTC signaling is not logged in")
        now = int(self._clock())
        value = ping_message(
            self._config, contact_id=self._contact_id, dynamic_id=self.dynamic_id, now=now
        )
        self._send(
            self._header(
                MessageType.MESSAGE, packet_id=now, encrypted=True, body_type=BodyType.MESSAGE
            ),
            MessageBody(
                0,
                codec.PING_COMMAND_TYPE,
                codec.PING_SUB_TYPE,
                self._contact_id,
                self._seal(now, value),
            ).encode(),
        )

    def _answer_message(self, endpoint: _Endpoint, header: Header, body: MessageBody) -> None:
        if self._contact_id is None:
            return
        self._send(
            header.response(ResponseCode.OK, body_type=BodyType.MESSAGE),
            MessageBody(
                body.channel,
                body.command_type,
                body.sub_type,
                self._contact_id,
                self._seal(header.packet_id, message_answer(self.dynamic_id)),
            ).encode(),
            endpoint=endpoint,
        )

    # ── calls ────────────────────────────────────────────────────────────────

    async def call(
        self,
        kind: CallKind,
        *,
        channel: int = 0,
        video_format: int = 0,
        sdp_info: SdpInfo | None = None,
        boot_action: int | None = None,
        wake: bool = True,
    ) -> Call:
        """Send a CALL of ``kind`` and return it; its events arrive on
        :attr:`Call.events` (:meth:`Call.wait_answer` waits for the device's answer).

        A private kind (:data:`~.codec.PRIVATE_CALL_KINDS`) needs ``sdp_info`` and
        travels on a socket of its own; it carries a token sealed with the session key.
        With ``wake``, a CALL unanswered after :data:`CALL_REPLY_TIMEOUT` is sent again
        over TCP, up to :data:`WAKE_ATTEMPTS` times. Raises
        :class:`~.exceptions.SignalingError` before a login.
        """
        if self._contact_id is None or self._session_key is None:
            raise SignalingError("RTC signaling is not logged in")
        private = kind in codec.PRIVATE_CALL_KINDS
        now = int(self._clock())
        token = None
        uuid = ""
        if private:
            token = self._crypto.seal(self._session_key, now, self._config.identity)
            uuid = private_call_uuid(self._config, kind, int(self._clock() * 1_000_000))
        attachment = call_attachment(
            self._config,
            kind,
            channel=channel,
            contact_id=self._contact_id,
            now=now,
            video_format=video_format,
            token=token,
            sdp_info=sdp_info,
            boot_action=boot_action,
        )
        self._call_counter = self._call_counter % 255 + 1
        header = self._header(
            MessageType.CALL,
            packet_id=now,
            mode=codec.WORK_PROTOCOL if private else 0,
            encrypted=True,
            body_type=BodyType.CALL,
            sub_id=self._call_counter,
        )
        call = Call(
            kind=kind,
            channel=channel,
            uuid=uuid,
            sub_id=self._call_counter,
            request_id=header.request_id,
            private=private,
        )
        endpoint = None
        if private:
            endpoint = await self._open_endpoint("private")
            self._private[uuid] = endpoint
        self._calls.append(call)
        body = CallBody(channel, uuid, self._contact_id, self._seal(now, attachment)).encode()
        self._send(header, body, endpoint=endpoint)
        if wake:
            self._spawn(self._wake(call, codec.encode_packet(header, body, obfuscated=False)))
        return call

    async def _wake(self, call: Call, packet: bytes) -> None:
        """Send ``packet`` (the plain CALL) over TCP while the CALL stays unanswered."""
        for attempt in range(1, WAKE_ATTEMPTS + 1):
            try:
                async with asyncio.timeout(CALL_REPLY_TIMEOUT):
                    await call.answered.wait()
                return
            except TimeoutError:
                pass
            if call.ended:
                return
            _LOGGER.debug(
                "%s: RTC CALL unanswered, sending it over TCP (%d/%d)",
                self._log_name,
                attempt,
                WAKE_ATTEMPTS,
            )
            try:
                await self._send_tcp(packet, self._private.get(call.uuid) or self._main)
            except (OSError, TimeoutError) as exc:
                _LOGGER.debug("%s: RTC TCP send failed: %s", self._log_name, exc)

    async def _send_tcp(self, packet: bytes, endpoint: _Endpoint | None) -> None:
        """A fresh TCP connection to the server on a random TCP port, ``packet`` on it;
        its answers are handled like datagrams, replies to them go out on ``endpoint``."""
        self._close_tcp()
        port = self._rng.choice(self._tcp_ports)
        async with asyncio.timeout(TCP_CONNECT_TIMEOUT):
            reader, writer = await asyncio.open_connection(self._server, port)
        _WIRE.debug("%s: rtc tcp tx to port %d\n%s", self._log_name, port, HexDump(packet))
        reading = self._spawn(self._read_tcp(reader, endpoint))
        self._tcp = (writer, reading)
        writer.write(packet)
        await writer.drain()

    async def _read_tcp(self, reader: asyncio.StreamReader, endpoint: _Endpoint | None) -> None:
        decoder = codec.StreamDecoder()
        try:
            while data := await reader.read(4096):
                for packet in decoder.feed(data):
                    if endpoint is not None:
                        self._received(endpoint, packet, (self._server, 0))
        except (OSError, ProtocolError) as exc:
            _LOGGER.debug("%s: RTC TCP stream closed: %s", self._log_name, exc)

    def _close_tcp(self) -> None:
        if self._tcp is not None:
            writer, task = self._tcp
            task.cancel()
            writer.close()
            self._tcp = None

    def _find_call(self, header: Header, body: CallBody) -> Call | None:
        for call in self._calls:
            if header.is_response and call.request_id == header.request_id:
                return call
        for call in self._calls:
            if body.uuid and call.uuid == body.uuid:
                return call
        live = [c for c in self._calls if not c.ended and c.channel == body.channel]
        return live[-1] if live else None

    def _call_packet(self, endpoint: _Endpoint, header: Header, body: CallBody) -> None:
        call = self._find_call(header, body)
        if call is None:
            _LOGGER.debug("%s: RTC call packet for no open call", self._log_name)
            return
        payload = self._open_attachment(header, body.attachment)
        kind = call_event(header)
        if header.message_type == MessageType.CALL and header.is_response:
            call.answered.set()
        if kind is CallEventKind.HANGUP:
            call.ended = True
        elif kind is CallEventKind.INFO and not header.is_response:
            # A private call's INFO is answered by echoing its attachment.
            echo = body if call.private else body.without_attachment()
            self._send(header.response(ResponseCode.OK), echo.encode(), endpoint=endpoint)
        elif kind is CallEventKind.TRYING:
            call.turn = _turn(payload) or call.turn
        elif kind is CallEventKind.OFFER:
            call.answer = payload
            call.device_request_id = payload.get("request_id")
            call.turn = _turn(payload) or call.turn
            self._send(
                self._header(MessageType.ACK, body_type=BodyType.CALL, sub_id=header.sub_id),
                body.without_attachment().encode(),
                endpoint=endpoint,
            )
        elif kind is CallEventKind.REFUSED:
            call.ended = True
        call.push(CallEvent(kind, header, payload))

    def send_info(self, call: Call, payload: Mapping[str, Any]) -> None:
        """INFO on ``call``: a candidate or an acknowledgement; the device's request id
        is added when its 200 carried one."""
        if self._contact_id is None:
            raise SignalingError("RTC signaling is not logged in")
        now = int(self._clock())
        value = info_payload(call.device_request_id, payload)
        self._send(
            self._header(
                MessageType.INFO, packet_id=now, encrypted=True, body_type=BodyType.CALL, sub_id=1
            ),
            CallBody(call.channel, call.uuid, self._contact_id, self._seal(now, value)).encode(),
            endpoint=self._private.get(call.uuid) if call.private else None,
        )

    def hangup(self, call: Call) -> None:
        """HANGUP ``call`` (once)."""
        if call.ended:
            return
        call.ended = True
        self._send(
            self._header(MessageType.HANGUP, body_type=BodyType.CALL, sub_id=call.sub_id),
            CallBody(call.channel, call.uuid, self._contact_id or "").encode(),
            endpoint=self._private.get(call.uuid) if call.private else None,
        )


def _turn(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    turn = payload.get("turn")
    return turn if isinstance(turn, Mapping) else None


__all__ = ["Call", "CallEvent", "SignalingClient"]
