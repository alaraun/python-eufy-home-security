"""eufy RTC signaling client (asyncio, UDP).

Runs the signaling half of a WebRTC session the way the eufy app does:

1. DISCOVER to the station's signaling host (UDP 5062): the answer names the server
   to log in to.
2. LOGIN: a request with an empty body draws a 401 challenge carrying the server's
   public key; the second request seals a fresh session key with it and proves the
   station identity; the 200 carries the client's contact id. A stored
   :class:`~.config.QuickLogin` younger than 23 h logs in with one request.
3. CALL per channel kind (:class:`~.codec.CallKind`): the server answers 100 (with a
   TURN relay), the device 200 with its offer; the client acknowledges with ACK and
   exchanges its answer and candidates in INFO. HANGUP ends a call.
4. While logged in, a MESSAGE ping every 3 s keeps the session alive, and every
   MESSAGE request from the server or device is answered 200.

A LOGIN request without an answer is sent again after 11-20 s, then at three times
the previous wait, up to 270 s. A packet with the re-discover flag starts DISCOVER and
a re-login. A CALL without an answer is sent again, plain, over TCP (5061 or 15061),
as the app does for a sleeping device.

Every attachment and message is sealed with the session key through an
:class:`~.crypto.RtcCrypto`. See ``docs/protocol/rtc-signaling.md``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from .._logging import HexDump, redact, redact_serial, wire_logger
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
from .config import QuickLogin, RtcConfig
from .crypto import RtcCrypto
from .sdp import SdpInfo

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("rtc")

DISCOVER_TIMEOUT: Final = 4.0
DISCOVER_ATTEMPTS: Final = 3
LOGIN_ATTEMPTS: Final = 4
LOGIN_RETRY_BASE: Final = 10.0
LOGIN_RETRY_FACTOR: Final = 3
LOGIN_RETRY_MAX: Final = 270.0
PING_INTERVAL: Final = 3.0
OFFER_TIMEOUT: Final = 60.0
"""How long a CALL waits for the device's offer: a battery device wakes first."""
CALL_REPLY_TIMEOUT: Final = 5.0
"""How long a CALL waits for any answer before it is sent again over TCP."""
WAKE_ATTEMPTS: Final = 3
TCP_CONNECT_TIMEOUT: Final = 5.0
CALL_FTV: Final = 20
NETWORK_UDP: Final = 1


def login_retry_delays(rng: random.Random) -> list[float]:
    """How long each LOGIN attempt waits for its answer: 10 s plus 1-10 s, then three
    times the previous wait, at most 270 s; :data:`LOGIN_ATTEMPTS` waits."""
    delay = LOGIN_RETRY_BASE + rng.randint(1, 10)
    delays = []
    for _ in range(LOGIN_ATTEMPTS):
        delays.append(min(delay, LOGIN_RETRY_MAX))
        delay *= LOGIN_RETRY_FACTOR
    return delays


def md5_hex(text: str) -> str:
    """Lower-case hex MD5 of ``text``: the attachments' ``account`` field and the
    private calls' uuid (an identifier, not a secret)."""
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def private_call_uuid(config: RtcConfig, kind: CallKind, micros: int) -> str:
    """The 36-character uuid of a private call: ``"FF00<kind>"`` and 31 hex digits."""
    digest = md5_hex(
        f"{config.station_sn}{config.app_id}{config.p2p_did}{config.p2p_license}{micros}{int(kind)}"
    )
    return f"FF00{int(kind)}{digest[:31]}"


class CallEventKind(StrEnum):
    """What happened on a call."""

    TRYING = "trying"
    """CALL 100 from the server; ``payload`` may carry ``turn``."""
    OFFER = "offer"
    """CALL 200 from the device; ``payload`` carries ``sdp`` and ``request_id``."""
    INFO = "info"
    """INFO from the device: a candidate, an SDP or ``content``."""
    HANGUP = "hangup"
    REFUSED = "refused"
    """CALL answered with an error code (480, 486)."""


@dataclass(frozen=True, slots=True)
class CallEvent:
    """One event of a :class:`Call`."""

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
    events: asyncio.Queue[CallEvent] = field(default_factory=asyncio.Queue)
    turn: Mapping[str, Any] | None = None
    device_request_id: Any = None
    offer: Mapping[str, Any] | None = None
    ended: bool = False
    answered: asyncio.Event = field(default_factory=asyncio.Event)
    """Set by the first answer to the CALL (100, 200 or an error code)."""

    async def wait_offer(self, timeout: float = OFFER_TIMEOUT) -> Mapping[str, Any]:
        """The device's offer (the CALL 200 payload). Raises
        :class:`~.exceptions.CallRefusedError` on an error code or a hang-up before
        it, :class:`~.exceptions.DeviceTimeoutError` after ``timeout``."""
        async with asyncio.timeout(timeout):
            while True:
                event = await self.events.get()
                if event.kind is CallEventKind.OFFER:
                    return event.payload
                if event.kind is CallEventKind.REFUSED:
                    raise CallRefusedError(
                        f"call refused with code {event.header.code}", code=event.header.code
                    )
                if event.kind is CallEventKind.HANGUP:
                    raise CallRefusedError("call hung up before the device's offer")


class _Endpoint(asyncio.DatagramProtocol):
    def __init__(self, client: SignalingClient, name: str) -> None:
        self._client = client
        self._name = name
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._client._received(self, data, addr)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("RTC signaling %s socket error: %s", self._name, exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None


class SignalingClient:
    """The signaling half of one station's RTC session."""

    def __init__(
        self,
        config: RtcConfig,
        crypto: RtcCrypto,
        *,
        port: int = codec.UDP_PORT,
        tcp_ports: Sequence[int] = codec.TCP_PORTS,
        clock: Callable[[], float] = time.time,
        rng: random.Random | None = None,
        on_login: Callable[[QuickLogin], None] | None = None,
    ) -> None:
        """``on_login`` receives the record of every login, the re-logins after a
        re-discover flag included; a consumer stores it for the next quick login."""
        self._config = config
        self._crypto = crypto
        self._port = port
        self._tcp_ports = tuple(tcp_ports)
        self._on_login = on_login
        self._clock = clock
        self._rng = rng or random.SystemRandom()
        self._route = self._rng.getrandbits(8)
        self._counter = 0
        self._call_counter = 0
        self._dynamic_id = self._rng.getrandbits(30)
        self._server = config.signaling_host
        self._main: _Endpoint | None = None
        self._private: dict[str, _Endpoint] = {}
        self._pending: dict[tuple[int, int], asyncio.Future[tuple[Header, bytes]]] = {}
        self._calls: list[Call] = []
        self._session_key: str | None = None
        self._contact_id: str | None = None
        self._issued_at = 0.0
        self._login_sub = 0
        self._ping_task: asyncio.Task[None] | None = None
        self._rediscover_task: asyncio.Task[None] | None = None
        self._wake_tasks: set[asyncio.Task[None]] = set()
        self._tcp: tuple[asyncio.StreamWriter, asyncio.Task[None]] | None = None
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
        if self._main is None:
            self._main = await self._open_endpoint("main")

    async def close(self) -> None:
        """Stop the ping, re-login and wake tasks, hang up open calls, close every
        socket."""
        tasks = [t for t in (self._ping_task, self._rediscover_task) if t is not None]
        tasks += self._wake_tasks
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._ping_task = self._rediscover_task = None
        self._wake_tasks.clear()
        self._close_tcp()
        for call in list(self._calls):
            if not call.ended:
                with contextlib.suppress(OSError, ProtocolError, SignalingError):
                    self.hangup(call)
        for endpoint in (self._main, *self._private.values()):
            if endpoint is not None and endpoint.transport is not None:
                endpoint.transport.close()
        self._main = None
        self._private.clear()
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    async def _open_endpoint(self, name: str) -> _Endpoint:
        loop = asyncio.get_running_loop()
        _, protocol = await loop.create_datagram_endpoint(
            lambda: _Endpoint(self, name),
            local_addr=("0.0.0.0", 0),  # noqa: S104 - answers arrive on any interface
        )
        return protocol

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
        try:
            header, body = codec.decode_packet(codec.deobfuscate(data))
        except ProtocolError as exc:
            _LOGGER.debug("%s: dropping an RTC signaling datagram: %s", self._log_name, exc)
            return
        _WIRE.debug(
            "%s: rtc rx type %s code %s from %s\n%s",
            self._log_name,
            header.message_type,
            header.code,
            addr[0],
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
        except (ProtocolError, SignalingError) as exc:
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
        _LOGGER.debug(
            "%s: unhandled RTC signaling message type %s", self._log_name, header.message_type
        )

    # ── DISCOVER and LOGIN ───────────────────────────────────────────────────

    async def discover(self) -> str:
        """Ask the signaling host which server to log in to; returns it and keeps it
        as :attr:`server`. Raises :class:`~.exceptions.DeviceTimeoutError` when none
        of the attempts is answered, :class:`~.exceptions.SignalingError` for a
        non-200 answer."""
        host = self._config.signaling_host
        for attempt in range(DISCOVER_ATTEMPTS):
            try:
                header, body = await self._request(
                    self._header(MessageType.DISCOVER),
                    timeout=DISCOVER_TIMEOUT,
                    address=host,
                )
            except DeviceTimeoutError:
                if attempt + 1 == DISCOVER_ATTEMPTS:
                    raise
                continue
            if header.code != ResponseCode.OK:
                raise SignalingError(f"DISCOVER answered {header.code}", code=header.code)
            answer = DiscoverAnswer.decode(body)
            self._server = answer.login_address(host)
            _LOGGER.debug("%s: RTC signaling server %s", self._log_name, self._server)
            return self._server
        raise AssertionError("unreachable")  # pragma: no cover

    async def login(self, record: QuickLogin | None = None) -> QuickLogin:
        """Log in: a quick login with a usable ``record`` (default: the config's),
        else the key exchange; returns the record a later client can quick-login with.
        Raises :class:`~.exceptions.SignalingError` when the server refuses the login,
        :class:`~.exceptions.DeviceTimeoutError` when every attempt goes unanswered."""
        stored = record or self._config.quick_login
        if stored is not None and stored.usable(self._clock()):
            self._server = stored.server or self._server
            body = ContactBody(
                stored.contact_id,
                self._crypto.seal(stored.session_key, int(self._clock()), self._config.identity),
            ).encode()
            header, answer = await self._login_request(
                lambda: self._header(
                    MessageType.LOGIN, mode=0, sub_id=self._login_sub, body_type=BodyType.CONTACT
                ),
                body,
            )
            if header.code == ResponseCode.OK:
                return self._logged_in(header, answer, stored.session_key)
            if header.code != ResponseCode.UNAUTHORIZED:
                raise SignalingError(f"quick LOGIN answered {header.code}", code=header.code)
            return await self._key_exchange(header, answer)
        header, answer = await self._login_request(
            lambda: self._header(
                MessageType.LOGIN, mode=codec.WORK_PROTOCOL, sub_id=self._login_sub
            ),
        )
        if header.code != ResponseCode.UNAUTHORIZED:
            raise SignalingError(f"LOGIN answered {header.code}, expected 401", code=header.code)
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
            raise SignalingError(f"LOGIN key exchange answered {header.code}", code=header.code)
        return self._logged_in(header, answer, session_key)

    def _logged_in(self, header: Header, body: bytes, session_key: str) -> QuickLogin:
        contact = ContactBody.decode(body).contact_id
        if not contact:
            raise ProtocolError("LOGIN 200 carries no contact id")
        self._session_key = session_key
        self._contact_id = contact
        self._login_sub = header.sub_id
        self._issued_at = self._clock()
        _LOGGER.debug("%s: RTC signaling logged in, contact %s", self._log_name, redact(contact))
        record = QuickLogin(session_key, contact, self._server, self._issued_at)
        if self._on_login is not None:
            self._on_login(record)
        return record

    def _schedule_rediscover(self) -> None:
        if not self.logged_in or self._rediscover_task is not None:
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
        if self._ping_task is None:
            self._ping_task = asyncio.get_running_loop().create_task(self._ping_loop(interval))

    async def _ping_loop(self, interval: float) -> None:
        while True:
            try:
                self.send_ping()
            except (OSError, SignalingError) as exc:
                _LOGGER.debug("%s: RTC ping not sent: %s", self._log_name, exc)
            await asyncio.sleep(interval)

    def send_ping(self) -> None:
        """One MESSAGE ping: channel 0, command type 2, sub type 0x66."""
        if self._contact_id is None:
            raise SignalingError("RTC signaling is not logged in")
        now = int(self._clock())
        content = {
            "eufy_contact_id": self._contact_id,
            "eufy_network_type": NETWORK_UDP,
            "eufy_app_id": self._config.app_id,
        }
        wrapper = {
            "to": "device",
            "account": md5_hex(f"0{self._config.user_id}{now}"),
            "eufy_client_dynamic_id": self._dynamic_id,
            "content": base64.b64encode(codec.json_bytes(content)).decode(),
        }
        self._send(
            self._header(
                MessageType.MESSAGE, packet_id=now, encrypted=True, body_type=BodyType.MESSAGE
            ),
            MessageBody(
                0,
                codec.PING_COMMAND_TYPE,
                codec.PING_SUB_TYPE,
                self._contact_id,
                self._seal(now, wrapper),
            ).encode(),
        )

    def _answer_message(self, endpoint: _Endpoint, header: Header, body: MessageBody) -> None:
        if self._contact_id is None:
            return
        reply = {
            "to": "device",
            "eufy_client_dynamic_id": self._rng.getrandbits(30),
            "account": "",
            "content": "",
            "eufy_network_type": NETWORK_UDP,
        }
        self._send(
            header.response(ResponseCode.OK, body_type=BodyType.MESSAGE),
            MessageBody(
                body.channel,
                body.command_type,
                body.sub_type,
                self._contact_id,
                self._seal(header.packet_id, reply),
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
        :attr:`Call.events` (:meth:`Call.wait_offer` waits for the device's offer).

        A private kind (:data:`~.codec.PRIVATE_CALL_KINDS`) needs ``sdp_info`` and
        travels on a socket of its own; it carries a token sealed with the session key.
        With ``wake``, a CALL unanswered after :data:`CALL_REPLY_TIMEOUT` is sent
        again over TCP, up to :data:`WAKE_ATTEMPTS` times.
        """
        if self._contact_id is None or self._session_key is None:
            raise SignalingError("RTC signaling is not logged in")
        private = kind in codec.PRIVATE_CALL_KINDS
        if private and sdp_info is None:
            raise ValueError(f"a {kind.name} call needs sdp_info")
        info = sdp_info
        now = int(self._clock())
        call_type, p2p_type = codec.CALL_TYPES[kind]
        attachment: dict[str, Any] = {
            "account": md5_hex(f"{channel}{self._config.user_id}{now}"),
            "ftv": CALL_FTV,
            "call_type": call_type,
        }
        if p2p_type is not None:
            attachment["eufy_p2p_type"] = p2p_type
        attachment |= {
            "to": "device",
            "eufy_from_contact": self._contact_id,
            "eufy_video_format": video_format,
            "eufy_network_type": NETWORK_UDP,
            "eufy_app_id": self._config.app_id,
        }
        uuid = ""
        if info is not None and private:
            token = self._crypto.seal(self._session_key, now, self._config.identity)
            attachment["token"] = base64.b64encode(token).decode()
            attachment["sdp_info"] = base64.b64encode(info.encode()).decode()
            if boot_action is not None:
                attachment["boot_action"] = boot_action
            uuid = private_call_uuid(self._config, kind, int(self._clock() * 1_000_000))
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
            endpoint = self._private.get(call.uuid) or await self._open_endpoint("private")
            self._private[call.uuid] = endpoint
        self._calls.append(call)
        body = CallBody(channel, uuid, self._contact_id, self._seal(now, attachment)).encode()
        self._send(header, body, endpoint=endpoint)
        if wake:
            task = asyncio.get_running_loop().create_task(
                self._wake(call, codec.encode_packet(header, body, obfuscated=False), endpoint)
            )
            self._wake_tasks.add(task)
            task.add_done_callback(self._wake_tasks.discard)
        return call

    async def _wake(self, call: Call, packet: bytes, endpoint: _Endpoint | None) -> None:
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
                await self._send_tcp(packet, endpoint or self._main)
            except (OSError, TimeoutError) as exc:
                _LOGGER.debug("%s: RTC TCP send failed: %s", self._log_name, exc)

    async def _send_tcp(self, packet: bytes, endpoint: _Endpoint | None) -> None:
        """A fresh TCP connection to the server on a random TCP port, ``packet`` on
        it; its answers are handled like datagrams, replies to them go out on
        ``endpoint``."""
        self._close_tcp()
        port = self._rng.choice(self._tcp_ports)
        async with asyncio.timeout(TCP_CONNECT_TIMEOUT):
            reader, writer = await asyncio.open_connection(self._server, port)
        _WIRE.debug(
            "%s: rtc tcp tx to %s:%d\n%s", self._log_name, self._server, port, HexDump(packet)
        )
        writer.write(packet)
        await writer.drain()
        task = asyncio.get_running_loop().create_task(
            self._read_tcp(reader, endpoint, (self._server, port))
        )
        self._tcp = (writer, task)

    async def _read_tcp(
        self, reader: asyncio.StreamReader, endpoint: _Endpoint | None, addr: tuple[str, int]
    ) -> None:
        decoder = codec.StreamDecoder()
        try:
            while data := await reader.read(4096):
                for packet in decoder.feed(data):
                    if endpoint is not None:
                        self._received(endpoint, packet, addr)
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
        mtype = header.message_type
        if mtype == MessageType.CALL and header.is_response:
            call.answered.set()
        if mtype == MessageType.HANGUP:
            call.ended = True
            event = CallEventKind.HANGUP
        elif mtype == MessageType.INFO:
            event = CallEventKind.INFO
            if not header.is_response:
                self._send(
                    header.response(ResponseCode.OK),
                    body.without_attachment().encode(),
                    endpoint=endpoint,
                )
        elif header.code == ResponseCode.TRYING:
            event = CallEventKind.TRYING
            turn = payload.get("turn")
            call.turn = turn if isinstance(turn, Mapping) else call.turn
        elif header.code == ResponseCode.OK:
            event = CallEventKind.OFFER
            call.offer = payload
            call.device_request_id = payload.get("request_id")
            turn = payload.get("turn")
            call.turn = turn if isinstance(turn, Mapping) else call.turn
            self._acknowledge(endpoint, header, body)
        elif header.is_response:
            call.ended = True
            event = CallEventKind.REFUSED
        else:
            event = CallEventKind.INFO
        call.events.put_nowait(CallEvent(event, header, payload))

    def _acknowledge(self, endpoint: _Endpoint, header: Header, body: CallBody) -> None:
        self._send(
            self._header(MessageType.ACK, body_type=BodyType.CALL, sub_id=header.sub_id),
            body.without_attachment().encode(),
            endpoint=endpoint,
        )

    def send_info(self, call: Call, payload: Mapping[str, Any]) -> None:
        """INFO on ``call``: the answer (``{"sdp": ...}``) or a candidate
        (``{"candidate": ...}``); the device's request id is added."""
        if self._contact_id is None:
            raise SignalingError("RTC signaling is not logged in")
        now = int(self._clock())
        value = {"request_id": call.device_request_id, **payload}
        self._send(
            self._header(
                MessageType.INFO,
                packet_id=now,
                encrypted=True,
                body_type=BodyType.CALL,
                sub_id=1,
            ),
            CallBody(call.channel, call.uuid, self._contact_id, self._seal(now, value)).encode(),
            endpoint=self._private.get(call.uuid) if call.private else None,
        )

    def hangup(self, call: Call) -> None:
        """HANGUP ``call`` and forget it."""
        if call.ended:
            return
        call.ended = True
        self._send(
            self._header(MessageType.HANGUP, body_type=BodyType.CALL, sub_id=call.sub_id),
            CallBody(call.channel, call.uuid, self._contact_id or "").encode(),
            endpoint=self._private.get(call.uuid) if call.private else None,
        )
