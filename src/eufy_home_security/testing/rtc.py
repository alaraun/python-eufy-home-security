"""A loopback eufy WebRTC signaling server and station for tests (``rtc`` code).

:class:`FakeRtcServer` answers on UDP and TCP on 127.0.0.1 as eufy's signaling server
and a station behind it do: DISCOVER (``server_addr: "self"``), LOGIN with a 401
challenge carrying the public half of an RSA-1024 key made for the test process, the
key exchange and the quick login, the MESSAGE ping, and a CALL with 100 (a TURN record)
then the device's 200 (a synthetic ``sdp_info``, optional ``request_id`` and
``transport_caps``), after which it trickles the device's ``file_candidate`` INFOs until
the client acknowledges them and acknowledges the client's. Its crypto is the real one,
so every attachment the client sends is decrypted and recorded (:attr:`received`). It
takes the client's CALL, INFO, ACK, HANGUP and MESSAGE answer only with the header fields
a station expects (a private CALL's mode, INFO sub_id 1, an ACK's or HANGUP's sub_id that
of its CALL, a MESSAGE answer from the socket the request reached); any other form is
recorded in :attr:`~FakeRtcServer.refused` and not acted on.

:meth:`FakeRtcServer.ice_factory` gives the session an in-memory ICE connection
(:class:`PipeIce`) that connects only with the credentials of both ``sdp_info`` and after
the client's first candidate; behind it the station runs a KCP data channel that echoes
every message (:attr:`FakeRtcServer.device_channels`).

Scripts: ``call_reply`` (``answer``, ``trying``, ``busy``, ``hangup``, ``silent``),
``udp_calls`` False (only a CALL over TCP is answered: a sleeping device),
``refuse_login``, ``drop_logins``, ``drop_discovers``, ``answer_repeats``,
``ice_connects`` False, ``ack_candidates``/``ack_only``, and
:meth:`~FakeRtcServer.hang_up`, :meth:`~FakeRtcServer.break_link`,
:meth:`~FakeRtcServer.send_candidate`, :meth:`~FakeRtcServer.send_info` mid-session.
Synthetic identities only (:data:`~.synthetic.SYNTHETIC`).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import functools
import json
import time
from dataclasses import dataclass, field
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..exceptions import CommunicationError, ProtocolError
from ..rtc import codec
from ..rtc.codec import (
    BodyType,
    CallBody,
    ContactBody,
    Endpoint,
    Header,
    KeyExchangeBody,
    MessageBody,
    MessageType,
)
from ..rtc.config import RtcConfig
from ..rtc.crypto import DEFAULT_SECRET, aes_ecb_decrypt, aes_ecb_encrypt
from ..rtc.data_channel import KcpDataChannel
from ..rtc.media import TurnServer
from ..rtc.sdp import SdpInfo
from .synthetic import SYNTHETIC

#: The synthetic P2P license of the fake station.
LICENSE: Final = "ABCDEF"
#: The synthetic app install id the fake config carries.
APP_ID: Final = "0123456789abcdef"
#: The contact id every login of the fake gets.
CONTACT: Final = "c0" * 16
#: The device's answer ``sdp_info`` (ICE credentials, content key, kcp_type-2 flag).
DEVICE_INFO: Final = SdpInfo(
    audio_ssrc=0x01020304,
    video_ssrc=0x05060708,
    ice_ufrag="dev01",
    ice_pwd="devpassword0123456789ab",  # noqa: S106 - synthetic
    content_key="k" * 16,
    content_iv="i" * 12,
    data_channel=True,
)
#: A TURN record on loopback (no TURN server behind it).
TURN: Final = {
    "turn_addr": "127.0.0.1",
    "turn_port": 3478,
    "turn_user": "user",
    "turn_password": "pass",
}
#: The device's one candidate line, as it sends it.
DEVICE_CANDIDATE: Final = "a=candidate:1 1 UDP 2130706431 127.0.0.1 9 typ host"
#: How often the fake station sends an unacknowledged candidate again.
CANDIDATE_RESEND: Final = 0.2


@functools.cache
def server_key() -> rsa.RSAPrivateKey:
    """The fake server's RSA-1024 key, made once per process."""
    return rsa.generate_private_key(public_exponent=0x10001, key_size=1024)  # noqa: S505 - protocol


def rtc_config(host: str = "127.0.0.1", **kwargs: Any) -> RtcConfig:
    """A config for the fake station (signaling host ``host``)."""
    return RtcConfig(
        station_sn=SYNTHETIC.station_sn,
        p2p_did=SYNTHETIC.did,
        p2p_license=LICENSE,
        signaling_host=host,
        user_id=SYNTHETIC.account_id,
        app_id=APP_ID,
        **kwargs,
    )


@dataclass
class Received:
    """One packet the fake received, its attachment decrypted when it could be."""

    header: Header
    body: bytes
    addr: tuple[str, int]
    via: str = "udp"
    payload: dict[str, Any] | None = None


class PipeIce:
    """One end of an in-memory ICE connection (:class:`~eufy_home_security.rtc.ice.IceAgent`)."""

    def __init__(self, server: FakeRtcServer | None = None) -> None:
        self._server = server
        self._inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.peer: PipeIce | None = None
        self.credentials: tuple[str, str] | None = None
        self.remote_candidates: list[str] = []
        self.closed = False
        self.drop_outbound = False
        self.lines = ["candidate:1 1 udp 2130706431 127.0.0.1 7 typ host"]
        """The candidate lines :meth:`gather` returns."""
        """True: every datagram sent is lost (a peer that went away)."""

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        self.credentials = (local_ufrag, local_pwd)
        return list(self.lines)

    def add_remote_candidate(self, candidate: str) -> None:
        self.remote_candidates.append(candidate)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        server = self._server
        if server is None:
            return
        if not server.ice_connects:
            await asyncio.Event().wait()
        await server.client_candidate.wait()
        device = server.device_info
        call = server.call_info
        if (remote_ufrag, remote_pwd) != (device.ice_ufrag, device.ice_pwd) or (
            call is None or self.credentials != (call.ice_ufrag, call.ice_pwd)
        ):
            raise CommunicationError("RTC ICE did not connect: credentials do not match")
        if self.peer is not None:
            server._attach(self.peer)

    async def recv(self) -> bytes:
        data = await self._inbox.get()
        if data is None:
            self._inbox.put_nowait(None)
            raise CommunicationError("RTC ICE connection closed")
        return data

    async def send(self, data: bytes) -> None:
        if self.closed or self.peer is None:
            raise CommunicationError("RTC ICE connection closed")
        if not self.drop_outbound:
            self.peer._inbox.put_nowait(data)

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._inbox.put_nowait(None)
            if self.peer is not None:
                self.peer._inbox.put_nowait(None)


@dataclass(eq=False)
class FakeRtcServer(asyncio.DatagramProtocol):
    """eufy's signaling server and a station behind it, on loopback."""

    call_reply: str = "answer"
    udp_calls: bool = True
    refuse_login: bool = False
    drop_logins: int = 0
    drop_discovers: int = 0
    answer_repeats: int = 1
    request_id: str | None = None
    """The 200's ``request_id``; None leaves it out (as a HomeBase 3 does)."""
    transport_caps: int | None = None
    turn: dict[str, Any] | None = field(default_factory=lambda: dict(TURN))
    device_info: SdpInfo = DEVICE_INFO
    ice_connects: bool = True
    ack_candidates: bool = True
    """False: the client's candidates are never acknowledged."""
    ack_only: set[int] | None = None
    """The candidate numbers acknowledged; None: all."""
    server_addr: str = "self"
    """The DISCOVER answer's ``server_addr``."""
    received: list[Received] = field(default_factory=list)
    sessions: dict[str, str] = field(default_factory=dict)
    """Contact id -> session key of every login."""
    call_info: SdpInfo | None = None
    """The client's ``sdp_info`` of the last CALL."""
    client_candidates: list[dict[str, Any]] = field(default_factory=list)
    device_acks: set[int] = field(default_factory=set)
    device_channels: list[KcpDataChannel] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    """Packets of the client in a form a station does not take (a header field off)."""
    port: int = 0
    tcp_port: int = 0

    def __post_init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.tcp: asyncio.Server | None = None
        self.client_candidate = asyncio.Event()
        self._tasks: set[asyncio.Task[None]] = set()
        self._pipes: list[PipeIce] = []
        self._calls: list[tuple[CallBody, Header, tuple[str, int]]] = []
        self._message_to: set[tuple[str, int]] = set()
        self._call_sub_ids: dict[str, int] = {}
        self._counter = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> FakeRtcServer:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=("127.0.0.1", 0)
        )
        self.port = transport.get_extra_info("sockname")[1]
        self.tcp = await asyncio.start_server(self._tcp_client, "127.0.0.1", 0)
        self.tcp_port = self.tcp.sockets[0].getsockname()[1]
        return self

    async def close(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.wait(self._tasks)
        for channel in self.device_channels:
            await channel.close()
        for pipe in self._pipes:
            await pipe.close()
        if self.transport is not None:
            self.transport.close()
        if self.tcp is not None:
            self.tcp.close()
            await self.tcp.wait_closed()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport

    def ice_factory(self) -> PipeIce:
        """The client end of a new in-memory ICE connection to this station."""
        client, device = PipeIce(self), PipeIce()
        client.peer, device.peer = device, client
        self._pipes += [client, device]
        return client

    def _attach(self, device: PipeIce) -> None:
        channel = KcpDataChannel(device, prefixed=self.device_info.data_channel)
        self.device_channels.append(channel)
        self._spawn(self._echo(channel))

    async def _echo(self, channel: KcpDataChannel) -> None:
        with contextlib.suppress(CommunicationError):
            while True:
                message = await channel.recv_message()
                await channel.send_message(message.payload, msg_type=message.msg_type)

    def _spawn(self, coro: Any) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ── scripted events ──────────────────────────────────────────────────────

    def kinds(self) -> list[int]:
        """The message types received, in order."""
        return [r.header.message_type for r in self.received]

    def of_type(self, message_type: int) -> list[Received]:
        return [r for r in self.received if r.header.message_type == message_type]

    def hang_up(self) -> None:
        """The station hangs up the last call."""
        body, _, addr = self._calls[-1]
        self._device_packet(MessageType.HANGUP, body, None, addr)

    async def break_link(self) -> None:
        """The station's side of every ICE connection goes away."""
        for pipe in self._pipes:
            await pipe.close()

    def send_candidate(self, number: int = 0, line: str = DEVICE_CANDIDATE) -> None:
        """The station sends a candidate INFO on the last call (again, for a seen number)."""
        self.send_info({"file_candidate": line, "file_candidate_num": number})

    def send_info(self, payload: dict[str, Any]) -> None:
        """The station sends an INFO with ``payload`` on the last call."""
        body, _, addr = self._calls[-1]
        self._device_packet(MessageType.INFO, body, payload, addr)

    def device_message(self, addr: tuple[str, int], *, flags: int = 0) -> None:
        """A MESSAGE request (the device's ping) to the client at ``addr``."""
        key = self.sessions[CONTACT]
        header = self._header(
            MessageType.MESSAGE, encrypted=True, body_type=BodyType.MESSAGE, flags=flags
        )
        data = aes_ecb_encrypt(key, header.packet_id, b'{"to": "contact"}')
        self.send(header, MessageBody(0, 2, 0x66, CONTACT, data).encode(), addr)

    # ── wire ─────────────────────────────────────────────────────────────────

    def send(self, header: Header, body: bytes, addr: tuple[str, int]) -> None:
        if header.message_type == MessageType.MESSAGE and not header.is_response:
            self._message_to.add(addr)
        if self.transport is not None and not self.transport.is_closing():
            self.transport.sendto(codec.obfuscate(codec.encode_packet(header, body)), addr)

    def _header(self, message_type: int, **fields: Any) -> Header:
        self._counter = self._counter % 255 + 1
        fields.setdefault("packet_id", int(time.time()))
        return Header(
            message_type=message_type,
            serial=SYNTHETIC.station_sn,
            counter=self._counter,
            route=1,
            sender=Endpoint.DEVICE,
            **fields,
        )

    def _seal(self, packet_id: int, value: dict[str, Any]) -> bytes:
        return aes_ecb_encrypt(self.sessions[CONTACT], packet_id, json.dumps(value).encode())

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        header, body = codec.decode_packet(codec.deobfuscate(data))
        self._handle(Received(header, body, addr), lambda h, b: self.send(h, b, addr))

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        decoder = codec.StreamDecoder()

        def reply(header: Header, body: bytes) -> None:
            writer.write(codec.encode_packet(header, body, obfuscated=False))

        with contextlib.suppress(OSError):
            while data := await reader.read(4096):
                for packet in decoder.feed(data):
                    header, body = codec.decode_packet(packet)
                    self._handle(Received(header, body, addr, "tcp"), reply)
        writer.close()

    def _payload(self, header: Header, contact: str, data: bytes) -> dict[str, Any] | None:
        key = self.sessions.get(contact)
        if not data or key is None:
            return None
        try:
            plain = aes_ecb_decrypt(key, header.packet_id, data) if header.encrypted else data
            return codec.json_text(plain)
        except ProtocolError:
            return None

    def _handle(self, item: Received, reply: Any) -> None:
        header, body = item.header, item.body
        mtype = header.message_type
        if mtype in (MessageType.CALL, MessageType.INFO, MessageType.ACK, MessageType.HANGUP):
            call = CallBody.decode(body)
            item.payload = self._payload(header, call.contact_id, call.attachment)
        elif mtype == MessageType.MESSAGE:
            message = MessageBody.decode(body)
            item.payload = self._payload(header, message.contact_id, message.data)
        self.received.append(item)
        if (problem := self._form(item)) is not None:
            self.refused.append(problem)
            return
        if header.is_response:
            return
        if mtype == MessageType.DISCOVER:
            if self.drop_discovers > 0:
                self.drop_discovers -= 1
                return
            answer = {"server_addr": self.server_addr, "timestamp": 1, "saddrs": []}
            reply(header.response(200, body_type=BodyType.JSON), json.dumps(answer).encode())
        elif mtype == MessageType.LOGIN:
            if self.drop_logins > 0:
                self.drop_logins -= 1
                return
            self._login(header, body, reply)
        elif mtype == MessageType.MESSAGE:
            reply(header.response(200), MessageBody.decode(body).encode())
        elif mtype == MessageType.CALL and (self.udp_calls or item.via == "tcp"):
            self._call(header, CallBody.decode(body), item, reply)
        elif mtype == MessageType.INFO and item.payload is not None:
            self._client_info(CallBody.decode(body), item)

    def _form(self, item: Received) -> str | None:
        """What is off in the client's packet's header; None when a station takes it."""
        header = item.header
        mtype = header.message_type
        if header.is_response:
            if mtype == MessageType.MESSAGE and item.addr not in self._message_to:
                return "MESSAGE 200 from another socket than the request reached"
            return None
        if mtype == MessageType.CALL:
            uuid = CallBody.decode(item.body).uuid
            self._call_sub_ids[uuid] = header.sub_id
            mode = codec.WORK_PROTOCOL if uuid else 0
            if header.mode != mode:
                return f"CALL mode {header.mode}, not {mode}"
        if mtype == MessageType.INFO and header.sub_id != 1:
            return f"INFO sub_id {header.sub_id}, not 1"
        if mtype in (MessageType.ACK, MessageType.HANGUP) and header.sub_id != (
            self._call_sub_ids.get(CallBody.decode(item.body).uuid)
        ):
            return f"{MessageType(mtype).name} sub_id {header.sub_id}, not the CALL's"
        return None

    def _challenge(self, header: Header, reply: Any) -> None:
        modulus = f"{server_key().public_key().public_numbers().n:0256x}"
        blob = aes_ecb_encrypt(DEFAULT_SECRET, header.packet_id, modulus.encode())
        reply(header.response(401, body_type=BodyType.DEFAULT_KEY_BLOB), blob)

    def _identity_ok(self, key: str, salt: int, sealed: bytes) -> bool:
        plain = aes_ecb_decrypt(key, salt, sealed).rstrip(b"\0")
        return plain == f"{SYNTHETIC.did}:{LICENSE}".encode()

    def _login(self, header: Header, body: bytes, reply: Any) -> None:
        if header.body_type == BodyType.KEY_EXCHANGE:
            exchange = KeyExchangeBody.decode(body)
            key = server_key().decrypt(exchange.sealed_key, padding.PKCS1v15()).decode()
            if self.refuse_login or not self._identity_ok(
                key, header.packet_id, exchange.sealed_identity
            ):
                self._challenge(header, reply)
                return
            self.sessions[CONTACT] = key
            reply(header.response(200, body_type=BodyType.CONTACT), ContactBody(CONTACT).encode())
            return
        if header.body_type == BodyType.CONTACT:
            contact = ContactBody.decode(body)
            known = self.sessions.get(contact.contact_id)
            if known is not None and self._identity_ok(known, header.packet_id, contact.data):
                reply(
                    header.response(200, body_type=BodyType.CONTACT), ContactBody(CONTACT).encode()
                )
                return
        self._challenge(header, reply)

    def _call(self, header: Header, call: CallBody, item: Received, reply: Any) -> None:
        payload = item.payload or {}
        raw = payload.get("sdp_info")
        if isinstance(raw, str):
            self.call_info = SdpInfo.decode(base64.b64decode(raw))
        self._calls.append((call, header, item.addr))
        if self.call_reply == "silent":
            return
        if self.call_reply == "busy":
            reply(header.response(486), call.without_attachment().encode())
            return
        trying = {"turn": self.turn} if self.turn else {}
        reply(
            header.response(100),
            CallBody(
                call.channel, call.uuid, CONTACT, self._seal(header.packet_id, trying)
            ).encode(),
        )
        if self.call_reply == "hangup":
            self._device_packet(MessageType.HANGUP, call, None, item.addr)
            return
        if self.call_reply != "answer":
            return
        answer: dict[str, Any] = {
            "sdp_info": base64.b64encode(self.device_info.encode()).decode(),
            "call_type": "scall",
            "eufy_p2p_type": "priv1",
            "port": codec.UDP_PORT,
        }
        if self.turn:
            answer["turn"] = self.turn
        if self.request_id is not None:
            answer["request_id"] = self.request_id
        if self.transport_caps is not None:
            answer["transport_caps"] = self.transport_caps
        for _ in range(self.answer_repeats):
            reply(
                header.response(200),
                CallBody(
                    call.channel, call.uuid, CONTACT, self._seal(header.packet_id, answer)
                ).encode(),
            )
        if item.via == "udp":
            self._spawn(self._trickle(call, item.addr))

    async def _trickle(self, call: CallBody, addr: tuple[str, int]) -> None:
        """Send the device's candidate until the client acknowledges it."""
        for _ in range(50):
            if 0 in self.device_acks:
                return
            self._device_packet(
                MessageType.INFO,
                call,
                {"file_candidate": DEVICE_CANDIDATE, "file_candidate_num": 0},
                addr,
            )
            await asyncio.sleep(CANDIDATE_RESEND)

    def _client_info(self, call: CallBody, item: Received) -> None:
        payload = item.payload or {}
        ack = payload.get("file_candidate_ack")
        if isinstance(ack, int):
            self.device_acks.add(ack)
            return
        number = payload.get("file_candidate_num")
        if isinstance(number, int) and "file_candidate" in payload:
            self.client_candidates.append(payload)
            self.client_candidate.set()
            if self.ack_candidates and (self.ack_only is None or number in self.ack_only):
                self._device_packet(
                    MessageType.INFO, call, {"file_candidate_ack": number}, item.addr
                )

    def _device_packet(
        self, mtype: int, call: CallBody, payload: dict[str, Any] | None, addr: tuple[str, int]
    ) -> None:
        header = self._header(mtype, encrypted=payload is not None, body_type=BodyType.CALL)
        attach = self._seal(header.packet_id, payload) if payload is not None else b""
        self.send(header, CallBody(call.channel, call.uuid, CONTACT, attach).encode(), addr)


__all__ = [
    "APP_ID",
    "CONTACT",
    "DEVICE_INFO",
    "LICENSE",
    "TURN",
    "FakeRtcServer",
    "PipeIce",
    "Received",
    "rtc_config",
    "server_key",
]
