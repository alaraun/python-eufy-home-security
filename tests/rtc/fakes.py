"""A fake RTC signaling server and a reversible stand-in for the signaling crypto."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

from eufy_home_security.p2p.xzyh import HEADER_LEN, encode_frame
from eufy_home_security.rtc import codec
from eufy_home_security.rtc.codec import (
    BodyType,
    CallBody,
    ContactBody,
    Header,
    KeyExchangeBody,
    MessageBody,
    MessageType,
    ResponseCode,
)
from eufy_home_security.rtc.command import decrypt_command_reply, encrypt_command
from eufy_home_security.rtc.config import RtcConfig
from eufy_home_security.rtc.data_channel import DataMsgType, KcpDataChannel
from eufy_home_security.rtc.media import AccessUnit, TurnServer
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.testing import SYNTHETIC

PUBLIC_KEY = "fake-public-key"
SESSION_KEY = "s" * 16
CONTACT = "c" * 32
LICENSE = "ABCDEF"
USER_ID = "u" * 40
APP_ID = "0123456789abcdef"
#: The device's answer sdp_info the fake CALL 200 carries.
DEVICE_INFO = SdpInfo(
    audio_ssrc=0x01020304,
    video_ssrc=0x05060708,
    ice_ufrag="dev01",
    ice_pwd="p" * 23,
    content_key="k" * 16,
    content_iv="i" * 12,
)
TURN = {"turn_addr": "198.51.100.9", "turn_port": 3478, "turn_user": "u", "turn_password": "p"}


class FakeCrypto:
    """Reversible, not cryptographic: records every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def open_challenge(self, body: bytes, salt: int) -> str:
        self.calls.append(("open_challenge", salt))
        return body.decode()

    def new_session_key(self) -> str:
        self.calls.append(("new_session_key", None))
        return SESSION_KEY

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        self.calls.append(("seal_session_key", public_key))
        return f"K:{public_key}:{session_key}".encode()

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        self.calls.append(("seal", salt))
        return b"S" + session_key.encode() + b"|" + data

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        prefix = b"S" + session_key.encode() + b"|"
        if not data.startswith(prefix):
            raise ValueError("not sealed with this key")
        return data[len(prefix) :]

    def new_media_secret(self, length: int) -> str:
        self.calls.append(("new_media_secret", length))
        return "m" * length


def seal(data: bytes) -> bytes:
    return FakeCrypto().seal(SESSION_KEY, 0, data)


def unseal(data: bytes) -> dict[str, Any]:
    return codec.json_text(FakeCrypto().open(SESSION_KEY, 0, data))


def config(port_host: str = "127.0.0.1", **kwargs: Any) -> RtcConfig:
    return RtcConfig(
        station_sn=SYNTHETIC.station_sn,
        p2p_did=SYNTHETIC.did,
        p2p_license=LICENSE,
        signaling_host=port_host,
        user_id=USER_ID,
        app_id=APP_ID,
        **kwargs,
    )


@dataclass
class Received:
    header: Header
    body: bytes
    addr: tuple[str, int]
    via: str = "udp"


Reply = Callable[[Header, bytes], None]


@dataclass
class FakeServer(asyncio.DatagramProtocol):
    """Answers DISCOVER and LOGIN as eufy's server does; CALL per ``call_reply``."""

    received: list[Received] = field(default_factory=list)
    call_reply: str = "offer"
    """``offer`` (100 then 200), ``trying`` (100 only), ``busy`` (486), ``silent``."""
    refuse_login: bool = False
    udp_calls: bool = True
    """False: a CALL over UDP goes unanswered (a sleeping device), only TCP answers."""
    drop_logins: int = 0
    """How many LOGIN requests go unanswered first."""
    request_id: str | None = "r1"
    """The CALL 200's ``request_id``; ``None`` leaves it out (as a HomeBase 3 does)."""
    transport: asyncio.DatagramTransport | None = None
    tcp: asyncio.Server | None = None
    tcp_port: int = 0
    on_packet: Callable[[Received], None] | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def kinds(self) -> list[int]:
        return [r.header.message_type for r in self.received]

    def send(self, header: Header, body: bytes, addr: tuple[str, int]) -> None:
        assert self.transport is not None
        self.transport.sendto(codec.obfuscate(codec.encode_packet(header, body)), addr)

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
        if self.tcp is not None:
            self.tcp.close()

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

    def _handle(self, item: Received, reply: Reply) -> None:
        header, body = item.header, item.body
        self.received.append(item)
        if self.on_packet is not None:
            self.on_packet(item)
        if header.is_response:
            return
        mtype = header.message_type
        if mtype == MessageType.DISCOVER:
            answer = {"server_addr": "self", "timestamp": 1, "saddrs": []}
            reply(header.response(200, body_type=BodyType.JSON), json.dumps(answer).encode())
        elif mtype == MessageType.LOGIN:
            if self.drop_logins > 0:
                self.drop_logins -= 1
                return
            self._login(header, body, reply)
        elif mtype == MessageType.CALL and (self.udp_calls or item.via == "tcp"):
            self._call(header, body, reply)

    def _login(self, header: Header, body: bytes, reply: Reply) -> None:
        if header.body_type == BodyType.KEY_EXCHANGE:
            exchange = KeyExchangeBody.decode(body)
            assert exchange.sealed_key.rstrip(b"\0") == f"K:{PUBLIC_KEY}:{SESSION_KEY}".encode()
            identity = FakeCrypto().open(SESSION_KEY, 0, exchange.sealed_identity)
            if self.refuse_login or identity != f"{SYNTHETIC.did}:{LICENSE}".encode():
                reply(
                    header.response(401, body_type=BodyType.DEFAULT_KEY_BLOB), PUBLIC_KEY.encode()
                )
                return
            ok = header.response(200, body_type=BodyType.CONTACT)
            reply(Header(**{**_fields(ok), "sub_id": 9}), ContactBody(CONTACT).encode())
            return
        if header.body_type == BodyType.CONTACT:
            contact = ContactBody.decode(body)
            if contact.contact_id == CONTACT:
                reply(
                    header.response(200, body_type=BodyType.CONTACT), ContactBody(CONTACT).encode()
                )
                return
        reply(header.response(401, body_type=BodyType.DEFAULT_KEY_BLOB), PUBLIC_KEY.encode())

    def _call(self, header: Header, body: bytes, reply: Reply) -> None:
        call = CallBody.decode(body)
        if self.call_reply == "silent":
            return
        if self.call_reply == "busy":
            reply(header.response(486), call.without_attachment().encode())
            return
        reply(
            Header(**{**_fields(header.response(100)), "encrypted": True}),
            CallBody(
                call.channel, call.uuid, CONTACT, seal(json.dumps({"turn": TURN}).encode())
            ).encode(),
        )
        if self.call_reply == "offer":
            offer: dict[str, Any] = {
                "sdp_info": base64.b64encode(DEVICE_INFO.encode()).decode(),
                "turn": TURN,
                "srflx": "203.0.113.5:2813",
                "port": 5062,
            }
            if self.request_id is not None:
                offer["request_id"] = self.request_id
            reply(
                Header(**{**_fields(header.response(200)), "encrypted": True}),
                CallBody(
                    call.channel, call.uuid, CONTACT, seal(json.dumps(offer).encode())
                ).encode(),
            )

    def device_message(self, addr: tuple[str, int], packet_id: int = 77, flags: int = 0) -> None:
        header = Header(
            message_type=MessageType.MESSAGE,
            packet_id=packet_id,
            serial=SYNTHETIC.station_sn,
            encrypted=True,
            body_type=BodyType.MESSAGE,
            counter=4,
            route=1,
            sender=0,
            flags=flags,
        )
        self.send(header, MessageBody(0, 2, 0x66, CONTACT, seal(b'{"to": "app"}')).encode(), addr)

    def device_packet(
        self,
        mtype: MessageType,
        call: CallBody,
        payload: dict[str, Any] | None,
        addr: tuple[str, int],
    ) -> None:
        header = Header(
            message_type=mtype,
            packet_id=99,
            serial=SYNTHETIC.station_sn,
            encrypted=payload is not None,
            body_type=BodyType.CALL,
            counter=5,
            route=2,
            sender=0,
        )
        attach = seal(json.dumps(payload).encode()) if payload is not None else b""
        self.send(header, CallBody(call.channel, call.uuid, CONTACT, attach).encode(), addr)


def _fields(header: Header) -> dict[str, Any]:
    return {name: getattr(header, name) for name in Header.__dataclass_fields__}


#: Servers started by the running test; the package's conftest closes them.
SERVERS: list[FakeServer] = []


async def start_server(**kwargs: Any) -> tuple[FakeServer, int]:
    loop = asyncio.get_running_loop()
    server = FakeServer(**kwargs)
    transport, _ = await loop.create_datagram_endpoint(lambda: server, local_addr=("127.0.0.1", 0))
    server.tcp = await asyncio.start_server(server._tcp_client, "127.0.0.1", 0)
    server.tcp_port = server.tcp.sockets[0].getsockname()[1]
    SERVERS.append(server)
    return server, transport.get_extra_info("sockname")[1]


# ── a station behind the data channel and the media plane ────────────────────

#: The key the fake station seals with (the device answer's content key).
STATION_KEY = DEVICE_INFO.content_key.encode()[:16]


def sealed_notification(plain: bytes) -> bytes:
    """A notification as the station sends it: header, then ``tag | iv | ct``."""
    reply = encrypt_command(STATION_KEY, encode_frame(0x0546, plain, bytes(6)), 0)
    return reply[:HEADER_LEN] + reply[HEADER_LEN : HEADER_LEN + 28] + reply[HEADER_LEN + 32 :]


class PipeIce:
    """In-memory ICE transport with a safe diagnostics() accessor (type counts only)."""

    def __init__(self, *, send_q: asyncio.Queue[bytes], recv_q: asyncio.Queue[bytes]) -> None:
        self._send_q = send_q
        self._recv_q = recv_q
        self.closed = False

    def diagnostics(self) -> dict[str, object]:
        return {
            "gathered": True,
            "controlling": False,
            "local_candidate_types": {"host": 1},
            "remote_candidate_types": {"host": 1, "srflx": 1},
            "selected_pair_types": {"local": "host", "remote": "srflx"},
            "turn_configured": True,
        }

    async def gather(self, *, local_ufrag: str, local_pwd: str, turn: Any) -> list[str]:
        return ["candidate:1 1 udp 1 192.0.2.7 5 typ host"]

    def add_remote_candidate(self, candidate: str) -> None:
        return None

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        return None

    async def recv(self) -> bytes:
        return await self._recv_q.get()

    async def send(self, data: bytes) -> None:
        self._send_q.put_nowait(data)

    async def close(self) -> None:
        self.closed = True


class StationMedia:
    """A media plane whose video starts once the station got a live open on the data
    channel (``video_on_data``) or on RTCP. ``packets_only``: packets arrive, but no
    frame is ever decoded."""

    instance: StationMedia | None = None
    video_on_data = True
    packets_only = False

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.commands: list[bytes] = []
        StationMedia.instance = self

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        return None

    def add_remote_candidate(self, candidate: str) -> None:
        return None

    async def frames(self) -> AsyncIterator[AccessUnit]:
        yield AccessUnit(b"", 0, False)

    async def send_command(self, data: bytes) -> None:
        self.commands.append(data)
        self.started.set()

    async def recv_command(self) -> bytes:
        await asyncio.Event().wait()
        return b""

    async def wait_packets(self) -> None:
        await self.started.wait()

    async def wait_media(self) -> None:
        if StationMedia.packets_only:
            await asyncio.Event().wait()
        await self.started.wait()

    def stats(self) -> dict[str, object]:
        return {"frames": 5, "rtp_by_payload_type": {97: 40}}

    async def close(self) -> None:
        return None


#: The JSON of every command the fake station received.
QUERIES: list[dict[str, Any]] = []


async def station_responder(device: KcpDataChannel) -> None:
    """The station: echo the heartbeat (and send one of its own), answer each 1350
    command with a sealed reply and a notification, and start video on a live open over
    the data channel."""
    while True:
        msg = await device.recv_message()
        if len(msg.payload) <= HEADER_LEN:
            await device.send_message(encode_frame(0x0473, b"", bytes(6)))
            await device.send_message(bytes(16), msg_type=DataMsgType.HEARTBEAT)
            continue
        plain = decrypt_command_reply(STATION_KEY, msg.payload[HEADER_LEN:])
        if b'"cmd":1003' in plain:
            if StationMedia.video_on_data and StationMedia.instance is not None:
                StationMedia.instance.started.set()
            continue
        QUERIES.append(json.loads(plain))
        reply = encode_frame(0x0546, b'{"code":0,"payload":{"num":2}}', bytes(6))
        await device.send_message(encrypt_command(STATION_KEY, reply, 0))
        await device.send_message(sealed_notification(b'{"cmd":1224,"mode":1}'), msg_type=3)


#: Responder tasks and their device channels; the package's conftest stops them.
STATIONS: list[tuple[asyncio.Future[None], KcpDataChannel]] = []


def station_ice() -> PipeIce:
    """The client end of an in-memory data channel to a running :func:`station_responder`."""
    c2d: asyncio.Queue[bytes] = asyncio.Queue()
    d2c: asyncio.Queue[bytes] = asyncio.Queue()
    device = KcpDataChannel(PipeIce(send_q=d2c, recv_q=c2d), conv=1)
    STATIONS.append((asyncio.ensure_future(station_responder(device)), device))
    return PipeIce(send_q=c2d, recv_q=d2c)


async def stop_stations() -> None:
    while STATIONS:
        task, device = STATIONS.pop()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await device.close()


__all__ = ["CONTACT", "ResponseCode"]
