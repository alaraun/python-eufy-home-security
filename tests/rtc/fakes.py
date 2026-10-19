"""A fake RTC signaling server and a reversible stand-in for the signaling crypto."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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
from eufy_home_security.rtc.config import RtcConfig
from eufy_home_security.testing import SYNTHETIC

PUBLIC_KEY = "fake-public-key"
SESSION_KEY = "s" * 16
CONTACT = "c" * 32
LICENSE = "ABCDEF"
USER_ID = "u" * 40
APP_ID = "0123456789abcdef"


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

    def new_media_secret(self) -> str:
        return "m" * 16


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


@dataclass
class FakeServer(asyncio.DatagramProtocol):
    """Answers DISCOVER and LOGIN as eufy's server does; CALL per ``call_reply``."""

    received: list[Received] = field(default_factory=list)
    call_reply: str = "offer"
    """``offer`` (100 then 200), ``trying`` (100 only), ``busy`` (486), ``silent``."""
    refuse_login: bool = False
    transport: asyncio.DatagramTransport | None = None
    on_packet: Callable[[Received], None] | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def kinds(self) -> list[int]:
        return [r.header.message_type for r in self.received]

    def send(self, header: Header, body: bytes, addr: tuple[str, int]) -> None:
        assert self.transport is not None
        self.transport.sendto(codec.obfuscate(codec.encode_packet(header, body)), addr)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        header, body = codec.decode_packet(codec.deobfuscate(data))
        item = Received(header, body, addr)
        self.received.append(item)
        if self.on_packet is not None:
            self.on_packet(item)
        if header.is_response:
            return
        mtype = header.message_type
        if mtype == MessageType.DISCOVER:
            answer = {"server_addr": "self", "timestamp": 1, "saddrs": []}
            self.send(
                header.response(200, body_type=BodyType.JSON), json.dumps(answer).encode(), addr
            )
        elif mtype == MessageType.LOGIN:
            self._login(header, body, addr)
        elif mtype == MessageType.CALL:
            self._call(header, body, addr)

    def _login(self, header: Header, body: bytes, addr: tuple[str, int]) -> None:
        if header.body_type == BodyType.KEY_EXCHANGE:
            exchange = KeyExchangeBody.decode(body)
            assert exchange.sealed_key.rstrip(b"\0") == f"K:{PUBLIC_KEY}:{SESSION_KEY}".encode()
            identity = FakeCrypto().open(SESSION_KEY, 0, exchange.sealed_identity)
            if self.refuse_login or identity != f"{SYNTHETIC.did}:{LICENSE}".encode():
                self.send(
                    header.response(401, body_type=BodyType.DEFAULT_KEY_BLOB),
                    PUBLIC_KEY.encode(),
                    addr,
                )
                return
            reply = header.response(200, body_type=BodyType.CONTACT)
            self.send(
                Header(**{**_fields(reply), "sub_id": 9}), ContactBody(CONTACT).encode(), addr
            )
            return
        if header.body_type == BodyType.CONTACT:
            contact = ContactBody.decode(body)
            if contact.contact_id == CONTACT:
                self.send(
                    header.response(200, body_type=BodyType.CONTACT),
                    ContactBody(CONTACT).encode(),
                    addr,
                )
                return
        self.send(
            header.response(401, body_type=BodyType.DEFAULT_KEY_BLOB), PUBLIC_KEY.encode(), addr
        )

    def _call(self, header: Header, body: bytes, addr: tuple[str, int]) -> None:
        call = CallBody.decode(body)
        if self.call_reply == "silent":
            return
        if self.call_reply == "busy":
            self.send(header.response(486), call.without_attachment().encode(), addr)
            return
        turn = {"turn": {"addr": "198.51.100.9", "port": 3478, "user": "u", "password": "p"}}
        self.send(
            Header(**{**_fields(header.response(100)), "encrypted": True}),
            CallBody(call.channel, call.uuid, CONTACT, seal(json.dumps(turn).encode())).encode(),
            addr,
        )
        if self.call_reply == "offer":
            offer = {
                "sdp": {"ice-u": "dev", "ice-p": "pwd", "asc": 1, "vsc": "2"},
                "request_id": "r1",
            }
            self.send(
                Header(**{**_fields(header.response(200)), "encrypted": True}),
                CallBody(
                    call.channel, call.uuid, CONTACT, seal(json.dumps(offer).encode())
                ).encode(),
                addr,
            )

    def device_message(self, addr: tuple[str, int], packet_id: int = 77) -> None:
        header = Header(
            message_type=MessageType.MESSAGE,
            packet_id=packet_id,
            serial=SYNTHETIC.station_sn,
            encrypted=True,
            body_type=BodyType.MESSAGE,
            counter=4,
            route=1,
            sender=0,
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
    SERVERS.append(server)
    return server, transport.get_extra_info("sockname")[1]


__all__ = ["CONTACT", "ResponseCode"]
