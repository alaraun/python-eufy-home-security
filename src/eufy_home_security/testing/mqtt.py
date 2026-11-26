"""An MQTT broker and certificate authority for tests of the MQTT transport.

- :func:`make_mqtt_pki`: a throwaway CA, a broker certificate for ``127.0.0.1`` and a client
  certificate, as PEM text, generated per call; nothing is ever read from disk.
- :class:`FakeMqttBroker`: a minimal MQTT 3.1.1 broker on loopback, TLS with a required client
  certificate. It records every CONNECT, SUBSCRIBE and PUBLISH it receives and can send a message
  to its subscribers or drop every connection. It never forwards anything anywhere.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import ipaddress
import json
import ssl
import struct
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..exceptions import ProtocolError
from ..lock_commands import cm2
from ..lock_commands.actions import LockAction, cbc_decrypt, serial_iv
from ..lock_commands.frames import cm2_frame, parse_cm2_frame
from ..lock_commands.mqtt_trans import encode_trans
from ..mqtt.envelope import request_topic, response_topic
from .locks import tlv_entries
from .synthetic import SYNTHETIC

_CONNECT, _CONNACK, _PUBLISH, _PUBACK = 1, 2, 3, 4
_SUBSCRIBE, _SUBACK, _UNSUBSCRIBE, _UNSUBACK = 8, 9, 10, 11
_PINGREQ, _PINGRESP, _DISCONNECT = 12, 13, 14
_SUBSCRIBE_FAILURE = 0x80
LOOPBACK = "127.0.0.1"


@dataclass(frozen=True, slots=True)
class MqttTestPki:
    """PEM text of one throwaway PKI: ``ca`` signs the broker's and the client's certificate."""

    ca_pem: str
    server_cert_pem: str
    server_key_pem: str
    client_cert_pem: str
    client_key_pem: str

    def register_answer(self, **overrides: Any) -> dict[str, Any]:
        """A ``data`` object of the certificate request for this PKI's client certificate,
        with ``endpoint_addr`` on loopback; ``overrides`` replace or add fields."""
        answer: dict[str, Any] = {
            "user_id": SYNTHETIC.account_id,
            "app_name": "eufy_security",
            "thing_name": "synthetic-thing",
            "certificate_id": "0" * 64,
            "certificate_pem": self.client_cert_pem,
            "private_key": self.client_key_pem,
            "public_key": "synthetic-public-key",
            "endpoint_addr": LOOPBACK,
            "origin": "synthetic",
            "amazon_root_ca_1_pem": self.ca_pem,
            "pkcs12": "synthetic-pkcs12",
        }
        return {**answer, **overrides}


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _pem_key(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _issue(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = False,
    server: bool = False,
) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(LOOPBACK))]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def make_mqtt_pki() -> MqttTestPki:
    """A fresh throwaway PKI (EC P-256 keys, one day valid)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = _issue("synthetic test ca", ca_key, _name("synthetic test ca"), ca_key, ca=True)
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = _issue("synthetic broker", server_key, ca_cert.subject, ca_key, server=True)
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_cert = _issue("synthetic thing", client_key, ca_cert.subject, ca_key)

    def pem(cert: x509.Certificate) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    return MqttTestPki(
        ca_pem=pem(ca_cert),
        server_cert_pem=pem(server_cert),
        server_key_pem=_pem_key(server_key),
        client_cert_pem=pem(client_cert),
        client_key_pem=_pem_key(client_key),
    )


@dataclass(frozen=True, slots=True)
class BrokerConnect:
    """One CONNECT the broker accepted."""

    client_id: str
    keepalive: int
    clean_session: bool
    protocol_level: int
    username: str | None
    password: bool
    """Whether the CONNECT carried a password."""
    client_certificate: bool
    """Whether the TLS peer presented a certificate the broker's CA signed."""


@dataclass(frozen=True, slots=True)
class BrokerPublish:
    """One PUBLISH the broker received from a client."""

    client_id: str
    topic: str
    payload: bytes
    qos: int
    retain: bool


@dataclass(slots=True)
class _Connection:
    client_id: str
    writer: asyncio.StreamWriter
    topics: set[str] = field(default_factory=set)
    packet_id: int = 0


class FakeMqttBroker:
    """A minimal MQTT 3.1.1 broker over TLS on loopback for one test.

    Exact topic filters only (no wildcards). ``refused_topics`` are answered with the SUBACK
    failure code; ``connack_code`` other than 0 refuses every CONNECT with that return code.
    ``connack_delay`` holds the CONNACK that many seconds (None: never sends it); a client
    that closes or sends anything before it ends the connection.
    """

    def __init__(self, pki: MqttTestPki) -> None:
        self._pki = pki
        self._server: asyncio.Server | None = None
        self._connections: list[_Connection] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.connects: list[BrokerConnect] = []
        self.subscriptions: list[tuple[str, str, int]] = []
        """(client id, topic filter, requested QoS) of every SUBSCRIBE entry."""
        self.unsubscriptions: list[tuple[str, str]] = []
        self.published: list[BrokerPublish] = []
        self.publish_hooks: list[Callable[[BrokerPublish], None]] = []
        """Called with every PUBLISH the broker receives (a fake device answering it)."""
        self.refused_topics: set[str] = set()
        self.connack_code = 0
        self.connack_delay: float | None = 0.0
        self.publish_acks = True
        """False: a QoS 1 PUBLISH gets no PUBACK (the client's publish keeps waiting)."""
        self.puback_delay = 0.0
        """Seconds a PUBACK is held after its PUBLISH arrived."""
        self.open_sockets = 0
        """TLS connections open now, with or without a CONNACK."""
        self.port = 0
        self._changed = asyncio.Condition()

    async def __aenter__(self) -> FakeMqttBroker:
        await self.async_start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.async_stop()

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cadata=self._pki.ca_pem)
        context.verify_mode = ssl.CERT_REQUIRED
        with tempfile.TemporaryDirectory(prefix="eufy-fake-broker-") as tmp:
            cert = Path(tmp, "cert.pem")
            key = Path(tmp, "key.pem")
            cert.write_text(self._pki.server_cert_pem)
            key.write_text(self._pki.server_key_pem)
            key.chmod(0o600)
            context.load_cert_chain(cert, key)
        return context

    async def async_start(self) -> int:
        """Listen on a free loopback port; returns it."""
        context = await asyncio.to_thread(self._ssl_context)
        self._server = await asyncio.start_server(self._serve, LOOPBACK, 0, ssl=context)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def async_stop(self) -> None:
        """Close every connection, answered or not, and the listener."""
        self.drop_connections()
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    def drop_connections(self) -> None:
        """Close every client connection without a DISCONNECT (a lost connection)."""
        for connection in self._connections:
            connection.writer.transport.abort()
        self._connections.clear()

    @property
    def connected_clients(self) -> list[str]:
        """The client ids connected now."""
        return [c.client_id for c in self._connections]

    async def wait_for(self, predicate: Any, timeout: float = 5.0) -> None:
        """Wait until ``predicate()`` is true (checked on every received packet)."""
        async with asyncio.timeout(timeout), self._changed:
            await self._changed.wait_for(predicate)

    async def send(self, topic: str, payload: bytes, *, qos: int = 0) -> int:
        """PUBLISH ``payload`` to every client subscribed to ``topic``; returns how many."""
        sent = 0
        for connection in list(self._connections):
            if topic not in connection.topics:
                continue
            variable = _string(topic)
            flags = qos << 1
            if qos:
                connection.packet_id = connection.packet_id % 0xFFFF + 1
                variable += struct.pack(">H", connection.packet_id)
            connection.writer.write(_packet(_PUBLISH, flags, variable + payload))
            await connection.writer.drain()
            sent += 1
        return sent

    async def _notify(self) -> None:
        async with self._changed:
            self._changed.notify_all()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self.open_sockets += 1
        connection: _Connection | None = None
        try:
            while True:
                header, body = await _read_packet(reader)
                kind, flags = header >> 4, header & 0x0F
                if kind == _CONNECT:
                    connection = await self._connect(body, reader, writer)
                    if connection is None:
                        break
                elif connection is None:
                    break
                elif kind == _SUBSCRIBE:
                    await self._subscribe(connection, body)
                elif kind == _UNSUBSCRIBE:
                    packet_id = struct.unpack(">H", body[:2])[0]
                    for topic in _strings(body[2:]):
                        connection.topics.discard(topic)
                        self.unsubscriptions.append((connection.client_id, topic))
                    writer.write(_packet(_UNSUBACK, 0, struct.pack(">H", packet_id)))
                elif kind == _PUBLISH:
                    self._publish(connection, flags, body, writer)
                elif kind == _PINGREQ:
                    writer.write(_packet(_PINGRESP, 0, b""))
                elif kind == _DISCONNECT:
                    break
                await writer.drain()
                await self._notify()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            self.open_sockets -= 1
            if connection is not None and connection in self._connections:
                self._connections.remove(connection)
            writer.transport.abort()
            await self._notify()
            if task is not None:
                self._tasks.discard(task)

    async def _connect(
        self, body: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> _Connection | None:
        name_len = struct.unpack(">H", body[:2])[0]
        offset = 2 + name_len
        level, flags = body[offset], body[offset + 1]
        keepalive = struct.unpack(">H", body[offset + 2 : offset + 4])[0]
        fields = _strings(body[offset + 4 :])
        client_id = fields[0]
        rest = fields[1:]
        if flags & 0x04:  # will topic and message
            rest = rest[2:]
        username = rest[0] if flags & 0x80 and rest else None
        peer = writer.get_extra_info("peercert")
        self.connects.append(
            BrokerConnect(
                client_id=client_id,
                keepalive=keepalive,
                clean_session=bool(flags & 0x02),
                protocol_level=level,
                username=username,
                password=bool(flags & 0x40),
                client_certificate=bool(peer),
            )
        )
        if self.connack_delay != 0:
            # Anything the client sends (or its close) before the CONNACK ends the connection.
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self.connack_delay):
                    await reader.read(1)
                    return None
        writer.write(_packet(_CONNACK, 0, bytes([0, self.connack_code])))
        await writer.drain()
        if self.connack_code:
            return None
        connection = _Connection(client_id, writer)
        self._connections.append(connection)
        return connection

    async def _subscribe(self, connection: _Connection, body: bytes) -> None:
        packet_id = struct.unpack(">H", body[:2])[0]
        codes = bytearray()
        offset = 2
        while offset < len(body):
            length = struct.unpack(">H", body[offset : offset + 2])[0]
            topic = body[offset + 2 : offset + 2 + length].decode()
            qos = body[offset + 2 + length]
            offset += 3 + length
            self.subscriptions.append((connection.client_id, topic, qos))
            if topic in self.refused_topics:
                codes.append(_SUBSCRIBE_FAILURE)
            else:
                connection.topics.add(topic)
                codes.append(qos)
        connection.writer.write(_packet(_SUBACK, 0, struct.pack(">H", packet_id) + bytes(codes)))

    def _publish(
        self, connection: _Connection, flags: int, body: bytes, writer: asyncio.StreamWriter
    ) -> None:
        qos = (flags >> 1) & 0x03
        length = struct.unpack(">H", body[:2])[0]
        topic = body[2 : 2 + length].decode()
        offset = 2 + length
        if qos:
            packet_id = body[offset : offset + 2]
            offset += 2
            if self.publish_acks:
                ack = _packet(_PUBACK, 0, packet_id)
                if self.puback_delay:
                    asyncio.get_running_loop().call_later(self.puback_delay, writer.write, ack)
                else:
                    writer.write(ack)
        received = BrokerPublish(
            connection.client_id, topic, body[offset:], qos, bool(flags & 0x01)
        )
        self.published.append(received)
        for hook in list(self.publish_hooks):
            hook(received)


def _string(text: str) -> bytes:
    data = text.encode()
    return struct.pack(">H", len(data)) + data


def _strings(data: bytes) -> list[str]:
    out = []
    offset = 0
    while offset + 2 <= len(data):
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        out.append(data[offset + 2 : offset + 2 + length].decode())
        offset += 2 + length
    return out


def _packet(kind: int, flags: int, body: bytes) -> bytes:
    length = len(body)
    encoded = bytearray()
    while True:
        byte, length = length % 128, length // 128
        encoded.append(byte | (0x80 if length else 0))
        if not length:
            break
    return bytes([kind << 4 | flags]) + bytes(encoded) + body


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = (await reader.readexactly(1))[0]
    length = 0
    shift = 0
    while True:
        byte = (await reader.readexactly(1))[0]
        length |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return header, await reader.readexactly(length)


@dataclass(frozen=True, slots=True)
class _LockCommand:
    """A lock command the fake lock took: its head, key, time value and asked action."""

    head: dict[str, Any]
    key: bytes
    time_value: int
    action: LockAction
    seq_num: int
    entries: dict[int, bytes]


class _NotTheAppsFormError(ValueError):
    """A published message that is not the app's lock command."""


def _compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _expect(condition: bool, reason: str) -> None:
    if not condition:
        raise _NotTheAppsFormError(reason)


@dataclass(slots=True, kw_only=True)
class FakeMqttLock:
    """A Wi-Fi lock on a :class:`FakeMqttBroker`: it answers each lock command published to
    its request topic on its response topic, as a lock is declared to (docs/protocol/
    mqtt.md § Lock commands), then reports its new state in a status report.

    It takes only the eufy app's lock message, byte for byte in its JSON layout: a command
    message (``cmd`` 9, no acknowledgement asked) whose payload is exactly
    ``{"account_id", "device_sn", "trans"}``, ``trans`` the compact JSON
    ``{"cmd":1940,"mChannel":0,"mValue3":0,"payload":{"apiCommand":6018,"lock_payload",
    "seq_num","time"}}`` with a numeric ``time``, and a cm2 frame of version 3, slave id 0,
    function type 2, encrypted, command 0x23. Anything else published to its topic is
    recorded in ``refused`` (with the reason) and not answered.

    ``owner_user_id`` is the user id the commands are keyed by and name (the member record's
    ``admin_user_id`` when the record names the sending account), which the message's
    ``account_id`` must carry too.
    ``users`` records each command's sender entries as decrypted: ``(A2 user id, A5 short
    user id as hex)``; ``names`` its sender name (A4, the account's nickname).
    ``answer_code`` is the lock's answer (0 accepted); an accepted command moves the lock to
    the asked state, or to ``move_to`` (a lock-state code), reported unless ``report`` is
    False; ``answer`` False: the lock sends nothing back. ``mismatch_first`` sends an answer
    to another request first. ``status_code`` is the status report's code (0: a state).
    ``report_first`` sends the status report (of the state the command leaves) before the
    answer, also when ``answer`` is False. Its messages are device messages (``cmd``
    ``answer_cmd``, 8) whose through data names ``answer_dev_sn`` (None: the lock itself;
    ``""``: no ``dev_sn``).
    ``received``
    records each command as decrypted: ``(action, seq_num)``. Call :meth:`attach`.
    :meth:`async_report` sends a status report the lock makes by itself (moved by hand or
    by key).
    """

    broker: FakeMqttBroker
    serial: str
    product_code: str
    owner_user_id: str
    state_code: int = 3
    answer_code: int = 0
    move_to: int | None = None
    report: bool = True
    mismatch_first: bool = False
    answer: bool = True
    status_code: int = 0
    report_first: bool = False
    answer_cmd: int = 8
    answer_dev_sn: str | None = None
    received: list[tuple[LockAction, int]] = field(default_factory=list)
    users: list[tuple[str, str]] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)

    def attach(self) -> None:
        self.broker.publish_hooks.append(self._on_publish)

    async def async_report(self, state_code: int, *, time_value: int = 0x6553F100) -> None:
        """Move the lock to ``state_code`` and send its status report, keyed by
        ``time_value`` (no command asked for it)."""
        self.state_code = state_code
        key = cm2.time_key(self.owner_user_id, time_value)
        report = bytes([0, 0xA1, 1, 90, 0xA2, 1, state_code])
        await self.broker.send(
            response_topic(self.product_code, self.serial),
            self._message(
                {"msg_seq": 0},
                sealed_key=key,
                iv=serial_iv(self.serial),
                command=cm2.STATUS_COMMAND,
                plain=report,
                time_text=f"{time_value:08x}",
            ),
        )

    def _message(
        self,
        head: dict[str, Any],
        *,
        sealed_key: bytes,
        iv: bytes,
        command: int,
        plain: bytes,
        time_text: str,
    ) -> bytes:
        """A device message carrying ``plain`` in a cm2 frame sealed under ``sealed_key``."""
        frame = cm2_frame(
            cm2.seal_body(plain, sealed_key, iv),
            command=command,
            function_type=cm2.FUNCTION_TYPE,
            version=cm2.FRAME_VERSION,
            encrypted=True,
        )
        dev_sn = self.serial if self.answer_dev_sn is None else self.answer_dev_sn
        through = {"dev_sn": dev_sn} if dev_sn else {}
        through |= {"lock_payload": frame.hex(), "time": time_text}
        trans = encode_trans(cm2.P2P_COMMAND, through)
        payload = {"account_id": self.owner_user_id, "device_sn": self.serial, "trans": trans}
        answer_head = {"cmd": self.answer_cmd, "msg_seq": head["msg_seq"] + 1000, "sess_id": "beef"}
        return json.dumps({"head": answer_head, "payload": json.dumps(payload)}).encode()

    def _on_publish(self, published: BrokerPublish) -> None:
        if published.topic != request_topic(self.product_code, self.serial):
            return
        try:
            command = self._read(published.payload)
        except (ProtocolError, ValueError, KeyError, TypeError) as err:
            self.refused.append(str(err) or type(err).__name__)
            return
        self.received.append((command.action, command.seq_num))
        self.users.append((command.entries[0xA2].decode(), command.entries[0xA5].hex()))
        self.names.append(command.entries[0xA4].decode())
        if not self.answer and not self.report_first:
            return
        task = asyncio.get_running_loop().create_task(
            self._answer(
                command.head,
                command.key,
                serial_iv(self.serial),
                command.time_value,
                command.action,
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _read(self, data: bytes) -> _LockCommand:
        """The app's lock command in ``data``; :class:`_NotTheAppsFormError` for anything else."""
        body = json.loads(data)
        head = body["head"]
        _expect((head["cmd"], head["cmd_status"]) == (9, 2), f"head {head}")
        text = body["payload"]
        payload = json.loads(text)
        _expect(
            list(payload) == ["account_id", "device_sn", "trans"], f"payload keys {list(payload)}"
        )
        _expect(text == _compact(payload), "payload is not compact JSON")
        _expect(payload["account_id"] == self.owner_user_id, "account_id is not the key user")
        _expect(payload["device_sn"] == self.serial, "device_sn is not the lock")
        trans_text = base64.b64decode(payload["trans"], validate=True).decode()
        outer = json.loads(trans_text)
        _expect(trans_text == _compact(outer), "trans is not compact JSON")
        _expect(
            list(outer) == ["cmd", "mChannel", "mValue3", "payload"], f"trans keys {list(outer)}"
        )
        _expect((outer["cmd"], outer["mChannel"], outer["mValue3"]) == (1940, 0, 0), "trans head")
        inner = outer["payload"]
        _expect(
            list(inner) == ["apiCommand", "lock_payload", "seq_num", "time"],
            f"payload object keys {list(inner)}",
        )
        _expect(inner["apiCommand"] == 6018, f"apiCommand {inner['apiCommand']}")
        for name in ("seq_num", "time"):
            _expect(type(inner[name]) is int, f"{name} is not a number")
        frame = parse_cm2_frame(bytes.fromhex(inner["lock_payload"]))
        layout = (
            frame.version,
            frame.slave_id,
            frame.function_type,
            frame.encrypted,
            frame.command,
        )
        _expect(layout == (3, 0, 2, True, 0x23), f"cm2 frame {layout}")
        time_value = inner["time"]
        key = cm2.time_key(self.owner_user_id, time_value)
        entries = tlv_entries(cbc_decrypt(frame.body, key, serial_iv(self.serial)))
        _expect(entries[0xA2].decode() == self.owner_user_id, "A2 is not the key user")
        action = LockAction.LOCK if entries[0xA3] == b"\x00" else LockAction.UNLOCK
        return _LockCommand(
            head=head,
            key=key,
            time_value=time_value,
            action=action,
            seq_num=inner["seq_num"],
            entries=entries,
        )

    async def _answer(
        self, head: dict[str, Any], key: bytes, iv: bytes, time_value: int, action: LockAction
    ) -> None:
        topic = response_topic(self.product_code, self.serial)

        def message(sealed_key: bytes, command: int, plain: bytes, time_text: str) -> bytes:
            return self._message(
                head,
                sealed_key=sealed_key,
                iv=iv,
                command=command,
                plain=plain,
                time_text=time_text,
            )

        time_text = f"{time_value:08x}"
        moved = self.answer_code == 0
        if moved:
            self.state_code = (
                self.move_to
                if self.move_to is not None
                else (4 if action is LockAction.LOCK else 3)
            )
        report = bytes([self.status_code, 0xA1, 1, 90, 0xA2, 1, self.state_code])
        status = message(key, cm2.STATUS_COMMAND, report, time_text)
        if self.report and self.report_first:
            await self.broker.send(topic, status)
        if self.answer:
            if self.mismatch_first:
                other = time_value ^ 0x40
                stale = message(
                    cm2.time_key(self.owner_user_id, other), 0x23, b"\x00\x00", f"{other:08x}"
                )
                await self.broker.send(topic, stale)
            answer = message(key, 0x23, bytes([self.answer_code, 0]), time_text)
            await self.broker.send(topic, answer)
        if moved and self.report and not self.report_first:
            await self.broker.send(topic, status)
