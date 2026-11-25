"""The eufy security MQTT envelope (declared, eufy app; see docs/protocol/mqtt.md).

Topics are ``cmd/eufy_security/<product code>/<serial>/req`` (the client publishes) and
``…/res`` (the device publishes, the client subscribes). Every message body is the JSON object
``{"head": {...}, "payload": "<JSON text>"}``; the payload of a request is
``{account_id, device_sn, trans, data, update_data, method}`` (a lock command's only
``{account_id, device_sn, trans}``) with ``trans`` the command
itself, which this module carries as given. Pure: no I/O.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from ..exceptions import ProtocolError

TOPIC_CATEGORY: Final = "eufy_security"
"""The category level of every security device's topics."""
HEAD_VERSION: Final = "1.0.0.1"
CMD_UPLINK_TRANS: Final = 8
"""``head.cmd`` of a device's message to the client."""
CMD_DOWNLINK_TRANS: Final = 9
"""``head.cmd`` of the client's command to a device."""
CMD_STATUS_REQUEST: Final = 1
"""``head.cmd_status`` of a request that asks for an acknowledgement."""
CMD_STATUS_REQUEST_NO_ACK: Final = 2
"""``head.cmd_status`` of a request that asks for none (every lock command)."""
_LEVELS: Final = 5
_SESS_ID_HEX: Final = 4


def request_topic(product_code: str, serial: str) -> str:
    """The topic the client publishes a command for device ``serial`` to."""
    return f"cmd/{TOPIC_CATEGORY}/{product_code}/{serial}/req"


def response_topic(product_code: str, serial: str) -> str:
    """The topic device ``serial`` publishes to, which the client subscribes."""
    return f"cmd/{TOPIC_CATEGORY}/{product_code}/{serial}/res"


def serial_of_topic(topic: str) -> str | None:
    """The serial a topic names (its fourth of five levels); None for another shape."""
    levels = topic.split("/")
    if len(levels) != _LEVELS or not levels[3]:
        return None
    return levels[3]


class MessageSequence:
    """The client's ``msg_seq`` counter: 1, 2, 3 … for the client's lifetime."""

    def __init__(self) -> None:
        self._last = 0

    def next(self) -> int:
        self._last += 1
        return self._last


@dataclass(frozen=True, slots=True, kw_only=True)
class MqttHead:
    """A message's ``head``. ``cmd`` is ``(business type << 16) | command code``."""

    client_id: str
    sess_id: str
    msg_seq: int
    seed: str
    timestamp: int
    cmd_status: int
    cmd: int
    sign_code: int = 0
    version: str = HEAD_VERSION

    @property
    def business_type(self) -> int:
        return self.cmd >> 16

    @property
    def cmd_code(self) -> int:
        return self.cmd & 0xFFFF

    def as_json(self) -> dict[str, Any]:
        """The head as the app writes it, in its field order."""
        return {
            "version": self.version,
            "client_id": self.client_id,
            "sess_id": self.sess_id,
            "msg_seq": self.msg_seq,
            "seed": self.seed,
            "timestamp": self.timestamp,
            "cmd_status": self.cmd_status,
            "cmd": self.cmd,
            "sign_code": self.sign_code,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> MqttHead:
        """Read a head as the app's lenient JSON reader does: unknown keys ignored, quoted
        numbers accepted, a missing field at its default; :class:`ProtocolError` for a field
        of another type."""
        return cls(
            version=_text(data, "version", HEAD_VERSION),
            client_id=_text(data, "client_id", ""),
            sess_id=_text(data, "sess_id", ""),
            msg_seq=_number(data, "msg_seq", 0),
            seed=_text(data, "seed", ""),
            timestamp=_number(data, "timestamp", 0),
            cmd_status=_number(data, "cmd_status", CMD_STATUS_REQUEST),
            cmd=_number(data, "cmd", -1),
            sign_code=_number(data, "sign_code", 0),
        )


def _text(data: Mapping[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ProtocolError(f"MQTT head {key} is not text")
    return value


def _number(data: Mapping[str, Any], key: str, default: int) -> int:
    value = data.get(key, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    raise ProtocolError(f"MQTT head {key} is not a number")


def _compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def build_request(
    *,
    client_id: str,
    account_id: str,
    device_sn: str,
    trans: str,
    msg_seq: int,
    cmd_code: int = CMD_DOWNLINK_TRANS,
    business_type: int = 0,
    need_ack: bool = False,
    sess_id: str | None = None,
    seed: str | None = None,
    timestamp: int | None = None,
    extra_fields: bool = True,
) -> tuple[MqttHead, bytes]:
    """The head and body of a command for ``device_sn``, as the eufy app builds them.

    ``account_id`` is the device owner's user id (the entry's ``member.admin_user_id``, ``""``
    when it names none); ``trans`` is the command, carried as given. ``sess_id`` defaults to 4
    random hex digits, ``seed`` to 32, ``timestamp`` to now (epoch s); ``need_ack`` sets
    ``cmd_status`` 1, else 2. ``extra_fields`` False leaves the empty ``data``,
    ``update_data`` and ``method`` out of the payload, as the app's lock commands send it.
    """
    head = MqttHead(
        client_id=client_id,
        sess_id=secrets.token_hex(_SESS_ID_HEX // 2) if sess_id is None else sess_id,
        msg_seq=msg_seq,
        seed=secrets.token_hex(16) if seed is None else seed,
        timestamp=int(time.time()) if timestamp is None else timestamp,
        cmd_status=CMD_STATUS_REQUEST if need_ack else CMD_STATUS_REQUEST_NO_ACK,
        cmd=(business_type << 16) | cmd_code,
    )
    payload = {"account_id": account_id, "device_sn": device_sn, "trans": trans}
    if extra_fields:
        payload |= {"data": "", "update_data": "", "method": ""}
    body = {"head": head.as_json(), "payload": _compact(payload)}
    return head, _compact(body).encode()


@dataclass(frozen=True, slots=True, kw_only=True)
class MqttMessage:
    """A message a device published: its topic and serial, head and payload."""

    topic: str
    device_sn: str
    head: MqttHead
    raw_payload: str
    """The ``payload`` text as received."""
    payload: Mapping[str, Any] | None
    """``raw_payload`` decoded, when it is a JSON object."""

    @property
    def trans(self) -> str | None:
        """The payload's ``trans`` (the device's answer or report), when it is text."""
        value = None if self.payload is None else self.payload.get("trans")
        return value if isinstance(value, str) else None


def parse_message(topic: str, data: bytes) -> MqttMessage:
    """The message ``data`` received on ``topic``; :class:`ProtocolError` for a topic that
    names no serial, a body that is no ``{head, payload}`` object, or a malformed head."""
    serial = serial_of_topic(topic)
    if serial is None:
        raise ProtocolError(f"MQTT topic of {topic.count('/') + 1} levels names no device")
    try:
        body = json.loads(data)
    except (UnicodeDecodeError, ValueError) as err:
        raise ProtocolError(f"MQTT message is not JSON: {err}") from err
    if not isinstance(body, Mapping) or not isinstance(body.get("head"), Mapping):
        raise ProtocolError("MQTT message has no head")
    raw = body.get("payload", "")
    raw_payload = raw if isinstance(raw, str) else _compact(raw)
    try:
        decoded = json.loads(raw_payload)
    except ValueError:
        decoded = None
    return MqttMessage(
        topic=topic,
        device_sn=serial,
        head=MqttHead.from_json(body["head"]),
        raw_payload=raw_payload,
        payload=decoded if isinstance(decoded, Mapping) else None,
    )
