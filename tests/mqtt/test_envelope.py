"""The MQTT envelope: topics, the request the client publishes, the messages it receives."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.mqtt.envelope import (
    CMD_DOWNLINK_TRANS,
    CMD_STATUS_REQUEST,
    CMD_STATUS_REQUEST_NO_ACK,
    CMD_UPLINK_TRANS,
    HEAD_VERSION,
    MessageSequence,
    MqttHead,
    build_request,
    parse_message,
    request_topic,
    response_topic,
    serial_of_topic,
)
from eufy_home_security.testing import SYNTHETIC

_SN = "T85D0P2000054321"
_CLIENT = f"android-eufy_security-{SYNTHETIC.account_id}-0011223344556677"


def test_topics_name_the_category_the_product_and_the_serial() -> None:
    assert request_topic("T85D0", _SN) == f"cmd/eufy_security/T85D0/{_SN}/req"
    assert response_topic("T85D0", _SN) == f"cmd/eufy_security/T85D0/{_SN}/res"


@pytest.mark.parametrize(
    ("topic", "serial"),
    [
        (f"cmd/eufy_security/T85D0/{_SN}/res", _SN),
        (f"cmd/eufy_security/T85D0/{_SN}", None),
        (f"cmd/eufy_security/T85D0/{_SN}/res/extra", None),
        ("cmd/eufy_security/T85D0//res", None),
    ],
)
def test_the_serial_is_the_fourth_of_five_levels(topic: str, serial: str | None) -> None:
    assert serial_of_topic(topic) == serial


def test_a_request_is_the_apps_head_and_payload_json() -> None:
    head, data = build_request(
        client_id=_CLIENT,
        account_id=SYNTHETIC.account_id,
        device_sn=_SN,
        trans="opaque-trans",
        msg_seq=7,
        sess_id="a1b2",
        seed="00" * 16,
        timestamp=1_700_000_000,
    )
    text = data.decode()
    assert " " not in text  # compact, as the app's JSON writer
    body = json.loads(text)
    assert list(body) == ["head", "payload"]
    assert list(body["head"]) == [
        "version",
        "client_id",
        "sess_id",
        "msg_seq",
        "seed",
        "timestamp",
        "cmd_status",
        "cmd",
        "sign_code",
    ]
    assert body["head"] == {
        "version": HEAD_VERSION,
        "client_id": _CLIENT,
        "sess_id": "a1b2",
        "msg_seq": 7,
        "seed": "00" * 16,
        "timestamp": 1_700_000_000,
        "cmd_status": CMD_STATUS_REQUEST_NO_ACK,
        "cmd": CMD_DOWNLINK_TRANS,
        "sign_code": 0,
    }
    assert (HEAD_VERSION, CMD_DOWNLINK_TRANS, CMD_STATUS_REQUEST_NO_ACK) == ("1.0.0.1", 9, 2)
    assert isinstance(body["payload"], str)
    payload = json.loads(body["payload"])
    assert list(payload) == ["account_id", "device_sn", "trans", "data", "update_data", "method"]
    assert payload == {
        "account_id": SYNTHETIC.account_id,
        "device_sn": _SN,
        "trans": "opaque-trans",
        "data": "",
        "update_data": "",
        "method": "",
    }
    assert head == MqttHead.from_json(body["head"])


def test_the_generated_head_fields_take_the_apps_shapes() -> None:
    head, _data = build_request(
        client_id=_CLIENT, account_id="", device_sn=_SN, trans="", msg_seq=1, need_ack=True
    )
    assert re.fullmatch(r"[0-9a-f]{4}", head.sess_id)
    assert re.fullmatch(r"[0-9a-f]{32}", head.seed)
    assert head.timestamp > 1_700_000_000
    assert head.cmd_status == CMD_STATUS_REQUEST == 1
    other, _ = build_request(client_id=_CLIENT, account_id="", device_sn=_SN, trans="", msg_seq=2)
    assert (other.sess_id, other.seed) != (head.sess_id, head.seed)


def test_the_command_carries_the_business_type_in_its_high_half() -> None:
    head, _ = build_request(
        client_id=_CLIENT,
        account_id="",
        device_sn=_SN,
        trans="",
        msg_seq=1,
        cmd_code=2,
        business_type=1,
    )
    assert head.cmd == (1 << 16) | 2
    assert (head.business_type, head.cmd_code) == (1, 2)


def test_the_message_sequence_counts_from_one() -> None:
    sequence = MessageSequence()
    assert [sequence.next() for _ in range(3)] == [1, 2, 3]


def _answer(head: dict[str, Any], payload: Any) -> bytes:
    return json.dumps({"head": head, "payload": payload}).encode()


def test_an_answer_parses_into_its_device_head_and_payload() -> None:
    topic = response_topic("T85D0", _SN)
    payload = json.dumps({"account_id": "x", "device_sn": _SN, "trans": "abc"})
    head = {"client_id": "lock", "msg_seq": "12", "cmd": CMD_UPLINK_TRANS, "cmd_status": 2}
    message = parse_message(topic, _answer({**head, "unknown": 1}, payload))
    assert message.device_sn == _SN
    assert message.topic == topic
    assert message.head.cmd == CMD_UPLINK_TRANS == 8
    assert message.head.msg_seq == 12  # a quoted number reads, as the app's lenient JSON
    assert message.head.version == HEAD_VERSION  # missing fields take their defaults
    assert message.payload == {"account_id": "x", "device_sn": _SN, "trans": "abc"}
    assert message.trans == "abc"


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '"text"'])
def test_a_payload_that_is_no_json_object_is_kept_raw(payload: str) -> None:
    message = parse_message(response_topic("T85D0", _SN), _answer({"cmd": 8}, payload))
    assert message.payload is None
    assert message.raw_payload == payload
    assert message.trans is None


@pytest.mark.parametrize(
    ("topic", "data"),
    [
        (f"cmd/eufy_security/T85D0/{_SN}/res", b"\xff"),
        (f"cmd/eufy_security/T85D0/{_SN}/res", b"[]"),
        (f"cmd/eufy_security/T85D0/{_SN}/res", b'{"payload": ""}'),
        (f"cmd/eufy_security/T85D0/{_SN}/res", b'{"head": {"cmd": "x"}, "payload": ""}'),
        (f"cmd/eufy_security/T85D0/{_SN}/res", b'{"head": {"msg_seq": true}, "payload": ""}'),
        ("not/a/topic", b'{"head": {}, "payload": ""}'),
    ],
)
def test_a_malformed_message_is_a_protocol_error(topic: str, data: bytes) -> None:
    with pytest.raises(ProtocolError):
        parse_message(topic, data)
