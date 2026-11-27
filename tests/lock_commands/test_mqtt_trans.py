"""The MQTT form of a lock command: the P2P payload object as base64 ``trans`` text."""

from __future__ import annotations

import base64
import json

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.lock_commands import mqtt_trans
from tests.json_depth import past_the_bound


def test_trans_is_base64_of_the_apps_payload_info_json() -> None:
    payload = {"apiCommand": 6018, "lock_payload": "ff09", "seq_num": 7, "time": 1700000037}
    trans = mqtt_trans.encode_trans(1940, payload)
    assert json.loads(base64.b64decode(trans)) == {
        "cmd": 1940,
        "mChannel": 0,
        "mValue3": 0,
        "payload": payload,
    }
    text = base64.b64decode(trans).decode()
    assert text.startswith('{"cmd":1940,"mChannel":0,"mValue3":0,"payload":{"apiCommand"')


def test_trans_round_trips() -> None:
    payload = {"dev_sn": "T85D0P2000000001", "lock_payload": "ff", "time": "6553f101"}
    assert mqtt_trans.decode_trans(mqtt_trans.encode_trans(1940, payload)) == (1940, payload)


def test_decode_accepts_wrapped_and_unpadded_base64() -> None:
    text = base64.b64encode(json.dumps({"cmd": 1940, "payload": {"a": 1}}).encode()).decode()
    wrapped = text[:10] + "\n" + text[10:].rstrip("=")
    assert mqtt_trans.decode_trans(wrapped) == (1940, {"a": 1})


@pytest.mark.parametrize(
    "trans",
    [
        "%%%",
        base64.b64encode(b"not json").decode(),
        base64.b64encode(b"[1, 2]").decode(),
        base64.b64encode(b'{"cmd": "x", "payload": {}}').decode(),
        base64.b64encode(b'{"cmd": 1940, "payload": "text"}').decode(),
        base64.b64encode(b'{"payload": {}}').decode(),
        pytest.param(
            base64.b64encode(past_the_bound({"cmd": 1940, "payload": {}}).encode()).decode(),
            id="deep",
        ),
    ],
)
def test_decode_refuses_what_is_no_payload_object(trans: str) -> None:
    with pytest.raises(ProtocolError):
        mqtt_trans.decode_trans(trans)
