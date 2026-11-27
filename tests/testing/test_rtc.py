"""``testing/rtc.py``: the fake WebRTC station's own contract."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from eufy_home_security.rtc import codec
from eufy_home_security.rtc.codec import BodyType, CallBody, Header, MessageBody, MessageType
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.rtc import (
    CONTACT,
    DEVICE_INFO,
    LICENSE,
    FakeRtcServer,
    rtc_config,
    server_key,
)

ADDR = ("127.0.0.1", 40000)


def _packet(message_type: int, body: bytes, **fields: Any) -> bytes:
    header = Header(message_type=message_type, packet_id=1, serial=SYNTHETIC.station_sn, **fields)
    return codec.obfuscate(codec.encode_packet(header, body))


def _call(uuid: str = "") -> bytes:
    return CallBody(0, uuid, CONTACT).encode()


@pytest.mark.parametrize(
    ("packets", "refused"),
    [
        ([(MessageType.CALL, _call(), {"mode": codec.WORK_PROTOCOL, "sub_id": 1})], "CALL mode"),
        ([(MessageType.CALL, _call("u" * 16), {"mode": 0, "sub_id": 1})], "CALL mode"),
        ([(MessageType.INFO, _call(), {"sub_id": 2, "body_type": BodyType.CALL})], "INFO sub_id"),
        (
            [
                (MessageType.CALL, _call("u" * 16), {"mode": codec.WORK_PROTOCOL, "sub_id": 3}),
                (MessageType.HANGUP, _call("u" * 16), {"sub_id": 1, "body_type": BodyType.CALL}),
            ],
            "HANGUP sub_id",
        ),
        ([(MessageType.ACK, _call("v" * 16), {"sub_id": 1})], "ACK sub_id"),
        (
            [
                (
                    MessageType.MESSAGE,
                    MessageBody(0, 2, 0x66, CONTACT).encode(),
                    {"is_response": True},
                )
            ],
            "MESSAGE 200",
        ),
    ],
)
def test_the_fake_refuses_a_header_a_station_does_not_take(
    packets: list[tuple[int, bytes, dict[str, Any]]], refused: str
) -> None:
    fake = FakeRtcServer(call_reply="silent")
    for message_type, body, fields in packets:
        fake.datagram_received(_packet(message_type, body, **fields), ADDR)
    assert [p.split(" ")[0:2] for p in fake.refused] == [refused.split(" ")[0:2]]


def test_the_fake_takes_the_forms_a_station_takes() -> None:
    fake = FakeRtcServer(call_reply="silent")
    uuid = "u" * 16
    fake.datagram_received(
        _packet(MessageType.CALL, _call(uuid), mode=codec.WORK_PROTOCOL, sub_id=3), ADDR
    )
    fake.datagram_received(_packet(MessageType.INFO, _call(uuid), sub_id=1), ADDR)
    fake.datagram_received(_packet(MessageType.ACK, _call(uuid), sub_id=3), ADDR)
    fake.datagram_received(_packet(MessageType.HANGUP, _call(uuid), sub_id=3), ADDR)
    assert fake.refused == []


def test_the_fake_config_uses_synthetic_identities() -> None:
    config = rtc_config()
    assert config.station_sn == SYNTHETIC.station_sn
    assert config.p2p_did == SYNTHETIC.did
    assert config.identity == f"{SYNTHETIC.did}:{LICENSE}".encode()
    assert config.user_id == SYNTHETIC.account_id


def test_the_device_answer_round_trips_through_sdp_info() -> None:
    assert SdpInfo.decode(DEVICE_INFO.encode()) == DEVICE_INFO


def test_the_server_key_is_made_once_and_is_rsa_1024() -> None:
    assert server_key() is server_key()
    assert server_key().key_size == 1024


def test_the_package_and_its_fakes_import_without_aioice() -> None:
    """The core and the rtc modules load without the extra; only ICE needs it."""
    code = (
        "import sys; sys.modules['aioice'] = None\n"
        "import eufy_home_security, eufy_home_security.testing, eufy_home_security.testing.rtc\n"
        "import eufy_home_security.rtc.session, eufy_home_security.rtc.ice\n"
        "from eufy_home_security.exceptions import MissingDependencyError\n"
        "try:\n"
        "    eufy_home_security.rtc.ice.IceTransport()\n"
        "except MissingDependencyError as err:\n"
        "    print(err.extra)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=50, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rtc"


def test_a_refused_packet_is_not_acted_on() -> None:
    fake = FakeRtcServer()  # an accepted CALL would be answered
    fake.datagram_received(_packet(MessageType.CALL, _call(), mode=codec.WORK_PROTOCOL), ADDR)
    assert len(fake.refused) == 1
    assert fake._calls == []
