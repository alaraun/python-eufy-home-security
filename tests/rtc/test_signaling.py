"""``rtc/signaling.py``: the JSON the client sends and how call packets are read."""

from __future__ import annotations

import base64
import itertools
import json
import random

import pytest

from eufy_home_security.rtc import signaling
from eufy_home_security.rtc.codec import CallKind, Header, MessageType
from eufy_home_security.rtc.config import RtcConfig
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.rtc.signaling import CallEventKind
from eufy_home_security.testing import SYNTHETIC

USER_ID = "user-0001"
APP_ID = "app-0001"
CONTACT = "c" * 32
NOW = 1_789_000_000
SDP = SdpInfo(
    audio_ssrc=1, video_ssrc=2, ice_ufrag="u", ice_pwd="p", content_key="k", content_iv="i"
)


def config() -> RtcConfig:
    return RtcConfig(
        station_sn=SYNTHETIC.station_sn,
        p2p_did=SYNTHETIC.did,
        p2p_license="ABCDEF",
        signaling_host="198.51.100.20",
        user_id=USER_ID,
        app_id=APP_ID,
    )


def test_a_plain_call_carries_the_account_hash_and_no_token() -> None:
    value = signaling.call_attachment(
        config(), CallKind.CHANNEL_P2P, channel=2, contact_id=CONTACT, now=NOW
    )
    assert value == {
        "account": signaling.md5_hex(f"2{USER_ID}{NOW}"),
        "ftv": 20,
        "call_type": "call",
        "eufy_p2p_type": "channel_p2p",
        "to": "device",
        "eufy_from_contact": CONTACT,
        "eufy_video_format": 0,
        "eufy_network_type": 1,
        "eufy_app_id": APP_ID,
    }


def test_a_command_call_has_no_p2p_type() -> None:
    value = signaling.call_attachment(
        config(), CallKind.COMMAND, channel=0, contact_id=CONTACT, now=NOW, video_format=3
    )
    assert (value["call_type"], value["eufy_video_format"]) == ("cmd", 3)
    assert "eufy_p2p_type" not in value


def test_a_private_call_carries_token_sdp_info_and_boot_action() -> None:
    value = signaling.call_attachment(
        config(),
        CallKind.PRIV_MEDIA,
        channel=1,
        contact_id=CONTACT,
        now=NOW,
        token=b"sealed",
        sdp_info=SDP,
        boot_action=2,
    )
    assert (value["call_type"], value["eufy_p2p_type"]) == ("scall", "priv_p2p")
    assert base64.b64decode(value["token"]) == b"sealed"
    assert SdpInfo.decode(base64.b64decode(value["sdp_info"])) == SDP
    assert value["boot_action"] == 2


def test_a_private_call_without_boot_action_leaves_it_out() -> None:
    value = signaling.call_attachment(
        config(), CallKind.PRIV1, channel=0, contact_id=CONTACT, now=NOW, token=b"t", sdp_info=SDP
    )
    assert value["eufy_p2p_type"] == "priv1"
    assert "boot_action" not in value


@pytest.mark.parametrize(("token", "sdp"), [(None, SDP), (b"t", None)])
def test_a_private_call_needs_token_and_sdp_info(token: bytes | None, sdp: SdpInfo | None) -> None:
    with pytest.raises(ValueError, match="needs a token and sdp_info"):
        signaling.call_attachment(
            config(),
            CallKind.PRIV_MEDIA,
            channel=0,
            contact_id=CONTACT,
            now=NOW,
            token=token,
            sdp_info=sdp,
        )


def test_a_plain_call_ignores_token_and_sdp_info() -> None:
    value = signaling.call_attachment(
        config(), CallKind.FILE, channel=0, contact_id=CONTACT, now=NOW, token=b"t", sdp_info=SDP
    )
    assert "token" not in value
    assert "sdp_info" not in value


def test_the_ping_wraps_the_contact_in_base64_json() -> None:
    value = signaling.ping_message(config(), contact_id=CONTACT, dynamic_id=77, now=NOW)
    assert value["to"] == "device"
    assert value["account"] == signaling.md5_hex(f"0{USER_ID}{NOW}")
    assert value["eufy_client_dynamic_id"] == 77
    assert json.loads(base64.b64decode(value["content"])) == {
        "eufy_contact_id": CONTACT,
        "eufy_network_type": 1,
        "eufy_app_id": APP_ID,
    }


def test_a_message_answer_carries_only_the_dynamic_id() -> None:
    assert signaling.message_answer(5) == {
        "to": "device",
        "eufy_client_dynamic_id": 5,
        "account": "",
        "content": "",
        "eufy_network_type": 1,
    }


@pytest.mark.parametrize(
    ("request_id", "expected"),
    [
        ("r1", {"request_id": "r1", "candidate": "c"}),
        (0, {"request_id": 0, "candidate": "c"}),
        (None, {"candidate": "c"}),
        ("", {"candidate": "c"}),
    ],
)
def test_info_leads_with_the_device_request_id(
    request_id: object, expected: dict[str, object]
) -> None:
    value = signaling.info_payload(request_id, {"candidate": "c"})
    assert value == expected
    assert list(value) == list(expected)


def test_private_call_uuid_is_36_characters() -> None:
    uuid = signaling.private_call_uuid(config(), CallKind.PRIV_MEDIA, 123)
    digest = signaling.md5_hex(f"{SYNTHETIC.station_sn}{APP_ID}{SYNTHETIC.did}ABCDEF1236")
    assert uuid == "FF006" + digest[:31]
    assert len(uuid) == 36


def test_md5_hex_is_lower_case_hex() -> None:
    assert signaling.md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e"


def test_login_waits_grow_threefold_up_to_270_s() -> None:
    seen_first = set()
    for seed in range(40):
        delays = signaling.login_retry_delays(random.Random(seed))
        assert len(delays) == signaling.LOGIN_ATTEMPTS
        assert 11 <= delays[0] <= 20
        seen_first.add(delays[0])
        for before, after in itertools.pairwise(delays):
            assert after == min(before * 3, 270)
    assert {11, 20} <= seen_first
    assert signaling.login_retry_delays(random.Random(0))[-1] == 270


def _header(mtype: MessageType, code: int = 0, *, response: bool = False) -> Header:
    return Header(
        message_type=mtype,
        packet_id=1,
        serial=SYNTHETIC.station_sn,
        code=code,
        is_response=response,
    )


@pytest.mark.parametrize(
    ("header", "event"),
    [
        (_header(MessageType.HANGUP), CallEventKind.HANGUP),
        (_header(MessageType.HANGUP, 200, response=True), CallEventKind.HANGUP),
        (_header(MessageType.INFO), CallEventKind.INFO),
        (_header(MessageType.INFO, 200, response=True), CallEventKind.INFO),
        (_header(MessageType.CALL, 100, response=True), CallEventKind.TRYING),
        (_header(MessageType.CALL, 200, response=True), CallEventKind.OFFER),
        (_header(MessageType.CALL, 486, response=True), CallEventKind.REFUSED),
        (_header(MessageType.CALL, 480, response=True), CallEventKind.REFUSED),
        (_header(MessageType.CALL), CallEventKind.INFO),
    ],
)
def test_a_call_packet_maps_to_its_event(header: Header, event: CallEventKind) -> None:
    assert signaling.call_event(header) is event
