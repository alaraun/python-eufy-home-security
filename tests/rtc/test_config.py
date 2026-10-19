"""``rtc/config.py`` and ``rtc/sdp.py``."""

from __future__ import annotations

import random
import string

import pytest

from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.rtc.config import (
    RtcConfig,
    firmware_number,
    signaling_domain,
    signaling_ipv4,
)
from eufy_home_security.rtc.sdp import (
    CONTENT_IV_LEN,
    CONTENT_KEY_LEN,
    ICE_PWD_LEN,
    ICE_UFRAG_LEN,
    CompactOffer,
    SdpInfo,
    answer_attributes,
    expand_offer,
)
from eufy_home_security.testing import SYNTHETIC

SERVERS = ["https://webrtc-signal-eu.example.com", "https://198.51.100.20"]


def _raw(**extra: object) -> dict[str, object]:
    return {
        "device_sn": SYNTHETIC.station_sn,
        "p2p_did": SYNTHETIC.did,
        "p2p_license": "ABCDEF",
        "signaling_servers": SERVERS,
        "main_sw_version": "4.1.2.3",
        "webrtc_sdk_version": "6.1.3",
        **extra,
    }


def test_the_signaling_host_is_the_first_bare_ipv4() -> None:
    assert signaling_ipv4(SERVERS) == "198.51.100.20"
    assert signaling_domain(SERVERS) == "webrtc-signal-eu.example.com"
    assert signaling_ipv4(["https://example.com", 5, "http://203.0.113.4/path"]) == "203.0.113.4"
    assert signaling_ipv4(["example.com"]) is None


def test_config_from_a_device_list_entry() -> None:
    cfg = RtcConfig.from_device(_raw(), user_id="u", app_id="a")
    assert cfg is not None
    assert cfg.signaling_host == "198.51.100.20"
    assert cfg.firmware == 4123
    assert cfg.sdk_version == "6.1.3"
    assert cfg.identity == f"{SYNTHETIC.did}:ABCDEF".encode()


@pytest.mark.parametrize("missing", ["p2p_license", "p2p_did", "device_sn", "signaling_servers"])
def test_an_entry_missing_an_input_has_no_config(missing: str) -> None:
    raw = _raw()
    del raw[missing]
    assert RtcConfig.from_device(raw, user_id="u", app_id="a") is None


def test_firmware_number() -> None:
    assert firmware_number("3.8.7.4") == 3874
    assert firmware_number("3.8.7.4h") is None
    assert firmware_number(None) is None


def test_sdp_info_generates_ice_credentials_and_keeps_the_secrets() -> None:
    info = SdpInfo.generate(
        content_key="k" * 16, content_iv="i" * 12, data_channel=True, rng=random.Random(1)
    )
    # The app's WebrtcApp_SetCallSdp: ufrag 5 chars, pwd 23, from the ice-char set.
    assert len(info.ice_ufrag) == ICE_UFRAG_LEN
    assert len(info.ice_pwd) == ICE_PWD_LEN
    ice_chars = set(string.ascii_letters + string.digits + "+/")
    assert set(info.ice_ufrag) <= ice_chars
    assert set(info.ice_pwd) <= ice_chars
    assert (info.content_key, info.content_iv, info.data_channel) == ("k" * 16, "i" * 12, True)
    assert "k" * 16 not in repr(info)


def test_sdp_info_field_lengths_match_the_app() -> None:
    # WebrtcApp_SetCallSdp @0x233ef4: ufrag 5, pwd 23, content key 16, iv 12.
    assert (ICE_UFRAG_LEN, ICE_PWD_LEN, CONTENT_KEY_LEN, CONTENT_IV_LEN) == (5, 23, 16, 12)


def test_sdp_info_layout_and_offer_template_are_not_known() -> None:
    with pytest.raises(UnsupportedError):
        SdpInfo.generate("k", "i").encode()
    with pytest.raises(UnsupportedError):
        expand_offer(CompactOffer.from_json({}))


def test_compact_offer_fields() -> None:
    offer = CompactOffer.from_json({"ice-u": "u", "ice-p": "p", "asc": 5, "vsc": "6", "sg": 1})
    assert (offer.ice_ufrag, offer.ice_pwd, offer.audio_ssrc, offer.video_ssrc) == ("u", "p", 5, 6)
    assert offer.fields["sg"] == 1
    assert CompactOffer.from_json({"asc": "x"}).audio_ssrc is None


def test_the_answer_keeps_ice_credentials_and_ssrc_lines() -> None:
    sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 97\r\na=ice-ufrag:abc\r\na=ice-pwd:def\r\na=ssrc:1 cname:x\r\na=rtcp-mux\r\n"
    assert answer_attributes(sdp) == "a=ice-ufrag:abc\r\na=ice-pwd:def\r\na=ssrc:1 cname:x\r\n"
