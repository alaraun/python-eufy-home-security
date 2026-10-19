"""``rtc/config.py`` and ``rtc/sdp.py``."""

from __future__ import annotations

import random

import pytest

from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.rtc.config import (
    RtcConfig,
    firmware_number,
    signaling_domain,
    signaling_ipv4,
)
from eufy_home_security.rtc.sdp import (
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
    info = SdpInfo.generate("k" * 16, "i" * 16, data_channel=True, rng=random.Random(1))
    assert len(info.ice_ufrag) == len(info.ice_pwd) == 64
    assert info.ice_ufrag.isalnum()
    assert (info.content_key, info.data_channel) == ("k" * 16, True)
    assert "k" * 16 not in repr(info)


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
