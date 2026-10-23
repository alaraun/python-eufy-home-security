"""``rtc/config.py`` and ``rtc/sdp.py``."""

from __future__ import annotations

import random
import string

import pytest

from eufy_home_security.cloud.models import CloudDevice, device_cache_entry
from eufy_home_security.exceptions import SignalingError
from eufy_home_security.rtc.config import (
    KCP_TYPE_MULTI,
    KCP_TYPE_SINGLE,
    RtcConfig,
    commands_encrypted,
    data_channel_kcp_type,
    firmware_number,
    missing_inputs,
    signaling_domain,
    signaling_ipv4,
)
from eufy_home_security.rtc.sdp import (
    CONTENT_IV_LEN,
    CONTENT_KEY_LEN,
    ICE_PWD_LEN,
    ICE_UFRAG_LEN,
    SDES_INLINE_KEY,
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
    assert missing_inputs(raw) == (missing,)
    assert RtcConfig.from_device(raw, user_id="u", app_id="a") is None


@pytest.mark.parametrize(
    ("extra", "missing"),
    [
        ({"p2p_license": ""}, ("p2p_license",)),
        ({"p2p_did": 5}, ("p2p_did",)),
        ({"signaling_servers": ["https://webrtc-signal-eu.example.com"]}, ("signaling_servers",)),
        ({"signaling_servers": "https://198.51.100.20"}, ("signaling_servers",)),
        ({"signaling_servers": 5}, ("signaling_servers",)),
        ({"p2p_license": None, "signaling_servers": []}, ("p2p_license", "signaling_servers")),
    ],
)
def test_missing_inputs_names_every_unusable_field(
    extra: dict[str, object], missing: tuple[str, ...]
) -> None:
    raw = _raw(**extra)
    assert missing_inputs(raw) == missing
    assert RtcConfig.from_device(raw, user_id="u", app_id="a") is None
    assert missing_inputs(_raw()) == ()


def test_a_station_entry_read_back_from_the_cache_keeps_its_config() -> None:
    entry = _raw(device_type=18, member={"admin_user_id": "o", "email": "a@b.example"})
    cached = CloudDevice.from_api(device_cache_entry(entry, keep_params=True))
    assert RtcConfig.from_device(cached.raw, user_id="u", app_id="a") == RtcConfig.from_device(
        entry, user_id="u", app_id="a"
    )


def test_firmware_number() -> None:
    assert firmware_number("3.8.7.4") == 3874
    assert firmware_number("3.8.7.4h") is None
    assert firmware_number(None) is None


def test_sdp_info_generates_ice_credentials_and_keeps_the_secrets() -> None:
    info = SdpInfo.generate(
        content_key="k" * 16, content_iv="i" * 12, data_channel=True, rng=random.Random(1)
    )
    # ufrag 5 chars, pwd 23, from the ice-char set.
    assert len(info.ice_ufrag) == ICE_UFRAG_LEN
    assert len(info.ice_pwd) == ICE_PWD_LEN
    ice_chars = set(string.ascii_letters + string.digits + "+/")
    assert set(info.ice_ufrag) <= ice_chars
    assert set(info.ice_pwd) <= ice_chars
    assert (info.content_key, info.content_iv, info.data_channel) == ("k" * 16, "i" * 12, True)
    assert "k" * 16 not in repr(info)


def test_sdp_info_field_lengths_match_the_app() -> None:
    # ufrag 5, pwd 23, content key 16, iv 12.
    assert (ICE_UFRAG_LEN, ICE_PWD_LEN, CONTENT_KEY_LEN, CONTENT_IV_LEN) == (5, 23, 16, 12)


def test_sdp_info_encodes_the_86_byte_layout() -> None:
    info = SdpInfo(
        audio_ssrc=0x11223344,
        video_ssrc=0x55667788,
        ice_ufrag="AbCdE",
        ice_pwd="p" * 23,
        content_key="k" * 16,
        content_iv="i" * 12,
        data_channel=True,
    )
    # reserved(2), data-channel flag + two 1s, device byte, ufrag[8], pwd[24],
    # content key[20], content IV[20], audio SSRC and video SSRC (little-endian u32).
    assert info.encode().hex() == (
        "00000101010041624364450000007070707070707070707070707070707070"
        "707070707070006b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b00000000"
        "69696969696969696969696900000000000000004433221188776655"
    )


def test_sdp_info_flags_and_ssrcs() -> None:
    plain = SdpInfo(
        audio_ssrc=1, video_ssrc=2, ice_ufrag="a", ice_pwd="b", content_key="c", content_iv="d"
    ).encode()
    assert plain[0x02] == 0  # data channel off
    assert (plain[0x03], plain[0x04]) == (1, 1)
    assert plain[0x4E:0x56] == bytes.fromhex("0100000002000000")


def test_sdp_info_rejects_an_oversized_field() -> None:
    bad = SdpInfo(
        audio_ssrc=0,
        video_ssrc=0,
        ice_ufrag="x" * 8,  # 8 leaves no room for the NUL in the 8-byte slot
        ice_pwd="p",
        content_key="k",
        content_iv="i",
    )
    with pytest.raises(SignalingError, match="does not fit"):
        bad.encode()


def test_sdp_info_round_trips_through_encode_decode() -> None:
    info = SdpInfo(
        audio_ssrc=0x11223344,
        video_ssrc=0x55667788,
        ice_ufrag="AbCdE",
        ice_pwd="p" * 23,
        content_key="k" * 16,
        content_iv="i" * 12,
        data_channel=True,
    )
    assert SdpInfo.decode(info.encode()) == info


def test_sdp_info_decode_reads_the_device_answer() -> None:
    # A HomeBase 3 answers the CALL 200 with sdp_info of this same shape (verified):
    # ICE ufrag 5, pwd 23, content key 16, content IV 12, then audio and video SSRC.
    info = SdpInfo.decode(
        SdpInfo(
            audio_ssrc=0xF22E039E,
            video_ssrc=0xB8A23CFA,
            ice_ufrag="dev01",
            ice_pwd="d" * 23,
            content_key="K" * 16,
            content_iv="V" * 12,
        ).encode()
    )
    assert (len(info.content_key), len(info.content_iv)) == (CONTENT_KEY_LEN, CONTENT_IV_LEN)
    assert (info.audio_ssrc, info.video_ssrc) == (0xF22E039E, 0xB8A23CFA)
    assert info.ice_ufrag == "dev01"
    assert info.data_channel is False


def test_sdp_info_decode_rejects_a_short_buffer() -> None:
    with pytest.raises(SignalingError, match="need 86"):
        SdpInfo.decode(bytes(80))


def test_expand_offer_fills_the_template_and_keeps_the_sdes_key() -> None:
    offer = CompactOffer.from_json(
        {"ice-u": "DEVUF", "ice-p": "DEVPWD", "asc": 111, "vsc": 222, "sgc": 333}
    )
    sdp = expand_offer(offer)
    assert sdp.endswith("\r\n")
    assert "\n" not in sdp.replace("\r\n", "")  # CRLF only
    assert "a=ice-ufrag:DEVUF\r\n" in sdp
    assert "a=ice-pwd:DEVPWD\r\n" in sdp
    assert f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{SDES_INLINE_KEY}\r\n" in sdp
    assert "a=setup:actpass\r\n" in sdp  # SDES, not DTLS
    assert "a=ssrc:111 cname:uIGCl7ux\r\n" in sdp  # audio
    assert "a=ssrc:222 cname:u21w8kF2\r\n" in sdp  # video
    assert "a=ssrc-group:FEC-FR 222 333\r\n" in sdp  # FEC group


def test_expand_offer_refuses_without_ice_credentials() -> None:
    with pytest.raises(SignalingError, match="no ICE credentials"):
        expand_offer(CompactOffer.from_json({}))


def test_compact_offer_fields() -> None:
    offer = CompactOffer.from_json({"ice-u": "u", "ice-p": "p", "asc": 5, "vsc": "6", "sg": 1})
    assert (offer.ice_ufrag, offer.ice_pwd, offer.audio_ssrc, offer.video_ssrc) == ("u", "p", 5, 6)
    assert offer.fields["sg"] == 1
    assert CompactOffer.from_json({"asc": "x"}).audio_ssrc is None


def test_the_answer_keeps_ice_credentials_and_ssrc_lines() -> None:
    sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 97\r\na=ice-ufrag:abc\r\na=ice-pwd:def\r\na=ssrc:1 cname:x\r\na=rtcp-mux\r\n"
    assert answer_attributes(sdp) == "a=ice-ufrag:abc\r\na=ice-pwd:def\r\na=ssrc:1 cname:x\r\n"


@pytest.mark.parametrize(
    ("model", "sdk", "kcp_type"),
    [
        ("T9000", "7.1.2", KCP_TYPE_MULTI),
        ("T9000", "1.1.2", KCP_TYPE_MULTI),  # the first component is not compared
        ("T9000", "7.1.1", KCP_TYPE_SINGLE),
        ("T9000", "7.2", KCP_TYPE_MULTI),
        ("T8N00", "7.0.9", KCP_TYPE_SINGLE),
        ("T8030", "6.1.3", KCP_TYPE_MULTI),
        ("T8030", "6.1.2", KCP_TYPE_SINGLE),
        ("T8224", "6.1.3", KCP_TYPE_MULTI),
        ("T9000", None, KCP_TYPE_MULTI),
        ("T9000", "x.y", KCP_TYPE_MULTI),
        ("T8030", "x.y", KCP_TYPE_SINGLE),
        ("T8410", "1.0.0", KCP_TYPE_MULTI),
    ],
)
def test_data_channel_kcp_type_follows_model_and_sdk(
    model: str, sdk: str | None, kcp_type: int
) -> None:
    assert data_channel_kcp_type(model, sdk) == kcp_type


@pytest.mark.parametrize(
    ("model", "firmware", "encrypted"),
    [
        ("T9000", 4100, True),
        ("T9000", 4099, False),
        ("T9000", None, False),
        ("T8N00", 1088, False),
        ("T8N00", 1089, True),
        ("T8N00", 1199, True),
        ("T8N00", 1200, False),
        ("T8N00", 1208, False),
        ("T8N00", 1209, True),
        ("T8030", 3743, True),
        ("T8030", 3742, False),
        ("T8223", 3376, True),
        ("T8223", 3375, False),
        ("T8224", 3476, True),
        ("T8224", 3475, False),
        ("T8172", 1021, True),
        ("T8172", 1020, False),
        ("T8025", 9999, False),
        ("T8410", None, True),
    ],
)
def test_commands_are_encrypted_per_model_and_firmware(
    model: str, firmware: int | None, encrypted: bool
) -> None:
    assert commands_encrypted(model, firmware) is encrypted
