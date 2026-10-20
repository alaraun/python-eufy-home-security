"""Tests for the in-frame AES-128-GCM decryption (:mod:`.rtc.frame_crypto`)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc.frame_crypto import EufyFrameDecryptor
from eufy_home_security.rtc.media import START_CODE, FrameDecryptor

KEY = "0123456789abcdef"  # 16 ASCII bytes
IV = "nonce--12char"[:12]  # 12 ASCII bytes


def _hevc_header(nal_type: int) -> bytes:
    # HEVC two-byte NAL header: F=0, type in bits 1..6 of byte 0, layer/tid byte 1.
    return bytes([(nal_type << 1) & 0x7E, 0x01])


def _encrypted_nal(nal_type: int, plaintext: bytes) -> bytes:
    # The device's layout: 2-byte header, then AES-128-GCM(ct || 16-byte tag).
    blob = AESGCM(KEY.encode()).encrypt(IV.encode(), plaintext, None)
    return _hevc_header(nal_type) + blob


def _clear_nal(nal_type: int, body: bytes) -> bytes:
    return _hevc_header(nal_type) + body


def _annex_b(*nals: bytes) -> bytes:
    return b"".join(START_CODE + n for n in nals)


def test_decrypts_sps_pps_idr_and_leaves_vps_and_pslices_clear() -> None:
    sps, pps, idr = b"SPS-param-set", b"PPS-param-set", b"IDR-slice-data" * 4
    vps = b"VPS-stays-clear"
    pslice = b"non-key-slice-stays-clear" * 2
    frame = _annex_b(
        _clear_nal(32, vps),
        _encrypted_nal(33, sps),
        _encrypted_nal(34, pps),
        _encrypted_nal(19, idr),
        _clear_nal(1, pslice),
    )
    out = EufyFrameDecryptor(KEY, IV).video(frame, keyframe=True)
    expected = _annex_b(
        _clear_nal(32, vps),
        _clear_nal(33, sps),
        _clear_nal(34, pps),
        _clear_nal(19, idr),
        _clear_nal(1, pslice),
    )
    assert out == expected


def test_a_p_frame_with_no_encrypted_nal_is_unchanged() -> None:
    frame = _annex_b(_clear_nal(1, b"trail-slice" * 3), _clear_nal(0, b"another-slice"))
    assert EufyFrameDecryptor(KEY, IV).video(frame, keyframe=False) == frame


def test_a_three_byte_start_code_is_handled() -> None:
    sps = b"param-set-here"
    frame = b"\x00\x00\x01" + _encrypted_nal(33, sps)
    out = EufyFrameDecryptor(KEY, IV).video(frame, keyframe=True)
    assert out == b"\x00\x00\x01" + _clear_nal(33, sps)


def test_a_bad_tag_is_a_protocol_error() -> None:
    nal = _encrypted_nal(33, b"param-set")
    tampered = _annex_b(nal[:-1] + bytes([nal[-1] ^ 0xFF]))
    with pytest.raises(ProtocolError, match="authentication failed"):
        EufyFrameDecryptor(KEY, IV).video(tampered, keyframe=True)


def test_key_and_iv_lengths_are_checked() -> None:
    with pytest.raises(ProtocolError, match="content key is"):
        EufyFrameDecryptor("short", IV)
    with pytest.raises(ProtocolError, match="content IV is"):
        EufyFrameDecryptor(KEY, "short")


def test_audio_is_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        EufyFrameDecryptor(KEY, IV).audio(b"\x00")


def test_it_satisfies_the_frame_decryptor_protocol() -> None:
    assert isinstance(EufyFrameDecryptor(KEY, IV), FrameDecryptor)
