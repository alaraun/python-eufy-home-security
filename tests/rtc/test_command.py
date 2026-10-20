"""``rtc/command.py``: command and notification AES-128-GCM, against known answers.

The known answers come from the app's native wire scheme
(``.work/notes/s1/B1_KEYS_CRYPTO.md`` §§2-3). Inputs are synthetic.
"""

from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from eufy_home_security.exceptions import SignalingError
from eufy_home_security.p2p.crypto import GCM_AAD
from eufy_home_security.p2p.xzyh import HEADER_LEN, encode_frame
from eufy_home_security.rtc.command import (
    CommandCipher,
    decrypt_notification,
    encrypt_command,
)

KEY = b"0123456789abcdef"
IV = bytes(range(12))
FRAME = encode_frame(0x0514, b'{"cmd":1350}', b"\x00" * 6)


def test_encrypt_command_is_the_app_wrapper() -> None:
    packet = encrypt_command(KEY, FRAME, 7, iv=IV)
    assert packet.hex() == (
        "585a594814052c0000000a0000010000"  # XZYH header: version 10, encrypted, len 0x2c
        "00f3d76a4df309002cb0a72bb9c8e912"  # GCM tag
        "000102030405060708090a0b"  # IV
        "07000000"  # command counter (little-endian)
        "861da7707a560107db133767"  # ciphertext of the 12-byte body
    )


def test_the_header_marks_the_encrypted_length() -> None:
    body = FRAME[HEADER_LEN:]
    packet = encrypt_command(KEY, FRAME, 0, iv=IV)
    assert packet[0x0A] == 10  # version byte
    assert packet[0x0D] == 1  # encrypted flag
    assert struct.unpack_from("<I", packet, 0x06)[0] == len(body) + 0x20  # tag+iv+counter+ct


def test_command_body_round_trips_under_the_media_key() -> None:
    body = FRAME[HEADER_LEN:]
    packet = encrypt_command(KEY, FRAME, 3, iv=IV)
    tag, nonce, counter, ciphertext = packet[16:32], packet[32:44], packet[44:48], packet[48:]
    assert struct.unpack("<I", counter)[0] == 3
    assert AESGCM(KEY).decrypt(nonce, ciphertext + tag, GCM_AAD) == body


def test_encrypt_command_rejects_a_short_frame() -> None:
    with pytest.raises(SignalingError, match="shorter than its header"):
        encrypt_command(KEY, b"\x00" * 8, 0)


def test_decrypt_notification_opens_the_payload() -> None:
    plaintext = b'{"notify":true}\x00'
    sealed = AESGCM(KEY).encrypt(IV, plaintext, GCM_AAD)
    payload = sealed[-16:] + IV + sealed[:-16]  # tag | iv | ciphertext
    assert decrypt_notification(KEY, payload) == plaintext


def test_decrypt_notification_falls_back_to_the_previous_key() -> None:
    old, new = b"k" * 16, b"n" * 16
    sealed = AESGCM(old).encrypt(IV, b"body", GCM_AAD)
    payload = sealed[-16:] + IV + sealed[:-16]
    assert decrypt_notification(new, payload, previous_key=old) == b"body"


def test_decrypt_notification_rejects_a_forged_payload() -> None:
    payload = b"\x00" * 40
    with pytest.raises(SignalingError, match="did not authenticate"):
        decrypt_notification(KEY, payload)


def test_decrypt_notification_rejects_a_short_payload() -> None:
    with pytest.raises(SignalingError, match="too short"):
        decrypt_notification(KEY, b"\x00" * 20)


def test_command_cipher_advances_the_counter() -> None:
    cipher = CommandCipher("0123456789abcdef")
    first = cipher.encrypt(FRAME, iv=IV)
    second = cipher.encrypt(FRAME, iv=IV)
    assert struct.unpack("<I", first[44:48])[0] == 0
    assert struct.unpack("<I", second[44:48])[0] == 1


def test_command_cipher_rotate_keeps_the_previous_key() -> None:
    cipher = CommandCipher("k" * 16)
    sealed = AESGCM(b"k" * 16).encrypt(IV, b"x", GCM_AAD)
    payload = sealed[-16:] + IV + sealed[:-16]
    cipher.rotate("n" * 16)  # a notification sealed with the old key still opens
    assert cipher.decrypt_notification(payload) == b"x"


def test_a_short_media_key_is_refused() -> None:
    with pytest.raises(SignalingError, match="shorter than 16"):
        CommandCipher("tooshort")
