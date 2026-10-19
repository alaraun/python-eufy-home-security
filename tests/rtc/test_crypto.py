"""``rtc/crypto.py``: the signaling crypto, against known answers.

The known answers come from the wire algorithm the eufy app's native SDK uses
(``.work/notes/s1/A_SIGNALING.md`` §4), the same one the live-verified login probe
runs against eufy's production signaling server. All inputs are synthetic.
"""

from __future__ import annotations

import random

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from eufy_home_security.exceptions import SignalingError, UnsupportedError
from eufy_home_security.rtc.crypto import (
    DEFAULT_SECRET,
    KEY_ALPHABET,
    RSA_EXPONENT,
    RtcSignalingCrypto,
    UnavailableCrypto,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    derive_key,
)

# A session key shaped like the app's (16 chars of [0-9A-Za-z]).
SESSION = "Ab3xYz90mN12pQrS"


# ── key derivation (get_aes_key_info_by_packetid @0x214578) ──────────────────


@pytest.mark.parametrize(
    ("salt", "expected"),
    [
        # A 10-digit packet id overwrites the last 10 bytes of the secret.
        (1697000000, "26232540215f31363937303030303030"),
        # A one-digit salt overwrites only the last byte; the rest of the secret stays.
        (7, "26232540215f657566795f616e6b6537"),
        (0, "26232540215f657566795f616e6b6530"),
        # The id is a signed 32-bit decimal: the minus sign is part of the string.
        (-1, "26232540215f657566795f616e6b2d31"),
        # Values past 2**31 wrap to negative, so the decimal (and key) differ.
        (123456789012345, "26232540212d32303435393131313735"),
    ],
)
def test_derive_key_matches_the_app(salt: int, expected: str) -> None:
    assert derive_key(DEFAULT_SECRET, salt).hex() == expected


def test_derive_key_is_always_sixteen_bytes() -> None:
    for salt in (0, 7, -2147483648, 2147483647, 999999999999):
        assert len(derive_key(DEFAULT_SECRET, salt)) == 16


# ── AES-128-ECB, zero padding (aesEncryptByKey @0x214398) ────────────────────


def test_seal_is_aes_128_ecb_with_zero_padding() -> None:
    plaintext = b'{"did":"T8030XYZ","n":1}'
    # Known answer for the algorithm (24 bytes zero-padded to 32, two ECB blocks).
    assert (
        aes_ecb_encrypt(SESSION, 1697000000, plaintext).hex()
        == "04a6d0d1d501a96d9e2225c1ad4c6b4dcb1baa7931e0288b0d048723dc151603"
    )


def test_open_reverses_seal_and_leaves_the_zero_padding() -> None:
    plaintext = b'{"did":"T8030XYZ","n":1}'
    sealed = aes_ecb_encrypt(SESSION, 1697000000, plaintext)
    opened = aes_ecb_decrypt(SESSION, 1697000000, sealed)
    assert opened.startswith(plaintext)
    assert len(opened) == 32
    assert opened.endswith(b"\0")


def test_empty_input_seals_to_nothing() -> None:
    assert aes_ecb_encrypt(SESSION, 1, b"") == b""


def test_decrypt_rejects_a_non_block_length() -> None:
    with pytest.raises(SignalingError, match="whole number of AES blocks"):
        aes_ecb_decrypt(SESSION, 1, b"\x00" * 17)


# ── LOGIN 401 challenge ──────────────────────────────────────────────────────


def test_open_challenge_decrypts_the_default_secret_blob() -> None:
    crypto = RtcSignalingCrypto()
    # The 401 body is the modulus text sealed with the default secret and its salt.
    body = aes_ecb_encrypt(DEFAULT_SECRET, 1697123456, b"DEADBEEF")
    assert crypto.open_challenge(body, 1697123456) == "DEADBEEF"


def test_open_challenge_strips_padding_and_whitespace() -> None:
    crypto = RtcSignalingCrypto()
    body = aes_ecb_encrypt(DEFAULT_SECRET, 1697123456, b"  DEADBEEF  ")
    assert crypto.open_challenge(body, 1697123456) == "DEADBEEF"


# ── key exchange (rsaEncryptByPubkey @0x21484c) ──────────────────────────────


def test_seal_session_key_is_pkcs1v15_with_exponent_65537() -> None:
    private = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=1024)  # noqa: S505 (eufy uses RSA-1024)
    modulus_hex = format(private.public_key().public_numbers().n, "064x")
    assert len(modulus_hex) == 256
    crypto = RtcSignalingCrypto()
    sealed = crypto.seal_session_key(modulus_hex, SESSION)
    assert len(sealed) == 128  # 1024-bit block
    assert private.decrypt(sealed, padding.PKCS1v15()) == SESSION.encode()


def test_seal_session_key_rejects_a_wrong_length_modulus() -> None:
    crypto = RtcSignalingCrypto()
    with pytest.raises(SignalingError, match="256-character RSA modulus"):
        crypto.seal_session_key("ab" * 64, SESSION)  # 128 chars, not 256


def test_seal_session_key_rejects_a_non_hex_modulus() -> None:
    crypto = RtcSignalingCrypto()
    with pytest.raises(SignalingError, match="not hexadecimal"):
        crypto.seal_session_key("z" * 256, SESSION)


def test_a_full_challenge_round_trip() -> None:
    """open_challenge, new_session_key, seal_session_key end to end."""
    private = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=1024)  # noqa: S505 (eufy uses RSA-1024)
    modulus_hex = format(private.public_key().public_numbers().n, "064x")
    salt = 1697000000
    challenge = aes_ecb_encrypt(DEFAULT_SECRET, salt, modulus_hex.encode())
    crypto = RtcSignalingCrypto()
    recovered = crypto.open_challenge(challenge, salt)
    assert recovered == modulus_hex
    session_key = crypto.new_session_key()
    sealed = crypto.seal_session_key(recovered, session_key)
    assert private.decrypt(sealed, padding.PKCS1v15()).decode() == session_key


# ── random material (generate_aes_key @0x2272b0, crypto_generate_str @0x230738) ─


def test_new_session_key_is_sixteen_chars_from_the_alphabet() -> None:
    crypto = RtcSignalingCrypto()
    key = crypto.new_session_key()
    assert len(key) == 16
    assert set(key) <= set(KEY_ALPHABET)


@pytest.mark.parametrize("length", [0, 12, 16, 23])
def test_new_media_secret_honours_the_length(length: int) -> None:
    crypto = RtcSignalingCrypto()
    secret = crypto.new_media_secret(length)
    assert len(secret) == length
    assert set(secret) <= set(KEY_ALPHABET)


def test_the_rng_is_injectable_for_reproducibility() -> None:
    a = RtcSignalingCrypto(random.Random(1)).new_session_key()
    b = RtcSignalingCrypto(random.Random(1)).new_session_key()
    assert a == b


def test_seal_round_trips_through_the_class() -> None:
    crypto = RtcSignalingCrypto()
    sealed = crypto.seal(SESSION, 42, b"hello")
    assert crypto.open(SESSION, 42, sealed).startswith(b"hello")


# ── the refusing stand-in ────────────────────────────────────────────────────


def test_unavailable_crypto_refuses_every_operation() -> None:
    crypto = UnavailableCrypto()
    with pytest.raises(UnsupportedError):
        crypto.open_challenge(b"", 0)
    with pytest.raises(UnsupportedError):
        crypto.new_session_key()
    with pytest.raises(UnsupportedError):
        crypto.seal_session_key("0" * 256, SESSION)
    with pytest.raises(UnsupportedError):
        crypto.seal(SESSION, 0, b"")
    with pytest.raises(UnsupportedError):
        crypto.open(SESSION, 0, b"")
    with pytest.raises(UnsupportedError):
        crypto.new_media_secret(16)
