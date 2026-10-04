"""MegaCrypto primitives."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from eufy_home_security.cloud import const, crypto
from eufy_home_security.exceptions import ProtocolError


def test_preset_roundtrip() -> None:
    blob = crypto.preset_encrypt("hello world", const.MEGA_PRESET_KEY)
    assert crypto.preset_decrypt(blob, const.MEGA_PRESET_KEY) == "hello world"


def test_body_roundtrip_uses_first_16_bytes_of_shared_key() -> None:
    shared = "ab" * 32
    blob = crypto.body_encrypt('{"x":1}', shared)
    assert crypto.body_decrypt(blob, shared) == '{"x":1}'


def test_body_decrypt_rejects_garbage() -> None:
    with pytest.raises(ProtocolError):
        crypto.body_decrypt("not base64!!", "ab" * 32)


def test_key_exchange_derives_the_same_shared_key_both_sides() -> None:
    # The client half:
    exchange = crypto.start_key_exchange(const.MEGA_PRESET_KEY)
    client_pub_hex = crypto.preset_decrypt(exchange.client_public_key, const.MEGA_PRESET_KEY)

    # A synthetic server: derive the shared secret and hand its own key back.
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_shared = server_key.exchange(ec.ECDH(), crypto.load_public_key(client_pub_hex)).hex()
    server_pub_enc = crypto.preset_encrypt(crypto.public_key_hex(server_key), const.MEGA_PRESET_KEY)

    client_shared = crypto.finish_key_exchange(exchange, server_pub_enc, const.MEGA_PRESET_KEY)
    assert client_shared == server_shared


def test_x_signature_is_stable_and_body_optional() -> None:
    a = crypto.x_signature("key", "1", "2", "body")
    assert a == crypto.x_signature("key", "1", "2", "body")
    assert crypto.x_signature("key", "1", "2") != a  # body changes the digest


def test_gtoken_is_md5_hex() -> None:
    assert crypto.gtoken("abc") == "900150983cd24fb0d6963f7d28e17f72"


@pytest.mark.parametrize("length", list(range(1, 40)))
def test_login_password_is_padded_to_a_32_byte_boundary(length: int) -> None:
    """PKCS7 at 256, not 128 — pinned against a well-meaning "fix" (see crypto.py)."""
    out = crypto.encrypt_login_password("x" * length)
    ct = base64.b64decode(out.encrypted)
    assert len(ct) % 16 == 0
    assert len(ct) == 32 * ((length // 32) + 1)
    assert out.client_public_key.startswith("04")
    assert len(out.client_public_key) == 130


def test_load_public_key_rejects_non_points() -> None:
    with pytest.raises(ProtocolError):
        crypto.load_public_key("00" * 10)


def test_login_password_repr_hides_the_ciphertext() -> None:
    out = crypto.encrypt_login_password("hunter2hunter2")
    assert out.encrypted not in repr(out)
