"""MegaCrypto primitives."""

from __future__ import annotations

import base64
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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


def test_a_rewrapped_password_matches_the_first_wrap() -> None:
    first = crypto.encrypt_login_password("hunter2hunter2")
    again = crypto.rewrap_login_password("hunter2hunter2", first.client_public_key, first.secret)
    assert (again.encrypted, again.client_public_key) == (first.encrypted, first.client_public_key)
    other = crypto.rewrap_login_password("other", "04" + "ab" * 64, first.secret)
    assert other.encrypted != first.encrypted
    assert other.client_public_key == "04" + "ab" * 64


def test_login_password_repr_hides_the_ciphertext() -> None:
    out = crypto.encrypt_login_password("hunter2hunter2")
    assert out.encrypted not in repr(out)


def _sealed(code: str, text: bytes, *, rounds: int = 100_000) -> str:
    """``salt16 ‖ nonce12 ‖ AES-256-GCM(text) ‖ tag16`` under PBKDF2-HMAC-SHA256, built
    without the module under test."""
    salt, nonce = bytes(range(16)), bytes(range(16, 28))
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, rounds).derive(code.encode())
    return base64.b64encode(salt + nonce + AESGCM(key).encrypt(nonce, text, None)).decode()


def test_an_invitation_code_opens_the_app_format() -> None:
    assert crypto.invite_code_opens("482913", _sealed("482913", b"share"))


@pytest.mark.parametrize(
    "sealed",
    [
        _sealed("482914", b"share"),
        _sealed("482913", b"share", rounds=1000),
        _sealed("482913", b""),
        "not base64!",
        base64.b64encode(bytes(28)).decode(),
        "",
    ],
    ids=["other-code", "other-rounds", "empty-text", "not-base64", "no-ciphertext", "empty"],
)
def test_an_invitation_code_does_not_open_anything_else(sealed: str) -> None:
    assert not crypto.invite_code_opens("482913", sealed)


@pytest.mark.parametrize(
    "reshape",
    [
        lambda b: "\n".join(b[i : i + 76] for i in range(0, len(b), 76)),
        lambda b: b.rstrip("="),
        lambda b: f" {b}\r\n",
    ],
    ids=["wrapped", "unpadded", "padded-with-whitespace"],
)
def test_an_invitation_code_tolerates_what_the_apps_decoder_does(
    reshape: Callable[[str], str],
) -> None:
    sealed = _sealed("482913", b"share-share-share-share-share-share-share-share-share-share")
    assert sealed.endswith("=")
    assert crypto.invite_code_opens("482913", reshape(sealed))


def test_a_sealed_invitation_opens_with_its_code_only() -> None:
    sealed = crypto.invite_seal("482913", "share")
    assert crypto.invite_code_opens("482913", sealed)
    assert not crypto.invite_code_opens("482910", sealed)
