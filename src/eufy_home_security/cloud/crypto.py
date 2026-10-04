"""MegaCrypto primitives: pure functions, no I/O.

The eufy_mega envelope, in one paragraph. A key exchange sends a fresh P-256
public key, AES-128-CBC'd under a static *preset* key, and gets the server's
public key back the same way; ECDH over the pair gives a 64-hex ``shared_key``.
From then on the pair ``(key_ident, shared_key)`` is the transport identity:
request and response bodies are ``base64(IV16 ‖ AES-128-CBC-PKCS7(json))`` under
``shared_key[:32]`` (hex-decoded, 16 bytes), and every request carries
``x-signature = HMAC-SHA256(key, ts + "+" + nonce + "+" + body)``, keyed with the
ASCII of ``shared_key[:32]`` (or of the preset, for the exchange itself).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..exceptions import ProtocolError
from .const import LOGIN_SERVER_PUBLIC_KEY

_IV_LEN = 16
_P256_UNCOMPRESSED_HEX_LEN = 130


def new_key_ident() -> str:
    """A random 32-hex value: a fresh ``x-key-ident`` or ``x-request-once``."""
    return secrets.token_hex(16)


def x_signature(key: str, ts: str, nonce: str, body: str | None = None) -> str:
    """``HMAC-SHA256(key_ascii, ts+"+"+nonce[+"+"+body])``, lowercase hex."""
    parts = [ts, nonce] if body is None else [ts, nonce, body]
    return hmac.new(key.encode(), "+".join(parts).encode(), hashlib.sha256).hexdigest()


def gtoken(user_id: str) -> str:
    """The ``gtoken`` header: lowercase MD5 of the user id (an identifier, not a secret)."""
    return hashlib.md5(user_id.encode(), usedforsecurity=False).hexdigest()


def _aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, block_bits: int = 128) -> bytes:
    padder = padding.PKCS7(block_bits).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _encrypt_iv_prefixed(plaintext: str, key: bytes) -> str:
    iv = os.urandom(_IV_LEN)
    return base64.b64encode(iv + _aes_cbc_encrypt(plaintext.encode(), key, iv)).decode()


def _decrypt_iv_prefixed(blob_b64: str, key: bytes) -> str:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
        if len(blob) <= _IV_LEN or (len(blob) - _IV_LEN) % _IV_LEN:
            raise ValueError("ciphertext is not whole AES blocks")
        return _aes_cbc_decrypt(blob[_IV_LEN:], key, blob[:_IV_LEN]).decode()
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise ProtocolError(f"cannot decrypt MegaCrypto body: {exc}") from exc


def preset_encrypt(plaintext: str, preset_key_hex: str) -> str:
    """Encrypt under a static preset key (key-exchange bootstrap)."""
    return _encrypt_iv_prefixed(plaintext, bytes.fromhex(preset_key_hex))


def preset_decrypt(blob_b64: str, preset_key_hex: str) -> str:
    """Inverse of :func:`preset_encrypt`; :class:`ProtocolError` on bad input."""
    return _decrypt_iv_prefixed(blob_b64, bytes.fromhex(preset_key_hex))


def signing_key(shared_key_hex: str) -> str:
    """The HMAC key of an established identity: the first 32 hex chars, as ASCII."""
    return shared_key_hex[:32]


def body_encrypt(plaintext: str, shared_key_hex: str) -> str:
    """Encrypt a request body under an established identity."""
    return _encrypt_iv_prefixed(plaintext, bytes.fromhex(shared_key_hex[:32]))


def body_decrypt(blob_b64: str, shared_key_hex: str) -> str:
    """Decrypt a response ``data`` field; :class:`ProtocolError` on bad input."""
    return _decrypt_iv_prefixed(blob_b64, bytes.fromhex(shared_key_hex[:32]))


def public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Uncompressed SEC1 point of the key's public half, hex (130 chars)."""
    return (
        private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
    )


def private_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    """The private scalar, 64 hex chars (for debug logging only)."""
    return f"{private_key.private_numbers().private_value:064x}"


def load_public_key(point_hex: str) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed P-256 point; :class:`ProtocolError` if it is not one."""
    if len(point_hex) != _P256_UNCOMPRESSED_HEX_LEN or not point_hex.lower().startswith("04"):
        raise ProtocolError("key exchange: server public key is not an uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(point_hex)
        )
    except ValueError as exc:
        raise ProtocolError(f"key exchange: invalid server public key: {exc}") from exc


@dataclass(frozen=True, slots=True)
class KeyExchange:
    """Client half of one key exchange, before the server has answered."""

    key_ident: str
    private_key: ec.EllipticCurvePrivateKey
    client_public_key: str
    """The preset-encrypted public key: both the body field and the signed value."""


def start_key_exchange(preset_key_hex: str) -> KeyExchange:
    """Mint a key ident and a P-256 key pair, and encrypt the public half."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return KeyExchange(
        key_ident=new_key_ident(),
        private_key=private_key,
        client_public_key=preset_encrypt(public_key_hex(private_key), preset_key_hex),
    )


def finish_key_exchange(
    exchange: KeyExchange, server_public_key_enc: str, preset_key_hex: str
) -> str:
    """Derive the 64-hex ``shared_key`` from the server's encrypted public key."""
    server_point = preset_decrypt(server_public_key_enc, preset_key_hex)
    server_key = load_public_key(server_point)
    return exchange.private_key.exchange(ec.ECDH(), server_key).hex()


@dataclass(frozen=True, slots=True)
class LoginPassword:
    encrypted: str = field(repr=False)
    client_public_key: str
    secret: bytes = field(repr=False)
    """The ECDH secret the password was wrapped under (kept for debug logging)."""


def encrypt_login_password(
    password: str, server_public_key_hex: str = LOGIN_SERVER_PUBLIC_KEY
) -> LoginPassword:
    """ECDH-wrap the account password for ``/passport/login``.

    ``AES-CBC(key=secret, iv=secret[:16])`` over the password, padded **PKCS7 at
    256 bits** — the key size, not the 16-byte AES block. That is not a typo, and it
    must not be "corrected": it reads like a bug (a 32-byte pad block yields pad bytes
    of 17-32, which a standard 16-byte unpad rejects), but logins succeed through
    exactly this. Whether the server pads at 32 or is merely lenient cannot be told
    apart at a sane price — a few failed logins lock the account for 24 h — so the block
    size that logs in stays. Change it only against a capture of the app's own login
    body.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    secret = private_key.exchange(ec.ECDH(), load_public_key(server_public_key_hex))
    ciphertext = _aes_cbc_encrypt(password.encode(), secret, secret[:16], block_bits=256)
    return LoginPassword(
        encrypted=base64.b64encode(ciphertext).decode(),
        client_public_key=public_key_hex(private_key),
        secret=secret,
    )
