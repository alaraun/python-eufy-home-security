"""Session crypto for the P2P command channel.

Three schemes live here:

* **AES-128-ECB** under the static serial key — the legacy scalar command path,
  and how the station wraps CONN_INIT and every ECB base->app notify.
* **AES-256-GCM** under the 32-byte session key — the modern command channel.
  app->base frames carry ``tag(16) ‖ nonce(12) ‖ seq_u32le(4) ‖ ciphertext``;
  base->app frames omit the 4-byte seq. AAD is the fixed ``b"eufy security"``.
  Both directions use the one session key; only the layouts differ (the seq).
* **ECIES** (P-256 + a custom HMAC-SHA256 KDF) — unwraps the session key from
  the CONN_INIT frame. The blob is ``eph_pub(33) ‖ iv(16) ‖ ct(16·k) ‖ tag(32)``
  and its true length is found by the HMAC tag; the ECDH is computed once.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections.abc import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import HandshakeError, ProtocolError

#: Fixed GCM additional-authenticated-data.
GCM_AAD = b"eufy security"
#: The app->base plaintext seq counter's initial value.
GCM_SEQ_START = 0x01020304

_ECIES_INFO = b"ECIES"
_ECIES_MIN_LEN = 33 + 16 + 16 + 32  # eph + iv + one ct block + tag


# ── AES-128-ECB (static key) ──────────────────────────────────────────────────


def _check_key(key: bytes) -> None:
    if len(key) != 16:
        raise ProtocolError(f"AES-128 key must be 16 bytes, got {len(key)}")


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-128-ECB, zero-padded up to a 16-byte boundary."""
    _check_key(key)
    pad = (-len(plaintext)) % 16
    padded = plaintext + b"\x00" * pad
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 (protocol)
    return enc.update(padded) + enc.finalize()


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-128-ECB: decrypt the block-aligned prefix, append any partial tail as-is."""
    _check_key(key)
    aligned = (len(ciphertext) // 16) * 16
    if aligned == 0:
        return ciphertext
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 (protocol)
    return dec.update(ciphertext[:aligned]) + dec.finalize() + ciphertext[aligned:]


# ── AES-256-GCM (session key) ─────────────────────────────────────────────────

#: The session key is 32 ASCII bytes (AES-256).
SESSION_KEY_LEN = 32


def _check_session_key(key: bytes) -> None:
    # AESGCM would also accept a 16/24-byte key; the protocol never uses one.
    if len(key) != SESSION_KEY_LEN:
        raise ProtocolError(f"GCM session key must be {SESSION_KEY_LEN} bytes, got {len(key)}")


def gcm_encrypt_command(session_key: bytes, plaintext: bytes, *, nonce: bytes, seq: int) -> bytes:
    """Build an app->base command frame: ``tag(16) ‖ nonce(12) ‖ seq_u32le ‖ ct``."""
    _check_session_key(session_key)
    if len(nonce) != 12:
        raise ProtocolError(f"GCM nonce must be 12 bytes, got {len(nonce)}")
    ct_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, GCM_AAD)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return tag + nonce + struct.pack("<I", seq & 0xFFFFFFFF) + ct


def gcm_decrypt_command(session_key: bytes, payload: bytes) -> bytes:
    """Decrypt an app->base command frame (``tag ‖ nonce ‖ seq ‖ ct``)."""
    _check_session_key(session_key)
    if len(payload) < 32:
        raise ProtocolError("GCM command frame shorter than its header")
    nonce, tag, ct = payload[16:28], payload[0:16], payload[32:]
    try:
        return AESGCM(session_key).decrypt(nonce, ct + tag, GCM_AAD)
    except InvalidTag as exc:
        raise ProtocolError("GCM command authentication failed") from exc


def gcm_decrypt_broadcast(session_key: bytes, payload: bytes) -> bytes:
    """Decrypt a base->app frame (``tag ‖ nonce ‖ ct``, no seq)."""
    _check_session_key(session_key)
    if len(payload) < 28:
        raise ProtocolError("GCM broadcast frame shorter than its header")
    nonce, tag, ct = payload[16:28], payload[0:16], payload[28:]
    try:
        return AESGCM(session_key).decrypt(nonce, ct + tag, GCM_AAD)
    except InvalidTag as exc:
        raise ProtocolError("GCM broadcast authentication failed") from exc


# ── ECIES (CONN_INIT session-key unwrap) ──────────────────────────────────────


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _kdf(shared: bytes, outlen: int = 48) -> bytes:
    """The custom HMAC-SHA256 feedback KDF from ``kdf_func`` (info = ``b"ECIES"``)."""
    feedback = _hmac(shared, _ECIES_INFO)
    out = _hmac(shared, feedback + _ECIES_INFO)
    while len(out) < outlen:
        feedback = _hmac(shared, feedback)
        out += _hmac(shared, feedback + _ECIES_INFO)
    return out[:outlen]


def _pkcs7_unpad(data: bytes) -> bytes:
    """Strip PKCS#7 padding, validating every pad byte (raises :class:`ProtocolError`)."""
    pad = data[-1] if data else 0
    if not 1 <= pad <= 16 or len(data) < pad or data[-pad:] != bytes([pad]) * pad:
        raise ProtocolError("ECIES plaintext has invalid PKCS#7 padding")
    return data[:-pad]


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def ecies_decrypt(blob: bytes, ecc_private_key_hex: str, blob_len: int | None = None) -> bytes:
    """Unwrap an ECIES blob to its plaintext.

    The ECDH secret depends only on the ephemeral public key at the front, so it
    is computed once; the blob's true length (it may carry an ECB over-read tail)
    is found by trying candidate lengths against the HMAC tag.
    """
    if len(blob) < 33:
        raise ProtocolError("ECIES blob too short to hold an ephemeral public key")
    try:
        priv = ec.derive_private_key(int(ecc_private_key_hex, 16), ec.SECP256R1())
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), blob[0:33])
        shared = priv.exchange(ec.ECDH(), eph_pub)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"ECIES ECDH failed: {exc}") from exc

    km = _kdf(shared, 48)
    aes_key, hmac_key = km[0:16], km[16:48]

    # Without a declared length, try every candidate whose ciphertext is a whole number
    # of AES blocks — no other length can match, and stepping by the block size cuts the
    # search by 16x. The HMAC is computed over the candidate's prefix, so the whole
    # search is still quadratic in the blob: callers must bound the input as well (the
    # CONN_INIT matcher does, see CONN_INIT_MAX_LEN).
    if blob_len is not None:
        candidates: Iterable[int] = (blob_len,)
    else:
        candidates = range(_ECIES_MIN_LEN, len(blob) + 1, 16)
    for length in candidates:
        if length < _ECIES_MIN_LEN or length > len(blob):
            continue
        iv, ct, tag = blob[33:49], blob[49 : length - 32], blob[length - 32 : length]
        if len(ct) < 16 or len(ct) % 16:
            continue
        if not hmac.compare_digest(_hmac(hmac_key, blob[33 : length - 32]), tag):
            continue
        dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        return _pkcs7_unpad(dec.update(ct) + dec.finalize())
    raise ProtocolError("ECIES decrypt failed (no candidate length matched the HMAC tag)")


def ecies_encrypt(
    plaintext: bytes, public_key: ec.EllipticCurvePublicKey, *, iv: bytes | None = None
) -> bytes:
    """Inverse of :func:`ecies_decrypt`, for tests and round-trip symmetry."""
    if iv is None:
        iv = os.urandom(16)
    if len(iv) != 16:
        raise ProtocolError(f"ECIES IV must be 16 bytes, got {len(iv)}")
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    shared = eph_priv.exchange(ec.ECDH(), public_key)
    km = _kdf(shared, 48)
    aes_key, hmac_key = km[0:16], km[16:48]
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = enc.update(_pkcs7_pad(plaintext)) + enc.finalize()
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    tag = _hmac(hmac_key, iv + ct)
    return eph_pub + iv + ct + tag


def _conn_init_block(payload: bytes, static_key: bytes) -> tuple[int, bytes]:
    """The cipher id and the ECIES blob (with its padding tail) of a CONN_INIT payload."""
    try:
        block = ecb_decrypt(static_key, payload)
    except ProtocolError as exc:
        raise HandshakeError(f"CONN_INIT ECB decrypt failed: {exc}") from exc
    if len(block) < 4:
        raise HandshakeError("CONN_INIT payload too short for a cipher id")
    return struct.unpack_from("<I", block, 0)[0], block[4:]


def conn_init_cipher_id(payload: bytes, static_key: bytes) -> int:
    """The cipher a CONN_INIT (0x044C) payload names: the station chooses it (40 on a
    HomeBase 3, 98 on a T8170), and only the static key is needed to read it."""
    return _conn_init_block(payload, static_key)[0]


def session_key_from_conn_init(
    payload: bytes, static_key: bytes, ecc_private_key_hex: str, cipher_id: int
) -> bytes:
    """Recover the 32-byte ASCII session key from a CONN_INIT (0x044C) payload.

    ECB-decrypt under the static key, check that it names ``cipher_id`` (the cipher
    ``ecc_private_key_hex`` belongs to), then ECIES-unwrap with that key. Any failure
    raises :class:`HandshakeError` (the usual cause is a cipher key that no longer
    matches the station).
    """
    named, blob = _conn_init_block(payload, static_key)
    if named != cipher_id:
        raise HandshakeError(f"CONN_INIT names cipher {named}, the key is cipher {cipher_id}")
    try:
        key = ecies_decrypt(blob, ecc_private_key_hex)
    except ProtocolError as exc:
        raise HandshakeError(f"CONN_INIT ECIES unwrap failed: {exc}") from exc
    if len(key) != SESSION_KEY_LEN or not all(32 <= b < 127 for b in key):
        raise HandshakeError("CONN_INIT unwrapped a key that is not 32 ASCII bytes")
    return key
