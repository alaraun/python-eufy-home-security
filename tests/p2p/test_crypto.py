"""Session crypto: AES-ECB, AES-GCM, ECIES, and the CONN_INIT session-key unwrap."""

from __future__ import annotations

import contextlib
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.cloud.const import CIPHER_ID_P2P
from eufy_home_security.exceptions import CipherUnusableError, HandshakeError, ProtocolError
from eufy_home_security.p2p import crypto
from eufy_home_security.p2p.did import static_key
from eufy_home_security.testing import SYNTHETIC

_KEY16 = b"0012345-123456-A"
_KEY32 = b"VbuNh~k8kycVPEdtKOwn17Dj3eMuzvu4"


def _ecc_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, format(priv.private_numbers().private_value, "x")


def test_ecb_round_trip_and_bad_key() -> None:
    ct = crypto.ecb_encrypt(_KEY16, b'{"cmd":10011}')
    assert len(ct) % 16 == 0
    assert crypto.ecb_decrypt(_KEY16, ct).startswith(b'{"cmd":10011}')
    with pytest.raises(ProtocolError):
        crypto.ecb_encrypt(b"short", b"x")
    with pytest.raises(ProtocolError):
        crypto.ecb_decrypt(b"short", b"x")


def test_ecb_decrypt_keeps_a_trailing_partial_block() -> None:
    # 16 aligned bytes + a 3-byte tail returned as-is
    ct = crypto.ecb_encrypt(_KEY16, b"A" * 16) + b"\x01\x02\x03"
    out = crypto.ecb_decrypt(_KEY16, ct)
    assert out[-3:] == b"\x01\x02\x03"


def test_gcm_command_round_trip_and_layout() -> None:
    nonce = bytes(range(12))
    frame = crypto.gcm_encrypt_command(_KEY32, b'{"a":1}', nonce=nonce, seq=crypto.GCM_SEQ_START)
    assert frame[16:28] == nonce
    assert struct.unpack_from("<I", frame, 28)[0] == crypto.GCM_SEQ_START
    assert crypto.gcm_decrypt_command(_KEY32, frame) == b'{"a":1}'


def test_gcm_command_rejects_bad_nonce_length() -> None:
    with pytest.raises(ProtocolError):
        crypto.gcm_encrypt_command(_KEY32, b"x", nonce=b"short", seq=1)


def test_gcm_broadcast_round_trip_omits_seq() -> None:
    # Build a base->app frame exactly as the station does: tag ‖ nonce ‖ ct, no seq.
    nonce = bytes(range(12))
    ct_and_tag = AESGCM(_KEY32).encrypt(nonce, b'{"params":[]}', crypto.GCM_AAD)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    frame = tag + nonce + ct
    assert crypto.gcm_decrypt_broadcast(_KEY32, frame) == b'{"params":[]}'


def test_gcm_auth_failure_raises_protocol_error() -> None:
    nonce = bytes(range(12))
    frame = bytearray(crypto.gcm_encrypt_command(_KEY32, b"payload here", nonce=nonce, seq=1))
    frame[-1] ^= 0xFF  # tamper the ciphertext
    with pytest.raises(ProtocolError):
        crypto.gcm_decrypt_command(_KEY32, bytes(frame))
    with pytest.raises(ProtocolError):
        crypto.gcm_decrypt_command(_KEY32, b"tooshort")
    with pytest.raises(ProtocolError):
        crypto.gcm_decrypt_broadcast(_KEY32, b"tooshort")


def test_ecies_round_trip_including_over_read_tail() -> None:
    priv, priv_hex = _ecc_keypair()
    secret = b"K" * 32
    blob = crypto.ecies_encrypt(secret, priv.public_key())
    assert crypto.ecies_decrypt(blob, priv_hex) == secret
    # a fixed length hint also works
    assert crypto.ecies_decrypt(blob, priv_hex, blob_len=len(blob)) == secret
    # an ECB over-read tail must not defeat the HMAC length search
    assert crypto.ecies_decrypt(blob + b"\x00" * 9, priv_hex) == secret


def test_ecies_finds_the_length_whatever_the_over_read() -> None:
    """An ECB over-read pads the blob by an arbitrary amount; every case must decrypt.

    The candidate search steps by the AES block size, since no other length can match.
    A tail of any size must still resolve, or a real handshake fails on a station whose
    padding happens to land off the step.
    """
    priv, priv_hex = _ecc_keypair()
    secret = b"K" * 32
    blob = crypto.ecies_encrypt(secret, priv.public_key())
    for tail in range(0, 33):
        assert crypto.ecies_decrypt(blob + b"\x00" * tail, priv_hex) == secret, tail


def test_ecies_rejects_a_wrong_key() -> None:
    priv, _ = _ecc_keypair()
    _, other_hex = _ecc_keypair()
    blob = crypto.ecies_encrypt(b"K" * 32, priv.public_key())
    with pytest.raises(ProtocolError):
        crypto.ecies_decrypt(blob, other_hex)


_ECC_SUBHEADER = bytes([crypto.CONN_INIT_ECC_VERSION, 0, 0xFF, crypto.FRAME_STATIC_ECB, 0, 0])


def _build_conn_init(session_key: bytes, cipher_id: int = CIPHER_ID_P2P) -> tuple[bytes, str]:
    """Encrypt a synthetic session key exactly as a CONN_INIT (0x044C) payload."""
    static = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    priv, priv_hex = _ecc_keypair()
    blob = crypto.ecies_encrypt(session_key, priv.public_key())
    plain = struct.pack("<I", cipher_id) + blob
    return crypto.ecb_encrypt(static, plain), priv_hex


def _rsa_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return priv, pem


def test_parse_conn_init_reads_version_and_cipher_id() -> None:
    static = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    payload, _ = _build_conn_init(b"x" * 32, cipher_id=98)
    parsed = crypto.parse_conn_init(payload, _ECC_SUBHEADER, static)
    assert (parsed.version, parsed.cipher_id, parsed.rsa) == (8, 98, False)


def test_parse_conn_init_reads_a_clear_payload_and_pads_a_partial_block() -> None:
    """Encryption type 0 is read as is; an ECB payload is zero-filled to whole blocks."""
    static = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    body = struct.pack("<I", 40) + bytes(range(129))
    clear = crypto.parse_conn_init(body, bytes([1, 0, 0xFF, crypto.FRAME_PLAIN, 0, 0]), static)
    assert (clear.version, clear.cipher_id, clear.body, clear.rsa) == (1, 40, body[4:], True)
    sealed = crypto.ecb_encrypt(static, body)[:133]  # a payload cut inside its last block
    parsed = crypto.parse_conn_init(sealed, bytes([1, 0, 0xFF, 1, 0, 0]), static)
    assert parsed.cipher_id == 40
    with pytest.raises(HandshakeError, match="subheader"):
        crypto.parse_conn_init(body, b"\x01", static)


def test_session_key_from_conn_init_recovers_the_key() -> None:
    static = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    session_key = bytes((65 + i % 26) for i in range(32))
    payload, priv_hex = _build_conn_init(session_key, cipher_id=98)
    parsed = crypto.parse_conn_init(payload, _ECC_SUBHEADER, static)
    assert crypto.session_key_from_conn_init(parsed, priv_hex) == session_key


def test_session_key_from_conn_init_rejects_a_bad_key() -> None:
    static = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    good, _ = _build_conn_init(bytes((65 + i % 26) for i in range(32)))
    _, other_hex = _ecc_keypair()
    with pytest.raises(HandshakeError):
        crypto.session_key_from_conn_init(
            crypto.parse_conn_init(good, _ECC_SUBHEADER, static), other_hex
        )


@pytest.mark.parametrize("trailer", [b"", b"\x00", b"\x00" * 11])
def test_aes_key_from_conn_init_unwraps_the_rsa_block(trailer: bytes) -> None:
    """The 128 bytes after the cipher id are RSA PKCS#1 v1.5; the key is 16 characters."""
    priv, pem = _rsa_keypair()
    wrapped = priv.public_key().encrypt(b"0123456789abcdef", padding.PKCS1v15())
    parsed = crypto.ConnInit(1, 40, wrapped + trailer)
    assert crypto.aes_key_from_conn_init(parsed, pem) == b"0123456789abcdef"
    bare = "".join(line for line in pem.splitlines() if "-----" not in line)
    assert crypto.aes_key_from_conn_init(parsed, bare) == b"0123456789abcdef"


def test_aes_key_from_conn_init_takes_the_key_up_to_a_nul() -> None:
    priv, pem = _rsa_keypair()
    cases = (
        (b"0123456789abcdef\x00junk", b"0123456789abcdef"),
        (b"0123456789abcdefXYZ", b"0123456789abcdef"),
        (b"short\x00", None),
        (b"\x01" * 16, None),
    )
    for plain, key in cases:
        wrapped = priv.public_key().encrypt(plain, padding.PKCS1v15())
        parsed = crypto.ConnInit(1, 40, wrapped)
        if key is None:
            with pytest.raises(HandshakeError, match="16-character"):
                crypto.aes_key_from_conn_init(parsed, pem)
        else:
            assert crypto.aes_key_from_conn_init(parsed, pem) == key


def test_aes_key_from_conn_init_rejects_a_wrong_or_bad_key_and_a_short_block() -> None:
    priv, _ = _rsa_keypair()
    _, other = _rsa_keypair()
    wrapped = priv.public_key().encrypt(b"0123456789abcdef", padding.PKCS1v15())
    with pytest.raises(HandshakeError):  # a decrypt error, or noise (implicit rejection)
        crypto.aes_key_from_conn_init(crypto.ConnInit(1, 40, wrapped), other)
    # A wrong-but-valid key is a stale key, not an unusable one: still a plain HandshakeError.
    with pytest.raises(HandshakeError) as noise:
        crypto.aes_key_from_conn_init(crypto.ConnInit(1, 40, wrapped), other)
    assert not isinstance(noise.value, CipherUnusableError)
    with pytest.raises(HandshakeError, match="not 128") as short:
        crypto.aes_key_from_conn_init(crypto.ConnInit(1, 40, wrapped[:100]), other)
    assert not isinstance(short.value, CipherUnusableError)  # a protocol shape, not a bad key
    # A key whose bytes do not parse is unusable (re-fetch cannot help); the cloud
    # lowercases the base64 on some accounts, which lands here.
    with pytest.raises(CipherUnusableError, match="does not parse") as bad:
        crypto.aes_key_from_conn_init(crypto.ConnInit(1, 40, wrapped), "not base64!")
    assert bad.value.reason == "rsa_unparsable"
    assert bad.value.cipher_id is None
    ecc = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(CipherUnusableError, match="not an RSA key") as wrong_type:
        crypto.aes_key_from_conn_init(crypto.ConnInit(1, 40, wrapped), ecc.decode())
    assert wrong_type.value.reason == "not_rsa"


def test_gcm_helpers_require_a_32_byte_session_key() -> None:
    nonce = bytes(range(12))
    frame = crypto.gcm_encrypt_command(_KEY32, b"x", nonce=nonce, seq=1)
    for key in (b"k" * 16, b"k" * 24, b"k" * 33, b""):
        with pytest.raises(ProtocolError):
            crypto.gcm_encrypt_command(key, b"x", nonce=nonce, seq=1)
        with pytest.raises(ProtocolError):
            crypto.gcm_decrypt_command(key, frame)
        with pytest.raises(ProtocolError):
            crypto.gcm_decrypt_broadcast(key, frame)


def test_pkcs7_unpad_validates_every_pad_byte() -> None:
    assert crypto._pkcs7_unpad(b"abc" + b"\x0d" * 13) == b"abc"
    assert crypto._pkcs7_unpad(b"\x10" * 16) == b""
    for bad in (b"", b"abc" + b"\x01" * 12 + b"\x03", b"x" * 15 + b"\x00", b"x" * 15 + b"\x11"):
        with pytest.raises(ProtocolError):
            crypto._pkcs7_unpad(bad)


@given(pt=st.binary(max_size=64))
@settings(max_examples=100)
def test_pkcs7_round_trips(pt: bytes) -> None:
    assert crypto._pkcs7_unpad(crypto._pkcs7_pad(pt)) == pt


@given(pt=st.binary(max_size=200))
@settings(max_examples=100)
def test_ecb_round_trips_any_plaintext(pt: bytes) -> None:
    assert crypto.ecb_decrypt(_KEY16, crypto.ecb_encrypt(_KEY16, pt)).startswith(pt)


@given(pt=st.binary(max_size=200), seq=st.integers(0, 0xFFFFFFFF))
@settings(max_examples=100)
def test_gcm_round_trips_any_plaintext(pt: bytes, seq: int) -> None:
    nonce = bytes(range(12))
    assert (
        crypto.gcm_decrypt_command(
            _KEY32, crypto.gcm_encrypt_command(_KEY32, pt, nonce=nonce, seq=seq)
        )
        == pt
    )


@given(data=st.binary(max_size=80))
@settings(max_examples=200)
def test_decoders_only_raise_protocol_error(data: bytes) -> None:
    for fn in (crypto.gcm_decrypt_command, crypto.gcm_decrypt_broadcast):
        with contextlib.suppress(ProtocolError):
            fn(_KEY32, data)
    with contextlib.suppress(ProtocolError):
        crypto.ecies_decrypt(data, "ab" * 32)
