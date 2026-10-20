"""The cryptographic operations eufy's RTC signaling needs.

The signaling client (:mod:`.signaling`) calls these at fixed points of the flow.
:class:`RtcSignalingCrypto` implements them; :class:`UnavailableCrypto` refuses every operation with
:class:`~.exceptions.UnsupportedError` for a client built without one.

Where each operation runs:

- LOGIN challenge (401): :meth:`RtcCrypto.open_challenge` turns the body into the
  server's public key.
- LOGIN key exchange: :meth:`RtcCrypto.new_session_key` makes the session key,
  :meth:`RtcCrypto.seal_session_key` seals it with the server's public key, and
  :meth:`RtcCrypto.seal` seals the station identity ``"<p2p_did>:<p2p_license>"``.
- Every encrypted attachment and message (header flag set): :meth:`RtcCrypto.seal`
  and :meth:`RtcCrypto.open` with the session key, salted with the header's
  packet id.
- A private CALL's ``sdp_info``: :meth:`RtcCrypto.new_media_secret` for the content
  key and IV.

The wire crypto (see ``docs/protocol/rtc-signaling.md`` § Cryptography):

- AES-128-ECB with zero padding; the key for a packet is the secret's first 16
  bytes with its tail overwritten by the decimal of the packet id (a signed 32-bit
  value), truncated at the first NUL and zero-padded back to 16.
- The LOGIN 401 blob uses the fixed default secret; everything after login uses the
  client-made 16-character session key.
- The session key is sealed with RSA-1024, PKCS#1 v1.5, public exponent 65537, the
  modulus a 256-character hex string from the 401 body.
- Random key material is drawn from ``[0-9A-Za-z]``.
"""

from __future__ import annotations

import random
import string
from typing import Final, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..exceptions import SignalingError, UnsupportedError

#: The fixed secret that encrypts the LOGIN 401 challenge blob.
DEFAULT_SECRET: Final = "&#%@!_eufy_anker"  # noqa: S105 (protocol constant, not a secret)

#: Public exponent of the server's RSA key.
RSA_EXPONENT: Final = 0x10001

#: Hex length of the 1024-bit RSA modulus; any other length is refused.
RSA_MODULUS_HEX_LEN: Final = 256

#: Length of a session key, in characters.
SESSION_KEY_LEN: Final = 16

#: The alphabet of every random key: digits, then lower, then upper case.
KEY_ALPHABET: Final = string.digits + string.ascii_lowercase + string.ascii_uppercase


def _as_int32(value: int) -> int:
    """``value`` as a signed 32-bit integer (the key carries the packet id's signed decimal)."""
    low = value & 0xFFFFFFFF
    return low - 0x100000000 if low >= 0x80000000 else low


def derive_key(secret: str, salt: int) -> bytes:
    """The 16-byte AES key for ``salt``: ``secret`` padded to 16 bytes, its tail overwritten by the decimal of the signed
    32-bit ``salt``, then cut at the first NUL and zero-padded back to 16."""
    key = bytearray(secret.encode()[:16].ljust(16, b"\0"))
    decimal = str(_as_int32(salt)).encode()
    key[16 - len(decimal) : 16] = decimal
    return bytes(key).split(b"\0", 1)[0].ljust(16, b"\0")


def aes_ecb_encrypt(secret: str, salt: int, data: bytes) -> bytes:
    """``data`` AES-128-ECB encrypted with ``derive_key(secret, salt)``, zero-padded
    to a multiple of the block size (empty input yields empty output)."""
    cipher = Cipher(algorithms.AES(derive_key(secret, salt)), modes.ECB())  # noqa: S305 (protocol)
    enc = cipher.encryptor()
    return enc.update(data + b"\0" * (-len(data) % 16)) + enc.finalize()


def aes_ecb_decrypt(secret: str, salt: int, data: bytes) -> bytes:
    """The inverse of :func:`aes_ecb_encrypt`; the zero padding is left on (callers
    cut at the first NUL)."""
    if len(data) % 16:
        raise SignalingError("RTC ciphertext is not a whole number of AES blocks")
    cipher = Cipher(algorithms.AES(derive_key(secret, salt)), modes.ECB())  # noqa: S305 (protocol)
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


@runtime_checkable
class RtcCrypto(Protocol):
    """The signaling's cryptographic operations."""

    def open_challenge(self, body: bytes, salt: int) -> str:
        """The server's public key (text) from a LOGIN 401 body."""
        ...

    def new_session_key(self) -> str:
        """A fresh session key for one login."""
        ...

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        """``session_key`` sealed for the server (the key exchange's first blob)."""
        ...

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        """``data`` encrypted with ``session_key``, salted with a packet id."""
        ...

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        """The inverse of :meth:`seal`."""
        ...

    def new_media_secret(self, length: int) -> str:
        """A random ``length``-character secret for a private call's key or IV."""
        ...


class RtcSignalingCrypto:
    """The RTC signaling crypto (the wire scheme of the module docstring).

    ``rng`` defaults to :class:`random.SystemRandom`; pass a seeded
    :class:`random.Random` only in tests.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.SystemRandom()

    def open_challenge(self, body: bytes, salt: int) -> str:
        plain = aes_ecb_decrypt(DEFAULT_SECRET, salt, body)
        return plain.split(b"\0", 1)[0].decode("ascii", "replace").strip()

    def new_session_key(self) -> str:
        return "".join(self._rng.choice(KEY_ALPHABET) for _ in range(SESSION_KEY_LEN))

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        modulus = _modulus(public_key)
        key = rsa.RSAPublicNumbers(e=RSA_EXPONENT, n=modulus).public_key()
        return key.encrypt(session_key.encode(), padding.PKCS1v15())

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        return aes_ecb_encrypt(session_key, salt, data)

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        return aes_ecb_decrypt(session_key, salt, data)

    def new_media_secret(self, length: int) -> str:
        return "".join(self._rng.choice(KEY_ALPHABET) for _ in range(length))


def _modulus(public_key: str) -> int:
    """The RSA modulus from a 401 challenge; it must be exactly 256 hex chars."""
    if len(public_key) != RSA_MODULUS_HEX_LEN:
        raise SignalingError(
            f"RTC LOGIN challenge is not a {RSA_MODULUS_HEX_LEN}-character RSA modulus"
        )
    try:
        return int(public_key, 16)
    except ValueError as exc:
        raise SignalingError("RTC LOGIN challenge modulus is not hexadecimal") from exc


class UnavailableCrypto:
    """An :class:`RtcCrypto` that refuses every operation."""

    REASON = "RTC signaling cryptography is not implemented in this library version"

    def _refuse(self) -> UnsupportedError:
        return UnsupportedError(self.REASON)

    def open_challenge(self, body: bytes, salt: int) -> str:
        raise self._refuse()

    def new_session_key(self) -> str:
        raise self._refuse()

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        raise self._refuse()

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        raise self._refuse()

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        raise self._refuse()

    def new_media_secret(self, length: int) -> str:
        raise self._refuse()
