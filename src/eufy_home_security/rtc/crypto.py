"""The cryptography of eufy's RTC signaling.

- Sealed fields (attachments, message data, the LOGIN challenge) are AES-128-ECB with
  zero padding. The key for a packet is a 16-byte secret whose tail is overwritten by
  the decimal of the packet id (a signed 32-bit value), cut at the first NUL and
  zero-padded back to 16 bytes (:func:`derive_key`).
- The LOGIN 401 blob is sealed with the fixed :data:`DEFAULT_SECRET`; everything after
  the login uses the client-made 16-character session key.
- The session key is sealed for the server with RSA-1024, PKCS#1 v1.5, public exponent
  65537; the modulus is the 256-character hex string the 401 blob opens to.
- Random key material is drawn from ``[0-9A-Za-z]``.

The LOGIN key exchange is verified against eufy's signaling server with a HomeBase 3
identity; see ``docs/protocol/rtc-signaling.md`` § Cryptography.
"""

from __future__ import annotations

import random
import string
from typing import Final

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..exceptions import ProtocolError

#: The fixed secret that seals the LOGIN 401 challenge blob.
DEFAULT_SECRET: Final = "&#%@!_eufy_anker"  # noqa: S105 (protocol constant, not a secret)

#: Public exponent of the server's RSA key.
RSA_EXPONENT: Final = 0x10001

#: Hex length of the 1024-bit RSA modulus; any other length is refused.
RSA_MODULUS_HEX_LEN: Final = 256

#: Length of a session key, in characters.
SESSION_KEY_LEN: Final = 16

#: The alphabet of every random key: digits, then lower, then upper case.
KEY_ALPHABET: Final = string.digits + string.ascii_lowercase + string.ascii_uppercase

_BLOCK: Final = 16


def _as_int32(value: int) -> int:
    """``value`` as a signed 32-bit integer."""
    low = value & 0xFFFFFFFF
    return low - 0x100000000 if low >= 0x80000000 else low


def derive_key(secret: str, salt: int) -> bytes:
    """The 16-byte AES key for ``salt``: ``secret`` padded to 16 bytes, its tail
    overwritten by the decimal of the signed 32-bit ``salt``, then cut at the first NUL
    and zero-padded back to 16."""
    key = bytearray(secret.encode()[:_BLOCK].ljust(_BLOCK, b"\0"))
    decimal = str(_as_int32(salt)).encode()
    key[_BLOCK - len(decimal) : _BLOCK] = decimal
    return bytes(key).split(b"\0", 1)[0].ljust(_BLOCK, b"\0")


def aes_ecb_encrypt(secret: str, salt: int, data: bytes) -> bytes:
    """``data`` AES-128-ECB encrypted with ``derive_key(secret, salt)``, zero-padded to
    a multiple of the block size (empty input yields empty output)."""
    cipher = Cipher(algorithms.AES(derive_key(secret, salt)), modes.ECB())  # noqa: S305 (protocol)
    enc = cipher.encryptor()
    return enc.update(data + b"\0" * (-len(data) % _BLOCK)) + enc.finalize()


def aes_ecb_decrypt(secret: str, salt: int, data: bytes) -> bytes:
    """The inverse of :func:`aes_ecb_encrypt`; the zero padding is left on (callers cut
    at the first NUL). Raises :class:`~.exceptions.ProtocolError` for a length that is
    not a whole number of blocks."""
    if len(data) % _BLOCK:
        raise ProtocolError("RTC ciphertext is not a whole number of AES blocks")
    cipher = Cipher(algorithms.AES(derive_key(secret, salt)), modes.ECB())  # noqa: S305 (protocol)
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def rsa_modulus(public_key: str) -> int:
    """The RSA modulus of a LOGIN challenge: exactly 256 hex digits (no sign or prefix).
    Raises :class:`~.exceptions.ProtocolError` otherwise."""
    if len(public_key) != RSA_MODULUS_HEX_LEN:
        raise ProtocolError(
            f"RTC LOGIN challenge is not a {RSA_MODULUS_HEX_LEN}-character RSA modulus"
        )
    if not all(c in string.hexdigits for c in public_key):
        raise ProtocolError("RTC LOGIN challenge modulus is not hexadecimal")
    return int(public_key, 16)


class RtcSignalingCrypto:
    """The signaling's cryptographic operations, at the points the signaling uses them.

    ``rng`` draws the random key material; it defaults to :class:`random.SystemRandom`.
    Pass a seeded :class:`random.Random` only in tests.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.SystemRandom()

    def open_challenge(self, body: bytes, salt: int) -> str:
        """The server's public key (hex text) from a LOGIN 401 body, salted with the
        401's packet id."""
        plain = aes_ecb_decrypt(DEFAULT_SECRET, salt, body)
        return plain.split(b"\0", 1)[0].decode("ascii", "replace").strip()

    def new_session_key(self) -> str:
        """A fresh session key for one login."""
        return self._random(SESSION_KEY_LEN)

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        """``session_key`` sealed for the server: the key exchange's first blob. Raises
        :class:`~.exceptions.ProtocolError` for a modulus no RSA key can be built from or
        too small for the key."""
        modulus = rsa_modulus(public_key)
        try:
            key = rsa.RSAPublicNumbers(e=RSA_EXPONENT, n=modulus).public_key()
            return key.encrypt(session_key.encode(), padding.PKCS1v15())
        except ValueError as exc:
            raise ProtocolError(f"RTC LOGIN challenge modulus is unusable: {exc}") from exc

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        """``data`` sealed with ``session_key``, salted with a packet id."""
        return aes_ecb_encrypt(session_key, salt, data)

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        """The inverse of :meth:`seal`, zero padding left on."""
        return aes_ecb_decrypt(session_key, salt, data)

    def new_media_secret(self, length: int) -> str:
        """A random ``length``-character secret: a private call's content key or IV."""
        return self._random(length)

    def _random(self, length: int) -> str:
        return "".join(self._rng.choice(KEY_ALPHABET) for _ in range(length))
