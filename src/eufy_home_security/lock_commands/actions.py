"""The lock action, the result of an answer, and helpers every lock form shares."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Final

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..exceptions import ProtocolError

API_ON_OFF: Final = 6018
"""The app's api number of lock/unlock; 1940 and 1930 payloads carry it as ``apiCommand``."""

_BLOCK: Final = 16


class LockAction(IntEnum):
    """What a command asks for, as the app's ``slOperation`` value."""

    UNLOCK = 0
    LOCK = 1


class LockResult(StrEnum):
    """What a lock answered to a lock or unlock command."""

    ACCEPTED = "accepted"
    """Taken; the state change follows (the app waits for the new state)."""
    ALREADY_UNLOCKED = "already_unlocked"
    """An unlock while the lock was already unlocked."""
    ALREADY_LOCKED = "already_locked"
    """A lock while the lock was already locked."""
    REFUSED = "refused"
    """Any other code: not applied."""


@dataclass(frozen=True, slots=True)
class LockReply:
    """A lock's answer: its raw result code and what it means."""

    code: int
    result: LockResult


def serial_iv(serial: str) -> bytes:
    """The AES IV every lock form uses: the serial's UTF-8 bytes zero-padded to 16.

    The app uses a 16-byte or longer serial whole; AES needs exactly 16, so a longer one
    raises :class:`ValueError`, as does an empty one.
    """
    raw = serial.encode()
    if not raw or len(raw) > _BLOCK:
        raise ValueError(f"lock serial must be 1..16 bytes, got {len(raw)}")
    return raw.ljust(_BLOCK, b"\0")


def cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC with PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def cbc_decrypt(blob: bytes, key: bytes, iv: bytes) -> bytes:
    """Inverse of :func:`cbc_encrypt`; :class:`ProtocolError` when ``blob`` does not open."""
    if not blob or len(blob) % _BLOCK:
        raise ProtocolError(f"lock answer ciphertext is {len(blob)} bytes, not whole AES blocks")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(blob) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except ValueError as exc:
        raise ProtocolError("lock answer does not decrypt under the request's key") from exc


def hex_bytes(text: str, what: str) -> bytes:
    """``text`` as hex, the app's way (an odd length gains a leading 0); ValueError if not hex."""
    if len(text) % 2:
        text = "0" + text
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{what} is not hex: {text!r}") from exc
