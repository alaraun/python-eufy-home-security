"""Command and notification encryption on the RTC media plane.

Commands the client sends the station (over an RTCP APP packet or the KCP data
channel) and the notifications the station sends back are AES-128-GCM with the
fixed AAD ``b"eufy security"`` under the per-call media key (the ``crypto_key`` from
the device's CALL/INFO attach). The command path is an XZYH frame whose body is
replaced by the GCM wrapper; a notification is the same wrapper after its frame
header.

Declared (eufy app); not verified on hardware.
"""

from __future__ import annotations

import os
import struct
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import SignalingError
from ..p2p.crypto import GCM_AAD
from ..p2p.xzyh import HEADER_LEN as FRAME_HEADER_LEN

#: The media key is an AES-128 key: the first 16 bytes of ``crypto_key``.
MEDIA_KEY_LEN: Final = 16
_GCM_IV_LEN: Final = 12
_GCM_TAG_LEN: Final = 16
#: XZYH subheader version byte of a GCM-encrypted command or notification.
_VERSION_GCM: Final = 10
#: The wrapper that precedes the ciphertext: GCM tag, IV and the command counter.
_WRAPPER_LEN: Final = _GCM_TAG_LEN + _GCM_IV_LEN + 4


def _key16(key: str | bytes) -> bytes:
    raw = key.encode() if isinstance(key, str) else bytes(key)
    if len(raw) < MEDIA_KEY_LEN:
        raise SignalingError("RTC media key is shorter than 16 bytes")
    return raw[:MEDIA_KEY_LEN]


def encrypt_command(key: bytes, frame: bytes, counter: int, *, iv: bytes | None = None) -> bytes:
    """An XZYH command ``frame`` (16-byte header + body) sealed for the station.

    Rewrites the header (version byte 10, encrypted flag, length) and replaces the
    body with ``tag | iv | counter | ciphertext``; the body is AES-128-GCM with the
    AAD :data:`~.p2p.crypto.GCM_AAD`. ``counter`` is the per-session command counter
    (stored in the packet, not part of the GCM). ``iv`` defaults to a fresh random
    nonce.
    """
    if len(frame) < FRAME_HEADER_LEN:
        raise SignalingError("RTC command frame is shorter than its header")
    nonce = iv if iv is not None else os.urandom(_GCM_IV_LEN)
    if len(nonce) != _GCM_IV_LEN:
        raise SignalingError("RTC command IV is not 12 bytes")
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, frame[FRAME_HEADER_LEN:], GCM_AAD)
    ciphertext, tag = ciphertext_and_tag[:-_GCM_TAG_LEN], ciphertext_and_tag[-_GCM_TAG_LEN:]
    header = bytearray(frame[:FRAME_HEADER_LEN])
    header[0x0A] = _VERSION_GCM
    header[0x0D] = 1
    struct.pack_into("<I", header, 0x06, len(ciphertext) + _WRAPPER_LEN)
    return bytes(header) + tag + nonce + struct.pack("<I", counter & 0xFFFFFFFF) + ciphertext


def decrypt_notification(key: bytes, payload: bytes, *, previous_key: bytes | None = None) -> bytes:
    """A station notification's payload (``tag | iv | ciphertext``, after its frame
    header) opened with the media key.

    Tries ``key`` then ``previous_key`` (the station keeps the previous key usable
    across a key change). Raises :class:`~.exceptions.SignalingError` when neither
    authenticates.
    """
    if len(payload) < _GCM_TAG_LEN + _GCM_IV_LEN:
        raise SignalingError("RTC notification payload is too short")
    tag = payload[:_GCM_TAG_LEN]
    nonce = payload[_GCM_TAG_LEN : _GCM_TAG_LEN + _GCM_IV_LEN]
    ciphertext = payload[_GCM_TAG_LEN + _GCM_IV_LEN :]
    for candidate in (key, previous_key):
        if candidate is None:
            continue
        try:
            return AESGCM(candidate).decrypt(nonce, ciphertext + tag, GCM_AAD)
        except InvalidTag:
            continue
    raise SignalingError("RTC notification did not authenticate")


class CommandCipher:
    """The per-call media key for commands and notifications; tracks the command
    counter and keeps the previous key usable across a :meth:`rotate`."""

    def __init__(self, crypto_key: str | bytes, *, previous_key: str | bytes | None = None) -> None:
        self._key = _key16(crypto_key)
        self._previous = _key16(previous_key) if previous_key is not None else None
        self._counter = 0

    def encrypt(self, frame: bytes, *, iv: bytes | None = None) -> bytes:
        """Seal an XZYH command ``frame`` and advance the counter."""
        packet = encrypt_command(self._key, frame, self._counter, iv=iv)
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        return packet

    def decrypt_notification(self, payload: bytes) -> bytes:
        """Open a station notification payload (current key, then the previous)."""
        return decrypt_notification(self._key, payload, previous_key=self._previous)

    def rotate(self, crypto_key: str | bytes) -> None:
        """Adopt a new media key, keeping the current one as the fallback."""
        self._previous, self._key = self._key, _key16(crypto_key)
