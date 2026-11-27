"""Command and notification encryption on an RTC call.

Commands the client sends the station (in an RTCP APP packet or over the data
channel) and the notifications and replies the station sends back are AES-128-GCM
with the AAD ``b"eufy security"`` under the call's media key, the station's
``crypto_key``. A command is an XZYH frame whose body is replaced by
``tag | iv | counter | ciphertext``; a reply carries the same wrapper after its frame
header, a notification ``tag | iv | ciphertext``.

Declared (eufy app); not verified on hardware. Where the key comes from is inferred,
not established: a HomeBase 3's CALL 200 carries no ``crypto_key``, only its
``sdp_info``, so the first 16 bytes of that answer's content key are the likely key
(:func:`media_key`). See
``docs/protocol/rtc-signaling.md`` § Command encryption.
"""

from __future__ import annotations

import os
import struct
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import ProtocolError
from ..p2p.crypto import GCM_AAD
from ..p2p.xzyh import HEADER_LEN as FRAME_HEADER_LEN

#: The media key is an AES-128 key: the first 16 bytes of the key text.
MEDIA_KEY_LEN: Final = 16
_GCM_IV_LEN: Final = 12
_GCM_TAG_LEN: Final = 16
_COUNTER_LEN: Final = 4
#: XZYH subheader version byte of a GCM-sealed command.
VERSION_GCM: Final = 10
#: What precedes a command's ciphertext: GCM tag, IV and the command counter.
_WRAPPER_LEN: Final = _GCM_TAG_LEN + _GCM_IV_LEN + _COUNTER_LEN


def is_sealed(frame: bytes) -> bool:
    """Whether an XZYH ``frame``'s header marks its body GCM-sealed (version byte 10)."""
    return len(frame) >= FRAME_HEADER_LEN and frame[0x0A] == VERSION_GCM


def media_key(content_key: str | bytes) -> bytes:
    """The 16-byte media key of a ``crypto_key`` or content key (the source is inferred;
    see the module docstring). Raises :class:`~.exceptions.ProtocolError` for a shorter
    one."""
    raw = content_key.encode() if isinstance(content_key, str) else bytes(content_key)
    if len(raw) < MEDIA_KEY_LEN:
        raise ProtocolError("RTC media key is shorter than 16 bytes")
    return raw[:MEDIA_KEY_LEN]


def encrypt_command(key: bytes, frame: bytes, counter: int, *, iv: bytes | None = None) -> bytes:
    """An XZYH command ``frame`` (16-byte header + body) sealed for the station.

    Sets the header's version byte to 10, its encrypted flag and its length, and
    replaces the body with ``tag | iv | counter | ciphertext``. ``counter`` is the
    per-call command counter (carried in the clear, outside the GCM). ``iv`` defaults to
    a fresh random nonce. Raises :class:`ValueError` for a frame shorter than its header
    or an IV that is not 12 bytes.
    """
    if len(frame) < FRAME_HEADER_LEN:
        raise ValueError("RTC command frame is shorter than its header")
    nonce = iv if iv is not None else os.urandom(_GCM_IV_LEN)
    if len(nonce) != _GCM_IV_LEN:
        raise ValueError("RTC command IV is not 12 bytes")
    sealed = AESGCM(key).encrypt(nonce, frame[FRAME_HEADER_LEN:], GCM_AAD)
    ciphertext, tag = sealed[:-_GCM_TAG_LEN], sealed[-_GCM_TAG_LEN:]
    header = bytearray(frame[:FRAME_HEADER_LEN])
    header[0x0A] = VERSION_GCM
    header[0x0D] = 1
    struct.pack_into("<I", header, 0x06, len(ciphertext) + _WRAPPER_LEN)
    return bytes(header) + tag + nonce + struct.pack("<I", counter & 0xFFFFFFFF) + ciphertext


def _open(keys: tuple[bytes | None, ...], payload: bytes, skip: int, what: str) -> bytes:
    """``payload`` = ``tag | iv | <skip bytes> | ciphertext`` opened with the first key
    that authenticates it."""
    if len(payload) < _GCM_TAG_LEN + _GCM_IV_LEN + skip:
        raise ProtocolError(f"RTC {what} payload is too short")
    tag = payload[:_GCM_TAG_LEN]
    nonce = payload[_GCM_TAG_LEN : _GCM_TAG_LEN + _GCM_IV_LEN]
    ciphertext = payload[_GCM_TAG_LEN + _GCM_IV_LEN + skip :]
    for key in keys:
        if key is None:
            continue
        try:
            return AESGCM(key).decrypt(nonce, ciphertext + tag, GCM_AAD)
        except InvalidTag:
            continue
    raise ProtocolError(f"RTC {what} did not authenticate")


def decrypt_notification(key: bytes, payload: bytes, *, previous_key: bytes | None = None) -> bytes:
    """A station notification's payload (``tag | iv | ciphertext``, after its frame
    header), opened with ``key``, else ``previous_key`` (the station keeps the previous
    key usable across a key change). Raises :class:`~.exceptions.ProtocolError` when
    neither authenticates it or it is too short."""
    return _open((key, previous_key), payload, 0, "notification")


def decrypt_command_reply(
    key: bytes, payload: bytes, *, previous_key: bytes | None = None
) -> bytes:
    """A station command reply's payload (``tag | iv | counter | ciphertext``, after its
    frame header), opened like :func:`decrypt_notification`."""
    return _open((key, previous_key), payload, _COUNTER_LEN, "command reply")


class CommandCipher:
    """A call's media key for commands, notifications and replies: counts the commands
    and keeps the previous key usable across a :meth:`rotate`."""

    def __init__(
        self, content_key: str | bytes, *, previous_key: str | bytes | None = None
    ) -> None:
        self._key = media_key(content_key)
        self._previous = media_key(previous_key) if previous_key is not None else None
        self._counter = 0

    def encrypt(self, frame: bytes, *, iv: bytes | None = None) -> bytes:
        """Seal an XZYH command ``frame`` and advance the counter."""
        packet = encrypt_command(self._key, frame, self._counter, iv=iv)
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        return packet

    def decrypt_notification(self, payload: bytes) -> bytes:
        """Open a station notification payload (current key, then the previous)."""
        return decrypt_notification(self._key, payload, previous_key=self._previous)

    def decrypt_reply(self, payload: bytes) -> bytes:
        """Open a station command reply payload (current key, then the previous)."""
        return decrypt_command_reply(self._key, payload, previous_key=self._previous)

    def rotate(self, content_key: str | bytes) -> None:
        """Adopt a new media key, keeping the current one as the fallback."""
        self._previous, self._key = self._key, media_key(content_key)
