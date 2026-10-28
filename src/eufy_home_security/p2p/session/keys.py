"""The cipher state of one station connection: the handshake's keys and the send sequences."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from ...exceptions import StationUnreachableError
from ..crypto import (
    FRAME_PLAIN,
    FRAME_SESSION_ECB,
    FRAME_STATIC_ECB,
    GCM_SEQ_START,
    STATIC_KEY_FALLBACK_MODELS,
    ecb_decrypt,
    frame_encryption,
)
from ..xzyh import Frame, FrameCipher

_RSA_STATE_ENCRYPTIONS: Mapping[int | None, str] = MappingProxyType(
    {FRAME_PLAIN: "clear", FRAME_STATIC_ECB: "type1", FRAME_SESSION_ECB: "type2"}
)
"""An RSA session's state-frame label by encryption type (subheader byte 3)."""


class SessionKeys:
    """The keys a handshake left (GCM session key, RSA AES key, static key) and the
    sequence numbers of the frames sent under them, as each handshake sets them.
    The frame predicates answer which key a frame of this connection is under."""

    def __init__(self, serial: str) -> None:
        self.serial = serial
        self.rsa_keyless = False
        """Whether the last RSA handshake left no session key: no cipher named, or its
        RSA key does not parse. The session then runs under the static key."""
        self.static_key: bytes | None = None
        self.session_key: bytes | None = None
        """The GCM session key of an ECIES handshake."""
        self.aes_key: bytes | None = None
        """The AES-128 session key of an RSA handshake: every frame is ECB under it."""
        self.gcm_seq = GCM_SEQ_START
        self.gcm_counter = 0
        self.ecb_seq = 0

    @property
    def rsa_session(self) -> bool:
        """See :attr:`StationSession.rsa_session`."""
        return self.aes_key is not None

    @property
    def static_key_session(self) -> bool:
        """See :attr:`StationSession.static_key_session`."""
        return self.aes_key is not None and self.aes_key == self.static_key

    @property
    def session_encryption(self) -> int:
        """Encryption type of the frames an RSA session sends: 2 under a delivered key;
        without one (no cipher named, or a key that does not parse), 1 (static key) to a
        model of :data:`~..crypto.STATIC_KEY_FALLBACK_MODELS` and 0 (clear) to any other."""
        if not self.rsa_keyless:
            return FRAME_SESSION_ECB
        if self.serial.startswith(STATIC_KEY_FALLBACK_MODELS):
            return FRAME_STATIC_ECB
        return FRAME_PLAIN

    def scalar_cipher(self) -> tuple[bytes, int]:
        """Key and encryption type of an ECB scalar frame: the session key on an RSA
        session (every command goes under it), else the static key."""
        key = self.require_static_key()
        if self.aes_key is not None:
            return self.aes_key, self.session_encryption
        return key, FRAME_STATIC_ECB

    def state_encryption(self, frame: Frame) -> str:
        """A state frame's label in :attr:`SessionStats.state_frames_by_encryption`."""
        if self.aes_key is None:
            return "gcm" if frame.cipher == FrameCipher.GCM else "ecb"
        return _RSA_STATE_ENCRYPTIONS.get(frame_encryption(frame.subheader), "other")

    @property
    def holds_own_key(self) -> bool:
        """Whether the session holds a key only it and the station know: a GCM session
        key, or an RSA session key that is not the static key."""
        if self.aes_key is not None:
            return not self.static_key_session
        return self.session_key is not None

    def ecb_key(self, frame: Frame) -> bytes | None:
        """The key of an ECB-tagged station frame: the RSA session's key when its
        encryption type (subheader byte 3) is 2, else the static key."""
        if self.aes_key is not None and frame_encryption(frame.subheader) == FRAME_SESSION_ECB:
            return self.aes_key
        return self.static_key

    def rsa_plaintext(self, frame: Frame) -> bytes | None:
        """An RSA session frame's body under the key its encryption type (subheader
        byte 3) names, as the eufy app takes it: clear as is, type 1 the static key,
        type 2 the session key; a partial last block stays as is. None on a GCM session
        or for another encryption type."""
        if self.aes_key is None:
            return None
        encryption = frame_encryption(frame.subheader)
        if encryption == FRAME_PLAIN:
            return frame.payload
        if encryption == FRAME_STATIC_ECB:
            key = self.static_key
        elif encryption == FRAME_SESSION_ECB:
            key = self.aes_key
        else:
            return None
        return None if key is None else ecb_decrypt(key, frame.payload)

    def session_ecb_frame(self, frame: Frame) -> bool:
        """Whether ``frame`` is ECB under an RSA session's key and so authenticated by the
        key only the cipher's owner could unwrap; never on a static-key session."""
        return (
            self.aes_key is not None
            and not self.static_key_session
            and frame.cipher == FrameCipher.ECB
            and frame_encryption(frame.subheader) == FRAME_SESSION_ECB
        )

    def session_key_frame(self, frame: Frame) -> bool:
        """Whether ``frame`` is ECB under an RSA session's key: encryption type 2, or
        type 1 on a static-key session, where both name the same key."""
        if self.aes_key is None or frame.cipher != FrameCipher.ECB:
            return False
        encryption = frame_encryption(frame.subheader)
        if encryption == FRAME_SESSION_ECB:
            return True
        return encryption == FRAME_STATIC_ECB and self.static_key_session

    def station_frame(self, frame: Frame) -> bool:
        """Whether an RSA session takes ``frame`` as the station's own: under its key, or
        clear on a static-key session, where clear authenticates no less than its key."""
        if self.session_key_frame(frame):
            return True
        return self.static_key_session and self.plain_rsa_frame(frame)

    def plain_rsa_frame(self, frame: Frame) -> bool:
        """Whether ``frame`` is an RSA session's clear frame (ECB tag, encryption type 0)."""
        return (
            self.aes_key is not None
            and frame.cipher == FrameCipher.ECB
            and frame_encryption(frame.subheader) == FRAME_PLAIN
        )

    def require_static_key(self) -> bytes:
        if self.static_key is None:
            raise StationUnreachableError("no P2P link")
        return self.static_key
