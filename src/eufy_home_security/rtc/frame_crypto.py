"""In-frame AES-128-GCM decryption of an RTC live view.

The device encrypts only the HEVC parameter sets and the IDR slice inside the
media frames; every other NAL unit (VPS, non-key slices) and every P-frame is in
clear. This is read from the app's native depacketizer (``jingle.so``:
``decryptIDRAesGcm``, ``DecryptSPSPPSAesGcm`` and their callers in the h264/h265
depacketizer): each encrypted NAL unit is

    ``[2-byte HEVC NAL header] [AES-128-GCM ciphertext] [16-byte tag]``

decrypted with the call's content key and IV used **as-is** (the key is the 16
ASCII bytes of ``content_key``, the nonce the 12 ASCII bytes of ``content_iv``),
**no additional authenticated data**, the tag the last 16 bytes of the unit. The
decrypted payload replaces the ciphertext; the 2-byte NAL header stays. The IV is
constant for the call, so it is reused across frames — the device's design.

This covers H.265 (the codec eufy stations stream). The same scheme in the app's
H.264 path skips a 1-byte NAL header; it is not implemented here because it is not
exercised by the verified hardware.
"""

from __future__ import annotations

from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import ProtocolError
from .media import START_CODE
from .sdp import SdpInfo

#: HEVC NAL unit types the device encrypts: SPS, PPS and the IDR_W_RADL slice.
_ENCRYPTED_HEVC_TYPES: Final = frozenset({19, 33, 34})
_HEVC_HEADER_LEN: Final = 2
_GCM_TAG_LEN: Final = 16
#: The shortest encryptable unit: header, one ciphertext byte, the tag.
_MIN_ENCRYPTED_NAL: Final = _HEVC_HEADER_LEN + 1 + _GCM_TAG_LEN


class EufyFrameDecryptor:
    """Decrypts the device's in-frame AES-128-GCM with a call's content key/IV.

    ``content_key`` and ``content_iv`` are the ASCII strings carried in the
    sdp_info the device encrypts with (its CALL-200 answer): a 16-character key
    and a 12-character IV (:meth:`~.sdp.SdpInfo.decode`).
    """

    def __init__(self, content_key: str, content_iv: str) -> None:
        key = content_key.encode("ascii")
        self._iv = content_iv.encode("ascii")
        if len(key) != 16:
            raise ProtocolError(f"RTC content key is {len(key)} bytes, need 16")
        if len(self._iv) != 12:
            raise ProtocolError(f"RTC content IV is {len(self._iv)} bytes, need 12")
        self._gcm = AESGCM(key)

    @classmethod
    def from_answer(cls, answer: SdpInfo) -> EufyFrameDecryptor:
        """Key the decryptor from the device's CALL-200 answer ``sdp_info``.

        The app decrypts incoming device media with the content key/IV of the
        **device's** answer (its remote SDP), not the app's own — confirmed from
        the native path ``WebrtcApp_Event_NewSetRemoteSDP_Info`` →
        ``handle_media_channel_connect_event`` → ``setMediaChannelKey``.
        """
        return cls(answer.content_key, answer.content_iv)

    def video(self, frame: bytes, *, keyframe: bool) -> bytes:
        """Return ``frame`` (an Annex B access unit) with its encrypted HEVC NAL
        units decrypted. A frame with no encrypted unit is returned unchanged;
        ``keyframe`` is accepted for the :class:`~.media.FrameDecryptor` interface
        and not required (only key frames carry encrypted units)."""
        del keyframe
        out = bytearray()
        for header, nal in self._split_annex_b(frame):
            out += header
            out += self._decrypt_nal(nal)
        return bytes(out)

    def audio(self, frame: bytes) -> bytes:
        raise NotImplementedError("RTC audio in-frame decryption is not implemented")

    def _decrypt_nal(self, nal: bytes) -> bytes:
        if len(nal) < _MIN_ENCRYPTED_NAL:
            return nal
        if ((nal[0] >> 1) & 0x3F) not in _ENCRYPTED_HEVC_TYPES:
            return nal
        header, blob = nal[:_HEVC_HEADER_LEN], nal[_HEVC_HEADER_LEN:]
        try:
            # blob is ciphertext || 16-byte tag, which is what AESGCM.decrypt wants.
            plaintext = self._gcm.decrypt(self._iv, blob, None)
        except InvalidTag as exc:
            raise ProtocolError("RTC in-frame GCM authentication failed") from exc
        return header + plaintext

    @staticmethod
    def _split_annex_b(frame: bytes) -> list[tuple[bytes, bytes]]:
        """Split an Annex B bitstream into (start code, NAL unit) pairs."""
        parts: list[tuple[bytes, bytes]] = []
        i = frame.find(START_CODE)
        if i != 0:  # tolerate a 3-byte start code at the head
            i = frame.find(b"\x00\x00\x01")
        while i != -1 and i < len(frame):
            code_len = 4 if frame[i : i + 4] == START_CODE else 3
            body_start = i + code_len
            nxt4 = frame.find(START_CODE, body_start)
            nxt3 = frame.find(b"\x00\x00\x01", body_start)
            nxt = min(x for x in (nxt4, nxt3) if x != -1) if (nxt4 != -1 or nxt3 != -1) else -1
            end = nxt if nxt != -1 else len(frame)
            parts.append((frame[i:body_start], frame[body_start:end]))
            i = nxt
        return parts
