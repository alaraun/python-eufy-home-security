"""Pure camera-media helpers: keyframe decrypt, media-frame parsing, request shapes.

Live video and clip downloads both arrive on DRW ch1 as XZYH VIDEO_FRAME
(0x0514) / AUDIO_FRAME (0x0515) records. This module holds only the pure parts —
no sockets, no ffmpeg:

* :func:`generate_media_rsa_key` / :func:`generate_media_ecc_key` mint the per-stream
  key pair whose public half the client hands the station in the open command; the
  station wraps the stream's AES key to it (:class:`MediaKeyType`).
* :func:`video_variant` / :func:`audio_variant` read how a record is protected from its
  XZYH subheader, as the app's media receiver does.
* :func:`parse_video_frame` / :func:`parse_audio_frame` split the media header.
* :class:`MediaDecoder` turns one stream's records into playable
  :class:`MediaFrame` objects: it undoes the small encrypted header prefix of a
  record that carries the RSA-wrapped stream key (other RSA-stream records are clear),
  or the AES-256-GCM of an ECC stream's records, unwrapping each stream key once.
* the ``*_payload`` builders shape the ``payload`` object of the open / download
  commands.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..devices.recipes import station_live_payload
from ..exceptions import ProtocolError, UnsupportedError
from .crypto import GCM_AAD, ecb_decrypt, ecies_decrypt, gcm_decrypt_broadcast
from .xzyh import Frame, FrameCipher, FrameType

#: XZYH frame types carried on the media channel.
VIDEO_FRAME_TYPE = FrameType.VIDEO_FRAME
AUDIO_FRAME_TYPE = FrameType.AUDIO_FRAME

#: Media header sizes (the u32le body length plus per-stream flags/timestamps).
VIDEO_HEADER_LEN = 22
AUDIO_HEADER_LEN = 16

#: Video codec codes carried in the video header's byte 5, matching the read-only
#: ``support_video_codec`` enum of the thing description (``0:H264, 1:H265``).
VIDEO_CODEC_H264 = 0
VIDEO_CODEC_HEVC = 1

#: The media clock both headers carry is in milliseconds; MPEG timestamps are 90 kHz.
MEDIA_CLOCK_HZ = 1000
PTS_CLOCK_HZ = 90_000

#: Keyframe body layout: an RSA-wrapped AES key, a marker byte, then an AES-ECB
#: header prefix over exactly 8 blocks, then clear HEVC.
KEYFRAME_RSA_LEN = 128
_KEYFRAME_MARKER = 1
_KEYFRAME_ENC_PREFIX = 128
KEYFRAME_MIN = KEYFRAME_RSA_LEN + _KEYFRAME_MARKER + _KEYFRAME_ENC_PREFIX  # 257
_KEYFRAME_AES_KEY_LEN = 16
_KEYFRAME_FLAG_OFFSET = 4

#: ECC video record: the 22-byte video header, the ECIES-wrapped stream key, the GCM tag
#: and IV, then the AES-256-GCM body (``video_encrypt_gcm`` in the app).
ECC_WRAPPED_KEY_LEN = 129
_GCM_TAG_LEN = 16
_GCM_IV_LEN = 12
_ECC_VIDEO_WRAPPED = slice(VIDEO_HEADER_LEN, VIDEO_HEADER_LEN + ECC_WRAPPED_KEY_LEN)
_ECC_VIDEO_TAG = slice(_ECC_VIDEO_WRAPPED.stop, _ECC_VIDEO_WRAPPED.stop + _GCM_TAG_LEN)
_ECC_VIDEO_IV = slice(_ECC_VIDEO_TAG.stop, _ECC_VIDEO_TAG.stop + _GCM_IV_LEN)
ECC_VIDEO_HEADER_LEN = _ECC_VIDEO_IV.stop  # 179
#: ECC audio record: the 16-byte audio header, the GCM tag and IV, then the body; the
#: key is the one the stream's video records carry (``audio_info_ecc`` in the app).
_ECC_AUDIO_TAG = slice(AUDIO_HEADER_LEN, AUDIO_HEADER_LEN + _GCM_TAG_LEN)
_ECC_AUDIO_IV = slice(_ECC_AUDIO_TAG.stop, _ECC_AUDIO_TAG.stop + _GCM_IV_LEN)
ECC_AUDIO_HEADER_LEN = _ECC_AUDIO_IV.stop  # 44
_GCM_MEDIA_KEY_LEN = 32
#: Param 1103 (``CAMERA_INFO``) from which the app offers an ECC media key.
ECC_MEDIA_ABILITY = 128

#: XZYH subheader bytes the app's media receiver reads.
_SUB_MEDIA_VERSION = 0
_SUB_ENCRYPTED = 3
_SUB_AUDIO_KIND = 5
_FLOODLIGHT_AUDIO = 3
#: Audio header byte 5: the stream type; 0 is AAC-LC.
_AUDIO_STREAM_TYPE_OFFSET = 5
_AUDIO_STREAM_AAC = 0

#: First NAL header byte of a picture-group start (the app's IDR test): HEVC IDR_W_RADL,
#: IDR_N_LP, CRA, VPS, SPS, PPS; H.264 IDR, SPS, PPS (``nal_ref_idc`` 3), SPS (``nal_ref_idc`` 1).
_GOP_START_NAL = frozenset({0x26, 0x28, 0x2A, 0x40, 0x42, 0x44, 0x65, 0x67, 0x68, 0x27})


class VideoVariant(StrEnum):
    """How a VIDEO_FRAME record is protected, read from its XZYH subheader.

    Byte 0 is the media version ``v``, byte 3 the encrypted flag ``e``; the app's
    receiver picks its path from these two alone (see :func:`video_variant`).
    """

    PLAIN = "plain"
    """A clear body after the 22-byte header (a HomeBase 3 P-frame: ``v`` 1, ``e`` 0)."""
    RSA_PREFIX = "rsa_prefix"
    """The 128-byte RSA-wrapped AES-128 key and a marker byte, then a body whose first
    128 bytes are AES-128-ECB (a HomeBase 3 keyframe: ``v`` 1, ``e`` 1)."""
    RSA_V3 = "rsa_v3"
    """``v`` 3 or more with ``e`` 1: a clear body after the 22-byte header."""
    ECC = "ecc"
    """``v`` 8 or 9: the ECIES-wrapped stream key, then an AES-256-GCM body, for a client
    that offered an ECC key (:attr:`MediaKeyType.ECC`)."""
    E2E = "e2e"
    """``v`` 4 or 5 with ``e`` 2 or more: end-to-end encrypted (the app plays it only from
    recordings). Not decoded."""


UNDECODABLE_VIDEO = frozenset({VideoVariant.E2E})
"""The variants :class:`MediaDecoder` never decodes (ECC needs a stream opened with an
ECC key, :meth:`MediaDecoder.decodes`)."""


def video_variant(subheader: bytes) -> VideoVariant:
    """The protection of a VIDEO_FRAME record from its subheader, by the app's rule."""
    if len(subheader) <= _SUB_ENCRYPTED:
        return VideoVariant.PLAIN
    version, encrypted = subheader[_SUB_MEDIA_VERSION], subheader[_SUB_ENCRYPTED]
    if version in (4, 5) and encrypted >= 2:
        return VideoVariant.E2E
    if version in (8, 9):
        return VideoVariant.ECC
    if version >= 3 and encrypted == 1:
        return VideoVariant.RSA_V3
    if version and encrypted:
        return VideoVariant.RSA_PREFIX
    return VideoVariant.PLAIN


class AudioVariant(StrEnum):
    """What an AUDIO_FRAME record carries, read from its subheader and header."""

    AAC = "aac"
    """One clear ADTS AAC-LC frame after the 16-byte header."""
    IGNORED = "ignored"
    """Media version 0 (or an unknown floodlight version): the app plays nothing."""
    G711 = "g711"
    """Floodlight audio (subheader byte 5 = 3, version 1): G.711 A-law. Not decoded."""
    ECC = "ecc"
    """Media version 8 or 9: AES-256-GCM under the key of the stream's video records."""
    E2E = "e2e"
    """Media version 4 or 5 with the encrypted flag 2 or more. Not decoded."""
    OTHER = "other"
    """A clear frame whose header names a stream type other than AAC-LC. Not decoded."""


def audio_variant(subheader: bytes, payload: bytes) -> AudioVariant:
    """What an AUDIO_FRAME record carries, by the app's rule.

    The subheader decides first (floodlight, ECC, E2E, version 0); a plain record of
    version 1 is AAC-LC, any other version names its stream type in header byte 5.
    """
    if len(subheader) <= _SUB_AUDIO_KIND:
        return AudioVariant.AAC
    version, encrypted = subheader[_SUB_MEDIA_VERSION], subheader[_SUB_ENCRYPTED]
    if subheader[_SUB_AUDIO_KIND] == _FLOODLIGHT_AUDIO:
        return {1: AudioVariant.G711, 2: AudioVariant.AAC}.get(version, AudioVariant.IGNORED)
    if version in (8, 9):
        return AudioVariant.ECC
    if version in (4, 5) and encrypted >= 2:
        return AudioVariant.E2E
    if version == 0:
        return AudioVariant.IGNORED
    if version == 1 or len(payload) <= _AUDIO_STREAM_TYPE_OFFSET:
        return AudioVariant.AAC
    if payload[_AUDIO_STREAM_TYPE_OFFSET] == _AUDIO_STREAM_AAC:
        return AudioVariant.AAC
    return AudioVariant.OTHER


def media_variant_label(frame_type: int, payload: bytes, subheader: bytes) -> str | None:
    """``"video:<variant>"`` / ``"audio:<variant>"`` for a media record (diagnostics);
    None for another frame type."""
    if frame_type == VIDEO_FRAME_TYPE:
        return f"video:{video_variant(subheader)}"
    if frame_type == AUDIO_FRAME_TYPE:
        return f"audio:{audio_variant(subheader, payload)}"
    return None


def starts_picture_group(data: bytes) -> bool:
    """Whether Annex-B ``data`` opens with an IDR picture or a parameter set (HEVC or
    H.264): the app's keyframe test, applied to the first NAL unit only."""
    if data.startswith(b"\x00\x00\x00\x01"):
        start = 4
    elif data.startswith(b"\x00\x00\x01"):
        start = 3
    else:
        return False
    return len(data) > start and data[start] in _GOP_START_NAL


class MediaKeyType(StrEnum):
    """The key pair a client offers in a live open; the station protects the stream for it."""

    RSA = "rsa"
    """An RSA-1024 modulus (256 hex chars): RSA-wrapped AES-128 keyframe prefixes."""
    ECC = "ecc"
    """A P-256 public key (128 hex chars): every record AES-256-GCM, its key ECIES-wrapped."""


def media_key_type_for(camera_info: int | None) -> MediaKeyType:
    """The key the app offers a device with param 1103 ``camera_info`` (None: absent):
    ECC from :data:`ECC_MEDIA_ABILITY`, else RSA."""
    if camera_info is not None and camera_info >= ECC_MEDIA_ABILITY:
        return MediaKeyType.ECC
    return MediaKeyType.RSA


def generate_media_ecc_key() -> tuple[str, ec.EllipticCurvePrivateKey]:
    """Mint a per-stream P-256 key pair; return ``(public_hex_upper, private_key)``.

    The public key is ``X ‖ Y`` (32 bytes each, big-endian) as 128 uppercase hex chars,
    the form the app's ``GetCrypto(8)`` returns.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    numbers = priv.public_key().public_numbers()
    return format(numbers.x, "064X") + format(numbers.y, "064X"), priv


def generate_media_rsa_key() -> tuple[str, rsa.RSAPrivateKey]:
    """Mint a per-session RSA-1024 keypair; return ``(modulus_hex_upper, private_key)``.

    The station PKCS#1 v1.5-wraps the per-session AES-128 video key to this
    modulus, so the key exists only because the client asked for it — nothing
    device-side is read. RSA-1024 is what the station's command expects; it is not a
    security parameter the client can choose.
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    modulus = priv.public_key().public_numbers().n
    return format(modulus, "0256X"), priv


class VideoCodec(StrEnum):
    """The codec of a video stream, from the video header's byte 5."""

    HEVC = "hevc"
    """H.265. What eufy cameras emit."""
    H264 = "h264"
    """H.264. Declared by the thing description's ``support_video_codec`` enum."""

    @classmethod
    def from_code(cls, code: int) -> VideoCodec | None:
        """The codec for a header code, or None for an unknown code."""
        if code == VIDEO_CODEC_HEVC:
            return cls.HEVC
        if code == VIDEO_CODEC_H264:
            return cls.H264
        return None


def ms_to_pts(milliseconds: int) -> int:
    """A header's millisecond stamp as 90 kHz MPEG ticks (exact: 90 ticks per ms)."""
    return milliseconds * (PTS_CLOCK_HZ // MEDIA_CLOCK_HZ)


@dataclass(frozen=True, slots=True)
class VideoFrame:
    """A parsed VIDEO_FRAME payload.

    The 22-byte header is ``[u32le datalen][u8 keyframe][u8 codec][u32le counter]
    [u16le width][u16le height][u32le timestamp_ms][4 bytes]``. Only ``datalen`` and
    the keyframe flag are needed to play a frame; the rest is what a muxer needs.
    """

    is_keyframe: bool
    data: bytes
    timestamp_ms: int = 0
    """The stream clock in milliseconds; shared with :attr:`AudioFrame.timestamp_ms`.

    Free-running from an arbitrary origin (station uptime, not wall clock), and it
    does **not** restart per stream, so use differences, never the absolute value.
    """
    codec: VideoCodec | None = None
    """The stream's codec, or None for an unknown header code."""
    width: int = 0
    height: int = 0
    """Frame size. It **changes mid-stream**: a camera behind a station starts at the
    sensor's full resolution and steps down to the streaming quality, a standalone camera
    starts small and climbs (see :mod:`.encoder`); each step is on a keyframe with fresh
    parameter sets."""
    counter: int = 0
    """The header's u32le frame counter. Its high 16 bits are a stream tag on a
    HomeBase 3 (``0x000f0000`` seen), so compare ``counter & 0xFFFF``."""
    variant: VideoVariant = VideoVariant.PLAIN
    """How the record is protected; :attr:`VideoVariant.RSA_PREFIX` bodies still
    carry the wrapped-key prefix that :meth:`MediaDecoder.decrypt_keyframe` strips."""

    @property
    def pts(self) -> int:
        """:attr:`timestamp_ms` in 90 kHz MPEG ticks."""
        return ms_to_pts(self.timestamp_ms)


@dataclass(frozen=True, slots=True)
class AudioFrame:
    """A parsed AUDIO_FRAME payload: one ADTS AAC-LC frame and its header fields.

    The 16-byte header is ``[u32le datalen][u16le ?][u16le counter][u32le timestamp_ms]
    [4 bytes]``.
    """

    data: bytes
    timestamp_ms: int = 0
    """The stream clock in milliseconds, the same clock as :attr:`VideoFrame.timestamp_ms`."""
    counter: int = 0
    """The header's u16le counter. **Not a frame index on every station**: on a
    HomeBase 3 it ticks ~40 ms while frames are 64 ms apart (AAC-LC, 1024 samples at
    16 kHz), so it advances by 1 or 2 per frame. Use :attr:`timestamp_ms` for timing."""

    @property
    def pts(self) -> int:
        """:attr:`timestamp_ms` in 90 kHz MPEG ticks."""
        return ms_to_pts(self.timestamp_ms)


def is_keyframe_record(payload: bytes) -> bool:
    """Whether a VIDEO_FRAME payload is flagged as a keyframe (a header peek, no decode)."""
    return len(payload) > _KEYFRAME_FLAG_OFFSET and payload[_KEYFRAME_FLAG_OFFSET] == 0x01


def _resolve_variant(payload: bytes, variant: VideoVariant | None) -> VideoVariant:
    """``variant``, or without a subheader the HomeBase 3 rule: a flagged keyframe
    carries the wrapped key, any other record is clear."""
    if variant is not None:
        return variant
    return VideoVariant.RSA_PREFIX if is_keyframe_record(payload) else VideoVariant.PLAIN


def video_record_is_key(payload: bytes, variant: VideoVariant | None = None) -> bool:
    """Whether a VIDEO_FRAME record starts a picture group (a header peek, no decrypt).

    A record carrying the RSA-wrapped key always does; a clear one when its header flags
    a keyframe or its first NAL unit is an IDR picture or a parameter set; an encrypted
    one (ECC) only by the header flag.
    """
    variant = _resolve_variant(payload, variant)
    if variant is VideoVariant.RSA_PREFIX or is_keyframe_record(payload):
        return True
    if variant in (VideoVariant.ECC, VideoVariant.E2E):
        return False
    return starts_picture_group(payload[VIDEO_HEADER_LEN : VIDEO_HEADER_LEN + 8])


def parse_video_frame(payload: bytes, *, variant: VideoVariant | None = None) -> VideoFrame:
    """Split a VIDEO_FRAME payload into its header fields and body bytes.

    Layout: ``[u32le datalen][18 header bytes][body]``; ``payload[4]`` (the first
    header byte after datalen) is the keyframe flag, ``payload[5]`` the codec (see
    :class:`VideoCodec`), then a u32le counter, u16le width, u16le height and a u32le
    millisecond timestamp.

    ``variant`` comes from the record's subheader (:func:`video_variant`); without
    one, a flagged keyframe is taken as :attr:`VideoVariant.RSA_PREFIX` and any other
    record as clear. :data:`UNDECODABLE_VIDEO` variants raise :class:`UnsupportedError`.
    An :attr:`VideoVariant.ECC` record's body is its ciphertext after the 179-byte
    header, whole (the app decrypts all of it), and only its header flag marks a keyframe.

    ``datalen`` counts the frame as it **decodes**, not the bytes on the wire. A
    wrapped-key body also carries the 129-byte prefix that
    :meth:`MediaDecoder.decrypt_keyframe` strips (128 bytes of RSA ciphertext plus the
    marker), so its record is 129 bytes longer than ``datalen`` — verified on a T8160,
    where decrypting the whole body yields exactly ``datalen`` bytes. Cutting the body
    at ``datalen`` therefore loses the *end* of every keyframe, which a decoder shows
    as unwritten green blocks in the bottom-right corner of the picture. Take the whole
    body and let the decrypt decide its length. A clear body is cut at ``datalen``.

    A body shorter than datalen raises :class:`ProtocolError`.
    """
    if len(payload) < VIDEO_HEADER_LEN:
        raise ProtocolError(f"video frame shorter than its {VIDEO_HEADER_LEN}-byte media header")
    data_len = struct.unpack_from("<I", payload, 0)[0]
    if data_len > len(payload) - VIDEO_HEADER_LEN:
        raise ProtocolError(
            f"video frame truncated: datalen {data_len}, "
            f"{len(payload) - VIDEO_HEADER_LEN} body bytes present"
        )
    counter, width, height, timestamp_ms = struct.unpack_from("<IHHI", payload, 6)
    variant = _resolve_variant(payload, variant)
    if variant in UNDECODABLE_VIDEO:
        raise UnsupportedError(f"{variant.value} video is not decoded by this library")
    if variant is VideoVariant.ECC:
        if len(payload) < ECC_VIDEO_HEADER_LEN:
            raise ProtocolError(
                f"ECC video frame shorter than its {ECC_VIDEO_HEADER_LEN}-byte header"
            )
        return VideoFrame(
            is_keyframe=is_keyframe_record(payload),
            data=payload[ECC_VIDEO_HEADER_LEN:],
            timestamp_ms=timestamp_ms,
            codec=VideoCodec.from_code(payload[5]),
            width=width,
            height=height,
            counter=counter,
            variant=variant,
        )
    # A clear body is exactly datalen long and a station may pad the datagram; a
    # wrapped-key body's extra bytes are the prefix the decrypt consumes.
    prefixed = variant is VideoVariant.RSA_PREFIX
    end = len(payload) if prefixed else VIDEO_HEADER_LEN + data_len
    body = payload[VIDEO_HEADER_LEN:end]
    return VideoFrame(
        is_keyframe=video_record_is_key(payload, variant),
        data=body,
        timestamp_ms=timestamp_ms,
        codec=VideoCodec.from_code(payload[5]),
        width=width,
        height=height,
        counter=counter,
        variant=variant,
    )


def parse_audio_frame(payload: bytes) -> AudioFrame:
    """The clear ADTS AAC-LC body of an AUDIO_FRAME payload, with its header fields.

    A body shorter than datalen raises :class:`ProtocolError`.
    """
    if len(payload) < AUDIO_HEADER_LEN:
        raise ProtocolError(f"audio frame shorter than its {AUDIO_HEADER_LEN}-byte media header")
    data_len = struct.unpack_from("<I", payload, 0)[0]
    if data_len > len(payload) - AUDIO_HEADER_LEN:
        raise ProtocolError(
            f"audio frame truncated: datalen {data_len}, "
            f"{len(payload) - AUDIO_HEADER_LEN} body bytes present"
        )
    counter, timestamp_ms = struct.unpack_from("<HI", payload, 6)
    return AudioFrame(
        data=payload[AUDIO_HEADER_LEN : AUDIO_HEADER_LEN + data_len],
        timestamp_ms=timestamp_ms,
        counter=counter,
    )


class MediaKind(StrEnum):
    """What a :class:`MediaFrame` carries."""

    VIDEO = "video"
    """Annex-B HEVC."""
    AUDIO = "audio"
    """One ADTS AAC-LC frame."""


@dataclass(frozen=True, slots=True)
class MediaFrame:
    """One playable media frame: decrypted, header stripped."""

    kind: MediaKind
    data: bytes
    is_keyframe: bool = False
    timestamp_ms: int = 0
    """The station's stream clock in milliseconds, shared by both tracks.

    Free-running from an arbitrary origin and continuous across streams, so a muxer
    must use differences from its own first frame, never the absolute value.
    """
    codec: VideoCodec | None = None
    """Video only: the codec this frame is coded with, or None if unknown."""
    width: int = 0
    height: int = 0
    """Video only: the frame size, which **changes mid-stream** (see :class:`VideoFrame`)."""

    @property
    def pts(self) -> int:
        """:attr:`timestamp_ms` in 90 kHz MPEG ticks."""
        return ms_to_pts(self.timestamp_ms)


class _ForeignKeyframeError(ProtocolError):
    """A keyframe that was not wrapped for this stream's RSA key, or that does not decode.

    Raised when the wrapped key does not unwrap to 16 bytes, when the unwrap itself
    fails, and (by :class:`~.session.MediaStream`) when the decrypted keyframe is not
    Annex-B. Before a stream's first keyframe this is usually a keyframe of another
    stream; after it, with the stream's own wrapped key, the keyframe is corrupt.
    """


class MediaDecoder:
    """Decode the media records of one stream opened with ``rsa_private_key`` or
    ``ecc_private_key`` (the key whose public half the open offered).

    The wrapped AES key is the same in every keyframe of a stream, so the unwrap runs
    once and is reused while the wrapped bytes stay the same.
    """

    __slots__ = ("_aes_key", "_ecc_key_hex", "_rsa_key", "_wrapped")

    def __init__(
        self,
        rsa_private_key: rsa.RSAPrivateKey | None = None,
        *,
        ecc_private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        if (rsa_private_key is None) == (ecc_private_key is None):
            raise ValueError("pass exactly one of rsa_private_key or ecc_private_key")
        self._rsa_key = rsa_private_key
        self._ecc_key_hex = (
            None
            if ecc_private_key is None
            else format(ecc_private_key.private_numbers().private_value, "064x")
        )
        self._wrapped: bytes | None = None
        self._aes_key = b""

    @property
    def key_type(self) -> MediaKeyType:
        """The key type the stream was opened with."""
        return MediaKeyType.RSA if self._rsa_key is not None else MediaKeyType.ECC

    @property
    def aes_key(self) -> bytes:
        """The stream's unwrapped AES key (AES-128 on an RSA stream, AES-256 on an ECC
        one); empty until a record carrying it was decrypted."""
        return self._aes_key

    def decodes(self, variant: VideoVariant) -> bool:
        """Whether this stream's key decodes video of ``variant``: RSA-wrapped keyframes
        need the RSA key, ECC records the ECC key; E2E is never decoded."""
        if variant in UNDECODABLE_VIDEO:
            return False
        if variant is VideoVariant.ECC:
            return self._ecc_key_hex is not None
        if variant is VideoVariant.RSA_PREFIX:
            return self._rsa_key is not None
        return True

    def decode(
        self, frame_type: int, payload: bytes, subheader: bytes | None = None
    ) -> MediaFrame | None:
        """A playable frame from one XZYH media record.

        ``subheader`` is the record's XZYH subheader: it selects the protection
        (:func:`video_variant`, :func:`audio_variant`), as the app's receiver does.
        Without it (None or empty), a flagged keyframe is taken to carry the wrapped key
        and audio to be AAC. None for other frame types and for audio that is not AAC-LC; video the
        library does not decode raises :class:`UnsupportedError`.
        """
        if frame_type == VIDEO_FRAME_TYPE:
            variant = video_variant(subheader) if subheader else None
            if variant is not None and not self.decodes(variant):
                raise UnsupportedError(
                    f"{variant.value} video does not decode with an {self.key_type.value} key"
                )
            video = parse_video_frame(payload, variant=variant)
            is_keyframe = video.is_keyframe
            if video.variant is VideoVariant.ECC:
                data = self.decrypt_ecc_video(payload)
                is_keyframe = is_keyframe or starts_picture_group(data[:8])
            elif video.variant is VideoVariant.RSA_PREFIX:
                data = self.decrypt_keyframe(video.data)
            else:
                data = video.data
            return MediaFrame(
                MediaKind.VIDEO,
                data,
                is_keyframe=is_keyframe,
                timestamp_ms=video.timestamp_ms,
                codec=video.codec,
                width=video.width,
                height=video.height,
            )
        if frame_type == AUDIO_FRAME_TYPE:
            kind = audio_variant(subheader, payload) if subheader else AudioVariant.AAC
            if kind is AudioVariant.ECC:
                clear = self.decrypt_ecc_audio(payload)
                if clear is None:
                    return None
                payload = clear
            elif kind is not AudioVariant.AAC:
                return None
            audio = parse_audio_frame(payload)
            return MediaFrame(MediaKind.AUDIO, audio.data, timestamp_ms=audio.timestamp_ms)
        return None

    def _gcm_key(self, wrapped: bytes) -> bytes:
        """The AES-256 key an ECC record's ECIES-wrapped bytes carry, unwrapped once per
        distinct wrap. The app keeps up to 32 plaintext bytes, zero-padded."""
        if wrapped == self._wrapped:
            return self._aes_key
        if self._ecc_key_hex is None:
            raise UnsupportedError("ECC media on a stream opened with an RSA key")
        try:
            plain = ecies_decrypt(wrapped, self._ecc_key_hex, ECC_WRAPPED_KEY_LEN)
        except ProtocolError as exc:
            raise _ForeignKeyframeError(
                f"ECC record not wrapped for this stream's key ({exc})"
            ) from exc
        if not plain:
            raise _ForeignKeyframeError("ECC record unwrapped to an empty key")
        key = plain[:_GCM_MEDIA_KEY_LEN].ljust(_GCM_MEDIA_KEY_LEN, b"\x00")
        self._aes_key, self._wrapped = key, wrapped
        return key

    def decrypt_ecc_video(self, payload: bytes) -> bytes:
        """An ECC VIDEO_FRAME record's Annex-B body: ``payload[22:151]`` is the
        ECIES-wrapped AES-256 key, ``[151:167]`` the GCM tag, ``[167:179]`` the IV, and
        everything after the AES-256-GCM ciphertext (AAD ``b"eufy security"``).

        A record wrapped for another key raises :class:`_ForeignKeyframeError`, a body
        that fails its tag :class:`ProtocolError`.
        """
        if len(payload) < ECC_VIDEO_HEADER_LEN:
            raise ProtocolError(
                f"ECC video frame shorter than its {ECC_VIDEO_HEADER_LEN}-byte header"
            )
        key = self._gcm_key(bytes(payload[_ECC_VIDEO_WRAPPED]))
        return _gcm_open(
            key,
            payload[_ECC_VIDEO_IV],
            payload[ECC_VIDEO_HEADER_LEN:],
            payload[_ECC_VIDEO_TAG],
        )

    def decrypt_ecc_audio(self, payload: bytes) -> bytes | None:
        """An ECC AUDIO_FRAME record as a clear audio record (its 16-byte header, then
        the body): ``payload[16:32]`` is the GCM tag, ``[32:44]`` the IV, the rest the
        ciphertext, under the key of the stream's video records.

        None before a video record brought the key, or when header byte 5 names a stream
        type other than AAC-LC.
        """
        if len(payload) < ECC_AUDIO_HEADER_LEN:
            raise ProtocolError(
                f"ECC audio frame shorter than its {ECC_AUDIO_HEADER_LEN}-byte header"
            )
        if self._ecc_key_hex is None or not self._aes_key:
            return None
        if payload[_AUDIO_STREAM_TYPE_OFFSET] != _AUDIO_STREAM_AAC:
            return None
        body = _gcm_open(
            self._aes_key,
            payload[_ECC_AUDIO_IV],
            payload[ECC_AUDIO_HEADER_LEN:],
            payload[_ECC_AUDIO_TAG],
        )
        return bytes(payload[:AUDIO_HEADER_LEN]) + body

    def decrypt_keyframe(self, video_body: bytes) -> bytes:
        """Decrypt a keyframe body to Annex-B HEVC.

        Only a fixed header prefix is encrypted: ``body[0:128]`` is the RSA-wrapped
        16-byte AES-128 key (constant for the stream), ``body[128]`` a marker, and
        ``body[129:257]`` AES-128-ECB over the first 128 bytes (VPS/SPS/PPS + slice
        header). The rest is clear. A body too short to hold the prefix is returned
        unchanged (a P-frame is already clear and needs no decrypt).

        A keyframe wrapped for another RSA key raises :class:`_ForeignKeyframeError`
        and leaves the stream key as it was. A wrong key rarely makes the unwrap
        raise: OpenSSL 3.2 and later apply implicit rejection to PKCS#1 v1.5 and
        return a pseudo-random plaintext of random length instead (measured: 18 of 20
        wrong-key unwraps returned 6-117 bytes on OpenSSL 4.0.1). The length check is
        therefore the real guard here; the 1-in-100 wrong key that comes out at 16
        bytes is caught by the caller's Annex-B check on the result.
        """
        if len(video_body) < KEYFRAME_MIN:
            return video_body
        if self._rsa_key is None:
            raise UnsupportedError("an RSA-wrapped keyframe on a stream opened with an ECC key")
        wrapped = video_body[0:KEYFRAME_RSA_LEN]
        if wrapped != self._wrapped:
            try:
                aes_key = self._rsa_key.decrypt(wrapped, padding.PKCS1v15())
            except ValueError as exc:
                raise _ForeignKeyframeError(
                    f"keyframe not wrapped for this stream's key (RSA unwrap failed: {exc})"
                ) from exc
            if len(aes_key) != _KEYFRAME_AES_KEY_LEN:
                raise _ForeignKeyframeError(
                    f"keyframe not wrapped for this stream's key "
                    f"(unwrapped to {len(aes_key)} bytes, not 16)"
                )
            # Pinned only once the length is right: a failed unwrap never replaces the key.
            self._aes_key, self._wrapped = aes_key, wrapped
        start = KEYFRAME_RSA_LEN + _KEYFRAME_MARKER
        # Exactly 8 whole blocks, no padding: ecb_decrypt's block-aligned case.
        clear_prefix = ecb_decrypt(self._aes_key, video_body[start:KEYFRAME_MIN])
        # One copy of the (megabyte-sized) clear tail, not three.
        return b"".join((clear_prefix, memoryview(video_body)[KEYFRAME_MIN:]))


def _gcm_open(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """AES-256-GCM decrypt of one media body (AAD :data:`~.crypto.GCM_AAD`)."""
    try:
        return AESGCM(key).decrypt(bytes(iv), bytes(ciphertext) + bytes(tag), GCM_AAD)
    except InvalidTag as exc:
        raise ProtocolError("ECC media record failed its GCM tag") from exc


def start_realtime_media_payload(
    account_id: str, channel: int, key_hex: str, *, homebase3: bool = True
) -> dict[str, Any]:
    """The CMD_START_REALTIME_MEDIA (1003) payload object; ``key_hex`` is the client's RSA
    modulus.

    ``homebase3`` adds what the app sends to a T8030 only (``extValue``, the channel
    list entry, ``stitch_mode``, ``audio_chn``, ``station_video_type``, ``pip_cord``);
    without it the payload is the camera handler's ``openLiveStream1350`` one, which the
    app sends to every other station (:func:`~..devices.recipes.station_live_payload`).
    """
    if not homebase3:
        return station_live_payload(account_id, key_hex)
    return {
        "streamtype": 0,
        "camera_type": 0,
        "entrytype": 0,
        "accountId": account_id,
        "chn_list": [{"cameraType": 0, "chn": channel, "index": 0, "sensor": 0}],
        "ClientOS": "ANDROID",
        "station_video_type": 0,
        "audio_chn": 0,
        "pip_cord": "",
        "stitch_mode": 1,
        "key": key_hex,
        "extValue": 1000,
    }


def stop_realtime_media_payload(account_id: str, channel: int) -> dict[str, Any]:
    """The CMD_STOP_REALTIME_MEDIA (1004) payload object."""
    return {"accountId": account_id, "chn_list": [{"chn": channel}]}


def _video_by_path_payload(path: str, key_hex: str) -> dict[str, Any]:
    """Shared shape for the by-path video commands: ``{filepath, key}`` where ``key``
    is the client's RSA modulus. Frames come back on the media channel like live video."""
    return {"filepath": path, "key": key_hex}


def download_video_payload(path: str, key_hex: str) -> dict[str, Any]:
    """The CMD_DOWNLOAD_VIDEO (1024) payload object."""
    return _video_by_path_payload(path, key_hex)


def record_view_payload(path: str, key_hex: str) -> dict[str, Any]:
    """The CMD_RECORD_VIEW (1025) payload — play a stored ``.zxvideo`` recording.

    Identical shape to the download; ``path`` is a
    history row's ``storage_path``. The frames arrive like live media.
    """
    return _video_by_path_payload(path, key_hex)


#: The ``RECORD_PLAY_CTRL`` (0x0402) value that ends a playback: the app's
#: ``ControlEvent`` STOP. The station sends it about 0.5 s after the last frame.
PLAYBACK_ENDED = 2
#: A clear control body is this short; anything longer is GCM ``tag ‖ nonce ‖ ct``.
_PLAY_CTRL_CLEAR_MAX = 8


def decode_record_play_ctrl(frame: Frame, session_key: bytes | None) -> int | None:
    """The control value of a station ``RECORD_PLAY_CTRL`` (0x0402) frame, or None.

    Seen under the GCM tag with the 5-byte body ``02 00 00 00 00`` at the end of a
    1025 playback (:data:`PLAYBACK_ENDED`). The value is the body's first ``u32le``.
    A body longer than :data:`_PLAY_CTRL_CLEAR_MAX` is decrypted under the session key
    first. None for another frame type or cipher, a body too short to carry a value,
    or ciphertext that does not authenticate.
    """
    if frame.type != FrameType.RECORD_PLAY_CTRL or frame.cipher != FrameCipher.GCM:
        return None
    body = frame.payload
    if len(body) > _PLAY_CTRL_CLEAR_MAX:
        if session_key is None:
            return None
        try:
            body = gcm_decrypt_broadcast(session_key, body)
        except ProtocolError:
            return None
    if len(body) < 4:
        return None
    return int(struct.unpack_from("<I", body)[0])


class StillFormat(StrEnum):
    """What a 1308 still's bytes are. The obfuscated variants' values are their magics."""

    JPEG = "jpeg"
    V1 = "eufysecurity"
    """AES-128-ECB over the first 256 bytes, keyed by serial, DID and a header code
    (:func:`decode_v1_still`)."""
    V2 = "v2_eufysecurity"
    """AES-256-GCM over the first 256 bytes; key derivation unknown, not decoded."""
    V8 = "v8_eufysecurity"
    """AES-256-GCM over the whole body, per-image key from the cloud."""
    UNKNOWN = "unknown"


_JPEG_MAGIC = b"\xff\xd8"
#: Longest magic first: ``v2_eufysecurity`` must not be read as V1's ``eufysecurity``.
_OBFUSCATED_STILLS = tuple(
    sorted((StillFormat.V1, StillFormat.V2, StillFormat.V8), key=len, reverse=True)
)


def classify_still(data: bytes) -> StillFormat:
    """Classify a still by its magic bytes (no decoding)."""
    if data.startswith(_JPEG_MAGIC):
        return StillFormat.JPEG
    for fmt in _OBFUSCATED_STILLS:
        if data.startswith(fmt.value.encode()):
            return fmt
    return StillFormat.UNKNOWN


# ── V1 still decoding (the app's gen_pic_code_v1) ──────────────────────────────

#: ``eufysecurity:<serial 16>:<code 10>:<body>``; the app reads the fields at these offsets.
_V1_SN = slice(13, 29)
_V1_CODE = slice(30, 40)
_V1_SEPARATORS = (12, 29, 40)
_V1_BODY = 41
#: Bytes of the body under AES-128-ECB (no padding); the rest is clear JPEG.
V1_ENCRYPTED_LEN = 256

_DID_PARTS = re.compile(r"([^-]+)-([^-]+)-(.*)")


def _hex_digit(char: str) -> int:
    """One character as ``sscanf("%x")`` reads it; 0 where that matches nothing."""
    return int(char, 16) if char in "0123456789abcdefABCDEF" else 0


def _did_suffix(did: str) -> int:
    """``cal_ppcs_id_suffix``: a small sum over four digits of the DID's number
    (a 6-digit PPCS or 9-digit WebRTC number), 100 for any other shape."""
    match = _DID_PARTS.fullmatch(did)
    number = match.group(2) if match else ""
    if len(number) == 6:
        picks = (0, 1, 3, 5)
    elif len(number) == 9:
        picks = (0, 5, 6, 8)
    else:
        return 100
    first, second, third, last = (_hex_digit(number[i]) for i in picks)
    return first + second + third + (third if third < 5 else 0) + last


def pic_check_code(serial: str, did: str, code: str) -> str:
    """The app's ``gen_pic_code_v1(serial, did, code)``: 32 upper-case hex characters.

    ``code`` is the 10 digits of a V1 still's header; the first 16 characters of the
    result are its AES-128 key.
    """
    suffix = _did_suffix(did)
    base = serial[_hex_digit(serial[-1]) % 10 :] + str(suffix)
    seed = hashlib.md5(f"{1000 - suffix}{int(code[2:10])}".encode()).hexdigest().upper()  # noqa: S324 (protocol)
    digest = bytearray(hashlib.sha256(f"01{base}{seed}".encode()).digest())
    for i in range(32):
        byte = digest[i]
        after = digest[10] if i == 31 else digest[i + 1]
        if i % 2 == 0 and i != 31:
            if byte < 0x7D or after <= 0x7C:
                digest[i] = (byte + after) & 0xFF
        elif byte > 0x7E or after >= 0x7F:
            digest[i] = abs(byte - after)
    return digest[16:].hex().upper()


def decode_v1_still(data: bytes, did: str) -> bytes:
    """The JPEG inside a V1 (``eufysecurity``) still, with the station's P2P DID.

    Raises :class:`ProtocolError` for a malformed header or a body that does not
    decrypt to a JPEG (a wrong DID).
    """
    if classify_still(data) is not StillFormat.V1:
        raise ProtocolError("not a V1 still")
    if any(data[i : i + 1] != b":" for i in _V1_SEPARATORS):
        raise ProtocolError("V1 still header is malformed")
    body = data[_V1_BODY:]
    if len(body) < V1_ENCRYPTED_LEN:
        raise ProtocolError(f"V1 still body is {len(body)} bytes, under {V1_ENCRYPTED_LEN}")
    try:
        serial, code = data[_V1_SN].decode("ascii"), data[_V1_CODE].decode("ascii")
        key = pic_check_code(serial, did, code)[:16].encode()
    except (UnicodeDecodeError, ValueError) as err:
        raise ProtocolError("V1 still header is malformed") from err
    image = ecb_decrypt(key, body[:V1_ENCRYPTED_LEN]) + body[V1_ENCRYPTED_LEN:]
    if not image.startswith(_JPEG_MAGIC):
        raise ProtocolError("V1 still did not decrypt to a JPEG")
    return image


@dataclass(frozen=True, slots=True)
class Still:
    """One still off the station's disk, labelled with the format it came in.

    A V1 still whose key the session could derive holds the decoded JPEG in
    ``data`` (``format`` stays ``V1``). Other obfuscated variants are returned as
    they came: they are not images, and they cannot be decoded yet.
    """

    path: str
    data: bytes
    format: StillFormat

    @property
    def is_image(self) -> bool:
        """Whether ``data`` is a displayable picture (a JPEG)."""
        return self.data.startswith(_JPEG_MAGIC)
