"""Camera-media pure helpers: keyframe decrypt, frame parsing, request shapes."""

from __future__ import annotations

import contextlib
import struct
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.exceptions import (
    EndToEndEncryptedError,
    PinProtectedKeyError,
    ProtocolError,
    UnsupportedError,
    VideoEncryptedPictureError,
)
from eufy_home_security.models import E2EKey, E2EKeyType
from eufy_home_security.p2p import crypto, media
from eufy_home_security.p2p.xzyh import Frame, FrameCipher, FrameType
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing import station as testing_station


def test_generate_media_rsa_key() -> None:
    mod_hex, priv = media.generate_media_rsa_key()
    assert len(mod_hex) == 256
    assert mod_hex == mod_hex.upper()
    assert isinstance(priv, rsa.RSAPrivateKey)
    assert priv.key_size == 1024


def test_parse_video_frame() -> None:
    body = b"HEVCDATA" * 4
    header = struct.pack("<I", len(body)) + b"\x01" + b"\x00" * 17  # keyframe flag: payload[4]
    frame = media.parse_video_frame(header + body)
    assert frame.is_keyframe
    assert frame.data == body
    # a P-frame (flag 0)
    header0 = struct.pack("<I", len(body)) + b"\x00" + b"\x00" * 17
    assert not media.parse_video_frame(header0 + body).is_keyframe


def test_parse_video_frame_reads_the_header_fields() -> None:
    """Codec, size, counter and the millisecond clock a muxer needs.

    Field layout as seen live: ``[u32le datalen][u8 keyframe][u8 codec][u32le counter]
    [u16le width][u16le height][u32le timestamp_ms][4 bytes]``.
    """
    body = b"HEVCDATA" * 4
    header = (
        struct.pack("<I", len(body))
        + bytes([1, media.VIDEO_CODEC_HEVC])
        + struct.pack("<IHHI", 983040, 3840, 2160, 3315877449)
        + b"\xa0\x01\x00\x00"
    )
    frame = media.parse_video_frame(header + body)
    assert frame.is_keyframe
    assert frame.data == body
    assert frame.codec is media.VideoCodec.HEVC
    assert (frame.width, frame.height) == (3840, 2160)
    assert frame.counter == 983040
    assert frame.timestamp_ms == 3315877449
    assert frame.pts == 3315877449 * 90


def test_parse_video_frame_reads_the_h264_codec_flag() -> None:
    """Byte 5 is the codec: 1 = HEVC, 0 = H.264 (``support_video_codec`` 0:H264, 1:H265)."""
    body = b"H264DATA"
    header = (
        struct.pack("<I", len(body))
        + bytes([1, media.VIDEO_CODEC_H264])
        + struct.pack("<IHHI", 1, 1920, 1080, 1000)
        + bytes(4)
    )
    assert media.parse_video_frame(header + body).codec is media.VideoCodec.H264
    # an unknown code is reported as unknown, not guessed
    unknown = struct.pack("<I", len(body)) + bytes([1, 9]) + bytes(16)
    assert media.parse_video_frame(unknown + body).codec is None


@pytest.mark.parametrize(
    ("version", "encrypted", "variant"),
    [
        (0, 0, media.VideoVariant.PLAIN),
        (1, 0, media.VideoVariant.PLAIN),
        (0, 1, media.VideoVariant.PLAIN),
        (1, 1, media.VideoVariant.RSA_PREFIX),
        (2, 1, media.VideoVariant.RSA_PREFIX),
        (2, 3, media.VideoVariant.RSA_PREFIX),
        (3, 1, media.VideoVariant.RSA_V3),
        (6, 1, media.VideoVariant.RSA_V3),
        (3, 2, media.VideoVariant.RSA_PREFIX),
        (4, 1, media.VideoVariant.RSA_V3),
        (4, 2, media.VideoVariant.E2E),
        (5, 7, media.VideoVariant.E2E),
        (8, 0, media.VideoVariant.ECC),
        (9, 1, media.VideoVariant.ECC),
    ],
)
def test_video_variant_follows_the_apps_subheader_rule(
    version: int, encrypted: int, variant: media.VideoVariant
) -> None:
    assert media.video_variant(bytes([version, 0, 1, encrypted, 10, 0])) is variant


def test_video_variant_of_a_short_subheader_is_plain() -> None:
    assert media.video_variant(b"\x01\x00\x01") is media.VideoVariant.PLAIN


@pytest.mark.parametrize(
    ("subheader", "stream_type", "variant"),
    [
        (bytes([2, 0, 0, 0, 10, 0]), 0, media.AudioVariant.AAC),
        (bytes([1, 0, 0, 0, 10, 0]), 4, media.AudioVariant.AAC),
        (bytes([2, 0, 0, 0, 10, 0]), 1, media.AudioVariant.OTHER),
        (bytes([0, 0, 0, 0, 10, 0]), 0, media.AudioVariant.IGNORED),
        (bytes([8, 0, 0, 1, 10, 0]), 0, media.AudioVariant.ECC),
        (bytes([4, 0, 0, 2, 10, 0]), 0, media.AudioVariant.E2E),
        (bytes([1, 0, 0, 0, 10, 3]), 0, media.AudioVariant.G711),
        (bytes([2, 0, 0, 0, 10, 3]), 0, media.AudioVariant.AAC),
        (bytes([0, 0, 0, 0, 10, 3]), 0, media.AudioVariant.IGNORED),
        (b"", 0, media.AudioVariant.AAC),
    ],
)
def test_audio_variant_follows_the_apps_rule(
    subheader: bytes, stream_type: int, variant: media.AudioVariant
) -> None:
    payload = struct.pack("<I", 2) + bytes([0, stream_type]) + bytes(10) + b"\xff\xf1"
    assert media.audio_variant(subheader, payload) is variant


def test_a_clear_record_without_a_subheader_or_flag_is_a_keyframe_by_its_first_nal() -> None:
    def record(body: bytes) -> bytes:
        return struct.pack("<I", len(body)) + bytes(18) + body

    idr_hevc = b"\x00\x00\x00\x01\x26\x01AAAA"
    sps_h264 = b"\x00\x00\x01\x67\x42AAAA"
    p_hevc = b"\x00\x00\x00\x01\x02\x01AAAA"
    plain = media.VideoVariant.PLAIN
    assert media.parse_video_frame(record(idr_hevc), variant=plain).is_keyframe
    assert media.parse_video_frame(record(sps_h264), variant=plain).is_keyframe
    assert not media.parse_video_frame(record(p_hevc), variant=plain).is_keyframe
    assert not media.parse_video_frame(record(b"garbage"), variant=plain).is_keyframe


def test_a_clear_keyframe_is_cut_at_datalen_and_not_decrypted() -> None:
    body = b"\x00\x00\x00\x01\x40\x01VPS"
    payload = struct.pack("<I", len(body)) + bytes([1, 1]) + bytes(16) + body + b"PAD"
    decoder = media.MediaDecoder(media.generate_media_rsa_key()[1])
    frame = decoder.decode(FrameType.VIDEO_FRAME, payload, bytes([3, 0, 1, 1, 10, 0]))
    assert frame is not None
    assert frame.is_keyframe
    assert frame.data == body


@pytest.mark.parametrize("subheader", [bytes([8, 0, 1, 1, 10, 0]), bytes([4, 0, 1, 2, 10, 0])])
def test_video_an_rsa_stream_does_not_decode_raises_unsupported(subheader: bytes) -> None:
    payload = struct.pack("<I", 4) + bytes(18) + b"BODY"
    decoder = media.MediaDecoder(media.generate_media_rsa_key()[1])
    with pytest.raises(UnsupportedError):
        decoder.decode(FrameType.VIDEO_FRAME, payload, subheader)


def test_audio_the_app_does_not_play_decodes_to_none() -> None:
    payload = struct.pack("<I", 2) + bytes(12) + b"\xff\xf1"
    decoder = media.MediaDecoder(media.generate_media_rsa_key()[1])
    assert decoder.decode(FrameType.AUDIO_FRAME, payload, bytes([0, 0, 1, 0, 10, 0])) is None
    assert decoder.decode(FrameType.AUDIO_FRAME, payload, bytes([2, 0, 1, 0, 10, 0])) is not None


def test_the_variant_label_names_the_media_kind() -> None:
    sub = bytes([1, 0, 1, 1, 10, 0])
    assert media.media_variant_label(FrameType.VIDEO_FRAME, b"", sub) == "video:rsa_prefix"
    assert media.media_variant_label(FrameType.AUDIO_FRAME, b"", sub) == "audio:aac"
    assert media.media_variant_label(FrameType.CMD_TRANSFER, b"", sub) is None


@pytest.mark.parametrize(
    ("camera_info", "key"),
    [
        (None, media.MediaKeyType.RSA),
        (-43, media.MediaKeyType.RSA),
        (127, media.MediaKeyType.RSA),
        (128, media.MediaKeyType.ECC),
        (255, media.MediaKeyType.ECC),
    ],
)
def test_the_app_offers_ecc_from_param_1103_128(
    camera_info: int | None, key: media.MediaKeyType
) -> None:
    assert media.media_key_type_for(camera_info) is key


def test_the_ecc_offer_is_the_uncompressed_point_without_its_prefix() -> None:
    public_hex, priv = media.generate_media_ecc_key()
    assert len(public_hex) == 128
    assert public_hex == public_hex.upper()
    point = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert point == b"\x04" + bytes.fromhex(public_hex)


def _ecc_decoder() -> tuple[media.MediaDecoder, testing_station.EccMediaKey]:
    public_hex, priv = media.generate_media_ecc_key()
    return media.MediaDecoder(ecc_private_key=priv), testing_station.EccMediaKey.for_offer(
        public_hex
    )


_ECC_SUB = bytes([8, 0, 1, 1, 10, 0])


def test_an_ecc_video_record_decrypts_to_its_clear_body() -> None:
    decoder, key = _ecc_decoder()
    body = b"\x00\x00\x00\x01\x40\x01" + bytes(300)
    record = testing_station.video_record(body, keyframe=True, counter=7, timestamp_ms=1000)
    sealed = testing_station.ecc_video_record(record, key)
    assert len(sealed) == len(record) + media.ECC_VIDEO_HEADER_LEN - media.VIDEO_HEADER_LEN
    frame = decoder.decode(FrameType.VIDEO_FRAME, sealed, _ECC_SUB)
    assert frame is not None
    assert (frame.data, frame.is_keyframe, frame.timestamp_ms) == (body, True, 1000)
    assert decoder.aes_key == key.key


def test_ecc_audio_waits_for_the_key_of_a_video_record() -> None:
    decoder, key = _ecc_decoder()
    audio = testing_station.ecc_audio_record(
        testing_station.audio_record(b"\xff\xf1AAC", timestamp_ms=5), key
    )
    assert decoder.decode(FrameType.AUDIO_FRAME, audio, _ECC_SUB) is None
    video = testing_station.video_record(b"\x00\x00\x00\x01\x02\x01", keyframe=False)
    decoder.decode(FrameType.VIDEO_FRAME, testing_station.ecc_video_record(video, key), _ECC_SUB)
    frame = decoder.decode(FrameType.AUDIO_FRAME, audio, _ECC_SUB)
    assert frame is not None
    assert (frame.data, frame.timestamp_ms) == (b"\xff\xf1AAC", 5)


def test_an_ecc_record_wrapped_for_another_key_is_foreign() -> None:
    decoder, _ = _ecc_decoder()
    _, other = _ecc_decoder()
    record = testing_station.video_record(b"\x00\x00\x00\x01\x26" + bytes(64), keyframe=True)
    with pytest.raises(media._ForeignKeyframeError):
        decoder.decode(
            FrameType.VIDEO_FRAME, testing_station.ecc_video_record(record, other), _ECC_SUB
        )
    assert decoder.aes_key == b""


def test_an_ecc_record_with_a_broken_tag_raises_protocol_error() -> None:
    decoder, key = _ecc_decoder()
    record = testing_station.video_record(b"\x00\x00\x00\x01\x26" + bytes(64), keyframe=True)
    sealed = bytearray(testing_station.ecc_video_record(record, key))
    sealed[-1] ^= 1
    with pytest.raises(ProtocolError, match="GCM tag"):
        decoder.decode(FrameType.VIDEO_FRAME, bytes(sealed), _ECC_SUB)


def test_a_decoder_decodes_the_variants_of_its_key() -> None:
    rsa_decoder = media.MediaDecoder(media.generate_media_rsa_key()[1])
    ecc_decoder, _ = _ecc_decoder()
    v = media.VideoVariant
    assert [rsa_decoder.decodes(x) for x in v] == [x not in (v.ECC, v.E2E) for x in v]
    assert [ecc_decoder.decodes(x) for x in v] == [x not in (v.RSA_PREFIX, v.E2E) for x in v]
    with pytest.raises(ValueError, match="exactly one"):
        media.MediaDecoder()


# ── end-to-end encrypted recordings ─────────────────────────────────────────

_E2E_SECRET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"  # 47 characters
_E2E_CIPHER = rsa.generate_private_key(65537, 1024)  # noqa: S505 (protocol)
_E2E_SUB = bytes([5, 0, 1, 7, 10, 0])  # version 5, key id 7: the owner's cloud cipher 7


def _e2e_sealed(clear: bytes, secret: bytes = _E2E_SECRET) -> bytes:
    """``tag ‖ ciphertext``: AES-256-GCM, key = secret[0:32], IV = secret[31:47]."""
    sealed = AESGCM(secret[0:32]).encrypt(secret[31:47], clear, b"eufy security")
    return sealed[-16:] + sealed[:-16]


def _e2e_video(
    clear: bytes,
    *,
    keyframe: bool = True,
    wrapped_plain: bytes = _E2E_SECRET,
    cipher: rsa.RSAPrivateKey = _E2E_CIPHER,
    secret: bytes = _E2E_SECRET,
) -> bytes:
    """An end-to-end encrypted video record built from the layout: header, 128-byte RSA
    wrap, one byte, tag, ciphertext; ``datalen`` counts tag and ciphertext."""
    body = _e2e_sealed(clear, secret)
    wrap = cipher.public_key().encrypt(wrapped_plain, padding.PKCS1v15())
    header = struct.pack("<I", len(body)) + bytes([int(keyframe), media.VIDEO_CODEC_H264])
    header += struct.pack("<IHHI", 3, 1600, 1200, 2000) + bytes(4)
    return header + wrap + b"\x5a" + body


def _e2e_audio(clear: bytes, *, stream_type: int = 0) -> bytes:
    body = _e2e_sealed(clear)
    header = struct.pack("<I", len(body)) + bytes([0, stream_type]) + struct.pack("<HI", 4, 2040)
    return header + bytes(4) + body


def _e2e_decoder(**keys: rsa.RSAPrivateKey) -> media.MediaDecoder:
    held = {int(k.removeprefix("c")): v for k, v in keys.items()}
    return media.MediaDecoder(media.generate_media_rsa_key()[1], e2e_keys=held)


_PICTURE = b"\x00\x00\x00\x01\x67" + bytes(200)


@pytest.mark.parametrize(
    ("version", "key_id", "expected"),
    [
        (5, 2, E2EKey(E2EKeyType.CIPHER, 2)),
        (5, 10, E2EKey(E2EKeyType.CIPHER, 10)),
        (4, 2, E2EKey(E2EKeyType.CIPHER, 2)),
        (4, 9, E2EKey(E2EKeyType.CIPHER, 9)),
        (4, 10, E2EKey(E2EKeyType.PIN, 10)),
        (4, 1, None),
        (5, 1, None),
        (3, 10, None),
        (6, 10, None),
        (8, 10, None),
    ],
)
def test_the_e2e_key_of_a_record_follows_the_apps_subheader_rule(
    version: int, key_id: int, expected: E2EKey | None
) -> None:
    assert media.e2e_key(bytes([version, 0, 0, key_id, 10, 0])) == expected


def test_a_short_subheader_names_no_e2e_key() -> None:
    assert media.e2e_key(bytes([4, 0, 0])) is None


def test_an_e2e_video_record_decrypts_under_its_cloud_cipher() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    frame = decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    assert frame is not None
    assert (frame.data, frame.is_keyframe, frame.timestamp_ms) == (_PICTURE, True, 2000)
    assert (frame.codec, frame.width, frame.height) == (media.VideoCodec.H264, 1600, 1200)
    assert decoder.aes_key == _E2E_SECRET[:32]


def test_an_unflagged_e2e_picture_group_start_is_a_keyframe() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    frame = decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE, keyframe=False), _E2E_SUB)
    assert frame is not None
    assert frame.is_keyframe


def test_the_e2e_key_string_ends_at_its_first_nul() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    record = _e2e_video(_PICTURE, wrapped_plain=_E2E_SECRET + b"\x00junk")
    frame = decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)
    assert frame is not None
    assert frame.data == _PICTURE


@pytest.mark.parametrize("plain", [_E2E_SECRET[:46], _E2E_SECRET + b"x", b"\x00" + _E2E_SECRET])
def test_an_e2e_key_string_that_is_not_47_bytes_is_foreign(plain: bytes) -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    with pytest.raises(media._ForeignKeyframeError, match="not 47"):
        decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE, wrapped_plain=plain), _E2E_SUB)


def test_an_e2e_record_wrapped_for_another_cipher_is_foreign() -> None:
    other = rsa.generate_private_key(65537, 1024)  # noqa: S505 (protocol)
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    with pytest.raises(media._ForeignKeyframeError):
        decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE, cipher=other), _E2E_SUB)
    assert decoder.aes_key == b""


def test_an_e2e_record_with_a_broken_tag_under_a_confirmed_key_raises_protocol_error() -> None:
    """A wrap whose key string already opened a record: a tag failure is a corrupt record."""
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    record = _e2e_video(_PICTURE)
    assert decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB) is not None
    broken = bytearray(record)
    broken[media.E2E_VIDEO_HEADER_LEN] ^= 1  # the tag's first byte
    with pytest.raises(ProtocolError, match="GCM tag") as err:
        decoder.decode(FrameType.VIDEO_FRAME, bytes(broken), _E2E_SUB)
    assert not isinstance(err.value, media._ForeignKeyframeError)


class _WrongUnwrap:
    """A cipher key whose unwrap gives 47 bytes that are not the record's key string, as an
    RSA unwrap under another key with implicit rejection does about once in a hundred."""

    def decrypt(self, _ciphertext: bytes, _padding: object) -> bytes:
        return bytes(range(65, 65 + 47))


def test_an_e2e_key_string_whose_first_tag_fails_is_foreign_and_not_kept() -> None:
    """An unwrap no record has confirmed, failing its tag, is another cipher's wrap: the
    record is foreign, and neither the key string nor the wrap is kept for the next one."""
    decoder = _e2e_decoder(c7=cast(rsa.RSAPrivateKey, _WrongUnwrap()))
    record = _e2e_video(_PICTURE)
    with pytest.raises(media._ForeignKeyframeError, match="failed its GCM tag"):
        decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)
    assert decoder.aes_key == b""
    assert decoder.decode(FrameType.AUDIO_FRAME, _e2e_audio(b"\xff\xf1AAC"), _E2E_SUB) is None
    decoder.add_e2e_key(7, _E2E_CIPHER)
    frame = decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)  # the same wrap
    assert frame is not None
    assert frame.data == _PICTURE


def test_an_e2e_record_too_short_for_its_tag_raises_protocol_error() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    cut = _e2e_video(_PICTURE)[: media.E2E_VIDEO_HEADER_LEN + 15]
    record = struct.pack("<I", 15) + cut[4:]
    with pytest.raises(ProtocolError, match="shorter than 167"):
        decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)


def test_the_e2e_key_unwraps_once_per_wrap() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    record = _e2e_video(_PICTURE)
    decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)
    decoder._e2e_keys = {7: rsa.generate_private_key(65537, 1024)}  # noqa: S505
    frame = decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)  # same wrap: no unwrap
    assert frame is not None
    assert frame.data == _PICTURE


def test_a_new_wrap_unwraps_again() -> None:
    other = b"Z" * 47
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    record = _e2e_video(_PICTURE, wrapped_plain=other, secret=other)
    frame = decoder.decode(FrameType.VIDEO_FRAME, record, _E2E_SUB)
    assert frame is not None
    assert frame.data == _PICTURE
    assert decoder.aes_key == other[:32]


def test_an_e2e_record_decrypts_under_the_cipher_its_subheader_names() -> None:
    other = rsa.generate_private_key(65537, 1024)  # noqa: S505 (protocol)
    decoder = _e2e_decoder(c3=other, c7=_E2E_CIPHER)
    frame = decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    assert frame is not None
    assert frame.data == _PICTURE


def test_an_e2e_record_of_a_cipher_not_held_names_the_cipher() -> None:
    decoder = _e2e_decoder(c3=_E2E_CIPHER)
    with pytest.raises(EndToEndEncryptedError, match="cipher 7") as err:
        decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    assert not isinstance(err.value, PinProtectedKeyError)
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.CIPHER, 7)
    refusal = decoder.e2e_refusal(_E2E_SUB)
    assert refusal is not None
    assert refusal.key_id == 7
    decoder.add_e2e_key(7, _E2E_CIPHER)
    assert decoder.e2e_refusal(_E2E_SUB) is None
    assert decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB) is not None


def test_an_e2e_record_of_the_users_pin_key_is_refused_naming_it() -> None:
    decoder = _e2e_decoder(c10=_E2E_CIPHER)  # a cloud cipher 10 does not stand in for it
    sub = bytes([4, 0, 0, 10, 1, 0x5B])
    with pytest.raises(PinProtectedKeyError, match="PIN-protected key") as err:
        decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), sub)
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.PIN, 10)
    assert isinstance(decoder.e2e_refusal(sub), PinProtectedKeyError)


def test_a_record_that_is_not_e2e_needs_no_e2e_key() -> None:
    assert _e2e_decoder().e2e_refusal(bytes([1, 0, 0, 1, 10, 0])) is None


# ── version-9 records: the user's PIN key on a recording ────────────────────

#: A version-9 record's key and a wrap no key the client holds opens.
_V9_KEY = testing_station.EccMediaKey(bytes(range(32)), bytes(range(129)))
_V9_PICTURE = b"\x00\x00\x00\x01\x40\x01" + bytes(64)


def _v9_sub(key_id: int, version: int = 9) -> bytes:
    return bytes([version, 0, 1, key_id, 10, 0])


def _ecc_record(key: testing_station.EccMediaKey = _V9_KEY, *, keyframe: bool = True) -> bytes:
    record = testing_station.video_record(_V9_PICTURE, keyframe=keyframe, timestamp_ms=40)
    return testing_station.ecc_video_record(record, key)


def _recording_decoder(offer: media.MediaKeyType) -> media.MediaDecoder:
    if offer is media.MediaKeyType.RSA:
        return media.MediaDecoder(media.generate_media_rsa_key()[1], e2e_keys={})
    return media.MediaDecoder(ecc_private_key=media.generate_media_ecc_key()[1], e2e_keys={})


@pytest.mark.parametrize("offer", list(media.MediaKeyType))
def test_a_version_9_recording_record_is_refused_as_the_users_pin_key(
    offer: media.MediaKeyType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Version 9 on a recording is wrapped for the user's PIN key whatever the open
    offered: refused naming byte 3 as the key id, before any unwrap."""

    def no_unwrap(*_args: object) -> bytes:
        raise AssertionError("a record of the PIN key is not unwrapped")

    monkeypatch.setattr(media, "ecies_decrypt", no_unwrap)
    decoder = _recording_decoder(offer)
    with pytest.raises(PinProtectedKeyError, match=r"key id 12\)") as err:
        decoder.decode(FrameType.VIDEO_FRAME, _ecc_record(), _v9_sub(12))
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.PIN, 12)
    assert decoder.aes_key == b""
    assert isinstance(decoder.e2e_refusal(_v9_sub(12)), PinProtectedKeyError)


def test_a_version_9_record_without_a_key_id_names_the_latest_one() -> None:
    """Byte 3 below 2 names no key: the record uses the key of the latest version-9
    record with one, or byte 3 itself when none came before."""
    decoder = _recording_decoder(media.MediaKeyType.RSA)
    ids = []
    for key_id in (1, 2, 0, 13, 1):
        refusal = decoder.e2e_refusal(_v9_sub(key_id))
        assert isinstance(refusal, PinProtectedKeyError)
        ids.append(refusal.key_id)
    assert ids == [1, 2, 2, 13, 13]
    assert decoder.e2e_refusal(_v9_sub(10, version=4)) is not None
    refusal = decoder.e2e_refusal(_v9_sub(0))
    assert refusal is not None
    assert refusal.key_id == 13, "a version-4 record names no version-9 key"


def test_a_version_9_live_record_decodes_under_the_stream_key() -> None:
    decoder, key = _ecc_decoder()
    assert decoder.e2e_refusal(_v9_sub(12)) is None
    frame = decoder.decode(FrameType.VIDEO_FRAME, _ecc_record(key), _v9_sub(12))
    assert frame is not None
    assert frame.data == _V9_PICTURE
    assert decoder.aes_key == key.key


def test_a_version_8_recording_record_decodes_under_the_stream_key() -> None:
    public_hex, priv = media.generate_media_ecc_key()
    decoder = media.MediaDecoder(ecc_private_key=priv, e2e_keys={})
    key = testing_station.EccMediaKey.for_offer(public_hex)
    assert decoder.e2e_refusal(_v9_sub(1, version=8)) is None
    frame = decoder.decode(FrameType.VIDEO_FRAME, _ecc_record(key), _v9_sub(1, version=8))
    assert frame is not None
    assert frame.data == _V9_PICTURE


def test_version_9_audio_on_a_recording_is_dropped() -> None:
    """A recording's version-9 audio needs the PIN key too; version 8 audio after it still
    decodes under the stream key."""
    public_hex, priv = media.generate_media_ecc_key()
    decoder = media.MediaDecoder(ecc_private_key=priv, e2e_keys={})
    key = testing_station.EccMediaKey.for_offer(public_hex)
    decoder.decode(FrameType.VIDEO_FRAME, _ecc_record(key), _v9_sub(1, version=8))
    audio = testing_station.ecc_audio_record(
        testing_station.audio_record(b"\xff\xf1AAC", timestamp_ms=5), key
    )
    assert decoder.decode(FrameType.AUDIO_FRAME, audio, _v9_sub(12)) is None
    frame = decoder.decode(FrameType.AUDIO_FRAME, audio, _v9_sub(1, version=8))
    assert frame is not None
    assert frame.data == b"\xff\xf1AAC"
    live, live_key = _ecc_decoder()
    live.decode(FrameType.VIDEO_FRAME, _ecc_record(live_key), _v9_sub(12))
    live_audio = testing_station.ecc_audio_record(
        testing_station.audio_record(b"\xff\xf1AAC", timestamp_ms=5), live_key
    )
    assert live.decode(FrameType.AUDIO_FRAME, live_audio, _v9_sub(12)) is not None


def test_a_live_decoder_decodes_no_e2e_record() -> None:
    decoder = media.MediaDecoder(media.generate_media_rsa_key()[1])
    assert not decoder.decodes(media.VideoVariant.E2E)
    assert _e2e_decoder().decodes(media.VideoVariant.E2E)
    with pytest.raises(UnsupportedError, match="e2e video does not decode"):
        decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    with pytest.raises(ValueError, match="live stream"):
        decoder.add_e2e_key(7, _E2E_CIPHER)


def test_e2e_audio_decrypts_under_the_key_of_the_latest_video_record() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    audio = _e2e_audio(b"\xff\xf1AAC")
    assert decoder.decode(FrameType.AUDIO_FRAME, audio, _E2E_SUB) is None  # no key yet
    decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    frame = decoder.decode(FrameType.AUDIO_FRAME, audio, _E2E_SUB)
    assert frame is not None
    assert (frame.kind, frame.data, frame.timestamp_ms) == (
        media.MediaKind.AUDIO,
        b"\xff\xf1AAC",
        2040,
    )


def test_e2e_audio_decrypts_its_datalen_bytes_only() -> None:
    """A record padded past its header's ``datalen`` decrypts the tag and ciphertext."""
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    frame = decoder.decode(FrameType.AUDIO_FRAME, _e2e_audio(b"\xff\xf1AAC") + bytes(8), _E2E_SUB)
    assert frame is not None
    assert frame.data == b"\xff\xf1AAC"


def test_e2e_audio_of_another_stream_type_is_not_delivered() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    decoder.decode(FrameType.VIDEO_FRAME, _e2e_video(_PICTURE), _E2E_SUB)
    assert (
        decoder.decode(FrameType.AUDIO_FRAME, _e2e_audio(b"G711", stream_type=2), _E2E_SUB) is None
    )


def test_e2e_audio_shorter_than_its_tag_raises_protocol_error() -> None:
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    with pytest.raises(ProtocolError, match="shorter than 32"):
        decoder.decode(FrameType.AUDIO_FRAME, bytes(31), _E2E_SUB)


def test_the_testing_e2e_records_decode() -> None:
    key = testing_station.E2EMediaKey.for_cipher(_E2E_CIPHER.public_key())
    record = testing_station.video_record(_PICTURE, keyframe=True)
    decoder = _e2e_decoder(c7=_E2E_CIPHER)
    sealed = testing_station.e2e_video_record(record, key)
    frame = decoder.decode(FrameType.VIDEO_FRAME, sealed, _E2E_SUB)
    assert frame is not None
    assert frame.data == _PICTURE
    audio = testing_station.e2e_audio_record(testing_station.audio_record(b"\xff\xf1A"), key)
    audio_frame = decoder.decode(FrameType.AUDIO_FRAME, audio, _E2E_SUB)
    assert audio_frame is not None
    assert audio_frame.data == b"\xff\xf1A"


def test_the_homebase2_open_payload_has_no_t8030_fields() -> None:
    hb2 = media.start_realtime_media_payload("acct", 2, "KEY", homebase3=False)
    assert hb2 == {
        "streamtype": 0,
        "camera_type": 0,
        "entrytype": 0,
        "accountId": "acct",
        "chn_list": [],
        "key": "KEY",
        "ClientOS": "ANDROID",
    }
    hb3 = media.start_realtime_media_payload("acct", 2, "KEY")
    assert hb3["chn_list"][0]["chn"] == 2
    assert hb3["extValue"] == 1000


def test_parse_audio_frame() -> None:
    body = b"\xff\xf1AACFRAME"
    payload = struct.pack("<I", len(body)) + b"\x00" * 12 + body
    assert media.parse_audio_frame(payload).data == body


def test_parse_audio_frame_reads_the_shared_clock() -> None:
    """The audio header carries the same millisecond clock as the video header."""
    body = b"\xff\xf1AACFRAME"
    payload = (
        struct.pack("<I", len(body))
        + struct.pack("<H", 0)
        + struct.pack("<HI", 18, 3315878314)
        + bytes(4)
        + body
    )
    frame = media.parse_audio_frame(payload)
    assert frame.data == body
    assert frame.counter == 18
    assert frame.timestamp_ms == 3315878314
    assert frame.pts == 3315878314 * 90


def test_ms_to_pts_is_exact() -> None:
    """90 kHz over a 1 kHz media clock is exactly 90 ticks per ms — no rounding."""
    assert media.ms_to_pts(0) == 0
    assert media.ms_to_pts(1) == 90
    assert media.ms_to_pts(64) == 5760  # one AAC-LC frame at 16 kHz
    assert media.ms_to_pts(3315877449) == 3315877449 * 90


def test_video_frames_report_a_resolution_change_mid_stream() -> None:
    """A live stream starts at the sensor's full resolution and steps down.

    Seen live on a T8160 at streaming quality "medium": 3840x2160 for the first ~0.6 s,
    then 1920x1080 for the rest, the switch on a keyframe. A muxer must follow the
    per-frame size rather than trusting the first frame.
    """
    body = b"HEVCDATA"

    def record(width: int, height: int, ms: int, *, keyframe: bool) -> bytes:
        return (
            struct.pack("<I", len(body))
            + bytes([int(keyframe), media.VIDEO_CODEC_HEVC])
            + struct.pack("<IHHI", 0, width, height, ms)
            + bytes(4)
            + body
        )

    first = media.parse_video_frame(record(3840, 2160, 1000, keyframe=True))
    switched = media.parse_video_frame(record(1920, 1080, 1620, keyframe=True))
    later = media.parse_video_frame(record(1920, 1080, 1660, keyframe=False))

    assert (first.width, first.height) == (3840, 2160)
    assert (switched.width, switched.height) == (1920, 1080)
    assert switched.is_keyframe, "a size change arrives on a keyframe, with new parameter sets"
    assert (later.width, later.height) == (1920, 1080)
    assert first.pts < switched.pts < later.pts


def test_parse_video_frame_keeps_a_keyframes_wrapped_key_prefix() -> None:
    """``datalen`` counts the DECODED frame, so a keyframe record is 129 bytes longer.

    Live on a T8160: every keyframe record carries exactly ``datalen + 129`` body bytes
    (128 RSA + 1 marker), and decrypting the whole body yields exactly ``datalen``.
    Cutting at ``datalen`` drops the tail of every keyframe, which shows as unwritten
    green blocks at the bottom right of the picture. A T8170 never pads, so the cut
    shows nothing there.
    """
    decoded_len = 400
    body = bytes((i * 3) & 0xFF for i in range(decoded_len + 129))
    header = (
        struct.pack("<I", decoded_len)
        + bytes([1, media.VIDEO_CODEC_HEVC])
        + struct.pack("<IHHI", 1, 2304, 1296, 5000)
        + bytes(4)
    )
    frame = media.parse_video_frame(header + body)
    assert frame.is_keyframe
    assert frame.data == body, "the whole body must survive, prefix included"
    assert len(frame.data) == decoded_len + 129

    # A P-frame is already clear: datalen is exact, and trailing datagram padding goes.
    pheader = (
        struct.pack("<I", decoded_len)
        + bytes([0, media.VIDEO_CODEC_HEVC])
        + struct.pack("<IHHI", 2, 2304, 1296, 5040)
        + bytes(4)
    )
    pframe = media.parse_video_frame(pheader + body)
    assert not pframe.is_keyframe
    assert pframe.data == body[:decoded_len]


def test_parse_frames_reject_short_input() -> None:
    with pytest.raises(ProtocolError, match="22-byte"):
        media.parse_video_frame(b"\x00" * 10)
    with pytest.raises(ProtocolError, match="16-byte"):
        media.parse_audio_frame(b"\x00" * 10)
    # an empty body with datalen 0 is a (degenerate) complete frame
    assert media.parse_audio_frame(bytes(16)).data == b""


def test_parse_frames_reject_a_body_shorter_than_datalen() -> None:
    video = struct.pack("<I", 10) + b"\x00" * 18 + b"short"
    with pytest.raises(ProtocolError, match="truncated"):
        media.parse_video_frame(video)
    audio = struct.pack("<I", 10) + b"\x00" * 12 + b"short"
    with pytest.raises(ProtocolError, match="truncated"):
        media.parse_audio_frame(audio)


def test_decrypt_keyframe_recovers_the_encrypted_prefix() -> None:
    _, priv = media.generate_media_rsa_key()
    aes_key = bytes(range(16))
    clear = bytes((i * 7) & 0xFF for i in range(300))  # > 257 so there is a clear tail
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()  # noqa: S305 (fixture)
    enc_prefix = enc.update(clear[:128]) + enc.finalize()
    wrapped = priv.public_key().encrypt(aes_key, padding.PKCS1v15())
    assert len(wrapped) == 128
    body = wrapped + b"\x00" + enc_prefix + clear[128:]

    assert media.MediaDecoder(priv).decrypt_keyframe(body) == clear


def test_decrypt_keyframe_passes_through_a_short_body() -> None:
    _, priv = media.generate_media_rsa_key()
    assert media.MediaDecoder(priv).decrypt_keyframe(b"short pframe") == b"short pframe"


class _WrongKey:
    """An RSA private key standing in for the wrong one: on OpenSSL >= 3.2 its PKCS#1
    v1.5 decrypt usually returns random bytes of random length, and rarely raises."""

    def __init__(self, result: bytes | Exception) -> None:
        self.result = result

    def decrypt(self, ciphertext: bytes, pad: padding.AsymmetricPadding) -> bytes:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.mark.parametrize(
    ("result", "match"),
    [
        (bytes(62), "unwrapped to 62 bytes"),  # implicit rejection: the common case
        (ValueError("Decryption failed"), "RSA unwrap failed"),
    ],
    ids=["wrong-length", "unwrap-raises"],
)
def test_decrypt_keyframe_rejects_a_keyframe_wrapped_for_another_key(
    result: bytes | Exception, match: str
) -> None:
    _, priv = media.generate_media_rsa_key()
    good = testing_station.media_keyframe(priv.public_key(), bytes(range(16)))
    decoder = media.MediaDecoder(priv)
    assert decoder.decrypt_keyframe(good) == testing_station.MEDIA_KEYFRAME
    decoder._rsa_key = _WrongKey(result)  # type: ignore[assignment]
    foreign = bytes(range(128)) + good[128:]

    with pytest.raises(media._ForeignKeyframeError, match=match) as info:
        decoder.decrypt_keyframe(foreign)

    assert "not wrapped for this stream's key" in str(info.value)
    assert isinstance(info.value, ProtocolError)
    # the stream key of the good keyframe stays: nothing was pinned
    assert (decoder.aes_key, decoder._wrapped) == (bytes(range(16)), good[:128])


def test_request_payload_shapes() -> None:
    start = media.start_realtime_media_payload("acct", 1, "AABB")
    assert start["accountId"] == "acct"
    assert start["key"] == "AABB"
    assert start["chn_list"] == [{"cameraType": 0, "chn": 1, "index": 0, "sensor": 0}]
    assert media.stop_realtime_media_payload("acct", 1) == {
        "accountId": "acct",
        "chn_list": [{"chn": 1}],
    }
    assert media.download_video_payload("/zx/x.zxvideo", "AABB") == {
        "filepath": "/zx/x.zxvideo",
        "key": "AABB",
    }
    # RECORD_VIEW (1025) shares the download's by-path shape
    assert media.record_view_payload("/zx/rec.zxvideo", "CCDD") == {
        "filepath": "/zx/rec.zxvideo",
        "key": "CCDD",
    }


@given(data=st.binary(max_size=64))
@settings(max_examples=120)
def test_frame_parsers_only_raise_protocol_error(data: bytes) -> None:
    for fn in (media.parse_video_frame, media.parse_audio_frame):
        with contextlib.suppress(ProtocolError):
            fn(data)


class _CountingKey:
    """An RSA private key that counts its decrypt calls."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self.key = key
        self.calls = 0

    def decrypt(self, ciphertext: bytes, pad: padding.AsymmetricPadding) -> bytes:
        self.calls += 1
        return self.key.decrypt(ciphertext, pad)


def test_decoder_unwraps_the_stream_key_once() -> None:
    _, priv = media.generate_media_rsa_key()
    aes_key = bytes(range(16, 32))
    clear = bytes((i * 11) & 0xFF for i in range(320))
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()  # noqa: S305 (fixture)
    body = (
        priv.public_key().encrypt(aes_key, padding.PKCS1v15())
        + b"\x00"
        + enc.update(clear[:128])
        + enc.finalize()
        + clear[128:]
    )
    keyframe = (
        struct.pack("<I", len(body))
        + bytes([1, media.VIDEO_CODEC_HEVC])
        + struct.pack("<IHHI", 7, 3840, 2160, 1234)
        + bytes(4)
        + body
    )
    counting = _CountingKey(priv)
    decoder = media.MediaDecoder(counting)  # type: ignore[arg-type]

    expected = media.MediaFrame(
        media.MediaKind.VIDEO,
        clear,
        is_keyframe=True,
        timestamp_ms=1234,
        codec=media.VideoCodec.HEVC,
        width=3840,
        height=2160,
    )
    assert decoder.decode(media.VIDEO_FRAME_TYPE, keyframe) == expected
    assert decoder.decode(media.VIDEO_FRAME_TYPE, keyframe) == expected
    assert counting.calls == 1

    audio = struct.pack("<I", 4) + struct.pack("<HHI", 0, 3, 1298) + bytes(4) + b"\xff\xf1ab"
    assert decoder.decode(media.AUDIO_FRAME_TYPE, audio) == media.MediaFrame(
        media.MediaKind.AUDIO, b"\xff\xf1ab", timestamp_ms=1298
    )
    assert decoder.decode(0x0547, b"") is None


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\xff\xd8\xff\xe0JFIF", media.StillFormat.JPEG),
        (b"eufysecurity\x00\x01", media.StillFormat.V1),
        (b"v2_eufysecurity\x00\x01", media.StillFormat.V2),
        (b"v8_eufysecurity\x00\x01", media.StillFormat.V8),
        (b"\x89PNG\r\n\x1a\n", media.StillFormat.UNKNOWN),
        (b"", media.StillFormat.UNKNOWN),
    ],
)
def test_classify_still_by_magic(data: bytes, expected: media.StillFormat) -> None:
    assert media.classify_still(data) is expected
    assert media.Still("/zx/a.jpg", data, expected).is_image is (data.startswith(b"\xff\xd8"))


def test_v1_still_is_image_when_decoded() -> None:
    assert media.Still("/zx/a.jpg", b"\xff\xd8\xff\xe0", media.StillFormat.V1).is_image is True
    assert media.Still("/zx/a.jpg", b"eufysecurity", media.StillFormat.V1).is_image is False


_KEY = bytes(range(32))


def _gcm(plain: bytes, key: bytes = _KEY) -> bytes:
    nonce = bytes(12)
    sealed = AESGCM(key).encrypt(nonce, plain, crypto.GCM_AAD)
    return sealed[-16:] + nonce + sealed[:-16]


_ECB_KEY = bytes(range(16, 32))


@pytest.mark.parametrize(
    ("ftype", "cipher", "payload", "value"),
    [
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, bytes.fromhex("0200000000"), 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, _gcm(bytes.fromhex("0200000000")), 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, _gcm(b"\x02\x00\x00\x00", bytes(32)), None),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"\x02", 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"\x02\x01\x00\x00\x00", 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"\x03\x00\x00\x00\x00", 3),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"", None),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"\x02" + bytes(15), None),
        (
            FrameType.RECORD_PLAY_CTRL,
            FrameCipher.ECB,
            crypto.ecb_encrypt(_ECB_KEY, bytes.fromhex("0200000000").ljust(16, b"\0")),
            2,
        ),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.ECB, b"\x02\x00\x00\x00\x00", 2),
        (
            FrameType.RECORD_PLAY_CTRL,
            FrameCipher.ECB,
            crypto.ecb_encrypt(_ECB_KEY, bytes(16)) + b"\x02",
            0,
        ),
        (FrameType.RECORD_PLAY_CTRL, 0x05, bytes.fromhex("0200000000"), None),
        (FrameType.NOTIFY_PAYLOAD, FrameCipher.GCM, bytes.fromhex("0200000000"), None),
    ],
    ids=[
        "gcm-clear",
        "gcm-sealed",
        "gcm-wrong-key",
        "gcm-one-byte",
        "first-byte-not-u32",
        "gcm-dropped",
        "gcm-empty",
        "gcm-longer-than-clear-is-decrypted",
        "static-key-block",
        "ecb-short-tail-as-is",
        "ecb-whole-blocks-decrypted",
        "unknown-cipher",
        "other-type",
    ],
)
def test_decode_record_play_ctrl(
    ftype: int, cipher: int, payload: bytes, value: int | None
) -> None:
    """The value is the first byte of the body under the key the frame names."""
    frame = Frame(type=ftype, subheader=bytes([cipher, 0, 0, 0, 0, 0]), payload=payload)
    assert media.decode_record_play_ctrl(frame, static_key=_ECB_KEY, session_key=_KEY) == value


def test_decode_record_play_ctrl_needs_the_key_its_cipher_names() -> None:
    gcm = Frame(FrameType.RECORD_PLAY_CTRL, bytes([FrameCipher.GCM, 0, 0, 0, 0, 0]), _gcm(b"\x02"))
    ecb = Frame(
        FrameType.RECORD_PLAY_CTRL,
        bytes([FrameCipher.ECB, 0, 0, 1, 0, 0]),
        crypto.ecb_encrypt(_ECB_KEY, b"\x02".ljust(16, b"\0")),
    )
    assert media.decode_record_play_ctrl(gcm, static_key=_ECB_KEY) is None
    assert media.decode_record_play_ctrl(ecb, session_key=_KEY) is None
    assert media.decode_record_play_ctrl(ecb, static_key=_ECB_KEY) == media.PLAYBACK_ENDED


def test_decode_record_play_ctrl_reads_a_clear_body_as_is() -> None:
    """An RSA session's clear frame (ECB tag, encryption type 0): no key is applied."""
    clear = Frame(
        FrameType.RECORD_PLAY_CTRL,
        bytes([FrameCipher.ECB, 0, 0, 0, 0, 0]),
        b"\x02".ljust(16, b"\0"),
    )
    assert media.decode_record_play_ctrl(clear, static_key=_ECB_KEY, clear=True) == 2
    empty = Frame(FrameType.RECORD_PLAY_CTRL, clear.subheader, b"")
    assert media.decode_record_play_ctrl(empty, clear=True) is None


@pytest.mark.parametrize(
    ("serial", "did", "code", "expected"),
    [
        (
            "T8160P2000067890",
            "EUPRAMA-123456-ABCDE",
            "0123456789",
            "E14FB20A7069CF6550196115864212C6",
        ),
        (
            "T8160P2000067890",
            "EUPRAMA-987654-ABCDE",
            "0123456789",
            "976FF97FAA40B321D80CA45A481FC499",
        ),
        (
            "T8160P2000067890",
            "EUPRAMA-123456789-ABCDE",
            "0123456789",
            "50532A1DDA95F226DF3FC03B874C0C2B",
        ),
        (
            "T8160P2000067890",
            "EUPRAMA-1234-ABCDE",
            "0123456789",
            "F01EF27507B0DB2E940C0FB93B61FC17",
        ),
        (
            "T8030P2000012345",
            "EUPRAMA-123456-ABCDE",
            "9900000001",
            "F64C866BAA13AC06A57F4850D544BC6A",
        ),
    ],
)
def test_pic_check_code_known_answer_vectors(
    serial: str, did: str, code: str, expected: str
) -> None:
    assert media.pic_check_code(serial, did, code) == expected


def test_decode_v1_still_round_trip() -> None:
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = testing_station.v1_still(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    assert media.decode_v1_still(wrapped, SYNTHETIC.did) == image


def test_decode_v1_still_with_a_wrong_did_raises_protocol_error() -> None:
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = testing_station.v1_still(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    with pytest.raises(ProtocolError, match="did not decrypt to a JPEG"):
        media.decode_v1_still(wrapped, "EUPRAMA-654321-ZZZZZ")


def test_decode_v1_still_on_a_non_v1_input_raises_protocol_error() -> None:
    with pytest.raises(ProtocolError, match="not a V1 still"):
        media.decode_v1_still(b"\xff\xd8\xff\xe0" + bytes(400), SYNTHETIC.did)
    with pytest.raises(ProtocolError, match="not a V1 still"):
        media.decode_v1_still(b"v2_eufysecurity\x00\x01", SYNTHETIC.did)


def test_decode_v1_still_header_malformations_raise_protocol_error() -> None:
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = testing_station.v1_still(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did)

    bad_sep = bytearray(wrapped)
    bad_sep[29] = ord("X")
    with pytest.raises(ProtocolError, match="malformed"):
        media.decode_v1_still(bytes(bad_sep), SYNTHETIC.did)

    with pytest.raises(ProtocolError, match="under 256"):
        media.decode_v1_still(wrapped[: 41 + 255], SYNTHETIC.did)


def test_v1_still_validation_raises_value_error() -> None:
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    with pytest.raises(ValueError, match="needs a 256-byte image"):
        testing_station.v1_still(image[:255], SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    with pytest.raises(ValueError, match="a 16-char serial"):
        testing_station.v1_still(image, "123456789012345", did=SYNTHETIC.did)
    with pytest.raises(ValueError, match="a 10-char code"):
        testing_station.v1_still(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did, code="123456789")


_STILL_IMAGE = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
_OTHER_DID = "EUPRAMA-654321-ZZZZZ"


def test_decode_v2_still_round_trip() -> None:
    wrapped = testing_station.v2_still(_STILL_IMAGE, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    assert media.classify_still(wrapped) is media.StillFormat.V2
    assert media.decode_v2_still(wrapped, SYNTHETIC.did) == _STILL_IMAGE


def test_decode_v2_still_raises_protocol_error_on_bad_input() -> None:
    wrapped = testing_station.v2_still(_STILL_IMAGE, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    with pytest.raises(ProtocolError, match=r"^V2 still failed its GCM tag$"):
        media.decode_v2_still(wrapped, _OTHER_DID)
    with pytest.raises(ProtocolError, match="not a V2 still"):
        media.decode_v2_still(_STILL_IMAGE, SYNTHETIC.did)
    with pytest.raises(ProtocolError, match="under 256"):
        media.decode_v2_still(wrapped[: 74 + 255], SYNTHETIC.did)
    bad_code = bytearray(wrapped)
    bad_code[33] = 0xFF
    with pytest.raises(ProtocolError, match="malformed"):
        media.decode_v2_still(bytes(bad_code), SYNTHETIC.did)


def test_v2_still_validation_raises_value_error() -> None:
    with pytest.raises(ValueError, match="needs a 256-byte image"):
        testing_station.v2_still(_STILL_IMAGE[:255])


@pytest.mark.parametrize("build", [testing_station.v1_still, testing_station.v2_still])
def test_decode_still_tries_each_did_of_the_header_serial(build: Any) -> None:
    wrapped = build(_STILL_IMAGE, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    asked: list[str] = []

    def dids(serial: str) -> list[str]:
        asked.append(serial)
        return [_OTHER_DID, SYNTHETIC.did]

    assert media.decode_still(wrapped, dids) == _STILL_IMAGE
    assert asked == [SYNTHETIC.camera_sn]
    with pytest.raises(ProtocolError):
        media.decode_still(wrapped, lambda _: [_OTHER_DID])
    with pytest.raises(ProtocolError, match="no DID known"):
        media.decode_still(wrapped, lambda _: [])
    bad_serial = bytearray(wrapped)
    bad_serial[20] = 0xFF
    with pytest.raises(ProtocolError, match="header is malformed"):
        media.decode_still(bytes(bad_serial), lambda _: [SYNTHETIC.did])


@pytest.mark.parametrize("data", [_STILL_IMAGE, b"\x89PNG\r\n\x1a\n", b""])
def test_decode_still_returns_other_bytes_unchanged(data: bytes) -> None:
    assert media.decode_still(data, lambda _: pytest.fail("no DID needed")) is data


def test_decode_still_refuses_a_video_encrypted_still() -> None:
    v8 = b"v8_eufysecurity:" + SYNTHETIC.camera_sn.encode() + bytes(400)
    with pytest.raises(VideoEncryptedPictureError, match="Video Encryption"):
        media.decode_still(v8, lambda _: [SYNTHETIC.did])


@pytest.mark.parametrize(
    ("code", "label"),
    [(media.VIDEO_CODEC_HEVC, "hevc"), (media.VIDEO_CODEC_H264, "h264"), (7, "code:7")],
)
def test_video_codec_label_names_an_unknown_code_by_its_number(code: int, label: str) -> None:
    record = testing_station.video_record(b"x", keyframe=False, codec=code)
    assert media.video_codec_label(record) == label
    assert media.video_codec_label(record[:5]) == "short"


def test_keyframe_layout_probe_names_every_layout_that_starts_annex_b() -> None:
    aes_key = bytes(range(16))
    _, private = media.generate_media_rsa_key()
    body = testing_station.media_keyframe(private.public_key(), aes_key)
    assert media.keyframe_layout_probe(aes_key, body) == "ecb@129"
    assert media.keyframe_layout_probe(b"", body) == "none"  # no stream key yet
    clear = testing_station.MEDIA_KEYFRAME
    assert media.keyframe_layout_probe(aes_key, clear) == "raw@0"
    unmarked = body[:128] + body[129:]  # the encrypted run right after the wrapped key
    assert media.keyframe_layout_probe(aes_key, unmarked) == "ecb@128"


def test_video_record_shape_shows_the_header_fields_and_the_body_head() -> None:
    record = testing_station.video_record(
        testing_station.MEDIA_PFRAME, keyframe=False, codec=media.VIDEO_CODEC_H264
    )
    shape = media.video_record_shape(record, bytes([1, 0, 0, 0, 0, 0]), outcome="frame")
    assert shape == media.MediaRecordShape(
        variant="plain",
        subheader="010000000000",
        key_flag=0,
        codec="h264",
        datalen=len(testing_station.MEDIA_PFRAME),
        record_len=len(record),
        width=testing_station.MEDIA_WIDTH,
        height=testing_station.MEDIA_HEIGHT,
        head=testing_station.MEDIA_PFRAME[:5].hex(),
        outcome="frame",
    )
    assert media.video_record_shape(record, None, outcome="frame", head=b"\0\0\0\1\x67").head == (
        "0000000167"
    )


SC = b"\x00\x00\x00\x01"


@pytest.mark.parametrize(
    ("data", "codec"),
    [
        (SC + b"\x40\x01\x0c" + SC + b"\x42\x01\x01", media.VideoCodec.HEVC),  # VPS, SPS
        (SC + b"\x26\x01\xaf", media.VideoCodec.HEVC),  # IDR_W_RADL alone
        (SC + b"\x67\x4d\x00" + SC + b"\x68\xee", media.VideoCodec.H264),  # SPS, PPS
        (SC + b"\x27\x4d\x00", media.VideoCodec.H264),  # SPS with nal_ref_idc 1
        (SC + b"\x09\xf0" + SC + b"\x65\x88", media.VideoCodec.H264),  # AUD, then IDR
        (b"\x00\x00\x01\x67\x42\x00", media.VideoCodec.H264),  # 3-byte start code
        (SC + b"\x41\x9a\x00", None),  # an H.264 P-slice tells nothing
        (SC + b"\x02\x01\xd0", None),  # an HEVC trailing picture tells nothing
        (b"HEVCDATA", None),
    ],
)
def test_picture_codec_reads_the_parameter_sets_and_irap_pictures(
    data: bytes, codec: media.VideoCodec | None
) -> None:
    assert media.picture_codec(data) is codec


def test_no_h264_picture_group_header_reads_as_hevc_and_back() -> None:
    profiles = (0x42, 0x4D, 0x58, 0x64)  # the byte after an SPS header: profile_idc
    for ref_idc in (1, 2, 3):
        for nal_type in (5, 7):
            for b1 in profiles:
                header = bytes(((ref_idc << 5) | nal_type, b1))
                assert media._nal_codec(header) is media.VideoCodec.H264
    for nal_type in (*range(16, 22), 32, 33, 34):
        for tid in range(1, 8):
            header = bytes((nal_type << 1, tid))
            assert media._nal_codec(header) is media.VideoCodec.HEVC


def test_drop_empty_nals_keeps_a_clean_frame_as_is() -> None:
    frame = SC + b"\x41\x9a\x01" + b"\x00\x00\x01\x41\x02"
    assert media.drop_empty_nals(frame)[0] is frame
    assert media.drop_empty_nals(b"P-FRAME!") == (b"P-FRAME!", 0)  # no start code: untouched


@pytest.mark.parametrize(
    ("data", "clean", "dropped"),
    [
        (SC + b"\x41\x01" + SC, SC + b"\x41\x01", 1),  # trailing start code
        (SC + SC + b"\x41\x01", SC + b"\x41\x01", 1),  # back-to-back start codes
        (
            SC + b"\x41\x01" + SC + b"\x00\x00" + SC + b"\x41\x02",
            SC + b"\x41\x01" + SC + b"\x41\x02",
            1,
        ),
        (SC + SC, b"", 2),
        (b"", b"", 0),
    ],
)
def test_drop_empty_nals_removes_units_with_no_bytes(
    data: bytes, clean: bytes, dropped: int
) -> None:
    assert media.drop_empty_nals(data) == (clean, dropped)
