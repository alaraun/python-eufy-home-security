"""Camera-media pure helpers: keyframe decrypt, frame parsing, request shapes."""

from __future__ import annotations

import contextlib
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.exceptions import ProtocolError
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


@pytest.mark.parametrize(
    ("ftype", "cipher", "payload", "value"),
    [
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, bytes.fromhex("0200000000"), 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, _gcm(bytes.fromhex("0200000000")), 2),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, _gcm(b"\x02\x00\x00\x00", bytes(32)), None),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.GCM, b"\x02\x00", None),
        (FrameType.RECORD_PLAY_CTRL, FrameCipher.ECB, bytes.fromhex("0200000000"), None),
        (FrameType.NOTIFY_PAYLOAD, FrameCipher.GCM, bytes.fromhex("0200000000"), None),
    ],
)
def test_decode_record_play_ctrl(
    ftype: int, cipher: int, payload: bytes, value: int | None
) -> None:
    frame = Frame(type=ftype, subheader=bytes([cipher, 0, 0, 0, 0, 0]), payload=payload)
    assert media.decode_record_play_ctrl(frame, _KEY) == value
    assert value == media.PLAYBACK_ENDED or value is None


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
