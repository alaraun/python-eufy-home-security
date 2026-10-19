from __future__ import annotations

import pytest

from eufy_home_security.images import (
    H264_CONTENT_TYPE,
    HEVC_CONTENT_TYPE,
    IMAGE_SOURCES,
    JPEG_CONTENT_TYPE,
    PNG_CONTENT_TYPE,
    WEBP_CONTENT_TYPE,
    CameraImage,
    ImageSource,
    picture_content_type,
)
from eufy_home_security.p2p.media import VideoCodec
from eufy_home_security.testing import SYNTHETIC


def test_image_sources_define_the_costs_and_content_types() -> None:
    assert set(IMAGE_SOURCES) == set(ImageSource)

    thumb = IMAGE_SOURCES[ImageSource.THUMBNAIL]
    assert thumb.source is ImageSource.THUMBNAIL
    assert thumb.content_type == JPEG_CONTENT_TYPE
    assert not thumb.high_resolution
    assert not thumb.needs_recording
    assert not thumb.wakes_camera

    trigger = IMAGE_SOURCES[ImageSource.TRIGGER_FRAME]
    assert trigger.source is ImageSource.TRIGGER_FRAME
    assert trigger.content_type == HEVC_CONTENT_TYPE
    assert trigger.high_resolution
    assert trigger.needs_recording
    assert not trigger.wakes_camera

    live = IMAGE_SOURCES[ImageSource.LIVE]
    assert live.source is ImageSource.LIVE
    assert live.content_type == HEVC_CONTENT_TYPE
    assert live.high_resolution
    assert not live.needs_recording
    assert live.wakes_camera


def test_camera_image_properties_follow_the_content_type_and_source() -> None:
    thumb = CameraImage(
        source=ImageSource.THUMBNAIL,
        device_sn=SYNTHETIC.camera_sn,
        data=b"jpeg",
        content_type=JPEG_CONTENT_TYPE,
    )
    assert thumb.is_jpeg
    assert not thumb.high_resolution

    hevc = CameraImage(
        source=ImageSource.TRIGGER_FRAME,
        device_sn=SYNTHETIC.camera_sn,
        data=b"hevc",
        content_type=HEVC_CONTENT_TYPE,
    )
    assert not hevc.is_jpeg
    assert hevc.high_resolution


H264_IDR = b"\x00\x00\x00\x01\x67\x4d\x00\x1f" + b"\x00\x00\x00\x01\x65" + bytes(40)
HEVC_IDR = b"\x00\x00\x00\x01\x40\x01" + bytes(40)


@pytest.mark.parametrize(
    ("data", "named", "codec"),
    [
        (H264_IDR, VideoCodec.HEVC, VideoCodec.H264),  # the picture outranks a header's name
        (HEVC_IDR, None, VideoCodec.HEVC),
        (b"not annex-b", VideoCodec.H264, VideoCodec.H264),
        (b"not annex-b", None, VideoCodec.HEVC),
    ],
)
def test_a_keyframe_image_names_the_codec_of_its_picture(
    data: bytes, named: VideoCodec | None, codec: VideoCodec
) -> None:
    image = CameraImage.keyframe(
        source=ImageSource.LIVE, device_sn=SYNTHETIC.camera_sn, data=data, codec=named, width=640
    )
    assert (image.codec, image.content_type, image.width) == (codec, codec.content_type, 640)
    assert not image.is_jpeg


def test_codec_content_types_and_mp4_tags() -> None:
    assert (VideoCodec.HEVC.content_type, VideoCodec.HEVC.mp4_tag) == (HEVC_CONTENT_TYPE, "hvc1")
    assert (VideoCodec.H264.content_type, VideoCodec.H264.mp4_tag) == (H264_CONTENT_TYPE, None)


@pytest.mark.parametrize(
    ("data", "content_type"),
    [
        (b"\xff\xd8\xff\xe0rest", JPEG_CONTENT_TYPE),
        (b"\x89PNG\r\n\x1a\nrest", PNG_CONTENT_TYPE),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", WEBP_CONTENT_TYPE),
        (b"eufysecurity:header", None),
        (b"v8_eufysecurity:header", None),
        (b"", None),
    ],
)
def test_a_pushed_picture_is_typed_by_its_magic(data: bytes, content_type: str | None) -> None:
    assert picture_content_type(data) == content_type
