from __future__ import annotations

from eufy_home_security.images import (
    HEVC_CONTENT_TYPE,
    IMAGE_SOURCES,
    JPEG_CONTENT_TYPE,
    CameraImage,
    ImageSource,
)
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
