"""Camera images: where a still can come from, what each source costs, and the result (pure).

A camera behind a station has three image sources (``docs/protocol/media.md``):

* the **thumbnail** the station stores with an event: a small JPEG, fast, the camera
  stays asleep;
* the **trigger frame**: the first keyframe of the event's recording, at the camera's
  recording resolution (3840x2160 on a T8160). Full quality, the camera stays asleep, but
  it takes a playback on a short-lived session and arrives as HEVC, not JPEG;
* a **live** keyframe: the same resolution, now, but it wakes a battery camera.

:data:`IMAGE_SOURCES` describes each one as data, so a consumer can build its options
and their descriptions from it. :class:`CameraImage` is what
:meth:`~eufy_home_security.station.Station.async_event_image` and
:meth:`~eufy_home_security.station.Station.async_camera_image` return. Turning HEVC
into JPEG is left to the consumer (Home Assistant has ffmpeg); the library has no native
dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .devices.support import Support

#: The MIME type of a JPEG image.
JPEG_CONTENT_TYPE: Final = "image/jpeg"
#: The MIME type of an Annex-B HEVC keyframe.
HEVC_CONTENT_TYPE: Final = "video/hevc"


class ImageSource(StrEnum):
    """Where a camera image comes from."""

    THUMBNAIL = "thumbnail"
    TRIGGER_FRAME = "trigger_frame"
    LIVE = "live"


@dataclass(frozen=True, slots=True, kw_only=True)
class ImageSourceInfo:
    """What one :class:`ImageSource` gives and costs."""

    source: ImageSource
    high_resolution: bool
    """Whether it has the camera's recording resolution (the thumbnail is 640x360)."""
    content_type: str
    """What :attr:`CameraImage.data` holds: a JPEG, or an HEVC keyframe to decode."""
    wakes_camera: bool
    """Whether it wakes a battery camera (spends its battery)."""
    needs_recording: bool
    """Whether it needs an event with a stored recording."""
    typical_seconds: float
    """Time to the image on a HomeBase 3 over LAN, without decoding (order of magnitude:
    thumbnail 0.4 s, trigger frame 1.1-1.4 s)."""
    support: Support
    """Verification status of the source on hardware."""


IMAGE_SOURCES: Final[dict[ImageSource, ImageSourceInfo]] = {
    ImageSource.THUMBNAIL: ImageSourceInfo(
        source=ImageSource.THUMBNAIL,
        high_resolution=False,
        content_type=JPEG_CONTENT_TYPE,
        wakes_camera=False,
        needs_recording=False,
        typical_seconds=0.5,
        support=Support.VERIFIED,
    ),
    ImageSource.TRIGGER_FRAME: ImageSourceInfo(
        source=ImageSource.TRIGGER_FRAME,
        high_resolution=True,
        content_type=HEVC_CONTENT_TYPE,
        wakes_camera=False,
        needs_recording=True,
        typical_seconds=1.5,
        support=Support.VERIFIED,
    ),
    ImageSource.LIVE: ImageSourceInfo(
        source=ImageSource.LIVE,
        high_resolution=True,
        content_type=HEVC_CONTENT_TYPE,
        wakes_camera=True,
        needs_recording=False,
        typical_seconds=5.0,
        support=Support.VERIFIED,
    ),
}


@dataclass(frozen=True, slots=True, kw_only=True)
class CameraImage:
    """One camera image and where it came from.

    ``data`` is a JPEG when :attr:`is_jpeg`, else an Annex-B HEVC keyframe (a trigger frame
    or a live keyframe) that a decoder accepts as is. A thumbnail that is not a plain JPEG
    (an obfuscated still) is never returned: it raises instead.
    """

    source: ImageSource
    device_sn: str
    data: bytes
    content_type: str
    record_id: int | None = None
    """The history record the image belongs to; None for a live image."""
    recorded_at: str | None = None
    """The record's ``start_time`` as the station wrote it (station-local time)."""
    preset: int | None = None
    """The preset slot a pan/tilt camera was turned to for this live image, else None."""
    width: int | None = None
    """The picture width a live keyframe's frame header names; None for the other sources."""
    height: int | None = None
    """The picture height a live keyframe's frame header names; None for the other sources."""

    @property
    def is_jpeg(self) -> bool:
        return self.content_type == JPEG_CONTENT_TYPE

    @property
    def high_resolution(self) -> bool:
        return IMAGE_SOURCES[self.source].high_resolution
