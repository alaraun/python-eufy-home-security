"""A live view of a camera with one or more lenses, as the eufy app builds it (pure).

The app lists a camera's lenses from its parameter 9240 and opens a live view in one
of a few layouts: one lens, every lens stacked, or one lens with another inset. The
layout reaches the station in the multi-camera live open
(:func:`~.recipes.open_live_stream_nvr`) through the input the app's live player hands
the handler (:func:`player_input`). See ``docs/protocol/media.md`` § Multi-camera open.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Final

from ..p2p._json import json_int
from .recipes import PIP_CORD_KEYS, StitchMode

LENS_LIST_PARAM: Final = 9240
"""The camera parameter that lists its lenses: a JSON list of ``{"type", "id"}``."""


class CameraId(IntEnum):
    """A lens by its id (the ``sensor`` of a channel-list entry)."""

    FIXED = 0
    MOVING = 1


@dataclass(frozen=True, slots=True)
class Lens:
    """One entry of a camera's lens list (:data:`LENS_LIST_PARAM`)."""

    type: int
    id: int


def parse_lenses(value: str | None) -> tuple[Lens, ...]:
    """The lenses a :data:`LENS_LIST_PARAM` value lists, in its order, as the app reads
    it: a missing ``type`` or ``id`` is 0, other keys are ignored, and no value, an
    empty one or one that does not decode as a whole (not a list, an entry not an
    object, a field not an integer) lists none."""
    if not value:
        return ()
    try:
        raw = json.loads(value)
    except ValueError:
        return ()
    if not isinstance(raw, list):
        return ()
    lenses = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            return ()
        kind, ident = json_int(entry.get("type", 0)), json_int(entry.get("id", 0))
        if kind is None or ident is None:
            return ()
        lenses.append(Lens(kind, ident))
    return tuple(lenses)


class LensSource(StrEnum):
    """Where a camera's lens list came from."""

    STATION = "station"
    """The parameters its station reported (a dump), which the app merges into the
    device's parameters and which win over the cloud's copy."""
    CLOUD = "cloud"
    """The cloud's parameter snapshot of the device, when the station reported none."""
    NONE = "none"
    """Neither lists one: the camera shows one lens."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LensReport:
    """A camera's lens list for diagnostics: how many lenses and from where."""

    count: int
    source: LensSource


class LensView(StrEnum):
    """The live view layouts the app offers for a camera."""

    MAIN = "main"
    """One lens: the fixed one (id 0)."""
    SUB = "sub"
    """One lens: the moving one (id 1)."""
    STACKED = "stacked"
    """Every lens, top to bottom."""
    PIP = "pip"
    """Picture in picture, at the app's default inset position."""


_LAYOUTS: Final[Mapping[LensView, tuple[StitchMode, CameraId]]] = MappingProxyType(
    {
        LensView.MAIN: (StitchMode.SINGLE, CameraId.FIXED),
        LensView.SUB: (StitchMode.SINGLE, CameraId.MOVING),
        LensView.STACKED: (StitchMode.STACKED, CameraId.FIXED),
        LensView.PIP: (StitchMode.PIP, CameraId.FIXED),
    }
)

PIP_STATION_VIDEO_TYPE: Final = 9
"""The ``station_video_type`` of a picture-in-picture view."""

PIP_CORD_DEFAULT: Final = (0.65, 0.7, 0.95, 0.9)
"""The app's default inset rectangle (x1, y1, x2, y2) as fractions of the picture."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LiveView:
    """The parameters of one live view (the app's ``LiveParams``)."""

    view: LensView
    stitch_mode: StitchMode
    chn_list: tuple[Mapping[str, int], ...]
    """One entry per lens shown: ``cameraType`` (0), ``chn``, ``index`` (its place),
    ``sensor`` (the lens id)."""
    audio_chn: int
    station_video_type: int
    pip_cord: tuple[float, float, float, float] | None


def default_lens_view(lenses: Sequence[Lens]) -> LensView:
    """The layout the app's live page opens in (upright): every lens stacked when the
    camera lists lenses, else the fixed one."""
    return LensView.STACKED if lenses else LensView.MAIN


def live_view(channel: int, lenses: Sequence[Lens], view: LensView) -> LiveView:
    """The app's live parameters for ``view`` of the camera on ``channel`` with
    ``lenses``. One lens names that lens; a layout of several names every listed lens
    (index 0 for the fixed one, 1 for the others), or the fixed one alone when the
    camera lists none."""
    stitch, camera = _LAYOUTS[view]
    if stitch is StitchMode.SINGLE:
        order = [(0, int(camera))]
    elif lenses:
        order = [(0 if lens.id == CameraId.FIXED else 1, lens.id) for lens in lenses]
    else:
        order = [(0, int(CameraId.FIXED))]
    return LiveView(
        view=view,
        stitch_mode=stitch,
        chn_list=tuple(
            MappingProxyType({"cameraType": 0, "chn": channel, "index": index, "sensor": sensor})
            for index, sensor in order
        ),
        audio_chn=channel,
        station_video_type=PIP_STATION_VIDEO_TYPE if stitch is StitchMode.PIP else int(camera),
        pip_cord=PIP_CORD_DEFAULT if stitch is StitchMode.PIP else None,
    )


def player_input(
    *, account_id: str, key_hex: str, view: LiveView, station_fields: bool
) -> dict[str, Any]:
    """The input the app's P2P live player hands a camera's handler for a live open.

    ``station_fields`` adds ``view``, which the player sends only to a HomeBase 3
    (:attr:`~..p2p.session.StationSession.homebase3`). ``key_hex`` is the client's media
    key.
    """
    out: dict[str, Any] = {
        "key": key_hex,
        "userId": account_id,
        "ClientOS": "ANDROID",
        "streamType": 0,
        "cameraType": 0,
        "entryType": 0,
    }
    if not station_fields:
        return out
    cord = (
        ""
        if view.pip_cord is None
        else _compact(dict(zip(PIP_CORD_KEYS, view.pip_cord, strict=True)))
    )
    return out | {
        "extValue": 1000,
        "chn_list": _compact([dict(e) for e in view.chn_list]),
        "audio_chn": view.audio_chn,
        "stitch_mode": int(view.stitch_mode),
        "station_video_type": view.station_video_type,
        "pip_cord": cord,
    }


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))
