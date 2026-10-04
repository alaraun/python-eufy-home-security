"""Wire recipes: what the eufy app sends for a thing-model action, per device.

The app hard-codes no per-device command table. Per product code it downloads a
thing description (the actions, properties and events a model has) and a handler
script, ``<PN>Handle.mix.js``, whose parsers turn an action's input into a
*recipe*: the command, a sub-command, the parameters, and where the answer arrives.
A small native executor sends the recipe (see ``docs/reference/thing-models.md``).

This module holds the recipes the library uses, as pure builders whose output is
exactly the handler's for the same input. ``scripts/thing_models.py`` runs the
handlers offline and writes their output for fixed inputs to
``tests/fixtures/thing_models/``; the tests hold these builders to it, so a new
handler version shows up as a failing golden, not as a surprise on hardware.
:meth:`Recipe.plaintext` gives the bytes to send; framing and encryption are the
session's job (:meth:`~..p2p.session.StationSession.async_run_recipe`).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Final

from ..exceptions import ProtocolError, UnsupportedError
from ..p2p._json import json_int
from ..p2p.xzyh import FrameType


class RecipeCommand(IntEnum):
    """The outer command of a recipe: which executor path sends it (the XZYH frame type)."""

    STOP_LIVE_STREAM = FrameType.STOP_REALTIME_MEDIA
    """Sent bare: an XZYH frame of this type with four zero bytes."""
    SET_PAYLOAD = FrameType.CMD_TRANSFER
    """A ``DeviceMsgBean`` with ``cmd`` = the sub-command (the station path)."""
    NOTIFY_PAYLOAD = FrameType.NOTIFY_PAYLOAD
    """Not sent: the frame type a notify-answered recipe waits for."""
    DOORBELL_PAYLOAD = FrameType.DOORBELL_PAYLOAD
    """``{"commandType": sub-command, "data": params}``: the standalone-device path."""


class SubCommand(IntEnum):
    """Sub-commands the library's recipes use (the handler's ``P2PCommandCode`` names)."""

    SUB_CMD_START_LIVESTREAM = 1000
    INDOOR_ROTATE = 6030
    COMMAND_INDOOR_SPAN_SET_POINT = 6032
    COMMAND_INDOOR_SPAN_DEL_POINT = 6033
    COMMAND_INDOOR_SPAN_CRUISE_QUERY = 6034
    COMMAND_INDOOR_SPAN_CRUISE_PREVIEW = 6035
    COMMAND_APP_SPAN_PTZ_PIC = 6097
    COMMAND_APP_SET_DEFAULT_POSITION = 6242
    COMMAND_DUAL_CAMERA_ZOOM = 6203


class PanTilt(IntEnum):
    """A one-step pan/tilt direction: the ``rotate_type`` of a 6030 recipe.

    Each value moves the camera one fixed step and stops; there is no separate
    stop command (on a T8170 the view shifts once and then holds). The name is the
    way the camera turns, which is the way the view moves: after ``LEFT`` the picture
    shows what was left of it.
    """

    LEFT = 1
    RIGHT = 2
    UP = 3
    DOWN = 4


class ResultFrom(IntEnum):
    """Where a recipe's answer arrives (the handler's ``ResultFrom``)."""

    CALLBACK = 0
    """The command's own receipt or reply."""
    NOTIFY = 1
    """A 1351 notify whose ``cmd`` is the recipe's ``notify_sub_cmd``, else its ``sub_cmd``."""
    PURE_NOTIFY = 2


class ConnectType(StrEnum):
    """How a device is reached: through which kind of station, or on its own."""

    HB1 = "HB1"
    HB2 = "HB2"
    HB3 = "HB3"
    HB4 = "HB4"
    M8020 = "M8020"
    M8021 = "M8021"
    M8022 = "M8022"
    M8023 = "M8023"
    M8024 = "M8024"
    M8025 = "M8025"
    T9000 = "T9000"
    T7000 = "T7000"
    NVR = "NVR"
    SINGLE = "SINGLE"
    """A standalone device: its own station."""


PARENT_CONNECT_TYPES: Final[Mapping[str, ConnectType]] = MappingProxyType(
    {
        "T8030": ConnectType.HB3,
        "T8010": ConnectType.HB2,
        "T8001": ConnectType.HB1,
        "T8020": ConnectType.M8020,
        "T8021": ConnectType.M8021,
        "T8022": ConnectType.M8022,
        "T8023": ConnectType.M8023,
        "T9000": ConnectType.T9000,
        "T8N00": ConnectType.NVR,
        "T7000": ConnectType.T7000,
        "T8025": ConnectType.M8025,
        "T8024": ConnectType.M8024,
        "T8040": ConnectType.HB4,
    }
)
"""The parent (station) serial prefix that makes a device a sub-device of that kind
(the handler's ``getConnectType``); any other parent means a standalone device."""


def connect_type(parent_sn: str | None, device_sn: str | None) -> ConnectType:
    """How the device ``device_sn`` under the station ``parent_sn`` is reached.

    The handler's rule: the parent's serial prefix names the station kind; without both
    serials the device counts as standalone. The handler's outdoor-mode exception
    (param 6271) is not applied: no T8030, T8160, T8170 or T8910 dump carries 6271.
    """
    if parent_sn is None or device_sn is None:
        return ConnectType.SINGLE
    return PARENT_CONNECT_TYPES.get(parent_sn[:5], ConnectType.SINGLE)


@dataclass(frozen=True, slots=True, kw_only=True)
class Recipe:
    """One command as the app's handler describes it.

    ``params`` is sent as given (the handler's key order is kept). ``timeout`` is
    the handler's, in seconds, when it names one.
    """

    identifier: str
    cmd: int
    sub_cmd: int | None = None
    params: Mapping[str, Any] | None = None
    notify_cmd: int | None = None
    notify_sub_cmd: int | None = None
    """The ``cmd`` of the answering notify when it differs from :attr:`sub_cmd`;
    the T8170 handler names none, so the notify carries the sub-command itself."""
    result_from: ResultFrom = ResultFrom.CALLBACK
    timeout: float | None = None

    @property
    def answer_cmd(self) -> int | None:
        """The ``cmd`` of the 1351 notify that answers this recipe, if one does."""
        if self.result_from is ResultFrom.CALLBACK:
            return None
        return self.notify_sub_cmd if self.notify_sub_cmd is not None else self.sub_cmd

    def plaintext(self) -> bytes:
        """The bytes the executor encrypts into a frame of type :attr:`cmd`.

        A 1700 recipe is ``{"commandType": sub_cmd, "data": params}`` (``data``
        omitted without params); a bare 1004 is four zero bytes, as the app sends it.
        Raises :class:`~..exceptions.UnsupportedError` for a recipe shape the library
        does not send this way (1350 recipes go through ``async_send_command``).
        """
        if self.cmd == RecipeCommand.DOORBELL_PAYLOAD and self.sub_cmd is not None:
            body: dict[str, Any] = {"commandType": self.sub_cmd}
            if self.params is not None:
                body["data"] = dict(self.params)
            return json.dumps(body, separators=(",", ":")).encode()
        if self.cmd == RecipeCommand.STOP_LIVE_STREAM and self.params is None:
            return bytes(4)
        raise UnsupportedError(f"recipe {self.identifier} (cmd {self.cmd}) has no direct encoding")

    def as_handler_dict(self) -> dict[str, Any]:
        """The recipe in the handler's own shape (the golden files' ``p2p`` object),
        without the fields the library does not use (``parsePayloadAction``,
        ``payloadFrom``, ``rtcSendRoute``, ``dropSameRequest``, ``condition``)."""
        out: dict[str, Any] = {"cmd": self.cmd}
        if self.sub_cmd is not None:
            out["subCmd"] = self.sub_cmd
        if self.timeout is not None:
            out["timeout"] = round(self.timeout * 1000)
        if self.notify_cmd is not None:
            out["notifyCmd"] = self.notify_cmd
        if self.notify_sub_cmd is not None:
            out["notifySubCmd"] = self.notify_sub_cmd
        if self.result_from is not ResultFrom.CALLBACK:
            out["resultFrom"] = int(self.result_from)
        if self.params is not None:
            out["params"] = dict(self.params)
        return out


HANDLER_UNUSED_KEYS: Final = frozenset(
    {"parsePayloadAction", "payloadFrom", "rtcSendRoute", "dropSameRequest", "condition"}
)
"""Handler recipe keys the library does not act on: the JS result shaping, the WebRTC
route, and the native request de-duplication."""

LIVE_OPEN_TIMEOUT: Final = 15.0
"""The handler's timeout for a live open (15000 ms)."""


def open_live_stream_single(
    *,
    channel: int,
    account_id: str,
    key_hex: str,
    entry_type: int = 0,
    camera_type: int = 0,
    stream_type: int = 0,
) -> Recipe:
    """Open live video on a standalone device (``openLiveStream1700``).

    ``key_hex`` is the RSA-1024 modulus of the stream key, ``account_id`` the
    station owner's id. Verified on a T8170: the HomeBase's 1350/1003 open is taken
    but never streams there.
    """
    return Recipe(
        identifier="open_live_stream",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.SUB_CMD_START_LIVESTREAM,
        timeout=LIVE_OPEN_TIMEOUT,
        params=MappingProxyType(
            {
                "cmd": int(SubCommand.SUB_CMD_START_LIVESTREAM),
                "mChannel": channel,
                "account_id": account_id,
                "mValueStrSub": account_id,
                "mValue3": 0,
                "mValue5": 0,
                "restore": 0,
                "video_type": 12,
                "encryptkey": key_hex,
                "entrytype": entry_type,
                "accountId": account_id,
                "camera_type": camera_type,
                "ivalue": 1,
                "extValue": 1000,
                "streamtype": stream_type,
            }
        ),
    )


def close_live_stream() -> Recipe:
    """Stop live video: a bare 1004 (every connect type's handler recipe)."""
    return Recipe(identifier="close_live_stream", cmd=RecipeCommand.STOP_LIVE_STREAM)


MIN_ZOOM: Final = 1.0
"""The widest picture zoom (1x). The camera reports 1x as ``dstZoom`` 0 or 1."""
MAX_ZOOM: Final = 12.0
"""The largest picture zoom the library sends. Measured on a T8170: 1-12 give the zoom
asked for, within 10 %; the camera stops at about 14x, whatever is asked beyond."""


def set_picture_zoom(zoom: float) -> Recipe:
    """Zoom the picture to ``zoom`` (``set_picture_zoom``): a 1350 ``DeviceMsgBean`` of
    cmd 6203 about the picture centre (``offset`` false, no window).

    The camera receipts it and echoes the parameters in a 6203 notify; the picture
    changes within about 3 s.
    """
    return Recipe(
        identifier="set_picture_zoom",
        cmd=RecipeCommand.SET_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_DUAL_CAMERA_ZOOM,
        params=MappingProxyType(
            {
                "x": 0,
                "y": 0,
                "w": 0,
                "h": 0,
                "offset": False,
                "orgZoom": 0,
                "dstZoom": _js_number(zoom),
            }
        ),
    )


def reported_zoom(obj: Mapping[str, Any]) -> float | None:
    """The picture zoom a 6203 notify reports (``payload.dstZoom``, 0 read as 1x);
    None when ``obj`` is not one."""
    if json_int(obj.get("cmd")) != SubCommand.COMMAND_DUAL_CAMERA_ZOOM:
        return None
    payload = obj.get("payload")
    value = payload.get("dstZoom") if isinstance(payload, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return max(float(value), MIN_ZOOM)


MAX_PRESET_SLOTS: Final = 5
"""How many preset slots a pan/tilt camera stores at once.

Measured on a T8170: a sixth :func:`store_preset` is receipted like any other and
stores nothing, so a store is only real once the read-back shows the slot in use.
"""


def query_preset_positions() -> Recipe:
    """Read the preset slots; answered by a 1351 notify carrying ``points``."""
    return Recipe(
        identifier="query_preset_positions",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_INDOOR_SPAN_CRUISE_QUERY,
        notify_cmd=RecipeCommand.NOTIFY_PAYLOAD,
        result_from=ResultFrom.NOTIFY,
        params=MappingProxyType({"value": 0}),
    )


def goto_preset(index: int) -> Recipe:
    """Turn the camera to preset ``index`` (``set_ptz_cruise_preview``)."""
    return Recipe(
        identifier="set_ptz_cruise_preview",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_INDOOR_SPAN_CRUISE_PREVIEW,
        params=MappingProxyType({"value": index}),
    )


def preset_picture(index: int) -> Recipe:
    """The picture stored for preset ``index`` (``get_preset_position_pic``);
    answered by a 1351 notify."""
    return Recipe(
        identifier="get_preset_position_pic",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_APP_SPAN_PTZ_PIC,
        notify_cmd=RecipeCommand.NOTIFY_PAYLOAD,
        result_from=ResultFrom.NOTIFY,
        params=MappingProxyType({"value": index}),
    )


def set_default_preset(index: int, *, confirm: bool = False) -> Recipe:
    """Make preset ``index`` the slot the camera returns to when idle
    (``default_preset_positions``): a 1350 ``DeviceMsgBean`` of cmd 6242.

    ``confirm`` sends ``settingstate`` 1, the app's answer to a -502 refusal
    (its "set anyway?" dialog); 0 otherwise. The handler follows with a turn to the
    slot (6035) and its stored picture (6097); the library turns and reads back.
    """
    return Recipe(
        identifier="default_preset_positions",
        cmd=RecipeCommand.SET_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_APP_SET_DEFAULT_POSITION,
        params=MappingProxyType({"index": index, "settingstate": int(confirm)}),
    )


def ptz_rotate(*, cmd_type: int, rotate_type: int, zoom: float = 1.0) -> Recipe:
    """Pan or tilt (``ptz_action_control``)."""
    return Recipe(
        identifier="ptz_action_control",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.INDOOR_ROTATE,
        params=MappingProxyType(
            {
                "cmd_type": cmd_type,
                "rotate_type": rotate_type,
                "zoom": _js_number(zoom),
                "ivalue": -1,
            }
        ),
    )


def pan_tilt(direction: PanTilt, *, zoom: float = 1.0) -> Recipe:
    """Move the camera one step in ``direction`` (the handler's ``ptz_action_control``).

    The recipe the app sends for a press on its pan/tilt pad: ``cmd_type`` 1,
    ``rotate_type`` the direction, ``ivalue`` -1. Receipt only — the camera
    answers no result and holds the new position until it goes idle, when it
    returns to its default preset.
    """
    return ptz_rotate(cmd_type=1, rotate_type=int(direction), zoom=zoom)


def store_preset(index: int, *, confirm: bool = False) -> Recipe:
    """Store the camera's current view in preset slot ``index``
    (``set_preset_positions``): a 1700 recipe of sub-command 6032.

    ``confirm`` sends ``settingstate`` 1, the app's answer to a refusal dialog.
    Receipt only: read the slots back (6034) to see whether the slot took. A
    camera whose slots are full receipts the command and stores nothing, and a
    camera still moving answers code 1 — see
    :meth:`~..station.Station.async_store_preset`.
    """
    return Recipe(
        identifier="set_preset_positions",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_INDOOR_SPAN_SET_POINT,
        params=MappingProxyType({"settingstate": int(confirm), "value": index}),
    )


def delete_preset(index: int) -> Recipe:
    """Clear preset slot ``index`` (``delete_preset_positions``): 1700 / 6033,
    receipt only; confirm with a 6034 read-back."""
    return Recipe(
        identifier="delete_preset_positions",
        cmd=RecipeCommand.DOORBELL_PAYLOAD,
        sub_cmd=SubCommand.COMMAND_INDOOR_SPAN_DEL_POINT,
        params=MappingProxyType({"value": index}),
    )


def _js_number(value: float) -> float | int:
    """``value`` as JavaScript serialises it: a whole number without a fraction (the
    handler sends ``"zoom": 1``, where Python's JSON would write ``1.0``)."""
    number = float(value)
    return int(number) if number.is_integer() else number


@dataclass(frozen=True, slots=True, kw_only=True)
class PresetPosition:
    """One preset slot of a pan/tilt camera, as the camera reports it (6034)."""

    index: int
    enabled: bool
    zoom: int
    is_default: bool
    """The slot the camera returns to on its own when idle (after a turn, a preset
    image or tracking); set with :func:`set_default_preset`."""


def parse_preset_positions(payload: Mapping[str, Any]) -> tuple[PresetPosition, ...]:
    """The slots of a 6034 notify payload (``{"points": [...]}``), in index order.

    Raises :class:`~..exceptions.ProtocolError` for a payload without a points list
    or a point without an integer index.
    """
    points = payload.get("points")
    if not isinstance(points, Sequence) or isinstance(points, (str, bytes)):
        raise ProtocolError("preset reply carries no points list")
    slots: list[PresetPosition] = []
    for point in points:
        if not isinstance(point, Mapping) or not isinstance(point.get("index"), int):
            raise ProtocolError("preset reply has a point without an integer index")
        slots.append(
            PresetPosition(
                index=point["index"],
                enabled=bool(point.get("enable", 0)),
                zoom=int(point.get("zoom", 1)),
                is_default=bool(point.get("isdefault", 0)),
            )
        )
    return tuple(sorted(slots, key=lambda slot: slot.index))


def free_preset_slot(slots: Sequence[PresetPosition]) -> int | None:
    """The lowest slot index of ``slots`` not in use, or None when none can take a
    store: every index is in use, or :data:`MAX_PRESET_SLOTS` already are."""
    if sum(s.enabled for s in slots) >= MAX_PRESET_SLOTS:
        return None
    return min((s.index for s in slots if not s.enabled), default=None)
