"""Decoding the station's parameter notifies: values it pushes in a 0x0547 frame.

A station reports some parameter changes between dumps as a JSON notify. The device is
the frame's subheader byte 2 (255 = the station); the forms, as the eufy app reads them
(see docs/protocol/events.md § Parameter notifies):

* a sensor's status list, ``{"cmd": 1829, "payload": {"params": [{"param_type": t,
  "param_value": v}, ...]}}``: each ``t`` := ``v``. ``params`` may also be a JSON string
  of the list, or the list written ``key=value``;
* an entry sensor's door state, ``{"cmd": 1550, "payload": {"status": s}}``: 1550 := ``s``;
* ``{"cmd": t, "payload": {"type": "updateCameraInfo", "value": v}}``: ``t`` := ``v``.

An int value is filed as its decimal string, as the dump's values are. Pure: the session
decrypts and files the values.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from ..exceptions import ProtocolError
from ._json import json_int, loads_json

CMD_SENSOR_STATUS: Final = 1829
"""A sensor's status list (the app's ``APP_CMD_SENSOR_STATUS``)."""
CMD_ENTRY_SENSOR_STATUS: Final = 1550
"""An entry sensor's door state, also the parameter that holds it."""
UPDATE_CAMERA_INFO: Final = "updateCameraInfo"
"""The ``payload.type`` of a notify that sets the parameter its ``cmd`` names."""

_KEY_EQUALS = re.compile(r"(\w+)=")


@dataclass(frozen=True, slots=True)
class ParamNotify:
    """The values one parameter notify sets, by parameter id."""

    values: Mapping[int, str] = field(default_factory=dict)
    skipped: int = 0
    """Items (or a whole notify) that carry no usable id or value, left out."""


def _value(raw: object) -> str | None:
    """A parameter value as filed: a string as is, an int as its decimal; else None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw)
    return raw if isinstance(raw, str) else None


def _object(raw: object) -> Mapping[str, Any] | None:
    """A JSON object, also when written as a JSON string; else None."""
    if isinstance(raw, str):
        try:
            raw = loads_json(raw)
        except ProtocolError:
            return None
    return raw if isinstance(raw, Mapping) else None


def _status_list(raw: object) -> list[Any] | None:
    """The 1829 ``params`` list: a list, or text holding one (JSON, or ``key=value``)."""
    if isinstance(raw, str):
        text = raw
        try:
            raw = loads_json(text)
        except ProtocolError:
            try:
                raw = loads_json(_KEY_EQUALS.sub(r'"\1":', text))
            except ProtocolError:
                return None
    return raw if isinstance(raw, list) else None


def _sensor_status(payload: Mapping[str, Any] | None) -> ParamNotify:
    items = _status_list(payload.get("params")) if payload is not None else None
    if items is None:
        return ParamNotify(skipped=1)
    values: dict[int, str] = {}
    skipped = 0
    for item in items:
        pid = json_int(item.get("param_type")) if isinstance(item, Mapping) else None
        value = _value(item.get("param_value")) if isinstance(item, Mapping) else None
        if pid is None or value is None:
            skipped += 1
            continue
        values[pid] = value
    return ParamNotify(values=values, skipped=skipped)


def _single(pid: int, raw: object) -> ParamNotify:
    value = _value(raw)
    return ParamNotify(skipped=1) if value is None else ParamNotify(values={pid: value})


def decode_param_notify(obj: Mapping[str, Any]) -> ParamNotify | None:
    """The values a 0x0547 JSON object sets; None when it is no parameter notify.

    A notify of a known form whose items carry no usable id or value gives the usable
    ones and counts the rest in :attr:`ParamNotify.skipped`.
    """
    cmd = json_int(obj.get("cmd"))
    if cmd is None:
        return None
    payload = _object(obj.get("payload"))
    if payload is not None and payload.get("type") == UPDATE_CAMERA_INFO:
        return _single(cmd, payload.get("value"))
    if cmd == CMD_SENSOR_STATUS:
        return _sensor_status(payload)
    if cmd == CMD_ENTRY_SENSOR_STATUS:
        status = json_int(payload.get("status")) if payload is not None else None
        return _single(cmd, status)
    return None
