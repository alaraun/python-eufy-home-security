"""Decoding the station's NOTIFY_PAYLOAD (0x0547) frames.

This frame type carries two very different things, told apart only by the ``cmd``
field: a camera event push (``cmd`` 2037, a double-encoded payload byte-for-byte
identical to what the cloud relays over FCM) and the plain application-level
result of one of the client's own commands. Mistaking a push for a command result would
let, say, an arm claim success off a stranger walking past a camera.

The JSON is the station's — and under ECB anyone's on the LAN — so every field is
type-checked and the untrusted ones validated (:class:`~..events.PushFieldReader`):
a field of the wrong JSON type is dropped (None), never passed through.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ..events import (
    RECORDING_SUFFIX,
    STILL_SUFFIX,
    EventSource,
    PushFieldReader,
    SecurityEvent,
    camera_dir,
    coerce_int,
    wall_ms,
)
from ..exceptions import ProtocolError
from ..models import FrameCipher
from ._json import json_int, loads_json
from .messages import CMD_CAMERA_PUSH_NOTIFY

_NO_RECORD: Mapping[str, Any] = {}


def _is_push(obj: Mapping[str, Any]) -> bool:
    # The station writes cmd as an int, but a decimal string names the same command.
    return json_int(obj.get("cmd")) == CMD_CAMERA_PUSH_NOTIFY


def is_command_result(obj: Mapping[str, Any]) -> bool:
    """True when a 0x0547 frame is a plain command result, not a camera push."""
    return not _is_push(obj)


def _text(value: Any) -> str | None:
    """A non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _bound_record(
    records: Any, device_sn: str | None, record_id: int | None
) -> Mapping[str, Any] | None:
    """The first attached record (``rec_content`` or ``pic_content`` entry) about this
    push, or None.

    The attached records can describe an earlier event, even on another camera. When the
    push names its own ``record_id``, only a record with that ``record_id`` is about it;
    otherwise (older firmware) only one naming the push's own device.
    """
    if not isinstance(records, list):
        return None
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if record_id is not None:
            if coerce_int(record.get("record_id")) == record_id:
                return record
        elif device_sn is not None and _text(record.get("device_sn")) == device_sn:
            return record
    return None


def stamped_accounts(payload: Mapping[str, Any]) -> frozenset[str]:
    """The account ids the station stamped on a push's ``rec_content`` records, lowercased.

    The stamp is the id the station accepts commands from (the owner's), whichever
    event the record describes.
    """
    records = payload.get("rec_content")
    if not isinstance(records, list):
        return frozenset()
    return frozenset(
        account.lower()
        for record in records
        if isinstance(record, Mapping) and (account := _text(record.get("account"))) is not None
    )


def _first_record(records: Any) -> Mapping[str, Any]:
    if isinstance(records, list) and records and isinstance(records[0], Mapping):
        return records[0]
    return _NO_RECORD


def _crop_record(
    records: Any, record_id: int | None, video_path: str | None, rec_bound: bool
) -> Mapping[str, Any] | None:
    """The ``pic_content`` entry whose crop belongs to this push, or None.

    With a push ``record_id``: the entry with that ``record_id``. Without one,
    ``pic_content`` names no device, so its first entry is kept only when its crop's
    ``CameraNN`` directory agrees with ``video_path``, or, when neither path has one,
    when the ``rec_content`` binding matched.
    """
    if record_id is not None:
        return _bound_record(records, None, record_id)
    record = _first_record(records)
    crop = record.get("crop_path")
    crop_dir = camera_dir(crop) if isinstance(crop, str) else None
    if crop_dir != camera_dir(video_path) or (crop_dir is None and not rec_bound):
        return None
    return record


def decode_camera_push(
    obj: Mapping[str, Any],
    *,
    station_sn: str | None,
    frame_cipher: FrameCipher | None = None,
    now_ms: Callable[[], int] = wall_ms,
) -> SecurityEvent | None:
    """Turn a camera push (cmd 2037) into a :class:`SecurityEvent`.

    The inner ``payload`` is a JSON string (double-encoded). Returns None for any
    other 0x0547 frame (a plain command result) or an undecodable payload.
    ``dedupe_key`` exists only when the push names both its device and its time.

    ``station_sn`` is the session's station and is always the event's: the payload's
    own serials are not trusted for it. The attached records (``rec_content``,
    ``pic_content``) often describe an earlier event, so their fields are used only
    from a record bound to this push: when the push carries a ``record_id``, the record
    with that same ``record_id``; without one, a ``rec_content`` entry naming the push's
    own ``device_sn`` for ``thumb_path`` and the ``video_path`` fallback, and a
    ``pic_content`` crop whose ``CameraNN`` directory agrees with the event's recording
    (``video_path``) — or, when neither path has one, when the ``rec_content`` binding
    matched. The push's own ``file_path`` is always the ``video_path``. Paths and
    the event time (``trigger_time``, else ``create_time``, epoch ms) are validated
    and a failing value is listed in ``rejected_fields``; ``now_ms`` is the host
    clock the skew check uses.

    ``arming`` is lifted into ``guard_mode`` by the rule the cloud decoder uses
    (:meth:`~..events.PushFieldReader.guard_mode`), and only from an authenticated
    (GCM) frame: under ECB it is listed in ``rejected_fields`` and stays in ``raw``.
    **Dormant path:** the station sends no arming, alarm or alarm-delay push over P2P
    (verified on fw 3.8.7.4: it reports those facts as ``0x047F`` and the alarm frames
    instead); the lifting is kept so a firmware that does send one passes the same
    rules. :class:`~..client.EufySecurity` orders it with the cloud's guard pushes
    and the ``0x047F`` reports (:class:`~..events.GuardModeTracker`) before it becomes
    a ``GuardModeChanged``.

    ``frame_cipher`` is the cipher of the frame that carried the push. An ECB push
    is still decoded, with :attr:`SecurityEvent.authenticated` False.
    """
    if not _is_push(obj):
        return None
    payload: Any = obj.get("payload")
    if isinstance(payload, str):
        try:
            payload = loads_json(payload)
        except ProtocolError:
            return None
    if not isinstance(payload, Mapping):
        return None

    reader = PushFieldReader(EventSource.P2P, now_ms=now_ms)
    common = reader.common(payload)
    device_sn = _text(payload.get("device_sn"))
    record_id: int | None = common["record_id"]
    record = _bound_record(payload.get("rec_content"), device_sn, record_id)
    rec = record if record is not None else _NO_RECORD
    event_time = reader.event_time(reader.payload_time(payload))
    guard_mode = reader.guard_mode(payload, authenticated=frame_cipher is not FrameCipher.ECB)
    thumb_path = reader.path("thumb_path", rec.get("thumb_path"), STILL_SUFFIX)
    video_path = reader.path(
        "video_path",
        _text(payload.get("file_path")) or rec.get("storage_path"),
        RECORDING_SUFFIX,
    )
    crop = _crop_record(payload.get("pic_content"), record_id, video_path, record is not None)
    crop_path = reader.path(
        "crop_path", (crop if crop is not None else _NO_RECORD).get("crop_path"), STILL_SUFFIX
    )
    return SecurityEvent(
        source=EventSource.P2P,
        station_sn=station_sn,
        device_sn=device_sn,
        event_time_ms=event_time,
        guard_mode=guard_mode,
        thumb_path=thumb_path,
        video_path=video_path,
        crop_path=crop_path,
        pic_url=_text(payload.get("pic_url")),
        frame_cipher=frame_cipher,
        rejected_fields=frozenset(reader.rejected),
        raw=dict(payload),
        **common,
    )
