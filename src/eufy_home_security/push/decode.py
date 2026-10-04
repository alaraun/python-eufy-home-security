"""Decode an eufy FCM data message into a :class:`SecurityEvent`.

A message is a flat string map (``app_data``). The event itself is the ``payload``
field: base64 (either alphabet, padding optional) of NUL-terminated JSON, not
encrypted. Older firmware uses single-letter keys inside it, newer firmware the
long names, and a single payload has been seen mixing both — so the short keys are
mapped onto the long ones rather than choosing a dialect.

Two outer fields decide what is lifted at all:

* ``app_tab`` names the app a message is for. The eufy account's FCM channel also
  carries ``eufy_home`` (robot vacuum) pushes; :func:`is_security_push` is False for
  those and the listener drops them. A message without ``app_tab`` is kept.
* ``type`` is the device type; at or above :data:`SERVER_PUSH_MIN_TYPE` it is an
  account-level server push (device removed, invitation, alarm notify) whose
  payload has a different, undocumented shape. Those decode *raw-only*: nothing
  but ``dedupe_key`` is lifted, the message stays in ``raw``. Below it, the outer
  ``type`` is never an alarm cause: ``alarm_type`` comes from the inner payload.

The inner payload is the same object the station pushes over P2P, so both
decoders lift it through one :class:`~..events.PushFieldReader`.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from collections.abc import Callable, Mapping
from typing import Any, Final

from ..events import (
    RECORDING_SUFFIX,
    EventSource,
    PushFieldReader,
    SecurityEvent,
    coerce_int,
    coerce_str,
    wall_ms,
)

# Short key -> long name. The long names are the app's own field names (its toString
# prints them), not obfuscated ones.
SHORT_KEYS: Final[Mapping[str, str]] = {
    "a": "msg_type",
    "s": "device_sn",
    "c": "channel",
    "n": "name",
    "p": "file_path",
    "t": "event_time",
    "m": "online",
    "e": "sensor_open",
    "k": "cipher",
    "f": "person_name",
    "i": "fetch_id",
    "j": "sense_id",
}

#: Outer ``type`` at or above this is an account-level server push (raw-only).
SERVER_PUSH_MIN_TYPE: Final = 10100

#: The ``app_tab`` of eufy Security pushes; other apps share the FCM channel.
SECURITY_APP_TAB: Final = "eufy_security"

# Below this an epoch value is seconds (every FCM `event_time` seen and the
# short-key `t`), at or above it milliseconds.
_MS_THRESHOLD: Final = 10_000_000_000


def decode_payload(value: object) -> dict[str, Any]:
    """Decode the ``payload`` field to a dict with short keys expanded; {} if it is not one."""
    if not isinstance(value, str) or not value.strip():
        return {}
    text = value.strip().replace("_", "/").replace("-", "+")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return {}
    body = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    try:
        parsed = json.loads(body)
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    for short, long in SHORT_KEYS.items():
        if short in parsed and long not in parsed:
            parsed[long] = parsed[short]
    return parsed


def _first(*values: object) -> object:
    """The first value that is neither None nor an empty string."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _ms(value: object) -> int | None:
    """An epoch in seconds or milliseconds (int, float or string) as ms; None if not one."""
    if value is None or isinstance(value, bool):
        return None
    try:
        num = float(str(value).strip())
    except ValueError:
        return None
    if not math.isfinite(num) or num <= 0:
        return None
    return int(num * 1000) if num < _MS_THRESHOLD else int(num)


def is_security_push(data: Mapping[str, Any]) -> bool:
    """False for a message addressed to another eufy app (``app_tab``)."""
    tab = data.get("app_tab")
    return tab in (None, "", SECURITY_APP_TAB)


def decode_push(data: Mapping[str, Any], *, now_ms: Callable[[], int] = wall_ms) -> SecurityEvent:
    """Turn one FCM data message into a :class:`SecurityEvent`. Never raises.

    ``guard_mode`` is the inner ``arming`` field — the one guard-mode source that
    also covers changes made outside P2P (an arm from the app). It is not lifted
    when the event time was rejected: a push that cannot be ordered must not move
    the reported mode (``guard_mode`` is then listed in ``rejected_fields`` too).
    ``push_id`` is the outer ``span_id``. The event time is the inner payload's
    ``trigger_time``/``create_time`` (ms) when it has one — the time the P2P copy
    carries, where the outer ``event_time`` is about 3 s later — else the outer (or
    short-key ``t``) time, converted to ms before it is validated (FCM times are
    seconds). Everything else stays in
    ``raw`` (the message as received; :func:`decode_payload` re-derives the inner
    object). A server push (``type`` ≥ :data:`SERVER_PUSH_MIN_TYPE`) lifts only
    ``push_id``.
    """
    try:
        push_id = coerce_str(_first(data.get("span_id")))
        device_type = coerce_int(data.get("type"))
        if device_type is not None and device_type >= SERVER_PUSH_MIN_TYPE:
            return SecurityEvent(source=EventSource.CLOUD, push_id=push_id, raw=data)
        inner = decode_payload(data.get("payload"))
        reader = PushFieldReader(EventSource.CLOUD, now_ms=now_ms)
        common = reader.common(inner)
        for name in ("channel", "msg_type", "event_type"):
            if common[name] is None:
                common[name] = coerce_int(data.get(name))
        inner_ms = reader.payload_time(inner)
        event_time_ms = reader.event_time(
            inner_ms
            if inner_ms is not None
            else _ms(_first(data.get("event_time"), inner.get("event_time")))
        )
        guard_mode = reader.guard_mode(inner)
        video_path = reader.path("video_path", inner.get("file_path"), RECORDING_SUFFIX)
        return SecurityEvent(
            source=EventSource.CLOUD,
            station_sn=coerce_str(_first(data.get("station_sn"), inner.get("station_sn"))),
            device_sn=coerce_str(_first(data.get("device_sn"), inner.get("device_sn"))),
            event_time_ms=event_time_ms,
            guard_mode=guard_mode,
            pic_url=coerce_str(inner.get("pic_url")),
            video_path=video_path,
            push_id=coerce_str(_first(push_id, inner.get("span_id"))),
            rejected_fields=frozenset(reader.rejected),
            raw=data,
            **common,
        )
    except Exception:
        return SecurityEvent(source=EventSource.CLOUD, raw=data)
