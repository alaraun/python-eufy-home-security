"""The MQTT form of a lock command: the P2P payload object as base64 ``trans`` text.

The eufy app sends a lock's P2P command over its MQTT broker as the payload object
``{"cmd", "mChannel": 0, "mValue3": 0, "payload"}`` (its JSON writer's form), base64 in the
message's ``trans``; the lock answers the same way (declared, eufy app;
docs/protocol/mqtt.md § Lock commands). Pure: no I/O.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from typing import Any

from ..exceptions import ProtocolError
from .anker import gson_json


def encode_trans(command: int, payload: Mapping[str, object]) -> str:
    """The ``trans`` text of P2P command ``command`` carrying ``payload``."""
    text = gson_json({"cmd": command, "mChannel": 0, "mValue3": 0, "payload": payload})
    return base64.b64encode(text.encode()).decode("ascii")


def decode_trans(trans: str) -> tuple[int, Mapping[str, Any]]:
    """``(command, payload object)`` of a ``trans`` text; whitespace and missing base64
    padding are accepted. :class:`ProtocolError` for text that is no such object."""
    compact = "".join(trans.split())
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        obj = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, ValueError) as err:
        raise ProtocolError(f"MQTT lock message trans does not decode: {err}") from err
    if not isinstance(obj, Mapping):
        raise ProtocolError("MQTT lock message trans is no object")
    command, payload = obj.get("cmd"), obj.get("payload")
    if not isinstance(command, int) or isinstance(command, bool):
        raise ProtocolError("MQTT lock message trans names no command")
    if not isinstance(payload, Mapping):
        raise ProtocolError("MQTT lock message trans carries no payload object")
    return command, payload
