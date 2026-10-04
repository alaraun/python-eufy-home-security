"""Cloud push events over Firebase Cloud Messaging."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._lazy import lazy_exports

if TYPE_CHECKING:
    from .decode import decode_push
    from .fcm import PushListener

__all__ = ["PushListener", "decode_push"]

__getattr__, __dir__ = lazy_exports(
    __name__, globals(), {"decode_push": "decode", "PushListener": "fcm"}
)
