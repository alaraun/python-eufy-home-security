"""Helpers the modules of the ``station`` package share."""

from __future__ import annotations

from typing import Final

from ..cloud.models import CloudDevice

_NOT_PAIRED: Final = "the device is not paired to this station"


def own_channel(device: CloudDevice) -> int | None:
    """The channel a standalone station's own block is filed under (its
    ``device_channel``, 0 when the cloud gives none); None for a hub."""
    if not device.is_standalone:
        return None
    return 0 if device.channel is None else device.channel
