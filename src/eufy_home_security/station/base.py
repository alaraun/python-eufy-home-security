"""Helpers the modules of the ``station`` package share."""

from __future__ import annotations

from typing import Final, NamedTuple

from ..cloud.models import CloudDevice
from ..models import ValueSource

_NOT_PAIRED: Final = "the device is not paired to this station"


def own_channel(device: CloudDevice) -> int | None:
    """The channel a standalone station's own block is filed under (its
    ``device_channel``, 0 when the cloud gives none); None for a hub."""
    if not device.is_standalone:
        return None
    return 0 if device.channel is None else device.channel


class ParamReport(NamedTuple):
    """A device's value of one parameter as last reported (``Station._param_report``)."""

    value: str
    source: ValueSource
    at: float | None
    """Epoch seconds the value dates from: its arrival over P2P, or the cloud's upload
    time of its copy; None when the cloud gives none."""
