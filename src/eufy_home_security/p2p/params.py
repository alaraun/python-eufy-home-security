"""Parameter-dump model.

The station's PARAM_NOTIFY (0x044F) frames carry a JSON object whose ``params``
list interleaves the parameters of every device in the home, each tagged with a
``dev_type``: 255 is the station itself (guard mode, storage, firmware, LAN IP),
and 0/1/… are the paired sub-devices (cameras, sensors), each with its own
battery, RSSI and name. Flattening would collapse per-device values (three
different battery params), so a dump is grouped by ``dev_type``.

:class:`ParamDump` is a mutable accumulator: several frames merge into one view.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..exceptions import ProtocolError
from ..models import PARAM_SUB_DEVICE_SERIALS, STATION_CHANNEL, GuardMode
from ._json import json_int, loads_json

#: param_type of the selected guard mode (a string int), reported on the station's
#: dev_type (== its channel, 255): 2 while Schedule is selected. The arming command
#: uses the same id (``messages.CMD_SET_ARMING`` is derived from this).
GUARD_MODE_PARAM = 1224
#: param_type of the effective guard mode, the mode in force (the app's
#: ``GET_ALARM_MODE``): a schedule slot's mode while Schedule is selected, else equal
#: to :data:`GUARD_MODE_PARAM`. The ``0x047F`` report carries the same value.
ACTIVE_MODE_PARAM = 1151
#: param_type of the base64 JSON list of paired sub-device serials.
SUB_DEVICE_SERIALS_PARAM = PARAM_SUB_DEVICE_SERIALS
#: The shape a 1072 entry must have to be taken as a serial.
_SERIAL_SHAPE = re.compile(r"T[0-9A-Z]{15}")
#: Frame-level (not per-param) fields worth keeping.
_META_KEYS = ("main_sw_version", "sec_sw_version", "hb_bind_type", "app_cloud_encrypt")


class ParamDump:
    """Accumulates decoded 0x044F parameter objects, grouped by ``dev_type``."""

    def __init__(self) -> None:
        self.devices: dict[int, dict[int, str]] = {}
        self.meta: dict[str, Any] = {}

    def ingest(
        self, obj: Mapping[str, Any], *, aliases: Mapping[int, Sequence[int]] | None = None
    ) -> int:
        """Merge one decoded 0x044F object; return the number of params merged.

        ``aliases`` files a block under other ``dev_type`` values instead of its own: a
        standalone device's block (labelled its cloud ``device_type``) goes under the
        station (255) and the device's own channel (see :func:`standalone_aliases`).

        Tolerant of malformed dumps: a non-list ``params``, a non-object entry, an
        id that is not an int or decimal string, or a value that is not a string
        or int is skipped. Int values are stored as their decimal string.
        """
        params = obj.get("params")
        if not isinstance(params, list):
            params = []
        merged = 0
        for param in params:
            if not isinstance(param, Mapping):
                continue
            pid = json_int(param.get("param_type"))
            dev = json_int(param.get("dev_type", 0))
            value = param.get("param_value")
            if pid is None or dev is None:
                continue
            if isinstance(value, int) and not isinstance(value, bool):
                value = str(value)
            elif not isinstance(value, str):
                continue
            for target in aliases.get(dev, (dev,)) if aliases else (dev,):
                self.devices.setdefault(target, {})[pid] = value
            merged += 1
        for key in _META_KEYS:
            if key in obj:
                self.meta[key] = obj[key]
        return merged

    @property
    def station(self) -> dict[int, str]:
        """The station's own parameters (dev_type 255)."""
        return self.devices.get(STATION_CHANNEL, {})

    @property
    def guard_mode(self) -> GuardMode | int | None:
        """The selected guard mode: param 1224 on the station, else on any device.

        Returns a :class:`GuardMode` when the code is a known member, the raw int
        when it is not, and None when no device reports param 1224.
        """
        return self._mode(GUARD_MODE_PARAM)

    @property
    def active_mode(self) -> GuardMode | int | None:
        """The effective guard mode (param 1151), by the rule of :attr:`guard_mode`."""
        return self._mode(ACTIVE_MODE_PARAM)

    def _mode(self, param: int) -> GuardMode | int | None:
        for params in (self.station, *self.devices.values()):
            code = json_int(params.get(param))
            if code is None:
                continue
            try:
                return GuardMode(code)
            except ValueError:
                return code
        return None

    def flatten(self) -> dict[tuple[int, int], str | None]:
        """Every parameter as ``{(dev_type, param_type): value}``."""
        return {
            (dev, pid): value
            for dev, params in self.devices.items()
            for pid, value in params.items()
        }

    def sub_device_serials(self, *, station_sn: str | None = None) -> list[str | None]:
        """The paired sub-device serials (station param 1072, a base64 JSON list).

        Position-preserving: an entry that is not serial-shaped (``T`` + 15 uppercase
        alphanumerics), repeats an earlier entry, or equals ``station_sn`` is None, so
        the positions of the others do not move. ``[]`` when absent or undecodable.
        """
        raw = self.station.get(SUB_DEVICE_SERIALS_PARAM)
        if not raw:
            return []
        try:
            decoded = loads_json(base64.b64decode(raw + "=" * (-len(raw) % 4)))
        except (ValueError, ProtocolError):
            return []
        if not isinstance(decoded, list):
            return []
        seen: set[str] = set()
        serials: list[str | None] = []
        for item in decoded:
            valid = (
                isinstance(item, str)
                and _SERIAL_SHAPE.fullmatch(item) is not None
                and item != station_sn
                and item not in seen
            )
            if valid:
                seen.add(item)
            serials.append(item if valid else None)
        return serials


def standalone_aliases(device_type: int, channel: int) -> dict[int, tuple[int, ...]]:
    """Where a standalone device's block goes: under the station (255) and its channel.

    A T8170 labels every parameter with its cloud ``device_type`` (48), where a HomeBase
    labels its own with 255 and each paired device's with that device's channel. Filing
    the block under both keeps one shape for consumers: the guard mode and the station
    state read 255, the device's battery, signal and settings read its channel.
    """
    return {device_type: (STATION_CHANNEL, channel)}
