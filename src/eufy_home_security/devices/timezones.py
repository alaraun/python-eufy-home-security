"""Device time zones: the eufy app's zone table (``data/timezones.json``).

A device keeps its zone in parameter 1215 as ``<POSIX TZ rule>|1.<sn>``, the form the
app writes: the rule sets the device clock, ``sn`` names the table row. A zone is offered
and written by its IANA id; :func:`encode_zone` renders the device form and
:func:`decode_zone` reads it back. The table is generated from the app by
``scripts/gen_timezones.py``.
"""

from __future__ import annotations

import functools
import importlib.resources
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..exceptions import ModelDataError

__all__ = [
    "TIMEZONE_DOMAIN",
    "TimeZone",
    "decode_zone",
    "encode_zone",
    "time_zones",
    "zone_ids",
]

#: The ``domain`` of a model-file setting whose values are this table's zone ids.
TIMEZONE_DOMAIN: Final = "timezone"
_FILE: Final = "timezones.json"
_SN_MARK: Final = "|1."
_SN: Final = re.compile(r"\d+")


@dataclass(frozen=True, slots=True)
class TimeZone:
    """One row of the app's zone table."""

    id: str
    """The IANA zone id (``Europe/Tallinn``); a key of ``zoneinfo``."""
    posix: str
    """The POSIX TZ rule the device clock follows (``EET-2EEST,M3.5.0/3,M10.5.0/4``)."""
    sn: int
    """The app's row number, kept with the rule on the device."""

    @property
    def device_value(self) -> str:
        """The value a device stores for this zone (param 1215)."""
        return f"{self.posix}{_SN_MARK}{self.sn}"


@dataclass(frozen=True, slots=True)
class _Table:
    zones: tuple[TimeZone, ...]
    by_id: Mapping[str, TimeZone]
    by_sn: Mapping[int, TimeZone]


@functools.cache
def _table() -> _Table:
    resource = importlib.resources.files("eufy_home_security.devices.data").joinpath(_FILE)
    try:
        data = json.loads(resource.read_text(encoding="utf-8"))
        zones = tuple(
            TimeZone(id=str(z["id"]), posix=str(z["posix"]), sn=int(z["sn"])) for z in data["zones"]
        )
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError) as err:
        raise ModelDataError(f"{_FILE}: {err}") from err
    by_id = {z.id: z for z in zones}
    by_sn = {z.sn: z for z in zones}
    if not zones or len(by_id) != len(zones) or len(by_sn) != len(zones):
        raise ModelDataError(f"{_FILE}: empty, or a duplicate id or sn")
    return _Table(zones, MappingProxyType(by_id), MappingProxyType(by_sn))


def time_zones() -> tuple[TimeZone, ...]:
    """Every zone of the table, in the app's order (by id). Reads package data on the
    first call: call it off the event loop the first time."""
    return _table().zones


def zone_ids() -> tuple[str, ...]:
    """The IANA ids of :func:`time_zones`, in the same order."""
    return tuple(z.id for z in _table().zones)


def encode_zone(zone_id: str) -> str:
    """The device value for IANA id ``zone_id``; ValueError for an id the table lacks."""
    zone = _table().by_id.get(zone_id)
    if zone is None:
        raise ValueError(f"{zone_id!r} is not a zone of the app's table")
    return zone.device_value


def decode_zone(raw: str | None) -> str | None:
    """The IANA id of a device value ``<rule>|1.<sn>``; None for any other form.

    A value without the row number (a bare IANA id or a bare rule) is not placed: a
    device given a bare id stores it but runs its clock on UTC, and one rule serves many
    zones. An unknown row number is None too.
    """
    if raw is None or _SN_MARK not in raw:
        return None
    sn = raw.split(_SN_MARK, 1)[1].split("|", 1)[0]
    if not _SN.fullmatch(sn):
        return None
    zone = _table().by_sn.get(int(sn))
    return None if zone is None else zone.id
