"""The station's storage record: disk and eMMC figures from ``1307`` / ``11001`` (pure).

The app's HDD screen asks ``{"cmd": 1307, "payload": {"version": 1, "cmd": 11001}}``
and the station answers with a ``0x0547`` whose ``payload.body`` holds the internal
disk (``hdd_info``), an external disk (``move_disk_info``) and the built-in eMMC
(``emmc_info``). Every size in the record is **MiB**. The station also pushes the
record unasked (when a format finishes, and as the answer to another client's query),
so :func:`storage_record` recognises it wherever it arrives.

The record comes off the network: every field is validated on its own, and a missing
or malformed one becomes ``None`` rather than an error. See
``docs/protocol/commands.md`` (Storage) for the wire format.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from ..exceptions import ProtocolError
from ._json import json_int, loads_json

#: The storage command (``NOTIFY_STORAGE``); its verb sits in ``payload.cmd``.
CMD_STORAGE: Final = 1307
#: Verb: read the storage record.
STORAGE_QUERY_INFO: Final = 11001
#: Verb: format a disk (destructive; the library never sends it).
STORAGE_FORMAT: Final = 11003
#: A standalone camera's built-in eMMC query (``SDINFO_EX``): a bare command frame of
#: this type answered by a frame of the same type with three ``int32`` (see
#: :func:`parse_sd_card_info`).
CMD_SD_INFO: Final = 1144

MIB_PER_GIB: Final = 1024
_MAX_MIB: Final = 1 << 40
"""Sizes above this (a zettabyte) are garbage, not a disk."""
_TEMPERATURE_RANGE: Final = (-40, 150)
_MAX_TEXT: Final = 256
_PARTED_READY: Final = 1
_PARTED_FORMATTING: Final = 2


def storage_query_payload() -> dict[str, int]:
    """The ``payload`` of a storage read, as the app sends it."""
    return {"version": 1, "cmd": STORAGE_QUERY_INFO}


# ── validation ───────────────────────────────────────────────────────────────


def _int(
    obj: Mapping[str, Any], key: str, low: int = -(1 << 31), high: int = (1 << 31) - 1
) -> int | None:
    value = json_int(obj.get(key))
    return value if value is not None and low <= value <= high else None


def _mib(obj: Mapping[str, Any], key: str) -> int | None:
    return _int(obj, key, 0, _MAX_MIB)


def _percent(obj: Mapping[str, Any], key: str) -> int | None:
    return _int(obj, key, 0, 100)


def _text(obj: Mapping[str, Any], key: str) -> str | None:
    value = obj.get(key)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if text and len(text) <= _MAX_TEXT and text.isprintable() else None


def _object(obj: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    value = obj.get(key)
    return value if isinstance(value, Mapping) else None


# ── the record ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class StorageMedium:
    """One storage medium of the record, with the same fields for every kind.

    :class:`DiskInfo` (the internal disk, an external disk) and :class:`EmmcInfo` (the
    built-in eMMC) share this shape, so a consumer can read either the same way. A
    figure a record does not carry stays None (a disk record has no wear, an eMMC
    record no temperature, device path or serial). Sizes are MiB, and the ``*_gib``
    figures are rounded to two decimals, like the app's.

    ``serial`` and ``label`` identify the physical disk: they are left out of
    ``repr`` and must go through :func:`~eufy_home_security.redact` in a log.
    """

    model: str | None = None
    """``device_module``, e.g. the drive's model string."""
    disk_type: int | None = None
    """``hdd_type`` (1 = a SATA SSD on the one station seen)."""
    path: str | None = None
    """The block device (``disk_path``, e.g. ``/dev/sda``)."""
    size_mib: int | None = None
    """The real size: the app's total."""
    nominal_size_mib: int | None = None
    """The advertised size."""
    used_mib: int | None = None
    """What counts as used; see the subclasses for its source."""
    system_mib: int | None = None
    """Reserved system areas."""
    recordings_used_mib: int | None = None
    """``video_used``."""
    recordings_capacity_mib: int | None = None
    """``video_size``: what recordings may occupy."""
    filesystem_used_mib: int | None = None
    """``disk_used``: the file system's own figure."""
    data_partition_mib: int | None = None
    """``data_partition_size``."""
    swap_mib: int | None = None
    """``swap_size``."""
    temperature_c: int | None = None
    """``cur_temperate``, °C."""
    health: int | None = None
    """``health``: 0 is healthy; other codes are not named by the app."""
    work_status: int | None = None
    """``work_status``: 0 idle; other codes unknown."""
    parted_status: int | None = None
    """``parted_status``: 1 ready, 2 formatting."""
    wear_percent: int | None = None
    """``eol_percent``: life used, 0-100 (end of life at 100)."""
    station_used_percent: int | None = None
    """The station's own use percentage (``data_used_percent``), when it reports one."""
    label: str | None = field(default=None, repr=False)
    """``hdd_label``: the file-system label, new on every format."""
    serial: str | None = field(default=None, repr=False)
    """``serial_number`` of the drive."""

    @property
    def free_mib(self) -> int | None:
        """``size_mib - used_mib`` (never below 0)."""
        if self.size_mib is None or self.used_mib is None:
            return None
        return max(self.size_mib - self.used_mib, 0)

    @property
    def used_percent(self) -> float | None:
        """Use, 0-100 with one decimal: the station's own figure when it reports one
        (the app shows that), otherwise ``used_mib`` of ``size_mib``."""
        if self.station_used_percent is not None:
            return float(self.station_used_percent)
        if self.size_mib is None or self.used_mib is None or self.size_mib == 0:
            return None
        return round(min(self.used_mib * 100 / self.size_mib, 100.0), 1)

    @property
    def used_gib(self) -> float | None:
        """The app's "used" figure (it labels GiB as GB)."""
        return _gib(self.used_mib)

    @property
    def size_gib(self) -> float | None:
        """The app's total."""
        return _gib(self.size_mib)

    @property
    def free_gib(self) -> float | None:
        return _gib(self.free_mib)

    @property
    def recordings_used_gib(self) -> float | None:
        return _gib(self.recordings_used_mib)

    @property
    def recordings_capacity_gib(self) -> float | None:
        return _gib(self.recordings_capacity_mib)

    @property
    def healthy(self) -> bool | None:
        """``health == 0``; None when the record has no health code."""
        return None if self.health is None else self.health == 0

    @property
    def formatting(self) -> bool | None:
        """Whether a format is in progress (``parted_status`` 2)."""
        return None if self.parted_status is None else self.parted_status == _PARTED_FORMATTING

    @property
    def ready(self) -> bool | None:
        """Whether the medium is partitioned and in use (``parted_status`` 1)."""
        return None if self.parted_status is None else self.parted_status == _PARTED_READY


@dataclass(frozen=True, slots=True, kw_only=True)
class DiskInfo(StorageMedium):
    """A disk in the storage record: the internal one (``hdd_info``) or an external one.

    ``size_mib`` is ``disk_size_1024`` and ``nominal_size_mib`` ``disk_size``;
    ``used_mib`` is the app's "used", ``system_size + system_size_data + video_used``,
    and ``system_mib`` the first two. So :attr:`used_gib` / :attr:`size_gib` match the
    app. An external disk (``move_disk_info``) carries only a path, a size and a use;
    its units are assumed to be MiB like the rest (no external disk has been seen).
    """


@dataclass(frozen=True, slots=True, kw_only=True)
class EmmcInfo(StorageMedium):
    """The station's built-in eMMC (``emmc_info``).

    ``size_mib`` is ``disk_size``, ``nominal_size_mib`` ``disk_nominal``, ``system_mib``
    ``system_size``, and ``used_mib`` = ``filesystem_used_mib`` = ``disk_used``.
    :attr:`used_percent` is the station's ``data_used_percent`` (the figure of param
    1190 and the app), which is not exactly ``used_mib`` of ``size_mib`` (20 against
    19.2 on the one station seen).
    """


@dataclass(frozen=True, slots=True, kw_only=True)
class StorageInfo:
    """One storage record of a station.

    ``disk`` is None when the record describes no internal disk: ``hdd_info`` is
    missing, or it carries neither a size nor a device path. ``external`` is None
    unless ``move_disk_info`` names a path or a size. Both "no disk" rules follow the
    record's shape: a station without a disk has not been seen.
    """

    storage_days: int | None = None
    """Days of recordings kept."""
    storage_events: int | None = None
    """Event records kept."""
    continuous_video_hours: int | None = None
    """``con_video_hours``."""
    format_transaction: str | None = None
    """The id of the last format request (``""`` → None)."""
    format_error: int | None = None
    """``format_errcode`` of the last format (0 = none)."""
    body_version: int | None = None
    disk: DiskInfo | None = None
    external: DiskInfo | None = None
    emmc: EmmcInfo | None = None

    @property
    def formatting(self) -> bool:
        """Whether any disk in the record is being formatted."""
        return any(d is not None and d.formatting for d in (self.disk, self.external))


def _gib(mib: int | None) -> float | None:
    return None if mib is None else round(mib / MIB_PER_GIB, 2)


def _sum(*values: int | None) -> int | None:
    if any(v is None for v in values):
        return None
    return sum(v for v in values if v is not None)


def _common(obj: Mapping[str, Any]) -> dict[str, Any]:
    """The fields that ``hdd_info`` and ``emmc_info`` name alike, as keyword arguments.

    Both records go through it, so a field one of them gains later is not lost.
    """
    return {
        "model": _text(obj, "device_module"),
        "disk_type": _int(obj, "hdd_type"),
        "path": _text(obj, "disk_path"),
        "recordings_used_mib": _mib(obj, "video_used"),
        "recordings_capacity_mib": _mib(obj, "video_size"),
        "filesystem_used_mib": _mib(obj, "disk_used"),
        "data_partition_mib": _mib(obj, "data_partition_size"),
        "swap_mib": _mib(obj, "swap_size"),
        "temperature_c": _int(obj, "cur_temperate", *_TEMPERATURE_RANGE),
        "health": _int(obj, "health"),
        "work_status": _int(obj, "work_status"),
        "parted_status": _int(obj, "parted_status"),
        "wear_percent": _percent(obj, "eol_percent"),
        "station_used_percent": _percent(obj, "data_used_percent"),
        "label": _text(obj, "hdd_label"),
        "serial": _text(obj, "serial_number"),
    }


def _parse_disk(hdd: Mapping[str, Any]) -> DiskInfo | None:
    size = _mib(hdd, "disk_size_1024")
    nominal = _mib(hdd, "disk_size")
    common = _common(hdd)
    if not size and not nominal and common["path"] is None:
        return None
    system = _sum(_mib(hdd, "system_size"), _mib(hdd, "system_size_data"))
    return DiskInfo(
        size_mib=size or None,
        nominal_size_mib=nominal or None,
        used_mib=_sum(system, common["recordings_used_mib"]),
        system_mib=system,
        **common,
    )


def _parse_external(move: Mapping[str, Any]) -> DiskInfo | None:
    size = _mib(move, "disk_size")
    common = _common(move)
    if not size and common["path"] is None:
        return None
    return DiskInfo(size_mib=size or None, used_mib=common["filesystem_used_mib"], **common)


def _parse_emmc(emmc: Mapping[str, Any]) -> EmmcInfo:
    common = _common(emmc)
    return EmmcInfo(
        size_mib=_mib(emmc, "disk_size"),
        nominal_size_mib=_mib(emmc, "disk_nominal"),
        system_mib=_mib(emmc, "system_size"),
        used_mib=common["filesystem_used_mib"],
        **common,
    )


def parse_storage_info(body: Mapping[str, Any]) -> StorageInfo:
    """A :class:`StorageInfo` from a record's ``body``; never raises on odd content."""
    hdd = _object(body, "hdd_info")
    move = _object(body, "move_disk_info")
    emmc = _object(body, "emmc_info")
    return StorageInfo(
        storage_days=_int(body, "storage_days", 0),
        storage_events=_int(body, "storage_events", 0),
        continuous_video_hours=_int(body, "con_video_hours", 0),
        format_transaction=_text(body, "format_transaction"),
        format_error=_int(body, "format_errcode"),
        body_version=_int(body, "body_version"),
        disk=None if hdd is None else _parse_disk(hdd),
        external=None if move is None else _parse_external(move),
        emmc=None if emmc is None else _parse_emmc(emmc),
    )


#: The ``SDINFO_EX`` (1144) response payload: three little-endian ``int32``.
SD_INFO_LEN: Final = 12


def parse_sd_card_info(payload: bytes) -> EmmcInfo | None:
    """The built-in eMMC of a standalone camera from a ``SDINFO_EX`` (1144) frame.

    The camera answers frame type 1144 with a 12-byte body (GCM-tagged but clear, like
    a receipt): three little-endian ``int32`` — a status code (0 normal), the total size
    and the free size, in the camera's own **MB** (base 1000, as the app formats them).
    ``used`` is ``total - free`` (the response carries no system reserve), and
    :attr:`~StorageMedium.used_percent` derives from it: the figure the eMMC diagnostic
    shows. None for a body too short or a non-positive total (no usable eMMC).

    The field order is by observation: the free size never exceeds the total, so with a
    status of 0 the layout ``[status, total, free]`` is the only consistent reading of a
    live ``[0, 7140, 7108]`` (a T8170's ~8 GB eMMC).
    """
    if len(payload) < SD_INFO_LEN:
        return None
    status, total, free = struct.unpack_from("<3i", payload)
    if total <= 0:
        return None
    free = max(min(free, total), 0)
    used = total - free
    return EmmcInfo(
        size_mib=total,
        used_mib=used,
        filesystem_used_mib=used,
        work_status=status,
    )


@dataclass(frozen=True, slots=True)
class StorageRecord:
    """A ``1307`` / ``11001`` reply: its result code and its ``body`` (None when absent)."""

    code: int
    body: Mapping[str, Any] | None


def storage_record(obj: Mapping[str, Any]) -> StorageRecord | None:
    """The storage record in a ``0x0547`` JSON object, or None when it is not one.

    ``payload`` may arrive as an object or as a JSON string. The result code is
    ``mIntRet`` (or ``code``; absent = 0); a code that is not an integer is -1.
    """
    if json_int(obj.get("cmd")) != CMD_STORAGE:
        return None
    payload = obj.get("payload")
    if isinstance(payload, str):
        try:
            payload = loads_json(payload)
        except ProtocolError:
            return None
    if not isinstance(payload, Mapping) or json_int(payload.get("cmd")) != STORAGE_QUERY_INFO:
        return None
    code = 0
    for key in ("mIntRet", "code"):
        if key in payload:
            parsed = json_int(payload[key])
            code = -1 if parsed is None else parsed
            break
    return StorageRecord(code, _object(payload, "body"))
