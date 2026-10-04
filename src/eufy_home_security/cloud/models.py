"""Typed views of what the eufy cloud returns."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from .._logging import redact, redact_serial
from ..devices.types import DeviceModel, model_for_serial, serial_prefix
from ..exceptions import ProtocolError


def _str_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_or_none(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class CloudParam:
    """One entry of a device's ``params`` snapshot in the cloud device list.

    The device (or its hub) uploads a parameter when it changes; ``updated_at`` is that
    upload's epoch seconds (``update_time``), None when the entry has none.
    """

    param_id: int
    value: str
    updated_at: float | None


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class FirmwareUpdate:
    """A firmware version the cloud OTA offers for a device (``get_rom_version``).

    Built only when an update is available: :meth:`from_api` returns None for a device
    already on the newest published firmware. ``download_url`` is the image on eufy's
    CDN (``full_package.file_path``); ``md5`` and ``size_bytes`` describe that file.
    """

    device_sn: str
    version_name: str
    """``rom_version_name`` — the offered version, e.g. ``3.8.7.4``."""
    rom_version: int | None = None
    download_url: str
    md5: str | None = None
    size_bytes: int | None = None
    forced: bool = False
    """The device or app forces this update (``force_upgrade`` / ``up_forced``)."""
    notes: str | None = None
    """``introduction`` — release notes, when the cloud sends them."""

    def __repr__(self) -> str:
        """Serial redacted (a firmware update lands in logs and HA diagnostics)."""
        return (
            f"FirmwareUpdate(device_sn={redact_serial(self.device_sn)!r}, "
            f"version_name={self.version_name!r}, size_bytes={self.size_bytes}, "
            f"forced={self.forced}, has_url={bool(self.download_url)})"
        )

    @classmethod
    def from_api(cls, device_sn: str, data: object) -> FirmwareUpdate | None:
        """Parse a ``get_rom_version`` ``data`` payload; None when up to date.

        The OTA subsystem answers an up-to-date device with an error object
        (``code`` 20004) or an entry without a ``full_package``; only a payload that
        carries a downloadable ``full_package.file_path`` is an available update.
        """
        if not isinstance(data, Mapping):
            return None
        package = data.get("full_package")
        if not isinstance(package, Mapping):
            return None
        url = _str_or_none(package.get("file_path"))
        version = _str_or_none(data.get("rom_version_name"))
        if url is None or version is None:
            return None
        return cls(
            device_sn=device_sn,
            version_name=version,
            rom_version=_int_or_none(data.get("rom_version")),
            download_url=url,
            md5=_str_or_none(package.get("file_md5")),
            size_bytes=_int_or_none(package.get("file_size")),
            forced=bool(data.get("force_upgrade")) or bool(data.get("up_forced")),
            notes=_str_or_none(data.get("introduction")),
        )


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CloudDevice:
    """One entry of ``app/house/get_devs_list``.

    ``owner_user_id`` is ``member.admin_user_id``: the station owner's cloud id,
    which every P2P command must carry and under which the station's cipher is
    fetched. It is *not* the logged-in user's id whenever the account is a shared
    member of someone else's house.
    """

    device_sn: str
    device_type: int
    name: str
    station_sn: str | None = None
    """``parent_sn``: the station this device is paired to."""
    channel: int | None = None
    """``device_channel``: the station slot, the ``channel`` on every event."""
    p2p_did: str | None = None
    local_ip: str | None = None
    owner_user_id: str | None = None
    member_type: int | None = None
    """``member.member_type``: 0 guest, 1 admin, 2 owner. UI-level only."""
    main_sw_version: str | None = None
    sec_sw_version: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __repr__(self) -> str:
        """Identifiers redacted: a device repr lands in logs and HA diagnostics."""
        return (
            f"CloudDevice(device_sn={redact_serial(self.device_sn)!r}, "
            f"device_type={self.device_type}, name={redact(self.name)!r}, "
            f"station_sn={redact_serial(self.station_sn)!r}, channel={self.channel}, "
            f"p2p_did={redact(self.p2p_did)!r}, local_ip={redact(self.local_ip)!r}, "
            f"owner_user_id={redact(self.owner_user_id)!r}, member_type={self.member_type})"
        )

    def as_redacted_dict(self) -> dict[str, Any]:
        """The device for diagnostics: JSON-safe, with every identifier left out.

        Serials go through :func:`redact_serial`; the P2P DID, the IP and the owner's
        user id are reported only as present or not, and the raw cloud entry is left
        out entirely.
        """
        return {
            "device_sn": redact_serial(self.device_sn),
            "station_sn": None if self.station_sn is None else redact_serial(self.station_sn),
            "device_type": self.device_type,
            "name": self.name,
            "channel": self.channel,
            "is_station": self.is_station,
            "member_type": self.member_type,
            "account_is_owner": self.account_is_owner,
            "main_sw_version": self.main_sw_version,
            "sec_sw_version": self.sec_sw_version,
            "has_p2p_did": self.p2p_did is not None,
            "has_local_ip": self.local_ip is not None,
            "has_owner_user_id": self.owner_user_id is not None,
            "model_id": self.model_id,
            "model_name": self.model_name,
        }

    @property
    def model(self) -> DeviceModel | None:
        """The catalogued model of this device's serial; ``None`` when the catalog does
        not know the prefix (:data:`~..devices.types.MODELS`)."""
        return model_for_serial(self.device_sn)

    @property
    def model_id(self) -> str | None:
        """The serial's 5-character model prefix (``"T8160"``), catalogued or not; HA's
        ``DeviceInfo`` ``model_id``. ``None`` only for a serial shorter than a prefix."""
        return serial_prefix(self.device_sn)

    @property
    def model_name(self) -> str | None:
        """The catalogued model's display name (``"eufyCam 3 (S330)"``); HA's
        ``DeviceInfo`` ``model``. ``None`` for a model the catalog does not know."""
        model = self.model
        return None if model is None else model.name

    @property
    def is_station(self) -> bool:
        """True for a device that is its own station (a HomeBase, a standalone camera).

        The account's device list also carries non-security products (a robot
        vacuum, say) that are their own parent but have no P2P identity; only a
        device with a ``p2p_did`` can be spoken to as a station.
        """
        own_parent = self.station_sn is None or self.station_sn == self.device_sn
        return own_parent and bool(self.p2p_did)

    @property
    def cloud_params(self) -> tuple[CloudParam, ...]:
        """The cloud's snapshot of this device's parameters; ``()`` when the entry carries
        none (the cache keeps it only for devices reached on demand).

        An entry without an integer ``param_type`` or with a value that is neither a
        string nor an integer is skipped.
        """
        raw = self.raw.get("params")
        if not isinstance(raw, list):
            return ()
        params = []
        for entry in raw:
            if not isinstance(entry, Mapping):
                continue
            param_id = _int_or_none(entry.get("param_type"))
            value = entry.get("param_value")
            if isinstance(value, int) and not isinstance(value, bool):
                value = str(value)
            if param_id is None or not isinstance(value, str):
                continue
            updated = entry.get("update_time")
            updated_at = (
                float(updated)
                if isinstance(updated, (int, float)) and not isinstance(updated, bool)
                else None
            )
            params.append(CloudParam(param_id, value, updated_at))
        return tuple(params)

    @property
    def rendezvous_servers(self) -> tuple[str, ...]:
        """This station's PPPP rendezvous hosts, decoded from ``app_conn`` (see
        :func:`~..p2p.pppp.decode_init_string`); ``()`` when absent or malformed.

        A battery station is woken by sending these servers a ``LOOKUP`` (see
        :class:`~..p2p.session.StationSession`)."""
        from ..p2p.pppp import decode_init_string  # noqa: PLC0415 - avoids a cloud→p2p import cycle

        encoded = self.raw.get("app_conn")
        if not isinstance(encoded, str) or not encoded:
            return ()
        try:
            return tuple(decode_init_string(encoded))
        except ProtocolError:
            return ()

    @property
    def is_standalone(self) -> bool:
        """True for a device that is its own station and also the device itself (a
        standalone camera), as opposed to a hub.

        The cloud tells them apart by ``parent_sn``: a T8170 standalone camera names its
        own serial, a HomeBase 3 leaves it empty. A standalone device labels its one
        parameter block with its ``device_type`` instead of the station's 255.
        """
        return self.is_station and self.station_sn == self.device_sn

    @property
    def has_member_relation(self) -> bool:
        """Whether the entry carries a ``member`` object at all."""
        member = self.raw.get("member")
        return isinstance(member, Mapping) and bool(member)

    @property
    def account_is_owner(self) -> bool:
        """Whether the logged-in account owns this device rather than being shared it.

        The owner's entry carries no member relation, or ``member_type`` 2; a shared
        member's entry names the owner in ``admin_user_id``.
        """
        return not self.has_member_relation or self.member_type == 2

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> CloudDevice:
        """Build from one raw device dict; unknown or malformed fields become None."""
        member = data.get("member")
        member = member if isinstance(member, Mapping) else {}
        return cls(
            device_sn=_str_or_none(data.get("device_sn")) or "",
            device_type=_int_or_none(data.get("device_type")) or 0,
            name=_str_or_none(data.get("device_name")) or "",
            station_sn=_str_or_none(data.get("parent_sn")),
            channel=_int_or_none(data.get("device_channel")),
            p2p_did=_str_or_none(data.get("p2p_did")),
            local_ip=_str_or_none(data.get("local_ip")),
            owner_user_id=_str_or_none(member.get("admin_user_id")),
            member_type=_int_or_none(member.get("member_type")),
            main_sw_version=_str_or_none(data.get("main_sw_version")),
            sec_sw_version=_str_or_none(data.get("sec_sw_version")),
            raw=MappingProxyType(dict(data)),
        )


# What of a ``get_devs_list`` entry is worth persisting: exactly what CloudDevice reads
# (:meth:`CloudDevice.from_api` and its properties) and the product code in ``raw``. The
# rest of an entry — the member's e-mail, phone and avatar, MAC addresses, MQTT and WebRTC
# details, firmware build times, cover images … — is personal or never read, and is
# four-fifths of the bytes.
CACHED_DEVICE_FIELDS: Final = (
    "device_sn",
    "device_type",
    "device_name",
    "parent_sn",
    "device_channel",
    "p2p_did",
    "local_ip",
    "main_sw_version",
    "sec_sw_version",
    "app_conn",  # rendezvous_servers: how a battery station is woken
    "device_new_pn",  # the product code that keys a model's settings
)
CACHED_MEMBER_FIELDS: Final = ("admin_user_id", "member_type")
CACHED_PARAM_FIELDS: Final = ("param_type", "param_value", "update_time")


def device_cache_entry(data: Mapping[str, Any], *, keep_params: bool) -> dict[str, Any]:
    """``data`` (one ``get_devs_list`` entry) reduced to what the cache keeps.

    :meth:`CloudDevice.from_api` of the result equals that of ``data`` in every
    field and property. ``params`` (the cloud's parameter snapshot) is kept only with
    ``keep_params`` — for a device reached on demand, whose state comes from that
    snapshot between sessions — and then reduced to what :attr:`CloudDevice.cloud_params`
    reads.
    """
    entry = {key: data[key] for key in CACHED_DEVICE_FIELDS if key in data}
    member = data.get("member")
    if isinstance(member, Mapping) and member:
        entry["member"] = {key: member[key] for key in CACHED_MEMBER_FIELDS if key in member}
    params = data.get("params")
    if keep_params and isinstance(params, list):
        entry["params"] = [
            {key: param[key] for key in CACHED_PARAM_FIELDS if key in param}
            for param in params
            if isinstance(param, Mapping)
        ]
    return entry
