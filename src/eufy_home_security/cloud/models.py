"""Typed views of what the eufy cloud returns."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal

from .._logging import redact, redact_serial
from ..devices.types import DeviceModel, model_for_serial, serial_prefix
from ..exceptions import CipherUnusableError, ProtocolError

type DeviceSource = Literal["house", "security"]
type KeyState = Literal["absent", "usable", "unusable"]
type KeyCase = Literal["mixed", "lower", "upper"]


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
    region: str | None = None
    """The cloud region (``eu``, ``us``) whose device list holds this device; every cloud
    call about it goes to that region. None for an entry the library did not list."""
    source: DeviceSource = "house"
    """The list that named the device: ``"house"`` (``app/house/get_devs_list``, what the
    library serves) or ``"security"`` (the security realm's lists, see
    :func:`security_device_entry`)."""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __repr__(self) -> str:
        """Identifiers redacted: a device repr lands in logs and HA diagnostics."""
        return (
            f"CloudDevice(device_sn={redact_serial(self.device_sn)!r}, "
            f"device_type={self.device_type}, name={redact(self.name)!r}, "
            f"station_sn={redact_serial(self.station_sn)!r}, channel={self.channel}, "
            f"p2p_did={redact(self.p2p_did)!r}, local_ip={redact(self.local_ip)!r}, "
            f"owner_user_id={redact(self.owner_user_id)!r}, member_type={self.member_type}, "
            f"region={self.region!r}, source={self.source!r})"
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
            "region": self.region,
            "source": self.source,
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
            region=_str_or_none(data.get(REGION_KEY)),
            source="security" if data.get(SOURCE_KEY) == "security" else "house",
            raw=MappingProxyType(dict(data)),
        )


#: The key the library adds to each ``get_devs_list`` entry: the region that listed it.
REGION_KEY: Final = "cloud_region"

#: The key :func:`security_device_entry` adds: the list that named the device.
SOURCE_KEY: Final = "cloud_source"


def security_device_entry(data: Mapping[str, Any], *, station: bool) -> dict[str, Any]:
    """A security-realm list entry in the house list's shape, tagged ``"security"``.

    ``station`` marks a ``get_hub_list`` entry (the app's ``QueryStationData``), else a
    ``get_devs_list`` one (``QueryDeviceData``). A station entry may name itself only in
    ``station_sn`` and has no parent unless it carries ``parent_sn``; a device entry names
    its station in ``station_sn``, which becomes ``parent_sn``. The name is
    ``device_name``, else ``station_name``. Every other field is kept as it is, so
    :meth:`CloudDevice.from_api` and :func:`device_cache_entry` read the result like a
    house-list entry. Seen on one account: a station entry has ``station_sn`` and no
    ``device_sn``.
    """
    entry = dict(data)
    serial = _str_or_none(data.get("device_sn"))
    if serial is None and station:
        serial = _str_or_none(data.get("station_sn"))
    entry["device_sn"] = serial or ""
    name = _str_or_none(data.get("device_name")) or _str_or_none(data.get("station_name"))
    if name is not None:
        entry["device_name"] = name
    parent = _str_or_none(data.get("parent_sn"))
    if parent is None and not station:
        parent = _str_or_none(data.get("station_sn"))
    entry.pop("parent_sn", None)
    if parent is not None:
        entry["parent_sn"] = parent
    entry[SOURCE_KEY] = "security"
    return entry


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CloudHouse:
    """One entry of ``app/house/get_house_list`` (``house_infos``): a home of the account.

    ``owner_user_id`` is the house's ``admin_user_id``; ``member_type`` this account's
    role in it (0 guest, 1 admin, 2 owner).
    """

    house_id: str
    name: str
    owner_user_id: str | None = None
    member_type: int | None = None
    is_default: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __repr__(self) -> str:
        """Identifiers redacted: a house repr lands in logs."""
        return (
            f"CloudHouse(house_id={redact(self.house_id)!r}, name={redact(self.name)!r}, "
            f"owner_user_id={redact(self.owner_user_id)!r}, member_type={self.member_type}, "
            f"is_default={self.is_default})"
        )

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> CloudHouse:
        """Build from one raw ``house_infos`` entry; malformed fields become None."""
        return cls(
            house_id=_str_or_none(data.get("house_id")) or "",
            name=_str_or_none(data.get("house_name")) or "",
            owner_user_id=_str_or_none(data.get("admin_user_id")),
            member_type=_int_or_none(data.get("member_type")),
            is_default=_int_or_none(data.get("is_default")) == 1 or data.get("is_default") is True,
            raw=MappingProxyType(dict(data)),
        )


_ECC_KEY_BYTES: Final = 32


@dataclass(frozen=True, slots=True, kw_only=True)
class RsaKeyCheck:
    """Whether a cipher's RSA ``private_key`` parses, without the key itself.

    ``case`` is the letter case of the base64 body (armour lines excluded): a key the
    cloud lowercased reads ``"lower"`` and does not parse. ``bits`` is the key size of a
    usable key; ``reason`` the :class:`~..exceptions.CipherUnusableError` reason of an
    unusable one.
    """

    state: KeyState
    case: KeyCase | None = None
    bits: int | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CipherRecord:
    """One entry of a ``get_ciphers`` answer: a cipher id's keys under one owner.

    ``ecc_private_key`` (hex P-256 scalar) unwraps a version-8 CONN_INIT,
    ``rsa_private_key`` (base64 DER, PEM armour optional) a legacy one; see
    docs/protocol/session-crypto.md.
    """

    cipher_id: int
    ecc_private_key: str | None = None
    rsa_private_key: str | None = None

    def __repr__(self) -> str:
        """Key states only: a record repr lands in logs."""
        return (
            f"CipherRecord(cipher_id={self.cipher_id}, ecc={self.ecc_state}, "
            f"rsa={'absent' if not self.rsa_private_key else 'held'})"
        )

    @classmethod
    def from_api(cls, data: object) -> CipherRecord | None:
        """Build from one ``get_ciphers`` entry; None without an integer ``cipher_id``."""
        if not isinstance(data, Mapping):
            return None
        cipher_id = _int_or_none(data.get("cipher_id"))
        if cipher_id is None:
            return None
        return cls(
            cipher_id=cipher_id,
            ecc_private_key=_key_or_none(data.get("ecc_private_key")),
            rsa_private_key=_key_or_none(data.get("private_key")),
        )

    @property
    def ecc_state(self) -> KeyState:
        """``"usable"`` for 32 bytes of hex, ``"absent"`` for none, else ``"unusable"``."""
        key = self.ecc_private_key
        if not key:
            return "absent"
        try:
            return "usable" if len(bytes.fromhex(key)) == _ECC_KEY_BYTES else "unusable"
        except ValueError:
            return "unusable"

    def check_rsa(self) -> RsaKeyCheck:
        """Parse the RSA key and report its state; the key itself is not returned."""
        from ..p2p.crypto import load_rsa_private_key  # noqa: PLC0415 - import cycle

        text = self.rsa_private_key
        if not text:
            return RsaKeyCheck(state="absent")
        body = "".join(line for line in text.splitlines() if "-----" not in line)
        upper = any(c.isupper() for c in body)
        lower = any(c.islower() for c in body)
        case: KeyCase | None = (
            "mixed" if upper and lower else "upper" if upper else "lower" if lower else None
        )
        try:
            key = load_rsa_private_key(text)
        except CipherUnusableError as err:
            return RsaKeyCheck(state="unusable", case=case, reason=err.reason)
        return RsaKeyCheck(state="usable", case=case, bits=key.key_size)


def _key_or_none(value: object) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


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
    REGION_KEY,
    SOURCE_KEY,
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
