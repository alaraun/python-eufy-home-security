"""A read-only account report: every device each eufy list names, firmware, cipher state.

:func:`async_account_report` asks every list the account's cloud sessions can reach
without a login (the house device list account-wide and per house, the pending
invitations, the security realm's station and device lists), each region's last-login
code, the host's IP country and each owner's whole cipher table, and returns an
:class:`AccountReport`: JSON-safe and secret-free, so a consumer can put it in a
diagnostics download as it is. Serials go through :func:`~._logging.redact_serial`;
no user id, house id, DID, IP, name, key or parameter value (but the camera-info
parameter's) leaves it.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Awaitable, Collection, Coroutine, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from ._logging import _hidden_text, redact_serial
from .cloud.api import EufyCloudApi
from .cloud.models import (
    CAMERA_INFO_PARAM,
    CipherRecord,
    CloudDevice,
    CloudInvite,
    InviteKind,
    KeyCase,
    KeyState,
)
from .devices.model_settings import product_code_of
from .devices.recipes import connect_type
from .exceptions import (
    AuthenticationError,
    EufySecurityError,
    RateLimitedError,
    SessionReplacedError,
)
from .storage import SessionCache

__all__ = [
    "AccountReport",
    "CipherReport",
    "DeviceEntryReport",
    "HouseReport",
    "InviteReport",
    "ListingReport",
    "LoginReport",
    "OwnerCiphersReport",
    "async_account_report",
]

_LOGGER = logging.getLogger(__name__)

# Errors after which the report sends nothing more: the account is throttled, its
# session is gone, or its credentials are refused.
_STOPPING: Final = (RateLimitedError, SessionReplacedError, AuthenticationError)
_ERROR_LEN: Final = 300

HOUSE: Final = "house"
"""The account-wide house device list (``app/house/get_devs_list``, what the library serves)."""
SECURITY_STATIONS: Final = "security_stations"
SECURITY_DEVICES: Final = "security_devices"
INVITES: Final = "invites"
"""The pending invitations (homes and single devices) sent to the account."""


def house_source(index: int) -> str:
    """The ``listed_by`` label of the ``index``-th (1-based) house's device list."""
    return f"house:{index}"


@dataclass(frozen=True, slots=True, kw_only=True)
class LoginReport:
    """One region's login: the ``ab`` its cached session was made with (None without
    one) and the cloud's ``get_last_login_code`` (the ``ab`` of the account's last login
    there, by any client), or why that was not read."""

    region: str
    ab: str | None
    last_login_code: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ListingReport:
    """One list the report asked in one region: how many entries it answered, or why not.

    ``source`` is :data:`HOUSE`, ``"houses"`` (the house list itself), :data:`INVITES`,
    :data:`SECURITY_STATIONS` or :data:`SECURITY_DEVICES`.
    """

    region: str
    source: str
    entries: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class HouseReport:
    """One house (home) of a region and its own device list (``listed_by``
    :func:`house_source` of ``index``)."""

    region: str
    index: int
    is_default: bool
    member_type: int | None
    account_is_owner: bool
    devices: int | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class InviteReport:
    """One pending invitation (see :class:`~.cloud.models.CloudInvite`) without names or
    ids: what it shares (``kind``, the device's redacted serial and product code) and
    when it was sent (epoch seconds)."""

    region: str
    kind: InviteKind
    device_sn: str | None
    product_code: str | None
    created_at: int | None

    @classmethod
    def of(cls, invite: CloudInvite) -> InviteReport:
        return cls(**invite.as_redacted_dict())


@dataclass(frozen=True, slots=True, kw_only=True)
class DeviceEntryReport:
    """One device, merged over every list that named it.

    ``listed_by`` names those lists (:data:`HOUSE`, :func:`house_source`,
    :data:`SECURITY_STATIONS`, :data:`SECURITY_DEVICES`); a device the library serves is
    listed by :data:`HOUSE`. ``model_support`` is the catalogue's support grade, None
    for a model the catalogue lacks; ``cloud_model`` the entry's own ``device_model``
    (``station_model`` on a security-realm station). ``connect_type`` is how a sub-device is reached
    (its station's kind), None for a station. ``owner`` is ``"own"`` or ``"owner N"``,
    the same label as :attr:`OwnerCiphersReport.owner`. ``camera_info`` is the
    :data:`CAMERA_INFO_PARAM` value of the cloud's parameter snapshot; ``param_ids`` the
    ids that snapshot holds (values left out). ``named_cipher_id`` is the cipher the
    station named in its last CONN_INIT to this library. ``served`` tells whether this
    client built a station for it (None before a discovery).
    """

    device_sn: str
    station_sn: str | None
    region: str | None
    listed_by: tuple[str, ...]
    device_type: int
    model_id: str | None
    model_name: str | None
    model_support: str | None
    product_code: str | None
    cloud_model: str | None
    is_station: bool
    is_standalone: bool
    connect_type: str | None
    account_is_owner: bool
    owner: str | None
    main_sw_version: str | None
    sec_sw_version: str | None
    main_hw_version: str | None
    sec_hw_version: str | None
    camera_info: int | None
    param_ids: tuple[int, ...]
    has_p2p_did: bool
    rendezvous_servers: int
    named_cipher_id: int | None
    served: bool | None


@dataclass(frozen=True, slots=True, kw_only=True)
class CipherReport:
    """One cipher record's state (see :class:`~.cloud.models.CipherRecord`), no key.

    ``named_by`` lists the stations (serials redacted) that named this cipher in their
    last CONN_INIT.
    """

    cipher_id: int
    ecc: KeyState
    rsa: KeyState
    rsa_case: KeyCase | None
    rsa_bits: int | None
    rsa_reason: str | None
    named_by: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerCiphersReport:
    """One owner's cipher table, read with one ``get_ciphers`` sweep named for
    ``station_sn`` (redacted)."""

    owner: str
    station_sn: str
    region: str
    ciphers: tuple[CipherReport, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AccountReport:
    """What :func:`async_account_report` found; :meth:`as_dict` is JSON-safe.

    ``regions`` are the login scopes asked (a session was held or cached; a region, or
    an extra country's ``<region>:<country>``); ``regions_without_session`` the scopes
    not asked, since asking them would cost a login. ``stopped`` is the error that ended
    the report's requests early (a throttle, a session another client took over, a
    refused credential), None when every request was sent.

    ``login_country`` is the country logins send as ``ab``, with its ``country_source``
    (``"option"``, ``"ip"``) and ``home_region``, all None while unknown;
    ``client_country`` the country eufy places the host's IP address in (asked on the
    first region's session), and ``logins`` each asked region's :class:`LoginReport`.
    """

    regions: tuple[str, ...]
    regions_without_session: tuple[str, ...]
    listings: tuple[ListingReport, ...]
    houses: tuple[HouseReport, ...]
    devices: tuple[DeviceEntryReport, ...]
    ciphers: tuple[OwnerCiphersReport, ...]
    invites: tuple[InviteReport, ...] = ()
    login_country: str | None = None
    country_source: str | None = None
    home_region: str | None = None
    client_country: str | None = None
    logins: tuple[LoginReport, ...] = ()
    stopped: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """The report as plain dicts, lists and scalars."""
        return {k: _plain(v) for k, v in dataclasses.asdict(self).items()}


def _plain(value: object) -> object:
    """``value`` with every tuple turned into a list, recursively."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _error_text(err: BaseException) -> str:
    """The error for the report: serials, account ids and e-mail addresses redacted."""
    return _hidden_text(f"{type(err).__name__}: {err}")[:_ERROR_LEN]


@dataclass
class _Seen:
    """A device's entries across the lists, in the order asked."""

    labels: list[str] = dataclasses.field(default_factory=list)
    devices: list[CloudDevice] = dataclasses.field(default_factory=list)

    def add(self, label: str, device: CloudDevice) -> None:
        if label not in self.labels:
            self.labels.append(label)
        self.devices.append(device)


async def async_account_report(
    cloud: EufyCloudApi,
    cache: SessionCache,
    *,
    ciphers: bool = True,
    served_stations: Collection[str] | None = None,
) -> AccountReport:
    """Ask every list and cipher table the account reaches without a login.

    Per region with a usable session (:meth:`EufyCloudApi.regions_with_session`): the
    house device list, the house list and each house's device list, the pending
    invitations, the security realm's station and device lists. Then, with ``ciphers``, one cipher sweep
    (:data:`~.cloud.const.CIPHER_ID_SWEEP`) per station owner, named for that owner's
    first station. Nothing is cached, nothing logs in, and the first throttle, kick-out
    or credential refusal ends the requests (:attr:`AccountReport.stopped`); every
    other failure is recorded where it happened. ``served_stations`` are the serials
    the caller built a station for (see :attr:`DeviceEntryReport.served`).
    """
    builder = _ReportBuilder(cloud, cache)
    regions = cloud.regions_with_session()
    client_country: str | None = None
    if regions:
        client_country = await builder.ask_client_country(regions[0])
    for region in regions:
        await builder.ask_region(region)
    labels, stations = _owners(cloud.user_id, builder.seen.values())
    cipher_reports: list[OwnerCiphersReport] = []
    if ciphers:
        for owner_id, station in stations.items():
            cipher_reports.append(await builder.ask_ciphers(owner_id, labels[owner_id], station))
    devices = tuple(
        _device_report(entry, cloud.user_id, labels, cache, served_stations)
        for entry in builder.seen.values()
    )
    country = cloud.login_country
    return AccountReport(
        regions=tuple(regions),
        regions_without_session=tuple(r for r in cloud.login_scopes() if r not in regions),
        listings=tuple(builder.listings),
        houses=tuple(builder.houses),
        devices=devices,
        ciphers=tuple(cipher_reports),
        invites=tuple(builder.invites),
        login_country=None if country is None else country.code,
        country_source=None if country is None else country.source,
        home_region=None if country is None else country.home_region,
        client_country=client_country,
        logins=tuple(builder.logins),
        stopped=builder.stopped,
    )


class _ReportBuilder:
    """Sends the report's requests, in order, until one stops them (:data:`_STOPPING`)."""

    def __init__(self, cloud: EufyCloudApi, cache: SessionCache) -> None:
        self._cloud = cloud
        self._cache = cache
        self.stopped: str | None = None
        self.listings: list[ListingReport] = []
        self.houses: list[HouseReport] = []
        self.invites: list[InviteReport] = []
        self.logins: list[LoginReport] = []
        self.seen: dict[str, _Seen] = {}

    async def _ask[T](self, request: Awaitable[T]) -> tuple[T | None, str | None]:
        """The request's result, or None and its error text; nothing sent once stopped."""
        if self.stopped is not None:
            if isinstance(request, Coroutine):
                request.close()
            return None, f"not asked: {self.stopped}"
        try:
            return await request, None
        except EufySecurityError as err:
            text = _error_text(err)
            if isinstance(err, _STOPPING):
                self.stopped = text
            return None, text

    def _note(self, label: str, devices: Sequence[CloudDevice]) -> None:
        for device in devices:
            if device.device_sn:
                self.seen.setdefault(device.device_sn, _Seen()).add(label, device)

    async def _listing[T](self, region: str, source: str, request: Awaitable[list[T]]) -> list[T]:
        result, error = await self._ask(request)
        self.listings.append(
            ListingReport(
                region=region,
                source=source,
                entries=None if result is None else len(result),
                error=error,
            )
        )
        return result or []

    async def ask_client_country(self, region: str) -> str | None:
        """The host's IP country, asked on ``region``'s session; None on any failure."""
        country, _error = await self._ask(self._cloud.async_client_country(region, login=False))
        return country

    async def ask_region(self, region: str) -> None:
        """Ask ``region``'s last-login code and its house, per-house, invitation and
        security-realm lists."""
        cloud = self._cloud
        code, error = await self._ask(cloud.async_last_login_code(region, login=False))
        self.logins.append(
            LoginReport(
                region=region, ab=cloud.session_ab(region), last_login_code=code, error=error
            )
        )
        self._note(
            HOUSE,
            await self._listing(region, HOUSE, cloud.async_list_house_devices(region, login=False)),
        )
        houses = await self._listing(region, "houses", cloud.async_list_houses(region, login=False))
        for index, house in enumerate(houses, start=1):
            found, error = await self._ask(
                cloud.async_list_house_devices(region, house.house_id, login=False)
            )
            self.houses.append(
                HouseReport(
                    region=region,
                    index=index,
                    is_default=house.is_default,
                    member_type=house.member_type,
                    account_is_owner=house.owner_user_id is not None
                    and house.owner_user_id == cloud.user_id,
                    devices=None if found is None else len(found),
                    error=error,
                )
            )
            self._note(house_source(index), found or [])
        invites = await self._listing(
            region, INVITES, cloud.async_list_invites(region, login=False)
        )
        self.invites += (InviteReport.of(invite) for invite in invites)
        for source, stations in ((SECURITY_STATIONS, True), (SECURITY_DEVICES, False)):
            listed = await self._listing(
                region,
                source,
                cloud.async_list_security_devices(region, stations=stations, login=False),
            )
            self._note(source, listed)

    async def ask_ciphers(
        self, owner_id: str, label: str, station: CloudDevice
    ) -> OwnerCiphersReport:
        """One owner's cipher sweep, reported without a key."""
        cloud, cache = self._cloud, self._cache
        region = station.region or cloud.device_region(station.device_sn)
        records, error = await self._ask(
            cloud.async_list_ciphers(station.device_sn, owner_id, region=region, login=False)
        )
        named: dict[int, list[str]] = {}
        for serial in cache.station_serials():
            cipher_id = cache.station_named_cipher_id(serial)
            account = cache.station_account_id(serial)
            if cipher_id is not None and account in {None, owner_id}:
                named.setdefault(cipher_id, []).append(redact_serial(serial))
        return OwnerCiphersReport(
            owner=label,
            station_sn=redact_serial(station.device_sn),
            region=region,
            ciphers=tuple(_cipher_report(r, named.get(r.cipher_id, ())) for r in records or ()),
            error=error,
        )


def _owner_id(devices: Sequence[CloudDevice], user_id: str | None) -> str | None:
    """The owner id of a device's entries: the first ``member.admin_user_id``, else the
    account's own id when an entry carries no member relation (the literal owner)."""
    for device in devices:
        if device.owner_user_id:
            return device.owner_user_id
    if any(not device.has_member_relation for device in devices):
        return user_id
    return None


def _owners(
    user_id: str | None, seen: Collection[_Seen]
) -> tuple[dict[str, str], dict[str, CloudDevice]]:
    """Each owner id's label (``"own"``, ``"owner N"`` in the order seen) and its first
    station."""
    labels: dict[str, str] = {}
    stations: dict[str, CloudDevice] = {}
    for entry in seen:
        owner = _owner_id(entry.devices, user_id)
        if owner is None:
            continue
        if owner not in labels:
            others = sum(1 for o in labels if o != user_id)
            labels[owner] = "own" if owner == user_id else f"owner {others + 1}"
        station = next((d for d in entry.devices if d.is_station), None)
        if station is not None and owner not in stations:
            stations[owner] = station
    return labels, stations


def _cipher_report(record: CipherRecord, named_by: Sequence[str]) -> CipherReport:
    rsa = record.check_rsa()
    return CipherReport(
        cipher_id=record.cipher_id,
        ecc=record.ecc_state,
        rsa=rsa.state,
        rsa_case=rsa.case,
        rsa_bits=rsa.bits,
        rsa_reason=rsa.reason,
        named_by=tuple(named_by),
    )


def _first[T](values: Iterable[T | None]) -> T | None:
    return next((v for v in values if v is not None), None)


def _raw_text(device: CloudDevice, key: str) -> str | None:
    value = device.raw.get(key)
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value).strip() or None


def _device_report(
    entry: _Seen,
    user_id: str | None,
    labels: Mapping[str, str],
    cache: SessionCache,
    served_stations: Collection[str] | None,
) -> DeviceEntryReport:
    """One device's entries merged: the first value any list gave, field by field."""
    devices = entry.devices
    first = devices[0]
    serial = first.device_sn
    station_sn = _first(d.station_sn for d in devices)
    is_station = any(d.is_station for d in devices)
    params = next((d.cloud_params for d in devices if d.cloud_params), ())
    camera_info = next((p.value for p in params if p.param_id == CAMERA_INFO_PARAM), None)
    model = first.model
    owner = _owner_id(devices, user_id)
    served = (
        None
        if served_stations is None
        else serial in served_stations or (station_sn is not None and station_sn in served_stations)
    )
    return DeviceEntryReport(
        device_sn=redact_serial(serial),
        station_sn=None if station_sn is None else redact_serial(station_sn),
        region=_first(d.region for d in devices),
        listed_by=tuple(entry.labels),
        device_type=first.device_type,
        model_id=first.model_id,
        model_name=first.model_name,
        model_support=None if model is None else model.evidence.support.value,
        product_code=product_code_of(
            _first(_raw_text(d, "device_new_pn") for d in devices), serial
        ),
        cloud_model=_first(
            _raw_text(d, "device_model") or _raw_text(d, "station_model") for d in devices
        ),
        is_station=is_station,
        is_standalone=any(d.is_standalone for d in devices),
        connect_type=None if is_station else connect_type(station_sn, serial).value,
        account_is_owner=all(d.account_is_owner for d in devices),
        owner=None if owner is None else labels.get(owner),
        main_sw_version=_first(d.main_sw_version for d in devices),
        sec_sw_version=_first(d.sec_sw_version for d in devices),
        main_hw_version=_first(_raw_text(d, "main_hw_version") for d in devices),
        sec_hw_version=_first(_raw_text(d, "sec_hw_version") for d in devices),
        camera_info=None if camera_info is None else _int_or_none(camera_info),
        param_ids=tuple(sorted({p.param_id for p in params})),
        has_p2p_did=any(d.p2p_did for d in devices),
        rendezvous_servers=max(len(d.rendezvous_servers) for d in devices),
        named_cipher_id=cache.station_named_cipher_id(serial) if is_station else None,
        served=served,
    )


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
