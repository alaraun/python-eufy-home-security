"""The entry point: one eufy account, its stations, and every event channel.

Typical use (Home Assistant passes its own session and a ``Store``)::

    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(http, email, password, store=JsonFileStore("~/.eufy.json"))
        await eufy.async_login()
        stations = await eufy.async_discover()
        eufy.subscribe(print)
        await eufy.async_start()
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from types import MappingProxyType, TracebackType
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from ._logging import Identifier, LogThrottle, Secret, redact_serial
from .cloud import arming
from .cloud.api import CipherKeys, EufyCloudApi, HttpSession, PasswordSource
from .cloud.const import CLOUD_STATE_REFRESH, FACES_BY_IDS_PATH, firmware_ota_type
from .cloud.models import CloudDevice, CloudInvite, FirmwareUpdate
from .cloud.status import CloudStatus, DeviceListSource
from .devices.model_settings import (
    Setting,
    bundled_codes,
    bundled_td_version,
    canonical_code,
    product_code_of,
    settings_of,
)
from .devices.td import parse_thing_description, td_version
from .devices.types import connects_on_demand
from .devices.webrtc import app_webrtc_only, route_device
from .diagnostics import AccountReport, async_account_report
from .events import (
    AlarmChanged,
    AlarmTracker,
    CloudProblem,
    CredentialsRefreshed,
    Event,
    EventBus,
    EventCallback,
    EventDeduplicator,
    GuardModeChanged,
    GuardModeTracker,
    PushChanged,
    PushPictureSource,
    SecurityEvent,
    StationsChanged,
    Unsubscribe,
    as_guard_mode,
    pic_url_kind,
)
from .exceptions import (
    CloudError,
    CommunicationError,
    EmptyResponseError,
    EufySecurityError,
    KeyExchangeRefusedError,
    ModelDataError,
    NoCachedSessionError,
    ProtocolError,
    SessionReplacedError,
    UnsupportedError,
    VideoEncryptedPictureError,
)
from .identity import StationClaims, is_device_serial
from .images import PushImage, picture_content_type
from .inclusion import Reach, StationChoice
from .models import GuardMode
from .network import LanPath, check_local_ports, lan_address, lan_path_for, with_discovery
from .p2p.crypto import CONN_INIT_NO_CIPHER
from .p2p.did import Did
from .p2p.media import StillFormat, classify_still, decode_still
from .p2p.pppp import BROADCAST, DISCOVERY_PORT
from .p2p.session import (
    DEFAULT_STATION_SESSIONS,
    CredentialProvider,
    P2PCredentials,
    StationSession,
    WakeProvider,
    _session_budget,
)
from .p2p.transport import Wake
from .station import RemoteStation, Station, station_block_aliases, station_channels
from .storage import SessionCache, Store

if TYPE_CHECKING:
    import aiohttp

    from .install import InstallState
    from .push.fcm import PushListener

_LOGGER = logging.getLogger(__name__)
_SKIP_THROTTLE = LogThrottle()  # one line per skipped device, not one per discovery
_SCAN_KEY_REFUSED = (
    "the cloud refused this client's key identity after a new key exchange; "
    "listed at the next refresh"
)

type ModelState = Literal["bundled", "cloud-listed", "unknown"]
type SkipReason = Literal["bad_serial", "bad_did", "webrtc_only", "no_did", "orphan"]


@dataclass(frozen=True, slots=True)
class SkippedDevice:
    """A device on the account that the library builds nothing for, and why.

    ``reason`` is ``"bad_serial"`` (its serial cannot name it in an id, see
    :func:`~.identity.is_device_serial`), ``"bad_did"`` (a station whose P2P id local P2P
    does not accept, see :meth:`~.p2p.did.Did.parse`; the eufy app's P2P stack refuses
    it too), ``"webrtc_only"`` (a station the eufy app reaches only over WebRTC, see
    :func:`~.devices.webrtc.app_webrtc_only`, or a device paired to one),
    ``"no_did"`` (its own parent but
    without a P2P id, so not a station: a non-security product, say) or ``"orphan"``
    (paired to a station that is not on the list, or was itself skipped).
    """

    device_sn_redacted: str
    """The serial through :func:`~._logging.redact_serial` (``"empty"`` for none)."""
    reason: SkipReason


@dataclass(frozen=True, slots=True)
class ModelStatus:
    """How the library knows one product code of the account.

    ``state`` is ``"bundled"`` (a settings file ships with the library),
    ``"cloud-listed"`` (no file; the cloud thing description's settings are listed
    read-only) or ``"unknown"`` (no file and no listing). ``bundled_td_version`` is the
    thing-description version the bundled file was generated from, ``cloud_td_version``
    the version the cloud last reported; either is None when not known.
    """

    product_code: str
    state: ModelState
    bundled_td_version: int | None
    cloud_td_version: int | None

    @property
    def newer_vendor_data(self) -> bool:
        """Whether the cloud's thing description is newer than the bundled file's."""
        return (
            self.bundled_td_version is not None
            and self.cloud_td_version is not None
            and self.cloud_td_version > self.bundled_td_version
        )


def _account_codes(devices: Sequence[CloudDevice]) -> tuple[str, ...]:
    """The product codes of ``devices`` (canonical), deduplicated and sorted."""
    codes = {product_code_of(d.raw.get("device_new_pn"), d.device_sn) for d in devices}
    return tuple(sorted(c for c in codes if c is not None))


def _load_settings(devices: Sequence[CloudDevice]) -> None:
    """Load the settings file of every device's model (blocking: package data, a worker
    thread only), so :meth:`Station.settings_for` reads no disk on the loop. A malformed
    file is left for :meth:`Station.settings_for` to raise."""
    for device in devices:
        code = product_code_of(device.raw.get("device_new_pn"), device.device_sn)
        if code is not None:
            with contextlib.suppress(ModelDataError):
                settings_of(code)


def _bundled_version(code: str) -> int | None:
    """:func:`~.devices.model_settings.bundled_td_version`, None for a malformed file
    (which :meth:`Station.settings_for` reports)."""
    try:
        return bundled_td_version(code)
    except ModelDataError:
        return None


def _by_code(
    things: Sequence[Mapping[str, Any]], codes: Sequence[str]
) -> dict[str, Mapping[str, Any]]:
    """The first TD per asked code, matched by ``profile.product_code``."""
    out: dict[str, Mapping[str, Any]] = {}
    for td in things:
        profile = td.get("profile")
        code = canonical_code(profile.get("product_code")) if isinstance(profile, Mapping) else None
        if code is not None and code in codes and code not in out:
            out[code] = td
    return out


class EufySecurity:
    """A eufy Security account: cloud login, local stations, and merged events."""

    def __init__(
        self,
        session: HttpSession,
        email: str,
        password: PasswordSource | None,
        *,
        store: Store,
        country: str | Sequence[str] = "",
        timezone: str = "",
        region: str | None = None,
        scan_regions: bool = False,
        station_hosts: Mapping[str, str] | None = None,
        local_ports: Mapping[str, int] | None = None,
        claims: StationClaims | None = None,
        stations: Mapping[str, Reach] | None = None,
        install: InstallState | None = None,
        deduplicate: bool = True,
        cloud_state_refresh: float = CLOUD_STATE_REFRESH,
        max_sessions: int = DEFAULT_STATION_SESSIONS,
        _cloud_factory: Callable[..., EufyCloudApi] | None = None,
        _discovery_port: int | None = None,
    ) -> None:
        """``password`` may be None once a login has cached it (see ``SessionCache``).

        ``country`` (ISO 3166 alpha-2, e.g. Home Assistant's ``hass.config.country``) is
        the country the account logs in with, as the eufy app does; without it the host's
        IP country is used (see :class:`EufyCloudApi`). eufy lists a device only to a
        login with the country it is held under, so a sequence adds extra countries: the
        first is the login country, each further one logs in once more on its own home
        region and its devices join the list. ``timezone`` is the IANA zone the cloud
        requests carry (Home Assistant's ``hass.config.time_zone``; default UTC).

        Each country logs in on its home cloud region only (one login scope each); while
        no country is known, every region does. ``region`` pins the login country's
        scope to one cloud region (``eu``, ``us``). Each device keeps the scope that
        listed it; a scope that lists nothing is suspended until
        ``async_discover(rescan_regions=True)``, or, with ``scan_regions``, every
        device-list refresh asks every scope (see :class:`EufyCloudApi`).

        ``email`` must look like an e-mail address (not empty, with an ``@``), else
        ``ValueError`` before anything is read or sent: a login with it would only
        spend the login budget.

        ``max_sessions`` is how many P2P sessions this client holds to one station at
        most (:attr:`Station.max_sessions`, changeable later per station): the station
        session, one for trigger frames and the rest for live streams of a second and
        further cameras. A HomeBase 3 holds 9 across all clients, the app included.
        Outside :data:`~.p2p.session.MIN_STATION_SESSIONS` ..
        :data:`~.p2p.session.STATION_SESSION_LIMIT`: ``ValueError``.

        ``local_ports`` pins one local UDP port per station serial, so a firewall can
        admit each station's replies (see :mod:`.network`); stations not in it bind an
        ephemeral port. Two stations cannot share a pinned port (ValueError).

        Pass one ``claims`` to every account of a process so that a station shared
        between accounts is served by exactly one of them. Likewise pass one
        ``install`` (:class:`~.install.InstallState`) to every account, so a request
        throttle the cloud answers one account with holds off the others too.

        ``stations`` includes stations by serial (see :mod:`.inclusion`):
        ``Reach.LOCAL`` builds a :class:`Station`, ``Reach.REMOTE`` a
        :class:`RemoteStation`; a station not listed is left out, and push events for
        it are dropped. None includes every station locally.

        ``deduplicate`` (default) passes every :class:`SecurityEvent` from both channels
        through one :class:`~.events.EventDeduplicator` (:attr:`deduplicator`) before
        it is emitted, so an occurrence that arrives over P2P and over the cloud, or
        is re-announced, is emitted once (plus enrichment copies that add media paths, a
        picture or a more specific kind, see :attr:`SecurityEvent.enriches`). False
        emits every decoded copy.

        Guard mode, whatever ``deduplicate`` says, passes one account-wide
        :class:`~.events.GuardModeTracker` for both channels: a guard-mode push (cloud,
        or P2P) that is stale for its station is dropped, event and all; a P2P report
        of the station's state is never dropped but orders the pushes after it; and a
        :class:`~.events.GuardModeChanged` is emitted only when the mode differs from
        the last one emitted for that station, so a change reported on both channels
        is emitted once, by the channel that delivered it first.

        The alarm lifecycle likewise passes one account-wide
        :class:`~.events.AlarmTracker`: a station's alarm tone frames over P2P and the
        cloud's alarm pushes become one :class:`~.events.AlarmChanged` per start and
        per end, and a change of guard mode to a disarmed mode ends an alarm.

        A station reached on demand (a battery device,
        :func:`~.devices.types.connects_on_demand`) holds no session. Its state comes from
        the cloud device list's parameter snapshot: kept in the cache, applied when the
        station is built, and fetched again every ``cloud_state_refresh`` seconds (one
        device-list call for the account) while :meth:`async_start` runs; pushes update it
        in between.

        ``_cloud_factory`` and ``_discovery_port`` are private seams for
        :mod:`eufy_home_security.testing` only: the factory is called like
        :class:`EufyCloudApi`, and the port is the UDP port every station session
        searches on (instead of the PPPP discovery port).
        """
        if "@" not in email.strip():
            raise ValueError("not an e-mail address")
        self._session_source = session
        self.cache = SessionCache(store, email)
        self.cloud = (_cloud_factory or EufyCloudApi)(
            self._http_session,
            self.cache,
            email,
            password,
            country=country,
            timezone=timezone,
            region=region,
            scan_regions=scan_regions,
            install=install,
        )
        self._discovery_port = DISCOVERY_PORT if _discovery_port is None else _discovery_port
        if cloud_state_refresh <= 0:
            raise ValueError("cloud_state_refresh must be positive")
        self._cloud_state_refresh = cloud_state_refresh
        self._cloud_state_task: asyncio.Task[None] | None = None
        self._station_hosts = dict(station_hosts or {})
        check_local_ports(local_ports or {})
        self._max_sessions = _session_budget(max_sessions)
        self._local_ports = dict(local_ports or {})
        self._bus = EventBus()
        # One ring for the account, both channels; it outlives every session reconnect.
        self.deduplicator: EventDeduplicator | None = EventDeduplicator() if deduplicate else None
        # Guard-mode ordering for the account, both channels; its stamps persist in the
        # push section once the cache is loaded.
        self._guard = GuardModeTracker()
        self._guard_loaded = False
        # The alarm state of every station, both channels.
        self._alarms = AlarmTracker()
        # CloudProblem error types already emitted since the last cloud success.
        self._cloud_problems: set[type[CloudError]] = set()
        self._unsubs: list[Unsubscribe] = []
        self._push: PushListener | None = None
        self._push_running = False
        self._push_error: EufySecurityError | None = None
        # Serialises the stations' credential lookups: concurrent starts on a cold cache
        # would otherwise each fetch the device list, owner id and security realm.
        self._credentials_lock = asyncio.Lock()
        self._claims = claims
        self._included = dict(stations) if stations is not None else None
        self.stations: dict[str, Station] = {}
        self.remote_stations: dict[str, RemoteStation] = {}
        # Stations on the account this instance does not serve: their pushes are dropped.
        self._not_served: frozenset[str] = frozenset()
        # Stations on this account that another account in the process serves.
        self.stations_served_elsewhere: tuple[CloudDevice, ...] = ()
        # Devices of the last device list that nothing is built for (see SkippedDevice).
        self.skipped_devices: tuple[SkippedDevice, ...] = ()
        # Every device the last discovery's list named, by serial: stations built, served
        # elsewhere, remote, paired devices and skipped devices alike.
        self.listed_devices: Mapping[str, CloudDevice] = MappingProxyType({})
        # Built stations the last discovery's list did not name (reported once each).
        self._unlisted: frozenset[str] = frozenset()
        self._discovered = False
        # The model scan (_async_scan_models): read-only settings listed from the cloud
        # TD per unbundled product code.
        self._scanned = False
        self._account_models: tuple[str, ...] = ()
        self._listed: dict[str, tuple[Setting, ...]] = {}
        self._cloud_td: dict[str, int] = {}
        # One line per (product code, reason) of the scan and per newer TD version.
        self._scan_throttle = LogThrottle(interval=math.inf)

    def _http_session(self) -> aiohttp.ClientSession:
        """The aiohttp session, resolving a factory on first use (see ``HttpSession``)."""
        source = self._session_source
        if callable(source):
            source = self._session_source = source()
        return source

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.async_close()

    # ── setup ────────────────────────────────────────────────────────────────

    async def async_login(
        self,
        *,
        verify_code: str | None = None,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        login_id: str | None = None,
        force: bool = False,
    ) -> None:
        """Log in (reusing a cached session unless ``force``).

        Raises ``LoginChallengeError`` for 2FA/captcha: call again with the answer;
        ``LoginVerificationError`` when the cloud refuses a code answer. After another client took over the session
        (``SessionReplacedError``) only ``force`` logs in again — a user's decision.
        """
        await self._ensure_cache_loaded()
        await self.cloud.async_login(
            verify_code=verify_code,
            captcha_id=captcha_id,
            captcha_answer=captcha_answer,
            login_id=login_id,
            force=force,
        )
        self._cloud_succeeded()

    @property
    def session_replaced(self) -> bool:
        """Whether another client's login ended the cloud session (see ``async_login``)."""
        return self.cloud.session_replaced

    async def async_cloud_status(self) -> CloudStatus:
        """What a login would need and what the budget allows; never contacts the cloud."""
        await self._ensure_cache_loaded()
        return self.cloud.cloud_status()

    async def async_firmware_updates(self, *, refresh: bool = False) -> list[FirmwareUpdate]:
        """The firmware updates the cloud OTA offers, one per device that has one.

        Checks every HomeBase-attached device (the hub and each paired camera) with its
        own serial under the hub's firmware-kit type, and returns a
        :class:`~.cloud.models.FirmwareUpdate` for each that a newer version is available
        for — an empty list when everything is current (the usual case). A standalone
        battery camera is skipped: its OTA kit type is not established. Uses the cached
        device list unless ``refresh``.

        This is one cloud call per device, on the account's shared throttle, so run it on
        a slow timer (eufy publishes firmware rarely) rather than per start. It surfaces
        the download URL and checksum the moment eufy publishes an update, for a Home
        Assistant ``update`` entity.
        """
        devices = await self.cloud.async_get_devices(refresh=refresh)
        hubs = frozenset(d.device_sn for d in devices if d.is_station and not d.is_standalone)
        updates: list[FirmwareUpdate] = []
        for device in devices:
            hub = device.device_sn if device.is_station else device.station_sn
            version = device.main_sw_version
            if hub not in hubs or not version:
                continue
            update = await self.cloud.async_check_firmware(
                device.device_sn,
                ota_type=firmware_ota_type(hub),
                current_version_name=version,
            )
            if update is not None:
                updates.append(update)
        return updates

    async def async_cache_summary(self) -> dict[str, Any]:
        """A JSON-safe, secret-free view of the cache and the cloud status, for diagnostics.

        The cache part comes from :meth:`SessionCache.redacted_summary`: the stored
        version, the sections present, which cloud-session and push fields are held
        (names only), the device count, and per station (serial via
        :func:`redact_serial`) whether its owner account id and its cipher key are cached,
        with that station's refresh ages from :meth:`async_cloud_status`.
        ``cloud_status`` holds the account-wide rest of it (login need, hold-offs,
        login budget, refresh ages, and per cloud region its session expiry, device
        count, listing age, login ``country_code`` and whether it is suspended). Never a password, token, key, openudid, owner or
        user id, push credential, full serial, DID or IP. Never contacts the cloud.
        """
        status = await self.async_cloud_status()
        per_station = {
            serial: {f.name: getattr(refresh, f.name) for f in fields(refresh)}
            for serial, refresh in status.stations.items()
        }
        summary = self.cache.redacted_summary(station_details=per_station)
        cloud_status: dict[str, Any] = {
            f.name: getattr(status, f.name) for f in fields(status) if f.name != "stations"
        }
        cloud_status["login_need"] = status.login_need.value
        cloud_status["regions"] = {
            region: {f.name: getattr(state, f.name) for f in fields(state)}
            for region, state in status.regions.items()
        }
        summary["cloud_status"] = cloud_status
        return summary

    async def async_account_report(self, *, ciphers: bool = True) -> AccountReport:
        """Every device each eufy list names, with firmware and cipher state, for
        diagnostics: see :func:`~.diagnostics.async_account_report`.

        Read-only and login-free: it asks only regions whose session is held or cached,
        caches nothing and changes no station. ``ciphers`` adds one cipher-table sweep
        per station owner. A few cloud requests per region: call it when a user asks
        (a diagnostics download), not on a timer.
        """
        await self._ensure_cache_loaded()
        served = (
            frozenset(self.stations) | frozenset(self.remote_stations) if self._discovered else None
        )
        return await async_account_report(
            self.cloud, self.cache, ciphers=ciphers, served_stations=served
        )

    async def async_pending_invites(self) -> list[CloudInvite]:
        """The invitations sent to the account that it has not accepted, in every region
        whose session is held or cached (see :meth:`EufyCloudApi.async_list_invites`).

        Login-free: a region without a session is not asked. A region whose request
        fails is skipped; the error is raised only when no region answered. The account
        sees a shared home's devices only once the invitation is accepted in the eufy
        app, so a consumer can tell the user so. Two cloud requests per region: call it
        when the device list comes back empty or on a user's request, not on a timer.
        """
        await self._ensure_cache_loaded()
        invites: list[CloudInvite] = []
        errors: list[EufySecurityError] = []
        regions = self.cloud.regions_with_session()
        for region in regions:
            try:
                invites += await self.cloud.async_list_invites(region, login=False)
            except EufySecurityError as err:
                _LOGGER.debug("pending invitations of the %s region not read: %r", region, err)
                errors.append(err)
        if errors and len(errors) == len(regions):
            raise errors[0]
        return invites

    async def async_reauthenticate(
        self,
        password: str,
        *,
        verify_code: str | None = None,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        login_id: str | None = None,
        take_over: bool = False,
    ) -> None:
        """One real login with ``password``, whatever the cache holds.

        The cached password is replaced only on success, and every station's key-refresh
        latch is released. See :meth:`EufyCloudApi.async_reauthenticate`.
        """
        await self._ensure_cache_loaded()
        await self.cloud.async_reauthenticate(
            password,
            verify_code=verify_code,
            captcha_id=captcha_id,
            captcha_answer=captcha_answer,
            login_id=login_id,
            take_over=take_over,
        )
        self._cloud_succeeded()

    async def async_reset_key_refresh(self, serial: str | None = None) -> None:
        """Release a station's key-refresh latch (None: every station).

        The release path after a ``KeyRejectedError``: the station's next rejected
        handshake may fetch its key once more (the per-station cipher cooldown still
        applies).
        """
        await self._ensure_cache_loaded()
        await self.cloud.async_reset_key_refresh(serial)

    async def _ensure_cache_loaded(self) -> None:
        """Read the store before anything reads or writes the cache.

        Without it, a cloud call made before :meth:`async_login` would work from an
        empty document — minting a new ``openudid``, logging in again — and then
        overwrite the stored one.
        """
        if not self.cache.loaded:
            await self.cache.async_load()

    async def async_discover(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[Station]:
        """Build a :class:`Station` per HomeBase from the (cached) device list.

        ``refresh`` forces a fresh cloud fetch; otherwise the cached list is used
        when there is one, so a warm start needs no cloud call at all.
        ``rescan_regions`` fetches too and asks every login scope, the suspended
        ones included (see :meth:`EufyCloudApi.async_fetch_devices`). With
        ``claims``, only the stations this account wins are built; the others are
        listed in :attr:`stations_served_elsewhere`. Stations included as remote go to
        :attr:`remote_stations`; the returned list holds the local ones. Devices
        nothing can be built for are listed in :attr:`skipped_devices`, every device of
        the list in :attr:`listed_devices`, and how the list was obtained in
        :attr:`device_list_source`. A discovery after the first emits
        :class:`~.events.StationsChanged` when it built a station or the list no longer
        names a built one.
        """
        await self._ensure_cache_loaded()
        devices = await self.cloud.async_get_devices(refresh=refresh, rescan_regions=rescan_regions)
        first = not self._discovered
        built = frozenset(self.stations) | frozenset(self.remote_stations)
        self._discovered = True
        self.listed_devices = MappingProxyType({d.device_sn: d for d in devices})
        candidates, children, self.skipped_devices = _group(devices)
        included = [d for d in candidates if self._reach(d.device_sn) is not None]
        if self._claims is None:
            served: frozenset[str] = frozenset(d.device_sn for d in included)
        else:
            served = self._claims.claim(self.cache.account, included)
        self.stations_served_elsewhere = tuple(d for d in included if d.device_sn not in served)
        self._not_served = frozenset(d.device_sn for d in candidates if d.device_sn not in served)
        await asyncio.to_thread(_load_settings, devices)
        await self._async_scan_models(devices, refresh=refresh or rescan_regions)
        for device in candidates:
            serial = device.device_sn
            sub_devices = tuple(children.get(serial, ()))
            if serial in self.stations:
                # Already built: its paired devices follow the list in place (DevicesChanged).
                self.stations[serial].update_sub_devices(sub_devices)
                self.stations[serial].apply_cloud_device(device)
                continue
            if serial not in served or serial in self.remote_stations:
                continue
            if self._reach(serial) is Reach.REMOTE:
                self.remote_stations[serial] = RemoteStation(device=device, sub_devices=sub_devices)
                continue
            session = StationSession(
                serial,
                self._credential_provider(serial),
                host=self._search_host(device),
                port=self._discovery_port,
                local_port=self._local_ports.get(serial, 0),
                did=device.p2p_did,
                expect_channels=station_channels(device, sub_devices),
                block_aliases=station_block_aliases(device),
                on_demand=connects_on_demand(serial),
                wake_provider=self._wake_provider(device) if connects_on_demand(serial) else None,
                key_refresh=_CachedKeyRefreshLatch(self.cache, serial),
                cloud_problems_reported=True,
                max_sessions=self._max_sessions,
            )
            station = Station(
                device,
                session,
                sub_devices=sub_devices,
                cache=self.cache,
                listed_settings=self._listed_settings,
                cloud_refresh=self.async_refresh_cloud_state,
            )
            station.apply_cloud_device(device)  # the cached snapshot, until a fresh one
            self.stations[serial] = station
            self._unsubs.append(station.subscribe(self._on_station_event))
        self._report_stations_changed(first, built, candidates)
        return list(self.stations.values())

    @property
    def device_list_source(self) -> DeviceListSource | None:
        """How the last device list was obtained (:data:`~.cloud.status.DeviceListSource`):
        ``"fetched"`` is a whole answer of every scope in use; None before the first list."""
        return self.cloud.device_list_source

    def _report_stations_changed(
        self, first: bool, built: frozenset[str], candidates: Sequence[CloudDevice]
    ) -> None:
        """Emit :class:`StationsChanged` for the stations this discovery built and the
        built ones its list no longer names (once each); nothing on the first discovery."""
        now_built = frozenset(self.stations) | frozenset(self.remote_stations)
        unlisted = built - {d.device_sn for d in candidates}
        removed, self._unlisted = unlisted - self._unlisted, unlisted
        added = now_built - built
        if first or not (added or removed):
            return
        self._bus.emit(
            StationsChanged(
                added=tuple(sorted(added)),
                removed=tuple(sorted(removed)),
                source=self.cloud.device_list_source,
            )
        )

    # ── models without a bundled file ───────────────────────────────────────

    async def _async_scan_models(self, devices: Sequence[CloudDevice], *, refresh: bool) -> None:
        """Ask the cloud for the thing description of every product code of the account,
        in one request, on the first discovery and on every ``refresh``.

        A code without a bundled file gets its TD's settings listed read-only
        (:func:`~.devices.td.parse_thing_description`); a bundled code whose TD version
        is newer than the file's is logged once at INFO. The request never logs in.
        Every failure is logged once per code and reason and leaves the code unlisted;
        none is raised.
        """
        if self._scanned and not refresh:
            return
        self._scanned = True
        codes = _account_codes(devices)
        self._account_models = codes
        if not codes:
            return
        bundled = frozenset(await asyncio.to_thread(bundled_codes))
        missing = tuple(c for c in codes if c not in bundled)
        try:
            things = await self.cloud.async_get_thing_descriptions(codes)
        except NoCachedSessionError:
            self._scan_note(missing, "no cached cloud session", logging.INFO)
            return
        except KeyExchangeRefusedError:
            # The next ordinary call runs a new key exchange; the next refresh lists them.
            self._scan_note(missing, _SCAN_KEY_REFUSED, logging.INFO)
            return
        except EufySecurityError as err:
            # The message, never the class name: an internal error type is no user text.
            reason = str(err) or "cloud request failed"
            self._scan_note(missing, reason, logging.WARNING, kind=type(err))
            return
        found = _by_code(things, codes)
        for code in codes:
            td = found.get(code)
            if td is None:
                if code in missing:
                    self._scan_note((code,), "not in the cloud's reply", logging.INFO)
                continue
            version = td_version(td)
            if version is not None:
                self._cloud_td[code] = version
            if code in missing:
                try:
                    settings = parse_thing_description(code, td)
                except ValueError as err:
                    self._scan_note((code,), str(err), logging.WARNING)
                    continue
                self._listed[code] = tuple(sorted(settings.values(), key=lambda s: s.key))
            else:
                await self._note_newer(code, version)

    def _scan_note(
        self, codes: Sequence[str], reason: str, level: int, *, kind: object = None
    ) -> None:
        """Log that the thing descriptions of ``codes`` (unbundled ones) stay unlisted:
        once per code and ``kind`` (``reason`` when None)."""
        if not codes:
            _LOGGER.debug("model scan skipped: %s", reason)
            return
        for code in codes:
            if self._scan_throttle.should_log(("scan", code, reason if kind is None else kind)):
                _LOGGER.log(
                    level, "no settings listed for %s from its thing description: %s", code, reason
                )

    async def _note_newer(self, code: str, version: int | None) -> None:
        """Log once when the cloud's TD of bundled ``code`` is newer than the file's."""
        if version is None:
            return
        bundled = await asyncio.to_thread(_bundled_version, code)
        newer = bundled is not None and version > bundled
        if newer and self._scan_throttle.should_log(("newer", code, version)):
            _LOGGER.info(
                "vendor data for %s is newer than bundled (td %d > %d)", code, version, bundled
            )

    def model_status(self) -> tuple[ModelStatus, ...]:
        """One :class:`ModelStatus` per product code of the account, sorted by code;
        ``()`` before the first :meth:`async_discover`. Sync and free of I/O: discovery
        has loaded the bundled listing and every account model's file."""
        if not self._account_models:
            return ()
        bundled = frozenset(bundled_codes())
        out: list[ModelStatus] = []
        for code in self._account_models:
            state: ModelState
            if code in bundled:
                state = "bundled"
            elif code in self._listed:
                state = "cloud-listed"
            else:
                state = "unknown"
            version = _bundled_version(code) if code in bundled else None
            out.append(ModelStatus(code, state, version, self._cloud_td.get(code)))
        return tuple(out)

    def _listed_settings(self, product_code: str) -> tuple[Setting, ...]:
        """The settings listed from the cloud TD for ``product_code``; ``()`` for none."""
        return self._listed.get(product_code, ())

    def _wake_provider(self, device: CloudDevice) -> WakeProvider:
        """A :class:`~.p2p.session.WakeProvider` for a battery station: its rendezvous
        servers (from the cloud entry) and a cached-or-fetched DSK. A cloud failure
        becomes a ``CloudProblem`` and returns None, so a wake falls back to LAN discovery."""
        cloud, serial = self.cloud, device.device_sn
        servers = device.rendezvous_servers

        async def provide() -> Wake | None:
            if not servers:
                return None
            await self._ensure_cache_loaded()
            try:
                dsk = await cloud.async_get_dsk_key(serial)
            except SessionReplacedError as err:
                # No wake is possible until a human takes the session back: fail the
                # connect now rather than after a LAN search a sleeping camera ignores.
                self._cloud_failed(err, serial)
                raise
            except CloudError as err:
                self._cloud_failed(err, serial)
                return None
            self._cloud_succeeded()
            return Wake(servers=servers, dsk=dsk)

        return provide

    def _credential_provider(self, station_sn: str) -> CredentialProvider:
        """The station's credentials; a cloud failure inside it becomes a ``CloudProblem``.

        A forced refresh that returns a key emits ``CredentialsRefreshed`` and counts as
        a successful cloud call.
        """
        cloud, cache = self.cloud, self.cache

        async def provide(*, refresh: bool, cipher_id: int | None) -> P2PCredentials:
            async with self._credentials_lock:
                return await fetch(refresh=refresh, cipher_id=cipher_id)

        async def fetch(*, refresh: bool, cipher_id: int | None) -> P2PCredentials:
            await self._ensure_cache_loaded()
            if cipher_id is None:
                cipher_id = cache.station_cipher_id(station_sn)
            elif cipher_id != cache.station_named_cipher_id(station_sn):
                # Stored before the fetch, so a failed fetch keeps the id the station named.
                cache.set_station_cipher_id(station_sn, cipher_id)
                await cache.async_save()
            owner_age = cache.seconds_since_refresh("owner")
            last_login = _last_login(cache)
            try:
                account_id = await cloud.async_get_station_owner_id(station_sn, refresh=refresh)
                # A station naming no cipher runs under its static key: nothing to fetch.
                keys = (
                    CipherKeys(ecc_private_key=None, rsa_private_key=None)
                    if cipher_id == CONN_INIT_NO_CIPHER
                    else await cloud.async_get_cipher_keys(station_sn, cipher_id, refresh=refresh)
                )
            except CloudError as err:
                self._cloud_failed(err, station_sn)
                raise
            if refresh:
                self._cloud_succeeded()
                age = cache.seconds_since_refresh("owner")
                self._bus.emit(
                    CredentialsRefreshed(
                        station_sn=station_sn,
                        cipher=True,
                        owner_id=age is not None and (owner_age is None or age < owner_age),
                        login=_last_login(cache) != last_login,
                    )
                )
            _LOGGER.debug(
                "%s: P2P credentials (refresh=%s): account_id %s, user_name %s, cipher %d key %s, "
                "RSA key %s",
                redact_serial(station_sn),
                refresh,
                Secret(account_id),
                Identifier(cloud.user_name),
                cipher_id,
                Secret(keys.ecc_private_key or ""),
                "held" if keys.rsa_private_key else "none",
            )
            return P2PCredentials(
                account_id=account_id,
                user_name=cloud.user_name,
                ecc_private_key=keys.ecc_private_key or "",
                cipher_id=cipher_id,
                rsa_private_key=keys.rsa_private_key,
            )

        return provide

    def _cloud_failed(self, error: CloudError, station_sn: str | None) -> None:
        """Emit a ``CloudProblem`` for ``error``, once per error type until a cloud success."""
        if not CloudProblem.covers(error) or type(error) in self._cloud_problems:
            return
        self._cloud_problems.add(type(error))
        self._bus.emit(CloudProblem(error=error, station_sn=station_sn))

    def _cloud_succeeded(self) -> None:
        """A cloud call or login succeeded: the next failure of any type is news again."""
        self._cloud_problems.clear()

    def _on_push_token_upload(self, error: CloudError | None) -> None:
        if error is None:
            self._cloud_succeeded()
        else:
            self._cloud_failed(error, None)

    @property
    def push_running(self) -> bool:
        """Whether the cloud push listener is listening (see :class:`~.events.PushChanged`).

        False before ``async_start(push=True)``, while the listener restarts after it
        stopped listening, and after ``async_close``.
        """
        return self._push_running

    @property
    def push_error(self) -> EufySecurityError | None:
        """The last push start or restart failure; None while listening or after a clean stop."""
        return self._push_error

    def _on_push_listening(self, running: bool, error: EufySecurityError | None) -> None:
        """Track the listener's state; emit ``PushChanged`` on a change, not per retry."""
        previous = self._push_error
        changed = running != self._push_running or (
            not running and error is not None and type(error) is not type(previous)
        )
        self._push_running, self._push_error = running, error
        if not changed:
            return
        if isinstance(error, CloudError) and CloudProblem.covers(error):
            # Delivered as a CloudProblem (de-duplicated with the token upload's report).
            self._cloud_failed(error, None)
            error = None
        self._bus.emit(PushChanged(running=running, error=error))

    def _reach(self, serial: str) -> Reach | None:
        return Reach.LOCAL if self._included is None else self._included.get(serial)

    def _search_host(self, device: CloudDevice) -> str | None:
        return self._station_hosts.get(device.device_sn) or lan_address(device.local_ip)

    async def async_station_choices(
        self, *, timeout: float | None = None, port: int = DISCOVERY_PORT
    ) -> list[StationChoice]:
        """Every station on the account, with its reach after one LAN probe.

        For a setup step that asks which stations to include (see :mod:`.inclusion`).
        Builds nothing and opens no session; the device list comes from the cache
        when there is one. Safe on a running account: the probe is the one of
        :meth:`async_probe_lan`, so a station with a connected session is never
        searched and is reported local, at the session's host.
        """
        await self._ensure_cache_loaded()
        candidates, children, self.skipped_devices = _group(await self.cloud.async_get_devices())
        paths = [
            lan_path_for(
                device,
                search_host=self._search_host(device),
                local_port=self._local_ports.get(device.device_sn, 0),
            )
            for device in candidates
        ]
        probed = await self._probe(paths, candidates, timeout=timeout, port=port)
        return [
            StationChoice(
                device=device, sub_devices=tuple(children.get(device.device_sn, ())), path=path
            )
            for device, path in zip(candidates, probed, strict=True)
        ]

    async def async_probe_lan(
        self, *, timeout: float | None = None, port: int = DISCOVERY_PORT
    ) -> list[LanPath]:
        """Each built station's :class:`LanPath`, with one LAN discovery folded in.

        Searches the broadcast address and every configured station address at once
        and records where each station answered from. It opens no session and needs
        no cloud, so it suits a setup step (a pinned local port is not reused here:
        discovery binds an ephemeral one).

        Guarantee: a station with a connected session is never sent a LAN_SEARCH. It is
        reported from its session instead (answered, ``observed_ip`` = the session's
        host), so the probe may run while the sessions are live. While any station of
        the account is connected no broadcast is sent either: only the known addresses
        of the stations that are not connected are searched, so a station without a
        known address is found only while nothing is connected.
        """
        stations = list(self.stations.values())
        return await self._probe(
            [station.lan_path for station in stations],
            [station.device for station in stations],
            timeout=timeout,
            port=port,
        )

    async def _probe(
        self,
        paths: list[LanPath],
        devices: list[CloudDevice],
        *,
        timeout: float | None,
        port: int,
    ) -> list[LanPath]:
        """``paths`` (one per device, same order) with one discovery folded in.

        Stations with a connected session are not searched (see :meth:`async_probe_lan`).
        """
        from .p2p.discovery import discover_stations  # noqa: PLC0415 - a setup-time call

        live = {
            serial: station.session
            for serial, station in self.stations.items()
            if station.session.connected
        }
        live_hosts = {session.host for session in live.values()}
        targets = {
            path.host
            for path in paths
            if path.host and path.serial not in live and path.host not in live_hosts
        }
        if not live:
            targets.add(BROADCAST)
        if all(path.serial in live for path in paths):
            targets.clear()

        async def search(target: str) -> list[Any]:
            try:
                return await discover_stations(timeout=timeout, port=port, target=target)
            except EufySecurityError as err:
                _LOGGER.debug("LAN probe of %s failed: %s", target, err)
                return []

        results = await asyncio.gather(*(search(target) for target in sorted(targets)))
        replies = [reply for found in results for reply in found]
        return [
            replace(path, answered=True, observed_ip=live[path.serial].host)
            if path.serial in live
            else with_discovery(path, device.p2p_did, replies)
            for path, device in zip(paths, devices, strict=True)
        ]

    # ── running ──────────────────────────────────────────────────────────────

    def subscribe(self, callback: EventCallback) -> Unsubscribe:
        """Receive events from every station and from cloud push."""
        return self._bus.subscribe(callback)

    async def async_start(
        self, *, p2p: bool = True, push: bool = True
    ) -> Mapping[str, EufySecurityError]:
        """Start local sessions and the push listener.

        Nothing here is fatal to the rest: a push registration that fails is
        logged and reported (:attr:`push_running`, :attr:`push_error` and a
        :class:`~.events.PushChanged`; call again later to retry it), and an
        unreachable station is logged while its supervisor keeps retrying in the
        background. Push never raises here.

        The stations connect concurrently: one station's failure or slow discovery
        neither delays nor cancels another's start. Their credential lookups are
        serialised, so stations on a cold cache share one device-list fetch.

        Returns the first-start error per station serial (empty when every station
        started). The same failure also arrives as a ``ConnectionChanged`` with its
        cause, emitted by the station's session.
        """
        errors: dict[str, EufySecurityError] = {}
        await self._ensure_cache_loaded()
        if push and self._push is None:
            # Imported here: the FCM stack is the slowest import and only `monitor`-style
            # callers need it.
            from .push.fcm import PushListener  # noqa: PLC0415

            listener = PushListener(
                self.cloud,
                self.cache,
                self._on_push,
                session=self._http_session(),
                on_token_upload=self._on_push_token_upload,
                on_listening=self._on_push_listening,
            )
            try:
                await listener.async_start()
            except Exception as err:
                # A typed error is an expected outage; anything else is a bug worth
                # a traceback. Either way the stations below still start.
                _LOGGER.warning(
                    "cloud push not started: %s",
                    err,
                    exc_info=not isinstance(err, EufySecurityError),
                )
                await _best_effort("stop the push listener", listener.async_stop)
                failure = (
                    err
                    if isinstance(err, EufySecurityError)
                    else CommunicationError(f"push listener did not start: {err!r}")
                )
                self._on_push_listening(False, failure)
            else:
                self._push = listener
                self._on_push_listening(True, None)
        if p2p:
            await self._start_cloud_state()
            stations = list(self.stations.values())
            outcomes = await asyncio.gather(
                *(station.async_start() for station in stations), return_exceptions=True
            )
            unexpected: BaseException | None = None
            for station, outcome in zip(stations, outcomes, strict=True):
                if isinstance(outcome, EufySecurityError):
                    errors[station.serial] = outcome
                    _LOGGER.warning(
                        "%s: local session not started: %s", redact_serial(station.serial), outcome
                    )
                elif isinstance(outcome, BaseException) and unexpected is None:
                    unexpected = outcome
            if unexpected is not None:
                raise unexpected  # a bug, not an outage: after every other start finished
        return errors

    async def async_close(self) -> None:
        """Stop everything and persist the cache.

        Best effort: one part failing to stop is logged and does not keep the rest
        running, and the cache is saved regardless.
        """
        try:
            if self._cloud_state_task is not None:
                task, self._cloud_state_task = self._cloud_state_task, None
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if self._push is not None:
                push, self._push = self._push, None
                await _best_effort("stop the push listener", push.async_stop)
            self._on_push_listening(False, None)
            stations = list(self.stations.values())
            self.stations.clear()
            for station in stations:
                await _best_effort(f"close {redact_serial(station.serial)}", station.async_close)
            if self._claims is not None:
                self._claims.release(self.cache.account)
            unsubs = list(self._unsubs)
            self._unsubs.clear()
            for unsub in unsubs:
                try:
                    unsub()
                except Exception:
                    _LOGGER.warning("unsubscribe failed while closing", exc_info=True)
        finally:
            if self.cache.loaded:
                await self.cache.async_save()

    async def async_probe_cloud_session(self) -> None:
        """Ask the cloud whether it still accepts this client's session; raises if not.

        One authenticated device-list fetch on the cached session (its account-wide,
        house and per-house lists: :meth:`EufyCloudApi.async_fetch_devices`), for a
        consumer to run on a long interval (hours) so a kick-out or a lapsed key identity that
        happens while nothing else talks to the cloud is noticed. Nothing is rebuilt
        or applied: no :class:`~.events.DevicesChanged`, no station update, no wake;
        the fetched list replaces the cached one as any refresh does.

        It never falls back to the cached list. A failure is raised (and reported once
        as a :class:`~.events.CloudProblem`, as every cloud failure is):
        :class:`~.exceptions.SessionReplacedError` (without I/O once latched),
        :class:`~.exceptions.KeyExchangeRefusedError`, :class:`~.exceptions.AuthenticationError`,
        :class:`~.exceptions.RateLimitedError`, or :class:`~.exceptions.CommunicationError`
        when the cloud could not be reached. It costs a login only as every call does:
        once, and only when the cloud says the token expired; a lapsed key identity
        costs a key exchange, never a login. It asks the regions in use only; with every
        region suspended it sends nothing.
        """
        await self._ensure_cache_loaded()
        try:
            await self.cloud.async_fetch_devices()
        except CloudError as err:
            self._cloud_failed(err, None)
            raise
        self._cloud_succeeded()

    async def async_refresh_cloud_state(self) -> int:
        """Fetch the device list and apply each station's entry
        (:meth:`Station.apply_cloud_device`): an on-demand station's state, every
        station's cloud copy of its settings. Returns how many values were news; wakes no
        station and fetches nothing without a station.

        :meth:`async_start` runs it every ``cloud_state_refresh`` seconds while there is a
        station, and once at start when a station has no cloud copy yet. A cloud failure is raised here, and in that loop
        reported as a :class:`~.events.CloudProblem` and retried at the next interval.
        """
        stations = dict(self.stations)
        if not stations:
            return 0
        await self._ensure_cache_loaded()
        try:
            devices = await self.cloud.async_get_devices(refresh=True)
        except CloudError as err:
            self._cloud_failed(err, None)
            raise
        self._cloud_succeeded()
        news = sum(
            stations[d.device_sn].apply_cloud_device(d) for d in devices if d.device_sn in stations
        )
        _LOGGER.debug("cloud state of %d station(s): %d new value(s)", len(stations), news)
        return news

    async def _start_cloud_state(self) -> None:
        """Start the cloud-state loop once, when there is a station.

        Every station takes the settings its dump lacks from the device list, and a
        station reached on demand its whole state; the loop refreshes that copy every
        ``cloud_state_refresh`` seconds. An on-demand station without any state yet (a
        cold cache), or a station without a cloud copy (a list cached without station
        parameters), is fetched before this returns, so a first ``async_update()`` finds
        state instead of waking the device; otherwise the cached snapshot serves until
        the first interval ends.
        """
        if self._cloud_state_task is not None and not self._cloud_state_task.done():
            return
        if not self.stations:
            return
        on_demand = [s for s in self.stations.values() if s.connects_on_demand]
        no_copy = [s for s in self.stations.values() if not s.has_cloud_copy]
        if no_copy or any(s.state is None for s in on_demand):
            await self._refresh_cloud_state_logged()
        self._cloud_state_task = asyncio.get_running_loop().create_task(
            self._refresh_cloud_state_every(), name="eufy-cloud-state"
        )

    async def _refresh_cloud_state_every(self) -> None:
        while True:
            await asyncio.sleep(self._cloud_state_refresh)
            await self._refresh_cloud_state_logged()

    async def _refresh_cloud_state_logged(self) -> None:
        try:
            await self.async_refresh_cloud_state()
        except EufySecurityError as err:
            _LOGGER.warning("cloud state refresh failed: %s", err)

    def _admit(self, event: SecurityEvent) -> SecurityEvent | None:
        """``event`` (or its enrichment copy) when it is news; None for a duplicate."""
        if self.deduplicator is None:
            return event
        admitted = self.deduplicator.admit(event)
        if admitted is None:
            _LOGGER.debug(
                "dropping a %s copy of an event already delivered (%s)",
                event.source,
                redact_serial(event.device_sn),
            )
        return admitted

    def _guard_tracker(self) -> GuardModeTracker:
        """The account's guard-mode ordering, merged with the persisted stamps once loaded."""
        if not self._guard_loaded and self.cache.loaded:
            self._guard_loaded = True
            self._guard.load(self.cache.section("push").get("guard_event_ms"))
        return self._guard

    def _store_guard_stamps(self) -> None:
        if self.cache.loaded:
            self.cache.section("push")["guard_event_ms"] = self._guard.stamps
            self.cache.schedule_save()

    def _on_station_event(self, event: Event) -> None:
        if isinstance(event, SecurityEvent):
            self._deliver(event)
            return
        if isinstance(event, GuardModeChanged):
            # The station's own state (0x047F, a parameter dump, an arm's result or read-back):
            # never stale, and later pushes are ordered after it.
            tracker = self._guard_tracker()
            tracker.note_report(event.station_sn)
            self._store_guard_stamps()
            if not tracker.changed(event.station_sn, event.mode, event.active_mode):
                _LOGGER.debug(
                    "%s: guard mode %r (in force %r) already delivered",
                    redact_serial(event.station_sn),
                    event.mode,
                    event.active_mode,
                )
                return
            self._emit_guard_mode(event)
            return
        if isinstance(event, AlarmChanged) and not self._alarms.report(event):
            return  # already known from the cloud
        self._bus.emit(event)

    def _on_push(self, event: SecurityEvent) -> None:
        if event.station_sn in self._not_served:
            # Left out, or served by another account (which gets its own push).
            _LOGGER.debug("dropping a push for a station this account does not serve")
            return
        self._deliver(event)

    def _deliver(self, event: SecurityEvent) -> None:
        """Emit a security event from either channel, then the guard-mode change it carries.

        An arming push's ``arming`` (``guard_mode``) is the selected mode and its ``mode``
        the effective one (see :class:`~.events.GuardModeChanged`).
        """
        tracker = self._guard_tracker()
        if event.guard_mode is not None:
            fresh = tracker.admit_push(event)
            self._store_guard_stamps()
            if not fresh:
                return
        admitted = self._admit(event)
        if admitted is None:
            return
        self._bus.emit(admitted)
        if (alarm := self._alarms.push(admitted)) is not None:
            self._emit_alarm(alarm)
        if admitted.guard_mode is None or not admitted.station_sn:
            return
        mode = as_guard_mode(admitted.guard_mode)
        active = tracker.active_mode(admitted.station_sn, mode, admitted.mode)
        station = self.stations.get(admitted.station_sn)
        if station is not None:
            station.session.note_guard_mode(mode, active)
        if tracker.changed(admitted.station_sn, mode, active):
            self._emit_guard_mode(
                GuardModeChanged(
                    station_sn=admitted.station_sn,
                    mode=mode,
                    active_mode=active,
                    source=admitted.source,
                )
            )

    def _emit_guard_mode(self, event: GuardModeChanged) -> None:
        """Emit a guard-mode change, then the end of an alarm that a disarm stops."""
        self._bus.emit(event)
        in_force = event.mode if event.active_mode is None else event.active_mode
        if isinstance(in_force, GuardMode) and in_force.is_disarmed:
            alarm = self._alarms.disarmed(event.station_sn, event.source)
            if alarm is not None:
                self._emit_alarm(alarm)

    def _emit_alarm(self, alarm: AlarmChanged) -> None:
        """Emit an alarm transition of the tracker, its station's state set first."""
        if (station := self.stations.get(alarm.station_sn)) is not None:
            station.note_alarm(alarm)
        self._bus.emit(alarm)

    # ── push pictures ────────────────────────────────────────────────────────

    async def async_push_image(
        self, event: SecurityEvent, source: PushPictureSource | None = None
    ) -> PushImage:
        """A picture the detection push ``event`` names, fetched as the eufy app does.

        * ``FACE``: the cloud's crop of the face the station matched
          (:attr:`SecurityEvent.face_id`): ``get_faces_by_ids``
          (:meth:`~.cloud.api.EufyCloudApi.async_get_faces`), then its ``face_url``.
        * ``PIC_URL``: the push's ``pic_url``, an https URL fetched from the cloud, or a
          still on the station's disk fetched over the station's session (a locally
          served station only).

        ``source`` None tries :attr:`SecurityEvent.picture_sources` in order (the app's:
        the face first) and returns the first that succeeds, raising the last failure.
        A picture the cloud serves in the eufy-obfuscated V1 or V2 format is decoded
        with its device's (else its station's) DID from the cached device list.
        Never wakes a camera and never logs in. Raises
        :class:`~.exceptions.UnsupportedError` when the push names no such picture (or a
        station path of a station not served here, or bytes that are no displayable
        picture and do not decode), its subclass
        :class:`~.exceptions.VideoEncryptedPictureError` for a picture protected by
        the account's Video Encryption, :class:`~.exceptions.EmptyResponseError` when
        the cloud keeps no picture of the face, and the typed errors of the cloud or
        station call.
        """
        sources = event.picture_sources
        if source is not None:
            if source not in sources:
                raise UnsupportedError(f"the push names no {source} picture")
            sources = (source,)
        if not sources:
            raise UnsupportedError("the push names no picture (no face id, no pic_url)")
        await self._ensure_cache_loaded()
        failure: EufySecurityError | None = None
        for candidate in sources:
            try:
                return await self._push_image(event, candidate)
            except EufySecurityError as err:
                _LOGGER.debug("push picture from %s failed: %s", candidate, err)
                failure = err
        raise cast(EufySecurityError, failure)

    async def _push_image(self, event: SecurityEvent, source: PushPictureSource) -> PushImage:
        serial = event.device_sn or event.station_sn
        region = self.cloud.device_region(serial) if serial else None
        face_id = event.face_id
        if source is PushPictureSource.FACE and face_id is not None and serial is not None:
            faces = await self.cloud.async_get_faces([face_id], serial, region=region, login=False)
            url = next((f.face_url for f in faces if f.face_id == face_id and f.face_url), None)
            if url is None:
                raise EmptyResponseError(
                    0, "the cloud keeps no picture of the push's face", endpoint=FACES_BY_IDS_PATH
                )
            data = await self.cloud.async_fetch_picture(url, region=region)
            data = self._decode_push_picture(data, source)
        elif source is PushPictureSource.PIC_URL and event.pic_url is not None:
            face_id = None
            if pic_url_kind(event.pic_url) == "https":
                data = await self.cloud.async_fetch_picture(event.pic_url, region=region)
                data = self._decode_push_picture(data, source)
            else:
                station = self.stations.get(event.station_sn or "")
                if station is None:
                    raise UnsupportedError(
                        "the push's picture is on a station not served locally here"
                    )
                data = (await station.async_fetch_still(event.pic_url)).data
        else:
            raise UnsupportedError(f"the push names no {source} picture")
        content_type = picture_content_type(data)
        if content_type is None:
            _log_undisplayable(source, data)
            raise UnsupportedError(f"the push's {source} picture is not a displayable image")
        return PushImage(
            source=source,
            device_sn=event.device_sn,
            data=data,
            content_type=content_type,
            face_id=face_id,
        )

    def _decode_push_picture(self, data: bytes, source: PushPictureSource) -> bytes:
        """``data`` with a V1 or V2 still decoded (:func:`~.p2p.media.decode_still`).

        The key's DID comes from the cached device list (:meth:`_picture_dids`); no
        cloud call. A V8 still raises :class:`VideoEncryptedPictureError`, a V1 or V2
        still that does not decode :class:`UnsupportedError`.
        """
        try:
            return decode_still(data, self._picture_dids)
        except VideoEncryptedPictureError:
            _log_undisplayable(source, data)
            raise
        except ProtocolError as err:
            _log_undisplayable(source, data)
            raise UnsupportedError(
                f"the push's {source} picture ({classify_still(data)}) did not decode: {err}"
            ) from err

    def _picture_dids(self, serial: str) -> list[str]:
        """The P2P DIDs that may key a picture of ``serial``, from the cached device list:
        the device's own, then its station's."""
        device = self.listed_devices.get(serial)
        if device is None:
            return []
        station = self.listed_devices.get(device.station_sn or "")
        return [entry.p2p_did for entry in (device, station) if entry and entry.p2p_did]

    # ── arming groups ────────────────────────────────────────────────────────

    async def async_arming_groups(self, house_id: str | None = None) -> arming.ArmingGroupList:
        """The arming groups (the eufy app's Group Control) of a house, in the cloud's order.

        ``house_id`` None is the house that holds this account's stations, ``ValueError``
        when they are in several. :class:`UnsupportedError` for the app's shared-devices
        view, a house no login scope lists, or a house the app arms with professional
        arming instead. Not cached: the house list, the house's device list and the
        groups are read each time; every arming-group call resolves the house this way.
        """
        house = await self._arming_house(house_id)
        return await self._arming_groups_of(house)

    async def async_create_arming_group(
        self,
        name: str,
        members: Mapping[str, GuardMode | int | str],
        house_id: str | None = None,
    ) -> arming.ArmingGroup:
        """Create a group of ``members`` (serial → the guard mode it takes on activation)
        in a house (``house_id`` as for :meth:`async_arming_groups`); returns it as listed.

        Refused before any write: a name the app refuses (:func:`~.cloud.arming.check_group_name`)
        or that another group of the house has, no member or a mode that cannot be a
        target (``ValueError``, both before any request); a member that is not a station
        or standalone device of the house, or a house already holding
        :data:`~.cloud.arming.MAX_GROUPS_PER_HOUSE` groups, or a custom mode a member's
        station does not have while its mode list is known (:class:`UnsupportedError`;
        :meth:`Station.target_mode_name`). A member's ``mode`` title is its station's
        name for the mode (a custom mode's own title) where known.
        :class:`ProtocolError` when the cloud accepts the group but does not list it.
        """
        trimmed = arming.check_group_name(name)
        targets = arming.target_modes(members)
        house = await self._arming_house(house_id)
        listing = await self._arming_groups_of(house)
        arming.check_unique_name(listing, trimmed)
        if len(listing.groups) >= arming.MAX_GROUPS_PER_HOUSE:
            raise UnsupportedError(
                f"the house already has {len(listing.groups)} arming groups "
                f"(at most {arming.MAX_GROUPS_PER_HOUSE})"
            )
        chosen = arming.build_members(house, targets, titles=self._member_titles(targets))
        await self.cloud.async_add_arming_group(
            house.house_id, trimmed, chosen, region=house.region
        )
        known = {group.group_id for group in listing.groups}
        after = await self._arming_groups_of(house)
        created = [g for g in after.groups if g.group_id not in known and g.name == trimmed]
        if len(created) != 1:
            raise ProtocolError("the cloud accepted the arming group but lists no new group")
        return created[0]

    async def async_update_arming_group(
        self,
        group_id: str,
        *,
        name: str | None = None,
        members: Mapping[str, GuardMode | int | str] | None = None,
        house_id: str | None = None,
    ) -> arming.ArmingGroup:
        """Rename group ``group_id`` and/or replace its whole member list; returns the
        group as listed afterwards.

        The cloud refuses an update without both the name and the members, so the one
        not given is sent as the group list reads it (a rename carries the current
        members with their stored mode names). The same refusals as
        :meth:`async_create_arming_group`, plus ``ValueError`` when neither ``name`` nor
        ``members`` is given and :class:`UnsupportedError` for a group the house does
        not have. A member keeping its mode keeps the mode name stored with it unless
        its station names the mode.
        """
        if name is None and members is None:
            raise ValueError("pass a name or members to update an arming group")
        trimmed = None if name is None else arming.check_group_name(name)
        targets = None if members is None else arming.target_modes(members)
        house = await self._arming_house(house_id)
        listing = await self._arming_groups_of(house)
        group = arming.find_group(listing, group_id)
        if trimmed is not None:
            arming.check_unique_name(listing, trimmed, group_id=group_id)
        chosen = (
            group.members
            if targets is None
            else arming.build_members(house, targets, group, titles=self._member_titles(targets))
        )
        await self.cloud.async_update_arming_group(
            house.house_id,
            group_id,
            region=house.region,
            name=group.name if trimmed is None else trimmed,
            members=chosen,
        )
        return arming.find_group(await self._arming_groups_of(house), group_id)

    async def async_delete_arming_group(
        self, group_id: str, *, house_id: str | None = None
    ) -> None:
        """Delete group ``group_id``; :class:`UnsupportedError` for a group the house does
        not have (checked before the delete is sent)."""
        house = await self._arming_house(house_id)
        arming.find_group(await self._arming_groups_of(house), group_id)
        await self.cloud.async_delete_arming_group(house.house_id, group_id, region=house.region)

    async def async_arming_group_logs(
        self, group_id: str, *, house_id: str | None = None
    ) -> tuple[arming.ArmingGroupLog, ...]:
        """The activation records of group ``group_id``, in the cloud's order."""
        house = await self._arming_house(house_id)
        return await self.cloud.async_arming_group_logs(
            house.house_id, group_id, region=house.region
        )

    async def async_activate_arming_group(
        self, group_id: str, *, house_id: str | None = None
    ) -> arming.ArmingActivation:
        """Activate group ``group_id`` as the eufy app does. **This changes the alarm
        state** of every member at once (arms or disarms stations, with their sirens,
        delays and notifications): call it only on a user's explicit request.

        The activation is recorded in the cloud first; if that fails, its error is raised
        and no station is touched. Then each member gets its target mode, concurrently,
        through :meth:`Station.async_set_guard_mode` (no retry):
        :attr:`~.cloud.arming.ArmingOutcome.SKIPPED_OFFLINE` when its session is down
        (a station reached on demand is woken), ``ALREADY`` when it reports the target mode,
        else ``CHANGED`` with the mode it applied, or ``FAILED`` with the error, also
        for a member this client has no local station for (remote, served by another
        account, left out) or whose target mode the library cannot write. Partial
        application is normal: :attr:`~.cloud.arming.ArmingActivation.complete` says
        whether every member is in its target mode.
        """
        house = await self._arming_house(house_id)
        group = arming.find_group(await self._arming_groups_of(house), group_id)
        await self.cloud.async_activate_arming_group(house.house_id, group_id, region=house.region)
        results = await asyncio.gather(*(self._arm_member(member) for member in group.members))
        _LOGGER.info(
            "arming group %r activated: %s",
            group.group_id,
            ", ".join(f"{redact_serial(r.device_sn)} {r.outcome}" for r in results) or "no members",
        )
        return arming.ArmingActivation(group=group, results=tuple(results))

    async def _arm_member(self, member: arming.ArmingGroupMember) -> arming.ArmingMemberResult:
        """One member's guard-mode write of an activation; never raises a library error."""

        def result(
            outcome: arming.ArmingOutcome,
            *,
            applied: GuardMode | int | None = None,
            error: EufySecurityError | None = None,
        ) -> arming.ArmingMemberResult:
            return arming.ArmingMemberResult(
                device_sn=member.device_sn,
                mode=member.mode,
                outcome=outcome,
                applied=applied,
                error=error,
            )

        mode = member.mode
        if not isinstance(mode, GuardMode) or mode not in arming.MODE_TITLES:
            error = UnsupportedError(f"guard mode {int(mode)} cannot be written")
            return result(arming.ArmingOutcome.FAILED, error=error)
        station = self.stations.get(member.device_sn)
        if station is None:
            error = UnsupportedError(
                f"{redact_serial(member.device_sn)} has no local station in this client",
                device_sn=member.device_sn,
            )
            return result(arming.ArmingOutcome.FAILED, error=error)
        if not station.connected and not station.connects_on_demand:
            return result(arming.ArmingOutcome.SKIPPED_OFFLINE)
        state = station.state
        if state is not None and state.guard_mode == mode:
            return result(arming.ArmingOutcome.ALREADY)
        try:
            applied = await station.async_set_guard_mode(mode)
        except EufySecurityError as err:
            return result(arming.ArmingOutcome.FAILED, error=err)
        return result(arming.ArmingOutcome.CHANGED, applied=applied)

    def _member_titles(self, targets: Mapping[str, GuardMode]) -> dict[str, str]:
        """Each target's mode name on its local station where that station's modes are
        known (:meth:`Station.target_mode_name`, which refuses a custom mode the station
        does not have)."""
        titles: dict[str, str] = {}
        for serial, mode in targets.items():
            station = self.stations.get(serial)
            if station is not None and (name := station.target_mode_name(mode)) is not None:
                titles[serial] = name
        return titles

    async def _arming_groups_of(self, house: arming.ArmingHouse) -> arming.ArmingGroupList:
        return await self.cloud.async_list_arming_groups(house.house_id, region=house.region)

    async def _arming_house(self, house_id: str | None) -> arming.ArmingHouse:
        """The house an arming-group call works on.

        ``house_id`` None picks the one house (of every login scope holding this
        account's stations) whose device list names one of them; stations in several
        houses is ``ValueError``. Refused with :class:`UnsupportedError`: the app's
        shared-devices view or an empty id, a house no scope lists (or none holding the
        stations), and a house with a model armed by the app's professional-arming flow
        (:data:`~.cloud.arming.PROFESSIONAL_ARMING_MODELS`).
        """
        await self._ensure_cache_loaded()
        if house_id is not None and house_id in ("", arming.SHARED_DEVICES_HOUSE_ID):
            raise UnsupportedError("arming groups belong to a house, not to shared devices")
        devices = await self.cloud.async_get_devices()
        own = {d.device_sn for d in devices if d.is_station}
        regions = sorted({d.region for d in devices if d.is_station and d.region})
        found: list[tuple[str, str, list[CloudDevice]]] = []
        for region in regions:
            for house in await self.cloud.async_list_houses(region):
                if house_id is not None and house.house_id != house_id:
                    continue
                listed = await self.cloud.async_list_house_devices(region, house.house_id)
                if house_id is None and not any(d.device_sn in own for d in listed):
                    continue
                found.append((house.house_id, region, listed))
        if not found:
            what = (
                "the house" if house_id is not None else "a house holding this account's stations"
            )
            raise UnsupportedError(f"no login scope lists {what}")
        if house_id is None and len(found) > 1:
            raise ValueError(f"this account's stations are in {len(found)} houses; pass house_id")
        chosen_id, region, listed = found[0]
        if arming.uses_professional_arming(d.device_sn for d in listed):
            raise UnsupportedError(
                "the house is armed with the eufy app's professional arming, not groups"
            )
        return arming.ArmingHouse(
            house_id=chosen_id,
            region=region,
            stations=frozenset(d.device_sn for d in listed if d.is_station),
        )


class _CachedKeyRefreshLatch:
    """The stale-key latch of one station, persisted in the session cache."""

    def __init__(self, cache: SessionCache, serial: str) -> None:
        self._cache = cache
        self._serial = serial

    def retry_blocked_for(self) -> float:
        return self._cache.key_refresh_slow_retry_left(self._serial)

    async def async_refreshed(self) -> None:
        self._cache.note_key_refresh(self._serial)
        await self._cache.async_save()

    async def async_accepted(self) -> None:
        if self._cache.clear_key_refresh(self._serial):
            _LOGGER.debug(
                "%s: key accepted; key-refresh latch cleared", redact_serial(self._serial)
            )
            await self._cache.async_save()


def _last_login(cache: SessionCache) -> float | None:
    """The stamp of the latest recorded login attempt, if any."""
    logins = cache.recent_logins(math.inf)
    return logins[-1] if logins else None


def _group(
    devices: list[CloudDevice],
) -> tuple[list[CloudDevice], dict[str, list[CloudDevice]], tuple[SkippedDevice, ...]]:
    """The stations in a device list, the devices paired to each, and the skipped rest.

    A device whose serial cannot name it in an id (see
    :func:`~.identity.is_device_serial`) or a station whose P2P id does not parse
    (:meth:`~.p2p.did.Did.parse`) is left out, with a warning: a consumer would
    otherwise fail on it while setting up every other device. A station the eufy app
    reaches only over WebRTC is left out with a warning, and the devices paired to it
    quietly, under the same reason. Any other station left out takes its devices with it
    (they are orphans). A device that is its own parent but has no P2P id is no station
    and is left out quietly.
    """
    skipped: list[SkippedDevice] = []

    def skip(device: CloudDevice, reason: SkipReason) -> None:
        label = redact_serial(device.device_sn) if device.device_sn else "empty"
        skipped.append(SkippedDevice(label, reason))
        if not _SKIP_THROTTLE.should_log((reason, device.device_sn)):
            return
        if reason == "webrtc_only" and not device.is_station:
            level, why = logging.INFO, "its station is reached only over the eufy app's WebRTC"
        else:
            level, why = {
                "bad_serial": (logging.WARNING, "its serial is not letters and digits"),
                "bad_did": (logging.WARNING, "its P2P id is not one local P2P accepts"),
                "webrtc_only": (
                    logging.WARNING,
                    "the eufy app reaches this station only over WebRTC, which the library "
                    "does not support",
                ),
                "no_did": (logging.INFO, "not a station (no P2P id) and paired to none"),
                "orphan": (logging.WARNING, "its station is not on the account's device list"),
            }[reason]
        _LOGGER.log(level, "skipping device %s: %s", label, why)

    webrtc_only = {
        d.device_sn for d in devices if d.is_station and app_webrtc_only(route_device(d))
    }
    usable = []
    for device in devices:
        if not is_device_serial(device.device_sn):
            skip(device, "bad_serial")
        elif device.is_station and not _did_parses(device.p2p_did):
            skip(device, "bad_did")
        elif device.is_station and device.device_sn in webrtc_only:
            skip(device, "webrtc_only")
        else:
            usable.append(device)
    stations = [d for d in usable if d.is_station]
    serials = {d.device_sn for d in stations}
    children: dict[str, list[CloudDevice]] = {}
    for device in usable:
        if device.is_station:
            continue
        if not device.station_sn or device.station_sn == device.device_sn:
            skip(device, "no_did")
        elif device.station_sn in webrtc_only:
            skip(device, "webrtc_only")
        elif device.station_sn in serials:
            children.setdefault(device.station_sn, []).append(device)
        else:
            skip(device, "orphan")
    return stations, children, tuple(skipped)


def _did_parses(did: str | None) -> bool:
    """Whether ``did`` is a P2P id a session can be built on."""
    try:
        Did.parse(did or "")
    except ProtocolError:
        return False
    return True


async def _best_effort(what: str, stop: Callable[[], Awaitable[None]]) -> None:
    """Await ``stop``; log (with traceback) rather than raise if it fails."""
    try:
        await stop()
    except Exception:
        _LOGGER.warning("could not %s", what, exc_info=True)


def _log_undisplayable(source: PushPictureSource, data: bytes) -> None:
    """Log a push picture's format and size (never its header past the magic: it holds
    the device serial); an unknown format's first 4 bytes in hex."""
    fmt = classify_still(data)
    if fmt is StillFormat.UNKNOWN:
        _LOGGER.debug(
            "push %s picture not shown: format %s, %d bytes, first bytes %s",
            source,
            fmt,
            len(data),
            data[:4].hex(),
        )
    else:
        _LOGGER.debug("push %s picture not shown: format %s, %d bytes", source, fmt, len(data))
