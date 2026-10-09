"""The eufy_mega cloud client: login, device list, cipher keys, owner id, push token.

One ``_call`` owns the envelope for both realms — header set, signing, body
encryption and the HTTP-200-with-a-body-``code`` check that this cloud reports
almost every failure as. Logging in is slow, rate-limited and locks the account
for 24 h after repeated failures, so the session, the per-station owner id and the
cipher keys are all cached; a login happens only on a miss, an expiry, or one
automatic retry when the server says the token has expired (or wants a re-key).
A credential rejection is never retried: every failed login counts toward the lock.
A throttling answer starts a persisted hold-off; until it ends every call (or, for a
login throttle, every login) is refused locally, and logins are capped per window.
Concurrent callers share one login (a lock with a re-check inside it), and every
change to the session is saved to the store at once.

The cloud runs one cluster per region (``eu``, ``us``). A login on either succeeds
for every account, but a cluster lists only the devices homed on it, so each region
holds its own session, every device remembers the region that listed it, and every
call about a device goes to that region.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, NoReturn

from .._logging import (
    Credential,
    Identifier,
    Payload,
    Secret,
    redact,
    redact_serial,
    wire_logger,
)
from ..exceptions import (
    AuthenticationError,
    CipherUnavailableError,
    CloudApiError,
    CommunicationError,
    EmptyResponseError,
    EufySecurityError,
    KeyExchangeRefusedError,
    LoginChallengeError,
    LoginLimitedError,
    NoCachedSessionError,
    ProtocolError,
    RateLimitedError,
    RefreshCooldownError,
    SessionRejectedError,
    SessionReplacedError,
)
from ..storage import SessionCache
from . import const, crypto
from .const import DSK_REFRESH_MARGIN
from .models import (
    REGION_KEY,
    CipherRecord,
    CloudDevice,
    CloudHouse,
    CloudInvite,
    FirmwareUpdate,
    LoginCountry,
    security_device_entry,
)
from .status import CloudStatus, LoginNeed, RegionStatus, StationRefreshStatus

if TYPE_CHECKING:
    import aiohttp

    from ..install import InstallState

# A ready aiohttp session, or a factory that makes one on first use. A factory lets
# a caller (the CLI) defer importing aiohttp until a cloud call actually happens;
# Home Assistant passes its shared session directly. The ``type`` alias is lazy, so
# defining it does not evaluate the ``aiohttp`` reference.
type HttpSession = aiohttp.ClientSession | Callable[[], aiohttp.ClientSession]

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("cloud")

_SUCCESS: Final = int(const.CloudCode.SUCCESS)
_HTTP_429_THROTTLE: Final = const.Throttle(login_only=False, seconds=const.REQUEST_HOLD_OFF_SECONDS)
"""The hold-off an HTTP 429 answer starts (a request throttle)."""

# The account-wide house device-list body (the house-scoped one names a ``house_id``).
_ACCOUNT_DEVICES_BODY: Final[Mapping[str, Any]] = MappingProxyType({"device_sn": ""})

type PasswordSource = str | Callable[[], Awaitable[str]]
"""The account password, or a coroutine function that produces it.

A callable is awaited only when a login is actually performed and no password is
cached — a cached session never needs it — so an interactive caller can prompt just
in time.
"""


@dataclass(slots=True)
class _Identity:
    """A MegaCrypto transport identity: the pair the gateway keeps its half of."""

    key_ident: str
    shared_key: str = field(repr=False)
    auth_token: str | None = field(default=None, repr=False)
    user_id: str | None = None
    region: str = const.DEFAULT_REGION
    """The region whose cluster minted this identity and accepts it."""

    def same_session(self, other: _Identity | None) -> bool:
        """Whether ``other`` is this login (a reload from the cache counts as the same)."""
        return (
            other is not None
            and other.region == self.region
            and other.key_ident == self.key_ident
            and other.auth_token == self.auth_token
        )


class _RekeyRequiredError(CloudApiError):
    """The gateway wants a new key exchange before it will serve this identity."""

    def __init__(
        self, code: int, message: str = "", *, endpoint: str = "", status: int = 200
    ) -> None:
        self.status = status
        super().__init__(code, message, endpoint=endpoint)


class _ScopeRefusedError(CloudApiError):
    """The cloud refused an extra country's login: the scope is skipped until a rescan."""


class _SessionExpiredError(SessionRejectedError):
    """The server no longer accepts the auth token (one re-login is allowed)."""


def _two_step(data: object) -> int:
    """``fa_info.step`` of a login answer: 26052 while two-step verification is pending."""
    info = data.get("fa_info") if isinstance(data, Mapping) else None
    step = info.get("step") if isinstance(info, Mapping) else None
    return step if isinstance(step, int) and not isinstance(step, bool) else 0


def _mapping(data: object, path: str) -> Mapping[str, Any]:
    """``data`` as a mapping, or :class:`ProtocolError` naming the endpoint."""
    if not isinstance(data, Mapping):
        raise ProtocolError(
            f"cloud response to {path} carried {type(data).__name__}, not an object"
        )
    return data


def _entries(data: object, path: str, key: str) -> list[Mapping[str, Any]]:
    """The mapping entries of ``data[key]``; none for a bare success or a null list,
    :class:`ProtocolError` when ``key`` holds something else."""
    if data is None:
        return []
    listed = _mapping(data, path).get(key)
    if listed is None:
        return []
    if not isinstance(listed, list):
        raise ProtocolError(f"cloud response to {path} has no {key} list")
    return [entry for entry in listed if isinstance(entry, Mapping)]


@dataclass(frozen=True, slots=True)
class CipherKeys:
    """One station cipher's private keys as ``get_ciphers`` returns them, None when absent:
    ``ecc_private_key`` (hex) unwraps an ECIES CONN_INIT, ``rsa_private_key`` (the
    cloud's ``private_key``, base64 PKCS#8) an RSA one."""

    ecc_private_key: str | None
    rsa_private_key: str | None


def _key_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


_COUNTRY_KEY: Final = "country"
"""``cloud.country``: the looked-up login country (``code``, ``source``, ``home_region``)."""
_AB_KEY: Final = "ab"
"""A cached session's ``ab``: what its login sent."""
_AB_WANTED_KEY: Final = "ab_wanted"
"""A cached session's settled ``ab``: what was asked for (differs after a refused country login)."""
_EXTRA_HOMES_KEY: Final = "extra_countries"
"""``cloud.extra_countries``: each looked-up extra country's home region."""
_INSTALL_IDS_KEY: Final = "install_ids"
"""``cloud.install_ids``: the ``openudid`` of each extra country's login scope."""

_REFUSED_KEY: Final = "refused"
"""``cloud.refused``: per extra scope whose login the cloud refused, the body ``code``,
when (``at``) and the extra countries given then (``countries``)."""

_CHALLENGES_KEY: Final = "challenges"
"""``cloud.challenges``: the ``login_id`` of each scope's unanswered login challenge."""

_LOOKUP_TRANSIENT: Final = (CommunicationError, RateLimitedError)
"""Failures of a country lookup that leave the answer open: asked again later."""


def _country_code(value: object) -> str | None:
    """``value`` as an upper-case ISO 3166 alpha-2 code; None for anything else."""
    if not isinstance(value, str):
        return None
    code = value.strip().upper()
    return code if len(code) == 2 and code.isascii() and code.isalpha() else None


def _country_codes(option: str | Sequence[str]) -> tuple[str, ...]:
    """The ``country`` option as codes, first kept, repeats dropped; ``ValueError`` for
    anything that is not an ISO 3166 alpha-2 code."""
    values = [option] if isinstance(option, str) else list(option)
    codes: list[str] = []
    for value in values:
        if not value.strip():
            continue
        code = _country_code(value)
        if code is None:
            raise ValueError(f"country {value!r} is not a two-letter ISO 3166 code")
        if code not in codes:
            codes.append(code)
    return tuple(codes)


def _ab_code(data: object) -> str | None:
    """The ``ab_code`` of a passport answer, None when it carries none."""
    code = data.get("ab_code") if isinstance(data, Mapping) else None
    return code if isinstance(code, str) and code else None


def _cached_country(cache: SessionCache) -> LoginCountry | None:
    """The login country cached by an earlier lookup, None when none is (or it is malformed)."""
    entry = cache.section("cloud").get(_COUNTRY_KEY) if cache.loaded else None
    if not isinstance(entry, dict):
        return None
    code, source, home = (
        _country_code(entry.get("code")),
        entry.get("source"),
        entry.get("home_region"),
    )
    if code is None or source not in {const.COUNTRY_SOURCE_OPTION, const.COUNTRY_SOURCE_IP}:
        return None
    return LoginCountry(
        code=code, source=str(source), home_region=home if home in const.REGIONS else None
    )


def _cached_extra_homes(cache: SessionCache) -> dict[str, str]:
    """The home region an earlier lookup found for each extra country."""
    entry = cache.section("cloud").get(_EXTRA_HOMES_KEY) if cache.loaded else None
    if not isinstance(entry, dict):
        return {}
    return {
        code: home
        for code, home in entry.items()
        if _country_code(code) == code and home in const.REGIONS
    }


class EufyCloudApi:
    """Async client for the eufy_mega ("eufy_security") cloud.

    The injected ``session`` and ``cache`` are never created here. Call
    :meth:`async_login` before anything else (it reuses cached sessions).

    Logins follow the app: one login per country, on that country's home cluster.
    A login lists only the devices its cluster holds for its ``ab`` country, so the
    countries decide what the account sees. The login country (:attr:`login_country`)
    is the first of ``country``, else the host's IP country; its home region
    (``estimate_domain``) is the login scope named by the region alone. Each further
    code of ``country`` is an extra country with its own session on its home region,
    the login scope ``<region>:<country>`` (:func:`~.const.scope`). A login sends its
    country as ``ab`` and every request carries it as the ``country`` header;
    ``timezone`` is the ``timezone`` header. While no country is known, every region
    is a scope, logged in with the region as ``ab`` and the header
    :data:`~.const.DEFAULT_COUNTRY`.

    ``region`` pins the login country's scope to that region and leaves out the extra
    countries homed elsewhere. A scope whose device list is empty is *suspended*: no
    later fetch or login asks it again until a rescan (``rescan_regions=True``), or,
    with ``scan_regions``, every fetch asks every scope. Scopes stand where regions do
    everywhere (listings, suspension, sessions, :attr:`CloudDevice.region`); the login
    budget and login hold-offs count per cluster.
    """

    def __init__(
        self,
        session: HttpSession,
        cache: SessionCache,
        email: str,
        password: PasswordSource | None,
        *,
        country: str | Sequence[str] = "",
        timezone: str = "",
        region: str | None = None,
        scan_regions: bool = False,
        install: InstallState | None = None,
    ) -> None:
        """``install`` shares a request hold-off with the other accounts of the process.

        ``country`` is an ISO 3166 alpha-2 code (any case), or a sequence of them: the
        first is the login country, each further one an extra country with its own
        session on its home region (see the class docstring); anything else raises
        ``ValueError``. ``timezone`` an IANA zone name. ``region`` not in
        :data:`~.const.REGIONS`: ``ValueError``.
        """
        self._session = session
        self._cache = cache
        self._install = install
        self._email = email.strip()
        self._password = password
        codes = _country_codes(country)
        self._country_option = codes[0] if codes else None
        self._extra_countries: tuple[str, ...] = codes[1:]
        self._extras_answered: set[str] = set()
        """The extra countries whose lookup eufy answered without a cluster in this process."""
        self._timezone = timezone or const.DEFAULT_TIMEZONE
        self._login_country: LoginCountry | None = None
        self._country_resolved = False
        """Whether a lookup of the login country answered in this process."""
        self._country_error: EufySecurityError | None = None
        """The last login country lookup's failure while it did not answer."""
        self._region_override = None if region is None else const.check_region(region)
        self._scan_regions = scan_regions
        self._identities: dict[str, _Identity] = {}
        """The live session identity per region."""
        self._challenge_region: str | None = None
        """The scope whose login raised this instance's last unanswered challenge."""
        self._login_lock = asyncio.Lock()
        self._cipher_unavailable: dict[tuple[str, int], tuple[float, str]] = {}
        """(monotonic time, owner id source) of the last empty ``get_ciphers`` answer per
        (station, cipher id), for the back-off."""

    # ── public properties ────────────────────────────────────────────────────

    @property
    def user_id(self) -> str | None:
        """This account's own cloud user id, once logged in."""
        return next((i.user_id for i in self._identities.values() if i.user_id), None)

    @property
    def user_name(self) -> str:
        """What the app sends as ``user_name``: the e-mail's local part."""
        return self._email.split("@", 1)[0] if "@" in self._email else self._email

    def _http(self) -> aiohttp.ClientSession:
        """The aiohttp session, resolving and memoising a factory on first use."""
        session = self._session
        if callable(session):
            session = self._session = session()
        return session

    # ── regions ──────────────────────────────────────────────────────────────

    @property
    def region(self) -> str:
        """The account's first region: the override, else the first region holding
        cached devices, else the login country's home region, else
        :data:`~.const.DEFAULT_REGION`. A forced login and a reauthentication go there."""
        if self._region_override:
            return self._region_override
        held = [r for r in self.regions_with_devices() if const.scope_country(r) is None]
        if held:
            return held[0]
        home = self._home_region()
        return home or const.DEFAULT_REGION

    def _home_region(self) -> str | None:
        """The home region of :attr:`login_country`."""
        country = self.login_country
        return country.home_region if country is not None else None

    def _login_order(self, regions: Sequence[str]) -> list[str]:
        """``regions`` with :attr:`region` first, as the app logs in to the home cluster."""
        first = self.region
        return sorted(regions, key=lambda r: r != first)

    def _listings(self) -> dict[str, dict[str, Any]]:
        """Each listed scope's last device-list record (``devices``, ``at``)."""
        listed = self._cache.section("cloud").get("listed")
        if not isinstance(listed, dict):
            return {}
        scopes = self.login_scopes()
        return {r: v for r, v in listed.items() if r in scopes and isinstance(v, dict)}

    def _extra_scopes(self) -> list[str]:
        """The login scope of each extra country whose home region is known, in the
        order given; with a ``region`` override only those on that region."""
        homes = _cached_extra_homes(self._cache)
        return [
            const.scope(homes[code], code)
            for code in self._extra_countries
            if code in homes and self._region_override in (None, homes[code])
        ]

    def login_scopes(self) -> list[str]:
        """Every login scope: the login country's home region (the override instead;
        every region while no country is known), then the extra countries'."""
        if self._region_override:
            regions = [self._region_override]
        else:
            home = self._home_region()
            regions = [home] if home else list(const.REGIONS)
        return regions + self._extra_scopes()

    def regions_with_devices(self) -> list[str]:
        """The scopes whose last device list held devices, regions first."""
        listings = self._listings()
        return [r for r in self.login_scopes() if _count(listings.get(r, {}).get("devices"))]

    def suspended_regions(self) -> list[str]:
        """The scopes whose last device list was empty: asked again only on a rescan."""
        listings = self._listings()
        return [
            r
            for r in self.login_scopes()
            if r in listings and not _count(listings[r].get("devices"))
        ]

    def regions_to_list(self, *, rescan: bool = False) -> list[str]:
        """The scopes the next device-list fetch asks: every scope on a ``rescan``; else
        every scope whose login was not refused (:meth:`refused_regions`) and, without
        ``scan_regions``, not suspended. A ``region`` override leaves out the other
        region and the extra countries homed there."""
        scopes = self.login_scopes()
        if rescan:
            return scopes
        skipped = set(self.refused_regions())
        if not self._scan_regions:
            skipped.update(self.suspended_regions())
        return [r for r in scopes if r not in skipped]

    def refused_regions(self) -> list[str]:
        """The extra countries' scopes whose login the cloud refused with a plain body
        code: no login and no device list asks them again until a rescan or a change of
        the extra countries."""
        refused = self._cache.section("cloud").get(_REFUSED_KEY)
        if not isinstance(refused, dict):
            return []
        countries = sorted(self._extra_countries)
        return [
            r
            for r in self._extra_scopes()
            if isinstance(record := refused.get(r), dict) and record.get("countries") == countries
        ]

    async def _refuse_scope(self, region: str, err: CloudApiError) -> NoReturn:
        """Record the refusal of extra scope ``region``'s login, warn, and raise it."""
        self._cache.section("cloud").setdefault(_REFUSED_KEY, {})[region] = {
            "code": err.code,
            "at": time.time(),
            "countries": sorted(self._extra_countries),
        }
        await self._cache.async_save()
        _LOGGER.warning(
            "the cloud refused the %s login (%s); %s is skipped until a rescan",
            region,
            err,
            region,
        )
        raise _ScopeRefusedError(err.code, err.message, endpoint=err.endpoint) from err

    def device_region(self, device_sn: str) -> str:
        """The scope serving ``device_sn``: the one that listed it, else :attr:`region`."""
        scopes = self.login_scopes()
        for entry in self._cache.cached_devices() or ():
            if entry.get("device_sn") == device_sn and entry.get(REGION_KEY) in scopes:
                return str(entry[REGION_KEY])
        return self.region

    def _regions_in_service(self) -> list[str]:
        """The scopes whose devices this account serves: :attr:`region` before any
        listing, none once every scope is suspended; with a ``region`` override always
        that region."""
        if self._region_override:
            served = self.regions_with_devices()
            return [self._region_override, *(s for s in served if s != self._region_override)]
        if not self._listings():
            return [self.region]
        refused = self.refused_regions()
        return [r for r in self.regions_with_devices() if r not in refused]

    def regions_with_session(self) -> list[str]:
        """The scopes a call can reach without a login: a session held or cached and
        not expiring within the margin, regions first."""
        regions = []
        for region in self.login_scopes():
            held = self._identities.get(region)
            cached = self._cached_session(region)
            if (held is not None and held.auth_token) or (
                cached is not None and self._session_usable(cached[3])
            ):
                regions.append(region)
        return regions

    def _host(self, service: str, region: str) -> str:
        """``service``'s host on the cluster of scope ``region``, from the session's
        ``mega_domain`` when that names the same cluster."""
        cluster = const.scope_region(region)
        domain = self._cache.cloud_sessions().get(region, {}).get("mega_domain")
        if not (isinstance(domain, str) and const.region_from_mega_domain(domain) == cluster):
            domain = None
        return const.cluster_host(service, cluster, domain)

    # ── login ──────────────────────────────────────────────────────────────

    async def async_login(
        self,
        *,
        verify_code: str | None = None,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        login_id: str | None = None,
        force: bool = False,
    ) -> None:
        """Establish a session in every region the next device list asks, reusing cached ones.

        ``force`` logs in to :attr:`region` even with a cached session; the other
        regions log in only without a usable cached session, home region first. A cached
        session made with another ``ab`` than the login country's logs in again once
        (:meth:`_remake_for_country`).

        Raises :class:`LoginChallengeError` when the account needs an e-mailed code
        or a captcha — re-call with the answer and the challenge's ``login_id``; the
        answer goes to the scope that asked (the challenge's ``region``, kept in the
        cache, so a new instance answers there too) and the other scopes follow, each
        of which may ask in turn —
        :class:`AuthenticationError` on bad credentials,
        :class:`RateLimitedError` when throttled or locked, and
        :class:`SessionReplacedError` after another client took the session over
        (only ``force`` logs in again then, and the latch is released only once that
        login succeeds).
        """
        answering = bool(verify_code or (captcha_id and captcha_answer))
        async with self._login_lock:
            self._take_over_or_raise_if_replaced(force)
            if self._login_possible() and (
                self._password_at_hand(prompt=False) or not self._all_sessions_cached()
            ):
                # The scopes follow the countries: look them up (no login) first.
                await self._resolve_login_country(retry=True)
                await self._resolve_extra_countries()
            first: str | None = None
            if answering or force:
                first = (self._challenge_scope(login_id) if answering else None) or self.region
                if answering:
                    _LOGGER.debug(
                        "answering the %s login challenge (login_id %s, verify_code %s, "
                        "captcha %s=%s)",
                        first,
                        login_id,
                        Credential(verify_code),
                        captcha_id,
                        Credential(captcha_answer),
                    )
                await self._do_login(
                    first,
                    verify_code=verify_code,
                    captcha_id=captcha_id,
                    captcha_answer=captcha_answer,
                    login_id=login_id,
                )
                await self._release_after_take_over(force)
            pending: list[str] = []
            for region in self.regions_to_list():
                if region == first:
                    continue
                if self._load_cached_session(region):
                    await self._remake_for_country(region)
                    continue
                pending.append(region)
            for region in self._login_order(pending):
                try:
                    await self._do_login(
                        region, verify_code=None, captcha_id=None, captcha_answer=None
                    )
                except _ScopeRefusedError:
                    continue  # skipped until a rescan; the other scopes carry on

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
        """One real login to :attr:`region` with ``password``, whatever the cache holds.

        The login country is looked up first when not known, so :attr:`region` is its
        home region. A challenge answer goes to the region that asked. Success replaces that
        region's session and the cached password, and releases every
        station's key-refresh latch. A rejection raises :class:`AuthenticationError`:
        the new password is not cached and the cached one is left as it was. Hold-offs
        and the login budget apply as in :meth:`async_login`, and so do login
        challenges (re-call with the answer and ``login_id``). With the
        session-replaced latch set, :class:`SessionReplacedError` is raised unless
        ``take_over`` (which clears it once the login succeeds, as
        ``async_login(force=True)`` does; a failed take-over leaves it set).
        """
        if not password:
            raise AuthenticationError("no password given to reauthenticate with")
        answering = bool(verify_code or (captcha_id and captcha_answer))
        async with self._login_lock:
            self._take_over_or_raise_if_replaced(take_over)
            if self._login_allowed():
                # The region follows the country: look it up (no login) first.
                await self._resolve_login_country(retry=True)
                await self._resolve_extra_countries()
            await self._do_login(
                (self._challenge_scope(login_id) if answering else None) or self.region,
                verify_code=verify_code,
                captcha_id=captcha_id,
                captcha_answer=captcha_answer,
                login_id=login_id,
                password=password,
            )
            if isinstance(self._password, str):
                self._password = password  # a given password must not outlive the change
            self._reset_key_refresh(None)
            self._release_replaced(take_over)
            await self._cache.async_save()

    def _take_over_or_raise_if_replaced(self, take_over: bool) -> None:
        """Refuse while the session-replaced latch is set, unless this is a take-over.

        The latch is released only by the take-over's successful login
        (:meth:`_release_replaced`): a take-over that fails (held off, refused, a
        challenge, no network) leaves it set, so the next plain login still refuses.
        """
        if not take_over:
            self._raise_if_replaced()

    def _release_replaced(self, take_over: bool) -> None:
        """After a successful take-over login: release the session-replaced latch."""
        if take_over and self._cache.clear_replaced():
            _LOGGER.debug("the session was taken back; the session-replaced latch is released")

    async def _release_after_take_over(self, take_over: bool) -> None:
        if take_over and self._cache.replaced_at is not None:
            self._release_replaced(take_over)
            await self._cache.async_save()

    async def async_reset_key_refresh(self, serial: str | None = None) -> None:
        """Release the key-refresh latch of ``serial``, or of every station when None."""
        self._reset_key_refresh(serial)
        await self._cache.async_save()

    def _reset_key_refresh(self, serial: str | None) -> None:
        for sn in self._cache.station_serials() if serial is None else [serial]:
            if self._cache.clear_key_refresh(sn):
                _LOGGER.debug("key-refresh latch released for %s", redact_serial(sn))

    def _cached_session(self, region: str) -> tuple[str, str, str, float | None] | None:
        """``region``'s cached ``(auth_token, key_ident, shared_key, expires_at)``, if complete."""
        cloud = self._cache.cloud_sessions().get(region, {})
        token, key_ident, shared_key = (
            cloud.get("auth_token"),
            cloud.get("key_ident"),
            cloud.get("shared_key"),
        )
        if not (
            isinstance(token, str)
            and token
            and isinstance(key_ident, str)
            and isinstance(shared_key, str)
        ):
            return None
        expires = cloud.get("expires_at")
        if not isinstance(expires, (int, float)) or isinstance(expires, bool):
            return token, key_ident, shared_key, None
        return token, key_ident, shared_key, float(expires)

    @staticmethod
    def _session_usable(expires: float | None) -> bool:
        """Whether a cached session is still used (not expired, or expiring within the margin)."""
        return expires is None or time.time() < expires - const.SESSION_EXPIRY_MARGIN

    def _load_cached_session(self, region: str) -> bool:
        """Make ``region``'s cached session live; whether it had a usable one."""
        cached = self._cached_session(region)
        if cached is None:
            _LOGGER.debug("no %s cloud session cached", region)
            return False
        token, key_ident, shared_key, expires = cached
        if not self._session_usable(expires):
            _LOGGER.debug("cached %s cloud session expired (or expires within the margin)", region)
            return False
        cloud = self._cache.cloud_session(region)
        user_id = cloud.get("user_id")
        identity = self._identities[region] = _Identity(
            key_ident=key_ident,
            shared_key=shared_key,
            auth_token=token,
            user_id=user_id if isinstance(user_id, str) else None,
            region=region,
        )
        _LOGGER.info(
            "%s cloud session restored from the cache (user %s, token expires %s)",
            region,
            redact(identity.user_id),
            _epoch(expires),
        )
        _LOGGER.debug(
            "cached %s identity: key_ident %s, shared_key %s, auth_token %s, mega_domain %s",
            region,
            Identifier(key_ident),
            Secret(shared_key),
            Secret(token),
            cloud.get("mega_domain"),
        )
        return True

    # ── login country ────────────────────────────────────────────────────────

    @property
    def login_country(self) -> LoginCountry | None:
        """The country logins use (see the class docstring), None while unknown: this
        process's lookup, else the cached one. No lookup happens here."""
        if self._country_resolved:
            return self._login_country
        cached = _cached_country(self._cache)
        if cached is not None and self._country_option not in (None, cached.code):
            return None  # cached for another option
        return cached

    def login_ab(self, region: str) -> str:
        """The ``ab`` a login to scope ``region`` sends: an extra scope's country, else the
        login country's code, else the region."""
        extra = const.scope_country(region)
        if extra is not None:
            return extra
        country = self.login_country
        return country.code if country is not None else region

    def _country_header(self, region: str | None = None) -> str:
        """The ``country`` header: an extra scope's country, else the login country, else
        the option, else the default."""
        extra = None if region is None else const.scope_country(region)
        if extra is not None:
            return extra
        country = self.login_country
        if country is not None:
            return country.code
        return self._country_option or const.DEFAULT_COUNTRY

    async def async_last_login_code(self, region: str, *, login: bool = True) -> str | None:
        """The ``ab`` of the account's last login on ``region``'s cluster, by any client
        (``get_last_login_code``); None when it names none. ``login``: see
        :meth:`_with_session`."""
        data = await self._authenticated_call(
            self._host("passport", region),
            const.LAST_LOGIN_CODE_PATH,
            {"email": self._email},
            region=region,
            expect_data=False,
            login=login,
        )
        return _ab_code(data)

    async def async_client_country(self, region: str, *, login: bool = True) -> str | None:
        """The country eufy places this host's IP address in (``get_client_real_code``),
        asked on ``region``'s session; None when it names none."""
        data = await self._authenticated_call(
            self._host("passport", region),
            const.CLIENT_COUNTRY_PATH,
            {},
            region=region,
            expect_data=False,
            login=login,
        )
        return _ab_code(data)

    def session_ab(self, region: str) -> str | None:
        """The ``ab`` ``region``'s cached session was made with; None without one.

        A session cached before logins recorded it was made with the region.
        """
        cloud = self._cache.cloud_sessions().get(region)
        if not cloud or self._cached_session(region) is None:
            return None
        ab = cloud.get(_AB_KEY)
        return ab if isinstance(ab, str) and ab else region

    def _session_ab_wanted(self, region: str) -> str | None:
        """The ``ab`` ``region``'s cached session settles: the one asked for when it was
        made or last re-made (a refused country login leaves its ``ab``), else its own."""
        wanted = self._cache.cloud_sessions().get(region, {}).get(_AB_WANTED_KEY)
        return wanted if isinstance(wanted, str) and wanted else self.session_ab(region)

    async def _resolve_login_country(self, *, retry: bool = False) -> None:
        """Look the login country up until a lookup answers; callers hold ``_login_lock``.

        The ``country`` option, else the cached country when it came from the IP, else
        ``get_client_real_code`` (before any login). Its home region comes from the
        cache when the code matches, else from ``estimate_domain``. A country the lookup
        names no ``mega-`` cluster for is not used, nor is it when ``estimate_domain``
        refuses the IP country; an option it refuses has no home region. A lookup that
        does not answer (the network, a throttle) is kept as :attr:`_country_error` and
        asked again only with ``retry``; no login is sent while it stands
        (:meth:`_raise_if_country_unknown`).
        """
        if self._country_resolved or (self._country_error is not None and not retry):
            return
        self._country_error = None
        try:
            await self._look_up_login_country()
        except _LOOKUP_TRANSIENT as err:
            self._country_error = err
            _LOGGER.info("login country lookup failed (%s); asked again before a login", err)
            return
        self._country_resolved = True

    def _raise_if_country_unknown(self, region: str) -> None:
        """Refuse a login to a region scope while the login country lookup did not answer."""
        if self._country_error is not None and const.scope_country(region) is None:
            raise self._country_error

    async def _look_up_login_country(self) -> None:
        """The lookups of :meth:`_resolve_login_country`; a transient failure raises."""
        cached = _cached_country(self._cache)
        option = self._country_option
        if option is not None:
            code, source = option, const.COUNTRY_SOURCE_OPTION
        elif cached is not None and cached.source == const.COUNTRY_SOURCE_IP:
            code, source = cached.code, cached.source
        else:
            looked_up = _country_code(await self._lookup_client_country())
            if looked_up is None:
                _LOGGER.info("login country unknown: logging in with the region as ab")
                return
            code, source = looked_up, const.COUNTRY_SOURCE_IP
        if cached is not None and cached.code == code and cached.home_region is not None:
            self._login_country = LoginCountry(
                code=code, source=source, home_region=cached.home_region
            )
        else:
            try:
                home = await self._lookup_home_region(code)
            except _LOOKUP_TRANSIENT:
                raise
            except EufySecurityError as err:
                _LOGGER.info("no home cluster for country %s: %s", code, err)
                home = None
                if source == const.COUNTRY_SOURCE_IP:
                    return
            else:
                if home is None:
                    _LOGGER.warning(
                        "eufy names no cluster for country %s; logging in with the region as ab",
                        code,
                    )
                    return
            self._login_country = LoginCountry(code=code, source=source, home_region=home)
        country = self._login_country
        _LOGGER.info(
            "login country %s (%s), home region %s",
            country.code,
            country.source,
            country.home_region,
        )
        if country.home_region is not None and cached != country:
            self._cache.section("cloud")[_COUNTRY_KEY] = {
                "code": country.code,
                "source": country.source,
                "home_region": country.home_region,
            }
            await self._cache.async_save()

    async def _resolve_extra_countries(self) -> None:
        """Look up the home region of each extra country neither cached nor answered in
        this process (``estimate_domain``, no login); callers hold ``_login_lock``.

        A country eufy names no ``mega-`` cluster for, or whose lookup it refuses, gets
        no session; a lookup that does not answer (the network, a throttle) is asked
        again on the next call. Only a found region is cached.
        """
        homes = _cached_extra_homes(self._cache)
        found: dict[str, str] = {}
        for code in self._extra_countries:
            if code in homes or code in self._extras_answered:
                continue
            try:
                home = await self._lookup_home_region(code)
            except _LOOKUP_TRANSIENT as err:
                _LOGGER.info("no home cluster for extra country %s yet: %s", code, err)
                continue
            except EufySecurityError as err:
                _LOGGER.warning("eufy refused the lookup of country %s (%s); no session", code, err)
                home = None
            self._extras_answered.add(code)
            if home is None:
                _LOGGER.warning("eufy names no cluster for country %s; no session for it", code)
                continue
            _LOGGER.info("extra country %s, home region %s", code, home)
            found[code] = home
        if found:
            self._cache.section("cloud")[_EXTRA_HOMES_KEY] = {**homes, **found}
            await self._cache.async_save()

    async def _lookup_client_country(self) -> str | None:
        """The host's IP country from ``get_client_real_code`` on a fresh key-exchange
        identity (no login), None when eufy names none or refuses the request; a
        lookup that does not answer (the network, a throttle) raises."""
        region = self._region_override or const.DEFAULT_REGION
        try:
            identity = await self._key_exchange(
                self._host("openapi", region), const.KEY_EXCHANGE_PATH, const.MEGA_PRESET_KEY
            )
            identity.region = region
            _code, _resp, data = await self._call(
                self._host("passport", region), const.CLIENT_COUNTRY_PATH, {}, identity
            )
        except _LOOKUP_TRANSIENT:
            raise
        except EufySecurityError as err:
            _LOGGER.info("IP country lookup refused: %s", err)
            return None
        return _ab_code(data)

    async def _lookup_home_region(self, country: str) -> str | None:
        """The region whose cluster ``estimate_domain`` names for ``country``; None when
        it names another kind of domain (not a eufy country). Raises
        :class:`CommunicationError` or :class:`ProtocolError` when it does not answer."""
        region = self._region_override or const.DEFAULT_REGION
        data = await self._post_plain(
            const.mega_host(region),
            const.ESTIMATE_DOMAIN_PATH,
            {"ab": country, "mode": const.ESTIMATE_DOMAIN_MODE},
            region=region,
        )
        domain = data.get("domain")
        return const.region_from_mega_domain(domain if isinstance(domain, str) else None)

    async def _post_plain(
        self, host: str, path: str, payload: Mapping[str, Any], *, region: str
    ) -> Mapping[str, Any]:
        """POST a plaintext JSON body with no identity to ``region``'s cluster; the
        answer's ``data`` object.

        Nothing is sent while a request hold-off runs. HTTP 429 or a throttle body code
        starts a hold-off as on :meth:`_call`; an answer that is no JSON object raises
        :class:`CommunicationError`, another non-zero body code :class:`CloudApiError`.
        """
        self._raise_if_held_off(login=False)
        import aiohttp  # noqa: PLC0415 - deferred so a cache-only run never imports it

        url = f"https://{host}{path}"
        headers = {
            "app-name": const.APP_NAME,
            "app-version": const.APP_VERSION,
            "os-type": const.OS_TYPE,
            "content-type": "application/json",
            "user-agent": const.USER_AGENT,
        }
        _LOGGER.debug("→ POST %s body=%s", url, Payload(dict(payload)))
        try:
            async with self._http().post(
                url,
                headers=headers,
                data=json.dumps(dict(payload)),
                timeout=aiohttp.ClientTimeout(total=const.HTTP_TIMEOUT_SECONDS),
            ) as resp:
                status = resp.status
                retry_after = _retry_after(resp.headers.get("Retry-After"))
                text = await resp.text()
        except (aiohttp.ClientError, TimeoutError, UnicodeDecodeError) as exc:
            raise CommunicationError(f"cloud request to {path} failed: {exc}") from exc
        _LOGGER.debug("← %s HTTP %s: %s", path, status, text[:500])
        if status == const.HTTP_TOO_MANY_REQUESTS:
            await self._hold_off(
                _HTTP_429_THROTTLE, status, "HTTP 429", path, region=region, retry_after=retry_after
            )
        if status != 200:
            raise classify_refusal(status, _loose_code(text), _message(_loose_object(text)), path)
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise CommunicationError(f"cloud response to {path} was not JSON") from exc
        if not isinstance(parsed, dict):
            raise CommunicationError(f"cloud response to {path} was not an object")
        code = _body_code(parsed.get("code", _SUCCESS), path)
        if code != _SUCCESS:
            if (throttle := const.THROTTLE_CODES.get(code)) is not None:
                await self._hold_off(throttle, code, _message(parsed), path, region=region)
            raise CloudApiError(code, _message(parsed), endpoint=path)
        return _mapping(parsed.get("data") or {}, path)

    async def _remake_for_country(self, region: str) -> None:
        """Log ``region`` in again once when its cached session was made with another
        ``ab`` than the login country; callers hold ``_login_lock``.

        Only with the country known and a password at hand (a cached one, or a string;
        never a prompt). The cached session stays in use whatever happens: a hold-off, a
        spent budget or no network leaves it for the next :meth:`async_login`; any other
        refusal (a challenge, a credential or body-code error) is recorded so it is not
        asked again for this country. The re-login runs unattended: a challenge it meets
        asks eufy for no e-mailed code and no captcha.
        """
        made = self._session_ab_wanted(region)
        if made is None or not self._password_at_hand(prompt=False):
            return
        try:
            self._raise_if_held_off(login=True, region=region)
        except RateLimitedError:
            return
        await self._resolve_login_country()
        wanted = self.login_ab(region)
        if made == wanted or (self.login_country is None and const.scope_country(region) is None):
            return
        _LOGGER.info(
            "%s cloud session was made with ab %s; logging in once with ab %s", region, made, wanted
        )
        try:
            await self._do_login(
                region,
                verify_code=None,
                captcha_id=None,
                captcha_answer=None,
                fallback=False,
                interactive=False,
            )
        except (RateLimitedError, CommunicationError) as err:
            _LOGGER.info(
                "%s re-login with ab %s not done (%s); kept the session", region, wanted, err
            )
        except EufySecurityError as err:
            _LOGGER.warning(
                "%s re-login with ab %s refused (%s); kept the session made with ab %s",
                region,
                wanted,
                err,
                made,
            )
            self._cache.cloud_session(region)[_AB_WANTED_KEY] = wanted
            await self._cache.async_save()

    async def _do_login(
        self,
        region: str,
        *,
        verify_code: str | None,
        captcha_id: str | None,
        captcha_answer: str | None,
        login_id: str | None = None,
        password: str | None = None,
        fallback: bool = True,
        interactive: bool = True,
    ) -> None:
        """One password login to ``region`` (``password`` overrides every source).

        The login sends :meth:`login_ab` as ``ab``, or, when the scope's session records
        that ``ab`` as refused (``ab_wanted`` is it, ``ab`` another), that other ``ab``.
        With ``fallback``, a country login
        the cloud refuses with a plain body code is sent once more with the region as
        ``ab`` (a second login of the budget), and the session records the country as
        the ``ab`` it settles, so no re-login follows for it. Without ``interactive`` a
        challenge is raised without asking eufy for a code or a captcha and is not
        recorded as the one to answer. A ``region`` that is no login scope once the
        country is known raises :class:`NoCachedSessionError` before anything is sent.
        An extra scope's login refused with a plain body code is recorded
        (:meth:`refused_regions`); a later login there raises it again without sending.
        Callers hold ``_login_lock``.
        """
        self._raise_if_held_off(login=True, region=region)
        password, source = (
            (password, "reauthenticating") if password else await self._login_password()
        )
        await self._resolve_login_country()
        self._raise_if_country_unknown(region)
        if region not in self.login_scopes():
            raise NoCachedSessionError(
                f"{region} is no login scope of this account (now {self.login_scopes()}); "
                "not logging in"
            )
        if region in self.refused_regions():
            record = self._cache.section("cloud")[_REFUSED_KEY][region]
            raise _ScopeRefusedError(
                int(record.get("code") or 0),
                f"the cloud refused the {region} login; not asked again until a rescan",
                endpoint=const.LOGIN_PATH,
            )
        wanted = self.login_ab(region)
        _LOGGER.info(
            "logging in to the eufy cloud as %s (password %s, region %s, ab %s)",
            Secret(self._email),
            source,
            region,
            wanted,
        )
        _LOGGER.debug(
            "login: password %s, openudid %s, %d login(s) in the budget window",
            Credential(password),
            Identifier(self._install_id(region)),
            len(
                self._cache.recent_logins(
                    const.LOGIN_BUDGET_WINDOW_SECONDS, const.scope_region(region)
                )
            ),
        )
        identity = await self._key_exchange(
            self._host("openapi", region),
            const.KEY_EXCHANGE_PATH,
            const.MEGA_PRESET_KEY,
            region=region,
        )
        answer = {
            "answer": captcha_answer or "",
            "captcha_id": captcha_id or "",
            "verify_code": verify_code or "",
            "login_id": login_id or "",
        }
        ab = wanted
        settled = self._cache.cloud_sessions().get(region, {})
        if settled.get(_AB_WANTED_KEY) == wanted and settled.get(_AB_KEY) not in (None, wanted):
            # The cloud refused this country for the scope before: send the ab it took.
            ab = str(settled[_AB_KEY])
            _LOGGER.info("%s login with ab %s, as the refused ab %s settled", region, ab, wanted)
        try:
            try:
                code, resp, data = await self._send_login(identity, password, ab, answer)
            except CloudApiError as err:
                if (
                    interactive
                    and type(err) is CloudApiError
                    and const.scope_country(region) is not None
                ):
                    await self._refuse_scope(region, err)
                fallback_ab = region if const.scope_country(region) is None else None
                if not (
                    fallback and fallback_ab and ab != fallback_ab and type(err) is CloudApiError
                ):
                    raise
                _LOGGER.warning(
                    "%s login with ab %s refused (%s); logging in with ab %s",
                    region,
                    ab,
                    err,
                    fallback_ab,
                )
                self._raise_if_held_off(login=True, region=region)
                ab = fallback_ab
                code, resp, data = await self._send_login(identity, password, ab, answer)
        except AuthenticationError as err:
            if not isinstance(err, _SessionExpiredError) and self._cache.password == password:
                # A rejected cached password is never tried again: each failure
                # counts toward the account lock.
                _LOGGER.warning("the cloud rejected the cached password; forgetting it")
                self._cache.drop_password()
                await self._cache.async_save()
            raise
        if code in const.CAPTCHA_CODES or code in const.VERIFY_CODE_CODES:
            await self._note_challenge(region, resp, data, interactive=interactive)
        if code in const.CAPTCHA_CODES:
            _LOGGER.info("%s login needs a captcha (code %s)", region, code)
            await self._raise_captcha_challenge(
                identity, code, self._extract_login_id(resp, data), request=interactive
            )
        if code in const.VERIFY_CODE_CODES:
            _LOGGER.info("%s login needs an e-mailed verification code (code %s)", region, code)
            await self._raise_verify_code_challenge(identity, code, resp, data, request=interactive)
        if not data:
            raise EmptyResponseError(code, "login returned no data", endpoint=const.LOGIN_PATH)
        step = _two_step(data)
        if step in const.VERIFY_CODE_CODES:
            # Code 0 with ``fa_info.step`` 26052: two-step verification is pending and
            # the token in this answer is not a session yet.
            await self._note_challenge(region, resp, data, interactive=interactive)
            _LOGGER.info(
                "%s login needs an e-mailed verification code (fa_info step %s)", region, step
            )
            await self._raise_verify_code_challenge(identity, step, resp, data, request=interactive)
        if self._challenge_region == region:
            self._challenge_region = None
        for key in (_CHALLENGES_KEY, _REFUSED_KEY):
            if isinstance(entries := self._cache.section("cloud").get(key), dict):
                entries.pop(region, None)
        self._store_session(identity, _mapping(data, const.LOGIN_PATH), ab=ab, ab_wanted=wanted)
        self._cache.set_password(password)
        await self._cache.async_save()

    async def _send_login(
        self, identity: _Identity, password: str, ab: str, answer: Mapping[str, str]
    ) -> tuple[int, dict[str, Any], Any]:
        """Send one ``passport/login`` with ``ab`` and the challenge ``answer`` fields,
        counted in the region's login budget before it is sent."""
        region = identity.region
        wrapped = crypto.encrypt_login_password(password)
        _LOGGER.debug(
            "login: password wrapped under an ephemeral ECDH key (client public key %s, "
            "ECDH secret %s, ciphertext %s)",
            wrapped.client_public_key,
            Credential(wrapped.secret),
            Credential(wrapped.encrypted),
        )
        payload = {
            "email": self._email,
            "password": wrapped.encrypted,
            "ab": ab,
            "client_secret_info": {"public_key": wrapped.client_public_key},
            **answer,
        }
        # Counted before it is sent: a login that times out may still have landed.
        self._cache.note_login(const.LOGIN_BUDGET_WINDOW_SECONDS, const.scope_region(region))
        await self._cache.async_save()
        return await self._call(
            self._host("passport", region),
            const.LOGIN_PATH,
            payload,
            identity,
            tolerate=const.VERIFY_CODE_CODES | const.CAPTCHA_CODES,
        )

    def _all_sessions_cached(self) -> bool:
        """Whether every scope the next device list asks has a usable cached session."""
        return all(
            (cached := self._cached_session(r)) is not None and self._session_usable(cached[3])
            for r in self.regions_to_list()
        )

    def _login_possible(self) -> bool:
        """Whether a login to some login scope could be sent now: a password at hand (or
        a prompt) and :meth:`_login_allowed`."""
        return self._password_at_hand() and self._login_allowed()

    def _login_allowed(self) -> bool:
        """Whether some login scope's cluster has no login hold-off or spent budget."""
        for region in self.login_scopes():
            try:
                self._raise_if_held_off(login=True, region=region)
            except RateLimitedError:
                continue
            return True
        return False

    def _password_at_hand(self, *, prompt: bool = True) -> bool:
        """Whether a login has a password without asking anyone: a given string, a cached
        one, or (with ``prompt``) a callable that produces one."""
        source = self._password
        return bool(
            (isinstance(source, str) and source)
            or self._cache.password
            or (prompt and callable(source))
        )

    async def _login_password(self) -> tuple[str, str]:
        """The password to log in with and where it came from ("given", "cached", "callable").

        The one given wins, else the cached one, else the callable's. Cached
        passwords let a lost session (an expiry, a cache version change) log in
        again unattended.
        """
        source = self._password
        if isinstance(source, str) and source:
            return source, "given"
        if cached := self._cache.password:
            return cached, "cached"
        if callable(source):
            return await source(), "callable"
        raise AuthenticationError("no password: none was given and none is cached")

    async def _note_challenge(
        self, region: str, resp: Mapping[str, Any], data: object, *, interactive: bool
    ) -> None:
        """Record ``region`` as the scope whose challenge an answer goes to, here and in
        the cache with its ``login_id``, so a new instance answers there too."""
        if not interactive:
            return
        self._challenge_region = region
        pending = self._cache.section("cloud").setdefault(_CHALLENGES_KEY, {})
        pending[region] = self._extract_login_id(resp, data)
        await self._cache.async_save()

    def _challenge_scope(self, login_id: str | None) -> str | None:
        """The scope a challenge answer goes to: this instance's last challenge, else
        the cached one whose ``login_id`` is ``login_id``, else the only one cached;
        None when none of them is a login scope."""
        scopes = self.login_scopes()
        if self._challenge_region in scopes:
            return self._challenge_region
        stored = self._cache.section("cloud").get(_CHALLENGES_KEY)
        pending: dict[str, object] = (
            {s: lid for s, lid in stored.items() if s in scopes} if isinstance(stored, dict) else {}
        )
        if login_id and (match := [s for s, lid in pending.items() if lid == login_id]):
            return match[-1]
        return next(iter(pending)) if len(pending) == 1 else None

    async def _raise_verify_code_challenge(
        self,
        identity: _Identity,
        code: int,
        resp: Mapping[str, Any],
        data: object,
        *,
        request: bool = True,
    ) -> NoReturn:
        """Ask for the login code with the answer's pending token (only with
        ``request``), then raise the challenge.

        The pending token is used for this one request and never stored as a session.
        A failed request still raises the challenge, with ``code_requested`` False.
        """
        requested = False
        token = data.get("auth_token") if isinstance(data, Mapping) else None
        if request and isinstance(token, str) and token:
            user_id = data.get("user_id") if isinstance(data, Mapping) else None
            pending = _Identity(
                key_ident=identity.key_ident,
                shared_key=identity.shared_key,
                auth_token=token,
                user_id=str(user_id) if user_id else None,
                region=identity.region,
            )
            try:
                await self._call(
                    self._host("push", identity.region),
                    const.SEND_VERIFY_CODE_PATH,
                    {
                        "transaction": str(int(time.time() * 1000)),
                        "message_type": const.VERIFY_CODE_BY_EMAIL,
                        "biz_type": const.VERIFY_CODE_BIZ_LOGIN,
                        "captcha_id": "",
                        "answer": "",
                    },
                    pending,
                )
            except EufySecurityError as err:
                _LOGGER.warning(
                    "%s cloud refused to e-mail a login verification code: %s", identity.region, err
                )
            else:
                requested = True
                _LOGGER.info("%s cloud asked to e-mail a login verification code", identity.region)
        raise LoginChallengeError(
            "verify_code",
            login_id=self._extract_login_id(resp, data),
            code=code,
            region=identity.region,
            code_requested=requested,
        )

    async def _raise_captcha_challenge(
        self, identity: _Identity, code: int, login_id: str, *, request: bool = True
    ) -> None:
        """Fetch a captcha (only with ``request``), then raise the challenge."""
        cid, image = await self._fetch_captcha(identity) if request else ("", "")
        raise LoginChallengeError(
            "captcha",
            login_id=login_id,
            captcha_id=cid,
            captcha_image=image,
            code=code,
            region=identity.region,
        )

    async def _fetch_captcha(self, identity: _Identity) -> tuple[str, str]:
        """Fetch a fresh captcha; returns ``(captcha_id, data-URI image)``."""
        _code, _resp, data = await self._call(
            self._host("passport", identity.region),
            const.CAPTCHA_PATH,
            None,
            identity,
        )
        data = _mapping(data or {}, const.CAPTCHA_PATH)
        cid = str(data.get("captcha_id") or "")
        item = str(data.get("item") or "")
        image = item if item.startswith("data:") else f"data:image/png;base64,{item}"
        _LOGGER.debug("fetched captcha %s (%d-char image)", cid, len(image))
        return cid, image

    @staticmethod
    def _extract_login_id(resp: Mapping[str, Any], data: object) -> str:
        for source in (data if isinstance(data, Mapping) else {}, resp):
            value = source.get("login_id")
            if isinstance(value, str) and value:
                return value
        return ""

    def _store_session(
        self, identity: _Identity, data: Mapping[str, Any], *, ab: str, ab_wanted: str
    ) -> None:
        """Make ``data``'s token ``identity``'s session and cache it with the ``ab`` it
        was made with and the ``ab`` asked for."""
        token = data.get("auth_token") or data.get("token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError("login succeeded but carried no auth token")
        user_id = data.get("ap_cloud_user_id") or data.get("user_id")
        identity.auth_token = token
        identity.user_id = str(user_id) if user_id else None
        region = identity.region
        self._identities[region] = identity

        expires_at = data.get("token_expires_at")
        ttl = time.time() + const.DEFAULT_SESSION_TTL
        if (
            isinstance(expires_at, (int, float))
            and not isinstance(expires_at, bool)
            and expires_at > time.time()
        ):
            ttl = float(expires_at)
        mega_domain = data.get("mega_domain") or data.get("domain")
        country_code = data.get("country_code")

        cloud = self._cache.cloud_session(region)
        cloud.clear()
        cloud.update(
            {
                "key_ident": identity.key_ident,
                "shared_key": identity.shared_key,
                "auth_token": token,
                "user_id": identity.user_id,
                "expires_at": ttl,
                _AB_KEY: ab,
                _AB_WANTED_KEY: ab_wanted,
            }
        )
        if isinstance(mega_domain, str) and mega_domain:
            cloud["mega_domain"] = mega_domain
        if isinstance(country_code, str) and country_code:
            cloud["country_code"] = country_code
        _LOGGER.info(
            "%s cloud login ok (user %s, token expires %s, ab %s, mega_domain %r, country_code %r)",
            region,
            redact(identity.user_id),
            _epoch(ttl),
            ab,
            mega_domain,
            country_code,
        )
        _LOGGER.debug(
            "new session: key_ident %s, shared_key %s, auth_token %s",
            Identifier(identity.key_ident),
            Secret(identity.shared_key),
            Secret(token),
        )

    async def _drop_session_if_current(self, failed: _Identity) -> None:
        """Forget ``failed`` — unless another task has already replaced it — and save.

        Concurrent calls can all fail on the same expired token; only the first may
        drop it, or a later one would wipe the session the first just logged in.
        """
        region = failed.region
        if not failed.same_session(self._identities.get(region)):
            return  # already dropped, or replaced by a newer login
        _LOGGER.debug(
            "dropping the %s cloud session (key_ident %s)", region, Identifier(failed.key_ident)
        )
        cloud = self._cache.cloud_session(region)
        del self._identities[region]
        for key in ("auth_token", "key_ident", "shared_key", "expires_at"):
            cloud.pop(key, None)
        await self._cache.async_save()

    @property
    def session_replaced(self) -> bool:
        """Whether another client's login ended the session; cleared by ``async_login(force=True)``."""
        return self._cache.replaced_at is not None

    def _raise_if_replaced(self) -> None:
        if self.session_replaced:
            raise SessionReplacedError(
                "another client logged in with this account; not logging in again automatically",
                code=const.CloudCode.SESSION_REPLACED,
            )

    async def _mark_replaced(self, failed: _Identity) -> None:
        """Latch the kick-out (persisted) and forget ``failed``, unless a newer login replaced it."""
        if not failed.same_session(self._identities.get(failed.region)):
            return
        self._cache.set_replaced()
        _LOGGER.warning(
            "another client logged in with this eufy account and ended this session; "
            "not logging in again until asked to"
        )
        await self._drop_session_if_current(failed)

    async def _ensure_session(self, region: str, *, login: bool = True) -> _Identity:
        """``region``'s live session: the one held, the cached one, or a new login.

        Without ``login``, no usable session raises :class:`NoCachedSessionError`.
        """
        self._raise_if_replaced()
        identity = self._identities.get(region)
        if identity is not None and identity.auth_token:
            return identity
        async with self._login_lock:
            self._raise_if_replaced()
            # Re-check: another task may have logged in while this one waited.
            identity = self._identities.get(region)
            if not (identity and identity.auth_token) and not self._load_cached_session(region):
                if not login:
                    raise NoCachedSessionError(
                        f"no usable {region} cloud session cached; not logging in"
                    )
                await self._resolve_login_country(retry=True)
                await self._do_login(region, verify_code=None, captcha_id=None, captcha_answer=None)
            identity = self._identities.get(region)
        if identity is None:  # pragma: no cover — login raises rather than return
            raise AuthenticationError("no cloud session after login")
        return identity

    async def _with_session[T](
        self, operation: Callable[[_Identity], Awaitable[T]], region: str, *, login: bool = True
    ) -> T:
        """Run ``operation`` on ``region``'s session, retrying once for each recoverable refusal.

        A session-expired code costs one re-login. A re-key answer (HTTP 463, body 463 /
        4404: the gateway forgot the key identity) costs one new key exchange on the
        same auth token, never a login, and a second refusal raises
        :class:`KeyExchangeRefusedError`. A credential rejection, a throttle, a session
        another client took over, or any other failure propagates at once.

        Without ``login`` nothing logs in: no usable session raises
        :class:`NoCachedSessionError`, and a session-expired code propagates with the
        session left for the next ordinary call.
        """
        identity = await self._ensure_session(region, login=login)
        rekeyed = relogged = False
        while True:
            try:
                return await operation(identity)
            except SessionReplacedError:
                await self._mark_replaced(identity)
                raise
            except _RekeyRequiredError as err:
                if rekeyed:
                    raise KeyExchangeRefusedError(
                        err.code, err.message, endpoint=err.endpoint, status=err.status
                    ) from err
                rekeyed = True
                identity = await self._rekey(identity, err)
            except _SessionExpiredError as err:
                if relogged or not login:
                    raise
                relogged = True
                _LOGGER.info("cloud session no longer accepted (%s); logging in once more", err)
                await self._drop_session_if_current(identity)
                identity = await self._ensure_session(region)

    async def _rekey(self, failed: _Identity, err: _RekeyRequiredError) -> _Identity:
        """A new key identity for the session of ``failed``, keeping its auth token.

        The app's answer to HTTP 463: a new key exchange on the login realm, then the
        same request again. Concurrent callers share one exchange; one that finds the
        session already replaced (re-keyed or logged in by another task) uses that.
        """
        region = failed.region
        async with self._login_lock:
            current = self._identities.get(region)
            if current is not None and current.auth_token and not failed.same_session(current):
                return current
            _LOGGER.info(
                "the cloud gateway no longer knows this key identity (%s); "
                "running a new key exchange on the same session, no login",
                err,
            )
            try:
                fresh = await self._key_exchange(
                    self._host("openapi", region),
                    const.KEY_EXCHANGE_PATH,
                    const.MEGA_PRESET_KEY,
                    region=region,
                )
            except _RekeyRequiredError as refused:
                raise KeyExchangeRefusedError(
                    refused.code, refused.message, endpoint=refused.endpoint, status=refused.status
                ) from refused
            fresh.auth_token = failed.auth_token
            fresh.user_id = failed.user_id
            self._identities[region] = fresh
            self._cache.cloud_session(region).update(
                {"key_ident": fresh.key_ident, "shared_key": fresh.shared_key}
            )
            await self._cache.async_save()
            return fresh

    # ── devices, owner id ────────────────────────────────────────────────────

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        """Every device on the account (``app/house/get_devs_list``), cached.

        Returns the cached list unless ``refresh`` or ``rescan_regions`` is set or
        nothing is cached (``rescan_regions``: see :meth:`async_fetch_devices`). A
        refresh that cannot reach the cloud (a network error or a throttle) falls back
        to the cache when there is one, so a Home Assistant restart during a cloud
        outage still comes up. A refusal from the cloud itself (a kick-out, a key
        identity a new key exchange did not restore, a credential or body-code error)
        always raises. :meth:`async_fetch_devices` never falls back.
        """
        if not (refresh or rescan_regions):
            cached = self._cache.cached_devices()
            if cached is not None:
                _LOGGER.debug("device list from the cache (%d devices)", len(cached))
                return [CloudDevice.from_api(d) for d in cached]
        try:
            return await self.async_fetch_devices(rescan_regions=rescan_regions)
        except (CommunicationError, RateLimitedError) as err:
            cached = self._cache.cached_devices()
            if cached is None:
                raise
            _LOGGER.warning("device list refresh failed (%s); using the cached list", err)
            return [CloudDevice.from_api(d) for d in cached]

    async def async_fetch_devices(self, *, rescan_regions: bool = False) -> list[CloudDevice]:
        """The device list fetched from the cloud now, cached; every failure raises.

        Asks each login scope of :meth:`regions_to_list` (``rescan_regions``: every
        scope), after looking up the login country when a login may follow and the
        extra countries' home regions neither cached nor answered in this process (a
        rescan asks every one not cached again). Each device
        is tagged with the scope that listed it (:attr:`CloudDevice.region`;
        a serial two scopes list keeps the first scope's entry). A scope that lists no
        devices is suspended. With every scope suspended nothing is sent and the cached
        (empty) list is returned. Nothing is cached unless every scope asked answered.
        """
        async with self._login_lock:
            if not self.session_replaced and self._login_possible():
                # The scopes follow the countries: look them up (no login) first.
                await self._resolve_login_country(retry=True)
            if rescan_regions:
                self._extras_answered.clear()
                self._cache.section("cloud").pop(_REFUSED_KEY, None)
            await self._resolve_extra_countries()
        regions = self.regions_to_list(rescan=rescan_regions)
        if not regions:
            _LOGGER.info(
                "device list not fetched: every login scope (%s) listed no devices last time; "
                "a rescan asks them again",
                ", ".join(self.login_scopes()),
            )
            return [CloudDevice.from_api(d) for d in self._cache.cached_devices() or ()]
        entries: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        listed_by: dict[str, str] = {}
        for region in regions:
            try:
                raw = await self._house_entries(region, _ACCOUNT_DEVICES_BODY, login=True)
            except _ScopeRefusedError:
                continue  # skipped until a rescan; the other scopes carry on
            counts[region] = len(raw)
            _LOGGER.info("the %s region lists %d device(s)", region, len(raw))
            for entry in raw:
                serial = str(entry.get("device_sn") or "")
                if serial and serial in listed_by:
                    _LOGGER.warning(
                        "%s is listed by the %s and the %s region; using the %s entry",
                        redact_serial(serial),
                        listed_by[serial],
                        region,
                        listed_by[serial],
                    )
                    continue
                listed_by[serial] = region
                entries.append({**entry, REGION_KEY: region})
        # A refused scope keeps the devices it listed last, for its stations' LAN use.
        refused = self.refused_regions()
        entries.extend(
            dict(entry)
            for entry in self._cache.cached_devices() or ()
            if entry.get(REGION_KEY) in refused and entry.get("device_sn") not in listed_by
        )
        self._cache.set_devices(entries)
        listed = self._cache.section("cloud").setdefault("listed", {})
        now = time.time()
        for region, count in counts.items():
            listed[region] = {"devices": count, "at": now}
        await self._cache.async_save()
        empty = [region for region, count in counts.items() if not count]
        if not entries:
            _LOGGER.warning(
                "the account lists no devices in the %s region(s); not asked again until a rescan",
                ", ".join(regions),
            )
        elif empty:
            _LOGGER.info(
                "no devices in the %s region(s); not asked again until a rescan", ", ".join(empty)
            )
        devices = [CloudDevice.from_api(d) for d in entries]
        for device in devices:
            _LOGGER.debug("  %r", device)
        return devices

    async def _house_entries(
        self, region: str, body: Mapping[str, Any], *, login: bool
    ) -> list[Mapping[str, Any]]:
        """The raw ``get_devs_list`` entries ``region`` answers ``body`` with."""
        data = await self._authenticated_call(
            self._host("house", region), const.DEVICES_PATH, dict(body), region=region, login=login
        )
        return _device_list(data)

    async def async_list_house_devices(
        self, region: str, house_id: str | None = None, *, login: bool = True
    ) -> list[CloudDevice]:
        """The house device list of ``region`` as the cloud answers it now; not cached.

        ``house_id`` None asks the account-wide list :meth:`async_fetch_devices` reads
        (body ``{"device_sn": ""}``); a house id asks that house in the app's body
        (``house_id``, empty ``categories`` and ``add_pns``). Each device is tagged with
        ``region``. Without ``login`` nothing logs in (see :meth:`_with_session`).
        """
        body: Mapping[str, Any] = (
            _ACCOUNT_DEVICES_BODY
            if house_id is None
            else {"house_id": house_id, "categories": [], "add_pns": []}
        )
        raw = await self._house_entries(region, body, login=login)
        return [CloudDevice.from_api({**entry, REGION_KEY: region}) for entry in raw]

    async def async_list_houses(self, region: str, *, login: bool = True) -> list[CloudHouse]:
        """The houses (homes) ``region`` lists for the account (``get_house_list``).

        Not cached. Without ``login`` nothing logs in (see :meth:`_with_session`).
        """
        data = await self._authenticated_call(
            self._host("house", region),
            const.HOUSES_PATH,
            {},
            region=region,
            login=login,
            expect_data=False,
        )
        if data is None:
            return []
        houses = _mapping(data, const.HOUSES_PATH).get("house_infos") or []
        if not isinstance(houses, list):
            raise ProtocolError(f"cloud response to {const.HOUSES_PATH} has no house_infos list")
        return [CloudHouse.from_api(h) for h in houses if isinstance(h, Mapping)]

    async def async_list_invites(self, region: str, *, login: bool = True) -> list[CloudInvite]:
        """The invitations sent to the account in ``region`` that it has not accepted:
        homes (``get_house_invite_records``), then single devices (``get_invites``).

        Not cached. An account sees a shared home's devices only after it accepts the
        invitation in the eufy app, so a pending one explains an empty device list.
        Without ``login`` nothing logs in (see :meth:`_with_session`).
        """
        houses = await self._authenticated_call(
            self._host("house", region),
            const.HOUSE_INVITES_PATH,
            {"transaction": crypto.new_key_ident(), "is_inviter": const.INVITES_RECEIVED},
            region=region,
            login=login,
            expect_data=False,
        )
        devices = await self._authenticated_call(
            self._host("devicerelation", region),
            const.DEVICE_INVITES_PATH,
            {
                "transaction": crypto.new_key_ident(),
                "is_inviter": const.INVITES_RECEIVED,
                "categories": [],
                "add_pns": [],
            },
            region=region,
            login=login,
            expect_data=False,
        )
        invites = [
            CloudInvite.from_house_api(entry, region=region)
            for entry in _entries(houses, const.HOUSE_INVITES_PATH, "house_invite_records")
        ]
        invites += [
            CloudInvite.from_device_api(entry, region=region)
            for entry in _entries(devices, const.DEVICE_INVITES_PATH, "invites")
        ]
        for invite in invites:
            _LOGGER.debug("  %r", invite)
        return invites

    async def async_list_security_devices(
        self, region: str, *, stations: bool, login: bool = True
    ) -> list[CloudDevice]:
        """The security realm's station list (``stations``: ``get_hub_list``) or device
        list (``get_devs_list``) of ``region``; not cached.

        The lists the eufy Security app reads with the account's session on the
        security realm; entries come back through :func:`~.models.security_device_entry`
        (``source`` ``"security"``) tagged with ``region``. The request body is the
        app's. Without ``login`` nothing logs in (see :meth:`_with_session`).
        """
        path = const.SECURITY_STATIONS_PATH if stations else const.SECURITY_DEVICES_PATH
        body = {
            "device_sn": "",
            "station_sn": "",
            "num": const.SECURITY_LIST_PAGE,
            "page": 0,
            "orderby": "",
            "time_zone": round(time.localtime().tm_gmtoff * 1000),
            "event_num_type": 1,
            "transaction": crypto.new_key_ident(),
        }

        async def fetch(base: _Identity) -> Any:
            sec = await self._security_identity(base)
            _code, _resp, data = await self._call(
                const.security_host(const.scope_region(region)), path, body, sec, category=True
            )
            return data

        data = await self._with_session(fetch, region, login=login)
        if data is None:
            return []
        if not isinstance(data, list):
            raise ProtocolError(f"cloud response to {path} is not a list")
        return [
            CloudDevice.from_api(
                {**security_device_entry(entry, station=stations), REGION_KEY: region}
            )
            for entry in data
            if isinstance(entry, Mapping)
        ]

    async def async_get_station_owner_id(self, station_sn: str, *, refresh: bool = False) -> str:
        """The owner id (``member.admin_user_id``) commands to ``station_sn`` must carry.

        Cached per station. Falls back to this account's own user id only when the
        station has no member relation at all — i.e. only for the literal owner.
        ``refresh`` re-reads the device list from the cloud, at most once per
        cooldown; inside it, the cached owner id (or cached list) is used instead.
        """
        cached = self._cache.station_account_id(station_sn)
        fetch = False
        if refresh:
            since = self._cache.seconds_since_refresh("owner")
            fetch = since is None or since >= const.FORCED_REFRESH_COOLDOWN
            if not fetch:
                _LOGGER.debug("owner id refresh for %s is on cooldown", redact_serial(station_sn))
        if not fetch and cached:
            _LOGGER.debug(
                "owner id for %s from the cache: %s", redact_serial(station_sn), Secret(cached)
            )
            return cached
        if fetch:
            self._cache.note_refresh("owner")
            await self._cache.async_save()
        devices = await self.async_get_devices(refresh=fetch)
        for device in devices:
            if device.device_sn != station_sn:
                continue
            owner = device.owner_user_id
            origin = "member.admin_user_id"
            if not owner and not device.has_member_relation:
                # No member relation at all means this account is the literal owner.
                owner, origin = self.user_id, "own user id (no member relation)"
            if owner:
                _check_owner_id(owner, station_sn)
                _LOGGER.debug(
                    "owner id for %s: %s (%s)", redact_serial(station_sn), Secret(owner), origin
                )
                self._cache.set_station_account_id(station_sn, owner)
                await self._cache.async_save()
                return owner
            raise CloudApiError(
                _SUCCESS,
                f"{redact_serial(station_sn)} has no owner id",
                endpoint=const.DEVICES_PATH,
            )
        raise CloudApiError(
            _SUCCESS,
            f"{redact_serial(station_sn)} is not on this account",
            endpoint=const.DEVICES_PATH,
        )

    # ── device session key (DSK) ───────────────────────────────────────────

    async def async_get_dsk_key(
        self, station_sn: str, *, refresh: bool = False, margin: float = DSK_REFRESH_MARGIN
    ) -> str:
        """The station's device session key (DSK), cached per station until it expires.

        A DSK wakes a battery station through its rendezvous servers (see
        :class:`~..p2p.session.StationSession`): the app fetches one per client and it
        lasts about an hour. The cache is used while at least ``margin`` seconds remain;
        ``refresh`` (or a stale cache) fetches a fresh one and passes the old key as
        ``invalid_dsk`` so the server rotates it.
        """
        cached = self._cache.dsk_key(station_sn)
        stale = cached[0] if cached else ""
        if not refresh and cached and cached[1] - time.time() > margin:
            _LOGGER.debug(
                "DSK for %s from the cache (expires in %.0fs): %s",
                redact_serial(station_sn),
                cached[1] - time.time(),
                Secret(cached[0]),
            )
            return cached[0]
        key, expiration = await self._fetch_dsk(station_sn, invalid_dsk=stale if refresh else "")
        _LOGGER.debug(
            "DSK for %s fetched (expires in %.0fs): %s",
            redact_serial(station_sn),
            expiration - time.time(),
            Secret(key),
        )
        self._cache.set_dsk_key(station_sn, key, expiration)
        await self._cache.async_save()
        return key

    async def _fetch_dsk(self, station_sn: str, *, invalid_dsk: str) -> tuple[str, float]:
        """Fetch the DSK and its expiration (epoch s) from ``get_dsk_keys``."""
        payload = {
            "device_dsks": [
                {"invalid_dsk": invalid_dsk, "device_sn": station_sn, "category": const.CATEGORY}
            ],
            "invalid_dsks": {},
            "station_sns": [station_sn],
        }
        region = self.device_region(station_sn)
        host = self._host("devicerelation", region)

        async def fetch(identity: _Identity) -> Any:
            _code, _resp, data = await self._call(
                host, const.DSK_KEYS_PATH, payload, identity, category=True
            )
            return data

        data = await self._with_session(fetch, region)
        items = _mapping(data, const.DSK_KEYS_PATH).get("device_dsks")
        if not isinstance(items, list):
            raise ProtocolError(f"cloud response to {const.DSK_KEYS_PATH} has no device_dsks list")
        for item in items:
            if isinstance(item, Mapping) and item.get("dsk_key"):
                key = item["dsk_key"]
                expiration = item.get("expiration")
                if isinstance(key, str) and isinstance(expiration, (int, float)):
                    return key, float(expiration)
        raise EmptyResponseError(
            _SUCCESS,
            f"no DSK for {redact_serial(station_sn)} in the cloud response",
            endpoint=const.DSK_KEYS_PATH,
        )

    # ── firmware (OTA) ─────────────────────────────────────────────────────

    async def async_check_firmware(
        self,
        device_sn: str,
        *,
        ota_type: str,
        current_version_name: str,
        rom_version: int = 0,
    ) -> FirmwareUpdate | None:
        """Ask the cloud OTA whether a newer firmware exists for a device; None if up to date.

        ``ota_type`` is the device's firmware-kit type (:func:`~.const.firmware_ota_type`)
        and ``current_version_name`` its installed version. A device on the newest
        published firmware answers with an embedded ``code`` 20004, returned here as None
        (see :class:`~.models.FirmwareUpdate`). This is a plain authenticated call, so it
        shares the account's throttle and one-re-login retry like every other; make it on
        a timer of the consumer's own choosing, never per start.
        """
        region = self.device_region(device_sn)
        host = self._host("ota", region)
        body = {
            "transaction": crypto.new_key_ident(),
            "current_version_name": current_version_name,
            "device_sn": device_sn,
            "device_type": ota_type,
            "rom_version": rom_version,
            "sn": device_sn,
        }
        data = await self._authenticated_call(
            host, const.OTA_ROM_PATH, body, region=region, expect_data=False
        )
        update = FirmwareUpdate.from_api(device_sn, data)
        _LOGGER.debug(
            "firmware for %s (%s at %s): %s",
            redact_serial(device_sn),
            ota_type,
            current_version_name,
            update or "up to date",
        )
        return update

    # ── cipher key ─────────────────────────────────────────────────────────

    async def async_get_cipher_key(
        self, station_sn: str, cipher_id: int = const.CIPHER_ID_P2P, *, refresh: bool = False
    ) -> str:
        """The station cipher's ``ecc_private_key`` (hex), cached per station.

        As :meth:`async_get_cipher_keys`; raises :class:`EmptyResponseError` when the
        cipher has no ECC key.
        """
        keys = await self.async_get_cipher_keys(station_sn, cipher_id, refresh=refresh)
        if not keys.ecc_private_key:
            raise EmptyResponseError(
                _SUCCESS,
                f"cipher {cipher_id} for {redact_serial(station_sn)} carried no ecc_private_key",
                endpoint=const.CIPHERS_PATH,
            )
        return keys.ecc_private_key

    async def async_get_cipher_keys(
        self, station_sn: str, cipher_id: int = const.CIPHER_ID_P2P, *, refresh: bool = False
    ) -> CipherKeys:
        """The station cipher's keys (``ecc_private_key`` and the RSA ``private_key``),
        cached per station.

        ``refresh`` honours the per-station refresh cooldown: called again inside it
        for the same station, it raises :class:`RefreshCooldownError` (``code`` 0) rather
        than risk a login-shaped fetch that could lock the account.

        An empty answer raises :class:`CipherUnavailableError`; for
        :data:`~.const.CIPHER_UNAVAILABLE_BACKOFF` after it, the same station and cipher
        raise it again without a request (``refresh`` included).
        """
        if not refresh:
            cached = CipherKeys(
                self._cache.cipher_key(station_sn, cipher_id),
                self._cache.rsa_cipher_key(station_sn, cipher_id),
            )
            if cached.ecc_private_key or cached.rsa_private_key:
                _LOGGER.debug(
                    "cipher %d for %s from the cache: ecc_private_key %s, RSA key %s",
                    cipher_id,
                    redact_serial(station_sn),
                    Secret(cached.ecc_private_key or ""),
                    "held" if cached.rsa_private_key else "none",
                )
                return cached
        self._raise_if_cipher_unavailable(station_sn, cipher_id)
        if refresh:
            left = self._cipher_cooldown_left(station_sn)
            if left:
                _LOGGER.debug("cipher refresh refused locally: cooldown, %.0fs left", left)
                raise RefreshCooldownError(
                    f"cipher refresh for {redact_serial(station_sn)} is on cooldown ({left:.0f}s left)",
                    retry_after=left,
                )
            self._cache.note_refresh("cipher", station_sn)
            await self._cache.async_save()

        owner = await self.async_get_station_owner_id(station_sn)
        try:
            keys = await self._fetch_cipher(station_sn, cipher_id, owner)
        except CipherUnavailableError as err:
            self._cipher_unavailable[(station_sn, cipher_id)] = (time.monotonic(), err.owner_source)
            raise
        _LOGGER.debug(
            "cipher %d for %s fetched: ecc_private_key %s, RSA key %s",
            cipher_id,
            redact_serial(station_sn),
            Secret(keys.ecc_private_key or ""),
            "held" if keys.rsa_private_key else "none",
        )
        self._cache.drop_cipher_key(station_sn, cipher_id)
        if keys.ecc_private_key:
            self._cache.set_cipher_key(station_sn, cipher_id, keys.ecc_private_key)
        if keys.rsa_private_key:
            self._cache.set_rsa_cipher_key(station_sn, cipher_id, keys.rsa_private_key)
        await self._cache.async_save()
        return keys

    async def _fetch_cipher(
        self, station_sn: str, cipher_id: int, owner_user_id: str
    ) -> CipherKeys:
        """Fetch one cipher's keys (see :meth:`_cipher_answer`)."""
        data = await self._cipher_answer(
            station_sn, [cipher_id], owner_user_id, self.device_region(station_sn), login=True
        )
        if not data:
            # code 0 with no data: no key for this cipher id under this user id (a
            # member's own id instead of the owner's, or an id the owner lacks).
            source = "own user id" if owner_user_id == self.user_id else "member.admin_user_id"
            backoff = const.CIPHER_UNAVAILABLE_BACKOFF
            raise CipherUnavailableError(
                f"the cloud has no key for cipher {cipher_id} of {redact_serial(station_sn)} "
                f"under owner id {redact(owner_user_id)} ({source}); "
                f"not asked again for {backoff:.0f}s",
                cipher_id=cipher_id,
                owner_source=source,
                retry_after=backoff,
                endpoint=const.CIPHERS_PATH,
            )
        for item in _cipher_items(data):
            if isinstance(item, Mapping) and str(item.get("cipher_id")) == str(cipher_id):
                keys = CipherKeys(
                    _key_text(item.get("ecc_private_key")), _key_text(item.get("private_key"))
                )
                if keys.ecc_private_key or keys.rsa_private_key:
                    return keys
        raise EmptyResponseError(
            _SUCCESS,
            f"cipher {cipher_id} for {redact_serial(station_sn)} carried no private key",
            endpoint=const.CIPHERS_PATH,
        )

    async def _cipher_answer(
        self,
        station_sn: str,
        cipher_ids: Sequence[int],
        owner_user_id: str,
        region: str,
        *,
        login: bool,
    ) -> Any:
        """``get_ciphers``' ``data`` for ``cipher_ids`` under ``owner_user_id``.

        The security-realm key exchange and the fetch share one session retry: a
        server-revoked token costs one re-login (``login``), not an
        :class:`AuthenticationError` for days.
        """
        payload = {
            "cipher_ids": list(cipher_ids),
            "user_id": owner_user_id,
            "station_sn": station_sn,
        }

        async def fetch(base: _Identity) -> Any:
            sec = await self._security_identity(base)
            _code, _resp, data = await self._call(
                const.security_host(const.scope_region(region)),
                const.CIPHERS_PATH,
                payload,
                sec,
                category=True,
            )
            return data

        return await self._with_session(fetch, region, login=login)

    async def async_list_ciphers(
        self,
        station_sn: str,
        owner_user_id: str,
        cipher_ids: Sequence[int] = const.CIPHER_ID_SWEEP,
        *,
        region: str | None = None,
        login: bool = True,
    ) -> list[CipherRecord]:
        """The cipher records ``owner_user_id`` holds among ``cipher_ids``; not cached.

        One ``get_ciphers`` request, named for ``station_sn`` (the key belongs to the
        cipher id under the owner, so any station of that owner reads the same table).
        The default asks :data:`~.const.CIPHER_ID_SWEEP`, the whole table. An empty
        answer is an empty list, not :class:`CipherUnavailableError`. ``region``
        defaults to the station's (:meth:`device_region`). Without ``login`` nothing
        logs in (see :meth:`_with_session`). The keys are secrets: never log or persist
        a record, report :meth:`CipherRecord.check_rsa` and ``ecc_state`` instead.
        """
        data = await self._cipher_answer(
            station_sn,
            cipher_ids,
            owner_user_id,
            region or self.device_region(station_sn),
            login=login,
        )
        if not data:
            return []
        records = (CipherRecord.from_api(item) for item in _cipher_items(data))
        return [record for record in records if record is not None]

    async def _security_identity(self, base: _Identity) -> _Identity:
        """Mint an eufy_security-realm identity on the session ``base``."""
        _LOGGER.debug(
            "security realm: key exchange on session key_ident %s", Identifier(base.key_ident)
        )
        sec = await self._key_exchange(
            const.security_host(const.scope_region(base.region)),
            const.SECURITY_KEY_EXCHANGE_PATH,
            const.SECURITY_PRESET_KEY,
            auth=base,
            region=base.region,
        )
        sec.auth_token = base.auth_token
        sec.user_id = base.user_id
        return sec

    # ── push token ─────────────────────────────────────────────────────────

    async def async_register_push_token(self, token: str) -> None:
        """Register an FCM token so the cloud pushes events to this install.

        Registered in every region whose device list holds devices (:attr:`region`
        before any listing; nowhere once every region is suspended), in order; the first
        failure raises. No platform field: FCM-vs-APNs is decided by the ``os-type: android`` header
        and the ordinary (openapi) identity this is signed under — never a
        security-realm one. There is no unregister endpoint; re-register on start.
        """
        for region in self._regions_in_service():
            await self._authenticated_call(
                self._host("push", region),
                const.PUSH_TOKEN_PATH,
                {"token": token, "is_notification_enable": True, "voip_token": token},
                region=region,
                expect_data=False,  # success is a bare code 0
            )
            _LOGGER.debug("registered push token %s in the %s region", Secret(token), region)

    # ── thing descriptions ─────────────────────────────────────────────────

    async def async_get_thing_descriptions(
        self, product_codes: Sequence[str]
    ) -> list[Mapping[str, Any]]:
        """The vendor thing descriptions of ``product_codes`` (``app/things/get_things_list``).

        One signed POST on the session of :attr:`region` this client holds or has cached.
        Returns the reply's ``things_list``; the cloud may omit codes it does not
        know, so the caller matches entries by ``profile.product_code``.

        It never spends a login: it never logs in, never logs in again,
        and never drops or refreshes the session. With no usable session (none
        cached, the cache not loaded, or one expiring within the margin) it raises
        :class:`NoCachedSessionError` without a request. An expired-token or re-key
        answer propagates as a :class:`CloudError` and leaves the session for the
        next ordinary call. A hold-off refuses locally, and a 429 or throttle code
        starts the account's shared hold-off exactly as every other call does. Only
        a session another client took over is latched and forgotten, as everywhere.
        """
        codes = list(product_codes)
        if not codes:
            return []
        if not self._cache.loaded:
            raise NoCachedSessionError("session cache not loaded; not logging in")
        # The lock a login takes, so this read never races one; no I/O under it.
        region = self.region
        async with self._login_lock:
            self._raise_if_replaced()
            identity = self._identities.get(region)
            if not (identity and identity.auth_token) and self._load_cached_session(region):
                identity = self._identities.get(region)
        if identity is None or not identity.auth_token:
            _LOGGER.debug("thing descriptions skipped: no usable cached cloud session")
            raise NoCachedSessionError("no usable cached cloud session; not logging in")
        body = {"product_codes": codes, "code_time_map": {}, "use_network_version": True}
        try:
            _code, _resp, data = await self._call(
                self._host("things", region),
                const.THINGS_PATH,
                body,
                identity,
            )
        except SessionReplacedError:
            await self._mark_replaced(identity)
            raise
        if not isinstance(data, Mapping) or not isinstance(data.get("things_list"), list):
            raise ProtocolError(f"cloud response to {const.THINGS_PATH} has no things_list")
        things = [t for t in data["things_list"] if isinstance(t, Mapping)]
        _LOGGER.debug(
            "thing descriptions from the cloud: %d requested, %d returned", len(codes), len(things)
        )
        return things

    # ── throttle ─────────────────────────────────────────────────────────────

    def _held_off(self, kind: str, region: str | None = None) -> float | None:
        """Seconds left on this account's ``kind`` hold-off (a login hold-off is per
        ``region``'s cluster); requests also see the install's."""
        cluster = None if region is None else const.scope_region(region)
        own = self._cache.held_off_for(kind, longest=const.LOCKOUT_HOLD_OFF_SECONDS, region=cluster)
        shared = (
            self._install.request_held_off_for()
            if kind == "requests" and self._install is not None
            else None
        )
        return max((left for left in (own, shared) if left is not None), default=None)

    def _record_hold_off(
        self, *, login_only: bool, seconds: float, region: str | None = None
    ) -> None:
        """Start a hold-off in this account's cache (not saved) and, for requests, the install's.

        A login hold-off holds off ``region``'s logins (every region's when None).
        """
        if login_only:
            for held in [const.scope_region(region)] if region is not None else const.REGIONS:
                self._cache.hold_off("login", seconds, region=held)
        else:
            self._cache.hold_off("requests", seconds)
        if not login_only and self._install is not None:
            # A request limit may be the host's: every account of the install waits.
            self._install.hold_off_requests(seconds)

    def _login_budget_wait(self, region: str) -> tuple[int, float | None]:
        """``region``'s logins in the budget window, and seconds until its next is allowed
        if its budget is spent."""
        window = const.LOGIN_BUDGET_WINDOW_SECONDS
        recent = self._cache.recent_logins(window, const.scope_region(region))
        if len(recent) < const.LOGIN_BUDGET:
            return len(recent), None
        # The next login is allowed once enough of the recent ones leave the window.
        return len(recent), max(recent[-const.LOGIN_BUDGET] + window - time.time(), 0.0)

    def _raise_if_held_off(self, *, login: bool, region: str = const.DEFAULT_REGION) -> None:
        """Refuse locally while a hold-off runs, or a login to ``region`` once its login
        hold-off runs or its budget is spent."""
        left = self._held_off("requests")
        if left is not None:
            _LOGGER.debug("cloud call refused locally: request hold-off, %.0fs left", left)
            raise RateLimitedError(
                f"holding off the eufy cloud after it throttled ({left:.0f}s left)",
                retry_after=left,
            )
        if not login:
            return
        left = self._held_off("login", region)
        if left is not None:
            _LOGGER.debug("%s login refused locally: login hold-off, %.0fs left", region, left)
            raise LoginLimitedError(
                f"holding off {region} logins after the cloud refused one ({left:.0f}s left)",
                retry_after=left,
            )
        count, left = self._login_budget_wait(region)
        if left is not None:
            cluster = const.scope_region(region)
            _LOGGER.debug(
                "%s login refused locally: the %s budget of %d is spent",
                region,
                cluster,
                const.LOGIN_BUDGET,
            )
            raise LoginLimitedError(
                f"{count} logins on the {cluster} cluster in the last "
                f"{const.LOGIN_BUDGET_WINDOW_SECONDS / 3600:.0f} h already; "
                f"next allowed in {left:.0f}s",
                retry_after=left,
            )

    def _raise_if_cipher_unavailable(self, station_sn: str, cipher_id: int) -> None:
        """Re-raise the empty answer for this station and cipher while its back-off runs."""
        key = (station_sn, cipher_id)
        last = self._cipher_unavailable.get(key)
        if last is None:
            return
        since, source = last
        left = const.CIPHER_UNAVAILABLE_BACKOFF - (time.monotonic() - since)
        if left <= 0:
            del self._cipher_unavailable[key]
            return
        _LOGGER.debug("cipher %d refused locally: no key last time, %.0fs left", cipher_id, left)
        raise CipherUnavailableError(
            f"the cloud had no key for cipher {cipher_id} of {redact_serial(station_sn)} "
            f"under the owner id ({source}); not asked again for {left:.0f}s",
            cipher_id=cipher_id,
            owner_source=source,
            retry_after=left,
            endpoint=const.CIPHERS_PATH,
        )

    def _cipher_cooldown_left(self, station_sn: str) -> float:
        """Seconds left on ``station_sn``'s forced cipher-refresh cooldown; 0.0 when none."""
        since = self._cache.seconds_since_refresh("cipher", station_sn)
        return 0.0 if since is None else max(const.FORCED_REFRESH_COOLDOWN - since, 0.0)

    # ── status ───────────────────────────────────────────────────────────────

    def cloud_status(self) -> CloudStatus:
        """The login, throttle and refresh state as the cache holds it; never contacts the cloud.

        The login need and the session expiry cover the regions the next device list
        asks (:meth:`regions_to_list`); the login hold-off and the budget wait cover
        those and :attr:`region`, where a forced login goes. A password counts as available when one is
        cached or a string was given; a password callable is a prompt, so without
        either the need is ``PASSWORD_REQUIRED``. The cache must be loaded.
        """
        now = time.time()
        in_use = self.regions_to_list()
        scopes = self.login_scopes()
        sessions = {region: self._cached_session(region) for region in scopes}
        expiries = [
            cached[3]
            for region in in_use
            if (cached := sessions[region]) is not None and cached[3] is not None
        ]
        expires = min(expiries) if expiries else None
        if self.session_replaced:
            need = LoginNeed.REPLACED
        elif all(
            (cached := sessions[region]) is not None and self._session_usable(cached[3])
            for region in in_use
        ):
            need = LoginNeed.NONE
        elif self._cache.password or (isinstance(self._password, str) and self._password):
            need = LoginNeed.CACHED_PASSWORD
        else:
            need = LoginNeed.PASSWORD_REQUIRED
        request_hold_off = self._held_off("requests")
        # A forced login or a reauthentication goes to :attr:`region` even when no
        # scope is in use.
        logging_in = [*in_use, self.region]
        login_hold_off = max(
            (left for r in logging_in if (left := self._held_off("login", r)) is not None),
            default=None,
        )
        budget_wait = max(
            (left for r in logging_in if (left := self._login_budget_wait(r)[1]) is not None),
            default=None,
        )
        count = max(self._login_budget_wait(r)[0] for r in const.REGIONS)
        attempts = self._cache.recent_logins(math.inf)
        return CloudStatus(
            login_need=need,
            password_cached=self._cache.password is not None,
            session_expires_in=None if expires is None else max(expires - now, 0.0),
            request_hold_off=request_hold_off,
            login_hold_off=login_hold_off,
            logins_in_window=count,
            login_budget=const.LOGIN_BUDGET,
            login_window=const.LOGIN_BUDGET_WINDOW_SECONDS,
            next_login_allowed_in=max(
                (w for w in (request_hold_off, login_hold_off, budget_wait) if w is not None),
                default=0.0,
            ),
            last_login_attempt_age=now - attempts[-1] if attempts else None,
            device_list_refresh_age=self._cache.seconds_since_refresh("owner"),
            stations={sn: self._station_refresh_status(sn) for sn in self._cache.station_serials()},
            regions={
                region: self._region_status(region, sessions[region], in_use, now)
                for region in scopes
            },
        )

    def _region_status(
        self,
        region: str,
        cached: tuple[str, str, str, float | None] | None,
        in_use: list[str],
        now: float,
    ) -> RegionStatus:
        listing = self._listings().get(region, {})
        at = listing.get("at")
        country = self._cache.cloud_sessions().get(region, {}).get("country_code")
        expires = cached[3] if cached else None
        return RegionStatus(
            session_expires_in=None if expires is None else max(expires - now, 0.0),
            devices=_count(listing.get("devices")) if listing else None,
            listed_age=now - at if isinstance(at, (int, float)) and at else None,
            country_code=country if isinstance(country, str) else None,
            in_use=region in in_use,
            suspended=region in self.suspended_regions(),
            login_refused=region in self.refused_regions(),
            logins_in_window=self._login_budget_wait(region)[0],
        )

    def _station_refresh_status(self, station_sn: str) -> StationRefreshStatus:
        return StationRefreshStatus(
            cipher_refresh_age=self._cache.seconds_since_refresh("cipher", station_sn),
            key_refresh_outstanding=self._cache.key_refresh_outstanding(station_sn) is not None,
            next_automatic_refresh_in=max(
                self._cipher_cooldown_left(station_sn),
                self._cache.key_refresh_slow_retry_left(station_sn),
            ),
        )

    async def _hold_off(
        self,
        throttle: const.Throttle,
        code: int,
        message: str,
        path: str,
        *,
        region: str,
        retry_after: float | None = None,
    ) -> NoReturn:
        """Record and persist the hold-off a throttling answer starts, then raise it.

        A per-region login throttle holds off logins to ``region``, the region that
        answered it; another login throttle (a credential lock) every region's logins; a
        request throttle every call.
        """
        kind = "login" if throttle.login_only else "requests"
        seconds = min(max(throttle.seconds, retry_after or 0.0), const.LOCKOUT_HOLD_OFF_SECONDS)
        self._record_hold_off(
            login_only=throttle.login_only,
            seconds=seconds,
            region=region if throttle.per_region else None,
        )
        await self._cache.async_save()
        left = self._held_off(kind, region) or seconds
        _LOGGER.warning(
            "eufy cloud throttled %s (code %s: %s); no %s for %.0f min",
            path,
            code,
            message,
            f"{region} logins" if throttle.login_only else "cloud calls",
            left / 60,
        )
        error = LoginLimitedError if throttle.login_only else RateLimitedError
        raise error(
            f"cloud throttled {path} (code {code}): {message}".rstrip(": "),
            retry_after=left,
            code=code,
        )

    # ── envelope ─────────────────────────────────────────────────────────────

    async def _authenticated_call(
        self,
        host: str,
        path: str,
        payload: Mapping[str, Any] | None,
        *,
        region: str,
        expect_data: bool = True,
        login: bool = True,
    ) -> Any:
        """A signed call on ``region``'s session, with one automatic re-login on an
        expired-token or re-key code (``login``: see :meth:`_with_session`).

        ``expect_data=False`` for endpoints whose success is a bare ``code: 0``.
        """

        async def call(identity: _Identity) -> Any:
            _code, _resp, data = await self._call(host, path, payload, identity)
            return data

        data = await self._with_session(call, region, login=login)
        if data is None and expect_data:
            raise EmptyResponseError(_SUCCESS, "response carried no data", endpoint=path)
        return data

    async def _key_exchange(
        self,
        host: str,
        path: str,
        preset_key: str,
        *,
        auth: _Identity | None = None,
        region: str = const.DEFAULT_REGION,
    ) -> _Identity:
        """Run one ECDH key exchange; returns a transport identity (no token yet) for the
        login scope ``region``, whose install id (:meth:`_install_id`) it carries.

        ``auth`` signs the exchange with a session (the security realm needs one).
        """
        exchange = crypto.start_key_exchange(preset_key)
        _LOGGER.debug(
            "key exchange %s: key_ident %s, client public key %s, client private key %s",
            path,
            Identifier(exchange.key_ident),
            crypto.public_key_hex(exchange.private_key),
            Secret(crypto.private_key_hex(exchange.private_key)),
        )
        _code, _resp, data = await self._call(
            host,
            path,
            None,
            _Identity(key_ident=exchange.key_ident, shared_key="", region=region),
            bootstrap=exchange,
            preset_key=preset_key,
            auth=auth,
        )
        server_pub = _mapping(data or {}, path).get("server_public_key")
        if not isinstance(server_pub, str) or not server_pub:
            raise CloudApiError(_SUCCESS, "key exchange returned no server key", endpoint=path)
        shared_key = crypto.finish_key_exchange(exchange, server_pub, preset_key)
        _LOGGER.debug(
            "key exchange %s: server public key %s, shared_key %s",
            path,
            crypto.preset_decrypt(server_pub, preset_key),
            Secret(shared_key),
        )
        return _Identity(key_ident=exchange.key_ident, shared_key=shared_key, region=region)

    def _install_id(self, region: str) -> str:
        """The ``openudid`` of scope ``region``: the install's own for a region; for an
        extra country a separate id minted once and kept (``cloud.install_ids``). eufy
        holds one session per install id and cluster, so a second country's login under
        the same id would end the first's session."""
        if const.scope_country(region) is None:
            return self._cache.openudid
        ids = self._cache.section("cloud").setdefault(_INSTALL_IDS_KEY, {})
        value = ids.get(region)
        if not isinstance(value, str) or not value:
            value = ids[region] = secrets.token_hex(8)
        return value

    def _headers(
        self,
        identity: _Identity,
        *,
        ts: str,
        nonce: str,
        signature: str,
        authenticated: bool,
        category: bool,
        auth_token: str | None,
        auth_user_id: str | None,
    ) -> dict[str, str]:
        headers = {
            "app-name": const.APP_NAME,
            "app-version": const.APP_VERSION,
            "app_version": const.APP_VERSION,
            "os-type": const.OS_TYPE,
            "os_type": const.OS_TYPE,
            "os-version": const.OS_VERSION,
            "os_version": const.OS_VERSION,
            "model-type": const.MODEL_TYPE,
            "phone-model": const.PHONE_MODEL,
            "phone_model": const.PHONE_MODEL,
            "openudid": self._install_id(identity.region),
            "x-encryption-info": const.ENCRYPTION_INFO,
            "x-key-ident": identity.key_ident,
            "x-request-ts": ts,
            "x-request-once": nonce,
            "x-signature": signature,
            "content-type": "application/json",
            "accept": "application/json",
            "accept-charset": "UTF-8",
            "user-agent": const.USER_AGENT,
            "country": self._country_header(identity.region),
            "language": const.DEFAULT_LANGUAGE,
            "timezone": self._timezone,
        }
        if authenticated and auth_token:
            headers["x-auth-token"] = auth_token
            headers["authorization"] = auth_token
            if auth_user_id:
                headers["gtoken"] = crypto.gtoken(auth_user_id)
        if category:
            headers["category"] = const.CATEGORY
            headers["app-tab"] = const.CATEGORY
        return headers

    async def _call(
        self,
        host: str,
        path: str,
        payload: Mapping[str, Any] | None,
        identity: _Identity,
        *,
        tolerate: frozenset[int] = frozenset(),
        category: bool = False,
        bootstrap: crypto.KeyExchange | None = None,
        preset_key: str | None = None,
        auth: _Identity | None = None,
    ) -> tuple[int, dict[str, Any], Any]:
        """POST one MegaCrypto call; sign, encrypt, and check the body code.

        Returns ``(code, full response, decrypted data)``. Raises the typed error
        for a failing ``code`` unless it is in ``tolerate``; ``data`` is the
        decrypted payload (dict or list), or None on a success with no data.
        Nothing is sent while a hold-off runs.
        """
        self._raise_if_held_off(login=False)
        ts = str(int(time.time()))
        nonce = crypto.new_key_ident()

        if bootstrap is not None and preset_key is not None:
            # Key exchange: plaintext body, signed with the preset. The security
            # realm exchange is authenticated (token + gtoken) but sends no category.
            body = json.dumps({"client_public_key": bootstrap.client_public_key})
            signature = crypto.x_signature(preset_key, ts, nonce, bootstrap.client_public_key)
            authenticated = auth is not None
            auth_token = auth.auth_token if auth else None
            auth_user_id = auth.user_id if auth else None
        else:
            # Established identity: encrypt the body (an empty body still must be
            # encrypted — the gateway decrypts every authenticated body).
            body = crypto.body_encrypt(json.dumps(dict(payload or {})), identity.shared_key)
            signature = crypto.x_signature(crypto.signing_key(identity.shared_key), ts, nonce, body)
            authenticated = identity.auth_token is not None
            auth_token = identity.auth_token
            auth_user_id = identity.user_id

        headers = self._headers(
            identity,
            ts=ts,
            nonce=nonce,
            signature=signature,
            authenticated=authenticated,
            category=category,
            auth_token=auth_token,
            auth_user_id=auth_user_id,
        )
        import aiohttp  # noqa: PLC0415 - deferred so a cache-only run never imports it

        url = f"https://{host}{path}"
        _LOGGER.debug(
            "→ POST %s headers=%s body=%s",
            url,
            Payload(headers),
            Payload(
                {"client_public_key": bootstrap.client_public_key}
                if bootstrap is not None
                else dict(payload or {})
            ),
        )
        _WIRE.debug("POST %s body %s", url, body)
        timeout = aiohttp.ClientTimeout(total=const.HTTP_TIMEOUT_SECONDS)
        started = time.monotonic()
        try:
            async with self._http().post(url, headers=headers, data=body, timeout=timeout) as resp:
                status = resp.status
                retry_after = _retry_after(resp.headers.get("Retry-After"))
                text = await resp.text()
        except (aiohttp.ClientError, TimeoutError) as exc:
            _LOGGER.debug("← %s failed after %.0f ms: %r", path, _ms(started), exc)
            raise CommunicationError(f"cloud request to {path} failed: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise ProtocolError(f"cloud response to {path} was not text: {exc}") from exc
        _WIRE.debug("← %s HTTP %s body %s", path, status, text)
        if status != 200:
            _LOGGER.debug(
                "← %s HTTP %s in %.0f ms (Retry-After %s): %s",
                path,
                status,
                _ms(started),
                retry_after,
                text[:500],
            )

        if status == const.HTTP_TOO_MANY_REQUESTS:
            await self._hold_off(
                _HTTP_429_THROTTLE,
                status,
                "HTTP 429",
                path,
                region=identity.region,
                retry_after=retry_after,
            )
        if status == const.HTTP_UNAUTHORIZED:
            body_code = _loose_code(text)
            if body_code in const.SESSION_REPLACED_CODES:
                raise SessionReplacedError(
                    f"cloud request to {path} returned HTTP 401 (code {body_code})",
                    code=body_code,
                )
            # Any other 401 body: the session is not usable, not taken over.
            raise _SessionExpiredError(
                f"cloud request to {path} returned HTTP 401 (code {body_code})",
                code=body_code or status,
            )
        if status != 200:
            raise classify_refusal(status, _loose_code(text), _message(_loose_object(text)), path)
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise CommunicationError(f"cloud response to {path} was not JSON") from exc
        if not isinstance(parsed, dict):
            raise CommunicationError(f"cloud response to {path} was not an object")

        code = _body_code(parsed.get("code", _SUCCESS), path)
        if code == _SUCCESS or code in tolerate:
            data = self._decode_data(parsed, identity)
            _LOGGER.debug(
                "← %s HTTP 200 code %s in %.0f ms: %s",
                path,
                code,
                _ms(started),
                # The device list is summarised by async_get_devices (full with wire dumps).
                f"<{len(data.get('devices') or []) if isinstance(data, Mapping) else '?'} devices>"
                if path == const.DEVICES_PATH
                else Payload({**parsed, "data": data}),
            )
            if path == const.DEVICES_PATH:
                _WIRE.debug("← %s data %s", path, Payload(data, limit=1_000_000))
            return code, parsed, data
        _LOGGER.debug(
            "← %s HTTP 200 code %s in %.0f ms: %s", path, code, _ms(started), Payload(parsed)
        )
        if (throttle := const.THROTTLE_CODES.get(code)) is not None:
            await self._hold_off(throttle, code, _message(parsed), path, region=identity.region)
        self._raise_for_code(code, parsed, path)
        raise AssertionError("unreachable")  # pragma: no cover

    def _decode_data(self, parsed: Mapping[str, Any], identity: _Identity) -> Any:
        """Decrypt the ``data`` field if it is an encrypted string; pass a dict/list through."""
        data = parsed.get("data")
        if data is None or data == "":
            return None
        if isinstance(data, (dict, list)):
            return data
        if isinstance(data, str):
            plain = crypto.body_decrypt(data, identity.shared_key)
            try:
                return json.loads(plain)
            except ValueError as exc:
                raise ProtocolError("decrypted cloud data was not JSON") from exc
        raise ProtocolError(f"cloud data field was {type(data).__name__}, not an object")

    def _raise_for_code(self, code: int, parsed: Mapping[str, Any], path: str) -> NoReturn:
        msg = _message(parsed)
        if code in const.REKEY_CODES:
            raise _RekeyRequiredError(code, msg, endpoint=path)
        if code in const.SESSION_REPLACED_CODES:
            raise SessionReplacedError(f"cloud session ended (code {code}): {msg}", code=code)
        if code in const.SESSION_EXPIRED_CODES:
            raise _SessionExpiredError(f"cloud session expired (code {code}): {msg}", code=code)
        if code in const.AUTH_FAILURE_CODES:
            raise AuthenticationError(f"cloud rejected the credentials (code {code}): {msg}")
        raise CloudApiError(code, msg, endpoint=path)


def _check_owner_id(owner: str, station_sn: str) -> None:
    """Raise ``ProtocolError`` unless ``owner`` fits the P2P command's account field.

    Every command carries the owner id in a NUL-terminated ``char[128]``, so it must
    be printable ASCII and at most 127 bytes. No narrower shape (40 hex, say) is
    assumed: that width was measured on one account only.
    """
    from ..p2p.messages import _ECB_ACCOUNT_LEN  # noqa: PLC0415 - the field's one definition

    if not (owner and owner.isascii() and owner.isprintable() and len(owner) < _ECB_ACCOUNT_LEN):
        raise ProtocolError(
            f"owner id for {redact_serial(station_sn)} is not printable ASCII of at most "
            f"{_ECB_ACCOUNT_LEN - 1} characters ({len(owner)} characters)"
        )


def _cipher_items(data: object) -> list[object]:
    """The entries of a non-empty ``get_ciphers`` ``data``: a list, ``{"ciphers": [...]}``
    or one entry."""
    items = (
        data
        if isinstance(data, list)
        else _mapping(data, const.CIPHERS_PATH).get("ciphers", [data])
    )
    if not isinstance(items, list):
        raise ProtocolError(f"cloud response to {const.CIPHERS_PATH} has no cipher list")
    return items


def _device_list(data: object) -> list[Mapping[str, Any]]:
    """The entries of a ``get_devs_list`` answer; ``ProtocolError`` for a malformed one.

    A malformed success raises, so it never overwrites a good cached list.
    """
    if isinstance(data, Mapping):
        if "devices" not in data:
            raise ProtocolError(f"cloud response to {const.DEVICES_PATH} has no devices")
        data = data["devices"]
    if data is None:
        return []
    if not isinstance(data, list):
        raise ProtocolError(f"cloud response to {const.DEVICES_PATH} has no device list")
    return [entry for entry in data if isinstance(entry, Mapping)]


def _count(value: object) -> int:
    """A stored device count; 0 for anything else."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _message(parsed: Mapping[str, Any]) -> str:
    return str(parsed.get("msg") or parsed.get("message") or "")


def _ms(started: float) -> float:
    return (time.monotonic() - started) * 1000


def _epoch(value: object) -> str:
    """An epoch-seconds value as local ISO time for a log line, else ``repr``."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
    return repr(value)


def classify_refusal(
    status: int, body_code: int | None, message: str = "", path: str = ""
) -> EufySecurityError:
    """The error for a non-200, non-401 answer (HTTP 401 is a kick-out, handled first).

    HTTP 463, or a re-key body code under any status, is the gateway refusing a lapsed
    key identity (live: HTTP 463 with body 4404): the session retries it once with a new
    key exchange. Anything else is a :class:`CommunicationError` naming the body code.
    """
    if status == const.HTTP_NEED_EXCHANGED_KEY or body_code in const.REKEY_CODES:
        return _RekeyRequiredError(
            body_code or status,
            f"HTTP {status}: {message}".rstrip(": "),
            endpoint=path,
            status=status,
        )
    where = f" (code {body_code})" if body_code is not None else ""
    return CommunicationError(
        f"cloud request to {path or 'the cloud'} returned HTTP {status}{where}"
    )


def _loose_object(text: str) -> Mapping[str, Any]:
    """An error page's JSON object, or an empty one."""
    try:
        parsed = json.loads(text)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _loose_code(text: str) -> int | None:
    """The body ``code`` of an error page if it carries one (a 401 body may not)."""
    code = _loose_object(text).get("code")
    return code if isinstance(code, int) and not isinstance(code, bool) else None


def _retry_after(value: str | None) -> float | None:
    """A ``Retry-After`` in seconds; None when absent or an HTTP date."""
    try:
        seconds = float(value) if value else None
    except ValueError:
        return None
    return seconds if seconds is not None and seconds >= 0 else None


def _body_code(value: object, path: str) -> int:
    """The body ``code`` as an int; :class:`ProtocolError` if it is not a number."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ProtocolError(f"cloud response to {path} carried a non-numeric code")
    try:
        return int(value)
    except ValueError as exc:
        raise ProtocolError(f"cloud response to {path} carried a non-numeric code") from exc
