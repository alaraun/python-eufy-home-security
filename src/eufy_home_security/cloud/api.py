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
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
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
    SessionReplacedError,
)
from ..storage import SessionCache
from . import const, crypto
from .const import DSK_REFRESH_MARGIN
from .models import REGION_KEY, CloudDevice, FirmwareUpdate
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


class _SessionExpiredError(AuthenticationError):
    """The server no longer accepts the auth token (one re-login is allowed)."""


def _mapping(data: object, path: str) -> Mapping[str, Any]:
    """``data`` as a mapping, or :class:`ProtocolError` naming the endpoint."""
    if not isinstance(data, Mapping):
        raise ProtocolError(
            f"cloud response to {path} carried {type(data).__name__}, not an object"
        )
    return data


class EufyCloudApi:
    """Async client for the eufy_mega ("eufy_security") cloud.

    The injected ``session`` and ``cache`` are never created here. Call
    :meth:`async_login` before anything else (it reuses cached sessions).

    ``region`` pins every call to that region's cluster. Without it, the first
    device-list fetch asks every region; a region that lists no devices is then
    *suspended*: no later fetch or login asks it again until a rescan
    (``rescan_regions=True``) or, with ``scan_regions``, every fetch asks every region
    (a device added on another region's cluster then appears; a region without a
    usable session costs a login).
    """

    def __init__(
        self,
        session: HttpSession,
        cache: SessionCache,
        email: str,
        password: PasswordSource | None,
        *,
        country: str = "",
        region: str | None = None,
        scan_regions: bool = False,
        install: InstallState | None = None,
    ) -> None:
        """``install`` shares a request hold-off with the other accounts of the process.

        ``region`` not in :data:`~.const.REGIONS`: ``ValueError``.
        """
        self._session = session
        self._cache = cache
        self._install = install
        self._email = email.strip()
        self._password = password
        self._country = country or const.DEFAULT_COUNTRY
        self._region_override = None if region is None else const.check_region(region)
        self._scan_regions = scan_regions
        self._identities: dict[str, _Identity] = {}
        """The live session identity per region."""
        self._challenge_region: str | None = None
        """The region whose login raised the last unanswered challenge."""
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
        cached devices, else :data:`~.const.DEFAULT_REGION`. A forced login and a
        reauthentication go there."""
        if self._region_override:
            return self._region_override
        held = self.regions_with_devices()
        return held[0] if held else const.DEFAULT_REGION

    def _listings(self) -> dict[str, dict[str, Any]]:
        """Each listed region's last device-list record (``devices``, ``at``)."""
        listed = self._cache.section("cloud").get("listed")
        if not isinstance(listed, dict):
            return {}
        return {r: v for r, v in listed.items() if r in const.REGIONS and isinstance(v, dict)}

    def regions_with_devices(self) -> list[str]:
        """The regions whose last device list held devices, in :data:`~.const.REGIONS` order."""
        listings = self._listings()
        return [r for r in const.REGIONS if _count(listings.get(r, {}).get("devices"))]

    def suspended_regions(self) -> list[str]:
        """The regions whose last device list was empty: asked again only on a rescan."""
        listings = self._listings()
        return [
            r for r in const.REGIONS if r in listings and not _count(listings[r].get("devices"))
        ]

    def regions_to_list(self, *, rescan: bool = False) -> list[str]:
        """The regions the next device-list fetch asks: the override alone; every region
        on a ``rescan`` or with ``scan_regions``; else every region not suspended."""
        if self._region_override:
            return [self._region_override]
        if rescan or self._scan_regions:
            return list(const.REGIONS)
        suspended = self.suspended_regions()
        return [r for r in const.REGIONS if r not in suspended]

    def device_region(self, device_sn: str) -> str:
        """The region serving ``device_sn``: the override, else the region that listed it,
        else :attr:`region`."""
        if self._region_override:
            return self._region_override
        for entry in self._cache.cached_devices() or ():
            if entry.get("device_sn") == device_sn and entry.get(REGION_KEY) in const.REGIONS:
                return str(entry[REGION_KEY])
        return self.region

    def _regions_in_service(self) -> list[str]:
        """The regions whose devices this account serves: :attr:`region` before any
        listing, none once every region is suspended."""
        if self._region_override:
            return [self._region_override]
        if not self._listings():
            return [self.region]
        return self.regions_with_devices()

    def _host(self, service: str, region: str) -> str:
        """``service``'s host on ``region``'s cluster, from the session's ``mega_domain``
        when that names the same region."""
        domain = self._cache.cloud_sessions().get(region, {}).get("mega_domain")
        if not (isinstance(domain, str) and const.region_from_mega_domain(domain) == region):
            domain = None
        return const.cluster_host(service, region, domain)

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
        regions log in only without a usable cached session.

        Raises :class:`LoginChallengeError` when the account needs an e-mailed code
        or a captcha — re-call with the answer and the challenge's ``login_id``; the
        answer goes to the region that asked (the challenge's ``region``) and the
        other regions follow —
        :class:`AuthenticationError` on bad credentials,
        :class:`RateLimitedError` when throttled or locked, and
        :class:`SessionReplacedError` after another client took the session over
        (only ``force`` logs in again then, and the latch is released only once that
        login succeeds).
        """
        answering = bool(verify_code or (captcha_id and captcha_answer))
        async with self._login_lock:
            self._take_over_or_raise_if_replaced(force)
            first: str | None = None
            if answering or force:
                first = (self._challenge_region if answering else None) or self.region
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
            for region in self.regions_to_list():
                if region == first or self._load_cached_session(region):
                    continue
                await self._do_login(region, verify_code=None, captcha_id=None, captcha_answer=None)

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

        A challenge answer goes to the region that asked. Success replaces that
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
            await self._do_login(
                (self._challenge_region if answering else None) or self.region,
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

    async def _do_login(
        self,
        region: str,
        *,
        verify_code: str | None,
        captcha_id: str | None,
        captcha_answer: str | None,
        login_id: str | None = None,
        password: str | None = None,
    ) -> None:
        """One password login to ``region`` (``password`` overrides every source).

        Callers hold ``_login_lock``.
        """
        self._raise_if_held_off(login=True, region=region)
        password, source = (
            (password, "reauthenticating") if password else await self._login_password()
        )
        _LOGGER.info(
            "logging in to the eufy cloud as %s (password %s, region %s)",
            Secret(self._email),
            source,
            region,
        )
        _LOGGER.debug(
            "login: password %s, openudid %s, %d login(s) in the budget window",
            Credential(password),
            Identifier(self._cache.openudid),
            len(self._cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS, region)),
        )
        identity = await self._key_exchange(
            self._host("openapi", region), const.KEY_EXCHANGE_PATH, const.MEGA_PRESET_KEY
        )
        identity.region = region
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
            "ab": region,
            "client_secret_info": {"public_key": wrapped.client_public_key},
            "answer": captcha_answer or "",
            "captcha_id": captcha_id or "",
            "verify_code": verify_code or "",
            "login_id": login_id or "",
        }
        # Counted before it is sent: a login that times out may still have landed.
        self._cache.note_login(const.LOGIN_BUDGET_WINDOW_SECONDS, region)
        await self._cache.async_save()
        try:
            code, resp, data = await self._call(
                self._host("passport", region),
                const.LOGIN_PATH,
                payload,
                identity,
                tolerate=const.VERIFY_CODE_CODES | const.CAPTCHA_CODES,
            )
        except AuthenticationError as err:
            if not isinstance(err, _SessionExpiredError) and self._cache.password == password:
                # A rejected cached password is never tried again: each failure
                # counts toward the account lock.
                _LOGGER.warning("the cloud rejected the cached password; forgetting it")
                self._cache.drop_password()
                await self._cache.async_save()
            raise
        if code in const.CAPTCHA_CODES or code in const.VERIFY_CODE_CODES:
            self._challenge_region = region
        if code in const.CAPTCHA_CODES:
            _LOGGER.info("%s login needs a captcha (code %s)", region, code)
            await self._raise_captcha_challenge(identity, code, self._extract_login_id(resp, data))
        if code in const.VERIFY_CODE_CODES:
            _LOGGER.info("%s login needs an e-mailed verification code (code %s)", region, code)
            raise LoginChallengeError(
                "verify_code",
                login_id=self._extract_login_id(resp, data),
                code=code,
                region=region,
            )
        if not data:
            raise EmptyResponseError(code, "login returned no data", endpoint=const.LOGIN_PATH)
        if self._challenge_region == region:
            self._challenge_region = None
        self._store_session(identity, _mapping(data, const.LOGIN_PATH))
        self._cache.set_password(password)
        await self._cache.async_save()

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

    async def _raise_captcha_challenge(self, identity: _Identity, code: int, login_id: str) -> None:
        cid, image = await self._fetch_captcha(identity)
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

    def _store_session(self, identity: _Identity, data: Mapping[str, Any]) -> None:
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
            }
        )
        if isinstance(mega_domain, str) and mega_domain:
            cloud["mega_domain"] = mega_domain
        if isinstance(country_code, str) and country_code:
            cloud["country_code"] = country_code
        _LOGGER.info(
            "%s cloud login ok (user %s, token expires %s, mega_domain %r, country_code %r)",
            region,
            redact(identity.user_id),
            _epoch(ttl),
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

    async def _ensure_session(self, region: str) -> _Identity:
        """``region``'s live session: the one held, the cached one, or a new login."""
        self._raise_if_replaced()
        identity = self._identities.get(region)
        if identity is not None and identity.auth_token:
            return identity
        async with self._login_lock:
            self._raise_if_replaced()
            # Re-check: another task may have logged in while this one waited.
            identity = self._identities.get(region)
            if not (identity and identity.auth_token) and not self._load_cached_session(region):
                await self._do_login(region, verify_code=None, captcha_id=None, captcha_answer=None)
            identity = self._identities.get(region)
        if identity is None:  # pragma: no cover — login raises rather than return
            raise AuthenticationError("no cloud session after login")
        return identity

    async def _with_session[T](
        self, operation: Callable[[_Identity], Awaitable[T]], region: str
    ) -> T:
        """Run ``operation`` on ``region``'s session, retrying once for each recoverable refusal.

        A session-expired code costs one re-login. A re-key answer (HTTP 463, body 463 /
        4404: the gateway forgot the key identity) costs one new key exchange on the
        same auth token, never a login, and a second refusal raises
        :class:`KeyExchangeRefusedError`. A credential rejection, a throttle, a session
        another client took over, or any other failure propagates at once.
        """
        identity = await self._ensure_session(region)
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
                if relogged:
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
                    self._host("openapi", region), const.KEY_EXCHANGE_PATH, const.MEGA_PRESET_KEY
                )
            except _RekeyRequiredError as refused:
                raise KeyExchangeRefusedError(
                    refused.code, refused.message, endpoint=refused.endpoint, status=refused.status
                ) from refused
            fresh.auth_token = failed.auth_token
            fresh.user_id = failed.user_id
            fresh.region = region
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

        Asks each region of :meth:`regions_to_list` (``rescan_regions``: every region)
        and tags each device with the region that listed it (:attr:`CloudDevice.region`;
        a serial two regions list keeps the first region's entry). A region that lists
        no devices is suspended. With every region suspended nothing is sent and the
        cached (empty) list is returned. Nothing is cached unless every region asked
        answered.
        """
        regions = self.regions_to_list(rescan=rescan_regions)
        if not regions:
            _LOGGER.info(
                "device list not fetched: every region (%s) listed no devices last time; "
                "a rescan asks them again",
                ", ".join(const.REGIONS),
            )
            return [CloudDevice.from_api(d) for d in self._cache.cached_devices() or ()]
        entries: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        listed_by: dict[str, str] = {}
        for region in regions:
            data = await self._authenticated_call(
                self._host("house", region), const.DEVICES_PATH, {"device_sn": ""}, region=region
            )
            raw = _device_list(data)
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

        ``refresh`` honours the per-station refresh cooldown: called again inside it
        for the same station, it raises :class:`RefreshCooldownError` (``code`` 0) rather
        than risk a login-shaped fetch that could lock the account.

        An empty answer raises :class:`CipherUnavailableError`; for
        :data:`~.const.CIPHER_UNAVAILABLE_BACKOFF` after it, the same station and cipher
        raise it again without a request (``refresh`` included).
        """
        if not refresh:
            cached = self._cache.cipher_key(station_sn, cipher_id)
            if cached:
                _LOGGER.debug(
                    "cipher %d for %s from the cache: %s",
                    cipher_id,
                    redact_serial(station_sn),
                    Secret(cached),
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
            key = await self._fetch_cipher(station_sn, cipher_id, owner)
        except CipherUnavailableError as err:
            self._cipher_unavailable[(station_sn, cipher_id)] = (time.monotonic(), err.owner_source)
            raise
        _LOGGER.debug(
            "cipher %d for %s fetched: ecc_private_key %s",
            cipher_id,
            redact_serial(station_sn),
            Secret(key),
        )
        self._cache.set_cipher_key(station_sn, cipher_id, key)
        await self._cache.async_save()
        return key

    async def _fetch_cipher(self, station_sn: str, cipher_id: int, owner_user_id: str) -> str:
        """Run the security-realm key exchange and fetch one cipher's ecc key.

        The exchange and the fetch share one session retry: a server-revoked token
        costs one re-login here, not an :class:`AuthenticationError` for days.
        """
        payload = {
            "cipher_ids": [cipher_id],
            "user_id": owner_user_id,
            "station_sn": station_sn,
        }

        region = self.device_region(station_sn)

        async def fetch(base: _Identity) -> Any:
            sec = await self._security_identity(base)
            _code, _resp, data = await self._call(
                const.security_host(region),
                const.CIPHERS_PATH,
                payload,
                sec,
                category=True,
            )
            return data

        data = await self._with_session(fetch, region)
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
        items = (
            data
            if isinstance(data, list)
            else _mapping(data, const.CIPHERS_PATH).get("ciphers", [data])
        )
        if not isinstance(items, list):
            raise ProtocolError(f"cloud response to {const.CIPHERS_PATH} has no cipher list")
        for item in items:
            if isinstance(item, Mapping) and str(item.get("cipher_id")) == str(cipher_id):
                key = item.get("ecc_private_key")
                if isinstance(key, str) and key:
                    return key
        raise EmptyResponseError(
            _SUCCESS,
            f"cipher {cipher_id} for {redact_serial(station_sn)} carried no ecc_private_key",
            endpoint=const.CIPHERS_PATH,
        )

    async def _security_identity(self, base: _Identity) -> _Identity:
        """Mint an eufy_security-realm identity on the session ``base``."""
        _LOGGER.debug(
            "security realm: key exchange on session key_ident %s", Identifier(base.key_ident)
        )
        sec = await self._key_exchange(
            const.security_host(base.region),
            const.SECURITY_KEY_EXCHANGE_PATH,
            const.SECURITY_PRESET_KEY,
            auth=base,
        )
        sec.auth_token = base.auth_token
        sec.user_id = base.user_id
        sec.region = base.region
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
        ``region``); requests also see the install's."""
        own = self._cache.held_off_for(kind, longest=const.LOCKOUT_HOLD_OFF_SECONDS, region=region)
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
            for held in [region] if region is not None else const.REGIONS:
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
        recent = self._cache.recent_logins(window, region)
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
            _LOGGER.debug(
                "%s login refused locally: budget of %d spent", region, const.LOGIN_BUDGET
            )
            raise LoginLimitedError(
                f"{count} {region} logins in the last "
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
        asks (:meth:`regions_to_list`). A password counts as available when one is
        cached or a string was given; a password callable is a prompt, so without
        either the need is ``PASSWORD_REQUIRED``. The cache must be loaded.
        """
        now = time.time()
        in_use = self.regions_to_list()
        sessions = {region: self._cached_session(region) for region in const.REGIONS}
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
        login_hold_off = max(
            (left for r in in_use if (left := self._held_off("login", r)) is not None),
            default=None,
        )
        budget_wait = max(
            (left for r in in_use if (left := self._login_budget_wait(r)[1]) is not None),
            default=None,
        )
        count = len(self._cache.recent_logins(const.LOGIN_BUDGET_WINDOW_SECONDS))
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
                for region in const.REGIONS
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
    ) -> Any:
        """A signed call on ``region``'s session, with one automatic re-login on an
        expired-token or re-key code.

        ``expect_data=False`` for endpoints whose success is a bare ``code: 0``.
        """

        async def call(identity: _Identity) -> Any:
            _code, _resp, data = await self._call(host, path, payload, identity)
            return data

        data = await self._with_session(call, region)
        if data is None and expect_data:
            raise EmptyResponseError(_SUCCESS, "response carried no data", endpoint=path)
        return data

    async def _key_exchange(
        self, host: str, path: str, preset_key: str, *, auth: _Identity | None = None
    ) -> _Identity:
        """Run one ECDH key exchange; returns a transport identity (no token yet).

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
            _Identity(key_ident=exchange.key_ident, shared_key=""),
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
        return _Identity(key_ident=exchange.key_ident, shared_key=shared_key)

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
            "openudid": self._cache.openudid,
            "x-encryption-info": const.ENCRYPTION_INFO,
            "x-key-ident": identity.key_ident,
            "x-request-ts": ts,
            "x-request-once": nonce,
            "x-signature": signature,
            "content-type": "application/json",
            "accept": "application/json",
            "accept-charset": "UTF-8",
            "user-agent": const.USER_AGENT,
            "country": self._country,
            "language": const.DEFAULT_LANGUAGE,
            "timezone": const.DEFAULT_TIMEZONE,
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
                const.Throttle(login_only=False, seconds=const.REQUEST_HOLD_OFF_SECONDS),
                status,
                "HTTP 429",
                path,
                region=identity.region,
                retry_after=retry_after,
            )
        if status == const.HTTP_UNAUTHORIZED:
            body_code = _loose_code(text)
            raise SessionReplacedError(
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
            raise _SessionExpiredError(f"cloud session expired (code {code}): {msg}")
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
