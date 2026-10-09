"""A snapshot of the cloud state a consumer decides on, read from the cache alone.

Building one never contacts the cloud: :meth:`EufyCloudApi.cloud_status` reads the
session cache, and ``EufySecurity.async_cloud_status`` loads it first. Standard
library only, so the package root can export these names without loading the
cloud client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class LoginNeed(StrEnum):
    """What ``async_login()`` would have to do now.

    ``REPLACED`` takes precedence: a latched account with an unexpired token reports
    it, because every cloud call raises :class:`SessionReplacedError` until a forced
    login or a take-over.
    """

    NONE = "none"
    """A cached, unexpired session: ``async_login()`` sends nothing."""
    CACHED_PASSWORD = "cached_password"  # noqa: S105 — a state name, not a secret
    """No session, but a login can run unattended (a cached or given password)."""
    PASSWORD_REQUIRED = "password_required"  # noqa: S105 — a state name, not a secret
    """No session and no password to run a login with: a human must supply one."""
    REPLACED = "replaced"
    """The session-replaced latch is set: only a forced login or a take-over logs in."""


@dataclass(frozen=True, slots=True, kw_only=True)
class StationRefreshStatus:
    """The automatic key-refresh state of one station (seconds; None when never)."""

    cipher_refresh_age: float | None
    """Seconds since a forced cipher refresh was attempted for this station."""
    key_refresh_outstanding: bool
    """A re-fetched key has not yet been followed by a successful handshake."""
    next_automatic_refresh_in: float
    """Seconds until an automatic cipher refresh is allowed again; 0.0 means now."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RegionStatus:
    """One login scope's session and device list (a region, or an extra country's
    ``<region>:<country>``), as the cache holds them."""

    session_expires_in: float | None
    """Seconds until this region's cached session expires (0.0 once past); None without one."""
    devices: int | None
    """Devices this region's last device list held; None when never listed."""
    listed_age: float | None
    """Seconds since this region's device list was last fetched; None when never."""
    country_code: str | None
    """The ``country_code`` of this region's last login answer, when it carried one."""
    in_use: bool
    """Whether the next device-list fetch asks this region."""
    suspended: bool
    """This region's last device list was empty: asked again only on a rescan, or on
    every fetch with ``scan_regions``."""
    login_refused: bool = False
    """The cloud refused this extra country's login with a plain body code: no login
    or device list asks it again until a rescan or a change of the extra countries."""
    logins_in_window: int = 0
    """Login attempts on this scope's cluster in the budget window (shared by the
    scopes of one cluster)."""
    next_login_allowed_in: float = 0.0
    """Seconds until a login to this scope is allowed: the longest of the request
    hold-off, its cluster's login hold-off and its cluster's budget wait; 0.0 when
    allowed now."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CloudStatus:
    """The login, throttle and refresh state of one account, as the cache holds it.

    Whether a call spent a login attempt is answered by comparing a region's
    ``logins_in_window`` (or ``last_login_attempt_age``) before and after it: the
    attempt is recorded before the login request is sent, whatever the outcome.
    """

    login_need: LoginNeed
    """Over the regions in use: ``NONE`` only when each holds an unexpired session."""
    password_cached: bool
    session_expires_in: float | None
    """Seconds until the first session of a region in use expires (0.0 once past); None
    when none of them holds one."""
    request_hold_off: float | None
    """Seconds left on the hold-off that refuses every cloud call; None when none."""
    login_hold_off: float | None
    """Seconds left on the hold-off that refuses logins to a region in use or to the
    first region (where a forced login goes); None when none."""
    logins_in_window: int
    """Login attempts in the budget window on the cluster that holds the most; the
    budget (``login_budget``) counts per cluster."""
    login_budget: int
    login_window: float
    next_login_allowed_in: float
    """Seconds until a login is not refused locally (hold-offs and budget); 0.0 means now."""
    last_login_attempt_age: float | None
    device_list_refresh_age: float | None
    """Seconds since a forced device-list / owner-id refresh (account-wide)."""
    stations: Mapping[str, StationRefreshStatus]
    """Per station serial the cache holds state for."""
    regions: Mapping[str, RegionStatus] = field(default_factory=dict)
    """Per cloud region (``eu``, ``us``), then per extra country's login scope."""
