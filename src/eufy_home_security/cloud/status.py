"""A snapshot of the cloud state a consumer decides on, read from the cache alone.

Building one never contacts the cloud: :meth:`EufyCloudApi.cloud_status` reads the
session cache, and ``EufySecurity.async_cloud_status`` loads it first. Standard
library only, so the package root can export these names without loading the
cloud client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
class CloudStatus:
    """The login, throttle and refresh state of one account, as the cache holds it.

    Whether a call spent a login attempt is answered by comparing
    ``logins_in_window`` before and after it: the attempt is recorded before the
    login request is sent, whatever the outcome.
    """

    login_need: LoginNeed
    password_cached: bool
    session_expires_in: float | None
    """Seconds until the cached session expires (0.0 once past); None without one."""
    request_hold_off: float | None
    """Seconds left on the hold-off that refuses every cloud call; None when none."""
    login_hold_off: float | None
    """Seconds left on the hold-off that refuses logins; None when none."""
    logins_in_window: int
    login_budget: int
    login_window: float
    next_login_allowed_in: float
    """Seconds until a login is not refused locally (hold-offs and budget); 0.0 means now."""
    last_login_attempt_age: float | None
    device_list_refresh_age: float | None
    """Seconds since a forced device-list / owner-id refresh (account-wide)."""
    stations: Mapping[str, StationRefreshStatus]
    """Per station serial the cache holds state for."""
