"""Protocol constants of the eufy_mega cloud.

Every static value here comes from the eufy Security Android app (``eufy_mega``
v6): the two MegaCrypto preset keys and the login server's public key are the app's
own constants, the header values are what its ktor client sends, and
the body codes are the app's own ``ErrorVo`` / ``NetConstant`` tables. They are
protocol constants shared by every install, not per-account secrets.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum
from typing import Final, NamedTuple

# ── regions and hosts ────────────────────────────────────────────────────────

# The app's production clusters (``MegaEnvironment`` US_PR / EU_PR; the QA ones are
# left out), each with its eufy_security realm gateway (the app's
# ``DEFAULT_SECURITY_CONFIG_DOMAIN`` and ``…_EU``; the US one names no region). One
# login serves one cluster, and each cluster lists only its own devices.
_SECURITY_HOSTS: Final = {"eu": "security-app-eu.eufylife.com", "us": "security-app.eufylife.com"}
REGIONS: Final = tuple(_SECURITY_HOSTS)
DEFAULT_REGION: Final = "eu"

# A login answer may carry a ``mega_domain``; every service host of that cluster is
# the domain with ``mega-`` swapped for ``app-{service}-``, which is how the app builds
# app-passport, app-house, app-push and the rest without a literal host table.
MEGA_DOMAIN_PREFIX: Final = "mega-"


def check_region(region: str) -> str:
    """``region`` if it names a cluster, else ``ValueError``."""
    if region not in REGIONS:
        raise ValueError(f"unknown region {region!r}; valid: {', '.join(REGIONS)}")
    return region


def cluster_host(service: str, region: str, mega_domain: str | None = None) -> str:
    """``app-{service}-{region}-pr.eufy.com``, or the account's own domain rewritten."""
    if mega_domain and mega_domain.startswith(MEGA_DOMAIN_PREFIX):
        return mega_domain.replace(MEGA_DOMAIN_PREFIX, f"app-{service}-", 1)
    return f"app-{service}-{check_region(region)}-pr.eufy.com"


def region_from_mega_domain(mega_domain: str | None) -> str | None:
    """``mega-us-pr.eufy.com`` → ``us``; None when the domain does not name one."""
    if not mega_domain or not mega_domain.startswith(MEGA_DOMAIN_PREFIX):
        return None
    region = mega_domain[len(MEGA_DOMAIN_PREFIX) :].split("-", 1)[0]
    return region if region in REGIONS else None


def security_host(region: str) -> str:
    """The eufy_security realm gateway (``/v3/...``) of ``region``'s cluster."""
    return _SECURITY_HOSTS[check_region(region)]


# ── MegaCrypto keys ──────────────────────────────────────────────────────────

# The eufy.com ("basic") realm preset: encrypts the client public key of the
# unauthenticated key exchange and signs that request.
MEGA_PRESET_KEY: Final = "2500a7d5617812f9d52515b2c8f20a3d"

# The eufy_security realm is a separate MegaCrypto cluster with its own key-ident
# registry and its own preset. An identity minted in the eufy.com realm is refused
# by ``/v3/app/cipher/get_ciphers`` with body code 463, so the cipher fetch runs a
# second, authenticated exchange with this preset.
SECURITY_PRESET_KEY: Final = "118c12c81e211149304bd70a0c071d01"

# The login server's static P-256 public key (uncompressed SEC1 hex). The account
# password is AES-CBC'd under an ECDH secret against it; the app ships the same
# literal in ``MegaAccountNetManager``.
LOGIN_SERVER_PUBLIC_KEY: Final = (
    "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a"
    "3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076"
)

# ── paths ────────────────────────────────────────────────────────────────────

KEY_EXCHANGE_PATH: Final = "/openapi/oauth/key/exchange"
SECURITY_KEY_EXCHANGE_PATH: Final = "/v3/openapi/oauth/key/exchange"
LOGIN_PATH: Final = "/passport/login"
CAPTCHA_PATH: Final = "/passport/generate/captcha"
DEVICES_PATH: Final = "/app/house/get_devs_list"
CIPHERS_PATH: Final = "/v3/app/cipher/get_ciphers"
DSK_KEYS_PATH: Final = "/app/devicerelation/get_dsk_keys"
PUSH_TOKEN_PATH: Final = "/app/push/register_push_token"  # noqa: S105 — a URL path, not a secret
OTA_ROM_PATH: Final = "/app/ota/get_rom_version"
THINGS_PATH: Final = "/app/things/get_things_list"

# The only hosts a thing description's ``profile.plugin_path`` (the handler bundle) is
# downloaded from: the vendor CDN hosts every fetched description names (eufy's own CDN
# and the CloudFront distribution older descriptions point at). A handler on any other
# host is refused before a request. Add a host here only when a fetched TD names it.
HANDLER_HOSTS: Final = frozenset({"aiot-public-cdn-pr.eufy.com", "d7p3a6aivdrwg.cloudfront.net"})

# The OTA subsystem answers a well-formed ``get_rom_version`` with a body ``code`` 0
# whose *data* is either the offered version's ``RomVersionData`` or, when the device is already on
# the newest published firmware, the error object ``{"reason": "error: code = 20004
# …"}``. So 20004 is "up to date", not a transport failure.
OTA_NO_UPGRADE_CODE: Final = 20004


def firmware_ota_type(station_sn: str) -> str:
    """The ``device_type`` a ``get_rom_version`` names for a device in this station's
    house: the station's **firmware kit**, not the cloud model code.

    A HomeBase updates itself and its paired cameras as one bundle, so every device
    behind a hub — the hub and each camera — is queried under the hub's kit type with
    its own serial. A HomeBase 3 (``T8030``) is ``T8030_Kit``;
    other hubs follow ``<model>_Kit`` (``T9000``/``T7000``/``T8025``) **[app]**. Derived
    from the 5-char model prefix so a new hub model needs no table change.
    """
    return f"{station_sn[:5]}_Kit"


# ── headers ──────────────────────────────────────────────────────────────────

APP_NAME: Final = "eufy_mega"
APP_VERSION: Final = "6.0.90_29798"
OS_TYPE: Final = "android"
OS_VERSION: Final = "29"
# A generic Android model; the cloud does not check it (an authenticated call answers
# the same with another value).
PHONE_MODEL: Final = "Pixel 7"
MODEL_TYPE: Final = "PHONE"
USER_AGENT: Final = "ktor-client"
CATEGORY: Final = "eufy_security"
ENCRYPTION_INFO: Final = "algo_ecdh"
DEFAULT_COUNTRY: Final = "US"
DEFAULT_LANGUAGE: Final = "en"
# The app sends the phone's IANA zone. Nothing observed depends on it.
DEFAULT_TIMEZONE: Final = "UTC"

# ── identities ───────────────────────────────────────────────────────────────

# The P2P command-channel cipher of a HomeBase: CONN_INIT names it, and its
# ``ecc_private_key`` unwraps the session key.
CIPHER_ID_P2P: Final = 40

# ── timing ───────────────────────────────────────────────────────────────────

# aiohttp's default is 300 s. security-app sits behind a WAF that stalls rather
# than refuses under pressure, so bound every request explicitly (see EufyCloudApi).
HTTP_TIMEOUT_SECONDS: Final = 30.0

# Used only when the login response carries no ``token_expires_at``. The app
# reuses one session for weeks; a login per start hits code 100028.
DEFAULT_SESSION_TTL: Final = 7 * 24 * 3600.0
# Treat a session as expired this long before the server says it is.
SESSION_EXPIRY_MARGIN: Final = 3600.0

# A forced re-fetch (the cipher, or the device list behind an owner id) is several
# round trips against the cloud and may cost a login; repeated login failures lock
# the account for 24 h. A P2P handshake failure asks for both, so both are throttled.
FORCED_REFRESH_COOLDOWN: Final = 900.0
#: After ``get_ciphers`` answered no key for a station's cipher, the same station and
#: cipher are not asked again for this long (the answer does not change by retrying).
CIPHER_UNAVAILABLE_BACKOFF: Final = 3600.0
# While a station's re-fetched key is still rejected (the key-refresh latch), at most
# one automatic refresh per this window.
KEY_REFRESH_SLOW_RETRY: Final = 24 * 3600.0
#: Seconds between device-list fetches that refresh the state of the stations reached
#: on demand (battery devices): the cloud snapshot is the state source that wakes none.
#: Home Assistant's Reolink integration wakes a battery camera at most every 6 h and
#: otherwise updates when the camera wakes on its own, at most hourly.
CLOUD_STATE_REFRESH: Final = 3600.0
#: Reuse a cached DSK while at least this many seconds remain before it expires; a
#: wake close to the edge fetches a fresh one so the key is still valid on arrival.
DSK_REFRESH_MARGIN: Final = 300.0

# How long every cloud call is held off after the cloud throttles. The limits are
# not published: these follow community reports (a "too fast" block lasts 30-60 min,
# and requests sent during it restart it; 100028 blocks logins for 1-2 h; failed
# logins lock the account for 24 h) and are set at the long end of each.
REQUEST_HOLD_OFF_SECONDS: Final = 3600.0
LOGIN_HOLD_OFF_SECONDS: Final = 2 * 3600.0
LOCKOUT_HOLD_OFF_SECONDS: Final = 24 * 3600.0

# The library's own login budget: at most this many login attempts in a rolling
# window, whatever their outcome. The cloud has answered 100028 on the 4th login
# within a few hours; a challenge (code, then answer) takes two.
LOGIN_BUDGET: Final = 3
LOGIN_BUDGET_WINDOW_SECONDS: Final = 6 * 3600.0


# ── body codes ───────────────────────────────────────────────────────────────


class CloudCode(IntEnum):
    """Body ``code`` values, named after the app's ``ErrorVo`` / ``NetConstant``.

    The cloud reports nearly every failure as HTTP 200 with one of these.
    """

    SUCCESS = 0
    SESSION_TIMEOUT = 401
    TS_NOT_MATCH = 461
    NEED_EXCHANGED_KEY = 463
    NEED_NEGOTIATE_KEY = 4404
    SIGNATURE_ERROR = 4416
    INPUT_PARAM_INVALID = 10000
    PASSWORD_ERROR_MUCH = 10019
    EMAIL_NOT_REGISTERED = 22008
    EMAIL_OR_PASSWORD_ERROR = 26006
    ACCOUNT_INACTIVATED = 26015
    # Not named in the app: its token check logs out on it. Live with HTTP 401 after
    # another client logged in with the account.
    SESSION_REPLACED = 26084
    VERIFY_CODE_ERROR = 26050
    VERIFY_CODE_EXPIRED = 26051
    NEED_VERIFY_CODE = 26052
    VERIFY_CODE_MAX = 26053
    VERIFY_CODE_NONE_MATCH = 26054
    VERIFY_PASSWORD_ERROR = 26055
    EMAIL_UNACTIVATED = 26105
    MEGA_EMAIL_OR_PASSWORD_ERROR = 26108
    API_REQUEST_LIMIT = 26145
    VERIFICATION_CODE_EXPIRED = 26167
    MAX_LOGIN_LIMIT = 100028
    LOGIN_ENCRYPTION_FAIL = 100029
    LOGIN_DECRYPTION_FAIL = 100030
    LOGIN_NEED_CAPTCHA = 100032
    LOGIN_CAPTCHA_ERROR = 100033
    PASSWORD_ERROR_5 = 100056
    # Not in the app's tables: community-reported with "The request is too fast.
    # Please stop and have a rest".
    REQUEST_TOO_FAST = 250999


# The login needs an e-mailed code (a wrong or expired one asks again).
VERIFY_CODE_CODES: Final = frozenset(
    {
        CloudCode.NEED_VERIFY_CODE,
        CloudCode.VERIFY_CODE_ERROR,
        CloudCode.VERIFY_CODE_EXPIRED,
        CloudCode.VERIFY_CODE_NONE_MATCH,
        CloudCode.VERIFICATION_CODE_EXPIRED,
    }
)
# The login needs a captcha answer (a wrong one gets a new captcha).
CAPTCHA_CODES: Final = frozenset({CloudCode.LOGIN_NEED_CAPTCHA, CloudCode.LOGIN_CAPTCHA_ERROR})
# The credentials are wrong or the account cannot log in as it is.
AUTH_FAILURE_CODES: Final = frozenset(
    {
        CloudCode.EMAIL_NOT_REGISTERED,
        CloudCode.EMAIL_OR_PASSWORD_ERROR,
        CloudCode.ACCOUNT_INACTIVATED,
        CloudCode.VERIFY_PASSWORD_ERROR,
        CloudCode.EMAIL_UNACTIVATED,
        CloudCode.MEGA_EMAIL_OR_PASSWORD_ERROR,
    }
)


class Throttle(NamedTuple):
    """How a throttling answer is held off: which calls, and for how long."""

    login_only: bool
    seconds: float
    per_region: bool = False
    """A login throttle that holds off only the region that answered it (a count of
    logins); a credential lock holds off every region's logins."""


# Throttling and account locks: hold off, never retry. A request throttle stops
# every call; a login throttle stops logins while a valid session keeps working.
THROTTLE_CODES: Final[Mapping[int, Throttle]] = {
    CloudCode.API_REQUEST_LIMIT: Throttle(login_only=False, seconds=REQUEST_HOLD_OFF_SECONDS),
    CloudCode.REQUEST_TOO_FAST: Throttle(login_only=False, seconds=REQUEST_HOLD_OFF_SECONDS),
    CloudCode.MAX_LOGIN_LIMIT: Throttle(
        login_only=True, seconds=LOGIN_HOLD_OFF_SECONDS, per_region=True
    ),
    CloudCode.PASSWORD_ERROR_MUCH: Throttle(login_only=True, seconds=LOCKOUT_HOLD_OFF_SECONDS),
    CloudCode.PASSWORD_ERROR_5: Throttle(login_only=True, seconds=LOCKOUT_HOLD_OFF_SECONDS),
    CloudCode.VERIFY_CODE_MAX: Throttle(login_only=True, seconds=LOCKOUT_HOLD_OFF_SECONDS),
}
# HTTP 429 is a request throttle too; its Retry-After is honoured when longer.
HTTP_TOO_MANY_REQUESTS: Final = 429
# Another client's login ended this session: never log in again automatically.
# HTTP 401 counts whatever the body says (the app logs out on it too).
SESSION_REPLACED_CODES: Final = frozenset({CloudCode.SESSION_REPLACED})
HTTP_UNAUTHORIZED: Final = 401

# The auth token is no longer valid: one re-login is allowed. These are the ONLY
# codes that may cost an automatic login; a credential rejection never does (each
# failed login counts toward the lock), and neither does a re-key (below).
SESSION_EXPIRED_CODES: Final = frozenset({CloudCode.SESSION_TIMEOUT})
# The gateway no longer knows the key ident (live: HTTP 463 with body 4404 "get identity
# error", 72 h after the key exchange on one account; the app's 463 handler re-keys). The
# client runs a NEW KEY EXCHANGE, keeps the auth token, and retries once, as the app does:
# verified live to restore the device list with no login. Never a login.
REKEY_CODES: Final = frozenset({CloudCode.NEED_EXCHANGED_KEY, CloudCode.NEED_NEGOTIATE_KEY})
# The HTTP status the gateway refuses a lapsed key identity with (the app's
# CODE_NEED_EXCHANGED_KEY); its body carries one of REKEY_CODES.
HTTP_NEED_EXCHANGED_KEY: Final = 463
