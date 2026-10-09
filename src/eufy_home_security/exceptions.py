"""Exception hierarchy.

Every error the library raises derives from :class:`EufySecurityError`, and each
branch maps onto one decision a caller (Home Assistant, in practice) has to make:

* :class:`AuthenticationError` — the credentials are wrong or need a human
  (reauthenticate).
* :class:`SessionReplacedError` — another client logged in with this account (a
  human decides; not a reauth).
* :class:`NoCachedSessionError` — there is no usable cached cloud session and the
  caller chose not to log in; nothing was sent (skip, not a reauth).
* :class:`CommunicationError` — the network or the station did not answer
  (retry later / mark unavailable).
* :class:`ProtocolError` — bytes arrived that do not decode (a bug, or a firmware
  change worth reporting).
* :class:`CommandError` — the station received a command and did not apply it.
* :class:`RecordNotFoundError` — no such record or media; its subclass
  :class:`StillNotWrittenError` means not yet (ask again later).
"""

from __future__ import annotations

from typing import ClassVar, Literal


class EufySecurityError(Exception):
    """Base class for every error raised by this library."""


# ── cloud ────────────────────────────────────────────────────────────────────


class CloudError(EufySecurityError):
    """The eufy cloud could not complete a request."""


class CloudApiError(CloudError):
    """The cloud answered with a non-success body code.

    The eufy cloud reports most failures as HTTP 200 with a non-zero ``code`` in
    the body, so this carries that code rather than an HTTP status.
    """

    def __init__(self, code: int, message: str = "", *, endpoint: str = "") -> None:
        self.code = code
        self.message = message
        self.endpoint = endpoint
        where = f" ({endpoint})" if endpoint else ""
        super().__init__(f"cloud error {code}{where}: {message}".rstrip(": "))


class EmptyResponseError(CloudApiError):
    """The cloud reported success but returned no data.

    Seen when a request names an identity the account cannot see — e.g. asking for
    a station's cipher under a shared member's own user id instead of the owner's.
    """


class CipherUnavailableError(EmptyResponseError):
    """The cloud holds no key for the cipher a station named, under the owner id asked.

    ``get_ciphers`` answered success with no data for ``cipher_id`` under the owner id
    asked: ``owner_source`` is ``"own user id"`` when that is this account's own id,
    else ``"member.admin_user_id"`` (another account owns the station). Retrying
    does not change that answer, so the same station and cipher are not asked again
    for ``retry_after`` seconds: until then this is raised without a request. Not a
    reauth; the share or the station binding needs a human.
    """

    def __init__(
        self,
        message: str,
        *,
        cipher_id: int,
        owner_source: str,
        retry_after: float,
        endpoint: str = "",
    ) -> None:
        self.cipher_id = cipher_id
        self.owner_source = owner_source
        self.retry_after = retry_after
        super().__init__(0, message, endpoint=endpoint)


class KeyExchangeRefusedError(CloudApiError):
    """The cloud gateway refused this client's key identity, and a new one did not help.

    The gateway answers HTTP 463 (body code 4404 ``get identity error`` or 463) once the
    identity from the last key exchange has lapsed (after 72 hours, in one sample).
    The library then runs a new key exchange, keeps the auth token, and retries once, as
    the eufy app does; this error means that retry was refused as well. The token and
    credentials were not the problem, so it is not a reauth, and no login was attempted.
    ``code`` is the body code, ``status`` the HTTP status (200 when the code came in a
    success envelope).
    """

    def __init__(
        self, code: int, message: str = "", *, endpoint: str = "", status: int = 200
    ) -> None:
        self.status = status
        super().__init__(code, message, endpoint=endpoint)


type RateLimitOrigin = Literal["cloud", "hold_off", "budget", "cooldown"]
"""Who refused a call: ``"cloud"`` eufy answered with a throttle code now; ``"hold_off"``
the library refused it locally because eufy throttled earlier; ``"budget"`` the library's
own login budget refused it, eufy was not asked; ``"cooldown"`` the library's per-station
refresh cooldown refused it."""


class RateLimitedError(CloudError):
    """The cloud is throttling this account, or the library is holding off after it did.

    Once the cloud throttles, every later call is refused locally until the back-off
    expires: requests sent during a block reportedly restart it. ``retry_after`` is
    the seconds left (None when unknown); ``code`` is the body code (or HTTP status)
    that started it, 0 for a limit the library applies on its own. ``origin`` says
    who refused (:data:`RateLimitOrigin`); ``scope`` is the login scope a refused
    login was for (``"eu"``, ``"eu:CH"``), None when the refusal covers every call
    or every scope's logins.
    """

    _ORIGIN: ClassVar[RateLimitOrigin] = "cloud"

    def __init__(
        self,
        message: str = "",
        *,
        retry_after: float | None = None,
        code: int = 0,
        scope: str | None = None,
        origin: RateLimitOrigin | None = None,
    ) -> None:
        self.retry_after = retry_after
        self.code = code
        self.scope = scope
        self.origin: RateLimitOrigin = origin or self._ORIGIN
        super().__init__(message or "the eufy cloud is rate-limiting this account")


class RefreshCooldownError(RateLimitedError):
    """A forced cipher-key refresh was refused by the library's own per-station cooldown.

    Not a eufy throttle: nothing was sent and the cloud limits are untouched (``code``
    is 0, ``origin`` ``"cooldown"``). It never becomes a ``CloudProblem``; wait
    ``retry_after``.
    """

    _ORIGIN: ClassVar[RateLimitOrigin] = "cooldown"


class LoginLimitedError(RateLimitedError):
    """Logins are blocked: too many of them, or too many failed ones.

    Not a credential problem, so not a reauth: wait ``retry_after``. Other cloud
    calls on a still-valid session keep working.
    """


class SessionReplacedError(CloudError):
    """Another client logged in with this account and the cloud ended this session.

    The eufy cloud keeps one session per account: a login from the app or another
    integration kicks the previous one out. The credentials are fine, so this is not
    a reauth, and nothing logs in again by itself — two clients on one account would
    kick each other out in a loop into the login lock. Every cloud call raises this
    until an explicit ``async_login(force=True)``; give each client its own account
    (shared from the owner) instead. ``code`` is the body code (or HTTP status).
    """

    def __init__(self, message: str = "", *, code: int = 0) -> None:
        self.code = code
        super().__init__(message or "another client logged in with this account")


class NoCachedSessionError(CloudError):
    """There is no usable cached cloud session and the caller chose not to log in.

    Raised by calls that must never spend a login, such as the thing
    description fetch: with no cached session, an unloaded session cache or one
    expiring within the safety margin, they refuse before sending anything; when the
    cloud answers the cached session as expired, they raise it instead of logging in
    again. Also raised, with nothing sent, for a login asked for a region that is no
    login scope of the account. It is not an :class:`AuthenticationError` — the
    credentials are not in question, so it must not start a reauth; the next ordinary
    call that may log in restores the session.
    """


class AuthenticationError(CloudError):
    """The account credentials were rejected."""


class SessionRejectedError(AuthenticationError):
    """The cloud no longer accepts this session and one new login did not help.

    HTTP 401 without the session-replaced code (26084), or a session-expired code,
    met again right after a fresh login. ``code`` is the answer's body code (0 when
    none). Not a takeover by another client: :class:`SessionReplacedError` is that.
    """

    def __init__(self, message: str, *, code: int = 0) -> None:
        self.code = code
        super().__init__(message)


class LoginChallengeError(AuthenticationError):
    """Login needs a human answer: an e-mailed verification code or a captcha.

    Re-run the login with the answer; ``login_id`` must be carried across both
    calls (it may be empty). ``captcha_image`` is a data URI when the challenge is a
    captcha. For a verification code the library has asked the cloud to e-mail one
    (``code_requested``); False when the login answer gave it no session to ask with.
    ``region`` is the login scope whose login asked (a region, or an extra country's
    ``<region>:<country>``); the answer goes there, also from a new client on the
    same cache.
    """

    def __init__(
        self,
        kind: str,
        *,
        login_id: str = "",
        captcha_id: str = "",
        captcha_image: str = "",
        code: int = 0,
        region: str = "",
        code_requested: bool = False,
    ) -> None:
        self.kind = kind
        self.code_requested = code_requested
        self.region = region
        self.login_id = login_id
        self.captcha_id = captcha_id
        self.captcha_image = captcha_image
        self.code = code
        super().__init__(f"login requires {kind}")


# ── transport ────────────────────────────────────────────────────────────────


class CommunicationError(EufySecurityError):
    """The network or the device did not answer."""


class StationUnreachableError(CommunicationError):
    """The station did not answer LAN discovery or dropped the session."""


class DeviceTimeoutError(CommunicationError, TimeoutError):
    """A request was sent but no application-level answer arrived in time."""


class DeviceBusyError(CommunicationError):
    """The camera is busy with another capture; nothing was sent.

    Raised at once instead of queueing, so a second request never moves a pan/tilt
    camera away from the view the first one is capturing: another capture, or a
    command that turns or zooms the camera (a pan/tilt step, a go-to, a preset store
    or default-preset write, a live open at a preset, a zoom).
    """


class LiveStreamLimitError(CommunicationError):
    """The station already carries this library's maximum of extra sessions; nothing was sent.

    ``limit`` is the number of extra sessions (live streams and recording downloads) this
    library opens to one station at most (:attr:`~.p2p.session.StationSession.max_sessions`
    - 1). A cap of the library, not a refusal by the station: retry when one of them
    closes, or raise the budget.
    """

    def __init__(self, message: str = "", *, limit: int) -> None:
        self.limit = limit
        super().__init__(message)


class ProtocolError(EufySecurityError):
    """A frame could not be decoded or decrypted."""


class HandshakeError(ProtocolError):
    """The P2P session key could not be established.

    The usual cause is a cipher key that no longer matches the station (it was
    re-paired, or the cloud re-keyed it); the cure is to fetch the cipher again.
    """


class KeyRejectedError(HandshakeError):
    """The station rejected a cipher key that was already re-fetched.

    No further automatic fetch happens until a handshake succeeds, the slow retry
    window (``KEY_REFRESH_SLOW_RETRY``) passes, or the latch is released with
    ``async_reset_key_refresh``. The password is usually fine: this is not a reauth.
    """


class CipherUnusableError(HandshakeError):
    """The cipher's key material cannot establish a session — and re-fetching won't help.

    Unlike a stale key (a well-formed key the station no longer accepts, which a
    re-fetch may cure), the key itself is unusable: it does not parse as a key. The
    cloud serves the same bytes on every fetch, so the library does **not** re-fetch
    it and sets **no** re-fetch latch; the cipher is tried again only after the library
    changes or the cached key is dropped. ``cipher_id`` is the cipher the station
    named (``None`` until the session attaches it); ``reason`` is a short machine tag.
    """

    def __init__(
        self, message: str, *, cipher_id: int | None = None, reason: str | None = None
    ) -> None:
        super().__init__(message)
        self.cipher_id = cipher_id
        self.reason = reason


# ── commands ─────────────────────────────────────────────────────────────────


class CommandError(EufySecurityError):
    """A command was not applied."""


class CommandRejectedError(CommandError):
    """The station answered a command with an error code."""

    def __init__(self, command: int, code: int, message: str = "") -> None:
        self.command = command
        self.code = code
        super().__init__(
            f"command {command} rejected with code {code}" + (f": {message}" if message else "")
        )


class CommandNotAppliedError(CommandError):
    """The station acknowledged the datagram but never acted on it.

    A transport ACK is not an application result. The station silently drops a
    command carrying an ``account_id`` it does not recognise — almost always
    because a shared member's own id was used instead of the station owner's.
    """

    def __init__(self, command: int, message: str = "") -> None:
        self.command = command
        super().__init__(message or f"command {command} was acknowledged but not applied")


class PresetSlotsFullError(CommandNotAppliedError):
    """The camera stores at most ``slots`` presets and all are in use.

    Distinguishes a full camera from a genuine not-applied store: both otherwise
    raise :class:`CommandNotAppliedError` with the same command id. Delete a slot
    before storing, or store into one already in use (that re-store succeeds).
    """

    def __init__(self, command: int, message: str, *, slots: int, in_use: tuple[int, ...]) -> None:
        self.slots = slots
        self.in_use = in_use
        super().__init__(command, message)


class UnsupportedError(EufySecurityError):
    """The device or firmware does not support the requested operation."""


class ModelDataError(EufySecurityError):
    """A bundled model settings file is malformed; the message names the file."""


class RecordNotFoundError(EufySecurityError):
    """The station's event database has no such record, or the record lacks the media asked for.

    Final for the request as made (a later event's still replaced the event's, another
    camera's row, nothing in the window) unless it is a :class:`StillNotWrittenError`.
    """


class StillNotWrittenError(RecordNotFoundError):
    """The device has not written the event's row or still yet: ask again later.

    Raised right after a detection: a HomeBase event's history row is missing or has
    no thumbnail yet, or a standalone device's newest still is older than the event.
    ``offset`` is that still's time minus the event's, in seconds (None for a
    HomeBase row).
    """

    def __init__(self, message: str, *, offset: float | None = None) -> None:
        self.offset = offset
        super().__init__(message)


class CommandUnsupportedError(CommandRejectedError, UnsupportedError):
    """The station does not handle this command: its receipt carried code -108.

    A rejection (``code`` is -108) and an :class:`UnsupportedError` at once: the
    firmware has no handler for the command, so sending it again changes nothing.
    """


class CameraWakeError(CommandRejectedError, CommunicationError):
    """The station could not wake the camera: its receipt carried a wake-failure code.

    A rejection (``code`` is -204 ``XM_WIFI_WAKEUP_FAIL``, -203 ``XM_WIFI_DISCONNECT`` or
    -205 ``XM_WIFI_TIMEOUT``) and a :class:`CommunicationError` at once: the station is
    up and answering, the camera behind it is not reachable. Not a
    :class:`StationUnreachableError`, which means the station itself.

    ``retry_after`` is set when the open was refused without asking the station: the
    seconds left in the camera's wake backoff (see
    :meth:`~.p2p.session.StationSession.async_open_live`).
    """

    def __init__(
        self, command: int, code: int, message: str = "", *, retry_after: float | None = None
    ) -> None:
        self.retry_after = retry_after
        super().__init__(command, code, message)
