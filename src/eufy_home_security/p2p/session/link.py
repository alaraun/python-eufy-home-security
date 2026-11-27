"""The P2P link of a station session: PPPP transport, handshake, frame ciphers.

:class:`P2PLink` is the :class:`StationLink` of a station reached over P2P. It brings the
PPPP link up (LAN search, rendezvous wake), runs the ``CONN_INIT`` handshake, seals the
session's commands (GCM after an ECIES handshake, AES-128-ECB after an RSA one),
reassembles DRW chunks into frames, opens a frame's JSON body and reads command receipts.
:class:`~eufy_home_security.p2p.session.StationSession` keeps the protocol: requests and
their replies, parameters, events and media. It reaches the link only through
:class:`StationLink`, except for what only a P2P link has (addresses, DID, the
connect path, raw frame sends), which it reads from the :class:`P2PLink` itself.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import TYPE_CHECKING, Any, Protocol, cast

from ..._logging import (
    Address,
    HexDump,
    LogThrottle,
    Payload,
    Secret,
    register_secret_bytes,
    wire_logger,
)
from ...cloud.const import FORCED_REFRESH_COOLDOWN
from ...events import DisconnectCause
from ...exceptions import (
    CipherUnusableError,
    CloudError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    KeyRejectedError,
    ProtocolError,
    RefreshCooldownError,
    SessionReplacedError,
    StationUnreachableError,
)
from ..crypto import (
    CONN_INIT_ECC_VERSION,
    CONN_INIT_NO_CIPHER,
    FRAME_PLAIN,
    GCM_SEQ_START,
    ConnInit,
    aes_key_from_conn_init,
    ecb_decrypt,
    ecb_encrypt,
    frame_encryption,
    gcm_decrypt_broadcast,
    gcm_encrypt_command,
    parse_conn_init,
    session_key_from_conn_init,
)
from ..did import Did, static_key
from ..messages import (
    conn_init_request,
    decode_command_receipt,
    decode_command_result,
    decode_json_payload,
    gcm_subheader,
)
from ..netif import async_local_networks
from ..pppp import DrwChunk, is_lan_address
from ..transport import ConnectPath, PPPPTransport, Wake
from ..xzyh import Frame, FrameCipher, FrameType, StreamDecoder, encode_frame
from .core import FrameDecoder, Inbound, Matcher
from .keys import SessionKeys
from .stats import HealthCounters

if TYPE_CHECKING:
    from . import CredentialProvider, KeyRefreshLatch, P2PCredentials, WakeProvider
    from .media_slot import MediaSlot

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("p2p")

_CLEAR_REPLY_TYPES = frozenset({FrameType.DB_SYNC, FrameType.MEDIA_DOWNLOAD})
"""Reply frame types a standalone device may send as clear JSON under the ECB tag."""


def _learns_host(peer: str, searched: Collection[str]) -> bool:
    """Whether a link's peer address becomes the host the next discovery searches: a
    LAN address (:func:`~..pppp.is_lan_address`), or one in ``searched`` (the hosts
    discovery already searches by unicast). A public peer is the station's router,
    which no ``LAN_SEARCH`` should go to unless it was configured."""
    return is_lan_address(peer) or peer in searched


class _MissingKeyError(HandshakeError):
    """The credentials hold no key for the handshake the station chose."""

    def __init__(self, cipher_id: int, *, rsa: bool, creds: P2PCredentials) -> None:
        self.cipher_id = cipher_id
        self.rsa = rsa
        self.creds = creds
        """The credentials that lack the key."""
        kind = "RSA" if rsa else "ECC"
        super().__init__(f"no {kind} private key held for cipher {cipher_id}")

    def held_by(self, creds: P2PCredentials) -> bool:
        """Whether ``creds`` hold the key this handshake needs."""
        return bool(creds.rsa_private_key if self.rsa else creds.ecc_private_key)

    def unusable(self) -> CipherUnusableError:
        """The error for an ECIES handshake still without its key (RSA falls back)."""
        return CipherUnusableError(str(self), cipher_id=self.cipher_id, reason="no_ecc_key")


class _CipherMismatchError(HandshakeError):
    """The credentials are for another cipher than the one CONN_INIT names."""

    def __init__(self, named: int, held: int) -> None:
        self.named = named
        super().__init__(f"CONN_INIT names cipher {named}, the key is cipher {held}")


@dataclass(frozen=True, slots=True)
class LinkTuning:
    """The ``p2p.session`` constants a :class:`P2PLink` reads, at their values when asked
    (:meth:`LinkHost._link_tuning`): they stay patchable where they are documented."""

    discovery_attempts: int
    discovery_timeout: float
    discovery_retry_delay: float
    handshake_timeout: float
    conn_init_min_len: int
    conn_init_max_len: int
    rsa_result_window: float


class StationLink(Protocol):
    """What a station session needs from the link to its station.

    The link brings the connection up and down, seals a command under its cipher, and
    hands every inbound frame to the session's dispatcher; the session owns requests,
    replies, state and events. :class:`P2PLink` is the P2P one.
    """

    @property
    def connected(self) -> bool:
        """Whether the link is open and holds a session key."""
        ...

    @property
    def link_generation(self) -> int:
        """Links brought up so far, the current one included."""
        ...

    async def connect(self) -> P2PCredentials:
        """Bring the link and its session key up; returns the credentials commands carry.

        Raises a :class:`~...exceptions.EufySecurityError` when it cannot.
        """
        ...

    def drop(self, reason: str) -> None:
        """Close the link (when one is up) and forget its session key."""
        ...

    def lost(self) -> None:
        """Forget a link that went down under the session, and its session key."""
        ...

    def send_command(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int:
        """Send ``plaintext`` sealed under the session's cipher; returns the send's index
        for :meth:`acked`. Raises :class:`~...exceptions.StationUnreachableError` without
        a session."""
        ...

    def acked(self, indices: Sequence[int], channel: int = 0) -> bool:
        """Whether the station acknowledged any of the sends ``indices`` on ``channel``."""
        ...

    def decode_receipt(self, channel: int, frame: Frame) -> tuple[int, int | None] | None:
        """The code of a command receipt and the result slot it answers (None outside an
        RSA session); None for any other frame."""
        ...

    def decode_json(self, frame: Frame, *, plain_rsa: bool) -> dict[str, Any] | None:
        """The JSON body of ``frame`` under the link's frame cipher; None when it has none."""
        ...


class LinkHost(FrameDecoder, Protocol):
    """The session members a :class:`P2PLink` calls: the handshake reply waits in the
    session's request core, inbound frames go to its dispatcher, a lost link to
    :meth:`_on_lost`, a failed handshake tears the session down."""

    on_demand: bool
    _account_mismatch_reported: bool
    _creds: P2PCredentials | None
    _media_slot: MediaSlot

    @property
    def static_key_session(self) -> bool: ...

    def _teardown(
        self,
        reason: str,
        *,
        cause: DisconnectCause | None = None,
        error: EufySecurityError | None = None,
    ) -> None: ...

    async def _request(
        self,
        send: Callable[[], object],
        match: Matcher,
        *,
        timeout: float,
        resend_after: float | None = None,
        label: str = "request",
        send_only_under_lock: bool = False,
    ) -> object: ...

    def _dispatch(self, inbound: Inbound) -> None: ...

    def _on_lost(self, exc: Exception) -> None: ...

    def _link_tuning(self) -> LinkTuning: ...


class P2PLink:
    """The :class:`StationLink` of a station reached over P2P (PPPP)."""

    def __init__(
        self,
        session: LinkHost,
        serial: str,
        credentials: CredentialProvider,
        *,
        host: str | None,
        port: int,
        local_port: int,
        did: Did | str | None,
        wake_provider: WakeProvider | None,
        key_refresh: KeyRefreshLatch,
        extra_hosts: Sequence[str],
        connect_path: ConnectPath | None,
        lan_reply_blocked: bool,
        local_networks: Sequence[IPv4Network] | None,
        health: HealthCounters,
        throttle: LogThrottle,
        log_name: str,
    ) -> None:
        # See StationSession for the arguments; health, throttle and log_name are the
        # session's own (shared, so its stats and log throttling cover the link).
        self._session = session
        self.serial = serial
        self._health = health
        self._throttle = throttle
        self._log_name = log_name
        self._wake_provider = wake_provider
        self._credentials = credentials
        self._key_refresh = key_refresh
        self._host = host
        self._search_host = host
        self._extra_hosts = tuple(extra_hosts)
        self._connect_path = connect_path
        self._lan_reply_blocked = lan_reply_blocked
        self._local_networks = None if local_networks is None else tuple(local_networks)
        self._expected_did = Did.parse(did) if isinstance(did, str) else did
        # The static key slices the id's text as the cloud lists it (see static_key).
        self._did_text = did if isinstance(did, str) else None
        self._port = port
        self._local_port = local_port

        self._transport: PPPPTransport | None = None
        self._links = 0
        """Transports this session brought up (:attr:`link_generation`)."""
        self._cipher_id: int | None = None
        """The cipher the station named in its last CONN_INIT (None before one arrived)."""
        self._keys = SessionKeys(self.serial)
        self._conn_init_version: int | None = None
        """The version (subheader byte 0) of the last CONN_INIT reply."""
        self._rsa_keyless_at: tuple[int, float] | None = None
        """(cipher id, monotonic time) of the last RSA handshake left without a key after
        a re-fetch: until ``FORCED_REFRESH_COOLDOWN`` passes, that cipher is not
        re-fetched again."""
        self._did: Did | None = None
        self._decoders: dict[int, StreamDecoder] = {}
        self._results_due: dict[int, list[tuple[float, int]]] = {}
        """An RSA session's sends awaiting their result: frame type → (deadline (monotonic),
        slot), oldest first."""
        self._result_slot = 0
        """The slot of the latest RSA send awaiting its result (:meth:`_send_request`)."""

    @property
    def connected(self) -> bool:
        return (
            (self._keys.session_key is not None or self._keys.aes_key is not None)
            and self._transport is not None
            and self._transport.is_open
        )

    @property
    def link_generation(self) -> int:
        """The number of transports this session has brought up, the current one
        included: a value read on one connection never matches on a later one."""
        return self._links

    async def connect(self) -> P2PCredentials:
        """See :meth:`StationLink.connect` and :meth:`StationSession.async_connect`."""
        try:
            creds = await self._establish(None)
        except CipherUnusableError:
            # The key cannot be used and the cloud serves the same bytes again;
            # re-fetching is pointless and would set the stale-key latch. Let it
            # propagate: the cipher is retried only after a library change or the
            # cached key being dropped.
            raise
        except HandshakeError as err:
            creds = await self._refetch_rejected_key(err)
            try:
                creds = await self._establish(creds)
            except CipherUnusableError:
                raise
            except _MissingKeyError as again:
                raise again.unusable() from again
            except HandshakeError as again:
                raise KeyRejectedError(
                    f"the station rejected the re-fetched cipher key too: {again}"
                ) from again
        await self._key_refresh.async_accepted()
        return creds

    def drop(self, reason: str) -> None:
        """See :meth:`StationLink.drop`."""
        if self._transport is not None:
            _LOGGER.debug("%s: tearing the session down: %s", self._log_name, reason)
            self._transport.close()
            self._retire_transport(self._transport)
            self._transport = None
        self._keys.session_key = None
        self._keys.aes_key = None

    def lost(self) -> None:
        """See :meth:`StationLink.lost`."""
        if self._transport is not None:
            self._retire_transport(self._transport)
        self._transport = None
        self._keys.session_key = None
        self._keys.aes_key = None

    def _rendezvous_on(self, attempt: int) -> bool:
        """Whether discovery attempt ``attempt`` (from 1) runs the rendezvous connect even
        when its DSK must be fetched from the cloud.

        An on-demand station runs it on every attempt: it is what wakes the station.
        A held station runs it once LAN discovery has failed an attempt, or from the
        first attempt when its last link came through it or needed a punch because its
        LAN reply was blocked. Otherwise the attempt runs it
        only with a DSK the provider already holds (``cached_only``), so a station the
        LAN reaches costs no cloud call. The eufy app runs both from the start; the
        library does so whenever that needs no cloud call. The LAN search runs on every
        attempt.
        """
        return (
            self._session.on_demand
            or attempt > 1
            or self._connect_path is ConnectPath.RENDEZVOUS
            or self._lan_reply_blocked
        )

    async def _wake(self, *, cached_only: bool) -> Wake | None:
        """The rendezvous material for this connection attempt, or None when it cannot
        be built (with ``cached_only``: when it would need a cloud call).

        A failure to fetch the DSK (a cloud outage) is not fatal: discovery falls back
        to a plain ``LAN_SEARCH``, which still finds the station if it happens to be awake.
        A :class:`SessionReplacedError` is fatal for an on-demand station: it is raised
        at once, since no wake can be built until someone takes the cloud session back.
        A held station searches the LAN on.
        """
        if self._wake_provider is None:
            return None
        try:
            wake = await self._wake_provider(cached_only=cached_only)
        except SessionReplacedError:
            if self._session.on_demand:
                raise
            _LOGGER.debug(
                "%s: no rendezvous (the cloud session was replaced); LAN discovery only",
                self._log_name,
            )
            return None
        except EufySecurityError as err:
            _LOGGER.debug(
                "%s: no wake material (%s); trying LAN discovery only", self._log_name, err
            )
            return None
        if wake is not None:
            register_secret_bytes(wake.dsk)
        elif cached_only:
            _LOGGER.debug(
                "%s: LAN discovery only on this attempt (no rendezvous servers, or no DSK held)",
                self._log_name,
            )
        return wake

    async def _host_networks(self) -> Sequence[IPv4Network] | None:
        """This host's directly connected networks: the ones the session was given,
        else read from the interfaces (off the event loop); None when unknown."""
        if self._local_networks is not None:
            return self._local_networks
        return await async_local_networks()

    async def _establish(self, creds: P2PCredentials | None) -> P2PCredentials:
        """Connect and unwrap the session key; returns the credentials that unwrapped it.

        The station names its cipher in CONN_INIT. Without ``creds``, or when they are
        another cipher's, the named cipher's credentials are loaded (from the cache,
        else the cloud) before the unwrap: a different cipher is not a stale key.
        """
        self._session._teardown("reconnecting")
        # A closed UDP transport releases its socket on the next loop iteration; a
        # pinned local port is only free again after that.
        await asyncio.sleep(0)
        self._session._media_slot.rx_at = 0.0
        last_error: EufySecurityError = StationUnreachableError("no discovery attempt made")
        for attempt in range(1, self._session._link_tuning().discovery_attempts + 1):
            _LOGGER.debug(
                "%s: connecting (attempt %d/%d) to %s, local port %s",
                self._log_name,
                attempt,
                self._session._link_tuning().discovery_attempts,
                Address(self._host or "broadcast"),
                self._local_port or "ephemeral",
            )
            wake = await self._wake(cached_only=not self._rendezvous_on(attempt))
            # A punch answer is classified by this host's networks (see PPPPTransport.connect).
            networks = None if wake is None else await self._host_networks()
            transport = PPPPTransport(on_chunk=self._on_chunk, on_lost=self._session._on_lost)
            try:
                did = await transport.connect(
                    self._host,
                    port=self._port,
                    local_port=self._local_port,
                    expected_did=self._expected_did,
                    timeout=self._session._link_tuning().discovery_timeout,
                    wake=wake,
                    extra_hosts=self._extra_hosts,
                    local_networks=networks,
                    on_link_grace=not self._session.on_demand,
                )
            except StationUnreachableError as err:
                last_error = err
                _LOGGER.debug("%s: discovery attempt %d failed: %s", self._log_name, attempt, err)
                if attempt < self._session._link_tuning().discovery_attempts:
                    await asyncio.sleep(self._session._link_tuning().discovery_retry_delay)
                continue
            except BaseException:
                transport.close()
                raise
            break
        else:
            raise last_error

        try:
            ecb_key = static_key(self.serial, self._did_text or did)
        except ProtocolError as err:
            # Not a HandshakeError: re-fetching the cipher key cannot fix a serial or
            # DID that does not yield a static key.
            self._retire_transport(transport)
            transport.close()
            raise ProtocolError(f"cannot derive the static key for this station: {err}") from err
        self._transport = transport
        self._links += 1
        self._did = did
        self._keys.static_key = ecb_key
        path = transport.path or ConnectPath.LAN
        self._connect_path = path
        self._lan_reply_blocked = transport.lan_reply_blocked
        searched = [host for host in (self._search_host, *self._extra_hosts) if host]
        if transport.peer is not None and _learns_host(transport.peer[0], searched):
            self._host = transport.peer[0]
        self._decoders.clear()
        self._results_due.clear()
        self._keys.gcm_seq = GCM_SEQ_START
        self._keys.gcm_counter = 0
        self._keys.ecb_seq = 0

        key = self._keys.static_key
        _LOGGER.debug(
            "%s: link up (DID %s); static ECB key %s; sending CONN_INIT",
            self._log_name,
            Secret(did),
            Secret(key),
        )

        def match(inbound: Inbound) -> Frame | None:
            if inbound.type != FrameType.CONN_INIT:
                return None
            # Bound the payload before the handshake decrypts it (CONN_INIT_MAX_LEN).
            if (
                not self._session._link_tuning().conn_init_min_len
                <= len(inbound.frame.payload)
                <= self._session._link_tuning().conn_init_max_len
            ):
                return None
            return inbound.frame

        try:
            payload = await self._session._request(
                lambda: transport.send_drw(0, conn_init_request()),
                match,
                timeout=self._session._link_tuning().handshake_timeout,
                label="CONN_INIT",
            )
        except DeviceTimeoutError as err:
            self._health.handshake_failures += 1
            self._session._teardown("no handshake reply")
            raise StationUnreachableError(
                "the station did not answer the session handshake"
            ) from err
        except BaseException:
            self._session._teardown("handshake interrupted")
            raise
        try:
            creds, conn_init, session_key = await self._unwrap_conn_init(
                cast(Frame, payload), key, creds
            )
        except CipherUnusableError as err:
            _LOGGER.debug("%s: handshake failed: %s", self._log_name, err)
            self._health.handshake_failures += 1
            self._session._teardown("cipher key unusable")
            raise
        except HandshakeError as err:
            _LOGGER.debug("%s: handshake failed: %s", self._log_name, err)
            self._health.handshake_failures += 1
            self._session._teardown("handshake failed")
            raise
        except CloudError:
            self._session._teardown("no credentials for the cipher the station named")
            raise
        except BaseException:
            self._session._teardown("handshake interrupted")
            raise
        if conn_init.rsa:
            self._keys.aes_key = session_key
        else:
            self._keys.session_key = session_key
        self._health.connects += 1
        self._health.connects_by_path[str(path)] += 1
        self._session._creds = creds
        self._session._account_mismatch_reported = False  # a new connection may report it again
        _LOGGER.debug(
            "%s: %s session key %s%s",
            self._log_name,
            "AES-128-ECB" if conn_init.rsa else "GCM",
            Secret(session_key),
            " (the static key)" if self._session.static_key_session else "",
        )
        peer = self._transport.peer
        _LOGGER.info(
            "%s: P2P session established via %s (%s)",
            self._log_name,
            Address(peer[0] if peer is not None else self._host),
            path,
        )
        return creds

    async def _unwrap_conn_init(
        self, frame: Frame, static: bytes, creds: P2PCredentials | None
    ) -> tuple[P2PCredentials, ConnInit, bytes]:
        """The credentials of the cipher CONN_INIT names, the parsed reply, and the
        session key they unwrap: a 32-byte GCM key (version 8, ECIES) or a 16-byte
        AES-128 key (any other version, RSA)."""
        refetched = creds is not None
        conn_init = parse_conn_init(frame.payload, frame.subheader, static)
        named = conn_init.cipher_id
        self._cipher_id = named
        self._conn_init_version = conn_init.version
        self._keys.rsa_keyless = False
        _LOGGER.debug(
            "%s: CONN_INIT reply (%d bytes, version %d, encryption %s) names cipher %d",
            self._log_name,
            len(frame.payload),
            conn_init.version,
            frame_encryption(frame.subheader),
            named,
        )
        if conn_init.rsa and named == CONN_INIT_NO_CIPHER:
            # No session key: the app fetches no cipher and keeps the static key.
            if creds is None or creds.cipher_id != named:
                creds = await self._load_credentials(refresh=False)
            self._keys.rsa_keyless = True
            return creds, conn_init, static
        if creds is None:
            creds = await self._load_credentials(refresh=False)
        elif named != creds.cipher_id:
            _LOGGER.debug(
                "%s: the station uses cipher %d, not %d; loading its key",
                self._log_name,
                named,
                creds.cipher_id,
            )
            creds = await self._load_credentials(refresh=False)
        if creds.cipher_id != named:
            raise _CipherMismatchError(named, creds.cipher_id)
        missing = _MissingKeyError(named, rsa=conn_init.rsa, creds=creds)
        if not missing.held_by(creds):
            if not conn_init.rsa:
                raise missing
            if not refetched and not self._rsa_keyless_recently(named):
                # Asked again on the same link, as the app does.
                creds = await self._refetch_rejected_key(missing)
                if not missing.held_by(creds):
                    self._rsa_keyless_at = (named, time.monotonic())
        if not missing.held_by(creds):
            # Still without an RSA key: the app sets no session key and keeps the static key.
            _LOGGER.log(
                logging.INFO
                if self._throttle.should_log(("rsa-keyless", named))
                else logging.DEBUG,
                "%s: the cloud serves no RSA key for cipher %d; the session runs under the "
                "static key, as in the eufy app",
                self._log_name,
                named,
            )
            self._keys.rsa_keyless = True
            return creds, conn_init, static
        if not conn_init.rsa:
            return creds, conn_init, session_key_from_conn_init(conn_init, creds.ecc_private_key)
        rsa_key = cast(str, creds.rsa_private_key)  # held_by checked it
        try:
            return creds, conn_init, aes_key_from_conn_init(conn_init, rsa_key)
        except CipherUnusableError as exc:
            # The app sets no session key when the RSA key fails to parse and runs the
            # session under the static key, as for a CONN_INIT naming no cipher.
            _LOGGER.info(
                "%s: cipher %d's RSA key cannot be used (%s); the session runs under the "
                "static key, as in the eufy app",
                self._log_name,
                named,
                exc.reason,
            )
            self._keys.rsa_keyless = True
            return creds, conn_init, static

    def _rsa_keyless_recently(self, cipher_id: int) -> bool:
        """Whether an RSA handshake for ``cipher_id`` was left without a key after a
        re-fetch within ``FORCED_REFRESH_COOLDOWN``."""
        last = self._rsa_keyless_at
        return (
            last is not None
            and last[0] == cipher_id
            and time.monotonic() - last[1] < FORCED_REFRESH_COOLDOWN
        )

    async def _refetch_rejected_key(self, err: HandshakeError) -> P2PCredentials:
        """Re-fetch the credentials after ``err``, unless the stale-key latch holds it back.

        A missing RSA key is no rejected key: the latch does not hold that re-fetch back.
        """
        rsa_missing = isinstance(err, _MissingKeyError) and err.rsa
        wait = 0.0 if rsa_missing else self._key_refresh.retry_blocked_for()
        if wait > 0:
            raise KeyRejectedError(
                f"the station rejects its cipher key, which was already re-fetched; "
                f"no automatic re-fetch for {wait:.0f}s ({err})"
            ) from err
        _LOGGER.log(
            logging.DEBUG if rsa_missing else logging.WARNING,
            "%s: %s (%s); re-fetching the cipher key once",
            self._log_name,
            "credentials without the key"
            if isinstance(err, _MissingKeyError)
            else "session key would not unwrap",
            err,
        )
        try:
            creds = await self._load_credentials(refresh=True)
        except RefreshCooldownError:
            if not rsa_missing:
                raise
            # The last forced fetch, inside the cooldown, served no RSA key either.
            creds = cast(_MissingKeyError, err).creds
        if isinstance(err, _MissingKeyError) and not err.held_by(creds):
            if err.rsa:
                return creds  # the static-key session follows; nothing for the latch
            raise err.unusable() from err  # no key came back: nothing for the latch
        if isinstance(err, _CipherMismatchError) and creds.cipher_id != err.named:
            # Another cipher's key is no stale key of this one: nothing for the latch.
            raise HandshakeError(
                f"{err}; the re-fetched credentials are for cipher {creds.cipher_id} too"
            ) from err
        await self._key_refresh.async_refreshed()  # only now: the fetch returned a key
        self._health.key_refreshes += 1
        return creds

    async def _load_credentials(self, *, refresh: bool) -> P2PCredentials:
        version = self._conn_init_version
        rsa = version is not None and version != CONN_INIT_ECC_VERSION
        creds = await self._credentials(
            refresh=refresh,
            cipher_id=self._cipher_id,
            **({"keys_optional": True} if rsa else {}),
        )
        _LOGGER.debug(
            "%s: credentials%s: owner account %s, user %s, cipher-%d private key %s, RSA key %s",
            self._log_name,
            " (re-fetched)" if refresh else "",
            Secret(creds.account_id),
            Secret(creds.user_name),
            creds.cipher_id,
            Secret(creds.ecc_private_key),
            "held" if creds.rsa_private_key else "none",
        )
        return creds

    def _retire_transport(self, transport: PPPPTransport) -> None:
        """Keep the counters of a transport this session is letting go of."""
        self._health.retired_wrong_port_drops += transport.wrong_port_drops

    def _on_chunk(self, chunk: DrwChunk) -> None:
        decoder = self._decoders.get(chunk.channel)
        if decoder is None:
            decoder = self._decoders[chunk.channel] = StreamDecoder()
        try:
            frames = decoder.feed(chunk.index, chunk.data)
        except ProtocolError as err:
            _LOGGER.warning("%s: channel %d stream reset: %s", self._log_name, chunk.channel, err)
            self._health.dropped_undecodable += 1
            # Resume from the next chunk that arrives. A reset to index 0 would wait
            # for an index the station has long passed, silencing the channel for
            # the rest of the session.
            self._decoders[chunk.channel] = StreamDecoder(first_index=None)
            return
        for frame in frames:
            self._session._dispatch(Inbound(chunk.channel, frame, self._session))

    def decode_json(self, frame: Frame, *, plain_rsa: bool) -> dict[str, Any] | None:
        """The JSON object of a frame :meth:`StationSession._decode_json` lets through."""
        payload = frame.payload
        if plain_rsa:
            return self._counted_json(payload)  # an RSA session's clear reply
        if (
            frame.cipher == FrameCipher.ECB
            and frame.type in _CLEAR_REPLY_TYPES
            and payload[:1] == b"{"
        ):
            # A standalone T8170 answers database queries and still fetches in clear
            # JSON under the ECB tag. Replies, not state: each
            # binds to its request by cmd, transaction or path.
            return self._counted_json(payload)
        if frame.cipher == FrameCipher.ECB:
            key = self._keys.ecb_key(frame)
            if key is None:
                return None
            if len(payload) < 16 or len(payload) % 16:
                self._health.dropped_undecodable += 1
                return None
            return self._counted_json(ecb_decrypt(key, payload))
        if frame.cipher == FrameCipher.GCM:
            if self._keys.session_key is None or len(payload) < 29:
                return None
            if decode_command_receipt(frame) is not None:
                return None  # a command receipt: GCM-tagged, but not ciphertext
            try:
                return self._counted_json(gcm_decrypt_broadcast(self._keys.session_key, payload))
            except ProtocolError:
                self._health.dropped_undecodable += 1
                if self._throttle.should_log(("gcm-auth", frame.type)):
                    _LOGGER.debug(
                        "%s: frame 0x%04x failed GCM authentication", self._log_name, frame.type
                    )
                return None
        return None

    def _counted_json(self, plain: bytes) -> dict[str, Any] | None:
        """The JSON object in ``plain``; one that has none counts as undecodable."""
        obj = decode_json_payload(plain)
        if obj is None:
            self._health.dropped_undecodable += 1
        return obj

    def send_command(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int:
        """Send ``plaintext`` under the session's cipher: GCM after an ECIES handshake,
        AES-128-ECB under the session key after an RSA one (subheader
        ``01 <seq> <dev_type> 02 <flag> 00``, as the app sends every command then)."""
        if self._keys.aes_key is not None:
            return self._send_session_ecb(
                plaintext, frame_type=frame_type, dev_type=dev_type, flag=flag
            )
        key = self._keys.session_key
        if key is None:
            raise StationUnreachableError("no P2P session")
        seq = self._keys.gcm_seq
        self._keys.gcm_seq += 1
        nonce = os.urandom(12)
        payload = gcm_encrypt_command(key, plaintext, nonce=nonce, seq=seq)
        self._keys.gcm_counter = (self._keys.gcm_counter + 2) & 0xFF
        frame = encode_frame(
            frame_type, payload, gcm_subheader(self._keys.gcm_counter, dev_type, flag=flag)
        )
        if _WIRE.isEnabledFor(logging.DEBUG):
            obj = decode_json_payload(plaintext)
            _WIRE.debug(
                "%s: tx GCM frame 0x%04x seq 0x%08x nonce %s: %s",
                self._log_name,
                frame_type,
                seq,
                Secret(nonce),
                HexDump(plaintext) if obj is None else Payload(obj),
            )
        return self._require_transport().send_drw(0, frame)

    def _send_session_ecb(
        self, plaintext: bytes, *, frame_type: int, dev_type: int, flag: int
    ) -> int:
        """An RSA session's frame: AES-128-ECB under the session key, zero-padded, or
        clear when the session sends encryption type 0."""
        key = cast(bytes, self._keys.aes_key)
        seq = self._keys.ecb_seq
        self._keys.ecb_seq = (seq + 1) & 0xFF
        encryption = self._keys.session_encryption
        subheader = bytes([FrameCipher.ECB, seq, dev_type & 0xFF, encryption, flag & 0xFF, 0x00])
        body = plaintext if encryption == FRAME_PLAIN else ecb_encrypt(key, plaintext)
        frame = encode_frame(frame_type, body, subheader)
        if _WIRE.isEnabledFor(logging.DEBUG):
            obj = decode_json_payload(plaintext)
            _WIRE.debug(
                "%s: tx session-ECB frame 0x%04x seq %d: %s",
                self._log_name,
                frame_type,
                seq,
                HexDump(plaintext) if obj is None else Payload(obj),
            )
        return self._send_request(frame_type, frame, self._require_transport())

    def _send_request(self, frame_type: int, frame: bytes, transport: PPPPTransport) -> int:
        """Send ``frame`` on channel 0; on an RSA session the next channel-0 frame of
        ``frame_type`` within :data:`~.RSA_RESULT_WINDOW` is read as its result, under a new
        slot (:attr:`_result_slot`)."""
        if self._keys.aes_key is not None:
            due = time.monotonic() + self._session._link_tuning().rsa_result_window
            self._result_slot += 1
            self._results_due.setdefault(frame_type, []).append((due, self._result_slot))
        return transport.send_drw(0, frame)

    def _take_result_due(self, frame_type: int) -> int | None:
        """The slot of the oldest send of ``frame_type`` that awaits its result, taken;
        None when none does."""
        due = self._results_due.get(frame_type)
        if not due:
            return None
        now = time.monotonic()
        while due and due[0][0] < now:
            due.pop(0)
        if not due:
            return None
        return due.pop(0)[1]

    def decode_receipt(self, channel: int, frame: Frame) -> tuple[int, int | None] | None:
        """The code of a command receipt on the request channel (0) and, on an RSA
        session, the slot of the send it answers; None for any other frame.

        A GCM session: a GCM-tagged clear receipt (:func:`decode_command_receipt`). An
        RSA session: the first channel-0 frame of a sent request's type whose payload
        holds 4 to 132 bytes is that request's result, its code the clear ``int32le``
        at ``payload[0:4]`` (:func:`decode_command_result`), as the eufy app reads it:
        nothing decrypted, the encryption type and the tail ignored. Frames of any other
        type stay notifies.
        """
        if channel != 0:
            return None
        if self._keys.aes_key is None:
            code = decode_command_receipt(frame)
            return None if code is None else (code, None)
        code = decode_command_result(frame.payload)
        if code is None or (slot := self._take_result_due(frame.type)) is None:
            return None
        return code, slot

    def acked(self, indices: Sequence[int], channel: int = 0) -> bool:
        """Whether the station acknowledged any of the DRW chunks ``indices`` on ``channel``."""
        transport = self._transport
        return transport is not None and any(transport.is_acked(channel, i) for i in indices)

    def _require_transport(self) -> PPPPTransport:
        if self._transport is None or not self._transport.is_open:
            raise StationUnreachableError("P2P link is not open")
        return self._transport
