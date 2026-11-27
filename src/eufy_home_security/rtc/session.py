"""One station's WebRTC session, from signaling to the data channel's ICE.

:class:`RtcSession` holds the link the eufy app opens to a WebRTC station: DISCOVER and
LOGIN (or a quick login), the 2 s ping, then a kind-5 (``priv1``) CALL whose answer
carries the device's ``sdp_info`` (its ICE credentials and content key) and
``transport_caps``. The client's ICE candidates go out as ``file_candidate`` INFOs,
sent again until the device acknowledges each; the device's candidates are acknowledged
and handed to ICE. Once ICE connects (the client is the controlled side) a KCP data
channel runs over it (:class:`~.data_channel.KcpDataChannel`). Commands on that channel
are not part of this module.

The client's ``sdp_info`` byte 2 carries bit 0 when the station's kcp_type is 2
(:func:`~.config.data_channel_kcp_type`) and never bit 1: the client runs KCP only, where
the eufy app also offers QUIC. The device's answer picks the transport from both
(:func:`select_transport`); the KCP framing follows the device's answer byte 2.

:meth:`RtcSession.start` connects once and raises the first attempt's error with nothing
left running. After that the session reconnects by itself: when the signaling socket
fails, the call is hung up or the data channel stops, it waits 1 s, closes everything,
waits 0.5 s and connects again, as the eufy app does; a failed reconnect waits 1.5 s
for its first three failures, then twice the previous wait, at most 64 s (the library's
back-off). :meth:`RtcSession.close` stops it. Internal: no station uses it yet. See
``docs/protocol/rtc-signaling.md`` § Session.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from .._logging import LogThrottle, redact_serial
from ..exceptions import (
    CommunicationError,
    DeviceTimeoutError,
    ProtocolError,
    SignalingError,
    UnsupportedError,
)
from .client import Call, SignalingClient
from .codec import CallKind
from .config import KCP_TYPE_MULTI, QuickLogin, RtcConfig, ServerInfo, data_channel_kcp_type
from .crypto import RtcSignalingCrypto
from .data_channel import KcpDataChannel
from .ice import IceAgent, IceTransport, require_aioice
from .media import TurnServer
from .sdp import CONTENT_IV_LEN, CONTENT_KEY_LEN, SdpInfo
from .signaling import CallEventKind

_LOGGER = logging.getLogger(__name__)

#: The channel the data-channel CALL names (the station itself).
DATA_CALL_CHANNEL: Final = 0
#: How long the data channel's ICE may take once the answer is in (the eufy app's wait).
ICE_TIMEOUT: Final = 20.0
#: How long the CALL waits for the device's answer.
ANSWER_TIMEOUT: Final = 60.0
#: After a loss: wait, close everything, wait, connect again (the eufy app's schedule).
LOSS_DELAY: Final = 1.0
REINIT_DELAY: Final = 0.5
#: Failed reconnects that wait :data:`LOSS_DELAY` + :data:`REINIT_DELAY`; later ones
#: double the wait up to :data:`RECONNECT_MAX`.
RECONNECT_STEADY_FAILURES: Final = 3
RECONNECT_MAX: Final = 64.0
#: Candidate re-sends per call; the device acknowledges within the first few.
CANDIDATE_RESENDS: Final = 50
#: Device candidate numbers taken per connection; more are acknowledged and dropped.
MAX_DEVICE_CANDIDATES: Final = 16
#: ``sdp_info`` byte 2 / ``transport_caps`` bits: bit 0 the kcp_type-2 framing, bit 1 QUIC.
FLAG_KCP_MULTI: Final = 0x01
FLAG_QUIC: Final = 0x02


class DataTransport(StrEnum):
    """What runs the data channel inside ICE."""

    KCP = "kcp"
    QUIC = "quic"


def select_transport(client_flag: int, transport_caps: int | None) -> DataTransport:
    """QUIC when both the client's ``sdp_info`` byte 2 and the device's
    ``transport_caps`` carry bit 1, else KCP (an answer without the field: KCP)."""
    return (
        DataTransport.QUIC if client_flag & (transport_caps or 0) & FLAG_QUIC else DataTransport.KCP
    )


def client_flag(kcp_type: int) -> int:
    """The client's ``sdp_info`` byte 2 for a station of ``kcp_type``: bit 0 for
    kcp_type 2, never bit 1 (no QUIC)."""
    return FLAG_KCP_MULTI if kcp_type == KCP_TYPE_MULTI else 0


def reconnect_delay(failures: int) -> float:
    """The wait before the next connect after ``failures`` failed ones in a row."""
    doublings = max(0, failures - RECONNECT_STEADY_FAILURES)
    return min((LOSS_DELAY + REINIT_DELAY) * 2.0**doublings, RECONNECT_MAX)


def candidate_resend_delay(count: int) -> float:
    """The wait before the ``count``-th re-send of unacknowledged candidates, in seconds
    (the eufy app's schedule: 100 ms steps for the first five, then 200 ms, plus 200 ms)."""
    return ((100 if count < 6 else 200) * count + 200) / 1000


@dataclass(frozen=True, slots=True)
class CallAnswer:
    """What the device's answer to the data-channel CALL says."""

    sdp_info: SdpInfo
    """The device's ICE credentials, content key and framing flag."""
    transport_caps: int | None
    """The device's ``transport_caps``; None when the answer carries none."""
    pbsdp: bool
    """Whether the answer carries the binary ``pbsdp`` form (not decoded)."""

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> CallAnswer:
        """The answer in a CALL 200 attachment. Raises
        :class:`~.exceptions.ProtocolError` without a readable ``sdp_info``."""
        raw = payload.get("sdp_info")
        if not isinstance(raw, str) or not raw:
            raise ProtocolError("the device's answer carries no sdp_info")
        try:
            info = SdpInfo.decode(base64.b64decode(raw, validate=True))
        except ValueError as exc:  # binascii.Error, and a non-ASCII text
            raise ProtocolError(f"the device's sdp_info is not base64: {exc}") from exc
        caps = payload.get("transport_caps")
        return cls(
            info,
            caps if isinstance(caps, int) and not isinstance(caps, bool) else None,
            "pbsdp" in payload,
        )


@dataclass(eq=False)
class _Attempt:
    """The state of one connection; closed as a whole."""

    signaling: SignalingClient
    lost: asyncio.Future[Exception]
    call: Call | None = None
    answer: CallAnswer | None = None
    ice: IceAgent | None = None
    channel: KcpDataChannel | None = None
    candidates: list[str] = field(default_factory=list)
    acked: set[int] = field(default_factory=set)
    seen: set[int] = field(default_factory=set)
    tasks: set[asyncio.Task[None]] = field(default_factory=set)

    def lose(self, exc: Exception) -> None:
        if not self.lost.done():
            self.lost.set_result(exc)


class RtcSession:
    """The WebRTC session to one station (by its serial in ``config``).

    ``ice_factory`` builds the ICE connection of each attempt (default
    :class:`~.ice.IceTransport`, which needs the ``rtc`` extra). ``on_login`` receives
    every login record for the consumer's quick-login cache, ``on_server_info`` the record
    of every login server (:func:`~.config.merge_server_info` keeps a list of them); a
    callback that raises is logged and does not stop the session. ``crypto``, ``clock`` and
    ``rng`` exist for tests.
    """

    def __init__(
        self,
        config: RtcConfig,
        *,
        ice_factory: Callable[[], IceAgent] | None = None,
        crypto: RtcSignalingCrypto | None = None,
        clock: Callable[[], float] = time.time,
        rng: random.Random | None = None,
        signaling_port: int | None = None,
        tcp_ports: tuple[int, ...] | None = None,
        on_login: Callable[[QuickLogin], None] | None = None,
        on_server_info: Callable[[ServerInfo], None] | None = None,
    ) -> None:
        self._config = config
        self._ice_factory = ice_factory
        self._rng = rng or random.SystemRandom()
        self._crypto = crypto or RtcSignalingCrypto(self._rng)
        self._clock = clock
        self._port = signaling_port
        self._tcp_ports = tcp_ports
        self._on_login = on_login
        self._on_server_info = on_server_info
        self._quick_login = config.quick_login
        self._lock = asyncio.Lock()
        self._generation = 0
        self._run: asyncio.Task[None] | None = None
        self._attempt: _Attempt | None = None
        self._link_generation = 0
        self._last_error: Exception | None = None
        self._warned = LogThrottle()
        self._log_name = redact_serial(config.station_sn)

    # ── state ────────────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        """Whether the data channel's ICE is up."""
        return self._attempt is not None

    @property
    def link_generation(self) -> int:
        """How many times the session connected; a new value means a new link."""
        return self._link_generation

    @property
    def last_error(self) -> Exception | None:
        """What ended the last connection or failed the last connect; None before."""
        return self._last_error

    @property
    def data_channel(self) -> KcpDataChannel | None:
        """The current connection's data channel; None while not connected."""
        return self._attempt.channel if self._attempt else None

    @property
    def answer(self) -> CallAnswer | None:
        """The device's answer of the current connection; None while not connected."""
        return self._attempt.answer if self._attempt else None

    @property
    def quick_login(self) -> QuickLogin | None:
        """The newest login record (the config's until the first login)."""
        return self._quick_login

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect, then keep the session up until :meth:`close`.

        Returns once the first connection is up; raises its error otherwise, with nothing
        left running: :class:`~.exceptions.MissingDependencyError` without the ``rtc``
        extra (before any socket), :class:`~.exceptions.SignalingError` for a refused
        login, :class:`~.exceptions.CallRefusedError` for a refused or hung-up CALL,
        :class:`~.exceptions.DeviceTimeoutError` for an unanswered step or ICE not up in
        :data:`ICE_TIMEOUT`, :class:`~.exceptions.UnsupportedError` for a device that picks
        QUIC, :class:`~.exceptions.CommunicationError` when ICE fails or :meth:`close`
        ran meanwhile. A second start while running returns at once. A cancelled start
        (cancelled again or not) returns only after the connect it cancelled has closed.
        """
        if self._ice_factory is None:
            require_aioice()
        generation = self._generation
        async with self._lock:
            if generation != self._generation:
                raise CommunicationError("RTC session closed before it started")
            if self._run is not None:
                return
            loop = asyncio.get_running_loop()
            first: asyncio.Future[None] = loop.create_future()
            run = loop.create_task(self._run_loop(first))
            self._run = run
            try:
                await asyncio.wait({first, run}, return_when=asyncio.FIRST_COMPLETED)
            except asyncio.CancelledError:
                run.cancel()
                while not run.done():  # a second cancel still waits for the cleanup
                    with contextlib.suppress(asyncio.CancelledError):
                        await asyncio.wait({run})
                if first.done() and not first.cancelled():
                    first.exception()  # read: nobody else will
                if self._run is run:
                    self._run = None
                raise
            if first.done():
                if first.exception() is not None and self._run is run:
                    self._run = None
                first.result()
                return
            if self._run is run:
                self._run = None
            raise CommunicationError("RTC session closed while it connected")

    async def close(self) -> None:
        """Stop the session: hang up, close every socket and task. A cancelled close
        still finishes in the background."""
        self._generation += 1
        run, self._run = self._run, None
        if run is not None:
            run.cancel()
            await asyncio.wait({run})

    async def _run_loop(self, first: asyncio.Future[None]) -> None:
        failures = 0
        while True:
            try:
                attempt = await self._connect_once()
            except Exception as exc:  # every connect failure: typed library or OS error
                if not first.done():
                    first.set_exception(exc)
                    return
                failures += 1
                self._last_error = exc
                level = logging.WARNING if self._warned.should_log("reconnect") else logging.DEBUG
                _LOGGER.log(level, "%s: RTC reconnect failed: %s", self._log_name, exc)
                await asyncio.sleep(reconnect_delay(failures))
                continue
            failures = 0
            self._attempt = attempt
            self._link_generation += 1
            if not first.done():
                first.set_result(None)
            try:
                cause = await attempt.lost
                self._attempt = None
                self._last_error = cause
                _LOGGER.debug("%s: RTC session lost: %s", self._log_name, cause)
                await asyncio.sleep(LOSS_DELAY)
            finally:
                self._attempt = None
                await self._close_attempt(attempt)
            await asyncio.sleep(REINIT_DELAY)

    # ── one connection ───────────────────────────────────────────────────────

    def _signaling(self, lost: Callable[[Exception], None]) -> SignalingClient:
        extra: dict[str, Any] = {}
        if self._port is not None:
            extra["port"] = self._port
        if self._tcp_ports is not None:
            extra["tcp_ports"] = self._tcp_ports
        return SignalingClient(
            self._config,
            crypto=self._crypto,
            clock=self._clock,
            rng=self._rng,
            on_login=self._logged_in,
            on_server_info=self._server_used,
            on_lost=lost,
            **extra,
        )

    def _logged_in(self, record: QuickLogin) -> None:
        self._quick_login = record
        self._notify(self._on_login, record)

    def _server_used(self, record: ServerInfo) -> None:
        self._notify(self._on_server_info, record)

    def _notify(self, callback: Callable[[Any], None] | None, record: object) -> None:
        """Hand ``record`` to a consumer's callback; its failure is logged, not raised."""
        if callback is None:
            return
        try:
            callback(record)
        except Exception:  # the consumer's code: any failure
            level = logging.WARNING if self._warned.should_log("callback") else logging.DEBUG
            _LOGGER.log(level, "%s: RTC login callback failed", self._log_name, exc_info=True)

    async def _connect_once(self) -> _Attempt:
        lost: asyncio.Future[Exception] = asyncio.get_running_loop().create_future()

        def on_lost(exc: Exception) -> None:
            if not lost.done():
                lost.set_result(exc)

        attempt = _Attempt(self._signaling(on_lost), lost)
        try:
            await self._connect(attempt)
        except BaseException:
            await self._close_attempt(attempt)
            raise
        return attempt

    async def _connect(self, attempt: _Attempt) -> None:
        signaling = attempt.signaling
        await signaling.open()
        record = self._quick_login
        if record is None or not record.usable(self._clock()):
            await signaling.discover()
        await signaling.login(record)
        signaling.start_ping()
        flag = client_flag(
            data_channel_kcp_type(self._config.station_sn[:5], self._config.sdk_version)
        )
        info = SdpInfo.generate(
            content_key=self._crypto.new_media_secret(CONTENT_KEY_LEN),
            content_iv=self._crypto.new_media_secret(CONTENT_IV_LEN),
            data_channel=bool(flag & FLAG_KCP_MULTI),
            rng=self._rng,
        )
        call = await signaling.call(CallKind.PRIV1, channel=DATA_CALL_CHANNEL, sdp_info=info)
        attempt.call = call
        answer = CallAnswer.parse(await call.wait_answer(ANSWER_TIMEOUT))
        attempt.answer = answer
        if select_transport(flag, answer.transport_caps) is DataTransport.QUIC:
            raise UnsupportedError("the station chose QUIC for the RTC data channel")
        ice = self._ice_factory() if self._ice_factory else IceTransport()
        attempt.ice = ice
        self._spawn(attempt, self._relay(attempt, call, ice))
        attempt.candidates = await ice.gather(
            local_ufrag=info.ice_ufrag, local_pwd=info.ice_pwd, turn=TurnServer.from_json(call.turn)
        )
        self._send_candidates(attempt, call)
        try:
            async with asyncio.timeout(ICE_TIMEOUT):
                await ice.connect(
                    remote_ufrag=answer.sdp_info.ice_ufrag, remote_pwd=answer.sdp_info.ice_pwd
                )
        except TimeoutError as exc:
            raise DeviceTimeoutError("the RTC data channel's ICE did not connect in time") from exc
        attempt.channel = KcpDataChannel(ice, prefixed=answer.sdp_info.data_channel)
        self._spawn(attempt, self._watch(attempt, attempt.channel))
        _LOGGER.debug("%s: RTC data channel up", self._log_name)

    @staticmethod
    def _spawn(attempt: _Attempt, coro: Any) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        attempt.tasks.add(task)
        task.add_done_callback(attempt.tasks.discard)

    @staticmethod
    def _send_candidates(attempt: _Attempt, call: Call) -> None:
        for index, line in enumerate(attempt.candidates):
            if index not in attempt.acked:
                attempt.signaling.send_info(
                    call, {"file_candidate": f"a={line}", "file_candidate_num": index}
                )

    async def _relay(self, attempt: _Attempt, call: Call, ice: IceAgent) -> None:
        """Feed the device's candidates to ICE (acknowledging each), re-send the client's
        own until acknowledged, and report a hang-up as a loss."""
        resends = 0
        while not call.ended:
            pending = any(n not in attempt.acked for n in range(len(attempt.candidates)))
            wait = (
                candidate_resend_delay(resends + 1)
                if pending and resends < CANDIDATE_RESENDS
                else None
            )
            try:
                async with asyncio.timeout(wait):
                    event = await call.events.get()
            except TimeoutError:
                resends += 1
                with contextlib.suppress(SignalingError, OSError):
                    self._send_candidates(attempt, call)
                continue
            if event.kind is CallEventKind.INFO:
                self._device_info(attempt, call, ice, event.payload)
        # A hang-up or an error code ends the call (``call.ended``).
        attempt.lose(SignalingError("the station ended the RTC data call"))

    def _device_info(
        self, attempt: _Attempt, call: Call, ice: IceAgent, payload: Mapping[str, Any]
    ) -> None:
        ack = payload.get("file_candidate_ack")
        if isinstance(ack, int) and not isinstance(ack, bool):
            if 0 <= ack < len(attempt.candidates):
                attempt.acked.add(ack)
            return
        line = payload.get("file_candidate")
        number = payload.get("file_candidate_num")
        if not isinstance(line, str) or not line:
            return
        if isinstance(number, int) and not isinstance(number, bool):
            with contextlib.suppress(SignalingError, OSError):
                attempt.signaling.send_info(call, {"file_candidate_ack": number})
            if number in attempt.seen or len(attempt.seen) >= MAX_DEVICE_CANDIDATES:
                return
            attempt.seen.add(number)
        try:
            ice.add_remote_candidate(line)
        except ProtocolError as exc:
            _LOGGER.debug("%s: RTC candidate ignored: %s", self._log_name, exc)

    @staticmethod
    async def _watch(attempt: _Attempt, channel: KcpDataChannel) -> None:
        failure = await channel.wait_closed()
        attempt.lose(
            failure
            if isinstance(failure, Exception)
            else CommunicationError("RTC data channel closed")
        )

    async def _close_attempt(self, attempt: _Attempt) -> None:
        """Close one connection whole; a cancel waits for it to finish, then re-raises."""
        closing = asyncio.get_running_loop().create_task(self._close_parts(attempt))
        try:
            await asyncio.wait({closing})
        except asyncio.CancelledError:
            await asyncio.wait({closing})
            raise

    async def _close_parts(self, attempt: _Attempt) -> None:
        tasks = list(attempt.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)
        try:
            if attempt.channel is not None:
                await attempt.channel.close()  # closes the ICE connection too
            elif attempt.ice is not None:
                await attempt.ice.close()
        except Exception as exc:  # a failing close must not keep the sockets open
            _LOGGER.debug("%s: RTC ICE close failed: %s", self._log_name, exc)
        await attempt.signaling.close()  # hangs up the call
