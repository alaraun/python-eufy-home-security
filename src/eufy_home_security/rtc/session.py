"""An RTC session with one station: signaling, then a live media call.

:class:`RtcSession` runs the app's sequence: DISCOVER, LOGIN, the ping, then per live
view a private media CALL (kind 6) carrying a generated :class:`~.sdp.SdpInfo`. The
device answers the CALL 200 with its own ``sdp_info`` (its ICE credentials, content
key and IV, SSRCs) and the TURN relay, then trickles its ICE candidates in INFO. The
app sends no SDP answer (its credentials travelled in the CALL), only its own
candidates in INFO; a :class:`MediaPlane` runs ICE and the media. Once ICE is up the
session sends the live open (:mod:`.live`) and waits for the station's status reply or
the first video frame. Commands go over the media connection (RTCP APP) or the data
channel, as the device's handler routes them (:class:`~.media.CommandRoute`).

Nothing here is wired into :class:`~.station.Station` yet.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .._logging import redact_serial
from ..exceptions import (
    CommandRejectedError,
    CommunicationError,
    DeviceTimeoutError,
    ProtocolError,
    SignalingError,
    UnsupportedError,
)
from ..p2p.messages import P2P_ERROR_CODES
from .codec import CallKind
from .command import CommandCipher
from .config import QuickLogin, RtcConfig
from .crypto import RtcCrypto
from .live import (
    LIVE_OPEN_FRAME,
    LIVE_OPEN_TIMEOUT,
    live_open_frame,
    msg_id,
    parse_reply,
    stream_id,
)
from .media import AccessUnit, CommandRoute, DataChannel, TurnServer
from .sdp import CONTENT_IV_LEN, CONTENT_KEY_LEN, SdpInfo
from .signaling import OFFER_TIMEOUT, Call, CallEventKind, SignalingClient

_LOGGER = logging.getLogger(__name__)


@runtime_checkable
class MediaPlane(Protocol):
    """ICE, SRTP and RTP for one media call."""

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        """Gather, send each local candidate through ``send_candidate``, connect with
        the device's ``remote`` credentials."""
        ...

    def add_remote_candidate(self, candidate: str) -> None: ...

    def frames(self) -> AsyncIterator[AccessUnit]:
        """The decrypted video access units until the call ends."""
        ...

    async def send_command(self, data: bytes) -> None:
        """A command as an RTCP APP packet on the media connection."""
        ...

    async def recv_command(self) -> bytes:
        """The device's next DATA body on the RTCP APP command channel."""
        ...

    async def wait_media(self) -> None:
        """Return once the first video frame is decoded."""
        ...

    async def close(self) -> None: ...


class UnavailableMediaPlane:
    """A :class:`MediaPlane` that refuses to start (a client without the ``rtc`` extra)."""

    REASON = "the RTC media plane needs the 'rtc' extra: pip install eufy-home-security[rtc]"

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        raise UnsupportedError(self.REASON)

    def add_remote_candidate(self, candidate: str) -> None:
        raise UnsupportedError(self.REASON)

    def frames(self) -> AsyncIterator[AccessUnit]:
        raise UnsupportedError(self.REASON)

    async def send_command(self, data: bytes) -> None:
        raise UnsupportedError(self.REASON)

    async def recv_command(self) -> bytes:
        raise UnsupportedError(self.REASON)

    async def wait_media(self) -> None:
        raise UnsupportedError(self.REASON)

    async def close(self) -> None:
        return None


def default_media_factory() -> MediaPlane:
    """The :class:`~.media_plane.RtcMediaPlane` when the ``rtc`` extra is installed,
    else an :class:`UnavailableMediaPlane`."""
    try:
        from .media_plane import RtcMediaPlane  # noqa: PLC0415 - optional extra
    except ImportError:
        return UnavailableMediaPlane()
    return RtcMediaPlane()


def answer_sdp_info(answer: Mapping[str, Any]) -> SdpInfo:
    """The device's ``sdp_info`` from a CALL 200 payload (base64 of the 86-byte
    structure). Raises :class:`~.exceptions.ProtocolError` when it is missing or
    unreadable."""
    raw = answer.get("sdp_info")
    if not isinstance(raw, str) or not raw:
        raise ProtocolError("the device's answer carries no sdp_info")
    try:
        return SdpInfo.decode(base64.b64decode(raw, validate=True))
    except (binascii.Error, SignalingError) as exc:
        raise ProtocolError(f"the device's sdp_info is unreadable: {exc}") from exc


@dataclass(slots=True, eq=False)
class LiveCall:
    """A live media call: its signaling call, its media plane and both sdp_info."""

    channel: int
    call: Call
    media: MediaPlane
    info: SdpInfo
    """The app's ``sdp_info``, sent in the CALL."""
    remote: SdpInfo | None = None
    """The device's answer ``sdp_info``."""
    cipher: CommandCipher | None = None
    """The command cipher keyed with the answer's content key (its counter runs per call)."""
    _relay: asyncio.Task[None] | None = field(default=None, repr=False)
    _replies: asyncio.Task[None] | None = field(default=None, repr=False)
    _waiters: dict[tuple[int, int], asyncio.Future[int]] = field(default_factory=dict, repr=False)


class RtcSession:
    """One station's RTC session."""

    def __init__(
        self,
        config: RtcConfig,
        crypto: RtcCrypto,
        *,
        media_factory: Callable[[], MediaPlane] | None = None,
        data_channel: DataChannel | None = None,
        signaling: SignalingClient | None = None,
        on_login: Callable[[QuickLogin], None] | None = None,
    ) -> None:
        """``on_login`` receives every login record, re-logins included (unused with
        an own ``signaling``, which takes it itself)."""
        self._config = config
        self._crypto = crypto
        self._media_factory = media_factory or default_media_factory
        self._data_channel = data_channel
        self.signaling = signaling or SignalingClient(config, crypto, on_login=on_login)
        self._live: dict[int, LiveCall] = {}
        self._opens = 0
        self._log_name = redact_serial(config.station_sn)

    async def start(self) -> QuickLogin:
        """Open the socket, DISCOVER, LOGIN and start the ping; returns the quick-login
        record to keep for the next start."""
        await self.signaling.open()
        if self._config.quick_login is None or not self._config.quick_login.usable():
            await self.signaling.discover()
        record = await self.signaling.login()
        self.signaling.start_ping()
        return record

    async def open_live(
        self,
        channel: int,
        *,
        timeout: float = OFFER_TIMEOUT,
        account_id: str | None = None,
        open_timeout: float = LIVE_OPEN_TIMEOUT,
    ) -> LiveCall:
        """Open a live media call to ``channel``: CALL, wait for the device's answer,
        relay candidates both ways, connect the media plane, send the live open.

        ``account_id`` is the station owner's user id the open carries (default the
        config's ``user_id``). Raises :class:`~.exceptions.CallRefusedError` when the
        device refuses the CALL, :class:`~.exceptions.CommandRejectedError` when the
        station answers the open with an error status (``code``),
        :class:`~.exceptions.DeviceTimeoutError` when the device does not answer the
        CALL in ``timeout`` or neither replies to the open nor sends video in
        ``open_timeout``, and :class:`~.exceptions.UnsupportedError` without the
        ``rtc`` extra. The call is hung up on every failure."""
        if channel in self._live:
            return self._live[channel]
        info = SdpInfo.generate(
            content_key=self._crypto.new_media_secret(CONTENT_KEY_LEN),
            content_iv=self._crypto.new_media_secret(CONTENT_IV_LEN),
        )
        call = await self.signaling.call(CallKind.PRIV_MEDIA, channel=channel, sdp_info=info)
        live = LiveCall(channel, call, self._media_factory(), info)
        try:
            live.remote = answer_sdp_info(await call.wait_offer(timeout))
            live._relay = asyncio.get_running_loop().create_task(self._relay_events(live))
            await live.media.start(
                info,
                live.remote,
                TurnServer.from_json(call.turn),
                lambda line: self.signaling.send_info(call, {"candidate": line}),
            )
            live.cipher = cipher = CommandCipher(live.remote.content_key)
            live._replies = asyncio.get_running_loop().create_task(self._read_replies(live))
            await self._send_live_open(
                live, cipher, account_id or self._config.user_id, open_timeout
            )
        except BaseException:
            await self._stop(live)
            raise
        self._live[channel] = live
        return live

    async def _send_live_open(
        self, live: LiveCall, cipher: CommandCipher, account_id: str, timeout: float
    ) -> None:
        """Send the 1350/1003 open; return on a status 0 reply or the first frame."""
        index, self._opens = self._opens, self._opens + 1
        stream = stream_id(index)
        frame = live_open_frame(live.channel, account_id, stream=stream, message_id=msg_id(index))
        reply: asyncio.Future[int] = asyncio.get_running_loop().create_future()
        live._waiters[(LIVE_OPEN_FRAME, stream)] = reply
        await live.media.send_command(cipher.encrypt(frame))
        media = asyncio.ensure_future(live.media.wait_media())
        either: set[asyncio.Future[Any]] = {reply, media}
        try:
            async with asyncio.timeout(timeout):
                await asyncio.wait(either, return_when=asyncio.FIRST_COMPLETED)
        except TimeoutError as exc:
            raise DeviceTimeoutError(
                "the device neither answered the RTC live open nor sent video"
            ) from exc
        finally:
            media.cancel()
            live._waiters.pop((LIVE_OPEN_FRAME, stream), None)
        if reply.done() and (status := reply.result()) != 0:
            raise CommandRejectedError(
                LIVE_OPEN_FRAME, status, f"RTC live open {P2P_ERROR_CODES.get(status, '')}".rstrip()
            )

    async def _read_replies(self, live: LiveCall) -> None:
        """Hand each status reply on the command channel to the command awaiting it."""
        while True:
            try:
                data = await live.media.recv_command()
            except CommunicationError as exc:
                _LOGGER.debug("%s: RTC command channel ended: %s", self._log_name, exc)
                return
            reply = parse_reply(data)
            waiter = live._waiters.pop((reply.command, reply.stream), None) if reply else None
            if reply is None or waiter is None:
                _LOGGER.debug("%s: RTC command data ignored (%d bytes)", self._log_name, len(data))
                continue
            if not waiter.done():
                waiter.set_result(reply.status)

    async def _relay_events(self, live: LiveCall) -> None:
        while not live.call.ended:
            event = await live.call.events.get()
            if event.kind is CallEventKind.HANGUP:
                _LOGGER.debug("%s: RTC live call hung up", self._log_name)
                return
            candidate = event.payload.get("candidate")
            if event.kind is CallEventKind.INFO and isinstance(candidate, str):
                try:
                    live.media.add_remote_candidate(candidate)
                except ProtocolError as exc:
                    _LOGGER.debug("%s: RTC candidate ignored: %s", self._log_name, exc)

    async def send_command(self, channel: int, route: CommandRoute, data: bytes) -> None:
        """Send a command the way the device's handler routes it."""
        if route is CommandRoute.RTCP:
            live = self._live.get(channel)
            if live is None:
                raise SignalingError("no RTC media call open for that channel")
            await live.media.send_command(data)
            return
        if self._data_channel is None:
            raise UnsupportedError(
                "the RTC data channel is not implemented in this library version"
            )
        await self._data_channel.send(data)

    async def close_live(self, channel: int) -> None:
        """Hang up the live call to ``channel``."""
        live = self._live.pop(channel, None)
        if live is not None:
            await self._stop(live)

    async def _stop(self, live: LiveCall) -> None:
        for task in (live._relay, live._replies):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        await live.media.close()
        self.signaling.hangup(live.call)

    async def close(self) -> None:
        """Hang up every call and close the signaling client."""
        for channel in list(self._live):
            await self.close_live(channel)
        if self._data_channel is not None:
            await self._data_channel.close()
        await self.signaling.close()
