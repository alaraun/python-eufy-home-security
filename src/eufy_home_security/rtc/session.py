"""An RTC session with one station: signaling, then a live media call.

:class:`RtcSession` runs the app's sequence: DISCOVER, LOGIN, the ping, then per live
view a private media CALL (kind 6) carrying a generated :class:`~.sdp.SdpInfo`. The
device answers the CALL 200 with its own ``sdp_info`` (its ICE credentials, content
key and IV, SSRCs) and the TURN relay, then trickles its ICE candidates in INFO. The
app sends no SDP answer (its credentials travelled in the CALL), only its own
candidates in INFO; a :class:`MediaPlane` runs ICE and the media. Commands go over
the media connection (RTCP APP) or the data channel, as the device's handler routes
them (:class:`~.media.CommandRoute`).

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
from ..exceptions import ProtocolError, SignalingError, UnsupportedError
from .codec import CallKind
from .config import QuickLogin, RtcConfig
from .crypto import RtcCrypto
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
    _relay: asyncio.Task[None] | None = field(default=None, repr=False)


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

    async def open_live(self, channel: int, *, timeout: float = OFFER_TIMEOUT) -> LiveCall:
        """Open a live media call to ``channel``: CALL, wait for the device's answer,
        relay candidates both ways, connect the media plane. Raises
        :class:`~.exceptions.CallRefusedError` when the device refuses,
        :class:`~.exceptions.DeviceTimeoutError` when it does not answer, and
        :class:`~.exceptions.UnsupportedError` without the ``rtc`` extra."""
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
        except BaseException:
            await self._stop(live)
            raise
        self._live[channel] = live
        return live

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
        if live._relay is not None:
            live._relay.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await live._relay
        await live.media.close()
        self.signaling.hangup(live.call)

    async def close(self) -> None:
        """Hang up every call and close the signaling client."""
        for channel in list(self._live):
            await self.close_live(channel)
        if self._data_channel is not None:
            await self._data_channel.close()
        await self.signaling.close()
