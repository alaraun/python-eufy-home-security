"""An RTC session with one station: signaling, then a live media call.

:class:`RtcSession` runs the app's sequence: DISCOVER, LOGIN, the ping, then per live
view a private media CALL carrying a generated :class:`~.sdp.SdpInfo`; the device's
offer goes to a :class:`MediaPlane`, whose answer and candidates return to the
device in INFO. Commands go over the media connection (RTCP APP) or the data
channel, as the device's handler routes them (:class:`~.media.CommandRoute`).

Nothing here is wired into :class:`~.station.Station`: stations the app reaches
only over RTC stay skipped until the cryptography and the media plane exist.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .._logging import redact_serial
from ..exceptions import ProtocolError, SignalingError, UnsupportedError
from .codec import CallKind
from .config import QuickLogin, RtcConfig
from .crypto import RtcCrypto
from .media import CommandRoute, DataChannel
from .sdp import CompactOffer, SdpInfo
from .signaling import OFFER_TIMEOUT, Call, CallEventKind, SignalingClient

_LOGGER = logging.getLogger(__name__)


@runtime_checkable
class MediaPlane(Protocol):
    """ICE, SRTP and RTP for one media call."""

    async def start(
        self, offer: CompactOffer, info: SdpInfo, turn: Mapping[str, Any] | None
    ) -> str:
        """Accept the device's offer; returns the SDP answer to send back."""
        ...

    def add_remote_candidate(self, candidate: str) -> None: ...

    async def send_command(self, data: bytes) -> None:
        """A command as an RTCP APP packet on the media connection."""
        ...

    async def close(self) -> None: ...


class UnavailableMediaPlane:
    """A :class:`MediaPlane` that refuses to start."""

    REASON = "the RTC media plane is not implemented in this library version"

    async def start(
        self, offer: CompactOffer, info: SdpInfo, turn: Mapping[str, Any] | None
    ) -> str:
        raise UnsupportedError(self.REASON)

    def add_remote_candidate(self, candidate: str) -> None:
        raise UnsupportedError(self.REASON)

    async def send_command(self, data: bytes) -> None:
        raise UnsupportedError(self.REASON)

    async def close(self) -> None:
        return None


def compact_offer(offer: Mapping[str, Any]) -> CompactOffer:
    """The compact offer inside a CALL 200 payload (its ``sdp`` object)."""
    sdp = offer.get("sdp")
    if isinstance(sdp, Mapping):
        return CompactOffer.from_json(sdp)
    raise ProtocolError("the device's offer carries no compact SDP object")


@dataclass(slots=True, eq=False)
class LiveCall:
    """A live media call: its signaling call and its media plane."""

    channel: int
    call: Call
    media: MediaPlane
    info: SdpInfo
    _relay: asyncio.Task[None] | None = field(default=None, repr=False)


class RtcSession:
    """One station's RTC session."""

    def __init__(
        self,
        config: RtcConfig,
        crypto: RtcCrypto,
        *,
        media_factory: type[MediaPlane] | None = None,
        data_channel: DataChannel | None = None,
        signaling: SignalingClient | None = None,
    ) -> None:
        self._config = config
        self._crypto = crypto
        self._media_factory = media_factory or UnavailableMediaPlane
        self._data_channel = data_channel
        self.signaling = signaling or SignalingClient(config, crypto)
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
        """Open a live media call to ``channel``: CALL, wait for the offer, start the
        media plane, send the answer, relay the device's candidates. Raises
        :class:`~.exceptions.CallRefusedError` when the device refuses, and
        :class:`~.exceptions.UnsupportedError` while a part is not implemented."""
        if channel in self._live:
            return self._live[channel]
        info = SdpInfo.generate(self._crypto.new_media_secret(), self._crypto.new_media_secret())
        call = await self.signaling.call(CallKind.PRIV_MEDIA, channel=channel, sdp_info=info)
        media: MediaPlane = self._media_factory()
        try:
            offer = await call.wait_offer(timeout)
            answer = await media.start(compact_offer(offer), info, call.turn)
            self.signaling.send_info(call, {"sdp": answer})
        except BaseException:
            await media.close()
            self.signaling.hangup(call)
            raise
        live = LiveCall(channel, call, media, info)
        live._relay = asyncio.get_running_loop().create_task(self._relay_events(live))
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
                live.media.add_remote_candidate(candidate)

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
        if live is None:
            return
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
