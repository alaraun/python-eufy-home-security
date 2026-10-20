"""An RTC session with one station: signaling, then a live media call.

:class:`RtcSession` runs the sequence: DISCOVER, LOGIN, the ping, then per live
view a private media CALL (kind 6) carrying a generated :class:`~.sdp.SdpInfo`. The
device answers the CALL 200 with its own ``sdp_info`` (its ICE credentials, content
key and IV, SSRCs) and the TURN relay, then trickles its ICE candidates in INFO. The
client sends no SDP answer (its credentials travelled in the CALL), only its own
candidates in INFO; a :class:`MediaPlane` runs ICE and the media. Once ICE is up the
session sends the live open (:mod:`.live`) and waits for the station's status reply or
the first video frame. Commands go over the media connection (RTCP APP) or the data
channel, as the device's handler routes them (:class:`~.media.CommandRoute`).

Not wired into :class:`~.station.Station`.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

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
from ..p2p.xzyh import HEADER_LEN
from .codec import CallKind
from .command import CommandCipher
from .config import QuickLogin, RtcConfig
from .crypto import RtcCrypto
from .data_channel import DataMsgType, KcpDataChannel, WrtcLinkMessage
from .live import (
    LIVE_OPEN_FRAME,
    LIVE_OPEN_TIMEOUT,
    live_open_frame,
    msg_id,
    parse_reply,
    stream_id,
)
from .media import AccessUnit, CommandRoute, DataChannel, IceTransport, TurnServer
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
    """The client's ``sdp_info``, sent in the CALL."""
    remote: SdpInfo | None = None
    """The device's answer ``sdp_info``."""
    cipher: CommandCipher | None = None
    """The command cipher keyed with the answer's content key (its counter runs per call)."""
    _relay: asyncio.Task[None] | None = field(default=None, repr=False)
    _replies: asyncio.Task[None] | None = field(default=None, repr=False)
    _waiters: dict[tuple[int, int], asyncio.Future[int]] = field(default_factory=dict, repr=False)


#: How long the data-channel ICE may take to connect once candidates are out.
DATA_ICE_TIMEOUT: Final = 20.0
#: How long :meth:`DataChannelCall.command` waits for the station's reply.
COMMAND_REPLY_TIMEOUT: Final = 10.0
#: How often an unacknowledged local candidate is re-sent as a ``file_candidate`` INFO.
DATA_CANDIDATE_RESEND: Final = 0.5


def default_ice_factory() -> IceTransport:
    """An :class:`~.media.IceTransport` over aioice with the ``rtc`` extra, else raise."""
    from .media_plane import AioiceTransport  # noqa: PLC0415 - optional extra

    return AioiceTransport()


@dataclass(slots=True, eq=False)
class DataChannelCall:
    """A kind-5 ("priv1") WebRTC data channel: its CALL, ICE and KCP channel.

    Commands are sent with :meth:`send_command` (an already-encrypted XZYH frame) and
    the station's replies arrive as :class:`~.data_channel.WrtcLinkMessage` from
    :meth:`recv`; :attr:`cipher` opens a reply (:meth:`~.command.CommandCipher.decrypt_reply`).
    """

    channel: int
    call: Call
    ice: IceTransport
    info: SdpInfo
    """The client's ``sdp_info``, sent in the CALL."""
    remote: SdpInfo | None = None
    """The device's answer ``sdp_info`` (its ICE credentials and media key)."""
    kcp: KcpDataChannel | None = None
    cipher: CommandCipher | None = None
    _local: list[str] = field(default_factory=list, repr=False)
    _acked: set[int] = field(default_factory=set, repr=False)
    _relay: asyncio.Task[None] | None = field(default=None, repr=False)

    async def send_command(self, frame: bytes) -> None:
        """Send an encrypted XZYH command ``frame`` as a reliable data-channel message."""
        if self.kcp is None:
            raise CommunicationError("RTC data channel has not connected")
        await self.kcp.send_message(frame, msg_type=DataMsgType.COMMAND)

    async def recv(self) -> WrtcLinkMessage:
        """The station's next data-channel message (command reply or notification)."""
        if self.kcp is None:
            raise CommunicationError("RTC data channel has not connected")
        return await self.kcp.recv_message()

    async def command(self, frame: bytes, *, timeout: float = COMMAND_REPLY_TIMEOUT) -> bytes:
        """Send a plaintext XZYH command ``frame`` and return the station's decrypted reply.

        Seals ``frame`` with the call's :class:`~.command.CommandCipher` (advancing its
        counter), sends it as a COMMAND message, and opens the next COMMAND reply that
        carries a body — skipping the bare heartbeat echo — with
        :meth:`~.command.CommandCipher.decrypt_reply`. Assumes one command in flight. The
        reply's format and key are declared from the app, not yet hardware-verified.
        """
        if self.kcp is None or self.cipher is None:
            raise CommunicationError("RTC data channel has not connected")
        await self.send_command(self.cipher.encrypt(frame))
        async with asyncio.timeout(timeout):
            while True:
                msg = await self.kcp.recv_message()
                if msg.msg_type == DataMsgType.COMMAND and len(msg.payload) > HEADER_LEN:
                    return self.cipher.decrypt_reply(msg.payload[HEADER_LEN:])


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
        self._data_calls: dict[int, DataChannelCall] = {}
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

    async def open_data_channel(
        self,
        channel: int,
        *,
        timeout: float = OFFER_TIMEOUT,
        connect_timeout: float = DATA_ICE_TIMEOUT,
        ice: IceTransport | None = None,
        old_protocol: bool = False,
    ) -> DataChannelCall:
        """Open the kind-5 ("priv1") data channel to ``channel``.

        Sends the CALL, relays ICE candidates both ways in the data channel's
        ``file_candidate``/``file_candidate_num`` INFO form (acked with
        ``file_candidate_ack``), connects ICE as the controlled agent and brings up KCP.
        Returns a :class:`DataChannelCall` for commands and replies. Raises
        :class:`~.exceptions.CallRefusedError` when the device refuses the CALL,
        :class:`~.exceptions.DeviceTimeoutError` when it does not answer in ``timeout``
        or ICE does not connect in ``connect_timeout``, and
        :class:`~.exceptions.UnsupportedError` without the ``rtc`` extra; hung up on any
        failure.
        """
        if channel in self._data_calls:
            return self._data_calls[channel]
        info = SdpInfo.generate(
            content_key=self._crypto.new_media_secret(CONTENT_KEY_LEN),
            content_iv=self._crypto.new_media_secret(CONTENT_IV_LEN),
            data_channel=True,
        )
        call = await self.signaling.call(CallKind.PRIV1, channel=channel, sdp_info=info)
        dc = DataChannelCall(channel, call, ice or default_ice_factory(), info)
        try:
            dc.remote = answer_sdp_info(await call.wait_offer(timeout))
            dc._relay = asyncio.get_running_loop().create_task(self._relay_data_candidates(dc))
            dc._local = await dc.ice.gather(
                local_ufrag=info.ice_ufrag,
                local_pwd=info.ice_pwd,
                turn=TurnServer.from_json(call.turn),
            )
            for index in range(len(dc._local)):
                self._send_data_candidate(dc, index)
            async with asyncio.timeout(connect_timeout):
                await dc.ice.connect(remote_ufrag=dc.remote.ice_ufrag, remote_pwd=dc.remote.ice_pwd)
            dc.kcp = KcpDataChannel(dc.ice, old_protocol=old_protocol)
            dc.cipher = CommandCipher(dc.remote.content_key)
        except TimeoutError as exc:
            await self._stop_data(dc)
            raise DeviceTimeoutError(
                "the device did not answer the RTC data CALL or ICE did not connect in time"
            ) from exc
        except BaseException:
            await self._stop_data(dc)
            raise
        self._data_calls[channel] = dc
        return dc

    def _send_data_candidate(self, dc: DataChannelCall, index: int) -> None:
        self.signaling.send_info(
            dc.call, {"file_candidate": f"a={dc._local[index]}", "file_candidate_num": index}
        )

    async def _relay_data_candidates(self, dc: DataChannelCall) -> None:
        """Feed the device's candidates to ICE (acking each) and re-send our own
        ``file_candidate`` INFOs until the device acknowledges them."""
        while not dc.call.ended:
            try:
                event = await asyncio.wait_for(dc.call.events.get(), DATA_CANDIDATE_RESEND)
            except TimeoutError:
                for index in range(len(dc._local)):
                    if index not in dc._acked:
                        self._send_data_candidate(dc, index)
                continue
            if event.kind is CallEventKind.HANGUP:
                _LOGGER.debug("%s: RTC data call hung up", self._log_name)
                return
            if event.kind is not CallEventKind.INFO:
                continue
            ack = event.payload.get("file_candidate_ack")
            if isinstance(ack, int):
                dc._acked.add(ack)
                continue
            candidate = event.payload.get("file_candidate")
            number = event.payload.get("file_candidate_num")
            if isinstance(candidate, str) and candidate:
                if isinstance(number, int):
                    self.signaling.send_info(dc.call, {"file_candidate_ack": number})
                try:
                    dc.ice.add_remote_candidate(candidate)
                except ProtocolError as exc:
                    _LOGGER.debug("%s: RTC data candidate ignored: %s", self._log_name, exc)

    async def close_data_channel(self, channel: int) -> None:
        """Hang up the data channel to ``channel``."""
        dc = self._data_calls.pop(channel, None)
        if dc is not None:
            await self._stop_data(dc)

    async def _stop_data(self, dc: DataChannelCall) -> None:
        if dc._relay is not None:
            dc._relay.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await dc._relay
        if dc.kcp is not None:
            await dc.kcp.close()  # closes the ICE transport too
        else:
            await dc.ice.close()
        self.signaling.hangup(dc.call)

    async def close(self) -> None:
        """Hang up every call and close the signaling client."""
        for channel in list(self._live):
            await self.close_live(channel)
        for channel in list(self._data_calls):
            await self.close_data_channel(channel)
        if self._data_channel is not None:
            await self._data_channel.close()
        await self.signaling.close()
