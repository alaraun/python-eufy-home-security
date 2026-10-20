"""Concrete media-plane transports for the RTC path, on the optional ``rtc`` extra.

These implement the interfaces of :mod:`.media` with the WebRTC building blocks the
eufy app uses, and assemble them into the live-view media plane:

- :class:`AioiceTransport` — one ICE connection via :mod:`aioice`, with the local
  credentials of the app's ``sdp_info``, the CALL's TURN relay, ICE-controlled.
- :class:`SdesSrtp` — SRTP/SRTCP with the fixed SDES key from the SDP template
  (``AES_CM_128_HMAC_SHA1_80``, the same master key both directions), via
  :mod:`pylibsrtp`.
- :class:`KcpDataChannel` — the station's KCP data channel (commands, notifications,
  files) as a codec over a packet transport, via :mod:`kcp`.
- :class:`RtcMediaPlane` — ICE, then SRTP, the H.265 depacketizer and the in-frame
  decryption of a kind-6 live call (:class:`~.session.MediaPlane`).

Importing this module needs the extra (``pip install eufy-home-security[rtc]``).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
from collections import deque
from collections.abc import AsyncIterator, Callable
from typing import Final, Protocol, runtime_checkable

try:
    from aioice import Candidate, Connection
    from kcp import KCP  # type: ignore[attr-defined]
    from pylibsrtp import Error as SrtpError
    from pylibsrtp import Policy, Session
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "the RTC media plane needs the 'rtc' extra: pip install eufy-home-security[rtc]"
    ) from exc

from .._logging import LogThrottle
from ..exceptions import (
    CommunicationError,
    DeviceTimeoutError,
    ProtocolError,
)
from .frame_crypto import EufyFrameDecryptor
from .media import (
    CANDIDATE_PREFIX,
    AccessUnit,
    H265Depacketizer,
    IceTransport,
    PayloadType,
    RtcpApp,
    RtpPacket,
    SrtpContext,
    TurnServer,
    candidate_body,
    is_rtcp,
)
from .rtcp_channel import APP_NAME, APP_SUBTYPE, RtcpChannel
from .sdp import SDES_INLINE_KEY, SdpInfo

_LOGGER = logging.getLogger(__name__)

#: Length of an ``AES_CM_128_HMAC_SHA1_80`` master key and salt (16 + 14 bytes).
SDES_KEY_LEN = 30
#: How long ICE may take to connect once the candidates are out (library choice).
ICE_TIMEOUT: Final = 20.0
#: Bound of the decoded-frame queue; the oldest frame is dropped when it is full.
FRAME_QUEUE: Final = 64


class AioiceTransport:
    """An :class:`~.media.IceTransport` over one :class:`aioice.Connection`.

    One component (the template bundles audio and video and muxes RTCP), UDP only,
    the controlled role (the device offers and nominates). Remote candidates may
    arrive before :meth:`gather`; they are kept and handed over then.
    """

    def __init__(self) -> None:
        self._connection: Connection | None = None
        self._pending: list[Candidate] = []
        self._tasks: set[asyncio.Task[None]] = set()

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        connection = Connection(
            ice_controlling=False,
            components=1,
            turn_server=(turn.host, turn.port) if turn else None,
            turn_username=turn.username if turn else None,
            turn_password=turn.password if turn else None,
            local_username=local_ufrag,
            local_password=local_pwd,
        )
        self._connection = connection
        pending, self._pending = self._pending, []
        for candidate in pending:
            await connection.add_remote_candidate(candidate)
        await connection.gather_candidates()
        return [f"{CANDIDATE_PREFIX}{c.to_sdp()}" for c in connection.local_candidates]

    def add_remote_candidate(self, candidate: str) -> None:
        try:
            parsed = Candidate.from_sdp(candidate_body(candidate))
        except ValueError as exc:
            raise ProtocolError(f"unreadable ICE candidate: {exc}") from exc
        if parsed.transport.lower() != "udp":
            return
        if self._connection is None:
            self._pending.append(parsed)
            return
        task = asyncio.get_running_loop().create_task(self._connection.add_remote_candidate(parsed))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        connection = self._require()
        connection.remote_username = remote_ufrag
        connection.remote_password = remote_pwd
        try:
            await connection.connect()
        except ConnectionError as exc:
            raise CommunicationError(f"RTC ICE did not connect: {exc}") from exc

    async def recv(self) -> bytes:
        try:
            return await self._require().recv()
        except ConnectionError as exc:
            raise CommunicationError("RTC ICE connection closed") from exc

    async def send(self, data: bytes) -> None:
        try:
            await self._require().send(data)
        except ConnectionError as exc:
            raise CommunicationError("RTC ICE connection closed") from exc

    async def close(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._connection is not None:
            await self._connection.close()

    def _require(self) -> Connection:
        if self._connection is None:
            raise CommunicationError("RTC ICE has not gathered candidates yet")
        return self._connection


class SdesSrtp:
    """SRTP/SRTCP keyed by one SDES master key, used for both directions.

    The eufy SDP template carries a single constant ``a=crypto`` line
    (:data:`~.sdp.SDES_INLINE_KEY`) and no DTLS, so the same 30-byte master key
    protects the station's media to the app and the app's RTCP back.
    """

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != SDES_KEY_LEN:
            raise ValueError(f"an SRTP master key is {SDES_KEY_LEN} bytes")
        profile = Policy.SRTP_PROFILE_AES128_CM_SHA1_80
        self._inbound = Session(
            Policy(key=master_key, ssrc_type=Policy.SSRC_ANY_INBOUND, srtp_profile=profile)
        )
        self._outbound = Session(
            Policy(key=master_key, ssrc_type=Policy.SSRC_ANY_OUTBOUND, srtp_profile=profile)
        )

    @classmethod
    def from_inline(cls, inline: str = SDES_INLINE_KEY) -> SdesSrtp:
        """The context for a base64 SDES ``inline`` key (the template's by default)."""
        return cls(base64.b64decode(inline))

    def unprotect_rtp(self, packet: bytes) -> bytes:
        return self._inbound.unprotect(packet)

    def unprotect_rtcp(self, packet: bytes) -> bytes:
        return self._inbound.unprotect_rtcp(packet)

    def protect_rtcp(self, packet: bytes) -> bytes:
        return self._outbound.protect_rtcp(packet)


@runtime_checkable
class PacketTransport(Protocol):
    """What :class:`KcpDataChannel` moves its segments over (an ICE connection)."""

    async def recv(self) -> bytes: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


class KcpDataChannel:
    """The station's KCP data channel over a packet ``transport``.

    KCP (``conv_id``) frames reliable, ordered messages the app would otherwise lose
    on the UDP connection. Segments the codec emits go out on ``transport``; incoming
    segments are fed back in, and whole messages surface from :meth:`recv`. An update
    task drives KCP's timers.
    """

    def __init__(self, transport: PacketTransport, *, conv_id: int = 0) -> None:
        self._transport = transport
        self._kcp = KCP(conv_id=conv_id)
        self._kcp.include_outbound_handler(self._queue_outbound)
        self._outbound: deque[bytes] = deque()
        self._received: asyncio.Queue[bytes] = asyncio.Queue()
        self._closed = False
        self._tasks = [
            asyncio.ensure_future(self._read_loop()),
            asyncio.ensure_future(self._tick()),
        ]

    def _queue_outbound(self, _kcp: object, data: bytes) -> None:
        self._outbound.append(bytes(data))

    async def _drain(self) -> None:
        while self._outbound:
            await self._transport.send(self._outbound.popleft())

    async def send(self, data: bytes) -> None:
        self._kcp.enqueue(data)
        self._kcp.flush()
        await self._drain()

    async def recv(self) -> bytes:
        return await self._received.get()

    async def _read_loop(self) -> None:
        while not self._closed:
            try:
                segment = await self._transport.recv()
            except asyncio.CancelledError:
                raise
            except Exception:
                return
            self._kcp.receive(segment)
            while self._kcp.next_packet_available:
                self._received.put_nowait(bytes(self._kcp.get_received()))
            await self._drain()  # KCP may owe an ack

    async def _tick(self) -> None:
        while not self._closed:
            self._kcp.update()
            await self._drain()
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        self._closed = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._transport.close()


class RtcMediaPlane:
    """The media plane of one kind-6 live call (:class:`~.session.MediaPlane`).

    :meth:`start` gathers ICE candidates under the app's ``sdp_info`` credentials,
    hands each to ``send_candidate`` (the session sends it in an INFO), then connects
    with the credentials of the device's answer ``sdp_info``. Every packet after
    that is SRTP-unprotected; H.265 RTP (payload type 97) is depacketized and its
    in-frame encryption removed with the answer's content key and IV
    (:meth:`~.frame_crypto.EufyFrameDecryptor.from_answer`); :meth:`frames` yields
    the Annex B access units. Audio, H.264, FlexFEC and RTCP are not delivered.
    """

    def __init__(
        self,
        ice: IceTransport | None = None,
        srtp: SrtpContext | None = None,
        *,
        connect_timeout: float = ICE_TIMEOUT,
    ) -> None:
        self._ice: IceTransport = ice or AioiceTransport()
        self._srtp: SrtpContext = srtp or SdesSrtp.from_inline()
        self._connect_timeout = connect_timeout
        self._depacketizer = H265Depacketizer()
        self._frames: asyncio.Queue[AccessUnit | None] = asyncio.Queue(FRAME_QUEUE + 1)
        self._reader: asyncio.Task[None] | None = None
        self._channel: RtcpChannel | None = None
        self._local_ssrc = 0
        self._throttle = LogThrottle(60.0)
        self._ended = False
        self._media = asyncio.Event()

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        """Connect the call's media; raises :class:`~.exceptions.CommunicationError`
        when ICE fails and :class:`~.exceptions.DeviceTimeoutError` after
        ``connect_timeout``."""
        decryptor = EufyFrameDecryptor.from_answer(remote)
        for line in await self._ice.gather(
            local_ufrag=local.ice_ufrag, local_pwd=local.ice_pwd, turn=turn
        ):
            send_candidate(line)
        try:
            async with asyncio.timeout(self._connect_timeout):
                await self._ice.connect(remote_ufrag=remote.ice_ufrag, remote_pwd=remote.ice_pwd)
        except TimeoutError as exc:
            raise DeviceTimeoutError("RTC ICE did not connect in time") from exc
        self._local_ssrc = local.audio_ssrc
        self._channel = RtcpChannel(self._send_app)
        self._channel.start()
        self._reader = asyncio.get_running_loop().create_task(self._read_loop(decryptor))

    async def _send_app(self, frame: bytes) -> None:
        """Put one ANKE frame on the wire, wrapped in a raw RTCP APP packet."""
        await self._ice.send(RtcpApp(APP_SUBTYPE, self._local_ssrc, APP_NAME, frame).encode())

    def add_remote_candidate(self, candidate: str) -> None:
        self._ice.add_remote_candidate(candidate)

    async def frames(self) -> AsyncIterator[AccessUnit]:
        """The decrypted H.265 access units, until the media connection ends."""
        while (frame := await self._frames.get()) is not None:
            yield frame

    async def send_command(self, data: bytes) -> None:
        """Send a command body to the device as a reliable ANKE DATA packet."""
        if self._channel is None:
            raise CommunicationError("RTC media plane has not started")
        await self._channel.send_data(data)

    async def recv_command(self) -> bytes:
        """The body of the device's next DATA packet on the command channel."""
        if self._channel is None:
            raise CommunicationError("RTC media plane has not started")
        return await self._channel.recv_data()

    async def wait_media(self) -> None:
        """Return once the first video frame is decoded."""
        await self._media.wait()

    async def close(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader
        if self._channel is not None:
            await self._channel.close()
        await self._ice.close()
        self._end()

    async def _read_loop(self, decryptor: EufyFrameDecryptor) -> None:
        try:
            while True:
                self._handle(await self._ice.recv(), decryptor)
        except CommunicationError as exc:
            _LOGGER.debug("RTC media connection ended: %s", exc)
        finally:
            self._end()

    def _handle(self, data: bytes, decryptor: EufyFrameDecryptor) -> None:
        if is_rtcp(data):
            self._handle_rtcp(data)
            return
        try:
            packet = RtpPacket.parse(self._srtp.unprotect_rtp(data))
        except (SrtpError, ProtocolError) as exc:
            if self._throttle.should_log("rtp"):
                _LOGGER.debug("RTC packet dropped: %s", exc)
            return
        if packet.payload_type != PayloadType.H265:
            if self._throttle.should_log(packet.payload_type):
                _LOGGER.debug("RTC payload type %d is not delivered", packet.payload_type)
            return
        for unit in self._depacketizer.push(packet):
            try:
                data = decryptor.video(unit.data, keyframe=unit.keyframe)
            except ProtocolError as exc:
                if self._throttle.should_log("frame"):
                    _LOGGER.warning("RTC video frame dropped: %s", exc)
                continue
            self._push(AccessUnit(data, unit.timestamp, unit.keyframe))

    def _handle_rtcp(self, data: bytes) -> None:
        """Route the command channel's RTCP APP packet to the channel; drop other RTCP.

        The command channel is RTCP APP name "AZWC" subtype 0 (``setCmd2Rtcp`` ->
        ``SendRtcpAppPacket(ssrc, 0, 0x415a5743, ...)``); the HomeBase 3 sends the
        same. These are raw (SDES, no DTLS), so they are parsed here before any
        SRTCP unprotect. SR/RR, the "ANKE"/subtype-30 keepalive, and any other RTCP
        are dropped.
        """
        if self._channel is None:
            return
        try:
            app = RtcpApp.parse(data)
        except ProtocolError:
            return
        if app.name == APP_NAME and app.subtype == APP_SUBTYPE:
            self._channel.feed(app.data)

    def _push(self, frame: AccessUnit) -> None:
        if self._ended:
            return
        if self._frames.qsize() >= FRAME_QUEUE:
            self._frames.get_nowait()
        self._frames.put_nowait(frame)
        self._media.set()

    def _end(self) -> None:
        if not self._ended:
            self._ended = True
            self._frames.put_nowait(None)
