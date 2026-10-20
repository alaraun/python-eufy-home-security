"""Concrete media-plane transports for the RTC path, on the optional ``rtc`` extra.

These implement the interfaces of :mod:`.media` with the WebRTC building blocks the
eufy app uses:

- :class:`SdesSrtp` — SRTP/SRTCP with the fixed SDES key from the SDP template
  (``AES_CM_128_HMAC_SHA1_80``, the same master key both directions), via
  :mod:`pylibsrtp`.
- :class:`KcpDataChannel` — the station's KCP data channel (commands, notifications,
  files) as a codec over a packet transport, via :mod:`kcp`.

Importing this module needs the extra (``pip install eufy-home-security[rtc]``).
Nothing here is verified against a station; our HomeBase 3 serves P2P.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
from collections import deque
from typing import Protocol, runtime_checkable

try:
    from kcp import KCP  # type: ignore[attr-defined]
    from pylibsrtp import Policy, Session
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "the RTC media plane needs the 'rtc' extra: pip install eufy-home-security[rtc]"
    ) from exc

from .sdp import SDES_INLINE_KEY

#: Length of an ``AES_CM_128_HMAC_SHA1_80`` master key and salt (16 + 14 bytes).
SDES_KEY_LEN = 30


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
