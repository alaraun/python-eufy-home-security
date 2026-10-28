"""The media slot of a station session: its one open stream (:class:`MediaSlot`)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from ..._logging import LogThrottle
from ...devices.live_open import NVR_OPENS, LiveOpen, LiveStop
from ...devices.live_view import LensView, LiveView, player_input
from ...devices.live_view import live_view as live_view_of
from ...devices.recipes import (
    RecipeCommand,
    close_live_stream,
    open_live_stream_nvr,
    open_live_stream_single,
)
from ...events import is_station_recording_path
from ...exceptions import (
    CameraWakeError,
    CommunicationError,
    EufySecurityError,
    UnsupportedError,
)
from .._json import json_int
from ..crypto import ecc_private_key_from_hex
from ..media import (
    MediaDecoder,
    MediaKeyType,
    download_video_payload,
    generate_media_ecc_key,
    generate_media_rsa_key,
    record_view_payload,
    start_realtime_media_payload,
    stop_realtime_media_payload,
)
from ..messages import (
    CMD_DOWNLOAD_VIDEO,
    CMD_RECORD_VIEW,
    CMD_START_REALTIME_MEDIA,
    CMD_STOP_REALTIME_MEDIA,
    DB_QUERY_LOCAL_EVENTS,
    ECB_RESULT_CODES,
    LIVE_OPEN_SUBHEADER_FLAG,
    RECEIPT_CODES,
    app_ping_frame,
    device_msg,
    history_query_verb,
)
from ..transport import PPPPTransport
from ..xzyh import FrameType
from .core import _RECORDING_COMMANDS, Inbound, _receipt_error, _rejection
from .keys import SessionKeys
from .media_stream import MediaStream, StreamOwner

if TYPE_CHECKING:
    from . import P2PCredentials
    from .budget import SessionBudget

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MediaWaits:
    """The waits a :class:`MediaSlot` reads, as ``p2p.session`` holds them when asked
    (``MEDIA_PING_INTERVAL``, ``MEDIA_DRAIN_GAP``, ``MEDIA_DRAIN_MAX``, ``WAKE_BACKOFF``)."""

    ping_interval: float
    drain_gap: float
    drain_max: float
    wake_backoff: tuple[float, ...]


class MediaSlot:
    """A station session's media slot: the one stream it carries, opened and routed here.

    It opens live and recording streams (a HomeBase live open goes to an extra session
    from the :class:`~.budget.SessionBudget` while the slot is busy), waits for the
    previous stream's frames to drain before an open, pings a standalone device's
    stream, takes the replies and receipts that answer an open, and releases a stream
    nobody reads. Every first-frame and idle timeout is a number: the session resolves
    the defaults before calling.
    """

    def __init__(self, session: SlotOwner) -> None:
        self._session = session
        self.stream: MediaStream | None = None
        self.rx_at = 0.0
        """When the last media frame arrived, attached to a stream or not."""
        self.slot_free = asyncio.Event()
        self.slot_free.set()
        self.pinger: asyncio.Task[None] | None = None

    @property
    def live_channel(self) -> int | None:
        """See :attr:`StationSession.media_slot_channel`."""
        stream = self.stream
        if stream is None or stream.command != CMD_START_REALTIME_MEDIA:
            return None
        return stream.channel

    async def open_live(
        self,
        channel: int,
        *,
        first_frame_timeout: float,
        idle_timeout: float,
        wait: bool = False,
        live_open: LiveOpen | None = None,
        live_stop: LiveStop | None = None,
        media_key: MediaKeyType = MediaKeyType.RSA,
        live_view: LiveView | None = None,
    ) -> MediaStream:
        """See :meth:`StationSession.async_open_live`."""
        standalone = self._session.standalone
        if standalone:
            single = live_open in (None, LiveOpen.SINGLE, LiveOpen.SINGLE_NO_EXT)
        else:
            single = live_open in (LiveOpen.SINGLE, LiveOpen.SINGLE_NO_EXT)
        homebase3 = self._session.homebase3
        bare_stop = standalone or not homebase3
        flag = LIVE_OPEN_SUBHEADER_FLAG
        nvr = live_open in NVR_OPENS
        if (single or nvr) and not standalone and live_stop is not None:
            bare_stop = live_stop is LiveStop.BARE
        if single and live_open is LiveOpen.SINGLE_NO_EXT:
            flag = 0  # subheader byte 4 (the stream id) is 0 without extValue
        if nvr:
            view = live_view or live_view_of(channel, (), LensView.MAIN)

            def open_frame(account_id: str, key_hex: str) -> tuple[int, bytes]:
                player = player_input(
                    account_id=account_id, key_hex=key_hex, view=view, station_fields=homebase3
                )
                recipe = open_live_stream_nvr(
                    channel=channel,
                    player=player,
                    camera_type_from_lens=live_open is LiveOpen.NVR_LENS,
                )
                body = json.dumps(dict(recipe.params or {}), separators=(",", ":"))
                return FrameType.CMD_TRANSFER, body.encode()

        elif single:

            def open_frame(account_id: str, key_hex: str) -> tuple[int, bytes]:
                recipe = open_live_stream_single(
                    channel=channel,
                    account_id=account_id,
                    key_hex=key_hex,
                    ext_value=live_open is not LiveOpen.SINGLE_NO_EXT,
                )
                return recipe.cmd, recipe.plaintext()

        else:

            def open_frame(account_id: str, key_hex: str) -> tuple[int, bytes]:
                payload = start_realtime_media_payload(
                    account_id, channel, key_hex, homebase3=homebase3
                )
                body = self.media_msg(account_id, CMD_START_REALTIME_MEDIA, channel, payload)
                return FrameType.CMD_TRANSFER, body

        def stop_frame(account_id: str) -> tuple[int, bytes]:
            if bare_stop:
                recipe = close_live_stream()
                # A standalone device's own 1700 stream stops with four zero bytes.
                body_channel = 0 if standalone and single else channel
                return recipe.cmd, recipe.plaintext(body_channel)
            payload = stop_realtime_media_payload(account_id, channel)
            body = self.media_msg(account_id, CMD_STOP_REALTIME_MEDIA, channel, payload)
            return FrameType.CMD_TRANSFER, body

        if not (standalone and single):
            left = self._session.wake_backoff_left(channel)
            if left > 0:
                raise CameraWakeError(
                    CMD_START_REALTIME_MEDIA,
                    self._session._wake_backoff.failures[channel][2],
                    f"the station could not wake the camera on channel {channel}; "
                    f"not retried for another {left:.0f}s",
                    retry_after=left,
                )
        _LOGGER.debug(
            "%s: live open %s (%s%s) on channel %d, subheader flag 0x%02x, %s stop",
            self._session._log_name,
            (live_open or (LiveOpen.SINGLE if single else LiveOpen.STATION)).value,
            "1700/1000" if single else "1350/1003",
            f", view {view.view.value}" if nvr else "",
            channel,
            flag,
            "bare 1004" if bare_stop else "1350/1004",
        )

        if standalone or self._session._budget.owner is not None:
            return await self.open_stream(
                CMD_START_REALTIME_MEDIA,
                channel,
                open_frame,
                stop_frame,
                first_frame_timeout=first_frame_timeout,
                idle_timeout=idle_timeout,
                wait=wait,
                media_key=media_key,
                flag=flag,
            )
        extra = await self._session._budget.live_route(first_frame_timeout, wait)
        if extra is not None:
            return await self._session._budget.open_extra_live(
                extra,
                channel,
                first_frame_timeout,
                idle_timeout,
                media_key,
                live_open=live_open,
                live_stop=live_stop,
                live_view=live_view,
            )
        try:
            return await self.open_stream(
                CMD_START_REALTIME_MEDIA,
                channel,
                open_frame,
                stop_frame,
                first_frame_timeout=first_frame_timeout,
                idle_timeout=idle_timeout,
                wait=wait,
                media_key=media_key,
                flag=flag,
            )
        finally:
            self._session._budget.slot_claimed = False
            self._session._budget.notify_capacity()

    async def open_recording(
        self,
        path: str,
        channel: int,
        *,
        download: bool = False,
        first_frame_timeout: float,
        idle_timeout: float,
        wait: bool = False,
    ) -> MediaStream:
        """See :meth:`StationSession.async_open_recording`."""
        if not is_station_recording_path(path):
            raise UnsupportedError("not a validated station recording path")
        # The app chooses native or JSON playback by station family, not filename.
        if history_query_verb(self._session.serial) == DB_QUERY_LOCAL_EVENTS:
            command = CMD_DOWNLOAD_VIDEO if download else CMD_RECORD_VIEW
            return await self.open_stream(
                command,
                channel,
                lambda _account_id, _key_hex: (command, b""),
                None,
                first_frame_timeout=first_frame_timeout,
                idle_timeout=idle_timeout,
                wait=wait,
                media_key=MediaKeyType.ECC,
                native_recording_path=path,
            )
        if path.endswith(".dat"):
            raise UnsupportedError("a 10011 station cannot play a native .dat path")
        command = CMD_DOWNLOAD_VIDEO if download else CMD_RECORD_VIEW
        build = download_video_payload if download else record_view_payload
        return await self.open_stream(
            command,
            channel,
            lambda account_id, key_hex: (
                FrameType.CMD_TRANSFER,
                self.media_msg(account_id, command, channel, build(path, key_hex)),
            ),
            None,
            first_frame_timeout=first_frame_timeout,
            idle_timeout=idle_timeout,
            wait=wait,
        )

    async def open_stream(
        self,
        command: int,
        channel: int,
        open_frame: Callable[[str, str], tuple[int, bytes]],
        stop_body: Callable[[str], tuple[int, bytes]] | None,
        *,
        first_frame_timeout: float,
        idle_timeout: float,
        wait: bool,
        media_key: MediaKeyType = MediaKeyType.RSA,
        flag: int = LIVE_OPEN_SUBHEADER_FLAG,
        native_recording_path: str | None = None,
    ) -> MediaStream:
        await self._session.async_connect()
        creds = self._session._require_creds()
        if native_recording_path is not None:
            # HomeBase 2's recording key is the station owner account's ECC key;
            # the newer JSON media path creates a fresh per-open key instead.
            decoder = MediaDecoder(ecc_private_key=ecc_private_key_from_hex(creds.ecc_private_key))
            frame_type, body = command, b""
        else:
            if media_key is MediaKeyType.ECC:
                key_hex, ecc_key = generate_media_ecc_key()
                decoder = MediaDecoder(ecc_private_key=ecc_key)
            else:
                # RSA key generation takes tens of milliseconds: keep it off the event loop.
                key_hex, rsa_key = await asyncio.to_thread(generate_media_rsa_key)
                decoder = MediaDecoder(rsa_key)
            frame_type, body = open_frame(creds.account_id, key_hex)
        slot_deadline = time.monotonic() + first_frame_timeout
        # The slot wait and the drain run without the op lock, so commands are not
        # queued behind them; the lock is taken only to open, after re-checking both.
        drain_deadline: float | None = None
        while True:
            if self.stream is not None:
                # An abandoned stream holds the slot for good: its deadlines are only
                # evaluated while something reads it. Reclaim it here as well as in the
                # supervisor, so an unsupervised session is not stuck either.
                self.close_abandoned()
            if self.stream is not None:
                await self.wait_for_slot(wait, slot_deadline, first_frame_timeout)
                drain_deadline = None
                continue
            if drain_deadline is None:
                drain_deadline = time.monotonic() + self._session._media_waits().drain_max
            pause = self.drain_wait(drain_deadline)
            if pause > 0:
                await asyncio.sleep(pause)
                continue
            async with self._session._op("media open"):
                if not self.slot_free.is_set() or self.drain_wait(drain_deadline) > 0:
                    continue  # another open won the slot, or frames arrived meanwhile
                stream = MediaStream(
                    self._session,
                    command=command,
                    channel=channel,
                    decoder=decoder,
                    stop_body=(None if stop_body is None else lambda: stop_body(creds.account_id)),
                    first_frame_timeout=first_frame_timeout,
                    idle_timeout=idle_timeout,
                )
                _LOGGER.debug(
                    "%s: opening %s (cmd %d) on channel %d with an %s key",
                    self._session._log_name,
                    "a recording" if command in _RECORDING_COMMANDS else "live media",
                    command,
                    channel,
                    media_key,
                )
                stream._open_frame_type = frame_type
                self.set_stream(stream)
                try:
                    if native_recording_path is not None:
                        stream._open_index = self._session._send_native_recording(
                            native_recording_path,
                            channel,
                            creds.account_id,
                            download=command == CMD_DOWNLOAD_VIDEO,
                        )
                    elif command == CMD_START_REALTIME_MEDIA:
                        # The station picks the live camera from the subheader, not the JSON.
                        stream._open_index = self._session._send_secure(
                            body, frame_type=frame_type, dev_type=channel, flag=flag
                        )
                    else:
                        stream._open_index = self._session._send_secure(body, frame_type=frame_type)
                except BaseException:
                    self.set_stream(None)
                    raise
                self._session._media_counters.opens += 1
                return stream

    async def wait_for_slot(self, wait: bool, deadline: float, timeout: float) -> None:
        """Wait for the open stream to close (``wait``), or raise at once / at ``deadline``."""
        if wait:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(remaining):
                        await self.slot_free.wait()
                if self.stream is None:
                    return
            raise CommunicationError(
                f"a media stream is still open on this session after {timeout:g}s"
            )
        raise CommunicationError("a media stream is already open on this session; close it first")

    def set_stream(self, stream: MediaStream | None) -> None:
        self.stream = stream
        self._session._last_used = time.monotonic()
        if stream is None:
            self.slot_free.set()
            self._session._budget.notify_capacity()
            if self._session._budget.owner is not None and not self._session._closed:
                # After the caller's stop (1004) goes out: then the CLOSE.
                asyncio.get_running_loop().call_soon(self._session._budget.end_extra_live)
            if self.pinger is not None:
                self.pinger.cancel()
                self.pinger = None
        else:
            self.slot_free.clear()
            if self._session.standalone and self.pinger is None:
                self.pinger = asyncio.get_running_loop().create_task(
                    self.ping_while_streaming(),
                    name=f"eufy-security-ping-{self._session._log_name}",
                )

    async def ping_while_streaming(self) -> None:
        """Send the app's 1139 PING every ``p2p.session.MEDIA_PING_INTERVAL`` while a stream is open."""
        while self.stream is not None and self._session.connected:
            self._session._keys.gcm_counter = (self._session._keys.gcm_counter + 2) & 0xFF
            with contextlib.suppress(EufySecurityError):
                self._session._require_transport().send_drw(
                    0, app_ping_frame(self._session._keys.gcm_counter)
                )
            await asyncio.sleep(self._session._media_waits().ping_interval)

    def drain_wait(self, deadline: float) -> float:
        """Seconds to wait until the previous stream's frames stop arriving (0: open now).

        Whatever ended that stream — a close, its idle end, a rejected open or a
        first-frame timeout — the station may still be sending it, and on the wire
        its P-frames are indistinguishable from the next stream's. The wait is
        bounded by ``deadline``.
        """
        waits = self._session._media_waits()
        now = time.monotonic()
        quiet_at = self.rx_at + waits.drain_gap
        if now >= quiet_at:
            return 0.0
        if now >= deadline:
            if self._session._throttle.should_log("media-drain-max"):
                _LOGGER.debug(
                    "%s: media still arriving after %.0fs; opening anyway",
                    self._session._log_name,
                    waits.drain_max,
                )
            return 0.0
        return min(quiet_at, deadline) - now

    @staticmethod
    def media_msg(account_id: str, command: int, channel: int, payload: Mapping[str, Any]) -> bytes:
        return device_msg(
            account_id,
            command,
            payload,
            channel=channel,
            value3=command,
            transaction=str(int(time.time() * 1000)),
            media=True,
        )

    def detach(self, stream: MediaStream) -> None:
        """Release the session from ``stream`` and send its stop, if it has one (live: 1004)."""
        if self.stream is not stream:
            return
        self.set_stream(None)
        if stream._stop_body is not None and self._session.connected:
            _LOGGER.debug("%s: stopping media (cmd %d)", self._session._log_name, stream.command)
            frame_type, body = stream._stop_body()
            with contextlib.suppress(EufySecurityError):
                self._session._send_secure(body, frame_type=frame_type, dev_type=stream.channel)

    def take_reply(self, stream: MediaStream, inbound: Inbound) -> bool:
        """Whether ``inbound`` is the reply to ``stream``'s open (then it is consumed here)."""
        obj = inbound.json()
        if obj is None or json_int(obj.get("cmd")) != stream.command:
            return False
        _LOGGER.debug(
            "%s: media cmd %d reply code %s",
            self._session._log_name,
            stream.command,
            obj.get("code"),
        )
        code = json_int(obj.get("code"))
        if code is not None and code != 0:
            self.fail(_rejection(stream.command, code, ECB_RESULT_CODES.get(code, "")))
        return True

    def answers_live_open(self, stream: MediaStream, inbound: Inbound) -> bool:
        """Whether the receipt ``inbound`` can answer ``stream``'s live open: the stream
        has not started and the receipt has the open's frame type. Receipts carry no
        command id, so a 1700 receipt is the open's only while no 1700 recipe waits."""
        if (
            stream._started
            or stream.command != CMD_START_REALTIME_MEDIA
            or inbound.type != stream._open_frame_type
        ):
            return False
        return (
            inbound.type != RecipeCommand.DOORBELL_PAYLOAD
            or not self._session._recipe_lock.locked()
        )

    def take_open_refusal(self, stream: MediaStream | None, inbound: Inbound, code: int) -> bool:
        """Fail a 1700 live open that has not started on its non-zero receipt."""
        if (
            stream is None
            or inbound.type != RecipeCommand.DOORBELL_PAYLOAD
            or not self.answers_live_open(stream, inbound)
        ):
            return False
        _LOGGER.debug(
            "%s: live open on channel %d refused: receipt %d %s",
            self._session._log_name,
            stream.channel,
            code,
            RECEIPT_CODES.get(code, ""),
        )
        self.fail(_receipt_error(RecipeCommand.DOORBELL_PAYLOAD, code))
        return True

    def take_wake_failure(self, stream: MediaStream | None, inbound: Inbound, code: int) -> bool:
        """Fail a HomeBase live open that has not started on a wake-failure receipt.

        Receipts carry no command id; a wake failure can only answer a command that
        wakes a camera, and the live open is the only one of those.
        """
        if stream is None or not self.answers_live_open(stream, inbound):
            return False
        failures = self._session._wake_backoff.failures.get(stream.channel, (0, 0.0, code))[0] + 1
        wake_backoff = self._session._media_waits().wake_backoff
        backoff = wake_backoff[min(failures, len(wake_backoff)) - 1]
        self._session._wake_backoff.failures[stream.channel] = (
            failures,
            time.monotonic() + backoff,
            code,
        )
        _LOGGER.info(
            "%s: the station could not wake the camera on channel %d (code %d %s); "
            "live opens of it refused for %.0fs",
            self._session._log_name,
            stream.channel,
            code,
            RECEIPT_CODES.get(code, ""),
            backoff,
        )
        self.fail(_receipt_error(stream.command, code))
        return True

    def fail(self, error: Exception) -> None:
        if self.stream is not None:
            self.stream._fail(error)
            self.set_stream(None)

    def count_failure(self, error: Exception, channel: int) -> None:
        """Count a stream of ``channel`` that ended in ``error``, unless the client closed
        the session."""
        if not self._session._closed:
            name = type(error).__name__
            counters = self._session._media_counters
            counters.failures[name] += 1
            counters.failures_by_channel.setdefault(channel, Counter())[name] += 1

    def close_abandoned(self) -> None:
        """Release a media stream whose deadline passed with nobody reading it.

        A stream evaluates its own timeouts only while it is being iterated, so
        ``async for ... : break`` without closing leaves the session's one media slot
        taken and the camera streaming for good. Waking the stream makes the next read
        raise as it would have; detaching frees the slot for the next open.
        """
        for extra in list(self._session._budget.extra_live):
            extra._media_slot.close_abandoned()
        stream = self.stream
        if stream is None or not stream._expired(time.monotonic()):
            return
        _LOGGER.debug(
            "%s: media stream for command %d timed out unread; releasing the slot",
            self._session._log_name,
            stream.command,
        )
        stream._wake.set()
        self.detach(stream)


class SlotOwner(StreamOwner, Protocol):
    """The station session members a :class:`MediaSlot` uses."""

    serial: str
    _closed: bool
    _last_used: float
    _keys: SessionKeys
    _throttle: LogThrottle
    _recipe_lock: asyncio.Lock
    _budget: SessionBudget

    @property
    def standalone(self) -> bool: ...

    @property
    def homebase3(self) -> bool: ...

    @property
    def connected(self) -> bool: ...

    def wake_backoff_left(self, channel: int) -> float: ...

    def _media_waits(self) -> MediaWaits: ...

    async def async_connect(self) -> None: ...

    def _require_creds(self) -> P2PCredentials: ...

    def _require_transport(self) -> PPPPTransport: ...

    def _op(self, label: str) -> AbstractAsyncContextManager[None]: ...

    def _send_secure(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int: ...

    def _send_native_recording(
        self, path: str, channel: int, account_id: str, *, download: bool
    ) -> int: ...
