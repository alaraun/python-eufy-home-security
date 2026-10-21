"""Read-only WebRTC diagnostics for a webrtc_only station, as a report safe to share.

Built to run on a volunteer's own hardware (the webrtc_only models, T9000/T8N00, this
library otherwise skips). The report dataclasses hold only *descriptors*: model codes,
firmware and SDK versions, channels, lengths, counts, timings, protocol-header bytes,
JSON key names and a whitelist of small integer fields. They have no field for a key,
a serial, an address, a token, an account id or any audio/video payload, so the whole
report can be read and shared as-is.

The collector drives the library's own path (:meth:`~.session.RtcSession.start`,
:meth:`~.session.RtcSession.open_data_channel`, :meth:`~.session.RtcSession.open_live`)
for one station: signaling, the kind-5 data channel, a heartbeat, read-only queries,
an optional window that records the station's notifications, and an optional live
view whose packet and frame counters (never payload) are recorded.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import struct
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, cast

from ..devices.recipes import WEBRTC_ONLY_STATIONS
from ..exceptions import CommunicationError, EufySecurityError
from ..p2p.messages import device_msg
from ..p2p.storage_info import CMD_STORAGE, storage_query_payload
from ..p2p.xzyh import HEADER_LEN, MAGIC, encode_frame
from .command import decrypt_command_reply, decrypt_notification, is_sealed
from .config import (
    commands_encrypted,
    data_channel_kcp_type,
    firmware_number,
    signaling_domain,
    signaling_ipv4,
)
from .data_channel import DataMsgType
from .live import LIVE_OPEN_FRAME, live_open_frame, msg_id, stream_id

if TYPE_CHECKING:
    from ..cloud.models import CloudDevice
    from .media import IceTransport
    from .session import DataChannelCall, LiveCall, RtcSession

#: XZYH frame type of the data channel's heartbeat (a bare 16-byte frame, no body).
_HEARTBEAT_XZYH: Final = 0x0473
#: XZYH frame type of a 1350 command / command reply.
_COMMAND_XZYH: Final = 0x0546
#: Subheader of a plaintext 1350 command before sealing.
_COMMAND_SUBHEADER: Final = bytes([8, 0, 0, 8, 0, 0])
#: The channel the app addresses station-level commands to.
STATION_CHANNEL: Final = 255
#: Read-only station queries: 1307 storage info, 9100 the station's bound devices.
_CMD_BIND_LIST: Final = 9100
_HEARTBEAT_TIMEOUT: Final = 3.0
_COMMAND_TIMEOUT: Final = 8.0
_LIVE_OPEN_WAIT: Final = 10.0
_MAX_MESSAGES: Final = 200
_MAX_NAMES: Final = 80
_MAX_VALUES: Final = 16
#: Integer JSON fields whose values the report keeps (status codes, modes, channels).
_INT_FIELDS: Final = frozenset(
    {
        "code",
        "cmd",
        "status",
        "result",
        "ret",
        "error_code",
        "mode",
        "mode_type",
        "guard_mode",
        "current_mode",
        "arm_mode",
        "alarm_mode",
        "param_type",
        "mChannel",
        "channel",
        "device_channel",
        "device_type",
        "type",
        "version",
        "value",
        "num",
        "count",
        "total",
        "msg_id",
    }
)
_SAFE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")


def _safe_name(name: str) -> str:
    """A JSON key name, or ``"?"`` for one that could carry an identifier (a serial
    used as a key, a long digit run)."""
    digits = sum(c.isdigit() for c in name)
    return name if _SAFE_NAME.match(name) and digits < 6 else "?"


@dataclass(frozen=True, slots=True)
class StationRecord:
    """A station's cloud record, by presence and version (no serial, DID, license or
    server address), plus what the app derives from it."""

    model: str
    is_webrtc_only: bool
    main_sw_version: str | None
    webrtc_sdk_version: str | None
    member_type: int | None
    """0 guest, 1 admin, 2 owner (the logged-in account's role)."""
    has_p2p_did: bool
    has_p2p_license: bool
    has_app_conn: bool
    signaling_servers: int
    signaling_ipv4: bool
    signaling_domain: bool
    webrtc_online_status: int | None
    kcp_type: int
    commands_encrypted: bool


@dataclass(frozen=True, slots=True)
class ChildRecord:
    """A device paired to the station: its model, channel and firmware."""

    model: str
    channel: int | None
    main_sw_version: str | None
    has_signaling: bool
    """Whether its own record carries ``signaling_servers`` and ``p2p_license``."""


@dataclass(frozen=True, slots=True)
class CallReport:
    """The kind-5 CALL answer, by field length (no values)."""

    answered: bool
    ice_ufrag_len: int
    ice_pwd_len: int
    content_key_len: int
    content_iv_len: int
    turn_present: bool
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class IceReport:
    """ICE connectivity by role and candidate-type counts (no addresses)."""

    connected: bool
    controlling: bool | None
    local_candidate_types: dict[str, int]
    remote_candidate_types: dict[str, int]


@dataclass(frozen=True, slots=True)
class MessageReport:
    """One inbound data-channel message, described without its payload."""

    phase: str
    at_ms: int
    msg_type: int
    """WrtcLinkProtocol type: 1 command, 2 file, 3 notification, 4 playback, 99 heartbeat."""
    length: int
    header_hex: str | None
    """The 16-byte XZYH header (type, length, subheader), when the payload is XZYH."""
    sealed: bool
    opened: bool
    key: str | None
    """``device_content_key`` / ``client_content_key`` for a sealed body that opened."""
    wrapper: str | None
    """``reply`` (tag|iv|counter|ct) or ``notification`` (tag|iv|ct)."""
    counter: int | None
    plaintext_len: int | None
    status: int | None
    """The int32 at the head of a body that is not JSON (a status reply)."""
    json_keys: list[str]
    json_ints: dict[str, list[int]]


@dataclass(frozen=True, slots=True)
class CommandReport:
    """One read-only command and where its reply is in :attr:`StationReport.messages`."""

    name: str
    sent: bool
    reply_index: int | None
    reply_ms: int | None


@dataclass(frozen=True, slots=True)
class LiveAttempt:
    route: str
    """``data_channel`` (the T9000/T8N00 handlers' route) or ``rtcp``."""
    status: int | None
    """The station's status for the open on the RTCP route (0 or a P2P error code)."""
    first_frame_ms: int | None


@dataclass(frozen=True, slots=True)
class LiveReport:
    """A live view of one camera channel: packet and frame counters, never payload."""

    channel: int
    camera_model: str | None
    answered: bool
    ice_connected: bool
    attempts: list[LiveAttempt]
    listen_s: float
    media: dict[str, object]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class StationReport:
    """One station's diagnostics."""

    station: StationRecord
    children: list[ChildRecord]
    channel: int
    phase_reached: str
    """The last phase that ran: signaling, call, heartbeat, commands, watch, live, done."""
    call: CallReport | None = None
    ice: IceReport | None = None
    heartbeat_ms: int | None = None
    heartbeats: int = 0
    """Heartbeat messages received (not listed in :attr:`messages`)."""
    commands: list[CommandReport] = field(default_factory=list)
    messages: list[MessageReport] = field(default_factory=list)
    live: LiveReport | None = None
    error: str | None = None
    """``<phase>: <exception type>`` (never the message, which may carry an address)."""
    error_code: int | None = None


# ── cloud records ────────────────────────────────────────────────────────────


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def describe_station(device: CloudDevice) -> StationRecord:
    """The descriptor of a station's cloud record (``device.raw``)."""
    raw = device.raw
    model = device.device_sn[:5]
    servers = raw.get("signaling_servers")
    servers = servers if isinstance(servers, list) else []
    sdk = _str(raw.get("webrtc_sdk_version"))
    online = raw.get("webrtc_online_status")
    return StationRecord(
        model=model,
        is_webrtc_only=model in WEBRTC_ONLY_STATIONS,
        main_sw_version=device.main_sw_version,
        webrtc_sdk_version=sdk,
        member_type=device.member_type,
        has_p2p_did=bool(_str(raw.get("p2p_did"))),
        has_p2p_license=bool(_str(raw.get("p2p_license"))),
        has_app_conn=bool(_str(raw.get("app_conn"))),
        signaling_servers=len(servers),
        signaling_ipv4=signaling_ipv4(servers) is not None,
        signaling_domain=signaling_domain(servers) is not None,
        webrtc_online_status=online if isinstance(online, int) else None,
        kcp_type=data_channel_kcp_type(model, sdk),
        commands_encrypted=commands_encrypted(model, firmware_number(device.main_sw_version)),
    )


def describe_children(station_sn: str, devices: Iterable[CloudDevice]) -> list[ChildRecord]:
    """The devices paired to ``station_sn``, by channel."""
    children = [d for d in devices if d.station_sn == station_sn and d.device_sn != station_sn]
    return [
        ChildRecord(
            model=d.device_sn[:5],
            channel=d.channel,
            main_sw_version=d.main_sw_version,
            has_signaling=bool(d.raw.get("signaling_servers")) and bool(d.raw.get("p2p_license")),
        )
        for d in sorted(children, key=lambda d: (d.channel is None, d.channel or 0))
    ]


def first_camera_channel(children: Sequence[ChildRecord]) -> ChildRecord | None:
    """The paired device with the lowest channel (the default live-view target)."""
    return next((c for c in children if c.channel is not None), None)


# ── message description ──────────────────────────────────────────────────────


def _walk(obj: Any, prefix: str, names: list[str], ints: dict[str, list[int]]) -> None:
    if isinstance(obj, dict):
        for raw_key, value in obj.items():
            key = _safe_name(str(raw_key))
            path = f"{prefix}.{key}" if prefix else key
            if len(names) < _MAX_NAMES and path not in names:
                names.append(path)
            if key in _INT_FIELDS and isinstance(value, int) and not isinstance(value, bool):
                values = ints.setdefault(path, [])
                if len(values) < _MAX_VALUES:
                    values.append(value)
            if prefix.count(".") < 2:
                _walk(value, path, names, ints)
    elif isinstance(obj, list):
        for item in obj[:_MAX_VALUES]:
            _walk(item, f"{prefix}[]", names, ints)
    elif isinstance(obj, str) and obj[:1] in "{[":
        with contextlib.suppress(ValueError):
            _walk(json.loads(obj), prefix, names, ints)


def _describe_plain(plain: bytes) -> tuple[list[str], dict[str, list[int]], int | None]:
    """JSON key paths and whitelisted ints of a plaintext body, else its int32 status."""
    text = plain.rstrip(b"\x00")
    try:
        parsed = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        status = struct.unpack_from("<i", plain)[0] if len(plain) >= 4 else None
        return [], {}, status
    names: list[str] = []
    ints: dict[str, list[int]] = {}
    _walk(parsed, "", names, ints)
    return names, ints, None


def describe_message(
    payload: bytes, msg_type: int, keys: Mapping[str, bytes], *, phase: str, at_ms: int
) -> MessageReport:
    """Describe one inbound data-channel payload: its header, which key and wrapper
    open a sealed body, and the body's JSON key paths — never the bytes themselves."""
    xzyh = len(payload) >= HEADER_LEN and payload[:4] == MAGIC
    header_hex = payload[:HEADER_LEN].hex() if xzyh else None
    body = payload[HEADER_LEN:] if xzyh else b""
    sealed = xzyh and is_sealed(payload)
    key_label = wrapper = None
    counter = plain = None
    if sealed:
        for label, key in keys.items():
            for name, opener in (
                ("reply", decrypt_command_reply),
                ("notification", decrypt_notification),
            ):
                try:
                    plain = opener(key, body)
                except EufySecurityError:
                    continue
                key_label, wrapper = label, name
                break
            if plain is not None:
                break
        if wrapper == "reply" or (plain is None and len(body) >= 32):
            counter = int.from_bytes(body[28:32], "little")
    elif body:
        plain = body
    names: list[str] = []
    ints: dict[str, list[int]] = {}
    status = None
    if plain is not None:
        names, ints, status = _describe_plain(plain)
    return MessageReport(
        phase=phase,
        at_ms=at_ms,
        msg_type=msg_type,
        length=len(payload),
        header_hex=header_hex,
        sealed=sealed,
        opened=plain is not None,
        key=key_label,
        wrapper=wrapper,
        counter=counter,
        plaintext_len=len(plain) if plain is not None else None,
        status=status,
        json_keys=names,
        json_ints=ints,
    )


# ── the collector ────────────────────────────────────────────────────────────


class _Inbox:
    """Reads every data-channel message, describes it under the current phase, and
    hands command replies and heartbeat echoes to whoever waits for them."""

    def __init__(self, call: DataChannelCall, keys: Mapping[str, bytes]) -> None:
        self._call = call
        self._keys = keys
        self._start = time.monotonic()
        self.phase = "heartbeat"
        self.messages: list[MessageReport] = []
        self.replies: asyncio.Queue[int] = asyncio.Queue()
        self.heartbeat = asyncio.Event()
        self.heartbeats = 0
        self._task = asyncio.ensure_future(self._run())

    def ms(self) -> int:
        return int((time.monotonic() - self._start) * 1000)

    async def _run(self) -> None:
        with contextlib.suppress(EufySecurityError):
            while True:
                msg = await self._call.recv()
                payload = msg.payload
                if msg.msg_type == DataMsgType.HEARTBEAT or (
                    len(payload) >= HEADER_LEN
                    and payload[:4] == MAGIC
                    and struct.unpack_from("<H", payload, 4)[0] == _HEARTBEAT_XZYH
                ):
                    self.heartbeat.set()
                    self.heartbeats += 1
                    continue
                if len(self.messages) >= _MAX_MESSAGES:
                    continue
                self.messages.append(
                    describe_message(
                        payload, int(msg.msg_type), self._keys, phase=self.phase, at_ms=self.ms()
                    )
                )
                if msg.msg_type == DataMsgType.COMMAND and len(payload) > HEADER_LEN:
                    self.replies.put_nowait(len(self.messages) - 1)

    async def close(self) -> None:
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task


def _error(phase: str, exc: EufySecurityError) -> tuple[str, int | None]:
    code = getattr(exc, "code", None)
    return f"{phase}: {type(exc).__name__}", code if isinstance(code, int) else None


async def _probe_commands(
    call: DataChannelCall, inbox: _Inbox, account_id: str
) -> list[CommandReport]:
    probes = {
        "storage_1307": device_msg(
            account_id, CMD_STORAGE, storage_query_payload(), channel=STATION_CHANNEL
        ),
        "bind_list_9100": device_msg(account_id, _CMD_BIND_LIST, {}, channel=STATION_CHANNEL),
    }
    reports: list[CommandReport] = []
    for name, message in probes.items():
        inbox.phase = name
        while not inbox.replies.empty():
            inbox.replies.get_nowait()
        start = time.monotonic()
        await call.send_command(call.seal(encode_frame(_COMMAND_XZYH, message, _COMMAND_SUBHEADER)))
        index: int | None = None
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_COMMAND_TIMEOUT):
                index = await inbox.replies.get()
        reports.append(
            CommandReport(
                name=name,
                sent=True,
                reply_index=index,
                reply_ms=int((time.monotonic() - start) * 1000) if index is not None else None,
            )
        )
    return reports


async def _wait_frame(live: LiveCall, timeout: float, start: float) -> int | None:
    try:
        async with asyncio.timeout(timeout):
            await live.media.wait_media()
    except TimeoutError:
        return None
    return int((time.monotonic() - start) * 1000)


async def _probe_live(
    session: RtcSession,
    call: DataChannelCall,
    inbox: _Inbox,
    *,
    channel: int,
    camera_model: str,
    account_id: str,
    listen_s: float,
) -> LiveReport:
    """Open a kind-6 live call to the camera's channel, send the live open over the
    data channel (the T9000/T8N00 route), fall back to RTCP when no frame arrives,
    then count packets and frames for ``listen_s``."""
    attempts: list[LiveAttempt] = []
    answered = connected = False
    live: LiveCall | None = None
    error: str | None = None
    try:
        live = await session.open_live(channel, account_id=account_id, send_open=False)
        answered = connected = True
        inbox.phase = "live_open_data_channel"
        start = time.monotonic()
        frame = live_open_frame(channel, account_id, stream=stream_id(0), message_id=msg_id(0))
        await call.send_command(call.seal(frame))
        first = await _wait_frame(live, _LIVE_OPEN_WAIT, start)
        attempts.append(LiveAttempt("data_channel", None, first))
        if first is None and live.cipher is not None:
            inbox.phase = "live_open_rtcp"
            stream = stream_id(1)
            reply: asyncio.Future[int] = asyncio.get_running_loop().create_future()
            live._waiters[(LIVE_OPEN_FRAME, stream)] = reply
            start = time.monotonic()
            rtcp_frame = live_open_frame(channel, account_id, stream=stream, message_id=msg_id(1))
            await live.media.send_command(live.cipher.encrypt(rtcp_frame))
            first = await _wait_frame(live, _LIVE_OPEN_WAIT, start)
            status = reply.result() if reply.done() else None
            attempts.append(LiveAttempt("rtcp", status, first))
        inbox.phase = "live"
        if any(a.first_frame_ms is not None for a in attempts):
            await asyncio.sleep(listen_s)
    except EufySecurityError as exc:
        error = _error("live", exc)[0]
    finally:
        stats_fn = getattr(live.media, "stats", None) if live is not None else None
        media = cast("dict[str, object]", stats_fn()) if callable(stats_fn) else {}
        await session.close_live(channel)
    return LiveReport(
        channel=channel,
        camera_model=camera_model,
        answered=answered,
        ice_connected=connected,
        attempts=attempts,
        listen_s=listen_s,
        media=media,
        error=error,
    )


def _ice_report(ice: IceTransport, *, connected: bool) -> IceReport:
    diag_fn = getattr(ice, "diagnostics", None)
    diag: dict[str, object] = cast("dict[str, object]", diag_fn()) if callable(diag_fn) else {}
    local = diag.get("local_candidate_types", {})
    remote = diag.get("remote_candidate_types", {})
    controlling = diag.get("controlling")
    return IceReport(
        connected=connected,
        controlling=controlling if isinstance(controlling, bool) else None,
        local_candidate_types=dict(local) if isinstance(local, dict) else {},
        remote_candidate_types=dict(remote) if isinstance(remote, dict) else {},
    )


async def collect_station(
    session: RtcSession,
    *,
    station: StationRecord,
    children: Sequence[ChildRecord],
    account_id: str,
    channel: int = 0,
    camera: ChildRecord | None = None,
    do_commands: bool = True,
    do_live: bool = True,
    listen_s: float = 8.0,
    watch_s: float = 0.0,
    on_watch: Callable[[float], None] | None = None,
    ice: IceTransport | None = None,
) -> StationReport:
    """Run the read-only probes for one station and return its report.

    Starts ``session`` (signaling), opens the data channel on ``channel``, checks the
    heartbeat, sends the read-only queries (``do_commands``), records notifications for
    ``watch_s`` seconds (``on_watch`` is told when that window opens), then opens a live
    view of ``camera`` (``do_live``). ``account_id`` is the station owner's user id the
    commands carry. Any library error ends the run for this station and is recorded as
    the phase and exception *type* only; the session is left for the caller to close.
    """
    from .session import default_ice_factory  # noqa: PLC0415 - optional rtc extra

    transport = ice if ice is not None else default_ice_factory()
    phase = "signaling"
    call_report: CallReport | None = None
    ice_report: IceReport | None = None
    heartbeat_ms: int | None = None
    commands: list[CommandReport] = []
    live: LiveReport | None = None
    inbox: _Inbox | None = None
    error: str | None = None
    code: int | None = None
    call: DataChannelCall | None = None
    try:
        await session.start()
        phase = "call"
        start = time.monotonic()
        call = await session.open_data_channel(channel, ice=transport)
        remote, info = call.remote, call.info
        if remote is None or call.call is None:
            raise CommunicationError("RTC data channel did not answer")
        call_report = CallReport(
            answered=True,
            ice_ufrag_len=len(remote.ice_ufrag),
            ice_pwd_len=len(remote.ice_pwd),
            content_key_len=len(remote.content_key),
            content_iv_len=len(remote.content_iv),
            turn_present=bool(call.call.turn),
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
        ice_report = _ice_report(transport, connected=True)
        keys = {
            "device_content_key": remote.content_key.encode()[:16],
            "client_content_key": info.content_key.encode()[:16],
        }
        inbox = _Inbox(call, keys)
        phase = "heartbeat"
        start = time.monotonic()
        await call.send_command(encode_frame(_HEARTBEAT_XZYH, b"", bytes(6)))
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_HEARTBEAT_TIMEOUT):
                await inbox.heartbeat.wait()
                heartbeat_ms = int((time.monotonic() - start) * 1000)
        if do_commands:
            phase = "commands"
            commands = await _probe_commands(call, inbox, account_id)
        if watch_s > 0:
            phase = inbox.phase = "watch"
            if on_watch is not None:
                on_watch(watch_s)
            await asyncio.sleep(watch_s)
        if do_live and camera is not None and camera.channel is not None:
            phase = "live"
            live = await _probe_live(
                session,
                call,
                inbox,
                channel=camera.channel,
                camera_model=camera.model,
                account_id=account_id,
                listen_s=listen_s,
            )
        phase = "done"
    except EufySecurityError as exc:
        error, code = _error(phase, exc)
        if ice_report is None and phase == "call":
            ice_report = _ice_report(transport, connected=False)
    finally:
        if inbox is not None:
            await inbox.close()
        if call is not None:
            await session.close_data_channel(channel)
        elif phase in ("signaling", "call"):
            await transport.close()
    return StationReport(
        station=station,
        children=list(children),
        channel=channel,
        phase_reached=phase,
        call=call_report,
        ice=ice_report,
        heartbeat_ms=heartbeat_ms,
        heartbeats=inbox.heartbeats if inbox is not None else 0,
        commands=commands,
        messages=inbox.messages if inbox is not None else [],
        live=live,
        error=error,
        error_code=code,
    )


# ── summary ──────────────────────────────────────────────────────────────────


def render_station(st: StationReport) -> list[str]:
    """A short human-readable summary of one station's report (the JSON is the full one)."""
    s = st.station
    lines = [
        f"WebRTC station {s.model} fw {s.main_sw_version} sdk {s.webrtc_sdk_version} "
        f"(kcp_type={s.kcp_type}, encrypted={s.commands_encrypted}) reached {st.phase_reached}"
    ]
    lines.extend(f"  child {c.model} ch {c.channel} fw {c.main_sw_version}" for c in st.children)
    if st.error is not None:
        lines.append(f"  error: {st.error} code={st.error_code}")
    if st.call is not None:
        lines.append(f"  CALL: answered turn={st.call.turn_present} in {st.call.elapsed_ms} ms")
    if st.ice is not None:
        i = st.ice
        lines.append(
            f"  ICE: connected={i.connected} controlling={i.controlling} "
            f"local={i.local_candidate_types} remote={i.remote_candidate_types}"
        )
    if st.call is not None:
        lines.append(f"  heartbeat echo: {st.heartbeat_ms} ms")
    for cmd in st.commands:
        reply = st.messages[cmd.reply_index] if cmd.reply_index is not None else None
        if reply is None:
            lines.append(f"  cmd {cmd.name}: no reply")
        else:
            lines.append(
                f"  cmd {cmd.name}: reply in {cmd.reply_ms} ms opened={reply.opened} "
                f"key={reply.key} keys={reply.json_keys[:8]}"
            )
    notes = [m for m in st.messages if m.msg_type == DataMsgType.NOTIFY]
    lines.append(f"  notifications: {len(notes)}, messages: {len(st.messages)}")
    if st.live is not None:
        lv = st.live
        tried = ", ".join(
            f"{a.route} status={a.status} first_frame={a.first_frame_ms} ms" for a in lv.attempts
        )
        lines.append(
            f"  live ch {lv.channel} ({lv.camera_model}): {tried or 'not opened'} "
            f"error={lv.error} media={lv.media}"
        )
    return lines
