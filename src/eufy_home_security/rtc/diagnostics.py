"""Read-only WebRTC data-channel diagnostics for a station, as a redactable report.

Built to run on a maintainer's or a volunteer's own hardware (the webrtc_only models,
T9000/T8N00, this library otherwise skips) and produce a file safe to share: the report
dataclasses hold only *descriptors* — lengths, counts, booleans, protocol-header bytes,
enum labels — and have no field for a key, a full serial, an address, a token, a cloud
account id or any audio/video payload. Redaction is by construction, so the whole report
can be read and shared as-is.

The collector drives the proven path (:meth:`~.session.RtcSession.open_data_channel` +
:class:`~.session.DataChannelCall`), so it exercises the same code a consumer would. Every
phase is read-only: a kind-5 CALL, ICE, KCP, a heartbeat, read-only storage/device-info
queries, and an optional live open whose *packet metadata* (never payload) is recorded.
"""

from __future__ import annotations

import asyncio
import json
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, cast

from ..devices.recipes import WEBRTC_ONLY_STATIONS
from ..exceptions import CommunicationError, EufySecurityError
from ..p2p.messages import device_msg
from ..p2p.storage_info import CMD_STORAGE, storage_query_payload
from ..p2p.xzyh import HEADER_LEN, MAGIC, encode_frame
from .command import decrypt_command_reply
from .data_channel import DataMsgType

if TYPE_CHECKING:
    from .media import IceTransport
    from .session import DataChannelCall, RtcSession

#: XZYH frame type of the data channel's heartbeat (a bare 16-byte frame, no body).
_HEARTBEAT_XZYH = 0x0473
#: XZYH frame type of a GCM command / command reply.
_COMMAND_XZYH = 0x0546
_HEARTBEAT_REPLY_TIMEOUT = 3.0
_COMMAND_REPLY_TIMEOUT = 8.0


@dataclass(frozen=True, slots=True)
class CallReport:
    """The kind-5 CALL answer, by field presence and length (no values)."""

    kind: int
    answered: bool
    sdp_info_present: bool
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
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class KcpReport:
    conv: int
    heartbeat_echoed: bool
    heartbeat_reply_ms: int | None


@dataclass(frozen=True, slots=True)
class CommandReport:
    """One read-only command and a description of its reply — never the reply bytes."""

    name: str
    sent: bool
    reply_received: bool
    reply_msg_type: int | None
    reply_decrypted: bool
    reply_key: str | None  # "device_content_key" / "client_content_key" / None
    reply_counter: int | None
    plaintext_len: int | None
    plaintext_json_keys: list[str]  # top-level JSON key NAMES only, no values


@dataclass(frozen=True, slots=True)
class MediaPacketReport:
    """One inbound data-channel packet during the live probe, by shape only."""

    msg_type: int
    length: int
    xzyh_type: int | None


@dataclass(frozen=True, slots=True)
class AvReport:
    """The live-open probe: packet metadata only, never any media payload bytes."""

    live_open_sent: bool
    listen_s: float
    packet_count: int
    total_bytes: int
    distinct_msg_types: list[int]
    packets: list[MediaPacketReport]


@dataclass(frozen=True, slots=True)
class StationReport:
    """One station's data-channel diagnostics (its model code, never its serial)."""

    model: str
    is_webrtc_only: bool
    channel: int
    call: CallReport | None = None
    ice: IceReport | None = None
    kcp: KcpReport | None = None
    commands: list[CommandReport] = field(default_factory=list)
    av: AvReport | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AuthReport:
    """The account side, by presence and count — no email, user id, token or serial."""

    logged_in: bool
    region: str | None
    user_id_present: bool
    device_count: int
    webrtc_only_count: int


@dataclass(frozen=True, slots=True)
class DiagnosticsReport:
    library_version: str
    created_utc: str
    auth: AuthReport
    stations: list[StationReport]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _xzyh_type(frame: bytes) -> int | None:
    """The XZYH frame type (``b"XZYH" | type u16le | …``, so at offset 4), or None if
    ``frame`` is not an XZYH frame. Any outer file_head is stripped by the transport
    before a payload reaches here."""
    if len(frame) >= HEADER_LEN and frame[:4] == MAGIC:
        return int(struct.unpack_from("<H", frame, 4)[0])
    return None


def _describe_reply(
    payload: bytes, keys: dict[str, bytes]
) -> tuple[str | None, int | None, int | None, list[str]]:
    """Describe a command reply: (key_label, counter, plaintext_len, json_keys).

    Tries each candidate media key against the command wrapper (``tag|iv|counter|ct``).
    Returns the key that opened it, the 4-byte counter, the plaintext length and the
    plaintext's top-level JSON key names — never values, never the plaintext itself.
    """
    body = payload[HEADER_LEN:] if len(payload) > HEADER_LEN else b""
    if len(body) < 32:
        return None, None, None, []
    counter = int.from_bytes(body[28:32], "little")
    for label, key in keys.items():
        try:
            plain = decrypt_command_reply(key, body)
        except EufySecurityError:
            continue
        names: list[str] = []
        try:
            parsed = json.loads(plain)
            if isinstance(parsed, dict):
                names = sorted(str(k) for k in parsed)
        except (ValueError, UnicodeDecodeError):
            names = []
        return label, counter, len(plain), names
    return None, counter, None, []


async def _probe_commands(call: DataChannelCall, account_id: str) -> list[CommandReport]:
    if call.cipher is None or call.remote is None or call.info is None:
        raise CommunicationError("RTC data channel is not connected")
    keys = {
        "device_content_key": call.remote.content_key.encode()[:16],
        "client_content_key": call.info.content_key.encode()[:16],
    }
    probes = {
        "storage_1307": device_msg(
            account_id,
            CMD_STORAGE,
            storage_query_payload(),
            transaction=str(int(time.time() * 1000)),
        ),
    }
    reports: list[CommandReport] = []
    for name, message in probes.items():
        clear = encode_frame(_COMMAND_XZYH, message, bytes([8, 0, 0, 8, 0, 0]))
        await call.send_command(call.cipher.encrypt(clear))
        received = decrypted = False
        msg_type = counter = plen = None
        key_label = None
        json_keys: list[str] = []
        try:
            async with asyncio.timeout(_COMMAND_REPLY_TIMEOUT):
                while True:
                    msg = await call.recv()
                    if msg.msg_type == DataMsgType.COMMAND and len(msg.payload) > HEADER_LEN:
                        received = True
                        msg_type = int(msg.msg_type)
                        key_label, counter, plen, json_keys = _describe_reply(msg.payload, keys)
                        decrypted = key_label is not None
                        break
        except TimeoutError:
            pass
        reports.append(
            CommandReport(
                name=name,
                sent=True,
                reply_received=received,
                reply_msg_type=msg_type,
                reply_decrypted=decrypted,
                reply_key=key_label,
                reply_counter=counter,
                plaintext_len=plen,
                plaintext_json_keys=json_keys,
            )
        )
    return reports


def _ice_report(ice: IceTransport, *, connected: bool, elapsed_ms: int) -> IceReport:
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
        elapsed_ms=elapsed_ms,
    )


async def _probe_heartbeat(call: DataChannelCall) -> KcpReport:
    start = time.monotonic()
    await call.send_command(encode_frame(_HEARTBEAT_XZYH, b"", bytes(6)))
    echoed = False
    reply_ms: int | None = None
    try:
        async with asyncio.timeout(_HEARTBEAT_REPLY_TIMEOUT):
            while True:
                msg = await call.recv()
                if _xzyh_type(msg.payload) == _HEARTBEAT_XZYH:
                    echoed = True
                    reply_ms = int((time.monotonic() - start) * 1000)
                    break
    except TimeoutError:
        pass
    return KcpReport(conv=1, heartbeat_echoed=echoed, heartbeat_reply_ms=reply_ms)


async def _probe_av(
    call: DataChannelCall, listen_s: float, live_open_frame: bytes | None
) -> AvReport:
    """Listen for ``listen_s`` and record only the SHAPE of each inbound packet — msg type,
    length, XZYH type, file_head flag — never a payload byte. Optionally sends a caller-
    supplied live-open command first (there is no confirmed webrtc_only open yet)."""
    sent = False
    if live_open_frame is not None and call.cipher is not None:
        await call.send_command(call.cipher.encrypt(live_open_frame))
        sent = True
    packets: list[MediaPacketReport] = []
    total = 0
    types: set[int] = set()
    deadline = time.monotonic() + listen_s
    try:
        while (remaining := deadline - time.monotonic()) > 0:
            async with asyncio.timeout(remaining):
                msg = await call.recv()
            if len(packets) < 200:
                packets.append(
                    MediaPacketReport(int(msg.msg_type), len(msg.payload), _xzyh_type(msg.payload))
                )
            total += len(msg.payload)
            types.add(int(msg.msg_type))
    except TimeoutError:
        pass
    return AvReport(
        live_open_sent=sent,
        listen_s=listen_s,
        packet_count=len(packets),
        total_bytes=total,
        distinct_msg_types=sorted(types),
        packets=packets,
    )


async def collect_station(
    session: RtcSession,
    *,
    model: str,
    channel: int,
    account_id: str,
    do_commands: bool = True,
    do_av: bool = True,
    listen_s: float = 6.0,
    live_open_frame: bytes | None = None,
    ice: IceTransport | None = None,
) -> StationReport:
    """Run the read-only data-channel probes for one station and return its report.

    One bad station never aborts the run: any library error is recorded as the exception
    *type* (never its message, which could carry an address or serial) in ``error``.
    """
    from .session import default_ice_factory  # noqa: PLC0415 - optional rtc extra

    transport = ice if ice is not None else default_ice_factory()
    is_webrtc_only = model in WEBRTC_ONLY_STATIONS
    start = time.monotonic()
    call_report: CallReport | None = None
    ice_report: IceReport | None = None
    kcp_report: KcpReport | None = None
    av_report: AvReport | None = None
    commands: list[CommandReport] = []
    error: str | None = None
    call: DataChannelCall | None = None
    try:
        call = await session.open_data_channel(channel, ice=transport)
        elapsed = int((time.monotonic() - start) * 1000)
        remote = call.remote
        if remote is None or call.call is None:
            raise CommunicationError("RTC data channel did not answer")
        call_report = CallReport(
            kind=5,
            answered=True,
            sdp_info_present=True,
            ice_ufrag_len=len(remote.ice_ufrag),
            ice_pwd_len=len(remote.ice_pwd),
            content_key_len=len(remote.content_key),
            content_iv_len=len(remote.content_iv),
            turn_present=bool(call.call.turn),
            elapsed_ms=elapsed,
        )
        ice_report = _ice_report(transport, connected=True, elapsed_ms=elapsed)
        kcp_report = await _probe_heartbeat(call)
        if do_commands:
            commands = await _probe_commands(call, account_id)
        if do_av:
            av_report = await _probe_av(call, listen_s, live_open_frame)
    except EufySecurityError as exc:
        error = type(exc).__name__  # the type only; a message could carry an address/serial
        ice_report = _ice_report(
            transport, connected=False, elapsed_ms=int((time.monotonic() - start) * 1000)
        )
    finally:
        if call is not None:
            await session.close_data_channel(channel)
        else:
            await transport.close()
    return StationReport(
        model=model,
        is_webrtc_only=is_webrtc_only,
        channel=channel,
        call=call_report,
        ice=ice_report,
        kcp=kcp_report,
        commands=commands,
        av=av_report,
        error=error,
    )


def render(report: DiagnosticsReport) -> str:
    """A short human-readable summary of ``report`` (the JSON is the full payload)."""
    lines = [
        f"eufy-home-security diagnostics (library {report.library_version}, {report.created_utc})",
        f"account: logged_in={report.auth.logged_in} region={report.auth.region} "
        f"devices={report.auth.device_count} webrtc_only={report.auth.webrtc_only_count}",
        "",
    ]
    for station in report.stations:
        lines.append(
            f"station {station.model} (webrtc_only={station.is_webrtc_only}) ch {station.channel}"
        )
        if station.error is not None:
            lines.append(f"  error: {station.error}")
        if station.call is not None:
            c = station.call
            lines.append(
                f"  CALL: answered={c.answered} turn={c.turn_present} in {c.elapsed_ms} ms"
            )
        if station.ice is not None:
            i = station.ice
            lines.append(
                f"  ICE: connected={i.connected} controlling={i.controlling} "
                f"local={i.local_candidate_types} remote={i.remote_candidate_types}"
            )
        if station.kcp is not None:
            k = station.kcp
            lines.append(
                f"  KCP: heartbeat_echoed={k.heartbeat_echoed} ({k.heartbeat_reply_ms} ms)"
            )
        lines.extend(
            f"  cmd {cmd.name}: reply={cmd.reply_received} decrypted={cmd.reply_decrypted} "
            f"key={cmd.reply_key} counter={cmd.reply_counter} json_keys={cmd.plaintext_json_keys}"
            for cmd in station.commands
        )
        if station.av is not None:
            a = station.av
            lines.append(
                f"  A/V: live_open_sent={a.live_open_sent} packets={a.packet_count} "
                f"bytes={a.total_bytes} msg_types={a.distinct_msg_types}"
            )
        lines.append("")
    return "\n".join(lines)
