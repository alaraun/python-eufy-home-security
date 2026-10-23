"""Read-only WebRTC diagnostics for a station the eufy app reaches over WebRTC, as a
report safe to share.

Built to run on a volunteer's own hardware: the stations the eufy app reaches only over
WebRTC (:func:`~..devices.webrtc.app_webrtc_only`), which this library otherwise skips,
and a station with a paired camera the app streams over WebRTC (:func:`webrtc_children`). The report dataclasses hold only *descriptors*: model codes,
firmware and SDK versions, channels, lengths, counts, timings, protocol-header bytes,
JSON key names and a whitelist of small integer fields. They have no field for a key,
a serial, an address, a token, an account id or any audio/video payload, so the whole
report can be read and shared as-is.

The collector drives the library's own path (:meth:`~.session.RtcSession.start`,
:meth:`~.session.RtcSession.open_data_channel`, :meth:`~.session.RtcSession.open_live`)
for one station: signaling, the kind-5 data channel, a heartbeat, read-only queries,
an opt-in re-send of the station's current guard mode, an optional window that records
the station's notifications, and an optional live view whose packet and frame
descriptors (never payload) are recorded. Every wait is bounded, any failure ends the
station's run with the phase it failed in, and an interrupted run still yields its
partial report (``on_report``).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import json
import re
import struct
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, cast

from .._logging import redact_serial
from ..devices.model_settings import BATTERY_PROPERTY, product_code_of, settings_of
from ..devices.webrtc import app_uses_webrtc, app_webrtc_only, route_device
from ..exceptions import CommunicationError, EufySecurityError
from ..models import PARAM_DEV_STATUS, STATION_CHANNEL, GuardMode
from ..p2p.messages import CMD_SET_ARMING, arm_payload, device_msg
from ..p2p.params import GUARD_MODE_PARAM
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
    from .media import IceTransport, TurnServer
    from .sdp import SdpInfo
    from .session import DataChannelCall, LiveCall, RtcSession

#: XZYH frame type of the data channel's heartbeat (a bare 16-byte frame, no body).
_HEARTBEAT_XZYH: Final = 0x0473
#: XZYH frame type of a 1350 command / command reply.
_COMMAND_XZYH: Final = 0x0546
#: Subheader of a plaintext 1350 command before sealing.
_COMMAND_SUBHEADER: Final = bytes([8, 0, 0, 8, 0, 0])
#: Read-only station queries: 1307 storage info, 9100 the station's bound devices.
_CMD_BIND_LIST: Final = 9100
_HEARTBEAT_TIMEOUT: Final = 3.0
_COMMAND_TIMEOUT: Final = 8.0
_LIVE_OPEN_WAIT: Final = 10.0
#: How long signaling (DISCOVER and LOGIN with its retries) may take for one station.
SIGNALING_BUDGET: Final = 45.0
#: A station's whole run is bounded by this plus its watch and listen windows.
STATION_BUDGET: Final = 300.0
_MAX_MESSAGES: Final = 200
_MAX_NAMES: Final = 80
_MAX_VALUES: Final = 16
#: Bytes kept from the head of a payload that is neither XZYH nor JSON.
_HEAD_LEN: Final = 4
#: Bytes of the answer sdp_info kept: the reserved, data-channel and config bytes before
#: the ICE username (see :meth:`~.sdp.SdpInfo.encode`).
_SDP_INFO_HEAD: Final = 6
#: The guard modes the opt-in re-send may repeat: plain selections, no schedule,
#: custom or geofence mode.
REWRITABLE_MODES: Final = frozenset({GuardMode.AWAY, GuardMode.HOME, GuardMode.DISARMED})
#: The name an opt-in guard-mode re-send carries (the station may log it).
REWRITE_USER_NAME: Final = "eufy-security diagnose"
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
        "event_type",
        "state",
        "online",
        "user",
        "delay",
        "alarm_type",
        "push_type",
        "sensor_type",
    }
)
#: The longest digit string a whitelisted field's value is read from.
_MAX_INT_DIGITS: Final = 4
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
    product_code: str | None = None
    guard_mode: int | None = None
    """The cloud's snapshot of the selected guard mode (param 1224)."""
    cloud_param_types: list[int] = field(default_factory=list)
    record_keys: list[str] = field(default_factory=list)
    """The key names of the station's cloud record (no values)."""


@dataclass(frozen=True, slots=True)
class ChildRecord:
    """A device paired to the station: its model, channel and firmware."""

    model: str
    channel: int | None
    main_sw_version: str | None
    has_signaling: bool
    """Whether its own record carries ``signaling_servers`` and ``p2p_license``."""
    product_code: str | None = None
    battery: bool | None = None
    """Whether the model's settings declare a battery; None without a settings file."""
    online: int | None = None
    """The cloud's snapshot of its online flag (param 1131: 1 online, else offline)."""
    cloud_param_types: list[int] = field(default_factory=list)


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
    answer_keys: list[str] = field(default_factory=list)
    """The key names of the device's CALL 200 payload (no values)."""
    sdp_info_head_hex: str | None = None
    """The answer sdp_info's bytes before its ICE username (flags, no credentials)."""
    data_channel_flag: bool | None = None
    timings_ms: dict[str, int] = field(default_factory=dict)
    """Since the CALL was sent: ``offer`` (the answer arrived), ``gathered``,
    ``first_remote_candidate``, ``connect_start``, ``connected``, ``first_recv``."""
    remote_candidates: int = 0


@dataclass(frozen=True, slots=True)
class IceReport:
    """ICE connectivity by role and candidate-type counts (no addresses)."""

    connected: bool
    controlling: bool | None
    local_candidate_types: dict[str, int]
    remote_candidate_types: dict[str, int]
    selected_pair_types: dict[str, str] | None = None
    """The candidate types of the selected pair: ``relay`` on either side is TURN."""
    turn_configured: bool | None = None


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
    head_hex: str | None = None
    """The first bytes of a payload that is neither XZYH nor JSON."""


@dataclass(frozen=True, slots=True)
class CommandReport:
    """One read-only command and where its reply is in :attr:`StationReport.messages`."""

    name: str
    sent: bool
    reply_index: int | None
    reply_ms: int | None
    request_keys: list[str] = field(default_factory=list)
    """The JSON key paths of the request sent."""


@dataclass(frozen=True, slots=True)
class LiveAttempt:
    route: str
    """``data_channel`` (the T9000/T8N00 handlers' route) or ``rtcp``."""
    status: int | None
    """The station's status for the open on the RTCP route (0 or a P2P error code)."""
    first_frame_ms: int | None
    """Until the first decrypted H.265 frame."""
    first_packet_ms: int | None = None
    """Until the first RTP packet of any payload type."""


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
    """The last phase that ran: ``signaling.<step>``, call, heartbeat, commands,
    guard_rewrite, watch, live, done."""
    signaling_ms: dict[str, int] = field(default_factory=dict)
    """How long each signaling step took (``open``, ``discover``, ``login``)."""
    call: CallReport | None = None
    ice: IceReport | None = None
    heartbeat_ms: int | None = None
    heartbeats: int = 0
    """Heartbeat messages received (not listed in :attr:`messages`)."""
    commands: list[CommandReport] = field(default_factory=list)
    messages: list[MessageReport] = field(default_factory=list)
    message_counts: dict[str, int] = field(default_factory=dict)
    """Every non-heartbeat message by ``<phase>/<msg_type>``, past the listing's cap too."""
    live: LiveReport | None = None
    error: str | None = None
    """``<phase>: <exception type>`` (never the message, which may carry an address)."""
    error_code: int | None = None
    interrupted: bool = False
    """The run was cancelled (Ctrl+C) in :attr:`phase_reached`: the report is partial."""


# ── cloud records ────────────────────────────────────────────────────────────


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _param_int(device: CloudDevice, param: int) -> int | None:
    for entry in device.cloud_params:
        if entry.param_id == param:
            value = entry.value.strip()
            return int(value) if value.lstrip("-").isdigit() else None
    return None


def _record_keys(raw: Mapping[str, Any]) -> list[str]:
    return sorted({_safe_name(str(key)) for key in raw})


def _battery(device: CloudDevice) -> bool | None:
    """Whether the device's settings declare a battery (reads package data)."""
    code = product_code_of(device.raw.get("device_new_pn"), device.device_sn)
    if code is None:
        return None
    try:
        settings = settings_of(code)
    except EufySecurityError:
        return None
    return BATTERY_PROPERTY in settings if settings else None


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
        is_webrtc_only=app_webrtc_only(route_device(device)),
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
        product_code=product_code_of(raw.get("device_new_pn"), device.device_sn),
        guard_mode=_param_int(device, GUARD_MODE_PARAM),
        cloud_param_types=sorted({p.param_id for p in device.cloud_params}),
        record_keys=_record_keys(raw),
    )


def describe_children(station_sn: str, devices: Iterable[CloudDevice]) -> list[ChildRecord]:
    """The devices paired to ``station_sn``, by channel. Reads the models' settings
    files (package data): call it off the event loop."""
    children = [d for d in devices if d.station_sn == station_sn and d.device_sn != station_sn]
    return [
        ChildRecord(
            model=d.device_sn[:5],
            channel=d.channel,
            main_sw_version=d.main_sw_version,
            has_signaling=bool(d.raw.get("signaling_servers")) and bool(d.raw.get("p2p_license")),
            product_code=product_code_of(d.raw.get("device_new_pn"), d.device_sn),
            battery=_battery(d),
            online=_param_int(d, PARAM_DEV_STATUS),
            cloud_param_types=sorted({p.param_id for p in d.cloud_params}),
        )
        for d in sorted(children, key=lambda d: (d.channel is None, d.channel or 0))
    ]


@dataclass(frozen=True, slots=True)
class LiveTarget:
    """The camera a station's live view opens, and why (a shortened serial, no name)."""

    channel: int
    model: str
    product_code: str | None
    serial: str | None
    """The camera's serial as :func:`~.._logging.redact_serial` shortens it; None for a
    channel no paired device has."""
    chosen_by: str
    """``camera_channel`` (the option), ``webrtc_child`` (the lowest channel the eufy app
    streams over WebRTC) or ``lowest_channel`` (the lowest paired channel)."""


def _paired(station_sn: str, devices: Iterable[CloudDevice]) -> list[CloudDevice]:
    """The devices paired to ``station_sn`` that have a channel, by channel."""
    return sorted(
        (
            d
            for d in devices
            if d.station_sn == station_sn and d.device_sn != station_sn and d.channel is not None
        ),
        key=lambda d: d.channel or 0,
    )


def webrtc_children(station_sn: str, devices: Iterable[CloudDevice]) -> list[CloudDevice]:
    """The devices paired to ``station_sn`` that the eufy app streams over WebRTC behind
    it (:func:`~..devices.webrtc.app_uses_webrtc`), by channel."""
    devices = list(devices)
    routes = [route_device(d) for d in devices]
    return [d for d in _paired(station_sn, devices) if app_uses_webrtc(d.device_sn, routes)]


def webrtc_probe_reason(
    station: CloudDevice, devices: Iterable[CloudDevice], *, webrtc_all: bool
) -> str | None:
    """Why diagnose probes ``station`` over WebRTC: ``webrtc_only`` (the app reaches it
    only over WebRTC), ``webrtc_child`` (a paired camera the app streams over WebRTC),
    ``webrtc_all`` (the option, any other station); None when it is not probed."""
    if app_webrtc_only(route_device(station)):
        return "webrtc_only"
    if webrtc_children(station.device_sn, devices):
        return "webrtc_child"
    if webrtc_all and station.is_station:
        return "webrtc_all"
    return None


def live_target(
    station_sn: str, devices: Iterable[CloudDevice], camera_channel: int | None = None
) -> LiveTarget | None:
    """The camera the live view of ``station_sn`` opens: ``camera_channel`` when given,
    else the lowest channel the app streams over WebRTC, else the lowest paired channel;
    None for a station with no paired channel."""
    devices = list(devices)
    paired = _paired(station_sn, devices)
    streamed = webrtc_children(station_sn, devices)
    if camera_channel is not None:
        device = next((d for d in paired if d.channel == camera_channel), None)
        channel, chosen_by = camera_channel, "camera_channel"
    elif streamed:
        device, chosen_by = streamed[0], "webrtc_child"
        channel = cast("int", device.channel)
    elif paired:
        device, chosen_by = paired[0], "lowest_channel"
        channel = cast("int", device.channel)
    else:
        return None
    if device is None:
        return LiveTarget(channel, "?", None, None, chosen_by)
    return LiveTarget(
        channel=channel,
        model=device.device_sn[:5],
        product_code=product_code_of(device.raw.get("device_new_pn"), device.device_sn),
        serial=redact_serial(device.device_sn),
        chosen_by=chosen_by,
    )


def rewritable_guard_mode(record: StationRecord) -> GuardMode | None:
    """The station's cloud guard mode when the opt-in re-send may repeat it
    (:data:`REWRITABLE_MODES`), else None."""
    if record.guard_mode is None:
        return None
    try:
        mode = GuardMode(record.guard_mode)
    except ValueError:
        return None
    return mode if mode in REWRITABLE_MODES else None


# ── message description ──────────────────────────────────────────────────────


def _small_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdigit() and len(value) <= _MAX_INT_DIGITS:
        return int(value)
    return None


def _walk(obj: Any, prefix: str, names: list[str], ints: dict[str, list[int]]) -> None:
    if isinstance(obj, dict):
        for raw_key, value in obj.items():
            key = _safe_name(str(raw_key))
            path = f"{prefix}.{key}" if prefix else key
            if len(names) < _MAX_NAMES and path not in names:
                names.append(path)
            number = _small_int(value) if key in _INT_FIELDS else None
            if number is not None:
                values = ints.setdefault(path, [])
                if len(values) < _MAX_VALUES:
                    values.append(number)
            if prefix.count(".") < 2:
                _walk(value, path, names, ints)
    elif isinstance(obj, list):
        for item in obj[:_MAX_VALUES]:
            _walk(item, f"{prefix}[]", names, ints)
    elif isinstance(obj, str) and obj[:1] in "{[":
        with contextlib.suppress(ValueError):
            _walk(json.loads(obj), prefix, names, ints)


def describe_json(obj: object) -> tuple[list[str], dict[str, list[int]]]:
    """The key paths of a parsed JSON value (three levels, identifier-like keys as
    ``"?"``, JSON in strings followed) and the values of its whitelisted small-integer
    fields (status codes, modes, channels); no other value."""
    names: list[str] = []
    ints: dict[str, list[int]] = {}
    _walk(obj, "", names, ints)
    return names, ints


def _describe_plain(
    plain: bytes, *, status: bool = True
) -> tuple[list[str], dict[str, list[int]], int | None] | None:
    """JSON key paths and whitelisted ints of a plaintext body, else (``status``) its
    int32 status, else None."""
    text = plain.rstrip(b"\x00")
    try:
        parsed = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        if not status:
            return None
        return [], {}, struct.unpack_from("<i", plain)[0] if len(plain) >= 4 else None
    names, ints = describe_json(parsed)
    return names, ints, None


def describe_message(
    payload: bytes, msg_type: int, keys: Mapping[str, bytes], *, phase: str, at_ms: int
) -> MessageReport:
    """Describe one inbound data-channel payload: its header, which key and wrapper
    open a sealed body, and the body's JSON key paths — never the bytes themselves. A
    payload that is not XZYH is read as JSON, else only its first bytes are kept."""
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
    described = _describe_plain(plain) if plain is not None else None
    head_hex = None
    if not xzyh:
        described = _describe_plain(payload, status=False)
        plain = payload if described is not None else None
        head_hex = payload[:_HEAD_LEN].hex() if described is None and payload else None
    names, ints, status = described or ([], {}, None)
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
        head_hex=head_hex,
    )


# ── cloud push and station events ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EventReport:
    """One event from the library's bus (cloud push or a P2P station), without its
    identifiers, names, paths or URLs."""

    at_ms: int
    kind: str
    """The event's class name (``SecurityEvent``, ``GuardModeChanged``, ...)."""
    source: str | None
    station_model: str | None
    device_model: str | None
    ints: dict[str, int]
    """Its small-integer fields (``msg_type``, ``event_type``, ``guard_mode``, ``mode`` ...)."""
    raw_keys: list[str]
    raw_ints: dict[str, list[int]]


#: The integer fields of an event the report keeps.
_EVENT_INTS: Final = (
    "channel",
    "msg_type",
    "event_type",
    "guard_mode",
    "mode",
    "alarm_type",
    "alarm_delay",
    "arming_user",
    "push_count",
)


def describe_event(event: object, at_ms: int) -> EventReport:
    """The descriptor of one bus event (see :class:`EventReport`)."""
    ints: dict[str, int] = {}
    for name in _EVENT_INTS:
        value = _small_int(getattr(event, name, None))
        if value is not None:
            ints[name] = value
    source = getattr(event, "source", None)
    raw = getattr(event, "raw", None)
    names, raw_ints = describe_json(dict(raw)) if isinstance(raw, Mapping) else ([], {})

    def model(name: str) -> str | None:
        serial = getattr(event, name, None)
        return serial[:5] if isinstance(serial, str) and serial else None

    return EventReport(
        at_ms=at_ms,
        kind=type(event).__name__,
        source=str(source) if source is not None else None,
        station_model=model("station_sn"),
        device_model=model("device_sn"),
        ints=ints,
        raw_keys=names,
        raw_ints=raw_ints,
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
        self.counts: dict[str, int] = {}
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
                count_key = f"{self.phase}/{int(msg.msg_type)}"
                self.counts[count_key] = self.counts.get(count_key, 0) + 1
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


class _TimedIce:
    """An :class:`~.media.IceTransport` that records when each step happened, in ms
    since it was made (just before the CALL), and counts the remote candidates."""

    def __init__(self, inner: IceTransport) -> None:
        self.inner = inner
        self.timings: dict[str, int] = {}
        self.remote_candidates = 0
        self._start = time.monotonic()

    def _mark(self, name: str) -> None:
        self.timings.setdefault(name, int((time.monotonic() - self._start) * 1000))

    def diagnostics(self) -> dict[str, object]:
        diag_fn = getattr(self.inner, "diagnostics", None)
        return cast("dict[str, object]", diag_fn()) if callable(diag_fn) else {}

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        self._mark("offer")
        lines = await self.inner.gather(local_ufrag=local_ufrag, local_pwd=local_pwd, turn=turn)
        self._mark("gathered")
        return lines

    def add_remote_candidate(self, candidate: str) -> None:
        self._mark("first_remote_candidate")
        self.remote_candidates += 1
        self.inner.add_remote_candidate(candidate)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        self._mark("connect_start")
        await self.inner.connect(remote_ufrag=remote_ufrag, remote_pwd=remote_pwd)
        self._mark("connected")

    async def recv(self) -> bytes:
        data = await self.inner.recv()
        self._mark("first_recv")
        return data

    async def send(self, data: bytes) -> None:
        await self.inner.send(data)

    async def close(self) -> None:
        await self.inner.close()


def _error(phase: str, exc: BaseException) -> tuple[str, int | None]:
    code = getattr(exc, "code", None)
    return f"{phase}: {type(exc).__name__}", code if isinstance(code, int) else None


async def _command(
    call: DataChannelCall, inbox: _Inbox, name: str, message: bytes
) -> CommandReport:
    """Send one station command and wait for the next command reply."""
    inbox.phase = name
    while not inbox.replies.empty():
        inbox.replies.get_nowait()
    start = time.monotonic()
    await call.send_command(call.seal(encode_frame(_COMMAND_XZYH, message, _COMMAND_SUBHEADER)))
    index: int | None = None
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(_COMMAND_TIMEOUT):
            index = await inbox.replies.get()
    return CommandReport(
        name=name,
        sent=True,
        reply_index=index,
        reply_ms=int((time.monotonic() - start) * 1000) if index is not None else None,
        request_keys=describe_json(json.loads(message))[0],
    )


async def _probe_commands(
    call: DataChannelCall, inbox: _Inbox, account_id: str, reports: list[CommandReport]
) -> None:
    probes = {
        "storage_1307": device_msg(
            account_id, CMD_STORAGE, storage_query_payload(), channel=STATION_CHANNEL
        ),
        "bind_list_9100": device_msg(account_id, _CMD_BIND_LIST, {}, channel=STATION_CHANNEL),
    }
    for name, message in probes.items():
        reports.append(await _command(call, inbox, name, message))


def guard_mode_message(account_id: str, mode: GuardMode) -> bytes:
    """The station's 1350/1224 guard-mode command at the station channel."""
    return device_msg(
        account_id, CMD_SET_ARMING, arm_payload(mode, REWRITE_USER_NAME), channel=STATION_CHANNEL
    )


async def _wait_first(
    live: LiveCall, timeout: float, start: float
) -> tuple[int | None, int | None]:
    """Until the first RTP packet and the first decoded frame, in ms since ``start``;
    both within ``timeout``."""

    def since() -> int:
        return int((time.monotonic() - start) * 1000)

    deadline = asyncio.get_running_loop().time() + timeout
    packet_ms: int | None = None
    wait_packets = getattr(live.media, "wait_packets", None)
    if callable(wait_packets):
        try:
            async with asyncio.timeout_at(deadline):
                await wait_packets()
        except TimeoutError:
            return None, None
        packet_ms = since()
    try:
        async with asyncio.timeout_at(deadline):
            await live.media.wait_media()
    except TimeoutError:
        return packet_ms, None
    frame_ms = since()
    return (packet_ms if packet_ms is not None else frame_ms), frame_ms


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
    data channel (the T9000/T8N00 route), fall back to RTCP when no packet arrives,
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
        packet_ms, frame_ms = await _wait_first(live, _LIVE_OPEN_WAIT, start)
        attempts.append(LiveAttempt("data_channel", None, frame_ms, packet_ms))
        if packet_ms is None and live.cipher is not None:
            inbox.phase = "live_open_rtcp"
            stream = stream_id(1)
            reply: asyncio.Future[int] = asyncio.get_running_loop().create_future()
            live._waiters[(LIVE_OPEN_FRAME, stream)] = reply
            start = time.monotonic()
            rtcp_frame = live_open_frame(channel, account_id, stream=stream, message_id=msg_id(1))
            await live.media.send_command(live.cipher.encrypt(rtcp_frame))
            packet_ms, frame_ms = await _wait_first(live, _LIVE_OPEN_WAIT, start)
            status = reply.result() if reply.done() else None
            attempts.append(LiveAttempt("rtcp", status, frame_ms, packet_ms))
        inbox.phase = "live"
        if any(a.first_packet_ms is not None for a in attempts):
            await asyncio.sleep(listen_s)
    except Exception as exc:  # any failure is recorded, never raised
        error = _error("live", exc)[0]
    finally:
        stats_fn = getattr(live.media, "stats", None) if live is not None else None
        media = cast("dict[str, object]", stats_fn()) if callable(stats_fn) else {}
        with contextlib.suppress(Exception):
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
    selected = diag.get("selected_pair_types")
    turn = diag.get("turn_configured")
    return IceReport(
        connected=connected,
        controlling=controlling if isinstance(controlling, bool) else None,
        local_candidate_types=dict(local) if isinstance(local, dict) else {},
        remote_candidate_types=dict(remote) if isinstance(remote, dict) else {},
        selected_pair_types=dict(selected) if isinstance(selected, dict) else None,
        turn_configured=turn if isinstance(turn, bool) else None,
    )


def _call_report(call: DataChannelCall, ice: _TimedIce, elapsed_ms: int) -> CallReport:
    remote = call.remote
    if remote is None or call.call is None:
        raise CommunicationError("RTC data channel did not answer")
    offer = call.call.offer or {}
    head: bytes | None = None
    raw = offer.get("sdp_info")
    if isinstance(raw, str):
        with contextlib.suppress(ValueError):
            head = base64.b64decode(raw)[:_SDP_INFO_HEAD]
    return CallReport(
        answered=True,
        ice_ufrag_len=len(remote.ice_ufrag),
        ice_pwd_len=len(remote.ice_pwd),
        content_key_len=len(remote.content_key),
        content_iv_len=len(remote.content_iv),
        turn_present=bool(call.call.turn),
        elapsed_ms=elapsed_ms,
        answer_keys=_record_keys(offer),
        sdp_info_head_hex=head.hex() if head else None,
        data_channel_flag=remote.data_channel,
        timings_ms=dict(ice.timings),
        remote_candidates=ice.remote_candidates,
    )


class _Steps:
    """Durations of named steps, one running at a time."""

    def __init__(self) -> None:
        self.ms: dict[str, int] = {}
        self.current: str | None = None
        self._since = 0.0

    def begin(self, name: str) -> None:
        self.end()
        self.current, self._since = name, time.monotonic()

    def end(self) -> None:
        if self.current is not None:
            self.ms[self.current] = int((time.monotonic() - self._since) * 1000)


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
    rewrite_guard_mode: GuardMode | None = None,
    ice: IceTransport | None = None,
    on_report: Callable[[StationReport], None] | None = None,
) -> StationReport:
    """Run the probes for one station and return its report.

    Starts ``session`` (signaling, within :data:`SIGNALING_BUDGET`), opens the data
    channel on ``channel``, checks the heartbeat, sends the read-only queries
    (``do_commands``), re-sends ``rewrite_guard_mode`` (opt-in, a write: the caller
    passes the station's current mode), records notifications for ``watch_s`` seconds
    (``on_watch`` is told when that window opens), then opens a live view of ``camera``
    (``do_live``). ``account_id`` is the station owner's user id the commands carry.
    The whole run is bounded by :data:`STATION_BUDGET` plus ``watch_s`` and
    ``listen_s``. Any failure ends the run for this station and is recorded as the
    phase and exception *type* only. ``on_report`` receives the report also when the
    run is cancelled (then partial, :attr:`StationReport.interrupted`), before the
    cancellation propagates. The session is left for the caller to close.
    """
    from .session import default_ice_factory  # noqa: PLC0415 - optional rtc extra

    phase = "signaling"
    steps = _Steps()
    call_report: CallReport | None = None
    ice_report: IceReport | None = None
    heartbeat_ms: int | None = None
    commands: list[CommandReport] = []
    live: LiveReport | None = None
    inbox: _Inbox | None = None
    error: str | None = None
    code: int | None = None
    interrupted = False
    call: DataChannelCall | None = None
    transport: _TimedIce | None = None

    def on_step(name: str) -> None:
        nonlocal phase
        steps.begin(name)
        phase = f"signaling.{name}"

    try:
        async with asyncio.timeout(STATION_BUDGET + watch_s + listen_s):
            async with asyncio.timeout(SIGNALING_BUDGET):
                await session.start(on_step=on_step)
            steps.end()
            steps.current = None
            phase = "call"
            transport = _TimedIce(ice if ice is not None else default_ice_factory())
            start = time.monotonic()
            call = await session.open_data_channel(channel, ice=transport)
            call_report = _call_report(call, transport, int((time.monotonic() - start) * 1000))
            ice_report = _ice_report(transport, connected=True)
            remote = cast("SdpInfo", call.remote)
            keys = {
                "device_content_key": remote.content_key.encode()[:16],
                "client_content_key": call.info.content_key.encode()[:16],
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
                await _probe_commands(call, inbox, account_id, commands)
            if rewrite_guard_mode is not None:
                phase = "guard_rewrite"
                message = guard_mode_message(account_id, rewrite_guard_mode)
                commands.append(
                    await _command(call, inbox, f"guard_rewrite_{CMD_SET_ARMING}", message)
                )
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
    except asyncio.CancelledError:
        interrupted = True
        error = f"{phase}: interrupted"
        raise
    except Exception as exc:  # any failure is recorded, never raised
        error, code = _error(phase, exc)
    finally:
        steps.end()
        if call_report is not None and transport is not None:
            call_report = dataclasses.replace(call_report, timings_ms=dict(transport.timings))
        if ice_report is None and transport is not None:
            ice_report = _ice_report(transport, connected=False)
            if call_report is None:
                call_report = CallReport(
                    answered="offer" in transport.timings,
                    ice_ufrag_len=0,
                    ice_pwd_len=0,
                    content_key_len=0,
                    content_iv_len=0,
                    turn_present=False,
                    elapsed_ms=0,
                    timings_ms=dict(transport.timings),
                    remote_candidates=transport.remote_candidates,
                )
        with contextlib.suppress(Exception):
            if inbox is not None:
                await inbox.close()
            if call is not None:
                await session.close_data_channel(channel)
            elif transport is not None:
                await transport.close()
        report = StationReport(
            station=station,
            children=list(children),
            channel=channel,
            phase_reached=phase,
            signaling_ms=dict(steps.ms),
            call=call_report,
            ice=ice_report,
            heartbeat_ms=heartbeat_ms,
            heartbeats=inbox.heartbeats if inbox is not None else 0,
            commands=commands,
            messages=inbox.messages if inbox is not None else [],
            message_counts=dict(inbox.counts) if inbox is not None else {},
            live=live,
            error=error,
            error_code=code,
            interrupted=interrupted,
        )
        if on_report is not None:
            on_report(report)
    return report


# ── summary ──────────────────────────────────────────────────────────────────


def render_station(st: StationReport) -> list[str]:
    """A short human-readable summary of one station's report (the JSON is the full one)."""
    s = st.station
    lines = [
        f"WebRTC station {s.model} fw {s.main_sw_version} sdk {s.webrtc_sdk_version} "
        f"(kcp_type={s.kcp_type}, encrypted={s.commands_encrypted}) reached {st.phase_reached}"
    ]
    lines.extend(
        f"  child {c.model} ch {c.channel} fw {c.main_sw_version} battery={c.battery}"
        for c in st.children
    )
    if st.signaling_ms:
        lines.append(f"  signaling: {st.signaling_ms} ms")
    if st.error is not None:
        lines.append(f"  error: {st.error} code={st.error_code}")
    if st.call is not None:
        lines.append(
            f"  CALL: answered={st.call.answered} turn={st.call.turn_present} "
            f"in {st.call.elapsed_ms} ms, steps {st.call.timings_ms}"
        )
    if st.ice is not None:
        i = st.ice
        lines.append(
            f"  ICE: connected={i.connected} controlling={i.controlling} "
            f"selected={i.selected_pair_types} "
            f"local={i.local_candidate_types} remote={i.remote_candidate_types}"
        )
    if st.call is not None and st.call.answered:
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
            f"{a.route} status={a.status} first_packet={a.first_packet_ms} ms "
            f"first_frame={a.first_frame_ms} ms"
            for a in lv.attempts
        )
        counts = {k: lv.media.get(k) for k in ("rtp_by_payload_type", "frames", "frame_failures")}
        lines.append(
            f"  live ch {lv.channel} ({lv.camera_model}): {tried or 'not opened'} "
            f"error={lv.error} {counts}"
        )
    return lines
