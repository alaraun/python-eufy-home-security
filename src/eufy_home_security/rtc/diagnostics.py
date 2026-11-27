"""A read-only WebRTC report of one station: what `eufy-security diagnose rtc` records.

:func:`async_diagnose_station` runs six steps against one station and returns an
:class:`RtcStationReport`:

1. **inputs**: which signaling inputs its device-list entry carries and how the eufy app
   routes it and each device paired to it (no network);
2. **login**: DISCOVER and LOGIN (:class:`~.session.RtcSession`, the library's own session);
3. **call**: the kind-5 data CALL with the client's KCP-only flag; the answer's key names,
   the device's ``transport_caps`` as the session reads it
   (:meth:`~.session.CallAnswer.parse`) with its source and ``pbsdp``'s field numbers
   (:func:`~.sdp.read_pbsdp`), the
   device's ``sdp_info`` shape;
4. **ice**: candidate types on each side, the selected pair, the time to connect;
5. **data channel**: for ``seconds``, every message the station sends unasked: its link type
   and header length, and for an XZYH frame its type, length, subheader and channel; the
   time to the first frame naming the guard-mode parameter (1224), clear or sealed (opened
   with the answer's content key, its contents never kept), and how many sealed frames
   opened;
6. with ``probe_kinds``, after the session closed: a fresh login and one CALL of kinds 1,
   3 and 4 each, their answer codes only.

Nothing is sent on the data channel and no command, setting or mode is touched; on the
wire go only DISCOVER, LOGIN, the MESSAGE ping and its answers, the CALLs with their ACK,
INFO (ICE candidates) and HANGUP, ICE checks and KCP acknowledgements. A failed step is
recorded (by error class, and code for a library error) and the steps that need it are
skipped; the run never raises for a station's answer or another library's error (only a
cancel ends it) and is bounded by :func:`station_budget`. The session closes when the watch ends,
at once when its link is lost and always before the probes (which use a client of their
own), so the data CALL is placed once per run.

The report is redacted as it is built (:meth:`RtcStationReport.as_dict`): serials by
:func:`~._logging.redact_serial`, addresses by their class (:func:`ip_class`), identifiers
and keys by their field name and length (:func:`placeholder`); of the device's answer only
the key names that are plain names and the values of :data:`ANSWER_INT_KEYS` (ints) and
:data:`ANSWER_TEXT_KEYS` (short text) are kept. :meth:`RtcStationReport.secrets_dict`
holds the raw values for a separate file. See ``docs/how-to/diagnose-rtc.md``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import dataclasses
import ipaddress
import json
import logging
import re
import struct
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.model_settings import product_code_of
from ..devices.webrtc import app_uses_webrtc, app_webrtc_only, route_device
from ..exceptions import CommunicationError, EufySecurityError, ProtocolError
from ..p2p._json import MAX_JSON_DEPTH, json_int, loads_json
from ..p2p.params import GUARD_MODE_PARAM
from ..p2p.xzyh import HEADER_LEN as XZYH_HEADER_LEN
from ..p2p.xzyh import MAGIC as XZYH_MAGIC
from . import session as rtc_session
from .client import Call, SignalingClient
from .codec import CallKind, ResponseCode
from .command import decrypt_notification, is_sealed, media_key
from .config import (
    KCP_TYPE_MULTI,
    KCP_TYPE_SINGLE,
    QuickLogin,
    RtcConfig,
    ServerInfo,
    commands_encrypted,
    data_channel_kcp_type,
    firmware_number,
    missing_inputs,
    signaling_domain,
    signaling_ipv4,
)
from .data_channel import DataMsgType, LinkMessage
from .ice import IceAgent, IceTransport, require_aioice
from .media import TurnServer
from .sdp import SdpInfo, read_pbsdp
from .session import CallAnswer, ConnectStep, RtcSession, _finish, client_flag, select_transport
from .signaling import CallEventKind

_LOGGER = logging.getLogger(__name__)

#: The CALL kinds ``probe_kinds`` tries: the older command, media and file channels.
PROBE_KINDS: Final = (CallKind.COMMAND, CallKind.CHANNEL_P2P, CallKind.FILE)
#: How long each probe CALL waits for its answer.
PROBE_TIMEOUT: Final = 8.0
#: Unasked frames kept per run; later ones are only counted.
MAX_FRAMES: Final = 200
#: How long step 5 listens by default, and at most, in seconds.
DEFAULT_WATCH: Final = 60.0
MAX_WATCH: Final = 600.0
#: Bytes of each frame kept in the secrets (never in the report).
SECRET_FRAME_BYTES: Final = 64
#: How often the watch checks that the session is still up.
_WATCH_SLICE: Final = 0.25
#: Time left for closing and bookkeeping in :func:`station_budget`.
_SLACK: Final = 10.0
#: Answer keys whose value is kept: numbers (as ints only) and type names (short text).
ANSWER_INT_KEYS: Final = frozenset({"transport_caps", "ftv", "port"})
ANSWER_TEXT_KEYS: Final = frozenset({"call_type", "eufy_p2p_type"})
#: Answer keys whose value is an address: kept as its class.
ANSWER_ADDRESS_KEYS: Final = frozenset({"addr", "srflx"})
_NAMED_KEYS: Final = ANSWER_INT_KEYS | ANSWER_TEXT_KEYS | ANSWER_ADDRESS_KEYS
#: Limits on the answer's key names, so a peer cannot fill the report.
MAX_ANSWER_KEYS: Final = 64
MAX_KEY_LEN: Final = 40
_SHORT_TEXT: Final = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
#: An answer key name kept as it is (as are the keys named above); any other shows as
#: ``<key:len>``.
_KEY_NAME: Final = re.compile(rf"^[a-z_]{{1,{MAX_KEY_LEN}}}$")
_CANDIDATE_TYPE: Final = re.compile(r"\btyp\s+([A-Za-z]+)")
_SHARED: Final = ipaddress.IPv4Network("100.64.0.0/10")
#: The steps of one run, in order.
STEPS: Final = ("inputs", "discover", "login", "call", "ice", "data_channel")


class StepStatus(StrEnum):
    """How a step ended."""

    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    """The run's own bound (:func:`station_budget`) ended it."""
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """One step's result: status, duration, and the error's class and code."""

    status: StepStatus
    seconds: float | None = None
    error: str | None = None
    """The exception's class name (its message is kept in the secrets only)."""
    code: int | None = None
    """The signaling response code an error carries (401, 486, ...)."""
    reason: str | None = None
    """Why a step was skipped (``"call failed"``, ``"quick login"``)."""


@dataclass(frozen=True, slots=True)
class DeviceRoute:
    """A device paired to the station, as step 1 reads it."""

    serial: str
    product_code: str | None
    channel: int | None
    webrtc: bool
    """Whether the eufy app reaches it over WebRTC."""


@dataclass(frozen=True, slots=True)
class InputsReport:
    """Step 1: the station's signaling inputs and routing."""

    outcome: StepOutcome
    product_code: str | None
    present: dict[str, bool]
    missing: tuple[str, ...]
    signaling_ipv4: int
    signaling_domains: int
    webrtc_sdk_version: str | None
    main_sw_version: str | None
    webrtc_only: bool
    kcp_type: int
    commands_encrypted: bool
    devices: tuple[DeviceRoute, ...]


@dataclass(frozen=True, slots=True)
class LoginReport:
    """Step 2: DISCOVER and LOGIN."""

    discover: StepOutcome
    login: StepOutcome
    quick_login: bool
    server: str | None
    """The login server's address class."""
    server_records: int
    """Server records the login reported (:class:`~.config.ServerInfo`)."""
    login_rtt_ms: int | None


@dataclass(frozen=True, slots=True)
class SdpReport:
    """The shape of the device's answer ``sdp_info``; no credential or key."""

    length: int
    flag_byte: int
    bytes_3_5: tuple[int, int, int]
    ufrag_len: int
    pwd_len: int
    key_len: int
    iv_len: int
    audio_ssrc_present: bool
    video_ssrc_present: bool


@dataclass(frozen=True, slots=True)
class CallReport:
    """Step 3: the kind-5 data CALL and the device's answer."""

    outcome: StepOutcome
    client_flag: int
    answer_keys: tuple[str, ...] = ()
    answer_values: dict[str, Any] = field(default_factory=dict)
    transport_caps: int | None = None
    """The device's ``transport_caps`` as the session reads it
    (:meth:`~.session.CallAnswer.parse`); None when the answer does not parse."""
    transport_caps_source: str = "none"
    """``pbsdp`` (a non-empty ``pbsdp``: 0 when it does not decode or lacks the field),
    ``json`` (the ``transport_caps`` key, read only without ``pbsdp``) or ``none``."""
    pbsdp_len: int | None = None
    pbsdp_decoded: bool | None = None
    pbsdp_fields: tuple[int, ...] = ()
    """The field numbers of ``pbsdp`` (no values), and of its field 3."""
    pbsdp_sdp_fields: tuple[int, ...] = ()
    request_id_present: bool = False
    turn_present: bool = False
    turn_keys: tuple[str, ...] = ()
    device_sdp: SdpReport | None = None
    transport: str | None = None
    """``kcp`` or ``quic``: what the answer and the client's flag select; None when the
    answer does not parse."""


@dataclass(frozen=True, slots=True)
class IceReport:
    """Step 4: the data channel's ICE."""

    outcome: StepOutcome
    local_types: dict[str, int] = field(default_factory=dict)
    remote_types: dict[str, int] = field(default_factory=dict)
    selected: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class FrameRecord:
    """One message the station sent unasked; never its payload."""

    at: float
    """Seconds after the watch began."""
    link_type: int
    header_len: int
    xzyh_type: int | None
    length: int
    """The XZYH frame's declared payload length, else the message's length."""
    subheader: str | None
    """The XZYH subheader's six bytes, hex."""
    channel: int | None
    """Subheader byte 2."""


@dataclass(frozen=True, slots=True)
class DataChannelReport:
    """Step 5: the data channel and what the station sent unasked."""

    outcome: StepOutcome
    kcp_type: int | None = None
    """From the device's answer: 2 with the KCP datagram prefix, else 1."""
    watched: float = 0.0
    messages: int = 0
    heartbeats: int = 0
    header_lens: tuple[int, ...] = ()
    frames: tuple[FrameRecord, ...] = ()
    frames_dropped: int = 0
    guard_mode_at: float | None = None
    """Seconds after the watch began to the first frame naming the guard-mode parameter
    (1224), clear or opened with the answer's content key; None when none came."""
    sealed_opened: int = 0
    """Sealed frames (subheader version 10) that opened with the answer's content key."""
    sealed_unread: int = 0
    ended: str | None = None
    """What ended the link during the watch (its error class), None when it held."""


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """Step 6: one CALL of an older kind."""

    kind: int
    outcome: StepOutcome
    codes: tuple[int, ...] = ()
    """The response codes seen (100, 200, 480, 486 ...), in order."""
    hung_up: bool = False


@dataclass(frozen=True, slots=True)
class ProbesReport:
    """Step 6: the probe client's login and each kind's answer."""

    login: StepOutcome
    kinds: tuple[ProbeReport, ...] = ()


@dataclass(frozen=True, slots=True)
class RtcStationReport:
    """The whole run for one station; :meth:`as_dict` is the redacted JSON."""

    station: str
    reason: str
    """Why the station was chosen (see :func:`rtc_stations`)."""
    inputs: InputsReport
    login: LoginReport
    call: CallReport
    ice: IceReport
    data_channel: DataChannelReport
    probes: ProbesReport
    secrets: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        """The report as JSON-safe data, without :attr:`secrets`."""
        return {
            f.name: _plain(getattr(self, f.name))
            for f in dataclasses.fields(self)
            if f.name != "secrets"
        }

    def secrets_dict(self) -> dict[str, Any]:
        """The raw values the report leaves out (serial, DID, license, contact id, the
        answer, candidates, error messages, frame heads), JSON-safe."""
        plain: dict[str, Any] = json.loads(json.dumps(self.secrets, default=str))
        return plain


def _plain(value: object) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


# ── redaction ────────────────────────────────────────────────────────────────


def ip_class(text: str) -> str:
    """The class of an IPv4 address (an ``ip:port`` too): ``loopback``, ``link_local``,
    ``shared`` (100.64/10), ``private``, ``public``, ``other``; ``not_ip`` otherwise."""
    host = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        return "not_ip"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address in _SHARED:
        return "shared"
    if address.is_private:
        return "private"
    return "public" if address.is_global else "other"


def placeholder(name: str, value: object) -> str:
    """``<name:len>``: the length of ``value``'s text (its JSON for a container, 0 for
    None) without the value."""
    if value is None:
        size = 0
    elif isinstance(value, str):
        size = len(value)
    elif isinstance(value, Mapping | list | tuple):
        size = len(json.dumps(value, separators=(",", ":"), default=str))
    else:
        size = len(str(value))
    return f"<{name}:{size}>"


def _answer_value(key: str, value: object) -> Any:
    if key in ANSWER_INT_KEYS and isinstance(value, int) and not isinstance(value, bool):
        return value
    if key in ANSWER_TEXT_KEYS and isinstance(value, str) and _SHORT_TEXT.match(value):
        return value
    if key in ANSWER_ADDRESS_KEYS and isinstance(value, str):
        return ip_class(value)
    return placeholder(key, value)


def _key_name(key: object) -> str:
    """``key`` when it is a plain lower-case name or a key named here, else ``<key:len>``."""
    text = str(key)
    return text if _plain_key(text) else placeholder("key", text)


def _plain_key(key: str) -> bool:
    return bool(_KEY_NAME.match(key)) or key in _NAMED_KEYS


def _key_names(value: Mapping[Any, Any]) -> tuple[str, ...]:
    return tuple(sorted(_key_name(k) for k in value))[:MAX_ANSWER_KEYS]


def _candidate_type(line: str) -> str:
    found = _CANDIDATE_TYPE.search(line)
    return found.group(1).lower() if found else "unknown"


def _error_fields(exc: BaseException) -> tuple[str, int | None]:
    """The class name of ``exc`` and, for a library error, its code; never its text."""
    code = getattr(exc, "code", None) if isinstance(exc, EufySecurityError) else None
    return type(exc).__name__, code if isinstance(code, int) else None


# ── step 1 and station choice ────────────────────────────────────────────────


def rtc_stations(
    devices: Sequence[CloudDevice], wanted: str | None = None
) -> list[tuple[CloudDevice, str]]:
    """The stations to diagnose, each with why: ``"station"`` (the eufy app reaches it
    only over WebRTC), ``"device"`` (it or a device paired to it is reached over WebRTC);
    with ``wanted`` (a serial) only that station, ``"asked"`` when neither applies."""
    routes = [route_device(d) for d in devices]
    found = []
    for device in devices:
        if device.station_sn not in (None, "", device.device_sn):
            continue
        if wanted is not None and device.device_sn != wanted:
            continue
        reason = _route_reason(device, devices, routes)
        if reason is None and wanted is not None:
            reason = "asked"
        if reason is not None:
            found.append((device, reason))
    return found


def _route_reason(
    station: CloudDevice, devices: Sequence[CloudDevice], routes: Sequence[Any]
) -> str | None:
    if app_webrtc_only(route_device(station)):
        return "station"
    serials = [station.device_sn] + [d.device_sn for d in _children(station, devices)]
    if any(app_uses_webrtc(serial, routes) for serial in serials):
        return "device"
    return None


def _children(station: CloudDevice, devices: Sequence[CloudDevice]) -> list[CloudDevice]:
    return [
        d for d in devices if d.station_sn == station.device_sn and d.device_sn != station.device_sn
    ]


def describe_inputs(station: CloudDevice, devices: Sequence[CloudDevice]) -> InputsReport:
    """Step 1 from the device list alone: what the station's entry carries, the kcp_type
    and command sealing the eufy app picks for it, and each paired device's route."""
    raw = station.raw
    servers = raw.get("signaling_servers")
    servers = servers if isinstance(servers, list) else []
    sdk = raw.get("webrtc_sdk_version")
    version = raw.get("main_sw_version")
    sdk = sdk if isinstance(sdk, str) and sdk else None
    version = version if isinstance(version, str) and version else None
    present = {
        "p2p_did": isinstance(raw.get("p2p_did"), str) and bool(raw["p2p_did"]),
        "p2p_license": isinstance(raw.get("p2p_license"), str) and bool(raw["p2p_license"]),
        "signaling_servers": bool(servers),
        "webrtc_sdk_version": sdk is not None,
        "main_sw_version": version is not None,
    }
    missing = missing_inputs(raw)
    prefix = station.device_sn[:5]
    routes = [route_device(d) for d in devices]
    return InputsReport(
        outcome=StepOutcome(StepStatus.FAILED if missing else StepStatus.OK),
        product_code=product_code_of(raw.get("device_new_pn"), station.device_sn),
        present=present,
        missing=missing,
        signaling_ipv4=sum(signaling_ipv4([s]) is not None for s in servers),
        signaling_domains=sum(signaling_domain([s]) is not None for s in servers),
        webrtc_sdk_version=sdk,
        main_sw_version=version,
        webrtc_only=app_webrtc_only(route_device(station)),
        kcp_type=data_channel_kcp_type(prefix, sdk),
        commands_encrypted=commands_encrypted(prefix, firmware_number(version)),
        devices=tuple(
            DeviceRoute(
                serial=redact_serial(d.device_sn),
                product_code=product_code_of(d.raw.get("device_new_pn"), d.device_sn),
                channel=d.channel,
                webrtc=app_uses_webrtc(d.device_sn, routes),
            )
            for d in _children(station, devices)
        ),
    )


# ── the run ──────────────────────────────────────────────────────────────────


def station_budget(seconds: float, probes: bool) -> float:
    """The longest one station's run may take: the session's first-start bound, the
    watch, the probes, and :data:`_SLACK`."""
    total = rtc_session.START_TIMEOUT + seconds + _SLACK
    if probes:
        total += len(PROBE_KINDS) * PROBE_TIMEOUT
    return total


class _RecordingIce:
    """An :class:`~.ice.IceAgent` that notes candidate types and connect time."""

    def __init__(self, inner: IceAgent, run: _Run) -> None:
        self._inner = inner
        self._run = run

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        lines = await self._inner.gather(local_ufrag=local_ufrag, local_pwd=local_pwd, turn=turn)
        self._run.local_candidates.extend(lines)
        return lines

    def add_remote_candidate(self, candidate: str) -> None:
        self._run.remote_candidates.append(candidate)
        self._inner.add_remote_candidate(candidate)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        await self._inner.connect(remote_ufrag=remote_ufrag, remote_pwd=remote_pwd)
        selected = getattr(self._inner, "selected_pair", None)
        if callable(selected):
            pair = selected()
            if isinstance(pair, tuple) and len(pair) == len(("local", "remote")):
                self._run.selected = (str(pair[0]), str(pair[1]))

    async def recv(self) -> bytes:
        return await self._inner.recv()

    async def send(self, data: bytes) -> None:
        await self._inner.send(data)

    async def close(self) -> None:
        await self._inner.close()


@dataclass(eq=False)
class _Run:
    """The state of one station's run."""

    config: RtcConfig
    loop: asyncio.AbstractEventLoop
    secrets: dict[str, Any]
    current: str | None = None
    started: dict[str, float] = field(default_factory=dict)
    ended: dict[str, float] = field(default_factory=dict)
    failures: dict[str, tuple[StepStatus, BaseException | None]] = field(default_factory=dict)
    call: Call | None = None
    server_info: list[ServerInfo] = field(default_factory=list)
    quick_login: QuickLogin | None = None
    local_candidates: list[str] = field(default_factory=list)
    remote_candidates: list[str] = field(default_factory=list)
    selected: tuple[str, str] | None = None
    session: RtcSession | None = None
    channel_report: DataChannelReport | None = None
    probe_login: StepOutcome | None = None
    probe_results: list[ProbeReport] = field(default_factory=list)
    probe_current: int | None = None
    probe_started: float | None = None
    """When the probe client began (None before step 6)."""

    # step bookkeeping

    def begin(self, name: str) -> None:
        now = self.loop.time()
        if self.current is not None and self.current not in self.ended:
            self.ended[self.current] = now
        self.current = name
        self.started[name] = now

    def finish(self) -> None:
        if self.current is not None and self.current not in self.ended:
            self.ended[self.current] = self.loop.time()

    def fail(self, exc: BaseException | None, status: StepStatus = StepStatus.FAILED) -> None:
        name = self.current or "discover"
        self.started.setdefault(name, self.loop.time())
        self.failures[name] = (status, exc)
        self.ended[name] = self.loop.time()
        if exc is not None:
            self.secrets.setdefault("errors", {})[name] = f"{type(exc).__name__}: {exc}"

    def first_failure(self) -> str | None:
        return next((s for s in STEPS if s in self.failures), None)

    def outcome(self, name: str, *, unused: str | None = None) -> StepOutcome:
        if name in self.failures:
            status, exc = self.failures[name]
            error, code = _error_fields(exc) if exc is not None else (None, None)
            return StepOutcome(status, self._seconds(name), error, code)
        if name in self.ended:
            return StepOutcome(StepStatus.OK, self._seconds(name))
        failed = self.first_failure()
        if failed is not None:
            status = self.failures[failed][0]
            word = "timed out" if status is StepStatus.TIMEOUT else "failed"
            return StepOutcome(StepStatus.SKIPPED, reason=f"{failed} {word}")
        return StepOutcome(StepStatus.SKIPPED, reason=unused)

    def _seconds(self, name: str) -> float | None:
        if name not in self.started:
            return None
        return round(self.ended.get(name, self.loop.time()) - self.started[name], 3)

    # session callbacks

    def on_step(self, step: ConnectStep, call: Call | None) -> None:
        """Note a connect step; only the first connect counts (a step seen before, or an
        answer after the first, is ignored)."""
        if step is ConnectStep.ANSWER:
            if self.call is None:
                self.call = call
                if call is not None and call.answer is not None:
                    self.secrets["answer"] = dict(call.answer)
            return
        if step.value not in self.started:
            self.begin(step.value)

    def on_login(self, record: QuickLogin) -> None:
        self.quick_login = record
        self.secrets["contact_id"] = record.contact_id

    def on_server_info(self, record: ServerInfo) -> None:
        self.server_info.append(record)
        self.secrets["login_server"] = record.ip

    def ice_factory(self, inner: Callable[[], IceAgent] | None) -> Callable[[], IceAgent]:
        def make() -> IceAgent:
            agent = inner() if inner is not None else _default_ice()
            return _RecordingIce(agent, self)

        return make


def _default_ice() -> IceAgent:
    return IceTransport()


async def async_diagnose_station(
    station: CloudDevice,
    devices: Sequence[CloudDevice],
    *,
    user_id: str,
    app_id: str,
    seconds: float = DEFAULT_WATCH,
    probe_kinds: bool = False,
    reason: str = "asked",
    ice_factory: Callable[[], IceAgent] | None = None,
    signaling_port: int | None = None,
    tcp_ports: tuple[int, ...] | None = None,
) -> RtcStationReport:
    """Run steps 1-6 against ``station`` (its entry in the account's ``devices``) and
    return the report; a station's failure is recorded, never raised.

    ``user_id`` is the account's user id, ``app_id`` the install id the session sends.
    ``seconds`` (at most :data:`MAX_WATCH`) is how long step 5 listens. Raises
    :class:`~.exceptions.MissingDependencyError` without the ``rtc`` extra, before
    anything is sent. ``ice_factory``, ``signaling_port`` and ``tcp_ports`` exist for
    tests.
    """
    if ice_factory is None:
        require_aioice()
    seconds = max(0.0, min(seconds, MAX_WATCH))
    secrets: dict[str, Any] = {
        "station_sn": station.device_sn,
        "p2p_did": station.raw.get("p2p_did"),
        "p2p_license": station.raw.get("p2p_license"),
        "signaling_servers": station.raw.get("signaling_servers"),
        "app_id": app_id,
    }
    inputs = describe_inputs(station, devices)
    config = None
    if inputs.outcome.status is StepStatus.OK:
        config = RtcConfig.from_device(station.raw, user_id=user_id, app_id=app_id)
    loop = asyncio.get_running_loop()
    run = _Run(config or _placeholder_config(), loop, secrets)
    if config is None:
        run.failures["inputs"] = (StepStatus.FAILED, None)
        return _report(run, station, reason, inputs, probe_kinds)
    try:
        async with asyncio.timeout(station_budget(seconds, probe_kinds)):
            await _connect_and_watch(run, seconds, ice_factory, signaling_port, tcp_ports)
            if run.session is not None:  # closed before the probes: it never reconnects
                await _close(run.session.close())
            if probe_kinds:
                await _probe(run, signaling_port, tcp_ports)
    except TimeoutError:
        if run.probe_current is not None:
            run.probe_results.append(
                ProbeReport(run.probe_current, StepOutcome(StepStatus.TIMEOUT))
            )
        elif run.probe_started is not None:
            seconds = round(loop.time() - run.probe_started, 3)
            run.probe_login = StepOutcome(StepStatus.TIMEOUT, seconds)
        else:
            run.fail(None, StepStatus.TIMEOUT)
    finally:
        if run.session is not None:
            await _close(run.session.close())
    return _report(run, station, reason, inputs, probe_kinds)


async def _close(closing: Awaitable[None]) -> None:
    """Await ``closing`` to its end; a cancel meanwhile is raised after it."""

    async def wrapped() -> None:
        await closing

    await _finish(asyncio.get_running_loop().create_task(wrapped()))


def _placeholder_config() -> RtcConfig:
    return RtcConfig(
        station_sn="", p2p_did="", p2p_license="", signaling_host="", user_id="", app_id=""
    )


async def _connect_and_watch(
    run: _Run,
    seconds: float,
    ice_factory: Callable[[], IceAgent] | None,
    signaling_port: int | None,
    tcp_ports: tuple[int, ...] | None,
) -> None:
    session = RtcSession(
        run.config,
        ice_factory=run.ice_factory(ice_factory),
        signaling_port=signaling_port,
        tcp_ports=tcp_ports,
        on_login=run.on_login,
        on_server_info=run.on_server_info,
        on_step=run.on_step,
    )
    run.session = session
    try:
        await session.start()
    except Exception as exc:
        run.fail(exc)
        return
    run.channel_report = await _watch(run, session, seconds)


async def _watch(run: _Run, session: RtcSession, seconds: float) -> DataChannelReport:
    """Step 5: read what the station sends for ``seconds``; a loss ends it."""
    channel = session.data_channel
    answer = session.answer
    kcp_type = None
    if answer is not None:
        kcp_type = KCP_TYPE_MULTI if answer.sdp_info.data_channel else KCP_TYPE_SINGLE
    began = run.loop.time()
    messages = heartbeats = dropped = sealed_opened = sealed_unread = 0
    guard_mode_at: float | None = None
    key = _notify_key(answer)
    header_lens: set[int] = set()
    frames: list[FrameRecord] = []
    heads: list[str] = []
    ended: BaseException | None = None
    if channel is None:  # lost between the session's start and the watch
        ended = session.last_error or CommunicationError("RTC session lost")
    while channel is not None:
        left = began + seconds - run.loop.time()
        if left <= 0:
            break
        if not session.connected:
            ended = session.last_error or CommunicationError("RTC session lost")
            break
        try:
            async with asyncio.timeout(min(left, _WATCH_SLICE)):
                message = await channel.recv_message()
        except TimeoutError:
            continue
        except Exception as exc:
            ended = session.last_error or exc
            break
        messages += 1
        header_lens.add(message.header_len)
        if message.msg_type == DataMsgType.HEARTBEAT:
            heartbeats += 1
            continue
        at = _frame_time(began, run.loop.time())
        names = _names_guard_mode(message.payload, key)
        if names is None:
            sealed_unread += 1
        elif names[0]:
            sealed_opened += 1
        if names is not None and names[1] and guard_mode_at is None:
            guard_mode_at = round(at, 3)
        if len(frames) >= MAX_FRAMES:
            dropped += 1
            continue
        frames.append(_frame(message, at))
        heads.append(message.payload[:SECRET_FRAME_BYTES].hex())
    watched = round(run.loop.time() - began, 3)
    if heads:
        run.secrets["frame_heads"] = heads
    if ended is not None:  # the caller closes the session before any further await
        run.fail(ended)
    else:
        run.finish()
    return DataChannelReport(
        outcome=run.outcome("data_channel"),
        kcp_type=kcp_type,
        watched=watched,
        messages=messages,
        heartbeats=heartbeats,
        header_lens=tuple(sorted(header_lens)),
        frames=tuple(frames),
        frames_dropped=dropped,
        guard_mode_at=guard_mode_at,
        sealed_opened=sealed_opened,
        sealed_unread=sealed_unread,
        ended=type(ended).__name__ if ended is not None else None,
    )


def _frame_time(began: float, now: float) -> float:
    return now - began


def _notify_key(answer: CallAnswer | None) -> bytes | None:
    """The key a sealed notification is opened with: the answer's content key."""
    if answer is None:
        return None
    try:
        return media_key(answer.sdp_info.content_key)
    except ProtocolError:
        return None


def _names_guard_mode(payload: bytes, key: bytes | None) -> tuple[bool, bool] | None:
    """``(sealed, names the guard-mode parameter)`` of an XZYH frame; None for a sealed
    frame that does not open. A frame names it by its type or a ``param_type`` /
    ``commandType`` of :data:`~..p2p.params.GUARD_MODE_PARAM` in its JSON body."""
    if len(payload) < XZYH_HEADER_LEN or payload[:4] != XZYH_MAGIC:
        return False, False
    frame_type = struct.unpack_from("<H", payload, 4)[0]
    body = payload[XZYH_HEADER_LEN:]
    sealed = is_sealed(payload)
    if sealed:
        if key is None:
            return None
        try:
            body = decrypt_notification(key, body)
        except ProtocolError:
            return None
    if frame_type == GUARD_MODE_PARAM:
        return sealed, True
    try:
        obj = loads_json(body)
    except ProtocolError:
        return sealed, False
    return sealed, _json_names(obj, GUARD_MODE_PARAM, MAX_JSON_DEPTH)


def _json_names(obj: object, param: int, depth: int) -> bool:
    if depth <= 0:
        return False
    if isinstance(obj, Mapping):
        for name in ("param_type", "commandType"):
            if name in obj and json_int(obj[name]) == param:
                return True
        obj = list(obj.values())
    if isinstance(obj, list):
        return any(_json_names(item, param, depth - 1) for item in obj)
    return False


def _frame(message: LinkMessage, at: float) -> FrameRecord:
    payload = message.payload
    if len(payload) >= XZYH_HEADER_LEN and payload[:4] == XZYH_MAGIC:
        frame_type, length = struct.unpack_from("<HI", payload, 4)
        subheader = payload[10:XZYH_HEADER_LEN]
        return FrameRecord(
            round(at, 3),
            message.msg_type,
            message.header_len,
            frame_type,
            length,
            subheader.hex(),
            subheader[2],
        )
    return FrameRecord(
        round(at, 3), message.msg_type, message.header_len, None, len(payload), None, None
    )


async def _probe(run: _Run, port: int | None, tcp_ports: tuple[int, ...] | None) -> None:
    """Step 6: a fresh client logs in and CALLs each of :data:`PROBE_KINDS` once."""
    if "login" not in run.ended or "login" in run.failures:
        return
    extra: dict[str, Any] = {}
    if port is not None:
        extra["port"] = port
    if tcp_ports is not None:
        extra["tcp_ports"] = tcp_ports
    began = run.probe_started = run.loop.time()
    client = SignalingClient(run.config, **extra)
    try:
        try:
            await client.open()
            await client.login(run.quick_login)
        except Exception as exc:
            error, code = _error_fields(exc)
            run.probe_login = StepOutcome(StepStatus.FAILED, None, error, code)
            run.secrets.setdefault("errors", {})["probe_login"] = f"{error}: {exc}"
            return
        run.probe_login = StepOutcome(StepStatus.OK, round(run.loop.time() - began, 3))
        for kind in PROBE_KINDS:
            run.probe_current = int(kind)
            run.probe_results.append(await _probe_kind(run, client, kind))
        run.probe_current = None
    finally:
        await _close(client.close())


async def _probe_kind(run: _Run, client: SignalingClient, kind: CallKind) -> ProbeReport:
    began = run.loop.time()
    codes: list[int] = []
    hung_up = False
    try:
        call = await client.call(kind, wake=False)
    except Exception as exc:
        error, code = _error_fields(exc)
        return ProbeReport(int(kind), StepOutcome(StepStatus.FAILED, None, error, code))
    status = StepStatus.OK
    try:
        async with asyncio.timeout(PROBE_TIMEOUT):
            while True:
                event = await call.events.get()
                if event.kind is CallEventKind.HANGUP:
                    hung_up = True
                    break
                if event.header.is_response and event.header.code != ResponseCode.NONE:
                    codes.append(event.header.code)
                if event.kind in (CallEventKind.OFFER, CallEventKind.REFUSED):
                    break
    except TimeoutError:
        status = StepStatus.TIMEOUT
    finally:
        try:
            client.hangup(call)
        except Exception as exc:
            _LOGGER.debug("RTC probe hang-up not sent: %s", exc)
    seconds = round(run.loop.time() - began, 3)
    return ProbeReport(int(kind), StepOutcome(status, seconds), tuple(codes), hung_up)


# ── the report ───────────────────────────────────────────────────────────────


def _report(
    run: _Run, station: CloudDevice, reason: str, inputs: InputsReport, probe_kinds: bool
) -> RtcStationReport:
    quick = run.config.quick_login is not None and run.config.quick_login.usable()
    server = run.server_info[-1] if run.server_info else None
    login = LoginReport(
        discover=run.outcome("discover", unused="quick login" if quick else None),
        login=run.outcome("login"),
        quick_login=quick,
        server=ip_class(server.ip) if server is not None else None,
        server_records=len(run.server_info),
        login_rtt_ms=server.avg_rtt
        if server is not None and not server.last_fail_timestamp
        else None,
    )
    if run.local_candidates or run.remote_candidates:
        run.secrets["local_candidates"] = list(run.local_candidates)
        run.secrets["remote_candidates"] = list(run.remote_candidates)
    ice = IceReport(
        outcome=run.outcome("ice"),
        local_types=dict(Counter(_candidate_type(c) for c in run.local_candidates)),
        remote_types=dict(Counter(_candidate_type(c) for c in run.remote_candidates)),
        selected=run.selected,
    )
    channel = run.channel_report or DataChannelReport(outcome=run.outcome("data_channel"))
    if not probe_kinds:
        probes = ProbesReport(StepOutcome(StepStatus.SKIPPED, reason="not asked"))
    elif run.probe_login is None:
        probes = ProbesReport(run.outcome("probes", unused="login failed"))
    else:
        done = {p.kind for p in run.probe_results}
        skipped = tuple(
            ProbeReport(int(k), StepOutcome(StepStatus.SKIPPED, reason="run timed out"))
            for k in PROBE_KINDS
            if int(k) not in done
        )
        probes = ProbesReport(run.probe_login, (*run.probe_results, *skipped))
    return RtcStationReport(
        station=redact_serial(station.device_sn),
        reason=reason,
        inputs=inputs,
        login=login,
        call=_call_report(run),
        ice=ice,
        data_channel=channel,
        probes=probes,
        secrets=run.secrets,
    )


def _call_report(run: _Run) -> CallReport:
    config = run.config
    flag = client_flag(data_channel_kcp_type(config.station_sn[:5], config.sdk_version))
    outcome = run.outcome("call")
    call = run.call
    answer = call.answer if call is not None else None
    if call is None or answer is None:
        return CallReport(outcome, flag)
    turn = call.turn
    if turn is not None:
        run.secrets["turn"] = dict(turn)
    pbsdp = answer.get("pbsdp")
    reading = read_pbsdp(pbsdp)  # the field listing only; the caps are the session's
    parsed = _parsed(answer)
    caps = parsed.transport_caps if parsed is not None else None
    source = "none"
    if parsed is not None and parsed.pbsdp:
        source = "pbsdp"
    elif caps is not None:
        source = "json"
    return CallReport(
        outcome=outcome,
        client_flag=flag,
        answer_keys=_key_names(answer),
        answer_values={
            str(k): _answer_value(str(k), v)
            for k, v in list(answer.items())[:MAX_ANSWER_KEYS]
            if _plain_key(str(k))
        },
        transport_caps=caps,
        transport_caps_source=source,
        pbsdp_len=len(pbsdp) if isinstance(pbsdp, str | bytes | list) else None,
        pbsdp_decoded=reading.decoded if reading is not None else None,
        pbsdp_fields=reading.fields if reading is not None else (),
        pbsdp_sdp_fields=reading.sdp_fields if reading is not None else (),
        request_id_present=answer.get("request_id") not in (None, ""),
        turn_present=turn is not None,
        turn_keys=_key_names(turn) if turn is not None else (),
        device_sdp=_sdp_report(answer.get("sdp_info")),
        transport=select_transport(flag, caps).value if parsed is not None else None,
    )


def _parsed(answer: Mapping[str, Any]) -> CallAnswer | None:
    """The answer as the session reads it; None when it does not parse."""
    try:
        return CallAnswer.parse(answer)
    except ProtocolError:
        return None


def _sdp_report(text: object) -> SdpReport | None:
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
        info = SdpInfo.decode(raw)
    except (binascii.Error, ValueError, EufySecurityError):
        return None
    return SdpReport(
        length=len(raw),
        flag_byte=raw[2],
        bytes_3_5=(raw[3], raw[4], raw[5]),
        ufrag_len=len(info.ice_ufrag),
        pwd_len=len(info.ice_pwd),
        key_len=len(info.content_key),
        iv_len=len(info.content_iv),
        audio_ssrc_present=info.audio_ssrc != 0,
        video_ssrc_present=info.video_ssrc != 0,
    )


__all__ = [
    "ANSWER_INT_KEYS",
    "ANSWER_TEXT_KEYS",
    "DEFAULT_WATCH",
    "MAX_WATCH",
    "CallReport",
    "DataChannelReport",
    "DeviceRoute",
    "FrameRecord",
    "IceReport",
    "InputsReport",
    "LoginReport",
    "ProbeReport",
    "ProbesReport",
    "RtcStationReport",
    "SdpReport",
    "StepOutcome",
    "StepStatus",
    "async_diagnose_station",
    "describe_inputs",
    "ip_class",
    "placeholder",
    "rtc_stations",
    "station_budget",
]
