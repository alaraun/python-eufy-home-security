"""Pure renderers: library data in, text (or JSON-ready dicts) out."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, assert_never

from .._logging import redact, redact_serial
from ..devices.capabilities import profile_for_serial
from ..devices.command_types import command_name
from ..devices.model_settings import SettingKind
from ..devices.types import model_for_serial
from ..events import (
    AccountMismatch,
    AlarmChanged,
    CameraBusyChanged,
    CloudProblem,
    ConnectionChanged,
    CredentialsRefreshed,
    DevicesChanged,
    Event,
    GuardModeChanged,
    ParamChanged,
    PresetsChanged,
    PushChanged,
    PushMessageType,
    SecurityEvent,
    StationsChanged,
    StationStateChanged,
    StorageChanged,
    ZoomChanged,
)
from ..models import STATION_CHANNEL, GuardMode
from ..network import LanPath, PathWarning, suggest_local_ports
from ..p2p.params import ParamDump

if TYPE_CHECKING:
    from ..client import ModelStatus
    from ..cloud.models import CloudDevice
    from ..devices.model_settings import Setting, Value
    from ..p2p.discovery import DiscoveredStation
    from ..p2p.storage_info import StorageInfo, StorageMedium
    from ..station import StationState, SubDeviceState

_MAX_VALUE = 60
# Station parameters the card shows elsewhere, so they are not repeated as profile rows.
_CARD_PARAMS = frozenset({"guard_mode", "sub_device_serials"})


def fmt_serial(serial: str | None, show: bool) -> str:
    """A serial for human output: redacted unless ``show``."""
    if not serial:
        return "?"
    return serial if show else redact_serial(serial)


def model_label(serial: str) -> str:
    """The catalog name for a serial, or its prefix when not catalogued."""
    model = model_for_serial(serial)
    return model.name if model else f"model {serial[:5]} (not in catalog)"


def guard_mode_label(mode: GuardMode | int | None) -> str:
    """``Home (1)``, ``unknown code 9`` or ``unknown``."""
    if mode is None:
        return "unknown"
    if isinstance(mode, GuardMode):
        return f"{mode.name.replace('_', ' ').title()} ({int(mode)})"
    return f"unknown code {mode}"


def _table(rows: Sequence[Sequence[str]], indent: str = "  ") -> list[str]:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return [
        (indent + "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True))).rstrip()
        for row in rows
    ]


def _truncate(value: object) -> str:
    text = str(value)
    return text if len(text) <= _MAX_VALUE else text[: _MAX_VALUE - 3] + "..."


# ── discover / devices ───────────────────────────────────────────────────────


def render_discovered(stations: Sequence[DiscoveredStation]) -> str:
    if not stations:
        return (
            "No station answered the LAN search. Stations only answer on the same "
            "layer-2 network (UDP broadcast to port 32108)."
        )
    rows = [("IP", "PORT", "DID")]
    rows += [(s.ip, str(s.port), str(s.did)) for s in stations]
    return "\n".join([f"{len(stations)} station(s) answered:", *_table(rows)])


def render_devices(devices: Sequence[CloudDevice], *, show_serials: bool) -> str:
    if not devices:
        return "The account has no devices."
    stations = [d for d in devices if d.is_station]
    station_sns = {d.device_sn for d in stations}
    children: dict[str, list[CloudDevice]] = {}
    orphans: list[CloudDevice] = []
    for device in devices:
        if device.is_station:
            continue
        if device.station_sn in station_sns:
            children.setdefault(device.station_sn or "", []).append(device)
        else:
            orphans.append(device)

    def row(device: CloudDevice, prefix: str) -> tuple[str, ...]:
        model = model_for_serial(device.device_sn)
        channel = "" if device.is_station or device.channel is None else f"ch {device.channel}"
        return (
            prefix + (device.name or "(unnamed)"),
            channel,
            fmt_serial(device.device_sn, show_serials),
            model.name if model else f"{device.device_sn[:5]} (not in catalog)",
            str(model.kind) if model else "",
            str(model.evidence.support) if model else "unknown",
            device.region or "",
        )

    rows: list[tuple[str, ...]] = [
        ("NAME", "CHANNEL", "SERIAL", "MODEL", "KIND", "SUPPORT", "REGION")
    ]
    for station in stations:
        rows.append(row(station, ""))
        rows.extend(row(child, "└ ") for child in children.get(station.device_sn, []))
    rows.extend(row(device, "") for device in orphans)
    return "\n".join(_table(rows, indent=""))


# ── network ──────────────────────────────────────────────────────────────────


def render_network(paths: Sequence[LanPath], *, show_serials: bool) -> str:
    """Each station's LAN path, and what a firewall between here and it must allow."""
    if not paths:
        return "The account has no station."
    rows: list[tuple[str, ...]] = [("NAME", "SERIAL", "ADDRESS", "FROM", "LOCAL PORT", "LAN REPLY")]
    rows.extend(
        (
            path.name or "(unnamed)",
            fmt_serial(path.serial, show_serials),
            path.station_ip or "?",
            str(path.host_source),
            str(path.local_port) if path.local_port else "ephemeral",
            {True: "yes", False: "no", None: "-"}[path.answered],
        )
        for path in paths
    )
    pinned = {path.local_port for path in paths if path.local_port}
    suggested = suggest_local_ports(
        (path.serial for path in paths if not path.local_port), taken=pinned
    )
    advice: list[str] = []
    for path in paths:
        who = path.name or fmt_serial(path.serial, show_serials)
        station = path.name or path.serial
        ip = path.station_ip or "<station IP>"
        for warning in path.warnings:
            match warning:
                case PathWarning.BROADCAST_ONLY if path.observed_ip:
                    advice.append(
                        f"{who}: found only by broadcast (at {path.observed_ip}), so this host "
                        "must be on the station's network; give the station a fixed IP and "
                        f"pass --host {path.observed_ip}"
                    )
                case PathWarning.BROADCAST_ONLY:
                    advice.append(
                        f"{who}: no LAN address is known, so discovery is a broadcast and this "
                        "host must be on the station's network; give the station a fixed IP "
                        "and pass --host"
                    )
                case PathWarning.EPHEMERAL_PORT:
                    advice.append(
                        f"{who}: if this host or the network filters inbound UDP, allow all UDP "
                        f"from {ip}, or pin a port (--station {station!r} --local-port "
                        f"{suggested[path.serial]}) and allow UDP from {ip} to it"
                    )
                case PathWarning.NO_LAN_REPLY:
                    advice.append(
                        f"{who}: did not answer LAN discovery: it is offline, on another "
                        "network, or a firewall drops its replies"
                    )
                case PathWarning.ADDRESS_CHANGED:
                    elsewhere = path.observed_ip or path.cloud_ip
                    advice.append(
                        f"{who}: the configured address {path.host} is not where the station "
                        f"is ({elsewhere}); its IP has changed, or the setting is stale"
                    )
        if path.local_port:
            advice.append(f"{who}: allow UDP from {ip} to this host's port {path.local_port}")
    lines = _table(rows, indent="")
    lines += ["", "Network:"]
    lines += [f"  - {line}" for line in advice]
    lines.append(
        "  - every rule names the station's address: give each station a fixed IP "
        "(a DHCP reservation)"
    )
    return "\n".join(lines)


# ── status ───────────────────────────────────────────────────────────────────


_ACRONYMS = {"lan": "LAN", "ip": "IP", "emmc": "eMMC", "hdd": "HDD"}


def _profile_label(name: str, value: str) -> tuple[str, str]:
    """A profile parameter name as a card label (``emmc_used_percent`` → ``eMMC used``)."""
    percent = name.endswith("_percent")
    words = [_ACRONYMS.get(w, w) for w in name.removesuffix("_percent").split("_")]
    if words[0] not in _ACRONYMS.values():
        words[0] = words[0].capitalize()
    return " ".join(words), f"{value}%" if percent else value


def _paired_serials(params: Mapping[int, str | None]) -> list[str]:
    dump = ParamDump()
    dump.devices[STATION_CHANNEL] = {pid: v for pid, v in params.items() if v is not None}
    return [serial for serial in dump.sub_device_serials() if serial is not None]


def _plain(text: str) -> str:
    """``text`` as is when it is printable ASCII, else its ``repr``: an identifier from
    data never reaches the terminal raw."""
    return text if text.isascii() and text.isprintable() else repr(text)


def render_status(
    state: StationState,
    *,
    name: str,
    host: str | None,
    show_serials: bool,
    models: Mapping[str, ModelStatus] | None = None,
) -> str:
    """A human status card for one station and its sub-devices.

    ``models`` (product code -> :class:`~..client.ModelStatus`) adds one line per model
    listed read-only from the cloud or with newer vendor data than bundled.
    """
    lines = [f'{model_label(state.serial)} "{name}"  {fmt_serial(state.serial, show_serials)}']
    lines.append(f"  Firmware:    {state.firmware or 'unknown'}")
    lines.append(f"  Guard mode:  {guard_mode_label(state.guard_mode)}")
    if state.active_mode is not None and state.active_mode != state.guard_mode:
        lines.append(f"  In force:    {guard_mode_label(state.active_mode)}")
    if host:
        lines.append(f"  Address:     {host}")
    profile = profile_for_serial(state.serial)
    for pname, pid in profile.params.items() if profile else ():
        value = state.params.get(pid)
        if pname in _CARD_PARAMS or value in (None, ""):
            continue
        label, text = _profile_label(pname, str(value))
        lines.append(f"  {label + ':':<12} {text}")
    paired = _paired_serials(state.params)
    if paired:
        lines.append(f"  Paired:      {len(paired)} device(s)")
    for channel in sorted(state.devices):
        dev = state.devices[channel]
        bits = [f"ch {channel}", f'"{dev.name}"' if dev.name else "(unnamed)"]
        if dev.serial:
            bits += [fmt_serial(dev.serial, show_serials), model_label(dev.serial)]
        # The station keeps serving an offline device's last values: say so, and label
        # them as last-known rather than letting them read as current.
        last = ""
        if dev.online is False:
            code = f" (code {dev.offline_code})" if dev.offline_code is not None else ""
            bits.append(f"OFFLINE{code}")
            last = "last "
        if dev.battery is not None:
            bits.append(f"{last}battery {dev.battery}%")
        if dev.rssi is not None:
            bits.append(f"{last}RSSI {dev.rssi} dBm")
        if dev.firmware:
            bits.append(f"fw {dev.firmware}")
        if dev.power_source is not None:
            bits.append(_charging_label(dev))
        if dev.low_battery:
            bits.append("LOW BATTERY")
        lines.append("  • " + "  ".join(bits))
    lines.extend(_model_lines(models or {}))
    return "\n".join(lines)


def _charging_label(dev: SubDeviceState) -> str:
    """``charging (solar)``, ``charging``, or ``not charging``, with the raw code."""
    if not dev.charging:
        return f"not charging ({dev.power_source})"
    how = " (solar)" if dev.solar_charging else ""
    return f"charging{how} ({dev.power_source})"


def _model_lines(models: Mapping[str, ModelStatus]) -> list[str]:
    lines: list[str] = []
    for code in sorted(models):
        status = models[code]
        if status.state == "cloud-listed":
            lines.append(f"  {code}: not in bundled data: settings listed read-only")
        if status.newer_vendor_data:
            lines.append(
                f"  {code}: vendor data newer than bundled "
                f"(td {status.cloud_td_version} > {status.bundled_td_version})"
            )
    return lines


def _param_block(title: str, params: Mapping[int, str | None]) -> list[str]:
    lines = [f"=== {title} — {len(params)} params ==="]
    if params:
        rows = [("ID", "NAME", "VALUE")]
        rows += [(str(pid), command_name(pid), _truncate(v)) for pid, v in sorted(params.items())]
        lines += _table(rows, indent="")
    return lines


def render_coverage(state: StationState, *, show_serials: bool) -> str:
    """Where the device's model settings and the dump disagree, per block.

    Whether a unit reports what its model's settings offer: UNREPORTED counts readable
    settings this block does not carry, UNREAD parameters the library reads
    nowhere (:class:`~..station.SettingsCoverage`).
    """
    lines = ["=== settings coverage ==="]
    rows = [("BLOCK", "KIND", "ONLINE", "SETTINGS", "REPORTED", "UNREPORTED", "UNREAD")]
    for cov in state.coverage():
        where = "station" if cov.channel == STATION_CHANNEL else f"channel {cov.channel}"
        online = "-" if cov.online is None else ("yes" if cov.online else "NO")
        rows.append(
            (
                where,
                cov.kind.value if cov.kind else "-",
                online,
                "yes" if cov.has_settings else "NONE",
                str(len(cov.reported)),
                str(len(cov.unreported)),
                str(len(cov.unread)),
            )
        )
    lines += _table(rows, indent="")
    for cov in state.coverage():
        where = "station" if cov.channel == STATION_CHANNEL else f"channel {cov.channel}"
        if show_serials and cov.serial:
            where += f" ({cov.serial})"
        if not cov.has_settings:
            lines += ["", f"{where}: no settings file for its model — the library claims none."]
            continue
        if cov.unreported:
            lines += [
                "",
                f"{where}: in the model settings but NOT reported — {', '.join(cov.unreported)}",
            ]
        if cov.unread:
            lines += [
                "",
                f"{where}: reported but read nowhere — "
                + ", ".join(f"{pid} {command_name(pid)}" for pid in cov.unread),
            ]
    return "\n".join(lines)


def render_raw_params(state: StationState) -> str:
    """Every parameter of the dump, grouped by ``dev_type``, with catalog names."""
    lines = _param_block(f"station (dev_type {STATION_CHANNEL})", state.params)
    for channel in sorted(state.devices):
        lines.append("")
        lines += _param_block(f"device (dev_type {channel})", state.devices[channel].params)
    return "\n".join(lines)


def _mode_json(mode: GuardMode | int | None) -> str | int | None:
    return mode.name.lower() if isinstance(mode, GuardMode) else mode


def status_json(state: StationState, *, name: str) -> dict[str, Any]:
    """The snapshot as JSON-ready data (full serials: this is machine output)."""
    return {
        "serial": state.serial,
        "name": name,
        "firmware": state.firmware,
        "guard_mode": _mode_json(state.guard_mode),
        "guard_mode_code": None if state.guard_mode is None else int(state.guard_mode),
        "active_mode": _mode_json(state.active_mode),
        "storage_status": state.storage_status,
        "subsystem_firmware": {str(pid): v for pid, v in sorted(state.subsystem_firmware.items())},
        "params": {str(pid): v for pid, v in sorted(state.params.items())},
        "devices": {
            str(channel): {
                "serial": dev.serial,
                "name": dev.name,
                "online": dev.online,
                "offline_code": dev.offline_code,
                "battery": dev.battery,
                "battery_temperature": dev.battery_temperature,
                "low_battery": dev.low_battery,
                "rssi": dev.rssi,
                "firmware": dev.firmware,
                "power_source": dev.power_source,
                "charging": dev.charging,
                "solar_charging": dev.solar_charging,
                "solar_intensity": dev.solar_intensity,
                "working_days": dev.working_days,
                "detected_events": dev.detected_events,
                "recorded_events": dev.recorded_events,
                "siren_actions": {_mode_json(m): v for m, v in dev.siren_actions.items()},
                "params": {str(pid): v for pid, v in sorted(dev.params.items())},
            }
            for channel, dev in sorted(state.devices.items())
        },
    }


# ── storage ──────────────────────────────────────────────────────────────────


def _gb(gib: float | None) -> str:
    # The app labels GiB as "GB"; so does the CLI, so the figures can be compared.
    return "?" if gib is None else f"{gib:.2f} GB"


def _medium_lines(title: str, medium: StorageMedium) -> list[str]:
    percent = "" if medium.used_percent is None else f" ({medium.used_percent:.1f} %)"
    lines = [
        f"  {title + ':':<14} {_gb(medium.used_gib)} used of {_gb(medium.size_gib)}{percent}",
        f"  {'':<14} {_gb(medium.free_gib)} free",
    ]
    bits = [medium.model or ""]
    if medium.temperature_c is not None:
        bits.append(f"{medium.temperature_c} °C")
    if medium.wear_percent is not None:
        bits.append(f"wear {medium.wear_percent} %")
    if medium.health is not None:
        bits.append("healthy" if medium.healthy else f"HEALTH CODE {medium.health}")
    if medium.formatting:
        bits.append("FORMATTING")
    elif medium.ready is False:
        bits.append(f"not ready (parted_status {medium.parted_status})")
    if shown := [bit for bit in bits if bit]:
        lines.append(f"  {'':<14} {'  '.join(shown)}")
    return lines


def render_storage(storage: StorageInfo, *, name: str) -> str:
    """The storage record in the eufy app's own figures."""
    lines = [f'Storage of "{name}"']
    if storage.disk is not None:
        lines += _medium_lines("Disk", storage.disk)
    else:
        lines.append(f"  {'Disk:':<14} none reported")
    if storage.external is not None:
        lines += _medium_lines("External disk", storage.external)
    if storage.emmc is not None:
        lines += _medium_lines("eMMC", storage.emmc)
    if storage.storage_events is not None and storage.storage_days is not None:
        lines.append(
            f"  {'Kept:':<14} {storage.storage_events} event(s) over {storage.storage_days} day(s)"
        )
    if storage.format_error:
        lines.append(f"  {'Last format:':<14} error {storage.format_error}")
    return "\n".join(lines)


_MEDIUM_DERIVED = (
    "free_mib",
    "used_percent",
    "used_gib",
    "size_gib",
    "free_gib",
    "recordings_used_gib",
    "recordings_capacity_gib",
)
_MEDIUM_FLAGS = ("healthy", "formatting", "ready")


def _medium_json(medium: StorageMedium | None, *, show_serials: bool) -> dict[str, Any] | None:
    if medium is None:
        return None
    data: dict[str, Any] = _jsonable(medium)
    if not show_serials:
        data.update({key: redact(data[key]) for key in ("serial", "label") if data[key]})
    data.update({key: getattr(medium, key) for key in (*_MEDIUM_DERIVED, *_MEDIUM_FLAGS)})
    return data


def storage_json(storage: StorageInfo, *, show_serials: bool) -> dict[str, Any]:
    """The record as JSON-ready data with the derived figures (serial and label
    redacted unless ``show_serials``)."""
    data: dict[str, Any] = _jsonable(storage)
    for key in ("disk", "external", "emmc"):
        data[key] = _medium_json(getattr(storage, key), show_serials=show_serials)
    data["formatting"] = storage.formatting
    return data


# ── settings ─────────────────────────────────────────────────────────────────


def setting_value(value: Value) -> str:
    """A setting value for display: ``true``/``false`` for a bool, else as is."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_setting_value(setting: Setting, value: Value | None) -> str:
    """A read setting value: ``VALUE (LABEL) UNIT``, ``unknown`` when absent."""
    if value is None:
        return "unknown"
    if setting.kind is SettingKind.FLAGS and isinstance(value, int):
        on, other = setting.decode_flags(value)
        names = ", ".join(setting.flag_label(f) for f in setting.flags if f in on) or "none"
        extra = f" (+0x{other:x})" if other else ""
        return _plain(f"{value} ({names}){extra}")
    text = setting_value(value)
    if (label := setting.label(value)) is not None:
        text += f" ({label})"
    if setting.unit is not None:
        text += f" {setting.unit.value}"
    return _plain(text)


def _domain(setting: Setting) -> str:
    """Enum values as ``value=label``, flags as ``member=label`` (several may be on), a
    range as ``min..max step s``; ``-`` otherwise."""
    if setting.kind is SettingKind.FLAGS:
        return "any of " + ", ".join(f"{f}={setting.flag_label(f)}" for f in setting.flags)
    if setting.kind is SettingKind.ENUM and setting.values:
        return ", ".join(
            f"{setting_value(v)}={label}" if (label := setting.label(v)) else setting_value(v)
            for v in setting.values
        )
    if setting.minimum is not None and setting.maximum is not None:
        step = "" if setting.step is None else f" step {setting_value(setting.step)}"
        return f"{setting_value(setting.minimum)}..{setting_value(setting.maximum)}{step}"
    return "-"


def _setting_rows(settings: Iterable[Setting]) -> list[str]:
    rows = [("KEY", "KIND", "VALUES", "UNIT", "WRITABLE", "APPLIES WHEN")]
    rows += [
        (
            _plain(s.key),
            s.kind.value,
            _plain(_domain(s)),
            s.unit.value if s.unit is not None else "-",
            "yes" if s.writable else _plain(s.note or "read-only"),
            f"{s.applies_when[0]} = {setting_value(s.applies_when[1])}"
            if s.applies_when is not None
            else "-",
        )
        for s in settings
    ]
    return _table(rows)


def render_mode_table_settings(camera: Sequence[Setting], sensor: Sequence[Setting]) -> str:
    """The per-mode delays and actions (``settings`` without ``--model``): every
    mode-table setting once, with the paired devices that carry it."""
    on_camera = {s.key for s in camera}
    on_sensor = {s.key for s in sensor}
    merged = {s.key: s for s in (*camera, *sensor)}
    rows = [("KEY", "VALUES", "UNIT", "DEVICES")]
    rows += [
        (
            key,
            _domain(s),
            s.unit.value if s.unit is not None else "-",
            " and ".join(
                kind
                for kind, keys in (("cameras", on_camera), ("sensors", on_sensor))
                if key in keys
            ),
        )
        for key, s in merged.items()
    ]
    return "\n".join(
        [
            "per-mode settings of a station's paired devices (address: --device SN or --channel N)",
            *_table(rows),
            "",
            "A model's own settings:  eufy-security settings --model PN  (e.g. T8160)",
        ]
    )


def render_model_settings(
    product_code: str, settings: Iterable[Setting], mode_table: Sequence[Setting] = ()
) -> str:
    """The settings of one model (``settings --model``): a row per setting in the
    model's file, then the per-mode settings it carries when paired to a station.
    A setting the library does not write says why in WRITABLE."""
    code = _plain(product_code)
    listed = list(settings)
    if not listed:
        return f"no bundled settings for {code}"
    out = [f"settings of {code}", *_setting_rows(listed)]
    if mode_table:
        out += ["", f"per-mode settings of a paired {code}", *_setting_rows(mode_table)]
    out += [
        "",
        "Read one:   eufy-security get KEY [--device SN | --channel N]",
        "Write one:  eufy-security set KEY VALUE [--device SN | --channel N]",
    ]
    return "\n".join(out)


# ── events and media ─────────────────────────────────────────────────────────


def _field(row: Mapping[str, Any], *names: str) -> Any:
    inner = row.get("payload")
    sources = (row, inner) if isinstance(inner, Mapping) else (row,)
    for name in names:
        for src in sources:
            value = src.get(name)
            if value not in (None, "", 0):
                return value
    return None


def _when(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return str(value) if value else "?"
    seconds = value / 1000 if value > 1e11 else value
    if seconds <= 1e9:
        return str(value)
    return datetime.fromtimestamp(seconds, tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def describe_station_row(str_extra: Any) -> str:
    """One-line summary of a media-less record (arming, alarms) from its ``str_extra``."""
    try:
        extra = json.loads(str_extra) if isinstance(str_extra, str) else None
    except ValueError:
        extra = None
    if not isinstance(extra, dict):
        return "(station event)"
    msg_type = extra.get("msg_type")
    try:
        bits = [PushMessageType(int(str(msg_type))).name.lower()]
    except ValueError:
        bits = ["station event"]
    mode = extra.get("arm_mode", extra.get("cur_mode"))
    if mode is not None:
        try:
            bits.append(guard_mode_label(GuardMode(int(mode))))
        except (TypeError, ValueError):
            bits.append(f"mode {mode}")
    if extra.get("user_name"):
        bits.append(f"by {extra['user_name']}")
    return " · ".join(bits)


_MEDIA_FIELDS = (
    ("video", ("storage_path", "file_path")),
    ("thumb", ("thumb_path",)),
    ("crop", ("crop_path", "crop_hb3_path")),
)


def has_media(row: Mapping[str, Any]) -> bool:
    return any(_field(row, *names) for _, names in _MEDIA_FIELDS)


_ENTITY_PICTURE = ("face_picture_content", "reid_picture_content", "pic_url")


def describe_db_entity(row: Mapping[str, Any]) -> str | None:
    """Render an AI picture-library row (``person``/``face``/``reid`` DB tables) as a
    useful line — name, person id, times seen, and its fetchable picture path — or
    ``None`` when the row is not one of those (a real event, handled elsewhere).

    These tables are not events; :func:`describe_station_row` would show them as
    ``(station event)``.
    """
    person_id = _field(row, "person_id")
    picture = _field(row, *_ENTITY_PICTURE)
    if person_id is None and picture is None:
        return None
    name = _field(row, "face_name", "reid_name", "name")
    when = _when(_field(row, "update_time", "create_time"))
    bits = [str(name) if name else "unnamed"]
    if person_id is not None:
        bits.append(f"person {person_id}")
    if relation := _field(row, "relation"):
        bits.append(str(relation))
    if seen := _field(row, "recognize_cnt"):
        bits.append(f"seen {seen}x")
    line = f"  • {when}  " + " · ".join(bits)
    if picture:
        line += f"\n      picture: {picture}"
    return line


def render_entities(rows: Sequence[Mapping[str, Any]], title: str) -> str:
    """The AI picture library (person / face / reid rows) as a list of entities.

    Kept separate from :func:`render_events`: these are the recognised-people
    library, not events, and mixing them into an event listing is just noise.
    """
    if not rows:
        return f"No {title} on the station."
    out = [f"{len(rows)} {title}:"]
    out.extend(describe_db_entity(row) or f"  • {row}" for row in rows)
    if any(_field(row, *_ENTITY_PICTURE) for row in rows):
        out += ["", "Fetch a picture:  eufy-security image <picture path> --out face.jpg"]
    return "\n".join(out)


def render_events(
    rows: Sequence[Mapping[str, Any]], start: str, end: str, *, show_serials: bool
) -> str:
    """Event records as a list whose paths can be copied into ``image``.

    The record schema varies by table and firmware: each field is looked up at
    the top level and inside a nested ``payload``, and anything missing is left out.
    """
    if not rows:
        return (
            f"No records between {start} and {end}. This reads the station's own storage "
            "only; try more --days or another --table. Camera detections arrive live "
            "(`monitor`), and a stored camera history needs a eufy cloud plan."
        )
    out = [f"{len(rows)} record(s), {start} to {end}:"]
    for row in rows:
        who = _field(row, "device_sn", "station_sn")
        head = f"  • {_when(_field(row, 'start_time', 'start_time_utc', 'create_time', 'trigger_time'))}"
        head += f"  {fmt_serial(who, show_serials) if isinstance(who, str) else '?'}"
        paths = [(label, _field(row, *names)) for label, names in _MEDIA_FIELDS]
        paths = [(label, path) for label, path in paths if path]
        if paths:
            kind = _field(row, "video_type", "event_type", "trigger_type")
            if kind is not None:
                head += f"  type {kind}"
        else:
            head += "  " + describe_station_row(_field(row, "str_extra"))
        out.append(head)
        out.extend(f"      {label}: {path}" for label, path in paths)
    if any(has_media(row) for row in rows):
        out += ["", "Fetch a still:  eufy-security image <thumb or crop path> --out still.jpg"]
    else:
        out += [
            "",
            "These are the station's local records (guard-mode/audit here). Camera "
            "detections arrive live — see `monitor` — and a stored, browsable camera "
            "history needs a eufy cloud plan.",
        ]
    return "\n".join(out)


def describe_image(blob: bytes) -> str:
    if blob[:3] == b"\xff\xd8\xff" or blob[:2] == b"\xff\xd8":
        return "JPEG"
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    return f"unknown format ({blob[:8].hex()})"


def decode_data_uri(uri: str) -> tuple[bytes, str]:
    """``data:image/png;base64,…`` → ``(bytes, ".png")``; raises ``ValueError``."""
    header, sep, body = uri.partition(",")
    if not sep or not header.startswith("data:"):
        raise ValueError("not a data URI")
    mime = header[5:].split(";", 1)[0] or "application/octet-stream"
    try:
        data = base64.b64decode(body, validate=False) if ";base64" in header else body.encode()
    except binascii.Error as err:
        raise ValueError(f"bad base64 in data URI: {err}") from err
    suffix = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif"}.get(mime, ".bin")
    return data, suffix


# ── monitor ──────────────────────────────────────────────────────────────────


def _event_name(event: SecurityEvent) -> str:
    if event.detection is not None:
        return f"{event.detection.name.lower()} detection"
    if event.message_type is not None:
        return event.message_type.name.lower()
    if event.event_type is not None or event.msg_type is not None:
        return f"msg_type {event.msg_type} event_type {event.event_type}"
    return "event"


def render_event(event: Event, *, now: datetime, show_serials: bool) -> str:
    """One monitor line per event."""
    stamp = now.strftime("%H:%M:%S")
    match event:
        case SecurityEvent():
            who = f'"{event.device_name}"' if event.device_name else ""
            sn = event.device_sn or event.station_sn
            bits = [f"[{stamp}] {event.source}: {_event_name(event)}"]
            if not event.authenticated:
                bits.append("unauthenticated (ECB)")
            if who or sn:
                bits.append(" ".join(b for b in (who, fmt_serial(sn, show_serials)) if b))
            if event.channel is not None:
                bits.append(f"ch {event.channel}")
            if event.person_name:
                bits.append(f"person {event.person_name}")
            if event.guard_mode is not None:
                bits.append(f"guard mode {guard_mode_label(_as_mode(event.guard_mode))}")
            if event.arming_source is not None:
                bits.append(f"by {event.arming_source}")
            if event.alarm_phase is not None:
                bits.append(f"alarm {event.alarm_phase}")
            if event.thumb_path:
                bits.append(f"thumb {event.thumb_path}")
            if event.rejected_fields:
                bits.append(f"rejected {','.join(sorted(event.rejected_fields))}")
            if event.enriches:
                bits.append("(adds media to an event already shown)")
            return "  ".join(bits)
        case AccountMismatch():
            return (
                f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} account mismatch: "
                "the station stamps another account id than commands carry; "
                "commands may be ignored"
            )
        case GuardModeChanged():
            in_force = (
                f" (in force {guard_mode_label(event.active_mode)})"
                if event.active_mode is not None and event.active_mode != event.mode
                else ""
            )
            return (
                f"[{stamp}] {event.source}: guard mode {guard_mode_label(event.mode)}{in_force}"
                f"  {fmt_serial(event.station_sn, show_serials)}"
            )
        case AlarmChanged():
            state = "alarm started" if event.alarming else "alarm ended"
            details = [
                f"{label} {value}"
                for label, value in (
                    ("ch", event.channel),
                    ("type", event.event_type),
                    ("for", None if event.duration_s is None else f"{event.duration_s}s"),
                    (
                        "stopped from",
                        None if event.stop_source is None else event.stop_source.name.lower(),
                    ),
                )
                if value is not None
            ]
            return "  ".join(
                [
                    f"[{stamp}] {event.source}: {state}",
                    *details,
                    fmt_serial(event.station_sn, show_serials),
                ]
            )
        case ParamChanged():
            where = "station" if event.channel == STATION_CHANNEL else f"ch {event.channel}"
            return (
                f"[{stamp}] param {where} {event.param_id} {command_name(event.param_id)}: "
                f"{_truncate(event.old)} → {_truncate(event.new)}"
            )
        case ConnectionChanged():
            state = "connected" if event.connected else "disconnected"
            reason = f" ({event.reason})" if event.reason else ""
            return f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} {state}{reason}"
        case CloudProblem():
            where = f"  {fmt_serial(event.station_sn, show_serials)}" if event.station_sn else ""
            return f"[{stamp}] cloud problem: {type(event.error).__name__}: {event.error}{where}"
        case PushChanged():
            if event.running:
                return f"[{stamp}] cloud push listening"
            cause = f": {type(event.error).__name__}: {event.error}" if event.error else ""
            return f"[{stamp}] cloud push not listening{cause}"
        case CredentialsRefreshed():
            fetched = [
                name
                for name, done in (
                    ("cipher", event.cipher),
                    ("owner id", event.owner_id),
                    ("login", event.login),
                )
                if done
            ]
            return (
                f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} credentials "
                f"refreshed ({', '.join(fetched) or 'nothing fetched'})"
            )
        case DevicesChanged():
            changes = [
                f"{label} {', '.join(fmt_serial(sn, show_serials) for sn in serials)}"
                for label, serials in (
                    ("added", event.added),
                    ("removed", event.removed),
                    ("moved", event.moved),
                )
                if serials
            ]
            return (
                f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} paired devices "
                f"changed: {'; '.join(changes) or 'nothing'}"
            )
        case StationsChanged():
            changes = [
                f"{label} {', '.join(fmt_serial(sn, show_serials) for sn in serials)}"
                for label, serials in (("added", event.added), ("removed", event.removed))
                if serials
            ]
            return (
                f"[{stamp}] stations changed ({event.source or 'unknown'} list): "
                f"{'; '.join(changes) or 'nothing'}"
            )
        case StationStateChanged():
            return (
                f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} state: guard mode "
                f"{guard_mode_label(event.state.guard_mode)}, "
                f"{len(event.state.devices)} device(s)"
            )
        case StorageChanged():
            disk = event.storage.disk
            used = "no disk" if disk is None else f"disk {_gb(disk.used_gib)} used"
            if disk is not None:
                used += f" of {_gb(disk.size_gib)}" + (" FORMATTING" if disk.formatting else "")
            return f"[{stamp}] {fmt_serial(event.station_sn, show_serials)} storage: {used}"
        case CameraBusyChanged():
            state = "capturing" if event.busy else "free"
            return f"[{stamp}] {fmt_serial(event.device_sn, show_serials)} {state}"
        case PresetsChanged():
            enabled = [str(slot.index) for slot in event.presets if slot.enabled]
            return (
                f"[{stamp}] {fmt_serial(event.device_sn, show_serials)} presets: "
                f"{', '.join(enabled) or 'none set'}"
            )
        case ZoomChanged():
            return f"[{stamp}] {fmt_serial(event.device_sn, show_serials)} zoom: {event.zoom:g}x"
        case _:
            assert_never(event)


def _as_mode(code: int) -> GuardMode | int:
    try:
        return GuardMode(code)
    except ValueError:
        return code


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.name.lower() if isinstance(value, GuardMode) else value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, frozenset):
        return sorted(_jsonable(v) for v in value)
    return value


def event_json(event: Event) -> dict[str, Any]:
    """An event as JSON-ready data: its type plus every field."""
    data: dict[str, Any] = {"type": type(event).__name__}
    data.update({f.name: _jsonable(getattr(event, f.name)) for f in fields(event)})
    if isinstance(event, ParamChanged):
        data["name"] = command_name(event.param_id)
    if isinstance(event, SecurityEvent):
        for name in ("scope", "alarm_phase", "arming_source", "dedupe_key"):
            data[name] = _jsonable(getattr(event, name))
    return data
