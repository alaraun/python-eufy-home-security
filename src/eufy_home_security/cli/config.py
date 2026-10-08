"""Command-line grammar: the argparse tree, defaults and credential lookup."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path

from ..cloud.const import REGIONS
from ..p2p.pppp import BROADCAST, DISCOVERY_PORT, LAN_DISCOVERY_TIMEOUT

PROG = "eufy-security"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130
MAX_DAYS = 36500
MAX_PORT = 65535
ENV_EMAIL = "EUFY_EMAIL"
ENV_PASSWORD = "EUFY_PASSWORD"  # noqa: S105 - the variable's name, not a secret


class UsageError(Exception):
    """The command line asks for something that cannot be done as stated (exit 2)."""


def _config_dir(env: Mapping[str, str]) -> Path:
    """``$XDG_CONFIG_HOME/eufy-security`` (``~/.config`` when unset)."""
    base = env.get("XDG_CONFIG_HOME") or str(Path("~/.config").expanduser())
    return Path(base) / PROG


def default_store_path(env: Mapping[str, str]) -> Path:
    """``$XDG_CONFIG_HOME/eufy-security/cache.json`` (``~/.config`` when unset)."""
    return _config_dir(env) / "cache.json"


def _add_global_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Options accepted before and after the subcommand.

    The subcommand copies default to SUPPRESS so they only override the
    top-level value when actually given.
    """

    def default(value: object) -> object:
        return argparse.SUPPRESS if suppress else value

    group = parser.add_argument_group("global options")
    group.add_argument(
        "--email", default=default(None), help=f"account e-mail (default: ${ENV_EMAIL})"
    )
    group.add_argument(
        "--store",
        type=Path,
        default=default(None),
        help="session cache file (default: $XDG_CONFIG_HOME/eufy-security/cache.json)",
    )
    group.add_argument(
        "--country",
        default=default(""),
        help="login country, ISO 3166 code such as DE (default: the host's IP country)",
    )
    group.add_argument(
        "--region",
        choices=REGIONS,
        default=default(None),
        help="use only this cloud region (default: every region that lists devices)",
    )
    group.add_argument(
        "--station",
        metavar="SN",
        default=default(None),
        help="station serial or name (default: the account's only station)",
    )
    group.add_argument(
        "--host",
        metavar="IP",
        default=default(None),
        help="station LAN address, skipping the broadcast (for routed or filtered networks)",
    )
    group.add_argument(
        "--local-port",
        metavar="N",
        type=int,
        default=default(0),
        help="pin the selected station's local UDP port so a firewall can admit its replies "
        "(default: ephemeral)",
    )
    group.add_argument(
        "--redact-serials",
        action="store_true",
        default=default(False),
        help="mask serial numbers in human output, e.g. before sharing it (full by default)",
    )
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=default(0),
        help="log INFO (-v) or DEBUG (-vv) to stderr",
    )
    group.add_argument(
        "--wire",
        action="store_true",
        default=default(False),
        help="also log hexdumps of every datagram and cloud request",
    )
    group.add_argument(
        "--secrets",
        action="store_true",
        default=default(False),
        help="log passwords, tokens, cipher and session keys in clear (with -vv); "
        "never share such a log",
    )


def _add_setting_target(sub: argparse.ArgumentParser) -> None:
    """``--device SN | --channel N``: the device a setting belongs to (none: the station)."""
    target = sub.add_mutually_exclusive_group()
    target.add_argument("--device", metavar="SN", help="paired device serial to address")
    target.add_argument(
        "--channel",
        metavar="N",
        type=int,
        help="station channel to address (255 or none: the station itself)",
    )


def build_parser() -> argparse.ArgumentParser:
    """The full ``eufy-security`` argument parser.

    The password is deliberately not an option: it comes from ``$EUFY_PASSWORD``
    or a prompt, never from the command line (shell history, ``ps``).
    """
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="eufy Security from the command line: local P2P to the HomeBase, "
        "the eufy cloud, and push events.",
        epilog=f"The password is read from ${ENV_PASSWORD} or prompted for.",
    )
    _add_global_options(parser, suppress=False)
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text, description=help_text)
        _add_global_options(sub, suppress=True)
        return sub

    discover = command("discover", "list stations answering a LAN broadcast (no login)")
    discover.add_argument(
        "--broadcast", default=BROADCAST, help=f"address to search (default {BROADCAST})"
    )
    discover.add_argument(
        "--port",
        type=int,
        default=DISCOVERY_PORT,
        help=f"UDP port to search (default {DISCOVERY_PORT})",
    )
    discover.add_argument(
        "--timeout",
        type=float,
        default=LAN_DISCOVERY_TIMEOUT,
        help=f"seconds to listen (default {LAN_DISCOVERY_TIMEOUT:g})",
    )

    command("login", "log in (answering an e-mailed code or captcha) and cache the session")
    devices = command("devices", "list the account's devices and their catalog support")
    devices.add_argument(
        "--rescan-regions",
        action="store_true",
        help="also ask the cloud regions that listed no devices last time",
    )
    command("network", "each station's LAN path and what a firewall must allow")

    status = command("status", "station snapshot: guard mode, firmware, sub-devices")
    shape = status.add_mutually_exclusive_group()
    shape.add_argument("--json", action="store_true", help="machine-readable output")
    shape.add_argument("--raw", action="store_true", help="every parameter, with names, per device")

    command("coverage", "where the model settings and the station's dump disagree")

    storage = command("storage", "disk and eMMC use, temperature and health (read-only)")
    storage.add_argument("--json", action="store_true", help="machine-readable output")

    guard = command("guard", "read or set the guard mode")
    guard.add_argument("action", nargs="?", choices=("get", "set"), default="get")
    guard.add_argument(
        "mode",
        nargs="?",
        help="for set: away, home, schedule, custom_1..3, geofence, disarmed, or a numeric code",
    )

    settings = command("settings", "list a model's settings, or the per-mode settings (no login)")
    settings.add_argument(
        "--model",
        metavar="PN",
        help="list the settings of product code PN, e.g. T8160, from its bundled file",
    )

    read = command("get", "read a setting of the station or of one of its devices")
    read.add_argument("key", help="setting key of the addressed device's model")
    _add_setting_target(read)

    setting = command("set", "write a setting of the station or of one of its devices")
    setting.add_argument("key", help="setting key of the addressed device's model")
    setting.add_argument("value", help="the setting's value (a number, true/false or text)")
    _add_setting_target(setting)

    events = command("events", "the station's own event records")
    events.add_argument("--days", type=int, default=7, help="how far back (default 7)")
    events.add_argument(
        "--table", default="history_record_info", help="event table (default history_record_info)"
    )
    events.add_argument("--count", type=int, default=100, help="max records (default 100)")
    events.add_argument(
        "--device",
        metavar="SN",
        action="append",
        dest="devices",
        help="only this device (repeatable; default: every paired device)",
    )
    events.add_argument(
        "--media-only", action="store_true", help="only records with a file to fetch"
    )
    events.add_argument("--json", action="store_true", help="print the raw records")

    history = command(
        "history", "the station's full history list (all devices; the app's own query)"
    )
    history.add_argument("--days", type=int, default=7, help="how far back (default 7)")
    history.add_argument("--count", type=int, default=100, help="max records (default 100)")
    history.add_argument(
        "--media-only", action="store_true", help="only records with a file to fetch"
    )
    history.add_argument("--json", action="store_true", help="print the raw records")

    persons = command(
        "persons", "the AI face/person library (recognised people and their pictures)"
    )
    persons.add_argument(
        "--kind",
        choices=("people", "faces", "bodies"),
        default="people",
        help="people (default), their face pictures, or body/re-ID pictures",
    )
    persons.add_argument("--count", type=int, default=200, help="max entries (default 200)")
    persons.add_argument("--json", action="store_true", help="print the raw rows")

    image = command("image", "download a still off the station by its path")
    image.add_argument("path", help="an event's thumb_path or crop_path")
    image.add_argument("--out", required=True, type=Path, help="file to write")

    def media_target(sub: argparse.ArgumentParser) -> None:
        target = sub.add_mutually_exclusive_group(required=True)
        target.add_argument("--device", metavar="SN", help="camera serial")
        target.add_argument("--channel", metavar="N", type=int, help="camera station channel")

    live = command("live", "record a camera's live video and audio (wakes a battery camera)")
    media_target(live)
    live.add_argument(
        "--seconds", type=float, default=10.0, help="seconds after the first frame (default 10)"
    )
    live.add_argument(
        "--preset",
        metavar="N",
        type=int,
        help="turn a pan/tilt camera to stored slot N first (needs --device)",
    )
    live.add_argument(
        "--out", required=True, type=Path, help="output prefix: writes PREFIX.hevc and PREFIX.aac"
    )

    recording = command("recording", "save a stored recording off the station's disk")
    recording.add_argument("path", help="the recording's .zxvideo path (from an event)")
    media_target(recording)
    recording.add_argument(
        "--download", action="store_true", help="use the download command (1024), not playback"
    )
    recording.add_argument(
        "--out", required=True, type=Path, help="output prefix: writes PREFIX.hevc and PREFIX.aac"
    )

    snapshot = command("snapshot", "one full-resolution keyframe as HEVC (live, or a recording's)")
    media_target(snapshot)
    snapshot.add_argument(
        "--recording", metavar="PATH", help="take the recording's first keyframe (no camera wake)"
    )
    snapshot.add_argument("--out", required=True, type=Path, help="file to write (.hevc)")

    monitor = command("monitor", "print events as they arrive, until Ctrl+C")
    monitor.add_argument("--no-push", action="store_true", help="skip cloud push (FCM)")
    monitor.add_argument("--no-p2p", action="store_true", help="skip local station sessions")
    monitor.add_argument("--json", action="store_true", help="one JSON object per line")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse ``argv`` and apply cross-option rules (argparse exits 2 on violations)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "guard":
        if args.action == "set" and not args.mode:
            parser.error("guard set needs a MODE")
        if args.action == "get" and args.mode:
            parser.error("guard get takes no MODE")
    if args.command == "monitor" and args.no_push and args.no_p2p:
        parser.error("--no-push and --no-p2p together leave nothing to monitor")
    if not 0 <= args.local_port <= MAX_PORT:
        parser.error(f"--local-port must be 0-{MAX_PORT}")
    if getattr(args, "days", None) is not None and not 1 <= args.days <= MAX_DAYS:
        parser.error(f"--days must be 1-{MAX_DAYS}")
    for option in ("count", "seconds", "timeout"):
        value = getattr(args, option, None)
        if value is not None and value <= 0:
            parser.error(f"--{option} must be greater than 0")
    return args
