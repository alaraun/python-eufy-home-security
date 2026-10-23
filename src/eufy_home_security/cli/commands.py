"""Subcommands: build the account, call the library, render."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import getpass
import json
import secrets
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

from .._logging import redact_serial
from ..devices import model_settings
from ..devices.settings import Scope, scope_for_kind
from ..devices.types import MODELS, DeviceKind
from ..events import Event
from ..exceptions import (
    CloudCertificateError,
    EufySecurityError,
    LoginChallengeError,
    StationUnreachableError,
    UnsupportedError,
)
from ..models import STATION_CHANNEL, GuardMode
from ..p2p.discovery import discover_stations
from ..storage import JsonFileStore, async_cached_account
from . import render
from .config import (
    ENV_EMAIL,
    ENV_PASSWORD,
    EXIT_ERROR,
    PROG,
    UsageError,
    default_store_path,
)

if TYPE_CHECKING:
    import aiohttp

    from ..client import EufySecurity
    from ..cloud.models import CloudDevice
    from ..devices.model_settings import Setting, Value
    from ..p2p.session import MediaStream
    from ..rtc.diagnostics import StationRecord
    from ..station import Station

LOGIN_CHALLENGE_ROUNDS = 3
MAX_DEVICE_CHANNEL = 50
"""Highest sub-device channel a station addresses; the station itself is ``STATION_CHANNEL``."""

type Prompt = Callable[[str], str]


@dataclass(slots=True)
class Context:
    """What a command runs with: parsed arguments, environment, prompts, HTTP session.

    The HTTP session (and aiohttp itself, the CLI's slowest import) is created on
    first use, so commands that never touch the cloud do not pay for it.
    """

    args: argparse.Namespace
    env: Mapping[str, str]
    prompt: Prompt = input
    secret_prompt: Prompt = field(default=getpass.getpass)
    http: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.http is not None:
            await self.http.close()
            self.http = None

    def http_session(self) -> aiohttp.ClientSession:
        """The shared HTTP session, opened on first call."""
        if self.http is None:
            import aiohttp  # noqa: PLC0415 - see the class docstring

            self.http = aiohttp.ClientSession()
        return self.http

    @property
    def show_serials(self) -> bool:
        return not self.args.redact_serials

    @property
    def store_path(self) -> Path:
        store: Path | None = self.args.store
        return store.expanduser() if store is not None else default_store_path(self.env)

    async def ask(self, question: str, *, secret: bool = False) -> str:
        """Prompt for an answer; a secret is returned verbatim (spaces can be part of it)."""
        answer = await asyncio.to_thread(self.secret_prompt if secret else self.prompt, question)
        if not answer.strip():
            raise UsageError("no answer given")
        return answer if secret else answer.strip()


# ── account and station ──────────────────────────────────────────────────────


async def open_account(ctx: Context, *, station_sn: str | None = None) -> EufySecurity:
    """An :class:`EufySecurity` for the configured account (not yet logged in).

    The e-mail comes from ``--email``, ``$EUFY_EMAIL`` or the session cache; the
    password from ``$EUFY_PASSWORD`` or a prompt that is only shown if a login
    actually happens (a cached session needs none). ``--host`` applies to
    ``station_sn`` only (see :func:`_pinned_station_serial`). An option the library
    refuses (a malformed e-mail, country code or local port) raises
    :class:`UsageError`.
    """
    from ..client import EufySecurity  # noqa: PLC0415 - aiohttp and the cloud, see Context

    store = JsonFileStore(ctx.store_path)
    email = ctx.args.email or ctx.env.get(ENV_EMAIL) or await async_cached_account(store)
    if not email:
        raise UsageError(
            f"no account e-mail: pass --email or set ${ENV_EMAIL} (remembered after a login)"
        )

    async def prompt_password() -> str:
        return await ctx.ask(f"eufy password for {email}: ", secret=True)

    hosts = {station_sn: ctx.args.host} if station_sn and ctx.args.host else None
    ports = {station_sn: ctx.args.local_port} if station_sn and ctx.args.local_port else None
    try:
        return EufySecurity(
            ctx.http_session,
            email,
            ctx.env.get(ENV_PASSWORD) or prompt_password,
            store=store,
            country=[c.strip() for c in ctx.args.country.split(",") if c.strip()],
            region=ctx.args.region,
            station_hosts=hosts,
            local_ports=ports,
        )
    except ValueError as err:
        raise UsageError(str(err)) from err


def select_station(stations: Sequence[Station], wanted: str | None, *, show: bool) -> Station:
    """The station named by ``--station`` (serial or name), or the only one."""
    if not stations:
        raise UsageError("the account has no station")
    if wanted:
        key = wanted.strip().lower()
        for station in stations:
            if key in {station.serial.lower(), station.name.lower()}:
                return station
    elif len(stations) == 1:
        return stations[0]
    choices = ", ".join(f'"{s.name}" {render.fmt_serial(s.serial, show)}' for s in stations)
    problem = f"no station matches {wanted!r}" if wanted else "several stations on this account"
    raise UsageError(f"{problem}; pass --station SERIAL or NAME. Choices: {choices}")


async def _login_and_pick(ctx: Context, eufy: EufySecurity) -> Station:
    await eufy.async_login()
    return await _select_refreshing(ctx, eufy)


async def _select_refreshing(
    ctx: Context, eufy: EufySecurity, wanted: str | None = None
) -> Station:
    """Pick the station from the cached device list, refreshing once on a named miss.

    A wanted serial or name that is not in the cached list is refetched from the
    cloud before giving up, so a station added since the last fetch is found; an
    ambiguous or empty match is not (a refresh would not disambiguate it).
    """
    wanted = wanted if wanted is not None else ctx.args.station
    try:
        return select_station(await eufy.async_discover(), wanted, show=ctx.show_serials)
    except UsageError:
        if not wanted:
            raise
        stations = await eufy.async_discover(refresh=True)
        return select_station(stations, wanted, show=ctx.show_serials)


async def _pinned_station_serial(ctx: Context) -> str | None:
    """With ``--host`` or ``--local-port``, the serial of the station they apply to.

    Both are keyed by serial in the library, so ``--station`` (a serial or a name) or
    the account's only station is resolved on a probe account first.
    """
    if not (ctx.args.host or ctx.args.local_port):
        return None
    async with await open_account(ctx) as probe:
        return (await _login_and_pick(ctx, probe)).serial


async def _with_station[T](ctx: Context, action: Callable[[Station], Awaitable[T]]) -> T:
    """Log in, pick the station, run ``action`` against it, close everything."""
    serial = await _pinned_station_serial(ctx)
    async with await open_account(ctx, station_sn=serial) as eufy:
        await eufy.async_login()
        station = await _select_refreshing(ctx, eufy, serial or ctx.args.station)
        return await action(station)


# ── commands ─────────────────────────────────────────────────────────────────


async def cmd_discover(ctx: Context) -> int:
    found = await discover_stations(
        timeout=ctx.args.timeout,
        port=ctx.args.port,
        target=ctx.args.broadcast,
        local_port=ctx.args.local_port,
    )
    print(render.render_discovered(found))
    return 0


async def cmd_settings(ctx: Context) -> int:
    """The per-mode settings; with ``--model PN`` PN's settings from its bundled file.

    Offline: no login, no HTTP session, no station.
    """
    if ctx.args.model is None:
        print(
            render.render_mode_table_settings(
                model_settings.mode_table_settings(Scope.CAMERA),
                model_settings.mode_table_settings(Scope.SENSOR),
            )
        )
        return 0
    typed: str = ctx.args.model.strip()
    code = model_settings.canonical_code(typed)
    if code is None:
        print(render.render_model_settings(typed, ()))
        return 0
    # The first lookup of a code reads its bundled file (package data): off the loop.
    settings = await asyncio.to_thread(model_settings.settings_of, code)
    model = MODELS.get(code)
    kind = model.kind if model is not None else None
    mode_table = (
        model_settings.mode_table_settings(scope_for_kind(kind))
        if settings and kind is not DeviceKind.STATION
        else ()
    )
    print(render.render_model_settings(code, [settings[k] for k in sorted(settings)], mode_table))
    return 0


async def cmd_login(ctx: Context) -> int:
    async with await open_account(ctx) as eufy:
        # Running `login` is the user's decision to take the session back.
        if not eufy.cache.loaded:
            await eufy.cache.async_load()
        await _login_answering_challenges(ctx, eufy, force=eufy.session_replaced)
        await eufy.async_discover()
        # Setup time is when the user can still fix the network: say what it needs.
        paths = await eufy.async_probe_lan()
    print(f"Logged in; session cached in {ctx.store_path}")
    if paths:
        print()
        print(render.render_network(paths, show_serials=ctx.show_serials))
    return 0


async def _login_answering_challenges(ctx: Context, eufy: EufySecurity, *, force: bool) -> None:
    """Log in, prompting for each 2FA code or captcha the cloud asks for."""
    answer: dict[str, str] = {}
    for attempt in range(1, LOGIN_CHALLENGE_ROUNDS + 1):
        try:
            await eufy.async_login(**answer, force=force)
            return
        except LoginChallengeError as challenge:
            if attempt == LOGIN_CHALLENGE_ROUNDS:
                # no attempt left to use an answer: do not ask for one
                raise UsageError(
                    f"gave up after {LOGIN_CHALLENGE_ROUNDS} login challenges"
                ) from None
            answer = await _answer_challenge(ctx, challenge)


async def _answer_challenge(ctx: Context, challenge: LoginChallengeError) -> dict[str, str]:
    if challenge.kind == "verify_code":
        code = await ctx.ask("eufy e-mailed a verification code; enter it: ")
        return {"verify_code": code, "login_id": challenge.login_id}
    if challenge.kind == "captcha":
        path = await asyncio.to_thread(_write_captcha, challenge.captcha_image)
        print(f"Captcha image written to {path}")
        return {
            "captcha_id": challenge.captcha_id,
            "captcha_answer": await ctx.ask("Characters shown in the captcha: "),
            "login_id": challenge.login_id,
        }
    raise challenge


def _write_captcha(data_uri: str) -> Path:
    data, suffix = render.decode_data_uri(data_uri)
    with tempfile.NamedTemporaryFile(prefix="eufy-captcha-", suffix=suffix, delete=False) as fh:
        fh.write(data)
    return Path(fh.name)


async def cmd_network(ctx: Context) -> int:
    serial = await _pinned_station_serial(ctx)
    async with await open_account(ctx, station_sn=serial) as eufy:
        await eufy.async_login()
        await eufy.async_discover()
        paths = await eufy.async_probe_lan()
    print(render.render_network(paths, show_serials=ctx.show_serials))
    return 0


async def cmd_devices(ctx: Context) -> int:
    async with await open_account(ctx) as eufy:
        await eufy.async_login()
        devices = await eufy.cloud.async_get_devices(
            refresh=True, rescan_regions=ctx.args.rescan_regions
        )
    print(render.render_devices(devices, show_serials=ctx.show_serials))
    return 0


async def cmd_status(ctx: Context) -> int:
    serial = await _pinned_station_serial(ctx)
    async with await open_account(ctx, station_sn=serial) as eufy:
        await eufy.async_login()
        station = await _select_refreshing(ctx, eufy, serial or ctx.args.station)
        state = await station.async_update(wake=True)  # an explicit read wakes it
        name = station.name
        if ctx.args.received:
            dump = await station.session.async_get_params(expect_channels=station.channels)
            print(json.dumps(dump.received, indent=2))
        elif ctx.args.json:
            print(json.dumps(render.status_json(state, name=name), indent=2))
        elif ctx.args.raw:
            print(render.render_raw_params(state))
        else:
            codes = {
                model_settings.product_code_of(d.raw.get("device_new_pn"), d.device_sn)
                for d in (station.device, *station.sub_devices)
            }
            models = {m.product_code: m for m in eufy.model_status() if m.product_code in codes}
            host = station.session.host
            print(
                render.render_status(
                    state, name=name, host=host, show_serials=ctx.show_serials, models=models
                )
            )
        return 0


async def cmd_coverage(ctx: Context) -> int:
    async def action(station: Station) -> int:
        state = await station.async_update(wake=True)  # an explicit read wakes it
        print(render.render_coverage(state, show_serials=ctx.show_serials))
        return 0

    return await _with_station(ctx, action)


async def cmd_storage(ctx: Context) -> int:
    async def action(station: Station) -> int:
        storage = await station.async_get_storage()
        if ctx.args.json:
            print(json.dumps(render.storage_json(storage, show_serials=ctx.show_serials), indent=2))
        else:
            print(render.render_storage(storage, name=station.name))
        return 0

    return await _with_station(ctx, action)


async def cmd_guard(ctx: Context) -> int:
    mode: GuardMode | None = None
    if ctx.args.action == "set":
        try:
            mode = GuardMode.parse(ctx.args.mode)
        except ValueError as err:
            raise UsageError(str(err)) from None

    async def action(station: Station) -> int:
        if mode is None:
            state = await station.async_update(wake=True)  # an explicit read wakes it
            print(f"Guard mode: {render.guard_mode_label(state.guard_mode)}")
            return 0
        applied = await station.async_set_guard_mode(mode)
        if applied != mode:
            print(
                f"eufy-security: asked for {render.guard_mode_label(mode)}, the station "
                f"reports {render.guard_mode_label(applied)}",
                file=sys.stderr,
            )
            return EXIT_ERROR
        print(f"Guard mode set: {render.guard_mode_label(applied)}")
        return 0

    return await _with_station(ctx, action)


async def cmd_get(ctx: Context) -> int:
    """Read a setting of the station (no target, or ``--channel 255``) or of a device
    from one fresh parameter dump: ``KEY = VALUE (LABEL) UNIT``, ``unknown`` when the
    dump does not report it."""
    key: str = ctx.args.key
    _check_channel(ctx.args.channel)

    async def action(station: Station) -> int:
        try:
            setting = station.setting(key, device_sn=ctx.args.device, channel=ctx.args.channel)
        except (UnsupportedError, ValueError) as err:
            raise UsageError(f"{err}; `{PROG} settings --model PN` lists a model's keys") from None
        state = await station.async_update(wake=True)  # an explicit read wakes it
        value = state.setting(key, device_sn=ctx.args.device, channel=ctx.args.channel)
        print(f"{key} = {render.render_setting_value(setting, value)}")
        return 0

    return await _with_station(ctx, action)


async def cmd_set(ctx: Context) -> int:
    """Write a setting of the station (no target, or ``--channel 255``) or of a device.

    The key is resolved on the addressed device's model after discovery and the value
    validated against it before anything is sent; the outcome is the station's answer.
    """
    key: str = ctx.args.key
    raw: str = ctx.args.value
    _check_channel(ctx.args.channel)

    async def action(station: Station) -> int:
        try:
            setting = station.setting(key, device_sn=ctx.args.device, channel=ctx.args.channel)
            if not setting.writable:
                raise UnsupportedError(f"{key} is not writable: {setting.note or 'read-only'}")
            value = _validated(setting, raw)
        except (UnsupportedError, ValueError) as err:
            raise UsageError(str(err)) from None
        outcome = await station.async_set_setting(
            key, value, device_sn=ctx.args.device, channel=ctx.args.channel
        )
        target = (
            render.fmt_serial(ctx.args.device, ctx.show_serials)
            if ctx.args.device
            else f"channel {ctx.args.channel}"
            if ctx.args.channel is not None
            else "the station"
        )
        shown = setting.label(value) or value
        print(f"{key} = {shown} on {target}: {outcome.value}")
        return 0

    return await _with_station(ctx, action)


def _validated(setting: Setting, raw: str) -> Value:
    """``raw`` as ``setting``'s value: read as a number first when it looks like one
    (a string setting then takes the text as is); the number's error when neither fits."""
    if not _looks_numeric(raw):
        return setting.validate(raw)
    try:
        return setting.validate(int(raw, 0))
    except ValueError:
        with contextlib.suppress(ValueError):
            return setting.validate(raw)
        raise


def _check_channel(channel: int | None) -> None:
    """Refuse, before any login, a channel no station addresses."""
    if channel is not None and not (
        0 <= channel <= MAX_DEVICE_CHANNEL or channel == STATION_CHANNEL
    ):
        raise UsageError(
            f"--channel must be 0-{MAX_DEVICE_CHANNEL} or {STATION_CHANNEL} (the station), "
            f"got {channel}"
        )


def _looks_numeric(text: str) -> bool:
    try:
        int(text, 0)
    except ValueError:
        return False
    return True


def date_window(days: int, today: date) -> tuple[str, str]:
    """``(start, end)`` as ``YYYYMMDD`` covering the last ``days`` days up to ``today``."""
    return (today - timedelta(days=days)).strftime("%Y%m%d"), today.strftime("%Y%m%d")


async def cmd_events(ctx: Context) -> int:
    start, end = date_window(ctx.args.days, datetime.now().astimezone().date())

    async def action(station: Station) -> int:
        rows = await station.async_query_events(
            start,
            end,
            device_sns=ctx.args.devices,
            count=ctx.args.count,
            table=ctx.args.table,
        )
        if ctx.args.media_only:
            rows = [row for row in rows if render.has_media(row)]
        if ctx.args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print(render.render_events(rows, start, end, show_serials=ctx.show_serials))
        return 0

    return await _with_station(ctx, action)


async def cmd_history(ctx: Context) -> int:
    start, end = date_window(ctx.args.days, datetime.now().astimezone().date())

    async def action(station: Station) -> int:
        records = await station.async_list_history(start, end, count=ctx.args.count)
        rows = [dict(record.raw) for record in records]
        if ctx.args.media_only:
            rows = [row for row in rows if render.has_media(row)]
        if ctx.args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print(render.render_events(rows, start, end, show_serials=ctx.show_serials))
        return 0

    return await _with_station(ctx, action)


_PERSON_TABLES = {
    "people": ("person_basic_info", "recognised people"),
    "faces": ("face_feature_info", "face pictures"),
    "bodies": ("reid_feature_info", "body (re-ID) pictures"),
}


async def cmd_persons(ctx: Context) -> int:
    table, title = _PERSON_TABLES[ctx.args.kind]
    # The person library has no date: ask for a wide range so the query misses nothing.
    start, end = date_window(3650, datetime.now().astimezone().date())

    async def action(station: Station) -> int:
        rows = await station.async_query_events(start, end, table=table, count=ctx.args.count)
        if ctx.args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print(render.render_entities(rows, title))
        return 0

    return await _with_station(ctx, action)


async def cmd_image(ctx: Context) -> int:
    out: Path = ctx.args.out

    async def action(station: Station) -> int:
        blob = await station.async_fetch_image(ctx.args.path)
        await asyncio.to_thread(out.write_bytes, blob)
        print(f"Wrote {len(blob)} bytes to {out} [{render.describe_image(blob)}]")
        return 0

    return await _with_station(ctx, action)


MEDIA_FLUSH_BYTES = 1 << 20


def _media_target(ctx: Context) -> dict[str, Any]:
    if ctx.args.device is not None:
        return {"device_sn": ctx.args.device}
    return {"channel": ctx.args.channel}


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as fh:
        fh.write(data)


async def _save_stream(stream: MediaStream, prefix: Path, *, seconds: float | None) -> None:
    """Write a stream to ``PREFIX.hevc`` or ``PREFIX.h264`` (by the codec of its first video
    frame) and ``PREFIX.aac``; ``seconds`` counts from the first frame.

    Frames are flushed as they arrive, so memory stays flat and a stream that fails
    part-way still leaves what came before the failure on disk.
    """
    from ..p2p.media import MediaKind, VideoCodec  # noqa: PLC0415 (keeps the CLI light)

    paths = {"video": Path(f"{prefix}.{VideoCodec.HEVC}"), "audio": Path(f"{prefix}.aac")}
    pending = {kind: bytearray() for kind in paths}
    frames = dict.fromkeys(paths, 0)
    size = dict.fromkeys(paths, 0)
    keyframes = 0
    deadline: float | None = None
    for path in paths.values():
        await asyncio.to_thread(path.write_bytes, b"")

    async def flush(kind: str) -> None:
        if pending[kind]:
            await asyncio.to_thread(_append, paths[kind], bytes(pending[kind]))
            pending[kind].clear()

    try:
        async with stream:
            async for frame in stream:
                if deadline is None and seconds is not None:
                    deadline = time.monotonic() + seconds
                if frame.kind is MediaKind.VIDEO and not frames["video"] and frame.codec:
                    await asyncio.to_thread(paths["video"].unlink)
                    paths["video"] = Path(f"{prefix}.{frame.codec}")
                    await asyncio.to_thread(paths["video"].write_bytes, b"")
                pending[frame.kind] += frame.data
                frames[frame.kind] += 1
                size[frame.kind] += len(frame.data)
                keyframes += frame.is_keyframe
                if len(pending[frame.kind]) >= MEDIA_FLUSH_BYTES:
                    await flush(frame.kind)
                if deadline is not None and time.monotonic() >= deadline:
                    break
            else:
                if seconds is not None:
                    print("The stream went quiet before --seconds elapsed", file=sys.stderr)
    finally:
        for kind in paths:
            await flush(kind)
    print(
        f"Wrote {frames['video']} video frames ({keyframes} keyframes, {size['video']} bytes) "
        f"to {paths['video']} and {frames['audio']} audio frames to {paths['audio']}"
    )
    if stream.dropped:
        print(f"Dropped {stream.dropped} frames: the writer fell behind", file=sys.stderr)
    if stream.skipped:
        print(
            f"Skipped {stream.skipped} video frames waiting for a keyframe after one that "
            "did not decode",
            file=sys.stderr,
        )


async def cmd_live(ctx: Context) -> int:
    async def action(station: Station) -> int:
        stream = await station.async_open_live(**_media_target(ctx), preset=ctx.args.preset)
        await _save_stream(stream, ctx.args.out, seconds=ctx.args.seconds)
        return 0

    return await _with_station(ctx, action)


async def cmd_recording(ctx: Context) -> int:
    async def action(station: Station) -> int:
        stream = await station.async_open_recording(
            ctx.args.path, **_media_target(ctx), download=ctx.args.download
        )
        await _save_stream(stream, ctx.args.out, seconds=None)
        return 0

    return await _with_station(ctx, action)


async def cmd_snapshot(ctx: Context) -> int:
    out: Path = ctx.args.out

    async def action(station: Station) -> int:
        blob = await station.async_snapshot(**_media_target(ctx), recording=ctx.args.recording)
        await asyncio.to_thread(out.write_bytes, blob)
        from ..p2p.media import VideoCodec, picture_codec  # noqa: PLC0415 (keeps the CLI light)

        codec = picture_codec(blob) or VideoCodec.HEVC
        print(
            f"Wrote a {len(blob)}-byte {codec.name} keyframe to {out} "
            f"(to a JPEG: ffmpeg -f {codec} -i {out} -frames:v 1 still.jpg)"
        )
        return 0

    return await _with_station(ctx, action)


async def cmd_monitor(ctx: Context) -> int:
    host_serial = await _pinned_station_serial(ctx)
    async with await open_account(ctx, station_sn=host_serial) as eufy:
        await eufy.async_login()
        stations = await eufy.async_discover()
        wanted = host_serial or (
            select_station(stations, ctx.args.station, show=ctx.show_serials).serial
            if ctx.args.station
            else None
        )

        def on_event(event: Event) -> None:
            sn = getattr(event, "station_sn", None)
            if wanted and sn and sn != wanted:
                return
            if ctx.args.json:
                print(json.dumps(render.event_json(event), default=str), flush=True)
            else:
                line = render.render_event(
                    event, now=datetime.now().astimezone(), show_serials=ctx.show_serials
                )
                print(line, flush=True)

        unsubscribe = eufy.subscribe(on_event)
        try:
            await eufy.async_start(p2p=not ctx.args.no_p2p, push=not ctx.args.no_push)
            print(
                f"Monitoring {len(stations)} station(s) "
                f"({', '.join(render.fmt_serial(s.serial, ctx.show_serials) for s in stations) or 'none'}); "
                "Ctrl+C to stop. An idle home is quiet.",
                file=sys.stderr,
                flush=True,
            )
            await asyncio.Event().wait()
        finally:
            unsubscribe()
    return 0  # pragma: no cover - only Ctrl+C ends the wait


_DIAGNOSE_EXPLAIN = """\
eufy-security diagnose — a diagnostics report of the whole account

What it does (read-only by default: nothing is armed, disarmed, changed or triggered):
  1. Log in to your account on THIS machine (asks for a 2FA code if eufy sends one;
     credentials never leave the machine and are never written to the report).
  2. Account: every device each eufy list names (model, firmware, which station it is
     paired to, battery or mains, online flag), the account's cipher state and
     region/session status.
  3. Each station served over local P2P (HomeBases, standalone cameras): connect,
     read its state and storage once, and record its session counters.
  4. Over WebRTC, the way the eufy app reaches them:
       - each station the eufy app reaches only over WebRTC (e.g. T9000, T8N00);
       - each station with a paired camera the eufy app streams over WebRTC, decided
         as the app decides it from the models and firmware (e.g. a Video Doorbell C30
         behind a HomeBase 3 on some firmware). Its P2P read of step 3 still runs; the
         live view below opens on that camera (the lowest channel if there are
         several).
     For each: place the data-channel call (with the time each step took and whether
     the connection is direct or relayed), check its keep-alive, send two read-only
     queries (storage, paired devices), and open a live view of one camera
     (--camera-channel picks another) for a few seconds to describe its video and
     audio streams (codec, resolution, frame rate, packet counts; never the picture
     or sound). --webrtc-all adds every other station; --no-webrtc skips this step.
  5. With --watch N: for N seconds, what the stations and the eufy cloud push send
     while you switch the guard mode in the eufy app (--no-push leaves the cloud push
     out). The window opens inside a WebRTC probe that gets that far, else on its own
     after the steps above, whatever failed before it.
  It wakes sleeping stations and battery cameras to reach them. Every step has a time
  limit, and the report is written even when a step fails or you press Ctrl+C.

Opt-in, a write (off unless you pass it):
  --rewrite-guard-mode  re-sends each WebRTC-probed station's CURRENT guard mode (as the
     eufy cloud reports it: Away, Home or Disarmed only) unchanged, once, after asking
     you to confirm the mode it read, to record how the station acknowledges a mode
     command. The station may log it or announce the mode as if it had been set.

What the report contains — and never:
  Collected: model codes, firmware/SDK versions, channels, serials shortened to the
  model and last four characters, which cloud fields are present, session and error
  counters, timings, protocol-header bytes, reply and push JSON key NAMES and a few
  status/mode integers, stream descriptors (codec, profile, resolution) and packet and
  frame counts.
  Never: your password/tokens, account id/email, full serial numbers, device names,
  IP addresses, encryption keys, or any audio/video content. The report is a JSON file
  for you to review before sharing; nothing is uploaded.
"""


def _library_version() -> str:
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    try:
        return version("eufy-home-security")
    except PackageNotFoundError:
        return "unknown"


#: How long the read of one P2P station may take before it is recorded as timed out.
DIAGNOSE_STATION_TIMEOUT = 90.0
#: How long the cloud push listener may take to start.
DIAGNOSE_PUSH_TIMEOUT = 45.0
#: Events from the library's bus (cloud push, P2P stations) kept in the report.
DIAGNOSE_MAX_EVENTS = 200


def nameless(view: Mapping[str, Any]) -> dict[str, Any]:
    """A redacted device view without its user-given ``name``."""
    return {k: v for k, v in view.items() if k != "name"}


def _unique_label(serial: str, taken: set[str]) -> str:
    """``serial`` redacted, numbered ``#2``, ``#3`` … where two would collide."""
    label, n = redact_serial(serial), 1
    while label in taken:
        n += 1
        label = f"{redact_serial(serial)}#{n}"
    taken.add(label)
    return label


@dataclass(slots=True)
class _Report:
    """The diagnose report being built, saved after every step and on any exit."""

    path: Path
    data: dict[str, Any]
    started: float = field(default_factory=time.monotonic)

    def ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    async def save(self) -> None:
        self.data["run_ms"] = self.ms()
        text = json.dumps(self.data, indent=2, sort_keys=True, default=str)
        await asyncio.to_thread(self.path.write_text, text)

    def error(self, step: str, exc: BaseException) -> None:
        self.data.setdefault("errors", {})[step] = type(exc).__name__


async def _diagnose_p2p(station: Station) -> dict[str, Any]:
    """Read ``station`` once (state, then storage unless it is reached on demand) and
    return its :meth:`~.station.Station.diagnostics` with the read's errors."""
    errors: dict[str, str] = {}
    try:
        async with asyncio.timeout(DIAGNOSE_STATION_TIMEOUT):
            await station.async_update(wake=True)
    except Exception as exc:  # any failure is recorded, never raised
        errors["state"] = type(exc).__name__
    if "state" not in errors and not station.connects_on_demand:
        try:
            async with asyncio.timeout(DIAGNOSE_STATION_TIMEOUT):
                await station.async_get_storage()
        except Exception as exc:  # any failure is recorded, never raised
            errors["storage"] = type(exc).__name__
    try:
        view = station.diagnostics()
    except Exception as exc:  # any failure is recorded, never raised
        return {"read_errors": {**errors, "diagnostics": type(exc).__name__}}
    return {**view, "read_errors": errors}


async def _confirm(ctx: Context, question: str) -> bool:
    """Whether the user answers ``yes``; no answer (or no terminal) is a no."""
    try:
        return (await ctx.ask(question)).lower() == "yes"
    except (UsageError, EOFError):
        return False


async def _guard_rewrite(
    ctx: Context, record: StationRecord
) -> tuple[GuardMode | None, str | None]:
    """The mode the opt-in re-send repeats for the station ``record``, and the note the
    report keeps (None when the option is off)."""
    from ..rtc import diagnostics as diag  # noqa: PLC0415

    if not ctx.args.rewrite_guard_mode:
        return None, None
    mode = diag.rewritable_guard_mode(record)
    if mode is None:
        return None, f"skipped: cloud guard mode {record.guard_mode} is not Away/Home/Disarmed"
    question = (
        f"The eufy cloud reports guard mode {mode.label} ({int(mode)}) for the {record.model}. "
        "Re-send it unchanged (a write to the station)? Type yes to send: "
    )
    if not await _confirm(ctx, question):
        return None, "declined"
    return mode, f"confirmed: {int(mode)}"


async def _diagnose_webrtc(
    ctx: Context, eufy: EufySecurity, devices: Sequence[CloudDevice], report: _Report
) -> None:
    """Probe over WebRTC the account's webrtc_only stations, every station with a paired
    camera the eufy app streams over WebRTC, and with ``--webrtc-all`` every other
    station (:func:`~..rtc.diagnostics.webrtc_probe_reason`), adding each station's
    report to ``report`` as soon as it is done (or interrupted)."""
    from ..rtc import diagnostics as diag  # noqa: PLC0415
    from ..rtc.config import RtcConfig, missing_inputs  # noqa: PLC0415
    from ..rtc.crypto import RtcSignalingCrypto  # noqa: PLC0415
    from ..rtc.session import RtcSession  # noqa: PLC0415

    sink: list[dict[str, Any]] = report.data["webrtc_stations"]
    user_id = eufy.cloud.user_id
    if not user_id:
        raise UsageError("logged in but the account has no user id")
    # A WebRTC station may lack the P2P fields `is_station` asks for: pick by parent.
    own_parent = [d for d in devices if d.station_sn in (None, d.device_sn)]
    targets: list[tuple[CloudDevice, str]] = []
    for d in own_parent:
        reason = diag.webrtc_probe_reason(d, devices, webrtc_all=ctx.args.webrtc_all)
        if reason is not None and (
            not ctx.args.station or ctx.args.station in (d.device_sn, d.name)
        ):
            targets.append((d, reason))
    app_id = secrets.token_hex(8)

    def on_watch(seconds: float) -> None:
        _open_watch_window(report, seconds)

    for device, reason in targets:
        record = diag.describe_station(device)
        children = await asyncio.to_thread(diag.describe_children, device.device_sn, devices)
        target = diag.live_target(device.device_sn, devices, ctx.args.camera_channel)
        camera = None
        if target is not None:
            camera = next(
                (c for c in children if c.channel == target.channel),
                diag.ChildRecord("?", target.channel, None, has_signaling=False),
            )
        extra = {
            "probe_reason": reason,
            "live_camera": None
            if target is None or ctx.args.no_live
            else dataclasses.asdict(target),
        }
        try:
            config = RtcConfig.from_device(device.raw, user_id=user_id, app_id=app_id)
        except Exception:  # any failure is recorded, never raised
            config = None
        if config is None:
            lacking = ", ".join(missing_inputs(device.raw)) or "a usable entry"
            entry = diag.StationReport(
                station=record,
                children=children,
                channel=ctx.args.channel,
                phase_reached="config",
                error=f"config: the station's cloud record has no {lacking}",
            )
            sink.append({**dataclasses.asdict(entry), **extra})
            print("\n".join(diag.render_station(entry)))
            continue
        rewrite, note = await _guard_rewrite(ctx, record)
        why = reason
        if camera is not None and not ctx.args.no_live:
            why += f", live view: {camera.model} on channel {camera.channel}"
        print(f"Probing WebRTC station {record.model} ({why}) ...", flush=True)
        session = RtcSession(config, RtcSignalingCrypto())
        done: list[diag.StationReport] = []
        try:
            result = await diag.collect_station(
                session,
                station=record,
                children=children,
                account_id=device.owner_user_id or user_id,
                channel=ctx.args.channel,
                camera=camera,
                do_commands=not ctx.args.no_commands,
                do_live=not ctx.args.no_live,
                listen_s=ctx.args.listen,
                watch_s=ctx.args.watch,
                on_watch=on_watch,
                rewrite_guard_mode=rewrite,
                on_report=done.append,
            )
            if not done:
                done.append(result)
        finally:
            sink.extend(
                {**dataclasses.asdict(entry), **extra, "guard_rewrite": note} for entry in done
            )
            with contextlib.suppress(Exception):
                await session.close()
        for entry in done:
            print("\n".join(diag.render_station(entry)))
        await report.save()


def _open_watch_window(report: _Report, seconds: float) -> None:
    """Record that a watch window opens now and tell the user what to do in it."""
    report.data.setdefault("watch_windows_ms", []).append([report.ms(), int(seconds * 1000)])
    print(
        f"Recording notifications for {seconds:.0f} s: switch the guard mode in the eufy "
        "app now (for example Home, then back to what it was).",
        flush=True,
    )


async def _watch_account(report: _Report, seconds: float) -> None:
    """The watch window of a run in which no WebRTC probe opened one: the cloud push and
    the library's bus events are recorded for ``seconds``."""
    _open_watch_window(report, seconds)
    await asyncio.sleep(seconds)
    await report.save()


def _strings(obj: object) -> Iterator[str]:
    """Every string value in ``obj`` (nested mappings and lists)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for value in obj.values():
            yield from _strings(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _strings(value)


def diagnose_hints(data: Mapping[str, Any]) -> list[str]:
    """Plain-language notes on what in the report ``data`` points at the network the
    run was made on rather than at the stations."""
    hints: list[str] = []
    reads = {
        label: (block.get("model"), set(block.get("read_errors", {}).values()))
        for label, block in data.get("stations", {}).items()
        if isinstance(block, Mapping)
    }
    if any(CloudCertificateError.__name__ in text for text in _strings(data)):
        keys = any(CloudCertificateError.__name__ in errors for _, errors in reads.values())
        hints.append(
            "The eufy cloud's certificate was not trusted on this network: a firewall, proxy "
            "or security software inspects encrypted connections here."
            + (
                " The station keys could not be fetched, so stations could not be read."
                if keys
                else ""
            )
            + " Run it on a network (or computer) without that inspection."
        )
    hints.extend(
        f"No local reply from station {label} ({model}): run it on the same network as "
        "that station, with the station powered and online."
        for label, (model, errors) in reads.items()
        if StationUnreachableError.__name__ in errors
    )
    return hints


async def _start_push(eufy: EufySecurity, report: _Report) -> Callable[[], None]:
    """Record every bus event (cloud push, P2P stations) from now on and start the push
    listener; returns the unsubscribe."""
    from ..rtc import diagnostics as diag  # noqa: PLC0415

    events: list[Any] = report.data.setdefault("events", [])

    def on_event(event: Event) -> None:
        if len(events) < DIAGNOSE_MAX_EVENTS:
            events.append(dataclasses.asdict(diag.describe_event(event, report.ms())))

    unsubscribe = eufy.subscribe(on_event)
    try:
        async with asyncio.timeout(DIAGNOSE_PUSH_TIMEOUT):
            await eufy.async_start(p2p=False, push=True)
    except Exception as exc:  # any failure is recorded, never raised
        report.data["push"] = {"running": False, "error": type(exc).__name__}
        return unsubscribe
    error = eufy.push_error
    report.data["push"] = {
        "running": eufy.push_running,
        "error": type(error).__name__ if error is not None else None,
    }
    return unsubscribe


def _diagnose_options(args: argparse.Namespace) -> dict[str, Any]:
    """The run's options for the report (no account data)."""
    names = ("no_p2p", "no_webrtc", "webrtc_all", "channel", "camera_channel", "listen",
             "watch", "no_commands", "no_live", "no_push", "rewrite_guard_mode")  # fmt: skip
    return {name: getattr(args, name, None) for name in names}


async def cmd_diagnose(ctx: Context) -> int:
    """One report of the account: every device, the P2P stations' health, and the
    WebRTC probe of the stations the eufy app reaches over WebRTC. The report file is written after every step
    and on any exit; ``complete`` says whether the run got to its end."""
    from datetime import UTC  # noqa: PLC0415

    if ctx.args.explain:
        print(_DIAGNOSE_EXPLAIN)
        return 0
    webrtc = not ctx.args.no_webrtc
    if webrtc:
        try:
            import aioice  # noqa: F401, PLC0415 - the rtc extra
            import pylibsrtp  # noqa: F401, PLC0415
        except ImportError as exc:
            raise UsageError(
                "diagnose needs the rtc extra for WebRTC stations: "
                "pip install 'eufy-home-security[rtc]' (or pass --no-webrtc)"
            ) from exc

    out: Path = ctx.args.output or Path(f"eufy-diagnostics-{int(time.time())}.json")
    report = _Report(
        out,
        {
            "library_version": _library_version(),
            "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "options": _diagnose_options(ctx.args),
            "complete": False,
            "aborted": None,
            "stations": {},
            "webrtc_stations": [],
        },
    )
    p2p: dict[str, Any] = report.data["stations"]
    logged_in = False
    try:
        async with await open_account(ctx) as eufy:
            await _login_answering_challenges(ctx, eufy, force=False)
            logged_in = True
            try:
                stations = await eufy.async_discover(refresh=True)
                # The entries as fetched: the cache keeps fewer fields.
                devices = list(eufy.listed_devices.values())
            except EufySecurityError as exc:
                report.error("discover", exc)
                stations = []
                try:
                    devices = await eufy.cloud.async_get_devices()
                except EufySecurityError as exc:
                    report.error("devices", exc)
                    devices = []
            await report.save()
            if not ctx.args.no_p2p:
                taken: set[str] = set()
                for station in stations:
                    if ctx.args.station and ctx.args.station not in (station.serial, station.name):
                        continue
                    label = _unique_label(station.serial, taken)
                    print(f"Reading station {label} ...", flush=True)
                    p2p[label] = await _diagnose_p2p(station)
                    with contextlib.suppress(Exception):
                        await station.async_close()
                    await report.save()
            unsubscribe: Callable[[], None] | None = None
            if ctx.args.watch > 0 and not ctx.args.no_push:
                unsubscribe = await _start_push(eufy, report)
            try:
                if webrtc:
                    await _diagnose_webrtc(ctx, eufy, devices, report)
                if ctx.args.watch > 0 and not report.data.get("watch_windows_ms"):
                    await _watch_account(report, ctx.args.watch)
            finally:
                if unsubscribe is not None:
                    unsubscribe()
            report.data["skipped_devices"] = [dataclasses.asdict(d) for d in eufy.skipped_devices]
            report.data["stations_served_elsewhere"] = [
                nameless(d.as_redacted_dict()) for d in eufy.stations_served_elsewhere
            ]
            report.data["models"] = [
                {**dataclasses.asdict(status), "newer_vendor_data": status.newer_vendor_data}
                for status in eufy.model_status()
            ]
            report.data["cache"] = await eufy.async_cache_summary()
            try:
                report.data["account"] = (await eufy.async_account_report()).as_dict()
            except EufySecurityError as exc:
                report.data["account"] = {"error": type(exc).__name__}
            report.data["hints"] = diagnose_hints(report.data)
        report.data["complete"] = True
    except BaseException as exc:
        cancelled = isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt))
        report.data["aborted"] = "interrupted" if cancelled else type(exc).__name__
        if logged_in:
            with contextlib.suppress(Exception):
                await report.save()
            print(f"\nPartial report written to {out}", file=sys.stderr)
        raise
    await report.save()
    for label, block in p2p.items():
        session = block.get("session", {})
        print(
            f"station {label} ({block.get('model')}): connected={block.get('connected')} "
            f"last_error={block.get('last_error')} read_errors={block['read_errors']} "
            f"connects={session.get('connects')}"
        )
    for hint in report.data["hints"]:
        print(f"\nNote: {hint}")
    print(f"\nFull report written to {out}")
    print("Review it before sharing; nothing was uploaded.")
    return 0


COMMANDS: dict[str, Callable[[Context], Coroutine[Any, Any, int]]] = {
    "discover": cmd_discover,
    "login": cmd_login,
    "devices": cmd_devices,
    "network": cmd_network,
    "status": cmd_status,
    "coverage": cmd_coverage,
    "storage": cmd_storage,
    "guard": cmd_guard,
    "settings": cmd_settings,
    "get": cmd_get,
    "set": cmd_set,
    "events": cmd_events,
    "history": cmd_history,
    "persons": cmd_persons,
    "image": cmd_image,
    "live": cmd_live,
    "recording": cmd_recording,
    "snapshot": cmd_snapshot,
    "monitor": cmd_monitor,
    "diagnose": cmd_diagnose,
}
