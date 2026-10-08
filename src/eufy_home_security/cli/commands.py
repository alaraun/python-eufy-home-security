"""Subcommands: build the account, call the library, render."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

from ..devices import model_settings
from ..devices.settings import Scope, scope_for_kind
from ..devices.types import MODELS, DeviceKind
from ..events import Event
from ..exceptions import LoginChallengeError, UnsupportedError
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
    from ..devices.model_settings import Setting, Value
    from ..p2p.session import MediaStream
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
    ``station_sn`` only (see :func:`_pinned_station_serial`).
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
    return EufySecurity(
        ctx.http_session,
        email,
        ctx.env.get(ENV_PASSWORD) or prompt_password,
        store=store,
        country=[c for c in ctx.args.country.split(",") if c.strip()],
        region=ctx.args.region,
        station_hosts=hosts,
        local_ports=ports,
    )


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
        answer: dict[str, str] = {}
        # Running `login` is the user's decision to take the session back.
        if not eufy.cache.loaded:
            await eufy.cache.async_load()
        force = eufy.session_replaced
        for attempt in range(1, LOGIN_CHALLENGE_ROUNDS + 1):
            try:
                await eufy.async_login(**answer, force=force)
                break
            except LoginChallengeError as challenge:
                if attempt == LOGIN_CHALLENGE_ROUNDS:
                    # no attempt left to use an answer: do not ask for one
                    raise UsageError(
                        f"gave up after {LOGIN_CHALLENGE_ROUNDS} login challenges"
                    ) from None
                answer = await _answer_challenge(ctx, challenge)
        await eufy.async_discover()
        # Setup time is when the user can still fix the network: say what it needs.
        paths = await eufy.async_probe_lan()
    print(f"Logged in; session cached in {ctx.store_path}")
    if paths:
        print()
        print(render.render_network(paths, show_serials=ctx.show_serials))
    return 0


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
        if ctx.args.json:
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
    """Write a stream to ``PREFIX.hevc`` / ``PREFIX.aac``; ``seconds`` counts from the first frame.

    Frames are flushed as they arrive, so memory stays flat and a stream that fails
    part-way still leaves what came before the failure on disk.
    """
    paths = {"video": Path(f"{prefix}.hevc"), "audio": Path(f"{prefix}.aac")}
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
        print(
            f"Wrote a {len(blob)}-byte HEVC keyframe to {out} "
            f"(to a JPEG: ffmpeg -i {out} -frames:v 1 still.jpg)"
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
}
