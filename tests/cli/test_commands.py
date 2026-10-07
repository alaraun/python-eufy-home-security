"""Commands run end to end: parsed arguments → library → rendered output.

The cloud is replaced by a stub; the station is the loopback ``FakeStation``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import replace
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, cast
from unittest.mock import Mock

import pytest

from eufy_home_security import client as client_module
from eufy_home_security.cli import commands
from eufy_home_security.cli.commands import Context, date_window, select_station
from eufy_home_security.cli.config import UsageError, parse_args
from eufy_home_security.cloud.api import CipherKeys
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.exceptions import LoginChallengeError
from eufy_home_security.models import GuardMode
from eufy_home_security.network import LanPath
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.pppp import DISCOVERY_PORT
from eufy_home_security.push import fcm as fcm_module
from eufy_home_security.station import Station
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.cloud import range_property, thing_description
from eufy_home_security.testing.station import MEDIA_AUDIO, MEDIA_KEYFRAME, FakeStation

CURRENT: dict[str, FakeStation] = {}


class StubCloud:
    challenge: ClassVar[LoginChallengeError | None] = None
    replaced: ClassVar[bool] = False

    emails: ClassVar[list[str]] = []
    device_refreshes: ClassVar[list[bool]] = []
    rescans: ClassVar[list[bool]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.user_name = "user"
        self.logins: list[dict[str, Any]] = []
        self.scanned_codes: list[list[str]] = []
        self.session_replaced = StubCloud.replaced
        StubCloud.emails.append(args[2])

    async def async_login(self, **kwargs: Any) -> None:
        self.logins.append(kwargs)
        if StubCloud.challenge is not None and not kwargs.get("verify_code"):
            raise StubCloud.challenge

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        StubCloud.device_refreshes.append(refresh)
        StubCloud.rescans.append(rescan_regions)
        return [
            CloudDevice(
                device_sn=SYNTHETIC.station_sn,
                device_type=18,
                name="Home Base",
                p2p_did=SYNTHETIC.did,
                local_ip="127.0.0.1",
            ),
            CloudDevice(
                device_sn=SYNTHETIC.camera_sn,
                device_type=19,
                name="Front",
                station_sn=SYNTHETIC.station_sn,
                channel=0,
            ),
        ]

    async def async_get_station_owner_id(self, station_sn: str, *, refresh: bool = False) -> str:
        return SYNTHETIC.account_id

    async def async_get_cipher_keys(
        self, station_sn: str, cipher_id: int = 40, *, refresh: bool = False
    ) -> CipherKeys:
        return CipherKeys(CURRENT["station"].ecc_private_key_hex, None)

    async def async_get_thing_descriptions(
        self, product_codes: Sequence[str]
    ) -> list[Mapping[str, Any]]:
        """The model scan's request: answered with no thing descriptions."""
        self.scanned_codes.append(list(product_codes))
        return []


class StubPush:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    async def async_start(self) -> None: ...

    async def async_stop(self) -> None: ...


@pytest.fixture
async def fake(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    await station.start()
    CURRENT["station"] = station
    StubCloud.challenge = None
    StubCloud.device_refreshes = []
    StubCloud.rescans = []
    monkeypatch.setattr(client_module, "EufyCloudApi", StubCloud)
    monkeypatch.setattr(fcm_module, "PushListener", StubPush)
    # The CLI passes the host only: bind every session and the LAN probe to the
    # fake's discovery port.
    monkeypatch.setattr(client_module, "EufySecurity", _bound_client(station.discovery_port))
    monkeypatch.setenv("EUFY_PASSWORD", "pw")
    yield station
    station.stop()


def _bound_client(port: int) -> type[client_module.EufySecurity]:
    discovery_port = port

    class Bound(client_module.EufySecurity):
        async def async_probe_lan(
            self, *, timeout: float | None = None, port: int = DISCOVERY_PORT
        ) -> list[LanPath]:
            return await super().async_probe_lan(timeout=0.5, port=discovery_port)

        async def async_discover(
            self, *, refresh: bool = False, rescan_regions: bool = False
        ) -> list[Station]:
            stations = await super().async_discover(refresh=refresh, rescan_regions=rescan_regions)
            for st in stations:
                st.session._port = port
            return stations

    return Bound


async def run(argv: list[str], tmp_path: Any, prompt: Callable[[str], str] | None = None) -> int:
    args = parse_args(
        [*argv[:0], "--email", SYNTHETIC.email, "--store", str(tmp_path / "cache.json"), *argv]
    )
    # XDG_CONFIG_HOME keeps every default path inside tmp_path.
    env = {"EUFY_PASSWORD": "pw", "XDG_CONFIG_HOME": str(tmp_path)}
    async with Context(args, env=env, prompt=prompt or input) as ctx:
        return await commands.COMMANDS[args.command](ctx)


async def test_status_human_json_raw(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await run(["--host", "127.0.0.1", "status"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "Guard mode:  Disarmed" in out
    assert '"Front"' in out
    assert "battery 87%" in out
    assert SYNTHETIC.station_sn in out  # full serials unless --redact-serials

    assert await run(["--host", "127.0.0.1", "status", "--json"], tmp_path) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["serial"] == SYNTHETIC.station_sn
    assert data["guard_mode"] == "disarmed"

    assert await run(["--host", "127.0.0.1", "status", "--raw"], tmp_path) == 0
    assert "SET_ARMING" in capsys.readouterr().out


class ListedCloud(StubCloud):
    """The stub cloud with the camera on an unbundled product code the cloud describes."""

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        devices = await super().async_get_devices(refresh=refresh)
        return [
            replace(d, raw={"device_new_pn": "T9999"}) if d.device_sn == SYNTHETIC.camera_sn else d
            for d in devices
        ]

    async def async_get_thing_descriptions(self, product_codes: Sequence[str]) -> list[Any]:
        return [thing_description("T9999", [range_property("record_time", 10, 120)])]


async def test_status_names_a_model_listed_read_only_from_the_cloud(
    fake: FakeStation,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(client_module, "EufyCloudApi", ListedCloud)
    assert await run(["--host", "127.0.0.1", "status"], tmp_path) == 0
    assert "  T9999: not in bundled data: settings listed read-only" in capsys.readouterr().out


async def test_guard_get_and_set(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await run(["--host", "127.0.0.1", "guard", "get"], tmp_path) == 0
    assert "Guard mode: Disarmed" in capsys.readouterr().out
    assert await run(["--host", "127.0.0.1", "guard", "set", "home"], tmp_path) == 0
    assert "Guard mode set: Home" in capsys.readouterr().out
    assert fake.guard_mode == GuardMode.HOME


@pytest.mark.parametrize(
    ("target", "shown"),
    [(["--device", SYNTHETIC.camera_sn], SYNTHETIC.camera_sn), (["--channel", "0"], "channel 0")],
)
async def test_set_writes_a_device_setting_and_shows_its_label(
    fake: FakeStation,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
    target: list[str],
    shown: str,
) -> None:
    argv = ["--host", "127.0.0.1", "set", "watermark_set", "2", *target]
    assert await run(argv, tmp_path) == 0
    out = capsys.readouterr().out
    assert f"watermark_set = Timestamp and logo on {shown}: applied" in out
    assert fake.ecb_received[-1] == (1214, 0, 2)


async def test_set_without_a_target_addresses_the_station(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    for extra, target in (([], "the station"), (["--channel", "255"], "channel 255")):
        argv = ["--host", "127.0.0.1", "set", "time_format_set", "1", *extra]
        assert await run(argv, tmp_path) == 0
        assert f"time_format_set = 1 on {target}: applied" in capsys.readouterr().out
        assert fake.ecb_received[-1] == (1253, 255, 1)


@pytest.mark.parametrize("channel", ["51", "-1"])
async def test_set_refuses_a_channel_no_station_has_before_login(
    fake: FakeStation, tmp_path: Any, channel: str
) -> None:
    StubCloud.emails.clear()
    with pytest.raises(UsageError, match="--channel must be 0-50 or 255"):
        await run(
            ["--host", "127.0.0.1", "set", "watermark_set", "2", "--channel", channel], tmp_path
        )
    assert StubCloud.emails == []  # no account was built, so no login
    assert fake.conn_inits == 0


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (["set", "watermark_set", "7", "--channel", "0"], r"7 is not one of \[0, 1, 2\]"),
        (["set", "watermark_set", "big", "--channel", "0"], "not one of"),
        (["set", "not_a_key", "1", "--channel", "0"], "unknown setting"),
        (["set", "watermark_set", "1"], "unknown setting"),  # the station (T8030) has none
        (["set", "watermark_set", "1", "--channel", "1"], "no paired device on channel 1"),
        (["set", "device_name", "Porch", "--channel", "0"], "not writable: .*cloud request"),
    ],
)
async def test_set_is_validated_on_the_device_and_sends_nothing(
    fake: FakeStation, tmp_path: Any, argv: list[str], match: str
) -> None:
    with pytest.raises(UsageError, match=match):
        await run(["--host", "127.0.0.1", *argv], tmp_path)
    assert fake.received == []
    assert fake.ecb_received == []


@pytest.mark.parametrize(
    ("block", "argv", "shown"),
    [
        (
            {1246: "2"},
            ["power_manager_mode", "--device", SYNTHETIC.camera_sn],
            "3 (Custom recording)",
        ),
        ({1167: "30"}, ["alarm_delay_away", "--channel", "0"], "30 s"),
        ({1251: "0"}, ["motion_stop_end_early", "--channel", "0"], "true"),
        ({}, ["power_manager_mode", "--channel", "0"], "unknown"),
    ],
)
async def test_get_prints_the_decoded_value_with_label_and_unit(
    fake: FakeStation,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
    *,
    block: dict[int, str],
    argv: list[str],
    shown: str,
) -> None:
    fake.params[0].update(block)
    assert await run(["--host", "127.0.0.1", "get", *argv], tmp_path) == 0
    assert capsys.readouterr().out.strip() == f"{argv[0]} = {shown}"


async def test_get_reads_the_station_without_a_target(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.params[255][1253] = "1"
    assert await run(["--host", "127.0.0.1", "get", "time_format_set"], tmp_path) == 0
    assert capsys.readouterr().out.strip().startswith("time_format_set = 1")


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (["get", "not_a_key", "--channel", "0"], r"unknown setting .*settings --model"),
        (["get", "watermark_set", "--channel", "1"], "no paired device on channel 1"),
    ],
)
async def test_get_refuses_an_unknown_key_or_target(
    fake: FakeStation, tmp_path: Any, argv: list[str], match: str
) -> None:
    with pytest.raises(UsageError, match=match):
        await run(["--host", "127.0.0.1", *argv], tmp_path)


async def test_email_comes_from_the_cache_and_no_password_is_asked(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(_question: str) -> str:
        raise AssertionError("the password must not be prompted for while a session is cached")

    monkeypatch.delenv("EUFY_PASSWORD")
    store = str(tmp_path / "cache.json")
    with pytest.raises(UsageError, match="no account e-mail"):
        await run_bare(["--store", store, "devices"], secret_prompt=never)

    assert await run(["devices"], tmp_path) == 0  # remembers the account
    StubCloud.emails.clear()
    assert await run_bare(["--store", store, "devices"], secret_prompt=never) == 0
    assert StubCloud.emails == [SYNTHETIC.email]


async def run_bare(argv: list[str], *, secret_prompt: Callable[[str], str]) -> int:
    """Like :func:`run` but with no e-mail or password from the command line or env."""
    args = parse_args(argv)
    async with Context(args, env={}, secret_prompt=secret_prompt) as ctx:
        return await commands.COMMANDS[args.command](ctx)


async def test_status_reads_the_cached_device_list_then_devices_refreshes_it(
    fake: FakeStation, tmp_path: Any
) -> None:
    args = ["--host", "127.0.0.1", "--station", "Home Base", "status"]
    assert await run(args, tmp_path) == 0
    # a normal command trusts the cache (--host adds a probe that reads it too)
    assert StubCloud.device_refreshes
    assert not any(StubCloud.device_refreshes)
    StubCloud.device_refreshes = []
    assert await run(["devices"], tmp_path) == 0
    assert StubCloud.device_refreshes == [True]  # `devices` forces a fresh fetch
    assert StubCloud.rescans[-1] is False
    assert await run(["devices", "--rescan-regions"], tmp_path) == 0
    assert StubCloud.rescans[-1] is True


async def test_select_refreshing_refetches_once_when_a_named_station_is_not_cached() -> None:
    """A station added since the cache was written is found after one refresh; an
    ambiguous or absent name is not retried (a refresh cannot disambiguate it)."""
    home = Station(
        CloudDevice(
            device_sn=SYNTHETIC.station_sn, device_type=18, name="Home Base", p2p_did=SYNTHETIC.did
        ),
        session=Mock(),
    )
    garage = Station(
        CloudDevice(
            device_sn="T8030P0000009999", device_type=18, name="Garage", p2p_did=SYNTHETIC.did
        ),
        session=Mock(),
    )

    class Eufy:
        def __init__(self) -> None:
            self.refreshes: list[bool] = []

        async def async_discover(self, *, refresh: bool = False) -> list[Station]:
            self.refreshes.append(refresh)
            return [home, garage] if refresh else [home]

    ctx = Context(parse_args(["status"]), env={})
    eufy = Eufy()
    picked = await commands._select_refreshing(ctx, cast(Any, eufy), "Garage")
    assert picked is garage
    assert eufy.refreshes == [False, True]

    eufy = Eufy()
    with pytest.raises(UsageError):
        await commands._select_refreshing(ctx, cast(Any, eufy), "Unknown")
    assert eufy.refreshes == [False, True]  # tried a refresh, still missing


async def test_login_and_network_say_what_the_firewall_must_allow(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await run(["login"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "Logged in" in out
    assert "allow all UDP from 127.0.0.1" in out
    assert "--local-port 32109" in out  # the suggestion for the only station

    assert await run(["--local-port", "32109", "network"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "allow UDP from 127.0.0.1 to this host's port 32109" in out
    assert "allow all UDP" not in out
    assert "did not answer LAN discovery" not in out  # the fake station answered the probe


async def test_login_does_not_prompt_for_an_answer_it_cannot_use(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    logins: list[dict[str, Any]] = []

    async def always_challenged(self: StubCloud, **kwargs: Any) -> None:
        logins.append(kwargs)
        raise LoginChallengeError("verify_code", login_id="L1")

    monkeypatch.setattr(StubCloud, "async_login", always_challenged)
    prompts: list[str] = []

    def answer(question: str) -> str:
        prompts.append(question)
        return "123456"

    with pytest.raises(UsageError, match="gave up"):
        await run(["login"], tmp_path, prompt=answer)
    assert len(logins) == commands.LOGIN_CHALLENGE_ROUNDS
    assert len(prompts) == commands.LOGIN_CHALLENGE_ROUNDS - 1


async def test_secret_answers_are_kept_verbatim() -> None:
    ctx = Context(parse_args(["login"]), env={}, prompt=lambda _q: " code ")
    ctx.secret_prompt = lambda _q: " pw "
    assert await ctx.ask("password: ", secret=True) == " pw "
    assert await ctx.ask("code: ") == "code"
    ctx.secret_prompt = lambda _q: "  "
    with pytest.raises(UsageError, match="no answer"):
        await ctx.ask("password: ", secret=True)


def _record_station_hosts(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Wrap the (already bound) client so each account records its ``station_hosts``."""
    seen: list[Any] = []
    base = client_module.EufySecurity

    class Recording(base):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            seen.append(kwargs.get("station_hosts"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(client_module, "EufySecurity", Recording)
    return seen


async def test_host_applies_to_a_station_named_by_name(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _record_station_hosts(monkeypatch)
    assert await run(["--host", "127.0.0.1", "--station", "Home Base", "status"], tmp_path) == 0
    assert seen[-1] == {SYNTHETIC.station_sn: "127.0.0.1"}


@pytest.mark.parametrize("redact", [False, True])
async def test_monitor_applies_host_and_shows_full_serials_unless_redacted(
    fake: FakeStation,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    redact: bool,
) -> None:
    seen = _record_station_hosts(monkeypatch)
    argv = ["--host", "127.0.0.1", "--station", "Home Base"] + (["--redact-serials"] * redact)
    task = asyncio.ensure_future(run([*argv, "monitor", "--no-push"], tmp_path))
    err = ""
    for _ in range(100):
        await asyncio.sleep(0.05)
        err += capsys.readouterr().err
        if "Monitoring" in err or task.done():
            break
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert (f"({SYNTHETIC.station_sn})" in err) is not redact
    assert seen[-1] == {SYNTHETIC.station_sn: "127.0.0.1"}


async def test_login_carries_the_challenge_login_id_into_the_answer(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    logins: list[dict[str, Any]] = []

    async def challenged_once(self: StubCloud, **kwargs: Any) -> None:
        logins.append(kwargs)
        if not kwargs.get("verify_code"):
            raise LoginChallengeError("verify_code", login_id="L1")

    monkeypatch.setattr(StubCloud, "async_login", challenged_once)
    assert await run(["login"], tmp_path, prompt=lambda _q: "123456") == 0
    assert (logins[-1].get("verify_code"), logins[-1].get("login_id")) == ("123456", "L1")


@pytest.mark.parametrize("replaced", [False, True])
async def test_login_takes_back_only_a_replaced_session(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, replaced: bool
) -> None:
    logins: list[dict[str, Any]] = []

    async def record(self: StubCloud, **kwargs: Any) -> None:
        logins.append(kwargs)

    monkeypatch.setattr(StubCloud, "replaced", replaced)
    monkeypatch.setattr(StubCloud, "async_login", record)
    assert await run(["login"], tmp_path) == 0
    # A healthy cached session is reused; running `login` after a kick-out is the
    # user's decision to log in again.
    assert logins[0]["force"] is replaced


async def test_login_answers_a_verify_code(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    StubCloud.challenge = LoginChallengeError("verify_code", login_id="L1")
    assert await run(["login"], tmp_path, prompt=lambda _q: "123456") == 0
    assert "Logged in" in capsys.readouterr().out


async def test_events_and_image(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.rows = [
        {
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/t.jpg",
            "start_time": 1_700_000_000_000,
        }
    ]
    fake.images["/zx/t.jpg"] = b"\xff\xd8\xff" + b"x" * 32
    assert await run(["--host", "127.0.0.1", "events", "--days", "2"], tmp_path) == 0
    assert "thumb: /zx/t.jpg" in capsys.readouterr().out
    out = tmp_path / "still.jpg"
    assert (
        await run(["--host", "127.0.0.1", "image", "/zx/t.jpg", "--out", str(out)], tmp_path) == 0
    )
    assert out.read_bytes() == fake.images["/zx/t.jpg"]


async def test_media_commands_write_playable_files(
    fake: FakeStation, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "MEDIA_IDLE_TIMEOUT", 0.3)
    host = ["--host", "127.0.0.1"]
    live = tmp_path / "live"
    argv = [*host, "live", "--channel", "0", "--seconds", "0.1", "--out", str(live)]
    assert await run(argv, tmp_path) == 0
    assert (tmp_path / "live.hevc").read_bytes().startswith(MEDIA_KEYFRAME)
    assert (tmp_path / "live.aac").read_bytes().startswith(MEDIA_AUDIO)

    clip = tmp_path / "clip"
    argv = [
        *host,
        "recording",
        "/zx/c.zxvideo",
        "--device",
        SYNTHETIC.camera_sn,
        "--out",
        str(clip),
    ]
    assert await run(argv, tmp_path) == 0
    assert (tmp_path / "clip.hevc").read_bytes().count(MEDIA_KEYFRAME) >= 2

    still = tmp_path / "still.hevc"
    argv = [
        *host,
        "snapshot",
        "--channel",
        "0",
        "--recording",
        "/zx/c.zxvideo",
        "--out",
        str(still),
    ]
    assert await run(argv, tmp_path) == 0
    assert still.read_bytes() == MEDIA_KEYFRAME


async def test_storage_prints_the_apps_figures(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await run(["--host", "127.0.0.1", "storage"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "14.16 GB used of 232.89 GB (6.1 %)" in out
    assert "218.73 GB free" in out
    assert "38 °C  healthy" in out
    assert "eMMC:          2.93 GB used of 15.62 GB (25.0 %)" in out
    assert "12.70 GB free" in out
    assert "wear 2 %  healthy" in out
    assert SYNTHETIC.disk_serial not in out

    argv = ["--host", "127.0.0.1", "--redact-serials", "storage", "--json"]
    assert await run(argv, tmp_path) == 0
    data = json.loads(capsys.readouterr().out)
    assert (data["disk"]["used_gib"], data["disk"]["size_gib"]) == (14.16, 232.89)
    assert (data["disk"]["formatting"], data["formatting"]) == (False, False)
    assert data["disk"]["serial"] != SYNTHETIC.disk_serial
    assert (data["emmc"]["wear_percent"], data["emmc"]["used_percent"]) == (2, 25.0)
    assert (data["emmc"]["free_gib"], data["emmc"]["healthy"]) == (12.7, True)
    assert data["external"] is None


async def test_history_lists_records(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    # One record today and one two days ago: the window covers both, today included.
    today = datetime.now().astimezone().date()
    fake.rows = [
        {
            "record_id": int(day.strftime("%Y%m%d")) * 100_000 + 34,
            "device_sn": SYNTHETIC.camera_sn,
            "start_time": f"{day.isoformat()} 15:14:43",
            "str_extra": '{"arm_mode":0,"msg_type":9,"user_name":"someone"}',
        }
        for day in (today, today - timedelta(days=2))
    ]
    assert await run(["--host", "127.0.0.1", "history", "--days", "2"], tmp_path) == 0
    assert "2 record(s)" in capsys.readouterr().out
    assert await run(["--host", "127.0.0.1", "history", "--count", "1"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "1 record(s)" in out
    assert today.isoformat() in out


async def test_persons_lists_the_picture_library(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.rows = [
        {
            "person_id": 17,
            "name": "stranger14",
            "relation": "family",
            "update_time": "2026-09-09",  # hygiene: ok
        }
    ]
    assert await run(["--host", "127.0.0.1", "persons"], tmp_path) == 0
    out = capsys.readouterr().out
    assert "recognised people" in out
    assert "stranger14 · person 17 · family" in out


def test_select_station_by_name_or_serial_else_usage_error() -> None:
    def st(sn: str, name: str) -> Station:
        return Station(
            CloudDevice(device_sn=sn, device_type=18, name=name, p2p_did=SYNTHETIC.did),
            session=Mock(),
        )

    a, b = st(SYNTHETIC.station_sn, "Home Base"), st("T8030P2000054321", "Garage")
    assert select_station([a, b], "garage", show=False) is b
    assert select_station([a, b], SYNTHETIC.station_sn, show=False) is a
    assert select_station([a], None, show=False) is a
    with pytest.raises(UsageError, match="several stations"):
        select_station([a, b], None, show=False)
    with pytest.raises(UsageError, match="no station matches"):
        select_station([a, b], "attic", show=False)
    with pytest.raises(UsageError, match="no station"):
        select_station([], None, show=False)


def test_date_window() -> None:
    assert date_window(2, date(2026, 3, 1)) == ("20260227", "20260301")


# ── Settings from the CLI ────────────────────────────────────────────────────


async def _run_offline(tmp_path: Path, argv: list[str]) -> int:
    """A network-free command: asserts no HTTP session was ever opened."""
    args = parse_args(["--store", str(tmp_path / "cache.json"), *argv])
    async with Context(args, env={"XDG_CONFIG_HOME": str(tmp_path)}) as ctx:
        code = await commands.COMMANDS[args.command](ctx)
        assert ctx.http is None
    return code


async def test_settings_without_a_model_lists_the_per_mode_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await _run_offline(tmp_path, ["settings"]) == 0
    out = capsys.readouterr().out
    row = next(line for line in out.splitlines() if line.strip().startswith("alarm_delay_away "))
    assert row.split()[1:] == ["0..300", "step", "1", "s", "cameras", "and", "sensors"]
    camera = next(line for line in out.splitlines() if "camera_action_home " in line)
    assert camera.split()[-1] == "cameras"
    assert "settings --model PN" in out
    assert "TIER" not in out


@pytest.mark.parametrize("typed", ["T8160", "t8160"])
async def test_settings_model_lists_the_models_settings_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], typed: str
) -> None:
    assert await _run_offline(tmp_path, ["settings", "--model", typed]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert "settings of T8160" in lines
    header = next(line for line in lines if line.strip().startswith("KEY"))
    assert header.split() == ["KEY", "KIND", "VALUES", "UNIT", "WRITABLE", "APPLIES", "WHEN"]
    power = next(line for line in lines if line.strip().startswith("power_manager_mode "))
    assert "0=Optimal battery life, 1=Optimal surveillance, 3=Custom recording" in power
    assert power.split()[-1] == "-"  # applies always, writable yes
    name = next(line for line in lines if line.strip().startswith("device_name "))
    assert "cloud request" in name
    clip = next(line for line in lines if line.strip().startswith("video_clip_length "))
    assert "power_manager_mode = 3" in clip
    assert "per-mode settings of a paired T8160" in out
    assert any(line.strip().startswith("camera_action_home ") for line in lines)
    assert "TIER" not in out


async def test_settings_model_of_a_station_has_no_per_mode_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await _run_offline(tmp_path, ["settings", "--model", "T8030"]) == 0
    out = capsys.readouterr().out
    assert "settings of T8030" in out
    assert "per-mode settings" not in out


@pytest.mark.parametrize("typed", ["T0000", "T8-160"])
async def test_settings_model_unknown_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], typed: str
) -> None:
    assert await _run_offline(tmp_path, ["settings", "--model", typed]) == 0
    assert f"no bundled settings for {typed}" in capsys.readouterr().out
