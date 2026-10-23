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
from unittest.mock import AsyncMock, Mock

import pytest

from eufy_home_security import client as client_module
from eufy_home_security._logging import redact_serial
from eufy_home_security.cli import commands
from eufy_home_security.cli.commands import Context, date_window, select_station
from eufy_home_security.cli.config import UsageError, parse_args
from eufy_home_security.cloud.api import CipherKeys, EufyCloudApi
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


async def test_status_received_prints_every_key_of_the_dump(
    fake: FakeStation, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    fake.dump_extra = {"future_list": [1]}
    assert await run(["--host", "127.0.0.1", "status", "--received"], tmp_path) == 0
    objects = json.loads(capsys.readouterr().out)
    station_block = next(o for o in objects if "future_list" in o)
    assert station_block["future_list"] == [1]
    assert any(p["param_type"] == 1224 for p in station_block["params"])


class ListedCloud(StubCloud):
    """The stub cloud with the camera on an unbundled product code the cloud describes."""

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        devices = await super().async_get_devices(refresh=refresh, rescan_regions=rescan_regions)
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


def _record_cloud_options(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Make each account's real cloud client record the options it is built with."""
    seen: dict[str, Any] = {}

    class Recording(EufyCloudApi):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            seen.update(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(client_module, "EufyCloudApi", Recording)
    return seen


async def _open_account(tmp_path: Path, options: list[str]) -> None:
    args = parse_args(
        ["--email", SYNTHETIC.email, "--store", str(tmp_path / "cache.json"), *options, "devices"]
    )
    async with Context(args, env={}) as ctx:
        await commands.open_account(ctx)


@pytest.mark.parametrize(
    ("country", "codes"),
    [("EE,CH", ["EE", "CH"]), (" ee , ch ,", ["ee", "ch"]), ("", [])],
)
async def test_country_is_split_on_commas_and_region_passed_through(
    country: str, codes: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _record_cloud_options(monkeypatch)
    await _open_account(tmp_path, ["--country", country, "--region", "us"])
    assert seen["country"] == codes
    assert seen["region"] == "us"


async def test_a_bad_country_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _record_cloud_options(monkeypatch)
    with pytest.raises(UsageError, match="XYZ"):
        await _open_account(tmp_path, ["--country", "XYZ"])


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
    values = ["0,", "15,", "30,", "45,", "60,", "180,", "300"]
    assert row.split()[1:] == [*values, "s", "cameras,", "doorbells", "and", "sensors"]
    camera = next(line for line in out.splitlines() if "camera_action_home " in line)
    assert camera.split()[-1] == "cameras"
    doorbell = next(line for line in out.splitlines() if "doorbell_action_home " in line)
    assert doorbell.split()[-1] == "doorbells"
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


async def test_diagnose_explain_prints_scope_and_exits(capsys: pytest.CaptureFixture[str]) -> None:
    async with Context(parse_args(["diagnose", "--explain"]), env={}) as ctx:
        assert await commands.COMMANDS["diagnose"](ctx) == 0
    out = capsys.readouterr().out
    assert "read-only" in out
    assert "Never:" in out  # the privacy note names what is never collected
    assert "station with a paired camera the eufy app streams over WebRTC" in out


class WebRtcCloud(StubCloud):
    """The stub cloud's HomeBase 3 and camera, plus a T9000 (two cameras, the user a
    shared member) and a T9000 lacking its license."""

    user_id = SYNTHETIC.account_id

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        base = "T9000" + SYNTHETIC.station_sn[5:]
        signaling = {
            "device_sn": base,
            "p2p_did": SYNTHETIC.did,
            "p2p_license": "ABCDEF",
            "signaling_servers": ["https://198.51.100.1"],
        }
        own = await super().async_get_devices(refresh=refresh, rescan_regions=rescan_regions)
        return [
            *own,
            CloudDevice(
                device_sn=base,
                device_type=91,
                name="Pro",
                p2p_did=SYNTHETIC.did,
                owner_user_id="o" * 40,
                raw=signaling,
            ),
            CloudDevice(
                device_sn="T8160" + SYNTHETIC.camera_sn[5:-1] + "1",
                device_type=19,
                name="Cam 4",
                station_sn=base,
                channel=4,
            ),
            CloudDevice(
                device_sn="T8410" + SYNTHETIC.camera_sn[5:],
                device_type=104,
                name="Cam 2",
                station_sn=base,
                channel=2,
            ),
            CloudDevice(
                device_sn="T9000" + SYNTHETIC.station_sn[5:-1] + "9",
                device_type=91,
                name="Bare",
                raw={"p2p_did": SYNTHETIC.did},
            ),
        ]


C30_SN = "T8224" + SYNTHETIC.camera_sn[5:-1] + "2"


class C30Cloud(WebRtcCloud):
    """:class:`WebRtcCloud` whose HomeBase 3 carries signaling fields, runs a firmware
    the eufy app streams a Video Doorbell C30 over WebRTC behind, and has a C30 (T8224)
    on channel 2 next to its camera on channel 0."""

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        hb3, *rest = await super().async_get_devices(refresh=refresh, rescan_regions=rescan_regions)
        raw = {
            "device_sn": hb3.device_sn,
            "p2p_did": SYNTHETIC.did,
            "p2p_license": "ABCDEF",
            "signaling_servers": ["https://198.51.100.1"],
        }
        c30 = CloudDevice(
            device_sn=C30_SN, device_type=7, name="Front Porch", station_sn=hb3.device_sn, channel=2
        )
        return [replace(hb3, raw=raw, main_sw_version="3.8.7.4"), c30, *rest]


@pytest.fixture
def account_views(fake: FakeStation, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cache summary and account report, which the stub cloud cannot serve (each is
    tested with the library); here the command only has to include them."""

    async def summary(self: Any) -> dict[str, Any]:
        return {"version": 1}

    async def account(self: Any, *, ciphers: bool = True) -> Any:
        return Mock(as_dict=Mock(return_value={"devices": []}))

    monkeypatch.setattr(client_module.EufySecurity, "async_cache_summary", summary)
    monkeypatch.setattr(client_module.EufySecurity, "async_account_report", account)


def _fake_collect(calls: list[dict[str, Any]]) -> Callable[..., Any]:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    async def collect(session: Any, **kwargs: Any) -> diagnostics.StationReport:
        calls.append(kwargs)
        return diagnostics.StationReport(
            station=kwargs["station"],
            children=list(kwargs["children"]),
            channel=kwargs["channel"],
            phase_reached="done",
        )

    return collect


@pytest.mark.usefixtures("account_views")
async def test_diagnose_reports_the_p2p_stations_and_probes_the_webrtc_ones(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "report.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--watch", "5", "--output", str(out)]
    assert await run(argv, tmp_path) == 0
    report = json.loads(out.read_text())
    # The HomeBase 3 over P2P: read once, its session counters recorded.
    (label, block), *_ = report["stations"].items()
    assert label.startswith("T8030")
    assert block["read_errors"] == {}
    assert block["session"]["connects"] >= 1
    assert all("name" not in d for d in block["devices"])
    assert block["storage"]["storage_days"] == 30  # read, without the disk's serial/label
    # The T9000 over WebRTC, with the owner's id and its lowest-channel camera (all of
    # them streamed over WebRTC); the one lacking its license is reported, not probed.
    assert len(calls) == 1
    call = calls[0]
    assert call["account_id"] == "o" * 40
    assert call["camera"].channel == 2
    assert (call["watch_s"], call["do_live"], call["do_commands"]) == (5.0, True, True)
    assert [s["phase_reached"] for s in report["webrtc_stations"]] == ["done", "config"]
    # The HomeBase 3 has no camera the eufy app streams over WebRTC: not probed.
    assert [s["probe_reason"] for s in report["webrtc_stations"]] == ["webrtc_only"] * 2
    assert report["webrtc_stations"][0]["live_camera"] == {
        "channel": 2,
        "model": "T8410",
        "product_code": "T8410",
        "serial": redact_serial("T8410" + SYNTHETIC.camera_sn[5:]),
        "chosen_by": "webrtc_child",
    }
    assert [c["channel"] for c in report["webrtc_stations"][0]["children"]] == [2, 4]
    assert "webrtc_only" in {d["reason"] for d in report["skipped_devices"]}
    assert (report["account"], report["cache"]) == ({"devices": []}, {"version": 1})
    assert "models" in report
    assert "stations_served_elsewhere" in report
    text = out.read_text()
    for private in (
        SYNTHETIC.did,
        SYNTHETIC.station_sn,
        SYNTHETIC.camera_sn,
        "198.51.100.1",
        "o" * 40,
        SYNTHETIC.account_id,
        "ABCDEF",
        "Home Base",
        SYNTHETIC.disk_serial,
        SYNTHETIC.disk_label,
    ):
        assert private not in text
    assert "Review it before sharing" in capsys.readouterr().out


@pytest.mark.usefixtures("account_views")
async def test_diagnose_picks_a_station_by_name_and_a_camera_by_channel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "r.json"
    argv = ["--station", "Pro", "diagnose", "--camera-channel", "4", "--no-live"]
    assert await run([*argv, "--output", str(out)], tmp_path) == 0
    assert [c["camera"].model for c in calls] == ["T8160"]
    assert calls[0]["do_live"] is False
    assert json.loads(out.read_text())["stations"] == {}  # the HomeBase 3 is not "Pro"


@pytest.mark.usefixtures("account_views")
async def test_diagnose_probes_a_homebase_3_with_a_c30_on_the_c30s_channel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", C30Cloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "r.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--output", str(out)]
    assert await run(argv, tmp_path) == 0
    report = json.loads(out.read_text())
    (label,) = report["stations"]  # its P2P read stays
    assert label.startswith("T8030")
    assert [c["station"].model for c in calls] == ["T8030", "T9000"]
    assert [c["camera"].channel for c in calls] == [2, 2]
    assert calls[0]["camera"].model == "T8224"
    hb3, t9000, _bare = report["webrtc_stations"]
    assert (hb3["probe_reason"], t9000["probe_reason"]) == ("webrtc_child", "webrtc_only")
    assert hb3["live_camera"] == {
        "channel": 2,
        "model": "T8224",
        "product_code": "T8224",
        "serial": redact_serial(C30_SN),
        "chosen_by": "webrtc_child",
    }
    assert "(webrtc_child, live view: T8224 on channel 2)" in capsys.readouterr().out
    text = out.read_text()
    for private in (C30_SN, SYNTHETIC.station_sn, "Front Porch", "ABCDEF", "198.51.100.1"):
        assert private not in text, private


@pytest.mark.usefixtures("account_views")
async def test_diagnose_live_view_of_a_homebase_3_follows_the_camera_channel_option(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", C30Cloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "r.json"
    argv = ["--station", "Home Base", "diagnose", "--no-p2p", "--camera-channel", "0"]
    assert await run([*argv, "--output", str(out)], tmp_path) == 0
    assert [(c["camera"].model, c["camera"].channel) for c in calls] == [("T8160", 0)]
    (hb3,) = json.loads(out.read_text())["webrtc_stations"]
    assert hb3["probe_reason"] == "webrtc_child"
    assert (hb3["live_camera"]["chosen_by"], hb3["live_camera"]["model"]) == (
        "camera_channel",
        "T8160",
    )
    assert await run([*argv, "--no-live", "--output", str(out)], tmp_path) == 0
    assert json.loads(out.read_text())["webrtc_stations"][0]["live_camera"] is None


@pytest.mark.usefixtures("account_views")
@pytest.mark.parametrize("cloud", [WebRtcCloud, C30Cloud], ids=["webrtc-only", "hb3-c30"])
async def test_diagnose_without_webrtc_reads_only_the_p2p_stations(
    cloud: type[StubCloud],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", cloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "r.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--no-webrtc", "--output", str(out)]
    assert await run(argv, tmp_path) == 0
    assert calls == []
    report = json.loads(out.read_text())
    assert report["webrtc_stations"] == []
    assert len(report["stations"]) == 1


def test_a_device_view_for_the_report_drops_the_name() -> None:
    view = CloudDevice(device_sn=SYNTHETIC.station_sn, device_type=18, name="Home Base")
    out = commands.nameless(view.as_redacted_dict())
    assert "name" not in out
    assert out["device_type"] == 18


@pytest.mark.usefixtures("account_views")
async def test_diagnose_without_p2p_probes_only_the_webrtc_stations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect(calls))
    out = tmp_path / "r.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--no-p2p", "--output", str(out)]
    assert await run(argv, tmp_path) == 0
    report = json.loads(out.read_text())
    assert report["stations"] == {}
    assert len(calls) == 1


# ── diagnose: end to end, robustness, opt-in write ───────────────────────────


@pytest.fixture
async def webrtc_station(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    """The WebRTC path of diagnose against the fake signaling server, an in-memory
    data channel to a fake station and a fake media plane (the real collector runs)."""
    from eufy_home_security.rtc import session as rtc_session  # noqa: PLC0415
    from eufy_home_security.rtc.signaling import SignalingClient  # noqa: PLC0415

    from ..rtc.fakes import (  # noqa: PLC0415
        QUERIES,
        FakeCrypto,
        StationMedia,
        config,
        start_server,
        station_ice,
        stop_stations,
    )

    QUERIES.clear()
    server, port = await start_server(request_id=None)
    real = rtc_session.RtcSession

    def session(_config: Any, _crypto: Any) -> Any:
        cfg = config(firmware=4200)
        crypto = FakeCrypto()
        return real(
            cfg,
            crypto,
            signaling=SignalingClient(cfg, crypto, port=port),
            media_factory=StationMedia,
        )

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    monkeypatch.setattr(rtc_session, "RtcSession", session)
    monkeypatch.setattr(rtc_session, "default_ice_factory", station_ice)
    yield
    await stop_stations()
    server.close()


def _fake_push(monkeypatch: pytest.MonkeyPatch) -> None:
    """A push listener that starts at once and delivers one guard-mode push."""
    from eufy_home_security.events import EventSource, SecurityEvent  # noqa: PLC0415

    async def start(self: Any, *, p2p: bool = True, push: bool = True) -> dict[str, Any]:
        assert (p2p, push) == (False, True)
        self._push_running = True
        self._bus.emit(
            SecurityEvent(
                source=EventSource.CLOUD,
                station_sn="T9000" + SYNTHETIC.station_sn[5:],
                guard_mode=1,
                device_name="Pro",
                raw={"msg_type": 1240, "user_name": "Alice", "mode": 1},
            )
        )
        return {}

    monkeypatch.setattr(client_module.EufySecurity, "async_start", start)


@pytest.mark.usefixtures("account_views", "webrtc_station")
async def test_diagnose_end_to_end_writes_a_complete_report_without_private_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    from ..rtc.fakes import DEVICE_INFO, QUERIES  # noqa: PLC0415

    _fake_push(monkeypatch)
    monkeypatch.setattr(diagnostics, "_LIVE_OPEN_WAIT", 0.2)
    out = tmp_path / "report.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--watch", "0.1", "--listen", "0.1"]
    assert await run([*argv, "--output", str(out)], tmp_path) == 0
    report = json.loads(out.read_text())
    assert (report["complete"], report["aborted"]) == (True, None)
    assert report["options"]["watch"] == 0.1
    assert report["push"] == {"running": True, "error": None}
    (event,) = report["events"]
    assert (event["station_model"], event["ints"]) == ("T9000", {"guard_mode": 1})
    assert event["raw_ints"] == {"mode": [1]}
    (_start_ms, length_ms), *_ = report["watch_windows_ms"]
    assert length_ms == 100
    station, bare = report["webrtc_stations"]
    assert (station["phase_reached"], station["error"]) == ("done", None)
    assert station["guard_rewrite"] is None
    assert [c["name"] for c in station["commands"]] == ["storage_1307", "bind_list_9100"]
    assert station["live"]["channel"] == 2
    assert bare["phase_reached"] == "config"
    assert 1224 not in {q["cmd"] for q in QUERIES}  # read-only without the opt-in
    text = out.read_text()
    for private in (
        SYNTHETIC.did,
        SYNTHETIC.station_sn,
        SYNTHETIC.station_sn[5:],
        SYNTHETIC.camera_sn,
        SYNTHETIC.account_id,
        SYNTHETIC.email,
        "o" * 40,
        "u" * 40,
        "ABCDEF",
        "198.51.100",
        "192.0.2",
        "203.0.113",
        DEVICE_INFO.content_key,
        DEVICE_INFO.ice_pwd,
        DEVICE_INFO.ice_ufrag,
        "Home Base",
        "Pro",
        "Cam 2",
        "Alice",
    ):
        assert private not in text, private


@pytest.mark.usefixtures("account_views", "webrtc_station")
@pytest.mark.parametrize(
    ("answer", "mode", "note", "sent"),
    [
        ("yes", 1, "confirmed: 1", True),
        ("no", 1, "declined", False),
        ("yes", 2, "skipped: cloud guard mode 2 is not Away/Home/Disarmed", False),
    ],
)
async def test_diagnose_re_sends_the_guard_mode_only_when_opted_in_and_confirmed(
    *,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    answer: str,
    mode: int,
    note: str,
    sent: bool,
) -> None:
    from ..rtc.fakes import QUERIES  # noqa: PLC0415

    real = WebRtcCloud.async_get_devices

    async def with_mode(self: Any, **kwargs: Any) -> list[CloudDevice]:
        devices = await real(self, **kwargs)
        station = devices[2]
        raw = {**station.raw, "params": [{"param_type": 1224, "param_value": str(mode)}]}
        return [*devices[:2], replace(station, raw=raw), *devices[3:]]

    monkeypatch.setattr(WebRtcCloud, "async_get_devices", with_mode)
    asked: list[str] = []

    def prompt(question: str) -> str:
        asked.append(question)
        return answer

    out = tmp_path / "r.json"
    argv = ["--station", "Pro", "diagnose", "--no-p2p", "--no-live", "--rewrite-guard-mode"]
    assert await run([*argv, "--output", str(out)], tmp_path, prompt=prompt) == 0
    (station,) = json.loads(out.read_text())["webrtc_stations"]
    assert station["guard_rewrite"] == note
    assert (1224 in {q["cmd"] for q in QUERIES}) is sent
    assert ("guard_rewrite_1224" in [c["name"] for c in station["commands"]]) is sent
    assert len(asked) == (0 if mode == 2 else 1)
    if asked:
        assert "Home (1)" in asked[0]


async def test_a_confirmation_without_a_terminal_is_a_no(tmp_path: Path) -> None:
    def no_terminal(_question: str) -> str:
        raise EOFError

    async with Context(parse_args(["diagnose"]), env={}, prompt=no_terminal) as ctx:
        assert await commands._confirm(ctx, "?") is False
    async with Context(parse_args(["diagnose"]), env={}, prompt=lambda _q: " ") as ctx:
        assert await commands._confirm(ctx, "?") is False
    async with Context(parse_args(["diagnose"]), env={}, prompt=lambda _q: "YES") as ctx:
        assert await commands._confirm(ctx, "?") is True


@pytest.mark.usefixtures("account_views")
@pytest.mark.parametrize(
    ("raised", "aborted"),
    [
        (KeyboardInterrupt(), "interrupted"),
        (asyncio.CancelledError(), "interrupted"),
        (RuntimeError("bug"), "RuntimeError"),
    ],
)
async def test_diagnose_writes_a_partial_report_when_a_run_is_cut_short(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    raised: BaseException,
    aborted: str,
) -> None:
    async def cut(*_args: Any) -> None:
        raise raised

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    monkeypatch.setattr(commands, "_diagnose_webrtc", cut)
    out = tmp_path / "r.json"
    with pytest.raises(type(raised)):
        await run(["--host", "127.0.0.1", "diagnose", "--output", str(out)], tmp_path)
    report = json.loads(out.read_text())
    assert (report["complete"], report["aborted"]) == (False, aborted)
    assert len(report["stations"]) == 1  # the P2P read before the cut is kept
    assert "Partial report written" in capsys.readouterr().err


@pytest.mark.usefixtures("account_views")
async def test_diagnose_writes_no_report_when_the_login_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.exceptions import LoginVerificationError  # noqa: PLC0415

    async def refused(self: StubCloud, **kwargs: Any) -> None:
        raise LoginVerificationError("26006", code=26006)

    monkeypatch.setattr(StubCloud, "async_login", refused)
    out = tmp_path / "r.json"
    with pytest.raises(LoginVerificationError):
        await run(["diagnose", "--no-webrtc", "--output", str(out)], tmp_path)
    assert not out.exists()


@pytest.mark.usefixtures("account_views")
async def test_diagnose_answers_a_verification_code_in_the_same_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    logins: list[dict[str, Any]] = []

    async def challenged_once(self: StubCloud, **kwargs: Any) -> None:
        logins.append(kwargs)
        if not kwargs.get("verify_code"):
            raise LoginChallengeError("verify_code", login_id="")

    monkeypatch.setattr(StubCloud, "async_login", challenged_once)
    out = tmp_path / "r.json"
    argv = ["--host", "127.0.0.1", "diagnose", "--no-webrtc", "--output", str(out)]
    assert await run(argv, tmp_path, prompt=lambda _q: "123456") == 0
    assert [entry.get("verify_code") for entry in logins] == [None, "123456"]
    assert json.loads(out.read_text())["complete"] is True


@pytest.mark.usefixtures("account_views")
async def test_diagnose_goes_on_when_the_device_lists_fail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.exceptions import CommunicationError  # noqa: PLC0415

    async def down(self: Any, **kwargs: Any) -> Any:
        raise CommunicationError("cloud down")

    monkeypatch.setattr(client_module.EufySecurity, "async_discover", down)
    monkeypatch.setattr(StubCloud, "async_get_devices", down)
    out = tmp_path / "r.json"
    assert await run(["diagnose", "--no-webrtc", "--output", str(out)], tmp_path) == 0
    report = json.loads(out.read_text())
    assert report["errors"] == {"discover": "CommunicationError", "devices": "CommunicationError"}
    assert (report["complete"], report["stations"]) == (True, {})


async def test_a_p2p_station_that_fails_in_any_way_is_recorded_not_raised() -> None:
    station = Mock(connects_on_demand=False)
    station.async_update = AsyncMock(side_effect=RuntimeError("bug"))
    station.diagnostics = Mock(return_value={"model": "T8030"})
    assert await commands._diagnose_p2p(station) == {
        "model": "T8030",
        "read_errors": {"state": "RuntimeError"},
    }
    station.async_update = AsyncMock()
    station.async_get_storage = AsyncMock(side_effect=TimeoutError())
    station.diagnostics = Mock(side_effect=KeyError("x"))
    assert await commands._diagnose_p2p(station) == {
        "read_errors": {"storage": "TimeoutError", "diagnostics": "KeyError"}
    }


@pytest.mark.usefixtures("account_views")
async def test_diagnose_records_a_push_listener_that_does_not_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    async def slow(self: Any, **kwargs: Any) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect([]))
    monkeypatch.setattr(client_module.EufySecurity, "async_start", slow)
    monkeypatch.setattr(commands, "DIAGNOSE_PUSH_TIMEOUT", 0.05)
    out = tmp_path / "r.json"
    argv = ["diagnose", "--no-p2p", "--watch", "1", "--output", str(out)]
    assert await run(argv, tmp_path) == 0
    assert json.loads(out.read_text())["push"] == {"running": False, "error": "TimeoutError"}


@pytest.mark.usefixtures("account_views")
@pytest.mark.parametrize(
    "argv", [["--watch", "1", "--no-push"], [], ["--watch", "1", "--no-webrtc"]]
)
async def test_diagnose_starts_push_only_for_a_webrtc_watch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, argv: list[str]
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(client_module, "EufyCloudApi", WebRtcCloud)
    monkeypatch.setattr(diagnostics, "collect_station", _fake_collect([]))
    started = AsyncMock()
    monkeypatch.setattr(client_module.EufySecurity, "async_start", started)
    out = tmp_path / "r.json"
    assert await run(["diagnose", "--no-p2p", *argv, "--output", str(out)], tmp_path) == 0
    started.assert_not_called()
    assert "push" not in json.loads(out.read_text())


def test_diagnose_explain_names_the_opt_in_write() -> None:
    assert "--rewrite-guard-mode" in commands._DIAGNOSE_EXPLAIN
    assert "a write" in commands._DIAGNOSE_EXPLAIN
