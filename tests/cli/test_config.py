from __future__ import annotations

from pathlib import Path

import pytest

from eufy_home_security.cli.commands import COMMANDS
from eufy_home_security.cli.config import (
    default_store_path,
    parse_args,
)
from eufy_home_security.testing import SYNTHETIC


@pytest.mark.parametrize(
    "argv",
    [
        ["discover", "--timeout", "0.5", "--broadcast", "192.0.2.255"],
        ["login"],
        ["devices"],
        ["status", "--raw"],
        ["status", "--json"],
        ["storage", "--json"],
        ["guard"],
        ["guard", "set", "away"],
        ["settings"],
        ["set", "watermark_set", "1", "--device", SYNTHETIC.camera_sn],
        ["set", "time_system", "12h", "--channel", "255"],
        ["events", "--days", "3", "--table", "event_record_info", "--media-only", "--json"],
        ["image", "/zx/thumb.jpg", "--out", "x.jpg"],
        ["live", "--channel", "0", "--seconds", "5", "--out", "front"],
        ["live", "--device", SYNTHETIC.camera_sn, "--preset", "2", "--out", "front"],
        [
            "recording",
            "/zx/clip.zxvideo",
            "--device",
            SYNTHETIC.camera_sn,
            "--download",
            "--out",
            "c",
        ],
        ["snapshot", "--channel", "1", "--recording", "/zx/clip.zxvideo", "--out", "x.hevc"],
        ["monitor", "--no-push", "--json"],
    ],
)
def test_every_subcommand_parses(argv: list[str]) -> None:
    args = parse_args(argv)
    assert args.command == argv[0]
    assert args.command in COMMANDS


def test_global_options_work_before_and_after_the_subcommand() -> None:
    before = parse_args(
        [
            "--email",
            SYNTHETIC.email,
            "--station",
            SYNTHETIC.station_sn,
            "--host",
            SYNTHETIC.station_ip,
            "status",
        ]
    )
    after = parse_args(
        ["status", "--station", SYNTHETIC.station_sn, "-vv", "--local-port", "40000"]
    )
    assert (before.email, before.station, before.host) == (
        SYNTHETIC.email,
        SYNTHETIC.station_sn,
        SYNTHETIC.station_ip,
    )
    assert before.verbose == 0
    assert (after.station, after.verbose, after.local_port, after.email) == (
        SYNTHETIC.station_sn,
        2,
        40000,
        None,
    )


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_the_password_is_never_an_option(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        parse_args([command, "--help"])
    assert "--password" not in capsys.readouterr().out
    with pytest.raises(SystemExit) as info:
        parse_args(["--password", "secret", command])
    assert info.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["guard", "set"],
        ["guard", "get", "home"],
        ["guard", "arm"],
        ["monitor", "--no-push", "--no-p2p"],
        ["set", "mirror", "on", "--device", SYNTHETIC.camera_sn, "--channel", "0"],
        ["status", "--json", "--raw"],
        ["events", "--days", "-1"],
        ["events", "--days", "0"],
        ["history", "--days", "36501"],
        ["--local-port", "65536", "status"],
        ["status", "--local-port", "-1"],
        ["events", "--count", "0"],
        ["persons", "--count", "-5"],
        ["live", "--channel", "0", "--seconds", "0", "--out", "front"],
        ["discover", "--timeout", "0"],
        ["image", "/zx/thumb.jpg"],
        ["registry"],  # no such command
        ["--registry-override", "x.json", "status"],  # no such option
        ["status", "--registry-override", "x.json"],
    ],
)
def test_usage_errors_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        parse_args(argv)
    assert info.value.code == 2


def test_default_store_path_follows_xdg() -> None:
    assert default_store_path({"XDG_CONFIG_HOME": "/cfg"}) == Path("/cfg/eufy-security/cache.json")
    assert default_store_path({}) == Path("~/.config/eufy-security/cache.json").expanduser()
