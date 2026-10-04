from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine, Iterator
from typing import Any

import aiohttp
import pytest

from eufy_home_security._logging import SECRET_LOGGER, WIRE_LOGGER
from eufy_home_security.cli import app, main
from eufy_home_security.cli.commands import COMMANDS, Context
from eufy_home_security.cli.config import UsageError, parse_args
from eufy_home_security.exceptions import (
    AuthenticationError,
    CloudApiError,
    CommandNotAppliedError,
    CommandRejectedError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    LoginChallengeError,
    LoginLimitedError,
    ProtocolError,
    RateLimitedError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
)


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    package = logging.getLogger("eufy_home_security")
    level, wire, secrets = package.level, WIRE_LOGGER.level, SECRET_LOGGER.level
    yield
    package.setLevel(level)
    WIRE_LOGGER.setLevel(wire)
    SECRET_LOGGER.setLevel(secrets)


@pytest.mark.parametrize(
    ("exc", "needle"),
    [
        (LoginChallengeError("verify_code"), "run `eufy-security login`"),
        (RateLimitedError("too many"), "24 h"),
        (RateLimitedError("too fast", retry_after=1500), "nothing is sent to it for 25 min"),
        (LoginLimitedError("100028", retry_after=7200), "next login is allowed in 2.0 h"),
        (LoginLimitedError("budget"), "in a while"),
        (SessionReplacedError(code=26084), "ends the other client's session"),
        (AuthenticationError("bad password"), "check the e-mail and password"),
        (CloudApiError(26006, "nope"), "eufy cloud error: cloud error 26006"),
        (CommandNotAppliedError(1224), "station owner's"),
        (CommandRejectedError(1253, -104), "the station refused: command 1253 rejected"),
        (StationUnreachableError("no reply"), "--local-port"),
        (DeviceTimeoutError("slow"), "did not answer in time"),
        (CommunicationError("down"), "network error: down"),
        (HandshakeError("bad key"), "re-paired"),
        (ProtocolError("garbled"), "-vv"),
        (UnsupportedError("no"), "not supported: no"),
        (EufySecurityError("plain"), "plain"),
    ],
)
def test_errors_map_to_one_friendly_line(exc: EufySecurityError, needle: str) -> None:
    message = app.describe_error(exc)
    assert needle in message
    assert "\n" not in message


@pytest.mark.parametrize(
    ("exc", "code", "needle"),
    [
        (StationUnreachableError("no reply"), 1, "layer 2"),
        (UsageError("pick one"), 2, "error: pick one"),
        (aiohttp.ClientConnectionError("refused"), 1, "ClientConnectionError: refused"),
    ],
)
async def test_run_maps_exceptions_to_exit_codes(
    exc: Exception,
    code: int,
    needle: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failing(ctx: Context) -> int:
        raise exc

    monkeypatch.setitem(COMMANDS, "settings", failing)
    assert await app.run(parse_args(["settings"]), env={}) == code
    assert needle in capsys.readouterr().err


def test_main_runs_a_command_and_handles_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["settings"]) == 0
    assert "alarm_delay_away" in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert main(["guard", "set"]) == 2


def test_ctrl_c_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(coro: Coroutine[Any, Any, int]) -> int:
        coro.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "run", interrupted)
    assert main(["settings"]) == 130


def test_verbosity_wire_and_secret_logging() -> None:
    app.configure_logging(2, True, True)
    assert logging.getLogger("eufy_home_security").level == logging.DEBUG
    assert WIRE_LOGGER.level == SECRET_LOGGER.level == logging.DEBUG
    app.configure_logging(1, False, False)
    assert logging.getLogger("eufy_home_security").level == logging.INFO
    assert WIRE_LOGGER.level == SECRET_LOGGER.level == logging.WARNING
