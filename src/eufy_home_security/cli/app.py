"""Entry point: parse, configure logging, run one command, map errors to exit codes."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Mapping

from .._logging import set_secret_logging, set_wire_logging
from ..exceptions import (
    AuthenticationError,
    CipherUnusableError,
    CloudError,
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
    SessionRejectedError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
)
from .commands import COMMANDS, Context, Prompt
from .config import EXIT_ERROR, EXIT_INTERRUPTED, EXIT_USAGE, UsageError

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def _duration(seconds: float | None) -> str:
    """``retry_after`` for a person: "40 s", "25 min", "2.0 h", or "a while"."""
    if seconds is None:
        return "a while"
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 90 * 60:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def describe_error(exc: EufySecurityError) -> str:
    """A one-line, actionable message for a library error."""
    match exc:
        case LoginChallengeError():
            return (
                f"the eufy cloud needs a {exc.kind.replace('_', ' ')} to log in: "
                "run `eufy-security login` first"
            )
        case LoginLimitedError():
            return (
                f"the eufy cloud is not taking logins for this account ({exc}); the next login "
                f"is allowed in {_duration(exc.retry_after)} — repeated failed logins lock the "
                "account for 24 h"
            )
        case RateLimitedError():
            return (
                f"the eufy cloud is rate-limiting this account ({exc}); nothing is sent to it "
                f"for {_duration(exc.retry_after)} — repeated failed logins lock the account "
                "for 24 h"
            )
        case SessionReplacedError():
            return (
                f"the eufy cloud ended this session: {exc}. `eufy-security login` logs in "
                "again, which ends the other client's session — give each client its own "
                "account shared from the owner"
            )
        case SessionRejectedError():
            return (
                f"the eufy cloud refused the session right after a fresh login ({exc}); the "
                "e-mail and password were accepted — retry later"
            )
        case AuthenticationError():
            return f"the eufy cloud rejected the login ({exc}); check the e-mail and password"
        case CloudError():
            return f"eufy cloud error: {exc}"
        case CommandNotAppliedError():
            return (
                f"{exc}. The station silently drops commands whose account id is not the "
                "station owner's; a shared member must send the owner's id (the library "
                "fetches it from the cloud — try again after `eufy-security devices`)"
            )
        case CommandRejectedError():
            return f"the station refused: {exc}"
        case StationUnreachableError():
            return (
                f"{exc}. The station must be reachable at layer 2 (same LAN/VLAN, UDP "
                "broadcast to port 32108); pass --host IP to skip the broadcast, and "
                "if a firewall filters the replies, allow them with a fixed --local-port N"
            )
        case DeviceTimeoutError():
            return f"the station did not answer in time: {exc}"
        case CommunicationError():
            return f"network error: {exc}"
        case CipherUnusableError():
            return (
                f"the station's cipher key cannot be used: {exc}. eufy serves the same key on "
                "every fetch, so it is not re-fetched; a station firmware update or a library "
                "update may cure it (please report with -vv)"
            )
        case HandshakeError():
            return (
                f"could not establish the P2P session: {exc}. The station may have been "
                "re-paired; the cipher key is re-fetched at most once per cooldown — retry later"
            )
        case ProtocolError():
            return f"unexpected data from the station (please report with -vv): {exc}"
        case UnsupportedError():
            return f"not supported: {exc}"
    return str(exc)


def configure_logging(verbose: int, wire: bool, secrets: bool) -> None:
    level = logging.WARNING if verbose <= 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(level=logging.WARNING, format=_LOG_FORMAT, stream=sys.stderr)
    logging.getLogger("eufy_home_security").setLevel(level)
    set_wire_logging(wire)
    set_secret_logging(secrets)


async def run(
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    prompt: Prompt | None = None,
    secret_prompt: Prompt | None = None,
) -> int:
    """Run the parsed command; returns the exit code (KeyboardInterrupt propagates)."""
    ctx = Context(args=args, env=os.environ if env is None else env)
    if prompt is not None:
        ctx.prompt = prompt
    if secret_prompt is not None:
        ctx.secret_prompt = secret_prompt
    try:
        async with ctx:
            return await COMMANDS[args.command](ctx)
    except UsageError as err:
        print(f"eufy-security: error: {err}", file=sys.stderr)
        return EXIT_USAGE
    except EufySecurityError as err:
        print(f"eufy-security: {describe_error(err)}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as err:
        if not _is_network_error(err):
            raise
        print(f"eufy-security: {type(err).__name__}: {err}", file=sys.stderr)
        return EXIT_ERROR


def _is_network_error(err: BaseException) -> bool:
    """An OSError, or an aiohttp ClientError (only possible once aiohttp is loaded)."""
    if isinstance(err, OSError):
        return True
    aiohttp = sys.modules.get("aiohttp")
    return aiohttp is not None and isinstance(err, aiohttp.ClientError)


def main_parsed(args: argparse.Namespace) -> int:
    """Run parsed arguments to completion (see :func:`eufy_home_security.cli.main`)."""
    configure_logging(args.verbose, args.wire, args.secrets)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
