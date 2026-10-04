"""The ``eufy-security`` command-line tool (argparse only, no extra dependencies)."""

from __future__ import annotations

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    """The ``eufy-security`` console script.

    Parses first and only then imports the runner: ``--help`` and argparse's
    own usage errors never load asyncio, logging or the library.
    """
    from .config import EXIT_USAGE, parse_args  # noqa: PLC0415

    try:
        args = parse_args(argv)
    except SystemExit as exc:  # --help, or a usage error argparse already printed
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    from .app import main_parsed  # noqa: PLC0415

    return main_parsed(args)
