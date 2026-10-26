"""Run every generator's ``--check`` in parallel: each regenerates from its inputs and
compares with the committed file(s), writing nothing.

    check_generated.py [NAME ...] [--skip NAME] [--jobs N]

``NAME`` picks generators by name (default: every one in :data:`CHECKS`); ``--jobs`` is
passed to ``gen_models.py`` (default: its own). Prints one line per check and the output
of each that fails; exits 0 when all pass, else 1. The model list
(``gen_app_models.py``) takes the app's input files as arguments and is not run here.
See docs/how-to/regenerate-models.md.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent

# name -> the script's arguments after ``python scripts/<name>.py``
CHECKS: Mapping[str, tuple[str, ...]] = {
    "gen_models": ("--check",),
    "gen_live_open": ("--check",),
    "gen_ptz": ("--check",),
    "gen_device_alarm": ("--check",),
    "gen_station_config": ("--check",),
    "gen_webrtc_routing": ("--check",),
    "gen_device_matrix": ("--check",),
    "gen_timezones": ("--check",),
}


def commands(names: Sequence[str], jobs: int | None = None) -> dict[str, list[str]]:
    """The command line of each named check."""
    out = {}
    for name in names:
        argv = [sys.executable, str(SCRIPTS / f"{name}.py"), *CHECKS[name]]
        if name == "gen_models" and jobs is not None:
            argv += ["--jobs", str(jobs)]
        out[name] = argv
    return out


def run_checks(checks: Mapping[str, Sequence[str]]) -> int:
    """Run ``checks`` (name -> command line) at once; report each in the given order.
    0 when every command exits 0, else 1."""

    def run(argv: Sequence[str]) -> tuple[int, str, float]:
        start = time.monotonic()
        done = subprocess.run(argv, capture_output=True, text=True, check=False)
        return done.returncode, done.stdout + done.stderr, time.monotonic() - start

    with ThreadPoolExecutor(max_workers=max(1, len(checks))) as pool:
        results = dict(zip(checks, pool.map(run, checks.values()), strict=True))
    failed = 0
    for name, (rc, output, seconds) in results.items():
        if rc == 0:
            print(f"ok      {name} ({seconds:.1f} s)")
            continue
        failed += 1
        print(f"FAILED  {name} (exit {rc}, {seconds:.1f} s)")
        for line in output.rstrip().splitlines():
            print(f"    {line}")
    print(f"{len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run every generator's --check in parallel.")
    parser.add_argument("names", nargs="*", metavar="NAME", help=", ".join(CHECKS))
    parser.add_argument("--skip", action="append", default=[], choices=list(CHECKS))
    parser.add_argument("--jobs", type=int, help="gen_models.py --jobs")
    args = parser.parse_args(argv)
    unknown = sorted(set(args.names) - set(CHECKS))
    if unknown:
        parser.error(f"no such check: {' '.join(unknown)}")
    names = [n for n in (args.names or CHECKS) if n not in args.skip]
    return run_checks(commands(names, args.jobs))


if __name__ == "__main__":
    sys.exit(main())
