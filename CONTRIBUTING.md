# Contributing

## Setup

```
uv sync                         # creates .venv with the dev tools
uv run prek install             # optional: run the hooks on every commit
```

## The loop

```
uv run pytest -n auto           # unit + protocol tests, one worker per core (no hardware, no network)
uv run ruff check --fix && uv run ruff format
uv run mypy                     # strict — keep it clean
uv run prek run --all-files     # everything the hooks run
```

`-n auto` runs the tests on parallel workers (pytest-xdist, work-stealing). Leave it
out for a single test, `--pdb`, or the live tests.

Live tests talk to a real station or the eufy cloud and are opt-in:
`EUFY_LIVE=1 uv run pytest -m live`, without `-n`: they share one real station.

### The denylist check

`scripts/check_denylist.py` (a hook, and `tests/test_denylist.py`) fails when a
tracked file contains an entry of the private denylist, `.work/denylist.txt` (or the
file `EUFY_DENYLIST` names). It also **fails when that file is missing**, so a lost
list is never mistaken for a clean tree. It only warns and passes when `CI` is set,
or when you opt out explicitly because you do not have the private list:

```
EUFY_DENYLIST_SKIP=1 uv run pytest
EUFY_DENYLIST_SKIP=1 uv run prek run --all-files
```

### Dev builds

Rebuilding the wheel with an unchanged version and reinstalling it is a silent
no-op, so a test host can keep running old code. For a build you deploy to test,
stamp the commit into the version as a PEP 440 local label (`0.1.0+g<sha>`, with
`.dirty` for uncommitted edits); `pyproject.toml` is not changed:

```
VIRTUAL_ENV= uv run python scripts/dev_build.py        # → dist/eufy_home_security-0.1.0+g<sha>-py3-none-any.whl
uv pip install --reinstall-package eufy-home-security dist/eufy_home_security-0.1.0+g*.whl
python -c "import eufy_home_security as e; print(e.__version__)"   # 0.1.0+g<sha>
```

Pass `--reinstall-package` whenever the version did not change (a plain `uv build`).
Local labels are for dev builds only: PyPI rejects them, and release builds carry
the version release-please sets. When `CACHE_LAYOUT_VERSION` changes, name it in the
commit (a `feat!`/`fix` body) so the changelog shows it: it costs every install one
unattended login.

### Build and release

```
uv build --no-sources                                   # dist/: sdist, then the wheel built from it
uv run --no-project python scripts/check_dist.py --dist dist
```

`check_dist.py` is what CI runs on every push: `twine check --strict`,
`check-wheel-contents`, an sdist that holds only the build inputs, a wheel rebuilt
from the sdist that is byte-identical, and the wheel and the sdist each installed
into a clean venv (import, package data, `eufy-security --help`), plus
`uv tool install` and `uvx`. Without `--dist` it builds into a temporary directory.
Builds are reproducible: `uv_build` fixes timestamps and ownership, so the same tree
gives the same bytes.

The sdist carries the package, `pyproject.toml`, README, LICENSE and CHANGELOG; tests
and docs stay in the repository, because they need its vendor corpus, `scripts/` and
git. Releases: release-please opens a release PR from the conventional commits;
merging it tags `vX.Y.Z` (a maintainer-pushed `v*` tag that matches the project
version releases the same way), and `.github/workflows/release.yml` builds once, runs
`check_dist.py` on that build and publishes exactly those files to PyPI by trusted
publishing (`pypi` environment, no token), with PEP 740 attestations.

## Ground rules

- **Asyncio only**, no blocking I/O on the event loop, no Home Assistant imports.
- **Typed errors** from `eufy_home_security.exceptions`; never report success on a
  transport ACK alone.
- **Tests mirror `src/`** — one test module per source module, each scenario in
  one place. Protocol tests run against the loopback fake station
  (`eufy_home_security.testing.FakeStation`, `src/eufy_home_security/testing/station.py`).
- **No real identifiers.** Serials, P2P ids, account ids, LAN addresses, names —
  none of it goes into code, tests, fixtures or docs. Use the synthetic identities
  of `eufy_home_security.testing.SYNTHETIC`, and build fixtures by encrypting
  synthetic plaintext with fake keys rather than committing captured traffic.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `test:`, `chore:` …); the
  changelog and version are generated from them.

## Adding or verifying a device

See [docs/how-to/add-a-device.md](docs/how-to/add-a-device.md). In short: add the
model and profile to `src/eufy_home_security/devices/` with honest `Evidence`
(settings come from the generated per-model file), add tests, and regenerate the
support matrix (`uv run python scripts/gen_device_matrix.py`). An entry becomes *verified* only
with evidence from real hardware. Open the pull request with the device template
(`?template=new_device.md`).

## Where things go

- `docs/` — functional documentation that ships with the project.
- `.work/` — your private scratch space (git-ignored here; keep it as its own
  repository). Probes, captures and investigation notes live there, never in the
  main tree.
