"""A content-addressed store of driver answers for ``scripts/gen_models.py``.

A driver job's reply depends only on the Node runtime and its environment, the driver
source, the handler file and the job's requests: the driver runs every job in a fresh
sandbox with a seeded ``Math.random`` and a fixed clock. The store keys each reply by the
SHA-256 of exactly those (:func:`runtime_version`, the driver's and the handler's bytes,
the requests as the driver receives them), so a run whose jobs were asked before replays
their replies without Node, and a changed input asks Node again for the jobs it touches
only.

One file per product, ``<root>/<PN>.answers``: a header line, then one record per job,
``<key> <digest> <size>\\n`` followed by ``size`` bytes of the zlib-compressed reply JSON;
``digest`` is the SHA-256 of that JSON. A record that does not decompress, whose JSON
does not match its digest, or whose reply does not fit the job is asked again; a damaged
or truncated file loses the records from the damage on. After a product's run its file
holds the jobs that run asked (and, when the product failed, the earlier records as
well), written to a temporary file and renamed into place.

The replies are derived from vendor code: the store lives in the private cache
(``.work/cache``), never in the repository or the package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HEADER = b"gen_models answers 1\n"
LEVEL = 1  # zlib level: replies are repetitive JSON, level 1 keeps writing cheap
# Besides every LC_* variable: the environment a handler's reply can depend on.
RUNTIME_ENV = frozenset({"TZ", "LANG", "LANGUAGE", "NODE_OPTIONS", "NODE_ICU_DATA"})
_RECORD = re.compile(rb"([0-9a-f]{64}) ([0-9a-f]{64}) ([0-9]{1,12})")

type Ask = Callable[[Mapping[str, Any]], list[Any]]


def file_digest(path: Path) -> str:
    """SHA-256 of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Node's build (Node, V8, ICU, time zone data) and the time zone and locale it resolves,
# wherever they come from (TZ, LANG, /etc/localtime).
RUNTIME_PROBE = (
    "const o = Intl.DateTimeFormat().resolvedOptions();"
    " JSON.stringify([process.versions, o.timeZone, o.locale])"
)


def runtime_version(node: str, env: Mapping[str, str] | None = None) -> str:
    """The runtime part of every key: what the Node binary ``node`` reports for
    ``RUNTIME_PROBE`` under ``env`` (default: this process's environment, which the
    driver's workers inherit), and the variables of ``env`` that can change a handler's
    reply: time zone, locale and Node options."""
    env = os.environ if env is None else env
    probe = subprocess.run(
        [node, "-p", RUNTIME_PROBE],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env=dict(env),
    ).stdout.strip()
    settings = sorted((k, v) for k, v in env.items() if k in RUNTIME_ENV or k.startswith("LC_"))
    return json.dumps([probe, settings])


@dataclass
class Stats:
    """Jobs per outcome: replayed from the store, asked of Node and stored, asked of Node
    without a key (not stored: the runtime, driver or handler could not be read); and
    damaged spots found in the store (a damaged record, or a file cut short or of another
    format)."""

    replayed: int = 0
    asked: int = 0
    unkeyed: int = 0
    damaged: int = 0

    def add(self, other: Stats) -> None:
        self.replayed += other.replayed
        self.asked += other.asked
        self.unkeyed += other.unkeyed
        self.damaged += other.damaged


@dataclass
class _Product:
    name: str
    path: Path
    stored: dict[str, tuple[str, bytes]]  # key -> (digest, compressed reply)
    used: dict[str, tuple[str, bytes]] = field(default_factory=dict)
    changed: bool = False


class AnswerStore:
    """Replays driver replies stored under ``root`` (None: every job goes to Node).

    ``runtime`` gives the runtime text (:func:`runtime_version`), asked once per store
    (a failure too: it is printed once to stderr, and no job is stored from then on), and
    ``driver`` is the driver source; both are part of every key. Between ``open(name)``
    and ``close(ok=...)`` the jobs of one product go through ``run``; outside them ``run``
    asks Node directly.
    """

    def __init__(self, root: Path | None, *, driver: Path, runtime: Callable[[], str]) -> None:
        self.root = root
        self._driver = driver
        self._runtime = runtime
        self._runtime_text: str | None = None
        self._runtime_failed = False
        self._prefix: dict[str, bytes] = {}  # handler path -> key prefix, per product
        self._product: _Product | None = None
        self.stats = Stats()

    def open(self, name: str) -> None:
        """Start the product ``name``: load its stored replies. The driver and handler
        files are read again for each product."""
        self.stats = Stats()
        self._prefix = {}
        if self.root is None:
            self._product = None
            return
        path = self.root / f"{name}.answers"
        stored, damaged = read_records(path)
        self.stats.damaged += damaged
        self._product = _Product(name, path, stored, changed=damaged > 0)

    def close(self, *, ok: bool) -> str | None:
        """End the product: write its file when it changed. ``ok``: the product was
        generated, so records its run did not ask are dropped; otherwise, or when a job
        went to Node without a key (what it would have replayed is unknown), they are
        kept. Returns a notice when the file could not be written (the run goes on)."""
        product, self._product = self._product, None
        if product is None:
            return None
        prune = ok and not self.stats.unkeyed
        keep = dict(product.used) if prune else {**product.stored, **product.used}
        if not product.changed and keep.keys() == product.stored.keys():
            return None
        try:
            write_records(product.path, keep)
        except OSError as err:
            return f"{product.name}: answers not stored: {err}"
        return None

    def run(self, job: Mapping[str, Any], ask: Ask) -> list[Any]:
        """The replies to ``job`` (``{"handler", "requests"}``): stored ones when the store
        holds the job's key, else ``ask(job)``'s, which are stored."""
        product = self._product
        requests = job["requests"]
        key = None if product is None else self._key(Path(job["handler"]), requests)
        if product is None:
            return ask(job)
        if key is None:
            replies = ask(job)
            self.stats.unkeyed += 1
            return replies
        found = product.used.get(key) or product.stored.get(key)
        if found is not None:
            replies = _replies(*found, len(requests))
            if replies is not None:
                product.used[key] = found
                self.stats.replayed += 1
                return replies
            self.stats.damaged += 1  # the reply asked below replaces the record
        replies = ask(job)
        text = json.dumps(replies).encode()
        digest = hashlib.sha256(text).hexdigest()
        product.used[key] = (digest, zlib.compress(text, LEVEL))
        product.changed = True
        self.stats.asked += 1
        return replies

    def _key(self, handler: Path, requests: Any) -> str | None:
        """The job's key; None when the runtime cannot be asked or the driver or the
        handler cannot be read (the job then goes to Node, which reports it)."""
        prefix = self._prefix.get(str(handler))
        if prefix is None:
            runtime = self._runtime_part()
            try:
                parts = (runtime, file_digest(self._driver), file_digest(handler))
            except OSError:
                return None
            if runtime is None:
                return None
            prefix = "\0".join((HEADER.decode().strip(), *parts, "")).encode()
            self._prefix[str(handler)] = prefix
        # the requests as DriverPool.run sends them (json.dumps of the job)
        return hashlib.sha256(prefix + json.dumps(requests).encode()).hexdigest()

    def _runtime_part(self) -> str | None:
        """The runtime text, asked on the first call only; None when that failed."""
        if self._runtime_text is None and not self._runtime_failed:
            try:
                self._runtime_text = self._runtime()
            except (OSError, subprocess.SubprocessError) as err:
                self._runtime_failed = True
                print(
                    f"answers: cannot ask the Node runtime ({err}); no job is stored",
                    file=sys.stderr,
                )
        return self._runtime_text


def _replies(digest: str, blob: bytes, count: int) -> list[Any] | None:
    """A stored reply list of ``count`` replies, or None when the record is damaged."""
    try:
        text = zlib.decompress(blob)
    except zlib.error:
        return None
    if hashlib.sha256(text).hexdigest() != digest:
        return None
    try:
        replies = json.loads(text)
    except ValueError:
        return None
    return replies if isinstance(replies, list) and len(replies) == count else None


def read_records(path: Path) -> tuple[dict[str, tuple[str, bytes]], int]:
    """The records of the file at ``path`` (none when it is missing or not a store file)
    and how many damaged spots cut it short (0 or 1)."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return {}, 0
    except OSError:
        return {}, 1
    if not data.startswith(HEADER):
        return {}, 1
    records: dict[str, tuple[str, bytes]] = {}
    pos = len(HEADER)
    while pos < len(data):
        end = data.find(b"\n", pos, pos + 160)
        match = _RECORD.fullmatch(data, pos, end) if end > 0 else None
        size = int(match[3]) if match else -1
        if match is None or end + 1 + size > len(data):
            return records, 1  # a damaged or truncated record: the rest is unreadable
        records[match[1].decode()] = (match[2].decode(), data[end + 1 : end + 1 + size])
        pos = end + 1 + size
    return records, 0


def write_records(path: Path, records: Mapping[str, tuple[str, bytes]]) -> None:
    """Write ``records`` to ``path`` through a temporary file renamed into place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as out:
            out.write(HEADER)
            for key, (digest, blob) in sorted(records.items()):
                out.write(f"{key} {digest} {len(blob)}\n".encode())
                out.write(blob)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
