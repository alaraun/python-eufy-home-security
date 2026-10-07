"""Persistence for what is expensive to re-derive.

Logging in to the eufy cloud is slow, rate-limited, and locks the account for 24 h
after repeated failures, so everything it yields is cached: the install identity
(``openudid``), cloud sessions, per-station owner ids and cipher keys, and the
FCM push registration — and the account password, so a lost session logs in again
unattended.

The library never decides *where* that lives. It takes a :class:`Store` — anything
with ``async_load()`` / ``async_save(data)``. Home Assistant's
``homeassistant.helpers.storage.Store`` already has exactly that shape and can be
passed in directly; :class:`JsonFileStore` serves the CLI and scripts, and
:class:`MemoryStore` serves tests.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import secrets
import tempfile
import time
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from ._logging import redact_serial
from .cloud.const import (
    CIPHER_ID_P2P,
    DEFAULT_REGION,
    KEY_REFRESH_SLOW_RETRY,
    LOCKOUT_HOLD_OFF_SECONDS,
    REGIONS,
    region_from_mega_domain,
)
from .cloud.models import REGION_KEY, device_cache_entry
from .devices.types import connects_on_demand

CACHE_VERSION = 2
#: The public name of :data:`CACHE_VERSION`. A change without a migration from the
#: previous version costs every install one unattended login (see :class:`SessionCache`),
#: so a deploy can warn before it. Version 1 is migrated.
CACHE_LAYOUT_VERSION: Final = CACHE_VERSION

#: How long :meth:`SessionCache.schedule_save` lets changes gather before it writes.
#: Only push delivery state (the dedupe ring, guard-mode stamps) is saved this way:
#: losing the last few seconds of it costs a redelivered push, not a login.
DELIVERY_STATE_SAVE_DELAY: Final = 30.0


class SectionPrivacy(StrEnum):
    """Whether a top-level cache section's contents may leave the library as they are."""

    REDACTED = "redacted"
    """Secrets or identifiers: only field names, counts and presence are ever reported."""
    SAFE = "safe"
    """Versions and timestamps only."""


#: Every top-level key of the cache document, classified. A key missing here is
#: reported by name only (``unclassified_sections``), and the guard test fails.
CACHE_SECTIONS: Final[Mapping[str, SectionPrivacy]] = MappingProxyType(
    {
        "version": SectionPrivacy.SAFE,
        "account": SectionPrivacy.REDACTED,
        "openudid": SectionPrivacy.REDACTED,
        "password": SectionPrivacy.REDACTED,
        "cloud": SectionPrivacy.REDACTED,
        "push": SectionPrivacy.REDACTED,
        "devices": SectionPrivacy.REDACTED,
        "stations": SectionPrivacy.REDACTED,
        "replaced": SectionPrivacy.SAFE,
        "refresh_attempts": SectionPrivacy.SAFE,
        "throttle": SectionPrivacy.SAFE,
    }
)

# What a CACHE_VERSION change keeps for the same account. Everything else is
# re-derived at the cost of one login; these let that login happen unattended (the
# password), within the cloud's limits (the hold-off and the login budget), and never
# after another client took the session over (the replaced latch).
_KEPT_ACROSS_VERSIONS = ("password", "throttle", "replaced")
# What async_forget_account keeps: the throttle state, so removing and re-adding an
# account cannot reset the cloud's limits (the install identity is kept separately).
_KEPT_WHEN_FORGOTTEN = ("version", "account", "throttle")
# Older layouts SessionCache migrates on load instead of dropping them.
_MIGRATED_VERSIONS: Final = (1,)
# Top-level section of the session-replaced latch.
_REPLACED = "replaced"

_LOGGER = logging.getLogger(__name__)


@runtime_checkable
class Store(Protocol):
    """Where the cache is persisted."""

    async def async_load(self) -> dict[str, Any] | None:
        """Return the stored document, or None if nothing has been stored."""
        ...

    async def async_save(self, data: dict[str, Any]) -> None:
        """Replace the stored document."""
        ...


class MemoryStore:
    """A store that lives only as long as the process."""

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self.data = data

    async def async_load(self) -> dict[str, Any] | None:
        return json.loads(json.dumps(self.data)) if self.data is not None else None

    async def async_save(self, data: dict[str, Any]) -> None:
        self.data = json.loads(json.dumps(data))


class JsonFileStore:
    """A JSON file, written atomically and readable only by its owner."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).expanduser()

    async def async_load(self) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._load)

    async def async_save(self, data: dict[str, Any]) -> None:
        await asyncio.to_thread(self._save, data)

    def _load(self) -> dict[str, Any] | None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        try:
            doc = json.loads(text)
        except ValueError:  # JSONDecodeError and UnicodeDecodeError both
            # An empty or truncated file must not wedge every later start: move it
            # aside (kept for inspection) and start from nothing.
            aside = self.path.with_name(f"{self.path.name}.corrupt")
            os.replace(self.path, aside)
            _LOGGER.warning("cache file was not valid JSON; moved it to %s", aside)
            return None
        return doc if isinstance(doc, dict) else None

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


async def async_cached_account(store: Store) -> str | None:
    """The account (e-mail) whose session ``store`` holds, if it holds one."""
    doc = await store.async_load() or {}
    readable = doc.get("version") in (CACHE_VERSION, *_MIGRATED_VERSIONS)
    account = doc.get("account") if readable else None
    return account if isinstance(account, str) and account else None


async def async_forget_account(store: Store, *, keep_install_identity: bool = True) -> None:
    """Remove every account secret and cloud-derived value from ``store``.

    Drops the password, the cloud session, the session-replaced latch, station keys
    and owner ids, the device list, the push registration and the refresh stamps.
    Keeps ``throttle`` (with the ``account`` it belongs to), so removing and re-adding
    the account cannot reset the hold-offs or the login budget; those stamps expire by
    themselves. Keeps ``openudid`` unless ``keep_install_identity`` is False. Never
    contacts the cloud; call it instead of deleting the store.
    """
    doc = await store.async_load()
    if not doc:
        return
    kept = {key: doc[key] for key in _KEPT_WHEN_FORGOTTEN if key in doc}
    if keep_install_identity and doc.get("openudid"):
        kept["openudid"] = doc["openudid"]
    await store.async_save(kept)
    _LOGGER.info("forgot the cached account data; kept %s", sorted(kept))


class SessionCache:
    """Typed access to the cached document, bound to one account.

    The document is namespaced so each subsystem owns its own section::

        {"version": 2, "account": "<email, lower-case>", "openudid": "…", "password": "…",
         "cloud": {"sessions": {"<region>": {...}}, "listed": {"<region>": {...}}},
         "push": {...}, "replaced": {"at": <epoch s>},
         "devices": [{..., "cloud_region": "<region>"}, …],
         "stations": {"<serial>": {"account_id": "…", "ciphers": {"40": "…"}, "cipher_id": 40,
                                   "rsa_ciphers": {"40": "…"},
                                   "refresh_attempts": {"cipher": <epoch s>},
                                   "key_refresh": <epoch s>,
                                   "dsk": {"key": "…", "expiration": <epoch s>},
                                   "presets": {"<camera serial>": [{...}, …]}}},
         "refresh_attempts": {"owner": <epoch s>},
         "throttle": {"requests": <epoch s>, "login": {"<region>": <epoch s>},
                      "logins": {"<region>": [<epoch s>, …]}}}

    Everything except ``openudid`` is scoped to ``account``: loading the cache for a
    different account discards the account-scoped part, so one install can never
    reuse another account's session or keys. A document of another ``version`` keeps
    only ``openudid``, the password, the throttle state and the session-replaced
    latch; the rest is fetched again. Version 1 (one session, flat in ``cloud``) is
    migrated: its session and devices belong to the region it was logged in to.

    The document holds the account password, the cloud session and each station's
    key: keep the store private.
    """

    def __init__(self, store: Store, account: str) -> None:
        self._store = store
        self._account = account.strip().lower()
        self._doc: dict[str, Any] = {}
        self._loaded = False
        self._lock = asyncio.Lock()
        self._pending_save: asyncio.Task[None] | None = None

    @property
    def account(self) -> str:
        """The account (e-mail, normalised) this cache belongs to."""
        return self._account

    @property
    def loaded(self) -> bool:
        """Whether the stored document has been read in (by load or a first save)."""
        return self._loaded

    async def async_load(self) -> None:
        """Load the document from the store (call once before use)."""
        self._doc = await self._read_store()
        self._loaded = True

    async def _read_store(self) -> dict[str, Any]:
        """The stored document, reduced to what this account may see."""
        doc = await self._store.async_load() or {}
        same_account = doc.get("account") == self._account
        if isinstance(doc.get("devices"), list):
            doc["devices"] = _device_entries(doc["devices"])  # fields outside the allowlist go
        if not doc:
            _LOGGER.debug("session cache: nothing stored yet")
        elif doc.get("version") in _MIGRATED_VERSIONS and same_account:
            region = _migrate_v1(doc)
            _LOGGER.info(
                "session cache: version 1 migrated; its session is the %s region's", region
            )
        elif doc.get("version") != CACHE_VERSION or not same_account:
            kept = {k: doc[k] for k in _KEPT_ACROSS_VERSIONS if same_account and k in doc}
            if doc.get("openudid"):
                kept["openudid"] = doc["openudid"]
            _LOGGER.info(
                "session cache is for %s; keeping only %s",
                f"version {doc.get('version')}, not {CACHE_VERSION}"
                if same_account
                else "another account",
                sorted(kept),
            )
            doc = kept
        else:
            _LOGGER.debug("session cache loaded: %s", _describe(doc))
        doc["version"] = CACHE_VERSION
        doc["account"] = self._account
        return doc

    async def async_save(self) -> None:
        """Persist the document.

        A save before any load first merges the stored document underneath, so a
        caller that skipped :meth:`async_load` cannot overwrite a good cache with a
        near-empty one (and the stored ``openudid`` is kept). The document is
        snapshotted on the loop, under the lock, so a store that writes from a
        worker thread never sees it change mid-dump. It writes whatever a
        :meth:`schedule_save` was waiting for, so that pending save is cancelled.
        """
        pending, self._pending_save = self._pending_save, None
        if pending is not None:
            pending.cancel()  # still sleeping: _save_later clears the handle before it writes
        async with self._lock:
            if not self._loaded:
                self._doc = _merge_over(await self._read_store(), self._doc)
                self._loaded = True
            snapshot = copy.deepcopy(self._doc)
            await self._store.async_save(snapshot)
        _LOGGER.debug("session cache saved: %s", _describe(snapshot))

    def schedule_save(self, delay: float = DELIVERY_STATE_SAVE_DELAY) -> None:
        """Persist the document within ``delay`` seconds, coalescing repeated calls.

        For state whose loss costs little and which changes often (push delivery
        state). Everything else saves at once with :meth:`async_save`, which also
        writes what a pending scheduled save was waiting for. A failed write is
        logged, not raised. Outside a running loop it does nothing: the next save
        persists the change.
        """
        if self._pending_save is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._pending_save = loop.create_task(
            self._save_later(delay), name="eufy-security-cache-save"
        )

    async def _save_later(self, delay: float) -> None:
        await asyncio.sleep(delay)
        self._pending_save = None  # from here on the write must not be cancelled
        try:
            await self.async_save()
        except Exception:
            _LOGGER.warning("session cache not saved", exc_info=True)

    def redacted_summary(
        self, *, station_details: Mapping[str, Mapping[str, Any]] | None = None
    ) -> dict[str, Any]:
        """What the document holds, JSON-safe and secret-free, for diagnostics.

        The stored version, the sections present, which fields the cloud session and
        the push registration hold (names, never values), the number of cached devices,
        and per station (keyed by :func:`redact_serial`) whether the owner account id
        and the P2P cipher key are cached and whether the station named the cipher id
        (``cipher_id_named``), merged with ``station_details[serial]``. A
        section not in :data:`CACHE_SECTIONS` is listed by name only. Never a password,
        token, key, openudid, user id, push credential, full serial, DID or IP.
        """
        doc = self._doc
        version = doc.get("version")
        devices = doc.get("devices")
        details = station_details or {}
        stations: dict[str, dict[str, Any]] = {}
        for serial, label in _unique_serial_labels(self.station_serials()).items():
            entry = doc["stations"][serial]
            entry = entry if isinstance(entry, dict) else {}
            ciphers = entry.get("ciphers")
            ciphers = ciphers if isinstance(ciphers, dict) else {}
            cipher_id = self.station_cipher_id(serial)
            stations[label] = {
                "account_id_cached": _present(entry.get("account_id")),
                "cipher_id": cipher_id,
                "cipher_id_named": self.station_named_cipher_id(serial) is not None,
                "cipher_cached": _present(ciphers.get(str(cipher_id))),
                **details.get(serial, {}),
            }
        return {
            "version": version
            if isinstance(version, int) and not isinstance(version, bool)
            else None,
            "sections": sorted(key for key in doc if key in CACHE_SECTIONS),
            "unclassified_sections": sorted(key for key in doc if key not in CACHE_SECTIONS),
            "password_cached": self.password is not None,
            "cloud_fields": _present_fields(doc.get("cloud")),
            "cloud_sessions": {
                region: _present_fields(session)
                for region, session in self.cloud_sessions().items()
            },
            "push_fields": _present_fields(doc.get("push")),
            "device_count": len(devices) if isinstance(devices, list) else None,
            "stations": stations,
        }

    # ── install identity ─────────────────────────────────────────────────────

    @property
    def openudid(self) -> str:
        """This install's eufy identity: 16 lowercase hex, minted once, kept forever.

        Never reuse a phone's or another install's value — the backend treats it as
        the device identity and has no way to list or unregister devices.
        """
        value = self._doc.get("openudid")
        if not isinstance(value, str) or not value:
            value = secrets.token_hex(8)
            self._doc["openudid"] = value
        return value

    # ── credentials ──────────────────────────────────────────────────────────

    @property
    def password(self) -> str | None:
        """The password of the last successful login, if one is kept."""
        value = self._doc.get("password")
        return value if isinstance(value, str) and value else None

    def set_password(self, password: str) -> None:
        self._doc["password"] = password

    def drop_password(self) -> None:
        self._doc.pop("password", None)

    # ── subsystem sections ───────────────────────────────────────────────────

    def section(self, name: str) -> dict[str, Any]:
        """A mutable, subsystem-owned section (``"cloud"``, ``"push"`` …)."""
        return _subsection(self._doc, name)

    def cloud_session(self, region: str) -> dict[str, Any]:
        """The mutable cloud session section of ``region`` (``cloud.sessions.<region>``)."""
        return _subsection(_subsection(self.section("cloud"), "sessions"), region)

    def cloud_sessions(self) -> dict[str, dict[str, Any]]:
        """Every stored region session by region, without creating a section."""
        cloud = self._doc.get("cloud")
        sessions = cloud.get("sessions") if isinstance(cloud, dict) else None
        if not isinstance(sessions, dict):
            return {}
        return {r: s for r, s in sessions.items() if isinstance(s, dict)}

    def station(self, serial: str) -> dict[str, Any]:
        """The mutable per-station section."""
        return _subsection(self.section("stations"), serial)

    def station_account_id(self, serial: str) -> str | None:
        """The owner id commands to ``serial`` must carry, if cached."""
        value = self.station(serial).get("account_id")
        return value if isinstance(value, str) and value else None

    def set_station_account_id(self, serial: str, account_id: str) -> None:
        self.station(serial)["account_id"] = account_id

    def cipher_key(self, serial: str, cipher_id: int) -> str | None:
        """The cached ECC private key (hex) of ``cipher_id`` for ``serial``."""
        value = self.station(serial).get("ciphers", {}).get(str(cipher_id))
        return value if isinstance(value, str) and value else None

    def set_cipher_key(self, serial: str, cipher_id: int, ecc_private_key: str) -> None:
        self.station(serial).setdefault("ciphers", {})[str(cipher_id)] = ecc_private_key

    def rsa_cipher_key(self, serial: str, cipher_id: int) -> str | None:
        """The cached RSA private key (the cloud's ``private_key``) of ``cipher_id`` for
        ``serial``: what a station answering with the RSA CONN_INIT needs."""
        value = self.station(serial).get("rsa_ciphers", {}).get(str(cipher_id))
        return value if isinstance(value, str) and value else None

    def set_rsa_cipher_key(self, serial: str, cipher_id: int, private_key: str) -> None:
        self.station(serial).setdefault("rsa_ciphers", {})[str(cipher_id)] = private_key

    def drop_cipher_key(self, serial: str, cipher_id: int) -> None:
        """Forget both keys of ``cipher_id`` for ``serial``."""
        station = self.station(serial)
        station.get("ciphers", {}).pop(str(cipher_id), None)
        station.get("rsa_ciphers", {}).pop(str(cipher_id), None)

    def dsk_key(self, serial: str) -> tuple[str, float] | None:
        """The cached device session key (DSK) and its expiration (epoch s) for
        ``serial``, or None when none is cached (see :meth:`set_dsk_key`)."""
        dsk = self.station(serial).get("dsk")
        if not isinstance(dsk, dict):
            return None
        key, expires = dsk.get("key"), dsk.get("expiration")
        if isinstance(key, str) and key and isinstance(expires, (int, float)):
            return key, float(expires)
        return None

    def set_dsk_key(self, serial: str, key: str, expiration: float) -> None:
        self.station(serial)["dsk"] = {"key": key, "expiration": expiration}

    def drop_dsk_key(self, serial: str) -> None:
        self.station(serial).pop("dsk", None)

    def presets(self, serial: str, device_sn: str) -> list[dict[str, Any]] | None:
        """The preset slots last read from camera ``device_sn`` of station ``serial``,
        as stored (see :meth:`set_presets`), or None when never read."""
        value = self.station(serial).get("presets", {}).get(device_sn)
        return value if isinstance(value, list) else None

    def set_presets(self, serial: str, device_sn: str, slots: list[dict[str, Any]]) -> None:
        """Store camera ``device_sn``'s preset slots, in the camera's own ``points`` shape
        (``index``, ``enable``, ``zoom``, ``isdefault``); saved with the next save."""
        self.station(serial).setdefault("presets", {})[device_sn] = slots

    def station_cipher_id(self, serial: str) -> int:
        """The cipher ``serial`` named in its last CONN_INIT, else :data:`CIPHER_ID_P2P`."""
        named = self.station_named_cipher_id(serial)
        return CIPHER_ID_P2P if named is None else named

    def station_named_cipher_id(self, serial: str) -> int | None:
        """The cipher ``serial`` named in its last CONN_INIT, None before one was stored."""
        value = self.station(serial).get("cipher_id")
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def set_station_cipher_id(self, serial: str, cipher_id: int) -> None:
        self.station(serial)["cipher_id"] = cipher_id

    # ── device list ──────────────────────────────────────────────────────────

    def cached_devices(self) -> list[dict[str, Any]] | None:
        """The stored ``get_devs_list`` entries, or None if never fetched.

        The device list changes rarely (a device is added or renamed), so it is
        cached to spare a cloud round trip — and, for a Home Assistant restart, to
        let local control come up before, or without, the cloud. Each entry holds only
        what :class:`~.cloud.models.CloudDevice` reads (see :meth:`set_devices`).
        Refresh with ``async_get_devices(refresh=True)`` (the CLI's ``devices``
        command does).
        """
        value = self._doc.get("devices")
        if not isinstance(value, list):
            return None
        return [dict(entry) for entry in value if isinstance(entry, dict)]

    def set_devices(self, raw_devices: list[dict[str, Any]]) -> None:
        """Store the ``get_devs_list`` entries, each reduced to what the library reads
        (:func:`~.cloud.models.device_cache_entry`): the member's e-mail and phone, MAC
        addresses and the like never reach the store. The cloud's ``params`` snapshot
        is kept only for a device reached on demand (:func:`~.devices.connects_on_demand`),
        whose state comes from it between sessions; elsewhere it is stale at once."""
        self._doc["devices"] = _device_entries(raw_devices)

    def station_serials(self) -> list[str]:
        """The serials the cache holds per-station state for, sorted."""
        stations = self._doc.get("stations")
        return sorted(stations) if isinstance(stations, dict) else []

    # ── session-replaced latch ───────────────────────────────────────────────

    @property
    def replaced_at(self) -> float | None:
        """Epoch s at which another client's login ended the session (the latch), if set."""
        section = self._doc.get(_REPLACED)
        return _epoch_or_none(section.get("at")) if isinstance(section, dict) else None

    def set_replaced(self) -> None:
        self._doc[_REPLACED] = {"at": int(time.time())}

    def clear_replaced(self) -> bool:
        """Release the latch; whether one was set."""
        return self._doc.pop(_REPLACED, None) is not None

    # ── refresh throttle ─────────────────────────────────────────────────────

    def seconds_since_refresh(self, kind: str, serial: str | None = None) -> float | None:
        """Seconds since a forced ``kind`` refresh was attempted, or None.

        ``"owner"`` (the device list behind the owner ids) is account-wide; pass
        ``serial`` for a per-station kind (``"cipher"``).
        """
        at = _epoch_or_none(self._refresh_stamps(serial, create=False).get(kind))
        return None if at is None else time.time() - at

    def note_refresh(self, kind: str, serial: str | None = None) -> None:
        self._refresh_stamps(serial, create=True)[kind] = time.time()

    def _refresh_stamps(self, serial: str | None, *, create: bool) -> dict[str, Any]:
        """The stamps of ``serial`` (or the account); a read never creates an empty section."""
        if create:
            parent = self._doc if serial is None else self.station(serial)
            return _subsection(parent, "refresh_attempts")
        if serial is None:
            entry: object = self._doc
        else:
            stations = self._doc.get("stations")
            entry = stations.get(serial) if isinstance(stations, dict) else None
        stamps = entry.get("refresh_attempts") if isinstance(entry, dict) else None
        return stamps if isinstance(stamps, dict) else {}

    # ── key-refresh latch (per station) ──────────────────────────────────────

    def key_refresh_outstanding(self, serial: str) -> float | None:
        """Epoch s of a successful key refresh not yet followed by a handshake success."""
        stations = self._doc.get("stations")
        entry = stations.get(serial) if isinstance(stations, dict) else None
        return _epoch_or_none(entry.get("key_refresh")) if isinstance(entry, dict) else None

    def key_refresh_slow_retry_left(self, serial: str) -> float:
        """Seconds until a latched station may refresh its key again; 0.0 when it may now.

        0.0 when no latch is set. A stamp in the future (the clock jumped back) counts
        as set now, so it can delay a refresh by one window at most.
        """
        at = self.key_refresh_outstanding(serial)
        if at is None:
            return 0.0
        return min(max(KEY_REFRESH_SLOW_RETRY - (time.time() - at), 0.0), KEY_REFRESH_SLOW_RETRY)

    def note_key_refresh(self, serial: str) -> None:
        """Set the latch; call only after a fetch returned a key."""
        self.station(serial)["key_refresh"] = time.time()

    def clear_key_refresh(self, serial: str) -> bool:
        """Release the latch for ``serial``; whether one was set."""
        stations = self._doc.get("stations")
        entry = stations.get(serial) if isinstance(stations, dict) else None
        return isinstance(entry, dict) and entry.pop("key_refresh", None) is not None

    # ── cloud throttle ───────────────────────────────────────────────────────

    def held_off_for(self, kind: str, *, longest: float, region: str | None = None) -> float | None:
        """Seconds left on the ``kind`` hold-off (``"requests"``, ``"login"``), or None.

        A hold-off kept per region (``"login"``) is read for ``region``; a single stored
        time applies to every region. A stored time more than ``longest`` ahead cannot
        have been set by this clock (it jumped back, or the document was edited) and is
        ignored rather than allowed to block the cloud indefinitely.
        """
        until = self.section("throttle").get(kind)
        if isinstance(until, dict):
            until = until.get(region) if region is not None else None
        if not isinstance(until, (int, float)) or isinstance(until, bool):
            return None
        left = until - time.time()
        return left if 0 < left <= longest else None

    def hold_off(self, kind: str, seconds: float, *, region: str | None = None) -> None:
        """Hold ``kind`` off for ``seconds`` from now (for ``region`` alone when given);
        never shortens a longer hold-off."""
        section = self.section("throttle")
        holder: dict[str, Any] = section
        key = kind
        if region is not None:
            holder, key = _per_region(section, kind), region
        until = time.time() + seconds
        current = holder.get(key)
        if isinstance(current, (int, float)) and not isinstance(current, bool):
            until = max(until, current)
        holder[key] = until

    def recent_logins(self, window: float, region: str | None = None) -> list[float]:
        """Epoch times of the login attempts inside the last ``window`` seconds, oldest
        first: those of ``region``, or of every region when None.

        As in :meth:`held_off_for`, a stamp more than ``LOCKOUT_HOLD_OFF_SECONDS``
        ahead cannot have been written by this clock and is ignored, so it cannot
        fill the login budget. A single stored list counts for every region.
        """
        now = time.time()
        cutoff, latest = now - window, now + LOCKOUT_HOLD_OFF_SECONDS
        stored = self.section("throttle").get("logins")
        if isinstance(stored, dict):
            lists = [stored.get(region)] if region is not None else list(stored.values())
        else:
            lists = [stored]
        return sorted(
            float(at)
            for entries in lists
            for at in (entries if isinstance(entries, list) else ())
            if isinstance(at, (int, float)) and not isinstance(at, bool) and cutoff < at <= latest
        )

    def note_login(self, window: float, region: str) -> None:
        """Record a login attempt to ``region`` now, forgetting those older than ``window``
        or implausible."""
        recent = self.recent_logins(window, region)
        _per_region(self.section("throttle"), "logins")[region] = [*recent, time.time()]


# The cloud session fields version 1 kept flat in ``cloud``.
_V1_SESSION_FIELDS: Final = (
    "key_ident",
    "shared_key",
    "auth_token",
    "user_id",
    "expires_at",
    "mega_domain",
)


def _migrate_v1(doc: dict[str, Any]) -> str:
    """Rewrite a version-1 document in place; returns the region its session served.

    The region is the one the session was logged in to (``cloud.region``), else the
    one its ``mega_domain`` names, else :data:`DEFAULT_REGION`. The session moves to
    ``cloud.sessions.<region>`` and every cached device is tagged with that region,
    which counts as listed with them. An empty device list is dropped, so the next
    fetch asks every region once.
    """
    cloud = doc.get("cloud")
    cloud = cloud if isinstance(cloud, dict) else {}
    stored = cloud.get("region")
    region = (
        stored
        if stored in REGIONS
        else region_from_mega_domain(cloud.get("mega_domain")) or DEFAULT_REGION
    )
    session = {key: cloud[key] for key in _V1_SESSION_FIELDS if key in cloud}
    migrated: dict[str, Any] = {"sessions": {region: session}} if session else {}
    devices = [e for e in doc.get("devices") or () if isinstance(e, dict)]
    if devices:
        for entry in devices:
            entry.setdefault(REGION_KEY, region)
        migrated["listed"] = {region: {"devices": len(devices), "at": None}}
    else:
        doc.pop("devices", None)
    doc["cloud"] = migrated
    return region


def _per_region(section: dict[str, Any], key: str) -> dict[str, Any]:
    """``section[key]`` as a per-region mapping; a single stored value becomes every
    region's."""
    value = section.get(key)
    if not isinstance(value, dict):
        value = section[key] = (
            {} if value is None else {region: copy.deepcopy(value) for region in REGIONS}
        )
    return value


def _device_entries(raw_devices: list[Any]) -> list[dict[str, Any]]:
    """``raw_devices`` as the cache stores them (see :meth:`SessionCache.set_devices`)."""
    entries = []
    for entry in raw_devices:
        if not isinstance(entry, dict):
            continue
        serial = entry.get("device_sn")
        on_demand = isinstance(serial, str) and connects_on_demand(serial)
        entries.append(device_cache_entry(entry, keep_params=on_demand))
    return entries


def _epoch_or_none(value: object) -> float | None:
    """A stored epoch-seconds stamp, or None when absent or malformed."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    return float(value)


def _present(value: object) -> bool:
    return value is not None and value not in ("", {}, [])


def _present_fields(section: object) -> list[str]:
    """The names of a section's fields that hold a value; never the values."""
    if not isinstance(section, dict):
        return []
    return sorted(str(key) for key, value in section.items() if _present(value))


def _unique_serial_labels(serials: list[str]) -> dict[str, str]:
    """Each serial's :func:`redact_serial` label, numbered where two would collide."""
    labels: dict[str, str] = {}
    taken: set[str] = set()
    for serial in serials:
        label, n = redact_serial(serial), 1
        while label in taken:
            n += 1
            label = f"{redact_serial(serial)}#{n}"
        taken.add(label)
        labels[serial] = label
    return labels


def _subsection(parent: dict[str, Any], name: str) -> dict[str, Any]:
    sec = parent.setdefault(name, {})
    if not isinstance(sec, dict):
        sec = parent[name] = {}
    return sec


def _describe(doc: dict[str, Any]) -> str:
    """What a cache document holds, for a log line: sections and their keys, no values."""
    parts = []
    for key, value in sorted(doc.items()):
        if key in ("version", "account"):
            continue
        if key == "stations" and isinstance(value, dict):
            parts.append(f"stations={len(value)}")
        elif key == "devices" and isinstance(value, list):
            parts.append(f"devices={len(value)}")
        elif isinstance(value, dict):
            parts.append(f"{key}[{','.join(sorted(value))}]")
        else:
            parts.append(key)
    return " ".join(parts) or "empty"


def _merge_over(stored: dict[str, Any], memory: dict[str, Any]) -> dict[str, Any]:
    """``memory`` written over ``stored``, one level deep; the stored openudid wins."""
    merged = dict(stored)
    for key, value in memory.items():
        if key == "openudid" and stored.get("openudid"):
            continue
        base = merged.get(key)
        if isinstance(base, dict) and isinstance(value, dict):
            merged[key] = {**base, **value}
        else:
            merged[key] = value
    return merged
