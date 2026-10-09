from __future__ import annotations

import asyncio
import json
import stat
import time
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security import storage
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.cloud.const import KEY_REFRESH_SLOW_RETRY
from eufy_home_security.exceptions import LoginLimitedError
from eufy_home_security.storage import (
    CACHE_VERSION,
    JsonFileStore,
    MemoryStore,
    SessionCache,
    Store,
    async_cached_account,
    async_forget_account,
)
from eufy_home_security.testing import SYNTHETIC


async def test_file_store_roundtrip_is_private(tmp_path: Path) -> None:
    store = JsonFileStore(tmp_path / "sub" / "cache.json")
    assert await store.async_load() is None
    await store.async_save({"a": 1})
    assert await store.async_load() == {"a": 1}
    assert stat.S_IMODE((tmp_path / "sub" / "cache.json").stat().st_mode) == 0o600


def test_stores_satisfy_protocol(tmp_path: Path) -> None:
    assert isinstance(MemoryStore(), Store)
    assert isinstance(JsonFileStore(tmp_path / "x.json"), Store)


async def test_cache_scopes_everything_but_openudid_to_the_account() -> None:
    store = MemoryStore()
    cache = SessionCache(store, "User@Example.com")
    await cache.async_load()
    udid = cache.openudid
    assert len(udid) == 16
    cache.set_cipher_key("T8030P2000012345", 40, "ab" * 32)
    cache.set_station_account_id("T8030P2000012345", "owner")
    await cache.async_save()

    same = SessionCache(store, "user@example.com")
    await same.async_load()
    assert same.cipher_key("T8030P2000012345", 40) == "ab" * 32
    assert same.station_account_id("T8030P2000012345") == "owner"

    other = SessionCache(store, "someone-else@example.com")
    await other.async_load()
    assert other.openudid == udid
    assert other.cipher_key("T8030P2000012345", 40) is None


async def test_refresh_stamps_are_per_kind_and_per_station() -> None:
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    assert cache.seconds_since_refresh("cipher", "T8030P2000012345") is None
    assert cache.station_serials() == []  # reading a stamp creates no station entry
    cache.note_refresh("cipher", "T8030P2000012345")
    since = cache.seconds_since_refresh("cipher", "T8030P2000012345")
    assert since is not None
    assert since < 5
    assert cache.seconds_since_refresh("cipher", "T8030P2000067890") is None
    assert cache.seconds_since_refresh("owner") is None  # each kind is throttled on its own
    assert "refresh_attempts" not in cache.redacted_summary()["sections"]  # nor a section
    cache.note_refresh("owner")
    assert cache.seconds_since_refresh("owner") is not None


async def test_key_refresh_latch_is_per_station_and_persists() -> None:
    store = MemoryStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    assert cache.key_refresh_outstanding("T8030P2000012345") is None
    assert not cache.clear_key_refresh("T8030P2000012345")
    cache.note_key_refresh("T8030P2000012345")
    cache.set_cipher_key("T8030P2000067890", 40, "ab" * 32)
    await cache.async_save()

    reloaded = SessionCache(store, "user@example.com")
    await reloaded.async_load()
    assert reloaded.station_serials() == ["T8030P2000012345", "T8030P2000067890"]
    assert reloaded.key_refresh_outstanding("T8030P2000012345") is not None
    assert reloaded.key_refresh_outstanding("T8030P2000067890") is None
    assert reloaded.clear_key_refresh("T8030P2000012345")
    assert reloaded.key_refresh_outstanding("T8030P2000012345") is None


async def test_key_refresh_slow_retry_window() -> None:
    serial = "T8030P2000012345"
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    assert cache.key_refresh_slow_retry_left(serial) == 0.0  # no latch
    cache.note_key_refresh(serial)
    assert cache.key_refresh_slow_retry_left(serial) == pytest.approx(KEY_REFRESH_SLOW_RETRY, abs=5)
    cache.station(serial)["key_refresh"] = time.time() - KEY_REFRESH_SLOW_RETRY - 1
    assert cache.key_refresh_slow_retry_left(serial) == 0.0  # the slow lane is open
    cache.station(serial)["key_refresh"] = time.time() + 10 * KEY_REFRESH_SLOW_RETRY
    assert cache.key_refresh_slow_retry_left(serial) == KEY_REFRESH_SLOW_RETRY  # clock jumped


async def test_hold_off_is_never_shortened_and_ignores_impossible_times() -> None:
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    assert cache.held_off_for("requests", longest=86400) is None
    cache.hold_off("requests", 3600)
    cache.hold_off("requests", 60)  # a shorter one does not replace it
    left = cache.held_off_for("requests", longest=86400)
    assert left is not None
    assert 3590 < left <= 3600
    assert cache.held_off_for("login", longest=86400) is None  # each kind on its own
    cache.section("throttle")["login"] = time.time() + 10 * 86400  # the clock jumped back
    assert cache.held_off_for("login", longest=86400) is None


async def test_login_attempts_persist_and_leave_the_window() -> None:
    store = MemoryStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    cache.section("throttle")["logins"] = {"eu": [time.time() - 7200, "junk"]}
    cache.note_login(3600, "eu")
    await cache.async_save()
    reloaded = SessionCache(store, "user@example.com")
    await reloaded.async_load()
    assert len(reloaded.recent_logins(3600, "eu")) == 1
    assert len(reloaded.section("throttle")["logins"]["eu"]) == 1  # the old one was dropped


async def test_login_attempts_and_login_hold_offs_count_per_region() -> None:
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    cache.note_login(3600, "eu")
    cache.note_login(3600, "eu")
    cache.note_login(3600, "us")
    assert (len(cache.recent_logins(3600, "eu")), len(cache.recent_logins(3600, "us"))) == (2, 1)
    assert len(cache.recent_logins(3600)) == 3  # every region
    cache.hold_off("login", 600, region="us")
    assert cache.held_off_for("login", longest=86400, region="eu") is None
    assert cache.held_off_for("login", longest=86400, region="us") is not None


async def test_a_single_stored_login_record_counts_for_every_region() -> None:
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    now = time.time()
    cache.section("throttle").update({"logins": [now - 60], "login": now + 600})
    for region in ("eu", "us"):
        assert cache.recent_logins(3600, region) == [now - 60]
        assert cache.held_off_for("login", longest=86400, region=region) is not None
    cache.note_login(3600, "eu")
    assert len(cache.recent_logins(3600, "us")) == 1  # kept for the other region
    assert len(cache.recent_logins(3600, "eu")) == 2


async def test_future_login_stamps_neither_count_nor_persist() -> None:
    cache = SessionCache(MemoryStore(), "user@example.com")
    await cache.async_load()
    recent = time.time() - 60
    cache.section("throttle")["logins"] = {"eu": [recent, time.time() + 10 * 86400]}  # clock
    assert cache.recent_logins(3600, "eu") == [recent]
    cache.note_login(3600, "eu")
    stored = cache.section("throttle")["logins"]["eu"]
    assert len(stored) == 2
    assert stored[0] == recent
    assert stored[1] <= time.time()


#: Extra-country install ids, kept wherever ``openudid`` is.
_INSTALL_IDS = {"eu:CH": "fedcba9876543210"}


async def test_a_version_change_keeps_the_password_throttle_and_install_identity() -> None:
    store = MemoryStore(
        {
            "version": CACHE_VERSION + 1,
            "account": "user@example.com",
            "openudid": "0123456789abcdef",
            "password": "secret",
            "throttle": {"logins": [1.0]},
            "cloud": {"auth_token": "old", "install_ids": _INSTALL_IDS},
            "devices": [{"device_sn": "T8030P2000012345"}],
        }
    )
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    assert cache.password == "secret"
    assert cache.section("throttle") == {"logins": [1.0]}
    assert cache.openudid == "0123456789abcdef"
    assert cache.section("cloud") == {"install_ids": _INSTALL_IDS}
    assert cache.cached_devices() is None

    other = SessionCache(store, "someone-else@example.com")
    await other.async_load()
    assert other.password is None  # never another account's password
    assert other.section("throttle") == {}
    assert other.openudid == "0123456789abcdef"
    assert other.section("cloud") == {"install_ids": _INSTALL_IDS}


@pytest.mark.parametrize(
    ("cloud", "region"),
    [
        ({"region": "us", "mega_domain": "mega-eu-pr.eufy.com"}, "us"),  # the login's region
        ({"mega_domain": "mega-us-pr.eufy.com"}, "us"),
        ({"region": "xx"}, "eu"),
    ],
)
async def test_version_1_moves_its_session_under_its_region(
    cloud: dict[str, str], region: str
) -> None:
    session = {"auth_token": "t", "key_ident": "k", "shared_key": "s", "expires_at": 9e9}
    store = MemoryStore(
        {
            "version": 1,
            "account": "user@example.com",
            "password": "secret",
            "cloud": {**session, **cloud},
            "devices": [{"device_sn": "T8030P2000012345"}],
            "stations": {"T8030P2000012345": {"account_id": "owner"}},
        }
    )
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    stored = cache.cloud_sessions()[region]
    assert {key: stored[key] for key in session} == session
    assert set(cache.cloud_sessions()) == {region}
    assert cache.cached_devices() == [{"device_sn": "T8030P2000012345", "cloud_region": region}]
    assert cache.section("cloud")["listed"] == {region: {"devices": 1, "at": None}}
    assert cache.station_account_id("T8030P2000012345") == "owner"
    assert cache.password == "secret"


async def test_version_1_without_devices_drops_the_empty_list() -> None:
    store = MemoryStore(
        {"version": 1, "account": "user@example.com", "cloud": {"auth_token": "t"}, "devices": []}
    )
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    assert cache.cached_devices() is None  # the next fetch asks every region once
    assert "listed" not in cache.section("cloud")


async def test_the_replaced_latch_survives_a_cache_version_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    cache.set_replaced()
    cache.section("cloud")["auth_token"] = "t"
    await cache.async_save()

    monkeypatch.setattr(storage, "CACHE_VERSION", CACHE_VERSION + 1)
    upgraded = SessionCache(store, "user@example.com")
    await upgraded.async_load()
    assert upgraded.replaced_at is not None
    assert upgraded.section("cloud") == {}


def _populated_document() -> dict[str, Any]:
    return {
        "version": CACHE_VERSION,
        "account": SYNTHETIC.email,
        "openudid": "0123456789abcdef",
        "password": "secret",
        "cloud": {
            "auth_token": "t",
            "key_ident": "k",
            "shared_key": "s",
            "install_ids": _INSTALL_IDS,
        },
        "replaced": {"at": 1},
        "push": {"fcm": {"token": "x"}},
        "stations": {SYNTHETIC.station_sn: {"account_id": "owner", "ciphers": {"40": "ab"}}},
        "devices": [{"device_sn": SYNTHETIC.station_sn}],
        "refresh_attempts": {"owner": 1.0},
        "throttle": {"login": time.time() + 3600, "logins": [time.time() - 60]},
    }


@pytest.mark.parametrize("keep_install_identity", [True, False])
async def test_forget_account_keeps_only_the_throttle_state(keep_install_identity: bool) -> None:
    doc = _populated_document()
    store = MemoryStore(doc)
    await async_forget_account(store, keep_install_identity=keep_install_identity)
    expected = {key: doc[key] for key in ("version", "account", "throttle")}
    if keep_install_identity:
        expected["openudid"] = doc["openudid"]
        expected["cloud"] = {"install_ids": _INSTALL_IDS}
    assert store.data == expected

    empty = MemoryStore()
    await async_forget_account(empty)
    assert empty.data is None  # nothing stored: nothing written


async def test_a_forgotten_account_still_honours_the_login_hold_off() -> None:
    store = MemoryStore(_populated_document())
    await async_forget_account(store)
    cache = SessionCache(store, SYNTHETIC.email)
    await cache.async_load()
    with aioresponses() as mock:
        async with aiohttp.ClientSession() as session:
            api = EufyCloudApi(session, cache, SYNTHETIC.email, "secret")
            with pytest.raises(LoginLimitedError):
                await api.async_login()
        assert not mock.requests


async def test_cached_account_is_the_email_of_the_stored_session() -> None:
    store = MemoryStore()
    assert await async_cached_account(store) is None
    cache = SessionCache(store, "User@Example.com")
    await cache.async_load()
    await cache.async_save()
    assert await async_cached_account(store) == "user@example.com"
    await store.async_save({"version": 0, "account": "user@example.com"})
    assert await async_cached_account(store) is None  # an older layout is not trusted
    await store.async_save({"version": 1, "account": "user@example.com"})
    assert await async_cached_account(store) == "user@example.com"  # migrated on load


async def test_corrupt_cache_file_is_moved_aside(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("")  # empty, as after a crash mid-write on a filesystem without fsync
    assert await JsonFileStore(path).async_load() is None
    assert (tmp_path / "cache.json.corrupt").exists()
    assert not path.exists()


async def test_save_hands_the_store_a_snapshot() -> None:
    saved: list[dict[str, Any]] = []

    class RecordingStore(MemoryStore):
        async def async_save(self, data: dict[str, Any]) -> None:
            saved.append(data)

    cache = SessionCache(RecordingStore(), "user@example.com")
    await cache.async_load()
    cache.section("cloud")["auth_token"] = "t1"
    await cache.async_save()
    cache.section("cloud")["auth_token"] = "t2"  # a mutation after (or during) the write
    assert saved[0]["cloud"]["auth_token"] == "t1"


class _CountingStore(MemoryStore):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__()
        self.saves = 0
        self.fail = fail

    async def async_save(self, data: dict[str, Any]) -> None:
        self.saves += 1
        if self.fail:
            raise OSError("disk full")
        await super().async_save(data)


async def test_a_scheduled_save_is_coalesced_and_written_later() -> None:
    store = _CountingStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    cache.section("push")["seen_spans"] = {"a": 1}
    cache.schedule_save(0.01)
    cache.schedule_save(0.01)
    await asyncio.sleep(0)
    assert store.saves == 0
    await asyncio.sleep(0.05)
    assert store.saves == 1
    assert store.data is not None
    assert store.data["push"]["seen_spans"] == {"a": 1}


async def test_an_immediate_save_covers_a_pending_scheduled_one() -> None:
    store = _CountingStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    cache.schedule_save(3600)
    await cache.async_save()
    await asyncio.sleep(0)
    assert store.saves == 1
    cache.schedule_save(0)  # a cancelled save does not block the next schedule
    await asyncio.sleep(0.01)
    assert store.saves == 2


async def test_a_failed_scheduled_save_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cache = SessionCache(_CountingStore(fail=True), "user@example.com")
    await cache.async_load()
    cache.schedule_save(0)
    await asyncio.sleep(0.01)
    assert "session cache not saved" in caplog.text


async def test_save_before_load_merges_over_the_stored_document() -> None:
    store = MemoryStore(
        {
            "version": CACHE_VERSION,
            "account": "user@example.com",
            "openudid": "0011223344556677",
            "cloud": {"auth_token": "kept", "region": "eu"},
            "devices": [{"device_sn": "x"}],
        }
    )
    cache = SessionCache(store, "user@example.com")
    assert cache.openudid != "0011223344556677"  # unloaded: a fresh value was minted
    cache.section("cloud")["region"] = "us"
    await cache.async_save()
    assert cache.loaded
    assert store.data is not None
    assert store.data["openudid"] == "0011223344556677"  # the stored identity wins
    assert store.data["cloud"] == {"auth_token": "kept", "region": "us"}
    assert store.data["devices"] == [{"device_sn": "x"}]
    assert json.loads(json.dumps(store.data)) == store.data


def test_station_cipher_id_defaults_and_validation() -> None:
    cache = SessionCache(MemoryStore(), "test@test.com")
    assert cache.station_cipher_id("T123") == 40
    assert cache.station_named_cipher_id("T123") is None

    cache.set_station_cipher_id("T123", 98)
    assert (cache.station_cipher_id("T123"), cache.station_named_cipher_id("T123")) == (98, 98)

    for invalid in ("invalid", True):
        cache.station("T123")["cipher_id"] = invalid
        assert cache.station_cipher_id("T123") == 40
        assert cache.station_named_cipher_id("T123") is None


async def test_session_cache_presets_roundtrip() -> None:
    store = MemoryStore()
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()

    assert cache.presets("T8030", "T8160") is None

    slots: list[dict[str, Any]] = [
        {"index": 1, "enable": 1, "zoom": 1, "isdefault": 0},
        {"index": 2, "enable": 0, "zoom": 2.0, "isdefault": 1},
    ]
    cache.set_presets("T8030", "T8160", slots)
    assert cache.presets("T8030", "T8160") == slots

    await cache.async_save()

    cache2 = SessionCache(store, "user@example.com")
    await cache2.async_load()
    assert cache2.presets("T8030", "T8160") == slots


async def test_stored_devices_hold_only_what_the_library_reads() -> None:
    hub = {
        "device_sn": SYNTHETIC.station_sn,
        "device_type": 18,
        "device_name": "HomeBase",
        "member": {"admin_user_id": SYNTHETIC.account_id, "email": SYNTHETIC.email},
        "wifi_mac": "00:00:5E:00:53:01",
        "params": [{"param_type": 1101, "param_value": "87", "update_time": 1}],
    }
    on_demand = {
        "device_sn": "T8170P2000012345",
        "device_type": 48,
        "device_name": "SoloCam",
        "bt_mac": "00:00:5E:00:53:02",
        "params": [{"param_type": 1101, "param_value": "87", "update_time": 1}],
    }
    slim_hub = {
        "device_sn": SYNTHETIC.station_sn,
        "device_type": 18,
        "device_name": "HomeBase",
        "member": {"admin_user_id": SYNTHETIC.account_id},
    }
    slim_on_demand = {
        "device_sn": "T8170P2000012345",
        "device_type": 48,
        "device_name": "SoloCam",
        "params": [{"param_type": 1101, "param_value": "87", "update_time": 1}],
    }
    # Stored entries with fields outside the allowlist are reduced on load …
    store = MemoryStore(
        {"version": CACHE_VERSION, "account": "user@example.com", "devices": [hub, on_demand]}
    )
    cache = SessionCache(store, "user@example.com")
    await cache.async_load()
    assert cache.cached_devices() == [slim_hub, slim_on_demand]
    await cache.async_save()
    assert store.data is not None
    assert store.data["devices"] == [slim_hub, slim_on_demand]
    assert SYNTHETIC.email not in json.dumps(store.data["devices"])
    # … and a fresh list the same way; the params snapshot stays only for on-demand devices.
    cache.set_devices([on_demand, hub])
    assert cache.cached_devices() == [slim_on_demand, slim_hub]
