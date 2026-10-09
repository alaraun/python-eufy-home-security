from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security import client as client_module
from eufy_home_security import storage as storage_module
from eufy_home_security._logging import LogThrottle, redact_serial
from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud.api import CipherKeys, EufyCloudApi, HttpSession, _SessionExpiredError
from eufy_home_security.cloud.const import KEY_REFRESH_SLOW_RETRY
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.model_settings import (
    bundled_td_version,
    settings_of,
)
from eufy_home_security.events import (
    AlarmChanged,
    CloudProblem,
    ConnectionChanged,
    CredentialsRefreshed,
    DevicesChanged,
    DisconnectCause,
    Event,
    EventSource,
    GuardModeChanged,
    PushChanged,
    SecurityEvent,
    StationsChanged,
)
from eufy_home_security.exceptions import (
    AuthenticationError,
    CipherUnavailableError,
    CloudError,
    CommunicationError,
    EufySecurityError,
    KeyExchangeRefusedError,
    KeyRejectedError,
    NoCachedSessionError,
    ProtocolError,
    RateLimitedError,
    RefreshCooldownError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
)
from eufy_home_security.identity import StationClaims
from eufy_home_security.inclusion import Reach
from eufy_home_security.install import InstallState
from eufy_home_security.models import GuardMode
from eufy_home_security.network import PathWarning
from eufy_home_security.p2p import discovery as discovery_module
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation
from eufy_home_security.p2p.messages import STANDALONE_RECEIPT_LEN
from eufy_home_security.p2p.pppp import BROADCAST
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.push import fcm as fcm_module
from eufy_home_security.storage import CACHE_SECTIONS, CACHE_VERSION, MemoryStore
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    warm_store,
)
from eufy_home_security.testing.cloud import (
    camera_device,
    enum_property,
    range_property,
    station_device,
    thing_description,
)

OTHER_STATION_SN = "T8030P2000054321"
OTHER_DID = "EUPRAMA-654321-ABCDE"
OWNER_ID = "fedcba9876543210fedcba9876543210fedcba98"  # a station owner other than this account


def garage_device(did: str = SYNTHETIC.did) -> dict[str, Any]:
    """A second station on the device list, with no LAN address listed for it."""
    entry = station_device(OTHER_STATION_SN, did=did, name="Garage")
    del entry["local_ip"]
    return entry


def two_stations(*, other_did: str = SYNTHETIC.did) -> FakeCloud:
    """The synthetic station and camera, plus the garage station."""
    return FakeCloud(devices=[station_device(), camera_device(), garage_device(other_did)])


def account(
    http: aiohttp.ClientSession,
    cloud: FakeCloud | None = None,
    *,
    store: MemoryStore | None = None,
    email: str = SYNTHETIC.email,
    **kwargs: Any,
) -> EufySecurity:
    """A real client on ``cloud`` (default :func:`two_stations`), after one login.

    Built on the fake cloud's seam directly rather than ``build_eufy_security``: these
    tests start push (a ``StubPush``), which needs a real HTTP session to hand over.
    """
    cloud = cloud if cloud is not None else two_stations()
    if store is None:
        store = warm_store(email=email, cloud=cloud)
    return EufySecurity(
        http, email, SYNTHETIC.password, store=store, _cloud_factory=cloud.make_api, **kwargs
    )


def cloud_factory(stub: type[StubCloud]) -> Callable[..., EufyCloudApi]:
    """A stub class as the private ``_cloud_factory`` seam.

    The stubs duck-type :class:`EufyCloudApi` without subclassing it (they implement
    only what a test calls), so the seam's type has to be asserted here.
    """
    return cast("Callable[..., EufyCloudApi]", stub)


def no_session() -> HttpSession:
    """No HTTP session, for a constructor that must raise before it uses one."""
    return cast("HttpSession", None)


class StubCloud:
    """A cloud client by hand, for what ``FakeCloud`` cannot express.

    It records the login arguments, never writes the cache, and is subclassed to
    inject failures and delays into single calls.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.cache = args[1]
        self.user_name = "user"
        self.logins: list[dict[str, Any]] = []
        self.scanned_codes: list[list[str]] = []

    async def async_login(self, **kwargs: Any) -> None:
        self.logins.append(kwargs)

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        return [
            CloudDevice(
                device_sn=SYNTHETIC.station_sn,
                device_type=18,
                name="Home Base",
                p2p_did=SYNTHETIC.did,
                local_ip=SYNTHETIC.station_ip,
            ),
            CloudDevice(
                device_sn=SYNTHETIC.camera_sn,
                device_type=19,
                name="Front",
                station_sn=SYNTHETIC.station_sn,
                channel=0,
            ),
            CloudDevice(
                device_sn=OTHER_STATION_SN, device_type=18, name="Garage", p2p_did=SYNTHETIC.did
            ),
        ]

    async def async_get_station_owner_id(self, station_sn: str, *, refresh: bool = False) -> str:
        return SYNTHETIC.account_id

    async def async_get_cipher_keys(
        self, station_sn: str, cipher_id: int = 40, *, refresh: bool = False
    ) -> CipherKeys:
        return CipherKeys("ab" * 32, None)

    async def async_get_thing_descriptions(
        self, product_codes: Sequence[str]
    ) -> list[Mapping[str, Any]]:
        """The model scan's request: answered with no thing descriptions."""
        self.scanned_codes.append(list(product_codes))
        return []

    async def async_reset_key_refresh(self, serial: str | None = None) -> None:
        assert serial is not None
        self.cache.clear_key_refresh(serial)
        await self.cache.async_save()


class StubPush:
    instances: ClassVar[list[StubPush]] = []

    def __init__(
        self,
        cloud: Any,
        cache: Any,
        callback: Callable[[SecurityEvent], None],
        *,
        session: Any,
        on_token_upload: Callable[[CloudError | None], None] | None = None,
        on_listening: Callable[[bool, Any], None] | None = None,
    ) -> None:
        self.callback = callback
        self.on_token_upload = on_token_upload
        self.on_listening = on_listening
        self.started = False
        self.stopped = False
        StubPush.instances.append(self)

    async def async_start(self) -> None:
        self.started = True

    async def async_stop(self) -> None:
        self.stopped = True


@pytest.fixture(autouse=True)
def stub_push(monkeypatch: pytest.MonkeyPatch) -> None:
    StubPush.instances.clear()
    monkeypatch.setattr(fcm_module, "PushListener", StubPush)


async def test_discover_groups_devices_under_their_station() -> None:
    store = MemoryStore()
    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http,
            SYNTHETIC.email,
            "pw",
            store=store,
            station_hosts={OTHER_STATION_SN: "192.0.2.20"},
            _cloud_factory=cloud_factory(StubCloud),
        )
        await eufy.async_login(verify_code="123456", login_id="lid-42")
        stations = {s.serial: s for s in await eufy.async_discover()}
        await eufy.async_close()

    assert set(stations) == {SYNTHETIC.station_sn, OTHER_STATION_SN}
    home = stations[SYNTHETIC.station_sn]
    assert [d.device_sn for d in home.sub_devices] == [SYNTHETIC.camera_sn]
    assert home.session.host == SYNTHETIC.station_ip
    assert home.session._expect_channels == home.channels  # every probe waits for them
    assert stations[OTHER_STATION_SN].session.host == "192.0.2.20"
    assert isinstance(eufy.cloud, StubCloud)
    assert eufy.cloud.logins == [
        {
            "verify_code": "123456",
            "captcha_id": None,
            "captcha_answer": None,
            "login_id": "lid-42",
            "force": False,
        }
    ]
    assert store.data is not None  # the cache was persisted on close


NEW_CAMERA_SN = "T8160P2000067891"


async def test_a_newly_paired_model_is_read_off_the_loop_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A device paired to a station already built gets its model's settings loaded too:
    # the file is read once, in a worker thread, never on the loop, and never again.
    import importlib.resources  # noqa: PLC0415

    from eufy_home_security.devices import model_settings  # noqa: PLC0415

    model_settings._load.cache_clear()
    model_settings.bundled_codes.cache_clear()
    loop_thread = threading.current_thread()
    reads: list[tuple[str, bool]] = []
    files = importlib.resources.files

    def recording(package: Any) -> Any:
        root = files(package)
        if package != model_settings._DATA_PACKAGE:
            return root

        class _Recorded:
            def joinpath(self, name: str) -> Any:
                reads.append((name, threading.current_thread() is loop_thread))
                return root.joinpath(name)

        return _Recorded()

    monkeypatch.setattr(importlib.resources, "files", recording)
    cloud = two_stations()
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        home = next(s for s in await eufy.async_discover() if s.serial == SYNTHETIC.station_sn)
        new = camera_device(NEW_CAMERA_SN, channel=1, name="Back") | {"device_new_pn": "T8170"}
        cloud.devices.append(new)
        await eufy.async_discover(refresh=True)
        assert ("T8170.json", False) in reads
        assert ("INDEX.json", False) in reads
        before = len(reads)
        for _ in range(3):
            assert home.settings_for(NEW_CAMERA_SN) == home.settings_for(NEW_CAMERA_SN)
        await eufy.async_close()
    assert len(reads) == before  # nothing read again, on the loop or off it
    assert not any(on_loop for _name, on_loop in reads)


async def test_refresh_updates_the_stations_already_built() -> None:
    cloud = two_stations()
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        eufy.subscribe(events.append)
        home = next(s for s in await eufy.async_discover() if s.serial == SYNTHETIC.station_sn)
        await eufy.async_discover()  # the same list: nothing changed
        cloud.devices.append(camera_device(NEW_CAMERA_SN, channel=1, name="Back"))
        again = await eufy.async_discover(refresh=True)
        await eufy.async_close()

    assert [e for e in events if isinstance(e, DevicesChanged)] == [
        DevicesChanged(station_sn=SYNTHETIC.station_sn, added=(NEW_CAMERA_SN,))
    ]
    assert home in again
    assert [d.device_sn for d in home.sub_devices] == [SYNTHETIC.camera_sn, NEW_CAMERA_SN]
    assert home.session.expect_channels == {0, 1}


async def test_a_discovery_names_its_list_and_the_stations_it_added_or_lost() -> None:
    """``listed_devices`` holds every device of the list; a later discovery reports a
    station it built or no longer finds once, with how its list was obtained."""
    cloud = two_stations()
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        eufy.subscribe(events.append)
        await eufy.async_discover()
        first = (eufy.device_list_source, set(eufy.listed_devices))
        cloud.devices = [d for d in cloud.devices if d["device_sn"] != OTHER_STATION_SN]
        await eufy.async_discover(refresh=True)
        await eufy.async_discover(refresh=True)  # still gone: not reported again
        kept = OTHER_STATION_SN in eufy.stations  # until the client is rebuilt
        cloud.devices.append(garage_device(SYNTHETIC.did))
        await eufy.async_discover(refresh=True)  # back: built already, nothing to report
        listed = set(eufy.listed_devices)
        await eufy.async_close()
    assert first == ("cache", {SYNTHETIC.station_sn, SYNTHETIC.camera_sn, OTHER_STATION_SN})
    assert listed == first[1]
    assert [e for e in events if isinstance(e, StationsChanged)] == [
        StationsChanged(removed=(OTHER_STATION_SN,), source="fetched")
    ]
    assert kept


async def test_a_discovery_reports_a_station_it_built_after_the_first() -> None:
    cloud = FakeCloud(devices=[station_device(), camera_device()])
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        eufy.subscribe(events.append)
        await eufy.async_discover()
        cloud.devices.append(garage_device(SYNTHETIC.did))
        await eufy.async_discover(refresh=True)
        await eufy.async_close()
    assert [e for e in events if isinstance(e, StationsChanged)] == [
        StationsChanged(added=(OTHER_STATION_SN,), source="fetched")
    ]


ODD_CAMERA_SN = "T8160-BAD_0001"
VACUUM_SN = "T2266P1000000001"
ORPHAN_SN = "T8161P1000000009"


class BadSerialCloud(StubCloud):
    """The stub's devices plus every kind of device the grouping skips.

    A station with no serial, a camera with a bad serial,
    a product with no P2P id, and a camera paired to a station not on the list.
    """

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        devices = await super().async_get_devices(refresh=refresh)
        return [
            *devices,
            CloudDevice(device_sn="", device_type=18, name="Blank", p2p_did=SYNTHETIC.did),
            CloudDevice(
                device_sn=ODD_CAMERA_SN,
                device_type=19,
                name="Odd",
                station_sn=SYNTHETIC.station_sn,
                channel=1,
            ),
            CloudDevice(device_sn=VACUUM_SN, device_type=0, name="Vacuum"),
            CloudDevice(
                device_sn=ORPHAN_SN, device_type=19, name="Lost", station_sn="T8030P9999999999"
            ),
        ]


async def test_discover_skips_and_lists_devices_it_cannot_build(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(client_module, "_SKIP_THROTTLE", LogThrottle())
    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http,
            SYNTHETIC.email,
            "pw",
            store=MemoryStore(),
            _cloud_factory=cloud_factory(BadSerialCloud),
        )
        with caplog.at_level("INFO", logger=client_module.__name__):
            stations = {s.serial: s for s in await eufy.async_discover()}
            await eufy.async_discover()  # a second discovery logs nothing new
        await eufy.async_close()

    assert set(stations) == {SYNTHETIC.station_sn, OTHER_STATION_SN}
    assert [d.device_sn for d in stations[SYNTHETIC.station_sn].sub_devices] == [
        SYNTHETIC.camera_sn
    ]
    assert [(s.device_sn_redacted, s.reason) for s in eufy.skipped_devices] == [
        ("empty", "bad_serial"),
        (redact_serial(ODD_CAMERA_SN), "bad_serial"),
        (redact_serial(VACUUM_SN), "no_did"),
        (redact_serial(ORPHAN_SN), "orphan"),
    ]
    skipped = [r for r in caplog.records if "skipping device" in r.getMessage()]
    assert [r.levelname for r in skipped] == ["WARNING", "WARNING", "INFO", "WARNING"]
    assert "skipping device empty:" in skipped[0].getMessage()
    assert all(ODD_CAMERA_SN not in r.getMessage() for r in skipped)  # redacted


@pytest.mark.parametrize("email", ["", "   ", "admin"])
def test_an_address_without_an_at_is_refused_before_any_cloud_client_exists(email: str) -> None:
    def factory(*args: Any, **kwargs: Any) -> EufyCloudApi:
        raise AssertionError("no cloud client for a bad address")

    with pytest.raises(ValueError, match="not an e-mail address"):
        EufySecurity(None, email, None, store=MemoryStore(), _cloud_factory=factory)  # type: ignore[arg-type]


def test_the_cloud_options_and_install_state_reach_the_cloud_client() -> None:
    install = InstallState()
    seen: dict[str, Any] = {}

    def factory(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return StubCloud(*args, **kwargs)

    options: dict[str, Any] = {
        "country": ["EE", "CH"],
        "timezone": "Europe/Tallinn",
        "region": "us",
        "scan_regions": True,
    }
    EufySecurity(
        no_session(),
        SYNTHETIC.email,
        None,
        store=MemoryStore(),
        install=install,
        _cloud_factory=factory,
        **options,
    )
    assert seen["install"] is install
    assert {key: seen[key] for key in options} == options


MEMBER_EMAIL = "member@example.com"
MEMBER_ID = "0000000000000000000000000000000000000042"


async def test_a_station_shared_by_two_accounts_is_served_once() -> None:
    both = {SYNTHETIC.station_sn, OTHER_STATION_SN}
    owners = dict.fromkeys(both, SYNTHETIC.account_id)
    owner_cloud = replace(two_stations(), owner_ids=owners)
    member_cloud = replace(two_stations(), owner_ids=owners, user_id=MEMBER_ID)  # a member
    rebuilds: list[str] = []
    claims = StationClaims(rebuilds.append)
    async with aiohttp.ClientSession() as http:
        member = account(http, member_cloud, email=MEMBER_EMAIL, claims=claims)
        assert {s.serial for s in await member.async_discover()} == both

        owner = account(http, owner_cloud, claims=claims)
        assert {s.serial for s in await owner.async_discover()} == both
        assert rebuilds == [MEMBER_EMAIL]  # the shared account must rebuild

        await member.async_close()
        member = account(http, member_cloud, email=MEMBER_EMAIL, claims=claims)
        assert await member.async_discover() == []
        assert {d.device_sn for d in member.stations_served_elsewhere} == both

        await owner.async_close()
        assert rebuilds == [MEMBER_EMAIL, MEMBER_EMAIL]  # its stations are free again
        assert {s.serial for s in await member.async_discover()} == both
        assert member.stations_served_elsewhere == ()
        await member.async_close()


async def test_credentials_come_from_the_owner() -> None:
    key = "ab" * 32
    cloud = FakeCloud(
        owner_ids={SYNTHETIC.station_sn: OWNER_ID}, cipher_keys={SYNTHETIC.station_sn: key}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)  # both are cached
        await eufy.async_login()
        await eufy.async_discover()
        provider = eufy.stations[SYNTHETIC.station_sn].session._credentials
        creds = await provider(refresh=True, cipher_id=None)
    assert creds.account_id == OWNER_ID
    assert creds.ecc_private_key == key
    assert cloud.calls == ["things", "owner:T8030***2345", "cipher:T8030***2345"]  # both re-read


def _arming(source: EventSource, mode: int, at_ms: int) -> SecurityEvent:
    return SecurityEvent(
        source=source,
        station_sn=SYNTHETIC.station_sn,
        msg_type=9,
        guard_mode=mode,
        event_time_ms=at_ms,
    )


async def test_guard_mode_from_both_channels_is_ordered_and_changes_once() -> None:
    events: list[Event] = []
    cloud = two_stations()
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    now_ms = int(time.time() * 1000)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, store=store)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start(p2p=False)
        push = StubPush.instances[0]
        assert push.started
        station_bus = eufy.stations[SYNTHETIC.station_sn].session._bus
        station_bus.emit(
            GuardModeChanged(
                station_sn=SYNTHETIC.station_sn,
                mode=GuardMode.HOME,
                active_mode=GuardMode.HOME,
                source=EventSource.P2P,
            )
        )  # a 0x047F report
        push.callback(_arming(EventSource.CLOUD, 0, now_ms - 60_000))  # an earlier change, late
        push.callback(_arming(EventSource.CLOUD, 1, now_ms - 5_000))  # the reported change
        p2p_ms = now_ms - 2_300
        station_bus.emit(_arming(EventSource.P2P, 0, p2p_ms))  # a P2P arming push
        push.callback(_arming(EventSource.CLOUD, 0, p2p_ms // 1000 * 1000))  # its cloud copy
        await eufy.async_close()
    assert push.stopped
    changes = [(e.mode, e.source) for e in events if isinstance(e, GuardModeChanged)]
    assert changes == [(GuardMode.HOME, EventSource.P2P), (GuardMode.AWAY, EventSource.P2P)]
    armings = [(e.source, e.guard_mode) for e in events if isinstance(e, SecurityEvent)]
    assert armings == [(EventSource.CLOUD, 1), (EventSource.P2P, 0), (EventSource.CLOUD, 0)]
    assert store.data is not None
    assert store.data["push"]["guard_event_ms"] == {SYNTHETIC.station_sn: p2p_ms}


async def test_a_report_moving_back_after_a_pushed_change_is_delivered() -> None:
    events: list[Event] = []
    now_ms = int(time.time() * 1000)
    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start(p2p=False)
        session = eufy.stations[SYNTHETIC.station_sn].session
        session._note_mode_report(GuardMode.AWAY)  # a 0x047F report
        StubPush.instances[0].callback(_arming(EventSource.CLOUD, 1, now_ms - 5_000))  # the app
        assert session.guard_mode == GuardMode.HOME
        session._note_mode_report(GuardMode.AWAY)  # the station reports it moved back
        await eufy.async_close()
    changes = [(e.mode, e.source) for e in events if isinstance(e, GuardModeChanged)]
    assert changes == [
        (GuardMode.AWAY, EventSource.P2P),
        (GuardMode.HOME, EventSource.CLOUD),
        (GuardMode.AWAY, EventSource.P2P),
    ]


async def test_a_schedule_boundary_on_both_channels_is_one_change() -> None:
    # Each boundary arrives on both channels; with both modes one guard mode, it is one
    # change, not two.
    events: list[Event] = []
    now_ms = int(time.time() * 1000)
    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start(p2p=False)
        session = eufy.stations[SYNTHETIC.station_sn].session
        session._set_modes(GuardMode.SCHEDULE, GuardMode.HOME)  # a parameter dump
        push = StubPush.instances[0]
        for offset, slot in enumerate((GuardMode.AWAY, GuardMode.HOME, GuardMode.DISARMED)):
            session._note_mode_report(slot)  # the boundary's 0x047F
            boundary = replace(
                _arming(EventSource.CLOUD, GuardMode.SCHEDULE, now_ms - 3_000 + offset),
                mode=slot,
                arming_user=0,
                user_name="Eufy Security",
            )
            push.callback(boundary)  # its cloud push, about a second later
        await eufy.async_close()
    changes = [(e.mode, e.active_mode) for e in events if isinstance(e, GuardModeChanged)]
    assert changes == [
        (GuardMode.SCHEDULE, GuardMode.HOME),
        (GuardMode.SCHEDULE, GuardMode.AWAY),
        (GuardMode.SCHEDULE, GuardMode.HOME),
        (GuardMode.SCHEDULE, GuardMode.DISARMED),
    ]


async def test_an_alarm_is_one_start_and_one_end_across_channels() -> None:
    events: list[Event] = []
    now_ms = int(time.time() * 1000)
    station_sn = SYNTHETIC.station_sn

    def alarm(alarming: bool) -> AlarmChanged:
        return AlarmChanged(station_sn=station_sn, alarming=alarming, source=EventSource.P2P)

    def alarm_push(alarm_type: int, at_ms: int) -> SecurityEvent:
        return SecurityEvent(
            source=EventSource.CLOUD,
            station_sn=station_sn,
            msg_type=10,
            alarm_type=alarm_type,
            event_time_ms=at_ms,
        )

    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start(p2p=False)
        bus = eufy.stations[station_sn].session._bus
        push = StubPush.instances[0]
        bus.emit(alarm(True))  # the tone frame
        push.callback(alarm_push(3, now_ms - 50))  # the cloud's copies
        push.callback(alarm_push(25, now_ms - 40))
        bus.emit(alarm(False))  # the tone ended
        push.callback(alarm_push(16, now_ms))  # the app's stop, already known
        push.callback(alarm_push(3, now_ms + 60_000))  # a new alarm, cloud only
        push.callback(_arming(EventSource.CLOUD, GuardMode.DISARMED, now_ms + 61_000))  # a disarm
        await eufy.async_close()
    lifecycle = [(e.alarming, e.source) for e in events if isinstance(e, AlarmChanged)]
    assert lifecycle == [
        (True, EventSource.P2P),
        (False, EventSource.P2P),
        (True, EventSource.CLOUD),
        (False, EventSource.CLOUD),
    ]
    assert sum(isinstance(e, SecurityEvent) and e.msg_type == 10 for e in events) == 4


async def test_guard_mode_stamps_outlive_the_client() -> None:
    cloud = two_stations()
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    now_ms = int(time.time() * 1000)
    delivered: list[int] = []
    for at_ms in (now_ms - 10_000, now_ms - 20_000):  # the second is a redelivered older push
        events: list[Event] = []
        async with aiohttp.ClientSession() as http:
            eufy = account(http, cloud, store=store)
            eufy.subscribe(events.append)
            await eufy.async_login()
            await eufy.async_start(p2p=False)
            StubPush.instances[-1].callback(_arming(EventSource.CLOUD, 1, at_ms))
            await eufy.async_close()
        delivered.append(sum(isinstance(e, GuardModeChanged) for e in events))
    assert delivered == [1, 0]


@pytest.mark.parametrize(
    "failure",
    [CommunicationError("no route to the push service"), RuntimeError("GCM registration failed")],
)
async def test_failed_push_start_does_not_block_local_sessions(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    class BrokenPush(StubPush):
        async def async_start(self) -> None:
            raise failure

    monkeypatch.setattr(fcm_module, "PushListener", BrokenPush)
    started: list[str] = []

    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        await eufy.async_login()
        await eufy.async_discover()
        for station in eufy.stations.values():

            async def fake_start(sn: str = station.serial) -> None:
                started.append(sn)

            monkeypatch.setattr(station, "async_start", fake_start)
        await eufy.async_start()
        await eufy.async_close()
    assert sorted(started) == sorted([SYNTHETIC.station_sn, OTHER_STATION_SN])
    assert StubPush.instances[0].stopped


async def test_start_returns_each_first_start_error_and_the_session_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "DISCOVERY_ATTEMPTS", 1)
    monkeypatch.setattr(session_module, "DISCOVERY_TIMEOUT", 0.3)
    fake = FakeStation()
    await fake.start()
    fake.stop()  # nothing answers on its port
    cloud = FakeCloud.for_stations(fake, FakeStation(serial=OTHER_STATION_SN))
    events: list[Event] = []
    hosts = {SYNTHETIC.station_sn: "127.0.0.1", OTHER_STATION_SN: "127.0.0.1"}
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, station_hosts=hosts, _discovery_port=fake.discovery_port)
        await eufy.async_login()
        await eufy.async_discover()
        eufy.subscribe(events.append)
        errors = await eufy.async_start(push=False)
        await eufy.async_close()
    assert {sn: type(err) for sn, err in errors.items()} == {
        SYNTHETIC.station_sn: StationUnreachableError,
        OTHER_STATION_SN: StationUnreachableError,
    }
    changes = [e for e in events if isinstance(e, ConnectionChanged)]
    assert sorted((e.station_sn, e.connected, e.cause) for e in changes) == [
        (SYNTHETIC.station_sn, False, DisconnectCause.UNREACHABLE),
        (OTHER_STATION_SN, False, DisconnectCause.UNREACHABLE),
    ]
    assert all(e.error is errors[e.station_sn] for e in changes)


@dataclass
class KeyRig:
    """One fake station behind a stub cloud whose key the station accepts only when ``good``.

    ``fetches`` counts forced cipher fetches that returned a key; ``error`` is raised by a
    forced fetch instead. Shared by every client built in a test (a restart included).
    The session cache runs on ``now``, a fake clock.
    """

    fake: FakeStation
    good: bool = False
    fetches: int = 0
    error: CloudError | None = None
    now: float = 1_800_000_000.0
    wrong_key: str = field(default_factory=lambda: FakeStation().ecc_private_key_hex)

    def cloud(self) -> type[StubCloud]:
        rig = self

        class RigCloud(StubCloud):
            async def async_get_station_owner_id(
                self, station_sn: str, *, refresh: bool = False
            ) -> str:
                if refresh:
                    self.cache.note_refresh("owner")  # the device list was re-read
                return SYNTHETIC.account_id

            async def async_get_cipher_keys(
                self, station_sn: str, cipher_id: int = 40, *, refresh: bool = False
            ) -> CipherKeys:
                if refresh:
                    if rig.error is not None:
                        raise rig.error
                    rig.fetches += 1
                return CipherKeys(rig.fake.ecc_private_key_hex if rig.good else rig.wrong_key, None)

        return RigCloud

    def client(self, http: aiohttp.ClientSession, store: MemoryStore) -> EufySecurity:
        return EufySecurity(
            http,
            SYNTHETIC.email,
            "pw",
            store=store,
            station_hosts={SYNTHETIC.station_sn: "127.0.0.1"},
            stations={SYNTHETIC.station_sn: Reach.LOCAL},
            _cloud_factory=cloud_factory(self.cloud()),
            _discovery_port=self.fake.discovery_port,
        )

    async def settle(self, retries: int = 3) -> None:
        """Let the supervisor attempt ``retries`` more handshakes."""
        target = self.fake.conn_inits + retries
        async with asyncio.timeout(10):
            while self.fake.conn_inits < target:
                await asyncio.sleep(0.02)


@pytest.fixture
async def rig(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[KeyRig]:
    fake = FakeStation()
    await fake.start()
    rig = KeyRig(fake)
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    monkeypatch.setattr(storage_module, "time", SimpleNamespace(time=lambda: rig.now))
    yield rig
    fake.stop()


async def wait_for(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(10):
        while not predicate():
            await asyncio.sleep(0.02)


def camera_push(fake: FakeStation, *, event_type: int = 3102, push_count: int = 1) -> None:
    """A P2P camera push for the synthetic camera, 400 ms into the cloud copy's second."""
    inner = {
        "msg_type": 18,
        "event_type": event_type,
        "device_sn": SYNTHETIC.camera_sn,
        "trigger_time": 1_700_000_000_400,
        "push_count": push_count,
        "rec_content": [
            {
                "device_sn": SYNTHETIC.camera_sn,
                "thumb_path": "/zx/Camera00/thumb.jpg",
                "account": SYNTHETIC.account_id,
            }
        ],
    }
    fake.send_json(FrameType.NOTIFY_PAYLOAD, {"cmd": 2037, "payload": json.dumps(inner)})


async def test_both_channels_deliver_each_occurrence_once_across_reconnects(rig: KeyRig) -> None:
    rig.good = True
    events: list[Event] = []

    def detections() -> list[SecurityEvent]:
        return [e for e in events if isinstance(e, SecurityEvent)]

    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, MemoryStore())
        await eufy.async_login()
        await eufy.async_discover()
        eufy.subscribe(events.append)
        await eufy.async_start()
        session = eufy.stations[SYNTHETIC.station_sn].session
        await wait_for(lambda: session.announced)
        StubPush.instances[0].callback(
            SecurityEvent(
                source=EventSource.CLOUD,
                station_sn=SYNTHETIC.station_sn,
                device_sn=SYNTHETIC.camera_sn,
                msg_type=18,
                event_type=3102,
                event_time_ms=1_700_000_000_000,
                push_id="span-1",
            )
        )  # the cloud copy first
        camera_push(rig.fake)  # the P2P copy adds the thumbnail: an enrichment
        camera_push(rig.fake)  # a duplicate
        camera_push(rig.fake, push_count=2)  # a re-announcement
        camera_push(rig.fake, event_type=3107)  # news (and a sentinel)
        await wait_for(lambda: len(detections()) == 3)
        rig.fake.send_close()
        await wait_for(lambda: not session.connected)
        await session.async_get_params()  # reconnected: the ring is the client's
        camera_push(rig.fake)
        camera_push(rig.fake, event_type=3108)
        await wait_for(lambda: len(detections()) == 4)
        dedupe = eufy.deduplicator
        await eufy.async_close()
    assert [(e.source, e.event_type, e.enriches) for e in detections()] == [
        (EventSource.CLOUD, 3102, False),
        (EventSource.P2P, 3102, True),
        (EventSource.P2P, 3107, False),
        (EventSource.P2P, 3108, False),
    ]
    assert detections()[1].thumb_path == "/zx/Camera00/thumb.jpg"
    assert dedupe is not None
    assert (dedupe.dropped_duplicates, dedupe.dropped_repeats) == (2, 1)


@pytest.mark.parametrize(("deduplicate", "delivered"), [(True, 1), (False, 2)])
async def test_deduplication_can_be_turned_off(deduplicate: bool, delivered: int) -> None:
    events: list[Event] = []
    detection = SecurityEvent(
        source=EventSource.CLOUD,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        event_type=3102,
        event_time_ms=1_700_000_000_000,
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, deduplicate=deduplicate)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_start(p2p=False)
        StubPush.instances[0].callback(detection)
        StubPush.instances[0].callback(replace(detection, push_id="another span"))
        await eufy.async_close()
    assert (eufy.deduplicator is not None) is deduplicate
    delivered_events = [e for e in events if isinstance(e, SecurityEvent)]
    assert [e.dedupe_key for e in delivered_events] == [detection.dedupe_key] * delivered


async def test_a_rejected_key_is_refetched_once_until_the_slow_lane_or_a_release(
    rig: KeyRig,
) -> None:
    store = MemoryStore()
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, store)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        errors = await eufy.async_start(push=False)
        assert isinstance(errors[SYNTHETIC.station_sn], KeyRejectedError)
        assert rig.fetches == 1
        assert [e for e in events if isinstance(e, CredentialsRefreshed)] == [
            CredentialsRefreshed(
                station_sn=SYNTHETIC.station_sn, cipher=True, owner_id=True, login=False
            )
        ]

        rig.now += 3600  # past the 15 min cipher cooldown, well inside the slow lane
        await rig.settle()
        assert rig.fetches == 1
        changes = [e for e in events if isinstance(e, ConnectionChanged)]
        assert [(e.cause, type(e.error)) for e in changes] == [
            (DisconnectCause.KEY_REJECTED, KeyRejectedError)
        ]
        await eufy.async_close()

        eufy = rig.client(http, store)  # a restart on the same store: the latch persisted
        await eufy.async_discover()
        errors = await eufy.async_start(push=False)
        assert isinstance(errors[SYNTHETIC.station_sn], KeyRejectedError)
        assert rig.fetches == 1

        rig.now += KEY_REFRESH_SLOW_RETRY  # the slow lane allows one more
        await wait_for(lambda: rig.fetches == 2)
        await rig.settle()
        assert rig.fetches == 2

        await eufy.async_reset_key_refresh(SYNTHETIC.station_sn)  # the release: one more
        await wait_for(lambda: rig.fetches == 3)
        await rig.settle()
        assert rig.fetches == 3
        await eufy.async_close()


async def test_an_accepted_key_clears_the_latch(rig: KeyRig) -> None:
    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, MemoryStore())
        await eufy.async_discover()
        await eufy.async_start(push=False)
        assert eufy.cache.key_refresh_outstanding(SYNTHETIC.station_sn) is not None

        rig.good = True  # the key is accepted again: the next handshake succeeds without a fetch
        station = eufy.stations[SYNTHETIC.station_sn]
        await wait_for(lambda: station.connected)
        assert eufy.cache.key_refresh_outstanding(SYNTHETIC.station_sn) is None
        assert rig.fetches == 1

        rig.good = False  # rotated again: a rejection may fetch once more
        rig.fake.send_close()
        await wait_for(lambda: rig.fetches == 2)
        await eufy.async_close()


@pytest.mark.parametrize(
    "error",
    [
        AuthenticationError("no password: none was given and none is cached"),
        SessionReplacedError(),
        RateLimitedError("throttled", retry_after=1234.0, code=26145),
    ],
)
async def test_a_background_cloud_failure_is_one_cloud_problem_until_a_login(
    rig: KeyRig, error: CloudError
) -> None:
    rig.error = error
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, MemoryStore())
        eufy.subscribe(events.append)
        await eufy.async_discover()
        errors = await eufy.async_start(push=False)
        assert errors[SYNTHETIC.station_sn] is error
        await rig.settle()

        def problems() -> list[CloudProblem]:
            return [e for e in events if isinstance(e, CloudProblem)]

        assert problems() == [CloudProblem(error=error, station_sn=SYNTHETIC.station_sn)]
        assert problems()[0].error is error  # retry_after and code travel with it
        # Delivered once: the station gets only the cause.
        changes = [e for e in events if isinstance(e, ConnectionChanged)]
        assert [(e.cause, e.error) for e in changes] == [
            (DisconnectCause.CREDENTIALS_UNAVAILABLE, None)
        ]
        assert (
            eufy.cache.key_refresh_outstanding(SYNTHETIC.station_sn) is None
        )  # no fetch, no latch

        await eufy.async_login()
        await wait_for(lambda: len(problems()) == 2)  # news again after a success
        await eufy.async_close()


async def test_the_local_cipher_cooldown_is_not_a_cloud_problem(rig: KeyRig) -> None:
    cooldown = RefreshCooldownError("on cooldown", retry_after=600.0)
    rig.error = cooldown
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, MemoryStore())
        eufy.subscribe(events.append)
        await eufy.async_discover()
        await eufy.async_start(push=False)
        await rig.settle()
        await eufy.async_close()
    assert not [e for e in events if isinstance(e, CloudProblem)]
    changes = [e for e in events if isinstance(e, ConnectionChanged)]
    assert [(e.cause, e.error) for e in changes] == [
        (DisconnectCause.CREDENTIALS_UNAVAILABLE, cooldown)
    ]


async def test_push_token_upload_failures_are_cloud_problems() -> None:
    events: list[Event] = []
    kicked = SessionReplacedError()
    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        await eufy.async_start(p2p=False)
        report = StubPush.instances[0].on_token_upload
        assert report is not None
        report(kicked)
        report(kicked)  # a supervisor restart failing the same way
        report(None)  # an upload succeeded
        report(kicked)
        await eufy.async_close()
    assert [e for e in events if isinstance(e, CloudProblem)] == [
        CloudProblem(error=kicked),
        CloudProblem(error=kicked),
    ]


async def test_local_ports_are_pinned_per_station() -> None:
    async with aiohttp.ClientSession() as http:
        eufy = account(http, local_ports={OTHER_STATION_SN: 32110})
        stations = {s.serial: s for s in await eufy.async_discover()}
    assert stations[OTHER_STATION_SN].session.local_port == 32110
    assert stations[SYNTHETIC.station_sn].session.local_port == 0  # not pinned: ephemeral


async def test_the_session_budget_applies_to_every_station_and_changes_per_station() -> None:
    async with aiohttp.ClientSession() as http:
        eufy = account(http, max_sessions=4)
        stations = {s.serial: s for s in await eufy.async_discover()}
    assert {s.max_sessions for s in stations.values()} == {4}
    stations[OTHER_STATION_SN].max_sessions = 9
    assert stations[OTHER_STATION_SN].session.max_sessions == 9
    assert stations[SYNTHETIC.station_sn].max_sessions == 4
    with pytest.raises(ValueError, match="max_sessions"):
        stations[SYNTHETIC.station_sn].max_sessions = 10


def test_a_session_budget_past_the_station_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="max_sessions must be an int from 2 to 9"):
        EufySecurity(
            None,  # type: ignore[arg-type]  # never used: construction fails first
            SYNTHETIC.email,
            "pw",
            store=MemoryStore(),
            max_sessions=10,
        )


async def test_probe_lan_records_where_each_station_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    searched: list[str] = []

    async def fake_discover(*, timeout: float, port: int, target: str) -> list[DiscoveredStation]:
        searched.append(target)
        if target == SYNTHETIC.station_ip:
            return [
                DiscoveredStation(ip=SYNTHETIC.station_ip, port=40000, did=Did.parse(SYNTHETIC.did))
            ]
        raise CommunicationError("no route")  # a failed search is just no reply

    monkeypatch.setattr(discovery_module, "discover_stations", fake_discover)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, two_stations(other_did=OTHER_DID))
        await eufy.async_discover()
        paths = {p.serial: p for p in await eufy.async_probe_lan()}

    assert sorted(searched) == sorted([BROADCAST, SYNTHETIC.station_ip])
    assert paths[SYNTHETIC.station_sn].answered is True
    assert paths[SYNTHETIC.station_sn].observed_ip == SYNTHETIC.station_ip
    assert paths[OTHER_STATION_SN].answered is False
    assert paths[OTHER_STATION_SN].warnings[-1] is PathWarning.NO_LAN_REPLY


async def test_stations_are_included_locally_remotely_or_not_at_all() -> None:
    claims = StationClaims()
    async with aiohttp.ClientSession() as http:
        eufy = account(http, claims=claims, stations={SYNTHETIC.station_sn: Reach.REMOTE})
        assert await eufy.async_discover() == []  # nothing local
        remote = eufy.remote_stations[SYNTHETIC.station_sn]
        assert [d.device_sn for d in remote.sub_devices] == [SYNTHETIC.camera_sn]
        assert OTHER_STATION_SN not in eufy.remote_stations
        assert claims.holder(SYNTHETIC.station_sn) == SYNTHETIC.email
        assert claims.holder(OTHER_STATION_SN) is None  # left out: free for another account

        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_start(p2p=False)
        push = StubPush.instances[-1]
        for serial in (SYNTHETIC.station_sn, OTHER_STATION_SN, "T8030P2000099999"):
            push.callback(SecurityEvent(source=EventSource.CLOUD, station_sn=serial))
        await eufy.async_close()

    received = [e.station_sn for e in events if isinstance(e, SecurityEvent)]
    # The left-out station's push is dropped; an unknown serial (a stale list) is not.
    assert received == [SYNTHETIC.station_sn, "T8030P2000099999"]


async def test_station_choices_offer_every_station_with_its_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_discover(*, timeout: float, port: int, target: str) -> list[DiscoveredStation]:
        if target == SYNTHETIC.station_ip:
            return [
                DiscoveredStation(ip=SYNTHETIC.station_ip, port=40000, did=Did.parse(SYNTHETIC.did))
            ]
        return []

    monkeypatch.setattr(discovery_module, "discover_stations", fake_discover)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, two_stations(other_did=OTHER_DID))
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        assert eufy.stations == {}  # offering builds nothing

    assert choices[SYNTHETIC.station_sn].reach is Reach.LOCAL
    assert choices[SYNTHETIC.station_sn].enabled_by_default
    assert [d.device_sn for d in choices[SYNTHETIC.station_sn].sub_devices] == [SYNTHETIC.camera_sn]
    assert choices[OTHER_STATION_SN].reach is Reach.REMOTE
    assert not choices[OTHER_STATION_SN].enabled_by_default


def test_two_stations_cannot_share_a_local_port() -> None:
    with pytest.raises(ValueError, match="two stations"):
        EufySecurity(
            None,  # type: ignore[arg-type]  # never used: construction fails first
            SYNTHETIC.email,
            "pw",
            store=MemoryStore(),
            local_ports={SYNTHETIC.station_sn: 32109, OTHER_STATION_SN: 32109},
        )


async def test_discover_before_login_keeps_the_stored_cache() -> None:
    """A cloud-backed call before async_login must read the store, not overwrite it."""
    from .cloud.conftest import FakeMega  # noqa: PLC0415 - the cloud harness, only here

    station = {
        "device_sn": SYNTHETIC.station_sn,
        "device_type": 18,
        "p2p_did": SYNTHETIC.did,
        "cloud_region": "eu",
    }
    store = MemoryStore(
        {
            "version": CACHE_VERSION,
            "account": SYNTHETIC.email,
            "openudid": "0011223344556677",
            "devices": [station],
            "cloud": {"listed": {"eu": {"devices": 1, "at": 1.0}, "us": {"devices": 0, "at": 1.0}}},
        }
    )
    fake_mega = FakeMega()
    with aioresponses() as mock:  # nothing may reach a real host
        fake_mega.install(mock)
        async with aiohttp.ClientSession() as http:
            eufy = EufySecurity(http, SYNTHETIC.email, "pw", store=store)
            stations = await eufy.async_discover()
            await eufy.async_close()
    assert [s.serial for s in stations] == [SYNTHETIC.station_sn]
    assert fake_mega.login_calls == 0
    assert store.data is not None
    assert store.data["openudid"] == "0011223344556677"
    assert store.data["devices"] == [station]


async def test_close_is_best_effort_and_forgets_the_stations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    closed: list[str] = []
    async with aiohttp.ClientSession() as http:
        # The stub never writes the cache, so a document in the store is the close's save.
        eufy = EufySecurity(
            http, SYNTHETIC.email, "pw", store=store, _cloud_factory=cloud_factory(StubCloud)
        )
        await eufy.async_login()
        await eufy.async_discover()
        for station in eufy.stations.values():

            async def fake_close(sn: str = station.serial) -> None:
                closed.append(sn)
                if sn == SYNTHETIC.station_sn:
                    raise RuntimeError("socket already gone")

            monkeypatch.setattr(station, "async_close", fake_close)
        await eufy.async_close()
    assert sorted(closed) == sorted(
        [SYNTHETIC.station_sn, OTHER_STATION_SN]
    )  # one failure, both run
    assert eufy.stations == {}
    assert store.data is not None  # saved despite the failure


# ── diagnostics: the redacted cache summary ─────────────────────────────────

_ECC_KEY = "5eed" * 16  # a synthetic cipher-40 key (hex)
_FCM_TOKEN = "synthetic-fcm-registration-token"


def _populated_store() -> MemoryStore:
    """A cache with every section the library writes, all secrets synthetic."""
    cloud = FakeCloud(cipher_keys={SYNTHETIC.station_sn: _ECC_KEY})
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    doc = store.data
    assert doc is not None
    now = time.time()
    doc["push"] = {
        "fcm_credentials": {"gcm": {"token": "synthetic-gcm-token", "android_id": "4242424242"}},
        "registered_token": _FCM_TOKEN,
        "registered_at": int(now),
        "seen_spans": {"synthetic-span-id": int(now)},
        "guard_event_ms": {SYNTHETIC.station_sn: int(now * 1000)},
    }
    doc["replaced"] = {"at": int(now)}
    doc["refresh_attempts"] = {"owner": now - 60}
    station = doc["stations"][SYNTHETIC.station_sn]
    station["key_refresh"] = now - 30
    station["refresh_attempts"] = {"cipher": now - 30}
    doc["stations"][OTHER_STATION_SN] = {}
    doc["throttle"] = {**doc.get("throttle", {}), "requests": now - 1, "login": now - 1}
    return store


def _string_leaves(value: object) -> set[str]:
    if isinstance(value, dict):
        return {k for k in value if isinstance(k, str)} | {
            s for v in value.values() for s in _string_leaves(v)
        }
    if isinstance(value, list):
        return {s for v in value for s in _string_leaves(v)}
    return {value} if isinstance(value, str) else set()


async def test_cache_summary_is_json_safe_and_secret_free() -> None:
    store = _populated_store()
    doc = store.data
    assert doc is not None
    eufy = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=FakeCloud())
    summary = await eufy.async_cache_summary()
    dumped = json.dumps(summary, sort_keys=True)
    assert json.loads(dumped) == summary

    secrets = {
        SYNTHETIC.password,
        SYNTHETIC.email,
        SYNTHETIC.account_id,
        SYNTHETIC.station_sn,
        SYNTHETIC.camera_sn,
        OTHER_STATION_SN,
        SYNTHETIC.did,
        SYNTHETIC.station_ip,
        _ECC_KEY,
        _FCM_TOKEN,
        doc["openudid"],
        doc["cloud"]["sessions"]["eu"]["auth_token"],
        doc["cloud"]["sessions"]["eu"]["shared_key"],
        doc["cloud"]["sessions"]["eu"]["key_ident"],
    }
    # Every value the document holds, and every key that is not a field name the
    # summary may list (the serial keys), must stay out.
    field_names = set(CACHE_SECTIONS) | set(summary["cloud_fields"]) | set(summary["push_fields"])
    field_names |= set().union(*summary["cloud_sessions"].values(), summary["cloud_sessions"])
    field_names |= {"at", "owner", "cipher", "ciphers", "account_id", "key_refresh", "logins"}
    field_names |= {"requests", "login", "refresh_attempts", "40", "gcm", "token", "android_id"}
    field_names |= set().union(*(set(d) for d in doc["devices"]))
    leaves = {s for s in _string_leaves(doc) if len(s) >= 6 and s not in field_names}
    for secret in secrets | leaves:
        assert secret not in dumped, secret

    assert summary["version"] == CACHE_VERSION
    assert summary["sections"] == sorted(CACHE_SECTIONS)
    assert summary["unclassified_sections"] == []
    assert summary["password_cached"] is True
    assert summary["cloud_fields"] == ["listed", "sessions"]
    assert "auth_token" in summary["cloud_sessions"]["eu"]
    assert summary["push_fields"] == sorted(doc["push"])
    assert summary["device_count"] == len(doc["devices"])
    assert set(summary["stations"]) == {"T8030***2345", "T8030***4321"}
    station = summary["stations"]["T8030***2345"]
    assert station["account_id_cached"] is True
    assert station["cipher_cached"] is True
    assert station["key_refresh_outstanding"] is True
    assert 0 < station["cipher_refresh_age"] < 120
    other = summary["stations"]["T8030***4321"]
    assert other["account_id_cached"] is other["cipher_cached"] is False
    assert other["cipher_refresh_age"] is None
    status = summary["cloud_status"]
    assert status["login_need"] == "replaced"
    cloud_status = await eufy.async_cloud_status()
    assert status["logins_in_window"] == cloud_status.logins_in_window
    assert cloud_status.regions
    assert status["regions"].keys() == cloud_status.regions.keys()
    for region, state in cloud_status.regions.items():
        # the ages tick between the two calls
        assert status["regions"][region] == pytest.approx(asdict(state), abs=5)
    assert 0 < status["device_list_refresh_age"] < 120
    assert "stations" not in status


def test_every_cache_section_the_library_writes_is_classified() -> None:
    """An unclassified top-level section fails here until CACHE_SECTIONS classifies it."""
    doc = _populated_store().data
    assert doc is not None
    assert set(doc) == set(CACHE_SECTIONS)  # classified, and the fixture writes them all
    src = Path(storage_module.__file__).parent
    written = {storage_module._REPLACED, *storage_module._KEPT_ACROSS_VERSIONS}
    written |= set(storage_module._KEPT_WHEN_FORGOTTEN)
    patterns = (
        r"section\(\s*\"(\w+)\"",
        r"\bdoc\[\s*\"(\w+)\"\s*\]",
        r"\b_?doc\.(?:get|pop|setdefault)\(\s*\"(\w+)\"",
    )
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            written.update(re.findall(pattern, text))
    assert written - set(CACHE_SECTIONS) == set()


async def test_an_unclassified_section_is_named_but_never_shown() -> None:
    store = _populated_store()
    assert store.data is not None
    store.data["future"] = {"secret": "synthetic-unclassified-value"}
    eufy = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=FakeCloud())
    summary = await eufy.async_cache_summary()
    assert summary["unclassified_sections"] == ["future"]
    assert "synthetic-unclassified-value" not in json.dumps(summary)


# ── push status ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("failure", "event_error", "cloud_problem"),
    [
        (CommunicationError("no route to the push service"), True, False),
        (RateLimitedError("held off", retry_after=60.0), False, True),
    ],
)
async def test_a_failed_push_start_is_reported_once(
    monkeypatch: pytest.MonkeyPatch,
    failure: EufySecurityError,
    event_error: bool,
    cloud_problem: bool,
) -> None:
    class BrokenPush(StubPush):
        async def async_start(self) -> None:
            raise failure

    monkeypatch.setattr(fcm_module, "PushListener", BrokenPush)
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        assert await eufy.async_start(p2p=False) == {}  # push never raises
        assert eufy.push_running is False
        assert eufy.push_error is failure
        await eufy.async_close()
    pushes = [e for e in events if isinstance(e, PushChanged)]
    assert pushes == [PushChanged(running=False)]  # nothing more on close: it never ran
    # A cloud error goes to CloudProblem only, as on ConnectionChanged.
    assert pushes[0].error is (failure if event_error else None)
    problems = [e for e in events if isinstance(e, CloudProblem)]
    expected = [CloudProblem(error=failure)] if isinstance(failure, CloudError) else []
    assert problems == (expected if cloud_problem else [])


async def test_push_status_follows_the_listener_without_an_event_per_retry() -> None:
    events: list[Event] = []
    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        before_start = eufy.push_running
        await eufy.async_start(p2p=False)
        assert (before_start, eufy.push_running) == (False, True)
        report = StubPush.instances[0].on_listening
        assert report is not None
        lost = CommunicationError("the push client stopped listening")
        retry = CommunicationError("still down")
        report(False, lost)  # the supervisor found the client stopped
        report(False, retry)  # a failed restart: same type, no event
        assert (eufy.push_running, eufy.push_error) == (False, retry)
        report(True, None)  # restarted
        assert (eufy.push_running, eufy.push_error) == (True, None)
        await eufy.async_close()
    pushes = [e for e in events if isinstance(e, PushChanged)]
    assert [(e.running, e.error) for e in pushes] == [
        (True, None),
        (False, lost),
        (True, None),
        (False, None),
    ]
    assert eufy.push_running is False


# ── probe on a running account ──────────────────────────────────────────────


async def test_the_lan_probe_never_searches_a_connected_station(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeStation()
    await fake.start()
    cloud = FakeCloud.for_stations(fake)
    cloud.devices.append(station_device(OTHER_STATION_SN, did=OTHER_DID))
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email,
            store=warm_store(email=SYNTHETIC.email, cloud=cloud),
            cloud=cloud,
            stations={fake.serial: fake},
            include={fake.serial: Reach.LOCAL},  # the other station is not built
        )
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.stations[fake.serial].connected)
        searches = fake.searches

        # Every built station is connected: nothing is sent at all.
        (path,) = await eufy.async_probe_lan(timeout=0.3, port=fake.discovery_port)
        assert fake.searches == searches
        assert path.answered is True
        assert path.observed_ip == "127.0.0.1"

        # A station that is not connected is still probed, but not by a broadcast.
        searched: list[str] = []

        async def fake_discover(
            *, timeout: float, port: int, target: str
        ) -> list[DiscoveredStation]:
            searched.append(target)
            return [DiscoveredStation(ip=target, port=40000, did=Did.parse(OTHER_DID))]

        monkeypatch.setattr(discovery_module, "discover_stations", fake_discover)
        choices = {c.serial: c for c in await eufy.async_station_choices(port=fake.discovery_port)}
        assert searched == [SYNTHETIC.station_ip]
        assert choices[fake.serial].reach is Reach.LOCAL
        assert choices[fake.serial].path.observed_ip == "127.0.0.1"
        assert choices[OTHER_STATION_SN].reach is Reach.LOCAL
        assert fake.searches == searches
        assert fake.conn_inits == 1
        await eufy.async_close()
    finally:
        fake.stop()


# ── concurrent start ────────────────────────────────────────────────────────


async def test_stations_start_concurrently_and_one_failure_does_not_hold_up_another(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "DISCOVERY_ATTEMPTS", 1)
    monkeypatch.setattr(session_module, "DISCOVERY_TIMEOUT", 1.0)
    up = FakeStation()
    await up.start()
    down = FakeStation(serial=OTHER_STATION_SN, did=Did.parse(OTHER_DID))
    cloud = FakeCloud.for_stations(up, down)
    events: list[Event] = []
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email,
            store=MemoryStore(),  # a cold cache
            cloud=cloud,
            stations={up.serial: up},
            station_hosts={down.serial: "127.0.0.2"},  # nothing answers there
        )
        await eufy.async_discover()
        eufy.subscribe(events.append)
        errors = await eufy.async_start(push=False)
        await eufy.async_close()
    finally:
        up.stop()
    assert {sn: type(err) for sn, err in errors.items()} == {
        OTHER_STATION_SN: StationUnreachableError
    }
    changes = [(e.station_sn, e.connected) for e in events if isinstance(e, ConnectionChanged)]
    # The reachable station came up before the unreachable one's discovery gave up.
    assert changes.index((up.serial, True)) < changes.index((OTHER_STATION_SN, False))
    # One login and one device list for both stations; a cipher fetch only for the
    # station that answered CONN_INIT. Calls to other regions (``call@region``) are left
    # to the region tests.
    home_region_calls = [call for call in cloud.calls if "@" not in call]
    assert sorted(home_region_calls) == sorted(
        ["login", "devices", "things", f"cipher:{redact_serial(up.serial)}"]
    )


async def test_credential_lookups_of_concurrent_starts_do_not_overlap() -> None:
    in_flight = peak = 0

    class SlowCloud(StubCloud):
        async def async_get_station_owner_id(
            self, station_sn: str, *, refresh: bool = False
        ) -> str:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return SYNTHETIC.account_id

    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http,
            SYNTHETIC.email,
            "pw",
            store=MemoryStore(),
            _cloud_factory=cloud_factory(SlowCloud),
        )
        credentials = await asyncio.gather(
            eufy._credential_provider(SYNTHETIC.station_sn)(refresh=False, cipher_id=None),
            eufy._credential_provider(OTHER_STATION_SN)(refresh=False, cipher_id=None),
        )
    assert [c.account_id for c in credentials] == [SYNTHETIC.account_id, SYNTHETIC.account_id]
    assert peak == 1  # the second waited: a cold cache is fetched once, then read


async def test_the_credential_provider_remembers_the_cipher_a_station_names() -> None:
    key = "aa" * 32
    cloud = FakeCloud(
        owner_ids={SYNTHETIC.station_sn: OWNER_ID}, cipher_keys={SYNTHETIC.station_sn: key}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)

        creds = await provider(refresh=False, cipher_id=None)
        assert (creds.cipher_id, creds.ecc_private_key) == (40, key)

        cloud.calls.clear()
        creds = await provider(refresh=False, cipher_id=98)
        assert creds.cipher_id == 98
        assert eufy.cache.station_cipher_id(SYNTHETIC.station_sn) == 98
        assert cloud.calls.count(f"cipher:{redact_serial(SYNTHETIC.station_sn)}") == 1

        cloud.calls.clear()
        creds = await provider(refresh=False, cipher_id=None)
        assert creds.cipher_id == 98
        assert not [call for call in cloud.calls if call.startswith("cipher:")]

        summary = await eufy.async_cache_summary()
        station = summary["stations"][redact_serial(SYNTHETIC.station_sn)]
        assert (station["cipher_id"], station["cipher_cached"]) == (98, True)
        assert station["cipher_id_named"] is True
        assert "cipher_40_cached" not in station


async def test_the_credential_provider_stores_a_named_default_cipher() -> None:
    cloud = FakeCloud(
        owner_ids={SYNTHETIC.station_sn: OWNER_ID}, cipher_keys={SYNTHETIC.station_sn: "aa" * 32}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        await provider(refresh=False, cipher_id=None)  # the provider's own pick
        assert eufy.cache.station_named_cipher_id(SYNTHETIC.station_sn) is None
        await provider(refresh=False, cipher_id=40)  # named by the station
        assert eufy.cache.station_named_cipher_id(SYNTHETIC.station_sn) == 40
        summary = await eufy.async_cache_summary()
        assert summary["stations"][redact_serial(SYNTHETIC.station_sn)]["cipher_id_named"]


async def test_a_station_connects_with_the_cipher_it_names_and_no_other_is_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    fake = FakeStation(cipher_id=98)
    await fake.start()
    cloud = FakeCloud.for_stations(fake, cipher_ids_held={98})  # this owner has no cipher 40
    store = warm_store(email=SYNTHETIC.email, cloud=replace(cloud, cipher_keys={}))
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=store,
        cloud=cloud,
        stations={fake.serial: fake},
        include={fake.serial: Reach.LOCAL},
    )
    try:
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.stations[fake.serial].connected)
        assert cloud.cipher_ids_requested == [98]
        assert eufy.cache.station_named_cipher_id(fake.serial) == 98
    finally:
        await eufy.async_close()
        fake.stop()


async def test_no_key_for_the_named_cipher_is_one_cloud_problem_and_no_fetch_storm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    fake = FakeStation(cipher_id=98, account_id=OWNER_ID)  # owned by another account
    await fake.start()
    cloud = replace(FakeCloud.for_stations(fake), cipher_keys={})  # the cloud has no key
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=store,
        cloud=cloud,
        stations={fake.serial: fake},
        include={fake.serial: Reach.LOCAL},
    )
    events: list[Event] = []
    eufy.subscribe(events.append)
    try:
        await eufy.async_discover()
        errors = await eufy.async_start(push=False)
        error = errors[fake.serial]
        assert isinstance(error, CipherUnavailableError)
        assert (error.cipher_id, error.owner_source) == (98, "member.admin_user_id")
        assert eufy.cache.station_named_cipher_id(fake.serial) == 98  # kept despite the failure

        inits = fake.conn_inits
        await wait_for(lambda: fake.conn_inits >= inits + 3)  # the supervisor retried
        assert cloud.cipher_ids_requested == [98]  # once: the retries were refused locally
        problems = [e for e in events if isinstance(e, CloudProblem)]
        assert [type(p.error) for p in problems] == [CipherUnavailableError]
        changes = [e for e in events if isinstance(e, ConnectionChanged)]
        assert {e.cause for e in changes} <= {DisconnectCause.CREDENTIALS_UNAVAILABLE}
    finally:
        await eufy.async_close()
        fake.stop()


async def test_discover_builds_a_standalone_station_that_reads_its_one_block() -> None:
    serial = "T8170" + SYNTHETIC.station_sn[5:]
    device = {
        "device_sn": serial,
        "parent_sn": serial,
        "device_type": 48,
        "device_channel": 0,
        "p2p_did": SYNTHETIC.did,
        "device_name": "standalone",
    }
    fake = FakeStation(
        serial=serial,
        cipher_id=98,
        receipt_len=STANDALONE_RECEIPT_LEN,
        params={48: {1224: "1", 1101: "51"}},
    )
    cloud = FakeCloud(
        devices=[device],
        owner_ids={serial: OWNER_ID},
        cipher_keys={serial: fake.ecc_private_key_hex},
    )
    await fake.start()
    try:
        async with aiohttp.ClientSession() as http:
            eufy = account(http, cloud)
            eufy._discovery_port = fake.discovery_port
            eufy._station_hosts = {serial: "127.0.0.1"}
            await eufy.async_login()
            [station] = await eufy.async_discover()
            try:
                assert station.is_standalone is True
                state = await station.async_update(wake=True)
                assert state.devices[0].serial == serial
                assert state.guard_mode is GuardMode.HOME
                assert eufy.cache.station_cipher_id(serial) == 98
            finally:
                await eufy.async_close()
    finally:
        fake.stop()


async def test_on_demand_station_discover_and_start() -> None:
    sn = "T8170P0000000000"
    device = {
        "device_sn": sn,
        "device_type": 48,
        "parent_sn": sn,
        "device_channel": 0,
        "device_name": "Solo",
        "p2p_did": SYNTHETIC.did,
        "local_ip": "127.0.0.1",
        "params": [
            {"param_type": 1101, "param_value": "87", "update_time": 1600000000.0},
            {"param_type": 1224, "param_value": "1", "update_time": 1600000000.0},
        ],
    }
    async with aiohttp.ClientSession() as http:
        fake = FakeStation(serial=sn)
        await fake.start()
        try:
            cloud = FakeCloud(devices=[device])
            client = account(http, cloud)
            client._discovery_port = fake.discovery_port
            client._station_hosts = {sn: "127.0.0.1"}
            await client.async_discover()
            station = client.stations[sn]
            # Discover applies the cloud snapshot, so the on-demand station has state
            # without ever waking the camera.
            assert station.connects_on_demand is True
            assert station.state is not None
            assert station.state.devices[0].battery == 87
            await client.async_start(p2p=True, push=False)
            await asyncio.sleep(0.1)
            assert fake.conn_inits == 0  # a battery station holds no session
            await client.async_close()
        finally:
            fake.stop()


async def test_async_refresh_cloud_state() -> None:
    async with aiohttp.ClientSession() as http:
        # no on-demand
        cloud = FakeCloud(devices=[station_device()])
        client = account(http, cloud, cloud_state_refresh=0.2)
        assert await client.async_refresh_cloud_state() == 0
        assert "devices" not in cloud.calls
        await client.async_close()

        sn = "T8170P0000000000"
        cloud2 = FakeCloud(
            devices=[
                {
                    "device_sn": sn,
                    "device_type": 48,
                    "parent_sn": sn,
                    "device_channel": 0,
                    "device_name": "Solo",
                    "p2p_did": SYNTHETIC.did,
                    "local_ip": "127.0.0.1",
                    "params": [
                        {"param_type": 1101, "param_value": "87", "update_time": 1600000000.0},
                    ],
                }
            ]
        )
        client2 = account(http, cloud2, cloud_state_refresh=0.1)
        await client2.async_discover()

        cloud2.devices[0]["params"].append(
            {"param_type": 1224, "param_value": "1", "update_time": 1600000001.0}
        )
        # With one on-demand station, it fetches the list and returns the number of new values
        count = await client2.async_refresh_cloud_state()
        assert count == 1
        assert cloud2.calls.count("devices") == 1

        events: list[Event] = []
        client2.subscribe(events.append)
        # A failing device-list fetch raises and emits CloudProblem.
        cloud2_original_devices = cloud2.devices

        async def failing_devices(*args: Any, **kwargs: Any) -> list[CloudDevice]:
            raise CloudError("Failed")

        # setattr: assigning over a method is what this test is for, and mypy
        # rejects the plain assignment form.
        setattr(client2.cloud, "async_get_devices", failing_devices)  # noqa: B010
        with pytest.raises(CloudError):
            await client2.async_refresh_cloud_state()

        assert any(isinstance(e, CloudProblem) for e in events)

        # With the cloud back, the refresh loop fetches the device list again.
        delattr(client2.cloud, "async_get_devices")
        cloud2.devices = cloud2_original_devices
        cloud2.calls.clear()

        await client2.async_start(p2p=True, push=False)
        await asyncio.sleep(0.3)
        assert cloud2.calls.count("devices") > 0

        await client2.async_close()
        cloud2.calls.clear()
        await asyncio.sleep(0.2)
        assert cloud2.calls.count("devices") == 0


async def test_guard_mode_push_updates_on_demand_station() -> None:
    async with aiohttp.ClientSession() as http:
        sn = "T8170P0000000000"
        cloud = FakeCloud(
            devices=[
                {
                    "device_sn": sn,
                    "device_type": 48,
                    "parent_sn": sn,
                    "device_channel": 0,
                    "device_name": "Solo",
                    "p2p_did": SYNTHETIC.did,
                }
            ]
        )
        client = account(http, cloud)
        await client.async_discover()

        event = SecurityEvent(
            source=EventSource.CLOUD,
            station_sn=sn,
            device_sn=sn,
            event_type=3103,
            guard_mode=GuardMode.HOME,
            event_time_ms=1800000000000,
            raw={},
        )
        client._deliver(event)
        state = client.stations[sn].state
        assert state is not None
        assert state.guard_mode == GuardMode.HOME

        await client.async_close()


def test_client_rejects_zero_cloud_state_refresh() -> None:
    with pytest.raises(ValueError, match="cloud_state_refresh"):
        EufySecurity(
            no_session(), "test@example.com", "pass", store=MemoryStore(), cloud_state_refresh=0
        )


STANDALONE_SN = "T8170P2000000001"


class FirmwareCloud(StubCloud):
    """Devices across a hub, and a standalone; records which get a firmware check."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.checks: list[tuple[str, str, str]] = []

    async def async_get_devices(
        self, *, refresh: bool = False, rescan_regions: bool = False
    ) -> list[CloudDevice]:
        return [
            CloudDevice(
                device_sn=SYNTHETIC.station_sn,
                device_type=18,
                name="Hub",
                p2p_did=SYNTHETIC.did,
                main_sw_version="3.8.7.4",
            ),
            CloudDevice(
                device_sn=SYNTHETIC.camera_sn,
                device_type=19,
                name="Cam",
                station_sn=SYNTHETIC.station_sn,
                channel=0,
                main_sw_version="3.4.3.0",
            ),
            CloudDevice(  # a standalone battery camera: its own station, no hub — skipped
                device_sn=STANDALONE_SN,
                device_type=48,
                name="Solo",
                station_sn=STANDALONE_SN,
                p2p_did=SYNTHETIC.did,
                main_sw_version="3.2.9.2",
            ),
            CloudDevice(  # a hub device with no reported version — skipped
                device_sn="T8030P2000099999",
                device_type=18,
                name="Quiet hub",
                p2p_did=SYNTHETIC.did,
            ),
        ]

    async def async_check_firmware(
        self,
        device_sn: str,
        *,
        ota_type: str,
        current_version_name: str,
        rom_version: int = 0,
    ) -> Any:
        self.checks.append((device_sn, ota_type, current_version_name))
        if device_sn == SYNTHETIC.camera_sn:
            return SimpleNamespace(device_sn=device_sn, version_name="3.5.0.0")
        return None


async def test_firmware_updates_checks_hub_devices_under_the_kit_type() -> None:
    store = warm_store(email=SYNTHETIC.email, cloud=two_stations())
    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http, SYNTHETIC.email, "pw", store=store, _cloud_factory=cloud_factory(FirmwareCloud)
        )
        updates = await eufy.async_firmware_updates()
        await eufy.async_close()

    cloud = eufy.cloud
    assert isinstance(cloud, FirmwareCloud)
    # The hub and its camera are checked (each with its own serial + version) under the
    # hub's kit type; the standalone and the version-less hub are skipped.
    assert cloud.checks == [
        (SYNTHETIC.station_sn, "T8030_Kit", "3.8.7.4"),
        (SYNTHETIC.camera_sn, "T8030_Kit", "3.4.3.0"),
    ]
    assert [u.device_sn for u in updates] == [SYNTHETIC.camera_sn]


async def test_stations_read_the_model_settings_after_discovery() -> None:
    """A station reads its devices' model settings, loaded off the loop at discovery."""
    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http,
            SYNTHETIC.email,
            "pw",
            store=MemoryStore(),
            _cloud_factory=cloud_factory(StubCloud),
        )
        stations = {s.serial: s for s in await eufy.async_discover()}
        await eufy.async_close()
    home = stations[SYNTHETIC.station_sn]
    assert {s.key for s in home.settings_for()} == set(settings_of("T8030"))
    camera = {s.key: s for s in home.settings_for(SYNTHETIC.camera_sn)}
    assert camera["watermark_set"] is settings_of("T8160")["watermark_set"]


# ── cloud session probe ──────────────────────────────────────────────────────


def _problems(events: list[Event]) -> list[CloudProblem]:
    return [e for e in events if isinstance(e, CloudProblem)]


async def test_the_session_probe_fetches_once_and_applies_nothing() -> None:
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        await eufy.async_discover()
        events: list[Event] = []
        eufy.subscribe(events.append)
        cloud.calls.clear()
        await eufy.async_probe_cloud_session()
        assert cloud.calls == ["devices"]
        assert events == []  # no DevicesChanged, no CloudProblem
        await eufy.async_close()


async def test_a_probe_on_a_kicked_out_session_raises_and_latches_once() -> None:
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        cloud.call_errors = [SessionReplacedError()]
        cloud.calls.clear()
        with pytest.raises(SessionReplacedError):
            await eufy.async_probe_cloud_session()
        assert eufy.session_replaced
        with pytest.raises(SessionReplacedError):
            await eufy.async_probe_cloud_session()  # latched: no I/O, no second problem
        assert cloud.calls == ["devices"]
        assert "login" not in cloud.calls
        assert [type(p.error) for p in _problems(events)] == [SessionReplacedError]

        await eufy.async_login(force=True)
        await eufy.async_probe_cloud_session()
        cloud.call_errors = [SessionReplacedError()]
        with pytest.raises(SessionReplacedError):
            await eufy.async_probe_cloud_session()
        assert len(_problems(events)) == 2  # news again after a success
        await eufy.async_close()


async def test_a_probe_rekeys_a_lapsed_identity_without_a_login() -> None:
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_probe_cloud_session()  # loads the cache
        before = eufy.cache.cloud_session("eu")["key_ident"]
        cloud.call_errors = [FakeCloud.refusal(463, 4404, "get identity error")]
        cloud.calls.clear()
        await eufy.async_probe_cloud_session()
        assert cloud.calls == ["devices", "devices"]  # refused, re-keyed, retried
        assert eufy.cache.cloud_session("eu")["key_ident"] != before
        assert _problems(events) == []
        await eufy.async_close()


async def test_a_probe_does_not_hide_a_refusal_behind_the_cached_list() -> None:
    refusal = FakeCloud.refusal(463, 4404, "get identity error")
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        await eufy.async_discover(refresh=True)  # a cached list exists
        events: list[Event] = []
        eufy.subscribe(events.append)
        cloud.call_errors = [refusal, FakeCloud.refusal(463, 4404, "get identity error")]
        with pytest.raises(KeyExchangeRefusedError):
            await eufy.async_probe_cloud_session()
        assert [type(p.error) for p in _problems(events)] == [KeyExchangeRefusedError]
        assert "login" not in cloud.calls[1:]
        cloud.call_errors = [CommunicationError("no route")]
        with pytest.raises(CommunicationError):
            await eufy.async_probe_cloud_session()  # unreachable: raised, not served stale
        await eufy.async_close()


async def test_a_latched_session_fails_an_on_demand_wake_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no cached DSK and the session latched, no wake can be built: the connect
    fails at once with the session's error instead of searching a LAN a sleeping
    battery camera never answers on."""
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", ("192.0.2.1",))
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        wake = eufy._wake_provider(CloudDevice.from_api(station_device()))
        cloud.call_errors = [SessionReplacedError()]
        with pytest.raises(SessionReplacedError):
            await eufy.async_probe_cloud_session()
        sent = list(cloud.calls)
        with pytest.raises(SessionReplacedError):
            await wake()
        assert cloud.calls == sent  # refused locally
        assert [type(p.error) for p in _problems(events)] == [SessionReplacedError]
        await eufy.async_close()


# ── models without a bundled file ───────────────────────────────────────────

UNBUNDLED = "T9999"


def unbundled_td(*, large_version: int = 1) -> dict[str, Any]:
    return thing_description(
        UNBUNDLED,
        [
            enum_property("motion_sensitivity", {1: "low", 2: "high"}),
            range_property("record_time", 10, 120, unit="s"),
        ],
        large_version=large_version,
    )


def unbundled_cloud(**kwargs: Any) -> FakeCloud:
    """The synthetic station with its camera reporting the unbundled product code."""
    camera = camera_device() | {"device_new_pn": UNBUNDLED}
    return FakeCloud(devices=[station_device(), camera], **kwargs)


async def test_an_unbundled_model_is_listed_read_only_after_one_request() -> None:
    cloud = unbundled_cloud(things={UNBUNDLED: unbundled_td()})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        settings = station.settings_for(SYNTHETIC.camera_sn)
        assert [s.key for s in settings] == ["motion_sensitivity", "record_time"]
        assert all(not s.writable and not s.readable for s in settings)
        assert {s.note for s in settings} == {"not in bundled data"}
        with pytest.raises(UnsupportedError, match="not writable"):
            await station.async_set_setting("motion_sensitivity", 2, device_sn=SYNTHETIC.camera_sn)
        await eufy.async_discover()  # warm: no second request
        await eufy.async_close()
    assert cloud.calls.count("things") == 1
    assert "login" not in cloud.calls


@pytest.fixture
def scan_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    return caplog


def scan_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The client's model-scan lines at INFO and above."""
    return [
        r
        for r in caplog.records
        if r.name == "eufy_home_security.client"
        and r.levelno >= logging.INFO
        and "thing description" in r.getMessage()
    ]


async def test_without_a_session_the_scan_lists_nothing_logs_once_and_retries_on_refresh(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    cloud = unbundled_cloud(
        things={UNBUNDLED: unbundled_td()}, things_error=NoCachedSessionError("no session")
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        assert eufy.model_status() == ()
        (station,) = await eufy.async_discover()
        assert station.settings_for(SYNTHETIC.camera_sn) == ()
        await eufy.async_discover(refresh=True)
        status = {m.product_code: m for m in eufy.model_status()}
        await eufy.async_close()
    assert cloud.calls.count("things") == 2
    assert "login" not in cloud.calls
    assert [r.levelno for r in scan_records(scan_logs)] == [logging.INFO]
    assert status[UNBUNDLED].state == "unknown"


@pytest.mark.parametrize(
    ("things", "error", "level"),
    [
        ({}, CloudError("synthetic"), logging.WARNING),
        ({}, ProtocolError("synthetic"), logging.WARNING),
        ({}, None, logging.INFO),  # the reply omits the code
        ({UNBUNDLED: {"profile": {"product_code": UNBUNDLED}}}, None, logging.WARNING),
    ],
    ids=["cloud-error", "protocol-error", "omitted", "no-properties"],
)
async def test_a_failed_listing_leaves_nothing_and_never_fails_discovery(
    scan_logs: pytest.LogCaptureFixture,
    things: dict[str, Any],
    error: EufySecurityError | None,
    level: int,
) -> None:
    cloud = unbundled_cloud(things=things, things_error=error)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        assert station.settings_for(SYNTHETIC.camera_sn) == ()
        await eufy.async_close()
    assert [r.levelno for r in scan_records(scan_logs)] == [level]


async def test_newer_vendor_data_is_logged_once_and_the_bundled_settings_stay(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    bundled = bundled_td_version("T8160")
    assert bundled is not None
    unbundled_camera = camera_device(NEW_CAMERA_SN, channel=1) | {"device_new_pn": UNBUNDLED}
    cloud = FakeCloud(
        devices=[station_device(), camera_device(), unbundled_camera],
        things={
            "T8160": thing_description("T8160", [], large_version=bundled + 1),
            UNBUNDLED: unbundled_td(),
        },
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        await eufy.async_discover(refresh=True)
        by_key = {s.key: s for s in station.settings_for(SYNTHETIC.camera_sn)}
        status = eufy.model_status()
        await eufy.async_close()
    assert cloud.things_requested == [("T8030", "T8160", UNBUNDLED)] * 2
    newer = f"vendor data for T8160 is newer than bundled (td {bundled + 1} > {bundled})"
    assert [r.getMessage() for r in scan_logs.records].count(newer) == 1
    assert all(by_key[k] == v for k, v in settings_of("T8160").items())
    from eufy_home_security import ModelStatus  # noqa: PLC0415 - the public export

    assert status == (
        ModelStatus("T8030", "bundled", bundled_td_version("T8030"), None),
        ModelStatus("T8160", "bundled", bundled, bundled + 1),
        ModelStatus(UNBUNDLED, "cloud-listed", None, 1),
    )
    assert [m.newer_vendor_data for m in status] == [False, True, False]


async def test_an_all_bundled_account_is_scanned_for_versions_and_stays_quiet(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    cloud = FakeCloud(things_error=NoCachedSessionError("no session"))
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_discover()
        await eufy.async_discover(refresh=True)
        status = eufy.model_status()
        await eufy.async_close()
    assert cloud.calls.count("things") == 2
    assert scan_records(scan_logs) == []
    assert {m.state for m in status} == {"bundled"}
    assert not any(m.newer_vendor_data for m in status)


# ── pending invitations ──────────────────────────────────────────────────────


def _expired() -> _SessionExpiredError:
    return _SessionExpiredError("cloud session expired (code 26006)", code=26006)


async def test_a_region_that_refuses_keeps_no_other_regions_invitations() -> None:
    invite = {"id": 4, "house_id": "house-2", "house_name": "Cottage", "action_user_nick": "Kim"}
    cloud = FakeCloud(region="us", house_invites=[invite])
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    cloud.calls.clear()
    cloud.call_errors = [_expired()]  # eu, asked first
    (pending,) = await eufy.async_pending_invites()
    assert (pending.region, pending.house_name) == ("us", "Cottage")
    assert "login" not in cloud.calls


async def test_pending_invitations_raise_when_no_region_answers() -> None:
    """A lapsed session is no reauth: no login was tried."""
    cloud = FakeCloud()
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    cloud.calls.clear()
    cloud.call_errors = [_expired(), _expired()]
    with pytest.raises(NoCachedSessionError) as caught:
        await eufy.async_pending_invites()
    assert not isinstance(caught.value, AuthenticationError)
    assert "login" not in cloud.calls
