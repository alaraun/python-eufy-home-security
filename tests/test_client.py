from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Network
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, ClassVar, cast

import aiohttp
import pytest
from aioresponses import aioresponses

from eufy_home_security import _logging as logging_module
from eufy_home_security import client as client_module
from eufy_home_security import storage as storage_module
from eufy_home_security._logging import LogThrottle, redact_serial
from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud import crypto
from eufy_home_security.cloud.api import CipherKeys, EufyCloudApi, HttpSession, _SessionExpiredError
from eufy_home_security.cloud.const import KEY_REFRESH_SLOW_RETRY, CloudCode
from eufy_home_security.cloud.models import CloudDevice, CloudInvite
from eufy_home_security.cloud.status import DeviceListSource, LoginNeed
from eufy_home_security.devices.capabilities import Capability
from eufy_home_security.devices.locks import LockState, LockStateSource
from eufy_home_security.devices.model_settings import (
    BATTERY_PROPERTY,
    PARENTLESS_ONLY,
    bundled_td_version,
    settings_of,
)
from eufy_home_security.devices.recipes import connect_type
from eufy_home_security.devices.support import Support
from eufy_home_security.devices.timezones import encode_zone, zone_ids
from eufy_home_security.devices.types import MODELS
from eufy_home_security.events import (
    AlarmChanged,
    CloudProblem,
    ConnectionChanged,
    CredentialsRefreshed,
    DetectedEventsCounted,
    DetectionType,
    DevicesChanged,
    DisconnectCause,
    Event,
    EventSource,
    GuardModeChanged,
    GuardModeOrigin,
    LockStateChanged,
    PushChanged,
    PushPictureSource,
    SecurityEvent,
    StationsChanged,
)
from eufy_home_security.exceptions import (
    AuthenticationError,
    CipherKeyMissingError,
    CipherUnavailableError,
    CloudApiError,
    CloudError,
    CommunicationError,
    EmptyResponseError,
    EufySecurityError,
    InviteCodeError,
    KeyExchangeRefusedError,
    KeyRejectedError,
    NoCachedSessionError,
    ProtocolError,
    RateLimitedError,
    RefreshCooldownError,
    SessionReplacedError,
    StationUnreachableError,
    UnsupportedError,
    VideoEncryptedPictureError,
)
from eufy_home_security.identity import StationClaims
from eufy_home_security.images import JPEG_CONTENT_TYPE, PushImage
from eufy_home_security.inclusion import Reach
from eufy_home_security.install import InstallState
from eufy_home_security.models import PARAM_DETECTED_EVENTS, PARAM_LAN_IP, GuardMode
from eufy_home_security.network import HostSource, PathWarning
from eufy_home_security.p2p import discovery as discovery_module
from eufy_home_security.p2p import netif
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p import transport as transport_module
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation
from eufy_home_security.p2p.media import Still, StillFormat
from eufy_home_security.p2p.messages import STANDALONE_RECEIPT_LEN
from eufy_home_security.p2p.pppp import BROADCAST, encode_sockaddr
from eufy_home_security.p2p.transport import RENDEZVOUS_PORT, ConnectPath, PPPPTransport, Wake
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.push import fcm as fcm_module
from eufy_home_security.push.decode import decode_push
from eufy_home_security.station import Station
from eufy_home_security.storage import CACHE_SECTIONS, CACHE_VERSION, MemoryStore
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    v1_still,
    v2_still,
    warm_store,
)
from eufy_home_security.testing.cloud import (
    camera_device,
    enum_property,
    range_property,
    station_device,
    thing_description,
)
from tests.p2p.test_transport import _PunchToServer

OTHER_STATION_SN = "T8030P2000054321"
OTHER_DID = "EUPRAMA-654321-ABCDE"
OWNER_ID = "fedcba9876543210fedcba9876543210fedcba98"  # a station owner other than this account
KEYS_OPTIONAL = {"keys_optional": True}  # as a session passes it after an RSA CONN_INIT


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
        self.device_list_source: DeviceListSource | None = "fetched"

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
    assert home.session.expect_channels == home.channels  # every probe waits for them
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
    model_settings._resolved.cache_clear()
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


@pytest.mark.parametrize("refresh", ["discover", "cloud_state"])
async def test_a_refresh_takes_the_stations_new_firmware_into_its_routing(refresh: str) -> None:
    """A HomeBase 3 updated into the range where the eufy app routes a paired T8L60 over
    WebRTC: after either device-list refresh the camera's pan/tilt and live are graded as
    routed, without a reload."""
    camera_sn = "T8L60P2000067890"
    hub = station_device() | {"main_sw_version": "3.8.0.0"}
    camera = camera_device(camera_sn) | {"device_new_pn": "T8L60"}
    cloud = FakeCloud(devices=[hub, camera])
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (home,) = await eufy.async_discover()
        assert not home.app_uses_webrtc(camera_sn)
        assert home.ptz_support(camera_sn, Capability.PTZ_CONTROL).support is Support.DECLARED
        hub["main_sw_version"] = "3.8.8.0"
        if refresh == "discover":
            await eufy.async_discover(refresh=True)
        else:
            await eufy.async_refresh_cloud_state()
        await eufy.async_close()
    assert home.device.main_sw_version == "3.8.8.0"
    assert home.app_uses_webrtc(camera_sn)
    control = home.ptz_support(camera_sn, Capability.PTZ_CONTROL)
    assert control.support is Support.UNKNOWN
    assert "over WebRTC" in control.source
    assert home.live_support(camera_sn).support is Support.UNKNOWN


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
LONG_DID_STATION_SN = "T8030P3000000001"
LONG_DID_CAMERA_SN = "T8113P3000000002"
LONG_DID = "TESTPRA-000123456-ABCDE12345"  # 9 digits, 10-character suffix
WEBRTC_STATION_SN = "T9000P4000000001"
WEBRTC_CAMERA_SN = "T8160P4000000002"


class BadSerialCloud(StubCloud):
    """The stub's devices plus every kind of device the grouping skips.

    A station with no serial, a camera with a bad serial,
    a product with no P2P id, a camera paired to a station not on the list, and a
    station the eufy app reaches only over WebRTC with its camera.
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
            CloudDevice(
                device_sn=LONG_DID_STATION_SN, device_type=18, name="Far", p2p_did=LONG_DID
            ),
            CloudDevice(
                device_sn=LONG_DID_CAMERA_SN,
                device_type=7,
                name="Behind far",
                station_sn=LONG_DID_STATION_SN,
                channel=0,
            ),
            CloudDevice(
                device_sn=WEBRTC_STATION_SN, device_type=18, name="Pro", p2p_did=SYNTHETIC.did
            ),
            CloudDevice(
                device_sn=WEBRTC_CAMERA_SN,
                device_type=19,
                name="Behind pro",
                station_sn=WEBRTC_STATION_SN,
                channel=0,
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
        (redact_serial(LONG_DID_STATION_SN), "bad_did"),
        (redact_serial(WEBRTC_STATION_SN), "webrtc_only"),
        (redact_serial(VACUUM_SN), "no_did"),
        (redact_serial(ORPHAN_SN), "orphan"),
        (redact_serial(LONG_DID_CAMERA_SN), "orphan"),
        (redact_serial(WEBRTC_CAMERA_SN), "webrtc_only"),
    ]
    skipped = [r for r in caplog.records if "skipping device" in r.getMessage()]
    assert [r.levelname for r in skipped] == [
        "WARNING",
        "WARNING",
        "WARNING",
        "WARNING",
        "INFO",
        "WARNING",
        "WARNING",
        "INFO",
    ]
    assert "only over WebRTC" in skipped[3].getMessage()
    assert "its P2P id is not one local P2P accepts" in skipped[2].getMessage()
    assert LONG_DID not in caplog.text
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
    assert cloud.calls == [
        "things",
        "owner:T8030***2345",
        "houses",
        "cipher:T8030***2345",
    ]  # both re-read


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
    changes = [(e.mode, e.source, e.origin) for e in events if isinstance(e, GuardModeChanged)]
    assert changes == [
        (GuardMode.HOME, EventSource.P2P, GuardModeOrigin.REPORT),
        (GuardMode.AWAY, EventSource.P2P, GuardModeOrigin.PUSH),  # the P2P arming push
    ]
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
    changes = [(e.mode, e.source, e.origin) for e in events if isinstance(e, GuardModeChanged)]
    assert changes == [
        (GuardMode.AWAY, EventSource.P2P, GuardModeOrigin.REPORT),
        (GuardMode.HOME, EventSource.CLOUD, GuardModeOrigin.PUSH),
        (GuardMode.AWAY, EventSource.P2P, GuardModeOrigin.REPORT),
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
        session._param_state.set_modes(GuardMode.SCHEDULE, GuardMode.HOME)  # a parameter dump
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

    states: list[bool] = []  # the station's alarming at each AlarmChanged

    async with aiohttp.ClientSession() as http:
        eufy = account(http)
        eufy.subscribe(events.append)
        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start(p2p=False)
        station = eufy.stations[station_sn]
        eufy.subscribe(
            lambda e: states.append(station.alarming) if isinstance(e, AlarmChanged) else None
        )
        bus = station.session._bus
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
    assert states == [alarming for alarming, _ in lifecycle]
    assert not station.alarming
    cloud_start = [e for e in events if isinstance(e, AlarmChanged)][2]
    assert cloud_start.event_time == datetime.fromtimestamp((now_ms + 60_000) / 1000, UTC)
    assert station.last_alarm is not None
    assert station.last_alarm.at.tzinfo is UTC  # the disarm that ended it, as last seen
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
        camera_push(rig.fake, event_type=3107)  # a new kind: an enrichment (and a sentinel)
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
        (EventSource.P2P, 3107, True),
        (EventSource.P2P, 3108, False),
    ]
    assert detections()[1].thumb_path == "/zx/Camera00/thumb.jpg"
    assert dedupe is not None
    assert (dedupe.dropped_duplicates, dedupe.dropped_repeats) == (2, 1)


async def test_admitted_pushes_do_not_create_counter_events(rig: KeyRig) -> None:
    """Pushes remain SecurityEvents even when the detected-events counter is absent."""
    rig.good = True
    rig.fake.params[0].pop(PARAM_DETECTED_EVENTS, None)
    events: list[Event] = []

    def counted() -> list[DetectedEventsCounted]:
        return [event for event in events if isinstance(event, DetectedEventsCounted)]

    def detections() -> list[SecurityEvent]:
        return [event for event in events if isinstance(event, SecurityEvent)]

    async with aiohttp.ClientSession() as http:
        eufy = rig.client(http, MemoryStore())
        eufy.subscribe(events.append)

        await eufy.async_login()
        await eufy.async_discover()
        await eufy.async_start()

        station = eufy.stations[SYNTHETIC.station_sn]
        await wait_for(lambda: station.session.announced)
        initial = await station.async_update()
        assert initial.devices[0].detected_events is None

        push = StubPush.instances[0]
        first = SecurityEvent(
            source=EventSource.CLOUD,
            station_sn=SYNTHETIC.station_sn,
            device_sn=SYNTHETIC.camera_sn,
            msg_type=18,
            event_type=int(DetectionType.MOTION),
            event_time_ms=1_700_000_000_000,
            unique_id="activity-first",
        )
        push.callback(first)
        assert counted() == []
        assert detections() == [first]

        rig.fake.params[0][PARAM_DETECTED_EVENTS] = "20"
        await station.async_update()  # new counter starts a baseline
        assert counted() == []

        second = replace(first, unique_id="activity-second", event_time_ms=1_700_000_001_000)
        push.callback(second)
        assert detections() == [first, second]
        assert counted() == []

        rig.fake.params[0][PARAM_DETECTED_EVENTS] = "21"
        await station.async_update()
        assert [event.count for event in counted()] == [1]
        await eufy.async_close()


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


# ── rendezvous probe in the station choices ─────────────────────────────────

BATTERY_SN = "T8134P2000012345"
"""A standalone battery camera: reached on demand."""
BATTERY_DID = "EUPRAMA-654322-ABCDE"
SERVERS = ("192.0.2.1",)


class Punches:
    """Stands in for ``PPPPTransport.punch_probe``: records each probe's DID and wake,
    holds it while ``gate`` is set and not released, then answers a punch for a DID in
    ``reached``, else raises :class:`StationUnreachableError`."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, reached: Sequence[str] = ()) -> None:
        self.probed: list[str] = []
        self.wakes: list[Wake] = []
        self.reached = set(reached)
        self.gate: asyncio.Event | None = None
        self.in_flight = 0
        self.peak = 0

        async def punch_probe(
            _transport: PPPPTransport, *, expected_did: Did, wake: Wake, timeout: float
        ) -> tuple[str, int]:
            self.probed.append(str(expected_did))
            self.wakes.append(wake)
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            try:
                await (self.gate.wait() if self.gate is not None else asyncio.sleep(0))
            finally:
                self.in_flight -= 1
            if str(expected_did) in self.reached:
                return ("192.0.2.77", 40000)
            raise StationUnreachableError("no punch through 1 rendezvous server within 5s")

        monkeypatch.setattr(PPPPTransport, "punch_probe", punch_probe)


def _lan_answers(monkeypatch: pytest.MonkeyPatch, *answering: tuple[str, str]) -> None:
    """LAN discovery answers each (ip, did) when that ip is searched, nothing else."""

    async def fake_discover(*, timeout: float, port: int, target: str) -> list[DiscoveredStation]:
        return [
            DiscoveredStation(ip=ip, port=40000, did=Did.parse(did))
            for ip, did in answering
            if target == ip
        ]

    monkeypatch.setattr(discovery_module, "discover_stations", fake_discover)


def _with_battery(cloud: FakeCloud) -> FakeCloud:
    cloud.devices.append(station_device(BATTERY_SN, did=BATTERY_DID, name="Battery"))
    return cloud


def _dsk_calls(cloud: FakeCloud) -> list[str]:
    return [call for call in cloud.calls if call.startswith("dsk:")]


@pytest.fixture
def servers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", SERVERS)


@pytest.mark.usefixtures("servers")
async def test_a_mains_station_only_its_servers_reach_is_offered_as_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The station answering LAN discovery costs no DSK and no punch; the one only a
    punch reaches is local, through its servers; a battery station is not probed."""
    _lan_answers(monkeypatch, (SYNTHETIC.station_ip, SYNTHETIC.did))
    punches = Punches(monkeypatch, reached=[OTHER_DID])
    cloud = _with_battery(two_stations(other_did=OTHER_DID))
    cloud.dsk_keys[OTHER_STATION_SN] = "dsk-of-the-garage-probe"
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        assert eufy.stations == {}
        await eufy.async_close()

    home, garage, battery = (
        choices[sn] for sn in (SYNTHETIC.station_sn, OTHER_STATION_SN, BATTERY_SN)
    )
    assert (home.rendezvous, home.reachable_via, home.reach) == (None, ConnectPath.LAN, Reach.LOCAL)
    assert (garage.rendezvous, garage.reachable_via) == (True, ConnectPath.RENDEZVOUS)
    assert garage.reach is Reach.LOCAL
    assert garage.enabled_by_default
    assert garage.path.answered is False  # the LAN advice still applies
    assert (battery.rendezvous, battery.reachable_via, battery.reach) == (None, None, Reach.REMOTE)
    assert battery.connects_on_demand
    assert not garage.connects_on_demand
    assert punches.probed == [OTHER_DID]
    assert [wake.servers for wake in punches.wakes] == [SERVERS]
    assert _dsk_calls(cloud) == [f"dsk:{redact_serial(OTHER_STATION_SN)}"]
    assert b"dsk-of-the-garage-probe" in logging_module._SECRET_BYTES  # starred in hexdumps


DECLARED_BATTERY_SN = "T81A0P2000012345"
"""A standalone camera off the app's on-demand list whose settings declare the battery
device flag."""
HELD_SN = "T8203P2000012345"
"""A standalone doorbell off the list whose settings do not declare the flag: held."""


@pytest.mark.usefixtures("servers")
async def test_a_station_whose_settings_declare_the_battery_flag_is_not_probed_through_its_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The setup probe and the choice follow the stations' on-demand rule: a camera off
    the app's list whose settings declare the battery device flag is not woken; a doorbell
    without the flag is probed."""
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    cloud = FakeCloud(
        devices=[
            station_device(DECLARED_BATTERY_SN, did=BATTERY_DID, name="Wall light"),
            station_device(HELD_SN, did=OTHER_DID, name="Doorbell"),
        ]
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        await eufy.async_close()

    battery, held = choices[DECLARED_BATTERY_SN], choices[HELD_SN]
    assert (battery.connects_on_demand, battery.rendezvous) == (True, None)
    assert (held.connects_on_demand, held.rendezvous) == (False, False)
    assert punches.probed == [OTHER_DID]
    assert _dsk_calls(cloud) == [f"dsk:{redact_serial(HELD_SN)}"]


@pytest.mark.usefixtures("servers")
async def test_a_station_its_servers_do_not_reach_stays_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, two_stations(other_did=OTHER_DID))
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        await eufy.async_close()

    assert sorted(punches.probed) == sorted([SYNTHETIC.did, OTHER_DID])
    for choice in choices.values():
        assert (choice.rendezvous, choice.reachable_via, choice.reach) == (
            False,
            None,
            Reach.REMOTE,
        )


async def test_a_station_without_rendezvous_servers_is_not_probed_through_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch, reached=[OTHER_DID])
    cloud = two_stations(other_did=OTHER_DID)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        choices = await eufy.async_station_choices()
        await eufy.async_close()

    assert punches.probed == []
    assert _dsk_calls(cloud) == []
    assert {c.rendezvous for c in choices} == {None}


@pytest.mark.usefixtures("servers")
@pytest.mark.parametrize(
    "error",
    [
        FakeCloud.refusal(200, 26050, "no dsk"),
        SessionReplacedError(),
        FakeCloud.refusal(401),  # an expired session: never a login here
    ],
    ids=["refused", "replaced", "expired"],
)
async def test_without_a_dsk_the_choices_keep_the_lan_result(
    monkeypatch: pytest.MonkeyPatch, error: EufySecurityError
) -> None:
    """A cloud failure (reported as a CloudProblem, as for a connect) leaves the
    station unprobed; nothing logs in."""
    _lan_answers(monkeypatch, (SYNTHETIC.station_ip, SYNTHETIC.did))
    punches = Punches(monkeypatch, reached=[OTHER_DID])
    cloud = two_stations(other_did=OTHER_DID)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        calls = len(cloud.calls)
        cloud.call_errors = [error]
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        await eufy.async_close()

    garage = choices[OTHER_STATION_SN]
    assert (garage.rendezvous, garage.reach) == (None, Reach.REMOTE)
    assert punches.probed == []
    assert "login" not in cloud.calls[calls:]
    (problem,) = _problems(events)
    assert problem.station_sn == OTHER_STATION_SN


@pytest.mark.usefixtures("servers")
async def test_a_connected_station_is_not_probed_and_reports_its_links_path(
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
            include={fake.serial: Reach.LOCAL},
        )
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.stations[fake.serial].connected)
        _lan_answers(monkeypatch)
        punches = Punches(monkeypatch)
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        assert punches.probed == [OTHER_DID]
        assert choices[fake.serial].reachable_via is ConnectPath.LAN
        assert choices[fake.serial].rendezvous is None

        # A link that came through the servers says so.
        eufy.stations[fake.serial].session._connect_path = ConnectPath.RENDEZVOUS
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        assert punches.probed == [OTHER_DID] * 2
        assert choices[fake.serial].rendezvous is True
        assert choices[fake.serial].reachable_via is ConnectPath.RENDEZVOUS
        await eufy.async_close()
    finally:
        fake.stop()


@pytest.mark.usefixtures("servers")
@pytest.mark.parametrize(
    ("last_link", "rendezvous"),
    [(ConnectPath.RENDEZVOUS, True), (ConnectPath.LAN, None), (None, None)],
)
async def test_a_built_station_that_is_down_reports_its_last_link_unprobed(
    monkeypatch: pytest.MonkeyPatch, last_link: ConnectPath | None, rendezvous: bool | None
) -> None:
    """A built station's own session reconnects it, through the servers too: the setup
    probe sends it no punch of its own and reports how its last link came up."""
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, two_stations(other_did=OTHER_DID))
        await eufy.async_discover()
        home = eufy.stations[SYNTHETIC.station_sn]
        assert not home.session.connected
        home.session._connect_path = last_link
        choices = {c.serial: c for c in await eufy.async_station_choices()}
        await eufy.async_close()

    assert SYNTHETIC.did not in punches.probed
    assert choices[SYNTHETIC.station_sn].rendezvous is rendezvous


@pytest.mark.usefixtures("servers")
async def test_cancelling_the_choices_call_cancels_the_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller cancelled during the rendezvous probe: no probe keeps running and no
    queued probe starts afterwards."""
    monkeypatch.setattr(client_module, "RENDEZVOUS_PROBE_CONCURRENCY", 2)
    monkeypatch.setattr(client_module, "RENDEZVOUS_PROBE_BUDGET", 30.0)
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    punches.gate = asyncio.Event()
    async with aiohttp.ClientSession() as http:
        eufy = account(http, _mains_stations(4))
        task = asyncio.create_task(eufy.async_station_choices(timeout=0.1))
        await wait_for(lambda: punches.in_flight == 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.05)
        in_flight_after_cancel = punches.in_flight
        punches.gate.set()
        await asyncio.sleep(0.1)
        probed_total = len(punches.probed)
        await eufy.async_close()
    assert (in_flight_after_cancel, probed_total) == (0, 2)


def _mains_stations(count: int) -> FakeCloud:
    return FakeCloud(
        devices=[
            station_device(f"T8030P20000{n:05d}", did=f"EUPRAMA-65{n:04d}-ABCDE", name=f"S{n}")
            for n in range(count)
        ]
    )


@pytest.mark.usefixtures("servers")
async def test_rendezvous_probes_run_concurrently_up_to_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module, "RENDEZVOUS_PROBE_CONCURRENCY", 2)
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    punches.gate = asyncio.Event()
    async with aiohttp.ClientSession() as http:
        eufy = account(http, _mains_stations(5))
        task = asyncio.create_task(eufy.async_station_choices())
        await wait_for(lambda: punches.in_flight == 2)
        await asyncio.sleep(0.05)
        assert (punches.in_flight, len(punches.probed)) == (2, 2)
        punches.gate.set()
        choices = await asyncio.wait_for(task, 5)
        await eufy.async_close()

    assert len(punches.probed) == 5
    assert punches.peak == 2
    assert {c.rendezvous for c in choices} == {False}


@pytest.mark.usefixtures("servers")
async def test_the_rendezvous_probes_end_within_their_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Probes still running at the budget's end are cancelled and report nothing."""
    monkeypatch.setattr(client_module, "RENDEZVOUS_PROBE_BUDGET", 0.2)
    _lan_answers(monkeypatch)
    punches = Punches(monkeypatch)
    punches.gate = asyncio.Event()  # never released
    async with aiohttp.ClientSession() as http:
        eufy = account(http, _mains_stations(2))
        loop = asyncio.get_running_loop()
        started = loop.time()
        choices = await asyncio.wait_for(eufy.async_station_choices(timeout=0.1), 5)
        elapsed = loop.time() - started
        await eufy.async_close()

    assert len(punches.probed) == 2
    assert punches.in_flight == 0  # cancelled, not left running
    assert elapsed < 1.5
    assert {(c.rendezvous, c.reach) for c in choices} == {(None, Reach.REMOTE)}


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
        ["login", "devices", "houses", "things", f"cipher:{redact_serial(up.serial)}"]
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


async def test_a_station_naming_no_cipher_gets_credentials_without_a_cipher_fetch() -> None:
    """Cipher 0 (an RSA CONN_INIT with no session key) needs no cipher keys: only the
    owner id is fetched."""
    cloud = FakeCloud(
        owner_ids={SYNTHETIC.station_sn: OWNER_ID}, cipher_keys={SYNTHETIC.station_sn: "aa" * 32}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_login()
        cloud.calls.clear()
        creds = await eufy._credential_provider(SYNTHETIC.station_sn)(refresh=False, cipher_id=0)
    assert (creds.cipher_id, creds.ecc_private_key, creds.rsa_private_key) == (0, "", None)
    assert creds.account_id == OWNER_ID
    assert not [call for call in cloud.calls if call.startswith("cipher:")]


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


@pytest.mark.parametrize(
    ("records", "error_type"),
    [({}, CipherUnavailableError), ({98: {}}, CipherKeyMissingError)],
    ids=["no_record", "keyless_record"],
)
async def test_no_key_for_the_named_cipher_is_one_cloud_problem_and_no_fetch_storm(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[int, dict[str, str]],
    error_type: type[EmptyResponseError],
) -> None:
    """An ECIES station's cipher the cloud serves no key for (no record, or one without a
    key): one CloudProblem of that empty answer, one request per back-off."""
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    fake = FakeStation(cipher_id=98, account_id=OWNER_ID)  # owned by another account
    await fake.start()
    cloud = replace(  # the cloud has no key
        FakeCloud.for_stations(fake), cipher_keys={}, cipher_records=records
    )
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
        assert type(error) is error_type
        assert isinstance(error, (CipherUnavailableError, CipherKeyMissingError))
        assert error.cipher_id == 98
        if isinstance(error, CipherUnavailableError):
            assert error.owner_source == "member.admin_user_id"
        assert eufy.cache.station_named_cipher_id(fake.serial) == 98  # kept despite the failure

        inits = fake.conn_inits
        await wait_for(lambda: fake.conn_inits >= inits + 3)  # the supervisor retried
        assert cloud.cipher_ids_requested == [98]  # once: the retries were refused locally
        problems = [e for e in events if isinstance(e, CloudProblem)]
        assert [type(p.error) for p in problems] == [error_type]
        changes = [e for e in events if isinstance(e, ConnectionChanged)]
        assert {e.cause for e in changes} <= {DisconnectCause.CREDENTIALS_UNAVAILABLE}
    finally:
        await eufy.async_close()
        fake.stop()


@pytest.mark.parametrize(
    ("served", "requested"),
    [("none", [1]), ("keyless_record", [1]), ("ecc_only", [1, 1])],
)
async def test_an_rsa_station_without_a_served_key_runs_under_the_static_key(
    monkeypatch: pytest.MonkeyPatch, served: str, requested: list[int]
) -> None:
    """A station answering the RSA CONN_INIT names a cipher the cloud serves no RSA key
    for (no record, a record without keys, one with only the ECC key): the session runs
    under the static key, as the eufy app does: one CONN_INIT per connect, no handshake
    failure, no CloudProblem, and reconnects inside the back-off ask the cloud nothing."""
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    fake = FakeStation(
        cipher_id=1, account_id=OWNER_ID, conn_init_version=1, static_key_session=True
    )
    await fake.start()
    base = FakeCloud.for_stations(fake)
    cloud = replace(
        base,
        cipher_keys=base.cipher_keys if served == "ecc_only" else {},
        rsa_cipher_keys={},
        cipher_records={1: {}} if served == "keyless_record" else {},
    )
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
        assert await eufy.async_start(push=False) == {}
        session = eufy.stations[fake.serial].session
        assert session.static_key_session
        assert fake.conn_inits == 1
        calls = list(cloud.calls)
        for connects in (2, 3, 4):
            session._teardown("test reconnect")
            async with asyncio.timeout(10):
                while not (fake.conn_inits >= connects and session.connected):
                    await asyncio.sleep(0.02)
            assert session.static_key_session
            assert fake.conn_inits == connects
        assert session.stats().handshake_failures == 0
        assert cloud.cipher_ids_requested == requested
        assert cloud.calls == calls  # no cloud request on a reconnect
        assert not [e for e in events if isinstance(e, (CloudProblem, CredentialsRefreshed))]
    finally:
        await eufy.async_close()
        fake.stop()


async def test_keys_optional_credentials_without_a_served_key_carry_the_owner_only() -> None:
    """``keys_optional`` (an RSA handshake): the cloud's empty answer for the cipher gives
    the owner's credentials without keys, no CloudProblem and no refresh event; within
    the back-off a refresh asks nothing. Without it the empty answer still raises."""
    cloud = FakeCloud(owner_ids={SYNTHETIC.station_sn: OWNER_ID})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        creds = await provider(refresh=False, cipher_id=1, **KEYS_OPTIONAL)
        again = await provider(refresh=True, cipher_id=1, **KEYS_OPTIONAL)
        assert creds == again
        assert (creds.account_id, creds.cipher_id) == (OWNER_ID, 1)
        assert (creds.ecc_private_key, creds.rsa_private_key) == ("", None)
        assert cloud.cipher_ids_requested == [1]
        assert not [e for e in events if isinstance(e, (CloudProblem, CredentialsRefreshed))]
        with pytest.raises(CipherUnavailableError):
            await provider(refresh=False, cipher_id=1)


async def test_keys_optional_credentials_for_a_keyless_record_carry_the_owner_only() -> None:
    """A ``get_ciphers`` record for the cipher that carries no key: with ``keys_optional``
    the owner's credentials without keys, asked once per back-off; without it a
    :class:`CipherKeyMissingError` (an ``EmptyResponseError``), again without a request."""
    cloud = FakeCloud(owner_ids={SYNTHETIC.station_sn: OWNER_ID}, cipher_records={1: {}})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        creds = await provider(refresh=False, cipher_id=1, **KEYS_OPTIONAL)
        assert creds == await provider(refresh=True, cipher_id=1, **KEYS_OPTIONAL)
        assert (creds.account_id, creds.ecc_private_key, creds.rsa_private_key) == (
            OWNER_ID,
            "",
            None,
        )
        assert not [e for e in events if isinstance(e, CloudProblem)]
        with pytest.raises(CipherKeyMissingError) as err:
            await provider(refresh=False, cipher_id=1)
        assert isinstance(err.value, EmptyResponseError)
        assert err.value.retry_after > 0
        assert cloud.cipher_ids_requested == [1]


@pytest.mark.parametrize(
    "error",
    [
        CommunicationError("no route"),
        RateLimitedError("slow down", retry_after=60.0),
        CloudApiError(10000, "server error"),
    ],
    ids=["network", "rate_limit", "api"],
)
async def test_keys_optional_credentials_keep_a_failed_cipher_fetch_an_error(
    error: EufySecurityError,
) -> None:
    """A cipher fetch that fails (network, rate limit, an error code) is no "no key"
    answer: it raises with ``keys_optional`` too."""
    cloud = FakeCloud(owner_ids={SYNTHETIC.station_sn: OWNER_ID})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        await eufy.cloud.async_get_station_owner_id(SYNTHETIC.station_sn)
        cloud.call_errors = [error]
        with pytest.raises(type(error)):
            await provider(refresh=False, cipher_id=1, **KEYS_OPTIONAL)


async def test_keys_optional_credentials_still_need_the_owner_id() -> None:
    cloud = FakeCloud(devices=[])  # the station is not on this account: no owner id
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        with pytest.raises(CloudApiError, match="not on this account"):
            await provider(refresh=False, cipher_id=1, **KEYS_OPTIONAL)
        assert cloud.cipher_ids_requested == []


@pytest.mark.parametrize(
    ("rsa_handshake", "served", "refreshed"),
    [
        (False, ("ecc", "rsa"), True),
        (True, ("ecc", "rsa"), True),
        (True, ("rsa",), True),
        (True, ("ecc",), False),
        (False, ("rsa",), False),
    ],
    ids=["ecies", "rsa", "rsa_only", "rsa_handshake_ecc_only", "ecies_rsa_only"],
)
async def test_a_refresh_is_announced_only_when_the_handshake_key_came_back(
    rsa_handshake: bool, served: tuple[str, ...], refreshed: bool
) -> None:
    """``CredentialsRefreshed`` follows a forced fetch that returned the key the
    handshake uses: the RSA key after an RSA CONN_INIT (``keys_optional``), else the
    ECC key. A fetch without it (an RSA station left on the static key) announces none."""
    cloud = FakeCloud(
        owner_ids={SYNTHETIC.station_sn: OWNER_ID},
        cipher_keys={SYNTHETIC.station_sn: "11" * 32} if "ecc" in served else {},
        rsa_cipher_keys={SYNTHETIC.station_sn: "rsa key"} if "rsa" in served else {},
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_login()
        provider = eufy._credential_provider(SYNTHETIC.station_sn)
        await provider(refresh=True, cipher_id=1, **(KEYS_OPTIONAL if rsa_handshake else {}))
        assert cloud.cipher_ids_requested == [1]
        assert [e.station_sn for e in events if isinstance(e, CredentialsRefreshed)] == (
            [SYNTHETIC.station_sn] if refreshed else []
        )


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


def standalone_device(sn: str, **extra: Any) -> dict[str, Any]:
    """A device that is its own station, with its catalogued cloud device type."""
    model = MODELS[sn[:5]]
    return {
        "device_sn": sn,
        "device_type": model.cloud_device_type,
        "parent_sn": sn,
        "device_channel": 0,
        "device_name": "Solo",
        "p2p_did": SYNTHETIC.did,
        "local_ip": "127.0.0.1",
    } | extra


# T8170: on the eufy app's on-demand list. T81A0: a battery camera the list leaves out.
@pytest.mark.parametrize("sn", ["T8170P0000000000", "T81A0P0000000000"])
async def test_on_demand_station_discover_and_start(sn: str) -> None:
    device = standalone_device(
        sn,
        params=[
            {"param_type": 1101, "param_value": "87", "update_time": 1600000000.0},
            {"param_type": 1224, "param_value": "1", "update_time": 1600000000.0},
        ],
    )
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


@pytest.mark.parametrize(
    ("sn", "on_demand", "battery"),
    [
        ("T8170P0000000000", True, True),  # on the app's list
        ("T8153P0000000000", True, None),  # on the app's list, no settings
        ("T81A0P0000000000", True, True),  # off the list, the battery device flag
        ("T84A1P0000000000", False, False),  # wired wall light: the flag declared False
        ("T8203P0000000000", False, True),  # a doorbell listing a battery, without the flag
        ("T8191P0000000000", False, None),  # a camera without settings: unknown
        ("T8030P0000000000", False, None),  # a HomeBase: not a camera or doorbell
    ],
)
async def test_a_station_is_reached_on_demand_by_the_app_list_or_the_battery_device_flag(
    sn: str, on_demand: bool, battery: bool | None
) -> None:
    cloud = FakeCloud(devices=[standalone_device(sn)])
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        assert station.connects_on_demand is on_demand
        assert station.has_battery() is battery
        await eufy.async_close()


async def test_a_standalone_doorbells_pushed_press_reaches_the_consumer() -> None:
    """A press pushed in the ``doorbell`` body arrives as the doorbell's DOORBELL_PRESS."""
    sn = "T8200" + SYNTHETIC.camera_sn[5:]
    body = {"event_type": "3103", "event_time": str(int(time.time())), "device_sn": sn}
    message = {"app_tab": "eufy_security", "type": "5", "span_id": "s1", "station_sn": sn}
    async with aiohttp.ClientSession() as http:
        eufy = account(http, FakeCloud(devices=[standalone_device(sn)]))
        await eufy.async_discover()
        events: list[Event] = []
        eufy.subscribe(events.append)
        await eufy.async_start(p2p=False)
        StubPush.instances[-1].callback(decode_push(message | {"doorbell": json.dumps(body)}))
        await eufy.async_close()
    presses = [
        (e.station_sn, e.device_sn)
        for e in events
        if isinstance(e, SecurityEvent) and e.detection is DetectionType.DOORBELL_PRESS
    ]
    assert presses == [(sn, sn)]


async def test_a_hub_gets_the_cloud_refresh_loop_and_a_missing_copy_is_fetched_at_start() -> None:
    """A hub's cloud copy (its settings the dump lacks) is refreshed on the interval;
    a list cached without station parameters is fetched once when the stations start."""
    fake = FakeStation()
    await fake.start()
    cloud = FakeCloud.for_stations(fake)
    cloud.devices[0].pop("params")  # as a list cached before station entries kept them
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email,
            store=MemoryStore(),
            cloud=cloud,
            stations={fake.serial: fake},
            cloud_state_refresh=0.2,
        )
        await eufy.async_discover()
        station = eufy.stations[fake.serial]
        before = station.has_cloud_copy
        cloud.devices[0]["params"] = [{"param_type": 1235, "param_value": "26"}]
        cloud.calls.clear()
        await eufy.async_start(push=False)
        assert cloud.calls.count("devices") == 1  # at start, not after the interval
        assert (before, station.has_cloud_copy) == (False, True)
        await asyncio.sleep(0.5)
        assert cloud.calls.count("devices") >= 2  # the loop runs without an on-demand station
        await eufy.async_close()
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


async def test_a_hubs_cloud_copy_comes_from_the_list_and_its_refresh() -> None:
    """Discovery (cached list included) gives a hub its cloud copy; an explicit refresh
    fetches the list once and updates it; nothing wakes or polls on its own."""
    fake = FakeStation()
    cloud = FakeCloud.for_stations(fake)
    cloud.devices[0]["params"] = [{"param_type": 1065, "param_value": "1", "update_time": 1.7e9}]
    cloud.devices[0]["time_zone"] = encode_zone(zone_ids()[1])
    await fake.start()
    try:
        async with aiohttp.ClientSession() as http:
            eufy = account(http, cloud, cloud_state_refresh=0.1)
            eufy._discovery_port = fake.discovery_port
            eufy._station_hosts = {SYNTHETIC.station_sn: "127.0.0.1"}
            [station] = await eufy.async_discover()
            assert "devices" not in cloud.calls  # the warm cache carried the copy
            try:
                state = await station.async_update()
                assert state.setting("device_cross_cam_tracking_swtich") is True
                assert state.setting("timezone_set") == zone_ids()[1]
                assert state.cloud_param_ids == (1065, 1215)

                cloud.devices[0]["params"][0]["param_value"] = "0"
                cloud.devices[0]["params"][0]["update_time"] = 1.7e9 + 1
                assert await eufy.async_refresh_cloud_state() == 1
                assert cloud.calls.count("devices") == 1
                assert station.state is not None
                assert station.state.setting("device_cross_cam_tracking_swtich") is False

                await eufy.async_start(p2p=False, push=False)
                await asyncio.sleep(0.3)
                assert cloud.calls.count("devices") == 1  # no loop without an on-demand station
            finally:
                await eufy.async_close()
    finally:
        fake.stop()


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


@pytest.mark.usefixtures("door_models")
async def test_a_lock_push_sets_the_state_of_the_station_it_is_paired_to() -> None:
    lock_sn = "T8502P2000000001"
    lock = {
        "device_sn": lock_sn,
        "device_type": 52,
        "parent_sn": SYNTHETIC.station_sn,
        "device_channel": 1,
        "device_name": "Front",
    }
    async with aiohttp.ClientSession() as http:
        client = account(http, FakeCloud(devices=[station_device(), lock]))
        await client.async_discover()
        seen: list[Event] = []
        client.subscribe(seen.append)
        try:
            client._deliver(
                SecurityEvent(
                    source=EventSource.CLOUD,
                    station_sn=SYNTHETIC.station_sn,
                    device_sn=lock_sn,
                    event_type=264,  # locked from the app
                    event_time_ms=int(time.time() * 1000),
                    raw={},
                )
            )
            reading = client.stations[SYNTHETIC.station_sn].lock_state(lock_sn)
        finally:
            await client.async_close()
    assert reading is not None
    assert (reading.state, reading.source, reading.event_type) == (
        LockState.LOCKED,
        LockStateSource.PUSH,
        264,
    )
    changed = [e for e in seen if isinstance(e, LockStateChanged)]
    assert [(e.device_sn, e.state) for e in changed] == [(lock_sn, LockState.LOCKED)]
    assert isinstance(seen[0], SecurityEvent)  # the push itself first


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
    behind = connect_type(SYNTHETIC.station_sn, SYNTHETIC.camera_sn)
    assert camera["watermark_set"] is settings_of("T8160", behind)["watermark_set"]


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
        assert cloud.calls == ["devices", "houses"]
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
        assert cloud.calls == ["devices", "devices", "houses"]  # refused, re-keyed, retried
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


async def test_only_a_fetched_dsk_counts_as_a_cloud_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DSK from the cache made no cloud call: it leaves a reported cloud problem
    reported, so the same failure again stays quiet. A fetched one makes it news."""
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", ("192.0.2.1",))
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        wake = eufy._wake_provider(CloudDevice.from_api(station_device()))
        serial = SYNTHETIC.station_sn

        async def failing_fetch() -> None:
            eufy.cache.drop_dsk_key(serial)
            cloud.call_errors = [FakeCloud.refusal(200, 26050, "no dsk")]
            assert await wake() is None

        await failing_fetch()
        assert len(_problems(events)) == 1
        eufy.cache.set_dsk_key(serial, "cached-dsk", time.time() + 3600)
        assert (await wake()) == Wake(servers=("192.0.2.1",), dsk="cached-dsk")
        await failing_fetch()
        assert len(_problems(events)) == 1  # the cache hit was no success
        eufy.cache.drop_dsk_key(serial)
        assert await wake() is not None  # fetched
        await failing_fetch()
        assert len(_problems(events)) == 2
        await eufy.async_close()


async def test_concurrent_connects_fetch_one_dsk_per_station(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A held and a short-lived session of one station, and a second station, all
    connecting at once: one ``get_dsk_keys`` per station."""
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", ("192.0.2.1",))
    fetch = EufyCloudApi._fetch_dsk

    async def slow_fetch(api: EufyCloudApi, station_sn: str, **kwargs: Any) -> Any:
        await asyncio.sleep(0.01)  # the request is in flight while the others ask
        return await fetch(api, station_sn, **kwargs)

    monkeypatch.setattr(EufyCloudApi, "_fetch_dsk", slow_fetch)
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        home = eufy._wake_provider(CloudDevice.from_api(station_device()))
        other = eufy._wake_provider(CloudDevice.from_api(garage_device()))
        await asyncio.gather(home(), home(), home(), other(), other())
        fetches = [call for call in cloud.calls if call.startswith("dsk:")]
        assert sorted(fetches) == sorted(
            f"dsk:{redact_serial(sn)}" for sn in (SYNTHETIC.station_sn, OTHER_STATION_SN)
        )
        await eufy.async_close()


async def test_every_station_gets_the_rendezvous_and_its_reported_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A held station has the rendezvous connect as well (see ``_rendezvous_on``);
    one without a configured or cloud address also searches the address it reports."""
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", ("192.0.2.1",))
    garage = garage_device() | {
        "params": [{"param_type": PARAM_LAN_IP, "param_value": "192.0.2.77"}]
    }
    cloud = FakeCloud(devices=[station_device(), camera_device(), garage])
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        stations = {s.serial: s for s in await eufy.async_discover()}
        home, other = stations[SYNTHETIC.station_sn], stations[OTHER_STATION_SN]
        assert not home.connects_on_demand
        assert home.session._wake_provider is not None
        assert other.session._wake_provider is not None
        assert (home.session.extra_hosts, other.session.extra_hosts) == ((), ("192.0.2.77",))
        assert other.lan_path.host_source is HostSource.DEVICE
        assert home.lan_path.host_source is HostSource.CLOUD
        await eufy.async_close()


async def test_a_cached_only_wake_never_calls_the_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    """``cached_only``: the wake from a fresh cached DSK, else None, with no fetch and
    no cloud problem either way."""
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", ("192.0.2.1",))
    async with aiohttp.ClientSession() as http:
        cloud = FakeCloud()
        eufy = account(http, cloud)
        events: list[Event] = []
        eufy.subscribe(events.append)
        wake = eufy._wake_provider(CloudDevice.from_api(station_device()))
        serial = SYNTHETIC.station_sn
        sent = list(cloud.calls)
        assert await wake(cached_only=True) is None
        eufy.cache.set_dsk_key(serial, "cached-dsk", time.time() + 3600)
        assert await wake(cached_only=True) == Wake(servers=("192.0.2.1",), dsk="cached-dsk")
        eufy.cache.set_dsk_key(serial, "stale-dsk", time.time() + 1)  # inside the margin
        assert await wake(cached_only=True) is None
        assert cloud.calls == sent
        assert _problems(events) == []
        await eufy.async_close()


async def test_a_cached_only_wake_without_servers_is_none() -> None:
    async with aiohttp.ClientSession() as http:
        eufy = account(http, FakeCloud())
        eufy.cache.set_dsk_key(SYNTHETIC.station_sn, "cached-dsk", time.time() + 3600)
        wake = eufy._wake_provider(CloudDevice.from_api(station_device()))
        assert await wake(cached_only=True) is None
        await eufy.async_close()


def _link_path_store(cloud: FakeCloud, paths: Mapping[str, object]) -> MemoryStore:
    """A warm store whose station entries hold ``paths`` as their last link path."""
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    assert store.data is not None
    for serial, path in paths.items():
        store.data.setdefault("stations", {}).setdefault(serial, {})["link_path"] = path
    return store


async def test_a_station_session_starts_from_the_cached_link_path() -> None:
    """The path a station's last link took, kept in the cache, is the session's initial
    one: a station last reached through its servers goes there on the first attempt
    after a restart."""
    cloud = two_stations()
    store = _link_path_store(cloud, {SYNTHETIC.station_sn: "rendezvous"})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, store=store)
        stations = {s.serial: s for s in await eufy.async_discover()}
        assert stations[SYNTHETIC.station_sn].session.connect_path is ConnectPath.RENDEZVOUS
        assert stations[SYNTHETIC.station_sn].session._rendezvous_on(1)
        assert stations[OTHER_STATION_SN].session.connect_path is None  # none stored
        await eufy.async_close()


async def test_a_link_records_its_path_in_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """A station kept as last reached through its servers that the LAN answers is
    stored as ``"lan"`` once its link is up, and survives the close."""
    fake = FakeStation()
    await fake.start()
    cloud = FakeCloud.for_stations(fake)
    store = _link_path_store(cloud, {fake.serial: "rendezvous"})
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email, store=store, cloud=cloud, stations={fake.serial: fake}
        )
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.cache.link_path(fake.serial) is ConnectPath.LAN)
        await eufy.async_close()
    finally:
        fake.stop()
    assert store.data is not None
    assert store.data["stations"][fake.serial]["link_path"] == "lan"


async def test_the_link_path_is_saved_only_when_it_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saves: list[float] = []
    monkeypatch.setattr(
        storage_module.SessionCache, "schedule_save", lambda self, delay=0.0: saves.append(delay)
    )
    cloud = two_stations()
    store = _link_path_store(cloud, {SYNTHETIC.station_sn: "lan"})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, store=store)
        stations = {s.serial: s for s in await eufy.async_discover()}
        session = stations[SYNTHETIC.station_sn].session
        up = ConnectionChanged(station_sn=SYNTHETIC.station_sn, connected=True)
        eufy._on_station_event(up)  # still lan
        assert saves == []
        session._connect_path = ConnectPath.RENDEZVOUS
        eufy._on_station_event(up)
        eufy._on_station_event(up)
        assert len(saves) == 1
        assert eufy.cache.link_path(SYNTHETIC.station_sn) is ConnectPath.RENDEZVOUS
        session._connect_path = ConnectPath.LAN
        eufy._on_station_event(ConnectionChanged(station_sn=SYNTHETIC.station_sn, connected=False))
        eufy._on_station_event(  # a link of a station this client did not build
            ConnectionChanged(station_sn="T8030P2000099999", connected=True)
        )
        assert len(saves) == 1
        await eufy.async_close()


@pytest.mark.parametrize("refresh", [False, True])
async def test_a_station_the_list_no_longer_names_loses_its_link_path(refresh: bool) -> None:
    """A whole list, the cached one or one fetched now, drops the path of a station it
    does not name."""
    cloud = FakeCloud(devices=[station_device(), camera_device()])
    store = _link_path_store(
        cloud, {SYNTHETIC.station_sn: "rendezvous", OTHER_STATION_SN: "rendezvous"}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, store=store)
        await eufy.async_discover(refresh=refresh)
        assert eufy.device_list_source == ("fetched" if refresh else "cache")
        assert eufy.cache.link_path(SYNTHETIC.station_sn) is ConnectPath.RENDEZVOUS
        assert eufy.cache.link_path(OTHER_STATION_SN) is None
        assert store.data is not None
        assert "link_path" not in store.data["stations"][OTHER_STATION_SN]  # saved at once
        await eufy.async_close()


async def test_a_listed_station_this_client_does_not_build_keeps_its_link_path() -> None:
    """A station the list still names keeps its path whether or not it is built here
    (included remote, or served by another account)."""
    cloud = two_stations()
    store = _link_path_store(
        cloud, {SYNTHETIC.station_sn: "rendezvous", OTHER_STATION_SN: "rendezvous"}
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(
            http,
            cloud,
            store=store,
            stations={SYNTHETIC.station_sn: Reach.LOCAL, OTHER_STATION_SN: Reach.REMOTE},
        )
        await eufy.async_discover()
        assert set(eufy.stations) == {SYNTHETIC.station_sn}
        assert eufy.cache.link_path(OTHER_STATION_SN) is ConnectPath.RENDEZVOUS
        await eufy.async_close()


@pytest.mark.parametrize("source", ["fallback", "unsent"])
async def test_a_list_that_is_not_whole_drops_no_link_path(
    monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    """A list the cloud did not answer whole (a failed refresh's fallback, or nothing
    sent while every scope is suspended) names no station's absence: every kept path
    stays."""
    cloud = FakeCloud(devices=[station_device(), camera_device()])
    store = _link_path_store(cloud, {OTHER_STATION_SN: "rendezvous"})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud, store=store)
        listed = eufy.cloud.async_get_devices

        async def partial(**kwargs: Any) -> list[CloudDevice]:
            devices = await listed(**kwargs)
            eufy.cloud.device_list_source = source  # type: ignore[assignment]
            return devices

        monkeypatch.setattr(eufy.cloud, "async_get_devices", partial)
        await eufy.async_discover()
        assert eufy.cache.link_path(OTHER_STATION_SN) is ConnectPath.RENDEZVOUS
        await eufy.async_close()


STATION_LAN = "192.0.2.77"
"""The punch-tested station's LAN address; routed to its loopback session socket."""
SERVER = ("192.0.2.1", RENDEZVOUS_PORT)
"""The station's rendezvous server; routed to a loopback :class:`_PunchToServer`."""


def _route_punches(monkeypatch: pytest.MonkeyPatch, fake: FakeStation, server_port: int) -> None:
    """Every transport the client opens reaches :data:`SERVER` at ``server_port`` and
    :data:`STATION_LAN` at the fake's session socket (its discovery socket at the
    discovery port), all on loopback, and drops the rest of what goes to the server's
    host."""
    connect = PPPPTransport.connect

    async def routed(transport: PPPPTransport, host: str | None, **kwargs: Any) -> Did:
        send, receive = transport._sendto, transport.datagram_received
        start_alive = transport._start_alive_thread
        station = ("127.0.0.1", fake.session_port)
        server = ("127.0.0.1", server_port)

        def sendto(packet: bytes, addr: tuple[str, int]) -> None:
            if addr == SERVER:
                send(packet, server)
            elif addr == (STATION_LAN, fake.discovery_port):
                send(packet, ("127.0.0.1", fake.discovery_port))
            elif addr[0] == STATION_LAN:
                send(packet, station)
            elif addr[0] != SERVER[0]:
                send(packet, addr)

        def received(data: bytes, addr: tuple[str | Any, int]) -> None:
            if addr == station:
                addr = (STATION_LAN, addr[1])
            elif addr == server:
                addr = SERVER
            receive(data, addr)

        transport._sendto = sendto  # type: ignore[method-assign]
        transport.datagram_received = received  # type: ignore[method-assign]
        transport._start_alive_thread = lambda peer: start_alive(  # type: ignore[method-assign]
            station if peer[0] == STATION_LAN else peer
        )
        return await connect(transport, host, **kwargs)

    monkeypatch.setattr(PPPPTransport, "connect", routed)


@pytest.mark.parametrize(
    ("stored", "networks", "path"),
    [
        (None, (IPv4Network("192.0.2.0/24"),), ConnectPath.LAN),
        ("rendezvous", (IPv4Network("192.0.2.0/24"),), ConnectPath.LAN),
        (None, (IPv4Network("198.51.100.0/24"),), ConnectPath.RENDEZVOUS),
    ],
)
async def test_a_station_answering_the_punch_first_is_stored_by_this_hosts_networks(
    monkeypatch: pytest.MonkeyPatch,
    stored: str | None,
    networks: tuple[IPv4Network, ...],
    path: ConnectPath,
) -> None:
    """A station that ignores the LAN search (as once after a close) and answers the
    punch toward its LAN address, with its DSK cached: in one of this host's networks
    the link is stored as ``"lan"`` (a stored ``"rendezvous"`` too), on another subnet
    as ``"rendezvous"``. No ``get_dsk_keys`` is sent."""
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 0.3)
    fake = FakeStation(ignore_searches=1000, answers_punch=True)
    await fake.start()
    server = _PunchToServer([encode_sockaddr(STATION_LAN, fake.session_port)])
    endpoint, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: server, local_addr=("127.0.0.1", 0)
    )
    _route_punches(monkeypatch, fake, endpoint.get_extra_info("sockname")[1])
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", (SERVER[0],))
    monkeypatch.setattr(netif, "local_networks", lambda: networks)
    cloud = FakeCloud.for_stations(fake)
    store = _link_path_store(cloud, {} if stored is None else {fake.serial: stored})
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=store, cloud=cloud, stations={fake.serial: fake}
    )
    try:
        await eufy.async_discover()
        eufy.cache.set_dsk_key(fake.serial, "cached-dsk", time.time() + 3600)
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: eufy.cache.link_path(fake.serial) is path)
        assert eufy.stations[fake.serial].session.stats().connects_by_path == {str(path): 1}
    finally:
        await eufy.async_close()
        fake.stop()
        endpoint.close()
    assert fake.searches > 0  # searched, and ignored
    assert not [call for call in cloud.calls if call.startswith("dsk:")]
    assert store.data is not None
    assert store.data["stations"][fake.serial]["link_path"] == str(path)


async def _punch_only_station(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FakeStation, asyncio.DatagramTransport]:
    """A started station at :data:`STATION_LAN` that ignores every LAN search but
    answers a punch, and its rendezvous server naming that address (the endpoint to
    close)."""
    fake = FakeStation(ignore_searches=1000, answers_punch=True)
    await fake.start()
    server = _PunchToServer([encode_sockaddr(STATION_LAN, fake.session_port)])
    endpoint, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: server, local_addr=("127.0.0.1", 0)
    )
    _route_punches(monkeypatch, fake, endpoint.get_extra_info("sockname")[1])
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", (SERVER[0],))
    return fake, endpoint


@pytest.mark.parametrize("override", [False, True])
async def test_a_station_whose_lan_reply_is_blocked_shows_it_on_its_lan_path(
    monkeypatch: pytest.MonkeyPatch, override: bool
) -> None:
    """A station on this host's network that never answers the LAN search but answers
    the punch toward its LAN address: linked after the on-link grace, as a LAN link,
    and its ``lan_path`` warns ``lan_reply_blocked`` at the address it answered from,
    with no local port pinned (discovery searches that address). The host's networks
    come from the interfaces, or from ``local_networks`` when given (the interfaces then
    unread)."""
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 0.3)
    fake, endpoint = await _punch_only_station(monkeypatch)
    ours = (IPv4Network("192.0.2.0/24"),)
    reads: list[None] = []

    def reader() -> tuple[IPv4Network, ...]:
        reads.append(None)
        return ours

    monkeypatch.setattr(netif, "local_networks", reader)
    cloud = FakeCloud.for_stations(fake)
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=MemoryStore(),
        cloud=cloud,
        stations={fake.serial: fake},
        station_hosts={fake.serial: STATION_LAN},
        local_networks=list(ours) if override else None,
    )
    try:
        await eufy.async_discover()
        station = eufy.stations[fake.serial]
        assert PathWarning.LAN_REPLY_BLOCKED not in station.lan_path.warnings
        eufy.cache.set_dsk_key(fake.serial, "cached-dsk", time.time() + 3600)
        started = time.monotonic()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: station.session.stats().connects == 1)
        assert time.monotonic() - started >= 0.3
        stats = station.session.stats()
        assert stats.connect_path == "lan"
        assert stats.lan_reply_blocked is True
        path = station.lan_path
        assert PathWarning.LAN_REPLY_BLOCKED in path.warnings
        assert PathWarning.EPHEMERAL_PORT in path.warnings
        assert path.station_ip == STATION_LAN
        assert path.local_port == 0
        assert bool(reads) is not override
        await wait_for(lambda: eufy.cache.lan_reply_blocked(fake.serial))
        assert eufy.cache.link_path(fake.serial) is ConnectPath.LAN
        # A probe while the link is up reports it from the session, warning kept.
        (probed,) = await eufy.async_probe_lan()
        assert probed.answered is None
        assert PathWarning.LAN_REPLY_BLOCKED in probed.warnings
    finally:
        await eufy.async_close()
        fake.stop()
        endpoint.close()
    assert fake.searches > 0  # searched at its address, and ignored


async def test_no_local_networks_means_no_station_is_on_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``local_networks=[]``: this host has no network to treat as on-link. The station
    above is punched at once (no grace) and links as ``"rendezvous"``, never flagged;
    the interfaces are not read."""
    monkeypatch.setattr(transport_module, "ON_LINK_PUNCH_GRACE", 2.0)
    fake, endpoint = await _punch_only_station(monkeypatch)

    def unread() -> tuple[IPv4Network, ...]:
        raise AssertionError("the interfaces were read")

    monkeypatch.setattr(netif, "local_networks", unread)
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=MemoryStore(),
        cloud=FakeCloud.for_stations(fake),
        stations={fake.serial: fake},
        station_hosts={fake.serial: STATION_LAN},
        local_networks=[],
    )
    try:
        await eufy.async_discover()
        station = eufy.stations[fake.serial]
        eufy.cache.set_dsk_key(fake.serial, "cached-dsk", time.time() + 3600)
        started = time.monotonic()
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: station.session.stats().connects == 1)
        assert time.monotonic() - started < 1.0
        stats = station.session.stats()
        assert stats.connect_path == "rendezvous"
        assert stats.lan_reply_blocked is False
        assert PathWarning.LAN_REPLY_BLOCKED not in station.lan_path.warnings
    finally:
        await eufy.async_close()
        fake.stop()
        endpoint.close()


@pytest.mark.parametrize(
    "networks",
    [
        ["192.0.2.0/24"],
        [IPv6Network("2001:db8::/32")],
        [IPv4Address("192.0.2.1")],
        IPv4Network("192.0.2.0/30"),  # a network, not a sequence of them
    ],
)
def test_local_networks_take_only_ipv4_networks(networks: Any) -> None:
    with pytest.raises(ValueError, match="local_networks"):
        EufySecurity(
            no_session(),
            SYNTHETIC.email,
            None,
            store=MemoryStore(),
            local_networks=networks,
            _cloud_factory=cloud_factory(StubCloud),
        )


async def test_a_station_stored_with_a_blocked_lan_reply_warns_and_goes_to_the_servers_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The kept record of an earlier run: the station's ``lan_path`` warns before its
    first link, and its first attempt runs the rendezvous with a DSK fetched from the
    cloud (no LAN-only first attempt); its LAN link then clears the record."""
    fake = FakeStation()
    await fake.start()
    calls: list[bool] = []
    connect = PPPPTransport.connect

    async def recording(transport: PPPPTransport, host: str | None, **kwargs: Any) -> Did:
        calls.append(kwargs.get("wake") is not None)
        kwargs.pop("wake", None)
        return await connect(transport, host, **kwargs)

    monkeypatch.setattr(PPPPTransport, "connect", recording)
    monkeypatch.setattr(CloudDevice, "rendezvous_servers", (SERVER[0],))
    cloud = FakeCloud.for_stations(fake)
    store = _link_path_store(cloud, {fake.serial: "lan"})
    assert store.data is not None
    store.data["stations"][fake.serial]["lan_reply_blocked"] = True
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=store, cloud=cloud, stations={fake.serial: fake}
    )
    try:
        await eufy.async_discover()
        station = eufy.stations[fake.serial]
        assert PathWarning.LAN_REPLY_BLOCKED in station.lan_path.warnings
        assert await eufy.async_start(push=False) == {}
        await wait_for(lambda: not eufy.cache.lan_reply_blocked(fake.serial))
        assert PathWarning.LAN_REPLY_BLOCKED not in station.lan_path.warnings
    finally:
        await eufy.async_close()
        fake.stop()
    assert calls == [True]
    assert [call for call in cloud.calls if call.startswith("dsk:")]
    assert "lan_reply_blocked" not in store.data["stations"][fake.serial]


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


# T81A0: a serial prefix whose bundled settings declare the flag; the cloud's code wins.
@pytest.mark.parametrize("sn", ["T8191P0000000000", "T81A0P0000000000"])
@pytest.mark.parametrize("listed_battery", [True, False])
async def test_an_unbundled_station_keeps_a_held_session_whatever_its_listing(
    sn: str, listed_battery: bool
) -> None:
    """The decision reads bundled settings of the cloud's product code only: a cloud
    listing that may arrive on a later discovery cannot change it after the station is
    built."""
    td = unbundled_td()
    if listed_battery:
        td["properties"].append(range_property(BATTERY_PROPERTY, 0, 100, unit="%"))
    device = standalone_device(sn, device_new_pn=UNBUNDLED)
    cloud = FakeCloud(devices=[device], things={UNBUNDLED: td})
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        assert station.has_battery() is listed_battery
        assert station.connects_on_demand is False
        await eufy.async_close()


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


async def test_a_rekey_answer_to_the_scan_rekeys_once_and_lists_the_settings(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    cloud = unbundled_cloud(
        things={UNBUNDLED: unbundled_td()},
        things_errors=[FakeCloud.refusal(463, 4404, "get identity error")],
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_probe_cloud_session()  # loads the cache
        logins = eufy.cloud.cloud_status().logins_in_window
        exchanges = cloud.key_exchanges
        (station,) = await eufy.async_discover()
        keys = [s.key for s in station.settings_for(SYNTHETIC.camera_sn)]
        assert eufy.cloud.cloud_status().logins_in_window == logins
        await eufy.async_close()
    assert keys == ["motion_sensitivity", "record_time"]
    assert cloud.key_exchanges == exchanges + 1
    assert cloud.calls.count("things") == 2  # refused, then retried once
    assert "login" not in cloud.calls
    assert scan_records(scan_logs) == []


async def test_a_second_rekey_answer_to_the_scan_is_logged_at_info_by_its_meaning(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    refusal = FakeCloud.refusal(463, 4404, "get identity error")
    cloud = unbundled_cloud(things={UNBUNDLED: unbundled_td()}, things_error=refusal)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        (station,) = await eufy.async_discover()
        assert station.settings_for(SYNTHETIC.camera_sn) == ()
        await eufy.async_close()
    assert cloud.calls.count("things") == 2
    assert "login" not in cloud.calls
    (record,) = scan_records(scan_logs)
    assert record.levelno == logging.INFO
    assert record.getMessage() == (
        f"no settings listed for {UNBUNDLED} from its thing description: the cloud refused "
        "this client's key identity after a new key exchange; listed at the next refresh"
    )


async def test_a_no_session_line_and_a_key_refused_line_for_one_code_both_appear(
    scan_logs: pytest.LogCaptureFixture,
) -> None:
    cloud = unbundled_cloud(
        things={UNBUNDLED: unbundled_td()},
        things_errors=[NoCachedSessionError("no session")],
        things_error=FakeCloud.refusal(463, 4404, "get identity error"),
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_discover()
        await eufy.async_discover(refresh=True)
        await eufy.async_close()
    prefix = f"no settings listed for {UNBUNDLED} from its thing description: "
    assert [r.getMessage() for r in scan_records(scan_logs)] == [
        f"{prefix}no cached cloud session",
        f"{prefix}the cloud refused this client's key identity after a new key exchange; "
        "listed at the next refresh",
    ]


@pytest.mark.parametrize(
    ("first", "second", "text"),
    [
        (CloudError("synthetic refusal"), CloudError("other text"), "synthetic refusal"),
        (CloudError(), CloudError(), "cloud request failed"),
    ],
    ids=["message", "no-message"],
)
async def test_a_scan_failure_is_logged_once_by_its_message_never_a_class_name(
    scan_logs: pytest.LogCaptureFixture, first: CloudError, second: CloudError, text: str
) -> None:
    cloud = unbundled_cloud(things_error=first)
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        await eufy.async_discover()
        cloud.things_error = second  # the same kind of failure, another text: no new line
        await eufy.async_discover(refresh=True)
        await eufy.async_close()
    assert cloud.calls.count("things") == 2
    assert [r.getMessage() for r in scan_records(scan_logs)] == [
        f"no settings listed for {UNBUNDLED} from its thing description: {text}"
    ]


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
    assert all(by_key[k] == v for k, v in settings_of("T8160").items() if k not in PARENTLESS_ONLY)
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


async def test_an_accepted_invitation_leaves_the_pending_list_without_a_login() -> None:
    entry = {"id": 3, "device_sn": SYNTHETIC.camera_sn, "user_id": "owner-1"}
    cloud = FakeCloud(device_invites=[entry])
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    cloud.calls.clear()
    (pending,) = await eufy.async_pending_invites()
    await eufy.async_accept_invite(pending)
    assert [i["invite_id"] for i in cloud.invite_accepts[0]["invites"]] == [3]
    assert await eufy.async_pending_invites() == []
    assert "accept_device_invite" in cloud.calls
    assert "login" not in cloud.calls


@pytest.mark.parametrize(
    ("region", "call"), [("us", "accept_device_invite"), ("eu", "accept_device_invite@eu")]
)
async def test_an_invitation_is_accepted_on_its_own_region_from_the_cached_session(
    region: str, call: str
) -> None:
    """No listing first: the cached session of the invitation's region, whichever region
    lists the account's devices, carries the accept."""
    entry = {"id": 3, "device_sn": SYNTHETIC.camera_sn}
    cloud = FakeCloud(region="us", device_invites=[entry])
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    cloud.calls.clear()
    invite = CloudInvite(kind="device", region=region, invite_id=3, device_sn=SYNTHETIC.camera_sn)
    await eufy.async_accept_invite(invite)
    assert cloud.calls == [call]
    assert [i["invites"][0]["invite_id"] for i in cloud.invite_accepts] == [3]


async def test_accepting_on_a_lapsed_session_does_not_log_in() -> None:
    entry = {"id": 3, "device_sn": SYNTHETIC.camera_sn}
    cloud = FakeCloud(device_invites=[entry])
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    (pending,) = await eufy.async_pending_invites()
    cloud.calls.clear()
    cloud.call_errors = [_expired()]
    with pytest.raises(NoCachedSessionError):
        await eufy.async_accept_invite(pending)
    assert "login" not in cloud.calls
    assert cloud.invite_accepts == []


@pytest.mark.parametrize("status", [401, 200], ids=["http-401", "body-code"])
async def test_a_replaced_session_on_an_accept_is_latched(status: int) -> None:
    """The next setup sees the replaced session without another request, for both
    answers that report a takeover."""
    entry = {"id": 3, "device_sn": SYNTHETIC.camera_sn}
    cloud = FakeCloud(device_invites=[entry])
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    eufy = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud)
    (pending,) = await eufy.async_pending_invites()
    cloud.calls.clear()
    cloud.call_errors = [FakeCloud.refusal(status, CloudCode.SESSION_REPLACED)]
    with pytest.raises(SessionReplacedError):
        await eufy.async_accept_invite(pending)
    assert cloud.invite_accepts == []
    assert "login" not in cloud.calls
    later = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud)
    assert (await later.async_cloud_status()).login_need is LoginNeed.REPLACED


async def test_a_code_invitation_is_accepted_only_with_its_code() -> None:
    sealed = crypto.invite_seal("482913", "share")
    entry = {"id": 4, "house_id": "house-2", "encrypted_data": sealed}
    cloud = FakeCloud(house_invites=[entry])
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    (pending,) = await eufy.async_pending_invites()
    with pytest.raises(InviteCodeError):
        await eufy.async_accept_invite(pending, code="000000")
    assert cloud.invite_accepts == []
    await eufy.async_accept_invite(pending, code="482913")
    assert cloud.invite_accepts[0]["house_id"] == "house-2"
    assert cloud.house_invites == []


# ── push pictures ────────────────────────────────────────────────────────────

_JPEG = b"\xff\xd8\xff\xe0synthetic"
_FACE_URL = "https://faces.example.invalid/f.jpg?sig=x"
_PIC_URL = "https://pictures.example.invalid/p.jpg"


def _face_push(**fields: Any) -> SecurityEvent:
    """A HomeBase 2 style short-key detection push naming a face."""
    return SecurityEvent(
        source=EventSource.CLOUD,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        msg_type=1,
        event_type=3101,
        event_time_ms=1_700_000_000_000,
        **({"fetch_id": "1a2b3c"} | fields),
    )


def _picture_client(cloud: FakeCloud) -> EufySecurity:
    return build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )


async def test_the_face_picture_of_a_push_comes_from_the_cloud() -> None:
    cloud = FakeCloud(
        faces={0x1A2B3C: {"ai_face_id": 0x1A2B3C, "face_url": _FACE_URL}},
        pictures={_FACE_URL: _JPEG},
    )
    image = await _picture_client(cloud).async_push_image(_face_push())
    assert image == PushImage(
        source=PushPictureSource.FACE,
        device_sn=SYNTHETIC.camera_sn,
        data=_JPEG,
        content_type=JPEG_CONTENT_TYPE,
        face_id=0x1A2B3C,
    )
    assert cloud.face_requests == [{"ai_face_ids": [0x1A2B3C], "station_sn": SYNTHETIC.camera_sn}]
    assert "login" not in cloud.calls


async def test_a_push_picture_falls_back_to_pic_url_when_the_cloud_keeps_no_face() -> None:
    cloud = FakeCloud(pictures={_PIC_URL: _JPEG})
    eufy = _picture_client(cloud)
    push = _face_push(pic_url=_PIC_URL)
    image = await eufy.async_push_image(push)
    assert (image.source, image.face_id, image.data) == (PushPictureSource.PIC_URL, None, _JPEG)
    with pytest.raises(EmptyResponseError):
        await eufy.async_push_image(push, PushPictureSource.FACE)


async def test_a_station_path_pic_url_is_fetched_from_the_served_station() -> None:
    eufy = _picture_client(FakeCloud())
    path = "/zx/hdd_data0/Camera00/snapshort.jpg"
    stills: list[str] = []

    async def fetch_still(still_path: str) -> Still:
        stills.append(still_path)
        return Still(path=still_path, data=_JPEG, format=StillFormat.JPEG)

    eufy.stations[SYNTHETIC.station_sn] = cast(
        Station, SimpleNamespace(async_fetch_still=fetch_still)
    )
    push = _face_push(fetch_id=None, pic_url=path)
    image = await eufy.async_push_image(push)
    assert (image.source, image.data, stills) == (PushPictureSource.PIC_URL, _JPEG, [path])
    other = _face_push(fetch_id=None, pic_url="relative/p.jpg")  # neither https nor /zx/
    with pytest.raises(UnsupportedError):
        await eufy.async_push_image(other, PushPictureSource.PIC_URL)
    assert stills == [path]  # never sent to the station
    del eufy.stations[SYNTHETIC.station_sn]
    with pytest.raises(UnsupportedError):
        await eufy.async_push_image(push)


@pytest.mark.parametrize(
    ("push", "source"),
    [
        (_face_push(fetch_id=None), None),  # names no picture
        (_face_push(fetch_id="3107"), None),  # a vehicle marker, not a face
        (_face_push(), PushPictureSource.PIC_URL),
        (_face_push(fetch_id=None, pic_url="ftp://x/p.jpg"), None),
    ],
)
async def test_a_push_without_that_picture_raises_unsupported_before_sending(
    push: SecurityEvent, source: PushPictureSource | None
) -> None:
    cloud = FakeCloud()
    with pytest.raises(UnsupportedError):
        await _picture_client(cloud).async_push_image(push, source)
    assert cloud.calls == []


_STILL_JPEG = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"


def _listing_client(cloud: FakeCloud, camera_did: str | None = None) -> EufySecurity:
    """A client whose cached device list holds the station and its camera (``camera_did``
    its own DID; None: none, as a HomeBase 2 child)."""
    eufy = _picture_client(cloud)
    camera = camera_device() | ({"p2p_did": camera_did} if camera_did else {})
    listed = [CloudDevice.from_api(station_device()), CloudDevice.from_api(camera)]
    eufy.listed_devices = MappingProxyType({d.device_sn: d for d in listed})
    return eufy


@pytest.mark.parametrize("build", [v1_still, v2_still])
@pytest.mark.parametrize("camera_did", [None, OTHER_DID])
async def test_an_obfuscated_pic_url_picture_is_decoded_with_the_cached_did(
    build: Callable[..., bytes], camera_did: str | None
) -> None:
    """Keyed by the station's DID: found after the camera's own (none, or another)."""
    wrapped = build(_STILL_JPEG, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    cloud = FakeCloud(pictures={_PIC_URL: wrapped})
    eufy = _listing_client(cloud, camera_did)
    cloud.calls.clear()
    image = await eufy.async_push_image(_face_push(fetch_id=None, pic_url=_PIC_URL))
    assert (image.source, image.data, image.content_type) == (
        PushPictureSource.PIC_URL,
        _STILL_JPEG,
        JPEG_CONTENT_TYPE,
    )
    assert "devices" not in cloud.calls


async def test_an_obfuscated_face_picture_is_decoded() -> None:
    cloud = FakeCloud(
        faces={0x1A2B3C: {"ai_face_id": 0x1A2B3C, "face_url": _FACE_URL}},
        pictures={_FACE_URL: v2_still(_STILL_JPEG, SYNTHETIC.camera_sn, did=SYNTHETIC.did)},
    )
    image = await _listing_client(cloud).async_push_image(_face_push(), PushPictureSource.FACE)
    assert (image.data, image.face_id) == (_STILL_JPEG, 0x1A2B3C)


@pytest.mark.parametrize(
    ("data", "error", "logged"),
    [
        (
            b"v8_eufysecurity:" + SYNTHETIC.camera_sn.encode() + bytes(400),
            VideoEncryptedPictureError,
            "format v8_eufysecurity, 432 bytes",
        ),
        (b"GIF89a-not-shown", UnsupportedError, "format unknown, 16 bytes, first bytes 47494638"),
        (
            v1_still(_STILL_JPEG, SYNTHETIC.camera_sn, did=OTHER_DID),
            UnsupportedError,
            "format eufysecurity, 447 bytes",
        ),
        (
            v1_still(_STILL_JPEG, OTHER_STATION_SN, did=SYNTHETIC.did),
            UnsupportedError,
            "format eufysecurity, 447 bytes",
        ),
    ],
    ids=["v8", "unknown", "v1-wrong-did", "v1-unlisted-device"],
)
async def test_a_pushed_picture_that_is_no_image_raises_and_logs_its_format(
    data: bytes, error: type[UnsupportedError], logged: str, caplog: pytest.LogCaptureFixture
) -> None:
    """V8 (Video Encryption), an unknown format, a V1 still no cached DID decodes or of a
    device the cached list does not hold."""
    cloud = FakeCloud(pictures={_PIC_URL: data})
    with (
        caplog.at_level(logging.DEBUG, logger=client_module.__name__),
        pytest.raises(UnsupportedError) as caught,
    ):
        await _listing_client(cloud).async_push_image(_face_push(fetch_id=None, pic_url=_PIC_URL))
    assert type(caught.value) is error
    assert logged in caplog.text
    assert SYNTHETIC.camera_sn not in caplog.text


@pytest.mark.parametrize(
    ("client_country", "expected"), [("OM", [False, True]), (None, [None, None])]
)
async def test_the_login_country_decides_a_country_gated_setting_variant(
    client_country: str | None, expected: list[bool | None]
) -> None:
    """The country the account logs in with reaches the stations' variant decision;
    while it is unknown, a country-gated group cannot be decided."""
    camera = camera_device() | {"device_new_pn": "T814X"}
    cloud = FakeCloud(
        devices=[station_device(), camera],
        client_country=client_country,
        country_regions={"OM": "eu"},
    )
    async with aiohttp.ClientSession() as http:
        eufy = account(http, cloud)
        home = next(s for s in await eufy.async_discover() if s.serial == SYNTHETIC.station_sn)
        members = ("player_model_config", "player_model_config__v1")
        assert [home.setting_in_use(k, SYNTHETIC.camera_sn) for k in members] == expected
        await eufy.async_close()
