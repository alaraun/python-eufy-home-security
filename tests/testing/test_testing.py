"""The shipped test doubles drive a real client end to end, with no network."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from collections.abc import AsyncIterator, Callable

import pytest

from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud import const
from eufy_home_security.cloud.status import LoginNeed
from eufy_home_security.events import Event, SecurityEvent
from eufy_home_security.exceptions import (
    CloudApiError,
    CommunicationError,
    LoginLimitedError,
    RateLimitedError,
    SessionRejectedError,
    SessionReplacedError,
    StationUnreachableError,
)
from eufy_home_security.install import InstallState
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.pppp import MsgType, decode_packet, encode_packet
from eufy_home_security.storage import MemoryStore
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    warm_store,
)


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    await station.start()
    yield station
    station.stop()


def client_for(
    fake: FakeStation, cloud: FakeCloud, store: MemoryStore | None = None
) -> EufySecurity:
    return build_eufy_security(
        email=SYNTHETIC.email,
        store=store if store is not None else warm_store(email=SYNTHETIC.email, cloud=cloud),
        cloud=cloud,
        stations={fake.serial: fake},
    )


async def wait_until(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.02)


async def test_a_warm_restart_makes_only_the_model_scan_request(fake: FakeStation) -> None:
    cloud = FakeCloud.for_stations(fake)
    eufy = client_for(fake, cloud)
    try:
        await eufy.async_login()
        stations = await eufy.async_discover()
        errors = await eufy.async_start(push=False)
    finally:
        await eufy.async_close()
    assert errors == {}
    assert [s.serial for s in stations] == [fake.serial]
    assert [d.device_sn for d in stations[0].sub_devices] == [SYNTHETIC.camera_sn]
    assert fake.conn_inits == 1  # the cached key handshook
    assert cloud.calls == ["things"]  # no login, no device list, no key


async def test_a_cold_start_records_each_cloud_request_redacted(fake: FakeStation) -> None:
    cloud = FakeCloud.for_stations(fake)
    eufy = client_for(fake, cloud, MemoryStore())
    try:
        await eufy.async_login()
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
    finally:
        await eufy.async_close()
    # The first device list asks every region; one outside ``cloud.region`` is named.
    assert cloud.calls == [
        "login",
        "login@us",
        "devices",
        "devices@us",
        "things",
        "cipher:T8030***2345",
    ]


async def test_a_region_lists_its_own_devices(fake: FakeStation) -> None:
    cloud = FakeCloud.for_stations(fake, region="us")
    eufy = client_for(fake, cloud, MemoryStore())
    try:
        await eufy.async_login()
        stations = await eufy.async_discover()
    finally:
        await eufy.async_close()
    assert {station.device.region for station in stations} == {"us"}
    assert cloud.calls[:4] == ["login@eu", "login", "devices@eu", "devices"]


async def test_a_login_error_is_raised_and_the_cloud_status_agrees(fake: FakeStation) -> None:
    """A throttle code holds off as the cloud's answer with that code does."""
    error = LoginLimitedError(retry_after=60, code=const.CloudCode.MAX_LOGIN_LIMIT)
    cloud = FakeCloud.for_stations(fake, login_error=error)
    eufy = client_for(fake, cloud, MemoryStore())
    try:
        with pytest.raises(LoginLimitedError) as raised:
            await eufy.async_login()
        status = await eufy.async_cloud_status()
        with pytest.raises(LoginLimitedError):
            await eufy.async_login()  # refused locally: no second login reaches the cloud
    finally:
        await eufy.async_close()
    assert raised.value.code == const.CloudCode.MAX_LOGIN_LIMIT
    assert status.login_need is LoginNeed.CACHED_PASSWORD
    assert status.login_hold_off == pytest.approx(const.LOGIN_HOLD_OFF_SECONDS, abs=5)
    assert status.next_login_allowed_in > 0
    assert cloud.calls == ["login"]


async def test_a_login_error_without_a_throttle_code_holds_off_for_its_retry_after() -> None:
    cloud = FakeCloud(login_error=LoginLimitedError(retry_after=60))
    eufy = build_eufy_security(email=SYNTHETIC.email, store=MemoryStore(), cloud=cloud)
    try:
        with pytest.raises(LoginLimitedError) as raised:
            await eufy.async_login()
        status = await eufy.async_cloud_status()
    finally:
        await eufy.async_close()
    assert raised.value is cloud.login_error
    assert status.login_hold_off is not None
    assert 0 < status.login_hold_off <= 60


async def _warm_cloud_client(cloud: FakeCloud) -> EufySecurity:
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    await eufy.async_login()
    cloud.calls.clear()
    return eufy


async def test_a_throttle_from_call_errors_holds_off_every_later_call() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    cloud.call_errors = [
        RateLimitedError("throttled", retry_after=600.0, code=const.CloudCode.API_REQUEST_LIMIT)
    ]
    try:
        with pytest.raises(RateLimitedError):
            await eufy.cloud.async_fetch_devices()
        status = await eufy.async_cloud_status()
        with pytest.raises(RateLimitedError):
            await eufy.cloud.async_fetch_devices()  # refused locally
    finally:
        await eufy.async_close()
    assert status.request_hold_off == pytest.approx(const.REQUEST_HOLD_OFF_SECONDS, abs=5)
    assert cloud.calls == ["devices"]


async def test_a_call_error_without_a_throttle_code_holds_off_for_its_retry_after() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    error = RateLimitedError("throttled", retry_after=60.0)
    cloud.call_errors = [error]
    try:
        with pytest.raises(RateLimitedError) as raised:
            await eufy.cloud.async_fetch_devices()
        status = await eufy.async_cloud_status()
    finally:
        await eufy.async_close()
    assert raised.value is error
    assert status.request_hold_off is not None
    assert 0 < status.request_hold_off <= 60


@pytest.mark.parametrize(
    ("status", "code", "error"),
    [
        (401, const.CloudCode.SESSION_REPLACED, SessionReplacedError),
        (401, None, SessionRejectedError),
        (429, None, RateLimitedError),
        (463, 4404, CloudApiError),
        (500, None, CommunicationError),
    ],
)
def test_a_refusal_is_the_error_the_library_raises_for_that_answer(
    status: int, code: int | None, error: type[Exception]
) -> None:
    assert isinstance(FakeCloud.refusal(status, code), error)


def test_a_success_is_no_refusal() -> None:
    with pytest.raises(ValueError, match="not a refusal"):
        FakeCloud.refusal(200, 0)


async def test_a_served_401_with_the_takeover_code_latches_the_session() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    cloud.call_errors = [FakeCloud.refusal(401, const.CloudCode.SESSION_REPLACED)]
    try:
        with pytest.raises(SessionReplacedError):
            await eufy.async_probe_cloud_session()
        assert eufy.session_replaced
    finally:
        await eufy.async_close()
    assert "login" not in cloud.calls


async def test_a_served_401_costs_one_login_and_a_retry() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    cloud.call_errors = [FakeCloud.refusal(401)]
    try:
        await eufy.cloud.async_fetch_devices()
    finally:
        await eufy.async_close()
    assert cloud.calls == ["devices", "login", "devices"]


async def test_a_served_429_holds_off_every_later_call() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    cloud.call_errors = [FakeCloud.refusal(429, retry_after=7200.0)]
    try:
        with pytest.raises(RateLimitedError):
            await eufy.cloud.async_fetch_devices()
        status = await eufy.async_cloud_status()
        with pytest.raises(RateLimitedError):
            await eufy.cloud.async_fetch_devices()  # refused locally
    finally:
        await eufy.async_close()
    assert status.request_hold_off == pytest.approx(7200.0, abs=5)  # the longer Retry-After
    assert cloud.calls == ["devices"]


async def test_a_region_without_a_device_list_answers_a_null_list() -> None:
    cloud = FakeCloud()
    eufy = await _warm_cloud_client(cloud)
    try:
        devices = await eufy.cloud.async_list_house_devices("us")
    finally:
        await eufy.async_close()
    assert devices == []
    assert cloud.calls == ["devices@us"]


async def test_a_request_limit_from_the_fake_cloud_holds_off_the_whole_install(
    fake: FakeStation,
) -> None:
    install = InstallState()
    cloud = FakeCloud.for_stations(fake, login_error=RateLimitedError(retry_after=60))
    other_email = "other@example.com"
    first = build_eufy_security(
        email=SYNTHETIC.email, store=MemoryStore(), cloud=cloud, install=install
    )
    other = build_eufy_security(
        email=other_email,
        store=warm_store(email=other_email, cloud=cloud),
        cloud=cloud,
        install=install,
    )
    try:
        with pytest.raises(RateLimitedError):
            await first.async_login()
        status = await other.async_cloud_status()
    finally:
        await first.async_close()
        await other.async_close()
    assert status.request_hold_off is not None
    assert 0 < status.request_hold_off <= 60
    assert cloud.calls == ["login"]


async def test_a_stopped_station_is_the_start_error(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "DISCOVERY_ATTEMPTS", 1)
    monkeypatch.setattr(session_module, "DISCOVERY_TIMEOUT", 0.3)
    eufy = client_for(fake, FakeCloud.for_stations(fake))
    fake.stop()  # nothing answers on its port
    try:
        await eufy.async_discover()
        errors = await eufy.async_start(push=False)
    finally:
        await eufy.async_close()
    assert {sn: type(err) for sn, err in errors.items()} == {fake.serial: StationUnreachableError}


async def test_a_camera_push_reaches_the_subscriber(fake: FakeStation) -> None:
    cloud = FakeCloud.for_stations(fake)
    eufy = client_for(fake, cloud)
    events: list[Event] = []
    eufy.subscribe(events.append)
    try:
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        fake.push_camera_event()
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        await eufy.async_close()
    push = next(e for e in events if isinstance(e, SecurityEvent))
    assert (push.station_sn, push.device_sn) == (fake.serial, SYNTHETIC.camera_sn)


async def test_a_second_clients_search_leaves_the_live_session_alone(fake: FakeStation) -> None:
    eufy = client_for(fake, FakeCloud.for_stations(fake))
    events: list[Event] = []
    eufy.subscribe(events.append)
    replies: list[bytes] = []

    class Prober(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
            replies.append(data)

    probe, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        Prober, local_addr=("127.0.0.1", 0)
    )
    try:
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        searches = fake.searches
        probe.sendto(encode_packet(MsgType.LAN_SEARCH), ("127.0.0.1", fake.discovery_port))
        await wait_until(lambda: bool(replies))  # answered, as the firmware does
        assert decode_packet(replies[0])[0] == MsgType.PUNCH_PKT
        assert fake.searches == searches + 1
        fake.push_camera_event()  # the first client's session still delivers
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        probe.close()
        await eufy.async_close()
    assert fake.conn_inits == 1  # no reset, no second handshake


def test_fake_stations_must_be_started_on_one_port() -> None:
    with pytest.raises(ValueError, match="start every FakeStation"):
        build_eufy_security(
            email=SYNTHETIC.email,
            store=MemoryStore(),
            cloud=FakeCloud(),
            stations={SYNTHETIC.station_sn: FakeStation()},
        )


def test_the_doubles_import_nothing_from_a_test_tree() -> None:
    code = (
        "import sys, eufy_home_security.testing; "
        "print(' '.join(m for m in sys.modules if m == 'tests' or m.startswith('tests.')))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == ""


async def test_the_fake_cloud_answers_thing_descriptions_for_the_codes_it_knows() -> None:
    from eufy_home_security.testing.cloud import range_property, thing_description  # noqa: PLC0415

    td = thing_description("T9999", [range_property("record_time", 10, 120)])
    cloud = FakeCloud(things={"T9999": td})
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    try:
        await eufy.async_login()
        assert await eufy.cloud.async_get_thing_descriptions(["T9999", "T9998"]) == [td]
        cloud.things_error = RateLimitedError(retry_after=60)
        with pytest.raises(RateLimitedError):
            await eufy.cloud.async_get_thing_descriptions(["T9999"])
    finally:
        await eufy.async_close()
    assert cloud.calls == ["things", "things"]
