"""Lock and unlock over the MQTT broker (``EufySecurity.use_mqtt`` / ``async_lock`` /
``async_unlock`` / ``lock_control``) against the loopback broker and a fake Wi-Fi lock."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import gc
import json
import logging
import secrets
import time
from collections.abc import Callable, Iterator
from types import MappingProxyType
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.locks import LockReading, LockState, LockStateSource
from eufy_home_security.events import Event, EventBus, EventSource, LockStateChanged, SecurityEvent
from eufy_home_security.exceptions import (
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    GuestAccessError,
    LockNotMovedError,
    MqttAccountRequiredError,
    UnsupportedError,
)
from eufy_home_security.lock_commands import cm2, control, frames
from eufy_home_security.lock_commands.actions import LockAction
from eufy_home_security.lock_commands.control import LockPath
from eufy_home_security.lock_commands.mqtt_trans import encode_trans
from eufy_home_security.mqtt import locks as mqtt_locks_module
from eufy_home_security.mqtt.account import EufyMqttAccount
from eufy_home_security.mqtt.envelope import MqttMessage, parse_message
from eufy_home_security.mqtt.locks import MqttLocks, mqtt_lock_control
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.station.locks import LOCK_REPORT_SLACK_SECONDS, ListedLocks
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    warm_store,
)
from eufy_home_security.testing.mqtt import FakeMqttBroker, FakeMqttLock, MqttTestPki

from .conftest import LOCK2_SN, LOCK_SN, OWNER, SHORT_USER, AccountUser, Rig, answer, lock, until

pytestmark = pytest.mark.usefixtures("short_waits")


@pytest.fixture
def wifi_lock(rig: Rig) -> Iterator[FakeMqttLock]:
    fake = FakeMqttLock(
        broker=rig.broker, serial=LOCK_SN, product_code="T85D0", owner_user_id=OWNER
    )
    fake.attach()
    yield fake
    assert fake.refused == []  # every command this client sent was the app's lock message


async def _served(rig: Rig, device: CloudDevice | None = None) -> EufyMqttAccount:
    device = device or lock()
    rig.eufy.listed_devices = MappingProxyType({device.device_sn: device})
    account = EufyMqttAccount(rig.eufy.cloud, port=rig.broker.port, server_ca_pem=rig.pki.ca_pem)
    await account.async_start([device])
    await account.async_wait_connected(5)
    await rig.broker.wait_for(
        lambda: any(t.endswith("/res") for _, t, _ in rig.broker.subscriptions)
    )
    rig.eufy.use_mqtt(account)
    return account


def _listed_lock_commands(
    account: object,
    device: CloudDevice | None = None,
    bus: EventBus | None = None,
    states: ListedLocks | None = None,
) -> MqttLocks:
    """Lock commands over a stand-in ``account`` for ``device`` (default :func:`lock`),
    a lock no station serves, its state kept by ``states`` (default a
    :class:`ListedLocks` on ``bus``)."""
    device = device or lock()
    states = states or ListedLocks(bus or EventBus(), lambda: [device])
    return MqttLocks(
        account,  # type: ignore[arg-type]
        user=AccountUser(),
        states=lambda serial: states if states.serves(serial) else None,
        devices=lambda serial: device if serial == device.device_sn else None,
    )


def _events(rig: Rig) -> list[Event]:
    seen: list[Event] = []
    rig.eufy.subscribe(seen.append)
    return seen


async def test_a_lock_over_mqtt_is_confirmed_by_its_status_report(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    account = await _served(rig)
    events = _events(rig)
    try:
        assert rig.eufy.lock_control(LOCK_SN).path is LockPath.MQTT
        assert await rig.eufy.async_lock(LOCK_SN) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK]
    assert wifi_lock.users == [(OWNER, SHORT_USER)]  # the member record's ids, as the app sends
    changes = [(e.state, e.source, e.station_sn) for e in events if isinstance(e, LockStateChanged)]
    assert changes == [
        (LockState.LOCKING, LockStateSource.COMMAND, None),  # the lock took it
        (LockState.LOCKED, LockStateSource.LOCK, None),
    ]
    sent = json.loads(rig.broker.published[-1].payload)
    assert (sent["head"]["cmd"], sent["head"]["cmd_status"]) == (9, 2)


@pytest.mark.parametrize(
    ("nick_name", "sender"),
    [("Kim R", "Kim R"), (None, SYNTHETIC.email.split("@")[0])],
)
async def test_an_mqtt_lock_command_names_the_accounts_nickname(
    rig: Rig, wifi_lock: FakeMqttLock, nick_name: str | None, sender: str
) -> None:
    """The sender entry is the login's nickname, the e-mail's local part without one."""
    assert nick_name != SYNTHETIC.email.split("@")[0]
    account = await _served(rig)
    try:
        assert await rig.eufy.async_lock(LOCK_SN) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert wifi_lock.names == [sender]


# The app's lock message for LOCK_SN, key user OWNER, nickname "Synthetic Nick", short id
# 0a1b, lock, at 1700000000 with time noise 37 and no stored sequence number.
VECTOR_LOCK_PAYLOAD = (
    "ff096a00030002402382e1b314449c8ef5fa3d2baf4ddb7cbafaadfdae585ec3"
    "e4b58f0a8bea3d00023e85c99da8a998707256f1b54f13b087e62ed1af5c2516"
    "c6408cb76620f0a7bfa21343541e8862b33b5f0a17d2e6a8c4b9ac6c37700805"
    "a0679bed507d3a0588de"
)
VECTOR_TRANS_JSON = (
    '{"cmd":1940,"mChannel":0,"mValue3":0,"payload":{"apiCommand":6018,'
    f'"lock_payload":"{VECTOR_LOCK_PAYLOAD}","seq_num":1700000001,"time":1700000037}}}}'
)


async def test_an_mqtt_lock_command_is_the_apps_message_byte_for_byte(
    rig: Rig, wifi_lock: FakeMqttLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(secrets, "randbelow", lambda _bound: 37)
    device = lock()
    account = await _served(rig, device)
    locks = MqttLocks(
        account,
        user=AccountUser(),
        states=rig.eufy._lock_states,
        devices=rig.eufy.listed_devices.get,
        clock=lambda: 1700000000.0,
    )
    try:
        state = await locks.async_command(
            device, LockAction.LOCK, control=mqtt_lock_control(device), timeout=5
        )
    finally:
        locks.close()
        await account.async_stop()
    assert state is LockState.LOCKED
    trans = base64.b64encode(VECTOR_TRANS_JSON.encode()).decode()
    sent = json.loads(rig.broker.published[-1].payload)
    assert sent["payload"] == (
        f'{{"account_id":"{OWNER}","device_sn":"{LOCK_SN}","trans":"{trans}"}}'
    )


Edit = Callable[[dict[str, Any]], dict[str, Any]]


def _same(obj: dict[str, Any]) -> dict[str, Any]:
    return obj


@pytest.mark.parametrize(
    "member",
    [
        {"member_user_id": "89abcdef0123456789abcdef0123456789abcdef"},
        {"member_type": 2},
        {"admin_user_id": None},
    ],
    ids=["record-names-another-account", "member-type-2", "no-admin-id"],
)
async def test_an_mqtt_lock_command_is_keyed_by_the_accounts_own_id_otherwise(
    rig: Rig, member: dict[str, Any]
) -> None:
    """The member record's ``admin_user_id`` keys and names the command only when the record
    names this account, holds one and its type is not 2; otherwise the account's own user id
    does, in the frame, its key and the message's ``account_id``."""
    record = {"admin_user_id": OWNER, "member_type": 1, "short_user_id": SHORT_USER}
    record |= {"member_user_id": SYNTHETIC.account_id} | member
    device = CloudDevice.from_api(
        {"device_sn": LOCK_SN, "device_type": 0, "device_new_pn": "T85D0", "member": record}
    )
    fake = FakeMqttLock(
        broker=rig.broker,
        serial=LOCK_SN,
        product_code="T85D0",
        owner_user_id=SYNTHETIC.account_id,
    )
    fake.attach()
    account = await _served(rig, device)
    try:
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert fake.refused == []
    assert fake.users == [(SYNTHETIC.account_id, SHORT_USER)]


async def test_use_mqtt_before_the_login_takes_the_user_id_of_the_later_login(
    pki: MqttTestPki, short_waits: None
) -> None:
    """The account's user id and name are read per command, not when ``use_mqtt`` is
    called: a client given its MQTT account before its login commands after it."""
    cloud = FakeCloud(mqtt_answer=pki.register_answer(), nick_name="Kim R")
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    eufy = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud)
    broker = FakeMqttBroker(pki)
    await broker.async_start()
    fake = FakeMqttLock(broker=broker, serial=LOCK_SN, product_code="T85D0", owner_user_id=OWNER)
    fake.attach()
    device = lock()
    eufy.listed_devices = MappingProxyType({device.device_sn: device})
    account = EufyMqttAccount(eufy.cloud, port=broker.port, server_ca_pem=pki.ca_pem)
    try:
        assert eufy.cloud.user_id is None
        eufy.use_mqtt(account)
        await eufy.async_login()
        await account.async_start([device])
        await account.async_wait_connected(5)
        await broker.wait_for(lambda: any(t.endswith("/res") for _, t, _ in broker.subscriptions))
        assert await eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
        await broker.async_stop()
        await eufy.async_close()
    assert fake.refused == []
    assert (fake.users, fake.names) == ([(OWNER, SHORT_USER)], ["Kim R"])


@pytest.mark.parametrize("user_id", ["", None])
async def test_an_mqtt_lock_command_needs_the_accounts_user_id(
    rig: Rig, wifi_lock: FakeMqttLock, user_id: str | None
) -> None:
    device = lock()
    account = await _served(rig, device)
    locks = MqttLocks(
        account,
        user=AccountUser(user_id),
        states=rig.eufy._lock_states,
        devices=rig.eufy.listed_devices.get,
    )
    try:
        with pytest.raises(UnsupportedError, match="cloud user id"):
            await locks.async_command(
                device, LockAction.LOCK, control=mqtt_lock_control(device), timeout=5
            )
    finally:
        locks.close()
        await account.async_stop()
    assert wifi_lock.received == []


def _a_form(
    *, inner: Edit = _same, outer: Edit = _same, version: int = cm2.FRAME_VERSION, slave_id: int = 0
) -> str:
    """The app's lock trans for LOCK_SN keyed by OWNER; ``inner`` / ``outer`` edit the payload
    objects, ``version`` / ``slave_id`` set the frame's bytes."""
    request = cm2.build_on_off_request(
        LOCK_SN,
        LockAction.LOCK,
        cm2.Cm2User(OWNER, "Synthetic Nick", SHORT_USER),
        seq_num=1700000001,
        time_value=1700000037,
        timestamp=1700000000,
    )
    payload = dict(request.payload)
    body = frames.parse_cm2_frame(bytes.fromhex(str(payload["lock_payload"]))).body
    payload["lock_payload"] = frames.cm2_frame(
        body,
        command=cm2.COMMAND_ON_OFF,
        function_type=cm2.FUNCTION_TYPE,
        version=version,
        encrypted=True,
        slave_id=slave_id,
    ).hex()
    obj = outer({"cmd": 1940, "mChannel": 0, "mValue3": 0, "payload": inner(payload)})
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def _b_order(inner: dict[str, Any]) -> dict[str, Any]:
    return {k: inner[k] for k in ("lock_payload", "seq_num", "apiCommand", "time")}


@pytest.mark.parametrize(
    ("form", "publish", "accepted"),
    [
        ({}, {}, True),
        ({"inner": _b_order}, {}, False),
        ({"inner": lambda p: p | {"apiCommand": 1940}}, {}, False),
        ({"inner": lambda p: p | {"time": f"{p['time']:08x}"}}, {}, False),
        ({"inner": lambda p: p | {"version": "1"}}, {}, False),
        ({"outer": lambda p: {"cmd": 1940, "account_id": "", **p}}, {}, False),
        ({"version": 2}, {}, False),
        ({"slave_id": 1}, {}, False),
        ({}, {"extra_fields": True}, False),
        ({}, {"account_id": SYNTHETIC.account_id}, False),
        ({}, {"need_ack": True}, False),
    ],
    ids=[
        "app-form",
        "inner-key-order",
        "api-command",
        "time-as-text",
        "version-key",
        "outer-account-id",
        "frame-version",
        "frame-slave-id",
        "envelope-extra-fields",
        "envelope-account",
        "head-asks-ack",
    ],
)
async def test_the_fake_lock_takes_only_the_apps_lock_message(
    rig: Rig, form: dict[str, Any], publish: dict[str, Any], accepted: bool
) -> None:
    fake = FakeMqttLock(
        broker=rig.broker, serial=LOCK_SN, product_code="T85D0", owner_user_id=OWNER
    )
    fake.attach()
    account = await _served(rig)
    options: dict[str, Any] = {"account_id": OWNER, "extra_fields": False} | publish
    try:
        await account.async_publish(LOCK_SN, _a_form(**form), **options)
        await rig.broker.wait_for(lambda: bool(fake.received or fake.refused))
    finally:
        await account.async_stop()
    assert (len(fake.received), len(fake.refused)) == ((1, 0) if accepted else (0, 1))


async def test_an_unlock_over_mqtt_skips_an_answer_to_another_request(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.mismatch_first = True
    wifi_lock.answer_code = 1  # the stale answer accepts, the lock's own refuses
    account = await _served(rig)
    try:
        with pytest.raises(CommandRejectedError) as raised:
            await rig.eufy.async_unlock(LOCK_SN, timeout=5)
    finally:
        await account.async_stop()
    assert raised.value.code == 1
    assert [a for a, _ in wifi_lock.received] == [LockAction.UNLOCK]


async def test_a_status_report_with_an_error_code_fails_the_mqtt_command(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.status_code = 2
    account = await _served(rig)
    events = _events(rig)
    try:
        async with asyncio.timeout(5):  # at the report, not after the state wait
            with pytest.raises(CommandRejectedError) as raised:
                await rig.eufy.async_lock(LOCK_SN)
    finally:
        await account.async_stop()
    assert (raised.value.command, raised.value.code) == (1940, 2)
    # It sets no state: locking from the take, unknown at the refusal (nothing reported).
    changes = [(e.state, e.source) for e in events if isinstance(e, LockStateChanged)]
    assert changes == [
        (LockState.LOCKING, LockStateSource.COMMAND),
        (LockState.UNKNOWN, LockStateSource.COMMAND),
    ]
    assert rig.eufy.lock_state(LOCK_SN) == LockReading(
        state=LockState.UNKNOWN, source=LockStateSource.COMMAND
    )


async def test_a_status_report_before_the_answer_confirms_the_mqtt_command(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """The asked state reported before any answer ends the command at once: the state
    counts, the missing answer does not."""
    wifi_lock.report_first, wifi_lock.answer = True, False
    account = await _served(rig)
    try:
        async with asyncio.timeout(3):  # not after the 20 s answer wait
            assert await rig.eufy.async_lock(LOCK_SN) is LockState.LOCKED
    finally:
        await account.async_stop()


class _StateThenFailure:
    """An MQTT account whose request ends in an error in the turn the lock's state
    arrives."""

    def __init__(self) -> None:
        self.locks: MqttLocks | None = None

    def add_listener(self, _callback: object) -> Callable[[], None]:
        return lambda: None

    async def async_request(self, device_sn: str, *_: object, **__: object) -> None:
        assert self.locks is not None
        self.locks._states[device_sn].set_result(LockState.LOCKED)
        raise DeviceTimeoutError("no MQTT answer", device_sn=device_sn)


async def test_a_request_error_beside_the_state_is_retrieved() -> None:
    """The state decides when it is in; the request's error beside it is retrieved, so
    the loop reports no unretrieved exception."""
    seen: list[dict[str, object]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, context: seen.append(context))
    try:
        account = _StateThenFailure()
        locks = _listed_lock_commands(account)
        account.locks = locks
        device = lock()
        control = mqtt_lock_control(device)
        state = await locks.async_command(device, LockAction.LOCK, control=control, timeout=5)
        for _ in range(3):
            await asyncio.sleep(0)
        gc.collect()
    finally:
        loop.set_exception_handler(None)
    assert state is LockState.LOCKED
    assert seen == []


class _Recording:
    """An MQTT account that records each request's waits and its listener, and answers the
    request with the broker's publish timeout."""

    def __init__(self) -> None:
        self.waits: list[tuple[object, object]] = []
        self.listener: Callable[[MqttMessage], None] | None = None

    def add_listener(self, callback: Callable[[MqttMessage], None]) -> Callable[[], None]:
        self.listener = callback
        return lambda: None

    async def async_request(self, device_sn: str, *_: object, **options: object) -> None:
        self.waits.append((options.get("publish_timeout"), options.get("timeout")))
        raise DeviceTimeoutError("MQTT publish not acknowledged", device_sn=device_sn)


@pytest.mark.parametrize(
    ("timeout", "waits"),
    [(None, (15.0, 20.0)), (75.0, (15.0, 20.0)), (5.0, (5.0, 5.0))],
)
async def test_an_mqtt_lock_command_keeps_the_apps_waits_within_its_bound(
    timeout: float | None, waits: tuple[float, float]
) -> None:
    """The publish has 15 s and the answer 20 s from the broker's acknowledgement, the
    app's waits, each cut to what is left of a ``timeout`` (which caps the call); the
    request's error says which one ran out."""
    account = _Recording()
    locks = _listed_lock_commands(account)
    device = lock()
    with pytest.raises(DeviceTimeoutError) as raised:
        await locks.async_command(
            device, LockAction.LOCK, control=mqtt_lock_control(device), timeout=timeout
        )
    assert str(raised.value) == "MQTT publish not acknowledged"
    ((publish_wait, answer_wait),) = account.waits
    assert publish_wait == pytest.approx(waits[0], abs=0.5)
    assert answer_wait == pytest.approx(waits[1], abs=0.5)


class _Silent:
    """An MQTT account whose request never ends."""

    def add_listener(self, _callback: object) -> Callable[[], None]:
        return lambda: None

    async def async_request(self, *_: object, **__: object) -> None:
        await asyncio.Event().wait()


async def test_an_mqtt_lock_commands_bound_caps_the_waits_together() -> None:
    """The publish and answer waits run one after the other; the call's ``timeout`` ends
    them both."""
    locks = _listed_lock_commands(_Silent())
    device = lock()
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(DeviceTimeoutError, match=r"no answer within 0\.3 s"):
        await locks.async_command(
            device, LockAction.LOCK, control=mqtt_lock_control(device), timeout=0.3
        )
    assert loop.time() - started < 2


async def test_a_silent_mqtt_lock_ends_at_the_answer_wait_within_a_longer_bound(
    rig: Rig, wifi_lock: FakeMqttLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mqtt_locks_module, "LOCK_ANSWER_TIMEOUT", 0.3)
    wifi_lock.answer = False
    account = await _served(rig)
    loop = asyncio.get_running_loop()
    try:
        started = loop.time()
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match=r"within 0\.3 s"):
                await rig.eufy.async_lock(LOCK_SN, timeout=75)
        assert loop.time() - started < 3
    finally:
        await account.async_stop()


async def test_a_lock_message_naming_no_text_serial_is_skipped() -> None:
    account = _Recording()
    locks = _listed_lock_commands(account)
    trans = encode_trans(1940, {"dev_sn": [LOCK_SN], "lock_payload": "ff", "time": "00"})
    assert account.listener is not None
    account.listener(parse_message(f"cmd/eufy_security/T85D0/{LOCK_SN}/res", answer({}, trans)))
    states = locks._states_of(LOCK_SN)
    assert states is not None
    assert states.reading(LOCK_SN) is None


@pytest.mark.parametrize(
    ("answer_cmd", "dev_sn", "confirmed"),
    [
        (8, None, True),
        (8, "", True),
        (9, None, False),
        (8, LOCK2_SN, False),
    ],
    ids=["device-message", "no-dev-sn-names-the-topics-lock", "not-a-device-message", "other-lock"],
)
async def test_an_mqtt_lock_reads_only_its_own_device_messages(
    rig: Rig, wifi_lock: FakeMqttLock, answer_cmd: int, dev_sn: str | None, confirmed: bool
) -> None:
    """Answers and status reports count only in a device message (``cmd`` 8) whose through
    data names the lock (``dev_sn``; the topic's lock when it names none)."""
    wifi_lock.answer_cmd, wifi_lock.answer_dev_sn = answer_cmd, dev_sn
    account = await _served(rig)
    events = _events(rig)
    try:
        if confirmed:
            assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
        else:
            with pytest.raises(DeviceTimeoutError, match="no answer"):
                await rig.eufy.async_lock(LOCK_SN, timeout=1)
    finally:
        await account.async_stop()
    assert bool([e for e in events if isinstance(e, LockStateChanged)]) is confirmed


async def test_no_status_report_over_mqtt_times_out(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await rig.eufy.async_lock(LOCK_SN, timeout=1)
    finally:
        await account.async_stop()


async def test_a_silent_mqtt_lock_times_out_within_the_given_timeout(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.answer = False
    account = await _served(rig)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="no answer"):
                await rig.eufy.async_lock(LOCK_SN, timeout=0.5)
    finally:
        await account.async_stop()


async def test_an_mqtt_lock_already_locked_sends_nothing(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    account = await _served(rig)
    try:
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK]


async def test_a_second_mqtt_command_while_one_waits_is_busy(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        first = asyncio.create_task(rig.eufy.async_lock(LOCK_SN, timeout=5))
        async with asyncio.timeout(5):
            while not wifi_lock.received:
                await asyncio.sleep(0.01)
            with pytest.raises(DeviceBusyError):
                await rig.eufy.async_unlock(LOCK_SN)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
    finally:
        await account.async_stop()
    assert len(wifi_lock.received) == 1


async def test_an_mqtt_lock_without_a_member_record_is_refused(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    device = CloudDevice.from_api(
        {"device_sn": LOCK_SN, "device_type": 0, "device_new_pn": "T85D0"}
    )
    account = await _served(rig, device)
    try:
        with pytest.raises(UnsupportedError, match="member"):
            await rig.eufy.async_lock(LOCK_SN)
    finally:
        await account.async_stop()
    assert wifi_lock.received == []


async def test_a_fault_state_over_mqtt_raises_lock_not_moved(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.move_to = 5
    account = await _served(rig)
    try:
        with pytest.raises(LockNotMovedError):
            await rig.eufy.async_lock(LOCK_SN, timeout=5)
    finally:
        await account.async_stop()


async def test_an_mqtt_lock_without_an_account_is_refused(rig: Rig) -> None:
    rig.eufy.listed_devices = MappingProxyType({LOCK_SN: lock()})
    with pytest.raises(MqttAccountRequiredError):
        await rig.eufy.async_lock(LOCK_SN)
    assert rig.broker.published == []


async def test_a_guest_of_an_mqtt_lock_is_refused(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    guest = dataclasses.replace(lock(), member_type=0)
    account = await _served(rig, guest)
    try:
        assert rig.eufy.lock_control(LOCK_SN).guest
        with pytest.raises(GuestAccessError):
            await rig.eufy.async_lock(LOCK_SN)
    finally:
        await account.async_stop()
    assert wifi_lock.received == []


async def test_a_device_not_listed_is_refused(rig: Rig) -> None:
    with pytest.raises(UnsupportedError, match="device list"):
        rig.eufy.lock_control(LOCK_SN)


# ── one merged reading per lock ───────────────────────────────────────────────


def _push(event_type: int, at_ms: int, serial: str = LOCK_SN) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.CLOUD, device_sn=serial, event_type=event_type, event_time_ms=at_ms
    )


async def test_a_status_report_before_any_command_is_the_locks_reading(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """A lock's own status report over MQTT is read with no command of this client
    pending, into the lock's one merged reading."""
    account = await _served(rig)
    try:
        await wifi_lock.async_report(4)
        await until(lambda: rig.eufy.lock_state(LOCK_SN) is not None)
    finally:
        await account.async_stop()
    reading = rig.eufy.lock_state(LOCK_SN)
    assert reading is not None
    assert (reading.state, reading.source, reading.raw) == (
        LockState.LOCKED,
        LockStateSource.LOCK,
        "4",
    )


async def test_a_lock_command_is_sent_when_a_newer_push_says_otherwise_than_mqtt(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """MQTT said locked; a newer push says unlocked (by hand): the merged reading is
    unlocked and a lock command is sent, not answered from the MQTT report."""
    account = await _served(rig)
    try:
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
        wifi_lock.state_code = 3  # moved by hand; only the push says so
        rig.eufy._deliver(_push(258, int(time.time() * 1000) + 1))
        assert rig.eufy.lock_state(LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK, LockAction.LOCK]


async def test_a_push_older_than_the_mqtt_report_keeps_the_mqtt_reading(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """The newest report wins: a push dated before the lock's MQTT report by more than the
    slack is dropped and the next lock command is answered from the reading, sending
    nothing."""
    account = await _served(rig)
    try:
        before = int(time.time() * 1000) - LOCK_REPORT_SLACK_SECONDS * 1000 - 1
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
        rig.eufy._deliver(_push(258, before))
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK]


async def test_a_push_inside_the_slack_before_an_mqtt_report_is_taken_and_commands_go_out() -> None:
    """The lock's MQTT report is dated by its arrival, a push by its event time on the
    lock's or the cloud's clock. Unlocked 1.5 s after a locked report, on a clock 2 s
    behind, the push is dated before the report: it is taken, and as the order of the two
    is unknown, neither command is answered from the reading."""
    now = 1_700_000_000_000
    device = lock()
    states = ListedLocks(EventBus(), lambda: [device], now_ms=lambda: now)
    account = _Recording()
    locks = _listed_lock_commands(account, device, states=states)
    control = mqtt_lock_control(device)
    states.on_report(LOCK_SN, 4)
    assert states.on_push(_push(258, now + 1_500 - 2_000)) is True
    assert states.reading(LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]
    for action in (LockAction.LOCK, LockAction.UNLOCK):
        with pytest.raises(DeviceTimeoutError):
            await locks.async_command(device, action, control=control, timeout=5)
    assert len(account.waits) == 2


async def test_a_second_push_of_the_same_state_before_an_mqtt_report_keeps_the_order_unknown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Two lock pushes dated before an unlocked MQTT report (inside the slack) may both
    predate it: the second one does not settle the reading, so a lock command is sent.
    The unknown order is logged once per lock (throttled)."""
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.station.locks")
    now = 1_700_000_000_000
    device = lock()
    states = ListedLocks(EventBus(), lambda: [device], now_ms=lambda: now)
    account = _Recording()
    locks = _listed_lock_commands(account, device, states=states)
    states.on_report(LOCK_SN, 3)
    assert states.on_push(_push(262, now - 500)) is True
    assert states.on_push(_push(262, now - 400)) is True
    assert states.reading(LOCK_SN).state is LockState.LOCKED  # type: ignore[union-attr]
    with pytest.raises(DeviceTimeoutError):
        await locks.async_command(
            device, LockAction.LOCK, control=mqtt_lock_control(device), timeout=5
        )
    assert len(account.waits) == 1
    unknown = [r.getMessage() for r in caplog.records if "order unknown" in r.getMessage()]
    assert unknown == [
        f"T85D0***4321: lock push (locked) dated {now - 500} ms, last report (lock: unlocked) "
        f"dated {now} ms: order unknown, the next lock command is sent"
    ]


async def test_each_lock_logs_its_own_unknown_order(caplog: pytest.LogCaptureFixture) -> None:
    """The unknown-order line is throttled per lock: a second lock still gets its own."""
    caplog.set_level(logging.DEBUG, logger="eufy_home_security.station.locks")
    now = 1_700_000_000_000
    devices = [lock(), lock(LOCK2_SN, "T85L0")]
    states = ListedLocks(EventBus(), lambda: devices, now_ms=lambda: now)
    for device in devices:
        states.on_report(device.device_sn, 3)
        assert states.on_push(_push(262, now - 500, device.device_sn)) is True
    unknown = [r.getMessage() for r in caplog.records if "order unknown" in r.getMessage()]
    assert [line.split(":")[0] for line in unknown] == ["T85D0***4321", "T85L0***4322"]


async def test_of_two_reports_in_one_millisecond_the_later_taken_is_the_last() -> None:
    """Two reports of the lock dated the same millisecond: the one taken later is the last
    report a push is ordered against. A push of its state dated before it settles nothing
    new, so an unlock is answered from the reading."""
    now = 1_700_000_000_000
    device = lock()
    states = ListedLocks(EventBus(), lambda: [device], now_ms=lambda: now)
    account = _Recording()
    locks = _listed_lock_commands(account, device, states=states)
    states.on_report(LOCK_SN, 4)
    states.on_report(LOCK_SN, 3)  # the same millisecond, taken later
    assert states.on_push(_push(257, now - 500)) is True
    state = await locks.async_command(
        device, LockAction.UNLOCK, control=mqtt_lock_control(device), timeout=5
    )
    assert state is LockState.UNLOCKED
    assert account.waits == []


@pytest.mark.parametrize(
    ("offset_ms", "ends"), [(-3_000, False), (1, True)], ids=["unsettled", "settled"]
)
async def test_only_a_settled_push_ends_an_mqtt_commands_wait(
    rig: Rig, wifi_lock: FakeMqttLock, offset_ms: int, ends: bool
) -> None:
    """An unlock the lock took waits for its state: a push of that state dated before the
    lock's last report (the order of the two unknown) does not end the wait, the lock's
    own report does; a push dated after the report ends it."""
    account = await _served(rig)
    try:
        await wifi_lock.async_report(4)
        await until(lambda: rig.eufy.lock_state(LOCK_SN) is not None)
        reported = rig.eufy.lock_state(LOCK_SN).observed_at  # type: ignore[union-attr]
        assert reported is not None
        wifi_lock.report = False
        unlocking = asyncio.create_task(rig.eufy.async_unlock(LOCK_SN, timeout=5))
        await until(
            lambda: rig.eufy.lock_state(LOCK_SN).state is LockState.UNLOCKING  # type: ignore[union-attr]
        )
        rig.eufy._deliver(_push(257, int(reported * 1000) + offset_ms))
        await asyncio.sleep(0.1)
        assert unlocking.done() is ends
        if not ends:
            assert rig.eufy.lock_state(LOCK_SN).state is LockState.UNLOCKING  # type: ignore[union-attr]
            await wifi_lock.async_report(3)
        async with asyncio.timeout(5):
            assert await unlocking is LockState.UNLOCKED
    finally:
        await account.async_stop()


@pytest.mark.parametrize("keep", [False, True], ids=["call-ended", "hold-expired"])
async def test_a_move_ending_with_nothing_reported_reads_what_its_event_says(
    monkeypatch: pytest.MonkeyPatch, keep: bool
) -> None:
    """A command's move ends on a lock with no report before it: the lock reads unknown
    (source ``command``), the reading its last ``LockStateChanged`` names."""
    monkeypatch.setattr(control, "LOCK_CONFIRM_TIMEOUT", 0.05)
    bus = EventBus()
    seen: list[Event] = []
    bus.subscribe(seen.append)
    device = lock()
    states = ListedLocks(bus, lambda: [device])
    taken = states.begin_move(LOCK_SN, LockAction.LOCK)
    states.end_move(LOCK_SN, taken_at=taken, keep=keep)
    await until(lambda: len(seen) == 2)
    changes = [e for e in seen if isinstance(e, LockStateChanged)]
    assert [(e.state, e.source) for e in changes] == [
        (LockState.LOCKING, LockStateSource.COMMAND),
        (LockState.UNKNOWN, LockStateSource.COMMAND),
    ]
    assert states.reading(LOCK_SN) == LockReading(
        state=LockState.UNKNOWN, source=LockStateSource.COMMAND
    )
    assert changes[-1].observed_at is None


async def test_each_report_taken_emits_one_event_and_sets_the_public_reading(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """``EufySecurity.lock_state`` is the merged reading; each report it takes emits one
    ``LockStateChanged`` (``changed`` False when the state repeats), a report it drops
    none."""
    account = await _served(rig)
    events = _events(rig)
    try:
        await wifi_lock.async_report(4)
        await until(lambda: len(events) == 1)
        first = rig.eufy.lock_state(LOCK_SN)
        await wifi_lock.async_report(4)
        await until(lambda: len(events) == 2)
        again = rig.eufy.lock_state(LOCK_SN)
        rig.eufy._deliver(_push(258, int(time.time() * 1000) - 60_000))  # older: dropped
    finally:
        await account.async_stop()
    changes = [e for e in events if isinstance(e, LockStateChanged)]
    assert [(e.state, e.source, e.changed) for e in changes] == [
        (LockState.LOCKED, LockStateSource.LOCK, True),
        (LockState.LOCKED, LockStateSource.LOCK, False),
    ]
    assert first is not None
    assert again is not None
    assert first.observed_at is not None
    assert again.observed_at is not None
    assert again.observed_at >= first.observed_at
    assert changes[1].observed_at == again.observed_at
    assert rig.eufy.lock_state(LOCK_SN) == again
    with pytest.raises(UnsupportedError, match="device list"):
        rig.eufy.lock_state(LOCK2_SN)


async def test_a_cancelled_mqtt_command_the_lock_took_keeps_it_moving_and_the_next_is_sent(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """Over MQTT as on the station path: an unlock the lock took (its answer accepted it)
    whose call is cancelled keeps the lock unlocking; a lock command is then sent
    although the last report is locked."""
    account = await _served(rig)
    try:
        await wifi_lock.async_report(4)
        await until(lambda: rig.eufy.lock_state(LOCK_SN) is not None)
        wifi_lock.report = False
        unlocking = asyncio.create_task(rig.eufy.async_unlock(LOCK_SN))
        await until(
            lambda: rig.eufy.lock_state(LOCK_SN).state is LockState.UNLOCKING  # type: ignore[union-attr]
        )
        unlocking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlocking
        held = rig.eufy.lock_state(LOCK_SN)
        assert held is not None
        assert (held.state, held.source) == (LockState.UNLOCKING, LockStateSource.COMMAND)
        wifi_lock.report = True
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.UNLOCK, LockAction.LOCK]


async def test_a_timed_out_mqtt_command_keeps_it_moving_until_the_locks_next_report(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await rig.eufy.async_lock(LOCK_SN, timeout=0.5)
        assert rig.eufy.lock_state(LOCK_SN).state is LockState.LOCKING  # type: ignore[union-attr]
        await wifi_lock.async_report(4)
        await until(
            lambda: rig.eufy.lock_state(LOCK_SN).source is LockStateSource.LOCK  # type: ignore[union-attr]
        )
    finally:
        await account.async_stop()
    assert rig.eufy.lock_state(LOCK_SN).state is LockState.LOCKED  # type: ignore[union-attr]


async def test_a_held_mqtt_move_ends_at_the_opposite_state_report(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    """A timed-out lock command's hold ends at the lock's next report even when that
    report is not the asked state."""
    wifi_lock.report = False
    account = await _served(rig)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await rig.eufy.async_lock(LOCK_SN, timeout=0.5)
        assert rig.eufy.lock_state(LOCK_SN).state is LockState.LOCKING  # type: ignore[union-attr]
        await wifi_lock.async_report(3)
        await until(
            lambda: rig.eufy.lock_state(LOCK_SN).source is LockStateSource.LOCK  # type: ignore[union-attr]
        )
    finally:
        await account.async_stop()
    assert rig.eufy.lock_state(LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]


async def test_a_held_mqtt_move_ends_at_a_jammed_push(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await rig.eufy.async_lock(LOCK_SN, timeout=0.5)
        rig.eufy._deliver(_push(517, int(time.time() * 1000)))
        reading = rig.eufy.lock_state(LOCK_SN)
    finally:
        await account.async_stop()
    assert reading is not None
    assert (reading.state, reading.source) == (LockState.JAMMED, LockStateSource.PUSH)


VIDEO_LOCK_SN = "T8531P2000054323"


async def test_a_lock_that_is_its_own_station_merges_mqtt_and_station_reports(
    rig: Rig,
) -> None:
    """A video lock that is its own station takes commands over MQTT: its MQTT status
    report and its station's dump feed one reading, so a dump after the MQTT report that
    says unlocked (the value the station held before) makes a lock command send."""
    fake_station = FakeStation()
    fake_station.serial = VIDEO_LOCK_SN
    fake_station.static_key = static_key(VIDEO_LOCK_SN, fake_station.did)
    for block in (fake_station.params[0], fake_station.params[255]):
        block |= {6000: "3"}
    await fake_station.start()
    device = dataclasses.replace(
        lock(VIDEO_LOCK_SN, "T8531"), station_sn=VIDEO_LOCK_SN, p2p_did=SYNTHETIC.did
    )
    fake = FakeMqttLock(
        broker=rig.broker, serial=VIDEO_LOCK_SN, product_code="T8531", owner_user_id=OWNER
    )
    fake.attach()
    station = Station(device, _station_session(fake_station, VIDEO_LOCK_SN))
    rig.eufy.stations[VIDEO_LOCK_SN] = station
    account = await _served(rig, device)
    try:
        await station.async_update()
        assert station.lock_state(VIDEO_LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]
        assert await rig.eufy.async_lock(VIDEO_LOCK_SN, timeout=5) is LockState.LOCKED
        assert station.lock_state(VIDEO_LOCK_SN).source is LockStateSource.LOCK  # type: ignore[union-attr]
        await station.async_update()  # the station still holds "3": unlocked by hand since
        assert station.lock_state(VIDEO_LOCK_SN).state is LockState.UNLOCKED  # type: ignore[union-attr]
        assert await rig.eufy.async_lock(VIDEO_LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
        rig.eufy.stations.pop(VIDEO_LOCK_SN)
        await station.async_close()
        fake_station.stop()
    assert [a for a, _ in fake.received] == [LockAction.LOCK, LockAction.LOCK]
    assert fake.refused == []


def _station_session(fake: FakeStation, serial: str) -> StationSession:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "Nick", fake.ecc_private_key_hex)

    return StationSession(serial, credentials, host="127.0.0.1", port=fake.discovery_port)
