"""Dedicated T8970 siren operations through synthetic HomeBases."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import replace

import pytest

import eufy_home_security.p2p.session as session_module
from eufy_home_security import DeviceAlarmOperationChanged
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.device_alarm import DeviceAlarm
from eufy_home_security.events import DisconnectCause, Event
from eufy_home_security.exceptions import (
    CommandUnsupportedError,
    DeviceBusyError,
    DeviceTimeoutError,
    StationUnreachableError,
    UnsupportedError,
)
from eufy_home_security.p2p.session import (
    CommandOutcome,
    P2PCredentials,
    StationSession,
)
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.station import Station, siren_loop
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

HB_SN = "T8010" + SYNTHETIC.station_sn[5:]
SIREN_SN = "T8970" + SYNTHETIC.camera_sn[5:]
SECOND_SN = SIREN_SN + "1"

HB = CloudDevice(
    device_sn=HB_SN,
    device_type=0,
    name="Synthetic HomeBase 2",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.4.2.6h",
)

SIREN = CloudDevice(
    device_sn=SIREN_SN,
    device_type=21,
    name="Synthetic siren",
    station_sn=HB_SN,
    channel=36,
)

SECOND = replace(
    SIREN,
    device_sn=SECOND_SN,
    channel=37,
)

INTERVAL = 0.2
DURATION = 1.0

type Transition = tuple[str, bool, bool | None]
type Rig = tuple[Station, FakeStation, list[Transition]]


def sent(fake: FakeStation) -> list[tuple[int, int]]:
    return [(obj["cmd"], obj["mChannel"]) for obj in fake.received]


def for_channel(
    fake: FakeStation,
    channel: int,
) -> list[int]:
    return [cmd for cmd, target in sent(fake) if target == channel]


async def wait_for(
    predicate: Callable[[], bool],
    timeout: float = 4.0,
) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.005)


def has_waiters(lock: asyncio.Lock) -> bool:
    return any(not waiter.done() for waiter in (lock._waiters or ()))


@pytest.fixture
async def rig(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Rig]:
    monkeypatch.setattr(
        siren_loop,
        "SIREN_REPEAT_INTERVAL",
        INTERVAL,
    )
    monkeypatch.setattr(
        siren_loop,
        "SIREN_REPEAT_DURATION",
        DURATION,
    )
    monkeypatch.setattr(
        session_module,
        "COMMAND_RECEIPT_TIMEOUT",
        1.0,
    )

    fake = FakeStation(serial=HB_SN)
    await fake.start()

    async def credentials(
        *,
        refresh: bool,
        cipher_id: int | None = None,
    ) -> P2PCredentials:
        return P2PCredentials(
            SYNTHETIC.account_id,
            "synthetic-user",
            fake.ecc_private_key_hex,
        )

    session = StationSession(
        HB_SN,
        credentials,
        host="127.0.0.1",
        port=fake.discovery_port,
    )

    station = Station(
        HB,
        session,
        sub_devices=(SIREN, SECOND),
    )

    transitions: list[Transition] = []

    def on_event(event: Event) -> None:
        if isinstance(event, DeviceAlarmOperationChanged):
            transitions.append(
                (
                    event.device_sn,
                    event.active,
                    station.device_alarm_operation_active(event.device_sn),
                )
            )

    unsubscribe = station.subscribe(on_event)

    try:
        await session.async_connect()
        assert not session.rsa_session
        yield station, fake, transitions

    finally:
        try:
            await station.async_close()
        finally:
            unsubscribe()
            fake.stop()


def expected_transitions(
    device_sn: str = SIREN_SN,
) -> list[Transition]:
    return [
        (device_sn, True, True),
        (device_sn, False, False),
    ]


async def test_capability_and_unsupported_choices(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    for device_sn in (SIREN_SN, SECOND_SN):
        assert station.supports_siren_test(device_sn)
        assert station.device_alarms(device_sn) == (DeviceAlarm.SOUND,)
        assert station.device_alarm_default(device_sn) is DeviceAlarm.SOUND
        assert station.device_alarm_operation_active(device_sn) is False

    assert not station.supports_siren_test(HB_SN)

    assert station.device_alarm_operation_active(HB_SN) is None

    with pytest.raises(UnsupportedError):
        await station.async_test_siren(HB_SN)

    for alarm in (DeviceAlarm.LIGHT, 99):
        with pytest.raises(UnsupportedError):
            await station.async_trigger_device_alarm(
                SIREN_SN,
                alarm,
            )

        with pytest.raises(UnsupportedError):
            await station.async_stop_device_alarm(
                SIREN_SN,
                alarm,
            )

    assert sent(fake) == []
    assert transitions == []


async def test_single_native_pulse(rig: Rig) -> None:
    station, fake, transitions = rig

    assert await station.async_test_siren(SIREN_SN) is CommandOutcome.DELIVERED

    await asyncio.sleep(INTERVAL * 2)

    assert sent(fake) == [(1826, 36)]

    obj = fake.received[0]

    assert obj["mValue3"] == 0
    assert set(obj["payload"]) == {"transaction"}
    assert obj["payload"]["transaction"].isdigit()
    assert fake.received_header_channels == [36]
    assert transitions == []

    assert station.device_alarm_operation_active(SIREN_SN) is False

    assert await station.async_stop_device_alarm(SECOND_SN) is CommandOutcome.DELIVERED

    assert sent(fake) == [
        (1826, 36),
        (1871, 37),
    ]


async def test_sustained_alarm_and_duplicate_on(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    assert await station.async_trigger_device_alarm(SIREN_SN) is CommandOutcome.DELIVERED

    assert transitions == [
        (SIREN_SN, True, True),
    ]

    assert station.device_alarm_on(SIREN_SN) is not True

    controller = station._alarms._siren_loops[SIREN_SN]
    task = controller._task

    assert await station.async_trigger_device_alarm(SIREN_SN) is CommandOutcome.DELIVERED

    assert controller._task is task

    with pytest.raises(DeviceBusyError):
        await station.async_test_siren(SIREN_SN)

    await wait_for(lambda: len(for_channel(fake, 36)) >= 2)

    assert await station.async_stop_device_alarm(SIREN_SN) is CommandOutcome.DELIVERED

    commands = for_channel(fake, 36)

    assert len(commands) >= 3
    assert all(cmd == 1826 for cmd in commands[:-1])
    assert commands[-1] == 1871
    assert transitions == expected_transitions()

    await asyncio.sleep(INTERVAL * 2)

    assert for_channel(fake, 36) == commands


async def test_automatic_cutoff(rig: Rig) -> None:
    station, fake, transitions = rig

    await station.async_trigger_device_alarm(SIREN_SN)

    await wait_for(lambda: station.device_alarm_operation_active(SIREN_SN) is False)

    commands = for_channel(fake, 36)

    assert 2 <= len(commands[:-1]) <= 5
    assert all(cmd == 1826 for cmd in commands[:-1])
    assert commands[-1] == 1871
    assert transitions == expected_transitions()

    await asyncio.sleep(INTERVAL * 2)

    assert for_channel(fake, 36) == commands


async def test_channel_reassignment(rig: Rig) -> None:
    station, fake, transitions = rig

    await station.async_trigger_device_alarm(SIREN_SN)

    station.update_sub_devices((replace(SIREN, channel=38), SECOND))

    await wait_for(lambda: station.device_alarm_operation_active(SIREN_SN) is False)

    await asyncio.sleep(INTERVAL * 2)

    assert sent(fake) == [(1826, 36)]
    assert transitions == expected_transitions()

    await station.async_test_siren(SIREN_SN)
    await station.async_stop_device_alarm(SIREN_SN)

    assert sent(fake) == [
        (1826, 36),
        (1826, 38),
        (1871, 38),
    ]


async def test_shutdown_interrupts_before_disconnect(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    await station.async_trigger_device_alarm(SIREN_SN)
    await station.async_close()

    assert sent(fake) == [
        (1826, 36),
        (1871, 36),
    ]

    assert not station.session.connected
    assert transitions == expected_transitions()

    await asyncio.sleep(INTERVAL * 2)

    assert len(sent(fake)) == 2


async def test_shutdown_waits_for_pending_test_receipt(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    fake.unanswered_commands.add(1826)

    async with asyncio.TaskGroup() as group:
        sound_test = group.create_task(station.async_test_siren(SIREN_SN))

        await wait_for(lambda: sent(fake) == [(1826, 36)])

        closing = group.create_task(station.async_close())

        await wait_for(lambda: station._alarms._siren_closing)

        assert not sound_test.done()
        assert not closing.done()
        assert bool(station.session.connected)
        assert station.session._op_lock.locked()

        fake.send_receipt(FrameType.CMD_TRANSFER, 0)

    assert sound_test.result() is CommandOutcome.DELIVERED
    assert sent(fake) == [(1826, 36), (1871, 36)]
    assert not station.session.connected
    assert transitions == []


async def test_off_supersedes_start_queued_behind_test(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    fake.unanswered_commands.add(1826)

    async def superseded_start() -> None:
        with pytest.raises(DeviceBusyError):
            await station.async_trigger_device_alarm(SIREN_SN)

    async with asyncio.TaskGroup() as group:
        sound_test = group.create_task(station.async_test_siren(SIREN_SN))

        await wait_for(lambda: sent(fake) == [(1826, 36)])

        lock = station._alarms._siren_locks[SIREN_SN]
        controller = station._alarms._siren_loops[SIREN_SN]

        group.create_task(superseded_start())

        await wait_for(lambda: has_waiters(lock))

        off = group.create_task(station.async_stop_device_alarm(SIREN_SN))

        await wait_for(controller._stop_requested.is_set)

        assert not sound_test.done()
        assert not off.done()

        fake.send_receipt(FrameType.CMD_TRANSFER, 0)

    assert sound_test.result() is CommandOutcome.DELIVERED
    assert off.result() is CommandOutcome.DELIVERED
    assert sent(fake) == [(1826, 36), (1871, 36)]
    assert transitions == []
    assert station.device_alarm_operation_active(SIREN_SN) is False


async def test_two_sirens_are_independent(
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station, fake, transitions = rig

    monkeypatch.setattr(
        siren_loop,
        "SIREN_REPEAT_DURATION",
        3.0,
    )

    await asyncio.gather(
        station.async_trigger_device_alarm(SIREN_SN),
        station.async_trigger_device_alarm(SECOND_SN),
    )

    assert station.device_alarm_operation_active(SIREN_SN) is True

    assert station.device_alarm_operation_active(SECOND_SN) is True

    await station.async_stop_device_alarm(SIREN_SN)

    assert station.device_alarm_operation_active(SIREN_SN) is False

    assert station.device_alarm_operation_active(SECOND_SN) is True

    first = for_channel(fake, 36)
    second_count = len(for_channel(fake, 37))

    assert first[-1] == 1871

    await wait_for(lambda: len(for_channel(fake, 37)) > second_count)

    assert for_channel(fake, 36) == first

    await station.async_stop_device_alarm(SECOND_SN)

    assert for_channel(fake, 37)[-1] == 1871

    for device_sn in (SIREN_SN, SECOND_SN):
        assert [item for item in transitions if item[0] == device_sn] == expected_transitions(
            device_sn
        )


async def test_off_suppresses_queued_refresh(
    rig: Rig,
) -> None:
    station, fake, transitions = rig
    session = station.session

    await station.async_trigger_device_alarm(SIREN_SN)

    controller = station._alarms._siren_loops[SIREN_SN]

    async with asyncio.TaskGroup() as group, session._op_lock:
        await wait_for(lambda: has_waiters(session._op_lock))

        off = group.create_task(station.async_stop_device_alarm(SIREN_SN))

        await wait_for(controller._stop_requested.is_set)

        assert not off.done()
        assert sent(fake) == [(1826, 36)]

    assert off.result() is CommandOutcome.DELIVERED

    assert sent(fake) == [
        (1826, 36),
        (1871, 36),
    ]

    assert transitions == expected_transitions()


async def test_off_preserves_pending_receipt(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    fake.unanswered_commands.add(1826)

    async with asyncio.TaskGroup() as group:
        on = group.create_task(station.async_trigger_device_alarm(SIREN_SN))

        await wait_for(lambda: sent(fake) == [(1826, 36)])

        off = group.create_task(station.async_stop_device_alarm(SIREN_SN))

        controller = station._alarms._siren_loops[SIREN_SN]

        await wait_for(controller._stop_requested.is_set)

        assert not on.done()
        assert not off.done()
        assert station.session._op_lock.locked()

        fake.send_receipt(FrameType.CMD_TRANSFER, 0)

    assert on.result() is CommandOutcome.DELIVERED
    assert off.result() is CommandOutcome.DELIVERED

    assert sent(fake) == [
        (1826, 36),
        (1871, 36),
    ]

    assert transitions == expected_transitions()


async def test_cancellation_preserves_receipt_wait(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    fake.unanswered_commands.update({1826, 1871})

    on = asyncio.create_task(station.async_trigger_device_alarm(SIREN_SN))

    await wait_for(lambda: sent(fake) == [(1826, 36)])

    on.cancel()

    with pytest.raises(asyncio.CancelledError):
        await on

    assert station.session._op_lock.locked()

    off = asyncio.create_task(station.async_stop_device_alarm(SIREN_SN))

    controller = station._alarms._siren_loops[SIREN_SN]

    await wait_for(controller._stop_requested.is_set)

    fake.send_receipt(FrameType.CMD_TRANSFER, 0)

    await wait_for(
        lambda: (
            sent(fake)
            == [
                (1826, 36),
                (1871, 36),
            ]
        )
    )

    off.cancel()

    with pytest.raises(asyncio.CancelledError):
        await off

    assert station.session._op_lock.locked()

    fake.send_receipt(FrameType.CMD_TRANSFER, 0)

    await wait_for(lambda: not controller.running)

    assert not station.session._op_lock.locked()
    assert transitions == expected_transitions()

    await asyncio.sleep(INTERVAL * 2)

    assert len(sent(fake)) == 2


@pytest.mark.parametrize("announced", [False, True])
async def test_connection_loss(
    rig: Rig,
    announced: bool,
) -> None:
    station, fake, transitions = rig
    session = station.session

    if announced:
        session._announce_connected()

    assert session.announced is announced

    await station.async_trigger_device_alarm(SIREN_SN)

    generation = session.link_generation

    session._teardown(
        "synthetic connection loss",
        cause=DisconnectCause.UNREACHABLE,
    )

    await wait_for(lambda: station.device_alarm_operation_active(SIREN_SN) is False)

    await asyncio.sleep(INTERVAL * 2)

    assert not session.connected
    assert session.link_generation == generation
    assert sent(fake) == [(1826, 36)]
    assert transitions == expected_transitions()

    await session.async_connect()

    assert session.link_generation != generation

    with pytest.raises(StationUnreachableError):
        await session.async_send_command(
            1826,
            channel=36,
            resend=False,
            receipt_only=True,
            expected_link_generation=generation,
        )

    assert sent(fake) == [(1826, 36)]


async def test_expired_refresh_is_not_sent(
    rig: Rig,
) -> None:
    station, fake, transitions = rig
    session = station.session

    await station.async_trigger_device_alarm(SIREN_SN)

    async with session._op_lock:
        await wait_for(lambda: has_waiters(session._op_lock))

        await asyncio.sleep(DURATION)

        assert sent(fake) == [(1826, 36)]

    await wait_for(lambda: station.device_alarm_operation_active(SIREN_SN) is False)

    assert sent(fake) == [
        (1826, 36),
        (1871, 36),
    ]

    assert transitions == expected_transitions()


async def test_delayed_rejection_keeps_command_attribution(
    rig: Rig,
) -> None:
    station, fake, _ = rig
    session = station.session

    fake.unhandled_commands.add(1826)
    fake.rejection_delay = 0.3
    fake.reply_to_settings = True

    async def rejected() -> None:
        with pytest.raises(CommandUnsupportedError) as error:
            await session.async_send_command(
                1826,
                channel=36,
                timeout=0.1,
                resend=False,
                receipt_only=True,
            )

        assert error.value.command == 1826
        assert error.value.code == -108

    async with asyncio.TaskGroup() as group:
        first = group.create_task(rejected())

        await wait_for(lambda: sent(fake) == [(1826, 36)])

        second = group.create_task(
            session.async_send_command(
                1107,
                timeout=1.0,
                resend=False,
            )
        )

        await wait_for(lambda: has_waiters(session._op_lock))

        assert not first.done()
        assert not second.done()
        assert len(sent(fake)) == 1

    assert second.result() is CommandOutcome.APPLIED
    assert [obj["cmd"] for obj in fake.received] == [
        1826,
        1107,
    ]


async def test_packet_ack_is_not_command_receipt(
    rig: Rig,
) -> None:
    station, fake, _ = rig

    fake.unanswered_commands.add(1826)

    with pytest.raises(DeviceTimeoutError):
        await station.session.async_send_command(
            1826,
            channel=36,
            timeout=0.1,
            resend=False,
            receipt_only=True,
        )

    assert sent(fake) == [(1826, 36)]
    assert not station.session._op_lock.locked()


async def test_unpaired_siren_is_refused_without_sending(
    rig: Rig,
) -> None:
    station, fake, transitions = rig

    station.update_sub_devices((SECOND,))

    assert not station.supports_siren_test(SIREN_SN)
    assert station.device_alarms(SIREN_SN) == ()
    assert station.device_alarm_operation_active(SIREN_SN) is None

    for operation in (
        station.async_test_siren,
        station.async_trigger_device_alarm,
        station.async_stop_device_alarm,
    ):
        with pytest.raises(UnsupportedError):
            await operation(SIREN_SN)

    assert sent(fake) == []
    assert transitions == []


async def test_incompatible_homebase_topology_is_refused() -> None:
    hub = replace(
        HB,
        device_sn="T8001" + HB_SN[5:],
        device_type=0,
    )

    siren = replace(
        SIREN,
        station_sn=hub.device_sn,
    )

    async def credentials(
        *,
        refresh: bool,
        cipher_id: int | None = None,
    ) -> P2PCredentials:
        raise AssertionError("Unsupported topology must not request credentials")

    session = StationSession(
        hub.device_sn,
        credentials,
        host="127.0.0.1",
    )

    station = Station(
        hub,
        session,
        sub_devices=(siren,),
    )

    try:
        assert not station.supports_siren_test(SIREN_SN)
        assert station.device_alarm_operation_active(SIREN_SN) is None

        with pytest.raises(UnsupportedError):
            await station.async_test_siren(SIREN_SN)

        assert not session.connected

    finally:
        await station.async_close()


@pytest.mark.parametrize(
    ("model", "device_type"),
    [("T8030", 18), ("T8025", 0), ("T9000", 0)],
)
async def test_compatible_homebase_siren_operations(
    model: str,
    device_type: int,
) -> None:
    hub = replace(
        HB,
        device_sn=model + HB_SN[5:],
        device_type=device_type,
        name="Synthetic compatible HomeBase",
    )
    siren = replace(SIREN, station_sn=hub.device_sn)

    fake = FakeStation(serial=hub.device_sn)
    await fake.start()

    async def credentials(
        *,
        refresh: bool,
        cipher_id: int | None = None,
    ) -> P2PCredentials:
        return P2PCredentials(
            SYNTHETIC.account_id,
            "synthetic-user",
            fake.ecc_private_key_hex,
        )

    session = StationSession(
        hub.device_sn,
        credentials,
        host="127.0.0.1",
        port=fake.discovery_port,
    )
    station = Station(hub, session, sub_devices=(siren,))

    try:
        assert station.supports_siren_test(SIREN_SN)
        assert station.device_alarms(SIREN_SN) == (DeviceAlarm.SOUND,)
        assert station.device_alarm_default(SIREN_SN) == DeviceAlarm.SOUND
        assert station.device_alarm_operation_active(SIREN_SN) is False

        assert await station.async_test_siren(SIREN_SN, timeout=1.0) is CommandOutcome.DELIVERED
        assert station.device_alarm_operation_active(SIREN_SN) is False

        assert (
            await station.async_trigger_device_alarm(SIREN_SN, timeout=1.0)
            is CommandOutcome.DELIVERED
        )
        assert station.device_alarm_operation_active(SIREN_SN) is True

        assert (
            await station.async_stop_device_alarm(SIREN_SN, timeout=1.0) is CommandOutcome.DELIVERED
        )
        assert station.device_alarm_operation_active(SIREN_SN) is False
        assert for_channel(fake, 36) == [1826, 1826, 1871]

    finally:
        try:
            await station.async_close()
        finally:
            fake.stop()
