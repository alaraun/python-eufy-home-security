"""``rtc/diagnostics.py``: the read-only WebRTC report, against the loopback fake station."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import struct
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.exceptions import MissingDependencyError
from eufy_home_security.p2p.xzyh import encode_frame
from eufy_home_security.rtc import client as client_mod
from eufy_home_security.rtc import diagnostics as diag
from eufy_home_security.rtc import session as session_mod
from eufy_home_security.rtc.codec import CallKind, MessageType
from eufy_home_security.rtc.data_channel import LINK_HEADER_LEN, LINK_HEADER_LEN_OLD, DataMsgType
from eufy_home_security.rtc.diagnostics import (
    RtcStationReport,
    StepStatus,
    async_diagnose_station,
    ip_class,
    placeholder,
    rtc_stations,
)
from eufy_home_security.rtc.sdp import read_pbsdp
from eufy_home_security.rtc.session import ConnectStep, RtcSession
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.rtc import (
    APP_ID,
    CONTACT,
    DEVICE_INFO,
    LICENSE,
    TURN,
    FakeRtcServer,
    rtc_config,
)

NVR_SN = "T8N00" + SYNTHETIC.station_sn[5:]
"""A synthetic NVR serial (the eufy app reaches a T8N00 only over WebRTC)."""
TURN_USER = "synthetic-turn-user"
TURN_PASSWORD = "synthetic-turn-secret"
SDK = "1.1.0"
"""Below the T8N00's kcp_type-2 SDK: the client offers no framing bit."""


def station_entry(serial: str = NVR_SN, **extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "device_sn": serial,
        "device_type": 0,
        "device_name": "Synthetic NVR",
        "device_new_pn": serial[:5],
        "p2p_did": SYNTHETIC.did,
        "p2p_license": LICENSE,
        "signaling_servers": ["https://127.0.0.1", "https://signal.example.com"],
        "main_sw_version": "1.3.0.0",
        "webrtc_sdk_version": SDK,
    }
    return entry | extra


def camera_entry(serial: str, parent: str, channel: int = 0) -> dict[str, Any]:
    return {
        "device_sn": serial,
        "device_type": 1,
        "device_name": "Synthetic camera",
        "device_new_pn": serial[:5],
        "parent_sn": parent,
        "device_channel": channel,
        "main_sw_version": "9.9.9.9",
    }


def devices(*entries: dict[str, Any]) -> list[CloudDevice]:
    return [CloudDevice.from_api(e) for e in entries]


@pytest.fixture
async def fake() -> AsyncIterator[FakeRtcServer]:
    seen: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, ctx: seen.append(ctx))
    server = await FakeRtcServer().start()
    yield server
    await server.close()
    await asyncio.sleep(0)
    loop.set_exception_handler(None)
    assert server.refused == []
    assert seen == []


@pytest.fixture
def run(fake: FakeRtcServer) -> Callable[..., Any]:
    async def run(*listed: dict[str, Any], **kwargs: Any) -> RtcStationReport:
        listed = listed or (station_entry(),)
        found = devices(*listed)
        kwargs.setdefault("seconds", 0.3)
        kwargs.setdefault("ice_factory", fake.ice_factory)
        return await async_diagnose_station(
            found[0],
            found,
            user_id=SYNTHETIC.account_id,
            app_id=APP_ID,
            signaling_port=fake.port,
            tcp_ports=(fake.tcp_port,),
            **kwargs,
        )

    return run


def secret_values() -> list[str]:
    """Every identifier and key of the synthetic run, as text."""
    values = []
    for f in dataclasses.fields(SYNTHETIC):
        value = getattr(SYNTHETIC, f.name)
        if isinstance(value, bytes):
            value = value.decode()
        if isinstance(value, str):
            values.append(value)
    values += [NVR_SN, LICENSE, CONTACT, APP_ID, "127.0.0.1", TURN_USER, TURN_PASSWORD]
    values += [DEVICE_INFO.ice_ufrag, DEVICE_INFO.ice_pwd]
    values += [DEVICE_INFO.content_key, DEVICE_INFO.content_iv, "signal.example.com"]
    return sorted(set(values))


# ── pure parts ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("192.0.2.10", "private"),
        ("10.1.2.3", "private"),
        ("169.254.1.1", "link_local"),
        ("100.64.0.1", "shared"),
        ("8.8.8.8", "public"),
        ("8.8.8.8:3478", "public"),
        ("signal.example.com", "not_ip"),
        ("", "not_ip"),
    ],
)
def test_an_address_is_reported_as_its_class(text: str, expected: str) -> None:
    assert ip_class(text) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("abcdef", "<did:6>"), ({"a": 1}, "<did:7>"), (None, "<did:0>"), (12, "<did:2>")],
)
def test_a_placeholder_keeps_the_field_name_and_length(value: object, expected: str) -> None:
    assert placeholder("did", value) == expected


def test_webrtc_only_stations_and_stations_with_a_routed_device_are_picked() -> None:
    hb3 = SYNTHETIC.station_sn
    routed_camera = "T8224" + SYNTHETIC.camera_sn[5:]
    plain = "T8025" + SYNTHETIC.station_sn[5:]
    found = devices(
        station_entry(),
        station_entry(hb3, main_sw_version="3.8.0.0"),
        camera_entry(routed_camera, hb3),
        station_entry(plain),
    )
    picked = {d.device_sn: reason for d, reason in rtc_stations(found)}
    assert picked == {NVR_SN: "station", hb3: "device"}


def test_a_named_station_is_picked_whatever_its_route() -> None:
    plain = "T8025" + SYNTHETIC.station_sn[5:]
    found = devices(station_entry(), station_entry(plain))
    assert [(d.device_sn, r) for d, r in rtc_stations(found, plain)] == [(plain, "asked")]
    assert [(d.device_sn, r) for d, r in rtc_stations(found, NVR_SN)] == [(NVR_SN, "station")]
    assert rtc_stations(found, "T8030P0000000000") == []


def test_the_inputs_name_what_is_present_and_how_each_device_is_routed() -> None:
    camera = "T8160" + SYNTHETIC.camera_sn[5:]
    found = devices(station_entry(), camera_entry(camera, NVR_SN, channel=3))
    inputs = diag.describe_inputs(found[0], found)
    assert inputs.outcome.status is StepStatus.OK
    assert inputs.present == {
        "p2p_did": True,
        "p2p_license": True,
        "signaling_servers": True,
        "webrtc_sdk_version": True,
        "main_sw_version": True,
    }
    assert (inputs.signaling_ipv4, inputs.signaling_domains) == (1, 1)
    assert (inputs.webrtc_sdk_version, inputs.main_sw_version) == (SDK, "1.3.0.0")
    assert inputs.webrtc_only is True
    assert inputs.kcp_type == 1  # T8N00 below SDK x.2: the single-stream framing
    assert [(d.product_code, d.channel, d.webrtc) for d in inputs.devices] == [("T8160", 3, True)]
    assert inputs.devices[0].serial == "T8160***7890"


def test_missing_inputs_fail_step_one_and_name_the_fields() -> None:
    found = devices(station_entry(p2p_license="", signaling_servers=["signal.example.com"]))
    inputs = diag.describe_inputs(found[0], found)
    assert inputs.outcome.status is StepStatus.FAILED
    assert inputs.missing == ("p2p_license", "signaling_servers")


# ── a run against the fake ───────────────────────────────────────────────────


async def test_a_full_run_records_every_step(fake: FakeRtcServer, run: Any) -> None:
    fake.transport_caps = 3
    fake.request_id = "synthetic-request"
    report = await run(probe_kinds=True)
    assert report.station == "T8N00***2345"
    assert report.inputs.outcome.status is StepStatus.OK
    login = report.login
    assert login.discover.status is StepStatus.OK
    assert login.login.status is StepStatus.OK
    assert login.quick_login is False
    assert login.server == "loopback"
    assert login.server_records == 1
    call = report.call
    assert call.outcome.status is StepStatus.OK
    assert call.transport_caps == 3
    assert call.transport == "kcp"
    assert call.client_flag == 0  # kcp_type 1 for this SDK
    assert call.request_id_present is True
    assert call.turn_present is True
    assert call.turn_keys == ("turn_addr", "turn_password", "turn_port", "turn_user")
    assert call.answer_keys == (
        "call_type",
        "eufy_p2p_type",
        "port",
        "request_id",
        "sdp_info",
        "transport_caps",
        "turn",
    )
    assert call.answer_values["transport_caps"] == 3
    assert (call.transport_caps, call.transport_caps_source) == (3, "json")
    assert call.answer_values["call_type"] == "scall"
    assert call.answer_values["request_id"] == "<request_id:17>"
    assert call.answer_values["sdp_info"].startswith("<sdp_info:")
    sdp = call.device_sdp
    assert sdp is not None
    assert (sdp.length, sdp.flag_byte, sdp.ufrag_len, sdp.pwd_len) == (86, 1, 5, 23)
    assert (sdp.key_len, sdp.iv_len) == (16, 12)
    assert (sdp.audio_ssrc_present, sdp.video_ssrc_present) == (True, True)
    assert report.ice.outcome.status is StepStatus.OK
    assert report.ice.local_types == {"host": 1}
    assert report.ice.remote_types == {"host": 1}
    assert report.ice.selected == ("host", "host")
    channel = report.data_channel
    assert channel.outcome.status is StepStatus.OK
    assert channel.kcp_type == 2  # the device's answer says prefixed
    assert [p.kind for p in report.probes.kinds] == [1, 3, 4]
    assert all(p.outcome.status is StepStatus.OK for p in report.probes.kinds)
    assert all(p.codes == (100, 200) for p in report.probes.kinds)
    assert report.probes.login.status is StepStatus.OK


async def test_the_report_carries_no_synthetic_identifier(fake: FakeRtcServer, run: Any) -> None:
    fake.request_id = "synthetic-request"
    fake.turn = TURN | {"turn_user": TURN_USER, "turn_password": TURN_PASSWORD}
    fake.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0473, b"payload-bytes", bytes(6)))]
    report = await run(probe_kinds=True)
    text = json.dumps(report.as_dict())
    leaked = [v for v in secret_values() if v and v in text]
    assert leaked == []
    assert b"payload-bytes".hex() not in text
    secrets = json.dumps(report.secrets_dict())
    for value in (NVR_SN, SYNTHETIC.did, LICENSE, CONTACT, "127.0.0.1", TURN_PASSWORD):
        assert value in secrets
    assert b"payload-bytes".hex() in secrets


async def test_a_run_sends_only_the_allowed_messages(fake: FakeRtcServer, run: Any) -> None:
    fake.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0473, b"x", bytes(6)))]
    await run(probe_kinds=False)
    allowed = {
        MessageType.DISCOVER,
        MessageType.LOGIN,
        MessageType.MESSAGE,
        MessageType.CALL,
        MessageType.ACK,
        MessageType.INFO,
        MessageType.HANGUP,
    }
    assert set(fake.kinds()) <= allowed
    assert fake.call_kinds() == [CallKind.PRIV1]
    assert fake.device_channels  # the data channel was up
    assert fake.device_received == []  # nothing was sent on it


async def test_the_fake_records_what_its_data_channel_receives(fake: FakeRtcServer) -> None:
    """The control for the no-write check: a message the client sends is recorded."""
    session = RtcSession(
        rtc_config(),
        ice_factory=fake.ice_factory,
        signaling_port=fake.port,
        tcp_ports=(fake.tcp_port,),
    )
    try:
        await session.start()
        assert session.data_channel is not None
        await session.data_channel.send_message(b"sent")
        async with asyncio.timeout(3):
            while not fake.device_received:
                await asyncio.sleep(0.01)
        assert [m.payload for m in fake.device_received] == [b"sent"]
    finally:
        await session.close()


async def test_probe_kinds_add_only_calls_of_kinds_1_3_4(fake: FakeRtcServer, run: Any) -> None:
    await run(probe_kinds=True)
    assert fake.call_kinds() == [CallKind.PRIV1, 1, 3, 4]
    assert fake.device_received == []


async def test_unasked_frames_are_recorded_without_their_payload(
    fake: FakeRtcServer, run: Any
) -> None:
    subheader = bytes([9, 0, 3, 12, 0, 1])
    fake.unasked = [
        (DataMsgType.HEARTBEAT, encode_frame(0x0473, b"", bytes(6))),
        (DataMsgType.NOTIFY, encode_frame(0x0514, b"\x01" * 40, subheader)),
        (DataMsgType.COMMAND, b"not an xzyh frame"),
    ]
    report = await run()
    channel = report.data_channel
    assert channel.heartbeats == 1
    assert channel.messages == 3
    assert channel.header_lens == (LINK_HEADER_LEN,)
    frames = [(f.link_type, f.xzyh_type, f.length, f.subheader, f.channel) for f in channel.frames]
    assert frames == [
        (DataMsgType.NOTIFY, 0x0514, 40, subheader.hex(), 3),
        (DataMsgType.COMMAND, None, 17, None, None),
    ]


async def test_the_older_link_header_is_recorded(fake: FakeRtcServer, run: Any) -> None:
    fake.device_old_header = True
    fake.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0514, b"x", bytes(6)))]
    report = await run()
    assert report.data_channel.header_lens == (LINK_HEADER_LEN_OLD,)


async def test_frames_beyond_the_cap_are_counted(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "MAX_FRAMES", 2)
    fake.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0514, b"x", bytes(6)))] * 3
    report = await run()
    assert len(report.data_channel.frames) == 2
    assert report.data_channel.frames_dropped == 1
    assert report.data_channel.messages == 3


async def test_a_busy_call_fails_step_three_and_skips_ice_and_the_channel(
    fake: FakeRtcServer, run: Any
) -> None:
    fake.call_reply = "busy"
    report = await run(probe_kinds=True)
    assert report.login.login.status is StepStatus.OK
    assert report.call.outcome.status is StepStatus.FAILED
    assert (report.call.outcome.error, report.call.outcome.code) == ("CallRefusedError", 486)
    assert report.ice.outcome.status is StepStatus.SKIPPED
    assert report.ice.outcome.reason == "call failed"
    assert report.data_channel.outcome.status is StepStatus.SKIPPED
    # The probes still run: they need only a login.
    assert report.probes.login.status is StepStatus.OK
    assert [p.codes for p in report.probes.kinds] == [(486,)] * 3


async def test_a_refused_login_fails_step_two_and_skips_the_rest(
    fake: FakeRtcServer, run: Any
) -> None:
    fake.refuse_login = True
    report = await run(probe_kinds=True)
    assert report.login.discover.status is StepStatus.OK
    assert report.login.login.status is StepStatus.FAILED
    assert report.login.login.error == "SignalingError"
    assert report.call.outcome.status is StepStatus.SKIPPED
    assert report.call.outcome.reason == "login failed"
    assert report.probes.login.status is StepStatus.SKIPPED


async def test_per_kind_replies_are_recorded(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "PROBE_TIMEOUT", 0.3)
    monkeypatch.setattr(client_mod, "CALL_REPLY_TIMEOUT", 0.05)
    fake.kind_replies = {1: "busy", 3: "silent", 4: "hangup"}
    async with asyncio.timeout(3):
        report = await run(probe_kinds=True)
    assert all(r.via == "udp" for r in fake.received)  # no TCP wake re-send
    probes = {p.kind: p for p in report.probes.kinds}
    assert probes[1].codes == (486,)
    assert probes[3].outcome.status is StepStatus.TIMEOUT
    assert probes[3].codes == ()
    assert probes[4].codes == (100,)
    assert probes[4].hung_up is True


async def test_an_unreadable_answer_fails_step_three_with_its_keys_recorded(
    fake: FakeRtcServer, run: Any
) -> None:
    fake.answer_extra = {"sdp_info": "AAAA"}
    report = await run()
    assert report.call.outcome.status is StepStatus.FAILED
    assert report.call.outcome.error == "ProtocolError"
    assert "sdp_info" in report.call.answer_keys
    assert report.call.device_sdp is None
    assert report.ice.outcome.status is StepStatus.SKIPPED


async def test_a_probe_cut_by_the_run_bound_is_a_timeout_and_the_rest_skipped(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "station_budget", lambda seconds, probes: 1.0)
    monkeypatch.setattr(diag, "PROBE_TIMEOUT", 5.0)
    fake.kind_replies = {1: "silent"}
    report = await run(seconds=0.2, probe_kinds=True)
    statuses = [(p.kind, p.outcome.status, p.outcome.reason) for p in report.probes.kinds]
    assert statuses == [
        (1, StepStatus.TIMEOUT, None),
        (3, StepStatus.SKIPPED, "run timed out"),
        (4, StepStatus.SKIPPED, "run timed out"),
    ]
    assert report.data_channel.outcome.status is StepStatus.OK


async def test_the_run_bound_during_the_probe_login_is_a_probe_timeout(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "station_budget", lambda seconds, probes: 1.5)

    async def drop_later_logins() -> None:
        while not fake.device_channels:
            await asyncio.sleep(0.01)
        fake.drop_logins = 1000

    task = asyncio.create_task(drop_later_logins())
    report = await run(seconds=0.2, probe_kinds=True)
    await task
    assert report.data_channel.outcome.status is StepStatus.OK
    assert report.probes.login.status is StepStatus.TIMEOUT
    assert [(p.kind, p.outcome.status, p.outcome.reason) for p in report.probes.kinds] == [
        (k, StepStatus.SKIPPED, "run timed out") for k in (1, 3, 4)
    ]


async def test_ice_that_never_connects_is_a_step_four_failure(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "ICE_TIMEOUT", 0.2)
    fake.ice_connects = False
    report = await run()
    assert report.call.outcome.status is StepStatus.OK
    assert report.ice.outcome.status is StepStatus.FAILED
    assert report.ice.outcome.error == "DeviceTimeoutError"
    assert report.ice.local_types == {"host": 1}
    assert report.data_channel.outcome.status is StepStatus.SKIPPED


async def test_the_first_start_bound_is_a_step_result(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "START_TIMEOUT", 0.3)
    fake.call_reply = "silent"
    report = await run()
    assert report.call.outcome.status is StepStatus.FAILED
    assert report.call.outcome.error == "DeviceTimeoutError"
    assert report.ice.outcome.status is StepStatus.SKIPPED


async def test_the_whole_run_is_bounded(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "station_budget", lambda seconds, probes: 0.4)
    fake.call_reply = "silent"
    loop = asyncio.get_running_loop()
    began = loop.time()
    report = await run()
    assert loop.time() - began < 2.0
    assert report.call.outcome.status is StepStatus.TIMEOUT
    assert report.ice.outcome.status is StepStatus.SKIPPED


def all_outcomes(report: RtcStationReport) -> list[diag.StepOutcome]:
    login, probes = report.login, report.probes
    found = [report.inputs.outcome, login.discover, login.login, report.call.outcome]
    found += [report.ice.outcome, report.data_channel.outcome, probes.login]
    return found + [p.outcome for p in probes.kinds]


async def test_a_loss_during_the_probes_never_reconnects(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "PROBE_TIMEOUT", 2.0)
    fake.kind_replies = {1: "silent"}

    async def break_during_probe() -> None:
        while 1 not in fake.call_kinds():
            await asyncio.sleep(0.01)
        await fake.break_link()
        await asyncio.sleep(2.0)  # past the session's reconnect wait

    task = asyncio.create_task(break_during_probe())
    report = await run(seconds=0.2, probe_kinds=True)
    await task
    assert fake.call_kinds() == [CallKind.PRIV1, 1, 3, 4]
    assert report.login.server_records == 1
    assert report.data_channel.outcome.status is StepStatus.OK
    assert all(o.seconds is None or o.seconds >= 0 for o in all_outcomes(report))


def test_steps_reported_after_the_first_link_are_ignored() -> None:
    loop = asyncio.new_event_loop()
    try:
        clock = iter([1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        loop.time = lambda: next(clock)  # type: ignore[method-assign]
        state = diag._Run(rtc_config(), loop, {})
        state.on_step(ConnectStep.DISCOVER, None)  # 1.0
        state.on_step(ConnectStep.LOGIN, None)  # 2.0: discover ends
        state.on_step(ConnectStep.CALL, None)  # 3.0: login ends
        state.on_step(ConnectStep.LOGIN, None)  # a reconnect's login: ignored
        assert state.outcome("login") == diag.StepOutcome(StepStatus.OK, 1.0)
        assert state.current == "call"
    finally:
        loop.close()


async def test_the_watch_is_capped(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diag, "MAX_WATCH", 0.2)
    async with asyncio.timeout(3):
        report = await run(seconds=100.0)
    assert report.data_channel.watched < 1.0


@pytest.mark.parametrize(
    ("key", "value", "kept"),
    [
        ("srflx", "8.8.8.8:4000", "public"),
        ("addr", "10.0.0.2", "private"),
        ("transport_caps", True, "<transport_caps:4>"),
        ("call_type", "x" * 33, "<call_type:33>"),
        ("call_type", "a b", "<call_type:3>"),
        ("port", 5062, 5062),
        ("ftv", 20, 20),
        ("token", "abc", "<token:3>"),
    ],
)
def test_answer_values_keep_only_allowed_short_values(
    key: str, value: object, kept: object
) -> None:
    assert diag._answer_value(key, value) == kept


def test_answer_key_names_are_bounded() -> None:
    names = diag._key_names({f"{'k' * 50}{i:03d}": i for i in range(100)})
    assert len(names) == diag.MAX_ANSWER_KEYS
    assert set(names) == {"<key:53>"}
    longest = "k" * diag.MAX_KEY_LEN
    assert diag._key_names({longest: 1, longest + "k": 1}) == (f"<key:{len(longest) + 1}>", longest)


def test_the_budget_covers_the_session_bound_the_watch_and_the_probes() -> None:
    assert diag.station_budget(60, probes=False) > session_mod.START_TIMEOUT + 60
    assert diag.station_budget(60, probes=True) > (
        session_mod.START_TIMEOUT + 60 + len(diag.PROBE_KINDS) * diag.PROBE_TIMEOUT
    )


async def test_a_lost_link_ends_the_watch_without_a_second_connect(
    fake: FakeRtcServer, run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A slow first probe keeps the run going past the session's reconnect wait.
    monkeypatch.setattr(diag, "PROBE_TIMEOUT", 2.0)
    fake.kind_replies = {1: "silent"}

    async def hang_up_soon() -> None:
        while not fake.device_channels:
            await asyncio.sleep(0.01)
        fake.hang_up()

    task = asyncio.create_task(hang_up_soon())
    report = await run(seconds=5.0, probe_kinds=True)
    await task
    channel = report.data_channel
    assert channel.outcome.status is StepStatus.FAILED
    assert channel.ended == "SignalingError"
    assert channel.watched < 0.9  # noticed before the session's 1 s loss wait ends
    assert fake.call_kinds() == [CallKind.PRIV1, 1, 3, 4]  # no reconnect


OWN = ("RtcSession.", "SignalingClient.", "KcpDataChannel.", "IceTransport.", "_close")


def own_tasks(fake: FakeRtcServer) -> list[asyncio.Task[Any]]:
    """Unfinished tasks of the client's code (the fake station's channels excluded)."""
    left = []
    for task in asyncio.all_tasks():
        coro: Any = task.get_coro()
        frame = getattr(coro, "cr_frame", None)
        owner = frame.f_locals.get("self") if frame is not None else None
        if any(owner is channel for channel in fake.device_channels):
            continue
        name = getattr(coro, "__qualname__", "")
        if not task.done() and (name.startswith(OWN) or "_close" in name):
            left.append(task)
    return left


@pytest.mark.parametrize("phase", ["call", "watch", "probe"])
@pytest.mark.parametrize("cancels", [1, 2])
async def test_a_cancelled_run_raises_and_leaves_nothing(
    fake: FakeRtcServer,
    run: Any,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    cancels: int,
) -> None:
    monkeypatch.setattr(diag, "PROBE_TIMEOUT", 5.0)
    if phase == "call":
        fake.call_reply = "silent"
    fake.kind_replies = {1: "silent"}
    reached: Callable[[], bool] = {
        "call": lambda: fake.call_kinds() == [CallKind.PRIV1],
        "watch": lambda: bool(fake.device_channels),
        "probe": lambda: fake.call_kinds() == [CallKind.PRIV1, 1],
    }[phase]
    task = asyncio.create_task(run(seconds=0.3 if phase == "probe" else 5.0, probe_kinds=True))
    async with asyncio.timeout(5):
        while not reached():
            await asyncio.sleep(0.01)
    for _ in range(cancels):
        task.cancel()
        await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        async with asyncio.timeout(5):
            await task
    assert own_tasks(fake) == []


async def test_missing_inputs_skip_every_network_step(fake: FakeRtcServer, run: Any) -> None:
    report = await run(station_entry(p2p_did=""), probe_kinds=True)
    assert report.inputs.outcome.status is StepStatus.FAILED
    for outcome in (report.login.login, report.call.outcome, report.probes.login):
        assert outcome.status is StepStatus.SKIPPED
        assert outcome.reason == "inputs failed"
    assert fake.received == []


async def test_without_the_extra_the_run_raises_before_any_socket(
    fake: FakeRtcServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing() -> None:
        raise MissingDependencyError("the WebRTC transport", extra="rtc")

    monkeypatch.setattr(diag, "require_aioice", missing)
    found = devices(station_entry())
    with pytest.raises(MissingDependencyError):
        await async_diagnose_station(
            found[0], found, user_id=SYNTHETIC.account_id, app_id=APP_ID, seconds=0.1
        )
    assert fake.received == []


#: ``PbMessageSdpUnit`` {1: 1, 3: {16: 3}}: tag 0x08 (field 1 varint), tag 0x1a (field 3
#: bytes) of 3 bytes: tag 0x80 0x01 (field 16 varint), value 3.
PBSDP_CAPS_3 = base64.b64encode(bytes([0x08, 0x01, 0x1A, 0x03, 0x80, 0x01, 0x03])).decode()


@pytest.mark.parametrize(
    ("pbsdp", "json_caps", "caps", "source", "decoded", "fields"),
    [
        (PBSDP_CAPS_3, 1, 3, "pbsdp", True, (1, 3)),  # pbsdp wins over the JSON key
        (base64.b64encode(struct.pack("<BB", 0x10, 3)).decode(), 3, 0, "pbsdp", True, (2,)),
        ("not base64!", 3, 0, "pbsdp", False, ()),  # undecodable: 0, never the JSON key
        ("", 1, 1, "json", None, ()),  # empty pbsdp: the JSON key
        (None, 3, 3, "json", None, ()),
        (None, None, None, "none", None, ()),
    ],
)
async def test_transport_caps_come_from_pbsdp_else_the_json_key(  # noqa: PLR0917
    fake: FakeRtcServer,
    run: Any,
    pbsdp: str | None,
    json_caps: int | None,
    caps: int | None,
    source: str,
    decoded: bool | None,
    fields: tuple[int, ...],
) -> None:
    fake.pbsdp = pbsdp
    fake.transport_caps = json_caps
    report = await run()
    call = report.call
    assert (call.transport_caps, call.transport_caps_source) == (caps, source)
    assert (call.pbsdp_decoded, call.pbsdp_fields) == (decoded, fields)
    assert call.transport == "kcp"
    if pbsdp:
        assert call.pbsdp_len == len(pbsdp)
        assert call.answer_values["pbsdp"] == f"<pbsdp:{len(pbsdp)}>"


def test_the_sdp_unit_fields_are_recorded() -> None:
    reading = read_pbsdp(PBSDP_CAPS_3)
    assert reading is not None
    assert reading.sdp_fields == (16,)


def guard_mode_frame(sealed: bool) -> bytes:
    """A PARAM_NOTIFY frame naming param 1224, clear or sealed as a station seals it."""
    body = json.dumps({"params": [{"param_type": "1224", "param_value": "1"}]}).encode()
    if not sealed:
        return encode_frame(0x044F, body, bytes(6))
    iv = bytes(range(12))
    sealed_body = AESGCM(DEVICE_INFO.content_key.encode()[:16]).encrypt(iv, body, b"eufy security")
    payload = sealed_body[-16:] + iv + sealed_body[:-16]  # tag | iv | ciphertext
    return encode_frame(0x044F, payload, bytes([10, 0, 0, 0, 0, 0]))


@pytest.mark.parametrize("sealed", [False, True])
async def test_the_first_frame_naming_the_guard_mode_param_is_timed(
    fake: FakeRtcServer, run: Any, sealed: bool
) -> None:
    other = encode_frame(0x044F, json.dumps({"params": []}).encode(), bytes(6))
    fake.unasked = [(DataMsgType.NOTIFY, other), (DataMsgType.NOTIFY, guard_mode_frame(sealed))]
    report = await run()
    channel = report.data_channel
    assert channel.guard_mode_at is not None
    assert 0 <= channel.guard_mode_at < 0.3
    assert (channel.sealed_opened, channel.sealed_unread) == ((1, 0) if sealed else (0, 0))
    assert "1224" not in json.dumps(report.as_dict()["data_channel"]["frames"])


async def test_a_sealed_frame_that_does_not_open_is_counted(fake: FakeRtcServer, run: Any) -> None:
    junk = encode_frame(0x044F, bytes(40), bytes([10, 0, 0, 0, 0, 0]))
    fake.unasked = [(DataMsgType.NOTIFY, junk)]
    report = await run()
    channel = report.data_channel
    assert (channel.sealed_opened, channel.sealed_unread, channel.guard_mode_at) == (0, 1, None)


async def test_without_a_guard_mode_frame_none_is_timed(fake: FakeRtcServer, run: Any) -> None:
    fake.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0514, b"x", bytes(6)))]
    report = await run()
    assert report.data_channel.guard_mode_at is None


@pytest.mark.parametrize(
    ("key", "kept"),
    [
        ("transport_caps", True),
        ("eufy_p2p_type", True),  # a known answer key keeps its digit
        ("p2p_did", False),
        ("T8N00ABCDEF12345", False),
        ("deadbeef01", False),
    ],
)
def test_only_plain_key_names_are_kept(key: str, kept: bool) -> None:
    names = diag._key_names({key: 1})
    assert names == ((key,) if kept else (f"<key:{len(key)}>",))


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("port", "SyntheticWifiNet", "<port:16>"),
        ("transport_caps", "3", "<transport_caps:1>"),
        ("ftv", "20", "<ftv:2>"),
        ("call_type", 5, "<call_type:1>"),
    ],
)
def test_numbers_and_type_names_are_kept_only_in_their_own_type(
    key: str, value: object, expected: str
) -> None:
    assert diag._answer_value(key, value) == expected


async def test_an_answer_key_that_is_no_plain_name_is_not_kept(
    fake: FakeRtcServer, run: Any
) -> None:
    fake.answer_extra = {"T8N00ABCDEF12345": "x", "port": "SyntheticWifiNet"}
    report = await run()
    text = json.dumps(report.as_dict())
    assert "T8N00ABCDEF12345" not in text
    assert "SyntheticWifiNet" not in text
    assert "<key:16>" in report.call.answer_keys


class _BrokenIce:
    """An ICE agent whose connect fails with an error that is no library error."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        raise RuntimeError("an ICE library failure naming 192.0.2.10")


async def test_an_error_of_another_library_is_the_steps_failure(
    fake: FakeRtcServer, run: Any
) -> None:
    report = await run(ice_factory=lambda: _BrokenIce(fake.ice_factory()), probe_kinds=True)
    assert report.ice.outcome.status is StepStatus.FAILED
    assert report.ice.outcome.error == "RuntimeError"
    assert "192.0.2.10" not in json.dumps(report.as_dict())
    assert "192.0.2.10" in json.dumps(report.secrets_dict())
    assert report.probes.login.status is StepStatus.OK  # the next steps still run
