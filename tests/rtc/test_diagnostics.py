"""``rtc/diagnostics.py``: the collector and its redacted report.

The collector runs against the fake signaling server, a device-side KCP channel over an
in-memory ICE pipe and a fake media plane; the report is checked to carry only
descriptors (no key, serial, address or payload bytes).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import struct
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import EventSource, SecurityEvent
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.xzyh import HEADER_LEN, encode_frame
from eufy_home_security.rtc import diagnostics
from eufy_home_security.rtc.command import encrypt_command
from eufy_home_security.rtc.config import KCP_TYPE_MULTI, KCP_TYPE_SINGLE
from eufy_home_security.rtc.data_channel import DataMsgType
from eufy_home_security.rtc.diagnostics import (
    ChildRecord,
    StationRecord,
    StationReport,
    collect_station,
    describe_children,
    describe_event,
    describe_message,
    describe_station,
    render_station,
    rewritable_guard_mode,
)
from eufy_home_security.rtc.session import RtcSession
from eufy_home_security.rtc.signaling import SignalingClient
from eufy_home_security.testing import SYNTHETIC

from .fakes import (
    DEVICE_INFO,
    QUERIES,
    STATION_KEY,
    FakeCrypto,
    PipeIce,
    StationMedia,
    config,
    sealed_notification,
    start_server,
    station_ice,
)

ACCOUNT = "u" * 40
STATION_SN = "T9000" + SYNTHETIC.station_sn[5:]
CAMERA_SN = "T8160" + SYNTHETIC.camera_sn[5:]
_KEYS = {"device_content_key": STATION_KEY, "client_content_key": b"m" * 16}


# ── cloud records ────────────────────────────────────────────────────────────


def _devices() -> list[CloudDevice]:
    return [
        CloudDevice(
            device_sn=STATION_SN,
            device_type=91,
            name="Base",
            p2p_did=SYNTHETIC.did,
            main_sw_version="4.2.0.0",
            member_type=1,
            raw={
                "p2p_did": SYNTHETIC.did,
                "p2p_license": "ABCDEF",
                "signaling_servers": ["https://198.51.100.1", "https://sig.example.com/x"],
                "webrtc_sdk_version": "7.1.2",
                "webrtc_online_status": 1,
                "params": [
                    {"param_type": 1224, "param_value": "1"},
                    {"param_type": 1176, "param_value": SYNTHETIC.station_sn},
                ],
                SYNTHETIC.station_sn: 1,
            },
        ),
        CloudDevice(
            device_sn=CAMERA_SN,
            device_type=19,
            name="Cam 3",
            station_sn=STATION_SN,
            channel=3,
            main_sw_version="2.1.0.0",
            raw={"params": [{"param_type": 1131, "param_value": 0}]},
        ),
        CloudDevice(
            device_sn="T8410" + SYNTHETIC.camera_sn[5:],
            device_type=104,
            name="Cam 1",
            station_sn=STATION_SN,
            channel=1,
            raw={"signaling_servers": ["https://198.51.100.1"], "p2p_license": "X"},
        ),
    ]


def test_describe_station_keeps_versions_and_presence_and_derives_the_modes() -> None:
    record = describe_station(_devices()[0])
    assert record == StationRecord(
        model="T9000",
        is_webrtc_only=True,
        main_sw_version="4.2.0.0",
        webrtc_sdk_version="7.1.2",
        member_type=1,
        has_p2p_did=True,
        has_p2p_license=True,
        has_app_conn=False,
        signaling_servers=2,
        signaling_ipv4=True,
        signaling_domain=True,
        webrtc_online_status=1,
        kcp_type=KCP_TYPE_MULTI,
        commands_encrypted=True,
        product_code="T9000",
        guard_mode=1,
        cloud_param_types=[1176, 1224],
        record_keys=[
            "?",
            "p2p_did",
            "p2p_license",
            "params",
            "signaling_servers",
            "webrtc_online_status",
            "webrtc_sdk_version",
        ],
    )
    assert SYNTHETIC.did not in str(record)
    assert SYNTHETIC.station_sn not in str(record)
    assert "198.51.100.1" not in str(record)


def test_describe_station_derives_the_old_firmware_modes() -> None:
    old = _devices()[0]
    old = CloudDevice(
        device_sn=old.device_sn,
        device_type=old.device_type,
        name=old.name,
        main_sw_version="4.0.9.9",
        raw={**old.raw, "webrtc_sdk_version": "7.1.1", "params": "none"},
    )
    record = describe_station(old)
    assert record.kcp_type == KCP_TYPE_SINGLE
    assert record.commands_encrypted is False
    assert (record.guard_mode, record.cloud_param_types) == (None, [])


def test_children_are_listed_by_channel_with_power_and_online_state() -> None:
    children = describe_children(STATION_SN, _devices())
    assert children == [
        ChildRecord("T8410", 1, None, has_signaling=True, product_code="T8410", battery=False),
        ChildRecord(
            "T8160",
            3,
            "2.1.0.0",
            has_signaling=False,
            product_code="T8160",
            battery=True,
            online=0,
            cloud_param_types=[1131],
        ),
    ]


HB3_SN = SYNTHETIC.station_sn


def _hb3(*children: tuple[str, int], parent: str = HB3_SN) -> list[CloudDevice]:
    """A station and its children, each ``(model, channel)``."""
    station = CloudDevice(device_sn=parent, device_type=18, name="Home Base", p2p_did=SYNTHETIC.did)
    return [
        station,
        *(
            CloudDevice(
                device_sn=model + SYNTHETIC.camera_sn[5:-1] + str(channel),
                device_type=7,
                name=f"Cam {channel}",
                station_sn=parent,
                channel=channel,
            )
            for model, channel in children
        ),
    ]


def test_a_homebase_3_with_a_camera_the_app_streams_over_webrtc_is_probed() -> None:
    devices = _hb3(("T8160", 0), ("T8224", 2), ("T8223", 6))
    assert diagnostics.webrtc_probe_reason(devices[0], devices, webrtc_all=False) == "webrtc_child"
    assert [d.channel for d in diagnostics.webrtc_children(HB3_SN, devices)] == [2, 6]
    target = diagnostics.live_target(HB3_SN, reversed(devices))
    assert target == diagnostics.LiveTarget(
        channel=2,
        model="T8224",
        product_code="T8224",
        serial="T8224***" + (SYNTHETIC.camera_sn[5:-1] + "2")[-4:],
        chosen_by="webrtc_child",
    )
    assert SYNTHETIC.camera_sn[5:-1] not in str(target)


@pytest.mark.parametrize(
    ("devices", "webrtc_all", "reason"),
    [
        (_hb3(("T8160", 0)), False, None),
        (_hb3(("T8160", 0)), True, "webrtc_all"),
        (_hb3(("T8224", 1)), True, "webrtc_child"),
        ([CloudDevice(device_sn="T2261" + "0" * 11, device_type=0, name="x")], True, None),
        (_hb3(("T8224", 1), parent="T8010" + HB3_SN[5:]), False, None),
        (_devices(), False, "webrtc_only"),
    ],
    ids=[
        "hb3-p2p-children",
        "webrtc-all",
        "child-before-all",
        "no-p2p-identity",
        "hb2-with-c30",
        "webrtc-only",
    ],
)
def test_which_stations_are_probed_over_webrtc(
    devices: list[CloudDevice], webrtc_all: bool, reason: str | None
) -> None:
    assert diagnostics.webrtc_probe_reason(devices[0], devices, webrtc_all=webrtc_all) == reason


def test_the_live_view_takes_the_option_else_the_lowest_paired_channel() -> None:
    devices = _hb3(("T8160", 4), ("T8224", 2))
    chosen = diagnostics.live_target(HB3_SN, devices, camera_channel=4)
    assert chosen is not None
    assert (chosen.channel, chosen.model, chosen.chosen_by) == (4, "T8160", "camera_channel")
    unknown = diagnostics.live_target(HB3_SN, devices, camera_channel=9)
    assert unknown == diagnostics.LiveTarget(9, "?", None, None, "camera_channel")
    lowest = diagnostics.live_target(STATION_SN, _devices())
    assert lowest is not None
    assert (lowest.channel, lowest.model, lowest.chosen_by) == (1, "T8410", "lowest_channel")
    assert diagnostics.live_target(HB3_SN, _hb3()) is None


@pytest.mark.parametrize("raw", [{}, {"device_new_pn": "Z9999"}], ids=["no-code", "no-file"])
def test_a_child_without_a_settings_file_has_an_unknown_power_source(raw: dict[str, Any]) -> None:
    child = CloudDevice(
        device_sn="Z9999" + "0" * 11, device_type=1, name="x", station_sn="S", raw=raw
    )
    assert describe_children("S", [child])[0].battery is None


def test_a_cloud_guard_mode_that_is_not_a_number_is_unknown() -> None:
    station = _devices()[0]
    raw = {**station.raw, "params": [{"param_type": 1224, "param_value": "home"}]}
    record = describe_station(dataclasses.replace(station, raw=raw))
    assert (record.guard_mode, record.cloud_param_types) == (None, [1224])


@pytest.mark.parametrize(
    ("cloud", "expected"),
    [
        (0, GuardMode.AWAY),
        (1, GuardMode.HOME),
        (63, GuardMode.DISARMED),
        (2, None),  # schedule
        (3, None),  # a custom mode
        (47, None),  # geofence
        (99, None),  # not a guard mode
        (None, None),
    ],
)
def test_only_a_plain_cloud_guard_mode_may_be_re_sent(
    cloud: int | None, expected: GuardMode | None
) -> None:
    record = dataclasses.replace(describe_station(_devices()[0]), guard_mode=cloud)
    assert rewritable_guard_mode(record) is expected


# ── message description ──────────────────────────────────────────────────────


def test_a_sealed_reply_is_opened_and_described_by_names_and_whitelisted_ints() -> None:
    body = json.dumps(
        {
            "code": 0,
            "payload": {"mode_type": 1, "device_sn": STATION_SN, "port": 5000, "mode": "2"},
            STATION_SN: 7,
        }
    ).encode()
    packet = encrypt_command(STATION_KEY, encode_frame(0x0546, body, bytes(6)), 5)
    report = describe_message(packet, DataMsgType.COMMAND, _KEYS, phase="p", at_ms=3)
    assert report.sealed
    assert report.opened
    assert (report.key, report.wrapper, report.counter) == ("device_content_key", "reply", 5)
    assert report.header_hex == packet[:HEADER_LEN].hex()
    assert report.json_keys == ["code", "payload", "payload.mode_type", "payload.device_sn",
                                "payload.port", "payload.mode", "?"]  # fmt: skip
    assert report.json_ints == {"code": [0], "payload.mode_type": [1], "payload.mode": [2]}
    assert STATION_SN not in str(report)


def test_a_long_digit_string_in_a_whitelisted_field_is_not_kept() -> None:
    names, ints = diagnostics.describe_json({"code": "12345", "mode": "1234", "value": True})
    assert ints == {"mode": [1234]}
    assert names == ["code", "mode", "value"]


def test_a_notification_opens_with_its_own_wrapper() -> None:
    packet = sealed_notification(b'{"cmd":1224,"mode":2}\x00')
    report = describe_message(packet, DataMsgType.NOTIFY, _KEYS, phase="watch", at_ms=0)
    assert (report.opened, report.wrapper, report.counter) == (True, "notification", None)
    assert report.json_ints == {"cmd": [1224], "mode": [2]}


def test_a_sealed_body_no_key_opens_keeps_only_its_counter() -> None:
    packet = encrypt_command(b"x" * 16, encode_frame(0x0546, b"{}", bytes(6)), 9)
    report = describe_message(packet, DataMsgType.COMMAND, _KEYS, phase="p", at_ms=0)
    assert (report.opened, report.key, report.counter, report.json_keys) == (False, None, 9, [])


def test_a_plaintext_status_reply_reports_its_status() -> None:
    packet = encode_frame(0x0546, struct.pack("<i", -106) + bytes(8), bytes([1, 0, 200, 0, 1, 0]))
    report = describe_message(packet, DataMsgType.COMMAND, _KEYS, phase="p", at_ms=0)
    assert (report.sealed, report.opened, report.status) == (False, True, -106)


def test_a_payload_that_is_not_xzyh_or_json_keeps_only_its_first_bytes() -> None:
    report = describe_message(b"\x01\x02\x03\x04\x05\x06", 2, _KEYS, phase="p", at_ms=0)
    assert (report.header_hex, report.opened, report.length) == (None, False, 6)
    assert (report.head_hex, report.status) == ("01020304", None)
    assert describe_message(b"", 2, _KEYS, phase="p", at_ms=0).head_hex is None


def test_a_plain_json_notification_is_described() -> None:
    payload = b'{"cmd":1224,"payload":{"mode_type":0,"user_name":"Alice"}}\x00'
    report = describe_message(payload, DataMsgType.NOTIFY, _KEYS, phase="watch", at_ms=0)
    assert (report.opened, report.header_hex, report.head_hex) == (True, None, None)
    assert report.json_ints == {"cmd": [1224], "payload.mode_type": [0]}
    assert "Alice" not in str(report)
    broken = describe_message(b"{not json", DataMsgType.NOTIFY, _KEYS, phase="w", at_ms=0)
    assert (broken.opened, broken.status, broken.head_hex) == (False, None, b"{not".hex())


def test_an_event_is_described_without_identifiers_names_or_paths() -> None:
    event = SecurityEvent(
        source=EventSource.CLOUD,
        station_sn=STATION_SN,
        device_sn=CAMERA_SN,
        channel=0,
        device_name="Front door",
        guard_mode=1,
        mode=0,
        thumb_path="/media/x.jpg",
        raw={"type": 3, "user_name": "Alice", "payload": '{"mode": 1, "sn": "T9000"}'},
    )
    report = describe_event(event, 1200)
    assert report.kind == "SecurityEvent"
    assert (report.source, report.station_model, report.device_model) == (
        "cloud",
        "T9000",
        "T8160",
    )
    assert report.ints == {"channel": 0, "guard_mode": 1, "mode": 0}
    assert report.raw_keys == ["type", "user_name", "payload", "payload.mode", "payload.sn"]
    assert report.raw_ints == {"type": [3], "payload.mode": [1]}
    text = str(report)
    for private in (STATION_SN, CAMERA_SN, "Front door", "Alice", "/media"):
        assert private not in text
    bare = describe_event(object(), 0)
    assert (bare.kind, bare.source, bare.ints, bare.raw_keys) == ("object", None, {}, [])


# ── the collector ────────────────────────────────────────────────────────────


async def _run(
    *, ice: Any = None, session_cfg: dict[str, Any] | None = None, **kwargs: Any
) -> StationReport:
    server, port = await start_server(request_id=None, **kwargs.pop("server", {}))
    crypto = FakeCrypto()
    cfg = config(firmware=4200, **(session_cfg or {}))
    session = RtcSession(
        cfg, crypto, signaling=SignalingClient(cfg, crypto, port=port), media_factory=StationMedia
    )
    devices = _devices()
    children = describe_children(STATION_SN, devices)
    try:
        return await collect_station(
            session,
            station=describe_station(devices[0]),
            children=children,
            account_id=ACCOUNT,
            camera=children[1],
            ice=ice if ice is not None else station_ice(),
            **{"listen_s": 0.05, **kwargs},
        )
    finally:
        await session.close()
        server.close()


@pytest.fixture(autouse=True)
def _media_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    QUERIES.clear()
    monkeypatch.setattr(StationMedia, "video_on_data", True)
    monkeypatch.setattr(StationMedia, "packets_only", False)


async def test_collect_station_runs_every_phase_and_describes_the_replies() -> None:
    watched: list[float] = []
    reports: list[StationReport] = []
    report = await _run(watch_s=0.05, on_watch=watched.append, on_report=reports.append)
    assert reports == [report]
    # Station queries go to the station channel 255 and carry the owner's id.
    assert [(q["cmd"], q["mChannel"], q["account_id"]) for q in QUERIES] == [
        (1307, 255, ACCOUNT),
        (9100, 255, ACCOUNT),
    ]
    assert report.heartbeats >= 1
    assert DataMsgType.HEARTBEAT not in {m.msg_type for m in report.messages}
    assert (report.error, report.interrupted, report.phase_reached) == (None, False, "done")
    assert list(report.signaling_ms) == ["open", "discover", "login"]
    assert report.call is not None
    assert report.call.content_key_len == 16
    assert report.call.answer_keys == ["port", "sdp_info", "srflx", "turn"]
    assert report.call.sdp_info_head_hex == DEVICE_INFO.encode()[:6].hex()
    assert report.call.data_channel_flag is False
    assert set(report.call.timings_ms) == {"offer", "gathered", "connect_start", "connected",
                                           "first_recv"}  # fmt: skip
    assert report.ice is not None
    assert report.ice.remote_candidate_types == {"host": 1, "srflx": 1}
    assert report.ice.selected_pair_types == {"local": "host", "remote": "srflx"}
    assert report.ice.turn_configured is True
    assert report.heartbeat_ms is not None
    assert [c.name for c in report.commands] == ["storage_1307", "bind_list_9100"]
    for cmd in report.commands:
        assert cmd.request_keys[:3] == ["account_id", "cmd", "mChannel"]
        reply = report.messages[cmd.reply_index]  # type: ignore[index]
        assert reply.phase == cmd.name
        assert (reply.opened, reply.key, reply.json_ints) == (
            True,
            "device_content_key",
            {"code": [0], "payload.num": [2]},
        )
    notes = [m for m in report.messages if m.msg_type == DataMsgType.NOTIFY]
    assert notes
    assert all(n.wrapper == "notification" for n in notes)
    assert report.message_counts["storage_1307/1"] == 1
    assert report.message_counts["bind_list_9100/3"] == 1
    assert watched == [0.05]
    assert report.live is not None
    assert report.live.channel == 3
    assert report.live.camera_model == "T8160"
    assert [a.route for a in report.live.attempts] == ["data_channel"]
    assert report.live.attempts[0].first_frame_ms is not None
    assert report.live.attempts[0].first_packet_ms is not None
    assert report.live.media == {"frames": 5, "rtp_by_payload_type": {97: 40}}
    text = json.dumps(dataclasses.asdict(report))
    for secret in (
        DEVICE_INFO.content_key,
        DEVICE_INFO.ice_pwd,
        STATION_SN,
        SYNTHETIC.did,
        ACCOUNT,
        "198.51.100",
        "192.0.2.7",
        "203.0.113.5",
    ):
        assert secret not in text
    assert "T9000" in render_station(report)[0]


async def test_the_message_counts_go_on_past_the_listing_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Call:
        def __init__(self, n: int) -> None:
            self.left = n

        async def recv(self) -> Any:
            from eufy_home_security.rtc.data_channel import WrtcLinkMessage  # noqa: PLC0415

            if not self.left:
                await asyncio.Event().wait()
            self.left -= 1
            return WrtcLinkMessage(DataMsgType.FILE_DATA, 0, b"\x00" * 8)

    monkeypatch.setattr(diagnostics, "_MAX_MESSAGES", 2)
    inbox = diagnostics._Inbox(_Call(5), _KEYS)  # type: ignore[arg-type]
    inbox.phase = "live"
    async with asyncio.timeout(2):
        while inbox.counts.get("live/2") != 5:
            await asyncio.sleep(0)
    await inbox.close()
    assert len(inbox.messages) == 2


async def test_an_opted_in_guard_mode_is_re_sent_unchanged_and_its_reply_recorded() -> None:
    report = await _run(rewrite_guard_mode=GuardMode.HOME, do_live=False)
    rewrite = QUERIES[-1]
    assert (rewrite["cmd"], rewrite["mChannel"], rewrite["account_id"]) == (1224, 255, ACCOUNT)
    assert rewrite["payload"] == {"mode_type": 1, "user_name": diagnostics.REWRITE_USER_NAME}
    cmd = report.commands[-1]
    assert cmd.name == "guard_rewrite_1224"
    assert cmd.reply_index is not None
    assert report.messages[cmd.reply_index].phase == "guard_rewrite_1224"
    assert "payload.mode_type" in cmd.request_keys


async def test_no_guard_mode_is_sent_without_the_opt_in() -> None:
    await _run(do_live=False)
    assert 1224 not in {q["cmd"] for q in QUERIES}


async def test_live_falls_back_to_rtcp_when_the_data_channel_open_brings_no_packet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(diagnostics, "_LIVE_OPEN_WAIT", 0.2)
    monkeypatch.setattr(StationMedia, "video_on_data", False)
    report = await _run(do_commands=False)
    assert report.live is not None
    assert [(a.route, a.first_packet_ms is None) for a in report.live.attempts] == [
        ("data_channel", True),
        ("rtcp", False),
    ]
    assert StationMedia.instance is not None
    assert len(StationMedia.instance.commands) == 1


async def test_packets_without_a_decoded_frame_count_as_media_and_are_listened_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(diagnostics, "_LIVE_OPEN_WAIT", 0.2)
    monkeypatch.setattr(StationMedia, "packets_only", True)
    loop = asyncio.get_running_loop()
    begun = loop.time()
    report = await _run(do_commands=False, listen_s=0.5)
    assert report.live is not None
    (attempt,) = report.live.attempts  # no RTCP fallback: packets arrived
    assert attempt.first_packet_ms is not None
    assert attempt.first_frame_ms is None
    assert loop.time() - begun >= 0.5  # the listen window ran


async def test_no_packet_on_either_route_skips_the_listen_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(diagnostics, "_LIVE_OPEN_WAIT", 0.1)
    monkeypatch.setattr(StationMedia, "video_on_data", False)

    async def no_media(self: StationMedia) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(StationMedia, "wait_packets", no_media)
    monkeypatch.setattr(StationMedia, "wait_media", no_media)
    async with asyncio.timeout(10):  # a 60 s listen window would outlast it
        report = await _run(do_commands=False, listen_s=60.0)
    assert report.live is not None
    assert len(report.live.attempts) == 2


async def test_a_media_plane_without_wait_packets_waits_for_the_first_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(StationMedia, "wait_packets")
    report = await _run(do_commands=False)
    assert report.live is not None
    (attempt,) = report.live.attempts
    assert attempt.first_packet_ms == attempt.first_frame_ms is not None


async def test_a_refused_login_ends_the_station_in_the_login_step() -> None:
    report = await _run(server={"refuse_login": True})
    assert report.phase_reached == "signaling.login"
    assert report.error is not None
    assert report.error.startswith("signaling.login: ")
    assert list(report.signaling_ms) == ["open", "discover", "login"]
    assert report.call is None
    assert report.messages == []


async def test_signaling_that_does_not_finish_in_its_budget_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(diagnostics, "SIGNALING_BUDGET", 0.2)
    report = await _run(server={"drop_logins": 9})
    assert report.error == "signaling.login: TimeoutError"


async def test_the_whole_station_run_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics, "STATION_BUDGET", -4.8)
    report = await _run(watch_s=5.0, do_commands=False)
    assert report.error == "watch: TimeoutError"
    assert report.call is not None


class _BrokenIce(PipeIce):
    async def gather(self, *, local_ufrag: str, local_pwd: str, turn: Any) -> list[str]:
        raise OSError("no route")


async def test_any_failure_is_recorded_with_what_ran_before_it() -> None:
    q: asyncio.Queue[bytes] = asyncio.Queue()
    ice = _BrokenIce(send_q=q, recv_q=q)
    report = await _run(ice=ice)
    assert report.error == "call: OSError"
    assert report.call is not None
    assert (report.call.answered, set(report.call.timings_ms)) == (True, {"offer"})
    assert report.ice is not None
    assert report.ice.connected is False
    assert ice.closed


async def test_a_cancelled_run_still_hands_over_its_partial_report() -> None:
    reports: list[StationReport] = []
    entered = asyncio.Event()
    task = asyncio.ensure_future(
        _run(watch_s=30.0, on_watch=lambda _s: entered.set(), on_report=reports.append)
    )
    async with asyncio.timeout(5):
        await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    (report,) = reports
    assert (report.interrupted, report.phase_reached) == (True, "watch")
    assert report.error == "watch: interrupted"
    assert [c.name for c in report.commands] == ["storage_1307", "bind_list_9100"]


def test_a_config_report_serializes_to_json_without_secrets() -> None:
    record = describe_station(_devices()[0])
    report = StationReport(station=record, children=[], channel=0, phase_reached="config")
    text = json.dumps(dataclasses.asdict(report))
    assert json.loads(text)["station"]["model"] == "T9000"
    assert "content_key" not in text
    assert render_station(report)[0].endswith("reached config")
