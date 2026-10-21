"""``rtc/diagnostics.py``: the read-only collector and its redacted report.

The collector runs against the fake signaling server, a device-side KCP channel over an
in-memory ICE pipe and a fake media plane; the report is checked to carry only
descriptors (no key, serial, address or payload bytes).
"""

from __future__ import annotations

import asyncio
import json
import struct
from collections.abc import AsyncIterator, Callable
from typing import Any

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.p2p.xzyh import HEADER_LEN, encode_frame
from eufy_home_security.rtc.command import decrypt_command_reply, encrypt_command
from eufy_home_security.rtc.config import KCP_TYPE_MULTI, KCP_TYPE_SINGLE
from eufy_home_security.rtc.data_channel import DataMsgType, KcpDataChannel
from eufy_home_security.rtc.diagnostics import (
    AuthReport,
    ChildRecord,
    DiagnosticsReport,
    StationRecord,
    StationReport,
    collect_station,
    describe_children,
    describe_message,
    describe_station,
    first_camera_channel,
    render,
)
from eufy_home_security.rtc.media import AccessUnit, TurnServer
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.rtc.session import RtcSession
from eufy_home_security.rtc.signaling import SignalingClient
from eufy_home_security.testing import SYNTHETIC

from .fakes import DEVICE_INFO, FakeCrypto, config, start_server

ACCOUNT = "u" * 40
KEY = DEVICE_INFO.content_key.encode()[:16]
STATION_SN = "T9000" + SYNTHETIC.station_sn[5:]
CAMERA_SN = "T8160" + SYNTHETIC.camera_sn[5:]
_KEYS = {"device_content_key": KEY, "client_content_key": b"m" * 16}


def _sealed_notification(plain: bytes) -> bytes:
    """A notification as the station sends it: header, then ``tag | iv | ct``."""
    reply = encrypt_command(KEY, encode_frame(0x0546, plain, bytes(6)), 0)
    return reply[:HEADER_LEN] + reply[HEADER_LEN : HEADER_LEN + 28] + reply[HEADER_LEN + 32 :]


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
            },
        ),
        CloudDevice(
            device_sn=CAMERA_SN,
            device_type=19,
            name="Cam 3",
            station_sn=STATION_SN,
            channel=3,
            main_sw_version="2.1.0.0",
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
    )
    assert SYNTHETIC.did not in str(record)
    assert "198.51.100.1" not in str(record)


def test_describe_station_derives_the_old_firmware_modes() -> None:
    old = _devices()[0]
    old = CloudDevice(
        device_sn=old.device_sn,
        device_type=old.device_type,
        name=old.name,
        main_sw_version="4.0.9.9",
        raw={**old.raw, "webrtc_sdk_version": "7.1.1"},
    )
    record = describe_station(old)
    assert record.kcp_type == KCP_TYPE_SINGLE
    assert record.commands_encrypted is False


def test_children_are_listed_by_channel_and_the_lowest_is_the_default_camera() -> None:
    children = describe_children(STATION_SN, _devices())
    assert children == [
        ChildRecord("T8410", 1, None, has_signaling=True),
        ChildRecord("T8160", 3, "2.1.0.0", has_signaling=False),
    ]
    assert first_camera_channel(children) == children[0]
    assert first_camera_channel([]) is None


# ── message description ──────────────────────────────────────────────────────


def test_a_sealed_reply_is_opened_and_described_by_names_and_whitelisted_ints() -> None:
    body = json.dumps(
        {
            "code": 0,
            "payload": {"mode_type": 1, "device_sn": STATION_SN, "port": 5000},
            STATION_SN: 7,
        }
    ).encode()
    packet = encrypt_command(KEY, encode_frame(0x0546, body, bytes(6)), 5)
    report = describe_message(packet, DataMsgType.COMMAND, _KEYS, phase="p", at_ms=3)
    assert report.sealed
    assert report.opened
    assert (report.key, report.wrapper, report.counter) == ("device_content_key", "reply", 5)
    assert report.header_hex == packet[:HEADER_LEN].hex()
    assert report.json_keys == ["code", "payload", "payload.mode_type", "payload.device_sn",
                                "payload.port", "?"]  # fmt: skip
    assert report.json_ints == {"code": [0], "payload.mode_type": [1]}
    assert STATION_SN not in str(report)


def test_a_notification_opens_with_its_own_wrapper() -> None:
    packet = _sealed_notification(b'{"cmd":1224,"mode":2}\x00')
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


def test_a_payload_that_is_not_xzyh_is_described_by_length_only() -> None:
    report = describe_message(b"\x01\x02\x03", 2, _KEYS, phase="p", at_ms=0)
    assert (report.header_hex, report.opened, report.length) == (None, False, 3)


# ── the collector ────────────────────────────────────────────────────────────


class _FakeIce:
    """In-memory ICE transport with a safe diagnostics() accessor (type counts only)."""

    def __init__(self, *, send_q: asyncio.Queue[bytes], recv_q: asyncio.Queue[bytes]) -> None:
        self._send_q = send_q
        self._recv_q = recv_q
        self.closed = False

    def diagnostics(self) -> dict[str, object]:
        return {
            "gathered": True,
            "controlling": False,
            "local_candidate_types": {"host": 1},
            "remote_candidate_types": {"host": 1, "srflx": 1},
        }

    async def gather(self, *, local_ufrag: str, local_pwd: str, turn: Any) -> list[str]:
        return ["candidate:1 1 udp 1 192.0.2.7 5 typ host"]

    def add_remote_candidate(self, candidate: str) -> None:
        return None

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        return None

    async def recv(self) -> bytes:
        return await self._recv_q.get()

    async def send(self, data: bytes) -> None:
        self._send_q.put_nowait(data)

    async def close(self) -> None:
        self.closed = True


class _Media:
    """A media plane whose video starts once the station got a live open on the data
    channel (``video_on_data``) or on RTCP."""

    instance: _Media | None = None
    video_on_data = True

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.commands: list[bytes] = []
        _Media.instance = self

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        return None

    def add_remote_candidate(self, candidate: str) -> None:
        return None

    async def frames(self) -> AsyncIterator[AccessUnit]:
        yield AccessUnit(b"", 0, False)

    async def send_command(self, data: bytes) -> None:
        self.commands.append(data)
        self.started.set()

    async def recv_command(self) -> bytes:
        await asyncio.Event().wait()
        return b""

    async def wait_media(self) -> None:
        await self.started.wait()

    def stats(self) -> dict[str, object]:
        return {"frames": 5, "rtp_by_payload_type": {97: 40}}

    async def close(self) -> None:
        return None


#: The JSON of every query the fake station received.
QUERIES: list[dict[str, Any]] = []


async def _device(device: KcpDataChannel) -> None:
    """The station: echo the heartbeat (and send one of its own), answer each 1350 query
    with a sealed reply and a notification, and start video on a live open over the data
    channel."""
    while True:
        msg = await device.recv_message()
        if len(msg.payload) <= HEADER_LEN:
            await device.send_message(encode_frame(0x0473, b"", bytes(6)))
            await device.send_message(bytes(16), msg_type=DataMsgType.HEARTBEAT)
            continue
        plain = decrypt_command_reply(KEY, msg.payload[HEADER_LEN:])
        if b'"cmd":1003' in plain:
            if _Media.video_on_data and _Media.instance is not None:
                _Media.instance.started.set()
            continue
        QUERIES.append(json.loads(plain))
        reply = encode_frame(0x0546, b'{"code":0,"payload":{"num":2}}', bytes(6))
        await device.send_message(encrypt_command(KEY, reply, 0))
        await device.send_message(_sealed_notification(b'{"cmd":1224,"mode":1}'), msg_type=3)


async def _run(**kwargs: Any) -> Any:
    c2d: asyncio.Queue[bytes] = asyncio.Queue()
    d2c: asyncio.Queue[bytes] = asyncio.Queue()
    device = KcpDataChannel(_FakeIce(send_q=d2c, recv_q=c2d), conv=1)
    responder = asyncio.ensure_future(_device(device))
    server, port = await start_server(request_id=None, **kwargs.pop("server", {}))
    crypto = FakeCrypto()
    cfg = config(firmware=4200)
    session = RtcSession(
        cfg, crypto, signaling=SignalingClient(cfg, crypto, port=port), media_factory=_Media
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
            listen_s=0.05,
            ice=_FakeIce(send_q=c2d, recv_q=d2c),
            **kwargs,
        )
    finally:
        responder.cancel()
        await device.close()
        await session.close()
        server.close()


async def test_collect_station_runs_every_phase_and_describes_the_replies() -> None:
    watched: list[float] = []
    _Media.video_on_data = True
    QUERIES.clear()
    report = await _run(watch_s=0.05, on_watch=watched.append)
    # Station queries go to the station channel 255 and carry the owner's id.
    assert [(q["cmd"], q["mChannel"], q["account_id"]) for q in QUERIES] == [
        (1307, 255, ACCOUNT),
        (9100, 255, ACCOUNT),
    ]
    assert report.heartbeats >= 1
    assert DataMsgType.HEARTBEAT not in {m.msg_type for m in report.messages}
    assert report.error is None
    assert report.phase_reached == "done"
    assert report.call is not None
    assert report.call.content_key_len == 16
    assert report.ice is not None
    assert report.ice.remote_candidate_types == {"host": 1, "srflx": 1}
    assert report.heartbeat_ms is not None
    assert [c.name for c in report.commands] == ["storage_1307", "bind_list_9100"]
    for cmd in report.commands:
        reply = report.messages[cmd.reply_index]
        assert reply.phase == cmd.name
        assert (reply.opened, reply.key, reply.json_ints) == (
            True,
            "device_content_key",
            {"code": [0], "payload.num": [2]},
        )
    notes = [m for m in report.messages if m.msg_type == DataMsgType.NOTIFY]
    assert notes
    assert all(n.wrapper == "notification" for n in notes)
    assert watched == [0.05]
    assert report.live is not None
    assert report.live.channel == 3
    assert report.live.camera_model == "T8160"
    assert [a.route for a in report.live.attempts] == ["data_channel"]
    assert report.live.attempts[0].first_frame_ms is not None
    assert report.live.media == {"frames": 5, "rtp_by_payload_type": {97: 40}}
    text = DiagnosticsReport("0", "t", AuthReport(True, "eu", 3, 1), [report]).to_json()
    for secret in (DEVICE_INFO.content_key, STATION_SN, SYNTHETIC.did, ACCOUNT, "198.51.100"):
        assert secret not in text
    assert "T9000" in render(DiagnosticsReport("0", "t", AuthReport(True, "eu", 3, 1), [report]))


async def test_live_falls_back_to_rtcp_when_the_data_channel_open_brings_no_video(
    monkeypatch: Any,
) -> None:
    from eufy_home_security.rtc import diagnostics  # noqa: PLC0415

    monkeypatch.setattr(diagnostics, "_LIVE_OPEN_WAIT", 0.2)
    _Media.video_on_data = False
    report = await _run(do_commands=False)
    assert report.live is not None
    assert [(a.route, a.first_frame_ms is None) for a in report.live.attempts] == [
        ("data_channel", True),
        ("rtcp", False),
    ]
    assert _Media.instance is not None
    assert len(_Media.instance.commands) == 1


async def test_a_refused_login_ends_the_station_in_the_signaling_phase() -> None:
    report = await _run(server={"refuse_login": True})
    assert report.phase_reached == "signaling"
    assert report.error is not None
    assert report.error.startswith("signaling: ")
    assert report.call is None
    assert report.messages == []


def test_report_json_carries_only_descriptors() -> None:
    record = describe_station(_devices()[0])
    report = DiagnosticsReport(
        library_version="0.0.0",
        created_utc="2000-01-01T00:00:00Z",
        auth=AuthReport(logged_in=True, region="eu", device_count=2, webrtc_only_count=1),
        stations=[StationReport(station=record, children=[], channel=0, phase_reached="config")],
    )
    parsed = json.loads(report.to_json())
    assert parsed["stations"][0]["station"]["model"] == "T9000"
    assert "content_key" not in report.to_json().replace("content_key_len", "")
