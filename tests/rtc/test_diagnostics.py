"""``rtc/diagnostics.py``: the read-only data-channel collector and its redacted report.

The collector runs against the fake signaling server and a device-side KCP channel over
an in-memory ICE pipe; the report is checked to carry only descriptors (no key, serial,
address or payload bytes).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from eufy_home_security.p2p.xzyh import HEADER_LEN, encode_frame
from eufy_home_security.rtc.codec import CallKind
from eufy_home_security.rtc.command import encrypt_command
from eufy_home_security.rtc.data_channel import DataMsgType, KcpDataChannel
from eufy_home_security.rtc.diagnostics import (
    AuthReport,
    DiagnosticsReport,
    StationReport,
    collect_station,
    render,
)
from eufy_home_security.rtc.session import RtcSession
from eufy_home_security.rtc.signaling import SignalingClient

from .fakes import DEVICE_INFO, FakeCrypto, config, start_server

ACCOUNT = "u" * 40


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


async def _session() -> tuple[Any, RtcSession]:
    server, port = await start_server(request_id=None)
    crypto = FakeCrypto()
    cfg = config()
    return server, RtcSession(cfg, crypto, signaling=SignalingClient(cfg, crypto, port=port))


async def _device_responder(device: KcpDataChannel, reply_frame: bytes, device_key: bytes) -> None:
    """Echo the heartbeat and answer any command with a sealed reply (as the station does)."""
    while True:
        msg = await device.recv_message()
        if len(msg.payload) <= HEADER_LEN:  # the bare heartbeat XZYH
            await device.send_message(
                encode_frame(0x0473, b"", bytes(6)), msg_type=DataMsgType.COMMAND
            )
        else:  # a GCM command
            await device.send_message(
                encrypt_command(device_key, reply_frame, 0), msg_type=DataMsgType.COMMAND
            )


async def test_collect_station_reports_the_probes_and_decrypts_the_reply() -> None:
    c2d: asyncio.Queue[bytes] = asyncio.Queue()
    d2c: asyncio.Queue[bytes] = asyncio.Queue()
    client_ice = _FakeIce(send_q=c2d, recv_q=d2c)
    device = KcpDataChannel(_FakeIce(send_q=d2c, recv_q=c2d), conv=1)
    device_key = DEVICE_INFO.content_key.encode()[:16]
    reply_frame = encode_frame(0x0546, b'{"storageList":[],"code":0}', bytes(6))
    responder = asyncio.ensure_future(_device_responder(device, reply_frame, device_key))
    _server, session = await _session()
    try:
        await session.start()
        report = await collect_station(
            session, model="T9000", channel=0, account_id=ACCOUNT, listen_s=0.2, ice=client_ice
        )
        assert report.model == "T9000"
        assert report.is_webrtc_only is True
        assert report.error is None
        # CALL + ICE descriptors
        assert report.call is not None and report.call.answered
        assert report.call.content_key_len == 16  # a length, not the key
        assert report.ice is not None and report.ice.connected
        assert report.ice.remote_candidate_types == {"host": 1, "srflx": 1}
        # KCP heartbeat echo
        assert report.kcp is not None and report.kcp.heartbeat_echoed
        # command reply decrypted + described (the item-1 data)
        assert len(report.commands) == 1
        cmd = report.commands[0]
        assert cmd.reply_received and cmd.reply_decrypted
        assert cmd.reply_key == "device_content_key"
        assert cmd.reply_counter == 0
        assert cmd.plaintext_json_keys == ["code", "storageList"]  # names only, sorted
        # A/V passive listen captured nothing (no live-open sent)
        assert report.av is not None and report.av.packet_count == 0
    finally:
        responder.cancel()
        await device.close()
        await session.close()


def test_report_json_carries_only_descriptors_no_secrets() -> None:
    report = DiagnosticsReport(
        library_version="0.0.0",
        created_utc="2000-01-01T00:00:00Z",
        auth=AuthReport(
            logged_in=True, region="eu", user_id_present=True, device_count=2, webrtc_only_count=1
        ),
        stations=[StationReport(model="T9000", is_webrtc_only=True, channel=0)],
    )
    text = report.to_json()
    parsed = json.loads(text)  # valid JSON
    assert parsed["auth"]["user_id_present"] is True
    assert '"user_id"' not in text and '"content_key"' not in text  # no secret value fields
    assert "T9000" in render(report)
