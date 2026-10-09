"""A fake HomeBase speaking PPPP/XZYH on loopback (a supported test double).

It implements the station side of every exchange the session uses, with synthetic
keys, so the real transport and session run end to end without hardware:
discovery (answered from a separate "session" socket, like the real station),
the ECIES CONN_INIT handshake (or the RSA one, :attr:`FakeStation.conn_init_version`),
parameter dumps, arming, legacy ECB scalars, image
and database requests, the storage record (asked for or pushed with
:meth:`FakeStation.send_storage`), mode-table writes (``SET_ALL_ACTION``, 1255),
unsolicited camera pushes, and media streams (live and recordings) with the
RSA-wrapped keyframe cipher.

Where the real station is awkward, the fake is too: a guard-mode report is GCM (a
u64-LE mode under the session key), every command gets a receipt of
:attr:`FakeStation.receipt_len` bytes (-108 for one it does not handle, 1051
included), nothing but the session's CLOSE stops a recording that is playing, and a
new open does not cancel it either: its frames keep arriving.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..cloud.const import CIPHER_ID_P2P
from ..devices.recipes import MAX_PRESET_SLOTS, ConnectType, connect_type
from ..devices.types import model_for_serial
from ..models import STATION_CHANNEL
from ..p2p.crypto import (
    CONN_INIT_ECC_VERSION,
    FRAME_PLAIN,
    FRAME_SESSION_ECB,
    FRAME_STATIC_ECB,
    GCM_AAD,
    ecb_decrypt,
    ecb_encrypt,
    ecies_encrypt,
    gcm_decrypt_command,
)
from ..p2p.did import Did, static_key
from ..p2p.media import (
    PLAYBACK_ENDED,
    V1_ENCRYPTED_LEN,
    VIDEO_CODEC_HEVC,
    StillFormat,
    pic_check_code,
)
from ..p2p.messages import (
    ECB_CHANNEL_VALUE_CMDS,
    HISTORY_RECORD_COUNTER,
    HISTORY_RECORD_ID_MIN,
    PARAM_QUERY_ALL,
    RECEIPT_LEN,
    RECEIPT_NOT_HANDLED,
    RECEIPT_TAKEN,
    STRING_CMDS,
    decode_json_payload,
    decode_string_command_body,
)
from ..p2p.mode_actions import CMD_SET_ALL_ACTION, applied_params
from ..p2p.pppp import (
    MsgType,
    decode_drw,
    decode_packet,
    encode_drw,
    encode_drw_ack,
    encode_packet,
)
from ..p2p.storage_info import CMD_SD_INFO
from ..p2p.xzyh import FrameCipher, FrameType, StreamDecoder, encode_frame
from .synthetic import SYNTHETIC

SESSION_KEY = SYNTHETIC.session_key
RSA_SESSION_KEY = SYNTHETIC.session_key[:16]
"""The 16-character AES-128 key an RSA CONN_INIT carries."""
_SESSION_FRAME_TYPES = frozenset(
    {
        FrameType.PARAM_NOTIFY,
        CMD_SET_ALL_ACTION,
        *STRING_CMDS,
        FrameType.DOORBELL_PAYLOAD,
        FrameType.STOP_REALTIME_MEDIA,
        CMD_SD_INFO,
        FrameType.CMD_TRANSFER,
    }
)
"""Frame types a GCM session carries; on an RSA session the same go ECB under its key."""
CHUNK = 180  # split outbound frames so reassembly is exercised

# Clear HEVC: an Annex-B start code + VPS NAL header, > 257 bytes so it has a clear tail.
MEDIA_KEYFRAME = b"\x00\x00\x00\x01\x40\x01" + bytes((i * 7) & 0xFF for i in range(394))
MEDIA_PFRAME = b"P-FRAME!" * 30
MEDIA_RECORDING_PFRAME = b"R-FRAME!" * 30
MEDIA_AUDIO = b"\xff\xf1AAC-FRAME"
MEDIA_GOP = 4  # a keyframe every this many video frames
MEDIA_INTERVAL = 0.005
MEDIA_WIDTH = 3840
MEDIA_HEIGHT = 2160
MEDIA_FRAME_MS = 40  # the stream clock advances this much per video frame
MEDIA_CLOCK_START = 1_000_000  # free-running: a real station's clock is never near 0


def media_keyframe(
    public: rsa.RSAPublicKey, aes_key: bytes, clear: bytes = MEDIA_KEYFRAME
) -> bytes:
    """A keyframe body as the station sends it: RSA-wrapped key, marker, ECB prefix, tail."""
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()  # noqa: S305 (protocol)
    prefix = enc.update(clear[:128]) + enc.finalize()
    return public.encrypt(aes_key, padding.PKCS1v15()) + b"\x00" + prefix + clear[128:]


def video_record(
    body: bytes,
    *,
    keyframe: bool,
    codec: int = VIDEO_CODEC_HEVC,
    counter: int = 0,
    width: int = MEDIA_WIDTH,
    height: int = MEDIA_HEIGHT,
    timestamp_ms: int = 0,
) -> bytes:
    """A VIDEO_FRAME payload: the 22-byte media header, then ``body``.

    The header is ``[u32le datalen][u8 keyframe][u8 codec][u32le counter][u16le width]
    [u16le height][u32le timestamp_ms][4 bytes]``, as a real camera sends it.
    """
    return (
        struct.pack("<I", len(body))
        + bytes([int(keyframe), codec])
        + struct.pack("<IHHI", counter, width, height, timestamp_ms)
        + bytes(4)
    ) + body


def audio_record(body: bytes, *, counter: int = 0, timestamp_ms: int = 0) -> bytes:
    """An AUDIO_FRAME payload: the 16-byte media header, then ``body``.

    The header is ``[u32le datalen][u16le ?][u16le counter][u32le timestamp_ms][4 bytes]``.
    """
    return (
        struct.pack("<I", len(body)) + struct.pack("<HHI", 0, counter, timestamp_ms) + bytes(4)
    ) + body


def v1_still(
    image: bytes,
    serial: str = SYNTHETIC.camera_sn,
    *,
    did: str = SYNTHETIC.did,
    code: str = "0123456789",
) -> bytes:
    """``image`` (a JPEG of at least 256 bytes) as a V1 ``eufysecurity`` still of
    ``serial`` (16 characters), as a T8170 stores it; the session decodes it with ``did``."""
    if len(image) < V1_ENCRYPTED_LEN or len(serial) != 16 or len(code) != 10:
        raise ValueError("a V1 still needs a 256-byte image, a 16-char serial, a 10-char code")
    key = pic_check_code(serial, did, code)[:16].encode()
    header = f"{StillFormat.V1.value}:{serial}:{code}:".encode()
    return header + ecb_encrypt(key, image[:V1_ENCRYPTED_LEN]) + image[V1_ENCRYPTED_LEN:]


def synthetic_storage_body(*, label: str = SYNTHETIC.disk_label) -> dict[str, Any]:
    """A storage record ``body`` (``1307`` / ``11001``) with synthetic figures (MiB).

    The shape of a HomeBase 3 with an internal 256 GB SSD and no external disk. The
    app would show "used" (4000 + 9000 + 1500) / 1024 = 14.16 GB of 238475 / 1024 =
    232.89 GB.
    """
    return {
        "body_version": 2,
        "storage_days": 30,
        "storage_events": 120,
        "con_video_hours": 0,
        "format_transaction": "",
        "format_errcode": 0,
        "hdd_info": {
            "serial_number": SYNTHETIC.disk_serial,
            "disk_path": "/dev/sda",
            "disk_size": 256000,
            "system_size": 4000,
            "disk_used": 2100,
            "video_used": 1500,
            "video_size": 220000,
            "cur_temperate": 38,
            "parted_status": 1,
            "work_status": 0,
            "hdd_label": label,
            "health": 0,
            "device_module": "ExampleSSD256GB",
            "hdd_type": 1,
            "disk_size_1024": 238475,
            "system_size_data": 9000,
        },
        "move_disk_info": {
            "disk_path": "",
            "disk_size": 0,
            "disk_used": 0,
            "part_layout_arr": [],
            "data": [],
        },
        "emmc_info": {
            "disk_nominal": 15974,
            "disk_size": 16000,
            "system_size": 5000,
            "disk_used": 3000,
            "data_used_percent": 25,
            "swap_size": 2048,
            "video_size": 10000,
            "video_used": 100,
            "data_partition_size": 12000,
            "eol_percent": 2,
            "work_status": 0,
            "health": 0,
        },
    }


def _record_id(row: dict[str, Any]) -> int | None:
    value = row.get("record_id")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _record_day(row: dict[str, Any]) -> str | None:
    """``YYYYMMDD`` of a date-prefixed ``record_id`` (``YYYYMMDD`` + a 5-digit counter)."""
    record_id = _record_id(row)
    return (
        str(record_id // HISTORY_RECORD_COUNTER)
        if record_id is not None and record_id >= HISTORY_RECORD_ID_MIN
        else None
    )


def _media_subheader(camera: int) -> bytes:
    """A media frame's subheader: the station tags it with the camera's channel (byte 2)."""
    return bytes([0, 0, camera, 0, 0, 0])


def _gcm_broadcast(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext, GCM_AAD)
    return sealed[-16:] + nonce + sealed[:-16]


@dataclass
class FakeStation:
    """One fake HomeBase; ``await start()`` binds it on loopback, ``stop()`` silences it."""

    serial: str = SYNTHETIC.station_sn
    did: Did = field(default_factory=lambda: Did.parse(SYNTHETIC.did))
    account_id: str = SYNTHETIC.account_id
    ecc_private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    guard_mode: int = 0
    schedule_mode: int = 1
    """The mode a schedule slot puts in force while Schedule (2) is selected."""
    ignore_searches: int = 0
    reply_to_settings: bool = False
    params: dict[int, dict[int, str]] = field(
        default_factory=lambda: {
            0: {1101: "87", 1142: "-52", 1217: "Front"},
            255: {1216: "Home Base", 7013: "3.8.7.4"},
        }
    )
    images: dict[str, bytes] = field(default_factory=dict)
    """Still bytes by path. A 1308 for a path not here gets no reply (the real station's
    answer to an unknown path is unmeasured), so the fetch times out."""
    image_reply_delay: dict[str, float] = field(default_factory=dict)
    """Seconds to wait before answering a 1308 for that path (a late reply)."""
    image_reply_file: dict[str, str | None] = field(default_factory=dict)
    """The ``file`` a 1308 reply for that path carries (None: no ``file``); default the path."""
    image_requests: list[str] = field(default_factory=list)
    """The path of every 1308 received, answered or not."""
    rows: list[dict[str, Any]] = field(default_factory=list)
    history_side_tables: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Other tables the station appends to every history page (AI crops, the person
    library), by ``table_name``."""
    history_queries: list[dict[str, Any]] = field(default_factory=list)
    """The inner ``payload`` of every history (10011) query received."""
    event_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    """The event-count (10013) item ``payload`` by device serial, as the T8170 answers:
    ``{"event_count": 11, "crop_hb3_path": "…_snapshot.jpg", "crop_cloud_path": ""}``."""
    event_count_ignored: int = 0
    """Event-count queries dropped before one is answered (a T8170 woken moments ago)."""
    event_count_unnamed: bool = False
    """Name no device in the event-count items (``"device_sn": ""``), as a T8170 sometimes does."""
    event_count_queries: int = 0
    """Event-count (10013) queries received, answered or not."""
    clear_replies: bool = False
    """Send database and still replies as clear JSON under the ECB tag, as a T8170 does."""
    storage: dict[str, Any] = field(default_factory=synthetic_storage_body)
    """The storage record ``body`` a ``1307`` / ``11001`` is answered with."""
    sd_info: tuple[int, int, int] | None = None
    """``(status, total, free)`` a standalone ``SDINFO_EX`` (``1144``) is answered with as
    three ``int32``; None: no answer (the frame is ignored)."""
    storage_reply_code: int = 0
    """``mIntRet`` of the storage reply (non-zero: the body is left out)."""
    storage_reply_cipher: int = FrameCipher.ECB
    """The cipher of the answer to a storage query: ECB, as the live station answered
    on a fresh session (a pushed record, :meth:`send_storage`, is GCM by default)."""
    received: list[dict[str, Any]] = field(default_factory=list)
    received_header_channels: list[int] = field(default_factory=list)
    """The subheader channel (byte 2) of each command in :attr:`received`, in step."""
    ecb_received: list[tuple[int, int, int]] = field(default_factory=list)
    mode_tables_received: list[dict[str, Any]] = field(default_factory=list)
    """Every 1255 mode-table body, in arrival order (whatever its account id)."""
    string_commands_received: list[tuple[int, int, str]] = field(default_factory=list)
    """Every string command (:data:`~..p2p.messages.STRING_CMDS`) as ``(command, channel,
    value)``, in arrival order; the value is stored as the param of that channel."""
    mode_table_receipt_code: int = 0
    """The code a 1255 receipt carries; non-zero leaves the parameters untouched."""
    drop_first_drw: bool = False
    apply_settings: bool = True
    ecb_apply_late: bool = False
    """Take an ECB scalar setting without answering it, and apply it only when the next
    parameter dump is asked for, as a T8160 does with a 1246 write: it applies it
    after the session has raised "acknowledged … but never acted on it"."""
    recording_frames: int = 6
    media_reply_code: int | None = None
    live_open_receipt_code: int = RECEIPT_TAKEN
    """The receipt a live open (1003) gets; non-zero streams nothing, as a HomeBase that
    cannot wake the camera (-204, about 12 s after the open, with ``live_open_receipt_delay``)."""
    live_open_receipt_delay: float = 0.0
    max_sessions: int | None = None
    """Sessions the station holds at most (a HomeBase 3: 9, a T8170: 4); a session
    punched past it makes the station CLOSE the longest-open other one. None: no limit."""
    send_ready: bool = True
    session_key: bytes = SESSION_KEY
    """The GCM session key a version-8 CONN_INIT carries: 32 bytes, printable on a
    HomeBase 3, not necessarily on other stations."""
    cipher_id: int = CIPHER_ID_P2P
    """The cipher CONN_INIT names (a HomeBase 3: 40; a T8170: 98). The fake unwraps with
    one key whatever the id; the cloud fake serves that key under any id."""
    receipt_len: int = RECEIPT_LEN
    """A receipt's body length (a T8170: ``STANDALONE_RECEIPT_LEN``)."""
    conn_init_version: int = CONN_INIT_ECC_VERSION
    """The CONN_INIT reply's version (subheader byte 0). 8: the ECIES handshake and a GCM
    session. Any other (1, as a T8410): the RSA handshake, then every frame either way is
    AES-128-ECB under :data:`RSA_SESSION_KEY` (encryption type 2), receipts in clear."""
    conn_init_encryption: int = FRAME_PLAIN
    """The RSA CONN_INIT's encryption type (subheader byte 3): 0 clear, the 133 bytes the
    app reads as is; otherwise ECB under the static key, padded to 144."""
    answer_conn_init: bool = True
    answer_params: bool = True
    params_cipher: int = FrameCipher.GCM
    """The cipher the parameter dump answers under (ECB: the firmware the session refuses)."""
    sub_blocks_after: float | None = None
    """Send the sub-device blocks this many seconds AFTER the station block (None: before)."""
    unhandled_commands: set[int] = field(default_factory=lambda: {1051})
    """Commands answered with receipt -108 and nothing else, as the real station answers
    ``DOWNLOAD_CANCEL`` (1051) and the ``GET_*`` commands."""
    rejection_delay: float = 0.0
    """Seconds before a -108 receipt (the real station: 11 to 17 s)."""
    relayed_channels: set[int] = field(default_factory=set)
    """Channels of paired Wi-Fi cameras (a T8170) the station passes a 1350 command on to
    only when the subheader names the channel; under another subheader channel the
    command gets receipt -108 after :attr:`rejection_delay` and nothing else, as a
    HomeBase 3 answers a header-0 picture zoom (6203) for its T8170."""
    playback_end_delay: float | None = 0.05
    """Seconds after a recording's last frame before its end-of-playback frame (the real
    station: about 0.5 s); None sends none."""
    preset_points: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"index": i, "enable": int(i < 3), "zoom": 1, "isdefault": int(i == 0)}
            for i in range(10)
        ]
    )
    """A pan/tilt camera's slots, answered to a 6034 query (1700 wrapper) in a 1351 notify."""
    live_ends_unpinged_after: float | None = None
    """End a live stream when no 1139 ping arrived for this many seconds (a T8170: about
    10 s); None streams until stopped."""
    live_keyframe_sizes: list[tuple[int, int]] = field(default_factory=list)
    """``(width, height)`` of a live stream's n-th keyframe, the frames after it keeping
    its size; past the list its last entry. Empty: every frame is 3840x2160. A T8170's
    climb is 1280x720, then 1920x1080, then 2880x1616."""
    preset_pictures: dict[int, bytes] = field(default_factory=dict)
    """The JPEG each slot answers a 6097 read with; a slot with none answers an empty
    string, as the real camera does for an empty slot."""

    def __post_init__(self) -> None:
        self.static_key = static_key(self.serial, self.did)
        self._rsa_cipher_key: rsa.RSAPrivateKey | None = None
        self._peers: dict[tuple[str, int], _Peer] = {}
        self._discovery: asyncio.DatagramTransport | None = None
        self._session: asyncio.DatagramTransport | None = None
        self.discovery_port = 0
        self.searches = 0
        self.conn_inits = 0
        self.client_closes = 0
        """Sessions a client ended with a PPPP CLOSE."""
        self.station_closes = 0
        """Sessions the station CLOSEd because :attr:`max_sessions` was exceeded."""
        self.max_live_cameras = 0
        """The most sessions that streamed live at the same time."""
        self.media_frames_sent = 0
        self.param_queries = 0
        self.opened_while_streaming: list[bool] = []
        """Per media open: whether an earlier stream was still sending to that session."""
        self.live_opens: list[int] = []
        """Per live open (1003): the camera channel it named in its subheader."""
        self._late_writes: list[tuple[int, int, int]] = []
        """ECB writes taken under :attr:`ecb_apply_late`, applied at the next dump."""
        self.doorbell_payloads: list[dict[str, Any]] = []
        """Every 1700 body received (``{"commandType", "data"}``), in arrival order."""
        self.preset_gotos: list[int] = []
        """The slot of every go-to-preset (1700 / 6035) received."""
        self.gotos_while_streaming: list[bool] = []
        """Per go-to-preset, in step with :attr:`preset_gotos`: whether a live stream of
        the channel it named was sending to that session when it arrived."""
        self.pan_tilts: list[int] = []
        """The ``rotate_type`` of every pan/tilt step (1700 / 6030) received."""
        self.preset_stores: list[int] = []
        """The slot of every preset store (1700 / 6032) received, applied or not."""
        self.preset_deletes: list[int] = []
        """The slot of every preset delete (1700 / 6033) received."""
        self.preset_picture_requests: list[int] = []
        """The slot of every preset-picture read (1700 / 6097) received."""
        self.default_preset_sets: list[tuple[int, int]] = []
        """Each default-preset write (1350 / 6242) received, as (index, settingstate)."""
        self.zoom_writes: list[float] = []
        """The ``dstZoom`` of every picture-zoom write (1350 / 6203) received."""
        self.bare_stops = 0
        """Bare 1004 stops received (a standalone device's live stop)."""
        self.pings = 0
        """App 1139 pings received (empty 0x0473 frames)."""
        self._last_ping = 0.0

    @property
    def ecc_private_key_hex(self) -> str:
        return f"{self.ecc_private_key.private_numbers().private_value:064x}"

    @property
    def rsa_session(self) -> bool:
        """Whether this station answers with the RSA CONN_INIT (:attr:`conn_init_version`)."""
        return self.conn_init_version != CONN_INIT_ECC_VERSION

    @property
    def rsa_cipher_key(self) -> rsa.RSAPrivateKey:
        """The RSA-1024 key of the cipher an RSA CONN_INIT names (made on first use)."""
        if self._rsa_cipher_key is None:
            # The size the station's 128-byte CONN_INIT block fixes.
            self._rsa_cipher_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,  # noqa: S505
            )
        return self._rsa_cipher_key

    @property
    def rsa_private_key_pem(self) -> str:
        """:attr:`rsa_cipher_key` as the cloud serves ``private_key``: PKCS#8 PEM."""
        return self.rsa_cipher_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    # ── sockets ──────────────────────────────────────────────────────────────

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        outer = self

        class _Discovery(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
                outer._on_discovery(data, (str(addr[0]), int(addr[1])))

        class _Session(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
                outer._on_session(data, (str(addr[0]), int(addr[1])))

        self._discovery, _ = await loop.create_datagram_endpoint(
            _Discovery, local_addr=("127.0.0.1", 0)
        )
        self._session, _ = await loop.create_datagram_endpoint(
            _Session, local_addr=("127.0.0.1", 0)
        )
        self.discovery_port = self._discovery.get_extra_info("sockname")[1]

    def stop(self) -> None:
        self._stop_media()
        for t in (self._discovery, self._session):
            if t is not None:
                t.close()

    def reset_session(self) -> None:
        """Forget every client session (without telling the clients)."""
        for peer in list(self._peers.values()):
            self._drop(peer)

    @property
    def sessions(self) -> int:
        """Client sessions currently open on the station."""
        return len(self._peers)

    @property
    def live_cameras(self) -> list[int]:
        """The camera channel of each session streaming live now, one entry per session."""
        return [
            p.live_camera
            for p in self._peers.values()
            if p.live_streaming and p.live_camera is not None
        ]

    # ── inbound ──────────────────────────────────────────────────────────────

    def _on_discovery(self, data: bytes, addr: tuple[str, int]) -> None:
        msg, _ = decode_packet(data)
        if msg != MsgType.LAN_SEARCH:
            return
        self.searches += 1
        if self.ignore_searches > 0:
            self.ignore_searches -= 1
            return
        # As the firmware: a search is answered from the session socket and leaves the
        # other sessions alone (a LAN probe, a second client). A search from a port that
        # already holds a session is that client starting over.
        if (peer := self._peers.get(addr)) is not None:
            self._drop(peer)
        if self._session is not None:
            self._session.sendto(encode_packet(MsgType.PUNCH_PKT, self.did.to_struct()), addr)

    def _on_session(self, data: bytes, addr: tuple[str, int]) -> None:
        msg, payload = decode_packet(data)
        peer = self._peers.get(addr)
        if peer is None:
            if msg != MsgType.PUNCH_PKT:
                return  # not a session's traffic
            # A client punching back opens a session; the others stay open up to
            # max_sessions, as on the real station.
            peer = self._peers[addr] = _Peer(addr)
            if self.max_sessions is not None and len(self._peers) > self.max_sessions:
                self.station_closes += 1
                victim = next(iter(self._peers.values()))
                self._sendto(victim, encode_packet(MsgType.CLOSE))
                self._drop(victim)
        token = _CURRENT_PEER.set(peer)
        try:
            self._on_peer_packet(peer, msg, payload)
        finally:
            _CURRENT_PEER.reset(token)

    def _on_peer_packet(self, peer: _Peer, msg: int, payload: bytes) -> None:
        if msg == MsgType.PUNCH_PKT:
            if self.send_ready:
                self._send(encode_packet(MsgType.P2P_RDY))
        elif msg == MsgType.ALIVE:
            self._send(encode_packet(MsgType.ALIVE_ACK))
        elif msg == MsgType.CLOSE:
            self.client_closes += 1
            self._drop(peer)
        elif msg == MsgType.DRW:
            if self.drop_first_drw:
                self.drop_first_drw = False
                return
            chunk = decode_drw(payload)
            self._send(encode_drw_ack(chunk.channel, [chunk.index]))
            decoder = peer.decoders.setdefault(chunk.channel, StreamDecoder())
            for frame in decoder.feed(chunk.index, chunk.data):
                self._on_frame(frame.type, frame.subheader, frame.payload)

    def _on_frame(self, ftype: int, subheader: bytes, payload: bytes) -> None:
        if ftype == FrameType.DEV_STATUS and not payload:
            self.pings += 1
            self._last_ping = asyncio.get_running_loop().time()
            return
        if ftype == FrameType.CONN_INIT:
            self.conn_inits += 1
            if self.answer_conn_init:
                self._answer_conn_init()
        elif subheader[0] == FrameCipher.GCM and not self.rsa_session:
            self._on_session_frame(ftype, subheader, gcm_decrypt_command(self.session_key, payload))
        elif (
            self.rsa_session
            and subheader[0] == FrameCipher.ECB
            and subheader[3] == FRAME_SESSION_ECB
        ):
            plain = ecb_decrypt(RSA_SESSION_KEY, payload)
            if ftype in _SESSION_FRAME_TYPES:
                self._on_session_frame(ftype, subheader, plain)
            else:
                self._on_ecb(ftype, subheader, plain)
        elif subheader[0] == FrameCipher.ECB:
            body = ecb_decrypt(self.static_key, payload)
            self._on_ecb(ftype, subheader, body)

    def _answer_conn_init(self) -> None:
        """The CONN_INIT reply: ECIES (version 8, ECB under the static key, encryption
        type 1, as a HomeBase 3 sends it) or RSA (any other version)."""
        cipher_id = struct.pack("<I", self.cipher_id)
        if not self.rsa_session:
            blob = ecies_encrypt(self.session_key, self.ecc_private_key.public_key())
            body = ecb_encrypt(self.static_key, cipher_id + blob)
            subheader = bytes([CONN_INIT_ECC_VERSION, 0, 0xFF, FRAME_STATIC_ECB, 0, 0])
        else:
            wrapped = self.rsa_cipher_key.public_key().encrypt(RSA_SESSION_KEY, padding.PKCS1v15())
            body = cipher_id + wrapped + b"\x00"
            if self.conn_init_encryption != FRAME_PLAIN:
                body = ecb_encrypt(self.static_key, body)
            subheader = bytes([self.conn_init_version, 0, 0xFF, self.conn_init_encryption, 0, 0])
        self.send_frame(
            FrameType.CONN_INIT, body, cipher=subheader[0], channel=2, subheader=subheader
        )

    def _on_session_frame(self, ftype: int, subheader: bytes, plain: bytes) -> None:
        """A client frame under the session's cipher (GCM, or an RSA session's ECB)."""
        if ftype == FrameType.PARAM_NOTIFY and plain[: len(PARAM_QUERY_ALL)] == PARAM_QUERY_ALL:
            self.param_queries += 1
            for channel, command, value in self._late_writes:
                self.params.setdefault(channel, {})[command] = str(value)
            self._late_writes.clear()
            if not self.answer_params:
                return  # a deaf session: the link and handshake still work
            # As the real station: a receipt (code 0) on the request channel first,
            # then the dump on channel 2.
            self.send_receipt(FrameType.PARAM_NOTIFY, RECEIPT_TAKEN, dev_type=0xFF)
            self.send_param_dump(cipher=self.params_cipher)
        elif ftype == CMD_SET_ALL_ACTION:
            obj = decode_json_payload(plain)
            if obj is None:
                return
            self.mode_tables_received.append(obj)
            self._on_mode_table(obj)
        elif ftype in STRING_CMDS:
            self._on_string_command(ftype, plain)
        elif ftype == FrameType.DOORBELL_PAYLOAD:
            obj = decode_json_payload(plain)
            if obj is None:
                return
            self.doorbell_payloads.append(obj)
            code = self.doorbell_receipt_code()
            self.send_receipt(FrameType.DOORBELL_PAYLOAD, code)
            if code == RECEIPT_TAKEN:
                self._on_doorbell_payload(obj, subheader)
        elif ftype == FrameType.STOP_REALTIME_MEDIA:
            self.bare_stops += 1
            self.send_receipt(FrameType.STOP_REALTIME_MEDIA, RECEIPT_TAKEN)
            self._stop_live()
        elif ftype == CMD_SD_INFO:
            # A standalone eMMC query: answer with a frame of the same type on
            # channel 0, three int32 (status, total, free), GCM-tagged but clear.
            if self.sd_info is not None:
                body = struct.pack("<3i", *self.sd_info)
                subheader = bytes([FrameCipher.GCM, 0, 0, 0, 1, 0])
                self.send_frame(
                    CMD_SD_INFO, body, cipher=FrameCipher.GCM, channel=0, subheader=subheader
                )
        elif ftype == FrameType.CMD_TRANSFER:
            obj = decode_json_payload(plain)
            if obj is None:
                return  # not a JSON command: the real station ignores it too
            self.received.append(obj)
            self.received_header_channels.append(subheader[2])
            target = obj.get("mChannel")
            if obj.get("cmd") in self.unhandled_commands or (
                target in self.relayed_channels and subheader[2] != target
            ):
                self.send_receipt(
                    FrameType.CMD_TRANSFER, RECEIPT_NOT_HANDLED, delay=self.rejection_delay
                )
                return
            if obj.get("cmd") == 1003 and self.live_open_receipt_code != RECEIPT_TAKEN:
                # As a HomeBase that cannot wake the camera: no queue receipt, one
                # failure receipt later, no stream.
                self.live_opens.append(subheader[2])
                self.send_receipt(
                    FrameType.CMD_TRANSFER,
                    self.live_open_receipt_code,
                    delay=self.live_open_receipt_delay,
                )
                return
            # Assumed for a foreign account_id too: the receipt is the queue's, and
            # whether the real station sends one then is not known.
            self.send_receipt(FrameType.CMD_TRANSFER, RECEIPT_TAKEN)
            self._on_command(obj, subheader)

    def doorbell_receipt_code(self) -> int:
        """The code a 1700 receipt carries; override to reject one. A camera that is
        still moving answers 1 (busy), and a rejected command is never acted on."""
        return RECEIPT_TAKEN

    def _on_doorbell_payload(self, obj: dict[str, Any], subheader: bytes) -> None:
        """A standalone device's 1700 wrapper: live open, preset query, go-to and edits."""
        command, data = obj.get("commandType"), obj.get("data") or {}
        if command == 1000:
            self.live_opens.append(subheader[2])
            self._start_media(data["encryptkey"], live=True, camera=subheader[2])
        elif command == 6034:
            self.send_json(
                FrameType.NOTIFY_PAYLOAD,
                {"cmd": 6034, "payload": {"points": self.preset_points}},
                channel=2,
            )
        elif command == 6035:
            self.preset_gotos.append(data["value"])
            peer = _CURRENT_PEER.get()
            self.gotos_while_streaming.append(
                peer is not None and peer.live_streaming and peer.live_camera == subheader[2]
            )
        elif command == 6030:
            self.pan_tilts.append(int(data["rotate_type"]))
        elif command == 6032:
            index = int(data["value"])
            self.preset_stores.append(index)
            in_use = [p for p in self.preset_points if p.get("enable")]
            # the real camera receipts a store it cannot make: at most 5 slots
            if len(in_use) < MAX_PRESET_SLOTS or any(p["index"] == index for p in in_use):
                for point in self.preset_points:
                    if point.get("index") == index:
                        point["enable"] = 1
        elif command == 6033:
            index = int(data["value"])
            self.preset_deletes.append(index)
            for point in self.preset_points:
                if point.get("index") == index:
                    point["enable"] = 0
                    point["isdefault"] = 0
        elif command == 6097:
            index = int(data["value"])
            self.preset_picture_requests.append(index)
            picture = self.preset_pictures.get(index, b"")
            self.send_json(
                FrameType.NOTIFY_PAYLOAD,
                {
                    "cmd": 6097,
                    "payload": {
                        "index": index,
                        # an empty slot answers an empty string, not an error
                        "data": base64.urlsafe_b64encode(picture).decode().rstrip("="),
                    },
                },
                channel=2,
            )
        elif self.apply_settings and data and isinstance(command, int):
            # A setting recipe (a recorded wire template): the value of its
            # first value-carrying field lands on the subheader's channel under the
            # command type, so a parameter dump reads it back.
            value = data.get("value", next(iter(data.values())))
            self.params.setdefault(subheader[2], {})[command] = str(value)

    def _own_blocks(self) -> list[int]:
        """The dump blocks that carry the station's own parameters (its guard mode).

        A HomeBase labels its own block 255. A standalone device labels its one block
        with its cloud device type (48 for a T8170), so an arm lands there too; 255 is
        written only when the fake holds it, or when there is no other block.
        """
        blocks: list[int] = []
        model = model_for_serial(self.serial)
        if (
            connect_type(self.serial, self.serial) is ConnectType.SINGLE
            and model is not None
            and model.cloud_device_type in self.params
        ):
            blocks.append(model.cloud_device_type)
        if STATION_CHANNEL in self.params or not blocks:
            blocks.append(STATION_CHANNEL)
        for block in blocks:
            self.params.setdefault(block, {})
        return blocks

    def _on_command(self, obj: dict[str, Any], subheader: bytes) -> None:
        if obj.get("account_id") != self.account_id:
            return  # the real station drops these without a word
        cmd = obj["cmd"]
        if cmd == 1224:
            if obj["payload"]["mode_type"] == self.guard_mode:
                return  # the real station is silent when asked for the mode it is in
            self.guard_mode = obj["payload"]["mode_type"]
            blocks = self._own_blocks()
            before = self.params[blocks[0]].get(1151)
            active = self.schedule_mode if self.guard_mode == 2 else self.guard_mode
            for block in blocks:
                self.params[block][1224] = str(self.guard_mode)
                self.params[block][1151] = str(active)
            if str(active) != before:  # the report carries the mode in force, never 2
                self.send_alarm_mode(active)  # as the live station: GCM, channel 2
            self.send_json(FrameType.NOTIFY_PAYLOAD, {"cmd": 1224, "code": 0})
        elif cmd == 1308:
            path = obj["payload"][0]["file"]
            self.image_requests.append(path)
            if path not in self.images:
                return
            content = base64.urlsafe_b64encode(self.images[path]).decode().rstrip("=")
            reply: dict[str, Any] = {"content": content}
            if (file := self.image_reply_file.get(path, path)) is not None:
                reply["file"] = file
            delay = self.image_reply_delay.get(path, 0.0)
            if delay > 0:
                asyncio.get_running_loop().call_later(
                    delay, self._send_reply, FrameType.MEDIA_DOWNLOAD, reply
                )
            else:
                self._send_reply(FrameType.MEDIA_DOWNLOAD, reply)
        elif cmd == 6242:
            payload = obj.get("payload") or {}
            index, state = int(payload.get("index", 0)), int(payload.get("settingstate", 0))
            self.default_preset_sets.append((index, state))
            for point in self.preset_points:
                point["isdefault"] = int(point.get("index") == index)
        elif cmd == 6203:
            payload = obj.get("payload") or {}
            self.zoom_writes.append(float(payload.get("dstZoom", 0)))
            # the real camera echoes the write's fields, ECB on channel 2
            self.send_json(
                FrameType.NOTIFY_PAYLOAD,
                {"cmd": 6203, "mChannel": subheader[2], "payload": payload},
                channel=2,
                cipher=FrameCipher.ECB,
            )
        elif cmd == 1307:
            if (obj.get("payload") or {}).get("cmd") == 11001:
                self.send_storage(cipher=self.storage_reply_cipher)
        elif cmd in (1003, 1024, 1025):
            if self.media_reply_code is not None:
                self.send_json(
                    FrameType.NOTIFY_PAYLOAD, {"cmd": cmd, "code": self.media_reply_code}
                )
                return
            peer = _CURRENT_PEER.get()
            self.opened_while_streaming.append(peer is not None and peer.streaming)
            # As the real station: the live camera is the subheader's channel byte, and a
            # recording's frames carry the channel the request names.
            camera = subheader[2] if cmd == 1003 else obj.get("mChannel", 0)
            if cmd == 1003:
                self.live_opens.append(camera)
            self._start_media(obj["payload"]["key"], live=cmd == 1003, camera=camera)
        elif cmd == 1004:
            self._stop_live()
        elif cmd == 1306:
            inner = obj.get("payload") or {}
            if inner.get("cmd") == 10011:
                self._answer_history(inner)
            elif inner.get("cmd") == 10013:
                self._answer_event_count(inner)
            else:
                self.send_json(FrameType.DB_SYNC, {"cmd": 1306, "data": json.dumps(self.rows)})
        else:
            payload = obj.get("payload")
            if self.apply_settings and isinstance(payload, dict) and "channel" in payload:
                value = next(v for k, v in payload.items() if k != "channel")
                reported = self.params.setdefault(payload["channel"], {})
                reported[cmd] = _stored_report(reported.get(cmd), payload, str(value))
            if self.reply_to_settings:
                self.send_json(FrameType.NOTIFY_PAYLOAD, {"cmd": cmd, "code": 0})

    def _answer_history(self, inner: dict[str, Any]) -> None:
        """A history page (10011), shaped and cut like the real station's.

        As observed live: a query returns rows of its ``start_date`` day only (a row
        without a date-prefixed ``record_id`` matches any day), newest first, at most
        ``count`` of them, from ``start_id`` down (that row included) when it is not 0.
        Rows nest under ``data[*].payload`` next to :attr:`history_side_tables`, and
        the reply names the inner verb, echoes the ``transaction`` and gives the page's
        newest and oldest ``record_id``.
        """
        query = inner.get("payload") or {}
        self.history_queries.append(dict(query))
        day = str(query.get("start_date", ""))
        start_id = int(query.get("start_id") or 0)
        rows = sorted(
            (row for row in self.rows if _record_day(row) in (None, day)),
            key=lambda row: _record_id(row) or 0,
            reverse=True,
        )
        if start_id:
            rows = [row for row in rows if (_record_id(row) or 0) <= start_id]
        page = rows[: int(query.get("count") or 30)]
        ids = [_record_id(row) or 0 for row in page]
        tables = [("history_record_info", page), *self.history_side_tables.items()]
        self.send_json(
            FrameType.DB_SYNC,
            {
                "cmd": 10011,
                "data": [{"payload": rows_, "table_name": name} for name, rows_ in tables],
                "start_id": ids[0] if ids else 0,
                "end_id": ids[-1] if ids else 0,
                "mIntRet": 0,
                "msg": "SUCCESSFUL",
                "table": "history_record_info",
                "transaction": inner.get("transaction"),
            },
        )

    def _answer_event_count(self, inner: dict[str, Any]) -> None:
        """An event-count reply (10013): one item per device of :attr:`event_summaries`,
        shaped like the T8170's; the first :attr:`event_count_ignored` queries get none."""
        self.event_count_queries += 1
        if self.event_count_queries <= self.event_count_ignored:
            return
        items = [
            {"device_sn": "" if self.event_count_unnamed else sn, "payload": dict(payload)}
            for sn, payload in self.event_summaries.items()
        ]
        self._send_reply(
            FrameType.DB_SYNC,
            {
                "data": items,
                "transaction": inner.get("transaction"),
                "table": "history_record_info",
                "cmd": 10013,
                "mIntRet": 0,
                "version": "1.3.0.1",
                "msg": "SUCCESSFUL",
            },
        )

    def _send_reply(self, ftype: int, obj: dict[str, Any]) -> None:
        """A database or still reply: GCM, or clear JSON under the ECB tag with
        :attr:`clear_replies`."""
        if self.clear_replies:
            self.send_frame(ftype, json.dumps(obj).encode(), cipher=FrameCipher.ECB, channel=1)
        else:
            self.send_json(ftype, obj)

    def _on_mode_table(self, obj: dict[str, Any]) -> None:
        """As the live station: a receipt of the request's own type on channel 0 (no
        0x0547), and the table applied — each listed device's action, each count-down's
        delay into the channels it lists, every other value left as it was."""
        if obj.get("account_id") != self.account_id:
            return  # the real station drops these without a word
        code = self.mode_table_receipt_code
        if code == 0 and self.apply_settings:
            for channel, values in applied_params(obj).items():
                block = self.params.setdefault(channel, {})
                block.update({param: str(value) for param, value in values.items()})
        self.send_frame(
            CMD_SET_ALL_ACTION,
            struct.pack("<i", code) + bytes(self.receipt_len - 4),
            cipher=FrameCipher.GCM,
            subheader=bytes([FrameCipher.GCM, 0, 0, 0, 1, 0]),
        )

    def _on_string_command(self, ftype: int, plain: bytes) -> None:
        """As a T8170: a string command (1215) of the owner is stored verbatim on the
        channel its body names and answered with receipt 0; another account's gets
        -104 and changes nothing."""
        try:
            channel, value, account = decode_string_command_body(plain)
        except (ValueError, UnicodeDecodeError):
            self.send_receipt(ftype, -104)
            return
        self.string_commands_received.append((ftype, channel, value))
        code = 0 if account == self.account_id else -104
        if code == 0 and self.apply_settings:
            self.params.setdefault(channel, {})[ftype] = value
        self.send_receipt(ftype, code)

    def _on_ecb(self, ftype: int, subheader: bytes, body: bytes) -> None:
        channel = subheader[2]
        offset = 4 if ftype in ECB_CHANNEL_VALUE_CMDS else 0  # [channel][value][account]
        value = struct.unpack_from("<I", body, offset)[0]
        account = body[offset + 4 : offset + 132].split(b"\x00", 1)[0].decode()
        self.ecb_received.append((ftype, channel, value))
        code = 0 if account == self.account_id else -104
        if self.ecb_apply_late and code == 0:
            self._late_writes.append((channel, ftype, value))
            return  # taken, never answered: the session reports it as not acted on
        if code == 0 and self.apply_settings:
            self.params.setdefault(channel, {})[ftype] = str(value)
        self.send_frame(ftype, struct.pack("<i", code) + b"\x00" * 12, cipher=FrameCipher.ECB)

    # ── media ────────────────────────────────────────────────────────────────

    @property
    def streaming(self) -> bool:
        """Whether any stream (live or recording) is still sending frames, to any session."""
        return any(peer.streaming for peer in self._peers.values())

    def _start_media(self, key_hex: str, *, live: bool, camera: int) -> None:
        peer = _CURRENT_PEER.get()
        if peer is None:
            return
        public = rsa.RSAPublicNumbers(65537, int(key_hex, 16)).public_key()
        loop = asyncio.get_running_loop()
        if live:
            peer.stop_live()
            peer.live = loop.create_task(self._stream(public, None, MEDIA_PFRAME, camera))
            peer.live_camera = camera
            self.max_live_cameras = max(self.max_live_cameras, len(self.live_cameras))
        else:
            task = loop.create_task(
                self._stream(public, self.recording_frames, MEDIA_RECORDING_PFRAME, camera)
            )
            peer.recordings.add(task)
            task.add_done_callback(peer.recordings.discard)

    def _stop_live(self) -> None:
        if (peer := _CURRENT_PEER.get()) is not None:
            peer.stop_live()

    def _stop_media(self) -> None:
        for peer in self._peers.values():
            peer.stop_media()

    async def _stream(
        self, public: rsa.RSAPublicKey, count: int | None, pframe: bytes, camera: int
    ) -> None:
        keyframe = media_keyframe(public, os.urandom(16))
        # Joined mid-GOP, like a real stream: a P-frame comes before the first keyframe.
        clock = MEDIA_CLOCK_START
        self.send_video(pframe, keyframe=False, camera=camera, timestamp_ms=clock)
        sent = 0
        loop = asyncio.get_running_loop()
        self._last_ping = max(self._last_ping, loop.time())
        sizes = self.live_keyframe_sizes if count is None else []
        size = (MEDIA_WIDTH, MEDIA_HEIGHT)
        while count is None or sent < count:
            if (
                count is None
                and self.live_ends_unpinged_after is not None
                and loop.time() - self._last_ping > self.live_ends_unpinged_after
            ):
                return  # as a T8170: an unpinged live stream just stops
            is_key = sent % MEDIA_GOP == 0
            if is_key and sizes:
                size = sizes[min(sent // MEDIA_GOP, len(sizes) - 1)]
            clock += MEDIA_FRAME_MS
            self.send_video(
                keyframe if is_key else pframe,
                keyframe=is_key,
                camera=camera,
                counter=sent + 1,
                timestamp_ms=clock,
                width=size[0],
                height=size[1],
            )
            self.send_frame(
                FrameType.AUDIO_FRAME,
                audio_record(MEDIA_AUDIO, counter=sent + 1, timestamp_ms=clock),
                cipher=0,
                channel=1,
                subheader=_media_subheader(camera),
            )
            sent += 1
            self.media_frames_sent = sent
            await asyncio.sleep(MEDIA_INTERVAL)
        if self.playback_end_delay is not None:
            await asyncio.sleep(self.playback_end_delay)
            self.send_playback_end()

    def send_playback_end(self) -> None:
        """The end-of-playback frame: ``RECORD_PLAY_CTRL`` (0x0402), GCM-tagged, body ``= 2``."""
        body = struct.pack("<IB", PLAYBACK_ENDED, 0)
        subheader = bytes([FrameCipher.GCM, 0, 0xFF, FrameCipher.GCM, 0, 0])
        self.send_frame(
            FrameType.RECORD_PLAY_CTRL, body, cipher=FrameCipher.GCM, channel=2, subheader=subheader
        )

    def send_video(
        self,
        body: bytes,
        *,
        keyframe: bool,
        camera: int = 0,
        counter: int = 0,
        timestamp_ms: int = 0,
        width: int = MEDIA_WIDTH,
        height: int = MEDIA_HEIGHT,
    ) -> None:
        """A video record of the camera on channel ``camera`` (subheader byte 2)."""
        self.send_frame(
            FrameType.VIDEO_FRAME,
            video_record(
                body,
                keyframe=keyframe,
                counter=counter,
                timestamp_ms=timestamp_ms,
                width=width,
                height=height,
            ),
            cipher=0,
            channel=1,
            subheader=_media_subheader(camera),
        )

    # ── outbound ─────────────────────────────────────────────────────────────

    def send_param_dump(self, *, cipher: int = FrameCipher.GCM) -> None:
        def send_block(dev_type: int) -> None:
            params = [
                {"dev_type": dev_type, "param_type": pid, "param_value": value}
                for pid, value in self.params[dev_type].items()
            ]
            body = {"params": params, "main_sw_version": "3.8.7.4"}
            self.send_json(FrameType.PARAM_NOTIFY, body, cipher=cipher)

        subs = [d for d in sorted(self.params) if d != 255]
        # A standalone device has no 255 block: its one block is labelled its device type.
        own = [255] if 255 in self.params else []
        if self.sub_blocks_after is None:
            for dev_type in [*subs, *own]:  # station block last
                send_block(dev_type)
            return
        for dev_type in own:
            send_block(dev_type)
        loop = asyncio.get_running_loop()
        for dev_type in subs:
            loop.call_later(self.sub_blocks_after, send_block, dev_type)

    def push_camera_event(self, event_type: int = 3102, *, cipher: int = FrameCipher.GCM) -> None:
        """An unsolicited camera event (cmd 2037) from the synthetic camera, under ``cipher``."""
        inner = {
            "msg_type": 18,
            "event_type": event_type,
            "device_sn": SYNTHETIC.camera_sn,
            "channel": 0,
            "name": "Front",
            "trigger_time": 1_700_000_000_000,
            "rec_content": [
                {
                    "device_sn": SYNTHETIC.camera_sn,
                    "thumb_path": "/zx/thumb.jpg",
                    "storage_path": "/zx/clip.zxvideo",
                    "station_sn": self.serial,
                    "account": self.account_id,
                }
            ],
        }
        self.send_json(
            FrameType.NOTIFY_PAYLOAD, {"cmd": 2037, "payload": json.dumps(inner)}, cipher=cipher
        )

    def send_storage(self, *, cipher: int = FrameCipher.GCM) -> None:
        """The storage record, as the answer to a query or pushed unasked (0x0547)."""
        payload: dict[str, Any] = {
            "cmd": 11001,
            "version": 0,
            "mIntRet": self.storage_reply_code,
            "msg": "",
            "old_storage_label": "",
            "cur_storage_label": "",
        }
        if self.storage_reply_code == 0:
            payload["body"] = self.storage
        self.send_json(FrameType.NOTIFY_PAYLOAD, {"cmd": 1307, "payload": payload}, cipher=cipher)

    def send_json(
        self,
        ftype: int,
        obj: dict[str, Any],
        channel: int = 1,
        *,
        cipher: int = FrameCipher.GCM,
    ) -> None:
        plain = json.dumps(obj).encode() + b"\x00\x00"
        if cipher == FrameCipher.ECB:
            body = ecb_encrypt(self.static_key, plain)
        else:
            body = self._seal(plain)
        self.send_frame(ftype, body, cipher=cipher, channel=channel)

    def send_zoom_report(self, zoom: float) -> None:
        """The camera's own zoom report (after a go-to or a live open): 6203 ``dstZoom``."""
        self.send_json(
            FrameType.NOTIFY_PAYLOAD,
            {"cmd": 6203, "payload": {"dstZoom": zoom}},
            channel=2,
            cipher=FrameCipher.ECB,
        )

    def send_receipt(self, ftype: int, code: int, *, dev_type: int = 0, delay: float = 0.0) -> None:
        """A command receipt on channel 0: the request's frame type, ``int32le code`` + zeros."""
        body = struct.pack("<i", code) + bytes(self.receipt_len - 4)
        subheader = bytes([FrameCipher.GCM, 0, dev_type, 0, 1, 0])
        if delay > 0:
            asyncio.get_running_loop().call_later(
                delay,
                lambda: self.send_frame(ftype, body, cipher=FrameCipher.GCM, subheader=subheader),
            )
        else:
            self.send_frame(ftype, body, cipher=FrameCipher.GCM, subheader=subheader)

    def send_alarm_mode(self, mode: int, *, cipher: int = FrameCipher.GCM) -> None:
        """A guard-mode report (0x047F): GCM u64-LE, or ECB with the mode as the first u32."""
        if cipher == FrameCipher.ECB:
            body = ecb_encrypt(self.static_key, struct.pack("<I", mode) + bytes(12))
        else:
            body = self._seal(struct.pack("<Q", mode))
        self.send_frame(FrameType.ALARM_MODE_NOTIFY, body, cipher=cipher, channel=2)

    def send_alarm_frame(
        self, ftype: int, *values: int, channel: int, cipher: int = FrameCipher.GCM
    ) -> None:
        """An alarm frame (tone 0x04B1, siren 0x04B2, light 0x0578): u32-LE ``values``
        about ``channel`` (subheader byte 2), on DRW channel 2 as the live station."""
        plain = struct.pack(f"<{len(values)}I", *values)
        if cipher == FrameCipher.ECB:
            body = ecb_encrypt(self.static_key, plain)
            subheader = bytes([cipher, 0, channel, FRAME_STATIC_ECB, 0, 0])
        else:
            body = self._seal(plain)
            subheader = bytes([cipher, 0, channel, 2, 0, 0])
        self.send_frame(ftype, body, cipher=cipher, channel=2, subheader=subheader, sealed=True)

    def _seal(self, plain: bytes) -> bytes:
        """A body under the session's cipher: GCM, or an RSA session's AES-128-ECB."""
        if self.rsa_session:
            return ecb_encrypt(RSA_SESSION_KEY, plain)
        return _gcm_broadcast(self.session_key, plain)

    def send_frame(
        self,
        ftype: int,
        payload: bytes,
        *,
        cipher: int,
        channel: int = 0,
        subheader: bytes | None = None,
        sealed: bool | None = None,
    ) -> None:
        """Send one frame. On an RSA session a GCM-tagged frame goes out ECB-tagged:
        encryption type 2 when its body is sealed (``sealed``; by default when there is
        no ``subheader``), else 0 (clear)."""
        if self.rsa_session and cipher == FrameCipher.GCM and ftype != FrameType.CONN_INIT:
            if sealed is None:
                sealed = subheader is None
            encryption = FRAME_SESSION_ECB if sealed else FRAME_PLAIN
            if subheader is None:
                subheader = bytes([FrameCipher.ECB, 0, 0xFF, encryption, 0, 0])
            else:
                subheader = bytes([FrameCipher.ECB, *subheader[1:3], encryption, *subheader[4:]])
            cipher = FrameCipher.ECB
        frame = encode_frame(ftype, payload, subheader or bytes([cipher, 0, 0xFF, cipher, 0, 0]))
        for peer in self._targets():
            for off in range(0, len(frame), CHUNK):
                index = peer.tx.get(channel, 0)
                peer.tx[channel] = (index + 1) & 0xFFFF
                self._sendto(peer, encode_drw(channel, index, frame[off : off + CHUNK]))

    def send_close(self) -> None:
        """The station closes the session(s) it is addressing (see :meth:`_targets`)."""
        for peer in self._targets():
            self._sendto(peer, encode_packet(MsgType.CLOSE))
            self._drop(peer)

    def _targets(self) -> list[_Peer]:
        """The sessions an outbound frame goes to.

        Inside the handling of a client's traffic (and in the tasks and timers it
        starts), that client's session alone, or nothing once it has closed. Anything
        a test sends directly goes to every open session, as a station push does.
        """
        peer = _CURRENT_PEER.get()
        if peer is None:
            return list(self._peers.values())
        return [peer] if self._peers.get(peer.addr) is peer else []

    def _send(self, packet: bytes) -> None:
        for peer in self._targets():
            self._sendto(peer, packet)

    def _sendto(self, peer: _Peer, packet: bytes) -> None:
        if self._session is not None:
            self._session.sendto(packet, peer.addr)

    def _drop(self, peer: _Peer) -> None:
        """Forget one session and stop what it was streaming."""
        peer.stop_media()
        if self._peers.get(peer.addr) is peer:
            del self._peers[peer.addr]


@dataclass(eq=False)
class _Peer:
    """One client session on the fake station: its DRW counters and its streams."""

    addr: tuple[str, int]
    tx: dict[int, int] = field(default_factory=dict)
    decoders: dict[int, StreamDecoder] = field(default_factory=dict)
    live: asyncio.Task[None] | None = None
    live_camera: int | None = None
    """The channel :attr:`live` streams."""
    recordings: set[asyncio.Task[None]] = field(default_factory=set)

    @property
    def live_streaming(self) -> bool:
        return self.live is not None and not self.live.done()

    @property
    def streaming(self) -> bool:
        return self.live_streaming or any(not task.done() for task in self.recordings)

    def stop_live(self) -> None:
        if self.live is not None:
            self.live.cancel()
            self.live = None

    def stop_media(self) -> None:
        self.stop_live()
        for task in self.recordings:
            task.cancel()
        self.recordings.clear()


_CURRENT_PEER: ContextVar[_Peer | None] = ContextVar("fake_station_peer", default=None)
"""The session whose traffic is being handled; tasks and timers started meanwhile keep it."""


def _stored_report(current: str | None, payload: Mapping[str, Any], plain: str) -> str:
    """What the station reports for a parameter after a payload write.

    As a T8170 does for its per-view quality (2730, as observed on hardware): a parameter that
    already reports base64 JSON ``{"mode_N": {"quality": q}, …}`` keeps that form, with
    the written ``quality`` put into the view the write names (``mode`` 12 → ``mode_1``,
    else ``mode_0``). Any other parameter reports the written value as a plain string.
    """
    if current is None or "quality" not in payload:
        return plain
    try:
        report = json.loads(base64.b64decode(current + "=" * (-len(current) % 4), validate=True))
    except ValueError:
        return plain
    if not isinstance(report, dict):
        return plain
    view = "mode_1" if payload.get("mode") == 12 else "mode_0"
    report[view] = {**(report.get(view) or {}), "quality": int(payload["quality"])}
    return base64.b64encode(json.dumps(report, separators=(",", ":")).encode()).decode()
