"""Outbound request builders and inbound payload decoders.

The command channel carries a ``DeviceMsgBean`` — a compact JSON object the app
serializes for every command::

    {"account_id", "cmd", "mChannel", "mValue3", "payload"[, "transaction"]}

``account_id`` must be the station **owner's** cloud user id; the station drops,
in silence, a command bearing any other id. Two wire schemes coexist: modern
payload-object commands ride a GCM ``CMD_TRANSFER`` (0x0546) frame, while legacy
plain scalars ride an XZYH frame whose *type is the command id* with an
AES-128-ECB body (see :func:`encode_ecb_scalar_frame`).

Errors: a builder given an argument outside its domain (a bad channel, a
non-ASCII or over-long account id) raises :class:`ValueError`; a decoder given
bytes or JSON from the station that do not decode raises :class:`ProtocolError`
or returns None where its docstring says so — never any other exception.
"""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from ..exceptions import ProtocolError, UnsupportedError
from ..models import STATION_CHANNEL, GuardMode
from . import crypto
from ._json import loads_json, raw_decode_json
from .params import GUARD_MODE_PARAM
from .xzyh import Frame, FrameCipher, FrameType, encode_frame

# ── command ids actually used by the client ──────────────────────────────────

CMD_START_REALTIME_MEDIA = 1003
CMD_STOP_REALTIME_MEDIA = 1004
CMD_DOWNLOAD_VIDEO = 1024
CMD_RECORD_VIEW = 1025
#: Also the parameter id (param_type) that reports the guard mode in a dump.
CMD_SET_ARMING = GUARD_MODE_PARAM
#: The event-database commands; each reply comes back as the XZYH frame type of
#: the same number, which is the canonical definition.
CMD_DATABASE = int(FrameType.DB_SYNC)
CMD_DATABASE_IMAGE = int(FrameType.MEDIA_DOWNLOAD)
CMD_CAMERA_PUSH_NOTIFY = 2037
#: Events-DB query verb (inside a CMD_DATABASE) with an explicit ``device_info``
#: list, used for the ``event_record`` / person tables. On history it returns only
#: a subset of the records.
DB_QUERY = 10000

#: The history-list verb the app uses: with the app's field set
#: (:func:`history_query_payload`) it returns one page of ``count`` records of one
#: day, newest first; ``start_id`` pages back from a ``record_id``.
DB_QUERY_HISTORY = 10011
#: The event-count verb: per device the number of events and the path of the newest
#: event's still (``crop_hb3_path``). A standalone T8170 answers it and not 10011;
#: its handler uses it for ``device_thumbnail_path`` and ``event_data_number``.
DB_EVENT_COUNT = 10013
HISTORY_RECORD_COUNTER = 100_000
"""A ``record_id`` is its day (``YYYYMMDD``) times this, plus a five-digit counter."""
HISTORY_RECORD_ID_MIN = 10_000_000 * HISTORY_RECORD_COUNTER
"""The smallest ``record_id`` that carries a day (day 10000000)."""


def record_id_day(record_id: int) -> date | None:
    """The day a ``record_id`` carries (``YYYYMMDD`` times :data:`HISTORY_RECORD_COUNTER`
    plus a counter), or None when it carries no valid calendar day."""
    if record_id < HISTORY_RECORD_ID_MIN:
        return None
    text = str(record_id // HISTORY_RECORD_COUNTER)
    if len(text) != 8:
        return None
    try:
        return date(int(text[:4]), int(text[4:6]), int(text[6:]))
    except ValueError:
        return None


#: "Get every parameter of every device." Rides a GCM PARAM_NOTIFY (0x044F) frame
#: whose subheader dev_type byte is 0xFF (the station). Two LE u32s: 0xFF, 0x387.
PARAM_QUERY_ALL = bytes.fromhex("ff00000087030000")

#: Largest image a MEDIA_DOWNLOAD reply may carry (decoded bytes).
MAX_IMAGE_BYTES = 1024 * 1024
#: The padded base64 length of a :data:`MAX_IMAGE_BYTES` payload; checked before decoding.
_MAX_IMAGE_B64_LEN = (MAX_IMAGE_BYTES + 2) // 3 * 4
_URLSAFE_TO_STD = str.maketrans("-_", "+/")

#: A command receipt's body length on a HomeBase 3: ``int32le code`` + 128 zero bytes.
RECEIPT_LEN = 132
#: The same receipt from a T8170 standalone camera: ``int32le code`` + 32 zero bytes.
STANDALONE_RECEIPT_LEN = 36
RECEIPT_LENS = frozenset({RECEIPT_LEN, STANDALONE_RECEIPT_LEN})
#: Receipt code: the station took the frame off its channel-0 queue (not "applied").
RECEIPT_TAKEN = 0
#: Receipt code: the station does not handle this command.
RECEIPT_NOT_HANDLED = -108
#: Receipt code: the station tried to wake the camera and failed (the camera's Wi-Fi).
RECEIPT_WAKE_FAILED = -204
#: Receipt codes meaning the camera, not the station, could not be reached.
CAMERA_WAKE_CODES = frozenset({-203, RECEIPT_WAKE_FAILED, -205})
#: Station result codes by name, spelled as in the app's
#: ``com.anker.esiotkit.p2p.constants.P2PErrorCode`` (0, -100..-135, -203..-205); declared.
P2P_ERROR_CODES: dict[int, str] = {
    0: "SUCCESSFUL",
    -100: "NULL_POINT",
    -101: "HAVE_CONNECT",
    -102: "MAX_HUB_CONNECT_NUM",
    -103: "INVALID_COMMAND",
    -104: "INVALID_ACCOUNT",
    -105: "WRITE_FLASH",
    -106: "NOT_FIND_DEV",
    -107: "INVALID_PARAM_LEN",
    -108: "WAIT_TIMEOUT",
    -109: "DEV_OFFLINE",
    -110: "INVALID_PARAM",
    -111: "OPEN_FILE_FAIL",
    -112: "HUB_UPDATEING",
    -113: "DEV_UPDATEING",
    -114: "DEV_BUSY",
    -115: "NOT_FACE",
    -116: "PARAM_NO_CHANGE",
    -117: "POWER_LOW",
    -118: "NOT_TFCARD",
    -119: "TFCARD_FORMATING",
    -120: "GET_EXEC_RESULT",
    -121: "HIGHT_TEMPERATURE",
    -122: "SET_P2P_INFO",
    -123: "MAX_DEV_CONNECT_NUM",
    -124: "PIPE_FAIL",
    -125: "HUB_NON_ADMIN",
    -126: "PPCS_CONNECTING",
    -127: "PLAY_STOP",
    -128: "DEV_CLOSE",
    -129: "MODE_DISABLE",
    -130: "MAX_NAS_CONNECT_NUM",
    -131: "WAKEUP_CAMRA_TYPE",
    -132: "TFCARD_VOLUME_OVERFLOW",
    -133: "COMMAND_TIMEOUT",
    -134: "CONNECT_TIMEOUT",
    -135: "TFCARD_REPAIRING",
    -203: "XM_WIFI_DISCONNECT",
    RECEIPT_WAKE_FAILED: "XM_WIFI_WAKEUP_FAIL",
    -205: "XM_WIFI_TIMEOUT",
}
#: Receipt codes by name. Observed: 0, -108 and -204; 0 and -108 are named for what a
#: receipt means (eufy: ``SUCCESSFUL``, ``WAIT_TIMEOUT``).
RECEIPT_CODES: dict[int, str] = P2P_ERROR_CODES | {
    RECEIPT_TAKEN: "TAKEN",
    RECEIPT_NOT_HANDLED: "NOT_HANDLED",
}


#: Subheader byte 4 of the app's live open (1003); every other client frame has 0.
LIVE_OPEN_SUBHEADER_FLAG = 0x0A


def gcm_subheader(counter: int, dev_type: int = 0, *, flag: int = 0) -> bytes:
    """The 6-byte XZYH subheader for a GCM frame: ``[08, counter, dev_type, 08, flag, 0]``.

    Byte 3 repeats the cipher tag, as in every client frame the app sends.
    ``dev_type`` is the target channel (255 the station): the app puts the command's
    ``mChannel`` there, and a live open (1003) streams the camera it names.
    """
    tag = FrameCipher.GCM
    return bytes([tag, counter & 0xFF, dev_type & 0xFF, tag, flag & 0xFF, 0x00])


def app_ping_frame(counter: int) -> bytes:
    """The app's 1139 PING: an empty frame, subheader ``[01, counter, FF, 0, 0, 0]``.

    The eufy app sends it every 3 s to a standalone device, which answers each on
    channel 2 and ends a live stream it is not pinged on, and about every 20 s to a
    HomeBase 3.
    """
    return encode_frame(FrameType.DEV_STATUS, b"", bytes([0x01, counter & 0xFF, 0xFF, 0, 0, 0]))


def conn_init_request() -> bytes:
    """The complete empty CONN_INIT XZYH frame (seq=1, flags 0xFF), as the app sends it."""
    # subheader = seq u16le (1) ‖ flags u8 (0xFF) ‖ 00 00 00
    subheader = struct.pack("<HB", 1, 0xFF) + b"\x00\x00\x00"
    return encode_frame(FrameType.CONN_INIT, b"", subheader)


def device_msg(
    account_id: str,
    cmd: int,
    payload: Mapping[str, Any] | Sequence[Any],
    *,
    channel: int = 0,
    value3: int = 0,
    transaction: str | None = None,
    media: bool = False,
) -> bytes:
    """Serialize a ``DeviceMsgBean`` command to compact JSON bytes.

    ``payload`` is an object for nearly every command, but a list for the image
    download (cmd 1308 takes ``[{"file": path}]``). ``media`` adds the fields the
    app sends on media commands only: ``mValueStrSub`` (the account id) and
    ``mValue5``.
    """
    obj: dict[str, Any] = {
        "account_id": account_id,
        "cmd": cmd,
        "mChannel": channel,
        "mValue3": value3,
        "payload": payload,
    }
    if media:
        obj["mValueStrSub"] = account_id
        obj["mValue5"] = 0
    if transaction is not None:
        obj["transaction"] = transaction
    return json.dumps(obj, separators=(",", ":")).encode()


def arm_payload(mode: GuardMode, user_name: str) -> dict[str, Any]:
    """The ALARM_MODE (1224) payload object. ``user_name`` is free text."""
    return {"mode_type": int(mode), "user_name": user_name}


def database_query_payload(
    device_sns: Sequence[str],
    start_date: str,
    end_date: str,
    *,
    count: int = 100,
    table: str = "history_record_info",
    transaction: str,
) -> dict[str, Any]:
    """The inner CMD_DATABASE (1306) object, including the mandatory paging fields.

    Without ``start_id`` / ``end_id`` / ``need_ai`` / ``update_time`` / ``alarm_id``
    the station never answers at all — no error, just silence.
    """
    return {
        "cmd": DB_QUERY,
        "payload": {
            "count": count,
            "detection_type": 0,
            "device_info": [{"device_sn": sn} for sn in device_sns],
            "start_date": start_date,
            "end_date": end_date,
            "start_time": f"{start_date}000000",
            "event_type": 0,
            "flag": 0,
            "res_unzip": 1,
            "storage_cloud": -1,
            "ai_type": 0,
            "need_ai": 1,
            "start_id": 0,
            "end_id": 1,
            "update_time": 0,
            "alarm_id": 0,
        },
        "table": table,
        "transaction": transaction,
    }


def event_count_payload(transaction: str) -> dict[str, Any]:
    """The inner CMD_DATABASE (1306) object of an event-count query (10013)."""
    return {"cmd": DB_EVENT_COUNT, "table": "history_record_info", "transaction": transaction}


def history_query_payload(
    start_date: str,
    end_date: str,
    *,
    count: int = 30,
    start_id: int = 0,
    end_id: int = 1,
    table: str = "history_record_info",
    transaction: str,
) -> dict[str, Any]:
    """The inner CMD_DATABASE (1306) object for a history list, verb ``DB_QUERY_HISTORY``.

    Reproduces the field set the eufy app sends: no
    ``device_info`` (all devices at once), and string sentinels for the id/time
    fields it leaves blank. Dates are ``YYYYMMDD``; the app asks for one day as
    ``start_date`` = that day, ``end_date`` = the next. ``start_id`` 0 asks for the
    newest rows; a later page passes the previous reply's ``end_id`` (its oldest
    ``record_id``, which the next page repeats). ``end_id`` stays 1.
    """
    return {
        "cmd": DB_QUERY_HISTORY,
        "payload": {
            "count": count,
            "start_date": start_date,
            "end_date": end_date,
            "start_id": start_id,
            "end_id": end_id,
            "flag": 0,
            "need_ai": 1,
            "res_unzip": 1,
            "update_time": "0",
            "start_time": "0",
            "alarm_id": "",
        },
        "table": table,
        "transaction": transaction,
    }


def flatten_history_rows(
    obj: Mapping[str, Any], table: str = "history_record_info"
) -> list[dict[str, Any]]:
    """The ``table`` rows from a ``DB_QUERY_HISTORY`` (10011) reply.

    Unlike the flat person/face dumps, a history reply nests the records one level
    down: ``data`` is a list of per-table wrappers (``table_name`` + a ``payload``
    list of rows). Besides the requested page of ``history_record_info`` the station
    appends its AI tables (crops, relations, head positions) and the **whole** person,
    face and body libraries to every page, so only the wrappers naming ``table`` (or
    naming no table) are kept. A wrapper that is already a bare row is tolerated.
    """
    records: list[dict[str, Any]] = []
    for entry in decode_database_rows(obj) or []:
        name = entry.get("table_name")
        if name is not None and name != table:
            continue
        inner = entry.get("payload")
        if isinstance(inner, list):
            records.extend(row for row in inner if isinstance(row, dict))
        elif "record_id" in entry:
            records.append(dict(entry))
    return records


def image_request_payload(path: str) -> list[dict[str, str]]:
    """The CMD_DATABASE_IMAGE (1308) payload — a list, unlike every other command."""
    return [{"file": path}]


# ── legacy ECB scalar commands ────────────────────────────────────────────────
#
# The app picks a body handler by command id. A command in none of these handlers
# is not a scalar on this path: the default handler rejects it (-103), and the app
# sends it as a GCM payload-object command instead.

#: Value handler: body = ``[u32 value][char[128] account]``.
ECB_VALUE_CMDS = frozenset({1249, 1250, 1251, 1252})

#: Station handler: same body as ECB_VALUE_CMDS, but the header channel is forced to 255.
ECB_STATION_CMDS = frozenset(
    {
        1029,
        1034,
        1036,
        1043,
        1057,
        1203,
        1218,
        1219,
        1220,
        1221,
        1222,
        1223,
        CMD_SET_ARMING,
        1232,
        1234,
        1235,
        1237,
        1238,
        1248,
        1253,
        1257,
        1269,
        1800,
    }
)

#: Channel + value handler: body = ``[u32 channel][u32 value][char[128] account]``.
ECB_CHANNEL_VALUE_CMDS = frozenset(
    {
        1011,
        1015,
        1017,
        1019,
        1035,
        1045,
        1056,
        1145,
        1146,
        1152,
        1200,
        1207,
        1210,
        1213,
        1214,
        1226,
        1227,
        1229,
        1230,
        1233,
        1236,
        1240,
        1241,
        1243,
        1246,
        1272,
        1273,
        1275,
        1400,
        1401,
        1402,
        1403,
        1408,
        1409,
        1410,
        1412,
        1413,
        1506,
        1507,
        1607,
        1609,
        1610,
        1611,
        1702,
        1703,
        1704,
        1705,
        1706,
        1707,
        1708,
        1709,
    }
)

#: Fixed 128-byte account-id char field appended to every ECB scalar body.
_ECB_ACCOUNT_LEN = 128

#: The result codes a station returns in an ECB scalar reply, with their eufy names.
ECB_RESULT_CODES: dict[int, str] = {
    code: P2P_ERROR_CODES[code] for code in (0, -103, -104, -106, -110)
}


def is_ecb_scalar(cmd: int) -> bool:
    """True if ``cmd`` is sent as a legacy AES-ECB scalar (not a GCM payload object)."""
    return cmd in ECB_VALUE_CMDS or cmd in ECB_STATION_CMDS or cmd in ECB_CHANNEL_VALUE_CMDS


# ── string commands ───────────────────────────────────────────────────────────

#: Commands the app sends as a string frame (its ``msgType 6`` set-with-string handler):
#: frame type = the command id, body :func:`string_command_body`. 1215 is the time zone.
STRING_CMDS = frozenset({1215})
_STRING_FIELD_LEN = 128


def string_command_body(value: str, account_id: str, *, channel: int) -> bytes:
    """The body of a string command: ``u32 0 | u8 channel | char[128] value |
    char[128] account_id``, each string NUL-terminated within its field.

    Raises ``ValueError`` for a channel outside 0..255, or a value or account id that
    is not ASCII or does not fit its field (127 bytes).
    """
    if not 0 <= channel <= STATION_CHANNEL:
        raise ValueError(f"string command channel must be 0..255, got {channel}")
    fields = []
    for name, text in (("value", value), ("account id", account_id)):
        try:
            raw = text.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(f"string command {name} must be ASCII") from None
        if len(raw) >= _STRING_FIELD_LEN or b"\x00" in raw:
            raise ValueError(
                f"string command {name} is {len(raw)} bytes; the field holds "
                f"{_STRING_FIELD_LEN - 1} without NUL"
            )
        fields.append(raw.ljust(_STRING_FIELD_LEN, b"\x00"))
    return bytes(4) + bytes([channel]) + b"".join(fields)


def decode_string_command_body(body: bytes) -> tuple[int, str, str]:
    """``(channel, value, account_id)`` of a :func:`string_command_body`; ValueError when
    ``body`` is not one."""
    if len(body) < 5 + 2 * _STRING_FIELD_LEN:
        raise ValueError("string command body too short")
    channel = body[4]
    value = body[5 : 5 + _STRING_FIELD_LEN].split(b"\x00", 1)[0]
    account = body[5 + _STRING_FIELD_LEN : 5 + 2 * _STRING_FIELD_LEN].split(b"\x00", 1)[0]
    return channel, value.decode("ascii"), account.decode("ascii")


def encode_ecb_scalar_frame(
    static_key: bytes,
    cmd: int,
    value: int,
    account_id: str,
    *,
    channel: int = 255,
    seq: int = 0,
    encryption: int = crypto.FRAME_STATIC_ECB,
) -> bytes:
    """Build a legacy ECB scalar command frame (frame type == the command id).

    Layout: cleartext ``"XZYH" | type=cmd | len | 01 seq channel <encryption> 00 00``
    then an AES-128-ECB body of ``[u32 channel]?[u32 value][char[128] account_id\\0]``
    under ``static_key`` (``encryption`` 1), or under an RSA session's key
    (``encryption`` 2). The channel byte routes to the sub-device (255 = station); the
    account id in the body is what the station authorises against. A command outside
    the scalar handlers raises :class:`UnsupportedError` (the app never sends it this way).

    Raises :class:`ValueError` for a channel outside 0..50/255 or an account id
    that is not ASCII or does not fit the 128-byte NUL-terminated field.
    """
    if not (0 <= channel <= 50 or channel == STATION_CHANNEL):
        raise ValueError(f"ECB scalar channel must be 0..50 or 255, got {channel}")
    try:
        acct = account_id.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("ECB scalar account id must be ASCII") from None
    if len(acct) >= _ECB_ACCOUNT_LEN:
        raise ValueError(
            f"ECB scalar account id is {len(acct)} bytes; the field holds {_ECB_ACCOUNT_LEN - 1}"
        )
    if cmd in ECB_STATION_CMDS:
        channel = STATION_CHANNEL
        prefix = b""
    elif cmd in ECB_CHANNEL_VALUE_CMDS:
        prefix = struct.pack("<I", channel)
    elif cmd in ECB_VALUE_CMDS:
        prefix = b""
    else:
        raise UnsupportedError(
            f"cmd {cmd} is not a legacy ECB scalar; the app sends it as a GCM "
            "payload-object command (or with a layout this builder does not model)"
        )
    body = prefix + struct.pack("<I", value & 0xFFFFFFFF) + acct
    body += b"\x00" * (_ECB_ACCOUNT_LEN - len(acct))
    body_wire = crypto.ecb_encrypt(static_key, body)
    subheader = bytes([FrameCipher.ECB, seq & 0xFF, channel, encryption & 0xFF, 0x00, 0x00])
    return encode_frame(cmd, body_wire, subheader)


# ── inbound payload decoders ──────────────────────────────────────────────────


def decode_json_payload(plain: bytes) -> dict[str, Any] | None:
    """The leading JSON object in ``plain``, tolerating NUL padding and trailing bytes.

    None when there is no object, or it is not strict JSON (NaN/Infinity, nesting
    too deep).
    """
    try:
        obj, _ = raw_decode_json(plain.decode("utf-8", "replace"))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def decode_command_receipt(frame: Frame, *, clear: bool = False) -> int | None:
    """The code of a command receipt, or None when ``frame`` is not one.

    The station answers every GCM frame it takes from channel 0 (a ``0x0546``
    command, the ``0x044F`` parameter query, a command-id frame) with one frame of
    the request's own type on channel 0: GCM-tagged but **not ciphertext**
    (encryption type 0, subheader byte 3), an ``int32le`` code followed by zero bytes
    (:data:`RECEIPT_LENS`: 128 on a HomeBase 3, 32 on a standalone T8170). Check for
    it before any decrypt attempt. With ``clear`` (an RSA session, whose frames carry
    the ECB tag) any frame of encryption type 0 qualifies. It carries no command id,
    and the channel is the caller's to check.
    """
    payload = frame.payload
    if clear:
        tagged = len(frame.subheader) > 3 and frame.subheader[3] == crypto.FRAME_PLAIN
    else:
        tagged = frame.cipher == FrameCipher.GCM
    if not tagged or len(payload) not in RECEIPT_LENS or any(payload[4:]):
        return None
    return int(struct.unpack_from("<i", payload, 0)[0])


def decode_ecb_scalar_result(payload: bytes) -> int:
    """The int32 (LE) result code an ECB scalar reply carries in its first 4 bytes."""
    if len(payload) < 4:
        raise ProtocolError("ECB scalar reply too short for a result code")
    return int(struct.unpack_from("<i", payload, 0)[0])


def decode_alarm_mode_notify(
    frame: Frame, *, static_key: bytes | None = None, session_key: bytes | None = None
) -> int | None:
    """The guard-mode code from an ALARM_MODE (0x047F) notify.

    The station sends this frame under either per-frame cipher, named by subheader
    byte 0 — read it, never assume it:

    * GCM under the session key (0x08): the body is an
      8-byte little-endian u64 whose value is the guard mode (byte 0 holds it),
      same value space as the SET_ARMING command and the FCM ``arming`` field.
    * AES-128-ECB under the static serial key (0x01) — no IV, so a given mode
      always encrypts identically; the first LE u32 is the mode.

    Returns None when the frame's cipher is unknown or its key was not supplied.
    """
    payload = frame.payload
    if frame.cipher == FrameCipher.GCM:
        if session_key is None or len(payload) < 28:
            return None
        try:
            plain = crypto.gcm_decrypt_broadcast(session_key, payload)
        except ProtocolError:
            return None
        return int.from_bytes(plain[:8], "little") if plain else None
    if frame.cipher == FrameCipher.ECB:
        if static_key is None or len(payload) < 16:
            return None
        block = crypto.ecb_decrypt(static_key, payload[:16])
        return int(struct.unpack_from("<I", block, 0)[0])
    return None


def decode_database_rows(obj: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    """The row list from a DB_SYNC reply. The station sends ``"[]"`` (a string) for none.

    Only object rows are returned; anything else in the list is dropped.
    """
    if "data" not in obj:
        return None
    rows = obj["data"]
    if isinstance(rows, str):
        try:
            rows = loads_json(rows)
        except ProtocolError:
            return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def decode_image_content(obj: Mapping[str, Any]) -> bytes | None:
    """The image bytes from a MEDIA_DOWNLOAD reply (URL-safe base64, padding optional).

    ``None`` when the reply carries no string ``content``. Content that is not
    strictly URL-safe base64, decodes to nothing, or would exceed
    :data:`MAX_IMAGE_BYTES` raises :class:`ProtocolError`. ASCII whitespace is
    ignored, so content wrapped in line breaks still decodes.
    """
    blob = obj.get("content")
    if not isinstance(blob, str):
        return None
    return _decode_image_b64(blob, empty_ok=False)


def decode_preset_picture(obj: Mapping[str, Any]) -> bytes | None:
    """The JPEG a 6097 preset-picture notify carries (``{"index", "data"}``).

    ``None`` when the payload has no string ``data``, and ``b""`` when the slot
    holds no picture: an empty ``data`` is the camera's answer for an empty slot,
    not a protocol error (verified on a T8170). Anything else is validated like
    :func:`decode_image_content`.
    """
    blob = obj.get("data")
    if not isinstance(blob, str):
        return None
    return _decode_image_b64(blob, empty_ok=True)


def _decode_image_b64(blob: str, *, empty_ok: bool) -> bytes:
    """Strict URL-safe base64 of an image payload, size-capped."""
    if len(blob) > 2 * _MAX_IMAGE_B64_LEN:
        raise ProtocolError(f"image reply exceeds {MAX_IMAGE_BYTES} bytes")
    blob = "".join(blob.split())
    if not blob and empty_ok:
        return b""
    padded = blob + "=" * (-len(blob) % 4)
    if len(padded) > _MAX_IMAGE_B64_LEN:
        raise ProtocolError(f"image reply exceeds {MAX_IMAGE_BYTES} bytes")
    if "+" in padded or "/" in padded:
        raise ProtocolError("image reply is not URL-safe base64")
    try:
        content = base64.b64decode(padded.translate(_URLSAFE_TO_STD), validate=True)
    except ValueError as err:
        raise ProtocolError("image reply is not valid base64") from err
    if not content and not empty_ok:
        raise ProtocolError("image reply has empty content")
    if len(content) > MAX_IMAGE_BYTES:
        raise ProtocolError(f"image reply exceeds {MAX_IMAGE_BYTES} bytes")
    return content
