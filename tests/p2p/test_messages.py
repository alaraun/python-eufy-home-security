"""Request builders and inbound payload decoders."""

from __future__ import annotations

import base64
import contextlib
import json
import struct
from datetime import date
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.exceptions import ProtocolError, UnsupportedError
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p import _json, crypto, messages
from eufy_home_security.p2p.messages import DB_EVENT_COUNT, event_count_payload
from eufy_home_security.p2p.xzyh import MAGIC, Frame, FrameCipher, FrameType
from eufy_home_security.testing import SYNTHETIC


def test_conn_init_request_is_the_empty_seq1_flags_ff_frame() -> None:
    frame = messages.conn_init_request()
    assert frame[:4] == MAGIC
    assert struct.unpack_from("<H", frame, 4)[0] == 0x044C
    assert struct.unpack_from("<I", frame, 6)[0] == 0  # empty payload
    assert frame[10:16] == b"\x01\x00\xff\x00\x00\x00"  # seq=1, flags=0xFF


@pytest.mark.parametrize(
    ("counter", "dev_type", "flag", "expected"),
    [
        (5, 0xFF, 0, bytes([0x08, 5, 0xFF, 0x08, 0, 0])),
        (10, 1, 0x0A, bytes([0x08, 10, 1, 0x08, 0x0A, 0])),
    ],
)
def test_gcm_subheader_layout(counter: int, dev_type: int, flag: int, expected: bytes) -> None:
    assert messages.gcm_subheader(counter, dev_type=dev_type, flag=flag) == expected


def test_database_command_ids_are_their_reply_frame_types() -> None:
    assert messages.CMD_DATABASE == int(FrameType.DB_SYNC) == 1306
    assert messages.CMD_DATABASE_IMAGE == int(FrameType.MEDIA_DOWNLOAD) == 1308


def test_device_msg_shape() -> None:
    raw = messages.device_msg(SYNTHETIC.account_id, 1224, {"mode_type": 0}, channel=255, value3=7)
    assert json.loads(raw) == {
        "account_id": SYNTHETIC.account_id,
        "cmd": 1224,
        "mChannel": 255,
        "mValue3": 7,
        "payload": {"mode_type": 0},
    }


def test_device_msg_keeps_a_list_payload_and_optional_transaction() -> None:
    doc = json.loads(
        messages.device_msg(SYNTHETIC.account_id, 1308, [{"file": "/x"}], transaction="t")
    )
    assert doc["payload"] == [{"file": "/x"}]
    assert doc["transaction"] == "t"


def test_arm_payload() -> None:
    assert messages.arm_payload(GuardMode.AWAY, "someone") == {
        "mode_type": 0,
        "user_name": "someone",
    }


def test_history_query_payload_matches_the_app_field_set() -> None:
    p = messages.history_query_payload("20260914", "20260915", count=30, transaction="t")
    assert p["cmd"] == messages.DB_QUERY_HISTORY == 10011
    assert p["table"] == "history_record_info"
    assert p["transaction"] == "t"
    inner = p["payload"]
    # the app sends no device_info and string sentinels for the blank id/time fields
    assert "device_info" not in inner
    assert inner["start_time"] == "0"
    assert inner["update_time"] == "0"
    assert inner["alarm_id"] == ""
    assert (inner["count"], inner["start_id"], inner["end_id"], inner["need_ai"]) == (30, 0, 1, 1)


def test_flatten_history_rows_unwraps_nested_payload_and_bare_rows() -> None:
    nested = {
        "cmd": 10011,
        "data": [
            {"payload": [{"record_id": 1}, {"record_id": 2}], "table_name": "history_record_info"},
            {"payload": [{"record_id": 3}]},
            # every page also carries other tables, the person library among them
            {"payload": [{"person_id": 7, "name": "stranger7"}], "table_name": "person_basic_info"},
        ],
    }
    assert [r["record_id"] for r in messages.flatten_history_rows(nested)] == [1, 2, 3]
    assert messages.flatten_history_rows(nested, "person_basic_info") == [
        {"record_id": 3},
        {"person_id": 7, "name": "stranger7"},
    ]
    # a reply that already has bare rows in data is tolerated
    bare = {"cmd": 10011, "data": [{"record_id": 9}]}
    assert messages.flatten_history_rows(bare) == [{"record_id": 9}]
    assert messages.flatten_history_rows({"cmd": 10011}) == []
    # non-object entries (a string-encoded list of ints) are dropped, not dereferenced
    assert messages.flatten_history_rows({"data": "[1,2]"}) == []
    assert messages.flatten_history_rows({"data": [None, "x", {"record_id": 4}]}) == [
        {"record_id": 4}
    ]


def test_database_query_payload_carries_the_mandatory_paging_fields() -> None:
    inner = messages.database_query_payload(["T8160X"], "20260908", "20260911", transaction="1")
    assert inner["cmd"] == messages.DB_QUERY
    assert inner["table"] == "history_record_info"
    assert inner["payload"]["device_info"] == [{"device_sn": "T8160X"}]
    for field in ("start_id", "end_id", "need_ai", "update_time", "alarm_id"):
        assert field in inner["payload"], field
    assert inner["payload"]["start_time"] == "20260908000000"


def test_image_request_payload_is_a_list() -> None:
    assert messages.image_request_payload("/zx/a.jpg") == [{"file": "/zx/a.jpg"}]


def test_is_ecb_scalar() -> None:
    assert messages.is_ecb_scalar(1250)  # value cmd
    assert messages.is_ecb_scalar(1224)  # station cmd
    assert messages.is_ecb_scalar(1210)  # channel-value cmd
    assert not messages.is_ecb_scalar(1167)  # a delay: default handler, not a scalar


def test_encode_ecb_scalar_frame_value_layout() -> None:
    frame = messages.encode_ecb_scalar_frame(
        SYNTHETIC.static_key, 1250, 0, "OWNERID", channel=1, seq=3
    )
    assert frame[:4] == MAGIC
    assert struct.unpack_from("<H", frame, 4)[0] == 1250  # frame type == command id
    assert struct.unpack_from("<I", frame, 6)[0] == 144  # 132 -> padded to 144
    assert frame[10] == FrameCipher.ECB
    assert frame[11] == 3  # seq
    assert frame[12] == 1  # channel
    assert frame[13] == 0x01  # enc flag
    body = crypto.ecb_decrypt(SYNTHETIC.static_key, frame[16:])
    assert struct.unpack_from("<I", body, 0)[0] == 0  # value (no channel prefix)
    assert body[4:11] == b"OWNERID"
    assert body[11] == 0
    # a value command defaults to the station channel
    assert messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1250, 0, "OWNERID")[12] == 255


def test_encode_ecb_scalar_frame_body_layout_follows_the_handler() -> None:
    # channel-value command leads with the channel u32
    pir = messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1210, 6, "OWNERID", channel=1)
    assert pir[12] == 1
    body = crypto.ecb_decrypt(SYNTHETIC.static_key, pir[16:])
    assert struct.unpack_from("<II", body, 0) == (1, 6)  # channel, value
    assert body[8:15] == b"OWNERID"
    # a station command forces channel 255
    station = messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1253, 1, "OWNERID", channel=0)
    assert station[12] == 255


def test_encode_ecb_scalar_frame_rejects_non_scalar_and_bad_caller_input() -> None:
    with pytest.raises(UnsupportedError):
        messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1167, 10, "OWNERID")  # a delay
    with pytest.raises(ValueError, match="channel"):
        messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1250, 0, "OWNERID", channel=51)
    with pytest.raises(ValueError, match="ASCII"):
        messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1250, 0, "öwner")
    with pytest.raises(ValueError, match="127"):
        messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1250, 0, "a" * 128)
    # 127 bytes + the terminating NUL is the largest id that fits
    frame = messages.encode_ecb_scalar_frame(SYNTHETIC.static_key, 1250, 0, "a" * 127)
    body = crypto.ecb_decrypt(SYNTHETIC.static_key, frame[16:])
    assert body[4:131] == b"a" * 127
    assert body[131] == 0


def test_decode_json_payload_tolerates_padding_and_rejects_non_objects() -> None:
    assert messages.decode_json_payload(b'{"cmd":2037}\x00\x00') == {"cmd": 2037}
    assert messages.decode_json_payload(b"not json") is None
    assert messages.decode_json_payload(b"[1,2,3]") is None  # not an object


def test_json_decoders_reject_non_finite_numbers_and_deep_nesting() -> None:
    for text in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
        assert messages.decode_json_payload(text) is None
        with pytest.raises(ProtocolError):
            _json.loads_json(text)
    deep = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    assert messages.decode_json_payload(deep) is None
    with pytest.raises(ProtocolError):
        _json.loads_json(deep)
    assert messages.decode_database_rows({"data": "[" * 100_000}) == []
    limit = _json.MAX_JSON_DEPTH
    assert _json.loads_json("[" * limit + "]" * limit) is not None
    with pytest.raises(ProtocolError):
        _json.loads_json("[" * (limit + 1) + "]" * (limit + 1))
    # brackets inside strings do not count
    nested_text = "[{" * 1000 + '"]'
    assert _json.loads_json(json.dumps({"k": nested_text})) == {"k": nested_text}
    assert _json.loads_json(' {"a": [1]} ') == {"a": [1]}
    with pytest.raises(ProtocolError):
        _json.loads_json('{"a":1} trailing')


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1224, 1224),
        ("1224", 1224),
        ("-6", -6),
        (True, None),
        (1.9, None),
        ("1.9", None),
        (" 1", None),
        ("\u0661", None),
        (None, None),
        ([1], None),
        ("9" * 40, None),
    ],
)
def test_json_int(value: object, expected: int | None) -> None:
    assert _json.json_int(value) == expected


def test_decode_ecb_scalar_result() -> None:
    assert messages.decode_ecb_scalar_result(struct.pack("<i", 0)) == 0
    assert messages.decode_ecb_scalar_result(struct.pack("<i", -104)) == -104
    assert messages.ECB_RESULT_CODES[-104] == "INVALID_ACCOUNT"
    assert messages.ECB_RESULT_CODES[-110] == "INVALID_PARAM"
    with pytest.raises(ProtocolError):
        messages.decode_ecb_scalar_result(b"\x00")


@pytest.mark.parametrize(
    ("ftype", "cipher", "payload", "code"),
    [
        (FrameType.CMD_TRANSFER, FrameCipher.GCM, bytes.fromhex("94ffffff") + bytes(128), -108),
        (FrameType.PARAM_NOTIFY, FrameCipher.GCM, bytes(132), 0),  # the query's receipt
        (0x04E7, FrameCipher.GCM, bytes(132), 0),  # a command-id frame's receipt
        (FrameType.CMD_TRANSFER, FrameCipher.ECB, bytes(132), None),
        (FrameType.CMD_TRANSFER, FrameCipher.GCM, bytes(131), None),
        (FrameType.CMD_TRANSFER, FrameCipher.GCM, bytes(131) + b"\x01", None),  # ciphertext
        (
            FrameType.CMD_TRANSFER,
            FrameCipher.GCM,
            bytes.fromhex("94ffffff") + bytes(32),
            -108,
        ),  # 36-byte receipt
        (
            FrameType.CMD_TRANSFER,
            FrameCipher.GCM,
            bytes.fromhex("94ffffff") + bytes(31) + b"\x01",
            None,
        ),  # 36-byte with non-zero trailing
        (
            FrameType.CMD_TRANSFER,
            FrameCipher.GCM,
            bytes.fromhex("94ffffff") + b"\x01" + bytes(31),
            None,
        ),  # 36-byte with non-zero trailing
    ],
)
def test_decode_command_receipt(ftype: int, cipher: int, payload: bytes, code: int | None) -> None:
    assert {132, 36} == messages.RECEIPT_LENS
    frame = Frame(type=ftype, subheader=bytes([cipher, 0, 0, 0, 1, 0]), payload=payload)
    assert messages.decode_command_receipt(frame) == code


def _alarm_frame(payload: bytes, cipher: int) -> Frame:
    return Frame(type=0x047F, subheader=bytes([cipher, 0x71, 0xFF, 0x02, 0, 0]), payload=payload)


def _gcm_broadcast(session_key: bytes, plaintext: bytes) -> bytes:
    """A base->app GCM frame: tag(16) ‖ nonce(12) ‖ ct (the decrypt_broadcast layout)."""
    nonce = bytes(range(12))
    ct_tag = AESGCM(session_key).encrypt(nonce, plaintext, crypto.GCM_AAD)
    return ct_tag[-16:] + nonce + ct_tag[:-16]


def test_decode_alarm_mode_notify_gcm_reads_u64_under_the_session_key() -> None:
    """The live-verified path: cipher 0x08, 8-byte u64-LE guard mode under the session key."""
    body = struct.pack("<Q", int(GuardMode.HOME))  # 01 00 00 00 00 00 00 00
    frame = _alarm_frame(_gcm_broadcast(SYNTHETIC.session_key, body), FrameCipher.GCM)
    assert messages.decode_alarm_mode_notify(frame, session_key=SYNTHETIC.session_key) == int(
        GuardMode.HOME
    )
    # wrong/absent session key or a failed tag => None, never a bogus value
    assert messages.decode_alarm_mode_notify(frame, session_key=None) is None
    assert messages.decode_alarm_mode_notify(frame, session_key=b"x" * 32) is None


def test_decode_alarm_mode_notify_ecb_reads_the_first_u32_under_the_static_key() -> None:
    """The fallback path: cipher 0x01, first LE u32 under the static serial key."""
    block = struct.pack("<I", int(GuardMode.HOME)) + b"\x7d\x7b\x5a\x6e" + b"\x00" * 8
    frame = _alarm_frame(crypto.ecb_encrypt(SYNTHETIC.static_key, block), FrameCipher.ECB)
    assert messages.decode_alarm_mode_notify(frame, static_key=SYNTHETIC.static_key) == int(
        GuardMode.HOME
    )
    assert messages.decode_alarm_mode_notify(_alarm_frame(b"", FrameCipher.ECB)) is None


def test_decode_database_rows_handles_the_empty_string_and_a_list() -> None:
    assert messages.decode_database_rows({"data": "[]"}) == []
    assert messages.decode_database_rows({"data": [{"x": 1}]}) == [{"x": 1}]
    assert messages.decode_database_rows({"count": 0}) is None  # no data key
    assert messages.decode_database_rows({"data": "not json"}) == []
    assert messages.decode_database_rows({"data": [{"x": 1}, 2, None, [3]]}) == [{"x": 1}]


def test_decode_image_content_uses_urlsafe_base64() -> None:
    raw = b"\xfb\xef\xbe\xff\xd8imag\xff\xd9"  # encodes to "----_9hpbWFn_9k="
    padded = base64.urlsafe_b64encode(raw).decode()
    assert "-" in padded
    assert "_" in padded
    assert messages.decode_image_content({"content": padded}) == raw
    assert messages.decode_image_content({"content": padded.rstrip("=")}) == raw
    assert messages.decode_image_content({"content": f"{padded[:8]}\r\n{padded[8:]}\n"}) == raw
    assert messages.decode_image_content({"file": "/x"}) is None


@pytest.mark.parametrize(
    "content",
    ["!!!=", "", "====", "abcde", "ab+/", " \n"],
    ids=["foreign", "empty", "only-padding", "bad-length", "std-alphabet", "only-whitespace"],
)
def test_decode_image_content_rejects_malformed_content(content: str) -> None:
    with pytest.raises(ProtocolError):
        messages.decode_image_content({"content": content})


def test_decode_image_content_caps_the_size_before_decoding() -> None:
    at_cap = base64.urlsafe_b64encode(b"\x00" * messages.MAX_IMAGE_BYTES).decode()
    assert len(messages.decode_image_content({"content": at_cap}) or b"") == (
        messages.MAX_IMAGE_BYTES
    )
    with pytest.raises(ProtocolError, match="exceeds"):
        messages.decode_image_content({"content": at_cap + "AAAA"})


@given(cmd=st.integers(1, 0xFFFF), value=st.integers(0, 0xFFFFFFFF), channel=st.integers(0, 50))
@settings(max_examples=80)
def test_ecb_scalar_frame_round_trips_the_value(cmd: int, value: int, channel: int) -> None:
    if not messages.is_ecb_scalar(cmd):
        return
    frame = messages.encode_ecb_scalar_frame(
        SYNTHETIC.static_key, cmd, value, SYNTHETIC.account_id, channel=channel
    )
    body = crypto.ecb_decrypt(SYNTHETIC.static_key, frame[16:])
    off = 4 if cmd in messages.ECB_CHANNEL_VALUE_CMDS else 0
    assert struct.unpack_from("<I", body, off)[0] == value


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=40,
)


@given(data=_JSON, as_text=st.booleans())
@settings(max_examples=200)
def test_row_decoders_accept_any_json(data: Any, as_text: bool) -> None:
    value: Any = data
    if as_text:
        with contextlib.suppress(ValueError):
            value = json.dumps(data)  # may contain NaN/Infinity: must be rejected, not raise
    obj = {"data": value}
    rows = messages.decode_database_rows(obj)
    assert rows is not None
    assert all(isinstance(row, dict) for row in rows)
    assert all(isinstance(row, dict) for row in messages.flatten_history_rows(obj))


@given(data=st.binary(max_size=64))
@settings(max_examples=150)
def test_scalar_result_only_raises_protocol_error(data: bytes) -> None:
    with contextlib.suppress(ProtocolError):
        messages.decode_ecb_scalar_result(data)


@pytest.mark.parametrize(
    ("record_id", "expected"),
    [
        (2026091700003, date(2026, 9, 17)),
        (2026010100000, date(2026, 1, 1)),
        (0, None),
        (42, None),
        (2026139900001, None),
        (2026023000001, None),
        (2026022800001, date(2026, 2, 28)),
    ],
)
def test_record_id_day(record_id: int, expected: date | None) -> None:
    assert messages.record_id_day(record_id) == expected


def test_event_count_payload_shape() -> None:
    assert event_count_payload("123") == {
        "cmd": 10013,
        "table": "history_record_info",
        "transaction": "123",
    }
    assert DB_EVENT_COUNT == 10013


def test_a_string_command_body_is_channel_value_and_account_in_fixed_fields() -> None:
    body = messages.string_command_body("JST-9|1.1307", "OWNERID", channel=3)
    assert len(body) == 4 + 1 + 128 + 128
    assert body[:5] == bytes([0, 0, 0, 0, 3])
    assert body[5:17] == b"JST-9|1.1307"
    assert not any(body[17:133])
    assert body[133:140] == b"OWNERID"
    assert messages.decode_string_command_body(body) == (3, "JST-9|1.1307", "OWNERID")


@pytest.mark.parametrize(
    ("value", "channel", "match"),
    [
        ("x" * 128, 0, "field"),
        ("a\x00b", 0, "field"),
        ("Zürich", 0, "ASCII"),
        ("x", 256, "channel"),
    ],
)
def test_a_string_command_body_refuses_what_its_fields_cannot_carry(
    value: str, channel: int, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        messages.string_command_body(value, "OWNERID", channel=channel)


def test_a_short_string_command_body_does_not_decode() -> None:
    with pytest.raises(ValueError, match="short"):
        messages.decode_string_command_body(bytes(100))
