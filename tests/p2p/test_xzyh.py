"""XZYH framing and the incremental StreamDecoder."""

from __future__ import annotations

import random
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security import models
from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p.xzyh import (
    HEADER_LEN,
    MAGIC,
    MAX_FRAME_LEN,
    Frame,
    FrameCipher,
    FrameType,
    StreamDecoder,
    encode_frame,
)


def _sub(cipher: int = FrameCipher.GCM) -> bytes:
    return bytes([cipher, 0, 0, 0, 0, 0])


def _chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]


def test_encode_frame_layout() -> None:
    frame = encode_frame(FrameType.CONN_INIT, b"payload_bytes", _sub(FrameCipher.ECB))
    assert frame[:4] == MAGIC
    assert struct.unpack_from("<H", frame, 4)[0] == FrameType.CONN_INIT
    assert struct.unpack_from("<I", frame, 6)[0] == len(b"payload_bytes")
    assert frame[16:] == b"payload_bytes"


def test_encode_frame_rejects_wrong_subheader_length() -> None:
    with pytest.raises(ProtocolError):
        encode_frame(FrameType.CONN_INIT, b"", b"\x00" * 5)


def test_frame_cipher_property() -> None:
    assert Frame(type=1, subheader=_sub(FrameCipher.ECB), payload=b"").cipher == FrameCipher.ECB
    assert Frame(type=1, subheader=b"", payload=b"").cipher is None


def test_frame_cipher_is_the_canonical_models_enum() -> None:
    assert FrameCipher is models.FrameCipher


def test_reassembles_a_frame_split_across_ordered_chunks() -> None:
    frame = encode_frame(FrameType.PARAM_NOTIFY, b"x" * 40, _sub())
    dec = StreamDecoder()
    out: list[Frame] = []
    for i, chunk in enumerate(_chunks(frame, 7)):
        out += dec.feed(i, chunk)
    assert len(out) == 1
    assert out[0].payload == b"x" * 40


def test_buffers_out_of_order_chunks_until_contiguous() -> None:
    frame = encode_frame(FrameType.DB_SYNC, b"payload_bytes", _sub())
    dec = StreamDecoder()
    assert dec.feed(1, frame[5:]) == []  # tail first: nothing yet
    out = dec.feed(0, frame[:5])
    assert len(out) == 1
    assert out[0].payload == b"payload_bytes"


def test_ignores_duplicate_and_already_consumed_indices() -> None:
    frame = encode_frame(FrameType.DB_SYNC, b"abcdefgh", _sub())
    dec = StreamDecoder()
    a, b = frame[:6], frame[6:]
    assert dec.feed(0, a) == []
    assert len(dec.feed(1, b)) == 1
    # re-deliver both consumed chunks: nothing new emitted
    assert dec.feed(0, a) == []
    assert dec.feed(1, b) == []


def test_two_frames_in_one_stream_emit_in_order() -> None:
    f1 = encode_frame(FrameType.CONN_INIT, b"first", _sub())
    f2 = encode_frame(FrameType.NOTIFY_PAYLOAD, b"second", _sub())
    dec = StreamDecoder()
    out: list[Frame] = []
    for i, chunk in enumerate(_chunks(f1 + f2, 4)):
        out += dec.feed(i, chunk)
    assert [f.payload for f in out] == [b"first", b"second"]


def test_index_wraparound() -> None:
    frame = encode_frame(FrameType.CONN_INIT, b"wrapped", _sub())
    dec = StreamDecoder(first_index=0xFFFF)
    out: list[Frame] = []
    idx = 0xFFFF
    for chunk in _chunks(frame, 6):
        out += dec.feed(idx, chunk)
        idx = (idx + 1) & 0xFFFF  # 0xFFFF -> 0
    assert len(out) == 1
    assert out[0].payload == b"wrapped"


def test_resync_after_garbage_between_frames() -> None:
    good = encode_frame(FrameType.CONN_INIT, b"ok", _sub())
    dec = StreamDecoder()
    stream = b"\x00\x01\x02garbage" + good
    out: list[Frame] = []
    for i, chunk in enumerate(_chunks(stream, 5)):
        out += dec.feed(i, chunk)
    assert len(out) == 1
    assert out[0].payload == b"ok"


def test_first_index_none_adopts_the_first_index_seen() -> None:
    frame = encode_frame(FrameType.CONN_INIT, b"adopted", _sub())
    dec = StreamDecoder(first_index=None)
    out: list[Frame] = []
    idx = 500
    for chunk in _chunks(frame, 6):
        out += dec.feed(idx, chunk)
        idx += 1
    assert len(out) == 1
    assert out[0].payload == b"adopted"


def test_exceeding_max_pending_raises() -> None:
    dec = StreamDecoder(max_pending=4)
    for i in range(1, 5):  # four pending future chunks (index 0 never delivered)
        dec.feed(i, b"x")
    with pytest.raises(ProtocolError):
        dec.feed(5, b"x")  # the fifth exceeds max_pending


def test_reassembly_is_bounded_in_bytes_not_only_in_chunks() -> None:
    """A lost chunk must not let the buffer grow to the chunk count times the MTU.

    Counting chunks alone bounds memory at ``max_pending`` whole UDP payloads —
    hundreds of megabytes, which is an out-of-memory kill on a small host. One lost
    chunk on the media channel is routine on UDP, and a session holds one decoder per
    channel byte taken off the wire.
    """
    dec = StreamDecoder(max_frame_len=4096, max_pending=100_000)
    chunk = b"x" * 60_000

    def feed_until_it_gives_up() -> None:
        for index in range(1, 1000):  # index 0 never arrives
            dec.feed(index, chunk)

    with pytest.raises(ProtocolError, match="buffered more than"):
        feed_until_it_gives_up()
    assert dec._pending_bytes <= 4096 + 60_000 + len(chunk), (
        "the guard fires within one frame plus one chunk of the budget"
    )


def test_a_completed_run_releases_its_buffered_bytes() -> None:
    """The byte count must fall as chunks are consumed, or it only ever ratchets up."""
    dec = StreamDecoder(max_frame_len=4096)
    body = b"v" * 64
    frame = encode_frame(FrameType.CONN_INIT, body, _sub())
    dec.feed(1, frame[10:])  # out of order: buffered
    assert dec._pending_bytes > 0
    out = dec.feed(0, frame[:10])  # completes the run
    assert [f.payload for f in out] == [body]
    assert dec._pending_bytes == 0, "consumed chunks are no longer counted"


def test_reset_clears_buffered_state() -> None:
    frame = encode_frame(FrameType.CONN_INIT, b"body", _sub())
    dec = StreamDecoder()
    dec.feed(1, frame[3:])  # a pending tail
    dec.reset()
    out: list[Frame] = []
    for i, chunk in enumerate(_chunks(frame, 6)):
        out += dec.feed(i, chunk)
    assert len(out) == 1
    assert out[0].payload == b"body"


def test_an_oversize_length_header_is_skipped_and_the_stream_recovers() -> None:
    assert MAX_FRAME_LEN >= 4 * 1024 * 1024  # well above a ~1 MiB 4K keyframe
    false_header = MAGIC + struct.pack("<HI", FrameType.DB_SYNC, 0xFFFFFFF0) + _sub()
    good = [
        encode_frame(FrameType.CONN_INIT, b"one", _sub()),
        encode_frame(FrameType.NOTIFY_PAYLOAD, b"two", _sub()),
    ]
    dec = StreamDecoder()
    out: list[Frame] = []
    for i, chunk in enumerate(_chunks(false_header + b"".join(good), 5)):
        out += dec.feed(i, chunk)
    assert [f.payload for f in out] == [b"one", b"two"]


def test_a_frame_at_the_length_limit_is_still_accepted() -> None:
    frame = encode_frame(FrameType.VIDEO_FRAME, b"v" * 64, _sub())
    dec = StreamDecoder(max_frame_len=64)
    assert [f.payload for f in dec.feed(0, frame)] == [b"v" * 64]
    over = StreamDecoder(max_frame_len=63)
    assert over.feed(0, frame) == []  # 65-byte claim: treated as a false header


def test_buffer_growth_past_the_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate a resync regression that stops trimming: the cap is the backstop.
    monkeypatch.setattr(StreamDecoder, "_resync", lambda self: False)
    dec = StreamDecoder(max_frame_len=32)
    for i in range(3):  # 48 bytes: exactly header + max_frame_len, still allowed
        assert dec.feed(i, b"\x00" * 16) == []
    with pytest.raises(ProtocolError):
        dec.feed(3, b"\x00" * 16)


@given(
    pieces=st.lists(
        st.one_of(
            st.binary(max_size=24).map(lambda p: encode_frame(FrameType.DB_SYNC, p, _sub())),
            st.tuples(st.integers(0, 0xFFFFFFFF), st.binary(max_size=8)).map(
                lambda t: MAGIC + struct.pack("<HI", FrameType.DB_SYNC, t[0]) + t[1]
            ),
            st.binary(max_size=16),
        ),
        max_size=20,
    ),
    chunk_size=st.integers(1, 17),
)
@settings(max_examples=150)
def test_random_false_headers_keep_the_buffer_bounded(pieces: list[bytes], chunk_size: int) -> None:
    limit = 64
    dec = StreamDecoder(max_frame_len=limit)
    for i, chunk in enumerate(_chunks(b"".join(pieces), chunk_size)):
        for frame in dec.feed(i, chunk):
            assert len(frame.payload) <= limit
        assert len(dec._buf) <= HEADER_LEN + limit


# ── property: shuffled / duplicated delivery still yields every frame once ────

_PAYLOADS = st.lists(st.binary(min_size=0, max_size=30), min_size=1, max_size=6)


@given(payloads=_PAYLOADS, chunk_size=st.integers(1, 9), seed=st.integers(0, 1_000_000))
@settings(max_examples=120)
def test_shuffled_duplicated_delivery_recovers_all_frames(
    payloads: list[bytes], chunk_size: int, seed: int
) -> None:
    frames = [encode_frame(FrameType.DB_SYNC, p, _sub()) for p in payloads]
    stream = b"".join(frames)
    indexed = list(enumerate(_chunks(stream, chunk_size)))

    rng = random.Random(seed)
    delivery = list(indexed)
    delivery.extend(rng.choice(indexed) for _ in range(rng.randint(0, len(indexed))))
    rng.shuffle(delivery)

    dec = StreamDecoder(max_pending=len(indexed) + 8)
    out: list[Frame] = []
    for idx, chunk in delivery:
        out += dec.feed(idx, chunk)
    assert [f.payload for f in out] == payloads


@given(chunks=st.lists(st.binary(max_size=32), min_size=1, max_size=20))
@settings(max_examples=150)
def test_decoder_only_raises_protocol_error_on_garbage(chunks: list[bytes]) -> None:
    dec = StreamDecoder(max_pending=64)
    try:
        for i, chunk in enumerate(chunks):
            for frame in dec.feed(i, chunk):
                assert isinstance(frame.payload, bytes)
                assert len(frame.subheader) == HEADER_LEN - 10
    except ProtocolError:
        pass
