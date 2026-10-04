"""MPEG-TS muxing: packet framing, program tables, timestamps."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.p2p.media import VideoCodec, ms_to_pts
from eufy_home_security.p2p.mpegts import (
    AUDIO_PID,
    PMT_PID,
    TS_PACKET_LEN,
    VIDEO_PID,
    TSMuxer,
)


def packets(data: bytes) -> list[bytes]:
    """Split a muxed stream into packets, asserting each is well formed."""
    assert len(data) % TS_PACKET_LEN == 0, "a TS stream is a whole number of packets"
    out = [data[i : i + TS_PACKET_LEN] for i in range(0, len(data), TS_PACKET_LEN)]
    for packet in out:
        assert packet[0] == 0x47, "every packet starts with the sync byte"
    return out


def pid_of(packet: bytes) -> int:
    return ((packet[1] & 0x1F) << 8) | packet[2]


def test_pat_and_pmt_are_single_well_formed_packets() -> None:
    mux = TSMuxer()
    pat, pmt = packets(mux.pat()), packets(mux.pmt())
    assert len(pat) == 1
    assert len(pmt) == 1
    assert pid_of(pat[0]) == 0x0000
    assert pid_of(pmt[0]) == PMT_PID
    # Both carry a payload-unit start and a pointer field of zero.
    for packet in (pat[0], pmt[0]):
        assert packet[1] & 0x40, "payload_unit_start_indicator"
        assert packet[4] == 0x00, "pointer_field"


def test_pmt_declares_the_codecs_stream_type() -> None:
    """HEVC is stream type 0x24, H.264 0x1B (ISO/IEC 13818-1)."""
    assert 0x24 in packets(TSMuxer(VideoCodec.HEVC).pmt())[0]
    assert 0x1B in packets(TSMuxer(VideoCodec.H264).pmt())[0]


def test_continuity_counters_advance_and_wrap() -> None:
    """A decoder reads a counter gap as lost packets, so they must be contiguous."""
    mux = TSMuxer()
    seen = [packets(mux.pat())[0][3] & 0x0F for _ in range(20)]
    assert seen == [i & 0x0F for i in range(20)], "PAT counter wraps at 16"

    mux = TSMuxer()
    counters = [
        packet[3] & 0x0F
        for i in range(6)
        for packet in packets(mux.video(b"\x00" * 400, 90_000 + i * 6000, keyframe=False))
    ]
    assert counters == [i & 0x0F for i in range(len(counters))]


def test_video_packets_carry_the_pid_and_start_flag() -> None:
    mux = TSMuxer()
    got = packets(mux.video(b"\xde\xad\xbe\xef" * 100, 90_000, keyframe=True))
    assert all(pid_of(p) == VIDEO_PID for p in got)
    assert got[0][1] & 0x40, "the first packet of an access unit starts a payload unit"
    assert not any(p[1] & 0x40 for p in got[1:]), "continuation packets do not"


def test_a_keyframe_carries_a_pcr_and_the_random_access_indicator() -> None:
    """A decoder joining mid-stream needs a clock reference and a start point."""
    mux = TSMuxer()
    first = packets(mux.video(b"\x01" * 500, 90_000, keyframe=True))[0]
    assert first[3] & 0x30 == 0x30, "adaptation field present"
    assert first[5] & 0x40, "random_access_indicator"
    assert first[5] & 0x10, "PCR_flag"

    pframe = packets(mux.video(b"\x01" * 500, 96_000, keyframe=False))[0]
    if pframe[3] & 0x20 and pframe[4]:
        assert not pframe[5] & 0x40, "a P-frame is not a random access point"
        assert not pframe[5] & 0x10, "and carries no PCR"


def test_pts_is_encoded_where_a_decoder_looks_for_it() -> None:
    mux = TSMuxer()
    pts = 1_234_567
    payload = packets(mux.video(b"\x00" * 100, pts, keyframe=False))[0]
    start = payload.index(b"\x00\x00\x01\xe0")
    field = payload[start + 9 : start + 14]
    decoded = (
        ((field[0] >> 1) & 0x07) << 30
        | field[1] << 22
        | ((field[2] >> 1) & 0x7F) << 15
        | field[3] << 7
        | ((field[4] >> 1) & 0x7F)
    )
    assert decoded == pts
    assert field[0] >> 4 == 0b0010, "PTS-only marker"


def test_timestamps_are_clamped_monotonic() -> None:
    """The camera's clock steps backwards; a decoder will not accept that.

    Seen live: successive frames whose header clock goes back a millisecond or two,
    which makes ffmpeg report "Invalid DTS ... replacing by guess". Pinning a backwards
    timestamp to its predecessor keeps the stream monotonic, and repeated timestamps are
    something decoders handle.
    """
    mux = TSMuxer()
    assert mux.next_pts(90_000) == 90_000
    assert mux.next_pts(96_000) == 96_000
    assert mux.next_pts(95_820) == 96_000, "a step backwards is pinned, not passed on"
    assert mux.next_pts(96_000) == 96_000
    assert mux.next_pts(102_000) == 102_000, "forward progress resumes"


def test_muxing_never_emits_a_backwards_timestamp() -> None:
    mux = TSMuxer()
    # A backwards step of 150 ticks (under 2 ms), the size the camera's clock makes.
    mux.video(b"\x00" * 50, 96_000, keyframe=True)
    out = packets(mux.video(b"\x00" * 50, 95_850, keyframe=False))
    payload = out[0]
    start = payload.index(b"\x00\x00\x01\xe0")
    field = payload[start + 9 : start + 14]
    decoded = (
        ((field[0] >> 1) & 0x07) << 30
        | field[1] << 22
        | ((field[2] >> 1) & 0x7F) << 15
        | field[3] << 7
        | ((field[4] >> 1) & 0x7F)
    )
    assert decoded == 96_000


def test_an_access_unit_delimiter_precedes_the_frame() -> None:
    """HEVC in TS needs an AUD; the codec decides which one."""
    hevc = TSMuxer(VideoCodec.HEVC).video(b"\xaa" * 20, 90_000, keyframe=False)
    assert b"\x00\x00\x00\x01\x46\x01\x50" in hevc
    h264 = TSMuxer(VideoCodec.H264).video(b"\xaa" * 20, 90_000, keyframe=False)
    assert b"\x00\x00\x00\x01\x09\xf0" in h264


def test_the_frame_bytes_survive_muxing() -> None:
    """Whatever the camera sent must come out again: parameter sets, IDR and all."""
    frame = bytes((i * 31) & 0xFF for i in range(5000))
    data = TSMuxer().video(frame, 90_000, keyframe=True)
    payload = bytearray()
    for packet in packets(data):
        offset = 4
        if packet[3] & 0x20:  # adaptation field present
            offset += 1 + packet[4]
        payload += packet[offset:]
    assert frame in bytes(payload)


def test_the_pmt_declares_audio_only_when_asked() -> None:
    """A track cannot be added later: consumers do not re-read the PMT."""
    silent = packets(TSMuxer().pmt())[0]
    with_audio = packets(TSMuxer(audio=True).pmt())[0]
    assert 0x0F not in silent[5:], "no AAC stream type when there is no audio track"
    assert 0x0F in with_audio[5:], "ADTS AAC is stream type 0x0F"
    assert not TSMuxer().has_audio
    assert TSMuxer(audio=True).has_audio


def test_audio_packets_carry_their_own_pid_and_counter() -> None:
    mux = TSMuxer(audio=True)
    frame = b"\xff\xf1" + b"\x00" * 200
    got = packets(mux.audio(frame, 90_000))
    assert all(pid_of(p) == AUDIO_PID for p in got)
    assert got[0][1] & 0x40, "the first packet starts a payload unit"
    # The audio counter advances independently of the video one.
    mux.video(b"\x00" * 300, 90_000, keyframe=True)
    again = packets(mux.audio(frame, 95_760))
    assert (again[0][3] & 0x0F) == (got[-1][3] & 0x0F) + 1


def test_an_audio_pes_declares_its_length() -> None:
    """Video PES is unbounded; audio is small and bounded, and demuxers rely on it."""
    frame = b"\xff\xf1" + b"\x11" * 190
    data = TSMuxer(audio=True).audio(frame, 90_000)
    start = data.index(b"\x00\x00\x01\xc0")
    declared = int.from_bytes(data[start + 4 : start + 6], "big")
    assert declared == 8 + len(frame), "PES header (3+5) plus the payload"


def test_the_audio_frame_bytes_survive_muxing() -> None:
    frame = bytes([0xFF, 0xF1]) + bytes((i * 13) & 0xFF for i in range(600))
    data = TSMuxer(audio=True).audio(frame, 90_000)
    payload = bytearray()
    for packet in packets(data):
        offset = 4
        if packet[3] & 0x20:
            offset += 1 + packet[4]
        payload += packet[offset:]
    assert frame in bytes(payload)


def test_the_two_tracks_are_clamped_independently() -> None:
    """One track's timestamp must never drag the other's, or lip sync is lost."""
    mux = TSMuxer(audio=True)
    assert mux.next_pts(180_000) == 180_000
    # Audio legitimately lags video; it must not be pulled forward to the video clock.
    assert mux.next_pts(90_000, audio=True) == 90_000
    assert mux.next_pts(95_760, audio=True) == 95_760
    # And a backwards step on the audio track is still clamped, on its own timeline.
    assert mux.next_pts(95_000, audio=True) == 95_760
    assert mux.next_pts(186_000) == 186_000


def test_audio_carries_no_pcr() -> None:
    """The clock lives on the video PID; two PCR sources would fight.

    A short audio frame is padded out with an adaptation field, so the presence of the
    field says nothing — only a field longer than its length byte carries flags.
    """
    for size in (50, 400, 1200):
        data = packets(TSMuxer(audio=True).audio(b"\xff\xf1" + b"\x00" * size, 90_000))
        for packet in data:
            if not packet[3] & 0x20:
                continue
            field_len = packet[4]
            if field_len == 0:
                continue  # a length byte and nothing else
            assert not packet[5] & 0x10, "no PCR_flag on audio"


def test_stuffing_never_looks_like_adaptation_flags() -> None:
    """A padded packet must not claim flags it does not carry.

    An adaptation field of one byte or more begins with its flags byte. Filling the
    whole field with 0xff (the natural "pad with stuffing" choice) sets every flag,
    including PCR_flag, so a decoder reads the next six stuffing bytes as a clock
    reference. This affects the last packet of almost every frame, video and audio
    alike, because that is where the padding lands.
    """
    mux = TSMuxer(audio=True)
    streams = [
        mux.video(b"\x00" * size, 90_000 + i * 3000, keyframe=i % 3 == 0)
        for i, size in enumerate((40, 190, 400, 1000))
    ]
    streams += [mux.audio(b"\xff\xf1" + b"\x00" * size, 95_000) for size in (30, 190, 700)]
    for stream in streams:
        for packet in packets(stream):
            if not packet[3] & 0x20:
                continue
            field_len = packet[4]
            if field_len == 0:
                continue
            flags = packet[5]
            if flags & 0x10:  # PCR_flag: only ever set on a keyframe's first packet
                assert packet[1] & 0x40, "a PCR may only ride the first packet of a unit"
                assert pid_of(packet) == VIDEO_PID, "the PCR lives on the video PID"
            assert not flags & 0x08, "no OPCR"
            assert not flags & 0x04, "no splicing point"
            assert not flags & 0x02, "no transport private data"
            assert not flags & 0x01, "no adaptation field extension"


def test_the_random_access_indicator_marks_only_keyframes() -> None:
    """It means "a decoder may start here", which is true only of a keyframe.

    Setting it on P-frames invites a decoder to start on one and render the macroblock
    garbage that follows until the next IDR.
    """
    mux = TSMuxer()
    key = packets(mux.video(b"\x00" * 300, 90_000, keyframe=True))[0]
    assert key[3] & 0x20, "adaptation field present"
    assert key[4], "and long enough to carry flags"
    assert key[5] & 0x40, "a keyframe is a random access point"

    pframe = packets(mux.video(b"\x00" * 300, 96_000, keyframe=False))[0]
    if pframe[3] & 0x20 and pframe[4]:
        assert not pframe[5] & 0x40, "a P-frame is not a random access point"


def test_a_clock_wrap_is_passed_through_not_clamped() -> None:
    """Clamping a wrap would freeze the stream at the pre-wrap timestamp forever.

    Two wraps are certain: the 33-bit PES timestamp turns over every 26.5 hours, and
    the station's u32 millisecond clock every 49.7 days of uptime.
    """
    mux = TSMuxer()
    mux.next_pts((1 << 33) - 1000)
    assert mux.next_pts(500) == 500, "the 33-bit PES clock wrapped"

    mux = TSMuxer()
    mux.next_pts(ms_to_pts(4_294_967_000))  # the station clock near its u32 limit
    assert mux.next_pts(ms_to_pts(1_000)) == ms_to_pts(1_000), "the station clock wrapped"

    # Jitter is still clamped: only a large step backwards counts as a wrap.
    mux = TSMuxer()
    mux.next_pts(96_000)
    assert mux.next_pts(95_820) == 96_000


@pytest.mark.parametrize("keyframe", [False, True])
@given(size=st.integers(min_value=1, max_value=4000))
@settings(max_examples=250, deadline=None)
def test_every_frame_size_packs_into_whole_packets(size: int, *, keyframe: bool) -> None:
    """The property that matters: no payload size may produce an oversized packet.

    A tail of exactly 183 bytes is the edge case: a negative stuffing length would make
    it a 189-byte packet. One oversized packet desyncs every packet after it, which a
    decoder shows as corruption at the end of the picture.
    """
    packets(TSMuxer().video(b"\x00" * size, 90_000, keyframe=keyframe))


@given(size=st.integers(min_value=1, max_value=2000))
@settings(max_examples=250, deadline=None)
def test_every_audio_size_packs_into_whole_packets(size: int) -> None:
    packets(TSMuxer(audio=True).audio(b"\xff\xf1" + b"\x00" * size, 90_000))
