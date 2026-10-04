"""Stream encoding: the settle gate that hides a camera's opening resolution ramp."""

from __future__ import annotations

from eufy_home_security.p2p.encoder import SILENT_AAC_FRAME, SILENT_AAC_FRAME_MS, StreamEncoder
from eufy_home_security.p2p.media import MediaFrame, MediaKind, VideoCodec
from eufy_home_security.p2p.mpegts import AUDIO_PID, TS_PACKET_LEN


class FakeClock:
    """A clock the test drives, so settle timing needs no sleeping."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def video(
    width: int = 2304,
    height: int = 1296,
    *,
    keyframe: bool = False,
    ms: int = 1000,
    data: bytes = b"\x00\x00\x00\x01\x26\x01payload",
) -> MediaFrame:
    return MediaFrame(
        MediaKind.VIDEO,
        data,
        is_keyframe=keyframe,
        timestamp_ms=ms,
        codec=VideoCodec.HEVC,
        width=width,
        height=height,
    )


def test_audio_frames_are_ignored() -> None:
    enc = StreamEncoder(clock=FakeClock())
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aac", timestamp_ms=1000)
    out = enc.feed(audio)
    assert out.data == b""
    assert not out.started


def test_the_stream_waits_for_the_size_to_settle_then_starts_on_a_keyframe() -> None:
    clock = FakeClock()
    enc = StreamEncoder(settle=6.0, clock=clock)

    # A keyframe at the opening size is not enough: the size has not held yet.
    assert not enc.feed(video(3840, 2160, keyframe=True)).started
    clock.advance(0.6)
    # The camera steps down; the settle window restarts at the new size.
    assert not enc.feed(video(2304, 1296, keyframe=True)).started
    clock.advance(3.0)
    assert not enc.feed(video(2304, 1296, keyframe=True)).started, "still inside settle"
    clock.advance(3.1)
    # Settled, but a P-frame cannot open a stream.
    assert not enc.feed(video(2304, 1296)).started
    out = enc.feed(video(2304, 1296, keyframe=True))
    assert out.started
    assert out.data
    assert enc.started
    assert enc.size == (2304, 1296)


def test_a_climbing_ramp_settles_too() -> None:
    """A standalone battery camera climbs 720p -> 1080p -> 2880x1616 over ~10 s."""
    clock = FakeClock()
    enc = StreamEncoder(settle=6.0, clock=clock)
    for width, height, delay in ((1280, 720, 5.4), (1920, 1080, 4.2), (2880, 1616, 0.0)):
        assert not enc.feed(video(width, height, keyframe=True)).started
        clock.advance(delay)
    clock.advance(6.1)
    assert enc.feed(video(2880, 1616, keyframe=True)).started
    assert enc.size == (2880, 1616)


def _start(clock: FakeClock, enc: StreamEncoder) -> None:
    enc.feed(video(keyframe=True))
    clock.advance(enc.settle + 0.1)
    assert enc.feed(video(keyframe=True, ms=1000)).started


def test_a_size_change_after_the_start_is_reported_not_muxed() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock)
    _start(clock, enc)
    out = enc.feed(video(1920, 1080, keyframe=True, ms=1040))
    assert out.resized
    assert out.data == b"", "nothing is muxed at the new size"


def test_a_followed_size_change_resumes_at_the_next_keyframe() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, follow_resize=True)
    _start(clock, enc)
    dropped = enc.feed(video(1920, 1080, keyframe=False, ms=1040))
    assert not dropped.resized
    assert dropped.data == b"", "a P-frame at the new size has no reference"
    resumed = enc.feed(video(1920, 1080, keyframe=True, ms=1080))
    assert resumed.restarted
    assert resumed.data
    assert enc.size == (1920, 1080)
    assert enc.resizes == 1
    assert enc.feed(video(1920, 1080, ms=1120)).data, "the stream carries on"


def test_a_followed_resize_repeats_the_tables_and_becomes_the_header() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, follow_resize=True, tables_every=1000)
    _start(clock, enc)
    enc.feed(video(ms=1040))
    resumed = enc.feed(video(1920, 1080, keyframe=True, ms=1080))
    pids = {
        ((resumed.data[o + 1] & 0x1F) << 8) | resumed.data[o + 2]
        for o in range(0, len(resumed.data), TS_PACKET_LEN)
    }
    assert 0x0000 in pids, "a PAT precedes the resuming keyframe"
    assert enc.header == resumed.data


def test_a_followed_resize_keeps_the_continuity_counters() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, follow_resize=True, tables_every=1000)
    _start(clock, enc)
    before = enc.feed(video(ms=1040)).data
    after = enc.feed(video(1920, 1080, keyframe=True, ms=1080)).data

    def video_cc(ts: bytes) -> list[int]:
        return [
            ts[o + 3] & 0x0F
            for o in range(0, len(ts), TS_PACKET_LEN)
            if ((ts[o + 1] & 0x1F) << 8) | ts[o + 2] == 0x0100
        ]

    assert video_cc(after)[0] == (video_cc(before)[-1] + 1) % 16, "one muxer, no CC jump"


def test_audio_flows_while_a_followed_resize_waits_for_a_keyframe() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True, follow_resize=True)
    enc.feed(MediaFrame(MediaKind.AUDIO, b"\xff\xf1" + b"\x00" * 20, timestamp_ms=990))
    _start(clock, enc)
    enc.feed(video(1920, 1080, ms=1040))
    audio = enc.feed(MediaFrame(MediaKind.AUDIO, b"\xff\xf1" + b"\x00" * 20, timestamp_ms=1050))
    assert audio.data


def test_a_known_audio_track_need_not_reappear_in_the_settle_window() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True, assume_audio=True)
    _start(clock, enc)
    assert enc.has_audio


def test_the_header_replays_tables_and_the_opening_keyframe() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock)
    assert enc.header == b""
    _start(clock, enc)
    assert enc.header
    assert len(enc.header) % TS_PACKET_LEN == 0
    assert enc.header[0] == 0x47


def test_tables_are_repeated_so_a_late_joiner_can_tune_in() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, tables_every=3)
    _start(clock, enc)  # the opening keyframe is frame 0, which carries the tables
    sizes = [len(enc.feed(video(ms=1040 + i * 40)).data) for i in range(6)]
    # Frames 1 and 2 carry no tables; frame 3 does again, and so on.
    assert sizes[0] == sizes[1], "no tables on the two frames after the start"
    assert sizes[2] - sizes[0] == 2 * TS_PACKET_LEN, "PAT+PMT come round again"
    assert sizes[3] == sizes[4] == sizes[0]
    assert sizes[5] - sizes[0] == 2 * TS_PACKET_LEN


def test_output_is_always_whole_ts_packets() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock)
    _start(clock, enc)
    for i in range(20):
        out = enc.feed(video(ms=1040 + i * 40, data=b"\x00" * (100 + i * 37)))
        assert len(out.data) % TS_PACKET_LEN == 0
        assert out.data[0] == 0x47


def test_audio_is_dropped_unless_the_encoder_was_built_for_it() -> None:
    """The PMT is written when the stream starts, so a track cannot appear later."""
    clock = FakeClock()
    enc = StreamEncoder(clock=clock)  # audio=False
    _start(clock, enc)
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aacframe", timestamp_ms=1000)
    assert enc.feed(audio).data == b""


def test_audio_rides_the_stream_once_it_has_started() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True)
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aacframe", timestamp_ms=1000)
    # Nothing before the video track settles: there is no PMT yet to declare it in.
    assert enc.feed(audio).data == b""
    _start(clock, enc)
    out = enc.feed(audio)
    assert out.data
    assert len(out.data) % TS_PACKET_LEN == 0
    assert not out.started
    assert not out.resized


def test_the_audio_track_is_declared_in_the_pmt_from_the_start() -> None:
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True)
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aac", timestamp_ms=1000)
    enc.feed(video(keyframe=True))
    enc.feed(audio)  # the camera is sending audio, so the track is declared
    clock.advance(enc.settle + 0.1)
    assert enc.feed(video(keyframe=True)).started
    assert 0x0F in enc.header, "ADTS AAC stream type in the opening tables"


def test_audio_does_not_disturb_the_video_settle_gate() -> None:
    """Audio arrives during the ramp; it must not start the stream or reset settling."""
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True, settle=6.0)
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aac", timestamp_ms=900)
    assert not enc.feed(video(3840, 2160, keyframe=True)).started
    clock.advance(0.6)
    assert not enc.feed(audio).started
    assert not enc.feed(video(keyframe=True)).started
    clock.advance(3.0)
    assert not enc.feed(audio).started
    clock.advance(3.1)
    assert enc.feed(video(keyframe=True)).started, "the audio frames changed nothing"


def test_audio_is_declared_only_if_the_camera_actually_sends_it() -> None:
    """A declared-but-silent track makes consumers wait for data that never comes.

    The PMT is written when the stream starts and cannot be revised, so the decision
    rests on what arrived during the settle window — audio flows throughout it.
    """
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True)
    _start(clock, enc)  # video only: no audio frame was ever offered
    assert 0x0F not in enc.header, "no AAC stream type when the camera sent no audio"
    audio = MediaFrame(MediaKind.AUDIO, b"\xff\xf1aac", timestamp_ms=1000)
    assert enc.feed(audio).data == b"", "and audio arriving later cannot be carried"

    # When audio does arrive during settle, the track is declared and carried.
    clock = FakeClock()
    enc = StreamEncoder(clock=clock, audio=True)
    enc.feed(video(keyframe=True))
    enc.feed(audio)
    clock.advance(enc.settle + 0.1)
    assert enc.feed(video(keyframe=True)).started
    assert 0x0F in enc.header
    assert enc.feed(audio).data


def test_the_codec_comes_from_the_frame() -> None:
    """An H.264 stream must be declared as H.264 in the PMT, not assumed HEVC."""
    clock = FakeClock()
    enc = StreamEncoder(clock=clock)
    frame = MediaFrame(
        MediaKind.VIDEO,
        b"\x00\x00\x00\x01\x65payload",
        is_keyframe=True,
        timestamp_ms=1000,
        codec=VideoCodec.H264,
        width=1920,
        height=1080,
    )
    enc.feed(frame)
    clock.advance(enc.settle + 0.1)
    out = enc.feed(frame)
    assert out.started
    assert 0x1B in out.data, "H.264 stream type in the PMT"


def _audio_pts(ts: bytes) -> list[int]:
    """PTS (90 kHz) of every audio PES start in ``ts``."""
    out = []
    for o in range(0, len(ts), TS_PACKET_LEN):
        pkt = ts[o : o + TS_PACKET_LEN]
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        if pid != AUDIO_PID or not pkt[1] & 0x40:
            continue
        body = 4 + (1 + pkt[4] if pkt[3] & 0x20 else 0)
        p = pkt[body + 9 : body + 14]
        out.append(
            ((p[0] >> 1) & 0x07) << 30 | p[1] << 22 | (p[2] >> 1) << 15 | p[3] << 7 | p[4] >> 1
        )
    return out


def camera_audio(ms: int) -> MediaFrame:
    return MediaFrame(MediaKind.AUDIO, b"\xff\xf1camera-aac", timestamp_ms=ms)


def test_settle_zero_starts_at_the_first_keyframe_of_a_ramp() -> None:
    enc = StreamEncoder(settle=0.0, follow_resize=True, clock=FakeClock())
    assert not enc.feed(video(1280, 720, ms=900)).started, "a P-frame cannot start it"
    out = enc.feed(video(1280, 720, keyframe=True, ms=1000))
    assert out.started
    assert enc.feed(video(1920, 1080, keyframe=True, ms=5000)).restarted
    assert enc.size == (1920, 1080)


def test_fill_audio_declares_the_track_and_carries_silence_until_the_camera_audio() -> None:
    enc = StreamEncoder(audio=True, settle=0.0, fill_audio=True, clock=FakeClock())
    assert enc.feed(video(keyframe=True, ms=1000)).started
    assert enc.has_audio, "declared though no audio arrived yet"
    silence = b"".join(enc.feed(video(ms=1000 + i * 40)).data for i in range(1, 11))
    assert silence.count(SILENT_AAC_FRAME) == 6, "one silent frame per 64 ms of 400 ms"
    real = enc.feed(camera_audio(1405))
    assert b"camera-aac" in real.data
    after = b"".join(enc.feed(video(ms=1440 + i * 40)).data for i in range(10))
    assert SILENT_AAC_FRAME not in after, "the fill stops at the first camera audio"


def test_the_silence_never_runs_past_the_video_time() -> None:
    """Real audio arrives no earlier than its video; silence ending later would overlap."""
    enc = StreamEncoder(audio=True, settle=0.0, fill_audio=True, clock=FakeClock())
    first = enc.feed(video(keyframe=True, ms=1000))
    chunks = [enc.feed(video(ms=1000 + i * 45)).data for i in range(1, 20)]
    pts = _audio_pts(first.data + b"".join(chunks))
    assert pts == sorted(pts)
    last_video_pts = (1000 + 19 * 45) * 90
    assert pts[-1] + SILENT_AAC_FRAME_MS * 90 <= last_video_pts
    assert pts[1] - pts[0] == SILENT_AAC_FRAME_MS * 90


def test_a_long_video_gap_is_not_back_filled() -> None:
    enc = StreamEncoder(audio=True, settle=0.0, fill_audio=True, clock=FakeClock())
    enc.feed(video(keyframe=True, ms=1000))
    after_gap = enc.feed(video(ms=61_000)).data
    assert after_gap.count(SILENT_AAC_FRAME) == 1, "silence resumes at the gap's end"


def test_audio_seen_before_the_start_needs_no_fill() -> None:
    enc = StreamEncoder(audio=True, settle=0.0, fill_audio=True, clock=FakeClock())
    enc.feed(camera_audio(990))
    enc.feed(video(keyframe=True, ms=1000))
    out = b"".join(enc.feed(video(ms=1000 + i * 40)).data for i in range(1, 11))
    assert SILENT_AAC_FRAME not in out


def test_fill_audio_without_audio_declares_no_track() -> None:
    enc = StreamEncoder(audio=False, settle=0.0, fill_audio=True, clock=FakeClock())
    enc.feed(video(keyframe=True, ms=1000))
    assert not enc.has_audio
    assert SILENT_AAC_FRAME not in enc.feed(video(ms=1200)).data


def test_silence_flows_while_a_followed_resize_waits_for_its_keyframe() -> None:
    enc = StreamEncoder(
        audio=True, settle=0.0, fill_audio=True, follow_resize=True, clock=FakeClock()
    )
    enc.feed(video(keyframe=True, ms=1000))
    dropped = enc.feed(video(1920, 1080, ms=1100))
    assert dropped.data.count(SILENT_AAC_FRAME) == 1, "video dropped, silence kept"
