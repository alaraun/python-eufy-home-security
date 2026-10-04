"""MPEG-TS muxing for camera media: Annex-B frames in, TS packets out.

A live stream is delivered to Home Assistant as MPEG-TS over HTTP, because that is the
one container both of HA's consumers accept from a single URL: PyAV (the ``stream``
component, which demuxes and remuxes for HLS and recording) and go2rtc (which
repacketises for WebRTC). Neither decodes video, so the camera's own HEVC travels to the
browser untouched — the whole point, since the typical Home Assistant host cannot decode
4K HEVC in realtime.

This module is pure: frames in, bytes out, no I/O and no sockets. What it must get right
is everything a decoder needs and a camera does not provide:

* **Real timestamps.** Each frame carries the station's own millisecond clock
  (:attr:`~.media.MediaFrame.pts`), which is used directly. Feeding a decoder a
  headerless elementary stream instead loses every timestamp and produces unplayable
  output.
* **Monotonic timestamps.** The camera's clock occasionally steps *backwards* by a
  millisecond or two. A decoder rejects or "repairs" a non-monotonic stream, so
  :class:`TSMuxer` clamps instead (see :meth:`TSMuxer.video`).
* **In-band parameter sets.** HEVC in MPEG-TS carries no out-of-band VPS/SPS/PPS, and a
  camera repeats them before each IDR; they are passed through so a late joiner can
  start at any keyframe.
"""

from __future__ import annotations

from .media import VideoCodec

__all__ = [
    "AUDIO_PID",
    "PCR_PID",
    "PMT_PID",
    "TS_PACKET_LEN",
    "VIDEO_PID",
    "TSMuxer",
]

#: An MPEG-TS packet is always exactly this long; a packet of any other size desyncs
#: every packet after it.
TS_PACKET_LEN = 188
_PAYLOAD_LEN = TS_PACKET_LEN - 4  # after the 4-byte transport header

#: The PIDs the muxer assigns. Their values are arbitrary (any spare PID works); what matters is
#: that the PMT names them consistently.
PMT_PID = 0x1000
VIDEO_PID = 0x0100
AUDIO_PID = 0x0101
PCR_PID = VIDEO_PID
"""The clock is carried on the video PID: video is the track with a keyframe to
anchor to, and both tracks share the station's one millisecond clock anyway."""

_PAT_PID = 0x0000
_PROGRAM_NUMBER = 1

#: PMT stream types (ISO/IEC 13818-1). HEVC is 0x24, AVC 0x1B, ADTS AAC 0x0F.
_STREAM_TYPE = {VideoCodec.HEVC: 0x24, VideoCodec.H264: 0x1B}
_STREAM_TYPE_AAC = 0x0F

#: PES stream ids: 0xE0 is the first video stream, 0xC0 the first audio stream.
_STREAM_ID_VIDEO = 0xE0
_STREAM_ID_AUDIO = 0xC0

#: An HEVC access-unit delimiter, emitted before each access unit.
_AUD_HEVC = b"\x00\x00\x00\x01\x46\x01\x50"
#: The H.264 equivalent.
_AUD_H264 = b"\x00\x00\x00\x01\x09\xf0"

_PTS_MODULUS = 1 << 33
"""A PES timestamp is 33 bits and wraps roughly every 26.5 hours."""

WRAP_THRESHOLD = 90_000 * 10
"""A backwards step larger than this (10 s in 90 kHz ticks) is a clock wrap, not jitter.

The camera's timestamps jitter by a millisecond or two, which is clamped. A wrap moves
the clock by hours, and must be passed through or the stream freezes — see
:meth:`TSMuxer.next_pts`.
"""


def _crc32_mpeg(data: bytes) -> int:
    """The MPEG-2 CRC-32 a PSI section ends with (poly 0x04C11DB7, no final xor)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
                if crc & 0x80000000
                else (crc << 1) & 0xFFFFFFFF
            )
    return crc


class TSMuxer:
    """Mux Annex-B video frames into MPEG-TS packets.

    One instance per stream: it owns the continuity counters and the timestamp state,
    both of which a decoder checks for gaps.

    Not thread-safe and not reentrant; call it from one task.
    """

    __slots__ = (
        "_audio",
        "_audio_cc",
        "_codec",
        "_last_audio_pts",
        "_last_pts",
        "_pat_cc",
        "_pmt_cc",
        "_video_cc",
    )

    def __init__(self, codec: VideoCodec = VideoCodec.HEVC, *, audio: bool = False) -> None:
        self._codec = codec
        self._audio = audio
        self._pat_cc = 0
        self._pmt_cc = 0
        self._video_cc = 0
        self._audio_cc = 0
        self._last_pts: int | None = None
        self._last_audio_pts: int | None = None

    @property
    def codec(self) -> VideoCodec:
        """The codec declared in the PMT."""
        return self._codec

    @property
    def has_audio(self) -> bool:
        """Whether the PMT declares an audio track.

        Fixed for the life of the muxer: a track cannot be added to a running stream,
        because consumers do not re-read the PMT once they have tuned in.
        """
        return self._audio

    # ── program tables ───────────────────────────────────────────────────────

    def _section_packet(self, pid: int, table: bytes, counter: int) -> bytes:
        """A whole PSI section in one packet: pointer field, table, CRC, stuffing."""
        body = table + _crc32_mpeg(table).to_bytes(4, "big")
        packet = (
            bytes(
                [
                    0x47,
                    0x40 | (pid >> 8),  # payload_unit_start_indicator
                    pid & 0xFF,
                    0x10 | (counter & 0x0F),  # payload only
                ]
            )
            + b"\x00"
            + body
        )  # pointer_field = 0
        return packet.ljust(TS_PACKET_LEN, b"\xff")

    def pat(self) -> bytes:
        """The Program Association Table: program 1 lives in :data:`PMT_PID`."""
        table = bytes(
            [
                0x00,  # table_id
                0xB0,
                0x0D,  # section_syntax_indicator + length (13)
                0x00,
                0x01,  # transport_stream_id
                0xC1,  # version 0, current
                0x00,
                0x00,  # section number, last section number
                (_PROGRAM_NUMBER >> 8) & 0xFF,
                _PROGRAM_NUMBER & 0xFF,
                0xE0 | (PMT_PID >> 8),
                PMT_PID & 0xFF,
            ]
        )
        out = self._section_packet(_PAT_PID, table, self._pat_cc)
        self._pat_cc = (self._pat_cc + 1) & 0x0F
        return out

    def pmt(self) -> bytes:
        """The Program Map Table: the video elementary stream, and audio if declared."""
        es_info = bytes(
            [
                _STREAM_TYPE[self._codec],
                0xE0 | (VIDEO_PID >> 8),
                VIDEO_PID & 0xFF,
                0xF0,
                0x00,  # no ES descriptors
            ]
        )
        if self._audio:
            es_info += bytes(
                [
                    _STREAM_TYPE_AAC,
                    0xE0 | (AUDIO_PID >> 8),
                    AUDIO_PID & 0xFF,
                    0xF0,
                    0x00,
                ]
            )
        # section_length counts everything after it, including the CRC.
        section_length = 9 + len(es_info) + 4
        table = (
            bytes(
                [
                    0x02,  # table_id
                    0xB0 | ((section_length >> 8) & 0x0F),
                    section_length & 0xFF,
                    (_PROGRAM_NUMBER >> 8) & 0xFF,
                    _PROGRAM_NUMBER & 0xFF,
                    0xC1,  # version 0, current
                    0x00,
                    0x00,  # section number, last section number
                    0xE0 | (PCR_PID >> 8),
                    PCR_PID & 0xFF,
                    0xF0,
                    0x00,  # no program descriptors
                ]
            )
            + es_info
        )
        out = self._section_packet(PMT_PID, table, self._pmt_cc)
        self._pmt_cc = (self._pmt_cc + 1) & 0x0F
        return out

    def tables(self) -> bytes:
        """PAT and PMT together, to be repeated so a late joiner can tune in."""
        return self.pat() + self.pmt()

    # ── video ────────────────────────────────────────────────────────────────

    @staticmethod
    def _pts_field(prefix: int, pts: int) -> bytes:
        """A 5-byte PES timestamp: 33 bits split across three marker-bit groups."""
        pts &= _PTS_MODULUS - 1
        return bytes(
            [
                (prefix << 4) | (((pts >> 30) & 0x07) << 1) | 1,
                (pts >> 22) & 0xFF,
                (((pts >> 15) & 0x7F) << 1) | 1,
                (pts >> 7) & 0xFF,
                ((pts & 0x7F) << 1) | 1,
            ]
        )

    def next_pts(self, pts: int, *, audio: bool = False) -> int:
        """``pts`` clamped so that track never goes backwards.

        The camera's clock is not reliably monotonic — successive frames have been seen
        to step back a millisecond or two. A decoder treats that as a broken stream
        (ffmpeg reports "Invalid DTS ... replacing by guess" and may drop the frame), so
        a small step backwards is pinned to its predecessor instead. Two frames then
        share a timestamp, which decoders handle; going backwards, they do not.

        A **large** step backwards is a wrap, not jitter, and must be passed through.
        Two wraps are certain in normal operation: the 33-bit PES timestamp turns over
        every 26.5 hours, and the station's own u32 millisecond clock every 49.7 days
        of uptime. Clamping a wrap would pin every later frame to the pre-wrap value
        and freeze the stream until it was restarted, so a backwards step of more than
        :data:`WRAP_THRESHOLD` is taken at face value and the track continues from there.

        The two tracks are clamped independently. They share the station's clock, but
        they arrive interleaved, so one track's timestamp must never constrain the
        other's — doing so would drag audio forward to the newest video frame and lose
        lip sync.
        """
        last = self._last_audio_pts if audio else self._last_pts
        if last is not None and pts < last and last - pts < WRAP_THRESHOLD:
            pts = last
        if audio:
            self._last_audio_pts = pts
        else:
            self._last_pts = pts
        return pts

    def _packetise(self, pes: bytes, pid: int, *, pcr: int | None, random_access: bool) -> bytes:
        """Split one PES packet into whole TS packets on ``pid``.

        The first packet carries the payload-unit start flag, and an adaptation field
        when one is needed — for the random-access indicator, for a PCR, or simply to
        pad a short tail out to a full packet.
        """
        video = pid == VIDEO_PID
        out = bytearray()
        view = memoryview(pes)
        first = True
        while view:
            adaptation = b""
            if first and (random_access or pcr is not None):
                flags = 0x40 if random_access else 0x00
                if pcr is not None:
                    adaptation = bytes([flags | 0x10]) + (
                        ((pcr & (_PTS_MODULUS - 1)) << 15) | (0x3F << 9)
                    ).to_bytes(6, "big")
                else:
                    adaptation = bytes([flags])

            space = _PAYLOAD_LEN - (1 + len(adaptation)) if adaptation else _PAYLOAD_LEN
            chunk = bytes(view[:space])
            view = view[space:]

            # Whatever is left of the payload area becomes the adaptation field. Sizing
            # it from the shortfall (rather than branching on "is one needed?") is what
            # makes the awkward case safe: a tail of exactly _PAYLOAD_LEN - 1 bytes
            # needs a 1-byte adaptation field, which holds a length and nothing else.
            shortfall = _PAYLOAD_LEN - len(chunk)
            counter = self._video_cc if video else self._audio_cc
            packet = bytearray(
                [
                    0x47,
                    (0x40 if first else 0x00) | (pid >> 8),
                    pid & 0xFF,
                    (0x30 if shortfall else 0x10) | (counter & 0x0F),
                ]
            )
            if video:
                self._video_cc = (counter + 1) & 0x0F
            else:
                self._audio_cc = (counter + 1) & 0x0F
            if shortfall:
                field_len = shortfall - 1
                packet.append(field_len)
                if field_len:
                    # An adaptation field of one byte or more *starts with its flags
                    # byte*; only what follows is stuffing. Filling the whole field with
                    # 0xff instead would be read as every flag set — including PCR_flag,
                    # sending a decoder looking for a clock reference that is not there.
                    field = adaptation or b"\x00"
                    packet += field + b"\xff" * (field_len - len(field))
            packet += chunk
            out += packet
            first = False
        return bytes(out)

    def video(self, frame: bytes, pts: int, *, keyframe: bool) -> bytes:
        """One access unit as whole TS packets.

        ``frame`` is Annex-B video — for a keyframe, the parameter sets and the IDR as
        the camera sent them. ``pts`` is in 90 kHz ticks (see
        :attr:`~.media.MediaFrame.pts`) and is clamped by :meth:`next_pts`.

        The first packet of a keyframe carries a PCR and the random-access indicator, so
        a decoder joining mid-stream can start there.
        """
        pts = self.next_pts(pts)
        aud = _AUD_HEVC if self._codec is VideoCodec.HEVC else _AUD_H264
        # PES packet length 0 means unbounded, which is legal (and usual) for video.
        pes = (
            bytes([0x00, 0x00, 0x01, _STREAM_ID_VIDEO])
            + b"\x00\x00"  # PES_packet_length: unbounded
            + b"\x80\x80\x05"  # flags: PTS only, 5-byte header
            + self._pts_field(0b0010, pts)
            + aud
            + frame
        )
        # random_access_indicator means "a decoder may start here", which is true only
        # of a keyframe. Setting it on P-frames invites a decoder to start on one and
        # render the macroblock garbage that follows.
        return self._packetise(
            pes,
            VIDEO_PID,
            pcr=pts if keyframe else None,
            random_access=keyframe,
        )

    def audio(self, frame: bytes, pts: int) -> bytes:
        """One ADTS AAC frame as whole TS packets.

        The camera's audio is already ADTS AAC-LC and is carried through untouched: no
        decode, no transcode. ``pts`` is clamped on the audio track's own timeline.

        Unlike video, an audio PES declares its length — audio packets are small and
        bounded, and some demuxers rely on it.
        """
        pts = self.next_pts(pts, audio=True)
        header = b"\x80\x80\x05" + self._pts_field(0b0010, pts)
        length = len(header) + len(frame)
        pes = (
            bytes([0x00, 0x00, 0x01, _STREAM_ID_AUDIO]) + length.to_bytes(2, "big") + header + frame
        )
        return self._packetise(pes, AUDIO_PID, pcr=None, random_access=False)
