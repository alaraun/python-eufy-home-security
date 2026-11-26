"""Live video from a station other than a HomeBase 3, a 1700 open on a HomeBase's session,
and media records in every protection.

The app reads each media record's protection from its XZYH subheader (byte 0 the media
version, byte 3 the encrypted flag); a HomeBase 2 gets the camera handlers' plain 1003
and a bare 1004 carrying the channel.
"""

from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import AsyncIterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from eufy_home_security.devices.live_open import LiveOpen, LiveStop
from eufy_home_security.devices.live_view import Lens, LensView, live_view
from eufy_home_security.exceptions import (
    CloudApiError,
    CommandNotAppliedError,
    CommandRejectedError,
    EndToEndEncryptedError,
    PinProtectedKeyError,
    UnsupportedError,
)
from eufy_home_security.models import E2EKey, E2EKeyType
from eufy_home_security.p2p.media import (
    MediaDecoder,
    MediaFrame,
    MediaKeyType,
    MediaKind,
    VideoVariant,
    generate_media_rsa_key,
)
from eufy_home_security.p2p.messages import CMD_RECORD_VIEW
from eufy_home_security.p2p.session import E2EKeyProvider, P2PCredentials, StationSession
from eufy_home_security.p2p.session import media_stream as media_stream_module
from eufy_home_security.p2p.session.media_stream import MediaStream
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import (
    MEDIA_AUDIO,
    MEDIA_GOP,
    MEDIA_KEYFRAME,
    MEDIA_RECORDING_PFRAME,
    E2EMediaKey,
    FakeStation,
    audio_record,
    e2e_audio_record,
    e2e_video_record,
    video_record,
)

HB2_SN = "T8010P2000054321"
"""A synthetic HomeBase 2 serial."""
CAMERA = 1


@pytest.fixture
async def hb2() -> AsyncIterator[FakeStation]:
    fake = FakeStation(serial=HB2_SN)
    await fake.start()
    yield fake
    fake.stop()


@pytest.fixture
async def hb3() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


def _session(station: FakeStation, e2e_keys: E2EKeyProvider | None = None) -> StationSession:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    return StationSession(
        station.serial,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        e2e_keys=e2e_keys,
    )


async def _frames(stream: MediaStream, keyframes: int = 2) -> list[MediaFrame]:
    """Frames up to and including the ``keyframes``-th keyframe."""
    out: list[MediaFrame] = []
    async with asyncio.timeout(5):
        async for frame in stream:
            out.append(frame)
            if sum(f.is_keyframe for f in out) >= keyframes:
                return out
    raise AssertionError("the stream ended early")


async def _until(predicate: object, timeout: float = 3.0) -> None:
    assert callable(predicate)
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


async def test_a_homebase2_open_is_the_handlers_1003_without_the_t8030_fields(
    hb2: FakeStation,
) -> None:
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        await _frames(stream, 1)
        (payload,) = hb2.live_open_payloads
        assert set(payload) == {
            "streamtype",
            "camera_type",
            "entrytype",
            "accountId",
            "chn_list",
            "key",
            "ClientOS",
        }
        assert payload["chn_list"] == []
        assert payload["accountId"] == SYNTHETIC.account_id
        assert hb2.live_opens == [CAMERA]
    finally:
        await session.async_close()


async def test_a_homebase2_stream_stops_with_a_bare_1004_carrying_the_channel(
    hb2: FakeStation,
) -> None:
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        await _frames(stream, 1)
        await stream.aclose()
        await _until(lambda: hb2.bare_stops == 1)
        assert hb2.bare_stop_frames == [(CAMERA, struct.pack("<I", CAMERA))]
        assert 1004 not in [obj.get("cmd") for obj in hb2.received]
        assert hb2.live_cameras == []
    finally:
        await session.async_close()


async def test_a_homebase3_keeps_its_t8030_open_and_1004_message(hb3: FakeStation) -> None:
    session = _session(hb3)
    try:
        stream = await session.async_open_live(CAMERA)
        await _frames(stream, 1)
        (payload,) = hb3.live_open_payloads
        assert payload["extValue"] == 1000
        assert payload["chn_list"] == [{"cameraType": 0, "chn": CAMERA, "index": 0, "sensor": 0}]
        await stream.aclose()
        await _until(lambda: 1004 in [obj.get("cmd") for obj in hb3.received])
        assert hb3.bare_stops == 0
    finally:
        await session.async_close()


TWO_LENSES = (Lens(1, 0), Lens(1, 1))
KEY_FIELDS = {"key", "ClientOS", "cameraType"}


def _spy_flags(session: StationSession, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The subheader flag (stream id) of each media open ``session`` sends."""
    flags: list[int] = []
    real = session._media_slot.open_stream

    async def spy(*args: object, **kwargs: object) -> MediaStream:
        flags.append(kwargs["flag"])  # type: ignore[arg-type]
        return await real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session._media_slot, "open_stream", spy)
    return flags


async def test_a_multi_camera_open_behind_a_homebase3_is_the_handlers_body_for_the_view(
    hb3: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _session(hb3)
    flags = _spy_flags(session, monkeypatch)
    view = live_view(CAMERA, TWO_LENSES, LensView.SUB)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.NVR_LENS, live_stop=LiveStop.STATION, live_view=view
        )
        await _frames(stream, 1)
        (obj,) = [o for o in hb3.received if o.get("cmd") == 1003]
        payload = obj.pop("payload")
        assert obj == {
            "cmd": 1003,
            "mChannel": CAMERA,
            "account_id": SYNTHETIC.account_id,
            "mValue3": 1003,
            "mValue5": 0,
        }
        assert {k: v for k, v in payload.items() if k not in KEY_FIELDS} == {
            "accountId": SYNTHETIC.account_id,
            "streamtype": 0,
            "camera_type": 1,
            "entrytype": 0,
            "stitch_mode": 1,
            "chn_list": [{"cameraType": 0, "chn": CAMERA, "index": 0, "sensor": 1}],
            "extValue": 1000,
            "audio_chn": CAMERA,
            "pip_cord": "",
        }
        assert flags == [0x0A]
        assert hb3.live_opens == [CAMERA]
        await stream.aclose()
        await _until(lambda: 1004 in [o.get("cmd") for o in hb3.received])
        assert hb3.bare_stops == 0
    finally:
        await session.async_close()


async def test_a_multi_camera_open_defaults_to_the_fixed_lens(hb3: FakeStation) -> None:
    session = _session(hb3)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.NVR, live_stop=LiveStop.STATION
        )
        await _frames(stream, 1)
        (payload,) = hb3.live_open_payloads
        assert payload["stitch_mode"] == 1
        assert payload["chn_list"] == [{"cameraType": 0, "chn": CAMERA, "index": 0, "sensor": 0}]
    finally:
        await session.async_close()


async def test_a_multi_camera_open_behind_a_homebase2_carries_no_view_and_stops_bare(
    hb2: FakeStation,
) -> None:
    session = _session(hb2)
    view = live_view(CAMERA, TWO_LENSES, LensView.PIP)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.NVR, live_stop=LiveStop.BARE, live_view=view
        )
        await _frames(stream, 1)
        (payload,) = hb2.live_open_payloads
        assert {k: v for k, v in payload.items() if k not in KEY_FIELDS} == {
            "accountId": SYNTHETIC.account_id,
            "streamtype": 0,
            "camera_type": 0,
            "entrytype": 0,
            "stitch_mode": 1,
            "chn_list": [],
        }
        await stream.aclose()
        await _until(lambda: hb2.bare_stops == 1)
        assert hb2.bare_stop_frames == [(CAMERA, struct.pack("<I", CAMERA))]
    finally:
        await session.async_close()


async def test_a_multi_camera_open_behind_a_homebase3_stops_bare_when_its_handler_does(
    hb3: FakeStation,
) -> None:
    session = _session(hb3)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.NVR, live_stop=LiveStop.BARE
        )
        await _frames(stream, 1)
        await stream.aclose()
        await _until(lambda: hb3.bare_stops == 1)
        assert 1004 not in [obj.get("cmd") for obj in hb3.received]
    finally:
        await session.async_close()


@pytest.mark.parametrize(
    ("mode", "flag", "ext_value"),
    [(LiveOpen.SINGLE_NO_EXT, 0x00, None), (LiveOpen.SINGLE, 0x0A, 1000)],
)
async def test_a_1700_open_behind_a_homebase3_goes_on_its_session_with_the_cameras_channel(
    hb3: FakeStation, mode: LiveOpen, flag: int, ext_value: int | None
) -> None:
    session = _session(hb3)
    try:
        stream = await session.async_open_live(CAMERA, live_open=mode, live_stop=LiveStop.STATION)
        await _frames(stream, 1)
        (body,) = hb3.doorbell_payloads
        assert body["commandType"] == 1000
        assert body["data"]["mChannel"] == CAMERA
        assert body["data"].get("extValue") == ext_value
        (subheader,) = hb3.doorbell_subheaders
        assert (subheader[2], subheader[4]) == (CAMERA, flag)
        assert hb3.live_open_payloads == []
        await stream.aclose()
        await _until(lambda: 1004 in [obj.get("cmd") for obj in hb3.received])
        stop = hb3.received.index(next(o for o in hb3.received if o.get("cmd") == 1004))
        assert hb3.received_header_channels[stop] == CAMERA
        assert hb3.bare_stops == 0
        assert hb3.pings == 0  # no 1139 ping on a HomeBase's session
    finally:
        await session.async_close()


@pytest.mark.parametrize("serial", [HB2_SN, SYNTHETIC.station_sn])
async def test_a_1700_open_behind_a_homebase_stops_with_a_bare_1004_when_its_handler_does(
    serial: str,
) -> None:
    fake = FakeStation(serial=serial)
    await fake.start()
    session = _session(fake)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.SINGLE_NO_EXT, live_stop=LiveStop.BARE
        )
        await _frames(stream, 1)
        assert [b["data"]["mChannel"] for b in fake.doorbell_payloads] == [CAMERA]
        await stream.aclose()
        await _until(lambda: fake.bare_stops == 1)
        assert fake.bare_stop_frames == [(CAMERA, struct.pack("<I", CAMERA))]
        assert 1004 not in [obj.get("cmd") for obj in fake.received]
        assert fake.pings == 0
    finally:
        await session.async_close()
        fake.stop()


async def test_a_refused_1700_open_fails_at_once(
    hb3: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hb3, "doorbell_receipt_code", lambda: -1)
    session = _session(hb3)
    try:
        stream = await session.async_open_live(
            CAMERA, live_open=LiveOpen.SINGLE_NO_EXT, first_frame_timeout=30
        )
        with pytest.raises(CommandRejectedError) as caught:
            async with asyncio.timeout(3):  # well before the first-frame timeout
                await _frames(stream, 1)
        assert (caught.value.command, caught.value.code) == (1700, -1)
        assert session.stats().media_failures_by_type == {"CommandRejectedError": 1}
    finally:
        await session.async_close()


async def test_a_1700_receipt_while_a_1700_command_waits_is_not_taken_as_the_opens(
    hb3: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hb3, "doorbell_receipt_code", lambda: -1)
    session = _session(hb3)
    try:
        async with session._recipe_lock:  # a 1700 recipe waiting for its own receipt
            stream = await session.async_open_live(
                CAMERA, live_open=LiveOpen.SINGLE_NO_EXT, first_frame_timeout=0.5
            )
            await _until(lambda: len(hb3.doorbell_payloads) == 1)
            await asyncio.sleep(0.1)  # the receipt is in
        with pytest.raises(CommandNotAppliedError):  # the first-frame timeout
            await _frames(stream, 1)
    finally:
        await session.async_close()


@pytest.mark.parametrize(
    "variant", [VideoVariant.RSA_PREFIX, VideoVariant.RSA_V3, VideoVariant.PLAIN]
)
async def test_every_decodable_protection_delivers_annex_b_keyframes(
    hb2: FakeStation, variant: VideoVariant
) -> None:
    hb2.video_variant = variant
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        frames = await _frames(stream)
        keyframes = [f.data for f in frames if f.kind is MediaKind.VIDEO and f.is_keyframe]
        assert keyframes == [MEDIA_KEYFRAME, MEDIA_KEYFRAME]
        assert any(f.kind is MediaKind.AUDIO for f in frames)
        counts = session.stats().media_frames_by_variant
        assert counts[f"video:{variant.value}"] > 0
        assert counts["audio:aac"] > 0
        await stream.aclose()
    finally:
        await session.async_close()


async def test_a_clear_keyframe_without_the_header_flag_is_found_by_its_first_nal(
    hb2: FakeStation,
) -> None:
    hb2.video_variant = VideoVariant.RSA_V3
    hb2.keyframe_flag = False
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        frames = await _frames(stream)
        assert frames[0].is_keyframe
        assert frames[0].data == MEDIA_KEYFRAME
        await stream.aclose()
    finally:
        await session.async_close()


@pytest.mark.parametrize("serial", [HB2_SN, SYNTHETIC.station_sn])
async def test_an_ecc_offer_streams_aes_gcm_video_and_audio(serial: str) -> None:
    fake = FakeStation(serial=serial)
    await fake.start()
    session = _session(fake)
    try:
        stream = await session.async_open_live(CAMERA, media_key=MediaKeyType.ECC)
        frames = await _frames(stream)
        assert fake.media_keys_offered == [MediaKeyType.ECC]
        (payload,) = fake.live_open_payloads
        assert len(payload["key"]) == 128
        assert payload["key"] == payload["key"].upper()
        keyframes = [f.data for f in frames if f.kind is MediaKind.VIDEO and f.is_keyframe]
        assert keyframes == [MEDIA_KEYFRAME, MEDIA_KEYFRAME]
        assert any(f.kind is MediaKind.AUDIO and f.data.startswith(b"\xff\xf1") for f in frames)
        counts = session.stats().media_frames_by_variant
        assert counts["video:ecc"] > 0
        assert counts["audio:ecc"] > 0
        await stream.aclose()
    finally:
        await session.async_close()
        fake.stop()


async def test_an_ecc_keyframe_without_the_header_flag_is_found_after_its_decrypt(
    hb2: FakeStation,
) -> None:
    hb2.keyframe_flag = False
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA, media_key=MediaKeyType.ECC)
        frames = await _frames(stream)
        assert frames[0].is_keyframe
        assert frames[0].data == MEDIA_KEYFRAME
        await stream.aclose()
    finally:
        await session.async_close()


async def test_a_station_that_ignores_the_ecc_offer_fails_the_open_naming_it(
    hb2: FakeStation,
) -> None:
    hb2.ecc_offer_ignored = True
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA, media_key=MediaKeyType.ECC)
        with pytest.raises(UnsupportedError, match=r"rsa_prefix video.*ECC key"):
            await _frames(stream, 1)
    finally:
        await session.async_close()


@pytest.mark.parametrize("variant", [VideoVariant.ECC, VideoVariant.E2E])
async def test_video_an_rsa_open_does_not_decode_fails_the_open_naming_it(
    hb2: FakeStation, variant: VideoVariant
) -> None:
    hb2.video_variant = variant
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        with pytest.raises(UnsupportedError, match=variant.value):
            await _frames(stream, 1)
        assert session.stats().media_failures_by_type == {"UnsupportedError": 1}
        await _until(lambda: hb2.bare_stops == 1)  # the open is stopped at the station
    finally:
        await session.async_close()


async def test_audio_of_media_version_0_is_not_delivered_as_the_app_drops_it(
    hb2: FakeStation,
) -> None:
    hb2.audio_media_version = 0
    session = _session(hb2)
    try:
        stream = await session.async_open_live(CAMERA)
        frames = await _frames(stream, 3)
        assert all(f.kind is MediaKind.VIDEO for f in frames)
        assert session.stats().media_frames_by_variant["audio:ignored"] > 0
        await stream.aclose()
    finally:
        await session.async_close()


# ── end-to-end encrypted recordings ─────────────────────────────────────────

NATIVE_CLIP = "/media/mmcblk0p1/Camera05/20310203112233.dat"
E2E_CIPHER = rsa.generate_private_key(65537, 1024)  # noqa: S505 (protocol)
E2E_CIPHER_TEXT = E2E_CIPHER.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()


@pytest.fixture
async def e2e_hb2() -> AsyncIterator[FakeStation]:
    """A HomeBase 2 whose recordings are end-to-end encrypted under the owner's cloud
    cipher 7 (subheader version 5, key id 7)."""
    fake = FakeStation(serial=SYNTHETIC.homebase2_station_sn)
    fake.video_variant = VideoVariant.E2E
    fake.e2e_cipher_key = E2E_CIPHER
    fake.e2e_media_version, fake.e2e_key_id = 5, 7
    fake.recording_frames = 12
    await fake.start()
    yield fake
    fake.stop()


class _Keys:
    """An :class:`E2EKeyProvider` recording the key ids asked, answering after ``delay``."""

    def __init__(self, answer: str | None = E2E_CIPHER_TEXT, delay: float = 0.2) -> None:
        self.answer = answer
        self.delay = delay
        self.asked: list[int] = []
        self.error: Exception | None = None

    async def __call__(self, key_id: int) -> str | None:
        self.asked.append(key_id)
        await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.answer


async def _recording_frames(session: StationSession) -> list[MediaFrame]:
    await session.async_connect()
    stream = await session.async_open_recording(NATIVE_CLIP, CAMERA)
    out: list[MediaFrame] = []
    async with asyncio.timeout(8), stream:
        out.extend([frame async for frame in stream])
    return out


async def test_an_e2e_recording_decodes_under_the_owners_cloud_cipher_fetched_once(
    e2e_hb2: FakeStation,
) -> None:
    """Records arriving while the key is fetched are held, then decoded in order."""
    keys = _Keys()
    session = _session(e2e_hb2, keys)
    try:
        started = asyncio.get_running_loop().time()
        frames = await _recording_frames(session)
        took = asyncio.get_running_loop().time() - started
    finally:
        await session.async_close()
    assert took < 2.0, "the station's end, taken during the fetch, ends it after the replay"
    video = [f for f in frames if f.kind is MediaKind.VIDEO]
    assert video[0].is_keyframe
    assert video[0].data == MEDIA_KEYFRAME
    assert len(video) == e2e_hb2.recording_frames, "nothing lost while the key was fetched"
    assert any(f.kind is MediaKind.AUDIO for f in frames)
    assert keys.asked == [7]


async def test_an_e2e_download_ends_on_the_stations_end_after_the_held_records(
    e2e_hb2: FakeStation,
) -> None:
    keys = _Keys()
    session = _session(e2e_hb2, keys)

    async def write(_chunk: bytes) -> None:
        return None

    try:
        await session.async_connect()
        async with asyncio.timeout(10):
            clip = await session.async_download_recording(NATIVE_CLIP, CAMERA, write)
    finally:
        await session.async_close()
    assert clip.video_frames == e2e_hb2.recording_frames
    assert keys.asked == [7]


async def test_records_past_the_key_wait_resume_video_at_a_keyframe(
    e2e_hb2: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first records are held, those past the cap dropped, and the records arriving
    after the key resume at their next keyframe, not at a P-frame missing its reference."""
    monkeypatch.setattr(media_stream_module, "MEDIA_KEY_WAIT_BYTES", 1200)
    e2e_hb2.recording_frames = 16
    e2e_hb2.recording_pause = (9, 0.6)  # frames 9-15 after the key; keyframes every 4th
    session = _session(e2e_hb2, _Keys(delay=0.3))
    try:
        frames = await _recording_frames(session)
    finally:
        await session.async_close()
    video = [f for f in frames if f.kind is MediaKind.VIDEO]
    assert video[0].is_keyframe
    held = next(i for i, f in enumerate(video) if i and f.is_keyframe)
    assert held < 4, "only the records under the cap were held"
    assert len(video) == held + 4, "after the key: from the keyframe at 12, not P-frame 9"


async def test_an_e2e_recording_of_the_users_pin_key_is_refused_without_a_fetch(
    e2e_hb2: FakeStation,
) -> None:
    e2e_hb2.e2e_media_version, e2e_hb2.e2e_key_id = 4, 10
    keys = _Keys()
    session = _session(e2e_hb2, keys)
    try:
        with pytest.raises(PinProtectedKeyError, match="PIN-protected key") as err:
            await _recording_frames(session)
    finally:
        await session.async_close()
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.PIN, 10)
    assert keys.asked == []


@pytest.mark.parametrize(
    ("keys", "message"),
    [
        (None, "cannot fetch cipher keys"),
        (_Keys(answer=None), "serves no RSA key"),
        (_Keys(answer="not a key"), "does not parse"),
        (_Keys(answer=E2E_CIPHER_TEXT), "could not be fetched"),
    ],
)
async def test_an_e2e_recording_whose_key_is_not_to_be_had_fails_naming_the_cipher(
    e2e_hb2: FakeStation, keys: _Keys | None, message: str
) -> None:
    if keys is not None and keys.answer == E2E_CIPHER_TEXT:
        keys.error = CloudApiError(500, "boom")
    session = _session(e2e_hb2, keys)
    try:
        with pytest.raises(EndToEndEncryptedError, match=message) as err:
            await _recording_frames(session)
    finally:
        await session.async_close()
    assert not isinstance(err.value, PinProtectedKeyError)
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.CIPHER, 7)


async def test_live_e2e_media_is_refused_as_the_app_plays_it_only_from_recordings(
    e2e_hb2: FakeStation,
) -> None:
    keys = _Keys()
    session = _session(e2e_hb2, keys)
    try:
        stream = await session.async_open_live(CAMERA)
        with pytest.raises(UnsupportedError, match="only from a recording") as err:
            await _frames(stream, 1)
    finally:
        await session.async_close()
    assert not isinstance(err.value, EndToEndEncryptedError)
    assert keys.asked == []


async def test_a_recording_opened_with_its_cloud_cipher_key_has_the_key_before_the_open(
    e2e_hb2: FakeStation,
) -> None:
    """With ``e2e_key`` (the history row's) the key is fetched before the open goes out,
    so no record waits for it; a later recording on the session reuses it."""
    session: StationSession
    open_at_fetch: list[bool] = []

    class Keys(_Keys):
        async def __call__(self, key_id: int) -> str | None:
            open_at_fetch.append(session._media_slot.stream is not None)
            return await super().__call__(key_id)

    keys = Keys()
    session = _session(e2e_hb2, keys)
    key = E2EKey(E2EKeyType.CIPHER, 7)
    try:
        counts = []
        for _ in range(2):
            stream = await session.async_open_recording(NATIVE_CLIP, CAMERA, e2e_key=key)
            async with asyncio.timeout(8), stream:
                frames = [frame async for frame in stream]
            assert "key_pending" not in {shape.outcome for shape in stream._shapes}
            counts.append(len([f for f in frames if f.kind is MediaKind.VIDEO]))
    finally:
        await session.async_close()
    assert open_at_fetch == [False]
    assert keys.asked == [7]
    assert counts == [e2e_hb2.recording_frames] * 2


async def test_a_recording_named_under_the_pin_key_is_refused_before_connecting(
    e2e_hb2: FakeStation,
) -> None:
    keys = _Keys()
    session = _session(e2e_hb2, keys)
    try:
        with pytest.raises(PinProtectedKeyError, match=r"key id 10\)"):
            await session.async_open_recording(
                NATIVE_CLIP, CAMERA, e2e_key=E2EKey(E2EKeyType.PIN, 10)
            )
    finally:
        await session.async_close()
    assert e2e_hb2.sessions == 0
    assert keys.asked == []


async def test_every_record_held_during_a_slow_key_fetch_is_delivered(
    e2e_hb2: FakeStation,
) -> None:
    """More records than the media queue holds arrive while the key is fetched (the whole
    recording and its end): all of them are delivered, none dropped."""
    e2e_hb2.recording_frames = media_stream_module.MEDIA_QUEUE_FRAMES + 50

    class Keys(_Keys):
        async def __call__(self, key_id: int) -> str | None:
            while e2e_hb2.media_frames_sent < e2e_hb2.recording_frames:
                await asyncio.sleep(0.02)
            await asyncio.sleep(0.2)  # the end of playback too
            return await super().__call__(key_id)

    session = _session(e2e_hb2, Keys(delay=0))
    try:
        await session.async_connect()
        stream = await session.async_open_recording(NATIVE_CLIP, CAMERA)
        async with asyncio.timeout(10), stream:
            frames = [frame async for frame in stream]
    finally:
        await session.async_close()
    video = [f for f in frames if f.kind is MediaKind.VIDEO]
    assert len(video) == e2e_hb2.recording_frames
    assert len(frames) - len(video) == e2e_hb2.recording_frames  # one audio record each
    assert (stream.dropped, stream.skipped) == (0, 0)
    assert stream.end_frame


@pytest.mark.parametrize("pause", [0, 0.001])
async def test_records_after_the_replay_queue_behind_its_backlog_for_a_reader_keeping_up(
    e2e_hb2: FakeStation, pause: float
) -> None:
    """The key arrives halfway through a recording opened by path: the records arriving
    while the reader works through the replayed backlog are queued behind it, not dropped
    as if the reader were slow."""
    e2e_hb2.recording_frames = 800

    class Keys(_Keys):
        async def __call__(self, key_id: int) -> str | None:
            while e2e_hb2.media_frames_sent < 400:
                await asyncio.sleep(0.005)
            return await super().__call__(key_id)

    session = _session(e2e_hb2, Keys(delay=0))
    frames: list[MediaFrame] = []
    try:
        await session.async_connect()
        stream = await session.async_open_recording(NATIVE_CLIP, CAMERA)
        async with asyncio.timeout(20), stream:
            async for frame in stream:
                frames.append(frame)
                await asyncio.sleep(pause)
    finally:
        await session.async_close()
    assert len([f for f in frames if f.kind is MediaKind.VIDEO]) == e2e_hb2.recording_frames
    assert (stream.dropped, stream.skipped) == (0, 0)


# A recording stream driven record by record (no station): the hold and its replay.

_E2E_RECORD_KEY = E2EMediaKey.for_cipher(E2E_CIPHER.public_key())


def _e2e_sub(key_id: int = 7, version: int = 5) -> bytes:
    return bytes([version, 0, CAMERA, key_id, 1, 0])


def _e2e_video(n: int, *, size: int = 0) -> bytes:
    """Video record ``n`` of a recording sealed for cipher 7: a keyframe every
    :data:`MEDIA_GOP`, ``size`` padding bytes added to the picture."""
    keyframe = n % MEDIA_GOP == 0
    body = (MEDIA_KEYFRAME if keyframe else MEDIA_RECORDING_PFRAME) + bytes(size)
    clear = video_record(body, keyframe=keyframe, counter=n, timestamp_ms=1000 + 40 * n)
    return e2e_video_record(clear, _E2E_RECORD_KEY)


def _e2e_audio(n: int) -> bytes:
    clear = audio_record(MEDIA_AUDIO, counter=n, timestamp_ms=1000 + 40 * n)
    return e2e_audio_record(clear, _E2E_RECORD_KEY)


def _e2e_stream(session: StationSession, first_frame_timeout: float = 5.0) -> MediaStream:
    return MediaStream(
        session,
        command=CMD_RECORD_VIEW,
        channel=CAMERA,
        decoder=MediaDecoder(generate_media_rsa_key()[1], e2e_keys={}),
        stop_body=None,
        first_frame_timeout=first_frame_timeout,
        idle_timeout=5.0,
    )


async def _key_settled(stream: MediaStream) -> None:
    async with asyncio.timeout(5):
        while stream._key_task is not None:
            await asyncio.sleep(0.01)


async def test_the_media_queue_takes_its_bound_behind_the_replayed_backlog(
    e2e_hb2: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The held records go into the queue whole; records arriving after the replay find
    room for the queue's bound behind them, then are dropped for the slow reader. The
    extra room shrinks as the reader works through the backlog."""
    monkeypatch.setattr(media_stream_module, "MEDIA_QUEUE_FRAMES", 4)
    session = _session(e2e_hb2, _Keys(delay=0))
    stream = _e2e_stream(session)
    try:
        for n in range(6):
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        await _key_settled(stream)
        assert len(stream._frames) == 5  # the sixth frame is held for a continuation
        queued = 0
        for n in range(6, 40):
            queued = len(stream._frames)
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
            if stream.dropped:
                break
        assert queued == 5 + 4, "the bound's 4 frames behind the 5 replayed"
        assert len(stream._frames) == queued
        now = time.monotonic()
        assert stream._expired(now), "full at its bound and dropping: unread"
        await anext(stream)
        assert not stream._expired(now), "under its bound: read"
        for _ in range(5):
            await anext(stream)
        assert len(stream._frames) == 3
        assert stream._queue_bound == 4 + 3, "as many replayed frames as are left at most"
    finally:
        await stream.aclose()
        await session.async_close()


def _counter(frame: MediaFrame) -> int:
    return (frame.timestamp_ms - 1000) // 40


async def test_after_the_hold_overflows_nothing_more_is_held(
    e2e_hb2: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Records keep arriving during the fetch after one did not fit: none of them is held,
    smaller ones included, and video resumes at the first keyframe after the key."""
    held = [_e2e_video(0), _e2e_audio(0)]
    for n in range(1, MEDIA_GOP):
        held += [_e2e_video(n), _e2e_audio(n)]
    big = 4000  # the keyframe at MEDIA_GOP does not fit; two P-frames and audio after it would
    cap = sum(map(len, held)) + 2 * (len(_e2e_video(1)) + len(_e2e_audio(1)))
    assert len(_e2e_video(MEDIA_GOP, size=big)) > cap - sum(map(len, held))
    monkeypatch.setattr(media_stream_module, "MEDIA_KEY_WAIT_BYTES", cap)
    gate = asyncio.Event()

    class Keys(_Keys):
        async def __call__(self, key_id: int) -> str | None:
            await gate.wait()
            return await super().__call__(key_id)

    session = _session(e2e_hb2, Keys(delay=0))
    stream = _e2e_stream(session)
    try:
        for n in range(2 * MEDIA_GOP):  # the hold overflows at MEDIA_GOP
            record = _e2e_video(n, size=big if n == MEDIA_GOP else 0)
            stream._feed(FrameType.VIDEO_FRAME, record, subheader=_e2e_sub())
            stream._feed(FrameType.AUDIO_FRAME, _e2e_audio(n), subheader=_e2e_sub())
        gate.set()
        await _key_settled(stream)
        for n in range(2 * MEDIA_GOP, 2 * MEDIA_GOP + 2):  # after the key
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
            stream._feed(FrameType.AUDIO_FRAME, _e2e_audio(n), subheader=_e2e_sub())
        stream._end()
        async with asyncio.timeout(5):
            frames = [frame async for frame in stream]
    finally:
        await stream.aclose()
        await session.async_close()
    after_key = [2 * MEDIA_GOP, 2 * MEDIA_GOP + 1]
    video = [_counter(f) for f in frames if f.kind is MediaKind.VIDEO]
    audio = [_counter(f) for f in frames if f.kind is MediaKind.AUDIO]
    # The last held P-frame goes too: the record lost after it may be its rest.
    assert video == [*range(MEDIA_GOP - 1), *after_key]
    assert audio == [*range(MEDIA_GOP), *after_key]


async def test_a_held_record_that_fails_the_stream_ends_the_replay(e2e_hb2: FakeStation) -> None:
    """A record of the PIN key among the held ones fails the stream before its first
    keyframe: the records held after it are not decoded, the reader gets the error."""
    session = _session(e2e_hb2, _Keys(delay=0))
    stream = _e2e_stream(session)
    try:
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(1), subheader=_e2e_sub())  # fetches
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(2), subheader=_e2e_sub(10, version=4))
        for n in range(MEDIA_GOP, MEDIA_GOP + 3):
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        await _key_settled(stream)
        assert not stream._frames
        with pytest.raises(PinProtectedKeyError):
            await anext(stream)
    finally:
        await stream.aclose()
        await session.async_close()


async def test_a_key_fetch_past_the_first_frame_wait_ends_the_stream_naming_the_cipher(
    e2e_hb2: FakeStation,
) -> None:
    """The first-frame wait runs out while the cipher key is still being fetched: the
    stream fails with the typed error naming the cipher, not as a stream that decoded
    nothing."""
    cancelled = asyncio.Event()

    class Keys(_Keys):
        async def __call__(self, key_id: int) -> str | None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return None

    session = _session(e2e_hb2, Keys(delay=0))
    stream = _e2e_stream(session, first_frame_timeout=0.3)
    try:
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(0), subheader=_e2e_sub())
        async with asyncio.timeout(5):
            with pytest.raises(EndToEndEncryptedError, match="cipher 7") as err:
                await anext(stream)
            await cancelled.wait()  # the fetch ends with the stream
    finally:
        await stream.aclose()
        await session.async_close()
    assert (err.value.key_type, err.value.key_id) == (E2EKeyType.CIPHER, 7)


class _GatedKeys(_Keys):
    """Answers each key id once its gate is set; ``failing`` ids raise."""

    def __init__(self, failing: tuple[int, ...] = ()) -> None:
        super().__init__(delay=0)
        self.gates: dict[int, asyncio.Event] = {}
        self.failing = failing

    def gate(self, key_id: int) -> asyncio.Event:
        return self.gates.setdefault(key_id, asyncio.Event())

    async def __call__(self, key_id: int) -> str | None:
        self.asked.append(key_id)
        await self.gate(key_id).wait()
        if key_id in self.failing:
            raise CloudApiError(500, "boom")
        return self.answer


async def _started_on_cipher_7(stream: MediaStream, keys: _GatedKeys) -> None:
    keys.gate(7).set()
    for n in range(2):
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
    await _key_settled(stream)
    assert stream._started


async def test_a_second_cipher_that_fails_on_a_started_stream_still_ends_it_on_time(
    e2e_hb2: FakeStation,
) -> None:
    """The station ends the recording while the key of a second cipher is fetched; the
    fetch fails: the stream ends then, not after its idle wait."""
    keys = _GatedKeys(failing=(8,))
    session = _session(e2e_hb2, keys)
    stream = _e2e_stream(session)
    try:
        await _started_on_cipher_7(stream, keys)
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(2), subheader=_e2e_sub(8))
        stream._end()
        keys.gate(8).set()
        async with asyncio.timeout(2):  # the idle wait is 5 s
            frames = [frame async for frame in stream]
    finally:
        await stream.aclose()
        await session.async_close()
    assert stream.ended
    assert [_counter(f) for f in frames if f.kind is MediaKind.VIDEO] == [0]


async def test_a_cipher_whose_key_failed_is_not_fetched_again_per_record(
    e2e_hb2: FakeStation,
) -> None:
    """Its later records are dropped, video resumes at a keyframe of a cipher it holds."""
    keys = _GatedKeys(failing=(8,))
    keys.gate(8).set()
    session = _session(e2e_hb2, keys)
    stream = _e2e_stream(session)
    try:
        await _started_on_cipher_7(stream, keys)
        for n in range(2, MEDIA_GOP + 2):
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub(8))
            await _key_settled(stream)
        for n in range(MEDIA_GOP + 2, 2 * MEDIA_GOP + 2):
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        stream._end()
        async with asyncio.timeout(2):
            frames = [frame async for frame in stream]
    finally:
        await stream.aclose()
        await session.async_close()
    assert keys.asked == [7, 8]
    video = [_counter(f) for f in frames if f.kind is MediaKind.VIDEO]
    assert video == [0, *range(2 * MEDIA_GOP, 2 * MEDIA_GOP + 2)]


async def test_a_second_fetch_during_the_replay_keeps_the_first_holds_overflow(
    e2e_hb2: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first hold overflowed; a held record names another cipher, whose fetch runs
    while records keep arriving: none of those is held, and video resumes at the first
    keyframe after both keys."""
    first = [
        (_e2e_video(0), _e2e_sub()),
        (_e2e_video(1), _e2e_sub()),
        (_e2e_video(2), _e2e_sub(8)),
        (_e2e_video(3), _e2e_sub()),
    ]
    big = 4000  # the keyframe at MEDIA_GOP does not fit, the P-frames after it would
    monkeypatch.setattr(
        media_stream_module,
        "MEDIA_KEY_WAIT_BYTES",
        sum(len(r) for r, _ in first) + 3 * len(_e2e_video(1)),
    )
    keys = _GatedKeys()
    session = _session(e2e_hb2, keys)
    stream = _e2e_stream(session)
    try:
        for record, sub in first:
            stream._feed(FrameType.VIDEO_FRAME, record, subheader=sub)
        stream._feed(FrameType.VIDEO_FRAME, _e2e_video(MEDIA_GOP, size=big), subheader=_e2e_sub())
        keys.gate(7).set()
        async with asyncio.timeout(5):
            while keys.asked != [7, 8]:
                await asyncio.sleep(0.01)
        for n in range(MEDIA_GOP + 1, 2 * MEDIA_GOP):  # during the second fetch
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        keys.gate(8).set()
        await _key_settled(stream)
        for n in range(2 * MEDIA_GOP, 2 * MEDIA_GOP + 2):  # after both keys
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        stream._end()
        async with asyncio.timeout(2):
            frames = [frame async for frame in stream]
    finally:
        await stream.aclose()
        await session.async_close()
    video = [_counter(f) for f in frames if f.kind is MediaKind.VIDEO]
    # The last held P-frame goes too: the record lost after it may be its rest.
    assert video == [0, 1, 2, 2 * MEDIA_GOP, 2 * MEDIA_GOP + 1]


async def test_a_hold_counts_the_frames_still_queued_against_its_cap(
    e2e_hb2: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second cipher's hold starts while the first replay sits unread in the queue: the
    queued frames' bytes count against the hold's cap, so holds cannot stack up."""
    keys = _GatedKeys()
    session = _session(e2e_hb2, keys)
    stream = _e2e_stream(session)
    try:
        await _started_on_cipher_7(stream, keys)
        for n in range(2, 2 * MEDIA_GOP):
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub())
        queued = sum(len(f.data) for f in stream._frames)
        second = _e2e_video(2 * MEDIA_GOP)
        monkeypatch.setattr(media_stream_module, "MEDIA_KEY_WAIT_BYTES", queued + len(second))
        stream._feed(FrameType.VIDEO_FRAME, second, subheader=_e2e_sub(8))  # fits exactly
        for n in range(2 * MEDIA_GOP + 1, 3 * MEDIA_GOP + 2):  # the rest does not
            stream._feed(FrameType.VIDEO_FRAME, _e2e_video(n), subheader=_e2e_sub(8))
        keys.gate(8).set()
        await _key_settled(stream)
        stream._end()
        async with asyncio.timeout(2):
            frames = [frame async for frame in stream]
    finally:
        await stream.aclose()
        await session.async_close()
    video = [_counter(f) for f in frames if f.kind is MediaKind.VIDEO]
    assert video == [*range(2 * MEDIA_GOP + 1)]
