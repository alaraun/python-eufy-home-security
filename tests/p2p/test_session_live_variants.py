"""Live video from a station other than a HomeBase 3, a 1700 open on a HomeBase's session,
and media records in every protection.

The app reads each media record's protection from its XZYH subheader (byte 0 the media
version, byte 3 the encrypted flag); a HomeBase 2 gets the camera handlers' plain 1003
and a bare 1004 carrying the channel.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.devices.live_open import LiveOpen, LiveStop
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    UnsupportedError,
)
from eufy_home_security.p2p.media import MediaFrame, MediaKeyType, MediaKind, VideoVariant
from eufy_home_security.p2p.session import MediaStream, P2PCredentials, StationSession
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import MEDIA_KEYFRAME, FakeStation

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


def _session(station: FakeStation) -> StationSession:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    return StationSession(station.serial, provider, host="127.0.0.1", port=station.discovery_port)


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
