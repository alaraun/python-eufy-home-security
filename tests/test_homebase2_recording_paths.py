"""HomeBase 2 recording paths are distinct from newer station ``.zxvideo`` paths."""

import pytest

from eufy_home_security.events import (
    MEDIA_PATH_PREFIX,
    RECORDING_SUFFIX,
    is_station_recording_path,
)


def test_existing_zxvideo_path_is_preserved() -> None:
    assert is_station_recording_path(f"{MEDIA_PATH_PREFIX}record{RECORDING_SUFFIX}")


@pytest.mark.parametrize("camera", ["00", "03", "05", "99"])
def test_homebase2_recording_path(camera: str) -> None:
    assert is_station_recording_path(f"/media/mmcblk0p1/Camera{camera}/20261024084022.dat")


@pytest.mark.parametrize(
    "path",
    [
        None,
        9,
        "",
        "/media/mmcblk0p1/Camera05/../20261024084022.dat",
        "/media/mmcblk0p1/Camera05/20261024084022.dat/another",
        "/media/mmcblk0p1/Camera5/20261024084022.dat",
        "/media/mmcblk0p1/Camera005/20261024084022.dat",
        "/media/mmcblk0p1/Camera05/2026102408402.dat",
        "/media/mmcblk0p1/Camera05/20261024084022.mp4",
        "/media/mmcblk0p1/video/20261024084022.dat",
        "/media/mmcblk0p1/Camera05/2026102408402é.dat",
        "/media/mmcblk0p1/Camera05/20261024084022.dat\n",
        "/media/sda1/Camera05/20261024084022.dat",
    ],
)
def test_reject_other_homebase2_shapes(path: object) -> None:
    assert not is_station_recording_path(path)


@pytest.mark.parametrize("camera", ["00", "05", "12", "99"])
@pytest.mark.parametrize("prefix", ["A123", "F001", "z987"])
def test_homebase2_doorbell_prefixed_recording_path(camera: str, prefix: str) -> None:
    assert is_station_recording_path(f"/media/mmcblk0p1/Camera{camera}/{prefix}_20261024084022.dat")


@pytest.mark.parametrize(
    "filename",
    [
        "1234_20261024084022.dat",  # prefix must start with a letter
        "A12_20261024084022.dat",
        "A1234_20261024084022.dat",
        "A123-20261024084022.dat",
        "A123_2026102408402.dat",
        "A123_202610240840222.dat",
        "A123_20261024084022.mp4",
        "A123_20261024084022.dat/extra",
        "../A123_20261024084022.dat",
        "A123_20261024084022.dat\n",
        "A12é_20261024084022.dat",
    ],
)
def test_reject_bad_doorbell_recording_filename(filename: str) -> None:
    assert not is_station_recording_path(f"/media/mmcblk0p1/Camera05/{filename}")
