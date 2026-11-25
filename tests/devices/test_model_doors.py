"""Where a lock model reports its lock state and which parameters and command a garage
model's doors use, from its file (``devices.model_settings.lock_state_read`` and
``garage_params``)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    GarageParams,
    LockStateRead,
    garage_params,
    lock_state_read,
)
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.exceptions import ModelDataError

GOOD_ENTRY = {"access": "ro", "kind": "bool", "read": None, "section": "other", "role": "status"}
LOCK = {"param": 1912, "contexts": {"standalone": 6000}}
GARAGE = {"state": 7500, "motors": 7501, "sensors": 7502, "control": {"cmd": 1700, "subCmd": 7500}}


def _clear() -> None:
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A temporary models directory the loader reads from, indexing ``T0001``."""
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    index = {"schema_version": 3, "codes": ["T0001"]}
    (tmp_path / "INDEX.json").write_text(json.dumps(index), encoding="utf-8")
    _clear()
    yield tmp_path
    _clear()


def _write(root: Path, **blocks: object) -> None:
    doc = {"schema_version": 3, "product_code": "T0001", "settings": {"mode": GOOD_ENTRY}}
    doc.update(blocks)
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")


def test_the_lock_block_names_the_state_param_per_context(data_root: Path) -> None:
    _write(data_root, lock=LOCK)
    read = lock_state_read("t0001")
    assert read == LockStateRead(1912, {"standalone": 6000})
    assert read is not None
    assert read.param_for(standalone=True) == 6000
    assert read.param_for() == 1912
    assert read.param_for(ConnectType.HB3) == 1912


def test_a_context_the_block_names_takes_its_own_param(data_root: Path) -> None:
    _write(data_root, lock={"param": 1912, "contexts": {"HB3": 1913}})
    read = lock_state_read("T0001")
    assert read is not None
    assert read.param_for(ConnectType.HB3) == 1913
    assert read.param_for(ConnectType.SINGLE) == 1912
    assert read.param_for(standalone=True) == 1912


def test_the_garage_block_names_its_params_and_command(data_root: Path) -> None:
    _write(data_root, garage=GARAGE)
    assert garage_params("T0001") == GarageParams(7500, 7501, 7502, 1700, 7500)


def test_a_file_without_the_blocks_has_neither(data_root: Path) -> None:
    _write(data_root)
    assert lock_state_read("T0001") is None
    assert garage_params("T0001") is None


@pytest.mark.parametrize("code", ["T0002", "", "bad code", None])
def test_a_code_without_a_file_has_neither(data_root: Path, code: str | None) -> None:
    assert lock_state_read(code) is None
    assert garage_params(code) is None


@pytest.mark.parametrize(
    "block",
    [
        [],
        {"param": 1912},
        {"param": "1912", "contexts": {}},
        {"param": 0, "contexts": {}},
        {"param": 1912, "contexts": {"standalone": True}},
        {"param": 1912, "contexts": {"nowhere": 6000}},
        {"param": 1912, "contexts": []},
        {"param": 1912, "contexts": {}, "extra": 1},
    ],
)
def test_a_malformed_lock_block_fails_the_file(data_root: Path, block: object) -> None:
    _write(data_root, lock=block)
    with pytest.raises(ModelDataError, match="lock"):
        lock_state_read("T0001")


@pytest.mark.parametrize(
    "block",
    [
        [],
        {k: v for k, v in GARAGE.items() if k != "sensors"},
        {**GARAGE, "state": "7500"},
        {**GARAGE, "motors": 70000},
        {**GARAGE, "control": {"cmd": 1700}},
        {**GARAGE, "control": {"cmd": 1700, "subCmd": True}},
        {**GARAGE, "extra": 1},
    ],
)
def test_a_malformed_garage_block_fails_the_file(data_root: Path, block: object) -> None:
    _write(data_root, garage=block)
    with pytest.raises(ModelDataError, match="garage"):
        garage_params("T0001")
