"""The package root: every public name resolves lazily; light imports stay light."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import eufy_home_security
import eufy_home_security.cloud
from eufy_home_security import _lazy

HEAVY = ("aiohttp", "firebase_messaging", "cryptography")
# The P2P session legitimately needs cryptography, but never the network stack: a
# warm `status` (cached session + device list) must reach the station without it.
NETWORK = ("aiohttp", "firebase_messaging")
RUNTIME = (*HEAVY, "asyncio")  # the package root installs its logging defaults
# Shipped in the wheel for consumers' tests; no library module may import it.
TESTING = "eufy_home_security.testing"
ROOT = Path(__file__).resolve().parent.parent


def test_every_public_name_resolves() -> None:
    for name in eufy_home_security.__all__:
        assert getattr(eufy_home_security, name) is not None
    assert name in dir(eufy_home_security)
    assert isinstance(eufy_home_security.__version__, str)
    with pytest.raises(AttributeError, match="no attribute"):
        _ = eufy_home_security.nope


def test_devices_exports_the_per_model_settings_api() -> None:
    from eufy_home_security import devices  # noqa: PLC0415
    from eufy_home_security.devices import (  # noqa: PLC0415
        Setting,
        SettingKind,
        SettingUnit,
        WireCommand,
        WritePath,
        model_settings,
        settings,
    )

    assert Setting is model_settings.Setting
    assert WireCommand is model_settings.WireCommand
    assert WritePath is model_settings.WritePath
    assert SettingKind is model_settings.SettingKind
    assert SettingUnit is settings.SettingUnit
    assert [k.name for k in SettingKind] == ["BOOL", "ENUM", "RANGE", "STRING", "OTHER", "FLAGS"]
    for name in devices.__all__:
        assert getattr(devices, name) is not None
    removed = {"SettingDef", "Encoding", "SETTINGS", "get_setting", "Tier", "WireTemplate"}
    assert removed.isdisjoint(devices.__all__)
    assert {"Evidence", "Support", "Scope", "mode_action_key"} <= set(devices.__all__)


def test_redaction_helpers_are_exported() -> None:
    from eufy_home_security import redact, redact_serial  # noqa: PLC0415

    assert redact_serial is eufy_home_security._logging.redact_serial
    assert redact is eufy_home_security._logging.redact


def test_every_cloud_public_name_resolves() -> None:
    for name in eufy_home_security.cloud.__all__:
        assert getattr(eufy_home_security.cloud, name) is not None


def test_the_cache_layout_version_is_the_storage_version() -> None:
    from eufy_home_security import storage  # noqa: PLC0415

    assert eufy_home_security.CACHE_LAYOUT_VERSION == storage.CACHE_VERSION


def test_exports_table_matches_all() -> None:
    assert set(eufy_home_security._EXPORTS) | {"__version__"} == set(eufy_home_security.__all__)


def test_lazy_exports_helper_resolves_modules_and_names() -> None:
    namespace: dict[str, object] = {}
    getattr_, dir_ = _lazy.lazy_exports(
        "eufy_home_security", namespace, {"models": "models", "GuardMode": "models"}
    )
    assert getattr_("models") is sys.modules["eufy_home_security.models"]
    assert getattr_("GuardMode") is eufy_home_security.models.GuardMode
    assert namespace["GuardMode"] is eufy_home_security.models.GuardMode  # resolved once
    assert dir_() == ["GuardMode", "models"]
    with pytest.raises(AttributeError):
        getattr_("other")


@pytest.mark.parametrize(
    ("module", "banned"),
    [
        ("eufy_home_security", HEAVY),
        ("eufy_home_security.models", HEAVY),
        ("eufy_home_security.identity", HEAVY),
        ("eufy_home_security.install", RUNTIME),
        ("eufy_home_security.cloud.status", RUNTIME),
        ("eufy_home_security.cli.commands", HEAVY),
        ("eufy_home_security.client", NETWORK),
        ("eufy_home_security.cloud.api", NETWORK),
        ("eufy_home_security.station", NETWORK),
        ("eufy_home_security.cli", RUNTIME),
        ("eufy_home_security.cli.config", RUNTIME),
    ],
)
def test_light_modules_do_not_load_the_heavy_dependencies(
    module: str, banned: tuple[str, ...]
) -> None:
    """The CLI's --help, usage errors and network-free commands must stay fast.

    No library module imports the shipped test doubles either.
    """
    banned = (*banned, TESTING)
    code = f"import sys, {module}; print(' '.join(m for m in {banned!r} if m in sys.modules))"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == "", f"{module} loaded {out}"


def test_release_config_bumps_conservatively_before_one_point_oh() -> None:
    """While the version is 0.x a breaking change bumps the minor and a feature the patch."""
    config = json.loads((ROOT / "release-please-config.json").read_text("utf-8"))
    package = config["packages"]["."]
    assert package["bump-minor-pre-major"] is True
    assert package["bump-patch-for-minor-pre-major"] is True
