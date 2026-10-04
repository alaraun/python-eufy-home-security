"""``scripts/thing_models.py``'s product-code resolution for ``fetch``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from eufy_home_security.testing import SYNTHETIC

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "thing_models_script", ROOT / "scripts" / "thing_models.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_product_codes_fall_back_to_the_serials_model() -> None:
    """A device without ``device_new_pn`` gets its serial's catalogued model."""
    devices = [
        {"device_sn": SYNTHETIC.station_sn},
        {"device_sn": SYNTHETIC.camera_sn},
        {"device_sn": SYNTHETIC.camera_sn, "device_new_pn": "T8161"},
        {"device_sn": "ZZZZZ0000000000"},
        {"device_new_pn": "  "},
    ]
    assert _script().product_codes(devices) == sorted(
        {SYNTHETIC.station_sn[:5], SYNTHETIC.camera_sn[:5], "T8161"}
    )
