"""``testing/rtc.py``: the fake WebRTC station's own contract."""

from __future__ import annotations

import subprocess
import sys

from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.rtc import DEVICE_INFO, LICENSE, rtc_config, server_key


def test_the_fake_config_uses_synthetic_identities() -> None:
    config = rtc_config()
    assert config.station_sn == SYNTHETIC.station_sn
    assert config.p2p_did == SYNTHETIC.did
    assert config.identity == f"{SYNTHETIC.did}:{LICENSE}".encode()
    assert config.user_id == SYNTHETIC.account_id


def test_the_device_answer_round_trips_through_sdp_info() -> None:
    assert SdpInfo.decode(DEVICE_INFO.encode()) == DEVICE_INFO


def test_the_server_key_is_made_once_and_is_rsa_1024() -> None:
    assert server_key() is server_key()
    assert server_key().key_size == 1024


def test_the_package_and_its_fakes_import_without_aioice() -> None:
    """The core and the rtc modules load without the extra; only ICE needs it."""
    code = (
        "import sys; sys.modules['aioice'] = None\n"
        "import eufy_home_security, eufy_home_security.testing, eufy_home_security.testing.rtc\n"
        "import eufy_home_security.rtc.session, eufy_home_security.rtc.ice\n"
        "from eufy_home_security.exceptions import MissingDependencyError\n"
        "try:\n"
        "    eufy_home_security.rtc.ice.IceTransport()\n"
        "except MissingDependencyError as err:\n"
        "    print(err.extra)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=50, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rtc"
