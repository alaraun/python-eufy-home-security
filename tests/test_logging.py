from __future__ import annotations

import logging
import subprocess
import sys
from collections.abc import Iterator

import pytest

from eufy_home_security._logging import (
    Address,
    Credential,
    HexDump,
    Identifier,
    LogThrottle,
    Payload,
    Secret,
    redact,
    redact_serial,
    scrub,
    set_secret_logging,
    set_wire_logging,
    wire_logger,
)


def test_secrets_render_redacted_until_secret_logging_is_on() -> None:
    body = {
        "email": "a@b.example",
        "password": "hunter2hunter2",
        "nested": [{"auth_token": "t" * 20}],
        "n": 3,
    }
    key = bytes(range(16))
    assert str(Secret(key)) == "***0e0f"
    assert str(Payload(body)) == (
        '{"email": "***mple", "password": "***", "nested": [{"auth_token": "***tttt"}], "n": 3}'
    )
    set_secret_logging(True)
    try:
        assert str(Secret(key)) == key.hex()
        assert str(Secret(None)) == "None"
        assert '"password": "hunter2hunter2"' in str(Payload(body))
        assert "more chars" in str(Payload({"x": "y" * 50}, limit=10))
    finally:
        set_secret_logging(False)


def test_package_debug_does_not_enable_wire_dumps() -> None:
    logging.getLogger("eufy_home_security").setLevel(logging.DEBUG)
    try:
        assert not wire_logger("p2p").isEnabledFor(logging.DEBUG)
        set_wire_logging(True)
        assert wire_logger("p2p").isEnabledFor(logging.DEBUG)
    finally:
        set_wire_logging(False)
        logging.getLogger("eufy_home_security").setLevel(logging.NOTSET)


def test_hexdump_renders_lazily_and_truncates() -> None:
    text = str(HexDump(bytes(range(40)), limit=16))
    assert text.startswith("(40 bytes)")
    assert "0000  00 01 02" in text
    assert "24 more bytes" in text


@pytest.mark.parametrize("value", ["pw", "hunter2hunter2", "a-much-longer-password-aja!"])
def test_a_credential_keeps_no_tail_and_no_length(value: str) -> None:
    assert str(Credential(value)) == "***"
    assert str(Payload({"password": value, "verify_code": value, "captcha_answer": value})) == (
        '{"password": "***", "verify_code": "***", "captcha_answer": "***"}'
    )
    set_secret_logging(True)
    try:
        assert str(Credential(value)) == value
    finally:
        set_secret_logging(False)


def test_a_credential_still_shows_whether_one_was_given() -> None:
    assert str(Credential(None)) == "None"
    assert str(Credential("")) == ""


def test_redaction() -> None:
    assert redact_serial("T8030P2000012345") == "T8030***2345"
    assert redact("0123456789abcdef") == "***cdef"
    assert redact("short") == "*****"
    assert redact(None) == "None"


def test_throttle() -> None:
    throttle = LogThrottle(interval=3600)
    assert throttle.should_log("k")
    assert not throttle.should_log("k")
    assert throttle.should_log("other")


def test_throttle_keys_are_bounded() -> None:
    """Keys come off the wire, so the table must not grow without limit.

    A peer address or a frame type from any host on the LAN becomes a key, in an object
    that lives as long as the session does.
    """
    throttle = LogThrottle(interval=3600, max_keys=64)
    for i in range(10_000):
        assert throttle.should_log(f"host-{i}")
    assert len(throttle._last) <= 64


def test_throttle_still_suppresses_a_repeat_after_eviction() -> None:
    """Eviction must not turn the throttle into a pass-through."""
    throttle = LogThrottle(interval=3600, max_keys=64)
    assert throttle.should_log("noisy")
    for i in range(32):
        throttle.should_log(f"other-{i}")
    assert not throttle.should_log("noisy"), "a recent key survives while there is room"


def test_import_keeps_an_application_configured_wire_level() -> None:
    """Home Assistant sets ``logger:`` levels before importing the library."""
    code = (
        "import logging; logging.getLogger('eufy_home_security.wire').setLevel(logging.DEBUG); "
        "import eufy_home_security._logging as l; print(l.WIRE_LOGGER.level)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == str(logging.DEBUG)


@pytest.fixture
def _secrets_restored() -> Iterator[None]:
    """Secret logging starts off; whatever a test switches, it is off again afterwards."""
    set_secret_logging(False)
    yield
    set_secret_logging(False)


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("device_sn", "T8030P2000012345", "T8030***2345"),
        ("deviceSn", "T8030P2000012345", "T8030***2345"),
        ("mValueStrSub", "T8030P2000012345", "T8030***2345"),
        ("app-conn", "conn", "****"),
        ("user_name", "john", "****"),
        ("name", "Home", "****"),
        ("thumb_path", "/a/b.jpg", "********"),
        ("openudid", "1234", "****"),
        ("android_id", "5678", "****"),
    ],
)
@pytest.mark.usefixtures("_secrets_restored")
def test_payload_masks_identifying_keys(key: str, value: str, expected: str) -> None:
    body = {key: value, "table_name": "device", "cmd": 123, "app-name": "eufySecurity"}
    result = str(Payload(body))
    assert '"table_name": "device"' in result
    assert '"cmd": 123' in result
    assert '"app-name": "eufySecurity"' in result
    assert f'"{key}": "{expected}"' in result

    set_secret_logging(True)
    assert value in str(Payload(body))


@pytest.mark.usefixtures("_secrets_restored")
def test_payload_masks_json_in_string() -> None:
    body = {"data": '{"device_sn": "T8030P2000012345", "cmd": 123}'}
    result = str(Payload(body))
    assert "T8030***2345" in result
    assert "T8030P2000012345" not in result

    set_secret_logging(True)
    assert "T8030P2000012345" in str(Payload(body))


@pytest.mark.usefixtures("_secrets_restored")
def test_scrub() -> None:
    text = (
        "Serial T8030P2000012345 and account 0123456789abcdef0123456789abcdef01234567 "
        "email a@b.com, path /zx/hdd_data0/Camera00/snapshort.jpg!"
    )
    scrubbed = scrub(text)
    assert "T8030P2000012345" not in scrubbed
    assert "T8030***2345" in scrubbed
    assert "0123456789abcdef0123456789abcdef01234567" not in scrubbed
    assert "***4567" in scrubbed
    assert "a@b.com" not in scrubbed
    assert "/zx/" not in scrubbed

    set_secret_logging(True)
    assert "T8030P2000012345" in scrub(text)


@pytest.mark.parametrize(
    ("params", "shown"),
    [
        ([{"param_type": 1217, "param_value": "Garden"}], '"param_value": "******"'),
        ([{"param_type": "1216", "param_value": "Station"}], '"param_value": "*******"'),
        ([{"param_type": 1101, "param_value": "87"}], '"param_value": "87"'),
    ],
)
@pytest.mark.usefixtures("_secrets_restored")
def test_payload_masks_identifying_parameter_values(params: list[object], shown: str) -> None:
    assert shown in str(Payload({"params": params}))


@pytest.mark.parametrize(
    ("raw", "redacted"),
    [
        ("192.168.1.1", "192.168.1.1"),
        ("127.0.0.1", "127.0.0.1"),
        ("169.254.1.1", "169.254.1.1"),
        ("8.8.8.8", "*******"),
        ("2607:f8b0:4005:801::200e", "***200e"),
        ("some-host.local", "some-host.local"),  # hygiene: ok
    ],
)
@pytest.mark.usefixtures("_secrets_restored")
def test_address(raw: str, redacted: str) -> None:
    assert str(Address(raw)) == redacted
    set_secret_logging(True)
    assert str(Address(raw)) == raw


@pytest.mark.usefixtures("_secrets_restored")
def test_identifier() -> None:
    assert str(Identifier("T8030P2000012345")) == "T8030***2345"
    assert str(Identifier("john")) == "****"
    assert str(Identifier("1234567890abcdef")) == "***cdef"
    set_secret_logging(True)
    assert str(Identifier("T8030P2000012345")) == "T8030P2000012345"


@pytest.mark.usefixtures("_secrets_restored")
def test_hexdump_stars_secrets() -> None:

    # 40-hex account id
    data1 = b"abc 0123456789abcdef0123456789abcdef01234567 def"
    hd1 = str(HexDump(data1))
    assert b"0123456789abcdef0123456789abcdef01234567".hex()[:10] not in hd1
    assert "2a 2a 2a 2a 2a" in hd1  # ***...

    # Serial
    data2 = b"T8030P2000012345"
    hd2 = str(HexDump(data2))
    assert "2a 2a 2a 2a 2a 2a 2a" in hd2

    # DID struct
    data3 = b"EST\x00\x00\x00\x00\x001234ABCDE"
    hd3 = str(HexDump(data3))
    assert "2a 2a 2a 2a 2a 2a 2a 2a  EST.....********" in hd3

    # DID text
    data4 = b"EST-123456-ABCDE"
    hd4 = str(HexDump(data4))
    assert "2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a" in hd4

    set_secret_logging(True)
    assert "2a 2a 2a 2a 2a" not in str(HexDump(data1))
