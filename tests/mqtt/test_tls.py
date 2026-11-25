"""The TLS context of the MQTT client: built off the loop from the PEM pair, nothing left on disk."""

from __future__ import annotations

import os
import ssl
import stat
import tempfile
from pathlib import Path

import pytest

from eufy_home_security.cloud.models import MqttCertificate
from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.mqtt import tls
from eufy_home_security.testing.mqtt import MqttTestPki, make_mqtt_pki


@pytest.fixture(scope="module")
def pki() -> MqttTestPki:
    return make_mqtt_pki()


def _all_gone(dirs: list[str]) -> bool:
    return not any(Path(d).exists() for d in dirs)


def _certificate(pki: MqttTestPki, **overrides: str) -> MqttCertificate:
    return MqttCertificate.from_api(pki.register_answer(**overrides))


async def test_the_context_holds_the_client_pair_and_verifies_the_broker(
    pki: MqttTestPki,
) -> None:
    context = await tls.async_tls_context(_certificate(pki), cadata=pki.ca_pem)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert [c["subject"] for c in context.get_ca_certs()] == [
        ((("commonName", "synthetic test ca"),),)
    ]


async def test_without_a_ca_the_system_store_verifies_the_broker(
    pki: MqttTestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded: list[bool] = []
    original = ssl.SSLContext.load_default_certs

    def spy(self: ssl.SSLContext, *args: object) -> None:
        loaded.append(True)
        original(self, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", spy)
    context = await tls.async_tls_context(_certificate(pki))
    assert loaded
    assert context.verify_mode is ssl.CERT_REQUIRED


async def test_the_pems_are_written_private_and_removed_after_loading(
    pki: MqttTestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, int] = {}
    dirs: list[str] = []
    original_mkdtemp = tempfile.mkdtemp
    original_load = ssl.SSLContext.load_cert_chain

    def mkdtemp(*args: object, **kwargs: object) -> str:
        path = original_mkdtemp(*args, **kwargs)  # type: ignore[call-overload]
        dirs.append(path)
        return str(path)

    def load(self: ssl.SSLContext, certfile: object, keyfile: object = None, **kw: object) -> None:
        for name in (certfile, keyfile):
            seen[str(name)] = stat.S_IMODE(os.stat(str(name)).st_mode)
        seen["dir"] = stat.S_IMODE(os.stat(Path(str(certfile)).parent).st_mode)
        original_load(self, certfile, keyfile)  # type: ignore[arg-type]

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load)
    await tls.async_tls_context(_certificate(pki), cadata=pki.ca_pem)
    assert seen.pop("dir") == 0o700
    assert list(seen.values()) == [0o600, 0o600]
    assert dirs
    assert _all_gone(dirs)


async def test_an_unusable_pair_is_a_protocol_error_and_leaves_nothing(
    pki: MqttTestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    dirs: list[str] = []
    original_mkdtemp = tempfile.mkdtemp

    def mkdtemp(*args: object, **kwargs: object) -> str:
        path = original_mkdtemp(*args, **kwargs)  # type: ignore[call-overload]
        dirs.append(path)
        return str(path)

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    broken = _certificate(pki, private_key="-----BEGIN PRIVATE KEY-----\nnot a key\n")
    with pytest.raises(ProtocolError, match="MQTT client certificate"):
        await tls.async_tls_context(broken, cadata=pki.ca_pem)
    assert dirs
    assert _all_gone(dirs)
