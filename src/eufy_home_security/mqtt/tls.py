"""The MQTT client's TLS context (TLS 1.2 or newer, the account's client certificate).

``ssl`` loads a certificate chain only from files: the PEM pair is written to a private
directory (mode 0700, files 0600) that is removed as soon as the context holds it. All of it
runs in a worker thread, off the event loop.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import ssl
import tempfile
from pathlib import Path

from ..cloud.models import MqttCertificate
from ..exceptions import ProtocolError

_PRIVATE_FILE = 0o600


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_FILE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _tls_context(certificate_pem: str, private_key: str, cadata: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=cadata)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    directory = Path(tempfile.mkdtemp(prefix="eufy-mqtt-"))
    try:
        cert, key = directory / "certificate.pem", directory / "private.key"
        _write_private(cert, certificate_pem)
        _write_private(key, private_key)
        context.load_cert_chain(cert, key)
    except (ssl.SSLError, ValueError) as err:
        raise ProtocolError(f"MQTT client certificate unusable: {err}") from err
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return context


async def async_tls_context(
    certificate: MqttCertificate, *, cadata: str | None = None
) -> ssl.SSLContext:
    """A client TLS context holding ``certificate``'s pair, verifying the broker against
    ``cadata`` (PEM) or, when None, the system's trust store as the eufy app does. Raises
    :class:`ProtocolError` for a pair ``ssl`` cannot load."""
    return await asyncio.to_thread(
        _tls_context, certificate.certificate_pem, certificate.private_key, cadata
    )
