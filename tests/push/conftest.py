"""Fixtures for the push tests: the aioresponses/aiohttp shim and Google mocks.

Everything is synthetic — a fake android id and token, a fake FCM token — and no
real socket is opened (the tests monkeypatch the MCS client's ``start``/``stop``).
"""

from __future__ import annotations

import inspect
from typing import Any, cast

import aiohttp
import pytest
from aioresponses import CallbackResult, aioresponses
from firebase_messaging.const import FCM_INSTALLATION, GCM_CHECKIN_URL, GCM_REGISTER_URL
from firebase_messaging.proto.checkin_pb2 import AndroidCheckinResponse

from eufy_home_security.push import const as push_const
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC

FAKE_ANDROID_ID = 1234567890123456789
FAKE_SECURITY_TOKEN = 987654321098765432
FAKE_FCM_TOKEN = "fakefid:APA91bFAKEtoken"

# aioresponses 0.7.9 vs aiohttp 3.14: ClientResponse gained a required
# `stream_writer`. Supply a stub so the pinned pair works together.
if "stream_writer" in inspect.signature(aiohttp.ClientResponse.__init__).parameters:
    _orig_response_init = aiohttp.ClientResponse.__init__

    class _StubStreamWriter:
        output_size = 0

    def _patched_response_init(
        self: Any, *args: Any, stream_writer: Any = None, **kwargs: Any
    ) -> None:
        writer = stream_writer or _StubStreamWriter()
        _orig_response_init(self, *args, stream_writer=cast(Any, writer), **kwargs)

    aiohttp.ClientResponse.__init__ = _patched_response_init  # type: ignore[method-assign]


class FakeCloud:
    """Stands in for EufyCloudApi: records every push-token registration."""

    def __init__(self) -> None:
        self.registered: list[str] = []
        # Errors the next registrations raise, in order, instead of registering.
        self.failures: list[Exception] = []

    async def async_register_push_token(self, token: str) -> None:
        if self.failures:
            raise self.failures.pop(0)
        self.registered.append(token)


def checkin_body() -> bytes:
    resp = AndroidCheckinResponse()
    resp.stats_ok = True  # a required field
    resp.android_id = FAKE_ANDROID_ID
    resp.security_token = FAKE_SECURITY_TOKEN
    return bytes(resp.SerializeToString())


def install_google_mocks(mock: aioresponses, register_body: dict[str, Any] | None = None) -> None:
    """Register the three Google endpoints an Android FCM registration hits."""
    mock.post(
        GCM_CHECKIN_URL,
        body=checkin_body(),
        status=200,
        headers={"Content-Type": "application/x-protobuf"},
        repeat=True,
    )
    install_url = f"{FCM_INSTALLATION}projects/{push_const.FCM_PROJECT_ID}/installations"
    mock.post(
        install_url,
        payload={
            "authToken": {"token": "fis-auth-token", "expiresIn": "604800s"},
            "refreshToken": "fis-refresh",
            "fid": "fakefid0000000000000000",
        },
        status=200,
        repeat=True,
    )

    def register_cb(url: str, **kwargs: Any) -> CallbackResult:
        if register_body is not None:
            register_body.update(dict(kwargs.get("data") or {}))
            register_body["_headers"] = dict(kwargs.get("headers") or {})
        return CallbackResult(status=200, body=f"token={FAKE_FCM_TOKEN}")

    mock.post(GCM_REGISTER_URL, callback=register_cb, repeat=True)


@pytest.fixture
def cache() -> SessionCache:
    return SessionCache(MemoryStore(), SYNTHETIC.email)


@pytest.fixture
def fake_cloud() -> FakeCloud:
    return FakeCloud()
