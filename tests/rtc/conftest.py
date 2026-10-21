"""Close the fake signaling servers and stations a test started."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from .fakes import SERVERS, stop_stations


@pytest.fixture(autouse=True)
async def _close_servers() -> AsyncIterator[None]:
    yield
    await stop_stations()
    while SERVERS:
        SERVERS.pop().close()
    await asyncio.sleep(0)
