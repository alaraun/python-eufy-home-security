"""Close the fake signaling servers a test started."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from .fakes import SERVERS


@pytest.fixture(autouse=True)
async def _close_servers() -> AsyncIterator[None]:
    yield
    while SERVERS:
        SERVERS.pop().close()
    await asyncio.sleep(0)
