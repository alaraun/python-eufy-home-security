"""Short hardware waits for tests that run the library against the loopback fakes.

The library's timeouts, settle times and back-offs are sized for real stations and the
eufy cloud. Against :class:`~.station.FakeStation` every answer comes in milliseconds,
so a test that meets a timeout on purpose (an unanswered command, an unreachable
station) would otherwise wait out the real value. :func:`short_timeouts` sets each
wait listed in :data:`SHORT_TIMEOUTS` on its defining module for the duration of a
``with`` block; every library call that takes a ``timeout=None`` reads it there at
call time.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final

_PACKAGE = "eufy_home_security"

SHORT_TIMEOUTS: Final[Mapping[str, tuple[str, Any]]] = {
    # name: (defining module, loopback value). Discovery spans one repeated search
    # (a station ignores the first after a close); handshake, parameter and database
    # queries outlast one DRW retransmit (1.5 s). COMMAND_TIMEOUT does not: a test that drops
    # a command frame sets it per test.
    "DISCOVERY_ATTEMPTS": ("p2p.session", 1),
    "DISCOVERY_TIMEOUT": ("p2p.session", 2.5),
    "HANDSHAKE_TIMEOUT": ("p2p.session", 2.5),
    "COMMAND_TIMEOUT": ("p2p.session", 0.5),
    "COMMAND_RECEIPT_TIMEOUT": ("p2p.session", 1.0),
    "PARAM_QUERY_TIMEOUT": ("p2p.session", 2.5),
    "MODE_REPORT_GRACE": ("p2p.session", 0.3),
    "MODE_TABLE_READBACK_DELAY": ("p2p.session", 0.05),
    "RECONNECT_BACKOFF": ("p2p.session", (0.1,)),
    "STILL_FETCH_TIMEOUT": ("p2p.session", 1.0),
    "HISTORY_QUERY_TIMEOUT": ("p2p.session", 2.5),
    "SD_INFO_TIMEOUT": ("p2p.session", 1.0),
    "MEDIA_LIVE_FIRST_FRAME_TIMEOUT": ("p2p.session", 2.0),
    "MEDIA_RECORDING_FIRST_FRAME_TIMEOUT": ("p2p.session", 2.0),
    "READBACK_DELAY": ("station", 0.05),
    "PRESET_STREAM_IDLE_SECONDS": ("station", 1.0),
    "PRESET_SETTLE_SECONDS": ("station", 0.05),
    "PTZ_SETTLE_SECONDS": ("station", 0.05),
    "PTZ_BUSY_DELAY": ("station", 0.05),
    "DEFAULT_PRESET_RESULT_WAIT": ("station", 0.1),
    "FULL_RESOLUTION_TIMEOUT": ("station", 1.0),
    "LIVE_OPEN_TIMEOUT": ("devices.recipes", 2.0),
    "CAPTURE_START_TIMEOUT": ("p2p.broadcast", 2.0),
    "LAN_DISCOVERY_TIMEOUT": ("p2p.pppp", 0.5),
}
"""Each shortened wait: its name, the module that defines it, and the value used.

Left out on purpose: waits whose length is part of what a fake reproduces or a test
observes (``PARAM_SETTLE``, ``MEDIA_IDLE_TIMEOUT``, ``MEDIA_DRAIN_MAX``, the picture-size
hold ``SETTLE_STATION``/``SETTLE_STANDALONE``, the probe schedule, the reprobe and
idle-close delays); set those per test where needed.
"""


@contextmanager
def short_timeouts(**overrides: Any) -> Iterator[None]:
    """Use :data:`SHORT_TIMEOUTS` (``overrides`` by name win) inside the block.

    Every value is restored on exit. Raises :class:`KeyError` for an override that
    names no entry. Use it around one test, e.g. as a pytest fixture::

        @pytest.fixture
        def short():
            with short_timeouts():
                yield

    Not for concurrent tests in one process: the values are module attributes.
    """
    unknown = set(overrides) - set(SHORT_TIMEOUTS)
    if unknown:
        raise KeyError(f"no such library wait: {', '.join(sorted(unknown))}")
    saved: list[tuple[Any, str, Any]] = []
    try:
        for name, (module_name, value) in SHORT_TIMEOUTS.items():
            module = importlib.import_module(f"{_PACKAGE}.{module_name}")
            saved.append((module, name, getattr(module, name)))
            setattr(module, name, overrides.get(name, value))
        yield
    finally:
        for module, name, value in reversed(saved):
            setattr(module, name, value)
