"""Which live open the app's handler sends for a product, per connect type (generated data).

``_live_open_data.py`` is written by ``scripts/gen_live_open.py`` from the product
handlers the eufy app runs: for each product and connect type, the library's open whose
recipe equals the handler's, or none; and where that open is a 1700 open behind a
station, the stop the handler sends. A product the table does not list (no cached
handler, or no ``open_live_stream`` action) has no recorded open. Pure lookups: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ._live_open_data import APP_VERSION, LIVE_OPEN, LIVE_STOP
from .recipes import ConnectType
from .versions import version_between


class LiveOpen(StrEnum):
    """A live open the library sends exactly as a product's handler describes it."""

    STATION = "station"
    """1350/1003 ``DeviceMsgBean`` with the plain payload
    (:func:`~.recipes.open_live_stream_station`); to a HomeBase 3 the library sends the
    app's T8030 fields as well, as the app's live player adds them."""
    SINGLE = "single"
    """1700 with sub-command 1000 and ``extValue`` (:func:`~.recipes.open_live_stream_single`).
    Behind a station it goes on the station's session with the camera's channel."""
    SINGLE_NO_EXT = "single_no_ext"
    """1700 with sub-command 1000, without ``extValue``."""


class LiveStop(StrEnum):
    """The stop a product's handler sends after its 1700 open behind a station."""

    BARE = "bare"
    """A bare 1004 frame whose body is the camera's channel (u32)."""
    STATION = "station"
    """A 1350 ``DeviceMsgBean`` of cmd 1004 naming the camera's channel."""


SINGLE_BEHIND: Final = frozenset({ConnectType.HB2, ConnectType.HB3})
"""Stations behind which the library sends a 1700 open: on the station's session, with
the camera's channel in the frame header."""

APP_WEBRTC_LIVE: Final[Mapping[ConnectType, frozenset[str]]] = MappingProxyType(
    {ConnectType.HB3: frozenset({"T8223", "T8224"})}
)
"""Products whose live view the eufy app streams over WebRTC behind that station kind,
inside the station firmware window of :data:`APP_WEBRTC_FIRMWARE` **[declared: eufy app]**.
The station's ``is_connect_webrtc`` is 1 only inside that window (0 outside it), and a
station at 1 routes the children its sub-device list names, which lists these products
on every firmware the window covers; the products' own ``is_connect_webrtc`` is 1."""

APP_WEBRTC_FIRMWARE: Final[Mapping[ConnectType, tuple[str, str]]] = MappingProxyType(
    {ConnectType.HB3: ("3.7.4.3", "4.1.9.999")}
)
"""The station firmware window, both bounds inclusive, in which the eufy app streams the
:data:`APP_WEBRTC_LIVE` products over WebRTC **[declared: eufy app]**; compared as the app
compares versions (:func:`~.versions.version_between`). Outside it, and with no firmware
known, the app streams them over P2P."""


_TABLE: Final[Mapping[str, Mapping[ConnectType, LiveOpen | None]]] = MappingProxyType(
    {
        code: MappingProxyType(
            {
                ConnectType(kind): None if mode is None else LiveOpen(mode)
                for kind, mode in modes.items()
            }
        )
        for code, modes in LIVE_OPEN.items()
    }
)

_STOPS: Final[Mapping[str, Mapping[ConnectType, LiveStop | None]]] = MappingProxyType(
    {
        code: MappingProxyType(
            {
                ConnectType(kind): None if stop is None else LiveStop(stop)
                for kind, stop in stops.items()
            }
        )
        for code, stops in LIVE_STOP.items()
    }
)


def app_version() -> str:
    """The eufy app build whose handlers the table was generated from."""
    return APP_VERSION


def has_live_open(product_code: str | None) -> bool:
    """Whether the table lists ``product_code`` (its handler has a live open)."""
    return product_code is not None and product_code.upper() in _TABLE


def live_open(product_code: str | None, connect: ConnectType) -> LiveOpen | None:
    """The open the handler of ``product_code`` sends under ``connect``; None when the
    product is not listed or its handler sends an open the library does not implement
    (see :func:`has_live_open` to tell the two apart)."""
    if product_code is None:
        return None
    return _TABLE.get(product_code.upper(), {}).get(connect)


def live_stop(product_code: str | None, connect: ConnectType) -> LiveStop | None:
    """The stop the handler of ``product_code`` sends after its 1700 open behind a
    ``connect`` station; None where it sends no 1700 open there, or a stop the library
    does not implement."""
    if product_code is None:
        return None
    return _STOPS.get(product_code.upper(), {}).get(connect)


def app_uses_webrtc(
    product_code: str | None, connect: ConnectType, *, station_firmware: str | None
) -> bool:
    """Whether the eufy app streams ``product_code`` over WebRTC under ``connect``, behind a
    station on ``station_firmware`` (None when unknown, which the app compares as below
    every window): :data:`APP_WEBRTC_LIVE` within :data:`APP_WEBRTC_FIRMWARE`."""
    if product_code is None or product_code.upper() not in APP_WEBRTC_LIVE.get(
        connect, frozenset()
    ):
        return False
    low, high = APP_WEBRTC_FIRMWARE[connect]
    return version_between(station_firmware or "", low, high)


def library_live_open(
    product_code: str | None, connect: ConnectType, *, station_firmware: str | None
) -> LiveOpen | None:
    """The open the library sends for ``product_code`` under ``connect``, behind a station
    on ``station_firmware``: the handler's (:func:`live_open`) where the library can send
    it there. On its own session (``SINGLE``) every :class:`LiveOpen`; behind a station
    :attr:`LiveOpen.STATION`, and a 1700 open behind a :data:`SINGLE_BEHIND` station when
    the library sends the handler's stop there (:func:`live_stop`) and the app does not
    stream the product over WebRTC there (:func:`app_uses_webrtc`). None otherwise."""
    mode = live_open(product_code, connect)
    if connect is ConnectType.SINGLE or mode is LiveOpen.STATION:
        return mode
    if (
        mode is None
        or connect not in SINGLE_BEHIND
        or app_uses_webrtc(product_code, connect, station_firmware=station_firmware)
        or live_stop(product_code, connect) is None
    ):
        return None
    return mode
