"""A fake eufy cloud at the HTTP seam, a warm cache, and a real client wired to the fakes.

:class:`FakeCloud` answers the cloud requests the library makes (login, device list,
cipher keys, push token) below :class:`~..cloud.api.EufyCloudApi`'s envelope, so the
real session caching, throttle, hold-offs, owner-id rules and cache writes all run.
Only the HTTP round trip (and its MegaCrypto key exchange) is replaced.
"""

from __future__ import annotations

import contextvars
import itertools
import time
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from .._logging import redact_serial
from ..client import EufySecurity
from ..cloud import const
from ..cloud.api import EufyCloudApi, HttpSession, PasswordSource, _Identity
from ..cloud.api import classify_refusal as _classify_refusal
from ..devices.types import model_for_serial
from ..exceptions import CommunicationError, EufySecurityError, LoginLimitedError, RateLimitedError
from ..inclusion import Reach
from ..storage import MemoryStore, SessionCache, Store
from .station import FakeStation
from .synthetic import SYNTHETIC

if TYPE_CHECKING:
    import aiohttp

    from ..cloud.crypto import KeyExchange

__all__ = [
    "FakeCloud",
    "build_eufy_security",
    "camera_device",
    "enum_property",
    "range_property",
    "station_device",
    "thing_description",
    "warm_store",
]

LOOPBACK = "127.0.0.1"
_AUTH_TOKEN = "synthetic-auth-token"  # noqa: S105 - a synthetic token
_SHARED_KEY = "synthetic-shared-key"
_KEY_IDENT = "synthetic-key-ident"
_DSK_KEY = "0123456789abcdef0123456789abcdef"  # a synthetic device session key
_DSK_TTL = 3600.0
_IDENTS = itertools.count(1)  # every key exchange mints a new identity, as the cloud's

# The station whose owner id is being looked up, so its device-list request is named.
_owner_lookup: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "eufy_testing_owner_lookup", default=None
)


def station_device(
    serial: str = SYNTHETIC.station_sn, *, did: str = SYNTHETIC.did, name: str = "Home Base"
) -> dict[str, Any]:
    """A device-list entry for a station, as ``get_devs_list`` returns it."""
    model = model_for_serial(serial)
    return {
        "device_sn": serial,
        "device_type": model.cloud_device_type if model else None,
        "device_name": name,
        "p2p_did": did,
        "local_ip": SYNTHETIC.station_ip,
        "main_sw_version": "3.8.7.4",
    }


def camera_device(
    serial: str = SYNTHETIC.camera_sn,
    *,
    station_sn: str = SYNTHETIC.station_sn,
    channel: int = 0,
    name: str = "Front",
) -> dict[str, Any]:
    """A device-list entry for a camera paired to ``station_sn`` on ``channel``."""
    model = model_for_serial(serial)
    return {
        "device_sn": serial,
        "device_type": model.cloud_device_type if model else None,
        "device_name": name,
        "parent_sn": station_sn,
        "device_channel": channel,
    }


def thing_description(
    code: str, properties: list[dict[str, Any]], *, large_version: int = 1
) -> dict[str, Any]:
    """A synthetic thing description of ``code`` as ``get_things_list`` returns it."""
    return {
        "profile": {"product_code": code},
        "properties": properties,
        "large_version": large_version,
        "version": "1.0",
    }


def enum_property(
    identifier: str, choices: Mapping[int | str, str], *, default: int | str | None = None
) -> dict[str, Any]:
    """A synthetic TD enum property: ``choices`` maps each value to its vendor desc."""
    rows = [
        {"value": str(v), "desc": desc, "isDefault": "1" if v == default else "0"}
        for v, desc in choices.items()
    ]
    return {
        "identifier": identifier,
        "access_mode": "RW",
        "data_type": {"type": "enum", "specs": {"eunmList": rows}},  # vendor spelling
    }


def range_property(
    identifier: str,
    minimum: float,
    maximum: float,
    *,
    step: float | None = None,
    unit: str | None = None,
    default: float | None = None,
) -> dict[str, Any]:
    """A synthetic TD int property with a numeric range."""
    specs: dict[str, Any] = {"min": str(minimum), "max": str(maximum)}
    if step is not None:
        specs["step"] = str(step)
    if unit is not None:
        specs["unit"] = unit
    if default is not None:
        specs["defaultValue"] = str(default)
    return {
        "identifier": identifier,
        "access_mode": "RW",
        "data_type": {"type": "int", "specs": specs},
    }


@dataclass
class FakeCloud:
    """The eufy cloud as a test controls it; shared by every client built on it.

    ``devices`` are raw device-list entries. ``owner_ids`` names each station's owner
    (sent as ``member.admin_user_id``; a station without one is the account's own).
    ``cipher_keys`` holds each station's P2P ECC private key (hex); a station without
    one gets the cloud's empty answer. ``login_error``, when set, is what a password
    login meets: a :class:`RateLimitedError` also starts the hold-off the real cloud
    answer would. ``calls`` records every request that reached the cloud: ``"login"``,
    ``"devices"``, ``"owner:<serial>"`` (a device-list request made to find a station's
    owner), ``"cipher:<serial>"``, ``"dsk:<serial>"``, ``"push_token"``, ``"things"``,
    with serials redacted.

    ``things`` holds the thing description per product code that ``get_things_list``
    returns (see :func:`thing_description`); a code not in it is omitted from the reply.
    ``things_error``, when set, is raised by every such request; it is independent of
    ``call_errors``, which a things request never consumes.

    ``call_errors`` makes the cloud refuse: each entry is raised, in order, by the next
    request that is not a login (after it is recorded in ``calls``), exactly as the
    library's own answer classification would raise it, so the real session handling
    runs on it: a :class:`~..exceptions.SessionReplacedError` latches the session, and
    ``refusal(463, 4404)`` is the gateway's lapsed-key answer, which the library meets
    with one key exchange and a retry (so it takes two to make a call fail with
    :class:`~..exceptions.KeyExchangeRefusedError`). ``dsk_keys`` holds each on-demand
    station's device session key; a station without one gets a synthetic key.
    """

    devices: list[dict[str, Any]] = field(
        default_factory=lambda: [station_device(), camera_device()]
    )
    owner_ids: dict[str, str] = field(
        default_factory=lambda: {SYNTHETIC.station_sn: SYNTHETIC.account_id}
    )
    cipher_keys: dict[str, str] = field(default_factory=dict)
    login_error: EufySecurityError | None = None
    call_errors: list[EufySecurityError] = field(default_factory=list)
    dsk_keys: dict[str, str] = field(default_factory=dict)
    things: dict[str, dict[str, Any]] = field(default_factory=dict)
    things_error: EufySecurityError | None = None
    things_requested: list[tuple[str, ...]] = field(default_factory=list)
    """The product codes of each ``get_things_list`` request, in order."""
    calls: list[str] = field(default_factory=list)
    key_exchanges: int = 0
    """Key exchanges run on this cloud (a login's, and a re-key's)."""
    user_id: str = SYNTHETIC.account_id
    """The logged-in account's own cloud user id."""

    @staticmethod
    def refusal(status: int, code: int | None = None, message: str = "") -> EufySecurityError:
        """The error the library raises for a non-200 answer with ``code`` in its body."""
        return _classify_refusal(status, code, message)

    @classmethod
    def for_stations(cls, *stations: FakeStation, **kwargs: Any) -> FakeCloud:
        """A cloud that lists each fake station (the synthetic camera under the first).

        Owner ids and cipher keys come from the fakes, so a session handshakes.
        """
        devices = [station_device(s.serial, did=str(s.did)) for s in stations]
        if stations:
            devices.append(camera_device(station_sn=stations[0].serial))
        return cls(
            devices=devices,
            owner_ids={s.serial: s.account_id for s in stations},
            cipher_keys={s.serial: s.ecc_private_key_hex for s in stations},
            **kwargs,
        )

    def make_api(
        self,
        session: HttpSession,
        cache: SessionCache,
        email: str,
        password: PasswordSource | None,
        **kwargs: Any,
    ) -> EufyCloudApi:
        """An :class:`EufyCloudApi` whose requests this fake answers (``_cloud_factory``)."""
        return _FakeCloudApi(self, session, cache, email, password, **kwargs)

    # ── answers ──────────────────────────────────────────────────────────────

    async def _answer(self, api: _FakeCloudApi, path: str, payload: Mapping[str, Any]) -> Any:
        if path == const.LOGIN_PATH:
            self.calls.append("login")
            if self.login_error is not None:
                await api.hold_off_for(self.login_error)
                raise self.login_error
            return {"auth_token": _AUTH_TOKEN, "user_id": self.user_id}
        if path == const.DEVICES_PATH:
            owner_of = _owner_lookup.get()
            self.calls.append(f"owner:{redact_serial(owner_of)}" if owner_of else "devices")
            self._raise_call_error()
            return {"devices": [self._with_owner(d) for d in self.devices]}
        if path == const.CIPHERS_PATH:
            serial = str(payload.get("station_sn"))
            self.calls.append(f"cipher:{redact_serial(serial)}")
            self._raise_call_error()
            key = self.cipher_keys.get(serial)
            if key is None:
                return None
            return [{"cipher_id": cid, "ecc_private_key": key} for cid in payload["cipher_ids"]]
        if path == const.DSK_KEYS_PATH:
            serial = str(payload.get("station_sns", [""])[0])
            self.calls.append(f"dsk:{redact_serial(serial)}")
            self._raise_call_error()
            key = self.dsk_keys.get(serial, _DSK_KEY)
            return {"device_dsks": [{"dsk_key": key, "expiration": time.time() + _DSK_TTL}]}
        if path == const.PUSH_TOKEN_PATH:
            self.calls.append("push_token")
            self._raise_call_error()
            return None
        if path == const.THINGS_PATH:
            self.calls.append("things")
            codes = list(payload.get("product_codes") or [])
            self.things_requested.append(tuple(codes))
            if self.things_error is not None:
                raise self.things_error
            return {"things_list": [self.things[c] for c in codes if c in self.things]}
        raise CommunicationError(f"the fake cloud does not answer {path}")

    def _raise_call_error(self) -> None:
        if self.call_errors:
            raise self.call_errors.pop(0)

    def _with_owner(self, device: Mapping[str, Any]) -> dict[str, Any]:
        entry = dict(device)
        owner = self.owner_ids.get(str(entry.get("device_sn")))
        if owner is not None and owner != self.user_id:
            entry["member"] = {"admin_user_id": owner, "member_type": 1}
        return entry


class _FakeCloudApi(EufyCloudApi):
    """The real cloud client with the HTTP round trip answered by a :class:`FakeCloud`."""

    def __init__(self, fake: FakeCloud, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._fake = fake

    async def hold_off_for(self, error: EufySecurityError) -> None:
        """Record the hold-off a throttling answer carrying ``error`` starts."""
        if not isinstance(error, RateLimitedError):
            return
        login = isinstance(error, LoginLimitedError)
        default = const.LOGIN_HOLD_OFF_SECONDS if login else const.REQUEST_HOLD_OFF_SECONDS
        seconds = min(error.retry_after or default, const.LOCKOUT_HOLD_OFF_SECONDS)
        self._record_hold_off(login_only=login, seconds=seconds)
        await self._cache.async_save()

    async def async_get_station_owner_id(self, station_sn: str, *, refresh: bool = False) -> str:
        token = _owner_lookup.set(station_sn)
        try:
            return await super().async_get_station_owner_id(station_sn, refresh=refresh)
        finally:
            _owner_lookup.reset(token)

    async def _key_exchange(
        self, host: str, path: str, preset_key: str, *, auth: _Identity | None = None
    ) -> _Identity:
        self._fake.key_exchanges += 1
        return _Identity(key_ident=f"{_KEY_IDENT}-{next(_IDENTS)}", shared_key=_SHARED_KEY)

    async def _call(
        self,
        host: str,
        path: str,
        payload: Mapping[str, Any] | None,
        identity: _Identity,
        *,
        tolerate: frozenset[int] = frozenset(),
        category: bool = False,
        bootstrap: KeyExchange | None = None,
        preset_key: str | None = None,
        auth: _Identity | None = None,
    ) -> tuple[int, dict[str, Any], Any]:
        self._raise_if_held_off(login=False)
        data = await self._fake._answer(self, path, payload or {})
        return int(const.CloudCode.SUCCESS), {"code": 0, "data": data}, data


def _no_http() -> aiohttp.ClientSession:
    raise CommunicationError(
        "eufy_home_security.testing fakes the cloud below HTTP and does not fake push: "
        "start the client with push=False"
    )


def _run_unsuspended[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine that never waits (the fake cloud and a memory store never do)."""
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value  # type: ignore[no-any-return]
    coro.close()
    raise RuntimeError("warm_store: a cache writer suspended")


async def _async_warm(api: EufyCloudApi, cache: SessionCache, cloud: FakeCloud) -> None:
    await cache.async_load()
    await api.async_login()
    for device in await api.async_get_devices():
        if not device.is_station:
            continue
        await api.async_get_station_owner_id(device.device_sn)
        if device.device_sn in cloud.cipher_keys:
            await api.async_get_cipher_key(device.device_sn)
    await cache.async_save()


def warm_store(*, email: str, cloud: FakeCloud) -> MemoryStore:
    """A store holding the cache document as after one login against ``cloud``.

    Written by the library's own cache writers (a password login, the device list,
    each station's owner id and cipher key), so it keeps the real layout. Nothing is
    recorded in ``cloud.calls``, and ``cloud.login_error`` is not applied.
    """
    store = MemoryStore()
    scratch = replace(cloud, login_error=None, calls=[])
    cache = SessionCache(store, email)
    api = scratch.make_api(_no_http, cache, email, SYNTHETIC.password)
    _run_unsuspended(_async_warm(api, cache, scratch))
    return store


def build_eufy_security(
    *,
    email: str,
    store: Store,
    cloud: FakeCloud,
    stations: Mapping[str, FakeStation] | None = None,
    password: PasswordSource | None = SYNTHETIC.password,
    include: Mapping[str, Reach] | None = None,
    **kwargs: Any,
) -> EufySecurity:
    """A real :class:`EufySecurity` wired to ``cloud`` and the fake ``stations``.

    Everything above the cloud's HTTP round trip and the stations' UDP port is the
    real library: cache, throttle, claims, inclusion, sessions, events. ``stations``
    maps serials to *started* fakes, reached on loopback; they must share one discovery
    port (the client searches every station on one port). ``include`` is passed on as
    the client's ``stations`` inclusion map; other ``kwargs`` go to the client as they
    are. Push is not faked: call ``async_start(push=False)``.
    """
    fakes = dict(stations or {})
    ports = {fake.discovery_port for fake in fakes.values()}
    if 0 in ports:
        raise ValueError("start every FakeStation before building the client")
    if len(ports) > 1:
        raise ValueError("the fake stations must share one discovery port")
    hosts = dict.fromkeys(fakes, LOOPBACK) | dict(kwargs.pop("station_hosts", None) or {})
    factory: Callable[..., EufyCloudApi] = cloud.make_api
    return EufySecurity(
        _no_http,
        email,
        password,
        store=store,
        station_hosts=hosts,
        stations=include,
        _cloud_factory=factory,
        _discovery_port=ports.pop() if ports else None,
        **kwargs,
    )
