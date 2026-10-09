"""A fake eufy cloud at the HTTP seam, a warm cache, and a real client wired to the fakes.

:class:`FakeCloud` answers the cloud requests the library makes (login, device list,
cipher keys, push token) below :class:`~..cloud.api.EufyCloudApi`'s envelope, so the
real session caching, throttle, hold-offs, owner-id rules and cache writes all run.
Only the HTTP round trip (and its MegaCrypto key exchange) is replaced.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import itertools
import json
import logging
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, NoReturn, cast

from .._logging import redact_serial
from ..client import EufySecurity
from ..cloud import const
from ..cloud.api import EufyCloudApi, HttpSession, PasswordSource, _Identity
from ..devices.types import model_for_serial
from ..exceptions import (
    CommunicationError,
    EufySecurityError,
    LoginLimitedError,
    RateLimitedError,
    RefreshCooldownError,
)
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
    "security_device",
    "security_station",
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

# The region whose cluster the current request goes to.
_request_region: contextvars.ContextVar[str] = contextvars.ContextVar(
    "eufy_testing_request_region", default=const.DEFAULT_REGION
)

# The station whose owner id is being looked up, so its device-list request is named.
_owner_lookup: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "eufy_testing_owner_lookup", default=None
)

# A refusal's HTTP answer, kept on the error :meth:`FakeCloud.refusal` returns.
_ANSWER_ATTR = "_fake_cloud_answer"
# The shared key a replayed request is encrypted under (the library's body cipher needs hex).
_REPLAY_KEY = "0" * 32


@dataclass(frozen=True, slots=True)
class _HttpAnswer:
    """A cloud HTTP answer, replayed through the library's own answer handling."""

    status: int
    body: str = ""
    retry_after: float | None = None


# The answer the current request is replayed against, served by ``_FakeCloudApi._http``.
_replaying: contextvars.ContextVar[_HttpAnswer | None] = contextvars.ContextVar(
    "eufy_testing_replaying", default=None
)


class _ReplayResponse:
    """An ``aiohttp`` response carrying one :class:`_HttpAnswer`."""

    def __init__(self, answer: _HttpAnswer) -> None:
        self.status = answer.status
        self.headers = (
            {} if answer.retry_after is None else {"Retry-After": str(answer.retry_after)}
        )
        self._body = answer.body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self) -> _ReplayResponse:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class _ReplaySession:
    """An ``aiohttp`` session whose every POST gets one :class:`_HttpAnswer`."""

    def __init__(self, answer: _HttpAnswer) -> None:
        self._answer = answer

    def post(self, url: str, **kwargs: Any) -> _ReplayResponse:
        return _ReplayResponse(self._answer)


class _Refusal(Exception):  # noqa: N818 - a control-flow signal, not an error
    """Raised by :meth:`FakeCloud._answer` to have the API refuse with ``error``."""

    def __init__(self, error: EufySecurityError) -> None:
        super().__init__(error)
        self.error = error


def _answer_of(error: EufySecurityError) -> _HttpAnswer | None:
    """The cloud answer behind ``error``: a refusal's own, or a throttle code's."""
    answer = getattr(error, _ANSWER_ATTR, None)
    if isinstance(answer, _HttpAnswer):
        return answer
    if not isinstance(error, RateLimitedError):
        return None
    if error.code == const.HTTP_TOO_MANY_REQUESTS:
        return _HttpAnswer(error.code, retry_after=error.retry_after)
    if error.code in const.THROTTLE_CODES:
        return _HttpAnswer(200, json.dumps({"code": error.code, "msg": str(error)}))
    return None


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


def security_station(
    serial: str = SYNTHETIC.station_sn,
    *,
    did: str = SYNTHETIC.did,
    name: str = "Home Base",
    params: Mapping[int, str] | None = None,
) -> dict[str, Any]:
    """A security-realm ``get_hub_list`` entry for a station: it names itself in
    ``station_sn`` only, as the cloud's does."""
    model = model_for_serial(serial)
    return {
        "station_sn": serial,
        "station_name": name,
        "device_type": model.cloud_device_type if model else 0,
        "p2p_did": did,
        "main_sw_version": "2.1.6.9h",
        "main_hw_version": "P1",
        "params": [
            {"param_type": param, "param_value": value} for param, value in (params or {}).items()
        ],
    }


def security_device(
    serial: str = SYNTHETIC.camera_sn,
    *,
    station_sn: str = SYNTHETIC.station_sn,
    channel: int = 0,
    name: str = "Front",
) -> dict[str, Any]:
    """A security-realm ``get_devs_list`` entry for a device paired to ``station_sn``."""
    model = model_for_serial(serial)
    return {
        "device_sn": serial,
        "device_name": name,
        "device_type": model.cloud_device_type if model else 0,
        "station_sn": station_sn,
        "device_channel": channel,
        "main_sw_version": "2.0.7.6",
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
    ``cipher_keys`` holds each station's P2P ECC private key (hex) and
    ``rsa_cipher_keys`` its RSA one (the cloud's ``private_key``), served for every id
    in ``cipher_ids_held`` (None: any id); a station with neither, or a request naming
    no held id, gets the cloud's empty answer. ``cipher_ids_requested`` records the
    ids each ``get_ciphers`` request named, in order. ``login_error``, when set, is what a
    password login meets, refused as a ``call_errors`` entry is (see below). ``calls``
    records every request that reached the cloud: ``"login"``,
    ``"devices"``, ``"owner:<serial>"`` (a device-list request made to find a station's
    owner), ``"cipher:<serial>"``, ``"dsk:<serial>"``, ``"push_token"``, ``"things"``,
    with serials redacted. A request to a region other than ``region`` is recorded with
    ``@<region>`` appended (``"login@us"``, ``"devices@us"``).

    ``devices`` are listed by the ``region`` cluster; ``region_devices`` holds the
    device list of each other region (a region not in it answers ``{"devices": null}``,
    as a cluster holding none of the account's devices does). Every region
    serves the same account (``user_id``), as the real clusters do.

    ``houses`` are the ``house_infos`` the ``region`` cluster's house list answers, and
    ``house_devices`` each house id's own device list (a ``get_devs_list`` naming a
    ``house_id``). ``security_stations`` and ``security_devices`` are the raw entries of
    the security realm's ``get_hub_list`` and ``get_devs_list`` in the ``region`` cluster
    (see :func:`security_station`, :func:`security_device`); other regions list none of
    these. ``cipher_records`` serves a cipher id the same keys for every station
    (``ecc_private_key``, ``private_key``), ahead of the per-station keys. These requests
    are recorded as ``"houses"``, ``"house:<house_id>"``, ``"security_stations"`` and
    ``"security_devices"``. ``house_invites`` and ``device_invites`` are the raw pending
    invitation entries (``house_invite_records``, ``invites``) of the ``region`` cluster,
    recorded as ``"house_invites"`` and ``"device_invites"``.

    ``things`` holds the thing description per product code that ``get_things_list``
    returns (see :func:`thing_description`); a code not in it is omitted from the reply.
    ``things_error``, when set, refuses every such request as a ``call_errors`` entry
    does; it is independent of ``call_errors``, which a things request never consumes.

    The login country lookups are answered from ``client_country`` (the IP country) and
    ``country_regions`` (each country's home region) and are not recorded in ``calls``;
    ``last_login_ab`` keeps each region's last login ``ab``, which a
    ``get_last_login_code`` request (recorded as ``"last_login_code"``) answers, and a
    ``get_client_real_code`` request on a session is recorded as ``"client_country"``.

    ``call_errors`` makes the cloud refuse: each entry refuses, in order, the next
    request that is not a login (after it is recorded in ``calls``), from inside the
    library's envelope, so the real session handling runs on it: a
    :class:`~..exceptions.SessionReplacedError` latches the session, and
    ``refusal(463, 4404)`` is the gateway's lapsed-key answer, which the library meets
    with one key exchange and a retry (so it takes two to make a call fail with
    :class:`~..exceptions.KeyExchangeRefusedError`). An entry from :meth:`refusal`, and
    a :class:`RateLimitedError` whose ``code`` is a throttle body code or HTTP 429, is
    that cloud answer run through the library's answer handling: the library's hold-off
    starts and the library's error is raised. Another :class:`RateLimitedError` holds
    off for its ``retry_after`` (the library's default when None, every region's logins
    for a :class:`LoginLimitedError`) and is raised as is; any other error is raised as
    is. ``dsk_keys`` holds each on-demand
    station's device session key; a station without one gets a synthetic key.
    """

    devices: list[dict[str, Any]] = field(
        default_factory=lambda: [station_device(), camera_device()]
    )
    region: str = const.DEFAULT_REGION
    """The region whose cluster lists ``devices``."""
    region_devices: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """The device list of each other region; a region not in it lists none."""
    owner_ids: dict[str, str] = field(
        default_factory=lambda: {SYNTHETIC.station_sn: SYNTHETIC.account_id}
    )
    cipher_keys: dict[str, str] = field(default_factory=dict)
    rsa_cipher_keys: dict[str, str] = field(default_factory=dict)
    cipher_ids_held: set[int] | None = None
    cipher_records: dict[int, dict[str, str]] = field(default_factory=dict)
    houses: list[dict[str, Any]] = field(default_factory=list)
    house_devices: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    security_stations: list[dict[str, Any]] = field(default_factory=list)
    security_devices: list[dict[str, Any]] = field(default_factory=list)
    house_invites: list[dict[str, Any]] = field(default_factory=list)
    device_invites: list[dict[str, Any]] = field(default_factory=list)
    cipher_ids_requested: list[int] = field(default_factory=list)
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
    client_country: str | None = None
    """The host's IP country ``get_client_real_code`` names; None names none."""
    country_regions: dict[str, str] = field(default_factory=dict)
    """``estimate_domain``: each country's home region; another country names no cluster."""
    last_login_ab: dict[str, str] = field(default_factory=dict)
    """The ``ab`` of the last login per region (``get_last_login_code``)."""

    @staticmethod
    def refusal(
        status: int, code: int | None = None, message: str = "", *, retry_after: float | None = None
    ) -> EufySecurityError:
        """The error the library raises for an answer of HTTP ``status`` with ``code`` in its body.

        Served from ``call_errors`` or as ``login_error``, the answer itself runs through
        the library's answer handling, with its side effects: HTTP 401 with the takeover
        code latches the session, any other 401 costs one login and a retry, and HTTP 429
        (``retry_after`` is its ``Retry-After``) or a throttle code starts the hold-off.
        Raises :class:`ValueError` for an answer the library accepts.
        """
        body = {"msg": message} if code is None else {"code": code, "msg": message}
        answer = _HttpAnswer(status, json.dumps(body), retry_after)
        error = _classify(answer)
        setattr(error, _ANSWER_ATTR, answer)
        return error

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
            rsa_cipher_keys={s.serial: s.rsa_private_key_pem for s in stations if s.rsa_session},
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

    def devices_of(self, region: str) -> list[dict[str, Any]]:
        """The device list ``region``'s cluster answers."""
        return self.devices if region == self.region else self.region_devices.get(region, [])

    async def _answer(self, path: str, payload: Mapping[str, Any]) -> Any:
        region = _request_region.get()

        def note(call: str) -> None:
            self.calls.append(call if region == self.region else f"{call}@{region}")

        if path == const.LOGIN_PATH:
            note("login")
            if self.login_error is not None:
                raise _Refusal(self.login_error)
            self.last_login_ab[region] = str(payload.get("ab"))
            return {"auth_token": _AUTH_TOKEN, "user_id": self.user_id}
        if path == const.LAST_LOGIN_CODE_PATH:
            note("last_login_code")
            self._raise_call_error()
            return {"ab_code": self.last_login_ab.get(region, "").upper()}
        if path == const.CLIENT_COUNTRY_PATH:
            note("client_country")
            self._raise_call_error()
            return {"ab_code": self.client_country or ""}
        if path == const.DEVICES_PATH and "house_id" in payload:
            house_id = str(payload["house_id"])
            note(f"house:{house_id}")
            self._raise_call_error()
            listed = self.house_devices.get(house_id, []) if region == self.region else []
            return {"devices": [self._with_owner(d) for d in listed]}
        if path in {const.HOUSE_INVITES_PATH, const.DEVICE_INVITES_PATH}:
            house = path == const.HOUSE_INVITES_PATH
            note("house_invites" if house else "device_invites")
            self._raise_call_error()
            listed = (
                (self.house_invites if house else self.device_invites)
                if region == self.region
                else []
            )
            return {"house_invite_records" if house else "invites": list(listed)}
        if path == const.HOUSES_PATH:
            note("houses")
            self._raise_call_error()
            return {"house_infos": list(self.houses) if region == self.region else []}
        if path in {const.SECURITY_STATIONS_PATH, const.SECURITY_DEVICES_PATH}:
            stations = path == const.SECURITY_STATIONS_PATH
            note("security_stations" if stations else "security_devices")
            self._raise_call_error()
            if region != self.region:
                return []
            return [
                self._with_owner(e, key="station_sn" if stations else "device_sn")
                for e in (self.security_stations if stations else self.security_devices)
            ]
        if path == const.DEVICES_PATH:
            owner_of = _owner_lookup.get()
            note(f"owner:{redact_serial(owner_of)}" if owner_of else "devices")
            self._raise_call_error()
            region_list = self.devices if region == self.region else self.region_devices.get(region)
            # A cluster that holds none of the account's devices answers a null list.
            return {
                "devices": None
                if region_list is None
                else [self._with_owner(d) for d in region_list]
            }
        if path == const.CIPHERS_PATH:
            serial = str(payload.get("station_sn"))
            note(f"cipher:{redact_serial(serial)}")
            self._raise_call_error()
            ids = [int(cid) for cid in payload["cipher_ids"]]
            self.cipher_ids_requested.extend(ids)
            keys = {
                name: value
                for name, value in (
                    ("ecc_private_key", self.cipher_keys.get(serial)),
                    ("private_key", self.rsa_cipher_keys.get(serial)),
                )
                if value is not None
            }
            held = [
                cid for cid in ids if self.cipher_ids_held is None or cid in self.cipher_ids_held
            ]
            records = [
                {"cipher_id": cid, **self.cipher_records[cid]}
                if cid in self.cipher_records
                else {"cipher_id": cid, **keys}
                for cid in ids
                if cid in self.cipher_records or (keys and cid in held)
            ]
            return records or None
        if path == const.DSK_KEYS_PATH:
            serial = str(payload.get("station_sns", [""])[0])
            note(f"dsk:{redact_serial(serial)}")
            self._raise_call_error()
            key = self.dsk_keys.get(serial, _DSK_KEY)
            return {"device_dsks": [{"dsk_key": key, "expiration": time.time() + _DSK_TTL}]}
        if path == const.PUSH_TOKEN_PATH:
            note("push_token")
            self._raise_call_error()
            return None
        if path == const.THINGS_PATH:
            note("things")
            codes = list(payload.get("product_codes") or [])
            self.things_requested.append(tuple(codes))
            if self.things_error is not None:
                raise _Refusal(self.things_error)
            return {"things_list": [self.things[c] for c in codes if c in self.things]}
        raise CommunicationError(f"the fake cloud does not answer {path}")

    def _raise_call_error(self) -> None:
        if self.call_errors:
            raise _Refusal(self.call_errors.pop(0))

    def _with_owner(self, device: Mapping[str, Any], *, key: str = "device_sn") -> dict[str, Any]:
        entry = dict(device)
        owner = self.owner_ids.get(str(entry.get(key)))
        if owner is not None and owner != self.user_id:
            entry["member"] = {"admin_user_id": owner, "member_type": 1}
        return entry


class _FakeCloudApi(EufyCloudApi):
    """The real cloud client with the HTTP round trip answered by a :class:`FakeCloud`."""

    def __init__(self, fake: FakeCloud, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._fake = fake

    def _http(self) -> aiohttp.ClientSession:
        answer = _replaying.get()
        if answer is None:
            return super()._http()
        return cast("aiohttp.ClientSession", _ReplaySession(answer))

    async def _refuse(
        self,
        error: EufySecurityError,
        path: str,
        region: str,
        replay: Callable[[], Awaitable[object]],
    ) -> NoReturn:
        """Refuse a request with ``error``, with the side effects the cloud answer has.

        An error with a cloud answer behind it (:func:`_answer_of`) is that answer
        replayed through the library's own handling, which raises. Another throttle holds
        off for its ``retry_after`` (the library's default when None) and is raised as is.
        """
        answer = _answer_of(error)
        if answer is not None:
            token = _replaying.set(answer)
            try:
                await replay()
            finally:
                _replaying.reset(token)
            raise ValueError(f"HTTP {answer.status} {answer.body} is not a refusal")
        if isinstance(error, RateLimitedError) and not isinstance(error, RefreshCooldownError):
            login = isinstance(error, LoginLimitedError)
            default = const.LOGIN_HOLD_OFF_SECONDS if login else const.REQUEST_HOLD_OFF_SECONDS
            throttle = const.Throttle(login_only=login, seconds=error.retry_after or default)
            with contextlib.suppress(RateLimitedError):
                await self._hold_off(throttle, error.code, str(error), path, region=region)
        raise error

    async def async_get_station_owner_id(self, station_sn: str, *, refresh: bool = False) -> str:
        token = _owner_lookup.set(station_sn)
        try:
            return await super().async_get_station_owner_id(station_sn, refresh=refresh)
        finally:
            _owner_lookup.reset(token)

    async def _key_exchange(
        self,
        host: str,
        path: str,
        preset_key: str,
        *,
        auth: _Identity | None = None,
        region: str = const.DEFAULT_REGION,
    ) -> _Identity:
        self._fake.key_exchanges += 1
        return _Identity(
            key_ident=f"{_KEY_IDENT}-{next(_IDENTS)}", shared_key=_SHARED_KEY, region=region
        )

    async def _lookup_client_country(self) -> str | None:
        """Answered from ``client_country``; no key exchange, nothing recorded in ``calls``."""
        return self._fake.client_country

    async def _lookup_home_region(self, country: str) -> str | None:
        """Answered from ``country_regions``; nothing recorded in ``calls``."""
        return self._fake.country_regions.get(country)

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
        token = _request_region.set(identity.region)
        try:
            data = await self._fake._answer(path, payload or {})
        except _Refusal as refusal:
            # The library's envelope, answered with the refusal's HTTP answer.
            replay = functools.partial(
                super()._call,
                host,
                path,
                payload,
                replace(identity, shared_key=_REPLAY_KEY),
                tolerate=tolerate,
                category=category,
                bootstrap=bootstrap,
                preset_key=preset_key,
                auth=auth,
            )
            await self._refuse(refusal.error, path, identity.region, replay)
        finally:
            _request_region.reset(token)
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


def _classify(answer: _HttpAnswer) -> EufySecurityError:
    """The error the library's answer handling raises for ``answer``, on a scratch cache."""
    cache = SessionCache(MemoryStore(), SYNTHETIC.email)
    api = _FakeCloudApi(FakeCloud(), _no_http, cache, SYNTHETIC.email, None)
    identity = _Identity(
        key_ident=_KEY_IDENT,
        shared_key=_REPLAY_KEY,
        auth_token=_AUTH_TOKEN,
        user_id=SYNTHETIC.account_id,
    )
    logger = logging.getLogger(EufyCloudApi.__module__)
    disabled, logger.disabled = logger.disabled, True  # no throttle warning: nothing was served
    token = _replaying.set(answer)
    try:
        _run_unsuspended(cache.async_load())
        _run_unsuspended(EufyCloudApi._call(api, "", "", None, identity))
    except EufySecurityError as error:
        return error
    finally:
        _replaying.reset(token)
        logger.disabled = disabled
    raise ValueError(f"HTTP {answer.status} {answer.body} is not a refusal")


async def _async_warm(api: EufyCloudApi, cache: SessionCache, cloud: FakeCloud) -> None:
    await cache.async_load()
    await api.async_login()
    for device in await api.async_get_devices():
        if not device.is_station:
            continue
        await api.async_get_station_owner_id(device.device_sn)
        if device.device_sn in cloud.cipher_keys or device.device_sn in cloud.rsa_cipher_keys:
            held = cloud.cipher_ids_held
            for cipher_id in [const.CIPHER_ID_P2P] if held is None else sorted(held):
                await api.async_get_cipher_keys(device.device_sn, cipher_id)
    await cache.async_save()


def warm_store(*, email: str, cloud: FakeCloud) -> MemoryStore:
    """A store holding the cache document as after the first login against ``cloud``.

    That login asks every region once: ``cloud.region`` lists ``cloud.devices``, and a
    region listing none is suspended (see :class:`~..cloud.api.EufyCloudApi`).

    Written by the library's own cache writers (a password login, the device list,
    each station's owner id and cipher key), so it keeps the real layout. Nothing is
    recorded in ``cloud.calls`` or ``cloud.cipher_ids_requested``, and
    ``cloud.login_error`` is not applied.
    """
    store = MemoryStore()
    scratch = replace(cloud, login_error=None, calls=[], cipher_ids_requested=[])
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
