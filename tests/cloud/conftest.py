"""A synthetic MegaCrypto server for the cloud tests.

Every fixture is built by encrypting synthetic plaintext with a freshly generated
server key pair — no captured ciphertext, no real identifiers. :class:`FakeMega`
registers aioresponses callbacks that speak the real envelope: it decrypts the
client's key-exchange public key, runs the same ECDH, and encrypts its replies
under the derived shared key, exactly as the live gateway does.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
from collections.abc import Callable, Mapping
from typing import Any, cast

import aiohttp
import pytest
from aioresponses import CallbackResult
from cryptography.hazmat.primitives.asymmetric import ec

# aioresponses 0.7.9 builds a ClientResponse without the `stream_writer` argument
# that aiohttp 3.14 made a required keyword-only. Give it a default so the pinned
# pair works together; harmless once aioresponses catches up.
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

from eufy_home_security.cloud import const, crypto
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC

FAKE_OWNER_ID = "fedcba9876543210fedcba9876543210fedcba98"
FAKE_AUTH_TOKEN = "auth-token-0123456789abcdef"
FAKE_PENDING_TOKEN = "pending-token-0123456789"
FAKE_ECC_KEY = "ab" * 32


def _url(host: str, path: str) -> str:
    return f"https://{host}{path}"


class FakeMega:
    """Stateful fake of both MegaCrypto realms, driven by aioresponses callbacks.

    It answers on every region's hosts with one account; ``devices`` are listed by
    ``region``'s cluster, ``region_devices`` by the others (none when absent).
    """

    def __init__(self, region: str = "eu") -> None:
        self.region = region
        self.region_devices: dict[str, list[dict[str, Any]]] = {}
        # Region -> the challenge code its logins answer with instead of ``login_code``.
        self.region_login_code: dict[str, int] = {}
        # (endpoint, region) of every request, in order.
        self.region_calls: list[tuple[str, str]] = []
        self._server_key = ec.generate_private_key(ec.SECP256R1())
        self._shared: dict[str, str] = {}  # key_ident -> shared_key hex
        self.calls: list[tuple[str, dict[str, Any]]] = []
        # Test-controlled behaviour:
        self.login_code = 0
        self.login_data: dict[str, Any] = {
            "auth_token": FAKE_AUTH_TOKEN,
            "ap_cloud_user_id": SYNTHETIC.account_id,
            "mega_domain": f"mega-{region}-pr.eufy.com",
        }
        self.login_extra: dict[str, Any] = {}
        # Regions whose login without a verify_code answers code 0 with ``fa_info.step`` 26052.
        self.two_step: set[str] = set()
        # The auth token of each ``sendmsg/verify_code`` request, with its body.
        self.code_requests: list[tuple[str, dict[str, Any]]] = []
        self.devices: list[dict[str, Any]] = []
        # get_things_list: the thing descriptions the fake knows; a request is answered
        # with those whose ``profile.product_code`` it names (unknown codes omitted).
        self.things: list[dict[str, Any]] = []
        # Endpoint ("devices", "ciphers", "push") -> a body code its next call answers
        # with instead of success, e.g. {"devices": 401}.
        self.code_once: dict[str, int] = {}
        # Endpoint -> the raw decrypted ``data`` its success carries instead of the default.
        self.data_override: dict[str, Any] = {}
        # Endpoint -> a function of the shared key returning the raw body its next call
        # answers with (malformed-response tests).
        self.body_once: dict[str, Callable[[str], str]] = {}
        # Endpoint -> (HTTP status, headers) its next call answers with.
        self.status_once: dict[str, tuple[int, dict[str, str]]] = {}
        # Endpoint -> (HTTP status, JSON body) each of its next calls answers with, in
        # order (the gateway's non-200 answers carry a body code, e.g. 463 / 4404).
        self.error_bodies: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        # Seconds every reply is delayed, so concurrent calls really interleave (a
        # synchronous callback completes a mocked request without yielding).
        self.latency = 0.0
        # Endpoint ("login", "devices", "push" …) -> a delay overriding ``latency``.
        self.slow: dict[str, float] = {}
        self.cipher_objects: list[dict[str, Any]] | None = None
        # get_house_list's house_infos, and each house id's own device list.
        self.houses: list[dict[str, Any]] = []
        self.house_devices: dict[str, list[dict[str, Any]]] = {}
        # The security realm's get_hub_list / get_devs_list entries.
        self.security_stations: list[dict[str, Any]] = []
        self.security_devices: list[dict[str, Any]] = []
        # "house_invites" / "device_invites" -> the answer's data (default: an empty list).
        self.invite_data: dict[str, Any] = {}
        # Endpoint -> the request headers of each call, in order.
        self.headers: dict[str, list[dict[str, str]]] = {}
        self.dsk_objects: list[dict[str, Any]] | None = None
        # get_rom_version: None → the OTA "up to date" error object (code 20004 in data);
        # a dict → returned as the RomVersionData.
        self.rom_version_data: dict[str, Any] | None = None
        self.captcha = {"captcha_id": "cap-123", "item": "aGVsbG8="}
        # get_client_real_code's ``ab_code`` (the caller's IP country); "" names none.
        self.client_country = ""
        # estimate_domain: country -> the region whose mega- domain it answers; any other
        # country gets a non-mega domain, as live.
        self.country_regions: dict[str, str] = {}
        # The ``ab`` of the last successful login per region (get_last_login_code).
        self.last_login_ab: dict[str, str] = {}
        # Login ``ab`` -> the devices only a session made with it lists (its own token).
        self.country_devices: dict[str, list[dict[str, Any]]] = {}
        self._token_ab: dict[str, str] = {}
        self._login_calls = 0

    # ── registration on an aioresponses mock ─────────────────────────────────

    def _delayed(
        self, endpoint: str, callback: Callable[..., CallbackResult], region: str = ""
    ) -> Any:
        async def cb(url: str, **kwargs: Any) -> CallbackResult:
            self.region_calls.append((endpoint, region))
            if delay := self.slow.get(endpoint, self.latency):
                await asyncio.sleep(delay)
            return callback(url, **kwargs)

        return cb

    def logins_in(self, region: str) -> int:
        """Login requests ``region``'s cluster received."""
        return sum(1 for endpoint, r in self.region_calls if endpoint == "login" and r == region)

    def install(self, mock: Any) -> None:
        for region in const.REGIONS:
            self._install_region(mock, region)

    def _install_region(self, mock: Any, region: str) -> None:
        openapi = const.cluster_host("openapi", region)
        passport = const.cluster_host("passport", region)
        house = const.cluster_host("house", region)
        push = const.cluster_host("push", region)
        sec = const.security_host(region)
        mock.post(
            _url(openapi, const.KEY_EXCHANGE_PATH),
            callback=self._delayed("exchange", self._exchange(const.MEGA_PRESET_KEY), region),
            repeat=True,
        )
        mock.post(
            _url(sec, const.SECURITY_KEY_EXCHANGE_PATH),
            callback=self._delayed("exchange", self._exchange(const.SECURITY_PRESET_KEY), region),
            repeat=True,
        )
        mock.post(
            _url(passport, const.LOGIN_PATH),
            callback=self._delayed("login", functools.partial(self._login, region=region), region),
            repeat=True,
        )
        mock.post(
            _url(passport, const.CAPTCHA_PATH),
            callback=self._delayed("captcha", self._captcha, region),
            repeat=True,
        )
        mock.post(
            _url(passport, const.CLIENT_COUNTRY_PATH),
            callback=self._delayed("client_country", self._client_country, region),
            repeat=True,
        )
        mock.post(
            _url(passport, const.LAST_LOGIN_CODE_PATH),
            callback=self._delayed(
                "last_login_code", functools.partial(self._last_login_code, region=region), region
            ),
            repeat=True,
        )
        mock.post(
            _url(const.mega_host(region), const.ESTIMATE_DOMAIN_PATH),
            callback=self._delayed("estimate_domain", self._estimate_domain, region),
            repeat=True,
        )
        mock.post(
            _url(house, const.DEVICES_PATH),
            callback=self._delayed(
                "devices", functools.partial(self._device_list, region=region), region
            ),
            repeat=True,
        )
        mock.post(
            _url(house, const.HOUSES_PATH),
            callback=self._delayed("houses", self._house_list, region),
            repeat=True,
        )
        for host, path, endpoint in (
            (house, const.HOUSE_INVITES_PATH, "house_invites"),
            (
                const.cluster_host("devicerelation", region),
                const.DEVICE_INVITES_PATH,
                "device_invites",
            ),
        ):
            mock.post(
                _url(host, path),
                callback=self._delayed(
                    endpoint, functools.partial(self._invite_list, endpoint=endpoint), region
                ),
                repeat=True,
            )
        for path, endpoint in (
            (const.SECURITY_STATIONS_PATH, "security_stations"),
            (const.SECURITY_DEVICES_PATH, "security_devices"),
        ):
            mock.post(
                _url(sec, path),
                callback=self._delayed(
                    endpoint, functools.partial(self._security_list, endpoint=endpoint), region
                ),
                repeat=True,
            )
        mock.post(
            _url(sec, const.CIPHERS_PATH),
            callback=self._delayed("ciphers", self._get_ciphers, region),
            repeat=True,
        )
        mock.post(
            _url(const.cluster_host("devicerelation", region), const.DSK_KEYS_PATH),
            callback=self._delayed("dsk", self._get_dsk, region),
            repeat=True,
        )
        mock.post(
            _url(push, const.PUSH_TOKEN_PATH),
            callback=self._delayed("push", self._push_token, region),
            repeat=True,
        )
        mock.post(
            _url(push, const.SEND_VERIFY_CODE_PATH),
            callback=self._delayed("sendmsg", self._send_verify_code, region),
            repeat=True,
        )
        mock.post(
            _url(const.cluster_host("ota", region), const.OTA_ROM_PATH),
            callback=self._delayed("ota", self._get_rom_version, region),
            repeat=True,
        )
        mock.post(
            _url(const.cluster_host("things", region), const.THINGS_PATH),
            callback=self._delayed("things", self._things, region),
            repeat=True,
        )

    @property
    def login_calls(self) -> int:
        return self._login_calls

    @property
    def things_calls(self) -> int:
        return sum(1 for name, _ in self.calls if name == "things")

    # ── helpers ──────────────────────────────────────────────────────────────

    def _ident(self, kwargs: dict[str, Any]) -> str:
        return str(kwargs["headers"]["x-key-ident"])

    def _shared_for(self, kwargs: dict[str, Any]) -> str:
        return self._shared[self._ident(kwargs)]

    def _decrypt_body(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        raw = kwargs["data"]
        text = raw.decode() if isinstance(raw, bytes) else str(raw)
        obj = json.loads(crypto.body_decrypt(text, self._shared_for(kwargs)))
        assert isinstance(obj, Mapping)
        return dict(obj)

    def _failure_once(self, endpoint: str, kwargs: dict[str, Any]) -> CallbackResult | None:
        if queued := self.error_bodies.get(endpoint):
            status_code, error_body = queued.pop(0)
            return CallbackResult(status=status_code, body=json.dumps(error_body))
        if (status := self.status_once.pop(endpoint, None)) is not None:
            return CallbackResult(status=status[0], headers=status[1], body="")
        if (body := self.body_once.pop(endpoint, None)) is not None:
            return CallbackResult(status=200, body=body(self._shared_for(kwargs)))
        code = self.code_once.pop(endpoint, None)
        if code is None:
            return None
        return CallbackResult(status=200, body=json.dumps({"code": code, "msg": "error"}))

    def _reply(self, shared: str, code: int, data: Any, **extra: Any) -> CallbackResult:
        body: dict[str, Any] = {"code": code, "msg": "ok" if code == 0 else "error", **extra}
        if data is not None:
            body["data"] = crypto.body_encrypt(json.dumps(data), shared)
        return CallbackResult(status=200, body=json.dumps(body))

    # ── endpoint callbacks ───────────────────────────────────────────────────

    def _exchange(self, preset: str) -> Any:
        def cb(url: str, **kwargs: Any) -> CallbackResult:
            body = json.loads(kwargs["data"])
            client_pub = crypto.preset_decrypt(body["client_public_key"], preset)
            client_key = crypto.load_public_key(client_pub)
            shared = self._server_key.exchange(ec.ECDH(), client_key).hex()
            self._shared[self._ident(kwargs)] = shared
            server_pub = crypto.public_key_hex(self._server_key)
            data = {"server_public_key": crypto.preset_encrypt(server_pub, preset)}
            return CallbackResult(status=200, body=json.dumps({"code": 0, "data": data}))

        return cb

    def _login(self, url: str, *, region: str = "", **kwargs: Any) -> CallbackResult:
        self._login_calls += 1
        shared = self._shared_for(kwargs)
        payload = self._decrypt_body(kwargs)
        self.calls.append(("login", payload))
        self.headers.setdefault("login", []).append(dict(kwargs["headers"]))
        if failure := self._failure_once("login", kwargs):
            return failure
        if code := self.region_login_code.get(region, self.login_code):
            return CallbackResult(
                status=200,
                body=json.dumps({"code": code, "msg": "challenge", **self.login_extra}),
            )
        if region in self.two_step and not payload.get("verify_code"):
            pending = {
                **self.login_data,
                "auth_token": FAKE_PENDING_TOKEN,
                "fa_info": {"info": "use verify code for 2fa", "step": 26052},
            }
            return self._reply(shared, 0, pending)
        ab = str(payload.get("ab"))
        self.last_login_ab[region] = ab
        data = {**self.login_data, "fa_info": {"info": "", "step": 0}}
        if ab in self.country_devices:
            data["auth_token"] = f"{FAKE_AUTH_TOKEN}-{ab}"
            self._token_ab[data["auth_token"]] = ab
        return self._reply(shared, 0, data)

    def _client_country(self, url: str, **kwargs: Any) -> CallbackResult:
        self.calls.append(("client_country", self._decrypt_body(kwargs)))
        if failure := self._failure_once("client_country", kwargs):
            return failure
        return self._reply(self._shared_for(kwargs), 0, {"ab_code": self.client_country})

    def _last_login_code(self, url: str, *, region: str = "", **kwargs: Any) -> CallbackResult:
        self.calls.append(("last_login_code", self._decrypt_body(kwargs)))
        if failure := self._failure_once("last_login_code", kwargs):
            return failure
        code = self.last_login_ab.get(region, "").upper()
        return self._reply(self._shared_for(kwargs), 0, {"ab_code": code})

    def _estimate_domain(self, url: str, **kwargs: Any) -> CallbackResult:
        """Plaintext both ways, as live: no identity, ``data`` not encrypted."""
        payload = json.loads(kwargs["data"])
        self.calls.append(("estimate_domain", payload))
        if failure := self._failure_once("estimate_domain", kwargs):
            return failure
        region = self.country_regions.get(str(payload.get("ab")))
        domain = f"mega-{region}-pr.eufy.com" if region else "aiot-api-eu.eufylife.com"
        body = {"code": 0, "msg": "success!", "data": {"domain": domain, "is_same_region": True}}
        return CallbackResult(status=200, body=json.dumps(body))

    def _send_verify_code(self, url: str, **kwargs: Any) -> CallbackResult:
        payload = self._decrypt_body(kwargs)
        self.code_requests.append((str(kwargs["headers"].get("x-auth-token")), payload))
        if failure := self._failure_once("sendmsg", kwargs):
            return failure
        return self._reply(self._shared_for(kwargs), 0, None)

    def _captcha(self, url: str, **kwargs: Any) -> CallbackResult:
        return self._reply(self._shared_for(kwargs), 0, self.captcha)

    def _device_list(self, url: str, *, region: str = "", **kwargs: Any) -> CallbackResult:
        payload = self._decrypt_body(kwargs)
        self.calls.append(("devices", payload))
        if failure := self._failure_once("devices", kwargs):
            return failure
        if "house_id" in payload:
            listed = self.house_devices.get(str(payload["house_id"]), [])
            return self._reply(self._shared_for(kwargs), 0, {"devices": listed})
        if (ab := self._token_ab.get(str(kwargs["headers"].get("x-auth-token")))) is not None:
            return self._reply(self._shared_for(kwargs), 0, {"devices": self.country_devices[ab]})
        if region and region != self.region:
            return self._reply(
                self._shared_for(kwargs), 0, {"devices": self.region_devices.get(region)}
            )
        data = self.data_override.get("devices", {"devices": self.devices})
        return self._reply(self._shared_for(kwargs), 0, data)

    def _house_list(self, url: str, **kwargs: Any) -> CallbackResult:
        self.calls.append(("houses", self._decrypt_body(kwargs)))
        if failure := self._failure_once("houses", kwargs):
            return failure
        return self._reply(self._shared_for(kwargs), 0, {"house_infos": self.houses})

    def _invite_list(self, url: str, *, endpoint: str, **kwargs: Any) -> CallbackResult:
        self.calls.append((endpoint, self._decrypt_body(kwargs)))
        if failure := self._failure_once(endpoint, kwargs):
            return failure
        key = "house_invite_records" if endpoint == "house_invites" else "invites"
        return self._reply(self._shared_for(kwargs), 0, self.invite_data.get(endpoint, {key: []}))

    def _security_list(self, url: str, *, endpoint: str, **kwargs: Any) -> CallbackResult:
        self.calls.append((endpoint, self._decrypt_body(kwargs)))
        self.headers.setdefault(endpoint, []).append(dict(kwargs["headers"]))
        if failure := self._failure_once(endpoint, kwargs):
            return failure
        entries = (
            self.security_stations if endpoint == "security_stations" else self.security_devices
        )
        return self._reply(self._shared_for(kwargs), 0, entries)

    def _get_ciphers(self, url: str, **kwargs: Any) -> CallbackResult:
        shared = self._shared_for(kwargs)
        payload = self._decrypt_body(kwargs)
        self.calls.append(("ciphers", payload))
        if failure := self._failure_once("ciphers", kwargs):
            return failure
        if self.cipher_objects is None:
            return self._reply(shared, 0, None)  # empty success
        return self._reply(shared, 0, self.cipher_objects)

    def _get_dsk(self, url: str, **kwargs: Any) -> CallbackResult:
        shared = self._shared_for(kwargs)
        self.calls.append(("dsk", self._decrypt_body(kwargs)))
        if failure := self._failure_once("dsk", kwargs):
            return failure
        if self.dsk_objects is None:
            return self._reply(shared, 0, {"device_dsks": []})
        return self._reply(shared, 0, {"device_dsks": self.dsk_objects})

    def _push_token(self, url: str, **kwargs: Any) -> CallbackResult:
        self.calls.append(("push", self._decrypt_body(kwargs)))
        if failure := self._failure_once("push", kwargs):
            return failure
        return self._reply(self._shared_for(kwargs), 0, None)  # a bare code 0, as live

    def _get_rom_version(self, url: str, **kwargs: Any) -> CallbackResult:
        shared = self._shared_for(kwargs)
        self.calls.append(("ota", self._decrypt_body(kwargs)))
        if failure := self._failure_once("ota", kwargs):
            return failure
        if self.rom_version_data is None:  # up to date: code-0 envelope, 20004 in the data
            reason = f"error: code = {const.OTA_NO_UPGRADE_CODE} reason =  message = "
            return self._reply(shared, 0, {"reason": reason})
        return self._reply(shared, 0, self.rom_version_data)

    def _things(self, url: str, **kwargs: Any) -> CallbackResult:
        payload = self._decrypt_body(kwargs)
        self.calls.append(("things", payload))
        if failure := self._failure_once("things", kwargs):
            return failure
        codes = set(payload.get("product_codes", []))
        default = {"things_list": [t for t in self.things if t["profile"]["product_code"] in codes]}
        return self._reply(self._shared_for(kwargs), 0, self.data_override.get("things", default))


@pytest.fixture
def fake_mega() -> FakeMega:
    return FakeMega()


@pytest.fixture
def cache() -> SessionCache:
    return SessionCache(MemoryStore(), SYNTHETIC.email)
