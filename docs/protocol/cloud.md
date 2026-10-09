# Cloud: eufy_mega

The cloud provides four things, all needed before any local traffic: a login
session, the device list, the station owner's user id, and the station's cipher 40
private key. After those are cached, a client can run a HomeBase on the LAN with no
cloud calls at all. Only cloud push ([events.md](events.md)) stays on the cloud; a
standalone battery camera also needs a [DSK](#device-session-key-dsk) for each wake.

Code: `src/eufy_home_security/cloud/crypto.py` (pure primitives),
`cloud/api.py` (calls), `cloud/const.py` (constants and codes).

## Hosts

| realm | host | used for |
|---|---|---|
| eufy.com ("basic") | `app-{service}-{region}-pr.eufy.com` | key exchange (`openapi`), login (`passport`), devices (`house`), push token (`push`), also `devicerelation`, `event`, `things` |
| eufy_security | `security-app-eu.eufylife.com` (`eu`), `security-app.eufylife.com` (`us`) | `/v3/...`, and in particular `/v3/app/cipher/get_ciphers` |

- `region` is `eu` or `us`: the app's two production environments (the rest are QA)
  **[app]**. The US security-realm host carries no region;
  `security-app-us.eufylife.com` does not resolve.
- Each region is its own cluster. A login on either succeeds for any account (code 0,
  the same user id, `ab_code` = the `ab` sent, `country_code` and an empty `domain`
  alike on both), but `get_devs_list` lists only the devices homed on that cluster; the
  other answers `{"devices": null}` **[verified]**. A session on one cluster does not end
  the other's **[verified]**. Within a cluster the login's country decides the list (see
  [Login country](#login-country)): the library logs in once per country, on that
  country's cluster (see [the guide](../how-to/home-assistant.md#cloud-regions)).
- A login answer's `mega_domain` (`mega-{region}-pr.eufy.com`), when present, gives the
  region's hosts: the domain with `mega-` replaced by `app-{service}-`, as the app builds
  them **[app]**. The library uses it only for the region it names; the answers seen so far
  carried none (`domain ""`).
- The library's `region` argument pins every call to one region.
- `POST mega-{region}-pr.eufy.com/passport/estimate_domain` names a country's cluster;
  the library uses it to find the home region of the login country (see
  [Login country](#login-country)).

## Request envelope (MegaCrypto)

Every call is `POST` with a JSON body, over HTTPS (the app uses HTTP/2, but HTTP/1.1 works).

| header | value |
|---|---|
| `app-name` | `eufy_mega` |
| `app-version`/`app_version`, `os-type`/`os_type`, `os-version`/`os_version`, `phone-model`/`phone_model`, `model-type` | app context. The app sends both dash and underscore spellings. `os-type: android` also decides FCM rather than APNs for push. |
| `openudid` | per-install id, 16 lowercase hex. Mint once and persist. |
| `country`, `language`, `timezone`, `user-agent: ktor-client` | context |
| `x-encryption-info` | `algo_ecdh` |
| `x-key-ident` | the identity's 32-hex key ident |
| `x-request-ts` | unix seconds |
| `x-request-once` | random 32-hex nonce |
| `x-signature` | `hex(HMAC-SHA256(signing_key_ascii, ts + "+" + once + "+" + signed_body))` |
| `x-auth-token`, `authorization` | the session token (authenticated calls) |
| `gtoken` | lowercase hex MD5 of the logged-in user id (authenticated calls) |
| `category`, `app-tab` | `eufy_security`. **Required** on `get_ciphers` and **forbidden** on the security-realm key exchange. The app sends it on other calls, and whether they need it is not established **[open]**. |

**Body encryption.** A request body is `base64(IV16 ‖ AES-128-CBC-PKCS7(json))` with
key `bytes.fromhex(shared_key[:32])` and a random IV. The response's `data` field is
encrypted the same way under the same key. `signed_body` is the base64 string
actually sent. An empty object must still be encrypted: a plaintext `{}` gets
`HTTP 400 symmetric.AesCBCDecryptV2 Error` **[verified]**.

**Signing key.** `shared_key[:32]` as ASCII for an established identity, or the
preset key's hex string as ASCII for the key exchange itself.

## Key exchange

Each realm has its own static preset key (embedded in the app) and its own exchange path.

| realm | preset key | path | authenticated |
|---|---|---|---|
| eufy.com | `2500a7d5617812f9d52515b2c8f20a3d` | `/openapi/oauth/key/exchange` on the `openapi` host | no |
| eufy_security | `118c12c81e211149304bd70a0c071d01` | `/v3/openapi/oauth/key/exchange` on `security-app-*` | yes (token + gtoken), no `category` |

```
client: priv, pub  = fresh P-256 key pair
        key_ident  = random 32-hex
        inner      = base64(IV16 ‖ AES-128-CBC-PKCS7(hex(pub_uncompressed_130), key=preset))
POST {"client_public_key": inner}
        x-key-ident = key_ident
        x-signature = HMAC-SHA256(preset_ascii, ts + "+" + once + "+" + inner)
resp:   data.server_public_key = same preset encryption of the server's uncompressed P-256 point
        shared_key = hex(ECDH(priv, server_pub).x)                  # 64 hex chars
```

From then on the pair `(key_ident, shared_key)` **is** the transport identity. An
identity minted in one realm is refused by the other's cipher gateway **[verified]**.

## Login

`POST app-passport-{region}-pr.eufy.com/passport/login`, on a fresh eufy.com identity:

```json
{"email": "<e-mail>", "password": "<wrapped>", "ab": "<country>",
 "client_secret_info": {"public_key": "<client P-256 pub, uncompressed hex>"},
 "answer": "", "captcha_id": "", "verify_code": "", "login_id": ""}
```

**Password wrap.** `secret = ECDH(client_priv, LOGIN_SERVER_PUBLIC_KEY).x` (32 bytes).
The value is `base64(AES-CBC(key=secret, iv=secret[:16], PKCS7-pad(password, block=256 bits)))`.
The login server public key is a static P-256 point embedded in the app
(`cloud/const.py: LOGIN_SERVER_PUBLIC_KEY`). The pad block is **256 bits**, the key
size, not the AES block size. That looks wrong, but short passwords log in with it
repeatedly **[verified]**. Change it only against a capture of the app's own login body.

**Response `data`** (fields that matter):

| field | use |
|---|---|
| `auth_token` | session token, valid for weeks (`token_expires_at` when present) |
| `ap_cloud_user_id` | the **logged-in** user's id. It feeds `gtoken`. It is **not** the P2P `account_id` for a shared member (see below). |
| `mega_domain` / `domain` | the cluster's host base when present; empty on the answers seen |
| `ab_code` | echoes the request's `ab` |
| `country_code` | echoes the request's `country` header (`US` on an EU-homed account sent `US`); not the account's home |
| `fa_info` | `{info, step}`: `step` 26052 while two-step verification is pending (see below), 0 otherwise **[verified: step 0]** |

## Login country

The eufy app logs in with the user's country, and the library does the same **[app]**:

1. **Country**: the `country` argument (ISO 3166 alpha-2; Home Assistant passes its own
   country setting; the first code of a list, see *Extra countries* below), else the
   host's IP country: `POST
   app-passport-{region}-pr.eufy.com/passport/get_client_real_code`, body `{}`, on a
   fresh key-exchange identity before any login, answers `{"ab_code": "<IP country>"}`
   **[verified]**. Neither known: `ab` is the region (`eu`/`us`) and the `country` header
   `US`.
2. **Home cluster**: `POST mega-{region}-pr.eufy.com/passport/estimate_domain`, a
   **plaintext** body `{"ab": "<country>", "mode": 1}` with no identity, answers
   plaintext `data.domain` = `mega-eu-pr.eufy.com` or `mega-us-pr.eufy.com` (and the
   product-domain map), the same from either host **[verified]**. A lowercase or unknown
   code answers another domain (`aiot-api-eu.eufylife.com`): the library then does not
   use the country. Only the home region logs in; the other cluster is not asked.
   A lookup of either step that does not answer (no network, a non-200 or non-JSON
   answer, a throttle) leaves the country open: no login is sent until a later lookup
   answers, which the next login asks again, so a cold cache spends no login on a
   guessed cluster. A body-code refusal counts as an answer: an IP country is then
   unknown, an option keeps its code without a home region.
3. **Login**: `ab` = the country, `country` header = the country, `timezone` header =
   the caller's IANA zone (default `UTC`). A login in the other cluster with the same
   `ab` succeeds but lists nothing there **[verified]**. While no country is known, every
   region logs in with `ab` = the region and the empty ones are suspended.
4. **Old sessions**: each cached session records the `ab` it was made with; one made with
   another `ab` logs in again once, inside the login budget. A plain body-code
   refusal of a country login (26502 "Failed to request." was seen for `ab` `US` on the
   `eu` cluster) keeps the old session there, or, for a fresh login, retries once with
   the region as `ab`; either way that country is not asked again for that region: a
   later login there (an expiry, a forced login) sends the `ab` the session settled on.
   The one-time re-login runs unattended: when it meets a challenge it asks for no
   e-mailed code and keeps the old session the same way.

`POST app-passport-{region}-pr.eufy.com/passport/get_last_login_code`, body `{"email":
…}`, answers `{"ab_code": …}`: the `ab` of the account's last login on that cluster, by
any client **[verified]**. The account report shows it per region, with the IP country.
The app compares it with the chosen country before logging in.

**What a country login lists [verified].** Within one cluster the login's `ab` decides
which devices the lists show: a login with another country lists the devices held under
that country and not the others. On a member account that holds a home shared under one
country (`AA`) and a home station shared under another (`BB`), both on `eu`, the `AA`
session lists only the first and a `BB` session only the second; the eufy app logged in
with `BB` shows the same split.
The `country` header does not change any list: on one session, `AA`, `BB`, `DE`, `GB` and
`US` headers answered the same house, security and invitation lists. Sessions made with
different `ab` on the same cluster coexist: a new `BB` login left the `AA` session valid.
`ab` = the region (`eu`) listed the same devices as `ab` = `AA` on that account.

**Extra countries.** `country` may name several codes (`["DE", "FR"]`). The first is the
login country above; each further one has its home region looked up
(`estimate_domain`, cached) and logs in once more there with `ab` = that country, as the
login scope `<region>:<country>` (`eu:FR`). Its devices join the device list tagged with
the scope, and every call about them (lists, ciphers, DSK, push) uses its session. An
extra scope is listed and suspended like a region; its logins count in its cluster's
login budget. Each extra scope logs in under its own install id (`openudid`, minted once
and cached): a `BB` login from another install id left an `AA` session on `eu` valid
**[verified]**, while `BB` and `AA` under one install id did not both survive
**[observed once]**, which reads as one session per install id and cluster. A country eufy names no cluster for gets no session, and a refused extra
login is not retried with the region as `ab`: a plain body-code refusal is recorded
(`cloud.refused`) and that scope is skipped, with no login and no device list, until a
rescan or a change of the extra countries; the other scopes carry on, and the devices
it listed last stay in the list. An extra country whose lookup does not
answer gets no session until a later lookup does: the next login or device-list fetch
asks again.

## Login challenges

A challenge arrives as a non-zero body `code` on `/passport/login`. The client
re-submits the login with the answer filled in. The codes and the flow come from the
app **[app]**. The library implements them, but they have not been triggered on a
live account.

| code(s) | challenge | re-submit with |
|---|---|---|
| 26052 `NEED_VERIFY_CODE` (26050 wrong, 26051/26167 expired, 26054 mismatch) | e-mailed code | `verify_code` and the `login_id` returned with the challenge (`LoginChallengeError.login_id`; pass it back as `async_login(login_id=…)`) |
| code 0 with `fa_info.step` 26052 | two-step verification | as 26052: the answer's `auth_token` is not a session; it serves only to ask for the code (below) **[app; reported: the token's first request answers HTTP 401]** |
| 100032 `LOGIN_NEED_CAPTCHA` (100033 wrong answer) | captcha | first `POST /passport/generate/captcha` (passport host), which returns `{captcha_id, item}` with `item` a base64 image, then re-submit with `captcha_id` and `answer` |

**Asking for the code [app].** For a 26052 answer that carries an `auth_token`, the
library sends `POST app-push-{region}-pr.eufy.com/app/sendmsg/verify_code` under that
token, body `{transaction, message_type: 2 (e-mail; 1 SMS, 3 app push), biz_type: 1004
(login), captcha_id: "", answer: ""}`, before raising `LoginChallengeError`
(`code_requested`). When that request fails (an HTTP 401, a body code, the network),
the challenge is raised all the same with `code_requested` false, so the login can still
be answered. The token is never stored. The answer is a new login with
`verify_code` and `login_id` (empty when the challenge carried none).

**Which scope answers.** Each login scope logs in on its own, so each can raise its own
challenge. The library keeps the scope of every unanswered challenge with its `login_id`
in the cache (`cloud.challenges`; no code, no captcha answer) and sends an answer to the
scope whose `login_id` it carries, else to the only one pending, else to the home
region; that scope's successful login clears it. Two-step verification therefore costs
two logins per scope, which count in its cluster's login budget.

## Device list

`POST app-house-{region}-pr.eufy.com/app/house/get_devs_list`, body `{"device_sn": ""}` (encrypted).

| field | use |
|---|---|
| `device_sn`, `device_type`, `device_name` | identity. `device_type` 18 = HomeBase 3 here, but event records for the same station say 43 **[verified]**. 19 = eufyCam 3. |
| `parent_sn` | the station a sub-device is paired to |
| `device_channel` | the sub-device slot: `mChannel` in commands, `channel` in events, `dev_type` in the parameter dump |
| `p2p_did` | the DID. Discovery also returns it, so LAN use does not strictly need this field. |
| `local_ip` | LAN address for unicast discovery |
| `member.admin_user_id` | **the station owner's user id = the P2P `account_id`** |
| `member.member_type` | 0 guest, 1 admin, 2 owner (super-admin). Only the app's UI enforces it; the station does not **[app]**. |
| `main_sw_version`, `sec_sw_version` | firmware. The command set is firmware-dependent. |
| `app_conn` | the PPPP **rendezvous servers** (obfuscated), which wake a battery station ([p2p-transport.md](p2p-transport.md#waking-a-battery-station-verified)). Decoded by `pppp.decode_init_string` **[verified]**. `p2p_conn` is the same list plus relay host names. |
| `p2p_license`, `signaling_servers`, `mqtt_info` | off-LAN relay / WebRTC / MQTT material, not used by LAN operation **[open]**. MQTT (`aiot-mqtt-eu.anker.com`) grants no topic for a camera, so it is not a camera channel **[verified]** |
| `parent_sn` = own `device_sn` | a standalone device (a T8170), its own station; a HomeBase 3 leaves `parent_sn` empty **[verified]** |
| `params` | the cloud's snapshot of every parameter: `[{param_type, param_value, update_time}]`, `update_time` in epoch seconds. The device (or its hub) uploads a value when it changes, so a battery camera's state is here without waking it **[verified]**: at one fetch a T8170's battery was 3 min old, its Wi-Fi signal 17 min and its guard mode 18 min. The library keeps it in the cache only for devices reached on demand. |

`app/devicerelation/get_device_list` returns a station → sub-devices tree but
carries no P2P material.

## Houses and the security realm's lists

Read by `EufyCloudApi.async_list_houses`, `async_list_house_devices(region, house_id)`
and `async_list_security_devices(region, stations=…)`, uncached; the library serves
only the account-wide house list above. The request bodies are the app's **[declared:
app]**; the answers below were read on one account (a shared member, one HomeBase 3
with four paired cameras) **[verified, one account]**.

- `POST app-house-{region}-pr.eufy.com/app/house/get_house_list`, body `{}`:
  `data.house_infos[]` with `house_id`, `house_name`, `admin_user_id`, `member_type`,
  `is_default`, `user_id` and location fields. The account had three houses in `eu`
  and one in `us`.
- The same `get_devs_list` per house: body `{"house_id": …, "categories": [],
  "add_pns": []}` (the app's shape). On that account one house listed the same six
  devices as the account-wide body (`{"device_sn": ""}`), the others none; the bare `{}`
  and `{"house_id": ""}` bodies list the same six as `{"device_sn": ""}`
  **[verified, one account]**.
- Pending invitations, read by `EufyCloudApi.async_list_invites(region)`: a shared home
  shows its devices only once the invitation is accepted in the eufy app.
  `POST app-house-{region}-pr.eufy.com/app/house/get_house_invite_records`, body
  `{"transaction": …, "is_inviter": 1}`: `data.house_invite_records[]` with `id`,
  `house_id`, `house_name`, `action_user_nick`, `role_type`, `email`, `user_id`.
  `POST app-devicerelation-{region}-pr.eufy.com/app/devicerelation/get_invites`, body
  `{"transaction": …, "is_inviter": 1, "categories": [], "add_pns": []}`: `data.invites[]`
  with `id`, `device_sn`, `product_code`, `action_user_nick`, `action_user_email`,
  `member_type`, `create_time`, `status`. `is_inviter` 1 asks the invitations sent to
  the account (the app's start-up invitation dialog), 0 the ones it sent **[declared:
  app]**. Both answer code 0 with empty lists on an account whose shares were accepted
  **[verified, one account]**; a pending entry has not been observed.
- The security realm (the same identity as `get_ciphers`, `category: eufy_security`):
  `POST <security host>/v3/app/get_hub_list` (stations; the region's host from
  [Hosts](#hosts)) and
  `/v3/app/get_devs_list` (devices), body `{"device_sn": "", "station_sn": "",
  "num": 1000, "page": 0, "orderby": "", "time_zone": <UTC offset ms>,
  "event_num_type": 1, "transaction": …}`. `data` is a list. A station entry names
  itself in `station_sn` only (no `device_sn`), with `station_name`, `station_model`,
  `p2p_did`, `app_conn`, `member`, `params` and firmware and hardware versions; a
  device entry has `device_sn`, `device_name`, `device_model`, its station in
  `station_sn`, `device_channel`, `local_ip`, `member` and `params`. Neither carries
  `device_new_pn`. On that account they listed the HomeBase 3 and its four cameras,
  the same as the house list; the house list's non-security device was not in them.
  The eufy Security app reads them in its binding flows and per-device screens.
  `security_device_entry` maps an entry to the house list's shape, tagged
  `cloud_source: "security"` (`CloudDevice.source`).

## Owner account_id

The station accepts commands only from the id it is bound to: the **owner's** cloud
user id. Take it from `devices[].member.admin_user_id` and never from the session.
If an entry has no `member` object at all, the logged-in account is the literal
owner, and its own id applies. The app resolves the id with exactly this rule
**[app]**, and a shared member arms, writes settings and streams with the owner's id
**[verified]**. A wrong id is acknowledged at the transport level and silently
ignored, with no error ([commands.md](commands.md)). The id only changes when the
sharing changes, so cache it per station. A station event push also carries the id
(`rec_content[].account`, [events.md](events.md)).

## Station ciphers (security realm)

1. Run the eufy_security key exchange on the logged-in session (token + gtoken, no `category`).
2. `POST <security host>/v3/app/cipher/get_ciphers` (the region's host from [Hosts](#hosts)) with that identity and `category: eufy_security`:

```json
{"cipher_ids": [40], "user_id": "<owner user id>", "station_sn": "T8030XXXXXXXXXXX"}
```

`data` decrypts to a list of
`{cipher_id, ecc_private_key (P-256, 64 hex), private_key (RSA PEM), user_id}`.
`ecc_private_key` unwraps the ECIES CONN_INIT (version 8) and is the root of the P2P
session key for every station the current app supports **[declared: app]**
([session-crypto.md](session-crypto.md)). The RSA `private_key` serves a station whose
CONN_INIT is not version 8 (the legacy RSA handshake). Whether it is usable depends on the
record **[verified, one account]**: in one response to a shared member, ciphers 98 and 155
came back intact (a mixed-case PEM that parses as RSA-1024) and 13, 40 and 212 came back
**lowercased by the server**, armour included. A lowercased body is irreversible, so
`load_rsa_private_key` fails and the library raises `CipherUnusableError`. Lowercased on
cipher 40 (a HomeBase 3's) on two accounts, and on cipher 202 of a standalone T8410
(one sample). The request body field name makes no difference (`station_sn` and `sn`
return the same key), and the unversioned endpoint 404s. The MegaCrypto decrypt is not
the cause: mixed-case fields (device names) and `ecc_private_key` survive intact in the
same response. Which records eufy lowercases, and whether the station owner is served
another copy, is **[open]**.

| request | answer **[verified]** |
|---|---|
| the owner's user id, an id the owner holds | the cipher object |
| the owner's user id, an id the owner does not hold (41) | `HTTP 200`, `code 0 "Succeed."`, **no `data`** |
| a shared member's own user id | `HTTP 200`, `code 0 "Succeed."`, **no `data`** |
| any, on a eufy.com-realm identity | `HTTP 200`, `code 463` |

The empty answer does not tell "wrong user id" from "no such cipher under this owner".
The library raises `CipherUnavailableError` for it (with the cipher id and whether the
user id asked was the account's own or `member.admin_user_id`) and does not ask the
same station and cipher again for an hour (`CIPHER_UNAVAILABLE_BACKOFF`), unless a
refreshed device list names another owner id for the station.

`EufyCloudApi.async_list_ciphers` reads an owner's whole table this way (default ids
0–400 in one request, `CIPHER_ID_SWEEP`; it answered the five held records
**[verified]**) as `CipherRecord`s, uncached; `CipherRecord.check_rsa()` and
`ecc_state` report whether each key is usable without exposing it.

The key belongs to the **cipher id under the owner**, not to the serial **[verified]**:
asked for ids 0–400 with each serial on one account (a HomeBase 3, a T8170, two T8160
and a T8910), the cloud served the same ids (13, 40, 98, 155, 212) with the same
`ecc_private_key` per id every time; 13 and 212 carry an empty one. Which id a station
uses is named in its CONN_INIT: 40 on the HomeBase 3, 98 on the T8170. Fetch only that
id, after the CONN_INIT reply: the eufy app does the same **[declared: app]**
([session-crypto.md](session-crypto.md)). Whether other owners hold the same ids is
**[open]** (one owner's table is known). Owner and members get the same key
**[verified]**. Whether a key changes when a station is re-bound is
**[open]**. The station gives no
signal for a stale key except that CONN_INIT fails to unwrap
([session-crypto.md](session-crypto.md)). On that failure, re-fetch once, then stop.
Whether a guest (`member_type` 0) is served is untested **[open]**.

## Response and error conventions

- **Failures arrive as HTTP 200 with a non-zero body `code`.** Check `code` before
  reading `data`, on every call.
- **Success can carry no data.** `code 0` without `data` is a real answer (for
  example, `get_ciphers` under the wrong user id). Treat it as "nothing", not as a
  parse error.
- A body that is not JSON text, a non-numeric `code`, or `data` that does not decrypt
  to JSON of the expected shape is a `ProtocolError`. A device-list success without a
  `devices` field is one too, and it leaves the cached list untouched.
- A WAF sits in front of `security-app-*`. Under pressure it answers 403 or stalls
  instead of refusing, so bound every request with a timeout (the library uses 30 s).

| group | codes (`cloud/const.py: CloudCode`) | client action |
|---|---|---|
| success | 0 | read `data` if present |
| session expired | 401, or HTTP 401 with any body code but 26084 | one re-login; refused again: `SessionRejectedError` |
| session replaced | 26084 `SESSION_REPLACED`, as body code or with HTTP 401 **[verified: HTTP 401 + 26084 after another client logged in]** | stop: never log in again automatically, or two clients on one account kick each other out into the login lock. The app logs out on it too. |
| re-key | HTTP status 463, or body 463 `NEED_EXCHANGED_KEY` / 4404 `NEED_NEGOTIATE_KEY` under any status. Live: `HTTP 463 {"code":4404,"msg":"get identity error"}` on `get_devs_list`, starting 72 h after the session's key exchange on one account **[verified, one sample]** | a new key exchange on the login realm, then the same request with the **same auth token** under the new `key_ident` / shared key; no login. **[verified]**: this restored the device list on a session refused for 18 h. The app does the same (its HTTP-463 handler re-keys and retries). A second refusal is `KeyExchangeRefusedError`. On `get_ciphers` 463 also means a wrong-realm identity. |
| signature / clock | 4416, 461 `TS_NOT_MATCH` | a client bug or clock skew, so do not retry blindly |
| bad credentials | 22008, 26006, 26015, 26055, 26105, 26108 | stop and ask the user. Never log in again automatically: each failure counts toward the lock. |
| challenge | 26050–26054, 26167, 100032, 100033 | see Login challenges |
| throttled (requests) | 26145 `API_REQUEST_LIMIT`, 250999 `REQUEST_TOO_FAST` **[reported]**, HTTP 429 | hold off every call (1 h, or a longer `Retry-After`) |
| throttled / locked (logins) | **100028 `MAX_LOGIN_LIMIT`** (hold off logins 2 h); 10019, 100056, 26053 (24 h) | hold off logins; a valid session keeps working |
| login crypto | 100029, 100030 | the password wrap was wrong |

## Device session key (DSK)

`POST app-devicerelation-{region}-pr.eufy.com/app/devicerelation/get_dsk_keys` with the
`Category: eufy_security` header and body
`{"device_dsks": [{"invalid_dsk": "", "device_sn": "<sn>", "category": "eufy_security"}],
"invalid_dsks": {}, "station_sns": ["<sn>"]}`.

`data.device_dsks[0]` = `{device_sn, dsk_key (20 chars), expiration (epoch s, ~1 h),
enabled, about_to_be_replaced, category}`. The DSK wakes a battery station over its
rendezvous servers ([p2p-transport.md](p2p-transport.md#waking-a-battery-station-verified)).
Each client gets its own key; pass a stale one as `invalid_dsk` to force a rotation. The
library caches it per station until ~5 min before it expires **[verified]**.

## Firmware (OTA)

`POST app-ota-{region}-pr.eufy.com/app/ota/get_rom_version` (a normal MegaCrypto call)
asks whether a newer firmware exists for a device. Body:

```json
{"transaction": "<32-hex>", "current_version_name": "3.8.7.4",
 "device_sn": "<sn>", "device_type": "T8030_Kit", "rom_version": 0, "sn": "<sn>"}
```

- **`device_type` is the station's firmware *kit*, not the cloud model code.** A HomeBase
  updates itself and its paired cameras as one bundle, so every device behind a hub — the
  hub and each camera, each by its own `device_sn` — is queried under the hub's kit type:
  `T8030_Kit` for a HomeBase 3 **[verified]**, `<model>_Kit` for the others (`T9000`,
  `T7000`, `T8025`) **[app]**. The app derives it from the station, not the device.
- **A device already on the newest published firmware is "up to date", reported oddly:**
  the envelope is `code 0 "success!"` and its `data` decrypts to the error object
  `{"reason": "error: code = 20004 reason =  message = "}`. So body `code` 20004 lives
  *inside* a success, and means no update — not a transport failure **[verified]**.
  The server keys the answer on the device's registered version, so sending an older
  `current_version_name` does not produce a package.
- **When an update exists**, `data` is the offered version:
  `{device_type, rom_version, rom_version_name, force_upgrade, up_forced, introduction,
  full_package: {file_md5, file_name, file_path, file_size}, …}`. **`full_package.file_path`
  is the image URL** on eufy's CDN, with `file_md5` and `file_size` **[app]**. No update
  has been seen for these devices (they are current), so the populated shape is app-only.

The library exposes this as `EufyCloudApi.async_check_firmware(...)` → a `FirmwareUpdate`
(or None when up to date) and `EufySecurity.async_firmware_updates()`, which checks the hub
and each camera and returns what has one. It is an ordinary authenticated call on the
account's shared throttle, meant for a slow poll, never per start (see below).

## Caching and rate limits

Logins are expensive. `/passport/login` returns `100028 Hit max login limit` after a
handful of logins in a short window **[verified]**, and repeated **failed** logins
lock the account for 24 h. A session lasts weeks, so there is no reason to log in
per start.

| item | lifetime | why cache it |
|---|---|---|
| `openudid` | forever | a new value looks like a new device to the backend and orphans push registrations |
| account password | until the cloud rejects it | a lost session (expiry, cache layout change) logs in again unattended |
| `key_ident`, `shared_key`, `auth_token`, logged-in `user_id` | until expiry, a session-expired answer, or a kick-out (26084, which also blocks automatic logins until a forced one) | a login per start hits 100028 |
| per-station owner `admin_user_id` | until the sharing changes | every command needs it |
| per-station `ecc_private_key` of the cipher the station names (`ciphers.<id>`), its RSA `private_key` when served (`rsa_ciphers.<id>`), and that id (`cipher_id`) | until the station is re-bound | several round trips behind a WAF, and may cost a login |
| FCM credentials and token | install-scoped | Google identity of the install ([events.md](events.md)) |

Rules the library follows: at most one automatic re-login per call, and only on a
session-expired code (a login-free call raises `NoCachedSessionError` instead) — never
on a re-key answer (a key exchange instead) and never
after a kick-out (26084), which blocks automatic logins until a forced one;
concurrent calls share one login; a cooldown (15 min) on forced cipher re-fetches and,
separately, on the forced device-list re-read behind an owner-id refresh (inside it
the cached owner id is used); no retries on throttle or credential codes; no cloud
call on a timer except the device-list refresh (`cloud_state_refresh`, 1 h) while a
station is reached on demand. The cipher fetch (security-realm key exchange plus
`get_ciphers`) sits inside the same one-re-login retry as every other authenticated
call. Every session change is saved to the store immediately.

**Stale cipher keys.** A P2P handshake whose session key does not unwrap asks for the
station's cipher again. The cipher cooldown is per station, so one base's refresh
never blocks another's; the device-list re-read behind the owner id stays
account-wide. A locally refused refresh is a `RefreshCooldownError` (`code` 0), which
is not a cloud throttle. Only a fetch that returned a key sets that station's
**key-refresh latch** (persisted with its keys); a failed fetch (throttle, rejected
credentials, network) sets nothing, so it cannot wedge the station. While the latch is
set, a rejected key raises `KeyRejectedError` without contacting the cloud. One more
automatic fetch is allowed once `KEY_REFRESH_SLOW_RETRY` (24 h) has passed, and that
fetch re-stamps the latch. The latch clears when a handshake succeeds, on
`async_reset_key_refresh(serial)` (the release), and on `async_reauthenticate`. Each
fetch that returned a key emits `CredentialsRefreshed`.

The limits themselves are not published. Reports put a "too fast" block (`250999`,
"The request is too fast. Please stop and have a rest", or HTTP 429) at 30–60 min per
IP or session, restarted by requests sent during it, and a `100028` login block at
1–2 h. So a throttling answer starts a **hold-off**, set at the long end of those
reports, that is persisted with the session: until it ends the library refuses locally
and sends nothing — every call for a request throttle, logins only for a login
throttle. Independently, at most 3 login attempts (of any outcome) are sent in a
rolling 6 h. A refusal is a `RateLimitedError` (`LoginLimitedError` for logins) carrying
`retry_after`.
