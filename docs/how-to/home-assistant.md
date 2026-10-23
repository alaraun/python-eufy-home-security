# Building a Home Assistant integration

`eufy_home_security` is shaped for Home Assistant: it imports nothing from HA, takes
an injected `aiohttp` session and a pluggable `Store`, raises typed errors, and pushes
state changes instead of only being polled. This is how a config-entry integration
maps onto it.

## Logic belongs in the library

This applies to everyone building the integration, human or AI agent. The integration
is a thin adapter: it maps the library's objects, events and typed errors onto Home
Assistant's config entries, coordinators, entities, flows and repairs. Everything
about eufy lives in the library, where it is tested once and verified against the
hardware. That covers the cloud, the stations, the cache, rate limits, identifiers and
which account serves which station.

- **Look for the library function first.** Before writing logic in the integration,
  check the public API (`eufy_home_security.__all__`) and these docs.
- **Missing or awkward? Change the library** instead of working around it: add the
  API to the library, with a test. How that change travels is up to the setup:
  - developing both locally (the library installed from a local checkout): make the
    change in that checkout and commit it there; no issue or pull request is needed;
  - using the published library: propose the change as an issue or pull request
    describing the need, the proposed API and a test.

  If the integration cannot wait for a release, keep the workaround small, point it
  at the library change, and delete it once the integration uses the new version.
- **Never re-implement protocol, caching, throttling or identity rules in the
  integration.** Never read or write the cache document, and never parse
  `CloudDevice.raw`: if the integration needs a field, the library should expose it.
- What stays in the integration is Home Assistant glue: config, reauth and reconfigure
  flows, entity classes, coordinators, repair issues, diagnostics, translations.

## One config entry = one account

```python
import hashlib

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.util.hass_dict import HassKey
from eufy_home_security import EufySecurity, StationClaims

CLAIMS: HassKey[StationClaims] = HassKey(f"{DOMAIN}_claims")


def cache_store(hass, email: str) -> Store:
    """One store per eufy account — the same one for the config flow and the entry."""
    account = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]
    return Store(hass, 1, f"{DOMAIN}.{account}", private=True, atomic_writes=True)


def station_claims(hass) -> StationClaims:
    """One claim registry for every account in this Home Assistant instance."""
    if (claims := hass.data.get(CLAIMS)) is None:

        def rebuild(account: str) -> None:  # account == the entry's unique_id
            entry = hass.config_entries.async_entry_for_domain_unique_id(DOMAIN, account)
            if entry is not None:
                hass.config_entries.async_schedule_reload(entry.entry_id)

        claims = hass.data[CLAIMS] = StationClaims(rebuild)
    return claims


async def async_setup_entry(hass, entry):
    eufy = EufySecurity(
        async_get_clientsession(hass),  # HttpSession accepts a live session directly
        entry.data[CONF_EMAIL],
        None,  # the password is cached by the library
        store=cache_store(hass, entry.data[CONF_EMAIL]),
        country=hass.config.country or "",  # the login country, as the eufy app's
        timezone=hass.config.time_zone,
        claims=station_claims(hass),
    )
    try:
        await eufy.async_login()  # reuses the cached session; no round trip when warm
    except (SessionReplacedError, RateLimitedError) as err:
        # Cloud degraded, not broken: raise the repair issue (see the error table) and
        # carry on. A warm cache serves the device list, owner ids and cipher keys below.
        ...
    stations = await eufy.async_discover()  # cached device list; raises only on a cold cache
    entry.runtime_data = eufy
    entry.async_on_unload(eufy.async_close)

    async def _on_stop(_event) -> None:
        await eufy.async_close()

    # HA does not unload entries on shutdown: close explicitly so the cache is saved.
    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_stop))
    ...
```

`async_close` is bounded: the push listener drops its MCS socket instead of waiting for
the TLS close the server never answers, and waits at most `push.const.STOP_TIMEOUT`
(2 s) for its tasks; the P2P sessions close without a round trip. A reload or options
change from the UI therefore does not outlive the HTTP request that started it.

The config flow is the only place that passes a password. A successful login caches
it together with the session, so the entry itself stores just the e-mail:

```python
async def async_step_user(self, user_input):
    email = user_input[CONF_EMAIL].strip().lower()  # == EufySecurity(...).cache.account
    await self.async_set_unique_id(email)
    self._abort_if_unique_id_configured()
    eufy = EufySecurity(
        async_get_clientsession(self.hass),
        email,
        user_input[CONF_PASSWORD],
        store=cache_store(self.hass, email),
        country=self.hass.config.country or "",
        timezone=self.hass.config.time_zone,
    )
    try:
        await eufy.async_login()  # caches the session and the password
    finally:
        await eufy.async_close()
    return self.async_create_entry(title=email, data={CONF_EMAIL: email})
```

`EufySecurity(...)` raises `ValueError` for an empty e-mail or one without `@`, before
anything touches the cache or the cloud: catch it and show an "invalid e-mail" form
error, so a typo never spends a sign-in. It raises `ValueError` too for a `country` that
is not a two-letter ISO 3166 code; HA's `hass.config.country` always is one (or None).

`country` and `timezone` make the logins look like the eufy app's: the login sends the
country as `ab`, only the home cluster of that country (eufy's own lookup) logs in, and
every request carries the country and the zone as headers. Without `country` the
library uses the country eufy places the HA host's IP address in; when neither is known
it logs in with `ab` = the region. A cached session made with another `ab` (a session
cached without an `ab`, or one made before the HA country changed) logs in again once per
region, inside the login budget; when that login is refused, the old session stays in
use and is not asked again for the same country. See
[cloud.md § Login country](../protocol/cloud.md#login-country).

**The country is the user's choice.** eufy lists a device only to a login with the
country it is held under: an account whose own devices sit under one country (`AA`) and
that accepted a home shared from an account in another (`BB`) sees the shared devices
only with `BB`, as the
eufy app does. HA's country and the host's IP are guesses. Offer a country list in the
config flow and the options (default: HA's country), pass it as
`country=[first, *extra]`, and rescan after it changes
(`async_discover(rescan_regions=True)`): each extra country costs one login on its home
region, and its devices come back with `CloudDevice.region` `<region>:<country>`.
When the list comes back empty, tell the user to check the country the eufy app logs
in with.

The cache is what keeps the integration clear of the cloud's limits. Read the next
section before writing the config flow.

## The cache

### What it holds

One JSON document per account. The library owns its layout; the integration only
provides where it lives.

| section | contents | refreshed |
|---|---|---|
| `openudid` | this install's eufy device identity, minted once | never; kept, with `cloud.install_ids`, when the account changes |
| `password` | the account password of the last successful login | on every successful login; dropped as soon as the cloud rejects it |
| `cloud.sessions.<region>` | per cloud region, and per extra country as `<region>:<country>`: key ident, shared key, auth token, user id, expiry, the `ab` the login sent and the one it asked for (`ab_wanted`), the login answer's `mega_domain` and `country_code` | on a login to that region: a miss, an expiry, or a session-expired answer. A re-key answer (HTTP 463) replaces only the key ident and shared key, by a key exchange, no login. A kick-out (26084) drops that region's session |
| `cloud.country` | the login country (`code`, `source` `option` or `ip`, `home_region`) | on the first login of a process when the country or its home region changed |
| `cloud.extra_countries` | each extra country's home region | when a login or a device list first needs an extra country not looked up |
| `cloud.install_ids` | the install id (`openudid`) of each extra country's login scope | minted on that scope's first key exchange, then kept wherever `openudid` is |
| `cloud.refused` | each extra country's scope whose login the cloud refused with a plain body code (the code, when, and the extra countries then) | on that refusal; cleared by a rescan, a later login there, or a change of the extra countries |
| `cloud.challenges` | each login scope with an unanswered login challenge, and the `login_id` its answer carried, if any (no code, no captcha answer) | when a login raises a challenge; cleared by that scope's next successful login |
| `cloud.pending_logins` | per login scope, the pending login a verification-code answer is sent inside: key ident, shared key, pending auth token and user id, the password wrap's client public key and ECDH secret, the `ab`, expiry (15 min) | when a login raises a verification-code challenge with a pending token; cleared by that scope's next successful login or a refused answer |
| `cloud.listed.<region>` | how many devices the region's last device list held, and when | on every device-list fetch that asked the region |
| `replaced` | when another client's login ended the session | set by a kick-out; blocks every non-forced login until `async_login(force=True)` or `async_reauthenticate(…, take_over=True)` |
| `stations.<serial>` | the owner's account id, the ECC private key of each cipher fetched for it (`ciphers`) and its RSA private key when served (`rsa_ciphers`), `cipher_id` (the cipher the station names in its handshake: 40 on a HomeBase 3, 98 on a T8170), the key-refresh latch, a standalone camera's device session key (`dsk`, with its expiry) and each camera's preset slots (`presets`) | keys on a P2P handshake failure: one fetch, then latched until a handshake succeeds, the latch is reset, or 24 h pass. `dsk` when a wake needs it and less than 5 min of it remain; `presets` on each preset read that differs |
| `devices` | the `get_devs_list` entries, each reduced to the fields `CloudDevice` reads (serials, type, name, channel, DID, IP, firmware versions, `app_conn`, the product code `device_new_pn`, the member's `admin_user_id` and `member_type`, and `cloud_region`, the region that listed it); the cloud's `params` snapshot for a station and a device reached on demand, and a station's `time_zone`. The member's e-mail and phone, MAC addresses and the rest never reach the store | only on `async_discover(refresh=True)`; an entry stored with more fields is reduced on load |
| `push` | FCM credentials, the registered token, recent push ids and guard-mode times | on push start; delivery state written at most 30 s after it changes, and on close |
| `refresh_attempts` | when the owner id (account-wide) and each station's cipher key were last force-fetched | with those fetches |
| `throttle` | hold-off end times (requests, logins) and recent login attempts | when the cloud throttles, and on every login |

Everything except the install identity (`openudid` and `cloud.install_ids`) belongs to
one account. A `EufySecurity` built for a different e-mail on the same store discards it
and starts over (it keeps the install identity).

The layout version is exported as `CACHE_LAYOUT_VERSION`. A deploy script can compare it
before and after an upgrade and warn while the account is throttled or kicked out.

A library update that changes the document's layout (its `version`) keeps the install
identity, the password, the throttle state and the `replaced` latch, and drops the rest. The next cloud call logs in
again with the cached password and fetches the device list and keys again. That is one
login cycle, within the hold-off and the login budget, and nobody is asked for anything.
Version 1 (one session, before regions) is migrated instead: its session and devices
become the region it was logged in to, so the migration itself costs no login. That
session carries no `ab`, so with a login country known it logs in again once, inside the
login budget (see the login country above). A version-1 cache
with an empty device list drops that list, so the next start asks every region once.

Most of it is secret. The password and the auth token open the account, and a
station's ECC key is enough to control that station from the LAN. So:

- create the HA `Store` with `private=True` and `atomic_writes=True` (HA's default is a
  plain overwrite: a crash mid-write would lose the session and `openudid`);
- never put the document in diagnostics or logs unredacted: drop `password`, `cloud`,
  `push`, `openudid` and every `ciphers` entry;
- do not expose it as an entity attribute.

### Where it lives

HA's `homeassistant.helpers.storage.Store` already has the `async_load()` /
`async_save(data)` shape of the library's `Store` protocol, so pass it straight in. The
library saves as soon as something changes (a login is on disk before `async_login()`
returns); HA's own envelope around the document does not interfere.

**Key the store by the account, not by `entry_id`.** The config flow has no `entry_id`
yet, and it has to log in to validate the credentials. With an account key, the flow's
login lands in the same store the entry then opens, so setup reuses that session. With
an `entry_id` key, the session is thrown away and setup logs in a second time. Use the
normalised e-mail as the entry's `unique_id` as well, so one account cannot be added twice.

### One live instance per store

A `EufySecurity` loads the document once and later writes the whole document back. Two
live instances on the same store therefore overwrite each other's changes: a lost
session means another login, and a lost hold-off means calling a throttled cloud again.

- **Config flow, adding the account:** nothing else is running. Build an instance, log
  in, `await eufy.async_close()` (which saves), then create the entry.
- **Login challenge:** carry `captcha_id` between flow steps, and close the instance
  before the step shows the form. The next step builds a new instance on the same
  store; it reloads the document, and the answer goes to the login scope that asked,
  inside that scope's pending login (the store keeps both for 15 min). Pass `login_id`
  only if you hold one; it is not part of the challenge. `LoginVerificationError` on
  the answer: the code was refused and the pending login dropped; show the first step
  again (a plain login e-mails a new code). The password stays cached. With extra countries
  each scope logs in on its own, so an account with two-step verification answers one
  challenge per scope: after an answer, `async_login` may raise the next scope's
  challenge; show the form again. Two logins per scope count in that cluster's budget
  (3 per 6 h), so the last answer can meet `LoginLimitedError`; after its
  `retry_after`, `async_login()` asks that scope again with a new code.
- **Reauth / reconfigure:** these carry a new password. If the entry is still loaded,
  unload it first. Build an instance on the store and call
  `await eufy.async_reauthenticate(password)`, then close, then
  `async_update_reload_and_abort`: the reload reads the store, including the newly
  cached password, again. Do not use `async_login()` here: on a warm cache it returns
  without logging in, so the new password is never checked or stored, and the old one
  fails later and counts toward the lockout. `async_reauthenticate` always makes one
  real login, replaces the cached password only on success (a rejection leaves the old
  one as it was), and releases every station's key-refresh latch. It raises
  `SessionReplacedError` while the kick-out latch is set, unless the user chose to take
  the session back (`take_over=True`).
- **Options flow, services, diagnostics:** use `entry.runtime_data`, never a new instance.

### Keep it

The cache is only worth anything if it survives. Do not add a "clear cache" button, and
do not delete or recreate the store on reload, on reauth, or on a password change. The
login replaces the session in place.

Deleting it costs:

- a new `openudid`: the backend sees a new phone, and the old install's push
  registration is orphaned;
- the cached password: the next login needs a reauth;
- a login, a device-list fetch and a cipher fetch per station, all at once;
- the **hold-off and the login budget**: a user who deletes and re-adds the integration
  while the account is throttled goes straight back to the cloud.

When the user removes the entry, call `async_forget_account` in `async_remove_entry`,
and never delete the store:

```python
from eufy_home_security import async_forget_account


async def async_remove_entry(hass, entry):
    await async_forget_account(cache_store(hass, entry.data[CONF_EMAIL]))
```

It removes the password, the session, the station keys and owner ids, the device list,
the push registration and the refresh stamps, and the kick-out latch (re-adding the
account is the user's decision). It keeps `throttle`, so removing and re-adding the
integration cannot walk a throttled account back into the cloud, and the install identity,
`openudid` and `cloud.install_ids` (`keep_install_identity=False` drops them too). Throttle stamps expire by themselves. It
never contacts the cloud. No live instance may be open on the store, which holds in
`async_remove_entry`.

### Refreshing on purpose

Nothing in the cache expires on a timer. `async_login()` and `async_discover()` use the
cache when it is warm, and the library re-fetches the session, the owner id and the
cipher key by itself when the cloud or the station says they are stale. What stays with
the integration is the device list:

- Refresh it deliberately: a daily `async_discover(refresh=True)`, or a "refresh
  devices" service. Never on every start.
- A refresh that cannot reach the cloud, or runs into a hold-off, returns the cached list,
  without the devices of a login scope no longer in use (a removed extra country).
- `eufy.device_list_source` says how the last list was obtained: `"fetched"` (every scope
  in use answered now: a whole, fresh list), `"cache"` (the cached list, covering every
  scope in use), `"fallback"` (the cached list after a refresh the cloud did not answer)
  or `"unsent"` (every scope suspended, nothing asked). Every one of them holds only
  devices of the scopes in use, so a removed country's devices are gone from each; a
  cleanup that must also see devices eufy stopped listing waits for `"fetched"`.
  `eufy.listed_devices` maps every serial of that list to its `CloudDevice`: built
  stations, stations served elsewhere, remote stations, paired and skipped devices.
- A refresh adds new stations and updates the paired devices of the stations already
  built. When a station's devices change it emits `DevicesChanged(station_sn, added,
  removed, moved)` (serials): reload the entry on it, and never diff device lists in the
  integration. A refresh that changed nothing emits nothing. A discovery after the first
  that built a station, or whose list no longer names a built one, emits
  `StationsChanged(added, removed, source)` (station serials, each removal once): reload
  on it too. A removed station stays in `eufy.stations` until the client is rebuilt.
- Serials come from the cloud device list only (`SubDeviceState.serial_source` is
  `"cloud"`). A device paired after the last device-list refresh, or a channel whose
  identity is ambiguous, has `serial=None`: build no entities for it until a refresh
  brings its cloud entry and emits `DevicesChanged`.

### Cloud regions

The eufy cloud runs two clusters, `eu` and `us` (the app's production environments). A
login on either succeeds for any account and answers the same user id, but a login lists
only the devices its cluster holds for the login's country: the other cluster, or
another country, answers an empty list, not an error. So the library logs in once per
country, on that country's home cluster (eufy's `estimate_domain`), and remembers, per
device, the *login scope* that listed it: the region (`eu`) for the login country,
`<region>:<country>` (`eu:FR`) for each extra country of `country=[…]`:

- A cold cache costs one login per country. The login budget (3 per 6 h) and a
  login-count throttle (100028) are kept per cluster, so two countries homed on `eu`
  share its budget; a credential lock (too many wrong passwords) holds off every
  cluster. `async_login()` on a cold cache logs in to every scope the next device list
  asks, so a login challenge surfaces there; its `LoginChallengeError.region` names the
  scope, and the answer (`async_login(verify_code=…)`) goes back to it, on
  this instance or a new one on the same store.
- While no country is known (no `country`, and eufy names no IP country), both regions
  log in with the region as `ab`.
- A scope's device list is its account-wide list merged with each of its houses' own
  lists, as the eufy app shows them (a shared home's devices can be in its house's list
  only; see `docs/protocol/cloud.md` § Device list).
- A scope that lists no devices in any of them is **suspended**: no later device list,
  login or push registration asks it. It is asked again only when the user says so:
  `async_discover(rescan_regions=True)` (one fetch that asks every scope), or the
  client option `EufySecurity(scan_regions=True)` (every device-list refresh asks every
  scope; one whose session lapsed costs a login). With every scope suspended a refresh
  sends nothing and returns the cached, empty list. There is no automatic retry.
- The cached device list is used only while it matches the scopes: a scope never listed
  (an extra country added, the login country moved to another home region, an override
  dropped) or a cached device of a scope no longer in use (a country removed) makes the
  next `async_discover()` fetch the list once.
- Every cloud call about a device goes to its scope's session: cipher key, DSK, firmware
  check. The push token is registered in every scope that has devices.
- `EufySecurity(region="eu" | "us")` pins the login country's scope to that region and
  leaves out extra countries homed on the other one.

For the integration:

| what | where | use |
|---|---|---|
| a device's region | `CloudDevice.region` (`station.device.region`, each sub-device's `CloudDevice`) | a diagnostic attribute; never part of an entity id |
| per-region state | `(await eufy.async_cloud_status()).regions[<region>]`: `devices` (None = never listed), `suspended`, `in_use`, `login_refused` (an extra country the cloud refused to log in: skipped until a rescan), `logins_in_window` (its cluster's logins in the budget window; the account-wide `CloudStatus.logins_in_window` is the fullest cluster's), `next_login_allowed_in` (0.0 when this scope may log in now), `session_state` (`SessionState`: `usable`; `none` never stored; `expired` past its expiry; `ended` the cloud answered it expired early, e.g. after another login under the same install id; `replaced` another client took it over), `listed_age`, `session_expires_in`, `country_code` | diagnostics; a repair issue when every region is suspended ("the account lists no devices in any eufy region") with a *rescan* fix |
| rescan | `async_discover(rescan_regions=True)` | only on the user's request: the "refresh device list" button and the repair's fix. Timers and automatic refreshes pass `refresh=True` alone, so a suspended region is never retried by itself |
| scan on every refresh | `EufySecurity(scan_regions=...)` | an options-flow switch, off by default |

The login answer's `country_code` echoes the request's `country` header (the login
country, else `US`), not the account's home.

### Account report (diagnostics)

`await eufy.async_account_report()` returns an `AccountReport` (`.as_dict()` is
JSON-safe and secret-free: put it in the config entry's diagnostics download as it is).
It answers "which devices does eufy list for this account, and could the library reach
them", including devices the library does not serve:

- `listings`: per region, how many entries each list answered (or its error): the
  account-wide house device list (`house`), the house list (`houses`), the pending
  invitations (`invites`), and the security realm's station and device lists
  (`security_stations`, `security_devices`). `houses`: per house, its own device count
  and this account's role.
- `invites`: each pending invitation sent to the account: whether it shares a home or a
  device, the device's redacted serial and product code, when it was sent.
- `devices`: each device once, merged over every list that named it (`listed_by`), with
  model, catalogue support grade, product code, the cloud's own model field, station
  kind (`connect_type`), firmware and hardware versions, the parameter ids of the cloud
  snapshot, the camera-info parameter (a version-8 hint), the cipher its station named
  in its last CONN_INIT, and `served` (whether this client built a station for it; None
  before a discovery).
  A device listed by the security realm but not by `house` is one the library does not
  serve.
- `login_country`, `country_source` (`option`, `ip`), `home_region`: the country the
  logins send as `ab` (None while unknown); `client_country`: the country eufy places
  the host's IP address in; `logins`: per region, the `ab` its session was made with and
  `last_login_code`, the `ab` of the account's last login there by any client (the eufy
  app's included).
- `ciphers`: per station owner (`"own"`, `"owner 1"` …), the whole cipher table read in
  one `get_ciphers` request: per cipher id whether the ECC key and the RSA key are
  usable, the RSA key's letter case and size, and which stations named it.
- Serials redacted; no user id, house id, DID, IP, name, key or parameter value (but
  the camera-info one). Error texts have serials, account ids and e-mail addresses
  redacted.

It never logs in: it asks only regions whose session is held or cached
(`regions_without_session` lists the rest), and the first throttle, kick-out or
credential refusal ends it (`stopped`); a region whose session the cloud no longer
accepts records `NoCachedSessionError` on its lists and the other regions are still
asked. It sends a few requests per region plus one per
owner, on the account's shared throttle, and caches nothing: call it from the
diagnostics download only, never on a timer. `ciphers=False` leaves the cipher sweep out.

#### Pending invitations

An account that a home or device was shared with sees those devices only after it
accepts the invitation in the eufy app. `await eufy.async_pending_invites()` returns the
invitations it has not accepted (`CloudInvite`: `kind` `"house"` or `"device"`,
`house_name` or `device_sn` / `product_code`, `inviter`, `region`), login-free and
uncached, two requests per region with a session. A region whose request fails is
skipped; the call raises only when no region answered, and a session the cloud no
longer accepts raises `NoCachedSessionError` there (no login was tried: not a reauth).
Ask it when the device list comes
back empty (and on a user's rescan), and when it is not empty raise a repair: "accept
the invitation from *inviter* to *home* in the eufy app, then rescan". `house_name` and
`inviter` are for that message only: keep them out of logs and diagnostics
(`as_redacted_dict()` has neither).

Each station's `stats()` (`SessionStats`) also carries `conn_init_version` (8: ECIES,
anything else: the legacy RSA handshake) and the `cipher_id` it named, once a CONN_INIT
reply arrived. `static_key_session` is True on an RSA session whose key is the static key
(cipher 0, or a station that wraps its static key): it works, but none of its pushes is
authenticated (see `docs/protocol/session-crypto.md`). `state_frames_by_encryption`
counts the state frames taken by encryption (`"type2"`, `"type1"`, `"clear"`, `"gcm"`,
`"ecb"`, …), and `state_authenticated` is False while the station's state came only in
clear or under the static key (an RSA station such as a T8414 sends its state under the
static key), True once it came under a key only the session holds, None before any.
Both are information only: state counts under any encryption, as in the eufy app.

### Firmware updates

`await eufy.async_firmware_updates()` asks the cloud OTA whether any device has a newer
firmware and returns a `FirmwareUpdate` per device that does. See
[the `update` entity](#update-entities-firmware) for how to build entities from it.

### What a warm cache buys

A normal HA restart performs no login and no device fetch: `async_login()` and
`async_discover()` answer from the document, and the P2P sessions need only the cached
station identities and cipher keys. The same holds during a eufy cloud outage or a
throttle: every entity is built and local control works. Only the FCM push needs the
cloud to be answering when it starts; `async_start()` logs that failure instead of
raising, so call it again later to retry the push.

## Which stations to include

Let the config flow say what it found, and let the user decide. The library
classifies; the flow only presents the choice and stores the answer.

`await eufy.async_station_choices()` lists every station on the account (each HomeBase,
and each standalone device) as a `StationChoice`. It runs one LAN probe, builds
nothing and opens no session:

| field | meaning |
|---|---|
| `reach` | `Reach.LOCAL` if the station answered LAN discovery, else `Reach.REMOTE` |
| `sub_devices` | the cameras and sensors paired to it; they are included with it |
| `supported` | whether the device catalog knows the model |
| `enabled_by_default` | local **and** supported |
| `path` | its `LanPath`, for the network step below |

What each reach gives:

| | local | remote |
|---|---|---|
| served by | a P2P session over the LAN | the account's cloud push |
| state, guard mode | read at start and kept current | only from a push after it changes |
| arm / disarm, settings | yes | **no** |
| live view, snapshots, recordings | yes | **no** |
| detections and other events | yes (station and push; camera detections from the station only where `station.local_events` is verified) | yes (push) |

The library has no cloud command path, so a remote station is monitor-only. Say so in
the flow before the user enables one.

**Config flow step "stations"** (after the login step):

- Headline: "Found N stations on your local network, with M cameras and sensors.
  They will be added with local control."
- One multi-select: every local station, preselected when `enabled_by_default`, listed
  with its sub-devices. Then every remote station, **not** preselected, labelled
  "remote: events only, no arming, settings or live view". Show an unsupported station
  as "not supported yet" and leave it unselected.
- Store the answer as `entry.options["stations"] = {serial: "local" | "remote"}` and pass
  it back as `EufySecurity(stations={sn: Reach(value) for sn, value in …})`. A station
  missing from it is left out: the library builds nothing for it, does not claim it
  from other accounts, and drops its push events.
- Then the network step, for the local stations only.

**Options flow:** the same step, run again with a fresh `async_station_choices()`.
Changing it reloads the entry. The probe is safe on a loaded entry: it never sends a
`LAN_SEARCH` to a station that has a connected session, and reports that station as local
from the session itself (`observed_ip` is the address it is connected to). While any
station is connected the probe also sends no broadcast, so an unconnected station is
found only at its known address (`station_hosts`, or the cloud's): one more reason for
the DHCP reservation and fixed address recommended in the network section.

**After setup:**
- Build entities from `eufy.stations` (full) and `eufy.remote_stations` (devices,
  event entities, and a read-only guard-mode sensor that stays unknown until the first
  push).
- Never demote a local station on its own: an unreachable one keeps its supervisor
  reconnecting and gets a repair issue (see the network section).
- A remote station that answers a later probe (the options flow, or a periodic
  `async_station_choices()` in the background) deserves a fixable repair issue:
  "HomeBase X is reachable on your network now; switch it to local control".

## Network, firewall and fixed addresses

Tell the user at setup what the network must allow. Once the entry is running, a
blocked path only looks like an unreachable station.

What the library relies on:

- **Discovery** sends a `LAN_SEARCH` to UDP 32108 on the station's address. If no
  address is known, it broadcasts, and a broadcast only reaches the host's own
  network. A container on a bridge network does not see the LAN at all.
- **The station replies from a random high port that changes every session.** A
  firewall cannot match the station's side, so a host or network firewall that filters
  inbound UDP has two options:
  1. allow all UDP from the station's address; or
  2. pin **one local UDP port per station** and allow UDP from the station's address
     to that port. Two stations cannot share a pinned port: the second cannot bind.
     A trigger frame (`async_event_trigger_frame`) opens a short-lived second session
     from an ephemeral port, which this rule does not cover: allow all UDP from the
     station's address if the integration fetches trigger frames.
- **Both rules name the station's address**, so the station needs a fixed IP: a DHCP
  reservation on the router. The same applies to a standalone camera, which the
  library treats as its own station.

The library describes each station's path; the integration only presents it:

| library | use in Home Assistant |
|---|---|
| `await eufy.async_probe_lan()` | one `LanPath` per station, after one LAN discovery (broadcast plus each configured address): no session, no cloud |
| `LanPath` | `station_ip`, `host`, `host_source` (`configured` / `cloud` / `broadcast`), `cloud_ip`, `observed_ip` (where it answered), `answered`, `local_port` as description placeholders |
| `LanPath.warnings` (`PathWarning`) | one translation key each: `broadcast_only`, `ephemeral_port`, `no_lan_reply`, `address_changed` |
| `suggest_local_ports(serials, taken=…)` | pre-fills a port per station; stable for the same stations |
| `EufySecurity(local_ports={serial: port}, station_hosts={serial: ip})` | what the options flow stores and setup passes back |

- **Probe duration:** `async_station_choices()` and `async_probe_lan()` listen for
  `LAN_DISCOVERY_TIMEOUT` (5 s) by default. A battery or solar standalone camera answers
  late (a T8170 after 2.1 s), so do not shorten it; show a progress step instead.
- **Config flow:** after the stations step, show a "network" step for the local
  stations: each one's path (the `StationChoice.path` from that step, or
  `async_probe_lan()` once they are built), its warnings, and the two firewall options
  with the suggested port filled in. Recommend a
  DHCP reservation for every station. Probe rather than trust the cloud: its device list
  often has no LAN address for a station, or a public one, so the address the station
  answers from is the one to show.
- **Options flow:** a local port (0 = ephemeral) and, optionally, a fixed address per
  station serial, stored in `entry.options` and passed as `local_ports` /
  `station_hosts`. `EufySecurity` raises `ValueError` for a port used twice, so validate
  in the form. Changing them reloads the entry.
- **Repairs:** when a station stays unreachable (its entry in the `async_start()` result,
  or a `ConnectionChanged(False)` whose cause is `unreachable` and that lasts), raise a repair issue
  carrying the placeholders of a fresh `async_probe_lan()`. `address_changed` deserves an
  issue of its own: the station's address has probably changed.

The CLI does the same: `eufy-security login` prints the advice once the session is
cached, and `eufy-security network` prints it on demand.

## Coordinator per station, push for the rest

A `DataUpdateCoordinator[StationState]` per station:

- `_async_update_data` is `await station.async_update()` — the local P2P parameter dump
  (a fraction of a second once the session is up). Use a *generous* poll interval; it is
  a safety net, not the main path.
- Real-time changes arrive by push, not polling. `eufy.subscribe(callback)` delivers
  `GuardModeChanged`, `StationStateChanged`, `ParamChanged`, `SecurityEvent` and
  `ConnectionChanged`, among others. Route each by `station_sn` / `channel`:
  - `GuardModeChanged`: set the coordinator's data directly,
    `coordinator.data = dataclasses.replace(coordinator.data, guard_mode=event.mode)`,
    then call `coordinator.async_update_listeners()`.
  - `SecurityEvent`: deliver it to the entities through the dispatcher
    (`async_dispatcher_send`), not through the coordinator.
  - `StationStateChanged(station_sn, state)`: a complete, fresh `StationState` after any
    dump that changed it (one pushed by the station, a probe, or a read), coalesced to
    one event per dump. Set `coordinator.data = event.state` and call
    `coordinator.async_update_listeners()`. `station.state` gives the same merged
    snapshot on demand.
  - `ParamChanged`: per parameter and low level; the integration does not need it
    (`StationStateChanged` carries the same change as typed state).
  - `ConnectionChanged(connected=False)`: `coordinator.async_set_update_error(...)`.
- **A battery station (`station.connects_on_demand`) must not be polled over P2P.** A
  held session keeps a battery camera awake, so the library holds none for it (a T8170
  and the other prefixes the eufy app never keeps connected, `ON_DEMAND_PREFIXES`):
  - `station.async_update()` returns its state **without waking it** (the cloud
    snapshot, pushes, the last session); only `async_update(wake=True)` reads it live.
    Keep the same coordinator and poll interval: the call is free.
  - The library refreshes that state itself: one device-list fetch for the account
    every `cloud_state_refresh` seconds (`EufySecurity(cloud_state_refresh=…)`, default
    `CLOUD_STATE_REFRESH` = 1 h, started by `async_start(p2p=True)`), each change
    arriving as `StationStateChanged`. A guard-mode push updates it at once, and so does
    a confirmed arm: `station.state` and the next `async_update()` carry the mode the
    station confirmed until a newer cloud snapshot or push reports another one.
    `await eufy.async_refresh_cloud_state()` fetches on request (a "refresh" button);
    it also refreshes every other station's cloud copy of its settings (see **State**
    below). The same interval keeps that copy fresh for every station, battery or not,
    and a station without a copy yet (a list cached by an older version) is fetched once
    at start.
  - Every command (arm, a setting, a snapshot) **wakes the camera first**: the library
    fetches its device session key (DSK, cached ~1 h) and pokes its rendezvous servers
    so it punches back over the LAN, then connects — the same path the eufy app uses. A
    `status` from cold sleep takes about 6.5 s; allow ~10 s. It can still fail with
    `StationUnreachableError` if the camera cannot be woken (its cloud link is down, or
    the cloud is unreachable so no DSK) — surface that as "could not reach the camera;
    try again" rather than a permanent error. An arm takes about 6 s: a T8170 sends no
    mode report, so the library confirms it by reading the mode back. The link ends
    when the camera falls asleep (a T8170 goes quiet about 7 s after the last command,
    and the link times out 15 s later) or after 120 s idle at the latest, with
    `ConnectionChanged(connected=False, cause=DisconnectCause.IDLE)`: **not an outage**,
    so do not mark anything unavailable on it. A `connected=True` precedes every command.
  - Availability: `SubDeviceState.online` (param 1131, from the snapshot), never
    `ConnectionChanged`. A live snapshot or stream wakes the camera: offer it on demand
    only, never on a timer.
- **Never call `coordinator.async_set_updated_data(...)` for a push.** In Home Assistant
  2026.8 it cancels and reschedules the poll timer, so steady push traffic postpones the
  guard-mode poll without bound. Setting `data` directly leaves `last_update_success`
  as it was: after an update error, entities stay unavailable until the next good poll.
- Start the local sessions once, in setup, with
  `errors = await eufy.async_start(p2p=True, push=False)`. It never raises for a
  station: the result maps each station serial that failed its first connection to the
  error (`{}` when all started), and each of those stations keeps retrying in the
  background. Raise the unreachable repair from it (see *Network*), and build that
  station's entities as unavailable.
  Stations start in parallel, so setup takes about as long as the slowest station (about
  20 s for an unreachable one), not the sum; their credential lookups are serialised, so
  a cold cache does not fetch once per station at the same moment.
- Push (FCM) is opt-in and needs the cloud; its start can take its whole deadline. If
  the user enabled it, start it after the platforms are forwarded, as a background task:
  `entry.async_create_background_task(hass, eufy.async_start(p2p=False, push=True), …)`.
- **Which stations need push for detections:** `station.local_events` (an `Evidence`)
  says whether the station pushes its cameras' detections over P2P; its paired devices
  follow it. Only `Support.VERIFIED` (a HomeBase 3) delivers them locally; for any other
  grade (a HomeBase 2, an uncatalogued station) the detections arrive by cloud push only,
  so offer or require push for that station and show `local_events.source` as the reason.
- **Push status:** `PushChanged(running, error)` arrives on every change, and
  `eufy.push_running` / `eufy.push_error` give it on demand; `async_start` never raises for
  push. While push is enabled but not running, raise a "push is not running" repair
  issue and clear it on `PushChanged(running=True)`. A cloud error behind it is already
  its own `CloudProblem` (see the error table), so the `PushChanged` then carries
  `error=None`: key repairs about the cloud on `CloudProblem`, not on this. A remote
  station depends on push alone, so mark its entities unavailable while
  `push_running` is False.

So arming, disarming and motion reach HA immediately; the poll only reconciles.

**Live guard mode over P2P.** The station reports a real guard-mode change on the P2P
channel: a `0x047f` report, about 1 s before the cloud push, which every open session
receives. The library delivers it as `GuardModeChanged(source=EventSource.P2P)`, with no
cloud and no push opt-in. What is covered:

| change made by | reaches HA live over P2P |
|---|---|
| Home Assistant itself (`async_set_guard_mode`) | yes, verified (HomeBase 3, fw 3.8.7.4) |
| another P2P client on the LAN (the CLI, another integration) | yes, a separate session saw it (fw 3.8.7.4) |
| the eufy app | yes, verified (fw 3.8.7.4, app 6.1.00): each app arm and disarm reached the library's sessions within a second |
| a schedule | yes, verified: each slot boundary reports the **slot's** mode (see below) |
| the keypad, a key fob | **not verified** |

- Apply every `GuardModeChanged` to the alarm panel straight away, as above; do not wait
  for the poll.
- Keep the poll as the safety net until the last row is settled: it catches a change
  made by a path that sends no report. Enable cloud push for remote stations, or where
  changes from the app must show within seconds.
- A mode set to the one already in force sends no report; the library settles that by
  read-back, so `async_set_guard_mode` still returns the applied mode.
- A change can arrive on both channels (the `0x047f` report, then the cloud push). The
  library emits one `GuardModeChanged` per change, from the channel that delivered it
  first, and drops a guard-mode push older than the last mode applied for that station,
  so a late or redelivered push never moves the panel back. The integration does no
  ordering of its own.
- **Schedule mode is two values, and the library keeps both.** `GuardModeChanged.mode`
  (and `StationState.guard_mode`) is the **selected** mode: `SCHEDULE` while a schedule
  runs. `GuardModeChanged.active_mode` (and `StationState.active_mode`) is the mode **in
  force**: the slot's mode under Schedule, equal to `mode` otherwise. One event per
  change of either, from whichever channel came first, so a schedule boundary is one
  `GuardModeChanged` with `mode=SCHEDULE` and the new `active_mode`. Arming to
  `GuardMode.SCHEDULE` returns `SCHEDULE` (confirmed by read-back).
- The station sends **no** arming push (msg_type 9) over P2P [verified]; the
  library's P2P arming-push path is dormant.

**Which events to trust.** Anyone on the LAN can derive a station's static key, so a
frame under it (ECB), or in clear, is forgeable. The library takes guard-mode reports,
parameter dumps and alarm frames under any encryption, as the eufy app does, so
`GuardModeChanged`, `AlarmChanged`, `ParamChanged` and `StationState` (and an arm's or
siren's confirmation) can come from such a frame; `stats().state_authenticated` says
whether the station's state has come under a key only the session holds (see
`docs/protocol/session-crypto.md`). `SecurityEvent` delivers every camera push and says
where it came from:

| `event.frame_cipher` | `event.authenticated` | meaning |
|---|---|---|
| `FrameCipher.GCM` | `True` | a P2P push under the session key |
| `FrameCipher.ECB` | `False` | a P2P push under the static key: could be forged |
| `FrameCipher.ECB`, `event.session_ecb` | `True` | a P2P push under an RSA session's key (legacy firmware) |
| `None` | `True` | a cloud push (TLS) |

- Let only an authenticated event drive a security decision: clearing TRIGGERED,
  setting `changed_by`, attributing an arm to a keypad or fob.
- Show an unauthenticated detection as a detection, but never let it change the alarm
  state.
- `authenticated` proves origin, not freshness: a GCM frame can be replayed within a
  session. Order by `event_time_ms`.

**One occurrence, one event.** `EufySecurity` de-duplicates before anything reaches
`eufy.subscribe` (`deduplicate=True`, the default), across the local push and the cloud
push and across reconnects, so the integration never de-duplicates:

- Count a detection once per `SecurityEvent` whose `enriches` is False, and turn the
  motion/person binary sensor on for it; there is no "cleared" edge, so turn it off on a
  timer.
- An event with `enriches=True` is the same occurrence arriving again with something the
  first copy lacked: media paths (typically the local copy after the cloud one), a
  picture source (`picture_sources`: fetch `async_push_image` again), or a more specific
  `detection` (a motion push followed by the same detection as a person, pet, vehicle or
  identified person). Update that occurrence's snapshot and kind (turn the person
  sensor on for an upgraded kind), do not count a new detection.
- A standalone T8170 sends two cloud pushes per detection, the second (`push_count` 2)
  with its own `unique_id` and the recording path in `file_path`, at the first one's
  `trigger_time`. The library matches them by device, event time (ms) and event type:
  the second arrives as an enrichment when its `video_path` is new, else it is dropped
  as a repeat. One detection, one event.
- A push without a `unique_id` (a HomeBase 2's) is keyed by its `session_id`, else by
  device and second regardless of its kind, so a later push that classifies the same
  detection differently is an enrichment, not a second detection.
- Station pushes (arming, alarm) are never merged away; a stale guard-mode push is
  dropped (see live guard mode above).
- For diagnostics, `eufy.deduplicator.dropped_duplicates` and `dropped_repeats`.
- For diagnostics, count events by `frame_cipher`, alongside the session's
  `state_frames_by_encryption`.
- Both decoders validate what they lift: media paths (`/zx/…`, the right suffix, no
  `..`, printable, bounded), event times (epoch ms, plausible, not far ahead of the host
  clock) and names (at most 64 characters). A value that fails is `None`, and its field
  name is in `event.rejected_fields`: log it at debug or count it, and use
  `thumb_path`, `crop_path` and `video_path` as they are. They are bound to the event's
  own record (`record_id`), so an earlier event's thumbnail or crop never leaks in;
  for the thumbnail call `await station.async_event_thumbnail(event)`: it takes the
  bound `thumb_path`, or finds the event's history row by `record_id` in one query.
  A `StillNotWrittenError` (a `RecordNotFoundError`) right after a detection is normal:
  the row, or its thumbnail, comes later (see [Camera images](#camera-images)); retry
  once, later, rather than in a loop. Any other `RecordNotFoundError` is final (another
  camera's row, no valid thumbnail path).
  Its `timeout` bounds the query and the fetch each (None: each its own default), and neither holds up an arm
  while it waits for a reply, so no shortened timeout is needed. A record id whose
  first eight digits are no calendar day (a forged push) raises `UnsupportedError`
  before anything is sent.

**Account mismatch.** `AccountMismatch(station_sn)` means the station stamps its records
with an owner account other than the one the library sends, so it may silently ignore
commands (arming, stills). Raise an `account_id_mismatch` repair issue for that station;
it is emitted at most once per connection and never carries either id.

**Availability.** `ConnectionChanged(connected=True)` arrives after the session's first
successful parameter read. `ConnectionChanged(connected=False)` carries a `cause`
(`DisconnectCause`) and the `error`, and is emitted once per outage and cause, also for
a station that never came up. `Station.connected` and `Station.last_error` give the
same state on demand. Map it:

| `cause` | HA response |
|---|---|
| `unreachable`, `probe_unanswered`, `station_closed`, `link_silent` | entities unavailable; the supervisor is already reconnecting. After a grace period, the unreachable repair issue |
| `key_rejected` | entities unavailable. The first rejection refreshes the key by itself; an `error` that is a `KeyRejectedError` means that refresh did not help (see the error table) |
| `key_unusable` | entities unavailable. The cipher key cannot be used at all (`CipherUnusableError`; `error.reason`: `no_rsa_key`/`no_ecc_key` when the cloud serves no key for the station's handshake): a device on older firmware that uses the legacy RSA handshake, whose RSA key eufy does not serve. An RSA key that eufy serves lowercased (`rsa_unparsable`) is not this case: the session runs under the static key, as in the eufy app (`static_key_session`). No re-fetch helps. Raise a repair telling the user to **update the device's firmware** in the eufy app (current firmware uses the ECIES handshake); do not call it a rejected key or suggest a reset. |
| `credentials_unavailable` | entities unavailable. With `error=None` the reason is the `CloudProblem` already emitted; with a `RefreshCooldownError` just wait, no repair |
| `protocol` | entities unavailable; log it, the supervisor retries |
| `closed` | the integration's own `async_close`: nothing to do |

`station_closed` is the station's own PPPP `CLOSE`: a HomeBase ends a session of its
own accord when more clients hold sessions than it serves (a HomeBase 3: 9, a T8170: 4; it then closes
one of them, not always the oldest) and when it reboots. `link_silent` is 15 s without a
datagram and no `CLOSE`: the station or the network in between went quiet. The
supervisor reconnects either way, within a second (its backoff of 5 s, 15 s, 60 s and
300 s applies only after a failed attempt). Neither is held back by
the library: a drop that reconnects within seconds still emits `connected=False` then
`connected=True`. Holding entities available across such a blip is the integration's
choice (a short grace before marking them unavailable); the library reports the link as
it is.

A closed session (`async_close`) never reconnects on its own — build a new
`EufySecurity` after a reload.

## Entities

- **Device registry** — each `CloudDevice` is a HA device, identified by its own serial;
  the station is the parent of its cameras and sensors through `via_device_id` (see
  *Device and entity ids*). `owner_user_id` / `member_type` are available for attribution.
  The model comes from the same object, for the station and every camera or sensor alike:
  `CloudDevice.model_name` → `DeviceInfo` `model`, `CloudDevice.model_id` → `model_id`.
- **`alarm_control_panel`** — the state comes from two values. The armed state is the
  mode **in force**, `active_mode` (from `GuardModeChanged`, or `StationState.active_mode`;
  `GuardMode` → HA armed away / armed home / disarmed / custom); the **selected** `mode`
  (`StationState.guard_mode`) says whether a schedule drives it: when it is
  `GuardMode.SCHEDULE`, show the panel from `active_mode` and expose "schedule" as an
  attribute (or as the selected option of a mode `select`). Test for disarmed with
  `mode.is_disarmed`, not `mode is GuardMode.DISARMED`: the station can also report
  `GuardMode.OFF` (6), which is a disarm too but cannot be written. An unknown code
  arrives as a plain `int`. The alarm lifecycle comes from **`AlarmChanged`**:
  `alarming=True` → triggered, `alarming=False` → back to the armed state. It is one
  start and one end per alarm across both channels (the P2P tone frames and the cloud
  alarm pushes), transitions only, and a disarm ends it; `stop_source` says `APP`
  (verified), `KEYPAD` or `HOMEBASE` when a stop named one, `duration_s` the tone's
  length over P2P. `at` is when the library saw the change (UTC, aware: the time to show
  as "triggered at"), `event_time` the time an alarm push carries itself (the station's
  trigger time where its payload names one), None for a P2P frame or a disarm. A cloud-only station gets no end when the alarm times out: expect it
  to stay triggered until a stop or disarm, or end it on a timer of your own. The same
  state is on the station: `station.alarming` (bool) and `station.last_alarm` (the last
  `AlarmChanged`, None before any), already set when a subscriber receives the event, so
  a panel or card reads it at setup and on any later refresh instead of keeping a copy.
  `DELAY`
  (pending) is only on the push: `SecurityEvent.alarm_phase is AlarmPhase.DELAY` for
  `alarm_delay` seconds (msg_type 16, unverified). For `changed_by`, use
  `arming_source` (keypad, key fob, app; `None` when not authenticated) and `user_name`
  only as a plain label: any client can send any name. Arm with
  `station.async_set_guard_mode(GuardMode.AWAY)`; it returns the mode the station
  actually applied.
- **`number` / `switch` / `select` / `sensor`** — generate from the device's settings,
  never from param ids. `station.settings_for(device_sn)` (`settings_for()` for the
  station itself) lists them: the settings of the device's model, read from the bundled
  per-model file and keyed by the vendor identifier (`power_manager_mode`,
  `watermark_set`), in display order: by section, then as the app lays them out (see
  [Grouping settings in a UI](#grouping-settings-in-a-ui)); for a paired camera or
  sensor the list includes the per-mode delays and actions (see **Per-mode actions**
  below). `station.setting(key, device_sn=…)` (or `channel=…`) returns one
  `Setting`. A model the library has no settings file for gets its settings read-only
  from the cloud, or `()` (see [Models without a settings file](#models-without-a-settings-file)).
  Each `Setting` says what entity it is:
  - `kind` (`SettingKind`): `BOOL` → `switch`; `ENUM` → `select` with the options in
    `values`; `RANGE` → `number` from `minimum`, `maximum` and `step`, unit from `unit`
    (`SettingUnit`: `s`, `ms`, `d`, `%`, or None); `STRING` and `OTHER` → at most a
    diagnostic `sensor`.
  - `writable=False` → a read-only `sensor` (`binary_sensor` for a bool). `note` says why
    a setting is not writable (on a writable one it is a caveat, such as `round trip
    does not return the written value`): the handler ignores, transforms or rejects the
    value, it has no write path, it is the guard mode (use `async_set_guard_mode`), or it goes
    over a transport the library does not send (`cloud request`, `app-local`,
    `multi-command write`, `Bluetooth`, `MQTT`).
  - `readable=False` → the dump never reports it, so its state is always unknown.
  - `applies_when`: see [`applies_when`](#applies_when).
  - Values are the vendor's: int for an enum or a range (a few enums have str values),
    bool for a bool, str for a string. `default` is the vendor default; a station setting
    neither source carries reads it (see **State**).
  - Unique ids: `entity_unique_id(serial, setting.key)`; every setting key is valid for it.
  - Display text: `name` (a short English title) and `labels` (value → the app's title,
    also `setting.label(value)`). Show an option by its label and map the picked label
    back to its value, or pass the label itself: the write accepts both.

  **Generate from the settings list, never from what the device reports.** A parameter
  block is a template the station serves per channel, not a capability list: both
  eufyCam 3 report whole `BAT_DOORBELL_*` and `INDOOR_*` families they cannot own, the
  motion sensor reports the hub's ten alarm and leaving delays, and two cameras of the
  same model on the same station do not even carry the same parameters. Enumerating the
  dump would put a doorbell chime switch on an outdoor camera and make entities come and
  go between polls. See [reference/source-of-truth.md](../reference/source-of-truth.md).

  The reverse risk — the settings list claiming a setting a given unit never reports — is
  the library's to audit, not yours: `StationState.coverage()` and `eufy-security
  coverage` compare the two per block. If it ever shows a listed setting going unreported
  on your hardware, that is a library bug to file, not something to work around.

  **State:** `state.setting(key, device_sn=…)` (or `channel=…`) on the coordinator's
  `StationState`, or `SubDeviceState.setting(key)`, returns the decoded public value (the
  type above), or None when no source has a value or the setting is not readable. Show
  None as unknown; never substitute a default yourself. A paired device's value comes
  from the dump. A station setting (no target, the station's serial, or channel 255)
  reads the dump, then the cloud's copy of the station (the device list's `params`, and
  its `time_zone` for the time-zone setting), then the setting's `default`, which is what
  the eufy app shows when neither carries the parameter; `state.setting_source(key, …)`
  says which (`ValueSource.P2P`, `CLOUD`, `APP_DEFAULT`, or None for no value). So a
  HomeBase 3's cross-camera tracking switches, alarm volume and time zone have values
  although its dump never reports them. Put the source in an entity attribute if you
  like; a `CLOUD` value is as fresh as the last device-list fetch
  ([source-of-truth.md](../reference/source-of-truth.md#where-a-station-settings-value-comes-from)),
  so a change made in the eufy app shows after the next `async_discover(refresh=True)` or
  `async_refresh_cloud_state()`. `setting()` raises
  `UnsupportedError` for a key the device does not have, so build entities from
  `settings_for` and it never fires. A T8170 reports `live_streaming_resolution` per
  view (single and dual view each keep one); the library reads the quality of the view
  the camera is in.

  **Write** with `station.async_set_setting(key, value, device_sn=…, channel=…)`. It
  validates the value before anything is sent (`Setting.validate`: a str, int or bool is
  coerced per kind, an enum also takes its label; `ValueError` outside the domain), sends
  it on the path the setting's codec names (an ECB scalar, a 1350 or 1700 sub-command, or
  a command of its own id) and returns the `CommandOutcome`: `APPLIED` when the station
  answered, `DELIVERED` when it only acknowledged. A rejection raises a typed
  `CommandError` (`CommandRejectedError`, `CommandNotAppliedError`): map it to your
  write-failed error. A setting the library does not write raises `UnsupportedError`
  with its `note`. Nothing is read back: the state shows the written value until the
  next dump replaces it, so the entity follows the write at once and the next poll
  settles it. A station setting the dump never reports keeps the written value until a
  later device-list fetch shows the cloud's value changed after the write. On a standalone camera (a T8170) address a setting with
  `device_sn=station.serial` (or no target): the library renders it for the camera's
  own channel.

  **Per-mode actions** — "sound the siren in Away", "notify in Home" — are bits of a
  per-mode action mask: each camera has `camera_action_away`, `camera_action_home` and
  `camera_action_custom_1`…`_3`, each sensor `sensor_action_<mode>`, and
  `mode_action_flags(scope, device.device_type)` names the bits that apply to that
  device (camera: `record`, `camera_siren`, `station_alarm`, `notification`,
  `light_alarm`, `report_monitor_center`; sensor: `notification`, `station_alarm`,
  `report_monitor_center`, and `motion_sensor_respond` on a motion sensor only, cloud
  `device_type` 10 or 127; `async_set_mode_action` refuses a flag the device does not
  have). A flag is on as the app's checkbox is ticked: `motion_sensor_respond` is the
  app's "React to motion", on while its bit (32) is **clear** (`MODE_ACTION_INVERTED`);
  read a switch with `mode_action_on(flag, mask)`, never `mask & bit`. Turning it off
  sets the bit and, as the app does, also turns that sensor's `notification` and
  `station_alarm` off in the same write (`MODE_ACTION_CLEARS`); turning it on again
  restores neither, so refresh those switches after a write. `MODE_ACTION_ALARM_AFFECTING`
  names the flags whose change changes what sounds or flashes on a trigger
  (`camera_siren`, `station_alarm`, `light_alarm`, and `motion_sensor_respond` for the
  HomeBase alarm it clears): confirm those switches with the user; `record`,
  `notification`, `privacy` and `report_monitor_center` sound nothing.
  `MODE_ACTION_LABELS` titles every flag. A siren accessory is of kind `other`, not `sensor`. One switch per (mode, flag), for
  example "Front · Away · camera siren", written with
  `station.async_set_mode_action("away", "camera_siren", on, device_sn=…)`: it reads the
  current mask fresh, changes that one bit, writes and confirms by read-back. **Never
  write a whole mask from Home Assistant state**: the bits without a name are mode bits,
  and a raw write clears them. The alarm and leaving delays (`alarm_delay_<mode>`,
  `leaving_delay_<mode>`, `RANGE` 0–300 s) are `number` entities on every camera and
  sensor, written with `async_set_setting`. They take only the app's choices,
  `setting.values` = `MODE_DELAY_CHOICES` (0, 15, 30, 45, 60, 180, 300 s): any other
  value is a `ValueError` before anything is sent, so offer those (a select, or a number
  that snaps to them). These settings are not in the model files:
  the library writes them through the station's mode tables. The table write is proven
  on hardware; the flag names come from the app.

  What to know before offering them:
  - Each write replaces the mode's whole table on the station (`SET_ALL_ACTION`): the
    library reads every device's current values fresh and writes them back unchanged,
    so a write is slower than other settings (a dump, the write, a read-back of every
    device). Every mode-table write of a station (single flag, bulk, delay setting)
    holds the same per-station lock, so concurrent writes run one after the other and
    keep each other's bits.
  - **A delay is one value per mode.** Setting a device's Away alarm delay to 30 also
    sets it to 30 on every device whose Away alarm delay is on; setting it to 0 turns
    off only that device. Refresh every delay entity after a write, and say so in the
    entity's description.
  - The write is refused (`UnsupportedError`, nothing sent) when the station has a
    paired device of no known kind (it may be a siren accessory whose triggers the
    table would clear), or when devices hold different values for a delay the table
    must carry unchanged; surface the message instead of retrying.

  **Bulk edits** (a matrix of devices × flags, and the delays, behind one Save) go in one
  call per mode, which reads the mode once, writes one table and confirms it by read-back:

  ```python
  table = await station.async_set_mode_actions(
      "away",
      {front_sn: {"record": True, "camera_siren": True}, hall_sn: {"station_alarm": False}},
      entry_s=30,  # alarm (entry) delay of every device that has it on
      entry_devices={front_sn: True},  # turn the entry delay on / off per device
      exit_s=None,
      exit_devices=None,  # leaving (exit) delay, same shape
      expect_revision=None,
  )
  table.actions[station.channel_for(front_sn)]  # the mask now in effect
  await station.async_set_mode_delays("home", exit_s=60)  # delays only, one write
  ```

  It returns the mode's `ModeTable` (`from eufy_home_security import ModeTable`: per-channel
  `actions`, `alarm_delays`, `leaving_delays`). The delays keep the one-value-per-mode
  rule: `entry_s`/`exit_s` set the value of every device that has the delay on afterwards
  (0 turns it off on all); a device turned on without a value takes the value the others
  share. Nothing is sent for an empty edit or one the table already holds (the current
  table is returned). Refused before anything is sent: a serial not paired to the
  station or a flag its kind does not have (`UnsupportedError`), a mode without
  per-device actions or one the station stores no table for (an undefined custom mode),
  the unknown-kind and delay cases above, a flag value that is not a bool, an `entry_s`
  or `exit_s` outside `MODE_DELAY_CHOICES` and a device turned on with no delay value to
  take (`ValueError`). A read-back that does not show
  the table raises `CommandNotAppliedError` naming the device and flag (`… camera_siren:
  wrote on, station reports off`). Turning `motion_sensor_respond` off clears the
  sensor's `notification` and `station_alarm` too, and asking for either on in the same
  edit is a `ValueError`. `expect_revision` is checked against the revision of
  the configuration the fresh read gives (`ConfigChangedError`, nothing sent, when it
  differs; see [Station configuration](#station-configuration)).

  **Labels:** `mode_action_label(flag)` (or `MODE_ACTION_LABELS`, from
  `eufy_home_security.devices`) gives each flag's display title in sentence case, the
  eufy app's title where it has one:

  | flag | label |
  |---|---|
  | `record` | Record video |
  | `camera_siren` | Camera alarm |
  | `station_alarm` | HomeBase alarm |
  | `notification` | Notification |
  | `privacy` | Privacy mode |
  | `motion_sensor_respond` | React to motion |
  | `report_monitor_center` | Monitoring center |
  | `light_alarm` | Light alarm |
  | `privacy_new` | Switch to privacy mode |
- **Diagnostic sensors** — from the typed state, never from `params`:
  - station: `StationState.name`, `lan_ip`, `firmware`, `sec_firmware`,
    `emmc_used_percent`. Disk figures come only from the storage record: param 1189
    reads 0 with an internal SSD in use, so the library does not read it. **`emmc_used_percent` is a HomeBase
    figure (param 1190); a standalone camera (a T8170) has no such param — its eMMC use
    comes from the storage record below (`storage.emmc.used_percent`), so show the eMMC
    from `storage.emmc` for a standalone camera, not this field.**
  - station storage, from `StorageInfo` (`await station.async_get_storage()`,
    [protocol/commands.md](../protocol/commands.md#storage-1307-verified)). Give the
    sizes in **GiB** (`used_gib`, `size_gib`, `free_gib`, unit `GiB`, device class
    `data_size`) so they match the numbers the eufy app shows (it labels GiB "GB"):
    - disk (`storage.disk`) and eMMC (`storage.emmc`), each when not None: both are a
      `StorageMedium` with the same attributes, so build **one set of descriptions
      for both** and skip a figure that reads None on a medium. Used, total, free,
      `used_percent`, `recordings_used_gib`, `wear_percent` (the eMMC's life used),
      `temperature_c` (°C, device class `temperature`; the disk's), a `problem`
      binary sensor from `healthy is False`, and a "formatting" binary sensor from
      `formatting`. The eMMC's `used_percent` is the app's figure, the same as the dump's
      `emmc_used_percent`. Keep `serial` and `label` out of state and attributes: they
      identify the drive, and the label changes on every format.
    - an external disk (`storage.external`) only when it is not None.
    - On a **standalone camera** (a T8170), `async_get_storage()` reads the camera's
      built-in eMMC through its own query and returns a `StorageInfo` with only
      `storage.emmc` set (no `disk`); it **wakes a battery camera**, so read it when the
      camera is awake anyway (at setup, or fold it into a preset/live capture) rather
      than on a timer. `storage.emmc.used_percent` is the "eMMC used" figure.
    - The library sends each model the query the eufy app sends it: a HomeBase 2 gets
      its eMMC and disk totals (sizes in MB, no recordings or wear figures), a HomeBase
      mini (T8023) and the older small HomeBases their eMMC only, like a standalone
      camera. A T8024 raises `CommandUnsupportedError` without sending anything, and a
      station that refuses the query raises `CommandRejectedError` at its receipt
      (within 30 s). Treat both as "no storage figures from this station": stop polling
      it until the next setup rather than logging an error per poll.
    - Poll it on its own slow interval (about 30 min: disk use moves slowly) rather than
      in the parameter-dump coordinator, and apply `StorageChanged(station_sn, storage)`
      in between: the station pushes a new record when a format finishes, and whenever
      the app opens its storage screen. `station.storage` has the last record.
    - No format button: a format (11003) destroys every recording, and the library
      does not send it.
  - each camera or sensor: `SubDeviceState.battery`, `rssi` (Wi-Fi for cameras, sub-1 GHz
    for the motion sensor; `wifi_rssi` / `sub1g_rssi` if you need both), `firmware`.
  - `SubDeviceState.kind` (`DeviceKind`) picks the platforms for a device.
  - `pir_event_ms` is the time of the sensor's last PIR event: fine for a "last motion"
    timestamp sensor, never for availability or "last seen". A quiet, healthy sensor
    keeps an old value, and so does a dead one.
  - **Charging and power manager** (cameras; each None when the block omits it, all
    *declared* from the vendor handlers, values live-read only). Build these and the
    battery sensor only where `station.has_battery(device_sn)` is not False: a
    mains-powered camera or a wired doorbell reports a charging field too, and the eufy
    app shows no battery for a model whose thing description lacks `battery_value`
    (None for a model without a settings list, and for kinds other than camera and
    doorbell):
    - `charging` / `solar_charging` (bool) from `power_source`, the raw param 2111
      code: 0/2 not charging, 1 USB, 3 AC, 4 built-in solar, 5 USB + built-in solar,
      6/8 external panel, 7/12 external + built-in, 20 a connected panel. A binary
      sensor "Charging" with
      `solar_charging` and `power_source` as attributes, or an enum sensor of the
      source; do not map a code outside that list to text.
    - `solar_intensity` (param 1309): raw solar input, 0 at night or without a panel;
      its scale is not known for every model, so a diagnostic number, not a percentage.
    - `battery_temperature` (°C, param 1138), and the app's power-manager figures since
      the last USB charge: `working_days`, `detected_events`, `recorded_events`
      (1191-1193). Diagnostic sensors; the counters only grow until the next USB charge.
    - `siren_actions` (params 1509-1513): the raw per-mode siren action by `GuardMode`,
      no named bits; attributes at most.
  - Motion sensor: `low_battery` (param 1601) is the sensor's own low-battery flag, a
    battery binary sensor beside `battery`. `pir_sensitivity_raw` (1609) is raw; the
    handler names only 0-2, so do not expose it as the sensitivity setting.
  - Station: `storage_status` (param 1135, raw) with `storage_ok` (the codes the app
    shows as normal), a diagnostic problem sensor; `subsystem_firmware` (5006-5012,
    version strings by param id, the subsystems unnamed): attributes on the station's
    `update` entity at most. `sd_info` (1102) is an undecoded integer: do not build
    an entity from it; disk figures come from `async_get_storage`.
  - **Availability** comes from three things, in this order: the coordinator's success,
    whether the device's block is in the dump at all, and **`SubDeviceState.online`**.
    Never from battery or signal, which a dead device keeps reporting unchanged.
  - **`SubDeviceState.online`** (param 1131) is the only field that separates a device
    that is still reporting from one the station merely remembers. The station keeps
    serving a departed device's last block for months: a departed T8910 kept quoting
    battery 30 % and -76 dBm for over a year, with `online` False.
    Bind `available` to it — `online is False` means unavailable; `None` means the block
    said nothing, which is not the same as offline, so treat it as available.
    `offline_code` carries the raw value when it is above 1: the app renders it as an
    offline reason but never names the codes, so show it as a diagnostic attribute at
    most, and do not map it to text.
  - The station's own reachability is not part of this: a `StationState` exists only
    because a dump arrived. Use `ConnectionChanged` for the station.
- **`update`** — firmware from the live dump: `StationState.firmware` and
  `SubDeviceState.firmware`. Fall back to `CloudDevice.main_sw_version` /
  `sec_sw_version` only when the dump has none: those come from the cached device list
  and go stale between refreshes. A motion sensor (T8910) reports no firmware in the
  dump, so for it the cloud value is the only source.
- **`camera`** — see [Camera images](#camera-images) and [Live streaming](#live-streaming) below.

### Settings per model

The settings of a model come from its file, as `settings_for` lists them before the
per-mode settings; a paired camera or sensor adds 15 per-mode delays and actions:

| model | settings | writable | read-only |
|---|---|---|---|
| T8030 | 74 | 12 | 62 |
| T8160 | 101 | 32 | 69 |
| T8170 | 145 | 41 | 104 |
| T8910 | 11 | 2 | 9 |

Every model's keys, values, units and labels are listed in
[reference/devices.md](../reference/devices.md#settings).

For the integration this means:

- **Keys are the vendor's.** Each setting is a `(serial, key)` unique id with the vendor
  identifier as key; new models arrive with a library release, without an integration
  release.
- **Names and labels come from the library.** Name the entity from `setting.name` and
  show each value by its label; do not ship translations of vendor keys.
- **Import the types from the package root:** `Setting`, `SettingKind`, `SettingControl`,
  `SettingUnit`, `CommandOutcome` and `SettingsCoverage` are exported there; capability grades
  (`Capability`, `Support`, `profile_for_serial`), `MODE_ACTION_FLAGS`,
  `MODE_ACTION_LABELS`, `MODE_ACTION_INVERTED`, `MODE_ACTION_CLEARS` and `mode_action_on`
  from `eufy_home_security.devices`.

`setting.name` is the eufy app's own title where the app has one (`Clip length`,
`Intervals between triggers`, `Working mode` on a T8160), else a title made from the key;
both in sentence case, as HA names entities.
`setting.unit` is the TD's unit, or the unit the app's control shows (seconds for
`video_clip_length` and `trigger_interval_time` on the custom-recording page); use it as
the entity's unit of measurement. `setting.variant_of` is the key of the setting the app
uses in this one's place on the same model (`record_resolution__v1` →
`record_resolution`, `nightvision_type` → `nightvision_type_new`), else `None`: register
a variant disabled by default instead of matching key suffixes. A variant identical to its
primary in codec, domain, labels and control is not in the file at all
(`detection_sensitivity_test_mode`): an entity registered under such a key has no
setting; remove it. `setting.advanced` marks a setting the app puts behind a warning
(`working_mode_value`: switching to Standard reduces the HomeBase's Wi-Fi range); register
it disabled by default and show `setting.note`, the warning, where the user enables it.
A readable setting that is not writable and has no control (`hb_keypad_is_password_set`,
a status the app only reads) is a sensor, not a switch.

**Settings a release drops.** A later release can drop a key (a variant folded into its
primary, a vendor property removed, a key the app offers a paired device only without a
parent). Ask the library instead of matching key patterns: for every stored setting
entity, at setup once the stations are built (after `async_discover()`),
`station.has_setting(key, device_sn)` (`device_sn` None for the station itself) says
whether the key is still a setting of that device here:

```python
for entry in entity_registry.entries_for_config_entry(entry_id):
    device_sn, key = parse_unique_id(entry.unique_id)  # the integration's own scheme
    if station.has_setting(key, device_sn) is False:
        entity_registry.async_remove(entry.entity_id)
```

- **True**: the key is in `settings_for(device_sn)`, the model's file in the device's
  context plus a paired device's per-mode delays and actions.
- **False**: the device's list is known and lacks the key: remove the entity.
- **None**: the list is unknown (a model without a settings file whose thing
  description is not listed yet, or no product code): keep the entity and ask again
  after the next discovery.

It covers settings only: a per-(mode, flag) switch is the integration's own key and
stays as long as `mode_action_flags` of the device names its flag.

#### One entity per writable setting: `setting.control`

`setting.control` (`SettingControl`, None when the library does not write the setting)
is the control to build, decided by the library from the vendor's codec; map it 1:1:

| `control` | kind | HA entity | value |
|---|---|---|---|
| `switch` | `BOOL` | `switch` | `setting.decode(raw)`; write `True`/`False` |
| `select` | `ENUM` | `select`, options = `setting.labels` in `values` order | the label of the value |
| `select` | `STRING` with `setting.domain` | `select`, options = `setting.values` (ids, no labels) | the id; write the id |
| `slider` | `RANGE` (≤ 200 steps) | `number`, `NumberMode.SLIDER`, min/max/step, `unit` | the number; numbered scales (`detection_sensitivity` 1–7, `ptz_turn_speed` 1–5) are ranges of the number the app shows |
| `box` | `RANGE` (more than 200 steps) | `number`, `NumberMode.BOX` | the number |
| `toggles` | `FLAGS` | one `switch` per member in `setting.flags`, named `setting.flag_label(member)` | on = `member in setting.decode_flags(raw)[0]`; write with `station.async_set_flag(key, member, on)` |
| `text` | `STRING` | `text` | the string |

Follow `control` for durations too: the app draws the clip length and the retrigger
interval as sliders; `unit` (seconds) still sets the device class. `OTHER` settings have
no control: show them read-only at most.

**Time zone (`timezone_set`, domain `timezone`).** `values` are the IANA ids of the eufy
app's zone table (`devices.timezones`, 503 zones, all `zoneinfo` keys). A write takes
an id (`"Europe/Tallinn"`) and sends the device form `<POSIX rule>|1.<row>`; anything
else raises `ValueError` before sending. The value read is the id, or None while the
device holds a form the table does not place (a bare id or rule another client wrote):
show `unknown`. Verified on a T8170 (write, read-back, the camera clock follows); the
HomeBase reports no zone. HA's own time-zone pickers show IANA ids, so the options
need no labels; sort or filter them in the integration if wanted.

Two kinds of setting share one parameter with others, and the library writes them by
reading the current mask fresh and moving only their bits, so other features' bits are
kept. Do not write them from the coordinator's cached value:

- a `FLAGS` setting (`detection_type_set`: human, vehicle, pet, other motion;
  `switching_notification`): write one member with `async_set_flag`;
- a `BOOL` with `setting.bit` (`notification_ignore_switch`, the per-type
  notification switches `notification_ai_*_switch`): `async_set_setting(key, on)` as
  for any switch; it raises `CommandNotAppliedError` (nothing sent) when the station
  does not report the current mask.

### `applies_when`

Some settings only take effect while another setting holds a given value.
`setting.applies_when` is `(key, value)` for those, else `None`: the other setting's
key and its public value. On a T8160, `video_clip_length`, `trigger_interval_time` and
`motion_stop_end_early` apply only while `power_manager_mode` is `3` (custom recording).
It is a hint for display: show or enable the entity only in that state, or say so in its
description. It never blocks a read or a write.

### Grouping settings in a UI

Every setting belongs to exactly one section: `setting.section` is its id (never None),
`setting.section_info` its `SettingSection(id, heading, order, alarm_affecting)`. `SETTING_SECTIONS` lists
every section in display order; `setting_section(id)` looks one up (`UnsupportedError`
for an unknown id). All are exported from the package root.

| id | heading | order | alarm-affecting | holds |
|---|---|---|---|---|
| `picture` | Picture | 10 | | night vision, image, lights and indicator LEDs, watermark, orientation |
| `detection` | Detection | 20 | | motion, sound, radar and AI detection, zones, package guard, cross-camera tracking |
| `recording` | Recording | 30 | | recording and streaming quality, clip length, continuous recording, audio recording |
| `audio` | Audio | 40 | | microphone, speaker, two-way talk |
| `power` | Power | 50 | | power mode, power source, battery and solar |
| `ptz` | Pan & tilt | 60 | | pan/tilt speed, tracking, cruise, presets, gestures |
| `notifications` | Notifications | 70 | | push notifications, their types, intervals and snooze |
| `doorbell` | Doorbell & chime | 80 | | chimes, ringtones, quick and automatic responses |
| `alarm` | Alarm | 90 | yes | siren, alarm tone and volume, prompts, anti-theft, SOS |
| `modes` | Modes | 100 | yes | guard modes, keypad, and the per-mode delays and device actions |
| `storage` | Storage | 110 | | HomeBase, NAS, SD-card and cloud storage |
| `network` | Network | 120 | | Wi-Fi, bridges, the HomeBase link, HomeKit and streaming protocols |
| `system` | System | 130 | | name, time zone and format, working mode, firmware, device information |
| `other` | Other | 140 | | a setting no other section fits |

- **Build tabs or headings from `setting.section`, never from lists of keys.** A new model
  or a new setting arrives in its section with a library release.
- **Ids are stable across releases;** a later release may add a section at any `order`.
  Place sections by `order`, and treat an id the UI does not know like any other (its
  `heading` from `section_info`), so a newer library never hides settings.
- **Within a section** `settings_for()` already gives the display order: the eufy app's
  placement where it has one (`page`, `group`, `order`), then the name. A variant
  (`variant_of`) shares its primary's section and follows it; an `advanced` setting stays
  in its section, hidden by default.
- **Per-mode delays and actions** (`camera_action_*`, `sensor_action_*`, `alarm_delay_*`,
  `leaving_delay_*`) are in `modes` (`MODES_SECTION`): a camera view skips that section
  rather than matching key patterns.
- **Confirm alarm-affecting settings.** `setting.alarm_affecting` is true for every
  setting of an alarm-affecting section (`alarm`, `modes`): a write sounds the HomeBase
  or camera (the alarm volume and tone play at once) or changes when and how the alarm
  sounds (siren, anti-theft, SOS, guard mode, keypad, per-mode delays and actions). Ask
  the user before sending one; the library does not prompt. The rule follows the
  section the settings-file generator gives each setting from the eufy app's page, so
  a new alarm setting is covered with the release that brings it.
- The same setting key can sit in different sections on different device kinds
  (`led_on_off`: `picture` on a camera, `system` on a HomeBase).
- A setting from a model without a settings file (see below) is in `other`.
- **What a frontend needs:** the whole layout per device, from one request: the
  sections in `SETTING_SECTIONS` order, each with its `heading` and the device's
  entities in `settings_for()` order. In Home Assistant that is a websocket command
  the integration registers (`websocket_api.async_register_command`, on the existing
  websocket), which the card or panel calls with `hass.callWS`. A UI takes sections,
  headings and order only from that layout and keeps no section table of its own.
- **An entity attribute is for templates only.** A `section` attribute with the id
  (kept out of the recorder) lets templates and automations filter entities by
  section; a card or panel does not read it, since it carries neither the heading
  nor the order.

### Models without a settings file

The bundled files cover 159 product codes. For any other code of the account,
`async_discover()` asks the cloud for its thing description, once on the first discovery
and again on every `async_discover(refresh=True)`, in the same request as every other
code. The request uses the cached cloud session and never logs in: without one, the
code stays unlisted until a later refresh. A re-key answer costs one key exchange on the
same session and one retry, as every cloud call. A failure is logged once (a key identity
the cloud still refuses at INFO, others at WARNING with the error's message) and never
fails discovery.

When the thing description arrives, `station.settings_for(device_sn)` lists the model's
properties with domain, labels, unit and default, all read-only: `writable` and
`readable` are False and `note` is `"not in bundled data"`. There is no codec, so the
state never reports a value and `async_set_setting` raises `UnsupportedError`. Offer
them as disabled diagnostic entities at most, or not at all. The listing is held in
memory only; after a restart it is back once discovery has run. A later library release
that bundles the model replaces it with writable settings under the same keys.

`eufy.model_status()` returns one `ModelStatus` per product code of the account (sync,
`()` before the first discovery): `state` is `"bundled"`, `"cloud-listed"` or
`"unknown"`, with `bundled_td_version` and `cloud_td_version`. `newer_vendor_data` is
True when the cloud's thing description is newer than the bundled file: the bundled data
stays in use, and the library logs it once at INFO. Put it in diagnostics, and raise a
repair issue at most for `"unknown"`.

### Station actions

Restart and sound/stop the alarm are calls on `Station`, not settings:

| call | does | refuses |
|---|---|---|
| `async_restart()` | reboots the station; returns after its answer | `config_support(StationFeature.RESTART)` is `UNKNOWN` |
| `async_trigger_alarm(seconds=30)` | sounds the station's siren (**alarm-affecting**) | `config_support(StationFeature.SOUND_ALARM)` is `UNKNOWN`; `ValueError` for seconds not in `SOUND_ALARM_SECONDS` (30) |
| `async_stop_alarm()` | stops the siren (**alarm-affecting**) | as the trigger, without the seconds |

Each returns `CommandOutcome.APPLIED` only once the station answered; a rejection raises
`CommandRejectedError`, an acknowledged command without an answer
`CommandNotAppliedError`. A refusal (`UnsupportedError`, naming the grade's reason)
comes before anything is sent.

Support per model is the station configuration support above
([§ Station configuration support](#station-configuration-support)): offer an action
only where `station.config_support(StationFeature.RESTART)` (or `SOUND_ALARM`) is not
`UNKNOWN`, behind a confirmation in the UI (both features are `alarm_affecting`), and
show the grade. After a restart the station's state is unavailable until the session
reconnects on its own (a `ConnectionChanged` reports the drop and the return); do not
retry the restart meanwhile. Wire formats:
[commands.md](../protocol/commands.md#station-actions-verified-t8030-declared-app).

### Device sirens and the camera switch

A device's own siren or light (the eufy app's alarm button, live view and device
card) is a call on the station it is paired to, for every device the app offers one:

| call | does | refuses |
|---|---|---|
| `device_alarms(device_sn)` | the offered choices (`DeviceAlarm.SOUND`, `LIGHT`, `SOUND_AND_LIGHT`), empty when none | — |
| `device_alarm_default(device_sn)` | the choice the app preselects, None when none | — |
| `async_trigger_device_alarm(device_sn, alarm=None)` | sounds `alarm` (default: the preselected one) for 30 s (**alarm-affecting**) | `UnsupportedError` when the app offers the device no alarm, or not that choice |
| `async_stop_device_alarm(device_sn, alarm=None)` | stops it (**alarm-affecting**) | as the trigger |
| `device_alarm_on(device_sn)` | whether it is on (`True`/`False`), None before any report, where `device_alarms` is empty and for a paired device without a channel | — |

The choices and requests come from the model's handler per connect type (generated
data, [commands.md § Device siren](../protocol/commands.md#device-siren-declared-app));
graded *declared (eufy app)*, not verified on hardware. Each returns
`CommandOutcome.APPLIED` only once the station answered or its alarm frame shows the
alarm in the asked state; otherwise as the station actions above. A serial that is
neither the station nor paired to it gets `()` / None and `UnsupportedError`, as does
an int choice that is no `DeviceAlarm`. For a
siren entity per device: create it where `device_alarms(sn)` is not empty, `turn_on` →
trigger, `turn_off` → stop, offer the choices as tones, and take `is_on` from
`device_alarm_on(sn)`, refreshed on `DeviceAlarmChanged` and read again on (re)connect
and on `StationStateChanged` (a device list change can move a device's channel).

`DeviceAlarmChanged(station_sn, device_sn, on, alarm, event_type, at)` is emitted once per
transition, whoever sounded or stopped the alarm (this library, the eufy app, a
detection, a timeout, a disarm); the state is set before it is emitted. `alarm` names the
choice whose request sends the reported type (a manual alarm), None for a detection's
siren and when off. A device counts as off before its first report, so the `[0, 0]`
frames an arm or disarm sends emit nothing. The state comes from the frames the eufy app
reads (declared: eufy app, not verified on hardware):

- a device whose alarm request is 1202 (most cameras behind a HomeBase): the
  device-siren frame on its channel, as the app counts it down: on from an alarm type
  with time left, off from an off type with none, other frames ignored; an on state
  reads off by itself (`event_type` None) a little after its time left runs out
  without an end frame, also across a dropped session. A parameter dump does not count;
- a device whose alarm request is 1201 (a HomeBase's own serial, most standalone
  devices, a few devices behind a station): the station's alarm tone, which is
  `alarming` and `AlarmChanged`, with their rules (no countdown); every such device of
  the station changes with it.

No `source` is given: a manual alarm from this library and from the eufy app send the
same request and are reported by the same frame.

A HomeBase's own serial is its station siren: the app offers sound, light and sound
and light there, and all send the request of `async_trigger_alarm` (refused where that
is). Do not create a second siren entity for it; the existing station siren covers it.

A camera's on/off switch is the setting `camera_on_off` (bool, `True` = on) on every
model whose handler writes it; write it with `async_set_setting("camera_on_off", on,
device_sn=…)`. The command and its polarity come from the model's file.

### Camera images

A camera has three image sources, described as data in `IMAGE_SOURCES`
(`ImageSourceInfo`: `high_resolution`, `content_type`, `wakes_camera`,
`needs_recording`, `typical_seconds`, `support`). Build the option labels and
descriptions from it rather than restating them.

| `ImageSource` | what | size | camera | typical |
|---|---|---|---|---|
| `THUMBNAIL` | the still the station stored with the event (`image/jpeg`) | 640×360 | stays asleep | about 0.4 s |
| `TRIGGER_FRAME` | the first keyframe of the event's recording (`video/hevc` or `video/h264`) | the recording's resolution: 3840×2160 on a T8160 | stays asleep | about 1–1.5 s, plus the decode |
| `LIVE` | a keyframe of the live stream now (`video/hevc` or `video/h264`) | 3840×2160 on a T8160 | **wakes a battery camera** | a few seconds (the camera wakes first) |

Two calls, each returning a `CameraImage(source, device_sn, data, content_type,
record_id, recorded_at, preset, width, height, codec)`, with `is_jpeg` and `high_resolution`
(`width`/`height`: a live keyframe's picture size, None for the other sources;
`preset`: the slot of a preset image, else None):

- **For a detection:** `await station.async_event_image(event, source)`. `THUMBNAIL`
  is `async_event_thumbnail` (the bound path, else the history row by `record_id`);
  `TRIGGER_FRAME` is `async_event_trigger_frame` (a short-lived second session, so
  arming and polls are never delayed); `LIVE` wakes the event's camera. Each source
  fails on its own, so "the thumbnail at once, then HD" is two calls.
- **On demand, without a detection:** `await station.async_camera_image(device_sn,
  source, days=7)`. `THUMBNAIL` and `TRIGGER_FRAME` come from the camera's newest
  recorded event in the history (today, then back day by day), with the camera asleep:
  this gives an HD image at setup, after a restart, or from a "refresh image" button,
  without spending battery. `record_id` and `recorded_at` say which event it shows;
  `RecordNotFoundError` when there is none in the window (for example after a format).
  `LIVE` takes a live keyframe.
- **For a cloud push that names a picture of its own:** `await
  eufy.async_push_image(event)` when `event.picture_sources` is not empty, returning a
  `PushImage(source, device_sn, data, content_type, face_id)` (`PushPictureSource.FACE`:
  the cloud's face crop of a person push, `PIC_URL`: the push's own picture). This is
  the only picture a HomeBase 2 person push has: its station path is not on the push,
  and the camera stays asleep. The library decodes the eufy-obfuscated V1/V2 pictures
  itself; `VideoEncryptedPictureError` (an `UnsupportedError`) means the account's
  Video Encryption protects the picture, which no client but the eufy app can show:
  keep the previous image. See [events.md](../protocol/events.md#push-pictures).
- **`LIVE` shows the camera asked for** on a station with several cameras (the live
  open names the channel in its subheader). A live stream
  whose frames come from another camera raises `ProtocolError` rather than returning
  that camera's view. No workaround is needed in the integration.

**Suggested configuration** (Configure options; the defaults cost no battery):

| option | values | behaviour |
|---|---|---|
| Camera image | **HD from the recording** (default) | on a detection: `THUMBNAIL`, then `TRIGGER_FRAME` replaces it once decoded; at setup: `async_camera_image(device_sn, TRIGGER_FRAME)` |
| | Fast thumbnail only | `THUMBNAIL` for detections and at setup; no playback, no ffmpeg |
| | HD only | `TRIGGER_FRAME` only (no low-resolution image in between) |
| HD image size | original (default) / 1920 wide | the ffmpeg scale below; the camera entity still scales on request |
| Live image when there is none | off (default) / on | `LIVE`, at most once per camera per 300 s: it wakes a battery camera |

A "refresh image" button per camera calls `async_camera_image(device_sn, <the chosen
HD or thumbnail source>)` and never `LIVE` unless the live option is on.

**Decoding a keyframe to JPEG stays in the integration** (Home Assistant ships ffmpeg;
the library has no native dependencies). Pipe `data` into ffmpeg with the image's codec
as the input format (`-f {image.codec}`: `hevc` or `h264`, see
[Video codecs](#video-codecs)):

```
ffmpeg -hide_banner -loglevel error -f <codec> -i pipe:0 -frames:v 1 [-vf scale=1920:-2] -q:v 2 -f image2 -c:v mjpeg pipe:1
```

Check that the output starts with `FF D8`, bound the run (about 20 s), and keep the
previous image on any failure. Never serve `video/hevc` or `video/h264` as the camera
image.

**Other rules:**
- **Offer what `station.image_sources(device_sn)` lists.** Behind a station it is all
  three; a standalone camera (T8170) lists no recordings, so it offers `THUMBNAIL`
  (its newest event still, through the event-count query) and `LIVE`, and
  `TRIGGER_FRAME` raises `UnsupportedError` at once. Its history listing is graded
  per verb: 10011 measured unanswered on a standalone T8170 (verification log, *T8170
  event history and stills*); the verb the app sends it and every station outside the
  HomeBase 3 family, 10017 (`history_query_verb`), is declared from the app and not
  observed on hardware. An unanswered 10017 query ends after one resend with
  `DeviceTimeoutError`, a reply without rows ends the listing empty; `THUMBNAIL` stays
  a standalone camera's only still until a log shows 10017 rows. Its stills come in the V1
  `eufysecurity` format, which the library decodes: the integration gets a JPEG.
- **A standalone camera's detection** (cloud push only, no path or record):
  `async_event_image(event, THUMBNAIL)` wakes it, reads its newest still and returns it
  only when the still's time lies within `STANDALONE_STILL_WINDOW` (2 s before to 30 s
  after) of the detection, read in the camera's own `timezone_set`. Otherwise
  `StillNotWrittenError` when the newest still is older than the detection (retry once,
  about 20 s later; `offset` is the still's time minus the detection's), a plain
  `RecordNotFoundError` when a later detection's still replaced it or there is no dated
  still (give up). On a T8170 the still was named 2 s after the
  trigger and the call took 2.5 s (one sample).
- **A standalone camera's HD image:** a woken T8170 climbs 1280×720 → 1920×1080 →
  2880×1616 over about 8.5 s, so a plain `LIVE` image is its first rung (1280×720 in
  5.2 s). `async_event_image(event, LIVE, full_resolution=True)` (also on
  `async_camera_image`) holds the stream until the size stops changing
  (`SETTLE_STANDALONE`, at most `FULL_RESOLUTION_TIMEOUT` = 30 s after the first
  keyframe) and returns the largest size's keyframe: 2880×1616 in 16.8–17.0 s on a T8170
  (two cold wakes), the camera awake meanwhile. Behind a station `SETTLE_STATION`
  applies. `TRIGGER_FRAME` of a standalone event raises `UnsupportedError` before
  anything is sent: the camera did not play its own recording (verification log,
  *T8170 recording playback*).
- A thumbnail that is still not a JPEG (V2 or V8, or a V1 still that did not decode)
  raises `UnsupportedError` from both calls; the lower-level `async_fetch_still`
  returns it labelled instead.
- `StillNotWrittenError` from a detection's thumbnail right after the push is normal: in
  one sample the event's history row was missing 3.8 s after the trigger and present
  (with its `thumb_path`) 42 s after. Show the trigger frame meanwhile, and retry the thumbnail
  once, later, not in a loop.
- Calls queue per station (one short-lived session at a time). Pass `wait=True` to a
  live `async_snapshot` when requests can overlap. A still fetch that times out can be
  retried; its late reply is never served as the next image.
- A live image never returns a stale frame: a battery camera woken again may first
  replay its previous stream's last keyframe (minutes old), so the library takes the
  fresh one that follows. Show `LIVE` images as they come.

### Live streaming

A camera's live video reaches Home Assistant as **MPEG-TS over HTTP**. That one URL
feeds both of HA's consumers — the `stream` component (HLS, recording, snapshots) and
go2rtc (WebRTC) — and neither decodes video, so the camera's own video (HEVC or H.264,
see [Video codecs](#video-codecs)) travels to the browser untouched.

**Nothing on the HA host decodes or re-encodes video, and that is not an optimisation.**
A typical HA host cannot do it: on an RK3328 board, decoding one 4K HEVC stream alone
measured **0.58× realtime** with all four cores saturated, while remuxing the same
stream costs about **2 % of one core**. Any design that decodes video on the host is
unusable on small hardware. Audio is passed through too; only WebRTC needs a transcode
(see *Audio*, below).

#### Which cameras stream

Ask the station: `station.live_support(device_sn)` returns an `Evidence` whose `support`
is `VERIFIED` (proven on hardware), `DECLARED` (the library sends the open the device's
own handler in the eufy app sends, under this station) or `UNKNOWN` (no open recorded, or
an open the library does not implement; `source` says which). Offer a stream entity for
anything but `UNKNOWN`. It depends on the station as well as the model: a Wi-Fi camera
linked to a HomeBase is opened differently from the same camera on its own, and the
library implements only some of those opens. `profile_for_serial(...).support(
Capability.LIVE_STREAM)` is `DECLARED` when the library sends the handler's open under
*some* station, so it can say yes for a camera this station cannot stream; prefer
`live_support`. Opening a stream the library cannot open raises `UnsupportedError`
before anything is sent.

#### What the library gives you

```python
from eufy_home_security import StreamBroadcast

broadcast = StreamBroadcast(
    lambda: station.async_open_live(device_sn, wait=True),
    audio=True,  # carry the camera's AAC; silence until it arrives
    standalone=station.is_standalone,  # the settle window, for on_resize="end"
    name=device_sn,  # for log messages
)

async for chunk in broadcast.subscribe():  # muxed MPEG-TS bytes
    await response.write(chunk)
```

`StreamBroadcast` opens the camera on the first subscriber, muxes once, fans the bytes
to every subscriber, and closes the camera when the last one leaves. **Two viewers of
one camera cost one station session**, which matters: a HomeBase 3 holds 9 sessions
across all clients, a T8170 4, and a live open wakes a battery camera.

| member | what |
|---|---|
| `subscribe()` | an async generator of muxed TS bytes; close it (or stop iterating) to unsubscribe |
| `header` | the current picture group (tables, the latest keyframe and everything since), sent to each new subscriber automatically |
| `size` | the frame size being streamed, once it has settled; follows a size change |
| `settle` | the settle window in use: 0 by default (see *Starting*) |
| `error` | why the last stream ended, or `None` if it ended cleanly |
| `ended_by_resize` | the last stream ended at a picture-size change (`on_resize="end"` only) |
| `resizes` | size changes the running stream followed (`on_resize="continue"`) |
| `subscribers` | how many readers are attached |
| `running` | whether the camera stream is open |
| `aclose()` | stop the camera and release every subscriber |

**Keep one broadcast per camera for the life of the config entry.** It reopens cleanly
on the next subscriber after a stream ends, with a fresh encoder; discarding and
rebuilding it per stream throws away nothing useful and costs an extra object.

**Telling the user why a stream failed.** A subscriber only ever sees its iteration end
— a failed stream must never hang a reader — so read `error` afterwards to decide what
to say. `StationUnreachableError` is "could not reach the camera, try again" and
deserves a retry; `None` after frames flowed is a clean end and deserves nothing.
`CameraWakeError` (a `CommunicationError`, not a `StationUnreachableError`) is a HomeBase
camera the station could not wake: the station is up, the camera is not reachable. It
arrives with the station's failure receipt, about 12 s after the open, not after the
20 s first-frame timeout. Answer the viewer with an error (HTTP 503) rather than an empty
200, and do not reopen at once: the session itself refuses further live opens of that
camera for `WAKE_BACKOFF` (60 s, then 300 s, then 900 s for consecutive failures), each
refusal a `CameraWakeError` with `retry_after` set and nothing sent, so a dashboard left
open does not make the station wake the camera again every few minutes. A stream of that
camera that starts clears the backoff; `StationSession.clear_wake_backoff(channel)` clears
it on the owner's word (a user pressing "retry"). `wake_backoff_left(channel)` says how
long is left.

#### Serving it

The library does not own an HTTP server — HA has one. Register a view that subscribes:

```python
class EufyStreamView(HomeAssistantView):
    url = "/api/eufy_security/stream/{token}"
    name = "api:eufy_security:stream"
    requires_auth = False  # see the note on tokens below

    async def get(self, request, token):
        broadcast = self.broadcasts.get(token)  # a random token per camera
        if broadcast is None:
            return web.Response(status=404)
        response = web.StreamResponse(headers={"Content-Type": "video/mp2t"})
        await response.prepare(request)
        try:
            async for chunk in broadcast.subscribe():
                await response.write(chunk)
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        return response
```

Then hand the URL to HA:

```python
async def stream_source(self) -> str | None:
    return f"http://127.0.0.1:8123/api/eufy_security/stream/{self._stream_token}"
```

`stream_source()` is called repeatedly (every WebRTC offer, every recording), so it must
**return a stable URL without opening anything**. The camera opens when something
actually connects.

**On `requires_auth`.** go2rtc fetches the URL as a plain HTTP client with no HA
credentials, so a view behind HA's auth is unreachable to it. Use an unguessable
per-camera token in the path and treat the URL as the secret, or bind the view to
loopback. Do not simply leave an authenticated camera stream open to the network.

**Do not put the camera serial in the URL.** go2rtc writes the URL it dials into its
own config and logs, so a serial in the path ends up recorded outside HA. A random
per-camera token avoids that and is what you want for the reason above anyway.

#### Starting: the first keyframe, then the camera's own ramp

A camera does not open at its final resolution, and the two kinds ramp in **opposite
directions** (measured):

| camera | ramp | first keyframe after the request |
|---|---|---|
| T8160 behind a HomeBase | 3840×2160 → 2304×1296 in ~0.6 s (none at the 4K quality) | ~2.4 s |
| T8170 standalone battery | 1280×720 → 1920×1080 → 2880×1616 over ~8.5 s | ~4.3 s, wake included |

Each step lands on a keyframe with fresh parameter sets, and the broadcast follows a
size change (below), so **by default the stream starts at the first keyframe** and the
ramp plays out in the viewer: a T8170 shows 1280×720 first and sharpens twice. HA's
stream worker carries both recorded ramps with every segment decoding.

With `on_resize="end"` a ramp step would end the stream, so that policy waits for the
size to hold for a settle window first (`SETTLE_STATION` = 2.5 s, `SETTLE_STANDALONE` =
6.0 s, both exported, picked by `standalone=station.is_standalone`); expect about 3 s
(station) or 12–20 s (battery) of latency there. An explicit `settle=` wins under
either policy.

**A size change after the start is followed by default** (`on_resize="continue"`).
A T8170 zoom from 2x to 2.5x, or a go-to between presets of different zoom, changes the
picture size mid-stream. MPEG-TS carries no picture size, so the broadcast keeps the
same muxer and resumes the video at the first keyframe of the new size, behind fresh
tables; that keyframe becomes the `header` for later subscribers. At most one frame
(67 ms at 15 fps) is dropped; audio keeps flowing. Measured against the consumers with
recorded T8170 zoom streams:

| consumer | result |
|---|---|
| HA `stream` worker (PyAV → fMP4 → HLS) | carries on: one discontinuity sequence, no `StreamEndedError`, every segment decodes |
| HLS in Chrome (MSE, init from the first segment) | plays through both changes, 0 dropped, 0 corrupted frames |
| go2rtc 1.9.14 → WebRTC H.265 in Chrome | follows both changes in the same session, 0 dropped frames, no reconnect |
| go2rtc 1.9.14 → fMP4 (`stream.mp4`) | carries on, decodes at both sizes |

HA's fMP4 init keeps the size of the first segment; players take the size from the
in-band parameter sets, which is what the table above measures.

With `on_resize="end"` the subscribers' stream ends at the change
and `ended_by_resize` says so (`error` stays `None`). Add `resize_grace=` seconds to keep
the camera stream open with no subscriber, so a reconnect within that time needs no
wake and no settle: the next subscriber gets the new size's keyframe at once. **A
battery camera stays awake for the grace time**: a stream costs about the same power as
a watched one, so 30 s of grace per resize end is 30 s of live-view battery.

#### Audio

The camera's AAC (16 kHz mono) is carried untouched, so **HLS and recording have audio
for free**. WebRTC cannot carry AAC at all — RFC 7874 admits only Opus and G.711 — so
that path needs an AAC→Opus transcode. It is audio-only (`-vn`, about 24 kb/s) and never
touches video, but it is still a transcode: leave it off unless someone wants WebRTC
audio.

`audio=True` declares the AAC track at the start. The camera's audio arrives shortly
after the first keyframe (0.2–0.6 s on a T8160, a few ms on a T8170), and a transport
stream cannot gain a track later: consumers read the program map once. So until the
camera's first audio frame the broadcast carries **silent AAC** (16 kHz mono, one frame
per 64 ms of video), and a camera that never sends audio gives a silent track, not a
missing one. Measured with HA's stream worker: a declared track with no data fails it
("Error muxing stream"); a track added by a later program map is ignored; the silence
fill plays through, with the camera's audio following. `fill_audio=False` declares the
track only if audio arrived before the start.

#### Which HA path serves it

HA wires both consumers to the same URL by itself:

| path | via | video | audio | latency |
|---|---|---|---|---|
| HLS, recording, snapshots | the `stream` component (demux/remux, no decode) | HEVC or H.264 passthrough | AAC passthrough | 4–8 s |
| WebRTC | go2rtc, which dials `stream_source()` | HEVC (Chrome 136+, Safari 18+; **not** Firefox); H.264 everywhere | needs Opus | 0.1–0.3 s |

Note HA's go2rtc is built **WebRTC-only**: its `mp4`, `hls` and `mpegts` modules are not
loaded and `/api/stream.mp4` returns 404. Do not plan to read media back out of it.

#### Costs and limits

- **Several cameras of one HomeBase stream at once; the library owns the cap.** A live
  open while the station session's slot is busy runs on an extra session to the same
  station, closed with the stream (see [media.md](../protocol/media.md)). The first
  camera's start is unchanged; a second pays one handshake (about 0.5 s, first keyframe
  in 2 to 3 s measured) and the first stream is undisturbed as it starts and stops.
  Keep no per-station rule of your own (no "one live view per station" in a card):
  - the budget is `station.max_sessions` (default 6: 5 live streams per station),
    from `EufySecurity(max_sessions=…)` for every station and settable per station at
    runtime. Offer it as an **option** of the config entry (a number, 2–9, default
    `DEFAULT_STATION_SESSIONS`, bounds `MIN_STATION_SESSIONS` / `STATION_SESSION_LIMIT`)
    and assign `station.max_sessions` from the options-update listener: no reload
    needed, running streams are not ended. Say in its description that a HomeBase 3
    holds 9 sessions for everyone, the eufy app included: at 9 the app or another
    client gets disconnected when it connects;
  - over the budget the open raises `LiveStreamLimitError` (`err.limit` = live streams),
    with `wait=True` after waiting up to `first_frame_timeout` for a stream to end.
    Answer the view with a 503 and a log line naming the limit; do not retry in a loop;
  - the same camera twice is still one broadcast (`StreamBroadcast` fan-out): opening
    it again would cost a session of the station's 9;
  - a live still (`async_snapshot` without `recording`) and a preset capture are live
    opens: while a live view holds the station session's slot they run on an extra
    session **[verified, HB3: a still of the viewed camera and of another camera, 2.2
    and 2.6 s, the view streaming on]**. A live view blocks a capture only when the
    budget is used up: `LiveStreamLimitError`, or with `wait=True` a wait for a stream
    to end. End a view for a capture only then, and only `station.media_slot_camera`'s
    (ending it frees the slot). Trigger frames never wait on live views.
  - the image calls that open live take `wait`: `async_snapshot` and
    `async_preset_image` (default `False`: raise at once) and
    `async_camera_image(…, ImageSource.LIVE)` (default `True`: wait). To capture at the
    budget without the first-frame wait, call with `wait=False`; on
    `LiveStreamLimitError` end `media_slot_camera`'s view and retry once with
    `wait=True`.
  - A standalone camera keeps one stream (it holds 4 sessions in all): fan out.
- **CPU and RAM.** Three simultaneous streams cost ~10–14 % CPU each for the
  library and ~2 % for the remux, with load average ~2 of 4 cores; RAM is the binding
  constraint on a 2 GB host. Tear streams down promptly.
- **A live stream wakes a battery camera and drains it.** Keep it strictly
  user-initiated: never poll, never pre-warm, never keep a broadcast open "ready".
- **Snapshots stay on `async_camera_image`.** Do not use go2rtc's `/api/frame.jpeg`: it
  returns 500 on an HEVC stream. The `stream` component's own keyframe decode costs
  about 200 ms per snapshot, which is the only decode anywhere in the path.
- `CameraEntityFeature.STREAM` on the entity; the rest of the camera entity is
  unchanged (see [Camera images](#camera-images)).

#### What the library handles so you do not

These are handled inside `StreamBroadcast`; none need integration code:

- **Timestamps.** Frames carry the station's own clock, and it is neither monotonic nor
  unbounded: it jitters backwards by a millisecond or two, the 33-bit PES clock wraps
  every 26.5 hours, and the station's millisecond clock wraps every 49.7 days. Jitter is
  clamped, wraps are passed through.
- **A viewer joining mid-stream** first gets the current picture group: the tables, the
  latest keyframe and every frame since, so every frame it receives decodes. The
  P-frames after a keyframe reference the frames before them; a keyframe alone followed
  by the live frames would show about a picture group of broken video.
- **Slow readers.** A subscriber that cannot keep up has its backlog dropped and resumes
  at a keyframe. It never stalls the camera — the station stops sending when its frames
  are not read, which would end the stream for everyone.
- **The codec is read per stream**, not assumed: a camera that sends H.264 is declared
  as H.264.
- **A keyframe sent in parts** (a HomeBase 2 camera splits a large one over several
  records) is joined into one picture before it is delivered.

### Video codecs

Cameras send **HEVC or H.264**, decided per camera, not per integration: a HomeBase 3's
cameras and the T8170 send HEVC; a HomeBase 2's cameras, some battery doorbells (T8210)
and Solo cameras send H.264, and a HomeBase 2 camera's header even names HEVC for its
H.264 picture. The library reads the codec from the picture and says so on every
output; hard-code neither codec anywhere.

| output | where the codec is | what to do with it |
|---|---|---|
| live MPEG-TS (`StreamBroadcast`) | declared in the TS itself | nothing: HLS and go2rtc read it |
| `MediaClip` (download, capture) | `clip.codec` | MP4 remux: `-tag:v {clip.codec.mp4_tag}` only when it is not None |
| `CameraImage` (trigger frame, live, preset) | `image.codec`, `image.content_type` | JPEG decode: `-f {image.codec}` |
| `station.async_snapshot`, `async_trigger_frame`, `async_event_trigger_frame` (bytes) | `picture_codec(data)` | as `CameraImage` |
| `MediaFrame` (a raw `MediaStream`) | `frame.codec` | as the TS muxer does |
| a camera, before opening anything | `station.video_codec(device_sn)`: the codec of its latest keyframe in this run, None before any | pick a player: WebRTC carries H.264 to every browser, HEVC only to Chrome 136+ and Safari 18+ |

`VideoCodec` values are ffmpeg's raw input format names (`hevc`, `h264`);
`VideoCodec.content_type` is `video/hevc` / `video/h264`, `VideoCodec.mp4_tag` is
`hvc1` / None. `picture_codec`, `VideoCodec` and the content-type constants are exported
from the package root. For diagnostics, `station.stats()` has `media_video_codecs` (by
header), `media_codec_overrides` (header vs picture) and `media_codecs_by_channel`.

### Recordings and clips

Two producers of video files, one shape: an MPEG-TS clip (`video/mp2t`, the camera's
video and AAC untouched, starting at a keyframe) written through the integration's own
`write` coroutine, returned with a `MediaClip` that says what was written.

| | call | camera | typical (T8160, 3840×2160) |
|---|---|---|---|
| a stored recording | `station.async_download_recording(record, write)` | stays asleep (off the station's disk) | 6–11 s clips in 4.9–6.6 s |
| the live stream now | `broadcast.async_capture(seconds, write)` | **wakes a battery camera**, shared with live viewers | `seconds` plus the camera's start, about 2.5 s cold |

`MediaClip`: `video_frames`, `audio_frames`, `keyframes`, `bytes_written`,
`duration_s` (by the camera's clock), `width`/`height` (the last frame's), `resizes`,
`codec` (`VideoCodec` the clip carries, None without video; picks the MP4 tag below),
`started_at` (aware), `device_sn`, `record_id` (downloads), `expected_frames` (the
record's `frame_num`), `ended_early` (a capture whose stream ended first), `stopped` (a
capture ended by its `stop` event; complete), `complete`, `content_type`.

#### The station's recordings

- `await station.async_list_recordings(device_sn=None, *, days=2, since=None,
  limit=None, before=None, until=None, timeout=None)`: the history rows with a
  recording, newest first, of one camera or of every camera paired here; one history
  query per day and page, the camera asleep. Pass `since` (the newest `started_at`
  already stored) for an incremental sync. A standalone camera lists none.
- **A page for a list view:** `limit` stops the walk at that many rows, so only today
  (and the days back to the page's last row) are asked, not the whole window;
  `before=<the last row's record_id>` gives the next page, starting in that row's day.
  A page shorter than `limit` means the window holds no more; a full page may be
  followed by an empty one. Keep `days` as the window bound: no day before it is asked.
- **Go to a day:** `until=<date>` lists that day's rows and older ones (host-local days,
  like the window), combinable with `limit`; the next page is `before=<last record_id>`
  as usual, and `before` wins when both are given. `days` still counts back from
  today: an `until` before the window lists nothing, a day after today lists from
  today. Size `days` to reach the chosen day (`(today - until).days + n`).
- **Slow pages:** `timeout` bounds each history query (None:
  `p2p.session.HISTORY_QUERY_TIMEOUT`, 15 s). An idle HomeBase 3 answers a query of
  50 rows in 0.5-3 s (median 0.7 s); a busy one takes several seconds and sometimes
  leaves a query unanswered that it answers when asked again. So a listing asks an
  unanswered page once more with the same cursor (logged at INFO), and a late answer
  to the first query is taken too; `DeviceTimeoutError` follows only when the second
  query times out as well, so one page may take up to twice `timeout`. A single
  `async_history_record` lookup is not resent.
- `HistoryRecord` carries what a media browser needs: `video_path` (the validated
  `.zxvideo` path, else None), `started_at`/`ended_at` (aware, in the row's own UTC
  offset), `duration_s`, `frame_count`, `size_bytes`, `thumb_path`, `record_id`.
- `Station.recording_settled(record)`: the row's end lies `RECORDING_QUIET` (30 s) in
  the past. A detection's row exists while its clip still records, so download only
  settled rows. After a download the library reads the row again: a clip that grew
  meanwhile comes back with `complete` False; download it again later.
- `await station.async_history_record(record_id)`: one row by id (None when the station
  has none), for a detection's `record_id`.
- Downloads run on an extra session from the same budget as live streams of other
  cameras (`max_sessions - 2`), one per station at a time; `wait=False` raises
  `LiveStreamLimitError` instead of queueing. The station session's commands, polls
  and trigger frames are never held up. `session.stats().recording_downloads` counts
  them.

#### A live clip

`StreamBroadcast.async_capture(seconds, write, *, start_timeout=30, stop=None)` taps the broadcast
the camera entity already serves:

- no second camera stream: a capture beside a live view shares it; a capture with no
  viewer opens the camera and closes it when done (like a subscriber);
- its own muxer and timestamps, from the next keyframe; a picture-size change is
  carried at the next keyframe;
- `seconds` of camera time; a writer slower than the camera loses video to the next
  keyframe (`CAPTURE_QUEUE_FRAMES`), the broadcast is never stalled;
- a stream that ends first returns what it got with `ended_early`; no keyframe within
  `start_timeout` raises `DeviceTimeoutError`; the open's error (asleep, −204, budget)
  is raised as is; `broadcast.captures` counts running captures.
- **Stop early:** pass an `asyncio.Event` as `stop` and set it (a "stop recording"
  action). The capture ends at the next frame, finalises the TS as for a full clip and
  returns it with `stopped` True, `ended_early` False, `complete` True. A stop before
  the first keyframe raises `CaptureStoppedError` (nothing was written: "nothing
  recorded"). The camera stays open for viewers and other captures; it closes when the
  stopped capture was the last holder. Cancelling the call instead loses the clip.

#### Storing them

Remuxing to MP4 is a stream copy with Home Assistant's ffmpeg (no decode). Pick the
video tag by `MediaClip.codec.mp4_tag`: `-tag:v hvc1` for HEVC (it makes the HEVC
playable in Safari and in HA's media browser), no tag for H.264 (ffmpeg's `avc1`
default; ffmpeg refuses `hvc1` on H.264 and writes nothing):

```
# HEVC
ffmpeg -hide_banner -loglevel error -y -i clip.ts -map 0 -c copy -tag:v hvc1 -movflags +faststart -f mp4 clip.mp4
# H.264
ffmpeg -hide_banner -loglevel error -y -i clip.ts -map 0 -c copy -movflags +faststart -f mp4 clip.mp4
```

The camera's frame timing varies (VFR); the MP4 carries it as is. Write to a temporary
name and rename on success; on a failure keep nothing.

**Suggested shape in the integration:**

- One media pool per camera (`<media>/eufy_home_security/<camera>/`), named
  `<stamp>_<camera>_<kind>.mp4|.jpg`, served by a `media_source` platform, with the
  detection's still beside its video. Retention prunes by age.
- **Recordings sync:** on each detection, and on a slow periodic catch-up (missed
  pushes, a restart), `async_list_recordings(since=<newest stored>)`, then download each
  settled row not yet stored, idempotent by `record_id`. A clip that is not `complete`
  is retried on the next pass.
- **A `record` entity service** on the camera: `duration` in seconds (a "Recording
  length" option gives the default; HA's own `camera.record` uses 30 s), returning
  the stored media id (`supports_response`) for an automation's next step. A capture
  already running for the camera, a standalone limit or a sleeping camera map to
  translated `HomeAssistantError`s.

### Update entities (firmware)

`await eufy.async_firmware_updates()` returns one `FirmwareUpdate` per device the cloud
OTA offers a newer firmware for (`from eufy_home_security import FirmwareUpdate`).
**An empty list is the normal, healthy state** — it means every device is on the newest
published firmware, not that the check failed. A check that fails raises (`CloudApiError`
when the OTA answers an error other than "up to date", `EmptyResponseError` for an answer
that is no verdict, the usual cloud errors otherwise): keep the entities' last state then.

| field | use in the `update` entity |
|---|---|
| `device_sn` | which HA device the entity belongs to |
| `version_name` | `latest_version` (e.g. `3.8.7.4`) |
| `download_url` | the image on eufy's CDN; see below — do not fetch it |
| `md5`, `size_bytes` | the image's checksum and length, for display only |
| `forced` | eufy marks the update mandatory; worth a hint in the UI, nothing more |
| `notes` | `release_summary`, when the cloud sends any |

The **installed** version is not on `FirmwareUpdate` — it comes from the device you
already have: `StationState.firmware` for the station, and the per-device entry for a
camera. Only devices whose installed version is known are checked at all.

**The library never installs firmware, and neither should the integration.** Set
`UpdateEntityFeature.INSTALL` only if you have a verified install path — the library
has none. Without it the entity is a notification: "an update exists, go to the eufy app".
Do not download `download_url` and do not try to push an image to a station: the OTA
write is not implemented, and a failed firmware write bricks a HomeBase.

**Poll it slowly, on its own timer — never from the station coordinator.** It is one
cloud call *per device*, on the account's shared throttle, and eufy publishes firmware
rarely: **daily is ample**, hourly is wasteful, per start is wrong. Give it a separate
`DataUpdateCoordinator` (account-scoped, not station-scoped) so a slow or throttled
firmware check never delays the entities that matter:

```python
firmware = DataUpdateCoordinator(
    hass,
    _LOGGER,
    name="eufy firmware",
    update_interval=timedelta(days=1),
    update_method=eufy.async_firmware_updates,
)
```

**Which devices are covered.** The hub and each camera paired to it are checked, each
under the hub's firmware-kit type. A **standalone battery camera is skipped** (a T8170
on its own): its OTA kit type is not established, so it is left out rather than guessed
at, and it simply never gets an `update` entity. Create entities from the devices you
know, and mark a device's entity "up to date" when it is absent from the list — do not
create entities from the returned list alone, or a device would lose its entity the
moment its update is installed.

**Errors.** A cloud hold-off, throttle or outage raises the usual cloud errors
(`RateLimitedError`, `CloudError` — see *Errors map to HA control flow*); let the
coordinator hold the previous result and try again on the next tick. A firmware check
failing is never a reason to fail setup or to mark anything else unavailable.

### Pan/tilt presets

A pan/tilt camera has preset slots, each a stored direction and zoom. The library reads
them, turns the camera to one, and takes that view's live image, so the integration can
offer one "capture" per preset without knowing any command.

#### Which cameras pan, tilt, zoom and keep presets

Ask the station: `station.ptz_support(device_sn, capability)` for
`Capability.PTZ_CONTROL` (one-step pan/tilt), `Capability.PTZ_PRESETS` (read the slots,
turn to one) and `Capability.PTZ_ZOOM` (picture zoom) returns an `Evidence` like
`live_support`: `VERIFIED` (proven on hardware: the T8170), `DECLARED` (the device's thing
description in the eufy app declares the actions and the library sends each as the
device's own handler does, under this station) or `UNKNOWN` (`source` says why: no such
action, or a recipe or route the library does not implement). Create the controls for
anything but `UNKNOWN`. The table behind it is generated from the app's handlers for
every product (`scripts/gen_ptz.py`), so a new pan/tilt model needs a regeneration, not
code. `profile_for_serial(...).support(...)` answers the same per model, `DECLARED` when
the library sends the actions under *some* station; prefer `ptz_support`.

Storing, deleting, picturing a slot and changing the default each need an action of
their own, which some models lack (a T8173 declares no store). Ask
`station.ptz_action_support(device_sn, action)` with `PtzAction.STORE`, `DELETE`,
`SET_DEFAULT` or `SLOT_PICTURE` (exported from the package root). It grades like
`ptz_support`, from the same generated data: `UNKNOWN` when a capability the action needs
is `UNKNOWN` under `ptz_support` (`PTZ_PRESETS`, and `PTZ_CONTROL` for a store, delete or
slot picture), or when the device's thing description does not declare the action or the
library does not send it as the handler does under this station; `VERIFIED` where proven
on hardware (the T8170) and sent there; else `DECLARED`. Create each control only where
its action is not `UNKNOWN`: the "Save view" button and the `save_preset` target for
`STORE` (with `make_default`, `SET_DEFAULT` too), the `delete_preset` target for `DELETE`,
the slot pictures for `SLOT_PICTURE`, the default select for `SET_DEFAULT`. A call for an
action the model lacks raises `PtzActionUnsupportedError` (an `UnsupportedError`;
`err.action` equals the `PtzAction`) before anything is sent; a slot the camera does not
have, or an empty one, stays a plain `UnsupportedError`.

| call | what | camera |
|---|---|---|
| `station.presets(device_sn)` | the slots as last read (`PresetPosition(index, enabled, zoom, is_default)`), or `None` if never read; no I/O | — |
| `await station.async_refresh_presets(device_sn)` | reads the slots from the camera | **wakes it** |
| `await station.async_preset_image(device_sn, preset)` | turns to `preset`, returns a `CameraImage` (`source=LIVE`, `preset=preset`) taken once the camera has settled (about 7 s after the turn, 8–10 s in all) | **wakes it**, and leaves it at the preset |
| `station.is_capturing(device_sn)` | whether a live or preset image of the camera is being taken | — |
| `station.default_preset(device_sn)` | the slot the camera returns to on its own when idle (the `is_default` slot), from the last read; `None` if never read or none is set | — |
| `await station.async_set_default_preset(device_sn, preset)` | make `preset` that slot and turn the camera there; returns the re-read slots | **wakes it** |
| `await station.async_pan_tilt(device_sn, PanTilt.LEFT)` | move the camera one step (`PanTilt.LEFT` / `RIGHT` / `UP` / `DOWN`) | **wakes it**, and moves it |
| `await station.async_save_preset(device_sn, preset=None, make_default=False)` | store the current view in the lowest free slot (or in `preset`), optionally make it the default; returns its `PresetPosition` as read back | **wakes it** |
| `station.free_preset(device_sn)` | the slot a save without `preset` would take, from the last read; `None` if never read or the camera is full; no I/O | — |
| `await station.async_store_preset(device_sn, preset)` | store the camera's current view in slot `preset`; returns the re-read slots | **wakes it** |
| `await station.async_delete_preset(device_sn, preset)` | clear slot `preset` (and its default flag); returns the re-read slots | **wakes it** |
| `await station.async_preset_picture(device_sn, preset)` | the JPEG the camera stored for that slot, or `None` when it has none | **wakes it**, without moving it |
| `station.zoom(device_sn)` | the picture zoom as last reported (1.0 = 1x), or `None` before the first report; no I/O | — |
| `await station.async_set_zoom(device_sn, zoom)` | zoom the picture to `zoom` (`MIN_ZOOM` 1 .. `MAX_ZOOM` 12) about its centre | **wakes it** |

**Build entities from the cached slots, never by waking the camera to look.** The
slots are kept in the session cache, so they are there after a restart; the library
re-reads them whenever the camera is awake anyway (any live or preset image) and emits
`PresetsChanged(station_sn, device_sn, presets)` when they differ. So:

- at setup, create per enabled slot a **button** "Capture preset *n*" and an **image**
  entity showing that preset's last capture (`image` platform, `image_last_updated` =
  when it was taken), with unique ids keyed by the slot index;
- when `presets(device_sn)` is `None` (never read), call `async_refresh_presets` once,
  at setup, and offer a "refresh presets" button for later;
- on `PresetsChanged`, add the entities of a new slot; mark those of a removed slot
  unavailable rather than deleting them, so entity ids and automations survive;
- offer a service action `capture_preset(device, preset)` for automations, calling the
  same method.

**One capture at a time is the library's job.** A capture holds the camera for its
8–10 s: a second call for **the same preset** joins it and gets the same image; any
other capture of that camera (another preset, a live image) raises `DeviceBusyError`
at once, before anything is sent, so the camera is never turned away from a view that
is being captured. Turn that into `HomeAssistantError("capture in progress")` (a toast);
do not queue presses and do not make the button unavailable while busy (entities that
flicker unavailable break automations). `CameraBusyChanged(station_sn, device_sn, busy)`
reports the state if a card should show it.

**The camera returns to its default preset on its own.** One slot is the *default*
(`PresetPosition.is_default`, `default_preset(device_sn)`): the camera turns back to it
whenever it goes idle — after a manual turn, a preset capture or motion tracking. So a
preset capture leaves the view on that preset only until the camera sleeps (about 7 s
later); it is not a way to *park* the camera. The default preset **is** the parking
position, and the library sets it (**verified**, T8170: write, read-back, and the camera
back at the new default after 90 s and 5 min of sleep).

#### The default preset as a select entity

Offer one **select** per pan/tilt camera, `EntityCategory.CONFIG`, named "Default
preset", so the choice is also available to automations (`select.select_option`):

| select | from the library |
|---|---|
| created when | `station.ptz_action_support(device_sn, PtzAction.SET_DEFAULT).support is not Support.UNKNOWN` |
| `options` | the enabled slots of `station.presets(device_sn)`, as strings (`"0"`, `"2"`, …), or friendlier labels you map back to the index |
| `current_option` | `station.default_preset(device_sn)`; `None` (unknown) when the slots were never read or no slot is the default |
| `async_select_option` | `await station.async_set_default_preset(device_sn, int(option))` |
| refreshed by | `PresetsChanged(station_sn, device_sn, presets)`: rebuild `options` and `current_option` from `event.presets` (no I/O) |
| available | while the camera's station is available; a capture in progress is an error on select, not unavailability (as for the capture buttons) |

- **Read, don't poll.** Both properties come from the cached slots, never from a wake.
  The library re-reads the slots whenever the camera is awake anyway and after every
  preset write, so a default changed in the eufy app shows up after the next capture or
  live view. The "refresh presets" button (above) covers the rest.
- **Setting it turns the camera** to the new default, as the app does, and returns the
  re-read slots once the camera shows the slot as default (about 1 s on an awake camera,
  plus a wake of 4–6 s on a sleeping one). It also emits `PresetsChanged`, so the select
  updates itself; do not set `current_option` optimistically.
- **Errors**, all raised before or instead of a change, so keep the previous value.
  Catch `DeviceBusyError` before `CommunicationError`, its base class:

  | error | when | HA |
  |---|---|---|
  | `UnsupportedError` | the model has no presets, or the slot is not stored (the last read showed it empty) | `ServiceValidationError` |
  | `DeviceBusyError` | a live or preset image of the camera is being taken: nothing was sent, since the turn would spoil that image | `HomeAssistantError("capture in progress")` |
  | `CommandNotAppliedError` | the camera took the write but the read-back does not show the slot as default | `HomeAssistantError` |
  | `CommandRejectedError` with `code == -502` | the camera asks for confirmation (the app's "set anyway?" dialog) | retry once with `confirm=True` only when a service field requests it, else an error |
  | `CommunicationError` | the camera could not be reached or woken | `HomeAssistantError`; the select stays available |

- `async_pan_tilt` refuses a camera held by a capture the same way (`DeviceBusyError`),
  and `async_save_preset(device_sn, make_default=True)` makes a new parking position:
  pan to it, then save it as the default (see *Saving the current view* below).
- **Deleting the default slot leaves no default.** The camera clears the slot's
  default flag with it, so `default_preset()` is `None` and the select shows unknown
  until another slot is set as default.

The camera stays at the last preset captured only until it next sleeps (above). A preset
image fails with `DeviceTimeoutError` if the stream ends before the camera settles, and
with `UnsupportedError` for a slot the last read showed empty, or for a camera without
presets; keep the previous image of that preset on any failure.

**A battery camera sleeps between calls; the library wakes it.** A standalone T8170 stops
answering about 7 s after its last use (transport keepalives outlast that), so a call more
than a few seconds after the previous one reconnects first (a wake, about 4–6 s) instead of
timing out. Nothing to do in the integration beyond expecting the first image after an idle
gap to take a few seconds.

#### Moving the camera, and editing its slots

`PTZ_CONTROL` (a second profile capability, alongside `PTZ_PRESETS`) covers moving the
camera; with `PTZ_PRESETS` as well it covers editing what its slots hold. The T8410
Indoor Cam 2K Pan & Tilt has `PTZ_CONTROL` without `PTZ_PRESETS` (declared): it offers
`async_pan_tilt` only, and every slot call raises `UnsupportedError` before sending.
`PanTilt`, `PresetPosition` and
`MAX_PRESET_SLOTS` import from the package root
(`from eufy_home_security import PanTilt`).

**`async_pan_tilt` is a step, not a joystick.** Each call moves the camera a fixed
amount and it stops there; there is no "stop" and no hold-to-pan. Map it to four
**buttons** (or a `service` action taking a direction), not to a continuous control —
and expect the user to press repeatedly. It returns once the camera has settled
(`PTZ_SETTLE_SECONDS`, 1.5 s: a step moves for about 0.7 s and ends about 1 s after the
send). A step sent while the previous one still moves shortens it, so queue presses
rather than firing them at once.

**A manual turn does not last.** The camera goes back to its default preset a few
seconds after it goes idle, so panning is for *looking now*, never for re-aiming the
camera. To make a new view stick, pan to it and then `async_save_preset` it (optionally
making it the default) while the camera is still awake. Say so in the UI, or users will report the camera "moving back
on its own" as a bug.

**A camera holds at most 5 stored slots** (`MAX_PRESET_SLOTS`), out of the ten indices a
read reports. Storing into a full camera raises `PresetSlotsFullError` (a
`CommandNotAppliedError`): the camera accepts the command and stores nothing, so the
library reads the slots back to tell. Surface it as "delete a preset first", and free
one with `async_delete_preset`. Every edit returns the
re-read slots and emits `PresetsChanged`, so entity bookkeeping is the same as for any
other slot change.

**`async_preset_picture` shows a slot without moving the camera.** It is the thumbnail
the camera stored when the slot was saved, so it is a picture of *that view* at the time
it was stored — not a current image. It is ideal for a "which preset is which" picker,
and cheap compared to `async_preset_image` (no turn, no stream, no 8–10 s hold). A slot
whose picture the camera does not have returns `None`; show a placeholder, not an error.
Do not present it as a live view — stamp it with the stored capture time or a "saved
view" label.

**A camera that is still moving rejects the next command**; the library retries that
case for you, so an edit issued right after a turn takes a few seconds rather than
failing. Budget for it in any service-call timeout.

#### Saving the current view

`async_save_preset` is the one call a "save view" button or service needs; the
integration never picks a slot index itself. It is fake-tested; the camera behaviour it
relies on is the one verified for the store (6032) and the default (6242) writes.

```python
# the lowest free slot
slot = await station.async_save_preset(device_sn)
# a new parking position
slot = await station.async_save_preset(device_sn, make_default=True)
# overwrite slot 2
slot = await station.async_save_preset(device_sn, preset=2)
# slot: PresetPosition(index, enabled=True, zoom, is_default), as read back
```

- **Without `preset`** it re-reads the slots and stores into the lowest free index, so a
  slot stored in the eufy app since the last read is never overwritten. When the last
  read already shows 5 slots it raises before sending anything.
- **With `preset`** it stores there, in use or not. That re-storing a slot in use
  replaces its view is **declared** (the library sends it and the read-back shows the
  slot in use either way; the new view itself is not confirmed on hardware). Offer this only as an explicit
  "overwrite slot *n*" field; the plain action takes the free slot.
- **With `make_default`** it then makes the slot the default and turns the camera there
  (`async_set_default_preset`); `confirm` is passed to both writes.
- **The view must still be there.** A pan lasts only while the camera is awake (about
  7 s after the last command, or as long as a live view runs); then the camera is back
  at its default. So the flow is: open the live view, pan until the view is right,
  press "Save view" while the view still runs (or within a few seconds of the last pan
  without one), and optionally tick "make default". Say this in the button's
  description.
- `station.free_preset(device_sn)` is the slot a save would take, or `None` when the
  camera is full (or was never read). It reads the cache only, so a card can show
  "delete a preset first" before the press; the save itself re-reads.

A service action on the camera entity, next to `pan_tilt` and `goto_preset`, and a
"Save view" **button** per pan/tilt camera whose `PtzAction.STORE` is not `UNKNOWN`
under `ptz_action_support` (next to the four pan buttons) calling
`async_save_preset(device_sn)`:

```yaml
save_preset:
  target: {entity: {integration: eufy_home_security, domain: camera}}
  fields:
    preset:        # optional: overwrite this slot instead of taking the lowest free one
      required: false
      selector: {number: {min: 0, max: 9, step: 1, mode: box}}
    make_default:
      required: false
      default: false
      selector: {boolean: {}}

delete_preset:
  target: {entity: {integration: eufy_home_security, domain: camera}}
  fields:
    preset:
      required: true
      selector: {number: {min: 0, max: 9, step: 1, mode: box}}
```

`delete_preset` calls `async_delete_preset(device_sn, preset)`. Return the saved index
as an optional service response (`SupportsResponse.OPTIONAL`) if automations want it.

**Errors** (catch `DeviceBusyError` before `CommunicationError`,
`PresetSlotsFullError` before `CommandNotAppliedError` and `PtzActionUnsupportedError`
before `UnsupportedError`, their base classes):

| error | when | HA |
|---|---|---|
| `PresetSlotsFullError` (`slots`, `in_use`) | 5 slots are stored and `preset` is not one of them; nothing was sent when the cached read already showed it | `HomeAssistantError("all 5 preset slots are in use; delete a preset first")` |
| `CommandNotAppliedError`, otherwise | the camera took the write but the read-back shows no store; with `err.command == 6242`, the store took but the slot did not become the default | `HomeAssistantError` |
| `PtzActionUnsupportedError` (`action`) | the model has no such action through this station: `ptz_action_support(device_sn, err.action)` is `UNKNOWN` (a T8173 has no store, so any save); nothing sent | `ServiceValidationError` naming the action, never "no preset slot *n*" |
| `UnsupportedError`, otherwise | a model without pan/tilt presets, or `preset` outside the camera's range (0–9); nothing sent | `ServiceValidationError` |
| `DeviceBusyError` | a live or preset image capture holds the camera; nothing sent | `HomeAssistantError("capture in progress")` |
| `CommandRejectedError` | the camera refused: code 1 on all `PTZ_BUSY_ATTEMPTS` attempts (still moving), or -502 for the default (`confirm` wanted) | `HomeAssistantError` |
| `CommunicationError` | the camera could not be reached or woken | `HomeAssistantError` |

`async_store_preset` and `async_delete_preset` raise the same errors; a delete that
did not take is `CommandNotAppliedError` with `err.command == 6033`.

**Entity bookkeeping** is the one already in place for `PresetsChanged`, which every
save, delete and default write emits when the slots change: a saved slot gains its
capture button and image entity and joins the default and live-view selects' options;
a deleted slot's entities go unavailable and it leaves the options; the default select
follows `is_default`. A re-stored slot keeps its index and entities, but its stored
picture (`async_preset_picture`) is a new one: refresh a "saved view" thumbnail after
any save of that index.

#### Pan/tilt in a live view

Two calls turn the camera without taking an image, so a live view can show a chosen
preset and switch presets while it runs:

| call | what | camera |
|---|---|---|
| `await station.async_open_live(device_sn, preset=n, wait=True)` | turns to slot `n`, then opens the live stream at once | **wakes it**; the first seconds may show it turning |
| `await station.async_goto_preset(device_sn, n)` | turns to slot `n`; no image, no stream of its own. Returns after `settle` (default: the library's, about 7 s; `settle=0` returns at the camera's receipt) | **wakes it**; a running live stream keeps running |

- **The order is the library's.** A sleeping battery camera must get its live open
  straight after the turn, or it sleeps and returns to its default before the stream
  starts; `async_open_live(preset=)` does both in that order. Build the broadcast as
  `StreamBroadcast(lambda: station.async_open_live(sn, preset=chosen(), wait=True),
  standalone=station.is_standalone)`, with `chosen()` returning `None` for "camera
  default".
- **Neither call ends a stream.** A change of the chosen preset while a view runs is one
  `async_goto_preset(sn, n, settle=0)`: the viewers see the camera turn. A change with no
  viewer sends nothing; the next open uses it.
- **Both check before sending**, as the other preset calls: `UnsupportedError` for a
  camera without presets or a slot the last read showed empty (an open at a stale slot
  raises rather than silently opening at the default), `DeviceBusyError` while an image
  capture holds the camera, `ValueError` for `preset=` without `device_sn`. A go-to the
  camera refuses raises and opens nothing.
- **`async_preset_image` opens its own stream.** On a standalone camera (one stream) a
  "capture preset *n*" press while a view runs has to end the view first; on a HomeBase
  it would run beside the view on an extra session, within the session budget, as a
  live still does (see [Costs and limits](#costs-and-limits); not verified with a
  HomeBase camera that has presets). Only the go-to and the open-at-a-preset share
  a running view.
- **`FakeStation.gotos_while_streaming`** records, per go-to, whether a live stream of
  that channel was open, so "switching while watching does not end the view" is testable
  without private state.

#### Zoom

`PTZ_ZOOM` (a profile capability) covers the picture zoom: `async_set_zoom(device_sn,
zoom)` with `MIN_ZOOM` ≤ `zoom` ≤ `MAX_ZOOM` (1 and 12, exported), and `zoom(device_sn)`,
the zoom the camera last reported. The camera reports it after every write, go-to and
live open, and the library emits `ZoomChanged(station_sn, device_sn, zoom)` when it
differs, so the entity follows the camera rather than what was last sent. It works the
same for a standalone T8170 and for one paired to a HomeBase 3.

- **Zoom is for the running view.** It lasts while the camera is awake and watched: a
  go-to sets the slot's own stored zoom, and a reopened view or the idle return (~7 s)
  is back at 1x. Offer it next to the live view, not as a setting: closing a zoomed
  view and opening it again gives 1x. When the link drops, `zoom()` is set to 1.0 and
  `ZoomChanged` is emitted.
- **A `number` entity fits** (slider 1–12, step 0.5, unit "×"): the camera honours
  fractions and reaches the asked zoom within 10 %. Make it available only while the
  camera is in single view: `async_set_zoom` raises `UnsupportedError` in dual view
  (param 6243 = 12) and for models without the capability, `ValueError` outside the
  range, and `DeviceBusyError` during a capture; it sends nothing then. Show
  `zoom()`, and `None` as unknown, not as 1x.
- **Crossing 2x changes the stream's picture size.** From 2.5x up a T8170 streams at
  2304×1296 instead of 2880×1616 (at `live_streaming_resolution` 1080p: 1920×1080 →
  2304×1296). A `StreamBroadcast` follows it by default (see the live-stream section);
  the view carries on. Zooms up to 2x keep the size. Neither `live_streaming_resolution`
  nor the handler's `fixed_resolution` (1700/1018) keeps the size fixed under zoom.
- **Pan steps grow with the zoom.** `async_pan_tilt` turns the camera a fixed angle, so
  at 8x one step moves the view more than a frame width. Offer pan/tilt at low zoom, or
  say so in the card.

How the camera behaves during a view (T8170, see the
[hardware verification](../reference/hardware-verification.md)):

- **The camera holds a preset for the whole view.** A view opened at a preset stays
  there (two minutes observed), well beyond the ~7 s idle return, because the stream
  keeps the camera awake; the idle return happens after the view ends.
- **A cold open shows the default first.** On a camera asleep for over a minute, the
  first keyframes (about 2 s) show the default view, and the chosen preset from about
  4 s after the call. Nothing to do; do not hide the first frames.
- **A go-to while watching turns the running stream.** The turn takes about 7 s and
  may sweep through other views; the stream does not end and the picture size does not
  change between two presets of the same zoom. A go-to to a preset with another zoom
  across 2x changes the size like a zoom does, and the broadcast follows it.
- **A pan step while watching holds** for the rest of the view (60 s observed); the
  camera returns to its default only once the view ends and it goes idle.
- **Several viewers share the turn.** A go-to during a broadcast with two viewers
  reaches both, with no error and no size change; one leaving does not end the other's
  view.

### Arming groups

The eufy app's Group Control arms or disarms several stations at once: a group is a
house-level list of members (a HomeBase or a standalone device) each with the guard mode
it takes. The library reads and writes the groups in the cloud and activates them as the
app does; none of it is verified on hardware or against the live cloud yet.

```python
from eufy_home_security import ArmingOutcome, GuardMode

listing = await eufy.async_arming_groups()  # ArmingGroupList(house_id, groups, guided)
group = await eufy.async_create_arming_group("Leaving", {hub_sn: "away", solo_sn: GuardMode.AWAY})
await eufy.async_update_arming_group(group.group_id, name="Out")  # or members={...}
activation = await eufy.async_activate_arming_group(group.group_id)  # changes alarm state
logs = await eufy.async_arming_group_logs(group.group_id)
await eufy.async_delete_arming_group(group.group_id)
```

The models are exported from the package root: `ArmingGroupList`, `ArmingGroup`,
`ArmingGroupMember`, `ArmingGroupPreset`, `ArmingGroupLog`, `ArmingActivation`,
`ArmingMemberResult` and `ArmingOutcome`.

- **The house.** Without `house_id` every call works on the house holding this account's
  stations (`ValueError` when they are in several houses: pass `house_id`). The app's
  shared-devices view has no groups, and a house with a T9000 uses the app's professional
  arming instead (`UnsupportedError` for both). Each call reads the house list and the
  house's device list first; nothing is cached, so read groups on a user's request or on
  a slow timer, not per poll.
- **Refusals before any write.** A name the app refuses (blank, over 31 characters with
  one above U+00FF counting two, special characters such as `!`, `/`, `'` or an emoji)
  or already used in the house, no member, or a mode that cannot be written
  (`GuardMode.OFF`, an unknown code): `ValueError`, before any request for the name and
  the modes. A member that is not a station or standalone device of the house (a paired
  camera, say), a 21st group, or a custom mode a member's station does not have while
  that station's mode list is known (`Station.target_mode_name`): `UnsupportedError`.
  Each member's `mode` title is its station's name for the mode (a custom mode's own
  title) where the station's list is known.
- **Activation changes the alarm state** of every member: offer it as a button or a
  service action the user presses, never from an automation the integration starts by
  itself. The activation is recorded in the cloud first; if that fails it raises and no
  station is touched. Then each member gets its mode over its own session, concurrently
  and without retry. `activation.results` has one `ArmingMemberResult` per member:
  `CHANGED` (with `applied`), `ALREADY` (it reported that mode; nothing sent),
  `SKIPPED_OFFLINE` (its session is down; a station reached on demand is woken instead)
  or `FAILED` with `error` (the station's typed error, or `UnsupportedError` for a member
  this client has no local station for: remote, served by another account, left out).
  `activation.complete` is true when every member is in its mode; otherwise tell the user
  which members failed, as the app's "Activate Again" does. The guard-mode changes arrive
  as `GuardModeChanged` like any other.
- **Status.** `ArmingGroup.active` is the cloud's flag for the last activated group; whether
  a group is in effect is better read from the members' own guard modes.
- **Logs.** `ArmingGroupLog.create_time` is the cloud's epoch seconds;
  `ArmingGroupLog.created_at` is the same as an aware UTC `datetime`. `user_name` is the
  name an activation was recorded under: the library sends the account's nickname, as
  the app does: the login answer's `nick_name`, else the account profile's, read once on
  the first activation without a login and kept with the cached session
  (`EufyCloudApi.async_activation_user_name`); the e-mail's local part only when neither
  names one. The members' guard-mode writes still carry the e-mail's local part.

### Station configuration

`Station.async_get_config()` returns a `StationConfig`: one read model of what the eufy
app shows on a HomeBase's Security and settings pages. Build a configuration card, a
"Security mode" select and the per-mode entities from it; the integration needs no mode
table of its own.

```python
config = await station.async_get_config()  # refresh=True: fresh P2P read + cloud list once
for mode in config.modes:  # ModeInfo(code, name, icon, custom), app order
    ...
config.settable_modes  # what async_set_guard_mode writes on this station
config.mode_tables[GuardMode.AWAY]  # ModeTableView | None, per device: action, delays
config.schedule, config.schedule_default  # weekly slots (1254) and the mode outside them
config.cross_camera  # switches, chosen cameras, tracking groups
config.alarm_volume, config.time_zone  # with config.setting_keys naming the setting
config.sources["schedule"]  # ValueSource.P2P / CLOUD / APP_DEFAULT
station.config  # the same, built from the current state, no I/O
```

- **Defined modes.** `config.modes` lists the modes the station has, in the app's order
  (`MODE_ORDER`: Home, Away, Off, Custom 1-3, Disarmed, Schedule, Geofencing):
  - Home, Away and Disarmed always, with their fixed names;
  - Custom 1-3 only when the station's mode list (param 1256, usually the cloud's copy)
    names them, with the user's title (`Custom N` when the title is blank), and while the
    station reports one as its mode;
  - Schedule when the schedule has a slot or Schedule is selected;
  - Geofencing while it is selected and Off while the station reports it: the library
    cannot tell whether a station offers either otherwise. The eufy app shows a
    Geofencing tile among its modes all the time, but geofencing follows the phones
    running the app, which Home Assistant cannot do, so it is never in `settable_modes`.

  A mode outside `modes` does not exist on the station: mark its per-mode entities
  unavailable (or do not create them) instead of showing `unknown`. Without a mode list
  from either source (`config.sources["modes"]` is `APP_DEFAULT`) only the built-in modes
  are listed; the client's cloud refresh fills it in.
- **Setting a mode.** `async_set_guard_mode` writes every mode in `settable_modes`: the
  defined modes except Off, which is report-only, and Geofencing. A custom mode is written through 1224
  like a built-in one; one the station does not have is refused (`UnsupportedError`,
  nothing sent) while its mode list is known, and sent as asked while it is not. A
  station model whose `config_support(StationFeature.GUARD_MODE)` is `UNKNOWN` (the
  T8N00 and T9000, which the eufy app reaches over WebRTC, and the models without data)
  is refused before sending (`UnsupportedError`, `device_sn` the station): hide the mode
  control there. A station whose model is not a station on record is written as before.
- **Names.** `ModeInfo.name` is the display name. For a code alone, `GuardMode.label` (or
  `guard_mode_label(code)`, which also names an unknown code) gives the sentence-case
  label: Away, Home, Schedule, Custom 1-3, Off, Geofencing, Disarmed.
- **Mode tables.** One entry per defined mode that has a table (Home, Away, Custom 1-3,
  Disarmed): each device's action mask (`ModeDeviceAction.flags` names its bits) and its
  entry (`alarm_delay`) and exit (`leaving_delay`) delays, read from the devices' own
  per-mode parameters in the dump (a write's read-back updates them at once), else from
  the copy the station stores per mode (on a HomeBase 3, 1157-1161 and 1177, usually from
  the cloud list, which lags a write until the next list fetch). None when no source
  carries the table (a mode never configured); a table is never invented.
  Where the stored copy lives depends on the model
  (`mode_table_storage(product_code)`):
  - `ACTION_PARAMS` (T8001, T8002, T8010, T8025): the devices' per-mode parameters only.
  - `HB3_TABLES` (T8030): the devices' parameters, else 1157-1161 / 1177.
  - `PRO_ALARM` (T8020, T8023, T8024, T8026): the devices' parameters, as the eufy app
    reads these models, else the station's 61300 Home, 61301 Away, 61307-61309 Custom 1-3
    and 61306 Disarmed (the parameter dump first, then the cloud list). The per-mode
    settings (`camera_action_<mode>`, `alarm_delay_<mode>`, ...) read the same copy where
    the device's block lacks them.

  The integration needs no per-model code: `config.mode_tables`, the per-mode settings
  and the writes below pick the layout. On these models the tables are *declared*
  (`config_support`), not tested on hardware.
- **Delay choices.** An entry (`alarm_delay`) or exit (`leaving_delay`) delay takes one of
  `MODE_DELAY_CHOICES` (`from eufy_home_security import MODE_DELAY_CHOICES`: 0, 15, 30,
  45, 60, 180, 300 s; 0 is off), the list the eufy app offers on every station. No model
  has a list of its own; a station whose `config_support(StationFeature.MODE_DELAYS)` is
  `UNKNOWN` (the app offers no delays there, or the library cannot send them) gets no
  delay control at all: among the declared models, the pro-alarm stations (T8020, T8023,
  T8024, T8026), where the eufy app shows no entry or exit delay. On such a station the
  paired devices list no per-mode delay settings (`station.has_setting(key, sn)` is
  False), and none of the per-mode actions where mode tables are `UNKNOWN`; a station of
  no model on record lists all of them. The per-mode delay settings carry the same list
  as `setting.values`.
- **Cross-camera tracking time.** `config.cross_camera.continuous_time_s` is the
  continuous tracking time in seconds (120-1800); `continuous_time` is the same choice
  as the setting's value (`setting_keys["cross_camera.continuous_time"]` names the
  setting): an option index on a HomeBase 3 (1 = "3 min" = 180 s), titled by the
  setting's `labels` and written with `async_set_setting`.
- **Cross-camera cameras.** `config.cross_camera.eligible` lists the serials tracking can
  follow, by channel: every paired device the eufy app's list offers (it leaves out
  sensors, keypads and sirens; a paired lock is listed, as in the app).
  `station.cross_camera_eligible()` gives the same from the cloud's device list, without
  a state. Offer these in the card's camera picker and group editor instead of picking
  by device kind: `async_set_cross_camera_cameras` and `async_set_cross_camera_groups`
  refuse any other serial with the same rule, and `None` chooses all of them.
  `cameras` None means every one of them is chosen. Declared from the app.
- **Missing and unreadable values.** A value no source carries is None and has no
  `sources` entry. A value a source carries but that does not decode is named in
  `config.unreadable` with the reason; the field falls back to the next source, else None.
- **Changes.** `StationConfigChanged(station_sn, revision, fields)` is emitted (through
  `Station.subscribe`) after any state update that changes the configuration: a parameter
  dump, a cloud refresh, a write's read-back; the first configuration is emitted too, with
  every field. Nothing is emitted when no field changed. Re-read `station.config` and
  refresh what `fields` names. A guard-mode change arrives at once as `GuardModeChanged`;
  the configuration follows with the next dump.
- **Revision.** `config.revision` changes whenever any field changes and is the same for
  the same content in every process (it fits a JSON number exactly). A write call that
  takes `expect_revision` reads the station fresh first and raises `ConfigChangedError`
  without sending anything when the revision differs; `err.config` is the fresh
  configuration, so a card shows it and asks the user to redo the edit. `ModeInUseError`
  (an `UnsupportedError`) refuses a change to a mode that is in use; its `reason` is a
  sentence a UI can show.

#### Changing the configuration

```python
info = await station.async_create_custom_mode("Garden", icon=3, expect_revision=rev)
info = await station.async_rename_custom_mode(GuardMode.CUSTOM_2, "Yard")  # ModeInfo
await station.async_delete_custom_mode("custom_2")
from eufy_home_security import GuardMode, Schedule, ScheduleSlot, Weekday

schedule = Schedule(
    account_id=None,
    slots=(ScheduleSlot(Weekday.MONDAY, time(8), time(17), GuardMode.AWAY),),
)
slots, default = await station.async_set_schedule(schedule, default_mode=GuardMode.DISARMED)
await station.async_set_cross_camera_cameras([cam_sn, other_sn])  # 2 or more; None: all
await station.async_set_cross_camera_groups([[cam_sn, other_sn]])  # []: no group
await station.async_set_mode_actions("away", {cam_sn: {"camera_siren": True}})
```

- **Slots to midnight.** A slot that runs to the end of its day has `end` 00:00
  (`slot.ends_at_midnight`; show it as 24:00). The eufy app stores and shows that end as
  23:59, and the library reads 23:59 (or a stored 24:00) as 00:00 and writes it back as
  23:59, so a card that re-sends the slots it read leaves them unchanged. Build one with
  `end=time(0)` (an end of `time(23, 59)` is the same slot). A slot over midnight is two
  slots, to 00:00 and from 00:00 on the next weekday, as the app stores it. Declared from
  the app, not tested on a station.
- **What is sent.** Each call reads the station fresh, changes the one object and writes
  it whole: the mode list (1256: add, rename or delete), the schedule (1254) and, when
  it changes, the mode outside its slots (1257), the tracking cameras (1072) or groups
  (1073), a mode table (1255). Nothing is sent for a value the station already holds.
  Writes of one object are serialised per station, so two concurrent edits keep each
  other's changes. On a HomeBase 3 (T8030) each is verified: written, confirmed, checked
  in the eufy app and restored (the 1257 default and the tracking switches aside); on
  other models they are declared from the eufy app (`config_support` grades them).
- **A new custom mode.** The station seeds its device table: every camera records and
  notifies, every sensor notifies (a motion sensor also reacts to motion), no delays;
  change them with `async_set_mode_actions`. `icon` is the app's `iconType` 0-7; the
  default 7 (`DEFAULT_MODE_ICON`) shows as the app's sliders ("customize") icon.
- **Refused before sending.** `UnsupportedError` when `config_support` of the call's
  feature is `UNKNOWN`, for a tracking serial not in `cross_camera.eligible` (a sensor,
  a keypad, another station's camera), for a mode list that cannot be read or that no
  source carries yet (a station without a cloud copy: refresh first). `ValueError`, with
  a message a card can show: a mode name that is empty, over 30 characters or already
  used, an icon outside 0-7, a fourth custom mode, a built-in or missing mode to rename
  or delete, a schedule slot or default whose mode the station does not have, an empty
  camera choice or group, a camera listed twice. A schedule's own rules (start before
  end, no overlap) raise their `ValueError` when the `ScheduleSlot` / `Schedule` is
  built. `ModeInUseError` (`reason`) for deleting the current mode or one the schedule
  uses. `ConfigChangedError` for a stale `expect_revision`.
- **`expect_revision`.** Pass the `revision` of the configuration the user edited; the
  call compares it with the fresh read it writes from. On `ConfigChangedError` show
  `err.config` and let the user redo the edit.
- **Confirmed, then shown.** A write counts only when the station confirms it. Where its
  parameter dump carries the value (1072, 1073, 1257, the mode tables), a fresh dump must
  show it (`CommandNotAppliedError` otherwise). A HomeBase 3's dump carries neither the
  mode list nor the schedule: there the station's zero receipt confirms it, and
  `station.config` shows the written value at once (source `P2P`) until the cloud's copy
  changes after the write; the next cloud refresh then carries it. A mode table a
  pro-alarm station keeps only in its stored copy (61300-61309) is confirmed the same
  way: by the dump where it carries the param, else by the zero receipt.
- **Never blind.** A mode table write replaces the whole mode, so it is refused before
  sending (`UnsupportedError`) when neither the devices' parameters nor the stored copy
  give the current table, when the stored copy does not decode, or when it makes a
  trigger sound a siren accessory (the library's table would clear that).
- **Ask first.** `StationFeature.alarm_affecting` names the writes that change how the
  station alarms (schedule, mode tables and delays, guard mode): confirm those with the
  user. Within a mode table, `MODE_ACTION_ALARM_AFFECTING` names the flags that make a
  device or the HomeBase sound or flash on a trigger, so a card can confirm a siren
  toggle and pass a record or notification toggle straight through; a delay is always
  alarm-affecting. Per setting, `setting.alarm_affecting` says the same (the alarm
  volume and tone sound the HomeBase when written). The bulk mode-table write is refused when `MODE_TABLES` (or, for delays,
  `MODE_DELAYS`) is `UNKNOWN`.

### Station configuration support

Which configuration sections a station offers comes from the library, per model, never
from a model list in the integration. `station.config_support(feature)` takes a
`StationFeature` (`GUARD_MODE`, `CUSTOM_MODES`, `SCHEDULE`, `MODE_TABLES`, `MODE_DELAYS`,
`CROSS_CAMERA`, `CROSS_CAMERA_GROUPS`, `ARMING_GROUPS`, `RESTART`, `SOUND_ALARM`,
`WORKING_MODE`) and returns an `Evidence`:

```python
from eufy_home_security import StationFeature
from eufy_home_security.devices import Support

support = {f: station.config_support(f) for f in StationFeature}
shown = [f for f, e in support.items() if e.support is not Support.UNKNOWN]
```

- **`UNKNOWN`: hide the section.** `source` says why (the model's thing description
  lacks it, the app reaches the model over WebRTC, the station's firmware is below the
  app's gate, no data for the model).
- **`DECLARED`: show it with a "not yet tested on this model" badge.** The eufy app
  offers it on the model and the library sends what the model's handler sends.
- **`VERIFIED`: show it plainly** (written and read back on hardware: the HomeBase 3's
  guard mode, mode tables and delays). `note` carries caveats, such as what was only read.
- **Confirm alarm-affecting writes.** `feature.alarm_affecting` is true for the guard
  mode, schedule, mode tables, delays, arming groups, restart and sound alarm: ask the
  user before sending, naming the effect. The library does not prompt.

Without a `Station` (a config flow, a diagnostics dump), the same answers come from
`eufy_home_security.devices.config_support(product_code, feature, firmware=...)`, with
`mode_table_storage`, `mode_table_params`, `max_custom_modes` and
`cross_camera_intervals` for the per-model data. The grades per model are in
[devices.md § Station configuration](../reference/devices.md#station-configuration).

## Errors map to HA control flow

The library raises typed errors; translate them at the coordinator / setup boundary:

| library error | HA response |
|---|---|
| `LoginChallengeError`, `AuthenticationError` | `raise ConfigEntryAuthFailed` — start the reauth flow. Answer a challenge with `async_login(verify_code=…)` (or `captcha_id`/`captcha_answer`). `LoginVerificationError` (an `AuthenticationError`): the cloud refused a code answer; the password is kept, start over with a plain login for a new code. A `verify_code` challenge (`kind`) is also how an account with two-step verification answers a correct password; `code_requested` says the library has asked eufy to e-mail the code. `SessionRejectedError` (an `AuthenticationError`): the cloud refused the session again after one fresh login |
| `SessionReplacedError` | not a reauth: another app or integration logged in with this account and the cloud ended the library's session. Raise a repair issue ("give Home Assistant its own eufy account, shared from the owner"). At setup, carry on from the cache: `async_discover()` and `async_start()` need no login when the cache is warm, so local control keeps working. `raise ConfigEntryNotReady` only if `async_discover()` fails too (a cold cache). Nothing logs in again by itself, restarts included (`EufySecurity.session_replaced`); when the user confirms in the repair flow, call `async_login(force=True)` and reload the entry |
| `LoginLimitedError` (a `RateLimitedError`) | not a reauth: the credentials are fine. Raise a repair issue ("eufy is refusing logins, retrying in …"; with `origin == "budget"` it is the library's own limit for `scope`, see below the table) and carry on from the cache as above; `raise ConfigEntryNotReady` only on a cold cache. Clear the issue on the next successful login |
| `RateLimitedError` | `raise ConfigEntryNotReady` / `UpdateFailed`; schedule the next attempt no sooner than `err.retry_after` seconds |
| `StationUnreachableError`, `DeviceTimeoutError` | `raise UpdateFailed` — the session's own supervisor is already reconnecting. A reply wait moves its deadline out by the time something else held the event loop (another integration's blocking setup at HA start; up to `p2p.session.LOOP_STALL_MAX`, 30 s), so a held loop alone does not raise `DeviceTimeoutError` |
| `DeviceBusyError` (a `CommunicationError`, raised while an image capture holds the camera: by another capture, a default-preset write or a pan/tilt step) | not an outage: from a button or service action, `raise HomeAssistantError` ("capture in progress"); never `UpdateFailed` |
| `CommandNotAppliedError` | surface to the user; usually a wrong owner id or an unpaired channel |
| `LiveStreamLimitError` (a `CommunicationError`; `limit`) | the station's session budget (`station.max_sessions`) allows no further live stream; nothing was sent. From a live view answer 503 and log the limit; the station is fine |
| `CameraWakeError` (a `CommandRejectedError` and a `CommunicationError`; `code` -204, -203 or -205) | the station could not wake the camera: not a station outage, no `UpdateFailed`. From a live view, answer 503 and let the session's wake backoff (`retry_after`) decide when the next attempt goes out; from a button or service action, `raise HomeAssistantError` ("the camera did not wake") |
| `KeyRejectedError` (a `HandshakeError`; in `ConnectionChanged.error`, `Station.last_error` or the `async_start()` result) | the station rejected a key that was already fetched again once. Not a reauth: raise a fixable repair issue whose fix calls `eufy.async_reset_key_refresh(serial)`, which allows one more fetch. Without it the library tries one fetch a day by itself |
| `RefreshCooldownError` (a `RateLimitedError`, `code` 0) | the library's own spacing of key fetches, not a eufy throttle: no repair, just wait |
| `CipherUnavailableError` (an `EmptyResponseError`; `cipher_id`, `owner_source`, `retry_after`) | the cloud has no key for the cipher the station named in its handshake, under the owner id asked (`owner_source`: `"member.admin_user_id"` or `"own user id"`). Not a reauth and not an outage of the station: the share or the station's binding needs the owner. Raise one non-fixable repair issue naming the station and `cipher_id`; clear it on `ConnectionChanged(connected=True)`. The library asks the same station and cipher again only after `retry_after` (an hour) or once a refreshed device list names another owner id; until then every attempt raises this without a request. A reload of the entry asks once more |
| `StillNotWrittenError` (a `RecordNotFoundError`; `offset`) | the device has not written the event's row or still yet: keep what is shown and ask once more later (about 20 s). A plain `RecordNotFoundError` is final for that event: no retry |
| `CaptureStoppedError` | a live capture's `stop` was set before its first keyframe: nothing was recorded, nothing to store. Not an error for the user who pressed stop |
| `ConfigChangedError` (`config`, `expected`) | a write's `expect_revision` is stale: the station's configuration changed elsewhere and nothing was sent. Show `err.config` and let the user redo the edit; not an outage |
| `ModeInUseError` (an `UnsupportedError`; `reason`) | the mode is in use (current, or named by the schedule or its default); nothing was sent. `raise HomeAssistantError` with `reason` |
| `KeyExchangeRefusedError` (a `CloudApiError`; `code` 4404 or 463, `status` 463) | the cloud gateway refused the client's key identity and a new key exchange did not restore it. Not a reauth and not a kick-out: no login was attempted and none helps by itself. Carry on from the cache and retry on the next interval; the library re-keys at each attempt. Raise a repair issue only if it persists (hours) |
| any error with `device_sn` (every `EufySecurityError` has the attribute, None by default) | the message names a device by its redacted serial (`T8030***4321 has no local station`); `err.device_sn` is that device's full serial (the first one the message names). Map it to the device's name for the user instead of matching the redacted form in the text; the message itself stays as it is, fit for logs |
| any error with `device_sns` (every `EufySecurityError`; `()` by default) | every device the error is about, in the order the message names them, `device_sn` first: one serial for an error about one device, several where a message names several. A mode-table write (`async_set_mode_actions`, `async_set_mode_delays`, `async_set_mode_action`) names several: `CommandNotAppliedError` for the devices whose flag or delay the read-back does not show, or for paired devices missing from the parameter dump, and `UnsupportedError` for devices of no known kind. Name each device for the user; a channel the cloud lists no device on is in the message only |

Errors that happen in the background (a key or owner-id refresh inside a running session,
the push listener's token upload) do not raise anywhere the integration can catch. They
arrive on `eufy.subscribe` instead:

| event | HA response |
|---|---|
| `CloudProblem(error=AuthenticationError)` | start the reauth flow (`entry.async_start_reauth(hass)`), the event-side equivalent of `ConfigEntryAuthFailed` |
| `CloudProblem(error=SessionReplacedError)` | the replaced repair issue, as in the table above |
| `CloudProblem(error=LoginLimitedError / RateLimitedError)` | the limited repair issue, using `error.retry_after` |
| `CloudProblem(error=KeyExchangeRefusedError)` | as in the table above: retry later, a repair issue only if it persists |
| `CloudProblem(error=CipherUnavailableError)` | the repair issue of the table above |
| `CredentialsRefreshed(station_sn, cipher, owner_id, login)` | a persistent, non-fixable repair issue telling the user a key or owner id was fetched (and whether it cost a login) |
| `ConnectionChanged(connected=True)` | clear that station's repair issues |

A `CloudProblem` is emitted at most once per error type until the next successful login,
reauthentication, token upload, forced fetch, device-session-key fetch, cloud-state
refresh or session probe; clearing its repair issue is the integration's call.

**Noticing a lost session while idle.** An account of HomeBases alone makes no
authenticated cloud call on a timer, so a kick-out or a lapsed key identity would stay
unseen until the next command needs the cloud. Call `await eufy.async_probe_cloud_session()`
on a long interval (hours): one device-list fetch on the cached session that applies
nothing (no `DevicesChanged`, no station update, no wake). It **never** answers from the
cached list: every failure raises (and is reported once as a `CloudProblem`), including
`CommunicationError` when the cloud could not be reached. It costs a login only where
every call does (a session-expired answer); a lapsed key identity costs a key exchange.
`async_discover(refresh=True)` and `async_refresh_cloud_state()` still fall back to the
cached list when the cloud cannot be reached, so a restart during an outage comes up —
but a refusal from the cloud itself (a kick-out, a key identity a new exchange did not
restore) raises there too.

**The session-replaced latch survives a failed take-over.** `async_login(force=True)` and
`async_reauthenticate(…, take_over=True)` release the latch only once their login
succeeds; one that fails (held off, rejected, a challenge, the network) leaves it set, so
nothing signs in by itself afterwards. An on-demand station whose device session key
must be fetched while the latch is set fails its connect at once with
`SessionReplacedError`, instead of after a LAN search a sleeping camera never answers.

For tests, `FakeCloud(call_errors=[…])` makes the next non-login requests raise, in
order, as the library's own answer classification would: `SessionReplacedError()` for a
kick-out, `FakeCloud.refusal(463, 4404)` for the gateway's lapsed-key answer (the
library re-keys once, so two in a row make a call fail with `KeyExchangeRefusedError`).
The fake also answers device-session-key requests (`dsk_keys`, else a synthetic key).

**The 24-hour lockout is the sharp edge.** The eufy cloud locks an account for a day
after a handful of failed logins. The cache exists so a normal restart performs **no**
login and **no** device fetch at all — keep it that way: never call
`async_login(force=True)` on a timer, and let `RateLimitedError` stop retries.
The library itself re-logs in at most once per call, and only when the server says
the session expired or wants a re-key — never after a credential rejection, and never
after another client's login ended the session. Calls
made concurrently on a cold cache share a single login.

**Throttling is held off for the whole account, and survives a restart.** When the
cloud throttles (HTTP 429, a "too fast" or request-limit code, a login limit or lock),
the library stores a not-before time in the cache (`throttle`) and refuses every later call locally
until it passes: requests sent during a block reportedly restart it. A request throttle
stops every cloud call (each station's credential refresh, the push listener's token
upload, device refreshes — which fall back to the cached list); a login throttle stops
only logins, so a still-valid session keeps working. On top of that the library allows
at most 3 login attempts in a rolling 6 h. Every refusal is a `RateLimitedError` with
`retry_after`, so the coordinator needs no timers of its own. Its `origin` says who
refused: `"cloud"` (eufy answered a throttle code now), `"hold_off"` (refused locally
because eufy throttled earlier), `"budget"` (the library's own 3-per-6-h login budget;
eufy was not asked) or `"cooldown"` (`RefreshCooldownError`). A refused login carries its
`scope` (`"eu"`, `"eu:FR"`): a budget refusal for an extra country's scope means only the
devices listed under that country wait, so the repair can name the country instead of
"eufy is refusing sign-ins". `scope` is None when the refusal covers every call or every
scope. `cloud_status().regions[scope].next_login_allowed_in` tells, without a login
attempt, whether a scope may log in now. Local control is
unaffected: the P2P sessions need no cloud once the station identities and cipher keys
are cached.

## Several accounts, and stations shared between them

### One eufy account per consumer

A login from another client ends the session of whoever was already logged in with
the same account. The eufy app, the CLI, another add-on and Home Assistant would log
each other out. The library does not log in again by itself when that happens, because
two consumers doing so would take turns until the account locks: every cloud call
raises `SessionReplacedError`, restarts included (`EufySecurity.session_replaced`), until
the user decides and the integration calls `async_login(force=True)`.

Give Home Assistant its own eufy account and share the HomeBase to it from the owner's
app with **admin** rights: a guest share cannot arm or change settings. Devices added
later have to be shared again. A throttle or a lock then hits only the integration's
account, and the phone app keeps working. The library handles a shared member itself:
commands carry the owner's id, which it fetches and caches per station.

### A station that several accounts can see

Home Assistant may hold entries for the owner's account and for a shared account, or
for two shared accounts. The same HomeBase is then in both device lists. Serving it
from both would open two P2P sessions to one base: the base limits sessions, and
live media is the first thing to stall. It would also deliver every event twice and
register the same ids twice.

Pass the same `StationClaims` to every `EufySecurity` (see `station_claims` above), and
likewise one `InstallState` (kept in `hass.data` the same way,
`EufySecurity(..., install=install_state(hass))`). When the cloud throttles requests for
one account, every account sharing the `InstallState` holds off too, since the limit may
be per host; a login hold-off stays with its own account.
`async_discover()` then builds each station in exactly one account:

- the **owner's account** wins; between shared accounts, the first to discover it;
- the other accounts get no `Station` for it and list it in
  `eufy.stations_served_elsewhere`: log it, or raise a non-fixable repair issue
  ("HomeBase X is provided by another eufy account");
- when an account loses a station to the owner, or a station it was waiting for is
  released (that account's entry unloaded), `StationClaims` calls
  `on_change(account)`. Reload that entry. The account is the normalised e-mail, which
  is why the entry's `unique_id` must be exactly that. An account keeps its sessions
  until it is reloaded.

Create devices and entities only for `eufy.stations` and their `sub_devices`, never for
`stations_served_elsewhere`.

### Device and entity ids

Since Home Assistant Core 2026.8, a device belongs to exactly one config entry and its
identifiers are unique only within that entry. Entity unique ids stay unique across
the whole integration. The claim above makes sure only one entry registers a
station's serials, so the ids below never collide between accounts:

| registry item | value |
|---|---|
| device `identifiers` | `{(DOMAIN, serial)}`: the station's serial, or the camera's or sensor's own serial |
| device parent | `via_device_id` = the station's device, from `device_registry.async_get_device_by_identifier((DOMAIN, station.serial), entry.entry_id)`; register the station first. `DeviceInfo["via_device"]` is deprecated since 2026.8 |
| device `manufacturer` | `"eufy"` |
| device `model` | `CloudDevice.model_name`: the catalogued display name (`"eufyCam 3 (S330)"`); `None` for a model the catalog does not know |
| device `model_id` | `CloudDevice.model_id`: the serial's 5-character prefix (`"T8160"`), set for uncatalogued models too |
| device `serial_number`, `sw_version` | `CloudDevice.device_sn`, `CloudDevice.main_sw_version` |
| entity `unique_id` | `entity_unique_id(serial, key)`: `key` is the setting's `Setting.key` for settings, or a fixed lower-case name for the rest (`"guard_mode"`, `"battery"`, `"camera"`) |

**A standalone device is one HA device.** A standalone camera (`station.is_standalone`,
from `CloudDevice.is_standalone`: a T8170) is its own station. The library files its
one parameter block twice, so it looks like any other station: `StationState` (guard
mode, `name`, `lan_ip`, `firmware`) **and** `StationState.devices[channel]`, a
`SubDeviceState` whose `serial` is the station's own (battery, signal, `online`,
settings). Register one device with `identifiers = {(DOMAIN, station.serial)}` and no
`via_device_id`, and put the entities of both views on it.

**Loop over `station.devices`, not `station.sub_devices`,** for every per-device entity
(battery, signal, `online`, firmware, detections, camera) and for the serials a
detection may name. `devices` is the paired devices plus, on a standalone station, the
station itself on its own channel; `sub_devices` stays empty there. On that one device
the station view already owns some keys, so skip the per-device descriptions whose key
the station has (`firmware`, `model`): `entity_unique_id(serial, key)` would collide.
Registering devices still iterates `sub_devices` (the station is registered on its own).
`station.channels`, `station.channel_for(station.serial)` and
`settings_for(station.serial)` include the device itself; `settings_for(None)` already
returns every setting of a standalone model, so do not add its serial as a second
settings target. Its `ParamChanged` events come
twice, on channel 255 and on its own channel: each entity listens to the channel of
the view it reads. A T8170 gets the settings of its model file (see [Settings per
model](#settings-per-model)); a standalone model without a file gets the read-only
listing at most (see [Models without a settings file](#models-without-a-settings-file)).

Build ids from the device's own serial, never from (station, channel). A camera moved
to another HomeBase keeps its serial, so its entities and history survive; its channel
and station change. `entity_unique_id` rejects anything that could make two different
(serial, key) pairs produce the same id.

## The password

Pass a password only where the user types one: the config flow, reauth and
reconfigure. After a successful login the library caches it with the session and uses
it for every later login (an expired session, a cache layout change), so
`async_setup_entry` passes `None` and `entry.data` holds only the e-mail.

- **Precedence:** a password passed in, then the cached one, then a `PasswordSource`
  callable (`Callable[[], Awaitable[str]]`), which is awaited only when a login really
  happens and nothing is cached.
- **A rejected password is not tried again.** If the cloud rejects the cached password,
  the library drops it and raises `AuthenticationError`: raise
  `ConfigEntryAuthFailed`, and the reauth flow passes the new one to
  `async_reauthenticate`. With no password
  given and none cached, a login raises `AuthenticationError` without contacting the
  cloud.
- The cached password lives in the private store, with the same protection as Home
  Assistant's own config entries. Redact it from diagnostics.

## Diagnostics

`diagnostics.py` builds on the library's redacted views and never reads the store:

```python
async def async_get_config_entry_diagnostics(hass, entry):
    eufy = entry.runtime_data
    stations = {
        redact_serial(s.serial): {
            "model": s.device.device_type,
            "connected": s.connected,
            "last_error": type(s.last_error).__name__ if s.last_error else None,
            "lan_path_warnings": [w.value for w in s.lan_path.warnings],
            "local_events": s.local_events.support.value,
            "sub_devices": [d.as_redacted_dict() for d in s.sub_devices],
            "cloud_params": list(s.state.cloud_param_ids) if s.state else None,
        }
        for s in eufy.stations.values()
    }
    return async_redact_data(
        {
            "cache": await eufy.async_cache_summary(),  # never contacts the cloud
            "stations": stations,
            "served_elsewhere": [d.as_redacted_dict() for d in eufy.stations_served_elsewhere],
        },
        TO_REDACT,  # names, anything HA adds
    )
```

- `async_cache_summary()` reports which cache sections and secrets are present (never
  their values), the `CloudStatus` (login need, hold-offs, login budget) and, per
  station, whether the owner id is cached, `cipher_id` (the cipher the station uses),
  `cipher_id_named` (whether the station named it in a handshake; false means `cipher_id`
  is the default 40 and no handshake has completed), `cipher_cached` (whether its key
  is), and the key-refresh latch state.
- `CloudDevice.as_redacted_dict()` gives a device without its DID, IP or owner id (only
  whether each is present) and with redacted serials.
- `StationState.cloud_param_ids` names the station parameters read from the cloud's copy
  (ids only: their values can hold mode names and schedules).
- Put any other serial through `redact_serial` (exported from the package root).
- A non-empty `unclassified_sections` in the summary means the library is newer than the
  integration; it lists names only and is safe to show.
- Add `eufy.skipped_devices` (`SkippedDevice(device_sn_redacted, reason)`: `bad_serial`,
  `bad_did`, `webrtc_only`, `no_did`, `orphan`). A `bad_serial`, `bad_did`,
  `webrtc_only` or `orphan` deserves a non-fixable repair issue; `bad_did` is a station
  whose P2P id local P2P does not accept (the eufy app does not connect to it either),
  and its paired devices are listed as `orphan`; `webrtc_only` is a station the eufy app
  reaches only over its WebRTC path, whatever is paired to it (its thing description says
  so: the HomeBase Professional S1 T9000, the NVR T8N00, the T7000 and the T8040), which
  the library does not speak, and every device paired to it;
  `no_did` is a device the library does not serve (a robot vacuum on the same account).
- Add per station `dataclasses.asdict(station.stats())` (`SessionStats`): it carries no
  identifiers and needs no redaction. For "live view shows no picture", look at
  `media_video_codecs`, `media_codec_overrides`, `media_first_records`,
  `media_rejected_keyframe` and `media_failures_by_channel` (which camera channel's
  opens failed, by error class); for "the picture freezes", at
  `media_frames_skipped_for_keyframe` against `media_frames_dropped_for_reader`
  (see `docs/protocol/media.md`). For "events stopped", compare
  `seconds_since_last_event` with `seconds_since_last_probe` and look at
  `state_frames_by_encryption`, `dropped_undecodable` and `wrong_port_drops`; for a flapping
  station, `reconnects`, `handshake_failures`, `key_refreshes` and `last_error` (a class
  name, kept after recovery). Add `eufy.push_running` and the deduplicator's counters.

## Testing the integration

Test against the real library, not a mock of it: `eufy_home_security.testing` ships in the
wheel (see [testing.md](testing.md)). It wires a real `EufySecurity` — real cache,
throttle, claims and inclusion — to a `FakeCloud` and loopback `FakeStation`s, so a test
can prove what a boundary mock cannot:

- **A warm restart makes no cloud call:** build with `warm_store(...)` and assert
  `cloud.calls == []` after `async_login()`, `async_discover()` and `async_start()`.
- **A first setup:** start from `MemoryStore()` instead.
- **Repair flows:** set `cloud.login_error = LoginLimitedError(retry_after=…)`; the
  hold-off is recorded, so `async_cloud_status()` agrees with the error.
- **Unreachable stations:** a stopped `FakeStation` makes `async_start()` return its error.
  Lower `DISCOVERY_ATTEMPTS` / `DISCOVERY_TIMEOUT` in `eufy_home_security.p2p.session`
  first, or the test waits the production timeouts.
- **Events:** `fake.push_camera_event(cipher=…)` reaches `eufy.subscribe`, GCM or ECB.
- **Modes and schedule:** `fake.set_mode_list({GuardMode.CUSTOM_1: "Night watch"})` and
  `fake.set_schedule([ScheduleSlot(...)], default=...)` seed what `StationConfig` reads;
  `mode_list_params` / `schedule_params` give the same values for the cloud's copy
  (`FakeCloud.set_station_params`). See [testing.md](testing.md#controlling-the-fakes).
- **A standalone battery camera:** a device-list entry whose `parent_sn` is its own serial
  (build it as `"T8170" + SYNTHETIC.station_sn[5:]`), `device_type` 48, `device_channel` 0,
  a `p2p_did`, and a `params` list (`param_type`, `param_value`, `update_time`) for its
  cloud state; and `FakeStation(serial=…, cipher_id=98,
  receipt_len=p2p.messages.STANDALONE_RECEIPT_LEN, params={48: {…}})`. It is reached on
  demand: `async_start()` never connects it (`fake.conn_inits == 0`), its state comes
  from the entry's `params`, and `station.async_update(wake=True)` reads the fake.
- Push (FCM) is not faked: start with `async_start(push=False)`.

Use only the synthetic identities in `testing.SYNTHETIC`, never a real serial.

## Manifest

List the library's loggers so users can turn on debug from the UI. The opt-in push
stack logs under `firebase_messaging`, outside the library's own tree:

```json
"loggers": ["eufy_home_security", "firebase_messaging"]
```

Wire-level hexdumps stay off even at DEBUG; enable them explicitly with
`set_wire_logging(True)` only when chasing a protocol issue.
