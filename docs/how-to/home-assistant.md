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
it logs in as before (`ab` = the region). A cached session made with another `ab` (every
session from before this, or after the HA country changes) logs in again once per
region, inside the login budget; when that login is refused, the old session stays in
use and is not asked again for the same country. See
[cloud.md § Login country](../protocol/cloud.md#login-country).

**The country is the user's choice.** eufy lists a device only to a login with the
country it is held under: an account whose own devices sit under `EE` and that accepted
a home shared from an account in `CH` sees the shared devices only with `CH`, as the
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
| `cloud.challenges` | the `login_id` of each login scope's unanswered login challenge (no code, no captcha answer) | when a login raises a challenge; cleared by that scope's next successful login |
| `cloud.listed.<region>` | how many devices the region's last device list held, and when | on every device-list fetch that asked the region |
| `replaced` | when another client's login ended the session | set by a kick-out; blocks every non-forced login until `async_login(force=True)` or `async_reauthenticate(…, take_over=True)` |
| `stations.<serial>` | the owner's account id, the ECC private key of each cipher fetched for it (`ciphers`), `cipher_id` (the cipher the station names in its handshake: 40 on a HomeBase 3, 98 on a T8170), and the key-refresh latch | on a P2P handshake failure: one fetch, then latched until a handshake succeeds, the latch is reset, or 24 h pass |
| `devices` | the `get_devs_list` entries, each reduced to the fields `CloudDevice` reads (serials, type, name, channel, DID, IP, firmware versions, `app_conn`, the product code `device_new_pn`, the member's `admin_user_id` and `member_type`, and `cloud_region`, the region that listed it); the cloud's `params` snapshot only for a device reached on demand. The member's e-mail and phone, MAC addresses and the rest never reach the store | only on `async_discover(refresh=True)`; an entry stored with more fields is reduced on load |
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
become the region it was logged in to, so the upgrade costs no login. A version-1 cache
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
- **Login challenge:** carry `login_id` (and `captcha_id`) between flow steps, and close
  the instance before the step shows the form. The next step builds a new instance on
  the same store; it reloads the document and answers with that `login_id`, and the
  answer goes to the login scope that asked (the store keeps it). With extra countries
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
- A refresh that cannot reach the cloud, or runs into a hold-off, returns the cached list.
- A refresh adds new stations and updates the paired devices of the stations already
  built. When a station's devices change it emits `DevicesChanged(station_sn, added,
  removed, moved)` (serials): reload the entry on it, and never diff device lists in the
  integration. A refresh that changed nothing emits nothing.
- A device paired after the last device-list refresh may still get an identity from
  the station's own serial list: its `SubDeviceState.serial_source` is `"param_1072"`
  instead of `"cloud"`. Use that serial for its entities (ids come from serials), but
  expect a `DevicesChanged` once a refresh brings its cloud entry. A channel whose
  identity is ambiguous gets `serial=None`: build no entities for it.

### Cloud regions

The eufy cloud runs two clusters, `eu` and `us` (the app's production environments). A
login on either succeeds for any account and answers the same user id, but a login lists
only the devices its cluster holds for the login's country: the other cluster, or
another country, answers an empty list, not an error. So the library logs in once per
country, on that country's home cluster (eufy's `estimate_domain`), and remembers, per
device, the *login scope* that listed it: the region (`eu`) for the login country,
`<region>:<country>` (`eu:CH`) for each extra country of `country=[…]`:

- A cold cache costs one login per country. The login budget (3 per 6 h) and a
  login-count throttle (100028) are kept per cluster, so two countries homed on `eu`
  share its budget; a credential lock (too many wrong passwords) holds off every
  cluster. `async_login()` on a cold cache logs in to every scope the next device list
  asks, so a login challenge surfaces there; its `LoginChallengeError.region` names the
  scope, and the answer (`async_login(verify_code=…, login_id=…)`) goes back to it, on
  this instance or a new one on the same store.
- While no country is known (no `country`, and eufy names no IP country), both regions
  log in with the region as `ab`, as before.
- A scope that lists no devices is **suspended**: no later device list, login or push
  registration asks it. It is asked again only when the user says so:
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
| per-region state | `(await eufy.async_cloud_status()).regions[<region>]`: `devices` (None = never listed), `suspended`, `in_use`, `login_refused` (an extra country the cloud refused to log in: skipped until a rescan), `logins_in_window` (its cluster's logins in the budget window; the account-wide `CloudStatus.logins_in_window` is the fullest cluster's), `listed_age`, `session_expires_in`, `country_code` | diagnostics; a repair issue when every region is suspended ("the account lists no devices in any eufy region") with a *rescan* fix |
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
  account-wide house device list the library serves (`house`), the house list
  (`houses`), the pending invitations (`invites`), and the security realm's station and
  device lists (`security_stations`, `security_devices`). `houses`: per house, its own
  device count and this account's role.
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
reply arrived.

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
| detections and other events | yes (station and push) | yes (push) |

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
    `await eufy.async_refresh_cloud_state()` fetches on request (a "refresh" button).
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
frame under it (ECB) is forgeable. The library already refuses guard-mode reports,
parameter dumps and alarm frames under that key once a session is up, so
`GuardModeChanged`, `AlarmChanged`, `ParamChanged` and `StationState` need no check.
`SecurityEvent` still delivers every camera push and says where it came from:

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
- An event with `enriches=True` is the same occurrence arriving again with media paths
  the first copy lacked (typically the local copy after the cloud one): update that
  occurrence's snapshot, do not count a new detection.
- A standalone T8170 sends two cloud pushes per detection, the second (`push_count` 2)
  with its own `unique_id` and the recording path in `file_path`, at the first one's
  `trigger_time`. The library matches them by device, event time (ms) and event type:
  the second arrives as an enrichment when its `video_path` is new, else it is dropped
  as a repeat. One detection, one event.
- Station pushes (arming, alarm) are never merged away; a stale guard-mode push is
  dropped (see live guard mode above).
- For diagnostics, `eufy.deduplicator.dropped_duplicates` and `dropped_repeats`.
- For diagnostics, count events by `frame_cipher`, alongside the session's
  `ecb_state_refused`.
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
| `key_unusable` | entities unavailable. The cipher key cannot be used at all (`CipherUnusableError`; `error.reason`: `rsa_unparsable`/`not_rsa`, or `no_rsa_key`/`no_ecc_key` when the cloud serves no key for the station's handshake) — usually a device on outdated firmware that uses the legacy RSA handshake, whose cloud key eufy serves corrupted or not at all. No re-fetch helps. Raise a repair telling the user to **update the device's firmware** in the eufy app; do not call it a rejected key or suggest a reset. |
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
  length over P2P. A cloud-only station gets no end when the alarm times out: expect it
  to stay triggered until a stop or disarm, or end it on a timer of your own. `DELAY`
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
  `watermark_set`), sorted as the app lays them out (group, page, order, key); for a
  paired camera or sensor the per-mode delays and actions follow (see **Per-mode
  actions** below). `station.setting(key, device_sn=…)` (or `channel=…`) returns one
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
    bool for a bool, str for a string. `default` is the vendor default, for display only.
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
  type above), or None when the dump does not carry it or the setting is not readable.
  Show None as unknown; never substitute a default. `setting()` raises
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
  settles it. On a standalone camera (a T8170) address a setting with
  `device_sn=station.serial` (or no target): the library renders it for the camera's
  own channel.

  **Per-mode actions** — "sound the siren in Away", "notify in Home" — are bits of a
  per-mode action mask: each camera has `camera_action_away`, `camera_action_home` and
  `camera_action_custom_1`…`_3`, each motion sensor `sensor_action_<mode>`, and
  `MODE_ACTION_FLAGS[scope]` names the bits that apply to that kind (camera: `record`,
  `camera_siren`, `station_alarm`, `notification`, `light_alarm`,
  `report_monitor_center`; sensor: `notification`, `station_alarm`,
  `motion_sensor_respond`, `report_monitor_center`). One switch per (mode, flag), for
  example "Front · Away · camera siren", written with
  `station.async_set_mode_action("away", "camera_siren", on, device_sn=…)`: it reads the
  current mask fresh, changes that one bit, writes and confirms by read-back. **Never
  write a whole mask from Home Assistant state**: the bits without a name are mode bits,
  and a raw write clears them. The alarm and leaving delays (`alarm_delay_<mode>`,
  `leaving_delay_<mode>`, `RANGE` in seconds) are `number` entities on every camera and
  sensor, written with `async_set_setting`. These settings are not in the model files:
  the library writes them through the station's mode tables. The table write is proven
  on hardware; the flag names come from the app.

  What to know before offering them:
  - Each write replaces the mode's whole table on the station (`SET_ALL_ACTION`): the
    library reads every device's current values fresh and writes them back unchanged,
    so a write is slower than other settings (a dump, the write, a read-back of every
    device) and two writes should not race.
  - **A delay is one value per mode.** Setting a device's Away alarm delay to 30 also
    sets it to 30 on every device whose Away alarm delay is on; setting it to 0 turns
    off only that device. Refresh every delay entity after a write, and say so in the
    entity's description.
  - The write is refused (`UnsupportedError`, nothing sent) when the station has a
    paired device of no known kind (it may be a siren accessory whose triggers the
    table would clear), or when devices hold different values for a delay the table
    must carry unchanged; surface the message instead of retrying.
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
    *declared* from the vendor handlers, values live-read only):
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
| T8030 | 75 | 13 | 62 |
| T8160 | 103 | 31 | 72 |
| T8170 | 146 | 39 | 107 |
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
  (`Capability`, `Support`, `profile_for_serial`) and `MODE_ACTION_FLAGS` from
  `eufy_home_security.devices`.

`setting.name` is the eufy app's own title where the app has one (`Clip length`,
`Intervals between triggers`, `Working Mode` on a T8160), else a title made from the key.
`setting.unit` is the TD's unit, or the unit the app's control shows (seconds for
`video_clip_length` and `trigger_interval_time` on the custom-recording page); use it as
the entity's unit of measurement. `setting.variant_of` is the key of the setting the app
uses in this one's place on the same model (`record_resolution__v1` →
`record_resolution`, `nightvision_type` → `nightvision_type_new`), else `None`: register
a variant disabled by default instead of matching key suffixes. A variant identical to its
primary in codec, domain, labels and control is not in the file at all
(`detection_sensitivity_test_mode`): an entity registered under such a key has no
setting; remove it.

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

### Models without a settings file

The bundled files cover 107 product codes. For any other code of the account,
`async_discover()` asks the cloud for its thing description, once on the first discovery
and again on every `async_discover(refresh=True)`, in the same request as every other
code. The request uses the cached cloud session and never logs in: without one, the
code stays unlisted until a later refresh. A failure is logged once and never fails
discovery.

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

### Camera images

A camera has three image sources, described as data in `IMAGE_SOURCES`
(`ImageSourceInfo`: `high_resolution`, `content_type`, `wakes_camera`,
`needs_recording`, `typical_seconds`, `support`). Build the option labels and
descriptions from it rather than restating them.

| `ImageSource` | what | size | camera | typical |
|---|---|---|---|---|
| `THUMBNAIL` | the still the station stored with the event (`image/jpeg`) | 640×360 | stays asleep | about 0.4 s |
| `TRIGGER_FRAME` | the first keyframe of the event's recording (`video/hevc`) | the recording's resolution: 3840×2160 on a T8160 | stays asleep | about 1–1.5 s, plus the decode |
| `LIVE` | a keyframe of the live stream now (`video/hevc`) | 3840×2160 on a T8160 | **wakes a battery camera** | a few seconds (the camera wakes first) |

Two calls, each returning a `CameraImage(source, device_sn, data, content_type,
record_id, recorded_at, preset, width, height)`, with `is_jpeg` and `high_resolution`
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

**Decoding HEVC to JPEG stays in the integration** (Home Assistant ships ffmpeg; the
library has no native dependencies). Pipe `data` into:

```
ffmpeg -hide_banner -loglevel error -f hevc -i pipe:0 -frames:v 1 [-vf scale=1920:-2] -q:v 2 -f image2 -c:v mjpeg pipe:1
```

Check that the output starts with `FF D8`, bound the run (about 20 s), and keep the
previous image on any failure. Never serve `video/hevc` as the camera image.

**Other rules:**
- **Offer what `station.image_sources(device_sn)` lists.** Behind a station it is all
  three; a standalone camera (T8170) lists no recordings, so it offers `THUMBNAIL`
  (its newest event still, through the event-count query) and `LIVE`, and
  `TRIGGER_FRAME` raises `UnsupportedError` at once. Its stills come in the V1
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
go2rtc (WebRTC) — and neither decodes video, so the camera's own HEVC travels to the
browser untouched.

**Nothing on the HA host decodes or re-encodes video, and that is not an optimisation.**
A typical HA host cannot do it: on an RK3328 board, decoding one 4K HEVC stream alone
measured **0.58× realtime** with all four cores saturated, while remuxing the same
stream costs about **2 % of one core**. Any design that decodes video on the host is
unusable on small hardware. Audio is passed through too; only WebRTC needs a transcode
(see *Audio*, below).

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
| `header` | tables plus the opening keyframe, sent to each new subscriber automatically |
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
| HLS, recording, snapshots | the `stream` component (demux/remux, no decode) | HEVC passthrough | AAC passthrough | 4–8 s |
| WebRTC | go2rtc, which dials `stream_source()` | HEVC (Chrome 136+, Safari 18+; **not** Firefox) | needs Opus | 0.1–0.3 s |

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
- **Parameter sets** are re-emitted at every keyframe, so a viewer joining mid-stream
  decodes at once rather than waiting.
- **Slow readers.** A subscriber that cannot keep up has its backlog dropped and resumes
  at a keyframe. It never stalls the camera — the station stops sending when its frames
  are not read, which would end the stream for everyone.
- **The codec is read per stream**, not assumed: a camera that sends H.264 is declared
  as H.264.

### Recordings and clips

Two producers of video files, one shape: an MPEG-TS clip (`video/mp2t`, the camera's
HEVC and AAC untouched, starting at a keyframe) written through the integration's own
`write` coroutine, returned with a `MediaClip` that says what was written.

| | call | camera | typical (T8160, 3840×2160) |
|---|---|---|---|
| a stored recording | `station.async_download_recording(record, write)` | stays asleep (off the station's disk) | 6–11 s clips in 4.9–6.6 s |
| the live stream now | `broadcast.async_capture(seconds, write)` | **wakes a battery camera**, shared with live viewers | `seconds` plus the camera's start, about 2.5 s cold |

`MediaClip`: `video_frames`, `audio_frames`, `keyframes`, `bytes_written`,
`duration_s` (by the camera's clock), `width`/`height` (the last frame's), `resizes`,
`started_at` (aware), `device_sn`, `record_id` (downloads), `expected_frames` (the
record's `frame_num`), `ended_early` (a capture whose stream ended first), `complete`,
`content_type`.

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

`StreamBroadcast.async_capture(seconds, write, *, start_timeout=30)` taps the broadcast
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

#### Storing them

Remuxing to MP4 is a stream copy with Home Assistant's ffmpeg (no decode; `hvc1` makes
the HEVC playable in Safari and in HA's media browser):

```
ffmpeg -hide_banner -loglevel error -y -i clip.ts -map 0 -c copy -tag:v hvc1 -movflags +faststart -f mp4 clip.mp4
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
published firmware, not that the check failed.

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

A pan/tilt camera (the T8170 Battery SoloCam: profile capability `PTZ_PRESETS`) has
preset slots, each a stored direction and zoom. The library reads them, turns the
camera to one, and takes that view's live image, so the integration can offer one
"capture" per preset without knowing any command.

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
| created when | `profile_for_serial(device_sn).support(Capability.PTZ_PRESETS) is not Support.UNKNOWN` |
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
"Save view" **button** per pan/tilt camera (next to the four pan buttons) calling
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

**Errors** (catch `DeviceBusyError` before `CommunicationError` and
`PresetSlotsFullError` before `CommandNotAppliedError`, their base classes):

| error | when | HA |
|---|---|---|
| `PresetSlotsFullError` (`slots`, `in_use`) | 5 slots are stored and `preset` is not one of them; nothing was sent when the cached read already showed it | `HomeAssistantError("all 5 preset slots are in use; delete a preset first")` |
| `CommandNotAppliedError`, otherwise | the camera took the write but the read-back shows no store; with `err.command == 6242`, the store took but the slot did not become the default | `HomeAssistantError` |
| `UnsupportedError` | a model without pan/tilt presets, or `preset` outside the camera's range (0–9); nothing sent | `ServiceValidationError` |
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

## Errors map to HA control flow

The library raises typed errors; translate them at the coordinator / setup boundary:

| library error | HA response |
|---|---|
| `LoginChallengeError`, `AuthenticationError` | `raise ConfigEntryAuthFailed` — start the reauth flow. Answer a challenge with `async_login(verify_code=…, login_id=challenge.login_id)` (or `captcha_id`/`captcha_answer`). A `verify_code` challenge (`kind`) is also how an account with two-step verification answers a correct password; `code_requested` says the library has asked eufy to e-mail the code. `SessionRejectedError` (an `AuthenticationError`): the cloud refused the session again after one fresh login |
| `SessionReplacedError` | not a reauth: another app or integration logged in with this account and the cloud ended the library's session. Raise a repair issue ("give Home Assistant its own eufy account, shared from the owner"). At setup, carry on from the cache: `async_discover()` and `async_start()` need no login when the cache is warm, so local control keeps working. `raise ConfigEntryNotReady` only if `async_discover()` fails too (a cold cache). Nothing logs in again by itself, restarts included (`EufySecurity.session_replaced`); when the user confirms in the repair flow, call `async_login(force=True)` and reload the entry |
| `LoginLimitedError` (a `RateLimitedError`) | not a reauth: the credentials are fine. Raise a repair issue ("eufy is refusing logins, retrying in …") and carry on from the cache as above; `raise ConfigEntryNotReady` only on a cold cache. Clear the issue on the next successful login |
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
| `KeyExchangeRefusedError` (a `CloudApiError`; `code` 4404 or 463, `status` 463) | the cloud gateway refused the client's key identity and a new key exchange did not restore it. Not a reauth and not a kick-out: no login was attempted and none helps by itself. Carry on from the cache and retry on the next interval; the library re-keys at each attempt. Raise a repair issue only if it persists (hours) |

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
`retry_after`, so the coordinator needs no timers of its own. Local control is
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
            "sub_devices": [d.as_redacted_dict() for d in s.sub_devices],
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
- Put any other serial through `redact_serial` (exported from the package root).
- A non-empty `unclassified_sections` in the summary means the library is newer than the
  integration; it lists names only and is safe to show.
- Add `eufy.skipped_devices` (`SkippedDevice(device_sn_redacted, reason)`: `bad_serial`,
  `no_did`, `orphan`). A `bad_serial` or `orphan` deserves a non-fixable repair issue;
  `no_did` is a device the library does not serve (a robot vacuum on the same account).
- Add per station `dataclasses.asdict(station.stats())` (`SessionStats`): it carries no
  identifiers and needs no redaction. For "events stopped", compare
  `seconds_since_last_event` with `seconds_since_last_probe` and look at
  `ecb_state_refused`, `dropped_undecodable` and `wrong_port_drops`; for a flapping
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
