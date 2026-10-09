# Debug logging

## Logger tree

Loggers follow the module path, so one subsystem can be turned up on its own:

| Logger | What it covers |
|---|---|
| `eufy_home_security` | everything |
| `eufy_home_security.cloud.api` | every HTTP call (URL, headers, body, status, API code, ms, response); the login flow step by step (cached session, password source, key exchanges, challenges, token), owner id and cipher keys, push-token upload, local hold-offs |
| `eufy_home_security.storage` | session cache loaded / saved (sections, never values), version or account changes |
| `eufy_home_security.client` | the P2P credentials handed to each station |
| `eufy_home_security.identity` | which account serves a station shared between accounts |
| `eufy_home_security.p2p.discovery` | LAN probe searches and who answered |
| `eufy_home_security.p2p.transport` | bind, LAN_SEARCH / PUNCH_PKT / P2P_RDY, every DRW chunk and ack, retransmits, keepalive (sampled), CLOSE, link down |
| `eufy_home_security.p2p.xzyh` | duplicate and out-of-order chunks (sampled) |
| `eufy_home_security.p2p.broadcast` | a shared live stream's subscribers falling behind, resolution changes, resize grace |
| `eufy_home_security.p2p.session` | handshake steps and keys, every request (label, resends, reply time), command-lock waits, parameter changes, guard mode, camera pushes and their record binding, still fetches, trigger frames, media streams (see [Tracing a detection](#tracing-a-detection)) |
| `eufy_home_security.devices.td` | thing-description properties skipped or units dropped while reading a cloud TD |
| `eufy_home_security.station` | event thumbnail source and history lookup outcome |
| `eufy_home_security.events` | de-duplication drops and enrichments, stale guard and alarm pushes |
| `eufy_home_security.push.fcm` | GCM checkin, Firebase install, GCM register, the MCS socket (connect, login, heartbeats, acks, resets), every push received and every drop decision |
| `eufy_home_security.wire.p2p` / `.wire.cloud` | hexdumps of every datagram; the full decoded P2P JSON of every command sent and notification received; raw cloud request and response bodies (identifiers masked like everywhere else, see [Redaction](#redaction)) |
| `eufy_home_security.secrets` | a switch, not a log source: see [Secrets](#secrets-the-full-auth-flow) |

At DEBUG the P2P loggers log every chunk of a parameter dump; raise
`eufy_home_security.p2p.transport` to INFO for a quieter log that still shows every
request and event.

```python
import logging

logging.basicConfig(level=logging.INFO)
logging.getLogger("eufy_home_security.p2p").setLevel(logging.DEBUG)
```

## Wire dumps

The `wire` loggers are held at WARNING even when the package is at DEBUG — a
parameter dump alone is hundreds of lines. Turn them on explicitly:

```python
from eufy_home_security import set_wire_logging

set_wire_logging(True)
```

The CLI does the same with `--wire`.

## Redaction

By default no log line, wire dumps included, carries a secret or an identifier:

| what | shown as |
|---|---|
| the account password, e-mailed verification codes, captcha answers, the password's ECDH wrap | `***` (no tail, no length) |
| tokens, keys, ECDH secrets | `***cdef` |
| serials | `T8030***2345` (model prefix and last four) |
| account and user ids, user names and nicknames, e-mail addresses, device, station and house names, a house's address and coordinates, DIDs, MAC addresses, house ids, the disk serial and label, `openudid`, the FCM `android_id` and message ids, the cloud session's `key_ident`, media paths | `***` plus the last four characters, or only stars for a short value |
| public IP addresses | `***` plus the last four characters |
| private, loopback and link-local IP addresses, host names | in full: they show which network path was taken |

The rules:

- A logged JSON body (a cloud request or response, a P2P command or notification, a
  push) is masked by key: `SENSITIVE_KEY_PARTS` for secrets and `IDENTIFYING_KEYS`
  for identifiers (`_logging.py`), with case, `_` and `-` ignored. A string that holds
  a JSON object is decoded and masked the same way. Any serial, 40-hex account id or
  e-mail address or station media path (`/zx/…`) left inside a string is redacted too.
- The device, house and invitation lists (`get_devs_list`, `get_house_list`,
  `get_house_invite_records`, `get_invites`) are logged as entry counts
  (`<3 house_infos>`); the full answer goes to the wire logger only.
- A hexdump stars out serials, DIDs (struct and text form) and 40-hex account ids in
  place, so its offsets stay valid. The rest is encrypted traffic or protocol bytes.
- Parameter values that identify the house (device and station names, the paired
  serial list, the LAN address) are redacted in the parameter lines (below).
- Exception messages carry no serial, DID, record id or path.

Everything above is logged in full only with the secrets switch
([Secrets](#secrets-the-full-auth-flow)). The CLI's own output (tables, status,
events) is not a log: it shows full serials; add `--redact-serials` before sharing it.

## Parameter lines

Every line that names a parameter or a command (a parameter change, a command sent,
its receipt and result, an ECB setting write, an alarm frame, a failed read-back) says
what the id means after a ` / `:

```
T8030***2345: param ch0/1167: '0' → '30' / alarm_delay_away (Alarm (entry) delay after this device triggers, Away mode): 0 s → 30 s
T8030***2345: param ch0/1239: '143' → '9' / camera_action_away (What this camera does when it triggers in Away mode): -camera_siren -light_alarm -station_alarm (143 → 9)
T8030***2345: param ch255/1224: '1' → '0' / guard_mode (selected guard mode): home → away
T8030***2345: param ch0/1101: '87' → '86' / battery (battery level): 87 % → 86 %
T8030***2345: param ch0/1217: '*****' → '****' / device_name (device name): ***** → ****
T8030***2345: param ch1/1309: '5' → '6' / solar_intensity (solar input): 5 → 6
T8030***2345: param ch1/1201: '5' → '6' / SET_TONE_FILE? (the app's name, meaning unknown)
T8030***2345: param ch1/4242: '5' → '6' / unknown
T8030***2345: cmd 1210 ch0 value3=0 / SET_PIRSENSITIVITY? (the app's name, meaning unknown)
```

The description comes from, in order:

1. The per-mode settings of the station's mode tables: the key, the first clause of its
   description, flag changes as `+added -removed`, and the unit. When the channel's
   device kind is not known yet, every setting that fits a sub-device is listed, joined
   by `|`.
2. The parameters the library reads into device state (battery, signal, online
   status, guard modes, firmware, names, storage use and status, last PIR event,
   charging source, solar input, battery temperature, the power-manager counters,
   per-mode siren actions, a sensor's low-battery flag and PIR sensitivity).
3. The app's name for the id, marked `?`: a lead from the app, not an established
   meaning.
4. `unknown`.

`eufy_home_security.devices.param_info.param_info(param_id, channel, scope)` gives
the same description to a consumer.

## Tracing a detection

At DEBUG the library logs one line per decision on the way from a camera push to an
image, with no serial (only `T8160***7890`), media path, record id, unique id or name:
the full payloads are on the wire logger only. In order:

| line | logger | what it says |
|---|---|---|
| `camera push 18:3102 under gcm from T8160***7890 ch0` | `p2p.session` | `msg_type:event_type`, the frame cipher (`gcm` authenticated, `ecb` forgeable on the LAN), device, channel, `push_count` when present |
| `push binding: record_id present, attached 1 record(s) / 1 crop(s); bound thumb False, video True, crop False; rejected none` | `p2p.session` | whether the push's attached records were its own (usually not on fw 3.8.7.4), and which fields failed validation (names only) |
| `dropping a p2p copy of 18:3102 from T8160***7890: duplicate, seen 1.2s ago` / `admitting a cloud copy as an enrichment` | `events` | the de-duplication decision (`duplicate`, or `repeat` for `push_count > 1`) |
| `event thumbnail: history record found in 0.41s` | `station` | the history lookup: `found`, `none`, `another camera's`, `no thumbnail yet`; or `from the push's bound path` |
| `image fetch sent` / `image fetch bound: jpeg, 34012 bytes in 0.38s` / `image fetch: no reply within 12s` / `discarded a late image reply, 13.1s after its request` | `p2p.session` | the 1308 still fetch |
| `trigger frame on channel 1: short-lived session open in 0.62s` / `… closed after 1.40s, 221961 bytes` | `p2p.session` | the trigger frame's second session |
| `guard mode write waited 2.95s for the command lock` | `p2p.session` | a wait of 50 ms or more behind another request (label: `image fetch`, `history query`, `parameter read`, `guard mode write`, `command`, `media open` …) |
| `opening live media (cmd 1003) on channel 0` / `media (cmd 1003 ch0) closed after 4.2s` | `p2p.session` | live and recording streams (never one line per frame) |

`RecordNotFoundError` messages name the outcome, never the record id, so a consumer can
log them as they are.

## Secrets: the full auth flow

To follow a login or a session handshake byte for byte — the password sent, the
auth token, ECDH public keys and shared secret, cipher keys, P2P session keys, FCM
credentials — turn on the `eufy_home_security.secrets` switch. Every value that is
otherwise redacted, identifiers included, is then logged in clear, in the same debug
lines:

```python
from eufy_home_security import set_secret_logging

set_secret_logging(True)
```

The CLI does the same with `--secrets` (combine with `-vv`). In Home Assistant:

```yaml
logger:
  logs:
    eufy_home_security: debug
    eufy_home_security.secrets: debug
```

Like the wire loggers, the switch is independent of the package level, so
*Enable debug logging* never exposes the account. A log taken with it on gives
full access to the account and the station: never share it.

## Home Assistant

The integration's `manifest.json` lists the package:

```json
"loggers": ["eufy_home_security"]
```

so *Enable debug logging* on the integration page raises the whole tree to DEBUG
(wire dumps stay off). For a narrower view use `configuration.yaml`:

```yaml
logger:
  logs:
    eufy_home_security.p2p.session: debug
```

## Reading the signals

- `no LAN discovery reply` once after a reconnect is normal: the station ignores
  the first search after a session closes, and discovery retries.
- `acknowledged … but never acted on it` means the station dropped a command —
  almost always an `account_id` that is not the station owner's.
- `replied under GCM, not ECB` means a firmware moved a setting to the
  payload-object path; the model's settings file needs regenerating
  ([regenerate-models.md](regenerate-models.md)).
- `parameter probe unanswered in Ns; re-establishing` is the liveness check doing its
  job: the link was up but the encrypted session was not.
