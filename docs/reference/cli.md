# `eufy-security` command line

The CLI is a thin wrapper over the library — every command maps onto one or two
public calls — and doubles as the tool for verifying devices.

## Credentials and state

| | |
|---|---|
| account | `--email`, else `$EUFY_EMAIL`, else the account the session cache belongs to — so after one login neither is needed. |
| password | `$EUFY_PASSWORD`, else the password cached by the last successful login, else a prompt — shown only if a login actually happens. A cached password the cloud rejects is forgotten, so the next run asks. **Never a flag** (it would land in shell history and process lists). |
| session cache | `--store PATH`, default `$XDG_CONFIG_HOME/eufy-security/cache.json` (`~/.config/…`), mode 0600. Holds the cloud session, the account password, the install's `openudid`, the device list, and per station the owner's account id and cipher key — so only the first run logs in. |

Do not pass the password through `export $(...)` word-splitting: quotes added by
`shlex.quote` are kept literally, and every failed login counts toward the cloud's
lock-out. A tiny wrapper that sets `os.environ` and `execv`s the CLI is safer.

## Global options

| option | |
|---|---|
| `--station SN\|NAME` | which station; required when the account has several |
| `--host IP` | the station's LAN address, skipping the broadcast |
| `--local-port N` | pin the selected station's local UDP port so a firewall can admit its replies by destination port (the station's source port changes every session). One port per station: use a different one for each |
| `--country CC[,CC…]` | login country, ISO 3166 code; further comma-separated codes add extra countries (default: the host's IP country; see [cloud.md](../protocol/cloud.md#login-country)) |
| `--region eu\|us` | log the login country in on this cloud region (default: its home region; every region while no country is known; see [the guide](../how-to/home-assistant.md#cloud-regions)) |
| `--redact-serials` | mask serials in human output, e.g. before sharing it (full by default; log lines are always redacted) |
| `-v` / `-vv` | INFO / DEBUG on stderr |
| `--wire` | hexdumps of every datagram and cloud request (noisy; contains encrypted traffic) |
| `--secrets` | with `-vv`: passwords, tokens, cipher and session keys in clear — the full auth flow. Never share such a log |

## Commands

| command | does | needs |
|---|---|---|
| `discover [--broadcast IP] [--port N] [--timeout S]` | list stations answering a LAN search: `--broadcast` the address searched (default 255.255.255.255), `--port` the UDP port (default 32108), `--timeout` seconds to listen (default 5) | LAN only |
| `login` | log in, answering an e-mailed code or a captcha, cache the session, and print what the network must allow (as `network`) | cloud |
| `network` | probes LAN discovery (no session), then lists each station's address (where it answered, or where the address came from), its local port, whether it answered, and the firewall and fixed-IP advice for it | cloud (cached) + LAN |
| `devices [--rescan-regions]` | the account's devices with their model's support grade and the cloud region that lists each; `--rescan-regions` also asks the regions that listed no devices last time | cloud |
| `status [--json \| --raw]` | one snapshot: guard mode (and the mode in force when it differs), firmware, address, the station's profile parameters (LAN IP, storage use, …), and every paired device with its battery, signal, firmware, charging state (`charging (solar) (CODE)`, `charging (CODE)` or `not charging (CODE)`, CODE the raw param 2111) and `LOW BATTERY` for a motion sensor that flags it; a device the station reports offline (param 1131) is marked `OFFLINE` and its battery and signal shown as `last` values, since the station keeps serving them. A model not in the bundled data, or with newer vendor data than bundled, gets a line of its own. `--json`: the station's `guard_mode`, `active_mode`, `storage_status`, `subsystem_firmware` and raw `params`, and per device `online`, `offline_code`, `battery`, `battery_temperature`, `low_battery`, `rssi`, `firmware`, `power_source`, `charging`, `solar_charging`, `solar_intensity`, `working_days`, `detected_events`, `recorded_events`, `siren_actions` (by mode) and the raw `params`; `--raw` = every parameter with its name | cloud + LAN |
| `coverage` | where the model settings and the station's dump disagree, per block: readable settings of the device's model that the device did not report, and parameters the library reads nowhere; also each sub-device's `online` flag. A maintenance lead, not a capability list — see [source-of-truth.md](source-of-truth.md) | cloud + LAN |
| `storage [--json]` | the storage record, read-only, in the eufy app's figures: disk used / total GB (GiB, as the app labels them), free, used %, temperature, health, formatting; eMMC used % and wear; events and days kept. `--json` adds every field in MiB (disk serial and label masked with `--redact-serials`) | cloud + LAN |
| `guard get` / `guard set MODE` | MODE: `away`, `home`, `disarmed`, `schedule`, `geofence`, `custom_1..3` or a code | cloud + LAN |
| `settings [--model PN]` | `--model PN`: the settings of product code PN (any case) from its bundled file, one row each: key (the vendor identifier), kind (`bool`, `enum`, `range`, `string`, `flags`, `other`), values (`value=label` for an enum, `any of member=label` for flags, `min..max step s` for a range), unit, writable (`yes`, or why the library does not write it: read-only, a cloud request, app-local, …) and the setting it applies under (`power_manager_mode = 3`); then, for a camera or sensor model, the per-mode delays and actions it carries when paired. A code with no bundled file prints `no bundled settings for PN`. Without `--model`: the per-mode settings (`alarm_delay_<mode>`, `leaving_delay_<mode>`, `camera_action_<mode>`, `sensor_action_<mode>`) and which paired devices carry them | nothing |
| `get KEY [--device SN \| --channel N]` | read one setting from a fresh parameter dump: `KEY = VALUE (LABEL) UNIT`, or `unknown` when the dump does not report it. No target (or `--channel 255`) reads the station's own setting; `--device` or `--channel` (0–50) a paired device's, and a standalone camera's own serial its own. A `--channel` outside 0–50 and 255 is refused before any login; a key the addressed device's model does not have is a usage error | cloud + LAN |
| `set KEY VALUE [--device SN \| --channel N]` | write one setting (the keys `settings --model` lists), addressed as for `get`. The key is resolved on the addressed device's model after discovery and the value validated before anything is sent: an enum takes its value or its label, a bool `true`/`false`/`on`/`off`/`1`/`0`. An unknown key, a setting the library does not write, a value outside the domain or a wrong target is a usage error. Prints `KEY = VALUE on TARGET: applied` (VALUE as its label when it has one) (the station answered it) or `delivered` (the datagram was acknowledged; the station sends no result for it). Nothing is read back: `get` or `status --raw` shows what the device reports | cloud + LAN |
| `events [--days N] [--table T] [--count N] [--device SN]… [--media-only] [--json]` | the station's own event records (DB verb 10000) from the last `--days` (default 7), at most `--count` (default 100), from table `--table` (default `history_record_info`); `--device` (repeatable) limits them to those devices, `--media-only` keeps records with a file to fetch, `--json` prints the raw records | cloud + LAN |
| `history [--days N] [--count N] [--media-only] [--json]` | the fuller history list across all devices (DB verb 10011: far more rows than `events` — arming audit plus camera detections with their recording/thumbnail paths), newest first: every day from `--days` ago up to and including today, paged like the app; `--days` defaults to 7, `--count` (default 100) caps the records shown | cloud + LAN |
| `persons [--kind people\|faces\|bodies] [--count N] [--json]` | the AI face/person library: recognised people, or their face / body-reID pictures with fetchable paths; `--count` defaults to 200; `--json` prints the raw rows | cloud + LAN |
| `image PATH --out FILE` | a still from the station's disk by its path (from an event or a person picture) | cloud + LAN |
| `live --device SN\|--channel N [--seconds S] [--preset N] --out PREFIX` | record a camera's live video and audio to `PREFIX.hevc` + `PREFIX.aac` for `--seconds` (default 10) from the first frame (wakes a battery camera); `--preset` first turns a pan/tilt camera to that stored slot (with `--device`) | cloud + LAN |
| `recording PATH --device SN\|--channel N [--download] --out PREFIX` | save a stored recording (a history row's `storage_path`) to `PREFIX.hevc` + `PREFIX.aac`, by playback (1025) or with `--download` the download command (1024) | cloud + LAN |
| `snapshot --device SN\|--channel N [--recording PATH] --out FILE` | one full-resolution HEVC keyframe: the camera's next one, or the recording's first (its trigger moment) | cloud + LAN |
| `monitor [--no-push] [--no-p2p] [--json]` | print events as they arrive until Ctrl+C: `--no-push` skips cloud push, `--no-p2p` the local sessions (not both), `--json` prints one object per line | cloud + LAN |

Numeric options are range-checked: `--days` 1–36500, `--local-port` 0–65535,
and `--count`, `--seconds` and `--timeout` must be greater than 0.

## Exit codes

| code | meaning |
|---|---|
| 0 | done |
| 1 | a library or network error, printed as one line: authentication, unreachable station, command not applied (usually the owner account id), … — or `guard set` read back a different mode than it asked for |
| 2 | usage error |
| 130 | interrupted |

## Verifying a device

`get KEY` (or `status --raw`) before, `set …`, `get KEY` after: the write holds when
the parameter moves and reads back. See
[how-to/add-a-device.md](../how-to/add-a-device.md).

`coverage` first, on a device known to be online: it shows which of its model's
settings this unit actually reports, so a write is never attempted against a parameter
the station does not serve.
