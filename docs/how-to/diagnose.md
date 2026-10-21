# Diagnosing a WebRTC-only station

Some eufy stations — the HomeBase Professional (`T9000`) and the NVR (`T8N00`) — are
reached by the app only over WebRTC, not the local P2P protocol the rest of this library
uses. `eufy_home_security` cannot yet serve those stations, and development needs data
from the real hardware. The `diagnose` command collects that data **read-only** and writes
a report that is safe to share.

It is useful to anyone volunteering a `T9000`/`T8N00` for testing, and to maintainers
confirming the data channel on their own hardware.

## What it does

All phases are read-only — nothing is written, armed, or triggered (it does wake a
sleeping station to reach it, which is unavoidable):

1. Log in to the account **on the machine running it** and list the devices.
2. For each target station: place the kind-5 ("priv1") CALL, connect ICE, bring up the KCP
   data channel, send a keep-alive.
3. Send read-only queries (storage info, device info) and describe the reply (unless
   `--no-commands`).
4. Listen briefly for live packets and record their shape (unless `--no-av`).

## What the report contains — and never

The report is built so it **cannot** hold a secret: every field is a descriptor.

- **Collected:** field lengths, counts, timings, protocol-header types, ICE candidate-type
  counts (host/srflx/relay), the role, the *label* of the key that decrypts a reply
  (`device_content_key`/`client_content_key`), a reply's 4-byte counter, and a reply's
  top-level JSON key **names**.
- **Never collected:** the account password or tokens, the account id or email, full
  serial numbers, IP addresses, encryption keys, or any audio/video payload bytes.

Credentials stay on the local machine and are never written to the report. The report is a
JSON file on disk; review it before sharing — nothing is uploaded.

## Running it

Needs the `rtc` extra (`aioice`); the command says so if it is missing.

```
pip install "eufy-home-security[rtc]"

# Read exactly what it will do and collect, without logging in:
eufy-security diagnose --explain

# Run it (prompts for the eufy password, or reads $EUFY_PASSWORD):
eufy-security --email you@example.com diagnose

# Smallest footprint first — signaling/ICE/KCP only, no commands, no A/V:
eufy-security --email you@example.com diagnose --no-commands --no-av
```

By default it probes the account's webrtc_only stations. Options: `--station SN` (one
station), `--all-stations` (every station, e.g. to compare on a non-webrtc_only HomeBase),
`--channel N`, `--listen SECONDS` (A/V listen window), `--no-commands`, `--no-av`,
`--output PATH`. The JSON report is written to `--output` or `eufy-diagnostics-<ts>.json`,
and a summary is printed.
