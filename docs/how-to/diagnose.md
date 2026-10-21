# Diagnosing a WebRTC-only station

Some eufy stations — the `T9000` and the NVR `T8N00` — are reached by the app only over
WebRTC, not the local P2P protocol the rest of this library uses. `eufy_home_security`
cannot serve those stations yet, and development needs data from real hardware. The
`diagnose` command collects that data without changing anything on the station and
writes a report that is safe to share.

## What it does

Nothing is armed, disarmed, changed or triggered. It does wake a sleeping station to
reach it, and a battery camera spends some charge on the live view.

1. Log in to the account **on the machine running it** (a 2FA code or captcha is asked
   for when eufy sends one) and list the devices.
2. Per target station, record its cloud record (model, firmware, WebRTC SDK version,
   which signaling fields are present) and its paired devices (model, channel,
   firmware). From these it derives what the app does: the data channel's KCP framing
   (`kcp_type`) and whether commands are AES-GCM-sealed.
3. Connect to eufy's signaling server, place the data-channel CALL (kind 5), connect ICE,
   bring up KCP and check the heartbeat echo.
4. Send two read-only queries over the data channel: storage info (1350/1307) and the
   station's paired-device list (1350/9100), addressed to the station channel 255
   (unless `--no-commands`).
5. With `--watch SECONDS`, keep the channel open and record every notification, e.g.
   while the user switches the guard mode in the eufy app: this shows the guard-mode
   notification without the tool sending a mode change itself.
6. Open a live call (kind 6) to one camera (the lowest paired channel, or
   `--camera-channel`), send the live open over the data channel (the route the
   station's handler declares), fall back to the RTCP route when no frame arrives, and
   count packets and frames for `--listen` seconds (unless `--no-live`).

Every inbound data-channel message is described in the report: its 16-byte XZYH header,
whether it is sealed, which key and wrapper open it (command reply `tag|iv|counter|ct`
or notification `tag|iv|ct`), and its JSON key names.

## What the report contains — and never

The report is built so it **cannot** hold a secret: every field is a descriptor.

- **Collected:** model codes, firmware and SDK versions, channels, the presence of
  cloud fields, timings, ICE candidate-type counts and role, protocol-header bytes, the
  *label* of the key that opens a message, JSON key names (a name that looks like a
  serial is replaced by `?`), the values of a fixed list of integer fields (status
  codes, modes, channels, counts), RTP packet counts per payload type, frame counts
  and the type of the first NAL unit of the first frames.
- **Never collected:** the account password or tokens, the account id or email, serial
  numbers, the DID or license, IP addresses, encryption keys, string values, or any
  audio/video payload bytes. An error is recorded as its phase and exception type, not
  its message.

Credentials stay on the local machine. The report is a JSON file on disk; review it
before sharing — nothing is uploaded.

A login from this tool ends the session of any other client logged in with the same
account, the eufy app included (see
[home-assistant.md § One eufy account per consumer](home-assistant.md#one-eufy-account-per-consumer)).
A second account the station is shared to with admin rights avoids that.

## Running it

Needs Python 3.13 or newer and the `rtc` extra (`aioice`, `pylibsrtp`; both ship
wheels, nothing is compiled).

```
pip install "eufy-home-security[rtc]"

# Read exactly what it will do and collect, without logging in:
eufy-security diagnose --explain

# Run it (prompts for the eufy password, or reads $EUFY_PASSWORD):
eufy-security --email you@example.com diagnose --watch 60

# Smallest footprint: signaling, data channel and heartbeat only:
eufy-security --email you@example.com diagnose --no-commands --no-live
```

By default it probes the account's webrtc_only stations. Options: `--station SN|NAME`
(one station), `--all-stations` (every station, e.g. a HomeBase 3 for comparison),
`--channel N` (the data-channel call, default 0), `--camera-channel N`, `--listen
SECONDS` (live view, default 8), `--watch SECONDS`, `--no-commands`, `--no-live`,
`--output PATH`. The JSON report is written to `--output` or
`eufy-diagnostics-<ts>.json`, and a summary is printed.
