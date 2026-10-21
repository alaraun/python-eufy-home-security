# Diagnostics report

`eufy-security diagnose` writes one read-only report of the whole account: every device
the eufy cloud lists, the health of each station the library serves over local P2P,
and a WebRTC probe of the stations the app reaches only over WebRTC (`T9000`, the NVR
`T8N00`), which the library cannot serve yet. The report is safe to share: it is built
from descriptors and redacted views only.

## What it does

Nothing is armed, disarmed, changed or triggered. It wakes sleeping stations and
battery cameras to reach them.

1. Log in to the account **on the machine running it** (a 2FA code or captcha is asked
   for when eufy sends one) and list the devices.
2. **Account:** the account report (`EufySecurity.async_account_report`: every device
   each eufy list names, with model, firmware, owner and cipher state), the session
   cache summary (`async_cache_summary`), the devices the library skips and why, and
   the model files the library has for the account's products.
3. **P2P stations** (HomeBases, standalone cameras): connect, read the state once
   (`async_update(wake=True)`) and, for a station with a held session, its storage, then
   record `Station.diagnostics()`: model, connection, last error type, LAN-path
   warnings, local-event support, paired devices, session counters, storage figures.
   A failed read is recorded by exception type under `read_errors`.
4. **WebRTC-only stations:**
   - the station's cloud record (firmware, WebRTC SDK version, which signaling fields
     are present) and its paired devices (model, channel, firmware), and what the app
     derives from them: the data channel's KCP framing (`kcp_type`) and whether
     commands are AES-GCM-sealed;
   - signaling, the data-channel CALL (kind 5), ICE, KCP and the heartbeat echo;
   - two read-only queries over the data channel: storage info (1350/1307) and the
     station's paired-device list (1350/9100), on the station channel 255 with the
     owner's id (skip with `--no-commands`);
   - with `--watch SECONDS`, every notification the station sends meanwhile, e.g. while
     the user switches the guard mode in the eufy app: the guard-mode notification
     without the tool sending a mode change;
   - a live call (kind 6) to one camera (the lowest paired channel, or
     `--camera-channel`): the live open over the data channel (the route the station's
     handler declares), the RTCP route when no frame arrives, then packet and frame
     counts for `--listen` seconds (skip with `--no-live`).

   Every inbound data-channel message is described: its 16-byte XZYH header, whether it
   is sealed, which key and wrapper open it (command reply `tag|iv|counter|ct` or
   notification `tag|iv|ct`), and its JSON key names.

## What the report contains — and never

- **Collected:** model codes, firmware and SDK versions, channels, serials shortened to
  the model and last four characters (`redact_serial`), the presence of cloud fields,
  session, error and media counters, timings, ICE candidate-type counts and role,
  protocol-header bytes, JSON key names (a name that looks like a serial becomes `?`),
  the values of a fixed list of integer fields (status codes, modes, channels, counts),
  RTP packet counts per payload type, frame counts and the type of the first NAL unit
  of the first frames.
- **Never collected:** the account password or tokens, the account or owner id, the
  e-mail, full serials, device names, the DID or license, IP addresses, encryption
  keys, disk serials and labels, string values of replies, or any audio/video payload
  bytes. An error is recorded as its type, not its message.

Credentials stay on the local machine. The report is a JSON file on disk; review it
before sharing — nothing is uploaded.

A login from this tool ends the session of any other client logged in with the same
account, the eufy app included (see
[home-assistant.md § One eufy account per consumer](home-assistant.md#one-eufy-account-per-consumer)).
A second account the stations are shared to with admin rights avoids that.

## Running it

Needs Python 3.13 or newer and, for the WebRTC stations, the `rtc` extra (`aioice`,
`pylibsrtp`; both ship wheels, nothing is compiled). Run it on the same network as the
stations: local P2P finds them by LAN broadcast.

```
pip install "eufy-home-security[rtc]"

# Read exactly what it will do and collect, without logging in:
eufy-security diagnose --explain

# Run it (prompts for the eufy password, or reads $EUFY_PASSWORD):
eufy-security --email you@example.com diagnose --watch 60
```

Options: `--station SN|NAME` (one station), `--no-p2p`, `--no-webrtc` (skip either
part; `--no-webrtc` needs no `rtc` extra), `--output PATH` (default
`eufy-diagnostics-<ts>.json`). WebRTC part: `--webrtc-all` (also probe the other
stations over WebRTC, e.g. a HomeBase 3 for comparison), `--channel N` (the
data-channel call, default 0), `--camera-channel N`, `--listen SECONDS` (default 8),
`--watch SECONDS`, `--no-commands`, `--no-live`. A summary is printed at the end.
