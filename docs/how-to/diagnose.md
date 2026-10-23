# Diagnostics report

`eufy-security diagnose` writes one report of the whole account (read-only unless the
opt-in below is given): every device
the eufy cloud lists, the health of each station the library serves over local P2P,
and a WebRTC probe of the stations the eufy app reaches over WebRTC, which the library
cannot serve that way yet: the stations it reaches only over WebRTC (`T9000`, the NVR
`T8N00`), and a HomeBase 3 with a paired camera the app streams over WebRTC (the
battery doorbells `T8223` and `T8224`, e.g. a Video Doorbell C30). The report is safe to share: it is built
from descriptors and redacted views only.

## What it does

Nothing is armed, disarmed, changed or triggered unless `--rewrite-guard-mode` is given
(see below). It wakes sleeping stations and battery cameras to reach them. Every wait
has a time limit (a WebRTC station's signaling 45 s, its whole run 300 s plus the watch
and listen windows), one failing step is recorded and the run goes on, and the report
file is rewritten after every step and on any exit: `complete` is true only for a run
that got to its end, `aborted` names what cut it short (`interrupted` for Ctrl+C, else
an exception type).

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
4. **WebRTC probe.** By default it probes each WebRTC-only station (`T9000`, `T8N00`)
   and each HomeBase 3 with a paired camera the eufy app streams over WebRTC (a
   `T8223` or `T8224`; the rule is `devices.live_open.app_uses_webrtc`). Such a
   HomeBase 3 keeps its P2P read of step 3 as well. `--webrtc-all` adds every other
   station, `--no-webrtc` skips the whole step. Each probed station's entry names why it
   was probed (`probe_reason`: `webrtc_only`, `webrtc_child` or `webrtc_all`) and the
   camera its live view used (`live_camera`: channel, model, product code, shortened
   serial, and `chosen_by`: `camera_channel`, `webrtc_child` or `lowest_channel`;
   null with `--no-live`). For each:
   - the station's cloud record (firmware, WebRTC SDK version, product code, which
     signaling fields are present, the record's key names, its cloud parameter ids and
     the cloud's guard mode) and its paired devices (model, product code, channel,
     firmware, battery or mains from the model's settings file, the cloud's online
     flag), and what the app derives from them: the data channel's KCP framing
     (`kcp_type`) and whether commands are AES-GCM-sealed;
   - signaling, step by step (`open`, `discover`, `login`, with durations; a failure
     names its step, e.g. `signaling.login: SignalingError` with the server's code),
     the data-channel CALL (kind 5: the answer's key names, the flag bytes of its
     `sdp_info`, the time to the answer, to the gathered and the first remote
     candidate, to ICE connected and the first datagram), ICE (role, candidate-type
     counts, the types of the selected pair: `relay` is TURN), KCP and the heartbeat
     echo;
   - two read-only queries over the data channel: storage info (1350/1307) and the
     station's paired-device list (1350/9100), on the station channel 255 with the
     owner's id (skip with `--no-commands`);
   - with `--watch SECONDS`, every notification the station sends meanwhile, e.g. while
     the user switches the guard mode in the eufy app: the guard-mode notification
     without the tool sending a mode change. The cloud push listener runs during the
     WebRTC part of such a run (`--no-push` leaves it out), and every event of the
     library's bus (cloud push, P2P stations) is recorded under `events`: its class,
     source, models, small-integer fields (`msg_type`, `event_type`, `guard_mode`,
     `mode` ...) and the key names of its raw payload; `watch_windows_ms` says when
     each watch window ran;
   - a live call (kind 6) to one camera (`--camera-channel` when given; else the
     lowest channel the eufy app streams over WebRTC, the doorbell behind a HomeBase 3;
     else the lowest paired channel): the live open over the data channel (the route the station's
     handler declares), the RTCP route when no RTP packet arrives, then `--listen`
     seconds of stream descriptors (skip with `--no-live`): per RTP payload type the
     packets, bytes, SSRC count, sequence gaps, timestamp steps and clock-rate estimate;
     for video (H.265 payload type 97, H.264 99) the packetization (single NAL unit,
     aggregation, fragmentation), NAL unit types, frames, keyframes and how many were
     decrypted, frame rate, keyframe interval, the parameter sets seen and what the
     SPS declares (profile, level, chroma format, width, height); for audio (payload
     type 111) the first four bytes of the first four packets (a format header such as
     ADTS); the time to the first packet and the first decrypted frame; the media
     plane's ICE timings and selected pair.

   Every inbound data-channel message is described: its 16-byte XZYH header, whether it
   is sealed, which key and wrapper open it (command reply `tag|iv|counter|ct` or
   notification `tag|iv|ct`), and its JSON key names; a payload that is not XZYH is read
   as JSON, else only its first four bytes are kept. `message_counts` counts every
   message by phase and type, past the 200 the listing keeps. Each command records the
   key names of the request it sent.

### Opt-in: re-send the current guard mode

`--rewrite-guard-mode` is a **write**. For each WebRTC-probed station whose cloud guard
mode (parameter 1224) is Away, Home or Disarmed, it asks on the terminal (showing the
mode it read) and, on `yes`, sends that same mode once as the station's 1350/1224
command at channel 255, after the read-only queries, to record the station's reply. A
schedule, custom or geofence mode is never re-sent; no terminal or any other answer is
a no. The station may log the command or announce the mode as if it had been set. The
station's entry records `guard_rewrite` (`confirmed: <mode>`, `declined`,
`skipped: ...`) and the reply under `commands`.

## What the report contains — and never

- **Collected:** model codes, firmware and SDK versions, channels, serials shortened to
  the model and last four characters (`redact_serial`), the presence of cloud fields,
  session, error and media counters, timings, ICE candidate-type counts and role,
  protocol-header bytes, JSON key names (a name that looks like a serial becomes `?`),
  the values of a fixed list of integer fields (status codes, modes, channels, counts),
  stream descriptors (codec, profile, level, resolution, packet and frame counts), the
  first four bytes of the first audio packets, and the run's options.
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

Needs Python 3.13 or newer and, for the WebRTC probe, the `rtc` extra (`aioice`,
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
stations over WebRTC, e.g. a HomeBase 3 without such a camera, for comparison),
`--channel N` (the data-channel call, default 0), `--camera-channel N` (the live
view's camera), `--listen SECONDS` (default 8),
`--watch SECONDS`, `--no-push`, `--no-commands`, `--no-live`, `--rewrite-guard-mode`
(the opt-in write above). A summary is printed at the end.
