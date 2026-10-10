# P2P transport: PPPP, DRW and XZYH

The station speaks PPPP (also known as CS2 Network or PPCS) over UDP. PPPP carries
discovery, the punch, keepalives and DRW chunks. Reassembled DRW chunks form a
per-channel byte stream of XZYH application frames. Nothing at this layer is
encrypted: the crypto is inside XZYH payloads ([session-crypto.md](session-crypto.md)).

Code: `src/eufy_home_security/p2p/pppp.py` (datagrams),
`p2p/transport.py` (socket, discovery, keepalive, ACK/retransmit), `p2p/did.py`,
`p2p/xzyh.py` (frames, reassembly).

## PPPP datagram

```
+------+------+-------------+-----------------+
| 0xF1 | type | length u16be| payload[length] |
+------+------+-------------+-----------------+
```

Some keepalives declare length 0 but carry a trailer, so a parser should treat the
payload as whatever follows the 4-byte header, bounded by the declared length when
the length fits.

| type | name | direction | payload | status |
|---|---|---|---|---|
| `0x30` | LAN_SEARCH | client → station :32108 (unicast or broadcast) | none | **[verified]** |
| `0x41` | PUNCH_PKT | both | 20-byte DID struct | **[verified]** |
| `0x42` | P2P_RDY | station → client | DID struct | **[verified]**, often skipped on the LAN |
| `0x43` | PUNCH_SUCCESS | station → client | peer sockaddr | **[app]** |
| `0xD0` | DRW | both | DRW sub-header + chunk | **[verified]** |
| `0xD1` | DRW_ACK | both | ACK sub-header + indices | **[verified]** |
| `0xE0` | ALIVE | both | none | **[verified]** |
| `0xE1` | ALIVE_ACK | both | none | **[verified]** |
| `0xF0` | CLOSE | both | none | **[verified]** |
| `0x00`/`0x01` | HELLO / HELLO_ACK | client ↔ master :32100 | NAT-reflected address | seen in app traffic, not implemented |
| `0x20`/`0x21`, `0x40`, `0xF9` | P2P_REQ/ACK, PUNCH_TO, RLY_HELLO | master / relay path | | seen in app traffic, not implemented |
| `0x26` | LOOKUP | client → rendezvous server :32100 | DID + the client's sockaddr + `02 05 01 05` + DSK | **[verified]** the wake ([below](#waking-a-battery-station-verified)) |

Only the LAN path is implemented. Off-LAN operation needs the master/relay handshake
and the `p2p_did`, `p2p_license` and `signaling_servers` fields from the device list
**[open]**.

## DID struct (20 bytes)

```
off  0..7   prefix, 1..7 ASCII capitals, NUL-padded   "EUPRAMA\0"
off  8..11  number, u32 big-endian, below 2**31       123456 → 00 01 E2 40
off 12..19  suffix, 1..7 ASCII capitals, NUL-padded   "ABCDE\0\0\0"
text form   EUPRAMA-123456-ABCDE (the number at least six digits, zero-padded)
```

These are the bounds the eufy app's P2P stack accepts **[declared]**; it refuses any
other id (a longer prefix or suffix, digits in the suffix) before sending a packet. The
library skips a station with such an id (`skipped_devices`, reason `bad_did`).

## Discovery and punch

```
client:ephemeral  → station:32108        F1 30 00 00                     LAN_SEARCH (repeat ~1 s)
station:R         → client:ephemeral     F1 41 00 14 <DID struct>        PUNCH_PKT from a random port R
client            → station:R            F1 41 00 14 <DID struct>        PUNCH_PKT echo
station:R         → client               F1 42 ...                       P2P_RDY (optional)
... DRW / DRW_ACK / ALIVE on client ↔ station:R for the rest of the session
```

Facts that shape a client **[verified]**:

| fact | consequence |
|---|---|
| The station answers from a **random high port that changes every session**, not from 32108. | Pin the peer to the address the PUNCH_PKT came from. `:32108` firewall rules and conntrack do not match the reply, which is a new flow. |
| Within one session, **every datagram from the station comes from that one port**: replies, pushes, parameter dumps and media alike. ACKs and keepalives sent only to that port keep every channel, media included, flowing. | Once the peer is pinned, the library accepts datagrams only from that exact (host, port) and drops the rest. A datagram from the station's IP on another port is not this session's traffic (another session on the base, or a forgery). It is dropped, counted, and logged at DEBUG (throttled). Before a peer is pinned, discovery filters on the searched host and the expected DID. |
| **The first LAN_SEARCH after a session is closed is ignored.** This holds after the client's own CLOSE and after another client's session closes. | Discovery must re-send until a timeout (the library sends every 1 s for 6 s, 3 attempts). A single failed search is not "station gone". |
| **A battery or solar standalone camera answers late, or not at all while asleep.** A T8170 answered one search after 2.1 s, and at another time no search for 15 s, broadcast or unicast, while its address still answered ARP. It wakes on its own about every 7 min. | Listen longer (`LAN_DISCOVERY_TIMEOUT`, 5 s) to catch a wake window, or **wake it deliberately** ([below](#waking-a-battery-station-verified)). |
| **The eufy app holds no session to a battery device.** A list of serial prefixes (battery SoloCams such as the T8170, battery doorbells, trackers, locks) is excluded from the app's watchdog, which reconnects every other session every 60 s while the app is in the foreground; the app closes every session 120 s after it leaves the foreground **[declared: app]**. | The library copies it: `devices.ON_DEMAND_PREFIXES`; such a station connects per command and closes after `ON_DEMAND_IDLE_CLOSE` (120 s) idle, and its state comes from the cloud snapshot ([cloud.md](cloud.md)). |
| A host firewall can only admit the station's replies by the **client's** port. | Bind a fixed local port **per station** when needed (two sessions cannot bind one port) and accept `udp dport <local port>` from the station's address, or accept all UDP from that address. Either rule needs the station on a fixed IP. With an open path, an ephemeral port is fine. |
| P2P_RDY is frequently absent on the LAN. | Wait briefly (the library waits 2 s), then proceed. |
| The station accepts several concurrent sessions, but has a **session budget** [verified]: a HomeBase 3 holds 9 sessions across all clients, a T8170 4. Idle or streaming makes no difference to the count. | The library holds at most `max_sessions` to a station (default 6: its session, 1 trigger-frame session, 4 extra live sessions; configurable 2–9) and closes short-lived ones at once. A live open next to 0, 2 or 4 idle extra sessions reached its first keyframe in 2 to 4 s; one outlier run with two idle extras got no frame in 25 s and did not recur. |
| **Too many sessions: the station closes one [verified].** With the eufy app, two long-lived foreign sessions and two library sessions connected, a library client opened six more, one at a time, each reading parameters fine. As the count passed about nine, the station sent CLOSE to an existing session twice (at the 5th and 6th extra): first the oldest, then one that was neither the oldest nor the newest. | A session can be dropped because *other* clients connected. Supervise and reconnect (the library's monitor reconnected in 8 s); never assume a slot is reserved. |

The library's LAN probe (`EufySecurity.async_probe_lan()` and `async_station_choices()`)
never sends a LAN_SEARCH to a station that has a connected session: it reports that
station from the session (answered, at the session's host). While any station has a
connected session the probe sends no broadcast either, only unicast searches to the
known addresses of the stations that are not connected.

## Waking a battery station **[verified]**

A battery station (a T8170 standalone camera; the app's no-session prefixes,
`devices.ON_DEMAND_PREFIXES`) keeps only a standing link to eufy's cloud while it sleeps
and does not answer a `LAN_SEARCH`. To reach it, poke it through its rendezvous servers,
exactly as the app does:

1. Decode the servers from the cloud device list's `app_conn` (three IPs for the T8170;
   `p2p_conn` is the same plus relay host names). The obfuscation is the app's
   `PPPP_DecodeString` — see `p2p/pppp.py: decode_init_string`.
2. Fetch the station's **device session key (DSK)** from the cloud ([cloud.md](cloud.md)):
   a 20-character key, valid ~1 h, one per client.
3. To each server on UDP **32100**: one `HELLO` (`0xF1 0x00`), then a `LOOKUP` (`0x26`)
   every second. The 64-byte LOOKUP body is the 20-byte DID struct, the client's own
   `sockaddr_in` (family `0x0002` big-endian, port little-endian, IPv4 reversed, 8 zero
   bytes), the four bytes `02 05 01 05`, and the DSK zero-padded to 24.
4. The server pokes the station over its cloud link; the station **punches back over the
   LAN** with the usual `PUNCH_PKT` (from a fresh high port), and the session proceeds
   exactly as after a `LAN_SEARCH`. On the T8170 the punch arrived ~1.8–3 s after the
   first LOOKUP; a `status` from cold sleep completed in 6.5 s.

The library sends the `LAN_SEARCH` and the LOOKUPs together each discovery round
(`transport.connect(wake=Wake(servers, dsk))`), so a station that happens to be awake is
still caught by the search. The DSK is a secret: it is starred out of wire hexdumps.

## Waking a paired camera **[verified]**

A camera paired to a HomeBase 3 is not woken through the cloud at all — the HomeBase
wakes it locally. The HomeBase runs its **own hidden 2.4 GHz Wi-Fi AP** (WPA2-PSK); its
cameras associate to that AP, not to the house LAN (for a Wi-Fi camera on the house LAN
see [below](#a-wi-fi-camera-paired-to-a-homebase-on-the-house-lan)), and stay
associated in power-save while they sleep. A client never addresses the camera
directly: a command (a live open, a setting) goes to the HomeBase over the LAN P2P
session with the camera's `mChannel`, and the HomeBase reaches the camera over its own
radio.

Verified on hardware (HomeBase 3, eufyCam 3) with a cold live open:

- **No cloud round trip.** With the HomeBase's switch port isolated from the internet
  gateway's port (bridge port isolation, so the cut held in the switch hardware), the
  HomeBase's ARP for the gateway went unanswered throughout and its lookups of eufy's
  cloud hosts led to no connection; a cold live open of a T8160 and of a T8170 (the
  house-LAN camera below) still woke the camera and streamed.
- **No re-association.** On the HomeBase's own Wi-Fi channel the wake carried only data
  and beacon frames — no association, authentication or deauthentication. The camera was
  already associated; it was near-idle before the command and began sending video about
  1–1.5 s after it, ramping straight into the stream.

So a paired camera's wake is a local power-save/data-plane event on the HomeBase's AP,
with the HomeBase as the camera's access point and controller. This is unlike a
standalone battery camera (above), which has no hub and must be reached through eufy's
rendezvous servers.

### A Wi-Fi camera paired to a HomeBase on the house LAN

A Wi-Fi battery camera (T8170) paired to a HomeBase 3 but associated to the house Wi-Fi
(bridge mode, Wi-Fi preferred) shares the HomeBase's L2 segment. The HomeBase still
wakes it locally, with a magic packet over plain IP **[verified]**:

- **Asleep, the camera holds a TCP connection to the HomeBase**, camera → HomeBase port
  10402. Every ~2 min the camera sends one 125-byte record (starting `ba dc cd ab`); the
  HomeBase only ACKs. The camera stays associated to its AP (one frame to the AP about
  every 30 s) and answers ARP, so a unicast frame reaches it.
- **Wake:** the HomeBase sends the 41-byte payload
  ```
  "WakeUpWifiCamera" (16 ASCII) | token (16 ASCII) | 01 00 00 00 | 00 00 00 00 | 00
  ```
  three times on that TCP connection, 1 s apart, and from 0.1 s after the first as UDP
  from HomeBase port 32008 to camera port 32108, every 100 ms for ~2.3 s
  (24–26 datagrams).
- **Token:** at the end of each awake period the camera sends a keep-alive login (76 bytes,
  encrypted) on the 10402 connection and the HomeBase answers it with a new
  16-character token in clear; the next wake carries exactly that token. One token per
  sleep cycle.
- **After the wake** (0.7–1.0 s to the camera's first TCP ACK): the camera opens TCP to
  HomeBase port 10400 (~2.1 s after the wake; `ba ab ba ab` framed records) and sends
  media as UDP to HomeBase port 10200 (~3.3 s). The client's video still comes from
  the HomeBase over its own P2P session; the camera never talks to the client or to any
  other host.

No cloud, rendezvous server or 802.11 (re)association takes part: the camera's only
peer in the captures is the HomeBase, the Wi-Fi link shows data frames only, and the
wake and stream succeed with both the HomeBase and the camera cut off from the
internet gateway.

#### Camera ↔ HomeBase channels after the wake

Both are framed by the magic `ba ab ba ab` **[verified on captures]**:

- **TCP 10400, control.** Record = 24-byte header (`[4] magic | u8 06 | u8 type | u16 2 |
  u8 seq | 3 bytes constant | u16 1 | u16 0/1 | u16 0 | 2 bytes | u32le record length
  − 20`), then TLVs `u16le length (incl. 4) | u16le tag | value`. The
  camera opens with type 0x01: ten 16/32-byte opaque TLVs (key material); the HomeBase
  answers with five. After that most values are **clear**: the HomeBase forwards the
  client's command as an XZYH frame with its JSON (the live open, 1003, with the client's
  RSA modulus as `key`), the camera sends its notifies as JSON (6203, 6445, 60012 bridge
  status, `power_source`) and a POSIX TZ string; the HomeBase echoes each one back.
  Types 0x06/0x07/0x08/0x0b carry only 16/32-byte opaque values (about one per second
  while streaming).
- **UDP camera → HomeBase 10200, media.** Units of a 24-byte transport header (`u32
  session | u16 0x51 | u16 0xc0 | u32 time | u32 packet seq | u32 0 | u32 payload
  length`) and a chunk; a datagram carries one unit or several back to back. Chunk:
  60-byte header (`u16 chunk length` at 4; key-frame flag `0x80` at 8; frame time at
  16; frame number at 24; fps at 28; width, height at 36, 40; whole-frame size at 44;
  fragment index at 50; stream kind at 54, 1 video / 0 audio) and up to 1280 bytes of
  the frame. The HomeBase acks every few packets with 24-byte datagrams back to the
  camera's port.
  - **Audio** (ADTS AAC) and **P-frames** (Annex-B HEVC) are sent **in clear**.
  - **Keyframes**: the first 128 bytes are encrypted under a key that does not appear on
    the wire; the rest is clear. The HomeBase decrypts that prefix and re-encrypts it
    under the client stream's AES key ([media.md](media.md#keyframe-decryption-verified));
    every other byte reaches the client unchanged.
    The prefix holds the parameter sets (VPS/SPS/PPS), so the P-frames alone do not
    decode without one keyframe's clear prefix; audio needs nothing.

## Keepalive and liveness

- Send `ALIVE` about every 0.7 s and answer every station `ALIVE` with `ALIVE_ACK`
  **[verified]**. The library declares the link lost after 15 s with no datagram
  (its own choice).
- **The station answers ALIVE whether or not the encrypted session above still
  works** **[verified]**. Traffic at this layer proves the UDP path, never the
  session. Use an application-level probe ([events.md](events.md)).

## DRW

```
F1 D0 <len u16be> | D1 <channel u8> <index u16be> | chunk bytes
```

- **Channel** is a logical stream (below). **Index** is a per-channel, per-direction
  counter that starts at 0 for each session and wraps at 16 bits.
- A chunk carries at most about 1 KB of stream bytes. Frames larger than that span
  many chunks: a full parameter dump of about 300 params arrives as about 23 chunks
  **[verified]**.
- The receiver reorders by index, drops duplicates and retransmits, and appends to
  the channel's byte stream.

**DRW_ACK:**

```
F1 D1 <len u16be> | D1 <channel u8> <count u16be> | <index u16be> × count
e.g. ACK ch0 idx5:   F1 D1 00 06  D1 00 00 01 00 05
```

- **ACK every received chunk promptly.** The station stops sending a channel whose
  chunks go unacked, and media stalls first **[verified]**.
- The station ACKs the client's chunks. Retransmit unacked chunks (the library: after 1.5 s,
  up to 3 times).
- **A DRW_ACK is transport only.** It proves the datagram arrived, never that the
  command was applied ([commands.md](commands.md)).

| DRW channel | carries | status |
|---|---|---|
| 0 | client → station commands and CONN_INIT; station → client CONN_INIT reply, command results, event pushes, image and database replies | **[verified]** for commands, CONN_INIT and results. The channel of push and reply frames is not established **[open]**. |
| 1 | media: video, audio | **[verified]** |
| 2 | parameter dump (`0x044F`), guard-mode notify (`0x047F`) | **[verified]** |

Decode every channel independently and route by XZYH frame type, not by channel.

## XZYH frame

```
+--------+-------------+--------------+----------------+-----------------+
| "XZYH" | type u16le  | length u32le | subheader (6)  | payload[length] |
+--------+-------------+--------------+----------------+-----------------+
  0..3     4..5          6..9           10..15            16..
```

- Frames follow each other directly in a channel's byte stream. A frame's header
  starts wherever the previous frame ended, which is not necessarily at a chunk
  boundary. If the stream desynchronises, scan to the next `XZYH`.
- `length` counts the payload only. It is the ciphertext length for encrypted
  frames (ECB payloads are 16-byte aligned).
- **The frame type is a CommandType number** ([commands.md](commands.md)), so the
  app's command enum doubles as the frame-type name table.

### Subheader

Byte 0 is a **per-frame cipher tag**. Read it on every frame, because the same
station uses both values within one session ([session-crypto.md](session-crypto.md)).

| sender / frame | bytes 0..5 | meaning | status |
|---|---|---|---|
| client CONN_INIT request | `01 00 FF 00 00 00` | seq u16le = 1, flags `0xFF` | **[verified]** (as the app sends it) |
| client GCM frame (`0x0546` command, `0x044F` param query) | `08 <ctr> <dev_type> 08 <flag> 00` | GCM tag, a message counter that starts at 2 and grows by 2 per GCM frame, target dev_type = channel (the app copies a command's `mChannel`; `0xFF` for the station-wide parameter query), `flag` `0x0a` on a live open (1003, or a standalone device's 1700/1000 open) and 0 otherwise. **A live open streams the camera byte 2 names** ([media.md](media.md#open-1003-verified)); **a HomeBase passes a 1350 command on to a paired Wi-Fi camera (a T8170) only when byte 2 names its channel**: with 0 a picture zoom (6203) for it is answered with receipt −108 after 6–12 s, with the channel it is echoed within 0.12 s. The library sends the channel on a live open, a stream stop, a 1700 command and a 1350 command to a device, 255 on the parameter query and a string command, and 0 on a 1350 command to the station (255) and on the other commands, which the station accepts | **[verified]** |
| station media frame (`0x0514`, `0x0515`) | `.. .. <channel> .. .. ..` | byte 2 = the channel of the camera the frames come from | **[verified]** |
| client ECB scalar (type = command id) | `01 <seq> <channel> 01 00 00` | ECB tag, seq u8, **sub-device channel** (0..50, 255 = station; anything else is refused with −110), "encrypted" flag | **[verified]** |
| station, any frame | `01 ...` or `08 ...` | `0x01` = AES-128-ECB under the static key, `0x08` = AES-256-GCM under the session key. The remaining bytes are not needed to decode. | **[verified]** byte 0, **[open]** bytes 1..5 |
| RSA session (CONN_INIT version ≠ 8), both directions | `01 <seq> <dev_type> <enc> <flag> 00` | byte 3 is the encryption type: `02` AES-128-ECB under the key the RSA CONN_INIT carried, `01` the static key, `00` clear (a receipt). The app sends every command `02` ([session-crypto.md](session-crypto.md#rsa-conn_init-declared-app-legacy)) | **[declared: app]** |
| station, receipt (request type on channel 0) | `08 00 FF 00 01 00` (query), `08 00 00 00 01 00` (command) | a 132-byte body (36 bytes on a T8170) that is not ciphertext: `int32le` code (0 taken, −108 not handled) + zero bytes ([commands.md](commands.md#command-receipt-verified)) | **[verified]** |

For the image request (`1308`), neither the subheader dev_type byte nor `mChannel`
changes the reply **[verified]**.

### Frame types

| type | = cmd | name | direction | content |
|---|---|---|---|---|
| `0x044C` | 1100 | CONN_INIT | both | handshake |
| `0x044F` | 1103 | PARAM_NOTIFY | both | client: GCM parameter query. Station: parameter dump / change push (JSON). |
| `0x0473` | 1139 | DEV_STATUS / PING | both | the app's empty keepalive: about every 20 s to a HomeBase 3, which answers with 8 zero bytes under GCM ([commands.md](commands.md)); every 3 s to a T8170, which needs it while streaming ([media.md](media.md#standalone-device-open-17001000-stop-bare-1004-ping-1139-verified)) |
| `0x047F` | 1151 | ALARM_MODE_NOTIFY | station | the guard mode in force after any change, under either cipher: GCM (byte 0 `0x08`) body = u64le mode; ECB (byte 0 `0x01`) body = a 16-byte block whose first u32le is the mode ([commands.md](commands.md#arming-1224-verified)) |
| `0x0402` | 1026 | RECORD_PLAY_CTRL | station | body `02 00 00 00 00`: a recording playback ended ([media.md](media.md)) |
| `0x0408` | 1032 | WIFI_STRENGTH (app enum WIFI_CONFIG) | station | camera RSSI while streaming |
| `0x04B1`, `0x04B2` | 1201, 1202 | SET_TONE_FILE, SET_DEVS_TONE_FILE | station | alarm tone / camera siren, `[event_type, seconds]`, GCM ([events.md](events.md#alarm-over-p2p)). Client `0x04B2` = stop the alarm |
| `0x04D3` | 1235 | SET_HUB_SPK_VOLUME | client | `u32 value ‖ account id` ([commands.md](commands.md)) |
| `0x04E6`, `0x04E7` | 1254, 1255 | SET_JSON_SCHEDULE, SET_ALL_ACTION | client | JSON bodies ([commands.md](commands.md#mode-actions-delays-and-schedule-app-writes-verified)) |
| `0x03EC` | 1004 | stream stop | client | bare stop: body = the camera channel as u32le (the app's form; four zero bytes for a standalone device) ([media.md](media.md)) |
| `0x0517`, `0x0518` | 1303, 1304 | CONVERT_MP4_OK, DOWNLOAD_FINISH (app enum DOENLOAD_FINISH) | station | after a 1024 download |
| `0x0514` | 1300 | VIDEO_FRAME | station | media ([media.md](media.md)) |
| `0x0515` | 1301 | AUDIO_FRAME | station | media |
| `0x051A` | 1306 | DB_SYNC | station | event-database reply, "new rows" notice |
| `0x051C` | 1308 | MEDIA_DOWNLOAD / IMAGE | station | image reply (JSON + base64) |
| `0x0546` | 1350 | CMD_TRANSFER / SET_PAYLOAD | both | client: GCM DeviceMsgBean. Station: the 132-byte command receipt ([commands.md](commands.md#command-receipt-verified)). |
| `0x0547` | 1351 | NOTIFY_PAYLOAD | station | command results **and** event pushes (`cmd` 2037) |
| `0x0578` | 1400 | FLOODLIGHT_MANUAL_SWITCH (app enum SET_FLOODLIGHT_MANUAL_SWITCH) | station | a camera's light state, u32 0/1 under GCM, per channel (subheader byte 2): 1 during an alarm **[verified]**, 0 at detections and periodically |
| `0x083F` | 2111 | BATTERY_STATUS (app enum SUB1G_REP_UNPLUG_POWER_LINE) | station | seen when a session ends; body undecoded **[open]** |
| `<cmd>` | cmd | legacy scalar | both | ECB scalar command and its same-type result ([session-crypto.md](session-crypto.md)) |
