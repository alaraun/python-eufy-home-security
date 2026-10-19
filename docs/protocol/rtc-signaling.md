# RTC signaling

Some stations are reached by the eufy app only over its WebRTC path, never over
PPPP: the T9000, the NVRs (T8N00, T7000) and the T8040. Their stations and every
device paired to them stay skipped (`webrtc_only`) until the library can run that
path. `eufy_home_security.rtc` holds the parts built so far: the signaling wire
format, the signaling client and the session sequence including its cryptography,
with the media plane behind an interface that has no implementation yet. Nothing in
`Station` uses it.

Tags as in [README.md](README.md#verification-markers): **[verified]** for what ran
against eufy's signaling server with a HomeBase 3 identity, **[app]** for the rest.

## Inputs

From the station's device-list entry **[app]**: `signaling_servers` (the first bare
IPv4 entry is the host; a domain entry is never resolved), `p2p_did`, `p2p_license`,
`main_sw_version` (dots removed, as an integer) and `webrtc_sdk_version`. From the
account: the user id and an install-wide app id. `RtcConfig.from_device` builds the
config; an entry without a serial, DID, license or IPv4 host has none.

## Transport

UDP to port 5062 on the signaling host **[verified]**. Every datagram is
obfuscated: `u16 8 | u16 len+pad | key[16] | u8 pad | u8 random | packet XOR key |
pad random bytes`, the key fresh per datagram, `pad` random below `0x3d3 - len`. A
receiver also takes a plain packet.

TCP to 5061 or 15061 (picked at random) carries plain packets back to back, transport
flag 0x3b = 0; a receiver reads 0x29 bytes, then the rest of the header (extension
length at 0x28) and the body **[app]**. The app sends a CALL again over TCP when no
session follows it **[app]**, presumably so the server wakes a sleeping device. The library sends an
unanswered CALL (no 100, 200 or error code within 5 s) over a fresh TCP connection,
at most three times; the 5 s and three tries are the library's choice.

## Packet

A 60-byte little-endian header, then the body (`rtc/codec.py`):

| offset | size | field |
|---|---|---|
| 0x00 | u16 | tag, 3 |
| 0x02 | u16 | CRC-16/XMODEM over 0x04..0x3c and the body |
| 0x04 | u16 | message type: 1 LOGIN, 2 CALL, 3 ACK, 4 INFO, 5 HANGUP, 6 UPDATE, 7 WAKEUP, 8 REPORT, 9 DISCOVER, 10 PING, 11 MESSAGE, 12 LOGOUT, 13 CONTROL |
| 0x06 | u16 | body length, at most 0x1000 |
| 0x08 | u32 | packet id: the sender's time in seconds |
| 0x0c | u8 | protocol version, 7 (the server answers with 8) |
| 0x0d | u8 | sender kind, 6 (Android) |
| 0x0e | u8 | 1 for a response |
| 0x0f | u8 | mode: 2 on a LOGIN request, 2 on a private CALL, else 0 |
| 0x10 | u16 | response code: 100, 200, 401, 480, 486 |
| 0x12 | u8 | 1 when the attachment is encrypted |
| 0x13 | u8 | flags; bit 0 asks for a new DISCOVER |
| 0x14 | 16 | station serial |
| 0x28 | u8 | extension length, 0x14 |
| 0x29 | u8 | body type: 2 JSON, 3 challenge blob, 4 key exchange, 6 contact, 7 call, 8 message |
| 0x2a | u8 | packet counter, 1..255 per client |
| 0x2b | u8 | route id, one random byte per client |
| 0x2c | u8 | sub-id: the login's (echoed from the last LOGIN 200), the call counter, 1 on INFO |
| 0x39 | 2 | `00 03` |
| 0x3b | u8 | 2 on an obfuscated packet |

A response echoes the request's packet id, counter and route; the three together
pair it with its request.

Bodies:

| type | layout |
|---|---|
| 4 key exchange | `blob[0x80] \| u16 len \| blob` |
| 6 contact | `contact_id[32] \| u16 len \| data` |
| 7 call | `u32 channel \| u16 attach_len \| uuid[36] \| contact_id[32] \| u8 no_attach \| u8 0 \| attach` |
| 8 message | `u32 channel \| u16 data_len \| u16 cmd_type \| u16 sub_type \| contact_id[32] \| 4 zero \| data` |

A call attachment and a message's data are JSON text, sealed with the session key
when the header's encrypted flag is set.

## Cryptography

`rtc/crypto.py` (`RtcSignalingCrypto`). Every sealed field is AES-128-ECB with zero
padding. The key for a packet is the 16-byte secret with its tail overwritten by the
decimal of the packet id taken as a signed 32-bit integer, then cut at the first NUL
and padded back to 16 bytes. The LOGIN 401 blob uses the fixed secret
`&#%@!_eufy_anker`; everything after login uses the session key. The session key is
16 characters of `[0-9A-Za-z]`, made fresh per login and sealed for the server with
RSA-1024, PKCS#1 v1.5, exponent 65537, the modulus a 256-character hex string the
401 blob opens to. A private call's content key (16 of `[0-9A-Za-z]`) and IV (12),
and its ICE username (5 ice-chars) and password (23), are random strings. The LOGIN
key exchange is **[verified]** against eufy's server; the rest is **[app]**.

## Sequence

1. **DISCOVER** to the signaling host, header only. The 200 carries JSON
   `{"server_addr": "<ip>" | "self", "saddrs": [...], "timestamp": n}`: the server
   to log in to **[verified]**.
2. **LOGIN**, mode 2, empty body: answered **401** with a body that opens to the
   server's public key. The second LOGIN reuses the 401's packet id with a new
   counter and carries body type 4: the fresh session key sealed for the server, then
   the station identity `"<p2p_did>:<p2p_license>"` sealed with the session key. The
   **200** carries body type 6, whose `contact_id` (32 characters) names this client
   from then on **[verified]**. The session key and contact id allow a one-request
   login (body type 6, mode 0) for 23 h.

   A LOGIN without an answer is sent again: the first wait is 10 s plus 1-10 s, each
   further wait three times the previous one, at most 270 s **[app]**; the library
   gives up after four waits. A packet with bit 0 of the flags byte (0x13) set asks
   the client for a new DISCOVER; the library then logs in again with its current
   session (the one-request login, the key exchange after a 401) **[app]**.
3. **MESSAGE ping** every 3 s: channel 0, command type 2, sub type 0x66, JSON
   `{"to": "device", "account": md5("0" + user id + time), "eufy_client_dynamic_id": n,
   "content": base64({"eufy_contact_id", "eufy_network_type": 1, "eufy_app_id"})}`.
   Every MESSAGE request from the server or the device is answered 200 with its ids
   echoed **[verified]**.
4. **CALL** per channel kind, body type 7 with the call's channel, encrypted JSON
   `{"account": md5(channel + user id + time), "ftv": 20, "call_type",
   "eufy_p2p_type", "to": "device", "eufy_from_contact", "eufy_video_format",
   "eufy_network_type": 1, "eufy_app_id"}`. A kind-3 call is answered **100** with a
   TURN relay `{"addr", "port": 3478, "user", "password"}` **[verified]**; a device
   that serves the call answers **200** with its offer and `request_id`, which the
   client acknowledges with **ACK** (the call body without attachment) **[app]**.
   480 and 486 refuse the call.
5. **INFO** carries the client's answer `{"request_id", "sdp"}` and candidates
   `{"request_id", "candidate"}`; the device's INFO is answered 200 **[app]**.
6. **HANGUP** ends a call.

| kind | `call_type` | `eufy_p2p_type` | used for |
|---|---|---|---|
| 1 | `cmd` | | the command channel |
| 3 | `call` | `channel_p2p` | media, when the work protocol is not 2 |
| 4 | `call` | `file_p2p` | notifications and files |
| 6 | `scall` | `priv_p2p` | live media (the app's kind) |

A private call (kind 5, 6) has a uuid `"FF00<kind>"` plus 31 hex digits, a `token`
(the station identity sealed with the session key), an `sdp_info` and travels on a
UDP socket of its own **[app]**. `sdp_info` packs both of the client's SSRCs, its ICE
username (5 ice-chars) and password (23), a content key (16) and IV (12) and a
data-channel flag into 86 bytes; the byte layout is not known, so the library cannot
send a private call yet.

## Media plane

The device's offer for a private call is compact (`ice-u`, `ice-p`, `asc`, `vsc`,
`sg`, `sgc`); the app expands it into a full SRTP offer from a template (not known).
Media runs on one ICE connection with the CALL's TURN relay: SRTP keyed through the
SDP, RTP H.265 (payload type 97) or H.264 (99), FlexFEC (125), audio on 111 (AAC),
parameter sets, IDR slices and audio additionally encrypted inside the frames.
Commands travel as RTCP APP packets on that connection (a handler's `rtcSendRoute`
1) or over a separate data channel (0) **[app]**. `rtc/media.py` parses RTP, builds
RTCP APP packets and depacketizes H.264 (RFC 6184) and H.265 (RFC 7798); ICE, SRTP,
the in-frame decryption and the data channel are interfaces.

## Open

- the `sdp_info` byte layout and the offer template;
- the media plane implementation;
- whether a device answers a kind-3 call with an offer: a HomeBase 3 the app reaches
  over PPPP answers 100, then hangs up after about 60 s.
