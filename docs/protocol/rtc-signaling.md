# RTC signaling and the WebRTC protocol layers

The eufy app reaches some devices over its WebRTC path instead of PPPP: every device
behind a T9000, T8N00, T7000 or T8040 station, and some cameras on their own or behind a
HomeBase 3 or T8025 in a firmware window (`station.app_uses_webrtc(device_sn)` evaluates
the app's rule). `eufy_home_security.rtc` holds the protocol layers of that path: the
signaling wire format and its cryptography, the messages the client sends, the private
call's `sdp_info`, command encryption, the RTCP APP command channel, the data channel's
framing over KCP, and RTP depacketizing. They are pure codecs and small state machines
over callbacks; **nothing opens a socket and no station uses them yet**, so these
modules are internal and carry no public API. Devices the app reaches only over WebRTC
stay skipped (`webrtc_only`).

Tags as in [README.md](README.md#verification-markers): **[verified]** for what ran
against eufy's signaling server and a HomeBase 3 (T8030, fw 3.8.7.4), **[app]** for what
follows the eufy app without a hardware run.

## Inputs

From the station's device-list entry **[app]**: `signaling_servers` (the first bare
IPv4 entry is the host; a domain entry is never resolved), `p2p_did`, `p2p_license`,
`main_sw_version` (dots removed, as an integer) and `webrtc_sdk_version`. From the
account: the user id and an install-wide app id. `rtc/config.py` `RtcConfig.from_device`
builds the config; an entry without a serial, DID, license or IPv4 host has none, and
`missing_inputs` names what is missing.

Per station prefix the app also decides **[app]**:

| decision | rule (`rtc/config.py`) |
|---|---|
| data-channel KCP framing | `data_channel_kcp_type`: kcp_type 2 (32-byte datagram prefix) unless the prefix is T8223, T8224, T8030 or T8025 below `webrtc_sdk_version` x.1.3, or T8N00 or T9000 below x.1.2 (the first component is not compared); an unreadable version means 1 for T8030 and T8025, else 2 |
| sealed commands | `commands_encrypted`: AES-GCM from firmware 4.1.0.0 on a T9000, 1.0.8.9-1.1.9.9 and from 1.2.0.9 on a T8N00, 3.7.4.3 on a T8030, 3.3.7.6 on a T8223, 3.4.7.6 on a T8224, 1.0.2.1 on a T8172; never on a T8025; always on any other prefix |

## Transport

UDP to port 5062 on the signaling host **[verified]**. Every datagram is
obfuscated: `u16 8 | u16 len+pad | key[16] | u8 pad | u8 random | packet XOR key |
pad random bytes`, the key fresh per datagram, `pad` random below `0x3d3 - len` (none
for a packet of 978 bytes or more). A receiver also takes a plain packet.

TCP to 5061 or 15061 carries plain packets back to back, transport flag 0x3b = 0; a
receiver reads 0x29 bytes, then the rest of the header (extension length at 0x28) and
the body (`codec.StreamDecoder`) **[app]**. The app sends a CALL again over TCP when no
answer follows it.

## Packet

A 60-byte little-endian header, then the body (`rtc/codec.py`):

| offset | size | field |
|---|---|---|
| 0x00 | u16 | tag, 3 |
| 0x02 | u16 | CRC-16/XMODEM over 0x04..0x3c and the body |
| 0x04 | u16 | message type: 1 LOGIN, 2 CALL, 3 ACK, 4 INFO, 5 HANGUP, 6 UPDATE, 7 WAKEUP, 8 REPORT, 9 DISCOVER, 10 PING, 11 MESSAGE, 12 LOGOUT, 13 CONTROL |
| 0x06 | u16 | body length, at most 0x1000 |
| 0x08 | u32 | packet id: the sender's time in seconds |
| 0x0c | u8 | protocol version, 7 |
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
pair it with its request. Bodies:

| type | layout |
|---|---|
| 4 key exchange | `blob[0x80] \| u16 len \| blob` |
| 6 contact | `contact_id[32] \| u16 len \| data` |
| 7 call | `u32 channel \| u16 attach_len \| uuid[36] \| contact_id[32] \| u8 no_attach \| u8 0 \| attach` |
| 8 message | `u32 channel \| u16 data_len \| u16 cmd_type \| u16 sub_type \| contact_id[32] \| 4 zero \| data` |

A call attachment and a message's data are JSON text, sealed with the session key
when the header's encrypted flag is set.

## Cryptography

`rtc/crypto.py`. Every sealed field is AES-128-ECB with zero padding. The key for a
packet is the 16-byte secret with its tail overwritten by the decimal of the packet id
taken as a signed 32-bit integer, then cut at the first NUL and padded back to 16
bytes. The LOGIN 401 blob uses the fixed secret `&#%@!_eufy_anker`; everything after
login uses the session key. The session key is 16 characters of `[0-9A-Za-z]`, made
fresh per login and sealed for the server with RSA-1024, PKCS#1 v1.5, exponent 65537,
the modulus a 256-character hex string the 401 blob opens to. A private call's content
key (16 of `[0-9A-Za-z]`) and IV (12), and its ICE username (5 ice-chars) and password
(23), are random strings. The LOGIN key exchange is **[verified]**; the rest is **[app]**.

## Sequence

What the client sends is built in `rtc/signaling.py`; the client that runs the sequence
is not part of the library yet.

1. **DISCOVER** to the signaling host, header only. The 200 carries JSON
   `{"server_addr": "<ip>" | "self", "saddrs": [...], "timestamp": n}`: the server to
   log in to (`DiscoverAnswer`) **[verified]**.
2. **LOGIN**, mode 2, empty body: answered **401** with a body that opens to the
   server's public key. The second LOGIN reuses the 401's packet id with a new counter
   and carries body type 4: the fresh session key sealed for the server, then the
   station identity `"<p2p_did>:<p2p_license>"` sealed with the session key. The
   **200** carries body type 6, whose `contact_id` (32 characters) names this client
   from then on **[verified]**. The session key and contact id allow a one-request login
   (body type 6, mode 0) for 23 h (`QuickLogin`) **[app]**. A LOGIN without an answer
   is sent again: the first wait is 10 s plus 1-10 s, each further wait three times the
   previous one, at most 270 s (`login_retry_delays`) **[app]**.
3. **MESSAGE ping** every 3 s: channel 0, command type 2, sub type 0x66, JSON
   `{"to": "device", "account": md5("0" + user id + time), "eufy_client_dynamic_id": n,
   "content": base64({"eufy_contact_id", "eufy_network_type": 1, "eufy_app_id"})}`
   (`ping_message`) **[app]**. Every MESSAGE request from the server or the device is
   answered 200 with its ids echoed (`message_answer`) **[verified]**.
4. **CALL** per channel kind, body type 7 with the call's channel, encrypted JSON
   `{"account": md5(channel + user id + time), "ftv": 20, "call_type",
   "eufy_p2p_type", "to": "device", "eufy_from_contact", "eufy_video_format",
   "eufy_network_type": 1, "eufy_app_id"}` (`call_attachment`). A call is answered
   **100** with a TURN relay `{"turn_addr", "turn_port", "turn_user", "turn_password",
   "alt_turn_addr", "alt_turn_port"}` **[verified]**; the app uses only the primary
   relay (`media.TurnServer`) **[app]**. A device that serves a private call answers
   **200** with its own `sdp_info`, the relay again, `srflx` and `port` **[verified]**;
   the client acknowledges with **ACK** (the call body without attachment). 480 and
   486 refuse the call (`call_event`).
5. **INFO** carries ICE candidates both ways: the device trickles
   `{"candidate": "a=candidate:…"}` **[verified]**, the client sends
   `{"candidate": "candidate:…"}`, with `request_id` first when the device's 200
   carried one (`info_payload`); the device's INFO is answered 200 **[app]**.
6. **HANGUP** ends a call.

| kind | `call_type` | `eufy_p2p_type` | used for |
|---|---|---|---|
| 1 | `cmd` | | the command channel |
| 3 | `call` | `channel_p2p` | media, when the work protocol is not 2 |
| 4 | `call` | `file_p2p` | notifications and files |
| 5 | `scall` | `priv1` | the data channel |
| 6 | `scall` | `priv_p2p` | live media |

A private call (kind 5, 6) has a uuid `"FF00<kind>"` plus 31 hex digits
(`private_call_uuid`), a `token` (the station identity sealed with the session key) and
an `sdp_info`, and travels on a UDP socket of its own **[app]**. `sdp_info` is an
86-byte little-endian struct (`rtc/sdp.py` `SdpInfo`): 2 reserved, a data-channel flag
(set for kcp_type 2), two bytes set to 1, a device-config byte, the ICE username (an
8-byte field) and password (24), a content key (20) and IV (20), then the audio and
video SSRCs as u32; base64 in the encrypted attachment. The device answers kind 5 and
kind 6 with an `sdp_info` of the same shape, content key 16 bytes and IV 12
**[verified]**.

## Media plane

The app builds a remote SDP from a fixed template for the event path (`sdp.py`
`expand_offer`), filling in the device's ICE credentials and SSRCs. The template is
**SDES, no DTLS**: `a=setup:actpass` and one constant
`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<constant>` line for both directions, audio
and video bundled with RTCP muxed **[app]**.

Media is RTP H.265 (payload type 97) or H.264 (99), FlexFEC (125), audio on 111 (AAC)
**[app]**. `rtc/media.py` parses RTP (CSRCs, extension, padding), tells RTCP apart
(second byte 192-223, RFC 5761), builds and parses RTCP APP packets, and depacketizes
H.264 (RFC 6184, single NAL units, STAP-A, FU-A) and H.265 (RFC 7798 without DONL:
single NAL units, aggregation and fragmentation units) into Annex B access units with a
keyframe flag; a lost fragment drops its NAL unit. No media has been received from a
device; ICE, SRTP and the in-frame encryption of parameter sets, IDR slices and audio
are not part of the library yet.

## Command encryption

`rtc/command.py` **[app]**. Commands and the station's replies and notifications are
AES-128-GCM with the AAD `eufy security` under the call's media key, the station's
`crypto_key`. Where that key comes from is **[open]**: a HomeBase 3's CALL 200 carries no
`crypto_key`, only its `sdp_info`, so the first 16 bytes of that answer's content key
are the inferred key (`media_key`). A command is the XZYH frame with header
byte 0x0a set to 10, byte 0x0d to 1 and the length to the new body, the body replaced
by `tag[16] | iv[12] | u32 counter | ciphertext`; the counter counts the call's commands
and is not authenticated. A reply carries the same wrapper after its frame header, a
notification `tag | iv | ciphertext`. A station keeps its previous key usable across a
key change, so the client tries the current key, then the previous one.

## Command channel

Commands travel in RTCP APP packets with name `AZWC` and subtype 0, sent raw over ICE
(not SRTCP, as there is no DTLS) with the client's audio SSRC. Inside each packet is a
frame of a small reliable protocol (`rtc/rtcp_channel.py`), all fields little-endian:

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `0x12345678` |
| 4 | 4 | sequence number |
| 8 | 1 | type: 1 DATA, 2 ACK, 4 heartbeat, 8 MTU request, 9 MTU response |
| 12 | 4 | body length |
| 16 | 4 | checksum: byte sum of bytes 0-15 and the body (not checked for 8 and 9) |
| 20 | n | body |

A DATA frame is acknowledged with an ACK of its sequence number and delivered once
(the last 1000 sequence numbers are remembered); an unacknowledged DATA is sent again
after 100, 200 and 500 ms, five resends at most; an MTU request is answered with an MTU
response; a heartbeat (sequence 0) goes out every second **[app]**. A HomeBase 3
acknowledges the client's DATA and sends its own replies as DATA **[verified]**.

## Data channel

The media of a kind-5 call is a KCP connection over its own ICE connection, on which the
device is the ICE-controlling side **[verified]**. KCP runs with conv 1, nodelay, fast
resend after 2, no congestion window, windows of 512 and MTU 1200 **[verified]**
(`rtc/data_channel.py`, over the KCP port in `rtc/_ikcp.py`, MIT). For a kcp_type-2
peer every datagram starts with a 32-byte prefix `u32 stream | u32 1 | 24 zero`, stream
1 for commands and 3 for downloads; kcp_type 1 sends bare segments. Inside KCP every
message starts with a link header:

| offset | size | field (24-byte header; 20-byte older header) |
|---|---|---|
| 0 | u16 | version, 9 |
| 2 | u16 | header length, 24 (20) |
| 4 | u32 | payload length (u16 in the older header) |
| 8 (6) | u8 | 1 |
| 12 (8) | u32 | time in seconds |
| 16 (12) | u8 | message type: 1 command, 2 file data, 3 notification, 4 playback, 0x63 heartbeat |
| 20 (16) | u32 | sequence number |

The payload is an XZYH frame; a heartbeat is a bare 16-byte frame of type 0x0473. The
device may put a 20-byte outer head before a message (`u32 0x585a5948 | u32 flags |
u32 length | u32 CRC32 | u32 offset`); the client sends none. KCP, both header
directions, the outer head and the heartbeat echo are **[verified]**; a command reply
over this channel has not been seen. The eufy app can also run this channel over QUIC,
chosen per call from the device's answer **[app]**; only KCP is implemented, and which
answer field picks QUIC is **[open]**.

## Open

- media from a device the station serves over WebRTC (ICE, SDES-SRTP, the in-frame
  encryption) and a successful live open;
- the QUIC data channel and the answer field that selects it;
- a command reply on the data channel;
- the source of the command media key (the answer's `sdp_info` content key is inferred);
- the client that runs the sequence, and a station transport that uses it.
