# RTC signaling and the WebRTC protocol layers

The eufy app reaches some devices over its WebRTC path instead of PPPP: every device
behind a T9000, T8N00, T7000 or T8040 station, and some cameras on their own or behind a
HomeBase 3 or T8025 in a firmware window (`station.app_uses_webrtc(device_sn)` evaluates
the app's rule). `eufy_home_security.rtc` holds that path up to a running data channel:
the signaling wire format and its cryptography, the messages the client sends, the
private call's `sdp_info`, command encryption, the RTCP APP command channel, the data
channel's framing over KCP, RTP depacketizing, and the asyncio signaling client and
session that bring a station's data channel up ([Client](#client), [Session](#session)).
**No station uses them yet**, so these modules are internal and carry no public API;
devices the app reaches only over WebRTC stay skipped (`webrtc_only`). ICE needs the
optional `rtc` extra (`aioice`); everything else runs without it.

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

What the client sends is built in `rtc/signaling.py`; `rtc/client.py` runs the
sequence ([Client](#client)).

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
3. **MESSAGE ping** every 2 s: channel 0, command type 2, sub type 0x66, JSON
   `{"to": "device", "account": md5("0" + user id + time), "eufy_client_dynamic_id": n,
   "content": base64({"eufy_contact_id", "eufy_network_type": 1, "eufy_app_id"})}`
   (`ping_message`), `n` a random 30-bit id fixed for the client's lifetime **[app]**.
   Every MESSAGE request from the server or the device is answered 200 with its ids
   echoed **[verified]**, carrying the same `eufy_client_dynamic_id` (`message_answer`)
   **[app]**.
4. **CALL** per channel kind, body type 7 with the call's channel, encrypted JSON
   `{"account": md5(channel + user id + time), "ftv": 20, "call_type",
   "eufy_p2p_type", "to": "device", "eufy_from_contact", "eufy_video_format",
   "eufy_network_type": 1, "eufy_app_id"}` (`call_attachment`). A call is answered
   **100** with a TURN relay `{"turn_addr", "turn_port", "turn_user", "turn_password",
   "alt_turn_addr", "alt_turn_port"}` **[verified]**; the app uses only the primary
   relay (`media.TurnServer`) **[app]**. A device that serves a private call answers
   **200** with its own `sdp_info`, the relay again, `srflx` and `port`, sometimes
   several times in a row **[verified]**; the client acknowledges each with **ACK** (the
   call body without attachment). 480 and 486 refuse the call (`call_event`). The answer
   to a kind-5 call may carry `transport_caps` (an integer) or the same in a binary
   `pbsdp` field **[app]** (see [Session](#session)).
5. **INFO** carries ICE candidates both ways, with `request_id` first when the device's
   200 carried one (`info_payload`). On a kind-5 call the device trickles
   `{"file_candidate": "a=candidate:…", "file_candidate_num": n}` and sends each again
   about every 200 ms until acknowledged **[verified]**; the client acknowledges with
   `{"file_candidate_ack": n}` and sends its own candidates the same way **[app]**. On a
   media call they travel as `{"candidate": …}` **[verified]**. A device INFO is answered
   200; on a private call the 200 echoes the INFO's attachment **[app]**.
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

## Client

`rtc/client.py` `SignalingClient` runs the sequence on the event loop: one UDP socket per
client plus one per private call, a TCP connection only to send a CALL again. It
**[app]**:

- logs in with a stored quick-login record younger than 23 h; a 401 to it falls back to
  the key exchange within the same attempt. Each login's record goes to `on_login` for
  the consumer's cache, and the login server's record (address, port, the login's round
  trip, when it was last used or failed) to `on_server_info`; `config.merge_server_info`
  keeps a per-station list of them as the eufy app does (a report replaces the record
  with the same address; beyond 8 per server type the slowest is dropped);
- sends DISCOVER three times, 4 s apart, before giving up, and uses its answer only when
  it names an IPv4 address (a name would need a DNS lookup on the event loop);
- answers a packet with the re-discover flag with DISCOVER and a quick login;
- sends an unanswered CALL again over TCP after 5 s, three times at most, to wake a
  sleeping device;
- drops datagrams from any address but the signaling host and the login server, and
  keeps at most 64 unread events per call (the oldest dropped);
- reports the first socket error (`on_lost`); `close` hangs up open calls, closes every
  socket and fails pending requests with `SignalingError`.

Errors: `SignalingError` (`code`: 401 for a refused login), `CallRefusedError` (486 or
480, `code` None for a hang-up before the answer), `DeviceTimeoutError` for a step that
gets no answer, `ProtocolError` for an answer that does not decode. The sequence up to
an ICE-connected data channel is **[verified]** on a HomeBase 3 with a probe client; this
client has run only against the library's loopback fake (`eufy_home_security.testing.rtc`).

## Session

`rtc/session.py` `RtcSession` holds one station's link, by station serial **[app]**:

1. DISCOVER (skipped with a usable quick login), LOGIN, the ping;
2. a kind-5 CALL on channel 0 whose `sdp_info` byte 2 has bit 0 set when the station's
   kcp_type is 2 and never bit 1. The eufy app also sets bit 1 when it offers QUIC; this
   client runs KCP only;
3. the device's answer: its `sdp_info` (ICE username and password, content key, byte 2)
   and `transport_caps`. The data channel runs QUIC when bit 1 is set in both the
   client's byte 2 and `transport_caps`, else KCP; with this client's byte it is always
   KCP (a device that picked QUIC would raise `UnsupportedError`);
4. ICE as the controlled side over `aioice` (`rtc/ice.py`: UDP and IPv4 only, the call's
   TURN relay, at most 16 remote candidates), the candidates exchanged as above; the
   client's own are sent again after 0.3, 0.4, ... s (100 ms steps, 200 ms from the
   sixth) until the device acknowledges each. ICE must connect within 20 s, the eufy
   app's wait;
5. the KCP data channel over the ICE connection, framed as the answer's byte 2 says (bit
   0: the 32-byte prefix).

`start` returns once the data channel is up and otherwise raises the attempt's error
with nothing left running: `MissingDependencyError` without the `rtc` extra (before any
socket), the client's errors above, `DeviceTimeoutError` when ICE does not connect in
time, `CommunicationError` when it fails. A signaling socket error or a hang-up of the
data call during these steps ends them at once with that error (a socket error as
`CommunicationError`). After that the session reconnects by itself
when the signaling socket fails, the device hangs up the call or the data channel stops:
it waits 1 s, closes everything, waits 0.5 s and connects again, as the eufy app does. A
failed reconnect waits 1.5 s for its first three failures, then twice the previous wait,
at most 64 s (the library's back-off). `close` hangs up and closes every socket and
task, the ICE connectivity checks of a connect still running included. One leftover is
aioice's: with a TURN server in the call, a cancel while candidates are gathered (or a
TURN allocation slower than aioice's 5 s gathering bound) leaves its TURN socket to the
garbage collector. No command is sent over the channel yet.

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
keyframe flag; a lost fragment drops its NAL unit, and an access unit whose payloads pass
4 MiB is dropped whole. No media has been received from a
device; ICE for a media call, SRTP and the in-frame encryption of parameter sets, IDR
slices and audio are not part of the library yet.

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
acknowledges the client's DATA and sends its own replies as DATA **[verified]**. The
client keeps at most 256 unread DATA bodies (a newer one is dropped unacknowledged, so
the device sends it again) and runs at most 64 tasks for resends and answers (an inbound
frame that needs another is dropped).

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

The payload is an XZYH frame; a heartbeat is a bare 16-byte frame of type 0x0473. KCP
carries a message in at most 127 segments, so a message with its link header is at most
149,352 bytes at MTU 1200, and a payload behind the older header at most 65,535 bytes;
the client refuses a longer one before sending. The
device may put a 20-byte outer head before a message (`u32 0x585a5948 | u32 flags |
u32 length | u32 CRC32 | u32 offset`); the client sends none. KCP, both header
directions, the outer head and the heartbeat echo are **[verified]**; a command reply
over this channel has not been seen. The client keeps at most 256 unread messages; when
KCP has sent a segment 20 times without an acknowledgement (the peer went away) the
channel ends with `CommunicationError`. The eufy app can also run this channel over
QUIC, chosen per call as [Session](#session) says **[app]**; only KCP is implemented.

## Open

- media from a device the station serves over WebRTC (ICE, SDES-SRTP, the in-frame
  encryption) and a successful live open;
- the QUIC data channel, and the layout of the binary `pbsdp` answer field;
- a command reply on the data channel;
- the source of the command media key (the answer's `sdp_info` content key is inferred);
- this client and session against hardware (only a probe client has run the sequence);
- a station transport that uses the session, and commands over the data channel;
- which channel number the app's kind-5 CALL names (the client sends 0, as the probe
  runs did).
