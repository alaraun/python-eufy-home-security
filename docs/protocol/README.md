# eufy Security protocol reference

How `eufy-home-security` talks to a eufy Security **HomeBase 3 (T8030)** and the
cameras paired to it: what goes on the wire and why. This is the reference for
maintainers and for anyone porting the client. For the library API, see the
how-to and reference docs.

## Files

| file | covers |
|---|---|
| [cloud.md](cloud.md) | eufy_mega login, request signing and body encryption, login challenges, the device list, the station owner's id, the security realm and `get_ciphers`, firmware OTA, error codes, caching and rate limits |
| [p2p-transport.md](p2p-transport.md) | PPPP datagrams, LAN discovery, punch, keepalive, DRW chunks and ACKs, the XZYH frame header and its subheader |
| [session-crypto.md](session-crypto.md) | the static serial key, the CONN_INIT and ECIES handshake, AES-GCM command and broadcast frames, how each frame picks its cipher, legacy ECB scalar frames |
| [commands.md](commands.md) | the DeviceMsgBean envelope, arming and how to confirm it, writing settings, the parameter dump, the event database, image fetch, result codes |
| [events.md](events.md) | local P2P pushes, parameter-change pushes, guard-mode announcements and ordering, liveness, cloud FCM push, P2P vs cloud |
| [media.md](media.md) | still images, live stream open, video/audio frame headers, keyframe decryption, recording download, what is proven |

## The layers

A client starts in the **cloud**. It logs in to eufy_mega with e-mail and password,
reads the device list (which gives the station serial, P2P DID, LAN address and the
**owner's user id**), and fetches the station's **cipher 40** private key from the
separate security realm. That happens once and is cached. Everything after it is
local. The client finds the station on the LAN with a PPPP `LAN_SEARCH`, punches a
UDP session, and keeps it up with `ALIVE`. Application data travels as **DRW**
chunks on numbered channels. Reassembled in order, each channel is a byte stream of
**XZYH** frames. The first frame exchange (**CONN_INIT**) is wrapped under a static
key derived from the serial and DID. It carries an ECIES blob that unwraps, with the
cipher 40 key, to a per-connection **AES-256-GCM session key**. Over that session
the client sends **commands** as JSON (arm, settings, parameter dump, event
database, image, media). The station answers with results, **parameter dumps** and
unsolicited **event pushes**, and each frame names its own cipher (GCM or legacy
ECB). **Media** (live video, recordings) comes back on its own channel with a
separate RSA/AES-128 keyframe scheme. Independently of all of this, **cloud push**
(Firebase Cloud Messaging) delivers the same events from the eufy backend. On fw
3.8.6.0 it is the only channel that announces a guard-mode change made from the app;
on fw 3.8.7.4 the station announces app, schedule and P2P changes locally too (`0x047F`).

```
e-mail + password
  └─ cloud (HTTPS, MegaCrypto)  login → device list → owner id → cipher key (id from CONN_INIT) [once, cached]
       └─ P2P (UDP, PPPP)       LAN_SEARCH → PUNCH → ALIVE / DRW / DRW_ACK
            └─ XZYH frames      per-channel byte stream of typed records
                 └─ crypto      CONN_INIT (static key + ECIES) → GCM session key
                      ├─ commands   DeviceMsgBean JSON (0x0546) · legacy ECB scalars
                      ├─ events     0x0547 cmd 2037 · 0x044F param dumps · 0x047F guard notify
                      └─ media      ch1 0x0514 / 0x0515, RSA-wrapped AES-128 keyframe prefix
  └─ cloud push (FCM)           Android registration → token on eufy → data messages
```

## What the cloud is needed for

The cloud is a **bootstrap**, not a control path: the library has no cloud command
path, and once the items below are cached a HomeBase 3 and its cameras are operated
over the LAN alone **[verified]** (a warm start makes no cloud call; a cloud throttle
or outage does not touch the P2P sessions). A standalone battery camera is the
exception, because it can only be woken through eufy's servers.

| item | needed for | lifetime | local alternative |
|---|---|---|---|
| login session (`auth_token`, ECDH identity) | only to fetch the items below | weeks | none needed once the rest is cached |
| device list (serial, DID, `local_ip`, channels) | building a `Station` per HomeBase | until a device is added or removed | the cached list; `LAN_SEARCH` returns the DID and address as well |
| owner `admin_user_id` | every P2P command (any other id is acknowledged and dropped) | until the sharing changes | cached; a station push also carries it (`rec_content[].account`) |
| `ecc_private_key` of the cipher the station names (40 on a HomeBase 3, 98 on a T8170) | unwrapping the CONN_INIT session key: **the hard dependency** | until the station is re-bound **[open]** | **none.** The station encrypts the session key to the account's P-256 key from pairing; the private half exists only in eufy's cloud. Cached for good; a rotation costs one fetch |
| DSK and the rendezvous servers (`app_conn`) | waking a sleeping battery station ([p2p-transport.md](p2p-transport.md#waking-a-battery-station-verified)) | ~1 h, per client | none (see below) |
| cloud `params` snapshot | the state of a sleeping camera without waking it | refreshed hourly | wake the camera, which needs the cloud anyway |
| cloud push (FCM) | a guard-mode change as it happens | install-scoped | on fw 3.8.7.4 the station announces app, schedule and P2P changes itself (`0x047F`, [events.md](events.md#guard-mode-announcements)); keypad changes are untested. On fw 3.8.6.0 app changes reach only the push |

**HomeBase 3 and its paired cameras.** After the bootstrap (login, device list, owner
id, cipher 40) discovery, the handshake, arming, settings, parameter dumps, the event
database, stills, live video and recording download are LAN-only. The cloud is
contacted again only for a cipher key that stops unwrapping, a sharing change or a new
device.

**Standalone battery camera (T8170).** Asleep, it answers no `LAN_SEARCH`; its only
standing link is to eufy's PPPP rendezvous servers, and the wake needs a fresh DSK from
the cloud plus UDP to those servers. The data path then punches back over the LAN
without a relay, so operation is local but each wake-hour costs a cloud call. MQTT is
not a channel: the broker grants no camera topic **[verified]**.

**The station's own cloud traffic** (parameter uploads, pushes, relay registration,
time, firmware) is outside the client's control. With the station offline the app, the
push channel and the cloud `params` snapshot are unavailable.

## Verification markers

Behaviour is tagged with the strength of its evidence:

| tag | meaning |
|---|---|
| **[verified]** | verified on HomeBase 3 (T8030, main fw 3.8.6.0 and/or 3.8.7.4) with eufyCam 3 (T8160) cameras, from a live session or a decoded capture |
| **[app]** | derived from the eufy Security app (code and resources) but not exercised on hardware |
| **[open]** | seen but not understood, or not established |

Untagged statements in a section inherit that section's tag.

## Glossary

| term | meaning |
|---|---|
| **DID** | P2P device id, `PREFIX-NUMBER-SUFFIX` (e.g. `EUPRAMA-123456-ABCDE`). The cloud device list carries it as `p2p_did`, and the station announces it as a 20-byte struct during discovery. Part of the static key. |
| **DRW** | "Data Read/Write", the PPPP datagram (`0xD0`) that carries application bytes as indexed chunks on a channel. Every chunk is acknowledged with `DRW_ACK` (`0xD1`). |
| **DRW channel** | A logical stream inside one PPPP session. 0 = commands and their results, 1 = media, 2 = parameter dumps and guard-mode notifies. Do not confuse it with a sub-device channel. |
| **channel** (sub-device) | A paired device's slot on its station: `device_channel` in the cloud device list, `mChannel` in a command, `channel` in an event push, `CameraNN` in storage paths. 255 addresses the station itself. Slots are not contiguous (e.g. 0, 1, 16). |
| **dev_type** | The field that groups the parameter dump. It equals the sub-device channel (255 = station). It is **not** the cloud `device_type` model code — except on a standalone device, which labels its one block with its `device_type` (48 on a T8170). The GCM subheader has a byte of the same name. |
| **device_type** | The cloud model code: 18 for a HomeBase 3 in the device list (event records for the same station say 43), 19 for eufyCam 3. |
| **owner account_id** | The station owner's cloud user id (`member.admin_user_id` in the device list). Every P2P command must carry it, and the cipher 40 fetch must name it. For a shared member it is **not** the logged-in user's id. A command with any other id is acknowledged and then silently dropped. |
| **cipher 40** | The cloud cipher record (`cipher_id` 40) whose `ecc_private_key` (P-256) unwraps the P2P session key from CONN_INIT on a HomeBase 3. The station names the id in CONN_INIT (a T8170 names 98); the key belongs to the id under the owner's account and is served to the owner or a member who names the owner ([cloud.md](cloud.md)). |
| **static key** | 16 ASCII bytes `serial[-7:] + did_text[7:16]` (for `EUPRAMA-123456-ABCDE`: `"-123456-A"`). The AES-128-ECB key for CONN_INIT, legacy scalar commands and ECB-tagged station frames. |
| **session key** | 32 ASCII bytes unwrapped from CONN_INIT. The AES-256-GCM key for commands and GCM-tagged station frames, in both directions. One per connection. |
| **CommandType** | The app's command number. XZYH frame types reuse the same numbering, so `0x0546` = 1350, `0x044F` = 1103. |
| **openudid** | A 16-hex per-install id sent to the cloud. Mint one per install, persist it, and never reuse another install's. |

## Where the code lives

| layer | module |
|---|---|
| cloud envelope, login, devices, ciphers | `src/eufy_home_security/cloud/crypto.py`, `cloud/api.py`, `cloud/const.py`, `cloud/models.py` |
| PPPP datagrams, the UDP transport and LAN discovery | `src/eufy_home_security/p2p/pppp.py`, `p2p/transport.py`, `p2p/did.py`, `p2p/discovery.py` |
| XZYH framing | `src/eufy_home_security/p2p/xzyh.py` |
| session crypto | `src/eufy_home_security/p2p/crypto.py` |
| command builders and decoders | `src/eufy_home_security/p2p/messages.py`, `p2p/params.py`, `p2p/notify.py`, `p2p/alarm.py`, `p2p/mode_actions.py`, `p2p/storage_info.py` |
| media | `src/eufy_home_security/p2p/media.py` |
| session orchestration | `src/eufy_home_security/p2p/session.py` |
| cloud push registration and decoding | `src/eufy_home_security/push/fcm.py`, `push/decode.py`, `push/const.py` |
| command names and the per-model settings | `src/eufy_home_security/devices/` (see `docs/reference/devices.md`, `docs/reference/models-schema.md`) |
