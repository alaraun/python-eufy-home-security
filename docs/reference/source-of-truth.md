# Source of truth

Which source answers which question, and why the other one does not. The
measurements below come from a HomeBase 3 (T8030, fw 3.8.7.4) with two eufyCam 3
(T8160) and a T8910 motion sensor; see
[hardware-verification.md](hardware-verification.md).

## The shape

```
   UPSTREAM                          LIBRARY                        CONSUMER
 ┌──────────────────┐
 │ eufy cloud       │ identity ──┐
 │ get_devs_list    │            │   ┌────────────────────┐
 │                  │            ├──▶│ CloudDevice        │──┐
 └──────────────────┘            │   │ serial, channel,   │  │
                                 │   │ model, owner       │  │
 ┌──────────────────┐            │   └────────────────────┘  │
 │ HomeBase P2P     │ live state │                           ▼
 │ parameter dump   │            │   ┌────────────────────┐ ┌──────────────┐
 │ 0x044F           │────────────┘   │ StationState       │ │ entity LIST  │
 │                  │───────────────▶│ SubDeviceState     │ │ from the     │
 └──────────────────┘                │  .online (1131)    │ │ MODEL only   │
                                     │  .setting(key)     │ └──────┬───────┘
 ┌──────────────────┐  changes       └─────────┬──────────┘        │
 │ 0x047f · 2037    │───────────────▶          │      ▲            │
 │ FCM cloud push   │                          │      │            ▼
 └──────────────────┘                     VALUES      │      ┌──────────────┐
                                                      │      │ entity VALUE │
 ┌──────────────────┐  meaning       ┌────────────────┴───┐  │ from the     │
 │ eufy app code    │───────────────▶│ model settings +   │  │ DUMP         │
 │ (not runtime)    │                │ profile + Support  │  └──────────────┘
 └──────────────────┘                └────────────────────┘
                                        ▲
                                        │  coverage() audits, never feeds
                                        └──────────── live dump
```

**The rule:** the model's settings (the bundled per-model file, generated from the
app's code) decide *which* entities exist; the dump decides *what they read*.
Reported parameters never create entities — they only audit the settings, through
[`StationState.coverage()`](#auditing-the-settings).

## Who is authoritative for what

| Question | Source of truth | Why not the other |
|---|---|---|
| Which devices exist | cloud device list | the dump carries no serials and no device type |
| Which channel a device is on | cloud `device_channel` | the dump carries no serials; 1072 is the cross-camera tracking camera selection, not a channel map |
| Which model a device is | the serial's prefix | the dump has no type field; markers are the fallback |
| Is a **sub-device** reachable | **P2P param 1131** | the cloud's copy is a last-known snapshot |
| Is the **station** reachable | the session itself | a `StationState` exists only because a dump arrived; 1140 is not in the dump |
| Current guard mode | P2P 1224, and `0x047f` for changes, ordered by `GuardModeTracker` | the cloud push for the same change lands about 1 s later |
| Current setting value | the P2P dump's parameter; for a station setting the dump lacks, the cloud's copy, then the setting's default ([below](#where-a-station-settings-value-comes-from)) | the cloud's copy is last-known, not live |
| **Which entities to offer** | **the model's settings (`Station.settings_for`)** | a parameter block is a template, not a capability list |
| Whether a setting is a control | `Setting.writable` (its `note` says why not) | a reported value says nothing about how to write it |
| What a parameter means | the eufy app's code: thing description and handler, at generate time | never a runtime source |
| Whether a model or capability is proven | its `Support` grade | the app's code alone proves nothing on hardware |

## Why entities do not come from reported parameters

It is tempting to build entities from what a device reports. That would be wrong,
and the hardware says so plainly.

Both eufyCam 3 report whole families they cannot own — `BAT_DOORBELL_CHIME_SWITCH`,
`BAT_DOORBELL_MECHANICAL_CHIME_SWITCH`, `INDOOR_SET_CONTINUE_ENABLE`,
`INDOOR_LED_SWITCH` and the rest. An outdoor battery camera has no mechanical
doorbell chime. The T8910 motion sensor reports all ten `ALARM_DELAY_*` and
`LEAVING_DELAY_*` parameters, which are the hub's alarm policy mirrored onto every
channel, not a capability of a PIR sensor.

The two T8160 are the same model on the same station and still do not agree with
each other: channel 0 carries 1164 `GET_DELAY_ALARM` and 1201 `SET_TONE_FILE` and
channel 1 does not.

So a block is a template the station serves per channel. Generating entities from
it would put a doorbell chime switch on an outdoor camera, and would make entities
appear and disappear between dumps.

## Auditing the settings

The opposite risk is real too: the settings are keyed on the *model*, not on the
unit, so they can claim a setting a given unit never reports.
`StationState.coverage()` — and `eufy-security coverage` — compares the two
directions per block: readable settings that are reported, readable settings that
are not reported, and reported parameters no setting reads.

Read a row as a lead, never as a capability statement. Three measured reasons it
can mislead:

1. **A parameter can exist and not be served.** See the next section.
2. **Presence does not mean ownership** — the alarm delays above.
3. **A block is only what the station said that time.** An offline device may
   report a short block, so *not reported* is a question to ask of a device known
   to be `online`.

## Neither upstream source is a superset

A `get_devs_list` and a parameter dump of the same station, the same minute:

| block | cloud | P2P | cloud only | P2P only |
|---|---|---|---|---|
| T8030 station | 45 | 47 | 16 | 18 |
| T8160 channel 0 | 112 | 112 | 3 | 3 |
| T8160 channel 1 | 112 | 110 | 3 | 1 |
| T8910 channel 16 | 32 | 31 | 1 | 0 |

The station's cloud-only sixteen include 1140 (the hub's online flag),
1157/1158/1159 (`ARM_DELAY_HOME`/`AWAY`/`CUS1`), 1235 (`SET_HUB_SPK_VOLUME`), 1254
(the schedule JSON), 1256 (custom modes) and 1278 (automation data) — configuration
and policy the live dump never serves. The dump's eighteen are runtime state the
cloud has no copy of: 1072 (the cross-camera tracking camera selection), 1189 and 1190 (storage), 1216 (the hub
name), 14000 (country).

So `PARAM_QUERY_ALL` is not "every parameter the station holds", and the cloud
snapshot is not a superset either. A value missing from one may simply live in the
other. The dump is also the only local read: every `GET_*` command the app defines is
rejected by the station, and a narrowed parameter query returns nothing
([commands.md](../protocol/commands.md#get-commands-not-served-verified)). So the
station's own settings read both, as below.

## Where a station setting's value comes from

`StationState.setting(key)` reads a setting of the station itself (no target, its own
serial, or channel 255) from three sources in turn, and
`StationState.setting_source(key)` names the one that answered (`ValueSource`):

| order | source | what it holds |
|---|---|---|
| 1 | `P2P`: the parameter dump | the station's live value. It wins whenever it carries the parameter (a HomeBase 3 reports 1280 as 0 where the cloud copy says 30) |
| 2 | `CLOUD`: the device list's station entry | its `params` (1065, 1069, 1070, 1235, 1254, 1256 and the 1157-1159 mode tables on a HomeBase 3, which its dump never carries) and its `time_zone` field, read by the time-zone setting (`domain` `timezone`); a HomeBase 3 never reports 1215 |
| 3 | `APP_DEFAULT`: the setting's `default` | used only when neither source carries the parameter: the value the eufy app shows then |

`None` from `setting_source` means no value: the setting is not readable, has no
default, or a source carries the parameter in a form the setting cannot place (then no
default stands in for it). A paired device's settings read its dump block only.

The cloud copy is the list the library already fetches: it is cached with the device
list (a warm start has it without a cloud call) and replaced on every fetch of that list
(`async_discover(refresh=True)`, `EufySecurity.async_refresh_cloud_state()`, and the
hourly refresh that runs while a station is reached on demand). A station reached on
demand files the list's parameters into its state as before; they report `CLOUD`.

A write the library sends shows at once (`P2P`), also for a parameter only the cloud
carries, whose cloud copy is stale until the station uploads the change. The written
value stays until a dump reports the parameter or a later list fetch shows the cloud
value changed after the write (and not dated before it by its `update_time`); then
that cloud value wins. `StationState.cloud_param_ids` lists the ids read from the
cloud, for diagnostics.

## Freshness

| value | how it becomes current |
|---|---|
| guard mode | a `0x047f` report (the mode in force) about 1 s before the cloud push (`arming` selected, `mode` in force); both are ordered by `GuardModeTracker`, which emits one `GuardModeChanged` per change of either mode |
| alarm | P2P tone frames (`0x04b1`) and cloud alarm pushes, merged by `AlarmTracker` into one `AlarmChanged` per start and end |
| a device's own alarm | P2P siren frames (`0x04b2`) on the device's channel, or the station's alarm for a device whose alarm is the station tone (1201); one `DeviceAlarmChanged` per change of `Station.device_alarm_on` |
| any parameter | the station pushes unsolicited dumps; `Station` coalesces each completed dump into one `StationStateChanged` |
| sub-device online | the same dumps: 1131 moves with the device |
| events | P2P `2037` locally and FCM from the cloud, de-duplicated across both channels by `EventDeduplicator` |

A push is never the only source of state: a push token can stop receiving without
notice, so a held session also re-reads the dump on a schedule (`PROBE_EVERY`, 300 s).

## Grades

Every model (`DeviceModel`), every capability of a profile and every event field the
library interprets carries `Support` with its provenance. Settings carry none: they
come from the app's code, and [hardware-verification.md](hardware-verification.md) records the ones proven on
hardware.

| grade | means | what a consumer may do |
|---|---|---|
| *verified* | proven on hardware — a live capture, or a write plus read-back | offer it |
| *declared* | present in the app's own code or enums, unproven here | offer a control only behind an explicit opt-in |
| *unknown* | seen but not understood, or known not to work | never offer a control; a read-only value may be shown, off by default |

A *verified* entry must have a row in
[hardware-verification.md](hardware-verification.md); `tests/devices` fails if one
does not.
