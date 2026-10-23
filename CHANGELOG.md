# Changelog

All notable changes to this project. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a minor release may change the
API. From 0.1.0 on, release-please writes the entries from the conventional commits.

## [0.4.6](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.5...v0.4.6) (2026-10-23)


### Bug Fixes

* **cloud:** list devices per house as the eufy app does, so a home shared with Share Home is served ([issue 45](https://github.com/alaraun/homeassistant-eufy-home-security/issues/45)) ([d1776de](https://github.com/alaraun/python-eufy-home-security/commit/d1776de65565be0e67248ca32023428e6d2806f2))
* **devices:** allow P2P live view of a HomeBase 3's T8223/T8224 outside the eufy app's WebRTC firmware range ([issue 108](https://github.com/alaraun/homeassistant-eufy-home-security/issues/108)) ([e0587e8](https://github.com/alaraun/python-eufy-home-security/commit/e0587e88499a00b532f9fef9c30885aebb454dad))
* **devices:** decide WebRTC or P2P for every device as the eufy app does ([e94ffab](https://github.com/alaraun/python-eufy-home-security/commit/e94ffab48fa9633d601c14e41b80927ea2d2237d))
* **devices:** take each model's kind from the eufy app's product category, so the eufyCam S3 Pro (T8162) and eight other models are recognised ([issue 123](https://github.com/alaraun/homeassistant-eufy-home-security/issues/123)) ([fd6dec7](https://github.com/alaraun/python-eufy-home-security/commit/fd6dec760d4293e09fdd557386fbe93c66fedc88))
* **p2p:** read RSA command results as the eufy app does ([issue 114](https://github.com/alaraun/homeassistant-eufy-home-security/issues/114)) ([0e3a2fc](https://github.com/alaraun/python-eufy-home-security/commit/0e3a2fc9ac63c14c6b5588dc6033baeecb6d4fbf))

## [0.4.5](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.4...v0.4.5) (2026-10-22)


### Bug Fixes

* **p2p:** take command receipts under any encryption on RSA sessions, as the eufy app does ([issue 114](https://github.com/alaraun/homeassistant-eufy-home-security/issues/114)) ([c22df81](https://github.com/alaraun/python-eufy-home-security/commit/c22df814dfde6d0930fb1c7a3cbdb471bfc06035))

## [0.4.4](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.3...v0.4.4) (2026-10-21)


### Bug Fixes

* **p2p:** take station state (settings, guard mode, alarms) under any encryption, as the eufy app does ([issue 114](https://github.com/alaraun/homeassistant-eufy-home-security/issues/114)) ([66878e3](https://github.com/alaraun/python-eufy-home-security/commit/66878e3e790190419e70467ff85df6a714bbe2a8))

## [0.4.3](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.2...v0.4.3) (2026-10-21)


### Features

* **history:** say what the history held when a camera image lookup finds nothing ([issue 107](https://github.com/alaraun/homeassistant-eufy-home-security/issues/107)) ([99237df](https://github.com/alaraun/python-eufy-home-security/commit/99237df2e26e02220b31d624a9419513bcacdcd3))


### Bug Fixes

* **cloud:** answer a login verification code inside the pending login ([issue 19](https://github.com/alaraun/homeassistant-eufy-home-security/issues/19)) ([83dd8fa](https://github.com/alaraun/python-eufy-home-security/commit/83dd8fae585e33c492a5e7df6eb982c35d136509))
* **push:** decode eufy-obfuscated push pictures (V1/V2), name V8 ([issue 107](https://github.com/alaraun/homeassistant-eufy-home-security/issues/107)) ([a27f1c1](https://github.com/alaraun/python-eufy-home-security/commit/a27f1c15fa2a46d06c0ed5f9331cc164f5f86f37))

## [0.4.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.1...v0.4.2) (2026-10-19)


### Features

* **cloud:** face picture of a detection push ([2b94775](https://github.com/alaraun/python-eufy-home-security/commit/2b9477500b9b5750d5c2a37a3916eca41dfde229))


### Bug Fixes

* **events:** merge the pushes of one detection and admit an upgraded kind ([2b94775](https://github.com/alaraun/python-eufy-home-security/commit/2b9477500b9b5750d5c2a37a3916eca41dfde229))
* **push:** classify a detection push as the eufy app does ([2b94775](https://github.com/alaraun/python-eufy-home-security/commit/2b9477500b9b5750d5c2a37a3916eca41dfde229))

## [0.4.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.4.0...v0.4.1) (2026-10-19)


### Features

* **p2p:** open a 1700 live stream behind a HomeBase 2 or 3 (T8600, T84xx and other Wi-Fi cameras whose handler sends it there) ([a19438a](https://github.com/alaraun/python-eufy-home-security/commit/a19438a3f93cf42004f10f11af594fad7b447b27))
* **station:** `Station.local_events` says whether a station pushes its cameras' detections over the LAN; a HomeBase 2 is graded unknown, its detections need cloud push ([47f74e2](https://github.com/alaraun/python-eufy-home-security/commit/47f74e2d8f8d9bb989f5442e2cc78c4b9f0c1f04))


### Bug Fixes

* **devices:** bundle the T8210C, T8510P and T8520P settings and live opens ([#112](https://github.com/alaraun/python-eufy-home-security/issues/112)) ([6a0f6b5](https://github.com/alaraun/python-eufy-home-security/commit/6a0f6b5e36e0873ff5116875dc1a3b0e2b0408ec))
* **devices:** the T8161's local event push is graded unknown, not declared ([47f74e2](https://github.com/alaraun/python-eufy-home-security/commit/47f74e2d8f8d9bb989f5442e2cc78c4b9f0c1f04))
* **p2p:** a live open on an extra session sends the open it was asked for ([a19438a](https://github.com/alaraun/python-eufy-home-security/commit/a19438a3f93cf42004f10f11af594fad7b447b27))
* **p2p:** a refused 1700 live open fails at once instead of waiting for the first frame ([a19438a](https://github.com/alaraun/python-eufy-home-security/commit/a19438a3f93cf42004f10f11af594fad7b447b27))

## [0.4.0](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.17...v0.4.0) (2026-10-15)


### ⚠ BREAKING CHANGES

* schedule slots that run to midnight read as ending at 00:00 (the stored 23:59 round-trips unchanged)
* cross-camera tracking needs at least two cameras, as the eufy app requires
* the guard-mode write is refused on station models graded unknown (T8N00, T9000, models without app data)
* arming-group updates send the name and every member each time (the cloud refuses one alone); EufyCloudApi.async_update_arming_group takes both
* async_set_guard_mode refuses a custom mode the station does not define; Geofencing is never a settable mode
* a motion sensor's React to motion (motion_sensor_respond) is on while action bit 32 is clear, as in the eufy app; turning it off also turns off its notification and HomeBase alarm
* per-mode entry and exit delays take only the eufy app's choices (MODE_DELAY_CHOICES: 0, 15, 30, 45, 60, 180, 300 s)
* the keypad password status is read-only
* set_alarm_type is no longer a setting: it sounds the HomeBase (see Station.async_trigger_alarm)
* sub-device serials come from the cloud device list only; parameter 1072 is the cross-camera tracking selection (SubDeviceState.serial_source "param_1072", SUB_DEVICE_SERIALS_ORDER_EVIDENCE and ParamDump.sub_device_serials removed)

### Features

* AlarmChanged carries when it was seen and the push's own time ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* arming groups (the eufy app's Group Control) ([#94](https://github.com/alaraun/python-eufy-home-security/issues/94)) ([fbacd16](https://github.com/alaraun/python-eufy-home-security/commit/fbacd1697e9445486d3e193c651e39603f93a0f8))
* arming-group activations are recorded under the account's profile nickname ([05dbb4c](https://github.com/alaraun/python-eufy-home-security/commit/05dbb4cb1d0f47ad040713dcdfb429101d62af95))
* ArmingGroupLog.created_at; guard-mode labels come from one table (GUARD_MODE_LABELS) ([d00a1c2](https://github.com/alaraun/python-eufy-home-security/commit/d00a1c2d51fb39f81d9f5982136c34edd417c60e))
* async_set_guard_mode refuses a custom mode the station does not define; Geofencing is never a settable mode ([d00a1c2](https://github.com/alaraun/python-eufy-home-security/commit/d00a1c2d51fb39f81d9f5982136c34edd417c60e))
* bulk per-mode table write and action flag labels ([4dc961d](https://github.com/alaraun/python-eufy-home-security/commit/4dc961d830440915e3026f1ea31af58421bb2bbd))
* codecs for HomeBase mode list, schedule, stored mode tables and cross-camera selection ([#93](https://github.com/alaraun/python-eufy-home-security/issues/93)) ([b728765](https://github.com/alaraun/python-eufy-home-security/commit/b7287657623160a293315b5ed29a1dda83dea576))
* cross-camera tracking names the devices it can follow; paired doorbells can be chosen ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* errors list every device they name in device_sns ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* every setting carries a UI section ([#95](https://github.com/alaraun/python-eufy-home-security/issues/95)) ([0bbbe57](https://github.com/alaraun/python-eufy-home-security/commit/0bbbe57837fcbb784856ed1f8697c630aea28d5a))
* export Schedule, ScheduleSlot, Weekday and ModeTable from the package root ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* HomeBase configuration writes: custom modes, schedule and its default mode, cross-camera cameras and groups ([d00a1c2](https://github.com/alaraun/python-eufy-home-security/commit/d00a1c2d51fb39f81d9f5982136c34edd417c60e))
* per-mode entry and exit delays take only the eufy app's choices (MODE_DELAY_CHOICES: 0, 15, 30, 45, 60, 180, 300 s) ([d00a1c2](https://github.com/alaraun/python-eufy-home-security/commit/d00a1c2d51fb39f81d9f5982136c34edd417c60e))
* per-model station configuration support (config_support) ([c69663d](https://github.com/alaraun/python-eufy-home-security/commit/c69663d139deaabf87bd827ae95d7521d86da9f5))
* pro-alarm stations (T8020, T8023, T8024, T8026) read, write and confirm their mode tables as the eufy app does ([534621a](https://github.com/alaraun/python-eufy-home-security/commit/534621ac9ad94aa058aa7f477417c8a0c8e978c2))
* schedule slots that run to midnight read as ending at 00:00 (the stored 23:59 round-trips unchanged) ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* setting existence, error device serial, alarm-affecting flags, cross-camera seconds, alarm state ([#103](https://github.com/alaraun/python-eufy-home-security/issues/103)) ([3eb31cb](https://github.com/alaraun/python-eufy-home-security/commit/3eb31cbb330f7c2734bcea3082fa3d8e90bd5c1a))
* setting names are in sentence case, as Home Assistant names entities ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))
* station configuration read model (modes, mode tables, schedule, cross-camera) ([#97](https://github.com/alaraun/python-eufy-home-security/issues/97)) ([127f5d3](https://github.com/alaraun/python-eufy-home-security/commit/127f5d3764d6b754d174796c89f8c69312684b01))
* station restart and sound/stop alarm ([#100](https://github.com/alaraun/python-eufy-home-security/issues/100)) ([430e39c](https://github.com/alaraun/python-eufy-home-security/commit/430e39cf34faa7e320a4a23591bb9e68f254e412))
* station settings read from the P2P dump, then the cloud device list, then the app default (StationState.setting_source) ([3f99ddf](https://github.com/alaraun/python-eufy-home-security/commit/3f99ddf3a3995074e1ad64635b895dc4fd22335b))
* **testing:** seed a station's mode list and schedule with typed helpers ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* the arming-group models are exported from the package root ([05dbb4c](https://github.com/alaraun/python-eufy-home-security/commit/05dbb4cb1d0f47ad040713dcdfb429101d62af95))
* the cloud device list is refreshed hourly for every station, and at start when it carries no station parameters ([3f99ddf](https://github.com/alaraun/python-eufy-home-security/commit/3f99ddf3a3995074e1ad64635b895dc4fd22335b))
* the guard-mode write is refused on station models graded unknown (T8N00, T9000, models without app data) ([534621a](https://github.com/alaraun/python-eufy-home-security/commit/534621ac9ad94aa058aa7f477417c8a0c8e978c2))
* working mode carries the eufy app's names (Standard, Performance (beta)) and is marked advanced (Setting.advanced) ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))


### Bug Fixes

* a mode-table write right after another configuration write is not refused as stale ([534621a](https://github.com/alaraun/python-eufy-home-security/commit/534621ac9ad94aa058aa7f477417c8a0c8e978c2))
* a motion sensor's React to motion (motion_sensor_respond) is on while action bit 32 is clear, as in the eufy app; turning it off also turns off its notification and HomeBase alarm ([d00a1c2](https://github.com/alaraun/python-eufy-home-security/commit/d00a1c2d51fb39f81d9f5982136c34edd417c60e))
* an empty working-mode read shows Standard, as the eufy app does ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))
* arming-group updates send the name and every member each time (the cloud refuses one alone); EufyCloudApi.async_update_arming_group takes both ([05dbb4c](https://github.com/alaraun/python-eufy-home-security/commit/05dbb4cb1d0f47ad040713dcdfb429101d62af95))
* cross-camera tracking needs at least two cameras, as the eufy app requires ([abacbed](https://github.com/alaraun/python-eufy-home-security/commit/abacbedd6cc48249dddd276b33faf9df68db6155))
* cross-camera tracking offers every paired device the eufy app lists, locks included ([bcaa7d9](https://github.com/alaraun/python-eufy-home-security/commit/bcaa7d906e4367e6bb597f39dc6cc7772a8b1444))
* light settings carry the eufy app's names; no two controls of a model share one ([#88](https://github.com/alaraun/python-eufy-home-security/issues/88)) ([b8ed387](https://github.com/alaraun/python-eufy-home-security/commit/b8ed3871711f8508a9fc4320c86c9661ca91a29a))
* per-mode settings are listed only where the eufy app offers mode tables or delays ([0452b01](https://github.com/alaraun/python-eufy-home-security/commit/0452b0101609268d0c77fe2a39012778737261d7))
* set_alarm_type is no longer a setting: it sounds the HomeBase (see Station.async_trigger_alarm) ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))
* single mode-table writes refuse models without mode-table or delay support ([534621a](https://github.com/alaraun/python-eufy-home-security/commit/534621ac9ad94aa058aa7f477417c8a0c8e978c2))
* sub-device serials come from the cloud device list only; parameter 1072 is the cross-camera tracking selection (SubDeviceState.serial_source "param_1072", SUB_DEVICE_SERIALS_ORDER_EVIDENCE and ParamDump.sub_device_serials removed) ([e631835](https://github.com/alaraun/python-eufy-home-security/commit/e631835081b1d1365d4173d733dab5c96dd375e0))
* switching_notification names no keyfob member and no Start Alarm Delay ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))
* T8023, T8024 and T8026 offer no mode delays and offer arming groups, as the eufy app reports ([534621a](https://github.com/alaraun/python-eufy-home-security/commit/534621ac9ad94aa058aa7f477417c8a0c8e978c2))
* the keypad password status is read-only ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))
* tracking assistance on a HomeBase 3 defaults to on, as the eufy app shows it ([23974a7](https://github.com/alaraun/python-eufy-home-security/commit/23974a7b6b7ffcab4e489ec9e07c75992059781c))


### Documentation

* a UI takes setting sections from one layout request; the attribute is for templates ([#96](https://github.com/alaraun/python-eufy-home-security/issues/96)) ([0a33c5f](https://github.com/alaraun/python-eufy-home-security/commit/0a33c5f0e968ffce14a6e08dadf21195cb7ed619))
* arming groups verified on the HomeBase 3 (T8030) ([bcaa7d9](https://github.com/alaraun/python-eufy-home-security/commit/bcaa7d906e4367e6bb597f39dc6cc7772a8b1444))


### Miscellaneous Chores

* release 0.4.0 ([#108](https://github.com/alaraun/python-eufy-home-security/issues/108)) ([178f179](https://github.com/alaraun/python-eufy-home-security/commit/178f1797cde0226f65d0704d558f4ff704806b49))

## [0.3.17](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.16...v0.3.17) (2026-10-14)


### Bug Fixes

* a keyframe sent in several records stays whole however its parts arrive ([134b57c](https://github.com/alaraun/python-eufy-home-security/commit/134b57c7e0168d5ee31ba713ee507478e54959d2))

## [0.3.16](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.15...v0.3.16) (2026-10-14)


### Features

* pan/tilt, presets and zoom for every model whose app handler declares them ([#84](https://github.com/alaraun/python-eufy-home-security/issues/84)) ([c0c0413](https://github.com/alaraun/python-eufy-home-security/commit/c0c041397f90b1752ebde8564b38d98c46b15953))

## [0.3.15](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.14...v0.3.15) (2026-10-13)


### Features

* history listing with the verb the app sends a station outside the HomeBase 3 family ([8b45ef0](https://github.com/alaraun/python-eufy-home-security/commit/8b45ef0606cead735a3cbcfac5f835492f5b1f2c))
* Station.has_battery tells whether a camera model runs on a battery ([3369719](https://github.com/alaraun/python-eufy-home-security/commit/33697193ab1193e20f5d79a0a6060c1cd103a23c))


### Bug Fixes

* a video PES carries a DTS, so the opening keyframe keeps one in libavformat ([86d2e14](https://github.com/alaraun/python-eufy-home-security/commit/86d2e1493b30c1ef7b378ddac97e77589799d890))


### Documentation

* PTZ_BUSY_CODE keeps its docstring; a standalone camera's history verb is graded in the HA guide ([0dd0dc3](https://github.com/alaraun/python-eufy-home-security/commit/0dd0dc3cca9835368a7d777e5e57cf696b25c030))

## [0.3.14](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.13...v0.3.14) (2026-10-13)


### Bug Fixes

* live view of a standalone camera whose frames name another channel plays instead of failing ([a456711](https://github.com/alaraun/python-eufy-home-security/commit/a456711d2ca051dd249a9a0295963c4ac8375e5c))

## [0.3.13](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.12...v0.3.13) (2026-10-13)


### Bug Fixes

* a station the eufy app reaches only over WebRTC (HomeBase Professional S1, NVR) is skipped instead of rediscovered forever ([8b4e748](https://github.com/alaraun/python-eufy-home-security/commit/8b4e7488bd0bb43d1537f97c7a0bf4fa66c58121))
* a storage medium is unhealthy only for the health codes the eufy app flags ([b7fcb05](https://github.com/alaraun/python-eufy-home-security/commit/b7fcb055e0e9e3c633b476f502f62c4ac499b30d))
* each station gets the storage query the eufy app sends it; a HomeBase 2 reports its eMMC and disk ([b7fcb05](https://github.com/alaraun/python-eufy-home-security/commit/b7fcb055e0e9e3c633b476f502f62c4ac499b30d))

## [0.3.12](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.11...v0.3.12) (2026-10-12)


### Bug Fixes

* a live viewer joining mid-stream gets the whole current picture group; no broken first seconds ([2c71ecc](https://github.com/alaraun/python-eufy-home-security/commit/2c71ecc9ddf65c6517d7ee5f4c08097de1082938))
* a station whose cipher RSA key does not parse connects under the static key, as in the eufy app ([d75f7b3](https://github.com/alaraun/python-eufy-home-security/commit/d75f7b3d829c0140fc2123f471fd26a4e5daaadc))
* a storage query the station refuses fails at its receipt instead of timing out ([d75f7b3](https://github.com/alaraun/python-eufy-home-security/commit/d75f7b3d829c0140fc2123f471fd26a4e5daaadc))

## [0.3.11](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.10...v0.3.11) (2026-10-12)


### Features

* CameraImage.codec and its content type follow the picture (video/hevc or video/h264); Station.video_codec names a camera's codec ([b99651e](https://github.com/alaraun/python-eufy-home-security/commit/b99651e42d1646a6691ba3849e2269b64c2d5276))
* VideoCodec, picture_codec and the image content types are exported; VideoCodec.content_type and mp4_tag ([b99651e](https://github.com/alaraun/python-eufy-home-security/commit/b99651e42d1646a6691ba3849e2269b64c2d5276))


### Bug Fixes

* a keyframe a camera sends in several records (HomeBase 2) is joined into one picture instead of dropped ([b99651e](https://github.com/alaraun/python-eufy-home-security/commit/b99651e42d1646a6691ba3849e2269b64c2d5276))

## [0.3.10](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.9...v0.3.10) (2026-10-11)


### Features

* MediaClip.codec names the clip's video codec; the documented MP4 remux tags hvc1 for HEVC only ([140b555](https://github.com/alaraun/python-eufy-home-security/commit/140b555e18fe63528c7d9c9de936ed0adec1cd21))
* SessionStats.media_failures_by_channel counts failed media opens per camera channel ([140b555](https://github.com/alaraun/python-eufy-home-security/commit/140b555e18fe63528c7d9c9de936ed0adec1cd21))


### Bug Fixes

* a station whose RSA CONN_INIT names cipher 0, or wraps its static key, comes up; its state is taken unauthenticated ([140b555](https://github.com/alaraun/python-eufy-home-security/commit/140b555e18fe63528c7d9c9de936ed0adec1cd21))

## [0.3.9](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.8...v0.3.9) (2026-10-11)


### Bug Fixes

* a live stream takes its codec from the keyframe picture; a HomeBase 2 camera streams H.264 under an HEVC header ([d736e44](https://github.com/alaraun/python-eufy-home-security/commit/d736e444ba14ff029c216a1b82a299830b7edada))
* a standalone device whose parameter block carries an unknown label (T8442: 1000) is read as its own ([d736e44](https://github.com/alaraun/python-eufy-home-security/commit/d736e444ba14ff029c216a1b82a299830b7edada))
* empty NAL units are removed from video before muxing ([d736e44](https://github.com/alaraun/python-eufy-home-security/commit/d736e444ba14ff029c216a1b82a299830b7edada))

## [0.3.8](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.7...v0.3.8) (2026-10-10)


### Features

* stop a live capture early and keep the clip ([#58](https://github.com/alaraun/python-eufy-home-security/issues/58)) ([391c059](https://github.com/alaraun/python-eufy-home-security/commit/391c059cc6b59712ce4079cb75c7ab53af6094fb))

## [0.3.7](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.6...v0.3.7) (2026-10-10)


### Features

* media diagnostics for a live view that shows no picture ([#56](https://github.com/alaraun/python-eufy-home-security/issues/56)) ([00993cc](https://github.com/alaraun/python-eufy-home-security/commit/00993ccf7c1c880b3d06139873fc3188c1164641))


### Bug Fixes

* a station with an unsupported P2P id is skipped; P2P ids follow the eufy app's bounds ([#55](https://github.com/alaraun/python-eufy-home-security/issues/55)) ([39e00b4](https://github.com/alaraun/python-eufy-home-security/commit/39e00b4500ed0188550eb3ab969d01a1c19fdb95))

## [0.3.6](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.5...v0.3.6) (2026-10-10)


### Bug Fixes

* read and write a device's settings in the context the app sees it ([#53](https://github.com/alaraun/python-eufy-home-security/issues/53)) ([b457637](https://github.com/alaraun/python-eufy-home-security/commit/b4576370323db7f5897773618183e5f2066e70c0))

## [0.3.5](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.4...v0.3.5) (2026-10-10)


### Features

* keep parameter-dump keys the library does not read; status --received ([#51](https://github.com/alaraun/python-eufy-home-security/issues/51)) ([c2ac52e](https://github.com/alaraun/python-eufy-home-security/commit/c2ac52eb138d4c26cbbf3ef3d328fd504bb131a3))


### Bug Fixes

* leave out a paired device's settings the app offers only without a parent ([#52](https://github.com/alaraun/python-eufy-home-security/issues/52)) ([f0ff19d](https://github.com/alaraun/python-eufy-home-security/commit/f0ff19d6e956e4eb23ed5a9061d9fefc0d89cce3))
* read a paired camera's own parameters from the dump's db_bypass_str ([#49](https://github.com/alaraun/python-eufy-home-security/issues/49)) ([5eda9b4](https://github.com/alaraun/python-eufy-home-security/commit/5eda9b423c3d06bd355ca62e343aefca20928b97))

## [0.3.4](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.3...v0.3.4) (2026-10-09)


### Features

* live video declared for every camera whose handler's open the library sends ([#46](https://github.com/alaraun/python-eufy-home-security/issues/46)) ([52041cc](https://github.com/alaraun/python-eufy-home-security/commit/52041ccbdbbc81d59636a0df252fbd17ea8bfaff))


### Documentation

* the app routes live opens to WebRTC by the parent's is_connect_webrtc ([#48](https://github.com/alaraun/python-eufy-home-security/issues/48)) ([f822c0b](https://github.com/alaraun/python-eufy-home-security/commit/f822c0bb1b980ee03f0446d7d5cd1973166b91fb))

## [0.3.3](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.2...v0.3.3) (2026-10-09)


### Features

* ECC media key for live streams ([#44](https://github.com/alaraun/python-eufy-home-security/issues/44)) ([df76f0e](https://github.com/alaraun/python-eufy-home-security/commit/df76f0e4224a9f91f6727bfc96f79499b93b13fd))

## [0.3.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.1...v0.3.2) (2026-10-09)


### Features

* live video from HomeBase 2 and other non-T8030 stations ([#42](https://github.com/alaraun/python-eufy-home-security/issues/42)) ([cef8f94](https://github.com/alaraun/python-eufy-home-security/commit/cef8f9436530b067a32261bea1f8fc2c59d409c4))

## [0.3.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.0...v0.3.1) (2026-10-09)


### Features

* a rate-limit error names who refused it (origin) and the login scope it was for; RegionStatus.next_login_allowed_in per scope ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* EufySecurity.device_list_source and listed_devices say how the last device list was obtained and what it named; StationsChanged reports stations a discovery built or no longer finds ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* mode_action_flags gives a sensor's per-mode actions by device type; only motion sensors get the respond action, and sirens are kind other ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* RegionStatus reports each scope's session state, login refusal and logins in the budget window ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the cloud package exports CipherKeys and RsaKeyCheck ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* warm_store takes the client's country and region; FakeCloud plays refusals and throttles through the library's own handling; short_timeouts covers the preset, pan/tilt, live-open and discovery-retry waits ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* without a product code from the cloud, the serial names the product variant (T8410C, T8420X, T8210C, T8510P, T8520P, T8W11C) ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))


### Bug Fixes

* a cached device list that misses a login scope is fetched again, and the cached-list fallback leaves out the devices of scopes no longer in use ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a failed verification-code request still raises the login challenge, and the one-time country re-login never asks for an e-mailed code ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a firmware check that gets no verdict raises instead of reading as up to date ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a login challenge raised for an extra country is answered there, also on a new client instance ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a login-free call whose session the cloud answers as expired raises NoCachedSessionError, not an authentication error; pending invitations survive one failing region ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a reply queued while the event loop was held is read in every wait phase of a request ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* an extra country whose login eufy refuses is skipped until a rescan instead of failing every login, and a refused login country is not sent again on later logins ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* async_event_thumbnail gives each of its queries its own default timeout ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* cloud_status counts logins per cluster and covers the first region when every scope is suspended ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* credentials without the key the station's handshake needs raise CipherUnusableError (no_rsa_key, no_ecc_key) after one refresh, and credentials for another cipher set no stale-key latch ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* house names, nicknames and locations are masked in debug logs, and error texts in the account report are scrubbed ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* on an RSA session only frames under the session key count as station state, and pushes under that key are authenticated ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the CLI reports a bad country, e-mail or port as a usage error and gives specific advice for SessionRejectedError and CipherUnusableError ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the empty-cipher back-off ends when the station's owner id changes ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the extra countries' install ids are kept wherever openudid is ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the login country is looked up before a login picks its region; a lookup that gets no answer spends no login and is asked again ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))


### Documentation

* the RSA handshake is declared and works with an intact key; cloud docs use neutral example countries ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))

## [0.3.0](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.8...v0.3.0) (2026-10-09)


### Features

* every product the eufy app names is in the model list ([#36](https://github.com/alaraun/python-eufy-home-security/issues/36)) ([36df33a](https://github.com/alaraun/python-eufy-home-security/commit/36df33ae9dff25f20d0b05592df6173ff5be79af))


### Bug Fixes

* an extra country logs in under its own install id ([#35](https://github.com/alaraun/python-eufy-home-security/issues/35)) ([2e79411](https://github.com/alaraun/python-eufy-home-security/commit/2e79411aa5d3d286e94da19700259e095b877d8a))


### Miscellaneous Chores

* release 0.3.0 ([#38](https://github.com/alaraun/python-eufy-home-security/issues/38)) ([acd4167](https://github.com/alaraun/python-eufy-home-security/commit/acd4167ed84d25c390bae5e0de02fb13f19b9e85))

## [0.2.8](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.7...v0.2.8) (2026-10-08)


### Features

* log in once per user-set country, on its home region only ([#33](https://github.com/alaraun/python-eufy-home-security/issues/33)) ([f5714a3](https://github.com/alaraun/python-eufy-home-security/commit/f5714a3db42fb60c4243d52609ca7ce90145ebb9))

## [0.2.7](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.6...v0.2.7) (2026-10-08)


### Features

* log in with the account's country, as the eufy app does ([#31](https://github.com/alaraun/python-eufy-home-security/issues/31)) ([d289991](https://github.com/alaraun/python-eufy-home-security/commit/d289991a90deac38086ed0bee9508fd61551ec29))
* pending home and device invitations ([#29](https://github.com/alaraun/python-eufy-home-security/issues/29)) ([cb5eb27](https://github.com/alaraun/python-eufy-home-security/commit/cb5eb27582653d24c381af77b5002508ef5ac14b))


### Bug Fixes

* a reply that arrived while the event loop was held is not a timeout ([#32](https://github.com/alaraun/python-eufy-home-security/issues/32)) ([afc3eb4](https://github.com/alaraun/python-eufy-home-security/commit/afc3eb402f17ebb009f05f5b078504b6c961887f))

## [0.2.6](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.5...v0.2.6) (2026-10-08)


### Bug Fixes

* a version-8 session key need not be printable ([#27](https://github.com/alaraun/python-eufy-home-security/issues/27)) ([0fad068](https://github.com/alaraun/python-eufy-home-security/commit/0fad068fb7bb6058163c35248db923e707bbdeeb))

## [0.2.5](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.4...v0.2.5) (2026-10-08)


### Features

* account report of every eufy device list, firmware and cipher state ([#25](https://github.com/alaraun/python-eufy-home-security/issues/25)) ([9f9809e](https://github.com/alaraun/python-eufy-home-security/commit/9f9809eaeda31599e73e51a6fc29b17f772a1c2b))

## [0.2.4](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.3...v0.2.4) (2026-10-07)


### Features

* a cipher key that does not parse is unusable, not rejected ([#23](https://github.com/alaraun/python-eufy-home-security/issues/23)) ([2a811eb](https://github.com/alaraun/python-eufy-home-security/commit/2a811eb426a4cac5ad2d8d5f6c2b2961b9526a7d))

## [0.2.3](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.2...v0.2.3) (2026-10-07)


### Bug Fixes

* a login pending two-step verification is a challenge, not a session ([#21](https://github.com/alaraun/python-eufy-home-security/issues/21)) ([6e0140e](https://github.com/alaraun/python-eufy-home-security/commit/6e0140ef3b9f7ebd73ecf5bb9852419b6c1f07ae))

## [0.2.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.1...v0.2.2) (2026-10-07)


### Features

* the RSA session variant and T8410/T8161 device profiles ([#19](https://github.com/alaraun/python-eufy-home-security/issues/19)) ([c8921d1](https://github.com/alaraun/python-eufy-home-security/commit/c8921d194e8cd54213bb6a385353fa4bd94b7189))

## [0.2.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.0...v0.2.1) (2026-10-07)


### Features

* find the account's devices in every cloud region ([#17](https://github.com/alaraun/python-eufy-home-security/issues/17)) ([f1bb721](https://github.com/alaraun/python-eufy-home-security/commit/f1bb721902cbe684ce4c70c67df74b60e46062c3))

## [0.2.0](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.2...v0.2.0) (2026-10-06)


### Features

* list recordings from a chosen day, and ask an unanswered history page once more ([#15](https://github.com/alaraun/python-eufy-home-security/issues/15)) ([ef22ed1](https://github.com/alaraun/python-eufy-home-security/commit/ef22ed1274fc73f3d644dc478b8921dc5dd78d25))
* read every hardware wait at call time; testing.short_timeouts ([#12](https://github.com/alaraun/python-eufy-home-security/issues/12)) ([054887a](https://github.com/alaraun/python-eufy-home-security/commit/054887a079d2c4f98a9748f29cc2362a21e78290))
* StillNotWrittenError for an event still that is not written yet ([#13](https://github.com/alaraun/python-eufy-home-security/issues/13)) ([7dde1e4](https://github.com/alaraun/python-eufy-home-security/commit/7dde1e4b98c391cda0054cf51dacf4b6042a584d))

## [0.1.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.1...v0.1.2) (2026-10-06)


### Bug Fixes

* fetch the cipher key the station names, after CONN_INIT ([#9](https://github.com/alaraun/python-eufy-home-security/issues/9)) ([a2af4fb](https://github.com/alaraun/python-eufy-home-security/commit/a2af4fb55fd5a5dbc4ff1299d83ca1d7f0e10c5f))

## [0.1.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.0...v0.1.1) (2026-10-05)


### Bug Fixes

* name the device channel in the subheader of 1350 commands ([#7](https://github.com/alaraun/python-eufy-home-security/issues/7)) ([9925351](https://github.com/alaraun/python-eufy-home-security/commit/9925351036e43fe324b6654a21338397d7a7c121))

## 0.1.0

The first public release: an asyncio client for eufy Security that works on the local
network and uses the eufy cloud only for login, keys and push.

### Local network

- Discovery and the encrypted P2P session to a HomeBase 3 (T8030) and to a standalone
  battery camera (T8170), including waking a sleeping camera.
- Guard mode: read, set and follow, confirmed by the station's own report.
- State from the station: battery, signal, firmware, storage, charging and online
  state, with change events.
- Live video and audio (HEVC + AAC) shared by several viewers, still images at full
  resolution, stored recordings (played back or downloaded as a clip) and event stills.
- Pan/tilt, presets and picture zoom on the T8170; per-mode alarm actions and delays.

### Settings

- Settings for 107 eufy products, generated from the eufy app's own thing descriptions
  and handlers: values, labels, units, the control to show, and how each is written
  and read back.

### Cloud and push

- `eufy_mega` login with the e-mailed code or a captcha, a session cache that survives
  restarts, the device list and the per-station keys.
- Push events over FCM, merged with the local session's events.
- Firmware-update notices.
- Protection against the cloud's limits: a login budget, hold-offs after throttling,
  and no automatic re-login after another client takes over the session.

### Tools

- The `eufy-security` command line: status, guard mode, settings, live video,
  recordings, events and more.
- `eufy_home_security.testing`: a fake station and a fake cloud for end-to-end tests of
  a consumer such as a Home Assistant integration.
- Support graded as data: each model and capability is *verified* on hardware,
  *declared* from the eufy app, or *unknown*, with its source.
