"""Protocol constants of the eufy Security app's Firebase (FCM) registration.

The Firebase project, app id, API key and sender id are read from the eufy
Security app's resources. The API key is restricted to the app's package
and signing certificate, which is why the registration must present both
(``X-Android-Package`` / ``X-Android-Cert``). They identify the *app*, the same for
every install; the per-install identity (Google's android id, eufy's openudid) is
minted at runtime and cached.
"""

from __future__ import annotations

from typing import Final

FCM_PROJECT_ID: Final = "batterycam-3250a"
FCM_APP_ID: Final = "1:348804314802:android:440a6773b3620da7"
FCM_API_KEY: Final = "AIzaSyCSz1uxGrHXsEktm7O3_wv-uLGpC9BvXR8"
FCM_SENDER_ID: Final = "348804314802"

APP_PACKAGE: Final = "com.oceanwing.battery.cam"
APP_CERT_SHA1: Final = "F051262F9F99B638F3C76DE349830638555B4A0A"

# What the app's own c2dm/register3 form carries. Google does not check them, but
# they are what an eufy install looks like on the wire.
GCM_VERSION: Final = "201216023"
APP_VERSION_CODE: Final = "741"
APP_VERSION_NAME: Final = f"v2.2.2_{APP_VERSION_CODE}"
ANDROID_OS_VERSION: Final = "25"
ANDROID_TARGET_VERSION: Final = "28"
FIID_CLIENT_VERSION: Final = "fiid-20.2.0"
FIREBASE_APP_NAME_HASH: Final = "R1dAH9Ui7M-ynoznwBdw01tLxhI"
FIREBASE_SDK_VERSION: Final = "a:16.3.1"
GCM_USER_AGENT: Final = "Android-GCM/1.5"

# Android checkin profile fields that do not identify the install.
CHECKIN_ESN: Final = "ABCDEF01"
CHECKIN_OTA_CERT: Final = "71Q6Rn2DDZl1zPDVaaeEHItd+Yg="
CHECKIN_LOGGING_ID: Final = 1234567890

HTTP_TIMEOUT_SECONDS: Final = 30.0
CHECKIN_RETRIES: Final = 3
REGISTER_RETRIES: Final = 5

# MCS heartbeats: the values that keep an MCS socket up for many hours without a
# reconnect. Raising them risks the backend dropping an idle socket silently.
SERVER_HEARTBEAT_INTERVAL: Final = 60
CLIENT_HEARTBEAT_INTERVAL: Final = 120

# Stopping waits at most this for the MCS client's tasks; the socket is aborted, not
# closed gracefully, so they normally end within milliseconds.
STOP_TIMEOUT: Final = 2.0

# The backend redelivers on reconnect and re-registration; the app de-duplicates
# on ``span_id`` with a ring of this size. The listener persists its ring (with
# first-seen times) so a restart does not replay old pushes, forgets entries after
# the retention, and batches the cache write (``storage.DELIVERY_STATE_SAVE_DELAY``).
DEDUPE_RING_SIZE: Final = 1000
DEDUPE_RETENTION_SECONDS: Final = 7 * 24 * 3600

# Registration (checkin + installation + register + eufy upload) must finish
# within this, however the per-call retries add up.
START_DEADLINE_SECONDS: Final = 60.0

# How often the listener checks that the MCS client has not given up, and the
# floor and ceiling of its restart backoff (doubling per failed restart).
SUPERVISE_INTERVAL: Final = 30.0
RESTART_BACKOFF_MIN: Final = 5.0
RESTART_BACKOFF_MAX: Final = 600.0
