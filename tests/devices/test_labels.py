"""Setting display names and choice labels."""

from __future__ import annotations

import pytest

from eufy_home_security.devices.labels import (
    SETTING_NAMES,
    choice_label,
    sentence_case,
    setting_name,
)


@pytest.mark.parametrize(
    ("identifier", "code", "vendor", "label"),
    [
        ("nightvision_type", 1, "B&W Night Vision", "B&W Night Vision"),
        ("live_streaming_resolution", 3, "3K HD", "3K HD"),
        ("live_streaming_resolution", 1, "HD(720P)", "HD(720P)"),
        ("live_streaming_resolution", 8, "Hight", "High"),
        ("live_streaming_resolution", 10, "4K UItra", "4K Ultra"),
        ("device_multiple_bridge_mode", 1, "hb", "HomeBase"),
        ("device_multiple_bridge_mode", 2, "route", "Router"),
        ("device_snooze_time", 0, "close", "Off"),
        ("device_snooze_time", 0, "0min", "Off"),
        ("device_snooze_time", 3600, "1hour", "1 hour"),
        ("device_snooze_time", 7200, "2hour", "2 hours"),
        ("device_cross_cam_interval", 1800, "30", "30 min"),
        ("device_cross_cam_interval", 900, "15min", "15 min"),
        ("device_alarm_duration", 300, "300", "300 s"),
        ("detection_sensitivity", 4, "4", "4"),
        ("watermark_set", 2, " logo", "Logo"),
        ("speaker_volume", 90, "低", "Low"),
        ("power_manager_mode", 0, "OPTIMAL_BATTERY_LIFE", "Optimal battery life"),
        ("time_format_set", 0, "Time_System_12", "12-hour"),
        ("time_format_set__v1", 1, "Time_System_24", "24-hour"),
        ("playback_play_speed", 2, "2x", "2x"),
        ("sensor_low_temperature_alarm_threshold", 32, "32°F", "32°F"),
        ("sensor_door_open_status_alert_config", 5, "5分钟", "5 min"),
        ("live_bottom_toolbar_list", 1, "BCTabBarFunctionAITracking", "AI Tracking"),
        ("set_alarm_type", 1, "homebase alarm", "HomeBase alarm"),
        ("any", 7, "", "Value 7"),
        ("any", 7, "未知", "Value 7"),
    ],
)
def test_choice_label(identifier: str, code: int, vendor: str, label: str) -> None:
    assert choice_label(identifier, code, vendor) == label


@pytest.mark.parametrize(
    ("identifier", "name"),
    [
        ("disable_ptz_turn_switch", "Privacy zones"),  # named after its binding (6248)
        ("device_silent_ota_switch", "Silent firmware updates"),
        ("audio_recording_on_off", "Record audio"),
        ("nightvision_type__v1", "Night vision"),
        ("hb_connect_nas_switch", "NAS storage"),
        ("sensor_grass_detection_sensitivity_level", "Sensor grass detection sensitivity level"),
        ("video_quality_hdr_switch", "Video quality HDR"),
    ],
)
def test_setting_name(identifier: str, name: str) -> None:
    assert setting_name(identifier) == name


def test_curated_names_are_short_titles() -> None:
    assert all(0 < len(n) <= 32 and n[0].isupper() for n in SETTING_NAMES.values())


@pytest.mark.parametrize(
    ("title", "name"),
    [
        ("Enable Floodlights", "Enable floodlights"),
        ("Recording Quality", "Recording quality"),
        ("Night Vision", "Night vision"),
        ("Status LED", "Status LED"),
        ("AI tracking", "AI tracking"),
        ("Sunset to Sunrise", "Sunset to sunrise"),
        ("Continuous Tracking Time", "Continuous tracking time"),
        ("Performance (Beta)", "Performance (beta)"),
        ("Cross-Camera Tracking", "Cross-camera tracking"),
        ("HomeBase Alarm Volume", "HomeBase alarm volume"),
        ("Connect To Wi-Fi", "Connect to Wi-Fi"),
        ("Works With Alexa", "Works with Alexa"),
        ("Record 2K Video On NAS", "Record 2K video on NAS"),
        ("Zone A", "Zone A"),
        ("Every Monday", "Every Monday"),
        ("Anti-Flicker 50 Hz", "Anti-flicker 50 Hz"),
    ],
)
def test_sentence_case(title: str, name: str) -> None:
    assert sentence_case(title) == name


def test_names_are_sentence_case() -> None:
    curated = list(SETTING_NAMES.values())
    mechanical = [setting_name(i) for i in ("video_quality_hdr_switch", "hb_connect_nas_status")]
    assert [n for n in curated + mechanical if sentence_case(n) != n] == []
