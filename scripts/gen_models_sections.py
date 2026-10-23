"""Assign each generated setting a UI section (``devices/sections.py``).

The section comes from, in order: the app page the setting lives on (:data:`PAGE_SECTIONS`;
a page that mixes several sections maps to None and defers), the station rules for a
HomeBase or other station model (:data:`STATION_RULES`), the identifier rules
(:data:`KEY_RULES`, first full match wins), else ``other``. A variant takes its primary's
section. Pure; see docs/reference/models-schema.md.
"""

from __future__ import annotations

import re
from typing import Any

from gen_models_codec import GeneratorError

from eufy_home_security.devices.sections import OTHER_SECTION, SETTING_SECTIONS

__all__ = ["KEY_RULES", "PAGE_SECTIONS", "STATION_RULES", "assign", "section_of"]

type Settings = dict[str, dict[str, Any]]

# Every app page the settings files name. None: the page holds settings of several
# sections, so the identifier decides.
PAGE_SECTIONS: dict[str, str | None] = {
    "AboutDevice": "system",
    "AudioSettings": None,
    "BottleWasherHomeScreen": None,
    "BottleWasherSettingScreen": None,
    "CUSButton": "modes",
    "ComputeCardAIFeatureScreen": "detection",
    "ComputeCardAddScreen": "detection",
    "ComputeCardHomeScreen": "detection",
    "CustomizeRecording": "recording",
    "DeliveryGuard": "detection",
    "DeliveryGuardGuideFourth": "detection",
    "FamiliarFace": "detection",
    "FillLightMode": "picture",
    "FirstUseFamiliarFace": "detection",
    "GlassBreakReadyToTest": "detection",
    "HomeKitSecurityVideo": "network",
    "IPCImageSetting": "picture",
    "IPCOrientation": "picture",
    "IPCRecordingQualityScreen": "recording",
    "LightSettingMain": "picture",
    "MotionActivatedLight": "picture",
    "MotionDetection": None,
    "MotionDetectionV2": "detection",
    "MultiBridgeSetting": "network",
    "NVRAboutDevice": "system",
    "NVREventRecordingScreen": "recording",
    "NVRFirmwareUpdateScreen": "system",
    "NVRPairedDevice": "system",
    "NVRSystemNotification": "notifications",
    "NightVision": "picture",
    "NightVisionAlwaysOn": "picture",
    "OnTheGo": "network",
    "OpenStatusAlert": "notifications",
    "PackageGuard": "detection",
    "PackageLiveCheckAssistance": "detection",
    "PanTiltSettings": "ptz",
    "PanTiltSpeed": "ptz",
    "PowerManager": "power",
    "ResponseSettingScreen": "doorbell",
    "RingtoneSettings": "doorbell",
    "SLMatterIntroScreen": "network",
    "SLPowerDuoPowerSupplySystemScreen": "power",
    "SOSStrongReminder": "alarm",
    "SecurityCodesScreen": "modes",
    "SelectHomeBaseConnection": "network",
    "SensorMotionTestMode": "detection",
    "SettingsGeneral": None,
    "SettingsHome": None,
    "SettingsNotification": "notifications",
    "SoundDetection": "detection",
    "SpotlightSettings": "picture",
    "ThingDeveloperScreen": None,
    "UncollectedPackageAlert": "detection",
    "VideoSettings": None,
    "WiFiConnection": "network",
}

# Identifier rules that apply on a station model before KEY_RULES.
STATION_RULES: tuple[tuple[str, str], ...] = (
    (r"led_on_off", "system"),  # the station's status light
)

# Identifier rules, (full-match pattern, section); the first match wins, so a specific
# pattern stands before a broader one.
KEY_RULES: tuple[tuple[str, str], ...] = (
    # Settings whose broader pattern points elsewhere.
    (r"ai_tracking_status|motion_track(ing)?_status|motion_tracking_switch", "ptz"),
    (r"live_tracking_switch|device_linkage_tracking_bypass", "ptz"),
    (r"motion_stop_end_early|video_clip_length|trigger_interval_time", "recording"),
    (r"audio_recording_on_off|support_audio_record_type", "recording"),
    (r"audio_settings_chimes_alert_switch", "doorbell"),
    (r"device_packages_.*|device_delivered_.*|device_delivery_.*", "detection"),
    (r"motion_activated_light_setting|motion_support_set_light_mode", "picture"),
    (r"notification_alarm_delay_value", "modes"),
    (r"ignore_no_sd_card_alarm", "storage"),
    # Notifications.
    (r"notification_.*|.*_notification(_switch|_master_switch)?", "notifications"),
    (r"motion_dection_.*_notification_switch|smart_lock_notification_.*", "notifications"),
    (r"device_snooze_.*|device_not_disturb_config|sensor_not_disturb_switch", "notifications"),
    (r"sensor_door_.*_alert_config|sensor_door_daily_check_status_config", "notifications"),
    # Modes.
    (r"arming_.*|cust_mode_config|geofence_config|support_arming", "modes"),
    (r"automation_.*|ordered_trigger_actions|hb_keypad_.*", "modes"),
    # Alarm.
    (r"alarm_.*|device_alarm_.*|device_set_alarm_light_type|last_event_device_alarm_info", "alarm"),
    (r"hb_set_alarm_params|hb_set_dangerous_event_status|device_has_buzzer", "alarm"),
    (r"prompt_volume_value|audio_alert_volume|ignore_set_alarm", "alarm"),
    (r"anti_theft_detection_switch|device_sos_.*|sensor_panic_.*|sensor_siren_.*", "alarm"),
    (r"sensor_alarm_timeout|sensor_low_temperature_alarm_threshold", "alarm"),
    (r"device_monitor_indoor_temperature_switch|device_indoor_temperatur_alarm_.*", "alarm"),
    (r"device_pro_alarm_subscription_switch|is_support_professional_alarm", "alarm"),
    # Pan & tilt.
    (r"ptz_.*", "ptz"),
    (r"auto_calibration_status|default_angle_.*|auto_cruise_schedule_list", "ptz"),
    (
        r"video_auto_cruise_switch|preset_positions_calibrate_time|camera_gun_ball_linkage_switch",
        "ptz",
    ),
    (r"gesture_control_.*|live_ptz_toolbar_list|device_vr_.*|vr_mode_min_memory", "ptz"),
    # Picture: the image, night vision, lights and LEDs.
    (r"nightvision_.*|smart_lock_night_vision_.*", "picture"),
    (
        r"(auto_|bottom_|zoom_)?spotlight_.*|enable_floodlights_status|support_setting_spotlight_switch",
        "picture",
    ),
    (r"light_.*|manual_light_brightness|led_.*|indicator_led_status|breathing_light_.*", "picture"),
    (r"watermark_set|rotate_image_180_on_off|video_mirror_mode_set|video_setting_.*", "picture"),
    (r"video_settings_led_activate_time|view_mode|(video_)?watch_view_mode", "picture"),
    (r"video_quality_(hdr|wdr|distortion_correction)_switch", "picture"),
    # Detection.
    (
        r"disable_ptz_turn_switch|(set_)?privacy_?zone.*|is_support_dynamic_privacy_zone",
        "detection",
    ),
    (r"detection_.*|motion_.*|montion_.*|sound_detection_.*|(device|nvr)_motion_.*", "detection"),
    (r".*detection_.*|multi_detection_sensitivity|alerts_detection_type", "detection"),
    (r".*activityzone.*|activity_privacy_zone_.*|set_ignore_.*|porch_set_ignore_zone", "detection"),
    (
        r"entry_activity_zone_condition|device_familiar_faces_.*|is_support_familiar_face",
        "detection",
    ),
    (r"device_agree_face_recognition_switch|device_agree_ai_terms_switch", "detection"),
    (r"ai_.*|aic_.*|hb_aic_.*|bind_ai_card_info|inserted_ai_card_info", "detection"),
    (r"device_cross_cam_.*|device_linkage_mode|device_wildlife_watch_mode_switch", "detection"),
    (r"sensor_motion_.*|sensor_grass_.*|(device_)?radar_.*|device_rain_mode", "detection"),
    (r"smart_lock_rain_mode_switch|support_smart_search_switch", "detection"),
    # Recording.
    (r"record_.*|live_streaming_resolution.*|device_continuous_.*", "recording"),
    (r"device_pre_recording_switch|device_recording_.*|device_event_.*", "recording"),
    (
        r"video_quality_.*|camera_snapshot_setting|model_config|device_set_time_lapse_photography",
        "recording",
    ),
    (r"(remember_)?video_download_type|playback_play_speed|encrypt_playback_version", "recording"),
    (r"support_video_codec|player_.*|recording_number|working_days|detected_events", "recording"),
    (r"smart_lock_no_recording_while_unlocked|daily_highlight_.*", "recording"),
    # Audio.
    (r"microphone_on_off|speaker_.*|video_intercom_.*|support_intercom_codec", "audio"),
    (r"device_white_noise_.*", "audio"),
    (
        r"smart_lock_lock_sound_.*|device_mute_switch|nvr_get_device_volume|pet_command_status",
        "audio",
    ),
    # Power.
    (r"power_.*|(backup_)?battery_.*|device_backup_battery_type|charging_status", "power"),
    (r"device_charging_mode|device_power_.*|solar_.*|is_connected_solar_panel", "power"),
    (r"device_is_battery_device|device_exist_battery|is_acpower_lost", "power"),
    (r"is_fast_charging_mode|sensor_is_low_power|is_wired_device", "power"),
    # Doorbell and chime.
    (r"device_chime_.*|device_indoor_chime_switch|device_existing_chime_time", "doorbell"),
    (r"device_audio_ringtone_volume|device_response_timeout_.*", "doorbell"),
    (r"quickresponse_.*|need_merge_quickresponse_list|ignore_play_quickresponse_p2p", "doorbell"),
    (r"device_video_visitor_count|smart_lock_enable_voip_switch", "doorbell"),
    (r"device_approach_interaction_plan|is_support_main_auxiliary_camera", "doorbell"),
    # Storage.
    (r"hb_connect_.*|nas_.*|.*storage.*|sd_card_.*|database_synchronize", "storage"),
    # Network.
    (r".*wifi.*|4g_.*|sim_.*|device_simslot.*|supported_bands", "network"),
    (
        r"device_multiple_bridge_.*|is_support_multiple_bridge.*|device_multi_route_connect_status",
        "network",
    ),
    (r"homebase_connect_support|ip_address|mac_address|subnet_mask", "network"),
    (r"setting_current_connection_type|device_connect_type|device_to_hb_connect_type", "network"),
    (r"device_generated_ssid_prefix|p2p_.*|device_p2p_did|get_device_old_p2p_did", "network"),
    (r".*webrtc.*|device_rtsp_.*|homekit_.*|is_support_mqtt|is_support_ble", "network"),
    (
        r"device_extender_info|device_sync_data_on_repetor|discover_third_party_device_switch",
        "network",
    ),
    (r"device_linked_matter_list|is_support_homekey|smart_lock_connect_to_wifi_bridge", "network"),
    (
        r"live_support_multi_live_stream|is_support_multi_live_stream|support_multiple_live_stream",
        "network",
    ),
    # System: identity, time, firmware, status and what the device supports.
    (r"device_name|timezone_set|time_format_set|device_(date|temperature)_format_set", "system"),
    (r"device_indoor_temperature_unit", "system"),
    (r"smart_lock_set_timezone|device_silent_ota_switch|is_support_silent_ota_switch", "system"),
    (r"auto_ota_.*|firmware_.*|is_device(_ready)?_upgrade|accessory_ota_status", "system"),
    (
        r"device_model|device_serial_number|device_status|device_is_online|device_ability_data",
        "system",
    ),
    (r"working_mode_value|(camera|device)_on_off(_privacy_mode)?|privacy_mode_status", "system"),
    (r"reset_device_mode|system_maintenance|device_cpu_info|device_current_temerature", "system"),
    (r"device_running_status|general_.*|hide_.*|device_house_area_locations", "system"),
    (r"device_support_.*|is_support_.*|support_.*|device_not_support_.*", "system"),
    (r"live_.*|home_card_.*|(add_device|setting|sdk)_model_config|query_event_list_cmd", "system"),
    (r"device_query_event_.*|device_text_event_data_type|device_sensor_count", "system"),
    (r"device_sub_device_info|device_live_view_switch|set_person_activity_status", "system"),
    (r"video_camera_count|device_monitor_status|device_back_screen_connect_status", "system"),
    (r"sensor_.*_status|smart_lock_.*", "system"),
)

_SECTION_IDS = frozenset(s.id for s in SETTING_SECTIONS)
_STATION = tuple((re.compile(p), s) for p, s in STATION_RULES)
_RULES = tuple((re.compile(p), s) for p, s in KEY_RULES)


def section_of(ident: str, entry: dict[str, Any], *, station: bool) -> tuple[str, str]:
    """``(section, source)`` of one primary setting; source is ``page``, ``station``,
    ``key`` or ``none``. Raises GeneratorError for a page :data:`PAGE_SECTIONS` lacks."""
    page = entry.get("page")
    if page is not None:
        if page not in PAGE_SECTIONS:
            raise GeneratorError(f"{ident}: page {page!r} has no entry in PAGE_SECTIONS")
        section = PAGE_SECTIONS[page]
        if section is not None:
            return section, "page"
    for rules, source in ((_STATION if station else (), "station"), (_RULES, "key")):
        for pattern, section in rules:
            if pattern.fullmatch(ident):
                return section, source
    return OTHER_SECTION, "none"


def assign(settings: Settings, *, station: bool) -> dict[str, int]:
    """Set ``section`` on every setting in place (a variant: its primary's); return counts
    per source. ``station``: the model is a station (HomeBase)."""
    counts: dict[str, int] = {}
    for ident, entry in settings.items():
        if "variant_of" in entry:
            continue
        section, source = section_of(ident, entry, station=station)
        entry["section"] = section
        key = f"section:{source}"
        counts[key] = counts.get(key, 0) + 1
    for entry in settings.values():
        primary = entry.get("variant_of")
        if primary is not None:
            entry["section"] = settings[primary]["section"]
            counts["section:variant"] = counts.get("section:variant", 0) + 1
    return counts


def _check_tables() -> None:
    named = {s for s in PAGE_SECTIONS.values() if s is not None}
    named |= {s for _, s in (*STATION_RULES, *KEY_RULES)}
    unknown = named - _SECTION_IDS
    if unknown:
        raise GeneratorError(f"unknown sections in the section tables: {sorted(unknown)}")


_check_tables()
