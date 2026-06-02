package com.sentrix.core.constants

object AnalyticsConstants {

    /* ============================================================
     * ANALYTICS EVENTS
     * ============================================================ */

    const val EVENT_APP_OPENED =
        "event_app_opened"

    const val EVENT_USER_LOGIN =
        "event_user_login"

    const val EVENT_USER_LOGOUT =
        "event_user_logout"

    const val EVENT_USER_REGISTERED =
        "event_user_registered"

    /* ============================================================
     * SECURITY EVENTS
     * ============================================================ */

    const val EVENT_SCAN_STARTED =
        "event_scan_started"

    const val EVENT_SCAN_COMPLETED =
        "event_scan_completed"

    const val EVENT_THREAT_DETECTED =
        "event_threat_detected"

    const val EVENT_THREAT_REMOVED =
        "event_threat_removed"

    const val EVENT_REALTIME_PROTECTION_ENABLED =
        "event_realtime_protection_enabled"

    const val EVENT_REALTIME_PROTECTION_DISABLED =
        "event_realtime_protection_disabled"

    /* ============================================================
     * NETWORK EVENTS
     * ============================================================ */

    const val EVENT_NETWORK_CONNECTED =
        "event_network_connected"

    const val EVENT_NETWORK_DISCONNECTED =
        "event_network_disconnected"

    const val EVENT_API_REQUEST =
        "event_api_request"

    const val EVENT_API_FAILURE =
        "event_api_failure"

    /* ============================================================
     * USER INTERACTION EVENTS
     * ============================================================ */

    const val EVENT_BUTTON_CLICK =
        "event_button_click"

    const val EVENT_SCREEN_VIEW =
        "event_screen_view"

    const val EVENT_NAVIGATION =
        "event_navigation"

    const val EVENT_PERMISSION_GRANTED =
        "event_permission_granted"

    const val EVENT_PERMISSION_DENIED =
        "event_permission_denied"

    /* ============================================================
     * SCAN TYPES
     * ============================================================ */

    const val SCAN_TYPE_QUICK =
        "quick_scan"

    const val SCAN_TYPE_FULL =
        "full_scan"

    const val SCAN_TYPE_CUSTOM =
        "custom_scan"

    const val SCAN_TYPE_REALTIME =
        "realtime_scan"

    /* ============================================================
     * THREAT TYPES
     * ============================================================ */

    const val THREAT_TYPE_MALWARE =
        "malware"

    const val THREAT_TYPE_SPYWARE =
        "spyware"

    const val THREAT_TYPE_RANSOMWARE =
        "ransomware"

    const val THREAT_TYPE_PHISHING =
        "phishing"

    const val THREAT_TYPE_NETWORK_ATTACK =
        "network_attack"

    /* ============================================================
     * USER PROPERTIES
     * ============================================================ */

    const val PROPERTY_USER_ID =
        "property_user_id"

    const val PROPERTY_DEVICE_ID =
        "property_device_id"

    const val PROPERTY_APP_VERSION =
        "property_app_version"

    const val PROPERTY_DEVICE_MODEL =
        "property_device_model"

    const val PROPERTY_ANDROID_VERSION =
        "property_android_version"

    /* ============================================================
     * SCREEN NAMES
     * ============================================================ */

    const val SCREEN_SPLASH =
        "screen_splash"

    const val SCREEN_LOGIN =
        "screen_login"

    const val SCREEN_DASHBOARD =
        "screen_dashboard"

    const val SCREEN_SCANNER =
        "screen_scanner"

    const val SCREEN_REPORTS =
        "screen_reports"

    const val SCREEN_SETTINGS =
        "screen_settings"

    /* ============================================================
     * ANALYTICS PARAMETERS
     * ============================================================ */

    const val PARAM_SCAN_DURATION =
        "param_scan_duration"

    const val PARAM_THREAT_COUNT =
        "param_threat_count"

    const val PARAM_SCAN_RESULT =
        "param_scan_result"

    const val PARAM_ERROR_MESSAGE =
        "param_error_message"

    const val PARAM_BUTTON_NAME =
        "param_button_name"

    /* ============================================================
     * PERFORMANCE METRICS
     * ============================================================ */

    const val METRIC_CPU_USAGE =
        "metric_cpu_usage"

    const val METRIC_MEMORY_USAGE =
        "metric_memory_usage"

    const val METRIC_NETWORK_USAGE =
        "metric_network_usage"

    const val METRIC_BATTERY_USAGE =
        "metric_battery_usage"

    /* ============================================================
     * ANALYTICS STATUS
     * ============================================================ */

    const val STATUS_SUCCESS =
        "success"

    const val STATUS_FAILED =
        "failed"

    const val STATUS_CANCELLED =
        "cancelled"

    /* ============================================================
     * FIREBASE COLLECTIONS
     * ============================================================ */

    const val COLLECTION_SECURITY_EVENTS =
        "security_events"

    const val COLLECTION_SCAN_REPORTS =
        "scan_reports"

    const val COLLECTION_USER_ACTIVITY =
        "user_activity"

}
