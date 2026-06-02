package com.sentrix.core.constants

object IntentConstants {

    /* ============================================================
     * GENERAL INTENT EXTRAS
     * ============================================================ */

    const val EXTRA_ID = "extra_id"
    const val EXTRA_NAME = "extra_name"
    const val EXTRA_TITLE = "extra_title"
    const val EXTRA_MESSAGE = "extra_message"
    const val EXTRA_TYPE = "extra_type"
    const val EXTRA_STATUS = "extra_status"

    /* ============================================================
     * USER INTENT EXTRAS
     * ============================================================ */

    const val EXTRA_USER_ID = "extra_user_id"
    const val EXTRA_USERNAME = "extra_username"
    const val EXTRA_EMAIL = "extra_email"
    const val EXTRA_PROFILE_IMAGE = "extra_profile_image"

    /* ============================================================
     * AUTHENTICATION INTENTS
     * ============================================================ */

    const val EXTRA_AUTH_TOKEN = "extra_auth_token"
    const val EXTRA_REFRESH_TOKEN = "extra_refresh_token"
    const val EXTRA_LOGIN_STATUS = "extra_login_status"

    /* ============================================================
     * SECURITY & THREAT INTENTS
     * ============================================================ */

    const val EXTRA_THREAT_ID = "extra_threat_id"
    const val EXTRA_THREAT_NAME = "extra_threat_name"
    const val EXTRA_THREAT_LEVEL = "extra_threat_level"
    const val EXTRA_THREAT_TYPE = "extra_threat_type"
    const val EXTRA_THREAT_STATUS = "extra_threat_status"

    /* ============================================================
     * SCAN INTENTS
     * ============================================================ */

    const val EXTRA_SCAN_ID = "extra_scan_id"
    const val EXTRA_SCAN_TYPE = "extra_scan_type"
    const val EXTRA_SCAN_STATUS = "extra_scan_status"
    const val EXTRA_SCAN_RESULT = "extra_scan_result"
    const val EXTRA_SCAN_PROGRESS = "extra_scan_progress"

    /* ============================================================
     * FILE INTENTS
     * ============================================================ */

    const val EXTRA_FILE_PATH = "extra_file_path"
    const val EXTRA_FILE_NAME = "extra_file_name"
    const val EXTRA_FILE_SIZE = "extra_file_size"
    const val EXTRA_FILE_TYPE = "extra_file_type"

    /* ============================================================
     * NETWORK INTENTS
     * ============================================================ */

    const val EXTRA_IP_ADDRESS = "extra_ip_address"
    const val EXTRA_DOMAIN = "extra_domain"
    const val EXTRA_NETWORK_STATUS = "extra_network_status"

    /* ============================================================
     * NOTIFICATION INTENTS
     * ============================================================ */

    const val EXTRA_NOTIFICATION_ID = "extra_notification_id"
    const val EXTRA_NOTIFICATION_TYPE = "extra_notification_type"

    /* ============================================================
     * DEVICE INTENTS
     * ============================================================ */

    const val EXTRA_DEVICE_ID = "extra_device_id"
    const val EXTRA_DEVICE_NAME = "extra_device_name"
    const val EXTRA_DEVICE_STATUS = "extra_device_status"

    /* ============================================================
     * SETTINGS INTENTS
     * ============================================================ */

    const val EXTRA_THEME_MODE = "extra_theme_mode"
    const val EXTRA_LANGUAGE = "extra_language"
    const val EXTRA_BIOMETRIC_ENABLED =
        "extra_biometric_enabled"

    /* ============================================================
     * ACTIVITY REQUEST CODES
     * ============================================================ */

    const val REQUEST_LOGIN = 1001
    const val REQUEST_REGISTER = 1002
    const val REQUEST_SCAN = 1003
    const val REQUEST_PERMISSION = 1004
    const val REQUEST_FILE_PICKER = 1005
    const val REQUEST_BIOMETRIC = 1006

    /* ============================================================
     * RESULT CODES
     * ============================================================ */

    const val RESULT_SUCCESS = 200
    const val RESULT_FAILED = 400
    const val RESULT_CANCELLED = 401

    /* ============================================================
     * BROADCAST ACTIONS
     * ============================================================ */

    const val ACTION_SCAN_STARTED =
        "com.sentrix.ACTION_SCAN_STARTED"

    const val ACTION_SCAN_COMPLETED =
        "com.sentrix.ACTION_SCAN_COMPLETED"

    const val ACTION_THREAT_DETECTED =
        "com.sentrix.ACTION_THREAT_DETECTED"

    const val ACTION_SECURITY_ALERT =
        "com.sentrix.ACTION_SECURITY_ALERT"

    const val ACTION_NETWORK_CHANGED =
        "com.sentrix.ACTION_NETWORK_CHANGED"

    /* ============================================================
     * SERVICE ACTIONS
     * ============================================================ */

    const val ACTION_START_PROTECTION =
        "com.sentrix.ACTION_START_PROTECTION"

    const val ACTION_STOP_PROTECTION =
        "com.sentrix.ACTION_STOP_PROTECTION"

    const val ACTION_START_SCAN =
        "com.sentrix.ACTION_START_SCAN"

    const val ACTION_STOP_SCAN =
        "com.sentrix.ACTION_STOP_SCAN"

}
