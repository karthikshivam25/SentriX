package com.sentrix.core.constants

object AppConstants {

    /* ============================================================
     * APPLICATION INFO
     * ============================================================ */

    const val APP_NAME = "SentriX"
    const val APP_TAG = "SENTRIX_SECURITY"

    const val APP_VERSION = "1.0.0"
    const val BUILD_TYPE = "PRODUCTION"

    /* ============================================================
     * PACKAGE INFO
     * ============================================================ */

    const val PACKAGE_NAME = "com.sentrix.security"
    const val SUPPORT_EMAIL = "support@sentrix.com"
    const val WEBSITE_URL = "https://www.sentrix.com"

    /* ============================================================
     * SHARED PREFERENCES
     * ============================================================ */

    const val PREF_NAME = "sentrix_preferences"

    const val PREF_IS_LOGGED_IN = "pref_is_logged_in"
    const val PREF_AUTH_TOKEN = "pref_auth_token"
    const val PREF_REFRESH_TOKEN = "pref_refresh_token"

    const val PREF_USER_ID = "pref_user_id"
    const val PREF_USERNAME = "pref_username"
    const val PREF_EMAIL = "pref_email"

    const val PREF_THEME_MODE = "pref_theme_mode"
    const val PREF_LANGUAGE = "pref_language"

    const val PREF_BIOMETRIC_ENABLED = "pref_biometric_enabled"
    const val PREF_REALTIME_PROTECTION = "pref_realtime_protection"

    /* ============================================================
     * DATABASE
     * ============================================================ */

    const val DATABASE_NAME = "sentrix_database"
    const val DATABASE_VERSION = 1

    /* ============================================================
     * INTENT KEYS
     * ============================================================ */

    const val EXTRA_USER_ID = "extra_user_id"
    const val EXTRA_SCAN_RESULT = "extra_scan_result"
    const val EXTRA_THREAT_LEVEL = "extra_threat_level"
    const val EXTRA_NOTIFICATION_TYPE = "extra_notification_type"

    /* ============================================================
     * DATE & TIME
     * ============================================================ */

    const val DATE_FORMAT = "dd/MM/yyyy"
    const val TIME_FORMAT = "HH:mm:ss"
    const val DATE_TIME_FORMAT = "dd/MM/yyyy HH:mm:ss"

    /* ============================================================
     * UI CONFIGURATION
     * ============================================================ */

    const val SPLASH_DELAY = 2500L
    const val ANIMATION_DURATION = 300L
    const val LOADING_DELAY = 1500L

    /* ============================================================
     * PAGINATION
     * ============================================================ */

    const val DEFAULT_PAGE_SIZE = 20
    const val MAX_PAGE_SIZE = 100

    /* ============================================================
     * LOGGING
     * ============================================================ */

    const val LOG_DEBUG = "DEBUG"
    const val LOG_ERROR = "ERROR"
    const val LOG_WARNING = "WARNING"
    const val LOG_INFO = "INFO"

    /* ============================================================
     * FILE & STORAGE
     * ============================================================ */

    const val TEMP_FOLDER = "temp"
    const val REPORT_FOLDER = "reports"
    const val EXPORT_FOLDER = "exports"

    const val APK_EXTENSION = ".apk"
    const val PDF_EXTENSION = ".pdf"
    const val JSON_EXTENSION = ".json"

    /* ============================================================
     * SECURITY LEVELS
     * ============================================================ */

    const val SECURITY_LOW = "LOW"
    const val SECURITY_MEDIUM = "MEDIUM"
    const val SECURITY_HIGH = "HIGH"
    const val SECURITY_CRITICAL = "CRITICAL"

    /* ============================================================
     * SCAN STATUS
     * ============================================================ */

    const val SCAN_PENDING = "PENDING"
    const val SCAN_RUNNING = "RUNNING"
    const val SCAN_COMPLETED = "COMPLETED"
    const val SCAN_FAILED = "FAILED"

    /* ============================================================
     * NOTIFICATION CHANNELS
     * ============================================================ */

    const val CHANNEL_SECURITY_ALERTS = "security_alerts"
    const val CHANNEL_SCAN_REPORTS = "scan_reports"
    const val CHANNEL_REALTIME_PROTECTION = "realtime_protection"

    /* ============================================================
     * THEME MODES
     * ============================================================ */

    const val THEME_LIGHT = "LIGHT"
    const val THEME_DARK = "DARK"
    const val THEME_SYSTEM = "SYSTEM"

    /* ============================================================
     * LANGUAGE CODES
     * ============================================================ */

    const val LANG_ENGLISH = "en"
    const val LANG_TAMIL = "ta"
    const val LANG_HINDI = "hi"

    /* ============================================================
     * BIOMETRIC TYPES
     * ============================================================ */

    const val BIOMETRIC_FACE = "FACE"
    const val BIOMETRIC_FINGERPRINT = "FINGERPRINT"

}