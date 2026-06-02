package com.sentrix.core.constants

object DatabaseConstants {

    /* ============================================================
     * DATABASE CONFIGURATION
     * ============================================================ */

    const val DATABASE_NAME = "sentrix_database"
    const val DATABASE_VERSION = 1

    /* ============================================================
     * TABLE NAMES
     * ============================================================ */

    const val TABLE_USERS = "users"
    const val TABLE_THREATS = "threats"
    const val TABLE_SCAN_HISTORY = "scan_history"
    const val TABLE_SECURITY_REPORTS = "security_reports"
    const val TABLE_DEVICE_ACTIVITY = "device_activity"
    const val TABLE_NETWORK_LOGS = "network_logs"
    const val TABLE_APP_PERMISSIONS = "app_permissions"
    const val TABLE_NOTIFICATIONS = "notifications"
    const val TABLE_REALTIME_EVENTS = "realtime_events"

    /* ============================================================
     * COMMON COLUMN NAMES
     * ============================================================ */

    const val COLUMN_ID = "id"
    const val COLUMN_CREATED_AT = "created_at"
    const val COLUMN_UPDATED_AT = "updated_at"

    /* ============================================================
     * USER TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_USER_ID = "user_id"
    const val COLUMN_USERNAME = "username"
    const val COLUMN_EMAIL = "email"
    const val COLUMN_PASSWORD = "password"
    const val COLUMN_PROFILE_IMAGE = "profile_image"

    /* ============================================================
     * THREAT TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_THREAT_NAME = "threat_name"
    const val COLUMN_THREAT_TYPE = "threat_type"
    const val COLUMN_THREAT_LEVEL = "threat_level"
    const val COLUMN_THREAT_DESCRIPTION = "threat_description"
    const val COLUMN_THREAT_STATUS = "threat_status"

    /* ============================================================
     * SCAN HISTORY TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_SCAN_ID = "scan_id"
    const val COLUMN_SCAN_TYPE = "scan_type"
    const val COLUMN_SCAN_STATUS = "scan_status"
    const val COLUMN_SCAN_RESULT = "scan_result"
    const val COLUMN_SCAN_DATE = "scan_date"

    /* ============================================================
     * DEVICE ACTIVITY TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_ACTIVITY_TYPE = "activity_type"
    const val COLUMN_ACTIVITY_DETAILS = "activity_details"
    const val COLUMN_ACTIVITY_TIME = "activity_time"

    /* ============================================================
     * NETWORK LOG TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_IP_ADDRESS = "ip_address"
    const val COLUMN_DOMAIN = "domain"
    const val COLUMN_REQUEST_TYPE = "request_type"
    const val COLUMN_RESPONSE_CODE = "response_code"
    const val COLUMN_NETWORK_STATUS = "network_status"

    /* ============================================================
     * APP PERMISSION TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_PACKAGE_NAME = "package_name"
    const val COLUMN_PERMISSION_NAME = "permission_name"
    const val COLUMN_PERMISSION_STATUS = "permission_status"
    const val COLUMN_RISK_LEVEL = "risk_level"

    /* ============================================================
     * NOTIFICATION TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_NOTIFICATION_TITLE = "notification_title"
    const val COLUMN_NOTIFICATION_MESSAGE = "notification_message"
    const val COLUMN_NOTIFICATION_TYPE = "notification_type"
    const val COLUMN_IS_READ = "is_read"

    /* ============================================================
     * REALTIME EVENT TABLE COLUMNS
     * ============================================================ */

    const val COLUMN_EVENT_NAME = "event_name"
    const val COLUMN_EVENT_TYPE = "event_type"
    const val COLUMN_EVENT_SEVERITY = "event_severity"
    const val COLUMN_EVENT_TIMESTAMP = "event_timestamp"

    /* ============================================================
     * QUERY LIMITS
     * ============================================================ */

    const val DEFAULT_QUERY_LIMIT = 50
    const val MAX_QUERY_LIMIT = 500

    /* ============================================================
     * DATABASE STATUS
     * ============================================================ */

    const val DB_SUCCESS = "DATABASE_SUCCESS"
    const val DB_ERROR = "DATABASE_ERROR"

}