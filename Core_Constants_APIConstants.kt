package com.sentrix.core.constants

object APIConstants {

    /* ============================================================
     * BASE URLS
     * ============================================================ */

    const val BASE_URL = "https://api.sentrix.com/"
    const val API_VERSION = "v1/"

    const val FULL_API_URL = BASE_URL + API_VERSION

    /* ============================================================
     * AUTHENTICATION ENDPOINTS
     * ============================================================ */

    const val LOGIN = "auth/login"
    const val REGISTER = "auth/register"
    const val LOGOUT = "auth/logout"
    const val REFRESH_TOKEN = "auth/refresh-token"
    const val FORGOT_PASSWORD = "auth/forgot-password"
    const val RESET_PASSWORD = "auth/reset-password"
    const val VERIFY_EMAIL = "auth/verify-email"

    /* ============================================================
     * USER ENDPOINTS
     * ============================================================ */

    const val USER_PROFILE = "user/profile"
    const val UPDATE_PROFILE = "user/update"
    const val CHANGE_PASSWORD = "user/change-password"

    /* ============================================================
     * SECURITY ENDPOINTS
     * ============================================================ */

    const val DEVICE_SCAN = "security/device-scan"
    const val APP_SCAN = "security/app-scan"
    const val MALWARE_SCAN = "security/malware-scan"
    const val NETWORK_SCAN = "security/network-scan"
    const val PHISHING_SCAN = "security/phishing-scan"
    const val PERMISSION_ANALYSIS = "security/permission-analysis"
    const val THREAT_ANALYSIS = "security/threat-analysis"

    /* ============================================================
     * ANALYTICS ENDPOINTS
     * ============================================================ */

    const val SECURITY_SCORE = "analytics/security-score"
    const val THREAT_REPORTS = "analytics/threat-reports"
    const val DEVICE_HEALTH = "analytics/device-health"
    const val WEEKLY_REPORT = "analytics/weekly-report"

    /* ============================================================
     * REAL-TIME PROTECTION
     * ============================================================ */

    const val REALTIME_STATUS = "protection/status"
    const val ENABLE_PROTECTION = "protection/enable"
    const val DISABLE_PROTECTION = "protection/disable"

    /* ============================================================
     * REQUEST HEADERS
     * ============================================================ */

    const val HEADER_AUTHORIZATION = "Authorization"
    const val HEADER_CONTENT_TYPE = "Content-Type"
    const val HEADER_ACCEPT = "Accept"
    const val HEADER_DEVICE_ID = "Device-Id"
    const val HEADER_PLATFORM = "Platform"

    const val CONTENT_TYPE_JSON = "application/json"
    const val BEARER_PREFIX = "Bearer "

    /* ============================================================
     * NETWORK CONFIGURATION
     * ============================================================ */

    const val CONNECT_TIMEOUT = 30L
    const val READ_TIMEOUT = 30L
    const val WRITE_TIMEOUT = 30L

    /* ============================================================
     * HTTP STATUS CODES
     * ============================================================ */

    const val HTTP_OK = 200
    const val HTTP_CREATED = 201
    const val HTTP_BAD_REQUEST = 400
    const val HTTP_UNAUTHORIZED = 401
    const val HTTP_FORBIDDEN = 403
    const val HTTP_NOT_FOUND = 404
    const val HTTP_CONFLICT = 409
    const val HTTP_SERVER_ERROR = 500

    /* ============================================================
     * RESPONSE KEYS
     * ============================================================ */

    const val KEY_SUCCESS = "success"
    const val KEY_MESSAGE = "message"
    const val KEY_DATA = "data"
    const val KEY_TOKEN = "token"
    const val KEY_ERROR = "error"

    /* ============================================================
     * API SECURITY
     * ============================================================ */

    const val API_KEY_HEADER = "X-API-KEY"
    const val DEVICE_SIGNATURE_HEADER = "X-DEVICE-SIGNATURE"

    /* ============================================================
     * SOCKET EVENTS
     * ============================================================ */

    const val SOCKET_THREAT_ALERT = "threat_alert"
    const val SOCKET_SCAN_UPDATE = "scan_update"
    const val SOCKET_SECURITY_EVENT = "security_event"

    /* ============================================================
     * CACHE KEYS
     * ============================================================ */

    const val CACHE_SECURITY_SCORE = "cache_security_score"
    const val CACHE_THREAT_REPORT = "cache_threat_report"
    const val CACHE_USER_PROFILE = "cache_user_profile"

}