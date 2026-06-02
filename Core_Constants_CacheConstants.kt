package com.sentrix.core.constants

object CacheConstants {

    /* ============================================================
     * CACHE CONFIGURATION
     * ============================================================ */

    const val CACHE_SIZE_MB = 50L
    const val CACHE_SIZE_BYTES =
        CACHE_SIZE_MB * 1024L * 1024L

    const val MEMORY_CACHE_SIZE_MB = 20L
    const val DISK_CACHE_SIZE_MB = 100L

    /* ============================================================
     * CACHE EXPIRATION TIMES
     * ============================================================ */

    const val CACHE_DURATION_SHORT = 5 * 60L
    const val CACHE_DURATION_MEDIUM = 30 * 60L
    const val CACHE_DURATION_LONG = 24 * 60 * 60L

    const val CACHE_EXPIRY_SECURITY_SCORE =
        15 * 60L

    const val CACHE_EXPIRY_SCAN_RESULTS =
        30 * 60L

    const val CACHE_EXPIRY_USER_PROFILE =
        24 * 60 * 60L

    const val CACHE_EXPIRY_NETWORK_LOGS =
        10 * 60L

    /* ============================================================
     * CACHE KEYS
     * ============================================================ */

    const val CACHE_USER_DATA =
        "cache_user_data"

    const val CACHE_AUTH_TOKEN =
        "cache_auth_token"

    const val CACHE_SECURITY_SCORE =
        "cache_security_score"

    const val CACHE_SCAN_HISTORY =
        "cache_scan_history"

    const val CACHE_SCAN_RESULTS =
        "cache_scan_results"

    const val CACHE_THREAT_REPORTS =
        "cache_threat_reports"

    const val CACHE_DEVICE_STATUS =
        "cache_device_status"

    const val CACHE_NETWORK_ANALYSIS =
        "cache_network_analysis"

    const val CACHE_PERMISSION_ANALYSIS =
        "cache_permission_analysis"

    const val CACHE_NOTIFICATION_DATA =
        "cache_notification_data"

    /* ============================================================
     * IMAGE CACHE
     * ============================================================ */

    const val CACHE_PROFILE_IMAGES =
        "cache_profile_images"

    const val CACHE_REPORT_IMAGES =
        "cache_report_images"

    /* ============================================================
     * CACHE TAGS
     * ============================================================ */

    const val TAG_API_CACHE =
        "API_CACHE"

    const val TAG_MEMORY_CACHE =
        "MEMORY_CACHE"

    const val TAG_DISK_CACHE =
        "DISK_CACHE"

    /* ============================================================
     * CACHE CLEANUP
     * ============================================================ */

    const val CACHE_CLEANUP_INTERVAL =
        12 * 60 * 60L

    const val MAX_CACHE_ENTRY_COUNT = 1000

    /* ============================================================
     * CACHE STATUS
     * ============================================================ */

    const val CACHE_HIT = "CACHE_HIT"
    const val CACHE_MISS = "CACHE_MISS"
    const val CACHE_EXPIRED = "CACHE_EXPIRED"
    const val CACHE_CLEARED = "CACHE_CLEARED"

    /* ============================================================
     * OFFLINE MODE CACHE
     * ============================================================ */

    const val OFFLINE_CACHE_ENABLED = true

    const val OFFLINE_CACHE_DURATION =
        7 * 24 * 60 * 60L

    /* ============================================================
     * SECURITY CACHE
     * ============================================================ */

    const val SECURE_CACHE_ENABLED = true

    const val ENCRYPT_CACHE_DATA = true

    /* ============================================================
     * CACHE DIRECTORIES
     * ============================================================ */

    const val CACHE_DIR_API = "api_cache"
    const val CACHE_DIR_IMAGES = "image_cache"
    const val CACHE_DIR_REPORTS = "report_cache"
    const val CACHE_DIR_TEMP = "temp_cache"

}
