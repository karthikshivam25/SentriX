package com.sentrix.core.constants

object ScanConstants {

    /* ============================================================
     * SCAN TYPES
     * ============================================================ */

    const val SCAN_TYPE_QUICK = "QUICK_SCAN"
    const val SCAN_TYPE_FULL = "FULL_SCAN"
    const val SCAN_TYPE_CUSTOM = "CUSTOM_SCAN"
    const val SCAN_TYPE_REALTIME = "REALTIME_SCAN"
    const val SCAN_TYPE_NETWORK = "NETWORK_SCAN"
    const val SCAN_TYPE_APK = "APK_SCAN"
    const val SCAN_TYPE_FILE = "FILE_SCAN"

    /* ============================================================
     * SCAN STATUS
     * ============================================================ */

    const val STATUS_PENDING = "PENDING"
    const val STATUS_INITIALIZING = "INITIALIZING"
    const val STATUS_RUNNING = "RUNNING"
    const val STATUS_PAUSED = "PAUSED"
    const val STATUS_COMPLETED = "COMPLETED"
    const val STATUS_CANCELLED = "CANCELLED"
    const val STATUS_FAILED = "FAILED"

    /* ============================================================
     * SCAN PRIORITY
     * ============================================================ */

    const val PRIORITY_LOW = 1
    const val PRIORITY_MEDIUM = 2
    const val PRIORITY_HIGH = 3
    const val PRIORITY_CRITICAL = 4

    /* ============================================================
     * SCAN ENGINE
     * ============================================================ */

    const val ENGINE_SIGNATURE_BASED =
        "SIGNATURE_BASED"

    const val ENGINE_HEURISTIC =
        "HEURISTIC"

    const val ENGINE_AI_ANALYSIS =
        "AI_ANALYSIS"

    const val ENGINE_BEHAVIORAL =
        "BEHAVIORAL"

    /* ============================================================
     * SCAN RESULTS
     * ============================================================ */

    const val RESULT_CLEAN = "CLEAN"
    const val RESULT_SUSPICIOUS = "SUSPICIOUS"
    const val RESULT_INFECTED = "INFECTED"
    const val RESULT_UNKNOWN = "UNKNOWN"

    /* ============================================================
     * THREAT SEVERITY
     * ============================================================ */

    const val SEVERITY_LOW = "LOW"
    const val SEVERITY_MEDIUM = "MEDIUM"
    const val SEVERITY_HIGH = "HIGH"
    const val SEVERITY_CRITICAL = "CRITICAL"

    /* ============================================================
     * SCAN ACTIONS
     * ============================================================ */

    const val ACTION_START_SCAN = "ACTION_START_SCAN"
    const val ACTION_STOP_SCAN = "ACTION_STOP_SCAN"
    const val ACTION_PAUSE_SCAN = "ACTION_PAUSE_SCAN"
    const val ACTION_RESUME_SCAN = "ACTION_RESUME_SCAN"

    /* ============================================================
     * SCAN LIMITS
     * ============================================================ */

    const val MAX_SCAN_FILE_SIZE_MB = 500L
    const val MAX_SCAN_DURATION_MINUTES = 60L
    const val MAX_SCAN_THREADS = 4

    /* ============================================================
     * REALTIME SCAN CONFIGURATION
     * ============================================================ */

    const val REALTIME_SCAN_INTERVAL = 15_000L
    const val BACKGROUND_SCAN_INTERVAL = 30_000L

    /* ============================================================
     * SCAN DIRECTORIES
     * ============================================================ */

    const val DIRECTORY_DOWNLOADS = "/Download/"
    const val DIRECTORY_APPS = "/Android/data/"
    const val DIRECTORY_TEMP = "/Temp/"
    const val DIRECTORY_CACHE = "/Cache/"

    /* ============================================================
     * FILE TYPES
     * ============================================================ */

    const val FILE_TYPE_APK = ".apk"
    const val FILE_TYPE_ZIP = ".zip"
    const val FILE_TYPE_JAR = ".jar"
    const val FILE_TYPE_DEX = ".dex"
    const val FILE_TYPE_EXE = ".exe"

    /* ============================================================
     * SCAN EVENTS
     * ============================================================ */

    const val EVENT_SCAN_STARTED =
        "EVENT_SCAN_STARTED"

    const val EVENT_SCAN_PROGRESS =
        "EVENT_SCAN_PROGRESS"

    const val EVENT_SCAN_COMPLETED =
        "EVENT_SCAN_COMPLETED"

    const val EVENT_THREAT_FOUND =
        "EVENT_THREAT_FOUND"

    /* ============================================================
     * SCAN METRICS
     * ============================================================ */

    const val METRIC_FILES_SCANNED =
        "FILES_SCANNED"

    const val METRIC_THREATS_FOUND =
        "THREATS_FOUND"

    const val METRIC_SCAN_DURATION =
        "SCAN_DURATION"

    /* ============================================================
     * QUARANTINE
     * ============================================================ */

    const val QUARANTINE_FOLDER =
        "SentriX_Quarantine"

    const val QUARANTINE_ENABLED = true

    /* ============================================================
     * SCAN LOGGING
     * ============================================================ */

    const val SCAN_LOG_TAG = "SENTRIX_SCAN"

    const val ENABLE_SCAN_LOGS = true

}
