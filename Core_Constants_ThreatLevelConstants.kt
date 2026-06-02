package com.sentrix.core.constants

object ThreatLevelConstants {

    /* ============================================================
     * THREAT LEVEL VALUES
     * ============================================================ */

    const val SAFE = 0
    const val LOW = 1
    const val MEDIUM = 2
    const val HIGH = 3
    const val CRITICAL = 4

    /* ============================================================
     * THREAT LEVEL NAMES
     * ============================================================ */

    const val LEVEL_SAFE = "SAFE"
    const val LEVEL_LOW = "LOW"
    const val LEVEL_MEDIUM = "MEDIUM"
    const val LEVEL_HIGH = "HIGH"
    const val LEVEL_CRITICAL = "CRITICAL"

    /* ============================================================
     * THREAT SCORE RANGES
     * ============================================================ */

    const val SCORE_SAFE_MIN = 0
    const val SCORE_SAFE_MAX = 20

    const val SCORE_LOW_MIN = 21
    const val SCORE_LOW_MAX = 40

    const val SCORE_MEDIUM_MIN = 41
    const val SCORE_MEDIUM_MAX = 60

    const val SCORE_HIGH_MIN = 61
    const val SCORE_HIGH_MAX = 80

    const val SCORE_CRITICAL_MIN = 81
    const val SCORE_CRITICAL_MAX = 100

    /* ============================================================
     * THREAT COLORS
     * ============================================================ */

    const val COLOR_SAFE = "#00C853"
    const val COLOR_LOW = "#64DD17"
    const val COLOR_MEDIUM = "#FFD600"
    const val COLOR_HIGH = "#FF6D00"
    const val COLOR_CRITICAL = "#D50000"

    /* ============================================================
     * THREAT DESCRIPTIONS
     * ============================================================ */

    const val DESCRIPTION_SAFE =
        "No security threats detected."

    const val DESCRIPTION_LOW =
        "Minor security risks detected."

    const val DESCRIPTION_MEDIUM =
        "Potentially harmful activity detected."

    const val DESCRIPTION_HIGH =
        "High-risk threats detected on the device."

    const val DESCRIPTION_CRITICAL =
        "Critical malware or system compromise detected."

    /* ============================================================
     * THREAT ACTIONS
     * ============================================================ */

    const val ACTION_IGNORE = "IGNORE"
    const val ACTION_MONITOR = "MONITOR"
    const val ACTION_REVIEW = "REVIEW"
    const val ACTION_QUARANTINE = "QUARANTINE"
    const val ACTION_REMOVE = "REMOVE"

    /* ============================================================
     * THREAT TYPES
     * ============================================================ */

    const val TYPE_MALWARE = "MALWARE"
    const val TYPE_SPYWARE = "SPYWARE"
    const val TYPE_RANSOMWARE = "RANSOMWARE"
    const val TYPE_PHISHING = "PHISHING"
    const val TYPE_NETWORK_ATTACK = "NETWORK_ATTACK"
    const val TYPE_PERMISSION_ABUSE = "PERMISSION_ABUSE"
    const val TYPE_ROOT_ACCESS = "ROOT_ACCESS"
    const val TYPE_DATA_LEAK = "DATA_LEAK"

    /* ============================================================
     * RISK FACTORS
     * ============================================================ */

    const val RISK_UNKNOWN_SOURCE_APP =
        "UNKNOWN_SOURCE_APP"

    const val RISK_DANGEROUS_PERMISSION =
        "DANGEROUS_PERMISSION"

    const val RISK_ROOTED_DEVICE =
        "ROOTED_DEVICE"

    const val RISK_UNENCRYPTED_CONNECTION =
        "UNENCRYPTED_CONNECTION"

    const val RISK_DEBUG_MODE_ENABLED =
        "DEBUG_MODE_ENABLED"

    /* ============================================================
     * THREAT STATUS
     * ============================================================ */

    const val STATUS_ACTIVE = "ACTIVE"
    const val STATUS_RESOLVED = "RESOLVED"
    const val STATUS_QUARANTINED = "QUARANTINED"
    const val STATUS_IGNORED = "IGNORED"

    /* ============================================================
     * ALERT PRIORITY
     * ============================================================ */

    const val PRIORITY_LOW = 1
    const val PRIORITY_MEDIUM = 2
    const val PRIORITY_HIGH = 3
    const val PRIORITY_URGENT = 4

}
