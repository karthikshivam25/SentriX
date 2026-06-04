package com.sentrix.domain.models

/**
 * Threat
 *
 * Represents a detected security threat
 * within the SentriX platform.
 *
 * Used by:
 * - ThreatDetectionEngine
 * - Malware Scanner
 * - VPN Detection
 * - Root Detection
 * - AI Threat Analysis
 * - Security Dashboard
 * - Incident Reporting
 */
data class Threat(

    /**
     * Unique threat identifier.
     */
    val id: String,

    /**
     * Threat title.
     */
    val title: String,

    /**
     * Detailed description.
     */
    val description: String,

    /**
     * Threat category.
     */
    val category: ThreatCategory,

    /**
     * Severity level.
     */
    val severity: ThreatSeverity,

    /**
     * Current threat status.
     */
    val status: ThreatStatus,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Time detected.
     */
    val detectedAt: Long,

    /**
     * Device component affected.
     */
    val affectedComponent: String,

    /**
     * Recommended action.
     */
    val recommendation: String,

    /**
     * Whether threat has been resolved.
     */
    val isResolved: Boolean = false,

    /**
     * Optional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Threat severity levels.
 */
enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Threat categories.
 */
enum class ThreatCategory {
    MALWARE,
    PHISHING,
    ROOT_DETECTION,
    EMULATOR_DETECTION,
    VPN_DETECTION,
    NETWORK_ATTACK,
    SUSPICIOUS_APP,
    DATA_LEAK,
    PERMISSION_ABUSE,
    UNKNOWN
}

/**
 * Threat lifecycle status.
 */
enum class ThreatStatus {
    DETECTED,
    INVESTIGATING,
    MITIGATED,
    RESOLVED,
    IGNORED
}
