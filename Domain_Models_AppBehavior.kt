package com.sentrix.domain.models

/**
 * AppBehavior
 *
 * Represents behavioral analysis data
 * collected from an application during
 * security monitoring and threat analysis.
 *
 * Used by:
 * - BehaviorAnalysisEngine
 * - Malware Detection Engine
 * - AI Threat Analyzer
 * - Application Monitor
 * - Security Dashboard
 * - Risk Assessment Engine
 */
data class AppBehavior(

    /**
     * Unique behavior record identifier.
     */
    val behaviorId: String,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Application display name.
     */
    val appName: String,

    /**
     * Behavior category.
     */
    val category: BehaviorCategory,

    /**
     * Behavior severity.
     */
    val severity: ThreatSeverity,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Description of observed behavior.
     */
    val description: String,

    /**
     * Timestamp when behavior
     * was detected.
     */
    val detectedAt: Long,

    /**
     * Frequency of occurrence.
     */
    val occurrenceCount: Int,

    /**
     * Whether behavior is considered
     * suspicious.
     */
    val isSuspicious: Boolean,

    /**
     * Recommended action.
     */
    val recommendation: String,

    /**
     * Additional permissions
     * involved in behavior.
     */
    val permissions: List<String> = emptyList(),

    /**
     * Optional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Application behavior categories.
 */
enum class BehaviorCategory {
    NETWORK_ACTIVITY,
    FILE_ACCESS,
    PERMISSION_USAGE,
    BACKGROUND_EXECUTION,
    DATA_COLLECTION,
    CLIPBOARD_ACCESS,
    SCREEN_CAPTURE,
    SMS_ACCESS,
    CONTACT_ACCESS,
    LOCATION_TRACKING,
    CAMERA_USAGE,
    MICROPHONE_USAGE,
    BATTERY_ABUSE,
    SYSTEM_MODIFICATION,
    UNKNOWN
}
