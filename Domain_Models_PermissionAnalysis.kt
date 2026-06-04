package com.sentrix.domain.models

/**
 * PermissionAnalysis
 *
 * Represents the security analysis of
 * application permissions performed by
 * the SentriX platform.
 *
 * Used by:
 * - PermissionAnalyzer
 * - ThreatDetectionEngine
 * - AppBehaviorAnalyzer
 * - RiskAssessmentEngine
 * - SecurityDashboard
 * - AIThreatAnalysis
 */
data class PermissionAnalysis(

    /**
     * Unique analysis identifier.
     */
    val analysisId: String,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Application display name.
     */
    val applicationName: String,

    /**
     * Total permissions requested.
     */
    val totalPermissions: Int,

    /**
     * Dangerous permissions count.
     */
    val dangerousPermissions: Int,

    /**
     * Permission risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Overall analysis verdict.
     */
    val verdict: PermissionVerdict,

    /**
     * Threat severity.
     */
    val severity: ThreatSeverity,

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Requested permissions.
     */
    val permissions: List<AppPermission> = emptyList(),

    /**
     * Security findings.
     */
    val findings: List<PermissionFinding> = emptyList(),

    /**
     * Recommendations.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Permission analysis verdict.
 */
enum class PermissionVerdict {
    SAFE,
    LOW_RISK,
    SUSPICIOUS,
    HIGH_RISK,
    MALICIOUS
}

/**
 * Application permission.
 */
data class AppPermission(

    /**
     * Android permission name.
     */
    val name: String,

    /**
     * Permission category.
     */
    val category: PermissionCategory,

    /**
     * Whether permission is dangerous.
     */
    val isDangerous: Boolean,

    /**
     * Whether permission is granted.
     */
    val isGranted: Boolean,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int
)

/**
 * Permission categories.
 */
enum class PermissionCategory {
    CAMERA,
    MICROPHONE,
    LOCATION,
    CONTACTS,
    SMS,
    STORAGE,
    PHONE,
    CALENDAR,
    NOTIFICATIONS,
    NETWORK,
    BLUETOOTH,
    SENSORS,
    SYSTEM,
    OTHER
}

/**
 * Permission security finding.
 */
data class PermissionFinding(

    /**
     * Finding title.
     */
    val title: String,

    /**
     * Finding description.
     */
    val description: String,

    /**
     * Severity level.
     */
    val severity: ThreatSeverity
)
