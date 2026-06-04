package com.sentrix.domain.models

/**
 * RiskProfile
 *
 * Represents the overall risk posture
 * of a device, user, or organization
 * within the SentriX platform.
 *
 * Used by:
 * - AI Risk Engine
 * - Threat Analysis Engine
 * - Security Dashboard
 * - Compliance Monitoring
 * - Security Recommendations
 * - Incident Response
 */
data class RiskProfile(

    /**
     * Unique profile identifier.
     */
    val profileId: String,

    /**
     * Entity identifier.
     * (User, Device, Organization)
     */
    val entityId: String,

    /**
     * Entity name.
     */
    val entityName: String,

    /**
     * Overall risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Current risk level.
     */
    val riskLevel: RiskLevel,

    /**
     * Number of active threats.
     */
    val activeThreats: Int,

    /**
     * Number of detected malware.
     */
    val detectedMalware: Int,

    /**
     * Number of vulnerabilities.
     */
    val vulnerabilities: Int,

    /**
     * Security score.
     */
    val securityScore: Int,

    /**
     * Last assessment timestamp.
     */
    val assessedAt: Long,

    /**
     * Risk factors contributing
     * to the overall score.
     */
    val riskFactors: List<RiskFactor> = emptyList(),

    /**
     * Recommended actions.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Optional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Risk levels.
 */
enum class RiskLevel {
    LOW,
    MODERATE,
    HIGH,
    CRITICAL
}

/**
 * Individual risk factor.
 */
data class RiskFactor(

    /**
     * Factor name.
     */
    val name: String,

    /**
     * Factor description.
     */
    val description: String,

    /**
     * Impact score (0 - 100).
     */
    val impactScore: Int,

    /**
     * Severity level.
     */
    val severity: ThreatSeverity
)
