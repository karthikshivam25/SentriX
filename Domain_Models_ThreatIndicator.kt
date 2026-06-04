package com.sentrix.domain.models

/**
 * ThreatIndicator
 *
 * Represents an Indicator of Compromise (IOC)
 * or security intelligence artifact used by
 * the SentriX platform for threat detection.
 *
 * Used by:
 * - ThreatIntelligenceEngine
 * - ThreatDetectionManager
 * - MalwareAnalysisEngine
 * - NetworkSecurityManager
 * - IntrusionDetectionEngine
 * - SecurityDashboard
 */
data class ThreatIndicator(

    /**
     * Unique indicator identifier.
     */
    val indicatorId: String,

    /**
     * Indicator value.
     */
    val value: String,

    /**
     * Indicator type.
     */
    val type: IndicatorType,

    /**
     * Threat category.
     */
    val category: ThreatCategory,

    /**
     * Threat severity.
     */
    val severity: ThreatSeverity,

    /**
     * Confidence score (0 - 100).
     */
    val confidenceScore: Int,

    /**
     * Reputation score (0 - 100).
     */
    val reputationScore: Int,

    /**
     * Source of intelligence.
     */
    val source: IntelligenceSource,

    /**
     * Indicator status.
     */
    val status: IndicatorStatus,

    /**
     * Date first observed.
     */
    val firstSeenAt: Long,

    /**
     * Date last observed.
     */
    val lastSeenAt: Long,

    /**
     * Description.
     */
    val description: String,

    /**
     * Recommended action.
     */
    val recommendation: String,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Types of threat indicators.
 */
enum class IndicatorType {
    IP_ADDRESS,
    DOMAIN,
    URL,
    FILE_HASH,
    PACKAGE_NAME,
    EMAIL_ADDRESS,
    CERTIFICATE,
    PROCESS_NAME,
    REGISTRY_KEY,
    NETWORK_SIGNATURE,
    UNKNOWN
}

/**
 * Intelligence sources.
 */
enum class IntelligenceSource {
    INTERNAL_ANALYSIS,
    THREAT_FEED,
    CLOUD_INTELLIGENCE,
    AI_ANALYSIS,
    COMMUNITY_FEED,
    SECURITY_RESEARCH,
    HYBRID
}

/**
 * Indicator lifecycle status.
 */
enum class IndicatorStatus {
    ACTIVE,
    MONITORING,
    EXPIRED,
    REVOKED,
    UNKNOWN
}
