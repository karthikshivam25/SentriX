package com.sentrix.domain.models

/**
 * IntrusionEvent
 *
 * Represents a detected intrusion attempt
 * or suspicious security event identified
 * by the SentriX platform.
 *
 * Used by:
 * - IntrusionDetectionEngine
 * - ThreatDetectionManager
 * - NetworkSecurityManager
 * - FirewallManager
 * - SecurityDashboard
 * - IncidentResponseManager
 */
data class IntrusionEvent(

    /**
     * Unique event identifier.
     */
    val eventId: String,

    /**
     * Event title.
     */
    val title: String,

    /**
     * Detailed event description.
     */
    val description: String,

    /**
     * Intrusion category.
     */
    val category: IntrusionCategory,

    /**
     * Event severity.
     */
    val severity: ThreatSeverity,

    /**
     * Event status.
     */
    val status: IntrusionStatus,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Source IP address.
     */
    val sourceIp: String,

    /**
     * Destination IP address.
     */
    val destinationIp: String,

    /**
     * Target component.
     */
    val targetComponent: String,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Detection engine.
     */
    val detectionEngine: String,

    /**
     * Recommended response.
     */
    val recommendation: String,

    /**
     * Whether the intrusion
     * was blocked.
     */
    val isBlocked: Boolean,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Intrusion categories.
 */
enum class IntrusionCategory {
    PORT_SCAN,
    BRUTE_FORCE_ATTACK,
    MALICIOUS_TRAFFIC,
    DNS_ATTACK,
    MAN_IN_THE_MIDDLE,
    DATA_EXFILTRATION,
    NETWORK_RECONNAISSANCE,
    PRIVILEGE_ESCALATION,
    UNAUTHORIZED_ACCESS,
    UNKNOWN
}

/**
 * Intrusion event status.
 */
enum class IntrusionStatus {
    DETECTED,
    INVESTIGATING,
    CONTAINED,
    MITIGATED,
    RESOLVED,
    FALSE_POSITIVE
}
