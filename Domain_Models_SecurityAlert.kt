package com.sentrix.domain.models

/**
 * SecurityAlert
 *
 * Represents a security alert generated
 * by the SentriX platform when a threat,
 * anomaly, or security event requires
 * user or system attention.
 *
 * Used by:
 * - AlertManager
 * - ThreatDetectionEngine
 * - MalwareScanner
 * - SecurityDashboard
 * - NotificationCenter
 * - IncidentResponseManager
 */
data class SecurityAlert(

    /**
     * Unique alert identifier.
     */
    val alertId: String,

    /**
     * Alert title.
     */
    val title: String,

    /**
     * Alert message.
     */
    val message: String,

    /**
     * Alert category.
     */
    val category: AlertCategory,

    /**
     * Alert severity.
     */
    val severity: ThreatSeverity,

    /**
     * Alert priority.
     */
    val priority: AlertPriority,

    /**
     * Alert status.
     */
    val status: AlertStatus,

    /**
     * Related threat identifier.
     */
    val relatedThreatId: String? = null,

    /**
     * Related malware identifier.
     */
    val relatedMalwareId: String? = null,

    /**
     * Timestamp when alert
     * was generated.
     */
    val createdAt: Long,

    /**
     * Timestamp when alert
     * was acknowledged.
     */
    val acknowledgedAt: Long? = null,

    /**
     * Recommended action.
     */
    val recommendation: String,

    /**
     * Whether user action
     * is required.
     */
    val requiresAction: Boolean,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Security alert categories.
 */
enum class AlertCategory {
    MALWARE_DETECTED,
    THREAT_DETECTED,
    DEVICE_INTEGRITY,
    NETWORK_SECURITY,
    PHISHING_ATTEMPT,
    SCAM_DETECTED,
    PERMISSION_RISK,
    FIREWALL_EVENT,
    INTRUSION_ATTEMPT,
    SYSTEM_SECURITY,
    COMPLIANCE_WARNING,
    INFORMATIONAL
}

/**
 * Alert priority levels.
 */
enum class AlertPriority {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Alert lifecycle status.
 */
enum class AlertStatus {
    NEW,
    ACKNOWLEDGED,
    IN_PROGRESS,
    RESOLVED,
    DISMISSED
}
