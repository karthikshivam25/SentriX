package com.sentrix.domain.models

/**
 * SystemHealth
 *
 * Represents the overall health, performance,
 * stability, and security condition of a device
 * or system monitored by the SentriX platform.
 *
 * This model is used to provide real-time health
 * insights, resource utilization metrics, system
 * diagnostics, and security posture indicators.
 *
 * Used by:
 * - SystemHealthManager
 * - DeviceMonitoringService
 * - SecurityDashboard
 * - PerformanceAnalyzer
 * - RealtimeProtectionEngine
 * - DeviceIntegrityManager
 * - AnalyticsEngine
 * - AlertManagementService
 */
data class SystemHealth(

    /**
     * Unique health record identifier.
     */
    val healthId: String,

    /**
     * Device identifier associated
     * with the health report.
     */
    val deviceId: String,

    /**
     * Timestamp when the health
     * snapshot was generated.
     */
    val recordedAt: Long,

    /**
     * Overall health score.
     *
     * Range:
     * 0 - 100
     */
    val healthScore: Int,

    /**
     * Overall system status.
     */
    val status: HealthStatus,

    /**
     * CPU utilization percentage.
     */
    val cpuUsagePercentage: Double,

    /**
     * Memory utilization percentage.
     */
    val memoryUsagePercentage: Double,

    /**
     * Storage utilization percentage.
     */
    val storageUsagePercentage: Double,

    /**
     * Battery level percentage.
     *
     * Applicable primarily to
     * mobile devices and laptops.
     */
    val batteryLevelPercentage: Int? = null,

    /**
     * Battery health percentage.
     */
    val batteryHealthPercentage: Int? = null,

    /**
     * Device temperature in Celsius.
     */
    val deviceTemperature: Double? = null,

    /**
     * Current network status.
     */
    val networkStatus: NetworkHealthStatus,

    /**
     * Current security score.
     */
    val securityScore: Int,

    /**
     * Number of active threats.
     */
    val activeThreats: Int = 0,

    /**
     * Number of active alerts.
     */
    val activeAlerts: Int = 0,

    /**
     * Indicates whether the device
     * passed integrity verification.
     */
    val integrityVerified: Boolean = true,

    /**
     * Indicates whether real-time
     * protection is active.
     */
    val realtimeProtectionEnabled: Boolean = true,

    /**
     * Indicates whether firewall
     * protection is active.
     */
    val firewallEnabled: Boolean = true,

    /**
     * Indicates whether VPN
     * protection is active.
     */
    val vpnEnabled: Boolean = false,

    /**
     * Number of running applications.
     */
    val runningApplications: Int = 0,

    /**
     * Number of running services.
     */
    val runningServices: Int = 0,

    /**
     * Health issues detected
     * during analysis.
     */
    val detectedIssues: List<SystemHealthIssue> =
        emptyList(),

    /**
     * Recommended actions for
     * improving system health.
     */
    val recommendations: List<String> =
        emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * Health status indicators.
 *
 * Represents the overall condition
 * of the monitored system.
 */
enum class HealthStatus {

    /**
     * System operating normally.
     */
    EXCELLENT,

    /**
     * Minor issues detected.
     */
    GOOD,

    /**
     * Moderate issues detected.
     */
    FAIR,

    /**
     * Significant issues detected.
     */
    POOR,

    /**
     * Critical condition requiring
     * immediate attention.
     */
    CRITICAL
}

/**
 * Network health status indicators.
 */
enum class NetworkHealthStatus {

    /**
     * Network functioning normally.
     */
    HEALTHY,

    /**
     * Network experiencing
     * degraded performance.
     */
    DEGRADED,

    /**
     * Network connectivity issues
     * detected.
     */
    UNSTABLE,

    /**
     * Network unavailable.
     */
    OFFLINE
}

/**
 * SystemHealthIssue
 *
 * Represents a health-related issue
 * identified during system analysis.
 */
data class SystemHealthIssue(

    /**
     * Unique issue identifier.
     */
    val issueId: String,

    /**
     * Issue title.
     */
    val title: String,

    /**
     * Detailed issue description.
     */
    val description: String,

    /**
     * Severity level.
     */
    val severity: HealthIssueSeverity,

    /**
     * Timestamp when the issue
     * was detected.
     */
    val detectedAt: Long,

    /**
     * Indicates whether the issue
     * has been resolved.
     */
    val isResolved: Boolean = false
)

/**
 * Health issue severity indicators.
 */
enum class HealthIssueSeverity {

    /**
     * Informational issue.
     */
    INFO,

    /**
     * Low severity issue.
     */
    LOW,

    /**
     * Medium severity issue.
     */
    MEDIUM,

    /**
     * High severity issue.
     */
    HIGH,

    /**
     * Critical severity issue.
     */
    CRITICAL
}
