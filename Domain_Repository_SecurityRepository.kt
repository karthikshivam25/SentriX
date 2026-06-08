package com.sentrix.domain.repositories

import com.sentrix.domain.models.SecurityAlert
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.SecurityReport

/**
 * SecurityRepository
 *
 * Repository responsible for
 * managing security-related
 * information within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - SecurityDashboard
 * - CyberDefenseManager
 * - SecurityAnalyticsEngine
 * - SecurityReportGenerator
 * - ThreatAnalysisEngine
 *
 * Responsibilities:
 * - Retrieve security metrics
 * - Manage security alerts
 * - Store security reports
 * - Track security posture
 * - Provide security analytics
 */
interface SecurityRepository {

    /**
     * Retrieves current
     * security metrics.
     *
     * @return Security metrics.
     */
    suspend fun getSecurityMetrics():
        SecurityMetrics

    /**
     * Updates security metrics.
     *
     * @param metrics Security metrics.
     */
    suspend fun updateSecurityMetrics(
        metrics: SecurityMetrics
    )

    /**
     * Retrieves all
     * security alerts.
     *
     * @return Alert list.
     */
    suspend fun getSecurityAlerts():
        List<SecurityAlert>

    /**
     * Retrieves active
     * security alerts.
     *
     * @return Active alerts.
     */
    suspend fun getActiveAlerts():
        List<SecurityAlert>

    /**
     * Saves security alert.
     *
     * @param alert Security alert.
     */
    suspend fun saveSecurityAlert(
        alert: SecurityAlert
    )

    /**
     * Removes security alert.
     *
     * @param alertId Alert ID.
     */
    suspend fun deleteSecurityAlert(
        alertId: String
    )

    /**
     * Retrieves latest
     * security report.
     *
     * @return Security report.
     */
    suspend fun getLatestReport():
        SecurityReport?

    /**
     * Saves security report.
     *
     * @param report Security report.
     */
    suspend fun saveSecurityReport(
        report: SecurityReport
    )

    /**
     * Retrieves security score.
     *
     * @return Security score.
     */
    suspend fun getSecurityScore():
        Int
}

/**
 * SecurityMetrics
 *
 * Represents overall
 * security statistics.
 */
data class SecurityMetrics(

    /**
     * Current security score.
     */
    val securityScore: Int,

    /**
     * Active threats.
     */
    val activeThreats: Int,

    /**
     * Resolved threats.
     */
    val resolvedThreats: Int,

    /**
     * Total scans executed.
     */
    val totalScans: Int,

    /**
     * Firewall status.
     */
    val firewallEnabled: Boolean,

    /**
     * Real-time protection status.
     */
    val realTimeProtectionEnabled: Boolean,

    /**
     * VPN protection status.
     */
    val vpnEnabled: Boolean
)

/**
 * SecurityAlert
 *
 * Represents a security
 * notification or warning.
 */
data class SecurityAlert(

    /**
     * Alert identifier.
     */
    val alertId: String,

    /**
     * Alert title.
     */
    val title: String,

    /**
     * Alert description.
     */
    val description: String,

    /**
     * Alert severity.
     */
    val severity:
        AlertSeverity,

    /**
     * Alert timestamp.
     */
    val createdAt: Long,

    /**
     * Alert status.
     */
    val isResolved: Boolean
)

/**
 * SecurityReport
 *
 * Represents generated
 * security report data.
 */
data class SecurityReport(

    /**
     * Report identifier.
     */
    val reportId: String,

    /**
     * Report generation time.
     */
    val generatedAt: Long,

    /**
     * Security score.
     */
    val securityScore: Int,

    /**
     * Total threats.
     */
    val totalThreats: Int,

    /**
     * Active threats.
     */
    val activeThreats: Int,

    /**
     * Report summary.
     */
    val summary: String
)

/**
 * Alert severity levels.
 */
enum class AlertSeverity {

    /**
     * Informational alert.
     */
    LOW,

    /**
     * Moderate severity alert.
     */
    MEDIUM,

    /**
     * High severity alert.
     */
    HIGH,

    /**
     * Critical alert.
     */
    CRITICAL
}
