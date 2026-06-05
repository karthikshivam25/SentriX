package com.sentrix.domain.usecases

import com.sentrix.domain.models.CyberDefenseProfile
import com.sentrix.domain.models.RealtimeProtectionStatus
import com.sentrix.domain.models.ScanStatistics
import com.sentrix.domain.models.SecurityAlert
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.SecurityPosture
import com.sentrix.domain.models.SystemHealth
import com.sentrix.domain.repositories.SecurityDashboardRepository

/**
 * GetSecurityDashboardUseCase
 *
 * Responsible for aggregating security-related
 * information from multiple SentriX subsystems
 * and generating a unified dashboard view.
 *
 * This use case serves as the primary source
 * of information for the Security Dashboard,
 * providing real-time visibility into device
 * security posture, threat activity, scan
 * results, cyber defense effectiveness,
 * protection status, and operational metrics.
 *
 * Used by:
 * - SecurityDashboard
 * - ExecutiveDashboard
 * - SecurityAnalyticsPlatform
 * - CyberDefenseManager
 * - SecurityOperationsCenter
 * - RealtimeProtectionEngine
 * - ReportingService
 * - AIRecommendationEngine
 *
 * Responsibilities:
 * - Aggregate security data
 * - Build dashboard summary
 * - Provide security insights
 * - Consolidate threat information
 * - Display protection status
 * - Support executive reporting
 */
class GetSecurityDashboardUseCase(
    private val repository: SecurityDashboardRepository
) {

    /**
     * Retrieves complete dashboard data.
     *
     * @return SecurityDashboardResult
     */
    suspend operator fun invoke():
        SecurityDashboardResult {

        val securityPosture =
            repository.getSecurityPosture()

        val systemHealth =
            repository.getSystemHealth()

        val securityMetrics =
            repository.getSecurityMetrics()

        val realtimeProtection =
            repository.getRealtimeProtectionStatus()

        val cyberDefenseProfile =
            repository.getCyberDefenseProfile()

        val scanStatistics =
            repository.getScanStatistics()

        val activeAlerts =
            repository.getActiveSecurityAlerts()

        return SecurityDashboardResult(
            generatedAt =
                System.currentTimeMillis(),

            securityPosture =
                securityPosture,

            systemHealth =
                systemHealth,

            securityMetrics =
                securityMetrics,

            realtimeProtection =
                realtimeProtection,

            cyberDefenseProfile =
                cyberDefenseProfile,

            scanStatistics =
                scanStatistics,

            activeAlerts =
                activeAlerts,

            dashboardSummary =
                generateSummary(
                    securityPosture,
                    activeAlerts.size
                )
        )
    }

    /**
     * Generates a high-level
     * dashboard summary.
     */
    private fun generateSummary(
        securityPosture: SecurityPosture,
        activeAlertCount: Int
    ): DashboardSummary {

        return DashboardSummary(
            overallSecurityScore =
                securityPosture.securityScore,

            riskScore =
                securityPosture.riskScore,

            activeThreats =
                securityPosture.activeThreats,

            activeAlerts =
                activeAlertCount,

            criticalThreats =
                securityPosture.criticalThreats,

            complianceScore =
                securityPosture.complianceScore
        )
    }
}

/**
 * SecurityDashboardResult
 *
 * Represents the complete security
 * dashboard data model.
 */
data class SecurityDashboardResult(

    /**
     * Dashboard generation timestamp.
     */
    val generatedAt: Long,

    /**
     * Current security posture.
     */
    val securityPosture:
        SecurityPosture,

    /**
     * Current system health.
     */
    val systemHealth:
        SystemHealth,

    /**
     * Aggregated security metrics.
     */
    val securityMetrics:
        SecurityMetrics,

    /**
     * Real-time protection status.
     */
    val realtimeProtection:
        RealtimeProtectionStatus,

    /**
     * Cyber defense profile.
     */
    val cyberDefenseProfile:
        CyberDefenseProfile,

    /**
     * Scan analytics.
     */
    val scanStatistics:
        ScanStatistics,

    /**
     * Active security alerts.
     */
    val activeAlerts:
        List<SecurityAlert>,

    /**
     * Dashboard summary.
     */
    val dashboardSummary:
        DashboardSummary
)

/**
 * DashboardSummary
 *
 * Provides a concise overview
 * of security status.
 */
data class DashboardSummary(

    /**
     * Overall security score.
     */
    val overallSecurityScore: Int,

    /**
     * Overall risk score.
     */
    val riskScore: Int,

    /**
     * Active threats detected.
     */
    val activeThreats: Int,

    /**
     * Active security alerts.
     */
    val activeAlerts: Int,

    /**
     * Critical threats detected.
     */
    val criticalThreats: Int,

    /**
     * Compliance score.
     */
    val complianceScore: Int
)
