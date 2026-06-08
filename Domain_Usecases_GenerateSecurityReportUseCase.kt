package com.sentrix.domain.usecases

/**
 * GenerateSecurityReportUseCase
 *
 * Responsible for generating
 * comprehensive security reports
 * for the SentriX cybersecurity
 * platform.
 *
 * Reports provide visibility into:
 * - Security posture
 * - Threat statistics
 * - Scan activity
 * - Protection status
 * - Recommendations
 *
 * Used by:
 * - SecurityDashboard
 * - ComplianceReportingService
 * - SecurityAnalyticsPlatform
 * - CyberDefenseManager
 * - ReportExportEngine
 *
 * Responsibilities:
 * - Generate security reports
 * - Summarize security status
 * - Aggregate security metrics
 * - Provide recommendations
 * - Support compliance audits
 */
class GenerateSecurityReportUseCase {

    /**
     * Generates security report.
     */
    operator fun invoke(
        securityScore: Int,
        totalThreats: Int,
        resolvedThreats: Int,
        activeThreats: Int,
        firewallEnabled: Boolean,
        realTimeProtectionEnabled: Boolean,
        vpnEnabled: Boolean
    ): SecurityReport {

        val protectionStatus =
            determineProtectionStatus(
                securityScore
            )

        val recommendations =
            generateRecommendations(
                activeThreats,
                firewallEnabled,
                realTimeProtectionEnabled,
                vpnEnabled
            )

        return SecurityReport(
            generatedAt =
                System.currentTimeMillis(),

            securityScore =
                securityScore,

            protectionStatus =
                protectionStatus,

            totalThreats =
                totalThreats,

            resolvedThreats =
                resolvedThreats,

            activeThreats =
                activeThreats,

            firewallEnabled =
                firewallEnabled,

            realTimeProtectionEnabled =
                realTimeProtectionEnabled,

            vpnEnabled =
                vpnEnabled,

            recommendations =
                recommendations
        )
    }

    /**
     * Determines protection status.
     */
    private fun determineProtectionStatus(
        securityScore: Int
    ): ProtectionStatus {

        return when {

            securityScore >= 90 ->
                ProtectionStatus.EXCELLENT

            securityScore >= 75 ->
                ProtectionStatus.GOOD

            securityScore >= 50 ->
                ProtectionStatus.MODERATE

            securityScore >= 25 ->
                ProtectionStatus.WEAK

            else ->
                ProtectionStatus.CRITICAL
        }
    }

    /**
     * Generates recommendations.
     */
    private fun generateRecommendations(
        activeThreats: Int,
        firewallEnabled: Boolean,
        realTimeProtectionEnabled: Boolean,
        vpnEnabled: Boolean
    ): List<String> {

        val recommendations =
            mutableListOf<String>()

        if (activeThreats > 0) {
            recommendations.add(
                "Resolve active threats immediately."
            )
        }

        if (!firewallEnabled) {
            recommendations.add(
                "Enable firewall protection."
            )
        }

        if (!realTimeProtectionEnabled) {
            recommendations.add(
                "Enable real-time protection."
            )
        }

        if (!vpnEnabled) {
            recommendations.add(
                "Use VPN for secure browsing."
            )
        }

        if (recommendations.isEmpty()) {
            recommendations.add(
                "No actions required. Security posture is healthy."
            )
        }

        return recommendations
    }
}

/**
 * SecurityReport
 *
 * Represents generated
 * security report.
 */
data class SecurityReport(

    /**
     * Report generation time.
     */
    val generatedAt: Long,

    /**
     * Security score.
     */
    val securityScore: Int,

    /**
     * Overall protection status.
     */
    val protectionStatus:
        ProtectionStatus,

    /**
     * Total detected threats.
     */
    val totalThreats: Int,

    /**
     * Resolved threats.
     */
    val resolvedThreats: Int,

    /**
     * Active threats.
     */
    val activeThreats: Int,

    /**
     * Firewall status.
     */
    val firewallEnabled: Boolean,

    /**
     * Real-time protection status.
     */
    val realTimeProtectionEnabled: Boolean,

    /**
     * VPN status.
     */
    val vpnEnabled: Boolean,

    /**
     * Security recommendations.
     */
    val recommendations:
        List<String>
)

/**
 * Protection status.
 */
enum class ProtectionStatus {

    /**
     * Excellent protection.
     */
    EXCELLENT,

    /**
     * Good protection.
     */
    GOOD,

    /**
     * Moderate protection.
     */
    MODERATE,

    /**
     * Weak protection.
     */
    WEAK,

    /**
     * Critical security condition.
     */
    CRITICAL
}
