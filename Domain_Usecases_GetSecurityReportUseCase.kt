package com.sentrix.domain.usecases

import com.sentrix.domain.models.CyberDefenseProfile
import com.sentrix.domain.models.ScanStatistics
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.SecurityPosture
import com.sentrix.domain.models.SystemHealth
import com.sentrix.domain.repositories.SecurityReportRepository

/**
 * GetSecurityReportUseCase
 *
 * Responsible for generating comprehensive
 * cybersecurity reports within the SentriX
 * cybersecurity platform.
 *
 * This use case aggregates security posture,
 * threat intelligence, scan analytics,
 * cyber defense effectiveness, compliance
 * information, system health metrics, and
 * operational security data into a unified
 * report suitable for users, administrators,
 * auditors, and executive stakeholders.
 *
 * Used by:
 * - SecurityDashboard
 * - ExecutiveReportingService
 * - ComplianceReportingEngine
 * - SecurityAnalyticsPlatform
 * - CyberDefenseManager
 * - SecurityOperationsCenter
 * - AuditManagementSystem
 * - RiskAssessmentEngine
 *
 * Responsibilities:
 * - Generate security reports
 * - Aggregate security analytics
 * - Summarize threat activity
 * - Provide compliance visibility
 * - Support auditing requirements
 * - Deliver executive insights
 */
class GetSecurityReportUseCase(
    private val repository: SecurityReportRepository
) {

    /**
     * Generates a complete
     * security report.
     *
     * @param request Report request.
     *
     * @return SecurityReportResult
     */
    suspend operator fun invoke(
        request: SecurityReportRequest
    ): SecurityReportResult {

        val securityPosture =
            repository.getSecurityPosture()

        val securityMetrics =
            repository.getSecurityMetrics()

        val scanStatistics =
            repository.getScanStatistics()

        val cyberDefenseProfile =
            repository.getCyberDefenseProfile()

        val systemHealth =
            repository.getSystemHealth()

        val executiveSummary =
            generateExecutiveSummary(
                securityPosture,
                securityMetrics
            )

        return SecurityReportResult(
            generatedAt =
                System.currentTimeMillis(),

            reportId =
                generateReportId(),

            reportType =
                request.reportType,

            securityPosture =
                securityPosture,

            securityMetrics =
                securityMetrics,

            scanStatistics =
                scanStatistics,

            cyberDefenseProfile =
                cyberDefenseProfile,

            systemHealth =
                systemHealth,

            executiveSummary =
                executiveSummary,

            reportSections =
                generateSections(
                    securityPosture,
                    securityMetrics,
                    scanStatistics
                )
        )
    }

    /**
     * Generates executive summary.
     */
    private fun generateExecutiveSummary(
        posture: SecurityPosture,
        metrics: SecurityMetrics
    ): ExecutiveSecuritySummary {

        return ExecutiveSecuritySummary(
            securityScore =
                posture.securityScore,

            riskScore =
                posture.riskScore,

            activeThreats =
                posture.activeThreats,

            criticalThreats =
                posture.criticalThreats,

            complianceScore =
                posture.complianceScore,

            totalThreatsDetected =
                metrics.totalThreats
        )
    }

    /**
     * Generates report sections.
     */
    private fun generateSections(
        posture: SecurityPosture,
        metrics: SecurityMetrics,
        scans: ScanStatistics
    ): List<SecurityReportSection> {

        return listOf(

            SecurityReportSection(
                title = "Security Posture",
                description =
                    "Current security posture assessment."
            ),

            SecurityReportSection(
                title = "Threat Analytics",
                description =
                    "Threat activity and detection statistics."
            ),

            SecurityReportSection(
                title = "Scan Analytics",
                description =
                    "Scan performance and findings."
            ),

            SecurityReportSection(
                title = "Risk Assessment",
                description =
                    "Current organizational risk exposure."
            )
        )
    }

    /**
     * Generates a unique report ID.
     */
    private fun generateReportId(): String {
        return "REPORT-${System.currentTimeMillis()}"
    }
}

/**
 * SecurityReportResult
 *
 * Represents a generated
 * cybersecurity report.
 */
data class SecurityReportResult(

    /**
     * Report generation timestamp.
     */
    val generatedAt: Long,

    /**
     * Unique report identifier.
     */
    val reportId: String,

    /**
     * Report type.
     */
    val reportType:
        SecurityReportType,

    /**
     * Security posture information.
     */
    val securityPosture:
        SecurityPosture,

    /**
     * Security metrics.
     */
    val securityMetrics:
        SecurityMetrics,

    /**
     * Scan analytics.
     */
    val scanStatistics:
        ScanStatistics,

    /**
     * Cyber defense profile.
     */
    val cyberDefenseProfile:
        CyberDefenseProfile,

    /**
     * System health information.
     */
    val systemHealth:
        SystemHealth,

    /**
     * Executive summary.
     */
    val executiveSummary:
        ExecutiveSecuritySummary,

    /**
     * Report sections.
     */
    val reportSections:
        List<SecurityReportSection>
)

/**
 * SecurityReportRequest
 *
 * Represents report generation
 * parameters.
 */
data class SecurityReportRequest(

    /**
     * Report type.
     */
    val reportType:
        SecurityReportType,

    /**
     * Report start date.
     */
    val startDate: Long? = null,

    /**
     * Report end date.
     */
    val endDate: Long? = null
)

/**
 * ExecutiveSecuritySummary
 *
 * Provides a concise executive
 * overview of security status.
 */
data class ExecutiveSecuritySummary(

    /**
     * Security score.
     */
    val securityScore: Int,

    /**
     * Risk score.
     */
    val riskScore: Int,

    /**
     * Active threats.
     */
    val activeThreats: Int,

    /**
     * Critical threats.
     */
    val criticalThreats: Int,

    /**
     * Compliance score.
     */
    val complianceScore: Int,

    /**
     * Total threats detected.
     */
    val totalThreatsDetected: Int
)

/**
 * SecurityReportSection
 *
 * Represents an individual
 * report section.
 */
data class SecurityReportSection(

    /**
     * Section title.
     */
    val title: String,

    /**
     * Section description.
     */
    val description: String
)

/**
 * Supported report types.
 */
enum class SecurityReportType {

    /**
     * Executive summary report.
     */
    EXECUTIVE,

    /**
     * Operational report.
     */
    OPERATIONAL,

    /**
     * Compliance report.
     */
    COMPLIANCE,

    /**
     * Threat intelligence report.
     */
    THREAT_INTELLIGENCE,

    /**
     * Incident response report.
     */
    INCIDENT_RESPONSE,

    /**
     * Full security assessment report.
     */
    COMPREHENSIVE
}
