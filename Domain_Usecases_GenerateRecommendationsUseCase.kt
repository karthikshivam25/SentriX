package com.sentrix.domain.usecases

import com.sentrix.domain.models.SecurityPosture
import com.sentrix.domain.models.SystemHealth
import com.sentrix.domain.models.ThreatLevel

/**
 * GenerateRecommendationsUseCase
 *
 * Responsible for generating intelligent
 * cybersecurity recommendations based on
 * security posture, threat intelligence,
 * risk assessments, system health, and
 * security analytics within the SentriX
 * cybersecurity platform.
 *
 * This use case helps users and security
 * administrators improve protection,
 * reduce risk exposure, remediate issues,
 * and strengthen overall cyber resilience.
 *
 * Used by:
 * - AIRecommendationEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - SecurityAnalyticsPlatform
 * - RiskAssessmentEngine
 * - ExecutiveReportingService
 * - ThreatAnalysisManager
 * - RealtimeProtectionEngine
 *
 * Responsibilities:
 * - Generate security recommendations
 * - Prioritize remediation actions
 * - Improve security posture
 * - Reduce cyber risk exposure
 * - Support compliance initiatives
 * - Provide proactive guidance
 */
class GenerateRecommendationsUseCase {

    /**
     * Generates security recommendations
     * using available security context.
     *
     * @param securityPosture
     * Current security posture.
     *
     * @param systemHealth
     * Current system health information.
     *
     * @return RecommendationResult
     */
    operator fun invoke(
        securityPosture: SecurityPosture,
        systemHealth: SystemHealth
    ): RecommendationResult {

        val recommendations =
            mutableListOf<SecurityRecommendation>()

        recommendations +=
            generateThreatRecommendations(
                securityPosture.threatLevel
            )

        recommendations +=
            generateVulnerabilityRecommendations(
                securityPosture
                    .unresolvedVulnerabilities
            )

        recommendations +=
            generateComplianceRecommendations(
                securityPosture
                    .failedComplianceControls
            )

        recommendations +=
            generateSystemHealthRecommendations(
                systemHealth
            )

        return RecommendationResult(
            generatedAt =
                System.currentTimeMillis(),
            totalRecommendations =
                recommendations.size,
            recommendations =
                recommendations.sortedByDescending {
                    it.priority.score
                }
        )
    }

    /**
     * Generates threat-based recommendations.
     */
    private fun generateThreatRecommendations(
        threatLevel: ThreatLevel
    ): List<SecurityRecommendation> {

        return when (threatLevel) {

            ThreatLevel.CRITICAL -> listOf(
                SecurityRecommendation(
                    title =
                        "Enable Emergency Protection",
                    description =
                        "Activate advanced protection controls immediately.",
                    category =
                        RecommendationCategory.THREAT_RESPONSE,
                    priority =
                        RecommendationPriority.CRITICAL
                ),
                SecurityRecommendation(
                    title =
                        "Initiate Incident Response",
                    description =
                        "Begin incident containment procedures.",
                    category =
                        RecommendationCategory.INCIDENT_RESPONSE,
                    priority =
                        RecommendationPriority.CRITICAL
                )
            )

            ThreatLevel.HIGH -> listOf(
                SecurityRecommendation(
                    title =
                        "Increase Security Monitoring",
                    description =
                        "Enable enhanced threat monitoring.",
                    category =
                        RecommendationCategory.MONITORING,
                    priority =
                        RecommendationPriority.HIGH
                )
            )

            ThreatLevel.MEDIUM -> listOf(
                SecurityRecommendation(
                    title =
                        "Review Threat Indicators",
                    description =
                        "Investigate detected threat activity.",
                    category =
                        RecommendationCategory.THREAT_RESPONSE,
                    priority =
                        RecommendationPriority.MEDIUM
                )
            )

            ThreatLevel.LOW -> emptyList()
        }
    }

    /**
     * Generates vulnerability-based recommendations.
     */
    private fun generateVulnerabilityRecommendations(
        vulnerabilityCount: Int
    ): List<SecurityRecommendation> {

        if (vulnerabilityCount <= 0) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title =
                    "Remediate Vulnerabilities",
                description =
                    "$vulnerabilityCount unresolved vulnerabilities detected.",
                category =
                    RecommendationCategory.VULNERABILITY_MANAGEMENT,
                priority =
                    if (vulnerabilityCount > 10)
                        RecommendationPriority.HIGH
                    else
                        RecommendationPriority.MEDIUM
            )
        )
    }

    /**
     * Generates compliance recommendations.
     */
    private fun generateComplianceRecommendations(
        failedControls: Int
    ): List<SecurityRecommendation> {

        if (failedControls <= 0) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title =
                    "Improve Compliance Controls",
                description =
                    "$failedControls controls require remediation.",
                category =
                    RecommendationCategory.COMPLIANCE,
                priority =
                    RecommendationPriority.MEDIUM
            )
        )
    }

    /**
     * Generates system health recommendations.
     */
    private fun generateSystemHealthRecommendations(
        systemHealth: SystemHealth
    ): List<SecurityRecommendation> {

        val recommendations =
            mutableListOf<SecurityRecommendation>()

        if (
            systemHealth.cpuUsagePercentage >= 85
        ) {
            recommendations +=
                SecurityRecommendation(
                    title =
                        "Reduce CPU Utilization",
                    description =
                        "High CPU usage detected.",
                    category =
                        RecommendationCategory.SYSTEM_OPTIMIZATION,
                    priority =
                        RecommendationPriority.MEDIUM
                )
        }

        if (
            systemHealth.memoryUsagePercentage >= 85
        ) {
            recommendations +=
                SecurityRecommendation(
                    title =
                        "Optimize Memory Usage",
                    description =
                        "Memory consumption exceeds recommended thresholds.",
                    category =
                        RecommendationCategory.SYSTEM_OPTIMIZATION,
                    priority =
                        RecommendationPriority.MEDIUM
                )
        }

        return recommendations
    }
}

/**
 * RecommendationResult
 *
 * Represents generated security
 * recommendations.
 */
data class RecommendationResult(

    /**
     * Generation timestamp.
     */
    val generatedAt: Long,

    /**
     * Total recommendations generated.
     */
    val totalRecommendations: Int,

    /**
     * Generated recommendations.
     */
    val recommendations:
        List<SecurityRecommendation>
)

/**
 * SecurityRecommendation
 *
 * Represents an actionable
 * cybersecurity recommendation.
 */
data class SecurityRecommendation(

    /**
     * Recommendation title.
     */
    val title: String,

    /**
     * Recommendation details.
     */
    val description: String,

    /**
     * Recommendation category.
     */
    val category:
        RecommendationCategory,

    /**
     * Recommendation priority.
     */
    val priority:
        RecommendationPriority
)

/**
 * Recommendation categories.
 */
enum class RecommendationCategory {

    /**
     * Threat mitigation.
     */
    THREAT_RESPONSE,

    /**
     * Vulnerability management.
     */
    VULNERABILITY_MANAGEMENT,

    /**
     * Compliance improvements.
     */
    COMPLIANCE,

    /**
     * Incident response actions.
     */
    INCIDENT_RESPONSE,

    /**
     * Security monitoring.
     */
    MONITORING,

    /**
     * System optimization.
     */
    SYSTEM_OPTIMIZATION,

    /**
     * Access control improvements.
     */
    ACCESS_CONTROL,

    /**
     * Security awareness.
     */
    SECURITY_AWARENESS
}

/**
 * Recommendation priorities.
 */
enum class RecommendationPriority(
    val score: Int
) {

    /**
     * Low priority.
     */
    LOW(1),

    /**
     * Medium priority.
     */
    MEDIUM(2),

    /**
     * High priority.
     */
    HIGH(3),

    /**
     * Critical priority.
     */
    CRITICAL(4)
}
