package com.sentrix.domain.usecases

import com.sentrix.domain.models.SecurityPosture
import com.sentrix.domain.models.ThreatLevel

/**
 * CalculateRiskScoreUseCase
 *
 * Responsible for calculating the overall
 * cybersecurity risk score for a device,
 * application, user, network, or organization
 * within the SentriX platform.
 *
 * This use case aggregates security posture,
 * threat intelligence, vulnerabilities,
 * compliance violations, active incidents,
 * and security control effectiveness to
 * produce a unified risk assessment.
 *
 * Used by:
 * - RiskAssessmentEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ThreatAnalysisEngine
 * - ComplianceManager
 * - ExecutiveReportingService
 * - SecurityAnalyticsPlatform
 * - AIRecommendationEngine
 *
 * Responsibilities:
 * - Calculate overall risk score
 * - Evaluate threat exposure
 * - Assess security weaknesses
 * - Measure control effectiveness
 * - Determine risk severity
 * - Generate mitigation recommendations
 */
class CalculateRiskScoreUseCase {

    /**
     * Calculates risk score from
     * security posture information.
     *
     * @param securityPosture
     * Current security posture.
     *
     * @return RiskScoreResult
     */
    operator fun invoke(
        securityPosture: SecurityPosture
    ): RiskScoreResult {

        val vulnerabilityRisk =
            securityPosture
                .unresolvedVulnerabilities * 3

        val incidentRisk =
            securityPosture
                .securityIncidents * 5

        val complianceRisk =
            securityPosture
                .failedComplianceControls * 2

        val threatRisk =
            calculateThreatRisk(
                securityPosture.threatLevel
            )

        val calculatedScore =
            (
                vulnerabilityRisk +
                incidentRisk +
                complianceRisk +
                threatRisk
            ).coerceIn(0, 100)

        val riskLevel =
            determineRiskLevel(
                calculatedScore
            )

        return RiskScoreResult(
            calculatedAt =
                System.currentTimeMillis(),
            overallRiskScore =
                calculatedScore,
            riskLevel =
                riskLevel,
            vulnerabilityRisk =
                vulnerabilityRisk,
            incidentRisk =
                incidentRisk,
            complianceRisk =
                complianceRisk,
            threatRisk =
                threatRisk,
            recommendations =
                generateRecommendations(
                    riskLevel
                )
        )
    }

    /**
     * Calculates threat-related risk.
     */
    private fun calculateThreatRisk(
        threatLevel: ThreatLevel
    ): Int {

        return when (threatLevel) {

            ThreatLevel.LOW -> 10

            ThreatLevel.MEDIUM -> 25

            ThreatLevel.HIGH -> 50

            ThreatLevel.CRITICAL -> 75
        }
    }

    /**
     * Determines risk severity level.
     */
    private fun determineRiskLevel(
        riskScore: Int
    ): RiskSeverityLevel {

        return when {

            riskScore >= 80 ->
                RiskSeverityLevel.CRITICAL

            riskScore >= 60 ->
                RiskSeverityLevel.HIGH

            riskScore >= 30 ->
                RiskSeverityLevel.MEDIUM

            else ->
                RiskSeverityLevel.LOW
        }
    }

    /**
     * Generates risk mitigation
     * recommendations.
     */
    private fun generateRecommendations(
        riskLevel: RiskSeverityLevel
    ): List<String> {

        return when (riskLevel) {

            RiskSeverityLevel.CRITICAL -> listOf(
                "Initiate immediate remediation",
                "Review critical vulnerabilities",
                "Escalate to security team",
                "Enable enhanced protection policies"
            )

            RiskSeverityLevel.HIGH -> listOf(
                "Address high-risk findings",
                "Review active security incidents",
                "Strengthen security controls"
            )

            RiskSeverityLevel.MEDIUM -> listOf(
                "Improve security posture",
                "Review unresolved findings"
            )

            RiskSeverityLevel.LOW -> listOf(
                "Maintain current security controls"
            )
        }
    }
}

/**
 * RiskScoreResult
 *
 * Represents the outcome of
 * risk score calculation.
 */
data class RiskScoreResult(

    /**
     * Calculation timestamp.
     */
    val calculatedAt: Long,

    /**
     * Overall calculated risk score.
     *
     * Range:
     * 0 - 100
     */
    val overallRiskScore: Int,

    /**
     * Determined risk severity.
     */
    val riskLevel: RiskSeverityLevel,

    /**
     * Risk contribution from
     * vulnerabilities.
     */
    val vulnerabilityRisk: Int,

    /**
     * Risk contribution from
     * security incidents.
     */
    val incidentRisk: Int,

    /**
     * Risk contribution from
     * compliance issues.
     */
    val complianceRisk: Int,

    /**
     * Risk contribution from
     * threat intelligence.
     */
    val threatRisk: Int,

    /**
     * Recommended mitigation actions.
     */
    val recommendations: List<String>
)

/**
 * Risk severity indicators.
 */
enum class RiskSeverityLevel {

    /**
     * Low risk exposure.
     */
    LOW,

    /**
     * Moderate risk exposure.
     */
    MEDIUM,

    /**
     * High risk exposure.
     */
    HIGH,

    /**
     * Critical risk exposure
     * requiring immediate action.
     */
    CRITICAL
}
