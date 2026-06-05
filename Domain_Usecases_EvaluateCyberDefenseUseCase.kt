package com.sentrix.domain.usecases

import com.sentrix.domain.models.CyberDefenseProfile
import com.sentrix.domain.models.SecurityPosture
import com.sentrix.domain.models.SystemHealth
import com.sentrix.domain.models.ThreatLevel

/**
 * EvaluateCyberDefenseUseCase
 *
 * Responsible for evaluating the overall
 * cyber defense effectiveness of a device,
 * user, network, or organization within
 * the SentriX cybersecurity platform.
 *
 * This use case analyzes security posture,
 * protection controls, threat exposure,
 * system health, defense capabilities,
 * compliance readiness, and operational
 * security metrics to determine the
 * effectiveness of deployed defenses.
 *
 * Used by:
 * - CyberDefenseManager
 * - SecurityDashboard
 * - SecurityAnalyticsEngine
 * - ExecutiveReportingService
 * - RiskAssessmentEngine
 * - AIRecommendationEngine
 * - SecurityOperationsCenter
 * - ComplianceMonitoringSystem
 *
 * Responsibilities:
 * - Evaluate defense effectiveness
 * - Assess security controls
 * - Measure cyber resilience
 * - Identify security gaps
 * - Calculate defense scores
 * - Generate improvement recommendations
 */
class EvaluateCyberDefenseUseCase {

    /**
     * Evaluates the effectiveness of
     * deployed cyber defense controls.
     *
     * @param profile Cyber defense profile
     * @param posture Security posture
     * @param systemHealth System health status
     *
     * @return CyberDefenseEvaluationResult
     */
    operator fun invoke(
        profile: CyberDefenseProfile,
        posture: SecurityPosture,
        systemHealth: SystemHealth
    ): CyberDefenseEvaluationResult {

        val protectionCoverageScore =
            calculateProtectionCoverage(profile)

        val threatResistanceScore =
            calculateThreatResistance(
                posture.threatLevel
            )

        val resilienceScore =
            calculateResilience(
                systemHealth.healthScore
            )

        val overallDefenseScore =
            (
                protectionCoverageScore +
                threatResistanceScore +
                resilienceScore
            ) / 3

        val defenseStatus =
            determineDefenseStatus(
                overallDefenseScore
            )

        return CyberDefenseEvaluationResult(
            evaluatedAt =
                System.currentTimeMillis(),
            overallDefenseScore =
                overallDefenseScore,
            defenseStatus =
                defenseStatus,
            protectionCoverageScore =
                protectionCoverageScore,
            threatResistanceScore =
                threatResistanceScore,
            resilienceScore =
                resilienceScore,
            strengths =
                identifyStrengths(
                    profile,
                    posture
                ),
            weaknesses =
                identifyWeaknesses(
                    profile,
                    posture
                ),
            recommendations =
                generateRecommendations(
                    defenseStatus
                )
        )
    }

    /**
     * Calculates protection coverage score.
     */
    private fun calculateProtectionCoverage(
        profile: CyberDefenseProfile
    ): Int {

        var enabledControls = 0

        if (profile.firewallEnabled)
            enabledControls++

        if (profile.vpnEnabled)
            enabledControls++

        if (profile.malwareProtectionEnabled)
            enabledControls++

        if (profile.intrusionDetectionEnabled)
            enabledControls++

        if (profile.phishingProtectionEnabled)
            enabledControls++

        if (profile.ransomwareProtectionEnabled)
            enabledControls++

        if (profile.aiProtectionEnabled)
            enabledControls++

        if (profile.zeroTrustEnabled)
            enabledControls++

        return ((enabledControls / 8.0) * 100)
            .toInt()
    }

    /**
     * Calculates threat resistance score.
     */
    private fun calculateThreatResistance(
        threatLevel: ThreatLevel
    ): Int {

        return when (threatLevel) {

            ThreatLevel.LOW -> 100

            ThreatLevel.MEDIUM -> 75

            ThreatLevel.HIGH -> 50

            ThreatLevel.CRITICAL -> 25
        }
    }

    /**
     * Calculates cyber resilience score.
     */
    private fun calculateResilience(
        healthScore: Int
    ): Int {
        return healthScore.coerceIn(0, 100)
    }

    /**
     * Determines defense effectiveness.
     */
    private fun determineDefenseStatus(
        score: Int
    ): CyberDefenseStatus {

        return when {

            score >= 90 ->
                CyberDefenseStatus.EXCELLENT

            score >= 75 ->
                CyberDefenseStatus.STRONG

            score >= 60 ->
                CyberDefenseStatus.MODERATE

            score >= 40 ->
                CyberDefenseStatus.WEAK

            else ->
                CyberDefenseStatus.CRITICAL
        }
    }

    /**
     * Identifies cyber defense strengths.
     */
    private fun identifyStrengths(
        profile: CyberDefenseProfile,
        posture: SecurityPosture
    ): List<String> {

        val strengths = mutableListOf<String>()

        if (profile.firewallEnabled) {
            strengths +=
                "Firewall protection enabled"
        }

        if (profile.zeroTrustEnabled) {
            strengths +=
                "Zero Trust security enabled"
        }

        if (profile.aiProtectionEnabled) {
            strengths +=
                "AI-powered protection active"
        }

        if (posture.securityScore >= 80) {
            strengths +=
                "Strong security posture"
        }

        return strengths
    }

    /**
     * Identifies cyber defense weaknesses.
     */
    private fun identifyWeaknesses(
        profile: CyberDefenseProfile,
        posture: SecurityPosture
    ): List<String> {

        val weaknesses = mutableListOf<String>()

        if (!profile.firewallEnabled) {
            weaknesses +=
                "Firewall protection disabled"
        }

        if (!profile.intrusionDetectionEnabled) {
            weaknesses +=
                "Intrusion detection disabled"
        }

        if (posture.unresolvedVulnerabilities > 0) {
            weaknesses +=
                "Unresolved vulnerabilities detected"
        }

        if (posture.failedComplianceControls > 0) {
            weaknesses +=
                "Compliance gaps identified"
        }

        return weaknesses
    }

    /**
     * Generates improvement recommendations.
     */
    private fun generateRecommendations(
        status: CyberDefenseStatus
    ): List<String> {

        return when (status) {

            CyberDefenseStatus.EXCELLENT -> listOf(
                "Maintain current security posture",
                "Continue proactive monitoring"
            )

            CyberDefenseStatus.STRONG -> listOf(
                "Optimize remaining security gaps",
                "Review emerging threats"
            )

            CyberDefenseStatus.MODERATE -> listOf(
                "Improve protection coverage",
                "Address identified weaknesses"
            )

            CyberDefenseStatus.WEAK -> listOf(
                "Strengthen security controls",
                "Perform comprehensive assessment"
            )

            CyberDefenseStatus.CRITICAL -> listOf(
                "Immediate remediation required",
                "Enable essential protections",
                "Conduct security incident review"
            )
        }
    }
}

/**
 * CyberDefenseEvaluationResult
 *
 * Represents the outcome of a
 * cyber defense effectiveness evaluation.
 */
data class CyberDefenseEvaluationResult(

    /**
     * Evaluation timestamp.
     */
    val evaluatedAt: Long,

    /**
     * Overall defense effectiveness score.
     *
     * Range:
     * 0 - 100
     */
    val overallDefenseScore: Int,

    /**
     * Defense effectiveness status.
     */
    val defenseStatus: CyberDefenseStatus,

    /**
     * Protection coverage score.
     */
    val protectionCoverageScore: Int,

    /**
     * Threat resistance score.
     */
    val threatResistanceScore: Int,

    /**
     * Cyber resilience score.
     */
    val resilienceScore: Int,

    /**
     * Identified strengths.
     */
    val strengths: List<String>,

    /**
     * Identified weaknesses.
     */
    val weaknesses: List<String>,

    /**
     * Recommended improvements.
     */
    val recommendations: List<String>
)

/**
 * Cyber defense effectiveness indicators.
 */
enum class CyberDefenseStatus {

    /**
     * Exceptional defense posture.
     */
    EXCELLENT,

    /**
     * Strong defense posture.
     */
    STRONG,

    /**
     * Adequate defense posture.
     */
    MODERATE,

    /**
     * Weak defense posture.
     */
    WEAK,

    /**
     * Critical defense deficiencies.
     */
    CRITICAL
}
