package com.sentrix.domain.usecases

import com.sentrix.domain.models.SecurityAlert
import com.sentrix.domain.models.ThreatIndicator
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.ThreatRepository

/**
 * AnalyzeThreatsUseCase
 *
 * Responsible for analyzing collected threat
 * intelligence, security alerts, indicators of
 * compromise, and suspicious activities within
 * the SentriX platform.
 *
 * This use case aggregates threat information,
 * evaluates risk severity, identifies emerging
 * attack patterns, and generates actionable
 * security insights for downstream systems.
 *
 * Used by:
 * - ThreatAnalysisManager
 * - RealtimeProtectionEngine
 * - SecurityDashboard
 * - SecurityOrchestrator
 * - AIThreatDetectionEngine
 * - IncidentResponseManager
 * - SecurityMonitoringService
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze active threats
 * - Correlate threat indicators
 * - Calculate threat severity
 * - Determine threat levels
 * - Generate security insights
 * - Support automated response actions
 */
class AnalyzeThreatsUseCase(
    private val threatRepository: ThreatRepository
) {

    /**
     * Executes threat analysis.
     *
     * Retrieves threat indicators and alerts,
     * correlates findings, calculates severity,
     * and produces a comprehensive threat
     * analysis result.
     *
     * @return ThreatAnalysisResult
     */
    suspend operator fun invoke(): ThreatAnalysisResult {

        val indicators =
            threatRepository.getThreatIndicators()

        val alerts =
            threatRepository.getSecurityAlerts()

        val activeThreats =
            indicators.count { it.isActive }

        val criticalThreats =
            alerts.count {
                it.severity == ThreatLevel.CRITICAL
            }

        val calculatedThreatLevel =
            determineThreatLevel(
                activeThreats = activeThreats,
                criticalThreats = criticalThreats
            )

        val riskScore =
            calculateRiskScore(
                activeThreats = activeThreats,
                criticalThreats = criticalThreats
            )

        return ThreatAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            activeThreats = activeThreats,
            criticalThreats = criticalThreats,
            threatLevel = calculatedThreatLevel,
            riskScore = riskScore,
            indicators = indicators,
            alerts = alerts,
            recommendations =
                generateRecommendations(
                    calculatedThreatLevel
                )
        )
    }

    /**
     * Determines the overall threat level
     * based on collected threat intelligence.
     */
    private fun determineThreatLevel(
        activeThreats: Int,
        criticalThreats: Int
    ): ThreatLevel {

        return when {
            criticalThreats >= 5 ->
                ThreatLevel.CRITICAL

            activeThreats >= 20 ->
                ThreatLevel.HIGH

            activeThreats >= 10 ->
                ThreatLevel.MEDIUM

            else ->
                ThreatLevel.LOW
        }
    }

    /**
     * Calculates overall risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        activeThreats: Int,
        criticalThreats: Int
    ): Int {

        val score =
            (activeThreats * 3) +
            (criticalThreats * 10)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates recommended actions
     * based on detected threat levels.
     */
    private fun generateRecommendations(
        threatLevel: ThreatLevel
    ): List<String> {

        return when (threatLevel) {

            ThreatLevel.CRITICAL -> listOf(
                "Isolate affected systems immediately",
                "Perform incident response procedures",
                "Enable emergency protection policies",
                "Notify security administrators"
            )

            ThreatLevel.HIGH -> listOf(
                "Review active security alerts",
                "Increase monitoring sensitivity",
                "Run a full security scan"
            )

            ThreatLevel.MEDIUM -> listOf(
                "Review suspicious activities",
                "Update threat signatures"
            )

            ThreatLevel.LOW -> listOf(
                "Continue normal monitoring"
            )
        }
    }
}

/**
 * ThreatAnalysisResult
 *
 * Represents the outcome of threat
 * analysis performed by the use case.
 */
data class ThreatAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Number of active threats.
     */
    val activeThreats: Int,

    /**
     * Number of critical threats.
     */
    val criticalThreats: Int,

    /**
     * Calculated threat level.
     */
    val threatLevel: ThreatLevel,

    /**
     * Overall risk score.
     */
    val riskScore: Int,

    /**
     * Threat indicators analyzed.
     */
    val indicators: List<ThreatIndicator>,

    /**
     * Security alerts analyzed.
     */
    val alerts: List<SecurityAlert>,

    /**
     * Recommended actions.
     */
    val recommendations: List<String>
)
