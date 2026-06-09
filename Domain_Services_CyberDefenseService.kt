package com.sentrix.domain.services

import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Main cybersecurity orchestration service for SentriX.
 *
 * This service coordinates threat analysis,
 * risk assessment, security recommendations,
 * and overall cyber defense operations.
 */
class CyberDefenseService(
    private val threatAnalysisService: ThreatAnalysisService,
    private val riskScoringService: RiskScoringService,
    private val threatPredictionService: ThreatPredictionService,
    private val securityRecommendationService: SecurityRecommendationService,
    private val realtimeProtectionService: RealtimeProtectionService
) {

    /**
     * Calculates overall cyber defense score.
     *
     * Higher score indicates stronger security posture.
     */
    suspend fun calculateDefenseScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        val riskScore =
            riskScoringService.calculateRiskScore(indicators)

        (100 - riskScore).coerceIn(0, 100)
    }

    /**
     * Determines current defense status.
     */
    suspend fun getDefenseStatus(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        val score = calculateDefenseScore(indicators)

        when {
            score >= 90 -> "EXCELLENT"
            score >= 75 -> "GOOD"
            score >= 50 -> "MODERATE"
            score >= 25 -> "WEAK"
            else -> "CRITICAL"
        }
    }

    /**
     * Determines whether active threats exist.
     */
    suspend fun hasActiveThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        realtimeProtectionService.hasActiveThreats(
            indicators
        )
    }

    /**
     * Returns critical threats.
     */
    suspend fun getCriticalThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", true)
        }
    }

    /**
     * Returns high priority threats.
     */
    suspend fun getHighPriorityThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", true)
        }
    }

    /**
     * Generates overall security recommendations.
     */
    suspend fun generateRecommendations(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): List<String> = withContext(Dispatchers.Default) {

        securityRecommendationService
            .generateRecommendations(
                indicators,
                metrics
            )
    }

    /**
     * Predicts future threat level.
     */
    suspend fun predictThreatLevel(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        threatPredictionService
            .predictThreatLevel(indicators)
    }

    /**
     * Calculates security health score.
     */
    suspend fun calculateSecurityHealth(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        riskScoringService
            .calculateSecurityHealthScore(indicators)
    }

    /**
     * Generates a complete cyber defense report.
     */
    suspend fun generateDefenseReport(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val defenseScore =
            calculateDefenseScore(indicators)

        val defenseStatus =
            getDefenseStatus(indicators)

        val predictedThreatLevel =
            predictThreatLevel(indicators)

        val recommendations =
            generateRecommendations(
                indicators,
                metrics
            )

        buildString {

            appendLine("SentriX Cyber Defense Report")
            appendLine("===========================")
            appendLine()

            appendLine("Defense Score: $defenseScore")
            appendLine("Defense Status: $defenseStatus")
            appendLine("Threat Count: ${indicators.size}")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Predicted Threat Level: $predictedThreatLevel")
            appendLine()

            appendLine("Recommendations:")

            recommendations.forEachIndexed { index, recommendation ->
                appendLine("${index + 1}. $recommendation")
            }
        }
    }

    /**
     * Determines whether the system
     * is currently secure.
     */
    suspend fun isSystemSecure(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        calculateDefenseScore(indicators) >= 75
    }

    /**
     * Returns overall security posture.
     */
    suspend fun getSecurityPosture(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        when {
            calculateDefenseScore(indicators) >= 90 ->
                "STRONG"

            calculateDefenseScore(indicators) >= 75 ->
                "SECURE"

            calculateDefenseScore(indicators) >= 50 ->
                "MODERATE"

            else ->
                "AT_RISK"
        }
    }

    /**
     * Generates executive summary
     * for dashboards and reports.
     */
    suspend fun generateExecutiveSummary(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val status =
            getDefenseStatus(indicators)

        val score =
            calculateDefenseScore(indicators)

        buildString {
            appendLine("SentriX Executive Security Summary")
            appendLine("----------------------------------")
            appendLine("Defense Status: $status")
            appendLine("Defense Score: $score")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Threats Detected: ${metrics.threatsDetected}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
        }
    }
}
