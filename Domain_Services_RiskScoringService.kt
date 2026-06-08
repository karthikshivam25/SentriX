package com.sentrix.domain.services

import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for calculating and managing
 * security risk scores across the SentriX platform.
 *
 * This service aggregates threat data,
 * evaluates security posture,
 * and generates risk-related insights.
 */
class RiskScoringService {

    /**
     * Calculates overall risk score from threat indicators.
     *
     * Severity weights:
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf { indicator ->
            when (indicator.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Calculates risk level based on score.
     *
     * Returns:
     * - CRITICAL
     * - HIGH
     * - MEDIUM
     * - LOW
     * - SAFE
     */
    suspend fun determineRiskLevel(
        riskScore: Int
    ): String = withContext(Dispatchers.Default) {

        when {
            riskScore >= 80 -> "CRITICAL"
            riskScore >= 60 -> "HIGH"
            riskScore >= 40 -> "MEDIUM"
            riskScore >= 20 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Calculates threat density percentage.
     *
     * Formula:
     * (Threat Count / Total Scans) × 100
     */
    suspend fun calculateThreatDensity(
        threatCount: Int,
        totalScans: Int
    ): Double = withContext(Dispatchers.Default) {

        if (totalScans <= 0) {
            return@withContext 0.0
        }

        (threatCount.toDouble() / totalScans) * 100
    }

    /**
     * Determines whether the environment
     * should be considered high risk.
     */
    suspend fun isHighRiskEnvironment(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        calculateRiskScore(indicators) >= 60
    }

    /**
     * Returns only critical risk indicators.
     */
    suspend fun getCriticalRiskIndicators(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns only high-risk indicators.
     */
    suspend fun getHighRiskIndicators(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Calculates security health score.
     *
     * Health score is inversely proportional
     * to risk score.
     */
    suspend fun calculateSecurityHealthScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        100 - calculateRiskScore(indicators)
    }

    /**
     * Generates a complete risk assessment summary.
     */
    suspend fun generateRiskSummary(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val riskScore = calculateRiskScore(indicators)
        val riskLevel = determineRiskLevel(riskScore)
        val healthScore = calculateSecurityHealthScore(indicators)

        buildString {
            appendLine("SentriX Risk Assessment Summary")
            appendLine("-------------------------------")
            appendLine("Risk Score: $riskScore")
            appendLine("Risk Level: $riskLevel")
            appendLine("Security Health Score: $healthScore")
            appendLine("Total Threats: ${indicators.size}")
            appendLine("Threats Detected: ${metrics.threatsDetected}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
            appendLine(
                if (riskScore >= 60)
                    "Status: Immediate Attention Required"
                else
                    "Status: Security Within Acceptable Limits"
            )
        }
    }

    /**
     * Calculates risk trend between
     * current and previous scores.
     */
    suspend fun calculateRiskTrend(
        previousRiskScore: Int,
        currentRiskScore: Int
    ): String = withContext(Dispatchers.Default) {

        when {
            currentRiskScore > previousRiskScore -> "INCREASING"
            currentRiskScore < previousRiskScore -> "DECREASING"
            else -> "STABLE"
        }
    }

    /**
     * Determines whether the system
     * security posture is healthy.
     */
    suspend fun isSecurityHealthy(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        calculateRiskScore(indicators) < 40
    }
}
