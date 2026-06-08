package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.SecurityMetrics
import com.cyberdefender.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for threat prediction and risk forecasting.
 *
 * This service analyzes current threat indicators
 * and historical security metrics to predict
 * future security risks.
 */
class ThreatPredictionService {

    /**
     * Predicts future threat level based on
     * currently detected threat indicators.
     *
     * Returns:
     * - CRITICAL
     * - HIGH
     * - MEDIUM
     * - LOW
     * - SAFE
     */
    suspend fun predictThreatLevel(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        val riskScore = calculatePredictionScore(indicators)

        when {
            riskScore >= 80 -> "CRITICAL"
            riskScore >= 60 -> "HIGH"
            riskScore >= 40 -> "MEDIUM"
            riskScore >= 20 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Predicts the probability of a future attack.
     *
     * Returns a percentage value between 0 and 100.
     */
    suspend fun predictAttackProbability(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): Double = withContext(Dispatchers.Default) {

        val score = calculatePredictionScore(indicators)
        val metricFactor = metrics.riskScore

        ((score + metricFactor) / 2.0)
            .coerceIn(0.0, 100.0)
    }

    /**
     * Predicts whether the system is likely
     * to face a critical threat soon.
     */
    suspend fun willFaceCriticalThreat(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): Boolean = withContext(Dispatchers.Default) {

        predictAttackProbability(indicators, metrics) >= 75.0
    }

    /**
     * Returns threat indicators that contribute
     * most significantly to future risks.
     */
    suspend fun getPredictedHighRiskThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", true) ||
            it.severity.equals("HIGH", true)
        }
    }

    /**
     * Calculates a prediction score based on
     * currently detected threats.
     *
     * Maximum score = 100.
     */
    suspend fun calculatePredictionScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf { threat ->
            when (threat.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Generates future threat recommendations
     * based on current security posture.
     */
    suspend fun generateRecommendations(
        threatLevel: String
    ): List<String> = withContext(Dispatchers.Default) {

        when (threatLevel.uppercase()) {

            "CRITICAL" -> listOf(
                "Perform an immediate full system scan.",
                "Enable all protection modules.",
                "Investigate critical threats immediately.",
                "Review device integrity status."
            )

            "HIGH" -> listOf(
                "Review active security alerts.",
                "Perform a deep malware scan.",
                "Verify network security settings."
            )

            "MEDIUM" -> listOf(
                "Monitor system activity closely.",
                "Update security definitions.",
                "Review application permissions."
            )

            "LOW" -> listOf(
                "Continue routine monitoring.",
                "Keep security modules enabled."
            )

            else -> listOf(
                "System appears secure.",
                "Maintain regular security checks."
            )
        }
    }

    /**
     * Generates a threat prediction summary.
     */
    suspend fun generatePredictionSummary(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val threatLevel = predictThreatLevel(indicators)
        val probability = predictAttackProbability(
            indicators,
            metrics
        )

        buildString {
            appendLine("Threat Prediction Summary")
            appendLine("-------------------------")
            appendLine("Current Threat Count: ${indicators.size}")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Predicted Threat Level: $threatLevel")
            appendLine(
                "Attack Probability: ${
                    String.format("%.2f", probability)
                }%"
            )
            appendLine(
                if (probability >= 75)
                    "Status: High Future Risk"
                else
                    "Status: Stable Security Posture"
            )
        }
    }

    /**
     * Determines whether the security posture
     * is expected to remain stable.
     */
    suspend fun isSecurityStable(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): Boolean = withContext(Dispatchers.Default) {

        predictAttackProbability(
            indicators,
            metrics
        ) < 50.0
    }

    /**
     * Returns the most severe threat currently present.
     */
    suspend fun getMostSevereThreat(
        indicators: List<ThreatIndicator>
    ): ThreatIndicator? = withContext(Dispatchers.Default) {

        indicators.maxByOrNull {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 4
                "HIGH" -> 3
                "MEDIUM" -> 2
                "LOW" -> 1
                else -> 0
            }
        }
    }
}
