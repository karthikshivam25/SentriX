package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Threat Detection Engine
 *
 * Responsible for:
 * - Threat identification
 * - Risk assessment
 * - Behavioral analysis
 * - Threat scoring
 * - Security recommendations
 */
class ThreatDetectionEngine {

    private val detectedThreats =
        ConcurrentHashMap<String, ThreatRecord>()

    data class ThreatRecord(
        val threatId: String,
        val threatName: String,
        val severity: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyze threat indicators.
     */
    suspend fun analyzeThreats(
        indicators: List<String>
    ): NetworkResult<List<ThreatRecord>> = withContext(Dispatchers.Default) {

        try {

            val threats = indicators.mapIndexed { index, indicator ->

                val severity = calculateIndicatorSeverity(indicator)

                ThreatRecord(
                    threatId = "THREAT_$index",
                    threatName = indicator,
                    severity = severity
                )
            }

            threats.forEach {
                detectedThreats[it.threatId] = it
            }

            NetworkResult.Success(threats)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Threat analysis failed"
            )
        }
    }

    /**
     * Registers a detected threat.
     */
    fun registerThreat(
        threatId: String,
        threatName: String,
        severity: Int
    ) {
        detectedThreats[threatId] = ThreatRecord(
            threatId = threatId,
            threatName = threatName,
            severity = severity.coerceIn(0, 100)
        )
    }

    /**
     * Removes a threat.
     */
    fun removeThreat(
        threatId: String
    ) {
        detectedThreats.remove(threatId)
    }

    /**
     * Returns all active threats.
     */
    fun getActiveThreats(): List<ThreatRecord> {
        return detectedThreats.values.toList()
    }

    /**
     * Finds a threat by ID.
     */
    fun getThreat(
        threatId: String
    ): ThreatRecord? {
        return detectedThreats[threatId]
    }

    /**
     * Calculates overall threat score.
     */
    fun calculateOverallThreatScore(): Int {

        if (detectedThreats.isEmpty()) {
            return 0
        }

        return detectedThreats.values
            .map { it.severity }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Determines threat level.
     */
    fun getThreatLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Checks if any critical threats exist.
     */
    fun hasCriticalThreats(): Boolean {
        return detectedThreats.values.any {
            it.severity >= 90
        }
    }

    /**
     * Generates security recommendations.
     */
    fun generateRecommendations(): List<String> {

        val recommendations = mutableListOf<String>()

        if (hasCriticalThreats()) {
            recommendations.add(
                "Immediate security review required."
            )
        }

        if (calculateOverallThreatScore() > 60) {
            recommendations.add(
                "Enable advanced threat protection."
            )
        }

        if (detectedThreats.isNotEmpty()) {
            recommendations.add(
                "Run a complete device security scan."
            )
        }

        if (recommendations.isEmpty()) {
            recommendations.add(
                "No immediate threats detected."
            )
        }

        return recommendations
    }

    /**
     * Clears all detected threats.
     */
    fun clearThreats() {
        detectedThreats.clear()
    }

    /**
     * Returns total threat count.
     */
    fun getThreatCount(): Int {
        return detectedThreats.size
    }

    /**
     * Calculates severity based on indicator.
     */
    private fun calculateIndicatorSeverity(
        indicator: String
    ): Int {

        return when {
            indicator.contains(
                "malware",
                ignoreCase = true
            ) -> 95

            indicator.contains(
                "root",
                ignoreCase = true
            ) -> 85

            indicator.contains(
                "phishing",
                ignoreCase = true
            ) -> 90

            indicator.contains(
                "spyware",
                ignoreCase = true
            ) -> 88

            indicator.contains(
                "trojan",
                ignoreCase = true
            ) -> 92

            else -> 40
        }
    }
}
