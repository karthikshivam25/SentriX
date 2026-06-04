package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * AI Threat Engine
 *
 * Responsible for:
 * - AI-powered threat assessment
 * - Behavioral anomaly detection
 * - Threat prediction
 * - Risk classification
 * - Security recommendations
 */
class AIThreatEngine {

    private val threatProfiles =
        ConcurrentHashMap<String, ThreatProfile>()

    data class ThreatProfile(
        val id: String,
        val name: String,
        val riskScore: Int,
        val confidence: Double,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Performs AI threat analysis.
     */
    suspend fun analyzeThreat(
        threatId: String,
        behavioralSignals: List<Int>
    ): NetworkResult<ThreatProfile> = withContext(Dispatchers.Default) {

        try {

            val riskScore =
                calculateRiskScore(behavioralSignals)

            val confidence =
                calculateConfidence(behavioralSignals)

            val profile = ThreatProfile(
                id = threatId,
                name = "AI Threat Analysis",
                riskScore = riskScore,
                confidence = confidence
            )

            threatProfiles[threatId] = profile

            NetworkResult.Success(profile)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "AI threat analysis failed"
            )
        }
    }

    /**
     * Registers a threat profile.
     */
    fun registerThreatProfile(
        profile: ThreatProfile
    ) {
        threatProfiles[profile.id] = profile
    }

    /**
     * Retrieves threat profile.
     */
    fun getThreatProfile(
        threatId: String
    ): ThreatProfile? {
        return threatProfiles[threatId]
    }

    /**
     * Returns all threat profiles.
     */
    fun getThreatProfiles(): List<ThreatProfile> {
        return threatProfiles.values.toList()
    }

    /**
     * Detects behavioral anomalies.
     */
    fun detectAnomaly(
        baselineScore: Int,
        currentScore: Int,
        threshold: Int = 25
    ): Boolean {
        return abs(currentScore - baselineScore) >= threshold
    }

    /**
     * Predicts future threat probability.
     */
    fun predictThreatProbability(
        riskScore: Int,
        confidence: Double
    ): Double {

        return ((riskScore / 100.0) * confidence)
            .coerceIn(0.0, 1.0)
    }

    /**
     * Calculates overall risk score.
     */
    fun calculateRiskScore(
        signals: List<Int>
    ): Int {

        if (signals.isEmpty()) {
            return 0
        }

        return signals.average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Calculates AI confidence score.
     */
    fun calculateConfidence(
        signals: List<Int>
    ): Double {

        if (signals.isEmpty()) {
            return 0.0
        }

        val variance =
            signals.map { value ->
                (value - signals.average()) *
                        (value - signals.average())
            }.average()

        return when {
            variance < 25 -> 0.95
            variance < 100 -> 0.85
            variance < 250 -> 0.75
            else -> 0.60
        }
    }

    /**
     * Returns threat level.
     */
    fun getThreatLevel(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 90 -> "CRITICAL"
            riskScore >= 75 -> "HIGH"
            riskScore >= 50 -> "MEDIUM"
            riskScore >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Generates AI security recommendations.
     */
    fun generateRecommendations(
        riskScore: Int
    ): List<String> {

        return when {
            riskScore >= 90 -> listOf(
                "Immediately isolate the affected device.",
                "Block all suspicious network traffic.",
                "Initiate incident response procedures."
            )

            riskScore >= 75 -> listOf(
                "Perform a full threat investigation.",
                "Enable advanced protection features.",
                "Review recent security events."
            )

            riskScore >= 50 -> listOf(
                "Monitor device activity closely.",
                "Run a detailed security scan."
            )

            riskScore >= 25 -> listOf(
                "Review anomalous behavior patterns."
            )

            else -> listOf(
                "No significant threats detected."
            )
        }
    }

    /**
     * Removes a threat profile.
     */
    fun removeThreatProfile(
        threatId: String
    ) {
        threatProfiles.remove(threatId)
    }

    /**
     * Clears all threat profiles.
     */
    fun clearThreatProfiles() {
        threatProfiles.clear()
    }

    /**
     * Returns total stored profiles.
     */
    fun getProfileCount(): Int {
        return threatProfiles.size
    }
}
