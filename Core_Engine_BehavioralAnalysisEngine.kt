package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs
import kotlin.math.roundToInt

/**
 * Behavioral Analysis Engine
 *
 * Responsible for:
 * - User and application behavior analysis
 * - Anomaly detection
 * - Pattern recognition
 * - Behavioral risk assessment
 * - Security recommendations
 */
class BehavioralAnalysisEngine {

    private val behaviorRecords =
        ConcurrentHashMap<String, BehaviorAnalysis>()

    data class BehaviorAnalysis(
        val entityId: String,
        val baselineScore: Int,
        val currentScore: Int,
        val anomalyDetected: Boolean,
        val riskScore: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Performs behavioral analysis.
     */
    suspend fun analyzeBehavior(
        entityId: String,
        baselineScore: Int,
        currentScore: Int
    ): NetworkResult<BehaviorAnalysis> = withContext(Dispatchers.Default) {

        try {

            val anomalyDetected = detectAnomaly(
                baselineScore = baselineScore,
                currentScore = currentScore
            )

            val riskScore = calculateRiskScore(
                baselineScore = baselineScore,
                currentScore = currentScore
            )

            val analysis = BehaviorAnalysis(
                entityId = entityId,
                baselineScore = baselineScore,
                currentScore = currentScore,
                anomalyDetected = anomalyDetected,
                riskScore = riskScore
            )

            behaviorRecords[entityId] = analysis

            NetworkResult.Success(analysis)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Behavioral analysis failed"
            )
        }
    }

    /**
     * Registers an analysis record.
     */
    fun registerAnalysis(
        analysis: BehaviorAnalysis
    ) {
        behaviorRecords[analysis.entityId] = analysis
    }

    /**
     * Retrieves an analysis record.
     */
    fun getAnalysis(
        entityId: String
    ): BehaviorAnalysis? {
        return behaviorRecords[entityId]
    }

    /**
     * Returns all analysis records.
     */
    fun getAnalyses(): List<BehaviorAnalysis> {
        return behaviorRecords.values.toList()
    }

    /**
     * Detects anomalous behavior.
     */
    fun detectAnomaly(
        baselineScore: Int,
        currentScore: Int,
        threshold: Int = 25
    ): Boolean {
        return abs(currentScore - baselineScore) >= threshold
    }

    /**
     * Calculates behavioral risk score.
     */
    fun calculateRiskScore(
        baselineScore: Int,
        currentScore: Int
    ): Int {

        return abs(
            currentScore - baselineScore
        ).coerceIn(0, 100)
    }

    /**
     * Calculates average risk score.
     */
    fun calculateAverageRiskScore(): Int {

        if (behaviorRecords.isEmpty()) {
            return 0
        }

        return behaviorRecords.values
            .map { it.riskScore }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Returns behavioral risk level.
     */
    fun getRiskLevel(
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
     * Checks whether behavior is high risk.
     */
    fun isHighRiskBehavior(
        riskScore: Int
    ): Boolean {
        return riskScore >= 75
    }

    /**
     * Generates recommendations.
     */
    fun generateRecommendations(
        riskScore: Int
    ): List<String> {

        return when {
            riskScore >= 90 -> listOf(
                "Immediate investigation required.",
                "Restrict sensitive activities.",
                "Trigger security incident workflow."
            )

            riskScore >= 75 -> listOf(
                "Investigate anomalous behavior.",
                "Increase monitoring frequency."
            )

            riskScore >= 50 -> listOf(
                "Review behavioral trends.",
                "Monitor entity activity closely."
            )

            riskScore >= 25 -> listOf(
                "Continue behavioral observation."
            )

            else -> listOf(
                "Behavior appears normal."
            )
        }
    }

    /**
     * Removes an analysis record.
     */
    fun removeAnalysis(
        entityId: String
    ) {
        behaviorRecords.remove(entityId)
    }

    /**
     * Clears all analysis records.
     */
    fun clearAnalyses() {
        behaviorRecords.clear()
    }

    /**
     * Returns total analysis count.
     */
    fun getAnalysisCount(): Int {
        return behaviorRecords.size
    }

    /**
     * Returns anomalous records only.
     */
    fun getAnomalousRecords(): List<BehaviorAnalysis> {
        return behaviorRecords.values.filter {
            it.anomalyDetected
        }
    }
}
