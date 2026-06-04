package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Threat Prediction Engine
 *
 * Responsible for:
 * - Predictive threat analysis
 * - Threat trend evaluation
 * - Future risk estimation
 * - Security forecasting
 * - Prevention recommendations
 */
class ThreatPredictionEngine {

    private val predictions =
        ConcurrentHashMap<String, ThreatPrediction>()

    data class ThreatPrediction(
        val predictionId: String,
        val currentRiskScore: Int,
        val predictedRiskScore: Int,
        val probability: Double,
        val confidence: Double,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Predicts future threat risk.
     */
    suspend fun predictThreat(
        predictionId: String,
        historicalScores: List<Int>
    ): NetworkResult<ThreatPrediction> = withContext(Dispatchers.Default) {

        try {

            val currentRisk =
                historicalScores.lastOrNull() ?: 0

            val predictedRisk =
                calculatePredictedRisk(historicalScores)

            val probability =
                calculateProbability(predictedRisk)

            val confidence =
                calculateConfidence(historicalScores)

            val prediction = ThreatPrediction(
                predictionId = predictionId,
                currentRiskScore = currentRisk,
                predictedRiskScore = predictedRisk,
                probability = probability,
                confidence = confidence
            )

            predictions[predictionId] = prediction

            NetworkResult.Success(prediction)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Threat prediction failed"
            )
        }
    }

    /**
     * Registers a prediction.
     */
    fun registerPrediction(
        prediction: ThreatPrediction
    ) {
        predictions[prediction.predictionId] = prediction
    }

    /**
     * Retrieves a prediction.
     */
    fun getPrediction(
        predictionId: String
    ): ThreatPrediction? {
        return predictions[predictionId]
    }

    /**
     * Returns all predictions.
     */
    fun getPredictions(): List<ThreatPrediction> {
        return predictions.values.toList()
    }

    /**
     * Calculates predicted risk score.
     */
    fun calculatePredictedRisk(
        historicalScores: List<Int>
    ): Int {

        if (historicalScores.isEmpty()) {
            return 0
        }

        if (historicalScores.size == 1) {
            return historicalScores.first()
        }

        val trend =
            historicalScores.zipWithNext()
                .map { (previous, current) ->
                    current - previous
                }
                .average()

        val prediction =
            historicalScores.last() + trend

        return prediction
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Calculates threat probability.
     */
    fun calculateProbability(
        predictedRisk: Int
    ): Double {

        return (predictedRisk / 100.0)
            .coerceIn(0.0, 1.0)
    }

    /**
     * Calculates prediction confidence.
     */
    fun calculateConfidence(
        historicalScores: List<Int>
    ): Double {

        return when {
            historicalScores.size >= 20 -> 0.95
            historicalScores.size >= 10 -> 0.85
            historicalScores.size >= 5 -> 0.75
            historicalScores.size >= 2 -> 0.65
            else -> 0.50
        }
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
     * Generates predictive recommendations.
     */
    fun generateRecommendations(
        predictedRisk: Int
    ): List<String> {

        return when {
            predictedRisk >= 90 -> listOf(
                "Immediate preventive action required.",
                "Activate emergency protection policies.",
                "Prepare incident response procedures."
            )

            predictedRisk >= 75 -> listOf(
                "Increase security monitoring.",
                "Review high-risk indicators.",
                "Enable advanced protection mechanisms."
            )

            predictedRisk >= 50 -> listOf(
                "Monitor threat trends closely.",
                "Investigate emerging risk factors."
            )

            predictedRisk >= 25 -> listOf(
                "Maintain routine security monitoring."
            )

            else -> listOf(
                "Predicted threat level remains low."
            )
        }
    }

    /**
     * Removes a prediction.
     */
    fun removePrediction(
        predictionId: String
    ) {
        predictions.remove(predictionId)
    }

    /**
     * Clears all predictions.
     */
    fun clearPredictions() {
        predictions.clear()
    }

    /**
     * Returns prediction count.
     */
    fun getPredictionCount(): Int {
        return predictions.size
    }

    /**
     * Returns high-risk predictions.
     */
    fun getHighRiskPredictions(
        minimumRiskScore: Int = 75
    ): List<ThreatPrediction> {
        return predictions.values.filter {
            it.predictedRiskScore >= minimumRiskScore
        }
    }
}
