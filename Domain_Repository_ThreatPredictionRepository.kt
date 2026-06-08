package com.sentrix.domain.repositories

import com.sentrix.domain.models.ThreatPrediction
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.models.ThreatTrend

/**
 * ThreatPredictionRepository
 *
 * Repository responsible for
 * managing threat prediction
 * information within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - AIThreatPredictionEngine
 * - ThreatAnalysisEngine
 * - CyberDefenseManager
 * - SecurityDashboard
 * - RiskAssessmentEngine
 *
 * Responsibilities:
 * - Store threat predictions
 * - Retrieve prediction history
 * - Analyze threat trends
 * - Support AI forecasting
 * - Provide predictive analytics
 */
interface ThreatPredictionRepository {

    /**
     * Retrieves all threat
     * predictions.
     *
     * @return Prediction list.
     */
    suspend fun getPredictions():
        List<ThreatPrediction>

    /**
     * Retrieves prediction
     * by identifier.
     *
     * @param predictionId Prediction ID.
     *
     * @return Threat prediction.
     */
    suspend fun getPredictionById(
        predictionId: String
    ): ThreatPrediction?

    /**
     * Saves threat prediction.
     *
     * @param prediction Prediction data.
     */
    suspend fun savePrediction(
        prediction: ThreatPrediction
    )

    /**
     * Updates prediction.
     *
     * @param prediction Prediction data.
     */
    suspend fun updatePrediction(
        prediction: ThreatPrediction
    )

    /**
     * Deletes prediction.
     *
     * @param predictionId Prediction ID.
     */
    suspend fun deletePrediction(
        predictionId: String
    )

    /**
     * Retrieves predictions
     * by threat level.
     *
     * @param threatLevel Threat level.
     *
     * @return Prediction list.
     */
    suspend fun getPredictionsByLevel(
        threatLevel: ThreatLevel
    ): List<ThreatPrediction>

    /**
     * Retrieves latest
     * prediction result.
     *
     * @return Latest prediction.
     */
    suspend fun getLatestPrediction():
        ThreatPrediction?

    /**
     * Retrieves total
     * prediction count.
     *
     * @return Prediction count.
     */
    suspend fun getPredictionCount():
        Int
}

/**
 * ThreatPrediction
 *
 * Represents a predicted
 * cybersecurity threat.
 */
data class ThreatPrediction(

    /**
     * Prediction identifier.
     */
    val predictionId: String,

    /**
     * Predicted threat name.
     */
    val threatName: String,

    /**
     * Threat category.
     */
    val category:
        ThreatPredictionCategory,

    /**
     * Predicted severity.
     */
    val threatLevel:
        ThreatLevel,

    /**
     * Prediction confidence.
     */
    val confidenceScore: Double,

    /**
     * Expected threat trend.
     */
    val threatTrend:
        ThreatTrend,

    /**
     * Prediction timestamp.
     */
    val predictedAt: Long,

    /**
     * Prediction summary.
     */
    val summary: String
)

/**
 * Threat prediction categories.
 */
enum class ThreatPredictionCategory {

    /**
     * Malware prediction.
     */
    MALWARE,

    /**
     * Ransomware prediction.
     */
    RANSOMWARE,

    /**
     * Phishing prediction.
     */
    PHISHING,

    /**
     * Network attack prediction.
     */
    NETWORK_ATTACK,

    /**
     * Data breach prediction.
     */
    DATA_BREACH,

    /**
     * Insider threat prediction.
     */
    INSIDER_THREAT,

    /**
     * Zero-day attack prediction.
     */
    ZERO_DAY_ATTACK,

    /**
     * Advanced persistent threat.
     */
    ADVANCED_PERSISTENT_THREAT
}

/**
 * Threat trends.
 */
enum class ThreatTrend {

    /**
     * Threat activity increasing.
     */
    INCREASING,

    /**
     * Threat activity stable.
     */
    STABLE,

    /**
     * Threat activity decreasing.
     */
    DECREASING,

    /**
     * Critical threat trend.
     */
    CRITICAL
}
