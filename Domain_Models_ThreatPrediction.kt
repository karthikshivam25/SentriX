package com.sentrix.domain.models

/**
 * ThreatPrediction
 *
 * Represents an AI-generated prediction
 * of potential future security threats
 * within the SentriX platform.
 *
 * Used by:
 * - AI Threat Engine
 * - Predictive Security Module
 * - Threat Intelligence System
 * - Security Dashboard
 * - Risk Assessment Engine
 * - Incident Prevention Services
 */
data class ThreatPrediction(

    /**
     * Unique prediction identifier.
     */
    val predictionId: String,

    /**
     * Predicted threat title.
     */
    val title: String,

    /**
     * Detailed prediction description.
     */
    val description: String,

    /**
     * Predicted threat category.
     */
    val category: ThreatCategory,

    /**
     * Estimated severity.
     */
    val severity: ThreatSeverity,

    /**
     * Probability score (0 - 100).
     */
    val probabilityScore: Int,

    /**
     * Estimated risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * AI confidence level (0 - 100).
     */
    val confidenceScore: Int,

    /**
     * Predicted occurrence timestamp.
     */
    val predictedAt: Long,

    /**
     * Potentially affected component.
     */
    val affectedComponent: String,

    /**
     * Recommended preventive actions.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Prediction source.
     */
    val predictionSource: PredictionSource,

    /**
     * Optional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Prediction source.
 */
enum class PredictionSource {
    AI_ENGINE,
    THREAT_INTELLIGENCE,
    BEHAVIOR_ANALYSIS,
    NETWORK_ANALYSIS,
    USER_ACTIVITY_ANALYSIS,
    CLOUD_ANALYTICS,
    HYBRID
}
