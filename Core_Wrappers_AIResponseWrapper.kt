package com.sentrix.core.wrappers

import com.sentrix.core.enums.AIAnalysisState

/**
 * Wrapper representing an AI analysis response.
 */
data class AIResponseWrapper(
    val requestId: String,
    val state: AIAnalysisState,
    val summary: String,
    val confidenceScore: Float = 0f,
    val riskScore: Int = 0,
    val recommendations: List<String> = emptyList(),
    val detectedPatterns: List<String> = emptyList(),
    val insights: List<String> = emptyList(),
    val modelVersion: String = "",
    val processingTimeMillis: Long = 0L,
    val createdAt: Long = System.currentTimeMillis(),
    val metadata: Map<String, Any> = emptyMap()
) {

    /**
     * Returns true if the analysis completed successfully.
     */
    fun isCompleted(): Boolean =
        state == AIAnalysisState.COMPLETED

    /**
     * Returns true if the analysis is currently running.
     */
    fun isProcessing(): Boolean =
        state == AIAnalysisState.PROCESSING

    /**
     * Returns true if the analysis failed.
     */
    fun hasFailed(): Boolean =
        state == AIAnalysisState.FAILED

    /**
     * Returns true if confidence is considered high.
     */
    fun isHighConfidence(): Boolean =
        confidenceScore >= 0.80f

    /**
     * Returns risk level based on score.
     */
    fun getRiskLevel(): String {
        return when (riskScore) {
            in 0..20 -> "Low"
            in 21..50 -> "Moderate"
            in 51..80 -> "High"
            else -> "Critical"
        }
    }

    /**
     * Returns processing time in seconds.
     */
    fun getProcessingTimeSeconds(): Double =
        processingTimeMillis / 1000.0

    /**
     * Returns true if recommendations exist.
     */
    fun hasRecommendations(): Boolean =
        recommendations.isNotEmpty()

    /**
     * Returns true if insights are available.
     */
    fun hasInsights(): Boolean =
        insights.isNotEmpty()

    companion object {

        fun empty(): AIResponseWrapper {
            return AIResponseWrapper(
                requestId = "",
                state = AIAnalysisState.IDLE,
                summary = ""
            )
        }
    }
}
