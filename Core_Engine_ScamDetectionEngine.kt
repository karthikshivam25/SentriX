package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Scam Detection Engine
 *
 * Responsible for:
 * - Scam message detection
 * - Fraud pattern recognition
 * - URL risk assessment
 * - Social engineering analysis
 * - Scam risk scoring
 */
class ScamDetectionEngine {

    private val detectedScams =
        ConcurrentHashMap<String, ScamAnalysis>()

    data class ScamAnalysis(
        val id: String,
        val content: String,
        val scamScore: Int,
        val category: String,
        val indicators: List<String>,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes text for scam indicators.
     */
    suspend fun analyzeContent(
        id: String,
        content: String
    ): NetworkResult<ScamAnalysis> = withContext(Dispatchers.Default) {

        try {

            val indicators = detectIndicators(content)
            val score = calculateScamScore(indicators)

            val result = ScamAnalysis(
                id = id,
                content = content,
                scamScore = score,
                category = determineCategory(indicators),
                indicators = indicators
            )

            detectedScams[id] = result

            NetworkResult.Success(result)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Scam analysis failed"
            )
        }
    }

    /**
     * Registers a scam analysis result.
     */
    fun registerAnalysis(
        analysis: ScamAnalysis
    ) {
        detectedScams[analysis.id] = analysis
    }

    /**
     * Retrieves analysis result.
     */
    fun getAnalysis(
        id: String
    ): ScamAnalysis? {
        return detectedScams[id]
    }

    /**
     * Returns all analyses.
     */
    fun getAnalyses(): List<ScamAnalysis> {
        return detectedScams.values.toList()
    }

    /**
     * Calculates scam score.
     */
    fun calculateScamScore(
        indicators: List<String>
    ): Int {

        return when {
            indicators.size >= 5 -> 100
            indicators.size == 4 -> 85
            indicators.size == 3 -> 70
            indicators.size == 2 -> 50
            indicators.size == 1 -> 30
            else -> 0
        }
    }

    /**
     * Determines scam risk level.
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
     * Checks if content is likely a scam.
     */
    fun isLikelyScam(
        score: Int,
        threshold: Int = 70
    ): Boolean {
        return score >= threshold
    }

    /**
     * Generates recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Block content immediately.",
                "Warn the user.",
                "Report the sender."
            )

            score >= 75 -> listOf(
                "Treat message as suspicious.",
                "Avoid clicking links.",
                "Verify sender identity."
            )

            score >= 50 -> listOf(
                "Review content carefully.",
                "Do not share sensitive information."
            )

            score >= 25 -> listOf(
                "Exercise caution."
            )

            else -> listOf(
                "No significant scam indicators detected."
            )
        }
    }

    /**
     * Removes an analysis record.
     */
    fun removeAnalysis(
        id: String
    ) {
        detectedScams.remove(id)
    }

    /**
     * Clears all analysis records.
     */
    fun clearAnalyses() {
        detectedScams.clear()
    }

    /**
     * Returns analysis count.
     */
    fun getAnalysisCount(): Int {
        return detectedScams.size
    }

    /**
     * Detects scam indicators in content.
     */
    private fun detectIndicators(
        content: String
    ): List<String> {

        val indicators = mutableListOf<String>()
        val text = content.lowercase()

        if ("urgent" in text) {
            indicators.add("URGENT_LANGUAGE")
        }

        if ("winner" in text ||
            "won" in text ||
            "lottery" in text
        ) {
            indicators.add("FAKE_REWARD")
        }

        if ("click here" in text ||
            "verify now" in text
        ) {
            indicators.add("PHISHING_CALL_TO_ACTION")
        }

        if ("bank account" in text ||
            "credit card" in text ||
            "otp" in text ||
            "password" in text
        ) {
            indicators.add("SENSITIVE_INFORMATION_REQUEST")
        }

        if ("limited time" in text ||
            "act now" in text
        ) {
            indicators.add("PRESSURE_TACTICS")
        }

        return indicators
    }

    /**
     * Determines scam category.
     */
    private fun determineCategory(
        indicators: List<String>
    ): String {

        return when {
            indicators.contains(
                "PHISHING_CALL_TO_ACTION"
            ) -> "PHISHING"

            indicators.contains(
                "FAKE_REWARD"
            ) -> "LOTTERY_SCAM"

            indicators.contains(
                "SENSITIVE_INFORMATION_REQUEST"
            ) -> "CREDENTIAL_THEFT"

            indicators.isNotEmpty() -> "SOCIAL_ENGINEERING"

            else -> "SAFE"
        }
    }
}
