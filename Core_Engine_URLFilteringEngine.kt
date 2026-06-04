package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.util.concurrent.ConcurrentHashMap

/**
 * URL Filtering Engine
 *
 * Responsible for:
 * - URL reputation analysis
 * - Phishing detection
 * - Domain validation
 * - URL categorization
 * - Safe browsing enforcement
 */
class URLFilteringEngine {

    private val analyzedUrls =
        ConcurrentHashMap<String, UrlAnalysis>()

    data class UrlAnalysis(
        val url: String,
        val domain: String,
        val riskScore: Int,
        val category: String,
        val isSafe: Boolean,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes a URL for security risks.
     */
    suspend fun analyzeUrl(
        url: String
    ): NetworkResult<UrlAnalysis> = withContext(Dispatchers.Default) {

        try {

            val domain = extractDomain(url)

            val riskScore = calculateRiskScore(url)

            val analysis = UrlAnalysis(
                url = url,
                domain = domain,
                riskScore = riskScore,
                category = determineCategory(url, riskScore),
                isSafe = riskScore < 70
            )

            analyzedUrls[url] = analysis

            NetworkResult.Success(analysis)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "URL analysis failed"
            )
        }
    }

    /**
     * Registers URL analysis.
     */
    fun registerAnalysis(
        analysis: UrlAnalysis
    ) {
        analyzedUrls[analysis.url] = analysis
    }

    /**
     * Retrieves URL analysis.
     */
    fun getAnalysis(
        url: String
    ): UrlAnalysis? {
        return analyzedUrls[url]
    }

    /**
     * Returns all analyzed URLs.
     */
    fun getAnalyses(): List<UrlAnalysis> {
        return analyzedUrls.values.toList()
    }

    /**
     * Determines if URL is safe.
     */
    fun isSafeUrl(
        url: String
    ): Boolean {
        return analyzedUrls[url]?.isSafe ?: true
    }

    /**
     * Calculates URL risk score.
     */
    fun calculateRiskScore(
        url: String
    ): Int {

        var score = 0
        val lowerUrl = url.lowercase()

        if (!lowerUrl.startsWith("https://")) {
            score += 20
        }

        if (lowerUrl.contains("@")) {
            score += 20
        }

        if (lowerUrl.contains("bit.ly") ||
            lowerUrl.contains("tinyurl") ||
            lowerUrl.contains("goo.gl")
        ) {
            score += 25
        }

        if (lowerUrl.contains("login") ||
            lowerUrl.contains("verify") ||
            lowerUrl.contains("secure")
        ) {
            score += 15
        }

        if (lowerUrl.length > 100) {
            score += 20
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Returns URL risk level.
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
     * Generates security recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Block URL immediately.",
                "Warn user about phishing risk.",
                "Report malicious domain."
            )

            score >= 75 -> listOf(
                "Avoid visiting this URL.",
                "Verify destination manually."
            )

            score >= 50 -> listOf(
                "Proceed with caution.",
                "Inspect URL before opening."
            )

            score >= 25 -> listOf(
                "Review URL carefully."
            )

            else -> listOf(
                "URL appears safe."
            )
        }
    }

    /**
     * Removes analysis result.
     */
    fun removeAnalysis(
        url: String
    ) {
        analyzedUrls.remove(url)
    }

    /**
     * Clears all analyzed URLs.
     */
    fun clearAnalyses() {
        analyzedUrls.clear()
    }

    /**
     * Returns total analyzed URL count.
     */
    fun getAnalysisCount(): Int {
        return analyzedUrls.size
    }

    /**
     * Extracts domain from URL.
     */
    private fun extractDomain(
        url: String
    ): String {

        return try {
            URI(url).host ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    /**
     * Determines URL category.
     */
    private fun determineCategory(
        url: String,
        riskScore: Int
    ): String {

        return when {
            riskScore >= 75 -> "PHISHING"

            url.contains(
                "bank",
                ignoreCase = true
            ) -> "FINANCIAL"

            url.contains(
                "shop",
                ignoreCase = true
            ) -> "E_COMMERCE"

            url.contains(
                "social",
                ignoreCase = true
            ) -> "SOCIAL_MEDIA"

            else -> "GENERAL"
        }
    }
}
