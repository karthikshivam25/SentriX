package com.sentrix.domain.usecases

import com.sentrix.domain.models.ScamAnalysis
import com.sentrix.domain.repositories.ScamRepository

/**
 * AnalyzeScamUseCase
 *
 * Responsible for analyzing messages,
 * communications, websites, emails,
 * SMS content, and social engineering
 * attempts to identify potential scams
 * within the SentriX cybersecurity platform.
 *
 * This use case evaluates scam indicators,
 * fraud patterns, impersonation attempts,
 * social engineering techniques, suspicious
 * language patterns, and threat intelligence
 * data to determine scam likelihood.
 *
 * Used by:
 * - ScamDetectionEngine
 * - PhishingProtectionService
 * - RealtimeProtectionEngine
 * - SecurityDashboard
 * - ThreatAnalysisManager
 * - AIThreatDetectionEngine
 * - FraudPreventionService
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Detect scam attempts
 * - Identify fraud indicators
 * - Detect impersonation attacks
 * - Evaluate social engineering risks
 * - Calculate scam risk scores
 * - Generate security recommendations
 */
class AnalyzeScamUseCase(
    private val repository: ScamRepository
) {

    /**
     * Executes scam analysis on
     * the provided content.
     *
     * @param content Text, message,
     * email, or communication content
     * to analyze.
     *
     * @return ScamAnalysisResult
     */
    suspend operator fun invoke(
        content: String
    ): ScamAnalysisResult {

        val scamKeywords =
            repository.getScamKeywords()

        val fraudPatterns =
            repository.getFraudPatterns()

        val detectedKeywords =
            scamKeywords.filter { keyword ->
                content.contains(
                    keyword,
                    ignoreCase = true
                )
            }

        val matchedPatterns =
            fraudPatterns.filter { pattern ->
                content.contains(
                    pattern.pattern,
                    ignoreCase = true
                )
            }

        val scamRiskLevel =
            determineRiskLevel(
                keywordMatches =
                    detectedKeywords.size,
                patternMatches =
                    matchedPatterns.size
            )

        val riskScore =
            calculateRiskScore(
                keywordMatches =
                    detectedKeywords.size,
                patternMatches =
                    matchedPatterns.size
            )

        return ScamAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            analyzedContent = content,
            riskLevel = scamRiskLevel,
            riskScore = riskScore,
            detectedKeywords =
                detectedKeywords,
            matchedPatterns =
                matchedPatterns,
            recommendations =
                generateRecommendations(
                    scamRiskLevel
                )
        )
    }

    /**
     * Determines scam risk level.
     */
    private fun determineRiskLevel(
        keywordMatches: Int,
        patternMatches: Int
    ): ScamRiskLevel {

        return when {

            patternMatches >= 5 ->
                ScamRiskLevel.CRITICAL

            patternMatches >= 3 ->
                ScamRiskLevel.HIGH

            keywordMatches >= 5 ->
                ScamRiskLevel.MEDIUM

            else ->
                ScamRiskLevel.LOW
        }
    }

    /**
     * Calculates scam risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        keywordMatches: Int,
        patternMatches: Int
    ): Int {

        val score =
            (keywordMatches * 8) +
            (patternMatches * 20)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates scam-related
     * security recommendations.
     */
    private fun generateRecommendations(
        riskLevel: ScamRiskLevel
    ): List<String> {

        return when (riskLevel) {

            ScamRiskLevel.CRITICAL -> listOf(
                "Do not interact with sender",
                "Block communication immediately",
                "Report scam attempt",
                "Do not share personal information"
            )

            ScamRiskLevel.HIGH -> listOf(
                "Verify sender identity",
                "Avoid clicking links",
                "Avoid sharing sensitive data"
            )

            ScamRiskLevel.MEDIUM -> listOf(
                "Exercise caution",
                "Verify authenticity independently"
            )

            ScamRiskLevel.LOW -> listOf(
                "No major scam indicators detected"
            )
        }
    }
}

/**
 * ScamAnalysisResult
 *
 * Represents the outcome of
 * scam analysis.
 */
data class ScamAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Original content analyzed.
     */
    val analyzedContent: String,

    /**
     * Calculated scam risk level.
     */
    val riskLevel: ScamRiskLevel,

    /**
     * Calculated scam risk score.
     */
    val riskScore: Int,

    /**
     * Scam-related keywords detected.
     */
    val detectedKeywords: List<String>,

    /**
     * Fraud patterns identified.
     */
    val matchedPatterns:
        List<FraudPattern>,

    /**
     * Recommended actions.
     */
    val recommendations: List<String>
)

/**
 * FraudPattern
 *
 * Represents a known fraud or
 * scam detection pattern.
 */
data class FraudPattern(

    /**
     * Pattern identifier.
     */
    val patternId: String,

    /**
     * Pattern name.
     */
    val name: String,

    /**
     * Detection pattern.
     */
    val pattern: String,

    /**
     * Pattern description.
     */
    val description: String,

    /**
     * Severity score.
     */
    val severityScore: Int
)

/**
 * Scam risk indicators.
 */
enum class ScamRiskLevel {

    /**
     * Low scam risk.
     */
    LOW,

    /**
     * Moderate scam risk.
     */
    MEDIUM,

    /**
     * High scam risk.
     */
    HIGH,

    /**
     * Critical scam risk.
     */
    CRITICAL
}
