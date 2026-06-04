package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Risk Scoring Engine
 *
 * Responsible for:
 * - Aggregating security signals
 * - Calculating overall risk score
 * - Risk classification
 * - Security posture evaluation
 * - Recommendation generation
 */
class RiskScoringEngine {

    private val riskProfiles =
        ConcurrentHashMap<String, RiskProfile>()

    data class RiskProfile(
        val profileId: String,
        val score: Int,
        val level: RiskLevel,
        val factors: List<String>,
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class RiskLevel {
        SAFE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Creates a risk profile from multiple risk factors.
     */
    suspend fun calculateRiskProfile(
        profileId: String,
        scores: List<Int>,
        factors: List<String>
    ): NetworkResult<RiskProfile> = withContext(Dispatchers.Default) {

        try {

            val score = calculateOverallScore(scores)
            val level = determineRiskLevel(score)

            val profile = RiskProfile(
                profileId = profileId,
                score = score,
                level = level,
                factors = factors
            )

            riskProfiles[profileId] = profile

            NetworkResult.Success(profile)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Risk profile calculation failed"
            )
        }
    }

    /**
     * Registers a risk profile.
     */
    fun registerProfile(
        profile: RiskProfile
    ) {
        riskProfiles[profile.profileId] = profile
    }

    /**
     * Retrieves a risk profile.
     */
    fun getProfile(
        profileId: String
    ): RiskProfile? {
        return riskProfiles[profileId]
    }

    /**
     * Returns all risk profiles.
     */
    fun getProfiles(): List<RiskProfile> {
        return riskProfiles.values.toList()
    }

    /**
     * Calculates overall score.
     */
    fun calculateOverallScore(
        scores: List<Int>
    ): Int {

        if (scores.isEmpty()) {
            return 0
        }

        return scores
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Determines risk level.
     */
    fun determineRiskLevel(
        score: Int
    ): RiskLevel {

        return when {
            score >= 90 -> RiskLevel.CRITICAL
            score >= 75 -> RiskLevel.HIGH
            score >= 50 -> RiskLevel.MEDIUM
            score >= 25 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
    }

    /**
     * Checks whether profile is high risk.
     */
    fun isHighRisk(
        score: Int
    ): Boolean {
        return score >= 75
    }

    /**
     * Generates recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Immediate remediation required.",
                "Restrict sensitive operations.",
                "Perform a full security audit."
            )

            score >= 75 -> listOf(
                "Investigate identified risks.",
                "Enable advanced protection features.",
                "Review security controls."
            )

            score >= 50 -> listOf(
                "Monitor security posture closely.",
                "Address medium-risk findings."
            )

            score >= 25 -> listOf(
                "Continue periodic monitoring."
            )

            else -> listOf(
                "Security posture is healthy."
            )
        }
    }

    /**
     * Returns average score across all profiles.
     */
    fun calculateAverageRiskScore(): Int {

        if (riskProfiles.isEmpty()) {
            return 0
        }

        return riskProfiles.values
            .map { it.score }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Removes a profile.
     */
    fun removeProfile(
        profileId: String
    ) {
        riskProfiles.remove(profileId)
    }

    /**
     * Clears all profiles.
     */
    fun clearProfiles() {
        riskProfiles.clear()
    }

    /**
     * Returns total profile count.
     */
    fun getProfileCount(): Int {
        return riskProfiles.size
    }

    /**
     * Returns critical-risk profiles.
     */
    fun getCriticalProfiles(): List<RiskProfile> {
        return riskProfiles.values.filter {
            it.level == RiskLevel.CRITICAL
        }
    }
}
