package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * App Behavior Engine
 *
 * Responsible for:
 * - Application behavior monitoring
 * - Usage pattern analysis
 * - Suspicious activity detection
 * - Behavioral risk scoring
 * - Security recommendations
 */
class AppBehaviorEngine {

    private val behaviorProfiles =
        ConcurrentHashMap<String, BehaviorProfile>()

    data class BehaviorProfile(
        val appPackage: String,
        val launchCount: Int,
        val networkRequests: Int,
        val permissionAccessCount: Int,
        val backgroundExecutionTime: Long,
        val riskScore: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes application behavior.
     */
    suspend fun analyzeBehavior(
        appPackage: String,
        launchCount: Int,
        networkRequests: Int,
        permissionAccessCount: Int,
        backgroundExecutionTime: Long
    ): NetworkResult<BehaviorProfile> = withContext(Dispatchers.Default) {

        try {

            val riskScore = calculateRiskScore(
                launchCount = launchCount,
                networkRequests = networkRequests,
                permissionAccessCount = permissionAccessCount,
                backgroundExecutionTime = backgroundExecutionTime
            )

            val profile = BehaviorProfile(
                appPackage = appPackage,
                launchCount = launchCount,
                networkRequests = networkRequests,
                permissionAccessCount = permissionAccessCount,
                backgroundExecutionTime = backgroundExecutionTime,
                riskScore = riskScore
            )

            behaviorProfiles[appPackage] = profile

            NetworkResult.Success(profile)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Behavior analysis failed"
            )
        }
    }

    /**
     * Registers a behavior profile.
     */
    fun registerProfile(
        profile: BehaviorProfile
    ) {
        behaviorProfiles[profile.appPackage] = profile
    }

    /**
     * Retrieves a behavior profile.
     */
    fun getProfile(
        appPackage: String
    ): BehaviorProfile? {
        return behaviorProfiles[appPackage]
    }

    /**
     * Returns all behavior profiles.
     */
    fun getProfiles(): List<BehaviorProfile> {
        return behaviorProfiles.values.toList()
    }

    /**
     * Calculates application risk score.
     */
    fun calculateRiskScore(
        launchCount: Int,
        networkRequests: Int,
        permissionAccessCount: Int,
        backgroundExecutionTime: Long
    ): Int {

        var score = 0

        score += (launchCount / 10)
        score += (networkRequests / 5)
        score += (permissionAccessCount * 2)
        score += (backgroundExecutionTime / 60000L).toInt()

        return score.coerceIn(0, 100)
    }

    /**
     * Calculates average risk score.
     */
    fun calculateAverageRiskScore(): Int {

        if (behaviorProfiles.isEmpty()) {
            return 0
        }

        return behaviorProfiles.values
            .map { it.riskScore }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Detects suspicious behavior.
     */
    fun isSuspiciousBehavior(
        riskScore: Int,
        threshold: Int = 70
    ): Boolean {
        return riskScore >= threshold
    }

    /**
     * Returns risk level.
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
     * Generates behavior-based recommendations.
     */
    fun generateRecommendations(
        riskScore: Int
    ): List<String> {

        return when {
            riskScore >= 90 -> listOf(
                "Immediately investigate application activity.",
                "Restrict network access.",
                "Consider quarantining the application."
            )

            riskScore >= 75 -> listOf(
                "Review application permissions.",
                "Monitor network communication.",
                "Perform a security assessment."
            )

            riskScore >= 50 -> listOf(
                "Track application behavior closely.",
                "Review background activity."
            )

            riskScore >= 25 -> listOf(
                "Continue monitoring application usage."
            )

            else -> listOf(
                "Application behavior appears normal."
            )
        }
    }

    /**
     * Removes a profile.
     */
    fun removeProfile(
        appPackage: String
    ) {
        behaviorProfiles.remove(appPackage)
    }

    /**
     * Clears all profiles.
     */
    fun clearProfiles() {
        behaviorProfiles.clear()
    }

    /**
     * Returns total profile count.
     */
    fun getProfileCount(): Int {
        return behaviorProfiles.size
    }

    /**
     * Returns high-risk applications.
     */
    fun getHighRiskApplications(
        minimumRiskScore: Int = 75
    ): List<BehaviorProfile> {
        return behaviorProfiles.values.filter {
            it.riskScore >= minimumRiskScore
        }
    }
}
