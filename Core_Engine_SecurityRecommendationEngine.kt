package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Security Recommendation Engine
 *
 * Responsible for:
 * - Generating security recommendations
 * - Security posture evaluation
 * - Personalized security guidance
 * - Risk mitigation suggestions
 * - Remediation planning
 */
class SecurityRecommendationEngine {

    private val recommendations =
        ConcurrentHashMap<String, Recommendation>()

    data class Recommendation(
        val recommendationId: String,
        val title: String,
        val description: String,
        val priority: Priority,
        val category: Category,
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class Priority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum class Category {
        DEVICE_SECURITY,
        NETWORK_SECURITY,
        MALWARE_PROTECTION,
        PRIVACY,
        PERMISSIONS,
        ACCOUNT_SECURITY,
        APPLICATION_SECURITY,
        SYSTEM_INTEGRITY
    }

    /**
     * Generates recommendations from a risk score.
     */
    suspend fun generateRecommendations(
        profileId: String,
        riskScore: Int
    ): NetworkResult<List<Recommendation>> = withContext(Dispatchers.Default) {

        try {

            val generatedRecommendations =
                buildRecommendations(riskScore)

            generatedRecommendations.forEach {
                recommendations[it.recommendationId] = it
            }

            NetworkResult.Success(generatedRecommendations)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Failed to generate recommendations"
            )
        }
    }

    /**
     * Registers a recommendation.
     */
    fun registerRecommendation(
        recommendation: Recommendation
    ) {
        recommendations[recommendation.recommendationId] =
            recommendation
    }

    /**
     * Retrieves a recommendation.
     */
    fun getRecommendation(
        recommendationId: String
    ): Recommendation? {
        return recommendations[recommendationId]
    }

    /**
     * Returns all recommendations.
     */
    fun getRecommendations(): List<Recommendation> {
        return recommendations.values.toList()
    }

    /**
     * Returns recommendations by priority.
     */
    fun getRecommendationsByPriority(
        priority: Priority
    ): List<Recommendation> {
        return recommendations.values.filter {
            it.priority == priority
        }
    }

    /**
     * Returns recommendations by category.
     */
    fun getRecommendationsByCategory(
        category: Category
    ): List<Recommendation> {
        return recommendations.values.filter {
            it.category == category
        }
    }

    /**
     * Determines overall security posture.
     */
    fun getSecurityPosture(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 90 -> "CRITICAL"
            riskScore >= 75 -> "HIGH_RISK"
            riskScore >= 50 -> "MODERATE_RISK"
            riskScore >= 25 -> "LOW_RISK"
            else -> "SECURE"
        }
    }

    /**
     * Generates remediation summary.
     */
    fun generateRemediationSummary(
        riskScore: Int
    ): String {

        return when {
            riskScore >= 90 ->
                "Immediate security remediation is required."

            riskScore >= 75 ->
                "Address high-priority security issues."

            riskScore >= 50 ->
                "Review and improve security controls."

            riskScore >= 25 ->
                "Perform routine security maintenance."

            else ->
                "Current security posture is healthy."
        }
    }

    /**
     * Removes a recommendation.
     */
    fun removeRecommendation(
        recommendationId: String
    ) {
        recommendations.remove(recommendationId)
    }

    /**
     * Clears all recommendations.
     */
    fun clearRecommendations() {
        recommendations.clear()
    }

    /**
     * Returns recommendation count.
     */
    fun getRecommendationCount(): Int {
        return recommendations.size
    }

    /**
     * Returns critical recommendations only.
     */
    fun getCriticalRecommendations(): List<Recommendation> {
        return recommendations.values.filter {
            it.priority == Priority.CRITICAL
        }
    }

    /**
     * Builds recommendations based on risk score.
     */
    private fun buildRecommendations(
        riskScore: Int
    ): List<Recommendation> {

        return when {

            riskScore >= 90 -> listOf(
                Recommendation(
                    recommendationId = "REC_CRITICAL_001",
                    title = "Run Full Security Scan",
                    description = "Perform a complete device and application security scan immediately.",
                    priority = Priority.CRITICAL,
                    category = Category.SYSTEM_INTEGRITY
                ),
                Recommendation(
                    recommendationId = "REC_CRITICAL_002",
                    title = "Restrict Network Access",
                    description = "Block suspicious connections until investigation is complete.",
                    priority = Priority.CRITICAL,
                    category = Category.NETWORK_SECURITY
                )
            )

            riskScore >= 75 -> listOf(
                Recommendation(
                    recommendationId = "REC_HIGH_001",
                    title = "Review Application Permissions",
                    description = "Audit sensitive permissions and remove unnecessary access.",
                    priority = Priority.HIGH,
                    category = Category.PERMISSIONS
                ),
                Recommendation(
                    recommendationId = "REC_HIGH_002",
                    title = "Enable Advanced Protection",
                    description = "Activate enhanced threat detection and monitoring.",
                    priority = Priority.HIGH,
                    category = Category.MALWARE_PROTECTION
                )
            )

            riskScore >= 50 -> listOf(
                Recommendation(
                    recommendationId = "REC_MEDIUM_001",
                    title = "Perform Security Audit",
                    description = "Review current security settings and device posture.",
                    priority = Priority.MEDIUM,
                    category = Category.DEVICE_SECURITY
                )
            )

            riskScore >= 25 -> listOf(
                Recommendation(
                    recommendationId = "REC_LOW_001",
                    title = "Monitor Security Status",
                    description = "Continue monitoring security events and system health.",
                    priority = Priority.LOW,
                    category = Category.APPLICATION_SECURITY
                )
            )

            else -> listOf(
                Recommendation(
                    recommendationId = "REC_SAFE_001",
                    title = "Maintain Current Security Configuration",
                    description = "No immediate action required. Continue routine monitoring.",
                    priority = Priority.LOW,
                    category = Category.DEVICE_SECURITY
                )
            )
        }
    }
}
