package com.sentrix.domain.repositories

import com.sentrix.domain.models.Recommendation
import com.sentrix.domain.models.RecommendationCategory
import com.sentrix.domain.models.RecommendationPriority

/**
 * RecommendationRepository
 *
 * Repository responsible for
 * managing security recommendations
 * within the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - GenerateRecommendationsUseCase
 * - SecurityDashboard
 * - CyberDefenseManager
 * - AIRecommendationEngine
 * - SecurityAdvisor
 *
 * Responsibilities:
 * - Store recommendations
 * - Retrieve recommendations
 * - Update recommendation status
 * - Track recommendation history
 * - Support security guidance
 */
interface RecommendationRepository {

    /**
     * Retrieves all
     * recommendations.
     *
     * @return Recommendation list.
     */
    suspend fun getRecommendations():
        List<Recommendation>

    /**
     * Retrieves recommendation
     * by identifier.
     *
     * @param recommendationId Recommendation ID.
     *
     * @return Recommendation.
     */
    suspend fun getRecommendationById(
        recommendationId: String
    ): Recommendation?

    /**
     * Saves recommendation.
     *
     * @param recommendation Recommendation.
     */
    suspend fun saveRecommendation(
        recommendation: Recommendation
    )

    /**
     * Updates recommendation.
     *
     * @param recommendation Recommendation.
     */
    suspend fun updateRecommendation(
        recommendation: Recommendation
    )

    /**
     * Deletes recommendation.
     *
     * @param recommendationId Recommendation ID.
     */
    suspend fun deleteRecommendation(
        recommendationId: String
    )

    /**
     * Retrieves recommendations
     * by priority.
     *
     * @param priority Priority level.
     *
     * @return Recommendation list.
     */
    suspend fun getRecommendationsByPriority(
        priority: RecommendationPriority
    ): List<Recommendation>

    /**
     * Retrieves recommendations
     * by category.
     *
     * @param category Recommendation category.
     *
     * @return Recommendation list.
     */
    suspend fun getRecommendationsByCategory(
        category: RecommendationCategory
    ): List<Recommendation>

    /**
     * Retrieves active
     * recommendations.
     *
     * @return Active recommendations.
     */
    suspend fun getActiveRecommendations():
        List<Recommendation>

    /**
     * Retrieves total
     * recommendation count.
     *
     * @return Recommendation count.
     */
    suspend fun getRecommendationCount():
        Int
}

/**
 * Recommendation
 *
 * Represents a security
 * recommendation generated
 * by the SentriX platform.
 */
data class Recommendation(

    /**
     * Recommendation identifier.
     */
    val recommendationId: String,

    /**
     * Recommendation title.
     */
    val title: String,

    /**
     * Recommendation details.
     */
    val description: String,

    /**
     * Recommendation category.
     */
    val category:
        RecommendationCategory,

    /**
     * Recommendation priority.
     */
    val priority:
        RecommendationPriority,

    /**
     * Creation timestamp.
     */
    val createdAt: Long,

    /**
     * Indicates whether
     * recommendation has
     * been completed.
     */
    val isCompleted: Boolean
)

/**
 * Recommendation categories.
 */
enum class RecommendationCategory {

    /**
     * Malware protection.
     */
    MALWARE,

    /**
     * Network security.
     */
    NETWORK_SECURITY,

    /**
     * Device security.
     */
    DEVICE_SECURITY,

    /**
     * Permission management.
     */
    PERMISSIONS,

    /**
     * Firewall protection.
     */
    FIREWALL,

    /**
     * VPN protection.
     */
    VPN,

    /**
     * Privacy protection.
     */
    PRIVACY,

    /**
     * General security.
     */
    GENERAL_SECURITY
}

/**
 * Recommendation priorities.
 */
enum class RecommendationPriority {

    /**
     * Low priority.
     */
    LOW,

    /**
     * Medium priority.
     */
    MEDIUM,

    /**
     * High priority.
     */
    HIGH,

    /**
     * Critical priority.
     */
    CRITICAL
}
