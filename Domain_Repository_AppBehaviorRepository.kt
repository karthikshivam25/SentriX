package com.sentrix.domain.repositories

import com.sentrix.domain.models.AppBehavior
import com.sentrix.domain.models.BehaviorCategory
import com.sentrix.domain.models.BehaviorRiskLevel

/**
 * AppBehaviorRepository
 *
 * Repository responsible for
 * managing application behavior
 * monitoring within the SentriX
 * cybersecurity platform.
 *
 * Used by:
 * - AppBehaviorAnalyzer
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - MalwareDetectionEngine
 *
 * Responsibilities:
 * - Monitor app behavior
 * - Store behavior records
 * - Detect suspicious activities
 * - Analyze behavior patterns
 * - Support threat detection
 */
interface AppBehaviorRepository {

    /**
     * Retrieves all
     * application behaviors.
     *
     * @return Behavior list.
     */
    suspend fun getBehaviors():
        List<AppBehavior>

    /**
     * Retrieves behavior
     * by identifier.
     *
     * @param behaviorId Behavior ID.
     *
     * @return App behavior.
     */
    suspend fun getBehaviorById(
        behaviorId: String
    ): AppBehavior?

    /**
     * Saves behavior record.
     *
     * @param behavior App behavior.
     */
    suspend fun saveBehavior(
        behavior: AppBehavior
    )

    /**
     * Updates behavior record.
     *
     * @param behavior App behavior.
     */
    suspend fun updateBehavior(
        behavior: AppBehavior
    )

    /**
     * Deletes behavior record.
     *
     * @param behaviorId Behavior ID.
     */
    suspend fun deleteBehavior(
        behaviorId: String
    )

    /**
     * Retrieves suspicious
     * behaviors.
     *
     * @return Suspicious behavior list.
     */
    suspend fun getSuspiciousBehaviors():
        List<AppBehavior>

    /**
     * Retrieves behaviors
     * by risk level.
     *
     * @param riskLevel Risk level.
     *
     * @return Behavior list.
     */
    suspend fun getBehaviorsByRisk(
        riskLevel: BehaviorRiskLevel
    ): List<AppBehavior>

    /**
     * Retrieves behaviors
     * by category.
     *
     * @param category Behavior category.
     *
     * @return Behavior list.
     */
    suspend fun getBehaviorsByCategory(
        category: BehaviorCategory
    ): List<AppBehavior>

    /**
     * Retrieves total
     * behavior count.
     *
     * @return Behavior count.
     */
    suspend fun getBehaviorCount():
        Int
}

/**
 * AppBehavior
 *
 * Represents application
 * behavior monitoring data.
 */
data class AppBehavior(

    /**
     * Behavior identifier.
     */
    val behaviorId: String,

    /**
     * Application identifier.
     */
    val appId: String,

    /**
     * Application name.
     */
    val appName: String,

    /**
     * Behavior category.
     */
    val category:
        BehaviorCategory,

    /**
     * Behavior description.
     */
    val description: String,

    /**
     * Risk level.
     */
    val riskLevel:
        BehaviorRiskLevel,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Indicates whether
     * behavior is suspicious.
     */
    val isSuspicious: Boolean
)

/**
 * Behavior categories.
 */
enum class BehaviorCategory {

    /**
     * Network activity.
     */
    NETWORK,

    /**
     * File system activity.
     */
    FILE_SYSTEM,

    /**
     * Permission usage.
     */
    PERMISSION_USAGE,

    /**
     * Background execution.
     */
    BACKGROUND_ACTIVITY,

    /**
     * Data access activity.
     */
    DATA_ACCESS,

    /**
     * System modification.
     */
    SYSTEM_MODIFICATION,

    /**
     * Communication activity.
     */
    COMMUNICATION,

    /**
     * Process execution.
     */
    PROCESS_EXECUTION
}

/**
 * Behavior risk levels.
 */
enum class BehaviorRiskLevel {

    /**
     * Low risk behavior.
     */
    LOW,

    /**
     * Medium risk behavior.
     */
    MEDIUM,

    /**
     * High risk behavior.
     */
    HIGH,

    /**
     * Critical risk behavior.
     */
    CRITICAL
}
