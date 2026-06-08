package com.sentrix.domain.repositories

import com.sentrix.domain.models.CyberDefenseAssessment
import com.sentrix.domain.models.CyberDefenseLevel
import com.sentrix.domain.models.DefenseComponent

/**
 * CyberDefenseRepository
 *
 * Repository responsible for
 * managing cyber defense
 * information within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - EvaluateCyberDefenseUseCase
 * - CyberDefenseManager
 * - SecurityDashboard
 * - ThreatAnalysisEngine
 * - SecurityAnalyticsEngine
 *
 * Responsibilities:
 * - Store defense assessments
 * - Retrieve defense status
 * - Track defense components
 * - Measure protection posture
 * - Support defense analytics
 */
interface CyberDefenseRepository {

    /**
     * Retrieves current
     * cyber defense assessment.
     *
     * @return Defense assessment.
     */
    suspend fun getDefenseAssessment():
        CyberDefenseAssessment?

    /**
     * Saves defense assessment.
     *
     * @param assessment Defense assessment.
     */
    suspend fun saveDefenseAssessment(
        assessment: CyberDefenseAssessment
    )

    /**
     * Updates defense assessment.
     *
     * @param assessment Defense assessment.
     */
    suspend fun updateDefenseAssessment(
        assessment: CyberDefenseAssessment
    )

    /**
     * Retrieves defense level.
     *
     * @return Defense level.
     */
    suspend fun getDefenseLevel():
        CyberDefenseLevel

    /**
     * Retrieves defense components.
     *
     * @return Component list.
     */
    suspend fun getDefenseComponents():
        List<DefenseComponent>

    /**
     * Retrieves active
     * defense components.
     *
     * @return Active components.
     */
    suspend fun getActiveComponents():
        List<DefenseComponent>

    /**
     * Calculates current
     * defense score.
     *
     * @return Defense score.
     */
    suspend fun getDefenseScore():
        Int

    /**
     * Retrieves defense history.
     *
     * @return Assessment history.
     */
    suspend fun getDefenseHistory():
        List<CyberDefenseAssessment>

    /**
     * Retrieves total
     * assessment count.
     *
     * @return Assessment count.
     */
    suspend fun getAssessmentCount():
        Int
}

/**
 * CyberDefenseAssessment
 *
 * Represents an overall
 * cyber defense assessment.
 */
data class CyberDefenseAssessment(

    /**
     * Assessment identifier.
     */
    val assessmentId: String,

    /**
     * Defense score.
     */
    val defenseScore: Int,

    /**
     * Defense level.
     */
    val defenseLevel:
        CyberDefenseLevel,

    /**
     * Assessment summary.
     */
    val summary: String,

    /**
     * Defense components.
     */
    val components:
        List<DefenseComponent>,

    /**
     * Assessment timestamp.
     */
    val assessedAt: Long
)

/**
 * DefenseComponent
 *
 * Represents a security
 * protection component.
 */
data class DefenseComponent(

    /**
     * Component identifier.
     */
    val componentId: String,

    /**
     * Component name.
     */
    val componentName: String,

    /**
     * Component status.
     */
    val isEnabled: Boolean,

    /**
     * Protection score.
     */
    val protectionScore: Int
)

/**
 * Cyber defense levels.
 */
enum class CyberDefenseLevel {

    /**
     * Excellent protection.
     */
    EXCELLENT,

    /**
     * Strong protection.
     */
    STRONG,

    /**
     * Moderate protection.
     */
    MODERATE,

    /**
     * Weak protection.
     */
    WEAK,

    /**
     * Critical condition.
     */
    CRITICAL
}
