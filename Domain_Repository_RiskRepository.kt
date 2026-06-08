package com.sentrix.domain.repositories

import com.sentrix.domain.models.RiskAssessment
import com.sentrix.domain.models.RiskCategory
import com.sentrix.domain.models.RiskLevel

/**
 * RiskRepository
 *
 * Repository responsible for
 * managing cybersecurity risk
 * information within the
 * SentriX platform.
 *
 * Used by:
 * - RiskAssessmentEngine
 * - CyberDefenseManager
 * - SecurityDashboard
 * - ThreatAnalysisEngine
 * - ComplianceManager
 *
 * Responsibilities:
 * - Store risk assessments
 * - Retrieve risk data
 * - Update risk status
 * - Analyze security risks
 * - Support risk reporting
 */
interface RiskRepository {

    /**
     * Retrieves all risks.
     *
     * @return Risk list.
     */
    suspend fun getRisks():
        List<RiskAssessment>

    /**
     * Retrieves risk by ID.
     *
     * @param riskId Risk identifier.
     *
     * @return Risk assessment.
     */
    suspend fun getRiskById(
        riskId: String
    ): RiskAssessment?

    /**
     * Saves risk assessment.
     *
     * @param risk Risk assessment.
     */
    suspend fun saveRisk(
        risk: RiskAssessment
    )

    /**
     * Updates risk assessment.
     *
     * @param risk Risk assessment.
     */
    suspend fun updateRisk(
        risk: RiskAssessment
    )

    /**
     * Deletes risk assessment.
     *
     * @param riskId Risk identifier.
     */
    suspend fun deleteRisk(
        riskId: String
    )

    /**
     * Retrieves risks by level.
     *
     * @param riskLevel Risk level.
     *
     * @return Risk list.
     */
    suspend fun getRisksByLevel(
        riskLevel: RiskLevel
    ): List<RiskAssessment>

    /**
     * Retrieves risks by category.
     *
     * @param category Risk category.
     *
     * @return Risk list.
     */
    suspend fun getRisksByCategory(
        category: RiskCategory
    ): List<RiskAssessment>

    /**
     * Retrieves active risks.
     *
     * @return Active risk list.
     */
    suspend fun getActiveRisks():
        List<RiskAssessment>

    /**
     * Retrieves total risk count.
     *
     * @return Number of risks.
     */
    suspend fun getRiskCount():
        Int
}

/**
 * RiskAssessment
 *
 * Represents a cybersecurity
 * risk assessment record.
 */
data class RiskAssessment(

    /**
     * Risk identifier.
     */
    val riskId: String,

    /**
     * Risk title.
     */
    val riskTitle: String,

    /**
     * Risk description.
     */
    val description: String,

    /**
     * Risk category.
     */
    val category:
        RiskCategory,

    /**
     * Risk severity level.
     */
    val riskLevel:
        RiskLevel,

    /**
     * Risk score.
     */
    val riskScore: Int,

    /**
     * Assessment timestamp.
     */
    val assessedAt: Long,

    /**
     * Resolution status.
     */
    val isResolved: Boolean
)

/**
 * Risk categories.
 */
enum class RiskCategory {

    /**
     * Malware risk.
     */
    MALWARE,

    /**
     * Network risk.
     */
    NETWORK,

    /**
     * Device integrity risk.
     */
    DEVICE_SECURITY,

    /**
     * Permission risk.
     */
    PERMISSION,

    /**
     * Privacy risk.
     */
    PRIVACY,

    /**
     * Data exposure risk.
     */
    DATA_EXPOSURE,

    /**
     * Authentication risk.
     */
    AUTHENTICATION,

    /**
     * System vulnerability.
     */
    VULNERABILITY
}

/**
 * Risk levels.
 */
enum class RiskLevel {

    /**
     * Low risk.
     */
    LOW,

    /**
     * Medium risk.
     */
    MEDIUM,

    /**
     * High risk.
     */
    HIGH,

    /**
     * Critical risk.
     */
    CRITICAL
}
