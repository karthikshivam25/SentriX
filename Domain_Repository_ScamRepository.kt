package com.sentrix.domain.repositories

import com.sentrix.domain.models.ScamAnalysis
import com.sentrix.domain.models.ScamCategory
import com.sentrix.domain.models.ScamRiskLevel

/**
 * ScamRepository
 *
 * Repository responsible for
 * managing scam detection and
 * scam intelligence within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - ScamDetectionEngine
 * - FraudProtectionService
 * - URLAnalysisEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Store scam reports
 * - Retrieve scam records
 * - Analyze scam patterns
 * - Detect fraud attempts
 * - Support threat intelligence
 */
interface ScamRepository {

    /**
     * Retrieves all scams.
     *
     * @return Scam list.
     */
    suspend fun getScams():
        List<ScamAnalysis>

    /**
     * Retrieves scam
     * by identifier.
     *
     * @param scamId Scam ID.
     *
     * @return Scam analysis.
     */
    suspend fun getScamById(
        scamId: String
    ): ScamAnalysis?

    /**
     * Saves scam analysis.
     *
     * @param scam Scam analysis.
     */
    suspend fun saveScam(
        scam: ScamAnalysis
    )

    /**
     * Updates scam analysis.
     *
     * @param scam Scam analysis.
     */
    suspend fun updateScam(
        scam: ScamAnalysis
    )

    /**
     * Deletes scam record.
     *
     * @param scamId Scam ID.
     */
    suspend fun deleteScam(
        scamId: String
    )

    /**
     * Retrieves detected scams.
     *
     * @return Scam list.
     */
    suspend fun getDetectedScams():
        List<ScamAnalysis>

    /**
     * Retrieves scams
     * by category.
     *
     * @param category Scam category.
     *
     * @return Scam list.
     */
    suspend fun getScamsByCategory(
        category: ScamCategory
    ): List<ScamAnalysis>

    /**
     * Retrieves scams
     * by risk level.
     *
     * @param riskLevel Risk level.
     *
     * @return Scam list.
     */
    suspend fun getScamsByRisk(
        riskLevel: ScamRiskLevel
    ): List<ScamAnalysis>

    /**
     * Retrieves total
     * scam count.
     *
     * @return Scam count.
     */
    suspend fun getScamCount():
        Int
}

/**
 * ScamAnalysis
 *
 * Represents scam
 * detection analysis.
 */
data class ScamAnalysis(

    /**
     * Scam identifier.
     */
    val scamId: String,

    /**
     * Scam title.
     */
    val title: String,

    /**
     * Scam description.
     */
    val description: String,

    /**
     * Scam category.
     */
    val category:
        ScamCategory,

    /**
     * Scam risk level.
     */
    val riskLevel:
        ScamRiskLevel,

    /**
     * Scam source.
     */
    val source: String,

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Indicates whether
     * scam is confirmed.
     */
    val isConfirmed: Boolean
)

/**
 * Scam categories.
 */
enum class ScamCategory {

    /**
     * Phishing scam.
     */
    PHISHING,

    /**
     * Banking fraud.
     */
    BANKING_FRAUD,

    /**
     * Investment scam.
     */
    INVESTMENT,

    /**
     * Lottery scam.
     */
    LOTTERY,

    /**
     * Tech support scam.
     */
    TECH_SUPPORT,

    /**
     * E-commerce fraud.
     */
    ECOMMERCE,

    /**
     * Identity theft.
     */
    IDENTITY_THEFT,

    /**
     * Social engineering.
     */
    SOCIAL_ENGINEERING
}

/**
 * Scam risk levels.
 */
enum class ScamRiskLevel {

    /**
     * Low risk scam.
     */
    LOW,

    /**
     * Medium risk scam.
     */
    MEDIUM,

    /**
     * High risk scam.
     */
    HIGH,

    /**
     * Critical risk scam.
     */
    CRITICAL
}
