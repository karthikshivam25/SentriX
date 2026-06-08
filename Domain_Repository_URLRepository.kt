package com.sentrix.domain.repositories

import com.sentrix.domain.models.URLAnalysis
import com.sentrix.domain.models.URLCategory
import com.sentrix.domain.models.URLRiskLevel

/**
 * URLRepository
 *
 * Repository responsible for
 * managing URL analysis and
 * website security intelligence
 * within the SentriX platform.
 *
 * Used by:
 * - URLAnalysisEngine
 * - ScamDetectionEngine
 * - PhishingProtectionService
 * - SecurityDashboard
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze URLs
 * - Store URL records
 * - Detect phishing websites
 * - Identify malicious domains
 * - Provide URL intelligence
 */
interface URLRepository {

    /**
     * Retrieves all
     * analyzed URLs.
     *
     * @return URL analysis list.
     */
    suspend fun getURLs():
        List<URLAnalysis>

    /**
     * Retrieves URL analysis
     * by identifier.
     *
     * @param urlId URL ID.
     *
     * @return URL analysis.
     */
    suspend fun getURLById(
        urlId: String
    ): URLAnalysis?

    /**
     * Saves URL analysis.
     *
     * @param analysis URL analysis.
     */
    suspend fun saveURL(
        analysis: URLAnalysis
    )

    /**
     * Updates URL analysis.
     *
     * @param analysis URL analysis.
     */
    suspend fun updateURL(
        analysis: URLAnalysis
    )

    /**
     * Deletes URL record.
     *
     * @param urlId URL ID.
     */
    suspend fun deleteURL(
        urlId: String
    )

    /**
     * Retrieves malicious URLs.
     *
     * @return Malicious URL list.
     */
    suspend fun getMaliciousURLs():
        List<URLAnalysis>

    /**
     * Retrieves URLs by
     * risk level.
     *
     * @param riskLevel Risk level.
     *
     * @return URL list.
     */
    suspend fun getURLsByRisk(
        riskLevel: URLRiskLevel
    ): List<URLAnalysis>

    /**
     * Retrieves URLs by
     * category.
     *
     * @param category URL category.
     *
     * @return URL list.
     */
    suspend fun getURLsByCategory(
        category: URLCategory
    ): List<URLAnalysis>

    /**
     * Retrieves total
     * analyzed URL count.
     *
     * @return URL count.
     */
    suspend fun getURLCount():
        Int
}

/**
 * URLAnalysis
 *
 * Represents URL
 * security analysis.
 */
data class URLAnalysis(

    /**
     * URL identifier.
     */
    val urlId: String,

    /**
     * Website URL.
     */
    val url: String,

    /**
     * Domain name.
     */
    val domain: String,

    /**
     * URL category.
     */
    val category:
        URLCategory,

    /**
     * Risk level.
     */
    val riskLevel:
        URLRiskLevel,

    /**
     * Analysis summary.
     */
    val summary: String,

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Indicates whether
     * URL is safe.
     */
    val isSafe: Boolean
)

/**
 * URL categories.
 */
enum class URLCategory {

    /**
     * Safe website.
     */
    SAFE,

    /**
     * Phishing website.
     */
    PHISHING,

    /**
     * Malware website.
     */
    MALWARE,

    /**
     * Scam website.
     */
    SCAM,

    /**
     * Suspicious website.
     */
    SUSPICIOUS,

    /**
     * Spam website.
     */
    SPAM,

    /**
     * Fake website.
     */
    FAKE,

    /**
     * Unknown category.
     */
    UNKNOWN
}

/**
 * URL risk levels.
 */
enum class URLRiskLevel {

    /**
     * Low risk URL.
     */
    LOW,

    /**
     * Medium risk URL.
     */
    MEDIUM,

    /**
     * High risk URL.
     */
    HIGH,

    /**
     * Critical risk URL.
     */
    CRITICAL
}
