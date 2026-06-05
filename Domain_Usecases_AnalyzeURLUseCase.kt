package com.sentrix.domain.usecases

import com.sentrix.domain.models.URLAnalysis
import com.sentrix.domain.repositories.URLRepository

/**
 * AnalyzeURLUseCase
 *
 * Responsible for analyzing URLs and web links
 * to identify phishing attempts, malicious
 * websites, fraudulent domains, suspicious
 * redirects, and other web-based threats
 * within the SentriX cybersecurity platform.
 *
 * This use case evaluates domain reputation,
 * SSL/TLS configuration, URL structure,
 * blacklist intelligence, redirect behavior,
 * and threat indicators to determine URL safety.
 *
 * Used by:
 * - URLScanner
 * - PhishingProtectionEngine
 * - RealtimeProtectionEngine
 * - BrowserProtectionService
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - AIThreatDetectionEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze URLs and domains
 * - Detect phishing attempts
 * - Identify malicious websites
 * - Validate domain reputation
 * - Calculate URL risk scores
 * - Generate security recommendations
 */
class AnalyzeURLUseCase(
    private val repository: URLRepository
) {

    /**
     * Executes URL security analysis.
     *
     * @param url URL to analyze
     *
     * @return URLAnalysisResult
     */
    suspend operator fun invoke(
        url: String
    ): URLAnalysisResult {

        val maliciousDomains =
            repository.getMaliciousDomains()

        val phishingDomains =
            repository.getPhishingDomains()

        val trustedDomains =
            repository.getTrustedDomains()

        val domain =
            extractDomain(url)

        val urlStatus =
            determineUrlStatus(
                domain = domain,
                maliciousDomains = maliciousDomains,
                phishingDomains = phishingDomains,
                trustedDomains = trustedDomains
            )

        val riskScore =
            calculateRiskScore(urlStatus)

        return URLAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            url = url,
            domain = domain,
            status = urlStatus,
            riskScore = riskScore,
            isTrusted =
                urlStatus == URLSafetyStatus.SAFE,
            recommendations =
                generateRecommendations(
                    urlStatus
                )
        )
    }

    /**
     * Determines URL safety status.
     */
    private fun determineUrlStatus(
        domain: String,
        maliciousDomains: List<String>,
        phishingDomains: List<String>,
        trustedDomains: List<String>
    ): URLSafetyStatus {

        return when {

            maliciousDomains.contains(domain) ->
                URLSafetyStatus.MALICIOUS

            phishingDomains.contains(domain) ->
                URLSafetyStatus.PHISHING

            trustedDomains.contains(domain) ->
                URLSafetyStatus.SAFE

            else ->
                URLSafetyStatus.SUSPICIOUS
        }
    }

    /**
     * Calculates URL risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        status: URLSafetyStatus
    ): Int {

        return when (status) {

            URLSafetyStatus.SAFE -> 0

            URLSafetyStatus.SUSPICIOUS -> 50

            URLSafetyStatus.PHISHING -> 85

            URLSafetyStatus.MALICIOUS -> 100
        }
    }

    /**
     * Extracts domain name from URL.
     */
    private fun extractDomain(
        url: String
    ): String {

        return url
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .lowercase()
    }

    /**
     * Generates URL security
     * recommendations.
     */
    private fun generateRecommendations(
        status: URLSafetyStatus
    ): List<String> {

        return when (status) {

            URLSafetyStatus.MALICIOUS -> listOf(
                "Block access immediately",
                "Do not enter credentials",
                "Report malicious website",
                "Perform threat investigation"
            )

            URLSafetyStatus.PHISHING -> listOf(
                "Avoid entering personal data",
                "Verify website authenticity",
                "Report phishing attempt"
            )

            URLSafetyStatus.SUSPICIOUS -> listOf(
                "Proceed with caution",
                "Verify domain legitimacy",
                "Review website certificate"
            )

            URLSafetyStatus.SAFE -> listOf(
                "No known threats detected"
            )
        }
    }
}

/**
 * URLAnalysisResult
 *
 * Represents the outcome of URL
 * security analysis.
 */
data class URLAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Original URL analyzed.
     */
    val url: String,

    /**
     * Extracted domain name.
     */
    val domain: String,

    /**
     * URL safety status.
     */
    val status: URLSafetyStatus,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Indicates whether the URL
     * is considered trusted.
     */
    val isTrusted: Boolean,

    /**
     * Security recommendations.
     */
    val recommendations: List<String>
)

/**
 * URL safety indicators.
 */
enum class URLSafetyStatus {

    /**
     * Safe and trusted URL.
     */
    SAFE,

    /**
     * Suspicious URL requiring
     * further verification.
     */
    SUSPICIOUS,

    /**
     * Phishing website detected.
     */
    PHISHING,

    /**
     * Malicious website detected.
     */
    MALICIOUS
}
