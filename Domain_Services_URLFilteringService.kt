package com.sentrix.domain.services

import com.sentrix.domain.models.URLAnalysis
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for URL filtering and web threat analysis.
 *
 * This service evaluates URLs,
 * detects malicious or suspicious websites,
 * and generates URL-related threat indicators.
 */
class URLFilteringService {

    /**
     * Analyzes URLs and generates threat indicators.
     *
     * Rules:
     * - Malicious URL -> CRITICAL threat.
     * - Phishing URL -> HIGH threat.
     * - Suspicious URL -> MEDIUM threat.
     * - Untrusted URL -> LOW threat.
     */
    suspend fun analyzeURLs(
        urlAnalyses: List<URLAnalysis>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        urlAnalyses.mapNotNull { url ->

            when {

                // Known malicious website
                url.isMalicious -> {
                    ThreatIndicator(
                        id = url.urlId,
                        threatName = "Malicious Website",
                        severity = "CRITICAL",
                        description = "Known malicious website detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Phishing website detected
                url.isPhishing -> {
                    ThreatIndicator(
                        id = url.urlId,
                        threatName = "Phishing Website",
                        severity = "HIGH",
                        description = "Potential credential theft website detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Suspicious website behavior
                url.isSuspicious -> {
                    ThreatIndicator(
                        id = url.urlId,
                        threatName = "Suspicious URL",
                        severity = "MEDIUM",
                        description = "URL exhibits suspicious characteristics",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Website reputation is unknown
                !url.isTrusted -> {
                    ThreatIndicator(
                        id = url.urlId,
                        threatName = "Untrusted Website",
                        severity = "LOW",
                        description = "Website trust level could not be verified",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns malicious URLs.
     */
    suspend fun getMaliciousURLs(
        urlAnalyses: List<URLAnalysis>
    ): List<URLAnalysis> = withContext(Dispatchers.Default) {

        urlAnalyses.filter {
            it.isMalicious
        }
    }

    /**
     * Returns phishing URLs.
     */
    suspend fun getPhishingURLs(
        urlAnalyses: List<URLAnalysis>
    ): List<URLAnalysis> = withContext(Dispatchers.Default) {

        urlAnalyses.filter {
            it.isPhishing
        }
    }

    /**
     * Returns suspicious URLs.
     */
    suspend fun getSuspiciousURLs(
        urlAnalyses: List<URLAnalysis>
    ): List<URLAnalysis> = withContext(Dispatchers.Default) {

        urlAnalyses.filter {
            it.isSuspicious
        }
    }

    /**
     * Returns untrusted URLs.
     */
    suspend fun getUntrustedURLs(
        urlAnalyses: List<URLAnalysis>
    ): List<URLAnalysis> = withContext(Dispatchers.Default) {

        urlAnalyses.filter {
            !it.isTrusted
        }
    }

    /**
     * Calculates URL security risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateURLRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Determines whether URL-related threats exist.
     */
    suspend fun hasURLThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns critical URL threats.
     */
    suspend fun getCriticalURLThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority URL threats.
     */
    suspend fun getHighPriorityURLThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Generates URL filtering summary.
     */
    suspend fun generateURLSummary(
        urlAnalyses: List<URLAnalysis>
    ): String = withContext(Dispatchers.Default) {

        val totalUrls = urlAnalyses.size

        val maliciousUrls = urlAnalyses.count {
            it.isMalicious
        }

        val phishingUrls = urlAnalyses.count {
            it.isPhishing
        }

        val suspiciousUrls = urlAnalyses.count {
            it.isSuspicious
        }

        buildString {
            appendLine("URL Security Summary")
            appendLine("--------------------")
            appendLine("Total URLs Analyzed: $totalUrls")
            appendLine("Malicious URLs: $maliciousUrls")
            appendLine("Phishing URLs: $phishingUrls")
            appendLine("Suspicious URLs: $suspiciousUrls")
            appendLine(
                if (maliciousUrls > 0 || phishingUrls > 0)
                    "Status: Dangerous URLs Detected"
                else
                    "Status: URLs Appear Safe"
            )
        }
    }

    /**
     * Checks whether all analyzed URLs are safe.
     */
    suspend fun areURLsSafe(
        urlAnalyses: List<URLAnalysis>
    ): Boolean = withContext(Dispatchers.Default) {

        urlAnalyses.none {
            it.isMalicious ||
            it.isPhishing ||
            it.isSuspicious
        }
    }
}
