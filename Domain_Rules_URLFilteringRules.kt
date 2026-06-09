package com.sentrix.domain.rules

import java.net.URI

/**
 * SentriX URL Filtering Rules
 *
 * Centralized URL reputation analysis, phishing detection,
 * malicious domain detection, and URL access decisions.
 */
object URLFilteringRules {

    enum class URLRiskLevel {
        SAFE,
        LOW_RISK,
        MEDIUM_RISK,
        HIGH_RISK,
        MALICIOUS
    }

    enum class URLDecision {
        ALLOW,
        WARN,
        BLOCK
    }

    private val SUSPICIOUS_TLDS = setOf(
        "xyz",
        "top",
        "click",
        "work",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga"
    )

    private val SHORTENER_DOMAINS = setOf(
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "t.co",
        "is.gd",
        "buff.ly"
    )

    private val PHISHING_KEYWORDS = setOf(
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "confirm",
        "banking",
        "wallet",
        "payment",
        "signin"
    )

    /**
     * Calculate URL risk score.
     */
    fun calculateRiskScore(
        url: String,
        hasValidSsl: Boolean,
        domainReputation: Int,
        isKnownMalicious: Boolean
    ): Int {

        var score = 0

        if (isKnownMalicious) score += 100

        if (!hasValidSsl) score += 20

        if (domainReputation < 50) {
            score += (50 - domainReputation)
        }

        if (containsSuspiciousKeywords(url)) {
            score += 15
        }

        if (usesSuspiciousTld(url)) {
            score += 20
        }

        if (isUrlShortener(url)) {
            score += 10
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Determine URL risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): URLRiskLevel {

        return when {
            riskScore >= 90 -> URLRiskLevel.MALICIOUS
            riskScore >= 70 -> URLRiskLevel.HIGH_RISK
            riskScore >= 40 -> URLRiskLevel.MEDIUM_RISK
            riskScore >= 15 -> URLRiskLevel.LOW_RISK
            else -> URLRiskLevel.SAFE
        }
    }

    /**
     * Determine filtering decision.
     */
    fun determineDecision(
        riskLevel: URLRiskLevel
    ): URLDecision {

        return when (riskLevel) {
            URLRiskLevel.SAFE,
            URLRiskLevel.LOW_RISK ->
                URLDecision.ALLOW

            URLRiskLevel.MEDIUM_RISK ->
                URLDecision.WARN

            URLRiskLevel.HIGH_RISK,
            URLRiskLevel.MALICIOUS ->
                URLDecision.BLOCK
        }
    }

    /**
     * Detect phishing characteristics.
     */
    fun isPotentialPhishingUrl(
        url: String
    ): Boolean {

        return containsSuspiciousKeywords(url) ||
                hasExcessiveSubdomains(url) ||
                containsEncodedCharacters(url)
    }

    /**
     * Check for suspicious keywords.
     */
    fun containsSuspiciousKeywords(
        url: String
    ): Boolean {

        val lowerUrl = url.lowercase()

        return PHISHING_KEYWORDS.any {
            lowerUrl.contains(it)
        }
    }

    /**
     * Check suspicious TLD.
     */
    fun usesSuspiciousTld(
        url: String
    ): Boolean {

        return try {
            val host = URI(url).host ?: return false
            val tld = host.substringAfterLast(".")
            SUSPICIOUS_TLDS.contains(tld.lowercase())
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check URL shortener.
     */
    fun isUrlShortener(
        url: String
    ): Boolean {

        return try {
            val host = URI(url).host ?: return false

            SHORTENER_DOMAINS.any {
                host.contains(it, ignoreCase = true)
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Detect excessive subdomains.
     */
    fun hasExcessiveSubdomains(
        url: String
    ): Boolean {

        return try {
            val host = URI(url).host ?: return false
            host.split(".").size > 4
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Detect encoded URLs often used for obfuscation.
     */
    fun containsEncodedCharacters(
        url: String
    ): Boolean {

        return url.contains("%") ||
                url.contains("@") ||
                url.contains("%2F", true) ||
                url.contains("%3A", true)
    }

    /**
     * Determine whether URL should be scanned deeply.
     */
    fun requiresDeepInspection(
        riskLevel: URLRiskLevel
    ): Boolean {

        return riskLevel == URLRiskLevel.MEDIUM_RISK ||
                riskLevel == URLRiskLevel.HIGH_RISK ||
                riskLevel == URLRiskLevel.MALICIOUS
    }

    /**
     * Determine whether user should be alerted.
     */
    fun requiresUserWarning(
        riskLevel: URLRiskLevel
    ): Boolean {

        return riskLevel == URLRiskLevel.MEDIUM_RISK ||
                riskLevel == URLRiskLevel.HIGH_RISK
    }

    /**
     * Generate URL security summary.
     */
    fun getSecuritySummary(
        riskLevel: URLRiskLevel
    ): String {

        return when (riskLevel) {

            URLRiskLevel.SAFE ->
                "URL appears safe."

            URLRiskLevel.LOW_RISK ->
                "Minor URL risk indicators detected."

            URLRiskLevel.MEDIUM_RISK ->
                "Potentially suspicious URL detected."

            URLRiskLevel.HIGH_RISK ->
                "High-risk URL detected."

            URLRiskLevel.MALICIOUS ->
                "Malicious URL detected and blocked."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        riskLevel: URLRiskLevel
    ): String {

        return when (riskLevel) {

            URLRiskLevel.SAFE ->
                "Allow access."

            URLRiskLevel.LOW_RISK ->
                "Allow and monitor."

            URLRiskLevel.MEDIUM_RISK ->
                "Warn user and perform deep inspection."

            URLRiskLevel.HIGH_RISK ->
                "Block access and log incident."

            URLRiskLevel.MALICIOUS ->
                "Block immediately and generate security alert."
        }
    }
}
