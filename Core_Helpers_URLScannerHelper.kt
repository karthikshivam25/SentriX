package com.sentrix.core.helpers

import android.util.Patterns
import com.sentrix.core.enums.SecurityStatus
import java.net.URI
import java.util.Locale

object URLScannerHelper {

    /**
     * Suspicious URL keywords
     */
    private val suspiciousKeywords = listOf(
        "login",
        "verify",
        "secure",
        "update",
        "banking",
        "wallet",
        "crypto",
        "free",
        "bonus",
        "gift",
        "prize",
        "claim",
        "hack",
        "crack"
    )

    /**
     * Suspicious domain extensions
     */
    private val suspiciousExtensions = listOf(
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    )

    /**
     * Analyze URL security
     */
    fun analyzeUrl(
        url: String
    ): URLScanResult {

        val normalizedUrl = normalizeUrl(url)

        val validUrl = isValidUrl(normalizedUrl)

        if (!validUrl) {

            return URLScanResult(
                url = url,
                normalizedUrl = normalizedUrl,
                domain = "",
                usesHttps = false,
                containsIpAddress = false,
                suspiciousKeywords = emptyList(),
                suspiciousExtension = false,
                securityStatus = SecurityStatus.CRITICAL,
                threatScore = 100,
                recommendation = "Invalid or malformed URL detected."
            )
        }

        val domain = getDomain(normalizedUrl)

        val usesHttps = normalizedUrl.startsWith(
            "https://",
            ignoreCase = true
        )

        val containsIpAddress =
            containsIPAddress(domain)

        val detectedKeywords =
            getSuspiciousKeywords(normalizedUrl)

        val suspiciousExtension =
            hasSuspiciousExtension(domain)

        val threatScore = calculateThreatScore(
            usesHttps = usesHttps,
            containsIpAddress = containsIpAddress,
            suspiciousKeywords = detectedKeywords,
            suspiciousExtension = suspiciousExtension
        )

        val securityStatus = getSecurityStatus(
            threatScore
        )

        return URLScanResult(
            url = url,
            normalizedUrl = normalizedUrl,
            domain = domain,
            usesHttps = usesHttps,
            containsIpAddress = containsIpAddress,
            suspiciousKeywords = detectedKeywords,
            suspiciousExtension = suspiciousExtension,
            securityStatus = securityStatus,
            threatScore = threatScore,
            recommendation = generateRecommendation(
                threatScore
            )
        )
    }

    /**
     * Validate URL format
     */
    fun isValidUrl(
        url: String
    ): Boolean {

        return Patterns.WEB_URL.matcher(url).matches()
    }

    /**
     * Normalize URL
     */
    fun normalizeUrl(
        url: String
    ): String {

        return if (
            url.startsWith("http://") ||
            url.startsWith("https://")
        ) {
            url.trim()
        } else {
            "https://${url.trim()}"
        }
    }

    /**
     * Extract domain
     */
    fun getDomain(
        url: String
    ): String {

        return try {

            URI(url).host ?: ""

        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Detect IP address usage
     */
    fun containsIPAddress(
        domain: String
    ): Boolean {

        val ipRegex =
            Regex(
                "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
                        "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            )

        return ipRegex.matches(domain)
    }

    /**
     * Detect suspicious keywords
     */
    fun getSuspiciousKeywords(
        url: String
    ): List<String> {

        val lowerCaseUrl =
            url.lowercase(Locale.getDefault())

        return suspiciousKeywords.filter {
            lowerCaseUrl.contains(it)
        }
    }

    /**
     * Check suspicious domain extension
     */
    fun hasSuspiciousExtension(
        domain: String
    ): Boolean {

        return suspiciousExtensions.any {
            domain.endsWith(it)
        }
    }

    /**
     * Calculate URL threat score
     */
    private fun calculateThreatScore(
        usesHttps: Boolean,
        containsIpAddress: Boolean,
        suspiciousKeywords: List<String>,
        suspiciousExtension: Boolean
    ): Int {

        var score = 0

        if (!usesHttps) {
            score += 25
        }

        if (containsIpAddress) {
            score += 30
        }

        if (suspiciousKeywords.isNotEmpty()) {
            score += suspiciousKeywords.size * 10
        }

        if (suspiciousExtension) {
            score += 20
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Convert score to security status
     */
    private fun getSecurityStatus(
        threatScore: Int
    ): SecurityStatus {

        return when {

            threatScore >= 80 -> {
                SecurityStatus.CRITICAL
            }

            threatScore >= 60 -> {
                SecurityStatus.DANGEROUS
            }

            threatScore >= 40 -> {
                SecurityStatus.WARNING
            }

            threatScore >= 20 -> {
                SecurityStatus.SAFE
            }

            else -> {
                SecurityStatus.SECURE
            }
        }
    }

    /**
     * Generate recommendation
     */
    private fun generateRecommendation(
        threatScore: Int
    ): String {

        return when {

            threatScore >= 80 -> {
                "Dangerous URL detected. Avoid visiting this website."
            }

            threatScore >= 60 -> {
                "Suspicious website detected. Proceed with extreme caution."
            }

            threatScore >= 40 -> {
                "Potentially unsafe URL identified."
            }

            threatScore >= 20 -> {
                "Minor security concerns detected."
            }

            else -> {
                "URL appears secure."
            }
        }
    }

    /**
     * URL scan result model
     */
    data class URLScanResult(
        val url: String,
        val normalizedUrl: String,
        val domain: String,
        val usesHttps: Boolean,
        val containsIpAddress: Boolean,
        val suspiciousKeywords: List<String>,
        val suspiciousExtension: Boolean,
        val securityStatus: SecurityStatus,
        val threatScore: Int,
        val recommendation: String
    )
}
