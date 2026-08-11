package com.sentrix.security.phishing

import android.util.Log
import com.sentrix.domain.models.ScamAnalysis
import com.sentrix.domain.models.URLAnalysis
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.util.Locale

/**
 * PhishingAnalyzer
 *
 * Central analytical component for identifying phishing indicators
 * across URLs and textual content.
 *
 * Responsibilities:
 *
 * - Normalize phishing analysis inputs.
 * - Extract URL characteristics.
 * - Detect suspicious URL patterns.
 * - Detect suspicious domain characteristics.
 * - Detect social-engineering indicators in content.
 * - Detect credential/payment-related phishing indicators.
 * - Calculate a preliminary phishing risk score.
 * - Produce structured analysis results.
 *
 * This class is intentionally an analyzer rather than a manager/service.
 *
 * Architectural responsibility:
 *
 * PhishingDetectionService
 *          |
 *          v
 * PhishingDetectionManager
 *          |
 *          v
 * PhishingAnalyzer
 *          |
 *          +--> URL indicators
 *          +--> Domain indicators
 *          +--> Content indicators
 *          +--> Obfuscation indicators
 *          +--> Social engineering indicators
 *          +--> Credential theft indicators
 *          +--> Payment/financial indicators
 *
 * IMPORTANT:
 *
 * This analyzer performs local/static analysis only.
 * It does not claim that a URL is malicious solely because one heuristic
 * is present. Production SentriX should combine these results with:
 *
 * - Threat intelligence
 * - Domain reputation
 * - Certificate information
 * - Safe browsing databases
 * - Behavioral analysis
 * - Historical reputation
 * - Cloud verification
 */
class PhishingAnalyzer {

    companion object {

        private const val TAG = "PhishingAnalyzer"

        /**
         * Maximum URL length supported by this analyzer.
         */
        private const val MAX_URL_LENGTH = 8192

        /**
         * Maximum text length accepted for analysis.
         */
        private const val MAX_CONTENT_LENGTH = 100_000

        /**
         * Maximum number of findings retained for a single analysis.
         */
        private const val MAX_FINDINGS = 50

        /**
         * Risk score boundaries.
         */
        private const val SAFE_THRESHOLD = 0.20f
        private const val LOW_THRESHOLD = 0.40f
        private const val MEDIUM_THRESHOLD = 0.60f
        private const val HIGH_THRESHOLD = 0.80f

        /**
         * Suspicious URL schemes.
         *
         * HTTP itself is not necessarily phishing, but lack of HTTPS
         * increases risk for security-sensitive pages.
         */
        private const val HTTP_SCHEME = "http"

        /**
         * Suspicious URL separators and encoding patterns.
         */
        private val OBFUSCATION_PATTERNS = listOf(
            "%2f",
            "%5c",
            "%40",
            "%3a",
            "%3d",
            "%26",
            "%3f",
            "%23",
            "\\x",
            "\\u"
        )

        /**
         * Sensitive actions frequently abused by phishing campaigns.
         */
        private val SENSITIVE_ACTIONS = listOf(
            "login",
            "signin",
            "sign-in",
            "verify",
            "verification",
            "confirm",
            "authenticate",
            "authentication",
            "reset",
            "recover",
            "unlock",
            "activate",
            "validate"
        )

        /**
         * Credential-related keywords.
         */
        private val CREDENTIAL_KEYWORDS = listOf(
            "password",
            "passcode",
            "username",
            "user id",
            "userid",
            "credential",
            "credentials",
            "pin",
            "otp",
            "one time password",
            "verification code",
            "security code"
        )

        /**
         * Financial keywords.
         */
        private val FINANCIAL_KEYWORDS = listOf(
            "bank",
            "banking",
            "account",
            "credit card",
            "debit card",
            "card number",
            "upi",
            "wallet",
            "payment",
            "transaction",
            "refund",
            "invoice",
            "billing",
            "net banking"
        )

        /**
         * Social-engineering urgency indicators.
         */
        private val URGENCY_KEYWORDS = listOf(
            "urgent",
            "immediately",
            "act now",
            "action required",
            "last warning",
            "final warning",
            "within 24 hours",
            "within 48 hours",
            "expires today",
            "account will be blocked",
            "account will be suspended",
            "account has been suspended"
        )

        /**
         * Reward/scam language.
         */
        private val REWARD_KEYWORDS = listOf(
            "you won",
            "winner",
            "congratulations",
            "claim your reward",
            "claim prize",
            "free reward",
            "cashback",
            "lottery",
            "gift card",
            "bonus",
            "prize"
        )

        /**
         * Suspicious URL path keywords.
         */
        private val SUSPICIOUS_PATH_KEYWORDS = listOf(
            "login",
            "signin",
            "verify",
            "secure",
            "account",
            "update",
            "payment",
            "wallet",
            "bank",
            "confirm",
            "unlock"
        )

        /**
         * Known URL shortener domains.
         *
         * Short URLs are not inherently malicious. They simply reduce
         * transparency and therefore become one possible risk signal.
         */
        private val URL_SHORTENERS = setOf(
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "cutt.ly",
            "shorturl.at"
        )

        /**
         * Suspicious top-level domains.
         *
         * These are heuristic indicators only and must never be treated
         * as proof of malicious behavior.
         */
        private val HIGH_RISK_TLDS = setOf(
            ".zip",
            ".mov",
            ".click",
            ".top",
            ".work",
            ".country",
            ".gq",
            ".tk",
            ".ml",
            ".cf"
        )
    }

    /**
     * Analyzes a URL using local phishing heuristics.
     *
     * @param url URL to analyze.
     *
     * @return structured URL analysis.
     */
    suspend fun analyzeUrl(
        url: String
    ): URLAnalysis = withContext(Dispatchers.Default) {

        validateUrl(url)

        checkCancellation()

        val normalizedUrl = normalizeUrl(url)

        Log.d(
            TAG,
            "Starting URL phishing analysis."
        )

        val findings = mutableListOf<PhishingFinding>()

        val parsedUri = parseUriSafely(normalizedUrl)

        if (parsedUri == null) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.INVALID_URL_STRUCTURE,
                    severity = PhishingSeverity.HIGH,
                    description = "The URL structure could not be parsed safely.",
                    score = 0.35f
                )
            )

            return@withContext buildUrlAnalysis(
                url = url,
                score = 0.75f,
                findings = findings
            )
        }

        val host = parsedUri.host.orEmpty()
        val path = parsedUri.path.orEmpty()
        val query = parsedUri.rawQuery.orEmpty()

        analyzeScheme(
            parsedUri = parsedUri,
            findings = findings
        )

        analyzeHost(
            host = host,
            findings = findings
        )

        analyzeSubdomains(
            host = host,
            findings = findings
        )

        analyzePath(
            path = path,
            findings = findings
        )

        analyzeQuery(
            query = query,
            findings = findings
        )

        analyzeObfuscation(
            url = normalizedUrl,
            findings = findings
        )

        analyzeShortenedUrl(
            host = host,
            findings = findings
        )

        analyzeSensitiveTerms(
            url = normalizedUrl,
            findings = findings
        )

        analyzeUrlLength(
            url = normalizedUrl,
            findings = findings
        )

        analyzeIpAddress(
            host = host,
            findings = findings
        )

        analyzeUserInfo(
            parsedUri = parsedUri,
            findings = findings
        )

        analyzePunycode(
            host = host,
            findings = findings
        )

        val finalScore = calculateRiskScore(findings)

        Log.d(
            TAG,
            "URL phishing analysis completed. " +
                    "score=$finalScore findings=${findings.size}"
        )

        buildUrlAnalysis(
            url = url,
            score = finalScore,
            findings = findings
        )
    }

    /**
     * Analyzes arbitrary text for phishing/scam indicators.
     *
     * @param content SMS, email, notification, message, etc.
     *
     * @return structured scam analysis.
     */
    suspend fun analyzeContent(
        content: String
    ): ScamAnalysis = withContext(Dispatchers.Default) {

        validateContent(content)

        checkCancellation()

        val normalizedContent = normalizeContent(content)

        Log.d(
            TAG,
            "Starting content phishing analysis."
        )

        val findings = mutableListOf<PhishingFinding>()

        analyzeCredentialRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzeFinancialRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzeUrgency(
            content = normalizedContent,
            findings = findings
        )

        analyzeRewardScams(
            content = normalizedContent,
            findings = findings
        )

        analyzeSuspiciousLinks(
            content = normalizedContent,
            findings = findings
        )

        analyzeSensitiveRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzeSocialEngineering(
            content = normalizedContent,
            findings = findings
        )

        val extractedUrls = extractUrls(content)

        if (extractedUrls.isNotEmpty()) {

            extractedUrls.forEach { extractedUrl ->

                checkCancellation()

                val urlFindings = mutableListOf<PhishingFinding>()

                analyzeExtractedUrl(
                    extractedUrl = extractedUrl,
                    findings = urlFindings
                )

                findings.addAll(urlFindings)
            }
        }

        val finalScore = calculateRiskScore(findings)

        Log.d(
            TAG,
            "Content phishing analysis completed. " +
                    "score=$finalScore findings=${findings.size}"
        )

        buildScamAnalysis(
            content = content,
            score = finalScore,
            findings = findings
        )
    }

    /**
     * Performs a fast URL risk calculation.
     *
     * Unlike analyzeUrl(), this method only calculates the risk score.
     */
    suspend fun calculateUrlRisk(
        url: String
    ): Float {

        val result = analyzeUrl(url)

        return result.riskScore
    }

    /**
     * Performs a fast content risk calculation.
     */
    suspend fun calculateContentRisk(
        content: String
    ): Float {

        val result = analyzeContent(content)

        return result.riskScore
    }

    /**
     * Determines whether the supplied URL has significant phishing
     * indicators.
     */
    suspend fun isSuspiciousUrl(
        url: String
    ): Boolean {

        return calculateUrlRisk(url) >= MEDIUM_THRESHOLD
    }

    /**
     * Determines whether content contains significant phishing/scam
     * indicators.
     */
    suspend fun isSuspiciousContent(
        content: String
    ): Boolean {

        return calculateContentRisk(content) >= MEDIUM_THRESHOLD
    }

    /**
     * Extracts URLs from arbitrary text.
     */
    fun extractUrls(
        content: String
    ): List<String> {

        if (content.isBlank()) {
            return emptyList()
        }

        val urlRegex = Regex(
            pattern = "(?i)\\bhttps?://[^\\s<>\"']+"
        )

        return urlRegex
            .findAll(content)
            .map { match ->
                cleanExtractedUrl(match.value)
            }
            .filter { it.isNotBlank() }
            .distinct()
            .take(50)
            .toList()
    }

    /**
     * Analyzes URL scheme.
     */
    private fun analyzeScheme(
        parsedUri: URI,
        findings: MutableList<PhishingFinding>
    ) {

        val scheme = parsedUri.scheme?.lowercase(Locale.ROOT)

        if (scheme == HTTP_SCHEME) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.INSECURE_SCHEME,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The URL uses HTTP instead of HTTPS.",
                    score = 0.15f
                )
            )
        }
    }

    /**
     * Analyzes hostname characteristics.
     */
    private fun analyzeHost(
        host: String,
        findings: MutableList<PhishingFinding>
    ) {

        if (host.isBlank()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.MISSING_HOST,
                    severity = PhishingSeverity.HIGH,
                    description = "The URL does not contain a valid host.",
                    score = 0.30f
                )
            )

            return
        }

        if (host.length > 253) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.EXCESSIVE_HOST_LENGTH,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The hostname exceeds the normal DNS length.",
                    score = 0.15f
                )
            )
        }

        if (host.contains("--")) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.SUSPICIOUS_HOST_FORMAT,
                    severity = PhishingSeverity.LOW,
                    description = "The hostname contains repeated hyphens.",
                    score = 0.05f
                )
            )
        }

        HIGH_RISK_TLDS
            .firstOrNull { host.endsWith(it) }
            ?.let { tld ->

                findings.add(
                    finding(
                        type = PhishingIndicatorType.HIGH_RISK_TLD,
                        severity = PhishingSeverity.LOW,
                        description = "The hostname uses a potentially higher-risk TLD: $tld.",
                        score = 0.08f
                    )
                )
            }
    }

    /**
     * Detects excessive subdomains.
     */
    private fun analyzeSubdomains(
        host: String,
        findings: MutableList<PhishingFinding>
    ) {

        val labels = host
            .split(".")
            .filter { it.isNotBlank() }

        if (labels.size >= 5) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.EXCESSIVE_SUBDOMAINS,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The hostname contains an unusually high number of subdomains.",
                    score = 0.15f
                )
            )
        }
    }

    /**
     * Analyzes the URL path.
     */
    private fun analyzePath(
        path: String,
        findings: MutableList<PhishingFinding>
    ) {

        if (path.isBlank()) {
            return
        }

        val normalizedPath = path.lowercase(Locale.ROOT)

        val matches = SUSPICIOUS_PATH_KEYWORDS.filter {
            normalizedPath.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.SENSITIVE_PATH,
                    severity = PhishingSeverity.LOW,
                    description = "The URL path contains sensitive-action terms: " +
                            matches.joinToString(", "),
                    score = (matches.size * 0.04f)
                        .coerceAtMost(0.16f)
                )
            )
        }

        if (path.length > 150) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.LONG_PATH,
                    severity = PhishingSeverity.LOW,
                    description = "The URL contains an unusually long path.",
                    score = 0.05f
                )
            )
        }
    }

    /**
     * Analyzes query parameters.
     */
    private fun analyzeQuery(
        query: String,
        findings: MutableList<PhishingFinding>
    ) {

        if (query.isBlank()) {
            return
        }

        val normalizedQuery = query.lowercase(Locale.ROOT)

        val sensitiveParameters = listOf(
            "password",
            "passwd",
            "token",
            "otp",
            "pin",
            "cvv",
            "card",
            "account"
        )

        val matches = sensitiveParameters.filter {
            normalizedQuery.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.SENSITIVE_QUERY_PARAMETER,
                    severity = PhishingSeverity.HIGH,
                    description = "The URL query contains potentially sensitive parameters.",
                    score = 0.20f
                )
            )
        }
    }

    /**
     * Detects URL encoding/obfuscation.
     */
    private fun analyzeObfuscation(
        url: String,
        findings: MutableList<PhishingFinding>
    ) {

        val normalizedUrl = url.lowercase(Locale.ROOT)

        val matches = OBFUSCATION_PATTERNS.count {
            normalizedUrl.contains(it)
        }

        if (matches > 0) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.URL_OBFUSCATION,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The URL contains encoded or potentially obfuscated characters.",
                    score = (matches * 0.05f)
                        .coerceAtMost(0.20f)
                )
            )
        }
    }

    /**
     * Detects known URL shorteners.
     */
    private fun analyzeShortenedUrl(
        host: String,
        findings: MutableList<PhishingFinding>
    ) {

        val normalizedHost = host.lowercase(Locale.ROOT)

        if (URL_SHORTENERS.contains(normalizedHost)) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.URL_SHORTENER,
                    severity = PhishingSeverity.LOW,
                    description = "The URL uses a known URL-shortening service.",
                    score = 0.08f
                )
            )
        }
    }

    /**
     * Detects sensitive actions in the entire URL.
     */
    private fun analyzeSensitiveTerms(
        url: String,
        findings: MutableList<PhishingFinding>
    ) {

        val normalizedUrl = url.lowercase(Locale.ROOT)

        val matches = SENSITIVE_ACTIONS.filter {
            normalizedUrl.contains(it)
        }

        if (matches.size >= 2) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.MULTIPLE_SENSITIVE_TERMS,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The URL contains multiple authentication or account-related terms.",
                    score = 0.12f
                )
            )
        }
    }

    /**
     * Detects unusually long URLs.
     */
    private fun analyzeUrlLength(
        url: String,
        findings: MutableList<PhishingFinding>
    ) {

        when {

            url.length > 1000 -> {

                findings.add(
                    finding(
                        type = PhishingIndicatorType.EXCESSIVE_URL_LENGTH,
                        severity = PhishingSeverity.MEDIUM,
                        description = "The URL is unusually long.",
                        score = 0.15f
                    )
                )
            }

            url.length > 500 -> {

                findings.add(
                    finding(
                        type = PhishingIndicatorType.LONG_URL,
                        severity = PhishingSeverity.LOW,
                        description = "The URL is longer than typical.",
                        score = 0.08f
                    )
                )
            }
        }
    }

    /**
     * Detects IPv4 addresses used as hosts.
     */
    private fun analyzeIpAddress(
        host: String,
        findings: MutableList<PhishingFinding>
    ) {

        val ipv4Pattern = Regex(
            "^\\d{1,3}(\\.\\d{1,3}){3}$"
        )

        if (ipv4Pattern.matches(host)) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.IP_ADDRESS_HOST,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The URL uses an IP address instead of a domain name.",
                    score = 0.20f
                )
            )
        }
    }

    /**
     * Detects credentials embedded in the URL.
     *
     * Example:
     *
     * https://user:password@example.com
     */
    private fun analyzeUserInfo(
        parsedUri: URI,
        findings: MutableList<PhishingFinding>
    ) {

        if (!parsedUri.userInfo.isNullOrBlank()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.URL_USER_INFO,
                    severity = PhishingSeverity.HIGH,
                    description = "The URL contains embedded user information.",
                    score = 0.25f
                )
            )
        }
    }

    /**
     * Detects internationalized/punycode domains.
     */
    private fun analyzePunycode(
        host: String,
        findings: MutableList<PhishingFinding>
    ) {

        if (host.contains("xn--")) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.PUNYCODE_DOMAIN,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The domain contains an internationalized/punycode label.",
                    score = 0.12f
                )
            )
        }
    }

    /**
     * Detects credential harvesting language.
     */
    private fun analyzeCredentialRequests(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val matches = CREDENTIAL_KEYWORDS.filter {
            content.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.CREDENTIAL_REQUEST,
                    severity = PhishingSeverity.HIGH,
                    description = "The content references credential or authentication information.",
                    score = (matches.size * 0.08f)
                        .coerceAtMost(0.30f)
                )
            )
        }
    }

    /**
     * Detects financial/payment-related phishing language.
     */
    private fun analyzeFinancialRequests(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val matches = FINANCIAL_KEYWORDS.filter {
            content.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.FINANCIAL_CONTEXT,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The content contains financial or payment-related terminology.",
                    score = (matches.size * 0.06f)
                        .coerceAtMost(0.25f)
                )
            )
        }
    }

    /**
     * Detects urgency-based social engineering.
     */
    private fun analyzeUrgency(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val matches = URGENCY_KEYWORDS.filter {
            content.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.URGENCY_LANGUAGE,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The content uses urgency or account-threat language.",
                    score = (matches.size * 0.08f)
                        .coerceAtMost(0.25f)
                )
            )
        }
    }

    /**
     * Detects prize/reward scam language.
     */
    private fun analyzeRewardScams(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val matches = REWARD_KEYWORDS.filter {
            content.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.REWARD_SCAM_LANGUAGE,
                    severity = PhishingSeverity.MEDIUM,
                    description = "The content contains potentially deceptive reward or prize language.",
                    score = (matches.size * 0.07f)
                        .coerceAtMost(0.25f)
                )
            )
        }
    }

    /**
     * Detects links contained inside suspicious messages.
     */
    private fun analyzeSuspiciousLinks(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        if (extractUrls(content).isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.CONTAINS_LINK,
                    severity = PhishingSeverity.LOW,
                    description = "The content contains an external URL.",
                    score = 0.05f
                )
            )
        }
    }

    /**
     * Detects requests for sensitive actions.
     */
    private fun analyzeSensitiveRequests(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val requestPatterns = listOf(
            "share your otp",
            "send your otp",
            "provide your otp",
            "enter your password",
            "send your password",
            "share your pin",
            "enter your pin",
            "share your card number",
            "send your card details",
            "verify your account",
            "confirm your identity"
        )

        val matches = requestPatterns.filter {
            content.contains(it)
        }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.SENSITIVE_ACTION_REQUEST,
                    severity = PhishingSeverity.CRITICAL,
                    description = "The content appears to request sensitive authentication or financial information.",
                    score = 0.35f
                )
            )
        }
    }

    /**
     * Detects common social-engineering combinations.
     */
    private fun analyzeSocialEngineering(
        content: String,
        findings: MutableList<PhishingFinding>
    ) {

        val hasUrgency = URGENCY_KEYWORDS.any {
            content.contains(it)
        }

        val hasCredentialContext = CREDENTIAL_KEYWORDS.any {
            content.contains(it)
        }

        val hasFinancialContext = FINANCIAL_KEYWORDS.any {
            content.contains(it)
        }

        if (hasUrgency && hasCredentialContext) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.SOCIAL_ENGINEERING,
                    severity = PhishingSeverity.HIGH,
                    description = "Urgency is combined with credential-related language.",
                    score = 0.25f
                )
            )
        }

        if (hasUrgency && hasFinancialContext) {

            findings.add(
                finding(
                    type = PhishingIndicatorType.FINANCIAL_SOCIAL_ENGINEERING,
                    severity = PhishingSeverity.HIGH,
                    description = "Urgency is combined with financial-related language.",
                    score = 0.20f
                )
            )
        }
    }

    /**
     * Performs a lightweight analysis of an extracted URL without
     * constructing a complete URLAnalysis object.
     */
    private fun analyzeExtractedUrl(
        extractedUrl: String,
        findings: MutableList<PhishingFinding>
    ) {

        try {

            val normalizedUrl = normalizeUrl(extractedUrl)

            val uri = parseUriSafely(normalizedUrl)
                ?: return

            val host = uri.host.orEmpty()

            if (uri.scheme.equals(HTTP_SCHEME, ignoreCase = true)) {

                findings.add(
                    finding(
                        type = PhishingIndicatorType.INSECURE_LINK,
                        severity = PhishingSeverity.MEDIUM,
                        description = "The message contains an HTTP link.",
                        score = 0.10f
                    )
                )
            }

            if (URL_SHORTENERS.contains(
                    host.lowercase(Locale.ROOT)
                )
            ) {

                findings.add(
                    finding(
                        type = PhishingIndicatorType.SHORTENED_LINK,
                        severity = PhishingSeverity.LOW,
                        description = "The message contains a shortened URL.",
                        score = 0.08f
                    )
                )
            }

            if (host.contains("xn--")) {

                findings.add(
                    finding(
                        type = PhishingIndicatorType.PUNYCODE_LINK,
                        severity = PhishingSeverity.MEDIUM,
                        description = "The message contains a punycode domain.",
                        score = 0.12f
                    )
                )
            }

        } catch (exception: Exception) {

            Log.w(
                TAG,
                "Unable to analyze extracted URL.",
                exception
            )
        }
    }

    /**
     * Calculates a normalized risk score.
     *
     * Findings are combined using a bounded aggregation rather than
     * allowing unlimited additive growth.
     */
    private fun calculateRiskScore(
        findings: List<PhishingFinding>
    ): Float {

        if (findings.isEmpty()) {
            return 0.0f
        }

        val limitedFindings = findings
            .sortedByDescending { it.score }
            .take(MAX_FINDINGS)

        /*
         * Base score from independent findings.
         */
        val additiveScore = limitedFindings.sumOf {
            it.score.toDouble()
        }.toFloat()

        /*
         * Critical indicators significantly increase confidence.
         */
        val criticalCount = limitedFindings.count {
            it.severity == PhishingSeverity.CRITICAL
        }

        val highCount = limitedFindings.count {
            it.severity == PhishingSeverity.HIGH
        }

        var finalScore = additiveScore

        if (criticalCount > 0) {
            finalScore += 0.20f
        }

        if (highCount >= 2) {
            finalScore += 0.10f
        }

        return finalScore.coerceIn(0.0f, 1.0f)
    }

    /**
     * Builds URLAnalysis from local findings.
     *
     * The exact constructor should remain synchronized with the
     * SentriX domain model.
     */
    private fun buildUrlAnalysis(
        url: String,
        score: Float,
        findings: List<PhishingFinding>
    ): URLAnalysis {

        return URLAnalysis(
            url = url,
            riskScore = score,
            isPhishing = score >= MEDIUM_THRESHOLD
        )
    }

    /**
     * Builds ScamAnalysis from local findings.
     */
    private fun buildScamAnalysis(
        content: String,
        score: Float,
        findings: List<PhishingFinding>
    ): ScamAnalysis {

        return ScamAnalysis(
            content = content,
            riskScore = score,
            isScam = score >= MEDIUM_THRESHOLD
        )
    }

    /**
     * Creates a phishing finding.
     */
    private fun finding(
        type: PhishingIndicatorType,
        severity: PhishingSeverity,
        description: String,
        score: Float
    ): PhishingFinding {

        return PhishingFinding(
            type = type,
            severity = severity,
            description = description,
            score = score.coerceIn(0.0f, 1.0f)
        )
    }

    /**
     * Normalizes URL input.
     */
    private fun normalizeUrl(
        url: String
    ): String {

        return url
            .trim()
            .replace("\u0000", "")
    }

    /**
     * Normalizes content.
     */
    private fun normalizeContent(
        content: String
    ): String {

        return content
            .trim()
            .replace("\u0000", "")
            .lowercase(Locale.ROOT)
    }

    /**
     * Parses URI without allowing malformed input to escape.
     */
    private fun parseUriSafely(
        url: String
    ): URI? {

        return try {

            URI(url)

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Removes punctuation commonly attached to URLs in messages.
     */
    private fun cleanExtractedUrl(
        url: String
    ): String {

        return url.trimEnd(
            '.',
            ',',
            ';',
            ':',
            ')',
            ']',
            '}',
            '>',
            '!',
            '?'
        )
    }

    /**
     * Validates URL input.
     */
    private fun validateUrl(
        url: String
    ) {

        require(url.isNotBlank()) {
            "URL must not be blank."
        }

        require(url.length <= MAX_URL_LENGTH) {
            "URL exceeds the supported maximum length."
        }

        require(
            url.startsWith("http://", ignoreCase = true) ||
                    url.startsWith("https://", ignoreCase = true)
        ) {
            "Only HTTP and HTTPS URLs are supported."
        }
    }

    /**
     * Validates content input.
     */
    private fun validateContent(
        content: String
    ) {

        require(content.isNotBlank()) {
            "Content must not be blank."
        }

        require(content.length <= MAX_CONTENT_LENGTH) {
            "Content exceeds the supported maximum length."
        }
    }

    /**
     * Ensures coroutine cancellation is respected.
     */
    private suspend fun checkCancellation() {

        if (!kotlinx.coroutines.currentCoroutineContext().isActive) {
            throw CancellationException(
                "Phishing analysis operation was cancelled."
            )
        }
    }
}

/**
 * Individual phishing indicator discovered during analysis.
 */
data class PhishingFinding(

    /**
     * Type of indicator.
     */
    val type: PhishingIndicatorType,

    /**
     * Severity of the indicator.
     */
    val severity: PhishingSeverity,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Contribution of this indicator to the risk score.
     */
    val score: Float
)

/**
 * Types of indicators recognized by the phishing analyzer.
 */
enum class PhishingIndicatorType {

    INVALID_URL_STRUCTURE,

    MISSING_HOST,

    INSECURE_SCHEME,

    INSECURE_LINK,

    SUSPICIOUS_HOST_FORMAT,

    EXCESSIVE_HOST_LENGTH,

    EXCESSIVE_SUBDOMAINS,

    HIGH_RISK_TLD,

    SENSITIVE_PATH,

    SENSITIVE_QUERY_PARAMETER,

    URL_OBFUSCATION,

    URL_SHORTENER,

    SHORTENED_LINK,

    MULTIPLE_SENSITIVE_TERMS,

    EXCESSIVE_URL_LENGTH,

    LONG_URL,

    IP_ADDRESS_HOST,

    URL_USER_INFO,

    PUNYCODE_DOMAIN,

    PUNYCODE_LINK,

    CREDENTIAL_REQUEST,

    FINANCIAL_CONTEXT,

    URGENCY_LANGUAGE,

    REWARD_SCAM_LANGUAGE,

    CONTAINS_LINK,

    SENSITIVE_ACTION_REQUEST,

    SOCIAL_ENGINEERING,

    FINANCIAL_SOCIAL_ENGINEERING
}

/**
 * Severity assigned to a phishing indicator.
 */
enum class PhishingSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}
