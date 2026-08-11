package com.sentrix.security.phishing

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.util.Locale

/**
 * PhishingURLAnalyzer
 *
 * Specialized URL analysis engine used by the SentriX phishing
 * protection subsystem.
 *
 * Responsibilities:
 *
 * - Validate URLs.
 * - Normalize URLs.
 * - Parse URL components.
 * - Analyze protocol/scheme.
 * - Analyze hostname.
 * - Detect IP-based URLs.
 * - Detect excessive subdomains.
 * - Detect suspicious domain structures.
 * - Detect punycode/internationalized domains.
 * - Detect URL obfuscation.
 * - Detect suspicious ports.
 * - Detect suspicious paths.
 * - Detect suspicious query parameters.
 * - Detect credential information embedded in URLs.
 * - Detect URL shorteners.
 * - Detect excessive URL length.
 * - Produce structured URL indicators and a normalized risk score.
 *
 * This class does NOT:
 *
 * - Query cloud threat intelligence.
 * - Perform DNS reputation checks.
 * - Perform Safe Browsing API checks.
 * - Download remote content.
 * - Visit the URL.
 * - Execute JavaScript.
 * - Trust a URL merely because HTTPS is present.
 *
 * Those responsibilities belong to other SentriX components.
 *
 * Architecture:
 *
 * PhishingDetectionService
 *          |
 *          v
 * PhishingDetectionManager
 *          |
 *          +-----------------------+
 *          |                       |
 *          v                       v
 * PhishingAnalyzer        PhishingURLAnalyzer
 *                                  |
 *                                  +--> URL structure
 *                                  +--> Host analysis
 *                                  +--> Domain analysis
 *                                  +--> Obfuscation
 *                                  +--> Path/query analysis
 *                                  +--> Risk indicators
 */
class PhishingURLAnalyzer {

    companion object {

        private const val TAG = "PhishingURLAnalyzer"

        /**
         * Maximum URL length supported by the analyzer.
         */
        private const val MAX_URL_LENGTH = 8192

        /**
         * Maximum number of findings returned.
         */
        private const val MAX_FINDINGS = 50

        /**
         * Risk thresholds.
         */
        private const val LOW_RISK_THRESHOLD = 0.25f
        private const val MEDIUM_RISK_THRESHOLD = 0.50f
        private const val HIGH_RISK_THRESHOLD = 0.75f

        /**
         * Supported URL schemes.
         */
        private val SUPPORTED_SCHEMES = setOf(
            "http",
            "https"
        )

        /**
         * URL shortening services.
         *
         * Presence of a shortener is not malicious by itself.
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
            "shorturl.at",
            "rebrand.ly",
            "s.id",
            "rb.gy"
        )

        /**
         * Suspicious URL path keywords.
         */
        private val SUSPICIOUS_PATH_TERMS = listOf(
            "login",
            "signin",
            "sign-in",
            "verify",
            "verification",
            "authenticate",
            "authentication",
            "account",
            "password",
            "reset",
            "recover",
            "unlock",
            "activate",
            "confirm",
            "payment",
            "wallet",
            "bank",
            "billing",
            "security"
        )

        /**
         * Sensitive query parameters frequently associated with
         * credential collection or tracking.
         */
        private val SENSITIVE_QUERY_PARAMETERS = listOf(
            "password",
            "passwd",
            "pass",
            "pwd",
            "otp",
            "pin",
            "cvv",
            "card",
            "cardnumber",
            "account",
            "username",
            "userid",
            "token",
            "auth",
            "authorization"
        )

        /**
         * URL encoding patterns commonly encountered in obfuscated URLs.
         */
        private val OBFUSCATION_PATTERNS = listOf(
            "%2f",
            "%2F",
            "%5c",
            "%5C",
            "%40",
            "%3a",
            "%3A",
            "%3f",
            "%3F",
            "%23",
            "%26",
            "%3d",
            "%3D",
            "%25"
        )

        /**
         * Suspicious port numbers.
         *
         * A non-standard port is only a signal, never proof of phishing.
         */
        private val SUSPICIOUS_PORTS = setOf(
            81,
            444,
            591,
            8000,
            8008,
            8080,
            8081,
            8888,
            9000,
            9090
        )

        /**
         * Potentially deceptive TLDs.
         *
         * These are heuristic signals only.
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

        /**
         * Common legitimate-looking brand keywords frequently abused
         * in phishing URLs.
         *
         * This list should eventually be replaced or supplemented by
         * SentriX threat-intelligence data.
         */
        private val HIGH_VALUE_BRAND_TERMS = listOf(
            "paypal",
            "microsoft",
            "google",
            "apple",
            "amazon",
            "facebook",
            "instagram",
            "whatsapp",
            "netflix",
            "linkedin",
            "bank",
            "sbi",
            "hdfc",
            "icici",
            "axis",
            "paytm",
            "phonepe"
        )

        /**
         * Suspicious separators frequently used to disguise domains.
         */
        private val SUSPICIOUS_DOMAIN_SEPARATORS = listOf(
            "--",
            ".."
        )

        /**
         * Regex for an IPv4 address.
         */
        private val IPV4_PATTERN = Regex(
            "^\\d{1,3}(\\.\\d{1,3}){3}$"
        )

        /**
         * Regex for hexadecimal IPv6 representation.
         */
        private val IPV6_PATTERN = Regex(
            "^[0-9a-fA-F:]+$"
        )
    }

    /**
     * Performs complete URL analysis.
     *
     * @param url URL to analyze.
     *
     * @return PhishingURLAnalysis containing indicators and risk.
     */
    suspend fun analyze(
        url: String
    ): PhishingURLAnalysis = withContext(Dispatchers.Default) {

        validateUrl(url)

        checkCancellation()

        val normalizedUrl = normalizeUrl(url)

        Log.d(
            TAG,
            "Starting phishing URL analysis."
        )

        val findings = mutableListOf<PhishingURLFinding>()

        val uri = parseUri(normalizedUrl)

        if (uri == null) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.INVALID_URL,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.50f,
                    description = "The URL could not be parsed safely."
                )
            )

            return@withContext buildResult(
                originalUrl = url,
                normalizedUrl = normalizedUrl,
                findings = findings
            )
        }

        checkCancellation()

        analyzeScheme(
            uri = uri,
            findings = findings
        )

        analyzeHost(
            uri = uri,
            findings = findings
        )

        analyzeIpAddress(
            uri = uri,
            findings = findings
        )

        analyzeSubdomains(
            uri = uri,
            findings = findings
        )

        analyzePunycode(
            uri = uri,
            findings = findings
        )

        analyzeDomainStructure(
            uri = uri,
            findings = findings
        )

        analyzePort(
            uri = uri,
            findings = findings
        )

        analyzeUserInfo(
            uri = uri,
            findings = findings
        )

        analyzePath(
            uri = uri,
            findings = findings
        )

        analyzeQuery(
            uri = uri,
            findings = findings
        )

        analyzeFragment(
            uri = uri,
            findings = findings
        )

        analyzeObfuscation(
            url = normalizedUrl,
            findings = findings
        )

        analyzeLength(
            url = normalizedUrl,
            findings = findings
        )

        analyzeShortener(
            uri = uri,
            findings = findings
        )

        analyzeBrandImpersonation(
            uri = uri,
            findings = findings
        )

        analyzeRepeatedEncoding(
            url = normalizedUrl,
            findings = findings
        )

        val result = buildResult(
            originalUrl = url,
            normalizedUrl = normalizedUrl,
            findings = findings
        )

        Log.d(
            TAG,
            "URL phishing analysis completed. " +
                    "risk=${result.riskScore}, " +
                    "classification=${result.classification}, " +
                    "findings=${result.findings.size}"
        )

        result
    }

    /**
     * Performs a lightweight URL analysis.
     *
     * Intended for frequent URL checks where a full result object
     * is not required by the caller.
     */
    suspend fun calculateRisk(
        url: String
    ): Float {

        return analyze(url).riskScore
    }

    /**
     * Returns true when the URL reaches the medium-risk threshold.
     */
    suspend fun isSuspicious(
        url: String
    ): Boolean {

        return analyze(url).riskScore >= MEDIUM_RISK_THRESHOLD
    }

    /**
     * Returns true when the URL reaches the high-risk threshold.
     */
    suspend fun isHighRisk(
        url: String
    ): Boolean {

        return analyze(url).riskScore >= HIGH_RISK_THRESHOLD
    }

    /**
     * Returns true when the URL appears structurally valid and
     * contains no significant local phishing indicators.
     *
     * Note:
     * A true result does NOT guarantee that the remote website is safe.
     */
    suspend fun isLocallySafe(
        url: String
    ): Boolean {

        val result = analyze(url)

        return result.riskScore < MEDIUM_RISK_THRESHOLD
    }

    /**
     * Normalizes a URL without performing any network operation.
     */
    fun normalizeUrl(
        url: String
    ): String {

        return url
            .trim()
            .replace("\u0000", "")
    }

    /**
     * Extracts the hostname from a URL.
     */
    fun extractHost(
        url: String
    ): String? {

        return try {

            URI(
                normalizeUrl(url)
            ).host

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Extracts the registrable-looking domain.
     *
     * This is intentionally lightweight and does not implement the full
     * Public Suffix List. Production domain reputation should use a proper
     * PSL-aware implementation.
     */
    fun extractBaseDomain(
        host: String
    ): String {

        val normalizedHost = host
            .trim()
            .lowercase(Locale.ROOT)
            .removePrefix("www.")

        val labels = normalizedHost
            .split(".")
            .filter { it.isNotBlank() }

        return when {
            labels.size >= 2 ->
                labels.takeLast(2).joinToString(".")

            else ->
                normalizedHost
        }
    }

    /**
     * Determines whether the host is an IP address.
     */
    fun isIpAddress(
        host: String
    ): Boolean {

        val normalizedHost = host
            .trim()
            .removePrefix("[")
            .removeSuffix("]")

        if (IPV4_PATTERN.matches(normalizedHost)) {
            return isValidIpv4(normalizedHost)
        }

        return normalizedHost.contains(":") &&
                IPV6_PATTERN.matches(normalizedHost)
    }

    /**
     * Analyzes URL scheme.
     */
    private fun analyzeScheme(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val scheme = uri.scheme
            ?.lowercase(Locale.ROOT)

        if (scheme == null) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.MISSING_SCHEME,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.40f,
                    description = "The URL does not contain a recognized scheme."
                )
            )

            return
        }

        if (!SUPPORTED_SCHEMES.contains(scheme)) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.UNSUPPORTED_SCHEME,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.40f,
                    description = "The URL uses an unsupported scheme."
                )
            )

            return
        }

        if (scheme == "http") {

            findings.add(
                finding(
                    type = PhishingURLIndicator.INSECURE_HTTP,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.12f,
                    description = "The URL uses HTTP rather than HTTPS."
                )
            )
        }
    }

    /**
     * Analyzes the hostname.
     */
    private fun analyzeHost(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host

        if (host.isNullOrBlank()) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.MISSING_HOST,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.45f,
                    description = "The URL does not contain a valid hostname."
                )
            )

            return
        }

        val normalizedHost = host.lowercase(Locale.ROOT)

        if (normalizedHost.length > 253) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.EXCESSIVE_HOST_LENGTH,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.15f,
                    description = "The hostname exceeds the normal DNS length."
                )
            )
        }

        if (normalizedHost.contains("..")) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.REPEATED_DOTS,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.12f,
                    description = "The hostname contains repeated dots."
                )
            )
        }

        if (normalizedHost.contains("--")) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.REPEATED_HYPHENS,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.05f,
                    description = "The hostname contains repeated hyphens."
                )
            )
        }

        HIGH_RISK_TLDS
            .firstOrNull { normalizedHost.endsWith(it) }
            ?.let { tld ->

                findings.add(
                    finding(
                        type = PhishingURLIndicator.HIGH_RISK_TLD,
                        severity = PhishingURLSeverity.LOW,
                        score = 0.07f,
                        description = "The hostname uses a potentially higher-risk TLD: $tld."
                    )
                )
            }
    }

    /**
     * Detects IPv4 and IPv6 hosts.
     */
    private fun analyzeIpAddress(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host ?: return

        if (!isIpAddress(host)) {
            return
        }

        findings.add(
            finding(
                type = PhishingURLIndicator.IP_ADDRESS_HOST,
                severity = PhishingURLSeverity.MEDIUM,
                score = 0.20f,
                description = "The URL uses an IP address instead of a domain name."
            )
        )
    }

    /**
     * Analyzes subdomain depth.
     */
    private fun analyzeSubdomains(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host ?: return

        if (isIpAddress(host)) {
            return
        }

        val labels = host
            .split(".")
            .filter { it.isNotBlank() }

        /*
         * Example:
         *
         * a.b.c.example.com
         *
         * contains three subdomain labels.
         */
        val subdomainCount = (labels.size - 2)
            .coerceAtLeast(0)

        when {

            subdomainCount >= 5 -> {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.EXCESSIVE_SUBDOMAINS,
                        severity = PhishingURLSeverity.HIGH,
                        score = 0.20f,
                        description = "The hostname contains an unusually large number of subdomains."
                    )
                )
            }

            subdomainCount >= 3 -> {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.MULTIPLE_SUBDOMAINS,
                        severity = PhishingURLSeverity.LOW,
                        score = 0.07f,
                        description = "The hostname contains multiple subdomains."
                    )
                )
            }
        }
    }

    /**
     * Detects punycode/internationalized domains.
     */
    private fun analyzePunycode(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host ?: return

        if (!host.contains("xn--", ignoreCase = true)) {
            return
        }

        val decodedHost = try {

            IDN.toUnicode(host)

        } catch (_: Exception) {

            null
        }

        findings.add(
            finding(
                type = PhishingURLIndicator.PUNYCODE_DOMAIN,
                severity = PhishingURLSeverity.MEDIUM,
                score = 0.15f,
                description = if (decodedHost != null) {
                    "The hostname contains an internationalized/punycode domain."
                } else {
                    "The hostname contains an invalid or unusual punycode label."
                }
            )
        )
    }

    /**
     * Analyzes domain structure for deceptive formatting.
     */
    private fun analyzeDomainStructure(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host ?: return

        if (isIpAddress(host)) {
            return
        }

        val labels = host
            .lowercase(Locale.ROOT)
            .split(".")
            .filter { it.isNotBlank() }

        labels.forEach { label ->

            if (label.length > 63) {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.EXCESSIVE_LABEL_LENGTH,
                        severity = PhishingURLSeverity.MEDIUM,
                        score = 0.10f,
                        description = "A hostname label exceeds the normal DNS label length."
                    )
                )
            }

            if (label.startsWith("-") ||
                label.endsWith("-")
            ) {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.INVALID_LABEL_BOUNDARY,
                        severity = PhishingURLSeverity.MEDIUM,
                        score = 0.10f,
                        description = "A hostname label begins or ends with a hyphen."
                    )
                )
            }
        }

        val separatorMatches =
            SUSPICIOUS_DOMAIN_SEPARATORS.count { separator ->
                host.contains(separator)
            }

        if (separatorMatches >= 2) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.SUSPICIOUS_DOMAIN_FORMAT,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.10f,
                    description = "The hostname contains multiple suspicious separators."
                )
            )
        }
    }

    /**
     * Analyzes the URL port.
     */
    private fun analyzePort(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val port = uri.port

        if (port <= 0) {
            return
        }

        if (port == 80 || port == 443) {
            return
        }

        if (SUSPICIOUS_PORTS.contains(port)) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.SUSPICIOUS_PORT,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.10f,
                    description = "The URL uses a non-standard web service port: $port."
                )
            )

        } else {

            findings.add(
                finding(
                    type = PhishingURLIndicator.NON_STANDARD_PORT,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.05f,
                    description = "The URL uses a non-standard port."
                )
            )
        }
    }

    /**
     * Detects user information embedded in a URL.
     *
     * Example:
     *
     * https://example-user@example.com
     */
    private fun analyzeUserInfo(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        if (!uri.rawUserInfo.isNullOrBlank()) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.EMBEDDED_USER_INFO,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.25f,
                    description = "The URL contains embedded user information."
                )
            )
        }
    }

    /**
     * Analyzes URL path.
     */
    private fun analyzePath(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val path = uri.path
            ?.lowercase(Locale.ROOT)
            ?: return

        if (path.isBlank()) {
            return
        }

        val matches = SUSPICIOUS_PATH_TERMS
            .filter { term ->
                path.contains(term)
            }
            .distinct()

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.SENSITIVE_PATH_TERMS,
                    severity = PhishingURLSeverity.LOW,
                    score = (matches.size * 0.04f)
                        .coerceAtMost(0.16f),
                    description =
                        "The URL path contains security-sensitive terms."
                )
            )
        }

        if (path.length > 200) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.LONG_PATH,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.05f,
                    description = "The URL contains an unusually long path."
                )
            )
        }

        if (path.count { it == '/' } >= 10) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.DEEP_PATH,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.05f,
                    description = "The URL contains unusually deep path nesting."
                )
            )
        }
    }

    /**
     * Analyzes URL query parameters.
     */
    private fun analyzeQuery(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val query = uri.rawQuery
            ?.lowercase(Locale.ROOT)
            ?: return

        if (query.isBlank()) {
            return
        }

        val matches = SENSITIVE_QUERY_PARAMETERS
            .filter { parameter ->
                query.contains(parameter)
            }
            .distinct()

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.SENSITIVE_QUERY_PARAMETER,
                    severity = PhishingURLSeverity.HIGH,
                    score = 0.20f,
                    description =
                        "The URL query contains potentially sensitive parameters."
                )
            )
        }

        if (query.length > 1000) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.LONG_QUERY,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.06f,
                    description = "The URL contains an unusually long query string."
                )
            )
        }

        if (query.count { it == '=' } >= 15) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.EXCESSIVE_PARAMETERS,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.06f,
                    description = "The URL contains an unusually large number of parameters."
                )
            )
        }
    }

    /**
     * Analyzes fragment identifiers.
     */
    private fun analyzeFragment(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val fragment = uri.rawFragment
            ?.lowercase(Locale.ROOT)
            ?: return

        if (fragment.isBlank()) {
            return
        }

        val sensitiveTerms = SENSITIVE_QUERY_PARAMETERS +
                SUSPICIOUS_PATH_TERMS

        val match = sensitiveTerms.any {
            fragment.contains(it)
        }

        if (match) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.SENSITIVE_FRAGMENT,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.05f,
                    description =
                        "The URL fragment contains a security-sensitive term."
                )
            )
        }
    }

    /**
     * Detects URL encoding patterns.
     */
    private fun analyzeObfuscation(
        url: String,
        findings: MutableList<PhishingURLFinding>
    ) {

        val lowerUrl = url.lowercase(Locale.ROOT)

        val encodedMatches = OBFUSCATION_PATTERNS.count {
            lowerUrl.contains(it.lowercase(Locale.ROOT))
        }

        if (encodedMatches > 0) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.ENCODED_URL,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = (encodedMatches * 0.04f)
                        .coerceAtMost(0.16f),
                    description =
                        "The URL contains encoded characters that may reduce readability."
                )
            )
        }

        if (lowerUrl.contains("%25")) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.DOUBLE_ENCODING,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.15f,
                    description =
                        "The URL contains a pattern associated with repeated URL encoding."
                )
            )
        }
    }

    /**
     * Detects unusually long URLs.
     */
    private fun analyzeLength(
        url: String,
        findings: MutableList<PhishingURLFinding>
    ) {

        when {

            url.length > 2000 -> {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.EXTREME_URL_LENGTH,
                        severity = PhishingURLSeverity.MEDIUM,
                        score = 0.15f,
                        description = "The URL is unusually long."
                    )
                )
            }

            url.length > 1000 -> {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.VERY_LONG_URL,
                        severity = PhishingURLSeverity.LOW,
                        score = 0.08f,
                        description = "The URL is longer than typical."
                    )
                )
            }

            url.length > 500 -> {

                findings.add(
                    finding(
                        type = PhishingURLIndicator.LONG_URL,
                        severity = PhishingURLSeverity.LOW,
                        score = 0.04f,
                        description = "The URL is moderately long."
                    )
                )
            }
        }
    }

    /**
     * Detects known URL shorteners.
     */
    private fun analyzeShortener(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host
            ?.lowercase(Locale.ROOT)
            ?: return

        if (URL_SHORTENERS.contains(host)) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.URL_SHORTENER,
                    severity = PhishingURLSeverity.LOW,
                    score = 0.08f,
                    description =
                        "The URL uses a known URL-shortening service."
                )
            )
        }
    }

    /**
     * Detects potential brand impersonation patterns.
     *
     * Example:
     *
     * secure-paypal-login.example.com
     *
     * The presence of a brand keyword alone is NOT treated as proof
     * of phishing.
     */
    private fun analyzeBrandImpersonation(
        uri: URI,
        findings: MutableList<PhishingURLFinding>
    ) {

        val host = uri.host
            ?.lowercase(Locale.ROOT)
            ?: return

        val baseDomain = extractBaseDomain(host)

        val matchedBrands = HIGH_VALUE_BRAND_TERMS
            .filter { brand ->
                host.contains(brand)
            }
            .distinct()

        if (matchedBrands.isEmpty()) {
            return
        }

        /*
         * If a brand keyword appears in a subdomain/path-like hostname
         * but isn't the base domain, it can indicate impersonation.
         */
        val baseContainsBrand = matchedBrands.any {
            baseDomain.contains(it)
        }

        if (!baseContainsBrand) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.POSSIBLE_BRAND_IMPERSONATION,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.18f,
                    description =
                        "The hostname contains a recognizable brand term outside the apparent base domain."
                )
            )
        }
    }

    /**
     * Detects repeated URL encoding.
     */
    private fun analyzeRepeatedEncoding(
        url: String,
        findings: MutableList<PhishingURLFinding>
    ) {

        val percentCount = url.count {
            it == '%'
        }

        if (percentCount >= 10) {

            findings.add(
                finding(
                    type = PhishingURLIndicator.EXCESSIVE_ENCODING,
                    severity = PhishingURLSeverity.MEDIUM,
                    score = 0.12f,
                    description =
                        "The URL contains an unusually high number of encoded characters."
                )
            )
        }
    }

    /**
     * Creates an individual finding.
     */
    private fun finding(
        type: PhishingURLIndicator,
        severity: PhishingURLSeverity,
        score: Float,
        description: String
    ): PhishingURLFinding {

        return PhishingURLFinding(
            type = type,
            severity = severity,
            score = score.coerceIn(0.0f, 1.0f),
            description = description
        )
    }

    /**
     * Calculates the final risk score.
     *
     * The algorithm intentionally caps the score at 1.0.
     *
     * Risk is based on multiple independent indicators rather than a
     * single signal.
     */
    private fun calculateRiskScore(
        findings: List<PhishingURLFinding>
    ): Float {

        if (findings.isEmpty()) {
            return 0.0f
        }

        val relevantFindings = findings
            .sortedByDescending {
                it.score
            }
            .take(MAX_FINDINGS)

        var score = relevantFindings.sumOf {
            it.score.toDouble()
        }.toFloat()

        val criticalCount = relevantFindings.count {
            it.severity == PhishingURLSeverity.CRITICAL
        }

        val highCount = relevantFindings.count {
            it.severity == PhishingURLSeverity.HIGH
        }

        val mediumCount = relevantFindings.count {
            it.severity == PhishingURLSeverity.MEDIUM
        }

        /*
         * Multiple independent high-severity indicators increase
         * confidence in the result.
         */
        if (criticalCount > 0) {
            score += 0.20f
        }

        if (highCount >= 2) {
            score += 0.15f
        }

        if (mediumCount >= 3) {
            score += 0.08f
        }

        return score.coerceIn(0.0f, 1.0f)
    }

    /**
     * Determines risk classification.
     */
    private fun classify(
        score: Float
    ): PhishingURLClassification {

        return when {

            score >= HIGH_RISK_THRESHOLD ->
                PhishingURLClassification.HIGH

            score >= MEDIUM_RISK_THRESHOLD ->
                PhishingURLClassification.MEDIUM

            score >= LOW_RISK_THRESHOLD ->
                PhishingURLClassification.LOW

            else ->
                PhishingURLClassification.SAFE
        }
    }

    /**
     * Builds final analysis result.
     */
    private fun buildResult(
        originalUrl: String,
        normalizedUrl: String,
        findings: List<PhishingURLFinding>
    ): PhishingURLAnalysis {

        val limitedFindings = findings
            .distinctBy {
                "${it.type}:${it.description}"
            }
            .sortedByDescending {
                it.score
            }
            .take(MAX_FINDINGS)

        val riskScore = calculateRiskScore(
            limitedFindings
        )

        val classification = classify(
            riskScore
        )

        val suspicious = classification !=
                PhishingURLClassification.SAFE

        return PhishingURLAnalysis(
            originalUrl = originalUrl,
            normalizedUrl = normalizedUrl,
            riskScore = riskScore,
            classification = classification,
            isSuspicious = suspicious,
            findings = limitedFindings
        )
    }

    /**
     * Parses a URI safely.
     */
    private fun parseUri(
        url: String
    ): URI? {

        return try {

            URI(url)

        } catch (exception: Exception) {

            Log.d(
                TAG,
                "Unable to parse URI.",
                exception
            )

            null
        }
    }

    /**
     * Validates the URL before analysis.
     */
    private fun validateUrl(
        url: String
    ) {

        require(url.isNotBlank()) {
            "URL must not be blank."
        }

        require(url.length <= MAX_URL_LENGTH) {
            "URL exceeds the maximum supported length."
        }

        val normalized = normalizeUrl(url)

        require(
            normalized.startsWith(
                "http://",
                ignoreCase = true
            ) ||
                    normalized.startsWith(
                        "https://",
                        ignoreCase = true
                    )
        ) {
            "Only HTTP and HTTPS URLs are supported."
        }
    }

    /**
     * Validates IPv4 octets.
     */
    private fun isValidIpv4(
        host: String
    ): Boolean {

        return try {

            host
                .split(".")
                .all { octet ->
                    octet.toInt() in 0..255
                }

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Respects coroutine cancellation.
     */
    private suspend fun checkCancellation() {

        if (!kotlinx.coroutines.currentCoroutineContext().isActive) {
            throw CancellationException(
                "Phishing URL analysis was cancelled."
            )
        }
    }
}

/**
 * Complete result produced by PhishingURLAnalyzer.
 */
data class PhishingURLAnalysis(

    /**
     * URL exactly as supplied by the caller.
     */
    val originalUrl: String,

    /**
     * Normalized URL used internally.
     */
    val normalizedUrl: String,

    /**
     * Risk score between 0.0 and 1.0.
     */
    val riskScore: Float,

    /**
     * Overall phishing classification.
     */
    val classification: PhishingURLClassification,

    /**
     * Whether significant local phishing indicators were detected.
     */
    val isSuspicious: Boolean,

    /**
     * Individual indicators discovered during analysis.
     */
    val findings: List<PhishingURLFinding>
)

/**
 * Individual URL phishing indicator.
 */
data class PhishingURLFinding(

    /**
     * Indicator type.
     */
    val type: PhishingURLIndicator,

    /**
     * Indicator severity.
     */
    val severity: PhishingURLSeverity,

    /**
     * Indicator contribution to the risk score.
     */
    val score: Float,

    /**
     * Human-readable explanation.
     */
    val description: String
)

/**
 * URL phishing risk classification.
 */
enum class PhishingURLClassification {

    /**
     * No significant local indicators detected.
     */
    SAFE,

    /**
     * Minor suspicious characteristics detected.
     */
    LOW,

    /**
     * Multiple indicators detected.
     */
    MEDIUM,

    /**
     * Strong phishing indicators detected.
     */
    HIGH
}

/**
 * Severity of an individual URL indicator.
 */
enum class PhishingURLSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Types of URL-level phishing indicators.
 */
enum class PhishingURLIndicator {

    INVALID_URL,

    MISSING_SCHEME,

    UNSUPPORTED_SCHEME,

    MISSING_HOST,

    INSECURE_HTTP,

    IP_ADDRESS_HOST,

    EXCESSIVE_HOST_LENGTH,

    REPEATED_DOTS,

    REPEATED_HYPHENS,

    HIGH_RISK_TLD,

    EXCESSIVE_SUBDOMAINS,

    MULTIPLE_SUBDOMAINS,

    PUNYCODE_DOMAIN,

    EXCESSIVE_LABEL_LENGTH,

    INVALID_LABEL_BOUNDARY,

    SUSPICIOUS_DOMAIN_FORMAT,

    SUSPICIOUS_PORT,

    NON_STANDARD_PORT,

    EMBEDDED_USER_INFO,

    SENSITIVE_PATH_TERMS,

    LONG_PATH,

    DEEP_PATH,

    SENSITIVE_QUERY_PARAMETER,

    LONG_QUERY,

    EXCESSIVE_PARAMETERS,

    SENSITIVE_FRAGMENT,

    ENCODED_URL,

    DOUBLE_ENCODING,

    EXTREME_URL_LENGTH,

    VERY_LONG_URL,

    LONG_URL,

    URL_SHORTENER,

    POSSIBLE_BRAND_IMPERSONATION,

    EXCESSIVE_ENCODING
}
