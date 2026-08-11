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
 * PhishingDomainAnalyzer
 *
 * Specialized analyzer responsible for evaluating domain-level
 * phishing indicators.
 *
 * Responsibilities:
 * - Validate and normalize domains.
 * - Analyze domain structure.
 * - Detect excessive subdomains.
 * - Detect suspicious labels.
 * - Detect punycode / IDN domains.
 * - Detect IP-based hosts.
 * - Detect suspicious TLD characteristics.
 * - Detect brand impersonation indicators.
 * - Detect domain entropy and character anomalies.
 * - Detect suspicious hyphen/number usage.
 * - Optionally perform controlled DNS resolution.
 * - Produce a structured domain risk assessment.
 *
 * IMPORTANT:
 * This class performs heuristic/domain-level analysis only.
 *
 * It does NOT establish that a domain is malicious simply because:
 * - it contains a brand name,
 * - it uses a particular TLD,
 * - it has many subdomains,
 * - it uses punycode,
 * - or it resolves to an IP address.
 *
 * These are indicators that should be combined with:
 * - Domain reputation
 * - Threat intelligence
 * - Certificate analysis
 * - WHOIS/RDAP information
 * - Domain age
 * - DNS reputation
 * - Historical observations
 * - Behavioral analysis
 *
 * Architecture:
 *
 * PhishingDetectionManager
 *          |
 *          v
 * PhishingAnalyzer
 *          |
 *          v
 * PhishingDomainAnalyzer
 *          |
 *          +--> Domain structure
 *          +--> TLD analysis
 *          +--> IDN analysis
 *          +--> Brand impersonation
 *          +--> Entropy analysis
 *          +--> DNS analysis
 *          +--> Risk calculation
 */
class PhishingDomainAnalyzer {

    companion object {

        private const val TAG = "PhishingDomainAnalyzer"

        /**
         * Maximum valid DNS hostname length.
         */
        private const val MAX_DOMAIN_LENGTH = 253

        /**
         * Maximum individual DNS label length.
         */
        private const val MAX_LABEL_LENGTH = 63

        /**
         * Maximum number of labels accepted before the domain is
         * considered unusually deep.
         */
        private const val MAX_NORMAL_LABELS = 4

        /**
         * Risk thresholds.
         */
        private const val LOW_RISK_THRESHOLD = 0.25f
        private const val MEDIUM_RISK_THRESHOLD = 0.50f
        private const val HIGH_RISK_THRESHOLD = 0.75f

        /**
         * Potentially suspicious TLDs.
         *
         * These are heuristic indicators only.
         */
        private val HIGH_RISK_TLDS = setOf(
            "zip",
            "mov",
            "click",
            "top",
            "work",
            "country",
            "gq",
            "tk",
            "ml",
            "cf"
        )

        /**
         * Common free/subdomain hosting patterns.
         *
         * Presence alone does NOT indicate malicious activity.
         */
        private val FREE_HOSTING_DOMAINS = setOf(
            "pages.dev",
            "github.io",
            "gitlab.io",
            "netlify.app",
            "vercel.app",
            "web.app",
            "firebaseapp.com",
            "blogspot.com",
            "wordpress.com"
        )

        /**
         * Common URL-shortener domains.
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
            "rb.gy"
        )

        /**
         * High-value brands that are frequently impersonated.
         *
         * This list should eventually be backed by SentriX threat
         * intelligence rather than remaining hard-coded.
         */
        private val PROTECTED_BRANDS = mapOf(
            "paypal" to setOf("paypal.com"),
            "microsoft" to setOf(
                "microsoft.com",
                "live.com",
                "office.com",
                "office365.com"
            ),
            "google" to setOf(
                "google.com",
                "googleusercontent.com"
            ),
            "apple" to setOf(
                "apple.com",
                "icloud.com"
            ),
            "amazon" to setOf(
                "amazon.com",
                "amazon.in"
            ),
            "facebook" to setOf(
                "facebook.com",
                "fb.com"
            ),
            "instagram" to setOf(
                "instagram.com"
            ),
            "whatsapp" to setOf(
                "whatsapp.com"
            ),
            "netflix" to setOf(
                "netflix.com"
            ),
            "linkedin" to setOf(
                "linkedin.com"
            ),
            "paytm" to setOf(
                "paytm.com"
            ),
            "phonepe" to setOf(
                "phonepe.com"
            ),
            "sbi" to setOf(
                "sbi.co.in",
                "onlinesbi.sbi"
            ),
            "hdfc" to setOf(
                "hdfcbank.com"
            ),
            "icici" to setOf(
                "icicibank.com"
            ),
            "axis" to setOf(
                "axisbank.com"
            )
        )

        /**
         * Suspicious terms commonly found in impersonating domains.
         */
        private val SUSPICIOUS_DOMAIN_TERMS = listOf(
            "login",
            "signin",
            "secure",
            "security",
            "verify",
            "verification",
            "account",
            "update",
            "confirm",
            "support",
            "service",
            "customer",
            "auth",
            "authentication",
            "wallet",
            "payment",
            "billing",
            "recover",
            "unlock"
        )

        /**
         * Characters that are frequently used in deceptive domains.
         */
        private val SUSPICIOUS_SYMBOLS = setOf(
            '_',
            '%',
            '@'
        )

        /**
         * Regex for IPv4 addresses.
         */
        private val IPV4_PATTERN = Regex(
            "^\\d{1,3}(\\.\\d{1,3}){3}$"
        )

        /**
         * Regex for simple IPv6 recognition.
         */
        private val IPV6_PATTERN = Regex(
            "^[0-9a-fA-F:]+$"
        )
    }

    /**
     * Performs complete domain analysis.
     *
     * @param domain domain name or hostname.
     *
     * @return structured domain analysis.
     */
    suspend fun analyze(
        domain: String
    ): PhishingDomainAnalysis = withContext(Dispatchers.Default) {

        validateDomain(domain)

        checkCancellation()

        val normalizedDomain = normalizeDomain(domain)

        Log.d(
            TAG,
            "Starting phishing domain analysis."
        )

        val findings = mutableListOf<PhishingDomainFinding>()

        analyzeBasicStructure(
            domain = normalizedDomain,
            findings = findings
        )

        checkCancellation()

        analyzeIpAddress(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeLabels(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeSubdomains(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeTld(
            domain = normalizedDomain,
            findings = findings
        )

        analyzePunycode(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeCharacterDistribution(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeDigitUsage(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeHyphenUsage(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeEntropy(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeSuspiciousTerms(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeBrandImpersonation(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeHostingProviderPattern(
            domain = normalizedDomain,
            findings = findings
        )

        analyzeUrlShortener(
            domain = normalizedDomain,
            findings = findings
        )

        val result = buildResult(
            domain = normalizedDomain,
            findings = findings
        )

        Log.d(
            TAG,
            "Domain analysis completed. " +
                    "risk=${result.riskScore}, " +
                    "classification=${result.classification}"
        )

        result
    }

    /**
     * Analyzes a complete URL by extracting its hostname first.
     */
    suspend fun analyzeUrl(
        url: String
    ): PhishingDomainAnalysis {

        val uri = try {

            URI(
                url.trim()
            )

        } catch (exception: Exception) {

            throw IllegalArgumentException(
                "Invalid URL.",
                exception
            )
        }

        val host = uri.host
            ?: throw IllegalArgumentException(
                "URL does not contain a valid hostname."
            )

        return analyze(host)
    }

    /**
     * Calculates only the domain risk score.
     */
    suspend fun calculateRisk(
        domain: String
    ): Float {

        return analyze(domain).riskScore
    }

    /**
     * Returns whether significant domain-level phishing indicators
     * have been detected.
     */
    suspend fun isSuspicious(
        domain: String
    ): Boolean {

        return analyze(domain).riskScore >= MEDIUM_RISK_THRESHOLD
    }

    /**
     * Returns whether the domain has high-risk local indicators.
     */
    suspend fun isHighRisk(
        domain: String
    ): Boolean {

        return analyze(domain).riskScore >= HIGH_RISK_THRESHOLD
    }

    /**
     * Normalizes a domain.
     */
    fun normalizeDomain(
        domain: String
    ): String {

        var normalized = domain
            .trim()
            .lowercase(Locale.ROOT)

        /*
         * Handle URLs passed accidentally to the domain analyzer.
         */
        if (normalized.startsWith("http://") ||
            normalized.startsWith("https://")
        ) {

            normalized = try {

                URI(normalized).host ?: normalized

            } catch (_: Exception) {

                normalized
            }
        }

        /*
         * Remove IPv6 brackets.
         */
        normalized = normalized
            .removePrefix("[")
            .removeSuffix("]")

        /*
         * Remove a trailing dot used by fully-qualified DNS names.
         */
        if (normalized.endsWith(".")) {
            normalized = normalized.dropLast(1)
        }

        return normalized
    }

    /**
     * Extracts the apparent base domain.
     *
     * NOTE:
     * This is intentionally lightweight and is not a replacement for
     * a Public Suffix List implementation.
     */
    fun extractBaseDomain(
        domain: String
    ): String {

        val normalized = normalizeDomain(domain)

        if (isIpAddress(normalized)) {
            return normalized
        }

        val labels = normalized
            .split(".")
            .filter { it.isNotBlank() }

        return when {

            labels.size >= 2 ->
                labels.takeLast(2).joinToString(".")

            else ->
                normalized
        }
    }

    /**
     * Returns the TLD of the supplied domain.
     */
    fun extractTld(
        domain: String
    ): String? {

        val normalized = normalizeDomain(domain)

        if (isIpAddress(normalized)) {
            return null
        }

        return normalized
            .split(".")
            .lastOrNull()
            ?.takeIf { it.isNotBlank() }
    }

    /**
     * Returns the number of subdomain labels.
     */
    fun countSubdomains(
        domain: String
    ): Int {

        val normalized = normalizeDomain(domain)

        if (isIpAddress(normalized)) {
            return 0
        }

        val labels = normalized
            .split(".")
            .filter { it.isNotBlank() }

        return (labels.size - 2)
            .coerceAtLeast(0)
    }

    /**
     * Determines whether a hostname is an IP address.
     */
    fun isIpAddress(
        domain: String
    ): Boolean {

        val normalized = normalizeDomain(domain)

        if (IPV4_PATTERN.matches(normalized)) {

            return normalized
                .split(".")
                .all {
                    try {
                        it.toInt() in 0..255
                    } catch (_: Exception) {
                        false
                    }
                }
        }

        return normalized.contains(":") &&
                IPV6_PATTERN.matches(normalized)
    }

    /**
     * Performs basic DNS resolution.
     *
     * This method should be used sparingly because DNS lookups are
     * network operations and can reveal information externally.
     *
     * The result is only an infrastructure indicator and must not be
     * treated as a maliciousness verdict.
     */
    suspend fun resolveAddresses(
        domain: String
    ): DomainDnsResult = withContext(Dispatchers.IO) {

        validateDomain(domain)

        checkCancellation()

        val normalizedDomain = normalizeDomain(domain)

        if (isIpAddress(normalizedDomain)) {

            return@withContext DomainDnsResult(
                domain = normalizedDomain,
                resolved = true,
                addresses = listOf(normalizedDomain),
                error = null
            )
        }

        try {

            val addresses = InetAddress
                .getAllByName(normalizedDomain)
                .map {
                    it.hostAddress
                }
                .distinct()

            DomainDnsResult(
                domain = normalizedDomain,
                resolved = addresses.isNotEmpty(),
                addresses = addresses,
                error = null
            )

        } catch (exception: Exception) {

            Log.d(
                TAG,
                "DNS resolution failed for domain.",
                exception
            )

            DomainDnsResult(
                domain = normalizedDomain,
                resolved = false,
                addresses = emptyList(),
                error = exception.message
            )
        }
    }

    /**
     * Analyzes basic domain structure.
     */
    private fun analyzeBasicStructure(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (domain.length > MAX_DOMAIN_LENGTH) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.EXCESSIVE_DOMAIN_LENGTH,
                    severity = PhishingDomainSeverity.HIGH,
                    score = 0.30f,
                    description =
                        "The domain exceeds the maximum normal DNS hostname length."
                )
            )
        }

        if (domain.contains("..")) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.REPEATED_DOTS,
                    severity = PhishingDomainSeverity.MEDIUM,
                    score = 0.12f,
                    description =
                        "The domain contains repeated dots."
                )
            )
        }

        if (domain.startsWith(".") ||
            domain.endsWith(".")
        ) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.INVALID_DOMAIN_BOUNDARY,
                    severity = PhishingDomainSeverity.MEDIUM,
                    score = 0.10f,
                    description =
                        "The domain contains an invalid boundary."
                )
            )
        }
    }

    /**
     * Detects IP-address domains.
     */
    private fun analyzeIpAddress(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (!isIpAddress(domain)) {
            return
        }

        findings.add(
            finding(
                type = PhishingDomainIndicator.IP_ADDRESS_DOMAIN,
                severity = PhishingDomainSeverity.MEDIUM,
                score = 0.20f,
                description =
                    "The host is an IP address rather than a conventional domain."
            )
        )
    }

    /**
     * Analyzes individual domain labels.
     */
    private fun analyzeLabels(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val labels = domain
            .split(".")
            .filter { it.isNotBlank() }

        labels.forEach { label ->

            if (label.length > MAX_LABEL_LENGTH) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.EXCESSIVE_LABEL_LENGTH,
                        severity = PhishingDomainSeverity.MEDIUM,
                        score = 0.10f,
                        description =
                            "A domain label exceeds the normal DNS label length."
                    )
                )
            }

            if (label.startsWith("-") ||
                label.endsWith("-")
            ) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.INVALID_HYPHEN_BOUNDARY,
                        severity = PhishingDomainSeverity.MEDIUM,
                        score = 0.10f,
                        description =
                            "A domain label begins or ends with a hyphen."
                    )
                )
            }

            if (label.contains("_")) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.UNDERSCORE_IN_DOMAIN,
                        severity = PhishingDomainSeverity.LOW,
                        score = 0.05f,
                        description =
                            "A domain label contains an underscore."
                    )
                )
            }

            if (label.contains("%")) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.ENCODED_DOMAIN_CHARACTER,
                        severity = PhishingDomainSeverity.MEDIUM,
                        score = 0.12f,
                        description =
                            "The domain contains a percent-encoded character pattern."
                    )
                )
            }
        }
    }

    /**
     * Detects excessive subdomain depth.
     */
    private fun analyzeSubdomains(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val labels = domain
            .split(".")
            .filter { it.isNotBlank() }

        if (labels.size > MAX_NORMAL_LABELS) {

            val subdomainCount =
                (labels.size - 2)
                    .coerceAtLeast(0)

            when {

                subdomainCount >= 5 -> {

                    findings.add(
                        finding(
                            type = PhishingDomainIndicator.EXCESSIVE_SUBDOMAINS,
                            severity = PhishingDomainSeverity.HIGH,
                            score = 0.20f,
                            description =
                                "The domain contains an unusually deep subdomain hierarchy."
                        )
                    )
                }

                subdomainCount >= 3 -> {

                    findings.add(
                        finding(
                            type = PhishingDomainIndicator.MULTIPLE_SUBDOMAINS,
                            severity = PhishingDomainSeverity.LOW,
                            score = 0.07f,
                            description =
                                "The domain contains multiple subdomains."
                        )
                    )
                }
            }
        }
    }

    /**
     * Analyzes TLD characteristics.
     */
    private fun analyzeTld(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        val tld = extractTld(domain)
            ?: return

        if (HIGH_RISK_TLDS.contains(tld)) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.HIGH_RISK_TLD,
                    severity = PhishingDomainSeverity.LOW,
                    score = 0.08f,
                    description =
                        "The domain uses a potentially higher-risk TLD: .$tld."
                )
            )
        }

        if (tld.length == 1) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.UNUSUAL_TLD,
                    severity = PhishingDomainSeverity.LOW,
                    score = 0.05f,
                    description =
                        "The domain uses an unusually short TLD."
                )
            )
        }
    }

    /**
     * Detects punycode.
     */
    private fun analyzePunycode(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (!domain.contains("xn--", ignoreCase = true)) {
            return
        }

        val decoded = try {

            IDN.toUnicode(domain)

        } catch (_: Exception) {

            null
        }

        if (decoded != null) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.PUNYCODE_DOMAIN,
                    severity = PhishingDomainSeverity.MEDIUM,
                    score = 0.15f,
                    description =
                        "The domain contains an internationalized/punycode label."
                )
            )

        } else {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.INVALID_PUNYCODE,
                    severity = PhishingDomainSeverity.HIGH,
                    score = 0.25f,
                    description =
                        "The domain contains a malformed punycode representation."
                )
            )
        }
    }

    /**
     * Analyzes the character distribution of domain labels.
     */
    private fun analyzeCharacterDistribution(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val labels = domain
            .split(".")
            .filter { it.isNotBlank() }

        labels.forEach { label ->

            val letters = label.count {
                it.isLetter()
            }

            val digits = label.count {
                it.isDigit()
            }

            val total = label.length

            if (total > 8) {

                val digitRatio =
                    digits.toFloat() / total.toFloat()

                if (digitRatio >= 0.60f) {

                    findings.add(
                        finding(
                            type = PhishingDomainIndicator.HIGH_DIGIT_RATIO,
                            severity = PhishingDomainSeverity.MEDIUM,
                            score = 0.10f,
                            description =
                                "A domain label contains an unusually high ratio of digits."
                        )
                    )
                }
            }

            if (letters > 0 &&
                digits > 0 &&
                label.length >= 10
            ) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.MIXED_ALPHANUMERIC_LABEL,
                        severity = PhishingDomainSeverity.LOW,
                        score = 0.05f,
                        description =
                            "A domain label mixes letters and digits."
                    )
                )
            }
        }
    }

    /**
     * Detects excessive numeric usage across the domain.
     */
    private fun analyzeDigitUsage(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val digits = domain.count {
            it.isDigit()
        }

        if (digits >= 8) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.EXCESSIVE_DIGITS,
                    severity = PhishingDomainSeverity.MEDIUM,
                    score = 0.10f,
                    description =
                        "The domain contains an unusually large number of digits."
                )
            )
        }
    }

    /**
     * Detects suspicious hyphen usage.
     */
    private fun analyzeHyphenUsage(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val hyphenCount = domain.count {
            it == '-'
        }

        when {

            hyphenCount >= 5 -> {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.EXCESSIVE_HYPHENS,
                        severity = PhishingDomainSeverity.MEDIUM,
                        score = 0.12f,
                        description =
                            "The domain contains an unusually high number of hyphens."
                    )
                )
            }

            hyphenCount >= 3 -> {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.MULTIPLE_HYPHENS,
                        severity = PhishingDomainSeverity.LOW,
                        score = 0.06f,
                        description =
                            "The domain contains multiple hyphens."
                    )
                )
            }
        }
    }

    /**
     * Estimates domain entropy.
     *
     * High entropy can indicate generated/randomized hostnames.
     * It is only a heuristic.
     */
    private fun analyzeEntropy(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        if (isIpAddress(domain)) {
            return
        }

        val baseDomain = extractBaseDomain(domain)

        val entropy = calculateEntropy(
            baseDomain
        )

        if (entropy >= 4.0) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.HIGH_DOMAIN_ENTROPY,
                    severity = PhishingDomainSeverity.MEDIUM,
                    score = 0.10f,
                    description =
                        "The apparent base domain has a relatively high character entropy."
                )
            )
        }
    }

    /**
     * Detects security-sensitive terms in domains.
     */
    private fun analyzeSuspiciousTerms(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        val normalized = domain
            .lowercase(Locale.ROOT)

        val matches = SUSPICIOUS_DOMAIN_TERMS
            .filter {
                normalized.contains(it)
            }
            .distinct()

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.SENSITIVE_DOMAIN_TERMS,
                    severity = PhishingDomainSeverity.LOW,
                    score = (matches.size * 0.04f)
                        .coerceAtMost(0.16f),
                    description =
                        "The domain contains security-sensitive terminology."
                )
            )
        }
    }

    /**
     * Detects possible brand impersonation.
     *
     * Example:
     *
     * secure-paypal-login.example.net
     *
     * The presence of a brand term is not sufficient for a malicious
     * verdict. The analyzer checks whether the apparent base domain
     * actually belongs to the protected brand.
     */
    private fun analyzeBrandImpersonation(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        val normalizedDomain =
            domain.lowercase(Locale.ROOT)

        val baseDomain =
            extractBaseDomain(normalizedDomain)

        PROTECTED_BRANDS.forEach { (brand, legitimateDomains) ->

            if (!normalizedDomain.contains(brand)) {
                return@forEach
            }

            val belongsToBrand =
                legitimateDomains.any { legitimateDomain ->
                    baseDomain == legitimateDomain ||
                            baseDomain.endsWith(
                                ".$legitimateDomain"
                            )
                }

            if (!belongsToBrand) {

                findings.add(
                    finding(
                        type = PhishingDomainIndicator.POSSIBLE_BRAND_IMPERSONATION,
                        severity = PhishingDomainSeverity.MEDIUM,
                        score = 0.18f,
                        description =
                            "The domain contains the protected brand term '$brand' outside its known domain."
                    )
                )
            }
        }
    }

    /**
     * Detects domains hosted under common free/static hosting platforms.
     *
     * These platforms are legitimate and are therefore treated only
     * as contextual indicators.
     */
    private fun analyzeHostingProviderPattern(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        val normalized =
            domain.lowercase(Locale.ROOT)

        val provider = FREE_HOSTING_DOMAINS
            .firstOrNull { hostedDomain ->
                normalized == hostedDomain ||
                        normalized.endsWith(
                            ".$hostedDomain"
                        )
            }

        if (provider != null) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.HOSTED_PLATFORM_DOMAIN,
                    severity = PhishingDomainSeverity.LOW,
                    score = 0.04f,
                    description =
                        "The domain appears to be hosted under a commonly used shared/static hosting platform."
                )
            )
        }
    }

    /**
     * Detects URL shortener domains.
     */
    private fun analyzeUrlShortener(
        domain: String,
        findings: MutableList<PhishingDomainFinding>
    ) {

        val normalized =
            domain.lowercase(Locale.ROOT)

        if (URL_SHORTENERS.contains(normalized)) {

            findings.add(
                finding(
                    type = PhishingDomainIndicator.URL_SHORTENER_DOMAIN,
                    severity = PhishingDomainSeverity.LOW,
                    score = 0.08f,
                    description =
                        "The domain belongs to a known URL-shortening service."
                )
            )
        }
    }

    /**
     * Calculates Shannon entropy.
     */
    private fun calculateEntropy(
        value: String
    ): Double {

        if (value.isEmpty()) {
            return 0.0
        }

        val frequency =
            value.groupingBy {
                it
            }.eachCount()

        val length =
            value.length.toDouble()

        return frequency.values.sumOf { count ->

            val probability =
                count / length

            -probability *
                    (kotlin.math.log(probability, 2.0))
        }
    }

    /**
     * Calculates final domain risk.
     */
    private fun calculateRiskScore(
        findings: List<PhishingDomainFinding>
    ): Float {

        if (findings.isEmpty()) {
            return 0.0f
        }

        val limitedFindings =
            findings
                .sortedByDescending {
                    it.score
                }
                .take(30)

        var score =
            limitedFindings
                .sumOf {
                    it.score.toDouble()
                }
                .toFloat()

        val highSeverityCount =
            limitedFindings.count {
                it.severity ==
                        PhishingDomainSeverity.HIGH
            }

        val mediumSeverityCount =
            limitedFindings.count {
                it.severity ==
                        PhishingDomainSeverity.MEDIUM
            }

        val criticalSeverityCount =
            limitedFindings.count {
                it.severity ==
                        PhishingDomainSeverity.CRITICAL
            }

        if (criticalSeverityCount > 0) {
            score += 0.20f
        }

        if (highSeverityCount >= 2) {
            score += 0.15f
        }

        if (mediumSeverityCount >= 3) {
            score += 0.08f
        }

        return score.coerceIn(
            0.0f,
            1.0f
        )
    }

    /**
     * Converts risk score to classification.
     */
    private fun classify(
        score: Float
    ): PhishingDomainClassification {

        return when {

            score >= HIGH_RISK_THRESHOLD ->
                PhishingDomainClassification.HIGH

            score >= MEDIUM_RISK_THRESHOLD ->
                PhishingDomainClassification.MEDIUM

            score >= LOW_RISK_THRESHOLD ->
                PhishingDomainClassification.LOW

            else ->
                PhishingDomainClassification.SAFE
        }
    }

    /**
     * Builds the final domain analysis.
     */
    private fun buildResult(
        domain: String,
        findings: List<PhishingDomainFinding>
    ): PhishingDomainAnalysis {

        val limitedFindings =
            findings
                .distinctBy {
                    "${it.type}:${it.description}"
                }
                .sortedByDescending {
                    it.score
                }
                .take(30)

        val riskScore =
            calculateRiskScore(
                limitedFindings
            )

        val classification =
            classify(
                riskScore
            )

        return PhishingDomainAnalysis(
            domain = domain,
            baseDomain = extractBaseDomain(domain),
            tld = extractTld(domain),
            subdomainCount = countSubdomains(domain),
            riskScore = riskScore,
            classification = classification,
            isSuspicious =
                classification !=
                        PhishingDomainClassification.SAFE,
            findings = limitedFindings
        )
    }

    /**
     * Creates a finding.
     */
    private fun finding(
        type: PhishingDomainIndicator,
        severity: PhishingDomainSeverity,
        score: Float,
        description: String
    ): PhishingDomainFinding {

        return PhishingDomainFinding(
            type = type,
            severity = severity,
            score = score.coerceIn(
                0.0f,
                1.0f
            ),
            description = description
        )
    }

    /**
     * Validates domain input.
     */
    private fun validateDomain(
        domain: String
    ) {

        require(domain.isNotBlank()) {
            "Domain must not be blank."
        }

        val normalized =
            normalizeDomain(domain)

        require(normalized.length <= MAX_DOMAIN_LENGTH) {
            "Domain exceeds the maximum supported length."
        }

        require(
            normalized.isNotBlank()
        ) {
            "Domain is invalid."
        }
    }

    /**
     * Checks coroutine cancellation.
     */
    private suspend fun checkCancellation() {

        if (!kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Phishing domain analysis was cancelled."
            )
        }
    }
}

/**
 * Complete result produced by PhishingDomainAnalyzer.
 */
data class PhishingDomainAnalysis(

    /**
     * Normalized analyzed domain.
     */
    val domain: String,

    /**
     * Apparent base domain.
     */
    val baseDomain: String,

    /**
     * Top-level domain.
     */
    val tld: String?,

    /**
     * Number of apparent subdomain labels.
     */
    val subdomainCount: Int,

    /**
     * Normalized risk score from 0.0 to 1.0.
     */
    val riskScore: Float,

    /**
     * Overall domain classification.
     */
    val classification: PhishingDomainClassification,

    /**
     * Whether significant local indicators were detected.
     */
    val isSuspicious: Boolean,

    /**
     * Individual domain findings.
     */
    val findings: List<PhishingDomainFinding>
)

/**
 * Individual domain-level phishing finding.
 */
data class PhishingDomainFinding(

    /**
     * Indicator type.
     */
    val type: PhishingDomainIndicator,

    /**
     * Indicator severity.
     */
    val severity: PhishingDomainSeverity,

    /**
     * Contribution to risk score.
     */
    val score: Float,

    /**
     * Human-readable explanation.
     */
    val description: String
)

/**
 * Domain phishing classification.
 */
enum class PhishingDomainClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH
}

/**
 * Severity of a domain indicator.
 */
enum class PhishingDomainSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Domain-level phishing indicators.
 */
enum class PhishingDomainIndicator {

    EXCESSIVE_DOMAIN_LENGTH,

    REPEATED_DOTS,

    INVALID_DOMAIN_BOUNDARY,

    IP_ADDRESS_DOMAIN,

    EXCESSIVE_LABEL_LENGTH,

    INVALID_HYPHEN_BOUNDARY,

    UNDERSCORE_IN_DOMAIN,

    ENCODED_DOMAIN_CHARACTER,

    EXCESSIVE_SUBDOMAINS,

    MULTIPLE_SUBDOMAINS,

    HIGH_RISK_TLD,

    UNUSUAL_TLD,

    PUNYCODE_DOMAIN,

    INVALID_PUNYCODE,

    HIGH_DIGIT_RATIO,

    MIXED_ALPHANUMERIC_LABEL,

    EXCESSIVE_DIGITS,

    EXCESSIVE_HYPHENS,

    MULTIPLE_HYPHENS,

    HIGH_DOMAIN_ENTROPY,

    SENSITIVE_DOMAIN_TERMS,

    POSSIBLE_BRAND_IMPERSONATION,

    HOSTED_PLATFORM_DOMAIN,

    URL_SHORTENER_DOMAIN
}

/**
 * DNS resolution result.
 */
data class DomainDnsResult(

    /**
     * Domain that was resolved.
     */
    val domain: String,

    /**
     * Whether resolution returned at least one address.
     */
    val resolved: Boolean,

    /**
     * Resolved addresses.
     */
    val addresses: List<String>,

    /**
     * Error message if resolution failed.
     */
    val error: String?
)
