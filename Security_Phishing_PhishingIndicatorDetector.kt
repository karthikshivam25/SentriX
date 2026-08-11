package com.sentrix.security.phishing

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.util.Locale

/**
 * PhishingIndicatorDetector
 *
 * Technical/contextual indicator extraction engine for SentriX.
 *
 * This component identifies observable indicators that may contribute
 * to a phishing determination.
 *
 * Responsibilities:
 *
 * - Extract URLs from arbitrary content.
 * - Extract domains from URLs.
 * - Detect IP-address URLs.
 * - Detect URL shorteners.
 * - Detect suspicious URL schemes.
 * - Detect excessive URL encoding.
 * - Detect suspicious host formatting.
 * - Detect email addresses.
 * - Detect suspicious sender/address patterns.
 * - Detect brand references.
 * - Detect sensitive-action context.
 * - Detect suspicious link text.
 * - Detect Unicode/obfuscation indicators.
 * - Detect multiple URLs.
 * - Produce structured indicator evidence.
 *
 * This class does NOT:
 *
 * - Perform final phishing classification.
 * - Query external threat intelligence.
 * - Perform DNS reputation.
 * - Perform WHOIS/RDAP lookup.
 * - Block URLs.
 * - Decide whether a sender is malicious.
 *
 * Those responsibilities belong to higher-level SentriX components.
 *
 * Architecture:
 *
 * PhishingContentAnalyzer
 *          |
 *          v
 * PhishingIndicatorDetector
 *          |
 *          +--> URL indicators
 *          +--> Domain indicators
 *          +--> Email indicators
 *          +--> Obfuscation indicators
 *          +--> Brand indicators
 *          +--> Action indicators
 *          |
 *          v
 * PhishingRiskEvaluator
 */
class PhishingIndicatorDetector {

    companion object {

        private const val TAG = "PhishingIndicatorDetector"

        private const val MAX_CONTENT_LENGTH = 100_000

        private const val MAX_URLS = 50

        private const val MAX_EMAILS = 50

        private const val MAX_INDICATORS = 150

        private const val LOW_RISK_THRESHOLD = 0.25f
        private const val MEDIUM_RISK_THRESHOLD = 0.50f
        private const val HIGH_RISK_THRESHOLD = 0.75f

        /**
         * URL extraction.
         *
         * Supports HTTP/HTTPS URLs commonly found in:
         * SMS, email, chat, notifications and browser text.
         */
        private val URL_REGEX = Regex(
            "(?i)\\bhttps?://[^\\s<>\"'\\[\\]{}]+"
        )

        /**
         * Bare domain detection.
         *
         * This intentionally avoids treating every dotted string as
         * a domain.
         */
        private val DOMAIN_REGEX = Regex(
            "(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+" +
                    "[a-z]{2,63}\\b"
        )

        /**
         * Email extraction.
         */
        private val EMAIL_REGEX = Regex(
            "(?i)\\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+" +
                    "@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" +
                    "(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\\b"
        )

        /**
         * URL shortener domains.
         */
        private val URL_SHORTENER_DOMAINS = setOf(
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
         * Suspicious schemes.
         *
         * HTTP is not automatically malicious, but it is less
         * protective than HTTPS.
         */
        private val SUSPICIOUS_SCHEMES = setOf(
            "http",
            "ftp",
            "file",
            "javascript",
            "data"
        )

        /**
         * Sensitive-action keywords.
         */
        private val SENSITIVE_ACTION_TERMS = listOf(
            "login",
            "log in",
            "signin",
            "sign in",
            "verify",
            "verification",
            "confirm",
            "confirmation",
            "update",
            "reset",
            "unlock",
            "activate",
            "authenticate",
            "authentication",
            "payment",
            "pay",
            "wallet",
            "banking",
            "account",
            "security",
            "password",
            "otp",
            "pin"
        )

        /**
         * High-value brands commonly targeted by phishing attacks.
         *
         * This should eventually be moved into SentriX threat
         * intelligence/configuration storage.
         */
        private val PROTECTED_BRANDS = setOf(
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
            "paytm",
            "phonepe",
            "sbi",
            "hdfc",
            "icici",
            "axis",
            "googlepay",
            "gpay"
        )

        /**
         * Suspicious URL/path terminology.
         */
        private val SENSITIVE_PATH_TERMS = listOf(
            "login",
            "signin",
            "verify",
            "verification",
            "account",
            "secure",
            "security",
            "password",
            "reset",
            "unlock",
            "payment",
            "billing",
            "wallet",
            "authenticate",
            "confirm"
        )

        /**
         * Common URL obfuscation characters.
         */
        private val OBFUSCATION_CHARACTERS = setOf(
            '%',
            '\\',
            '@'
        )

        /**
         * Unicode ranges that can sometimes be involved in
         * visually deceptive text.
         *
         * Detection is contextual only.
         */
        private val COMMON_LATIN_EXTENSIONS =
            setOf(
                'é',
                'è',
                'ê',
                'á',
                'à',
                'ä',
                'ö',
                'ü',
                'ñ',
                'ç'
            )
    }

    /**
     * Performs complete indicator detection.
     */
    suspend fun detect(
        content: String
    ): PhishingIndicatorDetectionResult =
        withContext(Dispatchers.Default) {

            validateContent(content)

            checkCancellation()

            val normalized =
                normalizeContent(content)

            Log.d(
                TAG,
                "Starting phishing indicator detection."
            )

            val indicators =
                mutableListOf<PhishingIndicator>()

            val urls =
                extractUrls(content)

            val emails =
                extractEmails(content)

            detectUrlIndicators(
                urls = urls,
                content = normalized,
                indicators = indicators
            )

            detectBareDomains(
                content = normalized,
                urls = urls,
                indicators = indicators
            )

            detectEmailIndicators(
                emails = emails,
                indicators = indicators
            )

            detectBrandIndicators(
                content = normalized,
                indicators = indicators
            )

            detectSensitiveActionIndicators(
                content = normalized,
                indicators = indicators
            )

            detectObfuscationIndicators(
                content = content,
                indicators = indicators
            )

            detectMultipleLinkIndicators(
                urls = urls,
                indicators = indicators
            )

            detectUnicodeIndicators(
                content = content,
                indicators = indicators
            )

            val finalIndicators =
                indicators
                    .distinctBy {
                        buildDeduplicationKey(it)
                    }
                    .sortedByDescending {
                        it.score
                    }
                    .take(MAX_INDICATORS)

            val score =
                calculateRiskScore(
                    finalIndicators
                )

            val classification =
                classify(score)

            Log.d(
                TAG,
                "Indicator detection completed. " +
                        "indicators=${finalIndicators.size}, " +
                        "risk=$score"
            )

            PhishingIndicatorDetectionResult(
                originalContent = content,
                normalizedContent = normalized,
                riskScore = score,
                classification = classification,
                isSuspicious =
                    classification !=
                            PhishingIndicatorClassification.SAFE,
                indicators = finalIndicators,
                extractedUrls = urls,
                extractedEmails = emails
            )
        }

    /**
     * Detects indicators for a single URL.
     */
    suspend fun detectUrl(
        url: String
    ): List<PhishingIndicator> =
        withContext(Dispatchers.Default) {

            require(url.isNotBlank()) {
                "URL must not be blank."
            }

            val indicators =
                mutableListOf<PhishingIndicator>()

            analyzeSingleUrl(
                url = cleanUrl(url),
                indicators = indicators
            )

            indicators
                .distinctBy {
                    buildDeduplicationKey(it)
                }
                .sortedByDescending {
                    it.score
                }
        }

    /**
     * Detects indicators in a single email address.
     */
    fun detectEmail(
        email: String
    ): List<PhishingIndicator> {

        require(email.isNotBlank()) {
            "Email address must not be blank."
        }

        val indicators =
            mutableListOf<PhishingIndicator>()

        analyzeSingleEmail(
            email = email.trim(),
            indicators = indicators
        )

        return indicators
            .distinctBy {
                buildDeduplicationKey(it)
            }
            .sortedByDescending {
                it.score
            }
    }

    /**
     * Extracts URLs from content.
     */
    fun extractUrls(
        content: String
    ): List<String> {

        return URL_REGEX
            .findAll(content)
            .map {
                cleanUrl(it.value)
            }
            .filter {
                it.isNotBlank()
            }
            .distinct()
            .take(MAX_URLS)
            .toList()
    }

    /**
     * Extracts bare domains from content.
     */
    fun extractDomains(
        content: String
    ): List<String> {

        return DOMAIN_REGEX
            .findAll(content)
            .map {
                it.value.lowercase(Locale.ROOT)
            }
            .distinct()
            .take(MAX_URLS)
            .toList()
    }

    /**
     * Extracts email addresses.
     */
    fun extractEmails(
        content: String
    ): List<String> {

        return EMAIL_REGEX
            .findAll(content)
            .map {
                it.value.lowercase(Locale.ROOT)
            }
            .distinct()
            .take(MAX_EMAILS)
            .toList()
    }

    /**
     * Returns whether the supplied content contains a URL.
     */
    fun containsUrl(
        content: String
    ): Boolean {

        return URL_REGEX.containsMatchIn(
            content
        )
    }

    /**
     * Returns whether content contains an email address.
     */
    fun containsEmail(
        content: String
    ): Boolean {

        return EMAIL_REGEX.containsMatchIn(
            content
        )
    }

    /**
     * Detects URL-related indicators.
     */
    private fun detectUrlIndicators(
        urls: List<String>,
        content: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        urls.forEach { url ->

            analyzeSingleUrl(
                url = url,
                indicators = indicators
            )

            /*
             * Check whether surrounding message text contains
             * sensitive actions.
             */
            if (
                SENSITIVE_ACTION_TERMS.any {
                    content.contains(it)
                }
            ) {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.URL_WITH_SENSITIVE_ACTION,
                        severity =
                            PhishingIndicatorSeverity.MEDIUM,
                        score =
                            0.12f,
                        value =
                            url,
                        description =
                            "A URL appears in content containing a security-sensitive action."
                    )
                )
            }
        }
    }

    /**
     * Performs detailed analysis of one URL.
     */
    private fun analyzeSingleUrl(
        url: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val normalizedUrl =
            cleanUrl(url)

        val uri =
            try {
                URI(normalizedUrl)
            } catch (_: Exception) {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.MALFORMED_URL,
                        severity =
                            PhishingIndicatorSeverity.MEDIUM,
                        score =
                            0.12f,
                        value =
                            normalizedUrl,
                        description =
                            "The URL could not be parsed reliably."
                    )
                )

                return
            }

        val scheme =
            uri.scheme
                ?.lowercase(Locale.ROOT)

        val host =
            uri.host
                ?.lowercase(Locale.ROOT)

        if (scheme == null) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.MISSING_URL_SCHEME,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.04f,
                    value =
                        normalizedUrl,
                    description =
                        "The URL does not expose a conventional URI scheme."
                )
            )
        }

        if (
            scheme != null &&
            SUSPICIOUS_SCHEMES.contains(
                scheme
            )
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.SUSPICIOUS_URL_SCHEME,
                    severity =
                        when (scheme) {
                            "javascript",
                            "data" ->
                                PhishingIndicatorSeverity.HIGH

                            "ftp",
                            "file" ->
                                PhishingIndicatorSeverity.MEDIUM

                            else ->
                                PhishingIndicatorSeverity.LOW
                        },
                    score =
                        when (scheme) {
                            "javascript",
                            "data" ->
                                0.25f

                            "ftp",
                            "file" ->
                                0.12f

                            "http" ->
                                0.05f

                            else ->
                                0.04f
                        },
                    value =
                        scheme,
                    description =
                        "The URL uses a scheme requiring additional security scrutiny."
                )
            )
        }

        if (
            scheme == "http"
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.INSECURE_HTTP,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.05f,
                    value =
                        normalizedUrl,
                    description =
                        "The URL uses HTTP instead of HTTPS."
                )
            )
        }

        if (host == null) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.MISSING_HOST,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        normalizedUrl,
                    description =
                        "The URL does not expose a conventional hostname."
                )
            )

            return
        }

        analyzeHost(
            host = host,
            indicators = indicators
        )

        analyzeUrlPath(
            path = uri.path ?: "",
            indicators = indicators
        )

        analyzeQuery(
            query = uri.rawQuery ?: "",
            indicators = indicators
        )

        analyzeUrlEncoding(
            url = normalizedUrl,
            indicators = indicators
        )

        analyzeUserInfo(
            uri = uri,
            indicators = indicators
        )
    }

    /**
     * Analyzes URL hostname characteristics.
     */
    private fun analyzeHost(
        host: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        if (isIpAddress(host)) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.IP_ADDRESS_HOST,
                    severity =
                        PhishingIndicatorSeverity.HIGH,
                    score =
                        0.22f,
                    value =
                        host,
                    description =
                        "The URL uses an IP address instead of a conventional domain."
                )
            )
        }

        if (
            host.contains(
                "xn--"
            )
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.PUNYCODE_HOST,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.15f,
                    value =
                        host,
                    description =
                        "The hostname contains a punycode label."
                )
            )
        }

        val labels =
            host.split(".")
                .filter {
                    it.isNotBlank()
                }

        if (labels.size >= 5) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.DEEP_HOSTNAME,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.12f,
                    value =
                        host,
                    description =
                        "The hostname contains an unusually deep label hierarchy."
                )
            )
        }

        val hyphenCount =
            host.count {
                it == '-'
            }

        if (hyphenCount >= 4) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.EXCESSIVE_HOST_HYPHENS,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        host,
                    description =
                        "The hostname contains multiple hyphens."
                )
            )
        }

        if (
            URL_SHORTENER_DOMAINS.contains(
                host
            )
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.URL_SHORTENER,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        host,
                    description =
                        "The URL uses a known URL-shortening service."
                )
            )
        }

        val digitCount =
            host.count {
                it.isDigit()
            }

        if (
            host.length >= 12 &&
            digitCount >= 5
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.NUMERIC_HOST,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        host,
                    description =
                        "The hostname contains an unusually high number of digits."
                )
            )
        }
    }

    /**
     * Analyzes URL path.
     */
    private fun analyzeUrlPath(
        path: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        if (path.isBlank()) {
            return
        }

        val normalized =
            path.lowercase(Locale.ROOT)

        val matches =
            SENSITIVE_PATH_TERMS.filter {
                normalized.contains(it)
            }

        if (matches.isNotEmpty()) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.SENSITIVE_URL_PATH,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        (matches.size * 0.05f)
                            .coerceAtMost(0.20f),
                    value =
                        path,
                    description =
                        "The URL path contains security-sensitive terminology."
                )
            )
        }

        if (
            path.length >= 150
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.EXCESSIVE_URL_PATH_LENGTH,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.05f,
                    value =
                        path,
                    description =
                        "The URL contains an unusually long path."
                )
            )
        }
    }

    /**
     * Analyzes query parameters.
     */
    private fun analyzeQuery(
        query: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        if (query.isBlank()) {
            return
        }

        val normalized =
            query.lowercase(Locale.ROOT)

        val sensitiveTerms =
            listOf(
                "password",
                "passwd",
                "passcode",
                "otp",
                "pin",
                "cvv",
                "card",
                "token",
                "session",
                "auth",
                "redirect",
                "returnurl",
                "url"
            )

        val matches =
            sensitiveTerms.filter {
                normalized.contains(it)
            }

        if (matches.isNotEmpty()) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.SENSITIVE_QUERY_PARAMETER,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        (matches.size * 0.06f)
                            .coerceAtMost(0.24f),
                    value =
                        "[redacted query]",
                    description =
                        "The URL query contains security-sensitive parameter names."
                )
            )
        }

        val parameterCount =
            query.count {
                it == '&'
            } + 1

        if (
            parameterCount >= 8
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.EXCESSIVE_QUERY_PARAMETERS,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.06f,
                    value =
                        parameterCount.toString(),
                    description =
                        "The URL contains an unusually large number of query parameters."
                )
            )
        }
    }

    /**
     * Detects URL encoding/obfuscation.
     */
    private fun analyzeUrlEncoding(
        url: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val percentCount =
            url.count {
                it == '%'
            }

        if (percentCount >= 5) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.EXCESSIVE_URL_ENCODING,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.12f,
                    value =
                        "percent-encoded=$percentCount",
                    description =
                        "The URL contains a relatively high amount of percent encoding."
                )
            )
        }

        if (
            url.contains(
                "%40",
                ignoreCase = true
            )
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.ENCODED_AT_SYMBOL,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        "%40",
                    description =
                        "The URL contains an encoded @ character."
                )
            )
        }
    }

    /**
     * Detects URL user-information fields.
     *
     * Example:
     *
     * https://username@example.com
     */
    private fun analyzeUserInfo(
        uri: URI,
        indicators: MutableList<PhishingIndicator>
    ) {

        if (
            !uri.rawUserInfo.isNullOrBlank()
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.URL_USER_INFO,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.14f,
                    value =
                        "[redacted]",
                    description =
                        "The URL contains user-information data before the hostname."
                )
            )
        }
    }

    /**
     * Detects bare domains that are not already represented by
     * extracted URLs.
     */
    private fun detectBareDomains(
        content: String,
        urls: List<String>,
        indicators: MutableList<PhishingIndicator>
    ) {

        val domains =
            extractDomains(content)

        if (domains.isEmpty()) {
            return
        }

        val urlHosts =
            urls.mapNotNull {
                try {
                    URI(it).host
                } catch (_: Exception) {
                    null
                }
            }.map {
                it.lowercase(Locale.ROOT)
            }.toSet()

        domains.forEach { domain ->

            if (
                !urlHosts.contains(
                    domain
                )
            ) {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.BARE_DOMAIN,
                        severity =
                            PhishingIndicatorSeverity.LOW,
                        score =
                            0.04f,
                        value =
                            domain,
                        description =
                            "The content contains a domain without an explicit URL scheme."
                    )
                )
            }
        }
    }

    /**
     * Analyzes email addresses.
     */
    private fun detectEmailIndicators(
        emails: List<String>,
        indicators: MutableList<PhishingIndicator>
    ) {

        emails.forEach { email ->

            analyzeSingleEmail(
                email = email,
                indicators = indicators
            )
        }
    }

    /**
     * Detailed email analysis.
     */
    private fun analyzeSingleEmail(
        email: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val normalized =
            email.lowercase(Locale.ROOT)

        val parts =
            normalized.split("@")

        if (parts.size != 2) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.MALFORMED_EMAIL,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        email,
                    description =
                        "The email address does not have a conventional structure."
                )
            )

            return
        }

        val localPart =
            parts[0]

        val domain =
            parts[1]

        if (
            localPart.length >= 40
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.LONG_EMAIL_LOCAL_PART,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.04f,
                    value =
                        "[redacted]",
                    description =
                        "The email address has an unusually long local part."
                )
            )
        }

        if (
            localPart.count {
                it.isDigit()
            } >= 6
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.NUMERIC_EMAIL_LOCAL_PART,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.04f,
                    value =
                        "[redacted]",
                    description =
                        "The email address contains an unusually high number of digits."
                )
            )
        }

        if (
            domain.contains(
                "xn--"
            )
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.PUNYCODE_EMAIL_DOMAIN,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.12f,
                    value =
                        domain,
                    description =
                        "The email domain contains a punycode label."
                )
            )
        }

        val suspiciousTerms =
            SENSITIVE_ACTION_TERMS.filter {
                localPart.contains(
                    it.replace(
                        " ",
                        ""
                    )
                )
            }

        if (
            suspiciousTerms.isNotEmpty()
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.SENSITIVE_EMAIL_ALIAS,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.06f,
                    value =
                        "[redacted]",
                    description =
                        "The email alias contains security-sensitive terminology."
                )
            )
        }

        detectBrandEmailImpersonation(
            localPart = localPart,
            domain = domain,
            indicators = indicators
        )
    }

    /**
     * Detects possible brand impersonation in an email address.
     */
    private fun detectBrandEmailImpersonation(
        localPart: String,
        domain: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        PROTECTED_BRANDS.forEach { brand ->

            val brandMentioned =
                localPart.contains(
                    brand
                ) ||
                        domain.contains(
                            brand
                        )

            if (!brandMentioned) {
                return@forEach
            }

            val expectedOfficialDomain =
                when (brand) {

                    "paypal" ->
                        "paypal.com"

                    "microsoft" ->
                        "microsoft.com"

                    "google",
                    "googlepay",
                    "gpay" ->
                        "google.com"

                    "apple" ->
                        "apple.com"

                    "amazon" ->
                        "amazon.com"

                    "facebook" ->
                        "facebook.com"

                    "instagram" ->
                        "instagram.com"

                    "whatsapp" ->
                        "whatsapp.com"

                    "netflix" ->
                        "netflix.com"

                    "linkedin" ->
                        "linkedin.com"

                    "paytm" ->
                        "paytm.com"

                    "phonepe" ->
                        "phonepe.com"

                    "sbi" ->
                        "sbi.co.in"

                    "hdfc" ->
                        "hdfcbank.com"

                    "icici" ->
                        "icicibank.com"

                    "axis" ->
                        "axisbank.com"

                    else ->
                        null
                }

            if (
                expectedOfficialDomain != null &&
                !domain.endsWith(
                    expectedOfficialDomain
                )
            ) {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.POSSIBLE_BRAND_EMAIL_IMPERSONATION,
                        severity =
                            PhishingIndicatorSeverity.MEDIUM,
                        score =
                            0.16f,
                        value =
                            domain,
                        description =
                            "The email references a protected brand but does not use its expected domain."
                    )
                )
            }
        }
    }

    /**
     * Detects brand references in message content.
     */
    private fun detectBrandIndicators(
        content: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val matches =
            PROTECTED_BRANDS.filter {
                content.contains(
                    it
                )
            }

        if (
            matches.isNotEmpty()
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.PROTECTED_BRAND_REFERENCE,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        (matches.size * 0.04f)
                            .coerceAtMost(0.16f),
                    value =
                        matches.joinToString(","),
                    description =
                        "The content references one or more commonly impersonated brands."
                )
            )
        }
    }

    /**
     * Detects sensitive-action context.
     */
    private fun detectSensitiveActionIndicators(
        content: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val matches =
            SENSITIVE_ACTION_TERMS.filter {
                content.contains(
                    it
                )
            }

        if (
            matches.isNotEmpty()
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.SENSITIVE_ACTION_LANGUAGE,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        (matches.size * 0.03f)
                            .coerceAtMost(0.15f),
                    value =
                        matches.joinToString(","),
                    description =
                        "The content contains security-sensitive action terminology."
                )
            )
        }
    }

    /**
     * Detects general text obfuscation.
     */
    private fun detectObfuscationIndicators(
        content: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val obfuscationCount =
            content.count {
                OBFUSCATION_CHARACTERS.contains(
                    it
                )
            }

        if (
            obfuscationCount >= 10
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.TEXT_OBFUSCATION,
                    severity =
                        PhishingIndicatorSeverity.MEDIUM,
                    score =
                        0.10f,
                    value =
                        "count=$obfuscationCount",
                    description =
                        "The content contains an unusually high number of characters sometimes associated with obfuscation."
                )
            )
        }
    }

    /**
     * Detects multiple links.
     */
    private fun detectMultipleLinkIndicators(
        urls: List<String>,
        indicators: MutableList<PhishingIndicator>
    ) {

        when {

            urls.size >= 5 -> {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.MULTIPLE_LINKS,
                        severity =
                            PhishingIndicatorSeverity.MEDIUM,
                        score =
                            0.10f,
                        value =
                            urls.size.toString(),
                        description =
                            "The content contains multiple URLs."
                    )
                )
            }

            urls.size >= 2 -> {

                indicators.add(
                    indicator(
                        type =
                            PhishingIndicatorType.MULTIPLE_LINKS,
                        severity =
                            PhishingIndicatorSeverity.LOW,
                        score =
                            0.04f,
                        value =
                            urls.size.toString(),
                        description =
                            "The content contains more than one URL."
                    )
                )
            }
        }
    }

    /**
     * Detects potentially unusual Unicode composition.
     *
     * This is deliberately conservative because legitimate messages
     * can contain Unicode characters.
     */
    private fun detectUnicodeIndicators(
        content: String,
        indicators: MutableList<PhishingIndicator>
    ) {

        val unicodeCharacters =
            content.count {
                it.code > 127
            }

        if (
            unicodeCharacters == 0
        ) {
            return
        }

        val nonLatinCharacters =
            content.count {
                it.isLetter() &&
                        it !in COMMON_LATIN_EXTENSIONS &&
                        it.code > 127
            }

        if (
            nonLatinCharacters >= 5
        ) {

            indicators.add(
                indicator(
                    type =
                        PhishingIndicatorType.UNICODE_TEXT,
                    severity =
                        PhishingIndicatorSeverity.LOW,
                    score =
                        0.04f,
                    value =
                        "unicode=$nonLatinCharacters",
                    description =
                        "The content contains non-ASCII characters requiring contextual analysis."
                )
            )
        }
    }

    /**
     * Calculates overall indicator risk.
     */
    private fun calculateRiskScore(
        indicators: List<PhishingIndicator>
    ): Float {

        if (
            indicators.isEmpty()
        ) {
            return 0.0f
        }

        val relevant =
            indicators
                .sortedByDescending {
                    it.score
                }
                .take(MAX_INDICATORS)

        var score =
            relevant.sumOf {
                it.score.toDouble()
            }.toFloat()

        val criticalCount =
            relevant.count {
                it.severity ==
                        PhishingIndicatorSeverity.CRITICAL
            }

        val highCount =
            relevant.count {
                it.severity ==
                        PhishingIndicatorSeverity.HIGH
            }

        val mediumCount =
            relevant.count {
                it.severity ==
                        PhishingIndicatorSeverity.MEDIUM
            }

        if (
            criticalCount > 0
        ) {
            score += 0.20f
        }

        if (
            criticalCount >= 2
        ) {
            score += 0.15f
        }

        if (
            highCount >= 2
        ) {
            score += 0.12f
        }

        if (
            mediumCount >= 3
        ) {
            score += 0.06f
        }

        return score.coerceIn(
            0.0f,
            1.0f
        )
    }

    /**
     * Converts score to classification.
     */
    private fun classify(
        score: Float
    ): PhishingIndicatorClassification {

        return when {

            score >= HIGH_RISK_THRESHOLD ->
                PhishingIndicatorClassification.HIGH

            score >= MEDIUM_RISK_THRESHOLD ->
                PhishingIndicatorClassification.MEDIUM

            score >= LOW_RISK_THRESHOLD ->
                PhishingIndicatorClassification.LOW

            else ->
                PhishingIndicatorClassification.SAFE
        }
    }

    /**
     * Creates an indicator object.
     */
    private fun indicator(
        type: PhishingIndicatorType,
        severity: PhishingIndicatorSeverity,
        score: Float,
        value: String,
        description: String
    ): PhishingIndicator {

        return PhishingIndicator(
            type = type,
            severity = severity,
            score = score.coerceIn(
                0.0f,
                1.0f
            ),
            value = value,
            description = description
        )
    }

    /**
     * Creates a stable deduplication key.
     */
    private fun buildDeduplicationKey(
        indicator: PhishingIndicator
    ): String {

        return listOf(
            indicator.type.name,
            indicator.value,
            indicator.description
        ).joinToString("|")
    }

    /**
     * Normalizes content.
     */
    private fun normalizeContent(
        content: String
    ): String {

        return content
            .trim()
            .replace(
                "\u0000",
                ""
            )
            .lowercase(
                Locale.ROOT
            )
            .replace(
                Regex("\\s+"),
                " "
            )
    }

    /**
     * Removes punctuation accidentally captured after URLs.
     */
    private fun cleanUrl(
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
     * Detects IPv4 and simple IPv6 addresses.
     */
    private fun isIpAddress(
        host: String
    ): Boolean {

        val ipv4 =
            Regex(
                "^\\d{1,3}(\\.\\d{1,3}){3}$"
            )

        if (
            ipv4.matches(host)
        ) {

            return host
                .split(".")
                .all {
                    try {
                        it.toInt() in 0..255
                    } catch (_: Exception) {
                        false
                    }
                }
        }

        return host.contains(":") &&
                host.matches(
                    Regex(
                        "^[0-9a-fA-F:]+$"
                    )
                )
    }

    /**
     * Validates content.
     */
    private fun validateContent(
        content: String
    ) {

        require(
            content.isNotBlank()
        ) {
            "Content must not be blank."
        }

        require(
            content.length <=
                    MAX_CONTENT_LENGTH
        ) {
            "Content exceeds the maximum supported length."
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
                "Phishing indicator detection was cancelled."
            )
        }
    }
}

/**
 * Complete indicator detection result.
 */
data class PhishingIndicatorDetectionResult(

    /**
     * Original content.
     */
    val originalContent: String,

    /**
     * Normalized content.
     */
    val normalizedContent: String,

    /**
     * Aggregated indicator risk score.
     */
    val riskScore: Float,

    /**
     * Overall indicator classification.
     */
    val classification: PhishingIndicatorClassification,

    /**
     * Whether significant indicators were detected.
     */
    val isSuspicious: Boolean,

    /**
     * Detected indicators.
     */
    val indicators: List<PhishingIndicator>,

    /**
     * URLs extracted from content.
     */
    val extractedUrls: List<String>,

    /**
     * Email addresses extracted from content.
     */
    val extractedEmails: List<String>
)

/**
 * Individual phishing indicator.
 */
data class PhishingIndicator(

    /**
     * Indicator type.
     */
    val type: PhishingIndicatorType,

    /**
     * Indicator severity.
     */
    val severity: PhishingIndicatorSeverity,

    /**
     * Indicator contribution to risk.
     */
    val score: Float,

    /**
     * Indicator value.
     *
     * Sensitive values should be redacted by higher-level logging
     * components before being persisted.
     */
    val value: String,

    /**
     * Human-readable explanation.
     */
    val description: String
)

/**
 * Types of technical/contextual phishing indicators.
 */
enum class PhishingIndicatorType {

    /**
     * URL could not be parsed.
     */
    MALFORMED_URL,

    /**
     * URL has no conventional scheme.
     */
    MISSING_URL_SCHEME,

    /**
     * Suspicious/non-standard URL scheme.
     */
    SUSPICIOUS_URL_SCHEME,

    /**
     * Plain HTTP URL.
     */
    INSECURE_HTTP,

    /**
     * URL has no hostname.
     */
    MISSING_HOST,

    /**
     * URL uses an IP address.
     */
    IP_ADDRESS_HOST,

    /**
     * Host uses punycode.
     */
    PUNYCODE_HOST,

    /**
     * Host contains many labels.
     */
    DEEP_HOSTNAME,

    /**
     * Host contains excessive hyphens.
     */
    EXCESSIVE_HOST_HYPHENS,

    /**
     * URL belongs to a URL-shortening service.
     */
    URL_SHORTENER,

    /**
     * Host contains many numeric characters.
     */
    NUMERIC_HOST,

    /**
     * URL path contains sensitive terminology.
     */
    SENSITIVE_URL_PATH,

    /**
     * URL path is unusually long.
     */
    EXCESSIVE_URL_PATH_LENGTH,

    /**
     * Query contains sensitive parameter names.
     */
    SENSITIVE_QUERY_PARAMETER,

    /**
     * URL contains many query parameters.
     */
    EXCESSIVE_QUERY_PARAMETERS,

    /**
     * URL contains excessive percent encoding.
     */
    EXCESSIVE_URL_ENCODING,

    /**
     * Encoded @ symbol.
     */
    ENCODED_AT_SYMBOL,

    /**
     * URL contains user-info component.
     */
    URL_USER_INFO,

    /**
     * Bare domain found in content.
     */
    BARE_DOMAIN,

    /**
     * Malformed email address.
     */
    MALFORMED_EMAIL,

    /**
     * Email local part is unusually long.
     */
    LONG_EMAIL_LOCAL_PART,

    /**
     * Email local part contains many digits.
     */
    NUMERIC_EMAIL_LOCAL_PART,

    /**
     * Email domain uses punycode.
     */
    PUNYCODE_EMAIL_DOMAIN,

    /**
     * Email alias contains sensitive terminology.
     */
    SENSITIVE_EMAIL_ALIAS,

    /**
     * Possible brand impersonation via email.
     */
    POSSIBLE_BRAND_EMAIL_IMPERSONATION,

    /**
     * Protected brand mentioned in content.
     */
    PROTECTED_BRAND_REFERENCE,

    /**
     * Security-sensitive action terminology.
     */
    SENSITIVE_ACTION_LANGUAGE,

    /**
     * Possible text obfuscation.
     */
    TEXT_OBFUSCATION,

    /**
     * Multiple URLs detected.
     */
    MULTIPLE_LINKS,

    /**
     * Non-ASCII/Unicode content requiring context.
     */
    UNICODE_TEXT,

    /**
     * URL appears alongside sensitive action language.
     */
    URL_WITH_SENSITIVE_ACTION
}

/**
 * Indicator severity.
 */
enum class PhishingIndicatorSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Overall indicator classification.
 */
enum class PhishingIndicatorClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH
}
