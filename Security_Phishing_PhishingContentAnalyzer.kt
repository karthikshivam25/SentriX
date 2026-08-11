package com.sentrix.security.phishing

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * PhishingContentAnalyzer
 *
 * Specialized analyzer responsible for detecting phishing and scam
 * indicators inside textual content.
 *
 * Supported content sources:
 *
 * - SMS messages
 * - Email content
 * - Push notifications
 * - Chat messages
 * - Browser-extracted text
 * - Clipboard content
 * - Payment-related messages
 * - Social-engineering messages
 *
 * Responsibilities:
 *
 * - Normalize content.
 * - Detect credential harvesting language.
 * - Detect OTP/PIN/password requests.
 * - Detect financial/payment requests.
 * - Detect urgency and fear tactics.
 * - Detect reward/prize scams.
 * - Detect impersonation language.
 * - Detect suspicious calls-to-action.
 * - Detect social-engineering combinations.
 * - Extract URLs from content.
 * - Delegate URL analysis to PhishingURLAnalyzer.
 * - Aggregate content and URL indicators.
 * - Produce a normalized risk score.
 *
 * IMPORTANT:
 *
 * Textual indicators alone do not prove that a message is malicious.
 * SentriX should combine this analyzer with:
 *
 * - Sender reputation
 * - Domain reputation
 * - Threat intelligence
 * - URL analysis
 * - Historical behavior
 * - User context
 * - ML/AI analysis
 *
 * Architecture:
 *
 * PhishingDetectionService
 *          |
 *          v
 * PhishingDetectionManager
 *          |
 *          v
 * PhishingContentAnalyzer
 *          |
 *          +--> Text indicators
 *          +--> Social engineering
 *          +--> Credential requests
 *          +--> Financial requests
 *          +--> URL extraction
 *          +--> PhishingURLAnalyzer
 *          +--> Risk aggregation
 */
class PhishingContentAnalyzer(
    private val urlAnalyzer: PhishingURLAnalyzer
) {

    companion object {

        private const val TAG = "PhishingContentAnalyzer"

        /**
         * Maximum content size supported.
         */
        private const val MAX_CONTENT_LENGTH = 100_000

        /**
         * Maximum URLs extracted from one message.
         */
        private const val MAX_EXTRACTED_URLS = 25

        /**
         * Risk thresholds.
         */
        private const val LOW_RISK_THRESHOLD = 0.25f
        private const val MEDIUM_RISK_THRESHOLD = 0.50f
        private const val HIGH_RISK_THRESHOLD = 0.75f

        /**
         * Credential-related terms.
         */
        private val CREDENTIAL_TERMS = listOf(
            "password",
            "passcode",
            "username",
            "user id",
            "userid",
            "login details",
            "login credentials",
            "credentials",
            "credential",
            "secret code",
            "security code"
        )

        /**
         * OTP-related terms.
         */
        private val OTP_TERMS = listOf(
            "otp",
            "one time password",
            "one-time password",
            "verification code",
            "verification otp",
            "security code",
            "authentication code"
        )

        /**
         * PIN-related terms.
         */
        private val PIN_TERMS = listOf(
            "pin",
            "upi pin",
            "atm pin",
            "card pin",
            "mpin",
            "passcode"
        )

        /**
         * Financial/payment terms.
         */
        private val FINANCIAL_TERMS = listOf(
            "bank",
            "bank account",
            "banking",
            "credit card",
            "debit card",
            "card number",
            "cvv",
            "upi",
            "upi payment",
            "payment",
            "transaction",
            "wallet",
            "net banking",
            "account balance",
            "refund",
            "invoice",
            "billing",
            "emi",
            "loan"
        )

        /**
         * Urgency and pressure indicators.
         */
        private val URGENCY_TERMS = listOf(
            "urgent",
            "urgently",
            "immediately",
            "act now",
            "action required",
            "immediate action",
            "last warning",
            "final warning",
            "within 24 hours",
            "within 48 hours",
            "expires today",
            "expires soon",
            "do it now",
            "respond immediately",
            "failure to act",
            "account will be blocked",
            "account will be suspended",
            "service will be terminated"
        )

        /**
         * Reward/prize scam terminology.
         */
        private val REWARD_TERMS = listOf(
            "you won",
            "you have won",
            "winner",
            "congratulations",
            "claim your reward",
            "claim reward",
            "claim prize",
            "free prize",
            "cash prize",
            "lottery",
            "lucky winner",
            "gift card",
            "cashback",
            "bonus",
            "reward points",
            "special offer"
        )

        /**
         * Account compromise terminology.
         */
        private val ACCOUNT_THREAT_TERMS = listOf(
            "account suspended",
            "account blocked",
            "account compromised",
            "account locked",
            "unusual activity",
            "suspicious activity",
            "unauthorized login",
            "unauthorized transaction",
            "security alert",
            "security warning",
            "verify your account",
            "confirm your identity",
            "identity verification"
        )

        /**
         * Common phishing actions.
         */
        private val PHISHING_ACTION_TERMS = listOf(
            "click here",
            "click the link",
            "tap here",
            "tap the link",
            "open this link",
            "verify now",
            "confirm now",
            "login now",
            "sign in now",
            "update now",
            "reset now",
            "unlock now",
            "activate now",
            "complete verification",
            "complete the verification"
        )

        /**
         * Sensitive information requests.
         */
        private val SENSITIVE_REQUEST_PATTERNS = listOf(
            "share your otp",
            "send your otp",
            "provide your otp",
            "enter your otp",
            "tell us your otp",
            "share the otp",
            "send the otp",
            "share your pin",
            "send your pin",
            "provide your pin",
            "enter your pin",
            "share your password",
            "send your password",
            "provide your password",
            "enter your password",
            "share your card details",
            "send your card details",
            "provide your card number",
            "send your cvv",
            "share your cvv",
            "share your bank details",
            "send your bank details"
        )

        /**
         * Impersonation phrases.
         */
        private val IMPERSONATION_TERMS = listOf(
            "bank representative",
            "bank officer",
            "customer support",
            "customer care",
            "security team",
            "security department",
            "technical support",
            "account manager",
            "official representative",
            "government officer",
            "income tax department",
            "police department",
            "courier department",
            "delivery partner"
        )

        /**
         * Remote-access/social-engineering tools.
         */
        private val REMOTE_ACCESS_TERMS = listOf(
            "remote access",
            "screen sharing",
            "screen share",
            "remote desktop",
            "anydesk",
            "teamviewer",
            "quick support",
            "remote support",
            "install support app",
            "download support app"
        )

        /**
         * Payment manipulation terminology.
         */
        private val PAYMENT_MANIPULATION_TERMS = listOf(
            "send money",
            "transfer money",
            "make payment",
            "pay immediately",
            "pay now",
            "transfer now",
            "scan qr",
            "scan this qr",
            "approve payment",
            "collect request",
            "payment request",
            "upi collect",
            "receive money",
            "refund processing fee"
        )

        /**
         * Threat/fear terminology.
         */
        private val FEAR_TERMS = listOf(
            "legal action",
            "police case",
            "arrest",
            "penalty",
            "fine",
            "court notice",
            "warrant",
            "account closure",
            "service termination",
            "blacklisted"
        )

        /**
         * Suspicious message structure patterns.
         */
        private val SUSPICIOUS_URL_REGEX = Regex(
            pattern = "(?i)\\bhttps?://[^\\s<>\"']+"
        )
    }

    /**
     * Performs complete content analysis.
     */
    suspend fun analyze(
        content: String
    ): PhishingContentAnalysis = withContext(Dispatchers.Default) {

        validateContent(content)

        checkCancellation()

        val normalizedContent = normalizeContent(content)

        Log.d(
            TAG,
            "Starting phishing content analysis."
        )

        val findings = mutableListOf<PhishingContentFinding>()

        analyzeCredentials(
            content = normalizedContent,
            findings = findings
        )

        analyzeOtpRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzePinRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzeFinancialContext(
            content = normalizedContent,
            findings = findings
        )

        analyzeUrgency(
            content = normalizedContent,
            findings = findings
        )

        analyzeAccountThreats(
            content = normalizedContent,
            findings = findings
        )

        analyzePhishingActions(
            content = normalizedContent,
            findings = findings
        )

        analyzeRewardScams(
            content = normalizedContent,
            findings = findings
        )

        analyzeSensitiveRequests(
            content = normalizedContent,
            findings = findings
        )

        analyzeImpersonation(
            content = normalizedContent,
            findings = findings
        )

        analyzeRemoteAccess(
            content = normalizedContent,
            findings = findings
        )

        analyzePaymentManipulation(
            content = normalizedContent,
            findings = findings
        )

        analyzeFearTactics(
            content = normalizedContent,
            findings = findings
        )

        analyzeSocialEngineeringCombinations(
            content = normalizedContent,
            findings = findings
        )

        val urls = extractUrls(content)

        if (urls.isNotEmpty()) {

            analyzeEmbeddedUrls(
                urls = urls,
                findings = findings
            )
        }

        val score = calculateRiskScore(
            findings
        )

        val classification = classify(
            score
        )

        Log.d(
            TAG,
            "Content phishing analysis completed. " +
                    "risk=$score classification=$classification"
        )

        PhishingContentAnalysis(
            originalContent = content,
            normalizedContent = normalizedContent,
            riskScore = score,
            classification = classification,
            isSuspicious =
                classification !=
                        PhishingContentClassification.SAFE,
            findings = findings
                .distinctBy {
                    "${it.type}:${it.description}"
                }
                .sortedByDescending {
                    it.score
                }
                .take(50),
            extractedUrls = urls
        )
    }

    /**
     * Returns only the content risk score.
     */
    suspend fun calculateRisk(
        content: String
    ): Float {

        return analyze(content).riskScore
    }

    /**
     * Returns whether the content is suspicious.
     */
    suspend fun isSuspicious(
        content: String
    ): Boolean {

        return analyze(content).riskScore >=
                MEDIUM_RISK_THRESHOLD
    }

    /**
     * Returns true when the content has high phishing risk.
     */
    suspend fun isHighRisk(
        content: String
    ): Boolean {

        return analyze(content).riskScore >=
                HIGH_RISK_THRESHOLD
    }

    /**
     * Extracts HTTP/HTTPS URLs from text.
     */
    fun extractUrls(
        content: String
    ): List<String> {

        if (content.isBlank()) {
            return emptyList()
        }

        return SUSPICIOUS_URL_REGEX
            .findAll(content)
            .map {
                cleanUrl(it.value)
            }
            .filter {
                it.isNotBlank()
            }
            .distinct()
            .take(MAX_EXTRACTED_URLS)
            .toList()
    }

    /**
     * Extracts suspicious keywords from content.
     */
    fun extractKeywords(
        content: String
    ): List<String> {

        val normalized =
            normalizeContent(content)

        val allTerms =
            CREDENTIAL_TERMS +
                    OTP_TERMS +
                    PIN_TERMS +
                    FINANCIAL_TERMS +
                    URGENCY_TERMS +
                    REWARD_TERMS +
                    ACCOUNT_THREAT_TERMS +
                    PHISHING_ACTION_TERMS +
                    IMPERSONATION_TERMS +
                    REMOTE_ACCESS_TERMS +
                    PAYMENT_MANIPULATION_TERMS +
                    FEAR_TERMS

        return allTerms
            .filter {
                normalized.contains(it)
            }
            .distinct()
    }

    /**
     * Detects credential harvesting language.
     */
    private fun analyzeCredentials(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            CREDENTIAL_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.CREDENTIAL_TERMS,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        (matches.size * 0.06f)
                            .coerceAtMost(0.24f),
                    description =
                        "The content contains credential-related terminology."
                )
            )
        }
    }

    /**
     * Detects OTP harvesting attempts.
     */
    private fun analyzeOtpRequests(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val otpMentioned =
            OTP_TERMS.any {
                content.contains(it)
            }

        if (!otpMentioned) {
            return
        }

        val explicitRequest =
            SENSITIVE_REQUEST_PATTERNS.any {
                content.contains(it) &&
                        (
                                it.contains("otp") ||
                                        it.contains("code")
                                )
            }

        findings.add(
            finding(
                type =
                    if (explicitRequest) {
                        PhishingContentIndicator.OTP_REQUEST
                    } else {
                        PhishingContentIndicator.OTP_CONTEXT
                    },
                severity =
                    if (explicitRequest) {
                        PhishingContentSeverity.CRITICAL
                    } else {
                        PhishingContentSeverity.HIGH
                    },
                score =
                    if (explicitRequest) {
                        0.35f
                    } else {
                        0.12f
                    },
                description =
                    if (explicitRequest) {
                        "The content appears to request an OTP or verification code."
                    } else {
                        "The content references an OTP or verification code."
                    }
            )
        )
    }

    /**
     * Detects PIN harvesting.
     */
    private fun analyzePinRequests(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val pinMentioned =
            PIN_TERMS.any {
                content.contains(it)
            }

        if (!pinMentioned) {
            return
        }

        val request =
            listOf(
                "share your pin",
                "send your pin",
                "provide your pin",
                "enter your pin",
                "tell us your pin",
                "share your upi pin",
                "enter your upi pin"
            ).any {
                content.contains(it)
            }

        findings.add(
            finding(
                type =
                    if (request) {
                        PhishingContentIndicator.PIN_REQUEST
                    } else {
                        PhishingContentIndicator.PIN_CONTEXT
                    },
                severity =
                    if (request) {
                        PhishingContentSeverity.CRITICAL
                    } else {
                        PhishingContentSeverity.HIGH
                    },
                score =
                    if (request) {
                        0.35f
                    } else {
                        0.10f
                    },
                description =
                    if (request) {
                        "The content appears to request a PIN."
                    } else {
                        "The content references PIN-related information."
                    }
            )
        )
    }

    /**
     * Detects financial context.
     */
    private fun analyzeFinancialContext(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            FINANCIAL_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.FINANCIAL_CONTEXT,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.05f)
                            .coerceAtMost(0.25f),
                    description =
                        "The content contains financial or payment-related terminology."
                )
            )
        }
    }

    /**
     * Detects urgency and time pressure.
     */
    private fun analyzeUrgency(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            URGENCY_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.URGENCY_LANGUAGE,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.07f)
                            .coerceAtMost(0.25f),
                    description =
                        "The content uses urgency or time-pressure language."
                )
            )
        }
    }

    /**
     * Detects account threat language.
     */
    private fun analyzeAccountThreats(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            ACCOUNT_THREAT_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.ACCOUNT_THREAT,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        (matches.size * 0.08f)
                            .coerceAtMost(0.28f),
                    description =
                        "The content claims that an account or service has a security problem."
                )
            )
        }
    }

    /**
     * Detects common phishing calls-to-action.
     */
    private fun analyzePhishingActions(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            PHISHING_ACTION_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.PHISHING_CALL_TO_ACTION,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.07f)
                            .coerceAtMost(0.21f),
                    description =
                        "The content contains actions commonly used to direct victims to phishing pages."
                )
            )
        }
    }

    /**
     * Detects prize/reward scams.
     */
    private fun analyzeRewardScams(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            REWARD_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.REWARD_SCAM,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.07f)
                            .coerceAtMost(0.25f),
                    description =
                        "The content contains potentially deceptive reward or prize language."
                )
            )
        }
    }

    /**
     * Detects explicit sensitive-data requests.
     */
    private fun analyzeSensitiveRequests(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            SENSITIVE_REQUEST_PATTERNS.filter {
                content.contains(it)
            }

        if (matches.isEmpty()) {
            return
        }

        findings.add(
            finding(
                type =
                    PhishingContentIndicator.SENSITIVE_DATA_REQUEST,
                severity =
                    PhishingContentSeverity.CRITICAL,
                score =
                    0.40f,
                description =
                    "The content explicitly requests sensitive authentication or financial information."
            )
        )
    }

    /**
     * Detects impersonation claims.
     */
    private fun analyzeImpersonation(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            IMPERSONATION_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.IMPERSONATION_LANGUAGE,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.06f)
                            .coerceAtMost(0.18f),
                    description =
                        "The content claims to represent a potentially trusted organization or authority."
                )
            )
        }
    }

    /**
     * Detects remote-access/social-engineering techniques.
     */
    private fun analyzeRemoteAccess(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            REMOTE_ACCESS_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.REMOTE_ACCESS_REQUEST,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        (matches.size * 0.10f)
                            .coerceAtMost(0.30f),
                    description =
                        "The content references remote-access or screen-sharing software."
                )
            )
        }
    }

    /**
     * Detects payment manipulation.
     */
    private fun analyzePaymentManipulation(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            PAYMENT_MANIPULATION_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.PAYMENT_MANIPULATION,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        (matches.size * 0.08f)
                            .coerceAtMost(0.30f),
                    description =
                        "The content contains language associated with payment or money-transfer requests."
                )
            )
        }
    }

    /**
     * Detects fear and intimidation tactics.
     */
    private fun analyzeFearTactics(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val matches =
            FEAR_TERMS.filter {
                content.contains(it)
            }

        if (matches.isNotEmpty()) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.FEAR_TACTIC,
                    severity =
                        PhishingContentSeverity.MEDIUM,
                    score =
                        (matches.size * 0.06f)
                            .coerceAtMost(0.20f),
                    description =
                        "The content uses fear, punishment, or intimidation language."
                )
            )
        }
    }

    /**
     * Detects combinations that are stronger than individual indicators.
     *
     * Examples:
     *
     * urgency + credential request
     * urgency + financial request
     * impersonation + sensitive request
     * reward + payment request
     * account threat + phishing action
     */
    private fun analyzeSocialEngineeringCombinations(
        content: String,
        findings: MutableList<PhishingContentFinding>
    ) {

        val hasUrgency =
            URGENCY_TERMS.any {
                content.contains(it)
            }

        val hasCredentials =
            CREDENTIAL_TERMS.any {
                content.contains(it)
            }

        val hasFinancial =
            FINANCIAL_TERMS.any {
                content.contains(it)
            }

        val hasImpersonation =
            IMPERSONATION_TERMS.any {
                content.contains(it)
            }

        val hasSensitiveRequest =
            SENSITIVE_REQUEST_PATTERNS.any {
                content.contains(it)
            }

        val hasReward =
            REWARD_TERMS.any {
                content.contains(it)
            }

        val hasPayment =
            PAYMENT_MANIPULATION_TERMS.any {
                content.contains(it)
            }

        val hasAccountThreat =
            ACCOUNT_THREAT_TERMS.any {
                content.contains(it)
            }

        val hasAction =
            PHISHING_ACTION_TERMS.any {
                content.contains(it)
            }

        if (hasUrgency && hasCredentials) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.URGENCY_CREDENTIAL_COMBINATION,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        0.22f,
                    description =
                        "Urgency is combined with credential-related language."
                )
            )
        }

        if (hasUrgency && hasFinancial) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.URGENCY_FINANCIAL_COMBINATION,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        0.20f,
                    description =
                        "Urgency is combined with financial-related language."
                )
            )
        }

        if (hasImpersonation && hasSensitiveRequest) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.IMPERSONATION_SENSITIVE_REQUEST,
                    severity =
                        PhishingContentSeverity.CRITICAL,
                    score =
                        0.35f,
                    description =
                        "An impersonation claim is combined with a request for sensitive information."
                )
            )
        }

        if (hasReward && hasPayment) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.REWARD_PAYMENT_COMBINATION,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        0.25f,
                    description =
                        "Reward language is combined with a payment request."
                )
            )
        }

        if (hasAccountThreat && hasAction) {

            findings.add(
                finding(
                    type =
                        PhishingContentIndicator.ACCOUNT_THREAT_ACTION_COMBINATION,
                    severity =
                        PhishingContentSeverity.HIGH,
                    score =
                        0.25f,
                    description =
                        "An account threat is combined with a request to perform an immediate action."
                )
            )
        }
    }

    /**
     * Analyzes URLs embedded inside content.
     */
    private suspend fun analyzeEmbeddedUrls(
        urls: List<String>,
        findings: MutableList<PhishingContentFinding>
    ) {

        urls.take(MAX_EXTRACTED_URLS)
            .forEach { url ->

                checkCancellation()

                try {

                    val result =
                        urlAnalyzer.analyze(url)

                    if (result.isSuspicious) {

                        findings.add(
                            finding(
                                type =
                                    PhishingContentIndicator.SUSPICIOUS_EMBEDDED_URL,
                                severity =
                                    when (
                                        result.classification
                                    ) {

                                        PhishingURLClassification.HIGH ->
                                            PhishingContentSeverity.CRITICAL

                                        PhishingURLClassification.MEDIUM ->
                                            PhishingContentSeverity.HIGH

                                        PhishingURLClassification.LOW ->
                                            PhishingContentSeverity.MEDIUM

                                        PhishingURLClassification.SAFE ->
                                            PhishingContentSeverity.LOW
                                    },
                                score =
                                    when (
                                        result.classification
                                    ) {

                                        PhishingURLClassification.HIGH ->
                                            0.35f

                                        PhishingURLClassification.MEDIUM ->
                                            0.25f

                                        PhishingURLClassification.LOW ->
                                            0.10f

                                        PhishingURLClassification.SAFE ->
                                            0.0f
                                    },
                                description =
                                    "The message contains a URL with phishing indicators."
                            )
                        )
                    }

                } catch (
                    exception: CancellationException
                ) {

                    throw exception

                } catch (
                    exception: Exception
                ) {

                    Log.w(
                        TAG,
                        "Unable to analyze embedded URL.",
                        exception
                    )
                }
            }
    }

    /**
     * Calculates the final risk score.
     */
    private fun calculateRiskScore(
        findings: List<PhishingContentFinding>
    ): Float {

        if (findings.isEmpty()) {
            return 0.0f
        }

        val relevant =
            findings
                .sortedByDescending {
                    it.score
                }
                .take(50)

        var score =
            relevant.sumOf {
                it.score.toDouble()
            }.toFloat()

        val criticalCount =
            relevant.count {
                it.severity ==
                        PhishingContentSeverity.CRITICAL
            }

        val highCount =
            relevant.count {
                it.severity ==
                        PhishingContentSeverity.HIGH
            }

        val mediumCount =
            relevant.count {
                it.severity ==
                        PhishingContentSeverity.MEDIUM
            }

        if (criticalCount > 0) {
            score += 0.20f
        }

        if (highCount >= 2) {
            score += 0.15f
        }

        if (mediumCount >= 3) {
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
    ): PhishingContentClassification {

        return when {

            score >= HIGH_RISK_THRESHOLD ->
                PhishingContentClassification.HIGH

            score >= MEDIUM_RISK_THRESHOLD ->
                PhishingContentClassification.MEDIUM

            score >= LOW_RISK_THRESHOLD ->
                PhishingContentClassification.LOW

            else ->
                PhishingContentClassification.SAFE
        }
    }

    /**
     * Creates a content finding.
     */
    private fun finding(
        type: PhishingContentIndicator,
        severity: PhishingContentSeverity,
        score: Float,
        description: String
    ): PhishingContentFinding {

        return PhishingContentFinding(
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
     * Normalizes content for matching.
     *
     * Original content is preserved separately in the result.
     */
    private fun normalizeContent(
        content: String
    ): String {

        return content
            .trim()
            .replace("\u0000", "")
            .lowercase(Locale.ROOT)
            .replace(
                Regex("\\s+"),
                " "
            )
    }

    /**
     * Removes punctuation attached to extracted URLs.
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
     * Validates incoming content.
     */
    private fun validateContent(
        content: String
    ) {

        require(content.isNotBlank()) {
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
     * Respects coroutine cancellation.
     */
    private suspend fun checkCancellation() {

        if (!kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Phishing content analysis was cancelled."
            )
        }
    }
}

/**
 * Complete phishing content analysis result.
 */
data class PhishingContentAnalysis(

    /**
     * Original content exactly as received.
     */
    val originalContent: String,

    /**
     * Normalized content used for analysis.
     */
    val normalizedContent: String,

    /**
     * Normalized risk score.
     */
    val riskScore: Float,

    /**
     * Overall phishing classification.
     */
    val classification: PhishingContentClassification,

    /**
     * Whether significant phishing/scam indicators were found.
     */
    val isSuspicious: Boolean,

    /**
     * Individual findings.
     */
    val findings: List<PhishingContentFinding>,

    /**
     * URLs extracted from the content.
     */
    val extractedUrls: List<String>
)

/**
 * Individual content-level phishing finding.
 */
data class PhishingContentFinding(

    /**
     * Indicator type.
     */
    val type: PhishingContentIndicator,

    /**
     * Indicator severity.
     */
    val severity: PhishingContentSeverity,

    /**
     * Contribution to overall risk.
     */
    val score: Float,

    /**
     * Human-readable explanation.
     */
    val description: String
)

/**
 * Overall phishing content classification.
 */
enum class PhishingContentClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH
}

/**
 * Severity of an individual content indicator.
 */
enum class PhishingContentSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Content-level phishing indicators.
 */
enum class PhishingContentIndicator {

    CREDENTIAL_TERMS,

    OTP_REQUEST,

    OTP_CONTEXT,

    PIN_REQUEST,

    PIN_CONTEXT,

    FINANCIAL_CONTEXT,

    URGENCY_LANGUAGE,

    ACCOUNT_THREAT,

    PHISHING_CALL_TO_ACTION,

    REWARD_SCAM,

    SENSITIVE_DATA_REQUEST,

    IMPERSONATION_LANGUAGE,

    REMOTE_ACCESS_REQUEST,

    PAYMENT_MANIPULATION,

    FEAR_TACTIC,

    URGENCY_CREDENTIAL_COMBINATION,

    URGENCY_FINANCIAL_COMBINATION,

    IMPERSONATION_SENSITIVE_REQUEST,

    REWARD_PAYMENT_COMBINATION,

    ACCOUNT_THREAT_ACTION_COMBINATION,

    SUSPICIOUS_EMBEDDED_URL
}
