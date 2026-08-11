package com.sentrix.security.phishing

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * PhishingPatternDetector
 *
 * Specialized pattern-detection engine for the SentriX phishing
 * protection subsystem.
 *
 * Responsibilities:
 * - Detect known phishing linguistic patterns.
 * - Detect credential-harvesting patterns.
 * - Detect OTP/PIN/password requests.
 * - Detect financial scam patterns.
 * - Detect urgency and fear patterns.
 * - Detect reward/prize scam patterns.
 * - Detect impersonation patterns.
 * - Detect suspicious calls-to-action.
 * - Detect social-engineering combinations.
 * - Detect payment manipulation patterns.
 * - Detect remote-access requests.
 * - Detect suspicious URL-related patterns in text.
 *
 * This component is intentionally focused on PATTERN DETECTION.
 *
 * It does not:
 * - Perform URL reputation checks.
 * - Perform DNS reputation checks.
 * - Contact threat-intelligence services.
 * - Make final allow/block decisions.
 * - Determine whether a sender is trustworthy.
 *
 * The output is structured evidence that can be consumed by:
 *
 * PhishingContentAnalyzer
 *          |
 *          v
 * PhishingPatternDetector
 *          |
 *          v
 * PhishingRiskEvaluator
 *          |
 *          v
 * Final SentriX Security Decision
 */
class PhishingPatternDetector {

    companion object {

        private const val TAG = "PhishingPatternDetector"

        /**
         * Maximum content size accepted by the detector.
         */
        private const val MAX_CONTENT_LENGTH = 100_000

        /**
         * Maximum number of findings returned.
         */
        private const val MAX_FINDINGS = 100

        /**
         * Maximum number of matched patterns returned for each
         * pattern category.
         */
        private const val MAX_CATEGORY_MATCHES = 20

        /**
         * Credential harvesting patterns.
         *
         * These patterns are intentionally phrase-oriented rather
         * than single-keyword based.
         */
        private val CREDENTIAL_PATTERNS = listOf(
            PatternDefinition(
                id = "CREDENTIAL_001",
                category = PhishingPatternCategory.CREDENTIAL_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(enter|provide|submit|share|send|confirm)\\s+" +
                            "(your\\s+)?(password|login\\s+credentials|credentials|username)"
                ),
                description =
                    "Requests the user to provide account credentials."
            ),
            PatternDefinition(
                id = "CREDENTIAL_002",
                category = PhishingPatternCategory.CREDENTIAL_HARVESTING,
                severity = PhishingPatternSeverity.CRITICAL,
                score = 0.30f,
                regex = Regex(
                    "(?i)\\b(share|send|provide|tell|give)\\s+" +
                            "(us\\s+)?your\\s+(password|passcode)"
                ),
                description =
                    "Explicitly requests a password or passcode."
            ),
            PatternDefinition(
                id = "CREDENTIAL_003",
                category = PhishingPatternCategory.CREDENTIAL_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.15f,
                regex = Regex(
                    "(?i)\\b(verify|confirm|update|validate)\\s+" +
                            "(your\\s+)?(login|account|credentials)"
                ),
                description =
                    "Uses account-verification language associated with credential harvesting."
            )
        )

        /**
         * OTP harvesting patterns.
         */
        private val OTP_PATTERNS = listOf(
            PatternDefinition(
                id = "OTP_001",
                category = PhishingPatternCategory.OTP_HARVESTING,
                severity = PhishingPatternSeverity.CRITICAL,
                score = 0.35f,
                regex = Regex(
                    "(?i)\\b(share|send|provide|tell|give)\\s+" +
                            "(us\\s+)?your\\s+(otp|one[- ]time\\s+password|verification\\s+code)"
                ),
                description =
                    "Explicitly requests an OTP or verification code."
            ),
            PatternDefinition(
                id = "OTP_002",
                category = PhishingPatternCategory.OTP_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(enter|submit)\\s+" +
                            "(your\\s+)?(otp|one[- ]time\\s+password|verification\\s+code)"
                ),
                description =
                    "Requests the user to enter an OTP or verification code."
            ),
            PatternDefinition(
                id = "OTP_003",
                category = PhishingPatternCategory.OTP_HARVESTING,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.08f,
                regex = Regex(
                    "(?i)\\b(otp|one[- ]time\\s+password|verification\\s+code)\\b"
                ),
                description =
                    "Message contains OTP-related terminology."
            )
        )

        /**
         * PIN harvesting patterns.
         */
        private val PIN_PATTERNS = listOf(
            PatternDefinition(
                id = "PIN_001",
                category = PhishingPatternCategory.PIN_HARVESTING,
                severity = PhishingPatternSeverity.CRITICAL,
                score = 0.35f,
                regex = Regex(
                    "(?i)\\b(share|send|provide|tell|give)\\s+" +
                            "(us\\s+)?your\\s+" +
                            "(upi\\s+pin|atm\\s+pin|card\\s+pin|pin|mpin)"
                ),
                description =
                    "Explicitly requests a PIN."
            ),
            PatternDefinition(
                id = "PIN_002",
                category = PhishingPatternCategory.PIN_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(enter|submit)\\s+" +
                            "(your\\s+)?(upi\\s+pin|atm\\s+pin|card\\s+pin|pin)"
                ),
                description =
                    "Requests the user to enter a PIN."
            )
        )

        /**
         * Financial information harvesting patterns.
         */
        private val FINANCIAL_PATTERNS = listOf(
            PatternDefinition(
                id = "FINANCIAL_001",
                category = PhishingPatternCategory.FINANCIAL_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(share|send|provide|enter|submit)\\s+" +
                            "(your\\s+)?(bank\\s+details|bank\\s+account|card\\s+details|card\\s+number)"
                ),
                description =
                    "Requests bank or payment information."
            ),
            PatternDefinition(
                id = "FINANCIAL_002",
                category = PhishingPatternCategory.FINANCIAL_HARVESTING,
                severity = PhishingPatternSeverity.CRITICAL,
                score = 0.30f,
                regex = Regex(
                    "(?i)\\b(share|send|provide|enter)\\s+" +
                            "(your\\s+)?(cvv|card\\s+verification\\s+value)"
                ),
                description =
                    "Requests a card verification value."
            ),
            PatternDefinition(
                id = "FINANCIAL_003",
                category = PhishingPatternCategory.FINANCIAL_HARVESTING,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(enter|provide|submit)\\s+" +
                            "(your\\s+)?(credit|debit)\\s+card\\s+(number|details)"
                ),
                description =
                    "Requests credit or debit card information."
            )
        )

        /**
         * Payment manipulation patterns.
         */
        private val PAYMENT_PATTERNS = listOf(
            PatternDefinition(
                id = "PAYMENT_001",
                category = PhishingPatternCategory.PAYMENT_MANIPULATION,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.22f,
                regex = Regex(
                    "(?i)\\b(send|transfer|pay|deposit)\\s+" +
                            "(the\\s+)?(money|amount|funds|payment)\\s+" +
                            "(now|immediately|today)"
                ),
                description =
                    "Creates pressure to make an immediate payment."
            ),
            PatternDefinition(
                id = "PAYMENT_002",
                category = PhishingPatternCategory.PAYMENT_MANIPULATION,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(scan|open)\\s+(this\\s+)?(qr|qr\\s+code)"
                ),
                description =
                    "Requests interaction with a QR code."
            ),
            PatternDefinition(
                id = "PAYMENT_003",
                category = PhishingPatternCategory.PAYMENT_MANIPULATION,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.22f,
                regex = Regex(
                    "(?i)\\b(approve|accept|authorize)\\s+" +
                            "(the\\s+)?(payment|collect\\s+request|transaction)"
                ),
                description =
                    "Requests approval of a payment or collection request."
            ),
            PatternDefinition(
                id = "PAYMENT_004",
                category = PhishingPatternCategory.PAYMENT_MANIPULATION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.15f,
                regex = Regex(
                    "(?i)\\b(refund|cashback)\\s+" +
                            "(processing\\s+fee|verification\\s+fee|activation\\s+fee)"
                ),
                description =
                    "Claims a refund or cashback requires a fee."
            )
        )

        /**
         * Urgency patterns.
         */
        private val URGENCY_PATTERNS = listOf(
            PatternDefinition(
                id = "URGENCY_001",
                category = PhishingPatternCategory.URGENCY,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.10f,
                regex = Regex(
                    "(?i)\\b(act\\s+now|respond\\s+now|do\\s+it\\s+now|immediately)"
                ),
                description =
                    "Uses immediate-action language."
            ),
            PatternDefinition(
                id = "URGENCY_002",
                category = PhishingPatternCategory.URGENCY,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(within\\s+(24|48)\\s+hours|before\\s+it\\s+expires|expires\\s+today)"
                ),
                description =
                    "Uses a deadline to create pressure."
            ),
            PatternDefinition(
                id = "URGENCY_003",
                category = PhishingPatternCategory.URGENCY,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.15f,
                regex = Regex(
                    "(?i)\\b(last\\s+warning|final\\s+warning|final\\s+notice)"
                ),
                description =
                    "Uses final-warning language."
            )
        )

        /**
         * Account-threat patterns.
         */
        private val ACCOUNT_THREAT_PATTERNS = listOf(
            PatternDefinition(
                id = "ACCOUNT_001",
                category = PhishingPatternCategory.ACCOUNT_THREAT,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(your\\s+account|account)\\s+" +
                            "(has\\s+been\\s+)?(blocked|suspended|locked|disabled)"
                ),
                description =
                    "Claims that an account has been blocked or suspended."
            ),
            PatternDefinition(
                id = "ACCOUNT_002",
                category = PhishingPatternCategory.ACCOUNT_THREAT,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.18f,
                regex = Regex(
                    "(?i)\\b(unusual|suspicious|unauthorized)\\s+" +
                            "(activity|login|transaction)"
                ),
                description =
                    "Claims that suspicious activity was detected."
            ),
            PatternDefinition(
                id = "ACCOUNT_003",
                category = PhishingPatternCategory.ACCOUNT_THREAT,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(verify|confirm|validate)\\s+" +
                            "(your\\s+)?(account|identity)"
                ),
                description =
                    "Requests account or identity verification."
            )
        )

        /**
         * Reward/prize patterns.
         */
        private val REWARD_PATTERNS = listOf(
            PatternDefinition(
                id = "REWARD_001",
                category = PhishingPatternCategory.REWARD_SCAM,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.15f,
                regex = Regex(
                    "(?i)\\b(congratulations|congrats)\\b.*\\b(won|winner|prize|reward)"
                ),
                description =
                    "Combines congratulations with an unexpected reward or prize."
            ),
            PatternDefinition(
                id = "REWARD_002",
                category = PhishingPatternCategory.REWARD_SCAM,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.14f,
                regex = Regex(
                    "(?i)\\b(claim|collect)\\s+" +
                            "(your\\s+)?(reward|prize|cashback|gift)"
                ),
                description =
                    "Requests the user to claim an unexpected reward."
            ),
            PatternDefinition(
                id = "REWARD_003",
                category = PhishingPatternCategory.REWARD_SCAM,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(lottery|lucky\\s+winner|jackpot|cash\\s+prize)"
                ),
                description =
                    "Contains lottery or prize language."
            )
        )

        /**
         * Impersonation patterns.
         */
        private val IMPERSONATION_PATTERNS = listOf(
            PatternDefinition(
                id = "IMPERSONATION_001",
                category = PhishingPatternCategory.IMPERSONATION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(bank\\s+(representative|officer)|customer\\s+(support|care)|security\\s+team)"
                ),
                description =
                    "Claims to represent a financial or support organization."
            ),
            PatternDefinition(
                id = "IMPERSONATION_002",
                category = PhishingPatternCategory.IMPERSONATION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(official\\s+representative|government\\s+officer|tax\\s+department)"
                ),
                description =
                    "Claims to represent an authority or government organization."
            ),
            PatternDefinition(
                id = "IMPERSONATION_003",
                category = PhishingPatternCategory.IMPERSONATION,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(this\\s+is|i\\s+am)\\s+" +
                            "(from|calling\\s+from)\\s+" +
                            "(your\\s+bank|the\\s+bank|security\\s+team)"
                ),
                description =
                    "Uses direct organizational impersonation language."
            )
        )

        /**
         * Remote access patterns.
         */
        private val REMOTE_ACCESS_PATTERNS = listOf(
            PatternDefinition(
                id = "REMOTE_001",
                category = PhishingPatternCategory.REMOTE_ACCESS,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.22f,
                regex = Regex(
                    "(?i)\\b(install|download|open)\\s+" +
                            "(anydesk|teamviewer|quick\\s+support|remote\\s+desktop)"
                ),
                description =
                    "Requests installation or use of remote-access software."
            ),
            PatternDefinition(
                id = "REMOTE_002",
                category = PhishingPatternCategory.REMOTE_ACCESS,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(share|allow|enable)\\s+" +
                            "(your\\s+)?(screen|screen\\s+sharing|remote\\s+access)"
                ),
                description =
                    "Requests screen sharing or remote access."
            )
        )

        /**
         * Social-engineering action patterns.
         */
        private val ACTION_PATTERNS = listOf(
            PatternDefinition(
                id = "ACTION_001",
                category = PhishingPatternCategory.PHISHING_ACTION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.10f,
                regex = Regex(
                    "(?i)\\b(click|tap|open)\\s+" +
                            "(here|this\\s+link|the\\s+link)"
                ),
                description =
                    "Directs the user to interact with a link."
            ),
            PatternDefinition(
                id = "ACTION_002",
                category = PhishingPatternCategory.PHISHING_ACTION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(login|sign\\s*in|verify|confirm|update|reset|unlock)\\s+now"
                ),
                description =
                    "Uses an immediate security-sensitive call to action."
            ),
            PatternDefinition(
                id = "ACTION_003",
                category = PhishingPatternCategory.PHISHING_ACTION,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.10f,
                regex = Regex(
                    "(?i)\\b(complete|finish)\\s+" +
                            "(your\\s+)?(verification|identity\\s+verification)"
                ),
                description =
                    "Requests completion of a verification process."
            )
        )

        /**
         * Fear/intimidation patterns.
         */
        private val FEAR_PATTERNS = listOf(
            PatternDefinition(
                id = "FEAR_001",
                category = PhishingPatternCategory.FEAR_TACTIC,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.12f,
                regex = Regex(
                    "(?i)\\b(legal\\s+action|police\\s+case|arrest|warrant)"
                ),
                description =
                    "Uses legal or law-enforcement threats."
            ),
            PatternDefinition(
                id = "FEAR_002",
                category = PhishingPatternCategory.FEAR_TACTIC,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.10f,
                regex = Regex(
                    "(?i)\\b(penalty|fine|court\\s+notice|blacklisted)"
                ),
                description =
                    "Uses punishment or penalty language."
            )
        )

        /**
         * Link-related patterns.
         */
        private val LINK_PATTERNS = listOf(
            PatternDefinition(
                id = "LINK_001",
                category = PhishingPatternCategory.SUSPICIOUS_LINK,
                severity = PhishingPatternSeverity.LOW,
                score = 0.04f,
                regex = Regex(
                    "(?i)\\bhttps?://[^\\s<>\"']+"
                ),
                description =
                    "Contains an HTTP or HTTPS URL."
            ),
            PatternDefinition(
                id = "LINK_002",
                category = PhishingPatternCategory.SUSPICIOUS_LINK,
                severity = PhishingPatternSeverity.MEDIUM,
                score = 0.10f,
                regex = Regex(
                    "(?i)\\b(bit\\.ly|tinyurl\\.com|t\\.co|cutt\\.ly|shorturl\\.at)/[^\\s]+"
                ),
                description =
                    "Contains a known URL-shortening service."
            )
        )

        /**
         * Payment/refund scam patterns.
         */
        private val REFUND_PATTERNS = listOf(
            PatternDefinition(
                id = "REFUND_001",
                category = PhishingPatternCategory.REFUND_SCAM,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.22f,
                regex = Regex(
                    "(?i)\\b(refund|cashback)\\b.*\\b(fee|charge|payment)\\b"
                ),
                description =
                    "Claims that a refund or cashback requires payment."
            ),
            PatternDefinition(
                id = "REFUND_002",
                category = PhishingPatternCategory.REFUND_SCAM,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(pay|send|transfer)\\b.*\\b(refund|cashback)\\b"
                ),
                description =
                    "Requests payment in connection with a refund."
            )
        )

        /**
         * Data-leakage patterns.
         */
        private val DATA_REQUEST_PATTERNS = listOf(
            PatternDefinition(
                id = "DATA_001",
                category = PhishingPatternCategory.SENSITIVE_DATA_REQUEST,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.22f,
                regex = Regex(
                    "(?i)\\b(send|share|provide|upload)\\s+" +
                            "(your\\s+)?(id\\s+proof|identity\\s+document|passport|aadhaar|pan\\s+card)"
                ),
                description =
                    "Requests sensitive identity documentation."
            ),
            PatternDefinition(
                id = "DATA_002",
                category = PhishingPatternCategory.SENSITIVE_DATA_REQUEST,
                severity = PhishingPatternSeverity.HIGH,
                score = 0.20f,
                regex = Regex(
                    "(?i)\\b(send|share|provide)\\s+" +
                            "(your\\s+)?(personal\\s+details|personal\\s+information)"
                ),
                description =
                    "Requests personal information."
            )
        )
    }

    /**
     * Performs complete pattern detection.
     */
    suspend fun detect(
        content: String
    ): PhishingPatternDetectionResult =
        withContext(Dispatchers.Default) {

            validateContent(content)

            checkCancellation()

            val normalized =
                normalizeContent(content)

            Log.d(
                TAG,
                "Starting phishing pattern detection."
            )

            val findings =
                mutableListOf<PhishingPatternFinding>()

            val allPatterns =
                buildPatternSet()

            allPatterns.forEach { pattern ->

                checkCancellation()

                val matches =
                    pattern.regex
                        .findAll(normalized)
                        .take(MAX_CATEGORY_MATCHES)
                        .toList()

                if (matches.isEmpty()) {
                    return@forEach
                }

                matches.forEach { match ->

                    findings.add(
                        PhishingPatternFinding(
                            patternId =
                                pattern.id,
                            category =
                                pattern.category,
                            severity =
                                pattern.severity,
                            score =
                                pattern.score,
                            matchedText =
                                sanitizeMatch(
                                    match.value
                                ),
                            description =
                                pattern.description,
                            startIndex =
                                match.range.first,
                            endIndex =
                                match.range.last
                        )
                    )
                }
            }

            /*
             * Add contextual combinations after individual patterns
             * have been identified.
             */
            findings.addAll(
                detectCombinations(
                    normalized
                )
            )

            val uniqueFindings =
                findings
                    .distinctBy {
                        "${it.patternId}:${it.startIndex}:${it.endIndex}"
                    }
                    .sortedByDescending {
                        it.score
                    }
                    .take(MAX_FINDINGS)

            val score =
                calculateRiskScore(
                    uniqueFindings
                )

            val classification =
                classify(
                    score
                )

            Log.d(
                TAG,
                "Pattern detection completed. " +
                        "findings=${uniqueFindings.size}, " +
                        "risk=$score"
            )

            PhishingPatternDetectionResult(
                originalContent =
                    content,
                normalizedContent =
                    normalized,
                riskScore =
                    score,
                classification =
                    classification,
                isSuspicious =
                    classification !=
                            PhishingPatternClassification.SAFE,
                findings =
                    uniqueFindings
            )
        }

    /**
     * Detects patterns in a single category.
     */
    suspend fun detectCategory(
        content: String,
        category: PhishingPatternCategory
    ): List<PhishingPatternFinding> =
        withContext(Dispatchers.Default) {

            validateContent(content)

            checkCancellation()

            val normalized =
                normalizeContent(content)

            buildPatternSet()
                .filter {
                    it.category == category
                }
                .flatMap { pattern ->

                    pattern.regex
                        .findAll(normalized)
                        .take(MAX_CATEGORY_MATCHES)
                        .map { match ->

                            PhishingPatternFinding(
                                patternId =
                                    pattern.id,
                                category =
                                    pattern.category,
                                severity =
                                    pattern.severity,
                                score =
                                    pattern.score,
                                matchedText =
                                    sanitizeMatch(
                                        match.value
                                    ),
                                description =
                                    pattern.description,
                                startIndex =
                                    match.range.first,
                                endIndex =
                                    match.range.last
                            )
                        }
                        .toList()
                }
                .sortedByDescending {
                    it.score
                }
        }

    /**
     * Returns true when at least one strong phishing pattern exists.
     */
    suspend fun hasStrongPhishingPattern(
        content: String
    ): Boolean {

        val result =
            detect(content)

        return result.findings.any {
            it.severity ==
                    PhishingPatternSeverity.CRITICAL ||
                    it.severity ==
                    PhishingPatternSeverity.HIGH
        }
    }

    /**
     * Returns all detected categories.
     */
    suspend fun detectCategories(
        content: String
    ): Set<PhishingPatternCategory> {

        return detect(content)
            .findings
            .map {
                it.category
            }
            .toSet()
    }

    /**
     * Extracts the strongest detected patterns.
     */
    suspend fun getTopPatterns(
        content: String,
        limit: Int = 10
    ): List<PhishingPatternFinding> {

        require(limit > 0) {
            "Limit must be greater than zero."
        }

        return detect(content)
            .findings
            .take(limit)
    }

    /**
     * Builds the complete pattern set.
     */
    private fun buildPatternSet(): List<PatternDefinition> {

        return CREDENTIAL_PATTERNS +
                OTP_PATTERNS +
                PIN_PATTERNS +
                FINANCIAL_PATTERNS +
                PAYMENT_PATTERNS +
                URGENCY_PATTERNS +
                ACCOUNT_THREAT_PATTERNS +
                REWARD_PATTERNS +
                IMPERSONATION_PATTERNS +
                REMOTE_ACCESS_PATTERNS +
                ACTION_PATTERNS +
                FEAR_PATTERNS +
                LINK_PATTERNS +
                REFUND_PATTERNS +
                DATA_REQUEST_PATTERNS
    }

    /**
     * Detects combinations of otherwise weaker indicators.
     *
     * These combinations are important because social engineering
     * attacks often become suspicious through the relationship between
     * multiple phrases rather than one phrase alone.
     */
    private fun detectCombinations(
        content: String
    ): List<PhishingPatternFinding> {

        val findings =
            mutableListOf<PhishingPatternFinding>()

        val hasUrgency =
            containsAny(
                content,
                URGENCY_PATTERNS
            )

        val hasCredentialRequest =
            containsAny(
                content,
                CREDENTIAL_PATTERNS
            )

        val hasOtpRequest =
            containsAny(
                content,
                OTP_PATTERNS
            )

        val hasPinRequest =
            containsAny(
                content,
                PIN_PATTERNS
            )

        val hasFinancialRequest =
            containsAny(
                content,
                FINANCIAL_PATTERNS
            )

        val hasImpersonation =
            containsAny(
                content,
                IMPERSONATION_PATTERNS
            )

        val hasAccountThreat =
            containsAny(
                content,
                ACCOUNT_THREAT_PATTERNS
            )

        val hasAction =
            containsAny(
                content,
                ACTION_PATTERNS
            )

        val hasReward =
            containsAny(
                content,
                REWARD_PATTERNS
            )

        val hasPayment =
            containsAny(
                content,
                PAYMENT_PATTERNS
            )

        val hasFear =
            containsAny(
                content,
                FEAR_PATTERNS
            )

        if (
            hasUrgency &&
            hasCredentialRequest
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_URGENCY_CREDENTIAL",
                    category =
                        PhishingPatternCategory.SOCIAL_ENGINEERING,
                    severity =
                        PhishingPatternSeverity.HIGH,
                    score =
                        0.22f,
                    description =
                        "Urgency is combined with credential-related requests."
                )
            )
        }

        if (
            hasUrgency &&
            (
                    hasOtpRequest ||
                            hasPinRequest
                    )
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_URGENCY_AUTH",
                    category =
                        PhishingPatternCategory.SOCIAL_ENGINEERING,
                    severity =
                        PhishingPatternSeverity.CRITICAL,
                    score =
                        0.30f,
                    description =
                        "Urgency is combined with an OTP or PIN request."
                )
            )
        }

        if (
            hasUrgency &&
            hasFinancialRequest
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_URGENCY_FINANCIAL",
                    category =
                        PhishingPatternCategory.SOCIAL_ENGINEERING,
                    severity =
                        PhishingPatternSeverity.HIGH,
                    score =
                        0.24f,
                    description =
                        "Urgency is combined with financial information requests."
                )
            )
        }

        if (
            hasImpersonation &&
            (
                    hasCredentialRequest ||
                            hasOtpRequest ||
                            hasPinRequest ||
                            hasFinancialRequest
                    )
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_IMPERSONATION_DATA",
                    category =
                        PhishingPatternCategory.IMPERSONATION,
                    severity =
                        PhishingPatternSeverity.CRITICAL,
                    score =
                        0.35f,
                    description =
                        "An impersonation claim is combined with a sensitive-information request."
                )
            )
        }

        if (
            hasAccountThreat &&
            hasAction
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_ACCOUNT_ACTION",
                    category =
                        PhishingPatternCategory.SOCIAL_ENGINEERING,
                    severity =
                        PhishingPatternSeverity.HIGH,
                    score =
                        0.25f,
                    description =
                        "An account threat is combined with an immediate action request."
                )
            )
        }

        if (
            hasReward &&
            hasPayment
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_REWARD_PAYMENT",
                    category =
                        PhishingPatternCategory.REWARD_SCAM,
                    severity =
                        PhishingPatternSeverity.HIGH,
                    score =
                        0.25f,
                    description =
                        "Reward language is combined with a payment request."
                )
            )
        }

        if (
            hasFear &&
            (
                    hasCredentialRequest ||
                            hasFinancialRequest ||
                            hasAction
                    )
        ) {

            findings.add(
                combinationFinding(
                    id =
                        "COMBO_FEAR_ACTION",
                    category =
                        PhishingPatternCategory.SOCIAL_ENGINEERING,
                    severity =
                        PhishingPatternSeverity.HIGH,
                    score =
                        0.22f,
                    description =
                        "Fear or intimidation is combined with a security-sensitive action."
                )
            )
        }

        return findings
    }

    /**
     * Checks whether any pattern in a category matches.
     */
    private fun containsAny(
        content: String,
        patterns: List<PatternDefinition>
    ): Boolean {

        return patterns.any {
            it.regex.containsMatchIn(
                content
            )
        }
    }

    /**
     * Creates a combination finding.
     */
    private fun combinationFinding(
        id: String,
        category: PhishingPatternCategory,
        severity: PhishingPatternSeverity,
        score: Float,
        description: String
    ): PhishingPatternFinding {

        return PhishingPatternFinding(
            patternId =
                id,
            category =
                category,
            severity =
                severity,
            score =
                score,
            matchedText =
                "",
            description =
                description,
            startIndex =
                -1,
            endIndex =
                -1
        )
    }

    /**
     * Calculates final risk score.
     */
    private fun calculateRiskScore(
        findings: List<PhishingPatternFinding>
    ): Float {

        if (findings.isEmpty()) {
            return 0.0f
        }

        val relevant =
            findings
                .sortedByDescending {
                    it.score
                }
                .take(MAX_FINDINGS)

        var score =
            relevant.sumOf {
                it.score.toDouble()
            }.toFloat()

        val criticalCount =
            relevant.count {
                it.severity ==
                        PhishingPatternSeverity.CRITICAL
            }

        val highCount =
            relevant.count {
                it.severity ==
                        PhishingPatternSeverity.HIGH
            }

        val mediumCount =
            relevant.count {
                it.severity ==
                        PhishingPatternSeverity.MEDIUM
            }

        /*
         * Multiple strong indicators increase confidence.
         */
        if (criticalCount > 0) {
            score += 0.20f
        }

        if (criticalCount >= 2) {
            score += 0.15f
        }

        if (highCount >= 2) {
            score += 0.12f
        }

        if (mediumCount >= 3) {
            score += 0.06f
        }

        return score.coerceIn(
            0.0f,
            1.0f
        )
    }

    /**
     * Converts a numerical score to classification.
     */
    private fun classify(
        score: Float
    ): PhishingPatternClassification {

        return when {

            score >= HIGH_RISK_THRESHOLD ->
                PhishingPatternClassification.HIGH

            score >= MEDIUM_RISK_THRESHOLD ->
                PhishingPatternClassification.MEDIUM

            score >= LOW_RISK_THRESHOLD ->
                PhishingPatternClassification.LOW

            else ->
                PhishingPatternClassification.SAFE
        }
    }

    /**
     * Normalizes text before matching.
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
     * Prevents excessively long matched strings from entering
     * logs/results.
     */
    private fun sanitizeMatch(
        value: String
    ): String {

        val normalized =
            value
                .replace(
                    Regex("\\s+"),
                    " "
                )
                .trim()

        return if (
            normalized.length > 200
        ) {

            normalized.take(200) + "..."

        } else {

            normalized
        }
    }

    /**
     * Validates incoming content.
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
                "Phishing pattern detection was cancelled."
            )
        }
    }

    /**
     * Internal pattern definition.
     */
    private data class PatternDefinition(

        val id: String,

        val category: PhishingPatternCategory,

        val severity: PhishingPatternSeverity,

        val score: Float,

        val regex: Regex,

        val description: String
    )
}

/**
 * Complete phishing pattern detection result.
 */
data class PhishingPatternDetectionResult(

    /**
     * Original content.
     */
    val originalContent: String,

    /**
     * Normalized content.
     */
    val normalizedContent: String,

    /**
     * Calculated pattern risk score.
     */
    val riskScore: Float,

    /**
     * Overall pattern classification.
     */
    val classification: PhishingPatternClassification,

    /**
     * Whether significant patterns were detected.
     */
    val isSuspicious: Boolean,

    /**
     * Detected pattern findings.
     */
    val findings: List<PhishingPatternFinding>
)

/**
 * Individual detected phishing pattern.
 */
data class PhishingPatternFinding(

    /**
     * Stable pattern identifier.
     */
    val patternId: String,

    /**
     * Pattern category.
     */
    val category: PhishingPatternCategory,

    /**
     * Pattern severity.
     */
    val severity: PhishingPatternSeverity,

    /**
     * Contribution to risk score.
     */
    val score: Float,

    /**
     * Matched content.
     *
     * For combination findings this may be empty.
     */
    val matchedText: String,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Start position in normalized content.
     */
    val startIndex: Int,

    /**
     * End position in normalized content.
     */
    val endIndex: Int
)

/**
 * Phishing pattern categories.
 */
enum class PhishingPatternCategory {

    /**
     * Username/password/credential harvesting.
     */
    CREDENTIAL_HARVESTING,

    /**
     * OTP or verification-code harvesting.
     */
    OTP_HARVESTING,

    /**
     * PIN harvesting.
     */
    PIN_HARVESTING,

    /**
     * Bank/card/financial information harvesting.
     */
    FINANCIAL_HARVESTING,

    /**
     * Payment manipulation.
     */
    PAYMENT_MANIPULATION,

    /**
     * Urgency and artificial deadlines.
     */
    URGENCY,

    /**
     * Account suspension/blocking threats.
     */
    ACCOUNT_THREAT,

    /**
     * Prize/reward/cashback scams.
     */
    REWARD_SCAM,

    /**
     * Organization or authority impersonation.
     */
    IMPERSONATION,

    /**
     * Remote-access/social-engineering requests.
     */
    REMOTE_ACCESS,

    /**
     * Suspicious click/login/verification actions.
     */
    PHISHING_ACTION,

    /**
     * Fear and intimidation.
     */
    FEAR_TACTIC,

    /**
     * Suspicious URLs or shortened links.
     */
    SUSPICIOUS_LINK,

    /**
     * Refund/cashback manipulation.
     */
    REFUND_SCAM,

    /**
     * Requests for sensitive personal documents/data.
     */
    SENSITIVE_DATA_REQUEST,

    /**
     * Combination of multiple indicators.
     */
    SOCIAL_ENGINEERING
}

/**
 * Severity of a detected phishing pattern.
 */
enum class PhishingPatternSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Overall pattern risk classification.
 */
enum class PhishingPatternClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH
}
