package com.sentrix.domain.rules

/**
 * SentriX Scam Detection Rules
 *
 * Centralized rules for detecting scams across
 * SMS, email, websites, social media messages,
 * fake job offers, investment fraud, and phishing campaigns.
 */
object ScamDetectionRules {

    enum class ScamRiskLevel {
        SAFE,
        LOW_RISK,
        MEDIUM_RISK,
        HIGH_RISK,
        SCAM
    }

    enum class ScamType {
        PHISHING,
        INVESTMENT_FRAUD,
        LOTTERY_SCAM,
        JOB_SCAM,
        TECH_SUPPORT_SCAM,
        ROMANCE_SCAM,
        BANKING_SCAM,
        CRYPTO_SCAM,
        IMPERSONATION_SCAM,
        UNKNOWN
    }

    private val SCAM_KEYWORDS = setOf(
        "urgent",
        "verify account",
        "click here",
        "limited time",
        "congratulations",
        "winner",
        "claim reward",
        "lottery",
        "free money",
        "guaranteed profit",
        "investment opportunity",
        "bank account suspended",
        "update kyc",
        "confirm identity",
        "crypto giveaway",
        "act immediately"
    )

    /**
     * Calculate scam risk score.
     */
    fun calculateRiskScore(
        content: String,
        containsSuspiciousLink: Boolean,
        senderReputation: Int,
        requestsSensitiveInformation: Boolean,
        containsUrgencyLanguage: Boolean
    ): Int {

        var score = 0

        if (containsSuspiciousKeywords(content)) score += 25
        if (containsSuspiciousLink) score += 25
        if (requestsSensitiveInformation) score += 20
        if (containsUrgencyLanguage) score += 15

        if (senderReputation < 50) {
            score += (50 - senderReputation)
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Determine scam risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): ScamRiskLevel {

        return when {
            riskScore >= 85 -> ScamRiskLevel.SCAM
            riskScore >= 65 -> ScamRiskLevel.HIGH_RISK
            riskScore >= 40 -> ScamRiskLevel.MEDIUM_RISK
            riskScore >= 15 -> ScamRiskLevel.LOW_RISK
            else -> ScamRiskLevel.SAFE
        }
    }

    /**
     * Detect scam type from content.
     */
    fun detectScamType(
        content: String
    ): ScamType {

        val text = content.lowercase()

        return when {

            text.contains("investment") ||
            text.contains("double your money") ||
            text.contains("guaranteed return") ->
                ScamType.INVESTMENT_FRAUD

            text.contains("lottery") ||
            text.contains("winner") ||
            text.contains("prize") ->
                ScamType.LOTTERY_SCAM

            text.contains("job offer") ||
            text.contains("work from home") ||
            text.contains("registration fee") ->
                ScamType.JOB_SCAM

            text.contains("technical support") ||
            text.contains("device infected") ->
                ScamType.TECH_SUPPORT_SCAM

            text.contains("romance") ||
            text.contains("send money") ->
                ScamType.ROMANCE_SCAM

            text.contains("bank account") ||
            text.contains("kyc") ||
            text.contains("otp") ->
                ScamType.BANKING_SCAM

            text.contains("crypto") ||
            text.contains("bitcoin") ||
            text.contains("wallet") ->
                ScamType.CRYPTO_SCAM

            text.contains("verify account") ||
            text.contains("login") ||
            text.contains("password") ->
                ScamType.PHISHING

            text.contains("official") &&
            text.contains("urgent") ->
                ScamType.IMPERSONATION_SCAM

            else ->
                ScamType.UNKNOWN
        }
    }

    /**
     * Check suspicious keywords.
     */
    fun containsSuspiciousKeywords(
        content: String
    ): Boolean {

        val text = content.lowercase()

        return SCAM_KEYWORDS.any {
            text.contains(it)
        }
    }

    /**
     * Detect urgency tactics.
     */
    fun usesUrgencyTactics(
        content: String
    ): Boolean {

        val text = content.lowercase()

        return text.contains("urgent") ||
                text.contains("immediately") ||
                text.contains("within 24 hours") ||
                text.contains("account suspended") ||
                text.contains("last chance")
    }

    /**
     * Detect requests for sensitive data.
     */
    fun requestsSensitiveInformation(
        content: String
    ): Boolean {

        val text = content.lowercase()

        return text.contains("password") ||
                text.contains("otp") ||
                text.contains("cvv") ||
                text.contains("bank account") ||
                text.contains("credit card") ||
                text.contains("pin")
    }

    /**
     * Determine whether content should be blocked.
     */
    fun shouldBlock(
        riskLevel: ScamRiskLevel
    ): Boolean {

        return riskLevel == ScamRiskLevel.HIGH_RISK ||
                riskLevel == ScamRiskLevel.SCAM
    }

    /**
     * Determine whether warning should be shown.
     */
    fun shouldWarnUser(
        riskLevel: ScamRiskLevel
    ): Boolean {

        return riskLevel == ScamRiskLevel.MEDIUM_RISK ||
                riskLevel == ScamRiskLevel.HIGH_RISK
    }

    /**
     * Generate scam analysis summary.
     */
    fun getAnalysisSummary(
        riskLevel: ScamRiskLevel,
        scamType: ScamType
    ): String {

        return when (riskLevel) {

            ScamRiskLevel.SAFE ->
                "No scam indicators detected."

            ScamRiskLevel.LOW_RISK ->
                "Minor scam indicators detected."

            ScamRiskLevel.MEDIUM_RISK ->
                "Potential scam detected: $scamType"

            ScamRiskLevel.HIGH_RISK ->
                "High-risk scam detected: $scamType"

            ScamRiskLevel.SCAM ->
                "Confirmed scam pattern detected: $scamType"
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        riskLevel: ScamRiskLevel
    ): String {

        return when (riskLevel) {

            ScamRiskLevel.SAFE ->
                "No action required."

            ScamRiskLevel.LOW_RISK ->
                "Monitor communication."

            ScamRiskLevel.MEDIUM_RISK ->
                "Warn user before interaction."

            ScamRiskLevel.HIGH_RISK ->
                "Block interaction and notify user."

            ScamRiskLevel.SCAM ->
                "Block immediately and generate security alert."
        }
    }

    /**
     * Determine whether security alert is required.
     */
    fun requiresSecurityAlert(
        riskLevel: ScamRiskLevel
    ): Boolean {

        return riskLevel == ScamRiskLevel.HIGH_RISK ||
                riskLevel == ScamRiskLevel.SCAM
    }
}
