package com.sentrix.domain.rules

/**
 * SentriX Device Trust Rules
 *
 * Centralized device trust evaluation engine responsible for
 * calculating trust scores, validating device integrity,
 * assessing risk factors, and determining device eligibility
 * for sensitive operations.
 */
object DeviceTrustRules {

    enum class TrustLevel {
        TRUSTED,
        MODERATELY_TRUSTED,
        LOW_TRUST,
        UNTRUSTED
    }

    /**
     * Calculate overall device trust score.
     */
    fun calculateTrustScore(
        integrityScore: Int,
        rootRiskScore: Int,
        securityPatchScore: Int,
        malwareRiskScore: Int,
        behaviorRiskScore: Int
    ): Int {

        val score =
            (integrityScore * 0.35) +
            ((100 - rootRiskScore) * 0.25) +
            (securityPatchScore * 0.15) +
            ((100 - malwareRiskScore) * 0.15) +
            ((100 - behaviorRiskScore) * 0.10)

        return score.toInt().coerceIn(0, 100)
    }

    /**
     * Determine trust level.
     */
    fun determineTrustLevel(
        trustScore: Int
    ): TrustLevel {

        return when {
            trustScore >= 85 ->
                TrustLevel.TRUSTED

            trustScore >= 65 ->
                TrustLevel.MODERATELY_TRUSTED

            trustScore >= 40 ->
                TrustLevel.LOW_TRUST

            else ->
                TrustLevel.UNTRUSTED
        }
    }

    /**
     * Determine whether device can access
     * sensitive functionality.
     */
    fun canAccessSensitiveFeatures(
        trustLevel: TrustLevel
    ): Boolean {

        return trustLevel == TrustLevel.TRUSTED ||
                trustLevel == TrustLevel.MODERATELY_TRUSTED
    }

    /**
     * Determine whether financial operations
     * should be allowed.
     */
    fun canPerformFinancialTransactions(
        trustLevel: TrustLevel,
        realtimeProtectionEnabled: Boolean
    ): Boolean {

        return trustLevel == TrustLevel.TRUSTED &&
                realtimeProtectionEnabled
    }

    /**
     * Check if device passes trust validation.
     */
    fun passesTrustValidation(
        trustScore: Int
    ): Boolean {
        return trustScore >= 70
    }

    /**
     * Determine whether device should be flagged.
     */
    fun shouldFlagDevice(
        trustLevel: TrustLevel
    ): Boolean {

        return trustLevel == TrustLevel.LOW_TRUST ||
                trustLevel == TrustLevel.UNTRUSTED
    }

    /**
     * Determine whether additional verification
     * should be required.
     */
    fun requiresAdditionalVerification(
        trustLevel: TrustLevel
    ): Boolean {

        return trustLevel == TrustLevel.MODERATELY_TRUSTED ||
                trustLevel == TrustLevel.LOW_TRUST
    }

    /**
     * Determine whether device should be blocked.
     */
    fun shouldBlockDevice(
        trustLevel: TrustLevel
    ): Boolean {

        return trustLevel == TrustLevel.UNTRUSTED
    }

    /**
     * Calculate security patch score.
     */
    fun calculatePatchScore(
        daysSinceLastSecurityUpdate: Int
    ): Int {

        return when {
            daysSinceLastSecurityUpdate <= 30 -> 100
            daysSinceLastSecurityUpdate <= 60 -> 85
            daysSinceLastSecurityUpdate <= 90 -> 70
            daysSinceLastSecurityUpdate <= 180 -> 50
            else -> 25
        }
    }

    /**
     * Determine whether device is considered healthy.
     */
    fun isHealthyDevice(
        trustScore: Int,
        activeThreats: Int
    ): Boolean {

        return trustScore >= 75 &&
                activeThreats == 0
    }

    /**
     * Calculate confidence level of trust assessment.
     */
    fun calculateTrustConfidence(
        completedChecks: Int,
        totalChecks: Int
    ): Double {

        if (totalChecks <= 0) {
            return 0.0
        }

        return completedChecks.toDouble() /
                totalChecks.toDouble()
    }

    /**
     * Generate trust summary.
     */
    fun getTrustSummary(
        trustLevel: TrustLevel
    ): String {

        return when (trustLevel) {

            TrustLevel.TRUSTED ->
                "Device is trusted and meets security requirements."

            TrustLevel.MODERATELY_TRUSTED ->
                "Device is generally trusted but requires monitoring."

            TrustLevel.LOW_TRUST ->
                "Device trust is reduced due to security concerns."

            TrustLevel.UNTRUSTED ->
                "Device cannot be trusted for sensitive operations."
        }
    }

    /**
     * Generate recommended action.
     */
    fun getRecommendedAction(
        trustLevel: TrustLevel
    ): String {

        return when (trustLevel) {

            TrustLevel.TRUSTED ->
                "No action required."

            TrustLevel.MODERATELY_TRUSTED ->
                "Perform additional security verification."

            TrustLevel.LOW_TRUST ->
                "Investigate device risks and strengthen protection."

            TrustLevel.UNTRUSTED ->
                "Restrict device access and perform remediation."
        }
    }

    /**
     * Determine whether a trust alert should be generated.
     */
    fun requiresTrustAlert(
        trustLevel: TrustLevel
    ): Boolean {

        return trustLevel == TrustLevel.LOW_TRUST ||
                trustLevel == TrustLevel.UNTRUSTED
    }
}
