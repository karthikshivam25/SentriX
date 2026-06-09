package com.sentrix.domain.rules

/**
 * SentriX Device Integrity Rules
 *
 * Evaluates device trustworthiness and system integrity
 * based on root detection, emulator detection,
 * bootloader status, security patches, and tampering indicators.
 */
object DeviceIntegrityRules {

    enum class IntegrityLevel {
        SECURE,
        MODERATE_RISK,
        HIGH_RISK,
        COMPROMISED
    }

    /**
     * Calculate device integrity score.
     * Returns value between 0 and 100.
     */
    fun calculateIntegrityScore(
        isRooted: Boolean,
        isEmulator: Boolean,
        isBootloaderUnlocked: Boolean,
        isDeveloperOptionsEnabled: Boolean,
        hasRecentSecurityPatch: Boolean,
        hasSystemTamperingDetected: Boolean,
        hasDebuggableAppsInstalled: Boolean
    ): Int {

        var score = 100

        if (isRooted) score -= 40
        if (isEmulator) score -= 15
        if (isBootloaderUnlocked) score -= 20
        if (isDeveloperOptionsEnabled) score -= 5
        if (!hasRecentSecurityPatch) score -= 10
        if (hasSystemTamperingDetected) score -= 25
        if (hasDebuggableAppsInstalled) score -= 10

        return score.coerceIn(0, 100)
    }

    /**
     * Determine device integrity level.
     */
    fun determineIntegrityLevel(
        integrityScore: Int
    ): IntegrityLevel {

        return when {
            integrityScore >= 85 -> IntegrityLevel.SECURE
            integrityScore >= 60 -> IntegrityLevel.MODERATE_RISK
            integrityScore >= 30 -> IntegrityLevel.HIGH_RISK
            else -> IntegrityLevel.COMPROMISED
        }
    }

    /**
     * Check whether device can be trusted
     * for sensitive operations.
     */
    fun isTrustedDevice(
        integrityLevel: IntegrityLevel
    ): Boolean {
        return integrityLevel == IntegrityLevel.SECURE
    }

    /**
     * Check whether financial transactions
     * should be restricted.
     */
    fun shouldRestrictSensitiveOperations(
        integrityLevel: IntegrityLevel
    ): Boolean {

        return integrityLevel == IntegrityLevel.HIGH_RISK ||
                integrityLevel == IntegrityLevel.COMPROMISED
    }

    /**
     * Check whether immediate security alert
     * should be generated.
     */
    fun requiresSecurityAlert(
        integrityLevel: IntegrityLevel
    ): Boolean {

        return integrityLevel == IntegrityLevel.COMPROMISED
    }

    /**
     * Detect suspicious device state.
     */
    fun isSuspiciousDeviceState(
        isRooted: Boolean,
        isBootloaderUnlocked: Boolean,
        hasSystemTamperingDetected: Boolean
    ): Boolean {

        return isRooted ||
                isBootloaderUnlocked ||
                hasSystemTamperingDetected
    }

    /**
     * Generate integrity assessment summary.
     */
    fun getIntegritySummary(
        integrityLevel: IntegrityLevel
    ): String {

        return when (integrityLevel) {

            IntegrityLevel.SECURE ->
                "Device integrity verified. No significant security concerns detected."

            IntegrityLevel.MODERATE_RISK ->
                "Minor security concerns detected. Monitoring recommended."

            IntegrityLevel.HIGH_RISK ->
                "Device integrity is at risk. Sensitive actions should be restricted."

            IntegrityLevel.COMPROMISED ->
                "Device integrity compromised. Immediate remediation required."
        }
    }

    /**
     * Recommended action for integrity level.
     */
    fun getRecommendedAction(
        integrityLevel: IntegrityLevel
    ): String {

        return when (integrityLevel) {

            IntegrityLevel.SECURE ->
                "No action required."

            IntegrityLevel.MODERATE_RISK ->
                "Review security settings and update device software."

            IntegrityLevel.HIGH_RISK ->
                "Disable sensitive operations and perform security inspection."

            IntegrityLevel.COMPROMISED ->
                "Block sensitive access and notify the user immediately."
        }
    }

    /**
     * Determine whether device passes
     * SentriX Trust Validation.
     */
    fun passesTrustValidation(
        integrityScore: Int
    ): Boolean {
        return integrityScore >= 70
    }

    /**
     * Calculate trust percentage.
     */
    fun calculateTrustPercentage(
        integrityScore: Int
    ): Double {
        return integrityScore.toDouble()
    }
}
