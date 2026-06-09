package com.sentrix.domain.rules

/**
 * SentriX Root Detection Rules
 *
 * Centralized rules for evaluating root indicators,
 * calculating root risk scores, and determining
 * device compromise status.
 */
object RootDetectionRules {

    enum class RootStatus {
        NOT_ROOTED,
        SUSPICIOUS,
        ROOTED,
        HIGHLY_COMPROMISED
    }

    /**
     * Common root management applications.
     */
    private val ROOT_APPS = setOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.zhiqupk.root.global"
    )

    /**
     * Common root binaries.
     */
    private val ROOT_BINARIES = setOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/system/app/Superuser.apk",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/data/local/xbin/su",
        "/data/local/bin/su"
    )

    /**
     * Calculate root risk score.
     */
    fun calculateRootRiskScore(
        hasRootBinary: Boolean,
        hasRootManagementApp: Boolean,
        canExecuteSuCommand: Boolean,
        isBootloaderUnlocked: Boolean,
        hasSystemPartitionModification: Boolean,
        hasDangerousSystemProperties: Boolean
    ): Int {

        var score = 0

        if (hasRootBinary) score += 30
        if (hasRootManagementApp) score += 25
        if (canExecuteSuCommand) score += 35
        if (isBootloaderUnlocked) score += 10
        if (hasSystemPartitionModification) score += 20
        if (hasDangerousSystemProperties) score += 15

        return score.coerceAtMost(100)
    }

    /**
     * Determine root status.
     */
    fun determineRootStatus(
        riskScore: Int
    ): RootStatus {

        return when {
            riskScore >= 80 -> RootStatus.HIGHLY_COMPROMISED
            riskScore >= 50 -> RootStatus.ROOTED
            riskScore >= 20 -> RootStatus.SUSPICIOUS
            else -> RootStatus.NOT_ROOTED
        }
    }

    /**
     * Check if device is rooted.
     */
    fun isRooted(
        status: RootStatus
    ): Boolean {

        return status == RootStatus.ROOTED ||
                status == RootStatus.HIGHLY_COMPROMISED
    }

    /**
     * Check if root detection requires action.
     */
    fun requiresImmediateAction(
        status: RootStatus
    ): Boolean {

        return status == RootStatus.HIGHLY_COMPROMISED
    }

    /**
     * Determine whether sensitive features
     * should be restricted.
     */
    fun shouldRestrictSensitiveOperations(
        status: RootStatus
    ): Boolean {

        return status == RootStatus.ROOTED ||
                status == RootStatus.HIGHLY_COMPROMISED
    }

    /**
     * Check package name against known root apps.
     */
    fun isKnownRootApp(
        packageName: String?
    ): Boolean {

        if (packageName.isNullOrBlank()) {
            return false
        }

        return ROOT_APPS.contains(packageName)
    }

    /**
     * Check file path against known root binaries.
     */
    fun isKnownRootBinary(
        filePath: String?
    ): Boolean {

        if (filePath.isNullOrBlank()) {
            return false
        }

        return ROOT_BINARIES.contains(filePath)
    }

    /**
     * Detect suspicious root indicators.
     */
    fun hasSuspiciousRootIndicators(
        hasRootBinary: Boolean,
        hasRootManagementApp: Boolean,
        canExecuteSuCommand: Boolean
    ): Boolean {

        return hasRootBinary ||
                hasRootManagementApp ||
                canExecuteSuCommand
    }

    /**
     * Get root assessment summary.
     */
    fun getAssessmentSummary(
        status: RootStatus
    ): String {

        return when (status) {

            RootStatus.NOT_ROOTED ->
                "No root indicators detected."

            RootStatus.SUSPICIOUS ->
                "Suspicious root-related indicators detected."

            RootStatus.ROOTED ->
                "Root access detected on the device."

            RootStatus.HIGHLY_COMPROMISED ->
                "Device appears heavily compromised with root access."
        }
    }

    /**
     * Get recommended action.
     */
    fun getRecommendedAction(
        status: RootStatus
    ): String {

        return when (status) {

            RootStatus.NOT_ROOTED ->
                "No action required."

            RootStatus.SUSPICIOUS ->
                "Monitor device and perform additional verification."

            RootStatus.ROOTED ->
                "Restrict sensitive operations and notify the user."

            RootStatus.HIGHLY_COMPROMISED ->
                "Block sensitive access immediately and initiate remediation."
        }
    }

    /**
     * Determine trust score impact.
     */
    fun getTrustPenalty(
        status: RootStatus
    ): Int {

        return when (status) {
            RootStatus.NOT_ROOTED -> 0
            RootStatus.SUSPICIOUS -> 15
            RootStatus.ROOTED -> 40
            RootStatus.HIGHLY_COMPROMISED -> 70
        }
    }
}
