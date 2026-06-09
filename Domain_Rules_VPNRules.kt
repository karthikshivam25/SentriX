package com.sentrix.domain.rules

/**
 * SentriX VPN Rules
 *
 * Centralized rules for VPN validation, trust evaluation,
 * privacy assessment, and security recommendations.
 */
object VPNRules {

    enum class VPNStatus {
        DISCONNECTED,
        CONNECTED,
        TRUSTED,
        SUSPICIOUS
    }

    enum class VPNTrustLevel {
        LOW,
        MEDIUM,
        HIGH
    }

    private val TRUSTED_VPN_PROVIDERS = setOf(
        "ProtonVPN",
        "Mullvad",
        "NordVPN",
        "ExpressVPN",
        "Surfshark",
        "IVPN",
        "Windscribe"
    )

    /**
     * Determine VPN status.
     */
    fun determineStatus(
        isVpnConnected: Boolean,
        hasDnsLeak: Boolean,
        hasIpLeak: Boolean
    ): VPNStatus {

        if (!isVpnConnected) {
            return VPNStatus.DISCONNECTED
        }

        if (hasDnsLeak || hasIpLeak) {
            return VPNStatus.SUSPICIOUS
        }

        return VPNStatus.CONNECTED
    }

    /**
     * Evaluate VPN trust level.
     */
    fun determineTrustLevel(
        providerName: String?,
        hasDnsLeak: Boolean,
        hasIpLeak: Boolean,
        usesStrongEncryption: Boolean
    ): VPNTrustLevel {

        var score = 0

        if (!providerName.isNullOrBlank() &&
            TRUSTED_VPN_PROVIDERS.contains(providerName)
        ) {
            score += 50
        }

        if (usesStrongEncryption) {
            score += 30
        }

        if (!hasDnsLeak) {
            score += 10
        }

        if (!hasIpLeak) {
            score += 10
        }

        return when {
            score >= 80 -> VPNTrustLevel.HIGH
            score >= 50 -> VPNTrustLevel.MEDIUM
            else -> VPNTrustLevel.LOW
        }
    }

    /**
     * Check whether VPN provider is trusted.
     */
    fun isTrustedProvider(
        providerName: String?
    ): Boolean {

        if (providerName.isNullOrBlank()) {
            return false
        }

        return TRUSTED_VPN_PROVIDERS.contains(providerName)
    }

    /**
     * Determine whether VPN is secure.
     */
    fun isSecureVpn(
        hasDnsLeak: Boolean,
        hasIpLeak: Boolean,
        usesStrongEncryption: Boolean
    ): Boolean {

        return !hasDnsLeak &&
                !hasIpLeak &&
                usesStrongEncryption
    }

    /**
     * Detect privacy risks.
     */
    fun hasPrivacyRisk(
        hasDnsLeak: Boolean,
        hasIpLeak: Boolean,
        usesStrongEncryption: Boolean
    ): Boolean {

        return hasDnsLeak ||
                hasIpLeak ||
                !usesStrongEncryption
    }

    /**
     * Calculate VPN security score.
     */
    fun calculateSecurityScore(
        isConnected: Boolean,
        hasDnsLeak: Boolean,
        hasIpLeak: Boolean,
        usesStrongEncryption: Boolean,
        trustedProvider: Boolean
    ): Int {

        var score = 0

        if (isConnected) score += 25
        if (!hasDnsLeak) score += 25
        if (!hasIpLeak) score += 25
        if (usesStrongEncryption) score += 15
        if (trustedProvider) score += 10

        return score.coerceIn(0, 100)
    }

    /**
     * Determine whether sensitive operations
     * should be allowed.
     */
    fun canPerformSensitiveOperations(
        securityScore: Int
    ): Boolean {
        return securityScore >= 70
    }

    /**
     * Generate VPN security summary.
     */
    fun getSecuritySummary(
        status: VPNStatus,
        trustLevel: VPNTrustLevel
    ): String {

        return when (status) {

            VPNStatus.DISCONNECTED ->
                "VPN is not connected."

            VPNStatus.SUSPICIOUS ->
                "VPN connection shows potential privacy leaks."

            VPNStatus.CONNECTED -> {
                when (trustLevel) {
                    VPNTrustLevel.HIGH ->
                        "Trusted VPN connection is active."

                    VPNTrustLevel.MEDIUM ->
                        "VPN connection is active with moderate trust."

                    VPNTrustLevel.LOW ->
                        "VPN connection is active but trust is limited."
                }
            }

            VPNStatus.TRUSTED ->
                "Trusted VPN connection established."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        status: VPNStatus,
        trustLevel: VPNTrustLevel
    ): String {

        return when (status) {

            VPNStatus.DISCONNECTED ->
                "Enable a trusted VPN when using public networks."

            VPNStatus.SUSPICIOUS ->
                "Investigate VPN configuration and verify privacy leaks."

            VPNStatus.CONNECTED -> {
                when (trustLevel) {
                    VPNTrustLevel.HIGH ->
                        "No action required."

                    VPNTrustLevel.MEDIUM ->
                        "Monitor VPN privacy and security settings."

                    VPNTrustLevel.LOW ->
                        "Consider switching to a trusted VPN provider."
                }
            }

            VPNStatus.TRUSTED ->
                "No action required."
        }
    }

    /**
     * Check if security alert should be generated.
     */
    fun requiresSecurityAlert(
        status: VPNStatus
    ): Boolean {
        return status == VPNStatus.SUSPICIOUS
    }
}
