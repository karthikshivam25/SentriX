package com.sentrix.domain.rules

/**
 * SentriX Network Security Rules
 *
 * Centralized rules for evaluating network security,
 * detecting suspicious connections, and calculating
 * network trust and risk levels.
 */
object NetworkSecurityRules {

    enum class NetworkSecurityLevel {
        SECURE,
        LOW_RISK,
        MEDIUM_RISK,
        HIGH_RISK,
        DANGEROUS
    }

    enum class ConnectionType {
        WIFI,
        MOBILE_DATA,
        VPN,
        ETHERNET,
        UNKNOWN
    }

    /**
     * Calculate network risk score.
     *
     * Returns score between 0 and 100.
     */
    fun calculateRiskScore(
        isVpnConnected: Boolean,
        isPublicWifi: Boolean,
        isEncryptedConnection: Boolean,
        hasSuspiciousDns: Boolean,
        hasMitmIndicators: Boolean,
        hasCertificateIssues: Boolean,
        hasOpenPortsDetected: Boolean
    ): Int {

        var score = 0

        if (isPublicWifi) score += 20
        if (!isEncryptedConnection) score += 25
        if (hasSuspiciousDns) score += 20
        if (hasMitmIndicators) score += 35
        if (hasCertificateIssues) score += 20
        if (hasOpenPortsDetected) score += 10

        // VPN reduces risk slightly
        if (isVpnConnected) score -= 10

        return score.coerceIn(0, 100)
    }

    /**
     * Determine network security level.
     */
    fun determineSecurityLevel(
        riskScore: Int
    ): NetworkSecurityLevel {

        return when {
            riskScore >= 80 -> NetworkSecurityLevel.DANGEROUS
            riskScore >= 60 -> NetworkSecurityLevel.HIGH_RISK
            riskScore >= 35 -> NetworkSecurityLevel.MEDIUM_RISK
            riskScore >= 15 -> NetworkSecurityLevel.LOW_RISK
            else -> NetworkSecurityLevel.SECURE
        }
    }

    /**
     * Check whether network is trusted.
     */
    fun isTrustedNetwork(
        securityLevel: NetworkSecurityLevel
    ): Boolean {

        return securityLevel == NetworkSecurityLevel.SECURE ||
                securityLevel == NetworkSecurityLevel.LOW_RISK
    }

    /**
     * Determine whether sensitive transactions
     * should be blocked.
     */
    fun shouldRestrictSensitiveOperations(
        securityLevel: NetworkSecurityLevel
    ): Boolean {

        return securityLevel == NetworkSecurityLevel.HIGH_RISK ||
                securityLevel == NetworkSecurityLevel.DANGEROUS
    }

    /**
     * Detect possible Man-in-the-Middle attack.
     */
    fun detectMitmRisk(
        hasCertificateIssues: Boolean,
        hasSuspiciousDns: Boolean,
        hasMitmIndicators: Boolean
    ): Boolean {

        return hasMitmIndicators ||
                (hasCertificateIssues && hasSuspiciousDns)
    }

    /**
     * Check if network encryption is acceptable.
     */
    fun isSecureEncryption(
        encryptionType: String?
    ): Boolean {

        if (encryptionType.isNullOrBlank()) {
            return false
        }

        return when (encryptionType.uppercase()) {
            "WPA3",
            "WPA2",
            "TLS1.3",
            "TLS1.2" -> true

            else -> false
        }
    }

    /**
     * Determine if DNS provider is suspicious.
     */
    fun isSuspiciousDnsProvider(
        dnsServer: String?
    ): Boolean {

        if (dnsServer.isNullOrBlank()) {
            return false
        }

        val suspiciousDnsServers = setOf(
            "0.0.0.0",
            "255.255.255.255"
        )

        return dnsServer in suspiciousDnsServers
    }

    /**
     * Calculate network trust score.
     */
    fun calculateTrustScore(
        riskScore: Int
    ): Int {
        return (100 - riskScore).coerceIn(0, 100)
    }

    /**
     * Generate network security summary.
     */
    fun getSecuritySummary(
        securityLevel: NetworkSecurityLevel
    ): String {

        return when (securityLevel) {

            NetworkSecurityLevel.SECURE ->
                "Network security verified. No threats detected."

            NetworkSecurityLevel.LOW_RISK ->
                "Minor network security concerns detected."

            NetworkSecurityLevel.MEDIUM_RISK ->
                "Moderate network security risks identified."

            NetworkSecurityLevel.HIGH_RISK ->
                "High-risk network detected. Caution recommended."

            NetworkSecurityLevel.DANGEROUS ->
                "Dangerous network environment detected."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        securityLevel: NetworkSecurityLevel
    ): String {

        return when (securityLevel) {

            NetworkSecurityLevel.SECURE ->
                "No action required."

            NetworkSecurityLevel.LOW_RISK ->
                "Continue monitoring network activity."

            NetworkSecurityLevel.MEDIUM_RISK ->
                "Verify network integrity and DNS configuration."

            NetworkSecurityLevel.HIGH_RISK ->
                "Avoid sensitive transactions and use VPN."

            NetworkSecurityLevel.DANGEROUS ->
                "Disconnect immediately and switch to a trusted network."
        }
    }

    /**
     * Determine if a security alert should be raised.
     */
    fun requiresSecurityAlert(
        securityLevel: NetworkSecurityLevel
    ): Boolean {

        return securityLevel == NetworkSecurityLevel.HIGH_RISK ||
                securityLevel == NetworkSecurityLevel.DANGEROUS
    }
}
