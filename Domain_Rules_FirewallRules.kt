package com.sentrix.domain.rules

/**
 * SentriX Firewall Rules
 *
 * Provides centralized firewall policies, traffic evaluation,
 * port risk assessment, and connection filtering logic.
 */
object FirewallRules {

    enum class FirewallDecision {
        ALLOW,
        BLOCK,
        MONITOR
    }

    enum class PortRiskLevel {
        SAFE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private val CRITICAL_PORTS = setOf(
        21,     // FTP
        23,     // Telnet
        135,    // RPC
        137,    // NetBIOS
        138,
        139,
        445,    // SMB
        1433,   // MSSQL
        3389    // RDP
    )

    private val HIGH_RISK_PORTS = setOf(
        22,     // SSH
        25,     // SMTP
        53,     // DNS
        110,    // POP3
        5900,   // VNC
        8080
    )

    /**
     * Evaluate inbound connection.
     */
    fun evaluateInboundConnection(
        port: Int,
        isTrustedSource: Boolean,
        isEncrypted: Boolean,
        hasThreatIndicators: Boolean
    ): FirewallDecision {

        if (hasThreatIndicators) {
            return FirewallDecision.BLOCK
        }

        if (!isTrustedSource && isHighRiskPort(port)) {
            return FirewallDecision.BLOCK
        }

        if (!isEncrypted && isSensitivePort(port)) {
            return FirewallDecision.MONITOR
        }

        return FirewallDecision.ALLOW
    }

    /**
     * Evaluate outbound connection.
     */
    fun evaluateOutboundConnection(
        destinationIpReputation: Int,
        usesSecureProtocol: Boolean,
        hasMaliciousIndicators: Boolean
    ): FirewallDecision {

        return when {
            hasMaliciousIndicators ->
                FirewallDecision.BLOCK

            destinationIpReputation < 30 ->
                FirewallDecision.BLOCK

            !usesSecureProtocol ->
                FirewallDecision.MONITOR

            else ->
                FirewallDecision.ALLOW
        }
    }

    /**
     * Calculate port risk level.
     */
    fun getPortRiskLevel(
        port: Int
    ): PortRiskLevel {

        return when {
            CRITICAL_PORTS.contains(port) ->
                PortRiskLevel.CRITICAL

            HIGH_RISK_PORTS.contains(port) ->
                PortRiskLevel.HIGH

            port in 1024..49151 ->
                PortRiskLevel.MEDIUM

            port in 49152..65535 ->
                PortRiskLevel.LOW

            else ->
                PortRiskLevel.SAFE
        }
    }

    /**
     * Check whether port is high risk.
     */
    fun isHighRiskPort(
        port: Int
    ): Boolean {

        return getPortRiskLevel(port) == PortRiskLevel.HIGH ||
                getPortRiskLevel(port) == PortRiskLevel.CRITICAL
    }

    /**
     * Check whether port carries sensitive traffic.
     */
    fun isSensitivePort(
        port: Int
    ): Boolean {

        return port == 21 ||
                port == 22 ||
                port == 23 ||
                port == 25 ||
                port == 53 ||
                port == 443 ||
                port == 445 ||
                port == 3389
    }

    /**
     * Calculate firewall threat score.
     */
    fun calculateThreatScore(
        blockedConnections: Int,
        suspiciousConnections: Int,
        maliciousConnections: Int
    ): Int {

        val score =
            (blockedConnections * 2) +
            (suspiciousConnections * 5) +
            (maliciousConnections * 10)

        return score.coerceAtMost(100)
    }

    /**
     * Determine whether emergency protection
     * should be enabled.
     */
    fun shouldEnableEmergencyMode(
        threatScore: Int
    ): Boolean {
        return threatScore >= 75
    }

    /**
     * Determine whether IP should be blocked.
     */
    fun shouldBlockIp(
        reputationScore: Int,
        failedAttempts: Int
    ): Boolean {

        return reputationScore < 20 ||
                failedAttempts >= 5
    }

    /**
     * Generate firewall security summary.
     */
    fun getFirewallSummary(
        threatScore: Int
    ): String {

        return when {
            threatScore >= 75 ->
                "Critical firewall threat activity detected."

            threatScore >= 50 ->
                "High firewall threat activity detected."

            threatScore >= 25 ->
                "Moderate firewall events detected."

            threatScore > 0 ->
                "Minor firewall events detected."

            else ->
                "Firewall operating normally."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        threatScore: Int
    ): String {

        return when {
            threatScore >= 75 ->
                "Enable emergency protection and block suspicious traffic."

            threatScore >= 50 ->
                "Increase monitoring and restrict risky connections."

            threatScore >= 25 ->
                "Review firewall logs and investigate anomalies."

            threatScore > 0 ->
                "Continue monitoring network activity."

            else ->
                "No action required."
        }
    }

    /**
     * Determine whether a security alert
     * should be raised.
     */
    fun requiresSecurityAlert(
        threatScore: Int
    ): Boolean {
        return threatScore >= 50
    }
}
