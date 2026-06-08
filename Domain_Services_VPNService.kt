package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.VPNConnection
import com.cyberdefender.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for VPN connection management and security analysis.
 *
 * This service validates VPN connections,
 * monitors connection status, and generates
 * VPN-related security threat indicators.
 */
class VPNService {

    /**
     * Analyzes VPN connections and generates threat indicators.
     *
     * Rules:
     * - Disconnected VPN -> HIGH threat.
     * - Untrusted VPN provider -> MEDIUM threat.
     * - Weak encryption -> HIGH threat.
     * - Expired VPN certificate -> CRITICAL threat.
     */
    suspend fun analyzeVPNConnections(
        vpnConnections: List<VPNConnection>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        vpnConnections.mapNotNull { vpn ->

            when {

                // VPN certificate has expired
                vpn.isCertificateExpired -> {
                    ThreatIndicator(
                        id = vpn.connectionId,
                        threatName = "Expired VPN Certificate",
                        severity = "CRITICAL",
                        description = "VPN certificate has expired and connection may be insecure",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Weak encryption detected
                vpn.encryptionLevel.equals("WEAK", ignoreCase = true) -> {
                    ThreatIndicator(
                        id = vpn.connectionId,
                        threatName = "Weak VPN Encryption",
                        severity = "HIGH",
                        description = "VPN is using weak encryption standards",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // VPN not connected
                !vpn.isConnected -> {
                    ThreatIndicator(
                        id = vpn.connectionId,
                        threatName = "VPN Disconnected",
                        severity = "HIGH",
                        description = "VPN protection is currently disabled",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // VPN provider is not trusted
                !vpn.isTrustedProvider -> {
                    ThreatIndicator(
                        id = vpn.connectionId,
                        threatName = "Untrusted VPN Provider",
                        severity = "MEDIUM",
                        description = "Connected VPN provider is not trusted",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns all active VPN connections.
     */
    suspend fun getActiveVPNConnections(
        vpnConnections: List<VPNConnection>
    ): List<VPNConnection> = withContext(Dispatchers.Default) {

        vpnConnections.filter {
            it.isConnected
        }
    }

    /**
     * Returns all disconnected VPN connections.
     */
    suspend fun getDisconnectedVPNConnections(
        vpnConnections: List<VPNConnection>
    ): List<VPNConnection> = withContext(Dispatchers.Default) {

        vpnConnections.filter {
            !it.isConnected
        }
    }

    /**
     * Returns VPN connections using weak encryption.
     */
    suspend fun getWeakEncryptionConnections(
        vpnConnections: List<VPNConnection>
    ): List<VPNConnection> = withContext(Dispatchers.Default) {

        vpnConnections.filter {
            it.encryptionLevel.equals("WEAK", ignoreCase = true)
        }
    }

    /**
     * Returns VPN connections with expired certificates.
     */
    suspend fun getExpiredCertificateConnections(
        vpnConnections: List<VPNConnection>
    ): List<VPNConnection> = withContext(Dispatchers.Default) {

        vpnConnections.filter {
            it.isCertificateExpired
        }
    }

    /**
     * Calculates overall VPN security risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateVPNRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Determines whether VPN-related threats exist.
     */
    suspend fun hasVPNThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns only critical VPN threats.
     */
    suspend fun getCriticalVPNThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Generates a VPN security summary.
     */
    suspend fun generateVPNSummary(
        vpnConnections: List<VPNConnection>
    ): String = withContext(Dispatchers.Default) {

        val totalConnections = vpnConnections.size

        val activeConnections = vpnConnections.count {
            it.isConnected
        }

        val disconnectedConnections = vpnConnections.count {
            !it.isConnected
        }

        val weakEncryptionCount = vpnConnections.count {
            it.encryptionLevel.equals("WEAK", ignoreCase = true)
        }

        buildString {
            appendLine("VPN Security Summary")
            appendLine("--------------------")
            appendLine("Total VPN Connections: $totalConnections")
            appendLine("Active Connections: $activeConnections")
            appendLine("Disconnected Connections: $disconnectedConnections")
            appendLine("Weak Encryption Connections: $weakEncryptionCount")
            appendLine(
                if (disconnectedConnections > 0)
                    "Status: VPN Protection Required"
                else
                    "Status: VPN Protected"
            )
        }
    }

    /**
     * Checks whether all VPN connections are secure.
     */
    suspend fun areVPNConnectionsSecure(
        vpnConnections: List<VPNConnection>
    ): Boolean = withContext(Dispatchers.Default) {

        vpnConnections.all {
            it.isConnected &&
            it.isTrustedProvider &&
            !it.isCertificateExpired &&
            !it.encryptionLevel.equals("WEAK", ignoreCase = true)
        }
    }
}
