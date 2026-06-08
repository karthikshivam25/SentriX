package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.NetworkConnection
import com.cyberdefender.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for network security analysis.
 *
 * This service monitors network connections,
 * identifies suspicious communication patterns,
 * and generates network-related threat indicators.
 */
class NetworkSecurityService {

    /**
     * Analyzes network connections and generates threat indicators.
     *
     * Rules:
     * - Unsecured connection -> HIGH threat.
     * - Suspicious IP address -> CRITICAL threat.
     * - Unknown network source -> MEDIUM threat.
     * - Excessive traffic -> LOW threat.
     */
    suspend fun analyzeConnections(
        connections: List<NetworkConnection>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        connections.mapNotNull { connection ->

            when {

                // Suspicious remote endpoint detected
                connection.isSuspiciousIp -> {
                    ThreatIndicator(
                        id = connection.connectionId,
                        threatName = "Suspicious Network Activity",
                        severity = "CRITICAL",
                        description = "Communication with suspicious IP address detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Connection is not encrypted
                !connection.isEncrypted -> {
                    ThreatIndicator(
                        id = connection.connectionId,
                        threatName = "Unsecured Connection",
                        severity = "HIGH",
                        description = "Data transmission is not encrypted",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Unknown source detected
                connection.isUnknownSource -> {
                    ThreatIndicator(
                        id = connection.connectionId,
                        threatName = "Unknown Network Source",
                        severity = "MEDIUM",
                        description = "Connection established from an unknown source",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Unusually high traffic volume
                connection.dataTransferredMb > 5000 -> {
                    ThreatIndicator(
                        id = connection.connectionId,
                        threatName = "Excessive Network Traffic",
                        severity = "LOW",
                        description = "Abnormal network traffic volume detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns suspicious connections.
     */
    suspend fun getSuspiciousConnections(
        connections: List<NetworkConnection>
    ): List<NetworkConnection> = withContext(Dispatchers.Default) {

        connections.filter {
            it.isSuspiciousIp
        }
    }

    /**
     * Returns unsecured connections.
     */
    suspend fun getUnsecuredConnections(
        connections: List<NetworkConnection>
    ): List<NetworkConnection> = withContext(Dispatchers.Default) {

        connections.filter {
            !it.isEncrypted
        }
    }

    /**
     * Returns unknown source connections.
     */
    suspend fun getUnknownSourceConnections(
        connections: List<NetworkConnection>
    ): List<NetworkConnection> = withContext(Dispatchers.Default) {

        connections.filter {
            it.isUnknownSource
        }
    }

    /**
     * Calculates network security risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateNetworkRiskScore(
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
     * Determines whether network threats exist.
     */
    suspend fun hasNetworkThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns critical network threats.
     */
    suspend fun getCriticalNetworkThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority network threats.
     */
    suspend fun getHighPriorityNetworkThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Generates a network security summary.
     */
    suspend fun generateNetworkSummary(
        connections: List<NetworkConnection>
    ): String = withContext(Dispatchers.Default) {

        val totalConnections = connections.size

        val suspiciousConnections = connections.count {
            it.isSuspiciousIp
        }

        val unsecuredConnections = connections.count {
            !it.isEncrypted
        }

        val unknownConnections = connections.count {
            it.isUnknownSource
        }

        buildString {
            appendLine("Network Security Summary")
            appendLine("------------------------")
            appendLine("Total Connections: $totalConnections")
            appendLine("Suspicious Connections: $suspiciousConnections")
            appendLine("Unsecured Connections: $unsecuredConnections")
            appendLine("Unknown Sources: $unknownConnections")
            appendLine(
                if (suspiciousConnections > 0)
                    "Status: Network Threats Detected"
                else
                    "Status: Network Secure"
            )
        }
    }

    /**
     * Checks whether all connections are secure.
     */
    suspend fun areConnectionsSecure(
        connections: List<NetworkConnection>
    ): Boolean = withContext(Dispatchers.Default) {

        connections.none {
            it.isSuspiciousIp ||
            !it.isEncrypted ||
            it.isUnknownSource
        }
    }
}
