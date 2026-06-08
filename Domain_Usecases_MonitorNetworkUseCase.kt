package com.sentrix.domain.usecases

/**
 * MonitorNetworkUseCase
 *
 * Responsible for monitoring
 * network activity within the
 * SentriX cybersecurity platform.
 *
 * Network monitoring helps:
 * - Detect suspicious connections
 * - Identify network threats
 * - Monitor data transfers
 * - Improve network security
 * - Prevent unauthorized access
 *
 * Used by:
 * - NetworkProtectionEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ThreatAnalysisEngine
 *
 * Responsibilities:
 * - Monitor network activity
 * - Analyze connections
 * - Detect suspicious behavior
 * - Generate network reports
 * - Assess network risk
 */
class MonitorNetworkUseCase {

    /**
     * Monitors network activity.
     */
    operator fun invoke(
        connections: List<NetworkConnection>
    ): NetworkMonitoringResult {

        val suspiciousConnections =
            connections.count {
                it.connectionRisk ==
                    NetworkRisk.HIGH
            }

        val criticalConnections =
            connections.count {
                it.connectionRisk ==
                    NetworkRisk.CRITICAL
            }

        return NetworkMonitoringResult(
            monitoredAt =
                System.currentTimeMillis(),

            totalConnections =
                connections.size,

            suspiciousConnections =
                suspiciousConnections,

            criticalConnections =
                criticalConnections,

            networkStatus =
                determineNetworkStatus(
                    suspiciousConnections,
                    criticalConnections
                ),

            connections =
                connections
        )
    }

    /**
     * Determines network status.
     */
    private fun determineNetworkStatus(
        suspiciousConnections: Int,
        criticalConnections: Int
    ): NetworkStatus {

        return when {

            criticalConnections >= 5 ->
                NetworkStatus.CRITICAL

            suspiciousConnections >= 10 ->
                NetworkStatus.HIGH_RISK

            suspiciousConnections >= 5 ->
                NetworkStatus.MODERATE_RISK

            else ->
                NetworkStatus.SECURE
        }
    }
}

/**
 * NetworkMonitoringResult
 *
 * Represents network
 * monitoring results.
 */
data class NetworkMonitoringResult(

    /**
     * Monitoring timestamp.
     */
    val monitoredAt: Long,

    /**
     * Total connections.
     */
    val totalConnections: Int,

    /**
     * Suspicious connections.
     */
    val suspiciousConnections: Int,

    /**
     * Critical connections.
     */
    val criticalConnections: Int,

    /**
     * Overall network status.
     */
    val networkStatus:
        NetworkStatus,

    /**
     * Network connection details.
     */
    val connections:
        List<NetworkConnection>
)

/**
 * NetworkConnection
 *
 * Represents a network
 * connection record.
 */
data class NetworkConnection(

    /**
     * Connection identifier.
     */
    val connectionId: String,

    /**
     * Remote IP address.
     */
    val remoteIp: String,

    /**
     * Port number.
     */
    val port: Int,

    /**
     * Protocol type.
     */
    val protocol: String,

    /**
     * Data transferred.
     */
    val dataTransferred: Long,

    /**
     * Connection timestamp.
     */
    val connectedAt: Long,

    /**
     * Connection risk level.
     */
    val connectionRisk:
        NetworkRisk
)

/**
 * Network risk levels.
 */
enum class NetworkRisk {

    /**
     * Safe connection.
     */
    LOW,

    /**
     * Moderate risk.
     */
    MEDIUM,

    /**
     * Suspicious connection.
     */
    HIGH,

    /**
     * Critical threat.
     */
    CRITICAL
}

/**
 * Network status.
 */
enum class NetworkStatus {

    /**
     * Network is secure.
     */
    SECURE,

    /**
     * Moderate risk detected.
     */
    MODERATE_RISK,

    /**
     * High risk detected.
     */
    HIGH_RISK,

    /**
     * Critical threat detected.
     */
    CRITICAL
}
