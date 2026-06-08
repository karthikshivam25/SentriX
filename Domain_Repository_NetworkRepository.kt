package com.sentrix.domain.repositories

import com.sentrix.domain.models.NetworkConnection
import com.sentrix.domain.models.NetworkRisk
import com.sentrix.domain.models.NetworkStatus

/**
 * NetworkRepository
 *
 * Repository responsible for
 * managing network-related
 * information within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - MonitorNetworkUseCase
 * - NetworkProtectionEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ThreatAnalysisEngine
 *
 * Responsibilities:
 * - Monitor network activity
 * - Store connection records
 * - Analyze network risks
 * - Detect suspicious traffic
 * - Provide network analytics
 */
interface NetworkRepository {

    /**
     * Retrieves all
     * network connections.
     *
     * @return Connection list.
     */
    suspend fun getConnections():
        List<NetworkConnection>

    /**
     * Retrieves connection
     * by identifier.
     *
     * @param connectionId Connection ID.
     *
     * @return Connection record.
     */
    suspend fun getConnectionById(
        connectionId: String
    ): NetworkConnection?

    /**
     * Saves connection.
     *
     * @param connection Network connection.
     */
    suspend fun saveConnection(
        connection: NetworkConnection
    )

    /**
     * Updates connection.
     *
     * @param connection Network connection.
     */
    suspend fun updateConnection(
        connection: NetworkConnection
    )

    /**
     * Deletes connection.
     *
     * @param connectionId Connection ID.
     */
    suspend fun deleteConnection(
        connectionId: String
    )

    /**
     * Retrieves suspicious
     * network connections.
     *
     * @return Suspicious connections.
     */
    suspend fun getSuspiciousConnections():
        List<NetworkConnection>

    /**
     * Retrieves connections
     * by risk level.
     *
     * @param risk Risk level.
     *
     * @return Connection list.
     */
    suspend fun getConnectionsByRisk(
        risk: NetworkRisk
    ): List<NetworkConnection>

    /**
     * Retrieves current
     * network status.
     *
     * @return Network status.
     */
    suspend fun getNetworkStatus():
        NetworkStatus

    /**
     * Retrieves total
     * connection count.
     *
     * @return Connection count.
     */
    suspend fun getConnectionCount():
        Int
}

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
     * Risk level.
     */
    val risk:
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
     * High risk.
     */
    HIGH,

    /**
     * Critical risk.
     */
    CRITICAL
}

/**
 * Network status.
 */
enum class NetworkStatus {

    /**
     * Secure network.
     */
    SECURE,

    /**
     * Moderate risk.
     */
    MODERATE_RISK,

    /**
     * High risk.
     */
    HIGH_RISK,

    /**
     * Critical threat detected.
     */
    CRITICAL
}
