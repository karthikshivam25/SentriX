package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Network Security Engine
 *
 * Responsible for:
 * - Network traffic analysis
 * - Connection security validation
 * - Intrusion detection
 * - Network risk assessment
 * - Security recommendations
 */
class NetworkSecurityEngine {

    private val monitoredConnections =
        ConcurrentHashMap<String, NetworkConnection>()

    data class NetworkConnection(
        val connectionId: String,
        val host: String,
        val ipAddress: String,
        val port: Int,
        val encrypted: Boolean,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes a network connection.
     */
    suspend fun analyzeConnection(
        connectionId: String,
        host: String,
        port: Int,
        encrypted: Boolean
    ): NetworkResult<NetworkConnection> = withContext(Dispatchers.IO) {

        try {

            val ipAddress = InetAddress
                .getByName(host)
                .hostAddress

            val connection = NetworkConnection(
                connectionId = connectionId,
                host = host,
                ipAddress = ipAddress,
                port = port,
                encrypted = encrypted
            )

            monitoredConnections[connectionId] = connection

            NetworkResult.Success(connection)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Network analysis failed"
            )
        }
    }

    /**
     * Registers a connection.
     */
    fun registerConnection(
        connection: NetworkConnection
    ) {
        monitoredConnections[connection.connectionId] =
            connection
    }

    /**
     * Retrieves a connection.
     */
    fun getConnection(
        connectionId: String
    ): NetworkConnection? {
        return monitoredConnections[connectionId]
    }

    /**
     * Returns all monitored connections.
     */
    fun getConnections(): List<NetworkConnection> {
        return monitoredConnections.values.toList()
    }

    /**
     * Calculates connection security score.
     */
    fun calculateSecurityScore(
        encrypted: Boolean,
        trustedHost: Boolean,
        suspiciousTraffic: Boolean
    ): Int {

        var score = 100

        if (!encrypted) score -= 40
        if (!trustedHost) score -= 30
        if (suspiciousTraffic) score -= 30

        return score.coerceIn(0, 100)
    }

    /**
     * Calculates overall network security score.
     */
    fun calculateOverallSecurityScore(): Int {

        if (monitoredConnections.isEmpty()) {
            return 100
        }

        val scores = monitoredConnections.values.map {

            calculateSecurityScore(
                encrypted = it.encrypted,
                trustedHost = true,
                suspiciousTraffic = false
            )
        }

        return scores.average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Detects suspicious network behavior.
     */
    fun detectSuspiciousActivity(
        failedConnections: Int,
        unusualPorts: Int,
        trafficSpikes: Int
    ): Boolean {

        val risk =
            (failedConnections * 10) +
            (unusualPorts * 15) +
            (trafficSpikes * 20)

        return risk >= 50
    }

    /**
     * Returns security level.
     */
    fun getSecurityLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "EXCELLENT"
            score >= 75 -> "SECURE"
            score >= 50 -> "WARNING"
            score >= 25 -> "AT_RISK"
            else -> "COMPROMISED"
        }
    }

    /**
     * Generates security recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Network security is optimal."
            )

            score >= 75 -> listOf(
                "Continue monitoring network activity."
            )

            score >= 50 -> listOf(
                "Review connection security settings.",
                "Investigate unusual traffic patterns."
            )

            score >= 25 -> listOf(
                "Enable stronger encryption.",
                "Restrict suspicious connections.",
                "Perform network diagnostics."
            )

            else -> listOf(
                "Immediate network security action required.",
                "Block suspicious traffic.",
                "Audit all active connections."
            )
        }
    }

    /**
     * Removes a monitored connection.
     */
    fun removeConnection(
        connectionId: String
    ) {
        monitoredConnections.remove(connectionId)
    }

    /**
     * Clears all monitored connections.
     */
    fun clearConnections() {
        monitoredConnections.clear()
    }

    /**
     * Returns total connection count.
     */
    fun getConnectionCount(): Int {
        return monitoredConnections.size
    }

    /**
     * Returns encrypted connections only.
     */
    fun getEncryptedConnections(): List<NetworkConnection> {
        return monitoredConnections.values.filter {
            it.encrypted
        }
    }
}
