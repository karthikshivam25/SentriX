package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * VPN Engine
 *
 * Responsible for:
 * - VPN connection management
 * - VPN security validation
 * - VPN provider analysis
 * - Connection monitoring
 * - VPN risk assessment
 */
class VPNEngine {

    private val vpnConnections =
        ConcurrentHashMap<String, VPNConnection>()

    data class VPNConnection(
        val connectionId: String,
        val providerName: String,
        val serverLocation: String,
        val isConnected: Boolean,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Establishes a VPN connection profile.
     */
    suspend fun connect(
        connectionId: String,
        providerName: String,
        serverLocation: String
    ): NetworkResult<VPNConnection> = withContext(Dispatchers.IO) {

        try {

            val connection = VPNConnection(
                connectionId = connectionId,
                providerName = providerName,
                serverLocation = serverLocation,
                isConnected = true
            )

            vpnConnections[connectionId] = connection

            NetworkResult.Success(connection)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "VPN connection failed"
            )
        }
    }

    /**
     * Disconnects a VPN connection.
     */
    fun disconnect(
        connectionId: String
    ): Boolean {
        return vpnConnections.remove(connectionId) != null
    }

    /**
     * Retrieves VPN connection.
     */
    fun getConnection(
        connectionId: String
    ): VPNConnection? {
        return vpnConnections[connectionId]
    }

    /**
     * Returns all active VPN connections.
     */
    fun getConnections(): List<VPNConnection> {
        return vpnConnections.values.toList()
    }

    /**
     * Checks if a VPN connection exists.
     */
    fun isConnected(
        connectionId: String
    ): Boolean {
        return vpnConnections[connectionId]?.isConnected == true
    }

    /**
     * Calculates VPN security score.
     */
    fun calculateSecurityScore(
        providerTrusted: Boolean,
        encryptionEnabled: Boolean,
        killSwitchEnabled: Boolean
    ): Int {

        var score = 0

        if (providerTrusted) score += 40
        if (encryptionEnabled) score += 35
        if (killSwitchEnabled) score += 25

        return score.coerceIn(0, 100)
    }

    /**
     * Returns VPN security level.
     */
    fun getSecurityLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "MAXIMUM"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "UNSECURED"
        }
    }

    /**
     * Evaluates VPN risk score.
     */
    fun calculateRiskScore(
        providerTrusted: Boolean,
        suspiciousActivityDetected: Boolean
    ): Int {

        var risk = 0

        if (!providerTrusted) {
            risk += 60
        }

        if (suspiciousActivityDetected) {
            risk += 40
        }

        return risk.coerceIn(0, 100)
    }

    /**
     * Generates VPN recommendations.
     */
    fun generateRecommendations(
        securityScore: Int
    ): List<String> {

        return when {
            securityScore >= 90 -> listOf(
                "VPN configuration is highly secure."
            )

            securityScore >= 75 -> listOf(
                "VPN configuration is secure.",
                "Continue monitoring connection health."
            )

            securityScore >= 50 -> listOf(
                "Enable additional VPN security features.",
                "Verify provider trustworthiness."
            )

            else -> listOf(
                "Use a trusted VPN provider.",
                "Enable encryption and kill switch.",
                "Review VPN security settings."
            )
        }
    }

    /**
     * Clears all VPN connections.
     */
    fun clearConnections() {
        vpnConnections.clear()
    }

    /**
     * Returns active connection count.
     */
    fun getConnectionCount(): Int {
        return vpnConnections.size
    }
}
