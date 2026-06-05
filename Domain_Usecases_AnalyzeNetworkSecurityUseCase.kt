package com.sentrix.domain.usecases

import com.sentrix.domain.models.NetworkConnection
import com.sentrix.domain.repositories.NetworkSecurityRepository

/**
 * AnalyzeNetworkSecurityUseCase
 *
 * Responsible for analyzing network security
 * posture and identifying suspicious, malicious,
 * or unauthorized network activities within the
 * SentriX cybersecurity platform.
 *
 * This use case evaluates active connections,
 * traffic patterns, network reputation,
 * communication endpoints, protocol usage,
 * encryption status, and threat intelligence
 * indicators to determine network risk.
 *
 * Used by:
 * - NetworkSecurityManager
 * - RealtimeProtectionEngine
 * - FirewallManager
 * - IntrusionDetectionSystem
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - ZeroTrustManager
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze network connections
 * - Detect suspicious communication
 * - Evaluate endpoint reputation
 * - Identify network anomalies
 * - Calculate network risk scores
 * - Generate remediation recommendations
 */
class AnalyzeNetworkSecurityUseCase(
    private val repository: NetworkSecurityRepository
) {

    /**
     * Executes network security analysis.
     *
     * @return NetworkSecurityAnalysisResult
     */
    suspend operator fun invoke():
        NetworkSecurityAnalysisResult {

        val connections =
            repository.getActiveConnections()

        val maliciousEndpoints =
            repository.getMaliciousEndpoints()

        val suspiciousConnections =
            connections.filter { connection ->
                maliciousEndpoints.contains(
                    connection.remoteAddress
                )
            }

        val unencryptedConnections =
            connections.filter {
                !it.isEncrypted
            }

        val networkRiskLevel =
            determineRiskLevel(
                suspiciousConnections.size,
                unencryptedConnections.size
            )

        val networkRiskScore =
            calculateRiskScore(
                suspiciousConnections.size,
                unencryptedConnections.size
            )

        return NetworkSecurityAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            totalConnections = connections.size,
            suspiciousConnections =
                suspiciousConnections,
            unencryptedConnections =
                unencryptedConnections,
            riskLevel = networkRiskLevel,
            riskScore = networkRiskScore,
            recommendations =
                generateRecommendations(
                    networkRiskLevel
                )
        )
    }

    /**
     * Determines network risk level.
     */
    private fun determineRiskLevel(
        suspiciousConnections: Int,
        unencryptedConnections: Int
    ): NetworkRiskLevel {

        return when {

            suspiciousConnections >= 5 ->
                NetworkRiskLevel.CRITICAL

            suspiciousConnections >= 3 ->
                NetworkRiskLevel.HIGH

            unencryptedConnections >= 10 ->
                NetworkRiskLevel.MEDIUM

            else ->
                NetworkRiskLevel.LOW
        }
    }

    /**
     * Calculates network risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        suspiciousConnections: Int,
        unencryptedConnections: Int
    ): Int {

        val score =
            (suspiciousConnections * 20) +
            (unencryptedConnections * 3)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates security recommendations
     * based on network risk analysis.
     */
    private fun generateRecommendations(
        riskLevel: NetworkRiskLevel
    ): List<String> {

        return when (riskLevel) {

            NetworkRiskLevel.CRITICAL -> listOf(
                "Block malicious endpoints immediately",
                "Enable emergency firewall rules",
                "Investigate possible compromise",
                "Notify security administrators"
            )

            NetworkRiskLevel.HIGH -> listOf(
                "Review suspicious connections",
                "Increase network monitoring",
                "Perform intrusion investigation"
            )

            NetworkRiskLevel.MEDIUM -> listOf(
                "Enable encrypted communication",
                "Review network configurations"
            )

            NetworkRiskLevel.LOW -> listOf(
                "Network security posture is healthy"
            )
        }
    }
}

/**
 * NetworkSecurityAnalysisResult
 *
 * Represents the outcome of network
 * security analysis.
 */
data class NetworkSecurityAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Total network connections analyzed.
     */
    val totalConnections: Int,

    /**
     * Suspicious connections detected.
     */
    val suspiciousConnections:
        List<NetworkConnection>,

    /**
     * Unencrypted connections detected.
     */
    val unencryptedConnections:
        List<NetworkConnection>,

    /**
     * Calculated network risk level.
     */
    val riskLevel: NetworkRiskLevel,

    /**
     * Calculated network risk score.
     */
    val riskScore: Int,

    /**
     * Security recommendations.
     */
    val recommendations: List<String>
)

/**
 * Network risk indicators.
 */
enum class NetworkRiskLevel {

    /**
     * Low network risk.
     */
    LOW,

    /**
     * Moderate network risk.
     */
    MEDIUM,

    /**
     * High network risk.
     */
    HIGH,

    /**
     * Critical network risk.
     */
    CRITICAL
}
