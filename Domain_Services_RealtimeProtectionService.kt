package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.SecurityAlert
import com.cyberdefender.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Service responsible for real-time threat monitoring
 * and protection management.
 *
 * This service monitors incoming threat indicators,
 * generates alerts, and maintains protection status.
 */
class RealtimeProtectionService {

    /**
     * Indicates whether real-time protection
     * is currently enabled.
     */
    private val protectionEnabled = AtomicBoolean(false)

    /**
     * Enables real-time protection.
     */
    suspend fun startProtection(): Boolean = withContext(Dispatchers.Default) {

        protectionEnabled.set(true)
        true
    }

    /**
     * Disables real-time protection.
     */
    suspend fun stopProtection(): Boolean = withContext(Dispatchers.Default) {

        protectionEnabled.set(false)
        true
    }

    /**
     * Returns current protection status.
     */
    suspend fun isProtectionEnabled(): Boolean = withContext(Dispatchers.Default) {

        protectionEnabled.get()
    }

    /**
     * Monitors threat indicators and returns
     * only active threats requiring attention.
     */
    suspend fun monitorThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            !it.severity.equals("SAFE", ignoreCase = true)
        }
    }

    /**
     * Generates real-time security alerts
     * from detected threat indicators.
     */
    suspend fun generateRealtimeAlerts(
        indicators: List<ThreatIndicator>
    ): List<SecurityAlert> = withContext(Dispatchers.Default) {

        indicators.map { indicator ->
            SecurityAlert(
                id = indicator.id,
                title = indicator.threatName,
                message = indicator.description,
                severity = indicator.severity,
                createdAt = indicator.timestamp,
                isRead = false
            )
        }
    }

    /**
     * Returns critical threats currently detected.
     */
    suspend fun getCriticalThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority threats currently detected.
     */
    suspend fun getHighPriorityThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Checks whether active threats exist.
     */
    suspend fun hasActiveThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Calculates protection risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateProtectionRiskScore(
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
     * Generates a real-time protection summary.
     */
    suspend fun generateProtectionSummary(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        val criticalThreats = indicators.count {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }

        val highThreats = indicators.count {
            it.severity.equals("HIGH", ignoreCase = true)
        }

        val mediumThreats = indicators.count {
            it.severity.equals("MEDIUM", ignoreCase = true)
        }

        val lowThreats = indicators.count {
            it.severity.equals("LOW", ignoreCase = true)
        }

        buildString {
            appendLine("Realtime Protection Summary")
            appendLine("---------------------------")
            appendLine("Protection Enabled: ${protectionEnabled.get()}")
            appendLine("Total Threats: ${indicators.size}")
            appendLine("Critical Threats: $criticalThreats")
            appendLine("High Threats: $highThreats")
            appendLine("Medium Threats: $mediumThreats")
            appendLine("Low Threats: $lowThreats")
            appendLine(
                if (indicators.isNotEmpty())
                    "Status: Active Threat Monitoring"
                else
                    "Status: System Protected"
            )
        }
    }

    /**
     * Clears resolved threats from the active list.
     */
    suspend fun clearResolvedThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filterNot {
            it.severity.equals("SAFE", ignoreCase = true)
        }
    }

    /**
     * Determines whether the system is protected.
     *
     * Protection is considered active when:
     * - Real-time protection is enabled.
     * - No active threats are present.
     */
    suspend fun isSystemProtected(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        protectionEnabled.get() &&
        indicators.isEmpty()
    }
}
