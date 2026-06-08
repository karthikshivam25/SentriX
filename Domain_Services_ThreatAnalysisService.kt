package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.ScanResult
import com.cyberdefender.domain.models.ThreatIndicator
import com.cyberdefender.domain.models.SecurityAlert
import com.cyberdefender.domain.models.SecurityMetrics
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for analyzing scan results,
 * generating threat indicators, alerts, and security metrics.
 */
class ThreatAnalysisService {

    /**
     * Analyzes scan results and converts them into threat indicators.
     *
     * Rules:
     * - If threats are detected, create a malware threat indicator.
     * - If device integrity is compromised, create an integrity risk indicator.
     * - Otherwise no threat indicator is generated.
     */
    suspend fun analyzeScanResults(
        scanResults: List<ScanResult>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        scanResults.mapNotNull { result ->

            when {

                // Malware or suspicious threats found during scan
                result.threatsDetected > 0 -> {
                    ThreatIndicator(
                        id = result.scanId,
                        threatName = "Potential Malware",
                        severity = determineSeverity(result.threatsDetected),
                        description = "${result.threatsDetected} threats detected during scan",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Device integrity validation failed
                result.isDeviceCompromised -> {
                    ThreatIndicator(
                        id = result.scanId,
                        threatName = "Device Integrity Risk",
                        severity = "HIGH",
                        description = "Device integrity verification failed",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // No threats found
                else -> null
            }
        }
    }

    /**
     * Converts threat indicators into user-facing security alerts.
     *
     * Each threat indicator becomes one security alert.
     */
    suspend fun generateSecurityAlerts(
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
     * Calculates an overall risk score based on threat severity.
     *
     * Severity weights:
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score is capped at 100.
     */
    suspend fun calculateRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf { indicator ->
            when (indicator.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Generates security metrics for dashboard reporting.
     *
     * Metrics include:
     * - Total scans performed
     * - Total threats detected
     * - Number of compromised devices
     * - Overall risk score
     */
    suspend fun generateSecurityMetrics(
        scanResults: List<ScanResult>,
        indicators: List<ThreatIndicator>
    ): SecurityMetrics = withContext(Dispatchers.Default) {

        // Total number of scans performed
        val totalScans = scanResults.size

        // Count compromised devices
        val compromisedDevices = scanResults.count {
            it.isDeviceCompromised
        }

        // Total threats found across all scans
        val threatsFound = scanResults.sumOf {
            it.threatsDetected
        }

        // Calculate overall risk score
        val riskScore = calculateRiskScore(indicators)

        SecurityMetrics(
            totalScans = totalScans,
            threatsDetected = threatsFound,
            compromisedDevices = compromisedDevices,
            riskScore = riskScore,
            lastUpdated = System.currentTimeMillis()
        )
    }

    /**
     * Returns only critical severity threats.
     */
    suspend fun getCriticalThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns only high-priority threats.
     */
    suspend fun getHighPriorityThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Checks whether any active threats exist.
     *
     * Returns:
     * true  -> Threats available
     * false -> System appears safe
     */
    suspend fun hasActiveThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Determines severity level based on number of detected threats.
     *
     * 20+ threats = CRITICAL
     * 10+ threats = HIGH
     * 5+ threats  = MEDIUM
     * 1+ threats  = LOW
     * 0 threats   = SAFE
     */
    private fun determineSeverity(threatCount: Int): String {
        return when {
            threatCount >= 20 -> "CRITICAL"
            threatCount >= 10 -> "HIGH"
            threatCount >= 5 -> "MEDIUM"
            threatCount > 0 -> "LOW"
            else -> "SAFE"
        }
    }
}
