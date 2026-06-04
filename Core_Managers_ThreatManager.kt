package com.sentrix.core.managers

import android.content.Context
import com.sentrix.core.enums.AlertPriority
import com.sentrix.core.enums.ScanStatus
import com.sentrix.core.enums.SecurityStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.CopyOnWriteArrayList

/**
 * ThreatManager
 *
 * Central manager responsible for:
 * - Threat registration
 * - Threat tracking
 * - Threat severity calculation
 * - Threat history maintenance
 * - Security status evaluation
 */
object ThreatManager {

    private val detectedThreats = CopyOnWriteArrayList<ThreatRecord>()

    /**
     * Add a new threat.
     */
    fun registerThreat(
        title: String,
        description: String,
        severity: Int,
        source: String
    ) {
        detectedThreats.add(
            ThreatRecord(
                title = title,
                description = description,
                severity = severity.coerceIn(1, 10),
                source = source,
                timestamp = System.currentTimeMillis()
            )
        )
    }

    /**
     * Remove threat.
     */
    fun removeThreat(title: String) {
        detectedThreats.removeAll {
            it.title.equals(title, ignoreCase = true)
        }
    }

    /**
     * Clear all threats.
     */
    fun clearThreats() {
        detectedThreats.clear()
    }

    /**
     * Get all threats.
     */
    fun getThreats(): List<ThreatRecord> {
        return detectedThreats.toList()
    }

    /**
     * Total threat count.
     */
    fun getThreatCount(): Int {
        return detectedThreats.size
    }

    /**
     * Calculate risk score.
     */
    fun calculateThreatScore(): Int {
        if (detectedThreats.isEmpty()) return 0

        return detectedThreats.sumOf { it.severity }
            .coerceIn(0, 100)
    }

    /**
     * Determine security status.
     */
    fun getSecurityStatus(): SecurityStatus {
        val score = calculateThreatScore()

        return when {
            score == 0 -> SecurityStatus.SECURE
            score <= 20 -> SecurityStatus.LOW_RISK
            score <= 50 -> SecurityStatus.MODERATE_RISK
            score <= 80 -> SecurityStatus.HIGH_RISK
            else -> SecurityStatus.CRITICAL
        }
    }

    /**
     * Get highest priority alert.
     */
    fun getAlertPriority(): AlertPriority {
        val score = calculateThreatScore()

        return when {
            score <= 10 -> AlertPriority.LOW
            score <= 30 -> AlertPriority.MEDIUM
            score <= 60 -> AlertPriority.HIGH
            else -> AlertPriority.CRITICAL
        }
    }

    /**
     * Returns latest threat.
     */
    fun getLatestThreat(): ThreatRecord? {
        return detectedThreats.maxByOrNull { it.timestamp }
    }

    /**
     * Returns critical threats.
     */
    fun getCriticalThreats(): List<ThreatRecord> {
        return detectedThreats.filter { it.severity >= 8 }
    }

    /**
     * Scan result evaluator.
     */
    suspend fun evaluateScanResult(
        context: Context,
        status: ScanStatus
    ): SecurityStatus = withContext(Dispatchers.Default) {

        when (status) {
            ScanStatus.COMPLETED -> {
                getSecurityStatus()
            }

            ScanStatus.SCANNING -> {
                SecurityStatus.MODERATE_RISK
            }

            ScanStatus.FAILED -> {
                SecurityStatus.HIGH_RISK
            }

            ScanStatus.CANCELLED -> {
                SecurityStatus.MODERATE_RISK
            }

            ScanStatus.IDLE -> {
                SecurityStatus.SECURE
            }
        }
    }

    /**
     * Generates threat summary.
     */
    fun generateThreatSummary(): String {

        if (detectedThreats.isEmpty()) {
            return "No threats detected."
        }

        val critical = getCriticalThreats().size

        return buildString {
            appendLine("Threat Summary")
            appendLine("---------------")
            appendLine("Total Threats : ${detectedThreats.size}")
            appendLine("Critical      : $critical")
            appendLine("Risk Score    : ${calculateThreatScore()}")
            appendLine("Status        : ${getSecurityStatus()}")
        }
    }

    /**
     * Threat model.
     */
    data class ThreatRecord(
        val title: String,
        val description: String,
        val severity: Int,
        val source: String,
        val timestamp: Long
    )
}
