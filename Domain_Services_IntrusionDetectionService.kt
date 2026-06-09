package com.sentrix.domain.services

import com.sentrix.domain.models.IntrusionEvent
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for intrusion detection and analysis.
 *
 * This service monitors intrusion events,
 * identifies suspicious activities,
 * and generates intrusion-related threat indicators.
 */
class IntrusionDetectionService {

    /**
     * Analyzes intrusion events and generates threat indicators.
     *
     * Rules:
     * - Active intrusion detected -> CRITICAL threat.
     * - Multiple failed login attempts -> HIGH threat.
     * - Suspicious access pattern -> MEDIUM threat.
     * - Unknown device access -> LOW threat.
     */
    suspend fun analyzeIntrusionEvents(
        intrusionEvents: List<IntrusionEvent>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        intrusionEvents.mapNotNull { event ->

            when {

                // Active intrusion detected
                event.isIntrusionDetected -> {
                    ThreatIndicator(
                        id = event.eventId,
                        threatName = "Intrusion Detected",
                        severity = "CRITICAL",
                        description = "Unauthorized access attempt detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Excessive failed login attempts
                event.failedLoginAttempts >= 10 -> {
                    ThreatIndicator(
                        id = event.eventId,
                        threatName = "Brute Force Attack",
                        severity = "HIGH",
                        description = "Multiple failed login attempts detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Suspicious behavior pattern
                event.isSuspiciousActivity -> {
                    ThreatIndicator(
                        id = event.eventId,
                        threatName = "Suspicious Activity",
                        severity = "MEDIUM",
                        description = "Abnormal access pattern detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Access from unknown device
                event.isUnknownDevice -> {
                    ThreatIndicator(
                        id = event.eventId,
                        threatName = "Unknown Device Access",
                        severity = "LOW",
                        description = "Access attempt from an unknown device",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns intrusion events where a confirmed intrusion was detected.
     */
    suspend fun getDetectedIntrusions(
        intrusionEvents: List<IntrusionEvent>
    ): List<IntrusionEvent> = withContext(Dispatchers.Default) {

        intrusionEvents.filter {
            it.isIntrusionDetected
        }
    }

    /**
     * Returns events with excessive failed login attempts.
     */
    suspend fun getBruteForceAttempts(
        intrusionEvents: List<IntrusionEvent>
    ): List<IntrusionEvent> = withContext(Dispatchers.Default) {

        intrusionEvents.filter {
            it.failedLoginAttempts >= 10
        }
    }

    /**
     * Returns suspicious activity events.
     */
    suspend fun getSuspiciousActivities(
        intrusionEvents: List<IntrusionEvent>
    ): List<IntrusionEvent> = withContext(Dispatchers.Default) {

        intrusionEvents.filter {
            it.isSuspiciousActivity
        }
    }

    /**
     * Returns events originating from unknown devices.
     */
    suspend fun getUnknownDeviceAccessEvents(
        intrusionEvents: List<IntrusionEvent>
    ): List<IntrusionEvent> = withContext(Dispatchers.Default) {

        intrusionEvents.filter {
            it.isUnknownDevice
        }
    }

    /**
     * Calculates intrusion risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateIntrusionRiskScore(
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
     * Determines whether intrusion threats exist.
     */
    suspend fun hasIntrusionThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns critical intrusion threats.
     */
    suspend fun getCriticalIntrusionThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority intrusion threats.
     */
    suspend fun getHighPriorityIntrusionThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Generates intrusion detection summary.
     */
    suspend fun generateIntrusionSummary(
        intrusionEvents: List<IntrusionEvent>
    ): String = withContext(Dispatchers.Default) {

        val totalEvents = intrusionEvents.size

        val intrusionCount = intrusionEvents.count {
            it.isIntrusionDetected
        }

        val bruteForceCount = intrusionEvents.count {
            it.failedLoginAttempts >= 10
        }

        val suspiciousCount = intrusionEvents.count {
            it.isSuspiciousActivity
        }

        buildString {
            appendLine("Intrusion Detection Summary")
            appendLine("---------------------------")
            appendLine("Total Events: $totalEvents")
            appendLine("Detected Intrusions: $intrusionCount")
            appendLine("Brute Force Attempts: $bruteForceCount")
            appendLine("Suspicious Activities: $suspiciousCount")
            appendLine(
                if (intrusionCount > 0)
                    "Status: Intrusion Threat Detected"
                else
                    "Status: No Active Intrusions"
            )
        }
    }

    /**
     * Checks whether the monitored environment is secure.
     */
    suspend fun isEnvironmentSecure(
        intrusionEvents: List<IntrusionEvent>
    ): Boolean = withContext(Dispatchers.Default) {

        intrusionEvents.none {
            it.isIntrusionDetected ||
            it.failedLoginAttempts >= 10 ||
            it.isSuspiciousActivity
        }
    }
}
