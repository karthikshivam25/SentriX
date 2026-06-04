package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Realtime Protection Engine
 *
 * Responsible for:
 * - Continuous threat monitoring
 * - Realtime event analysis
 * - Suspicious activity detection
 * - Automated threat response
 * - Protection status management
 */
class RealtimeProtectionEngine {

    private val monitoredEvents =
        ConcurrentHashMap<String, SecurityEvent>()

    data class SecurityEvent(
        val eventId: String,
        val eventType: String,
        val severity: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes a realtime security event.
     */
    suspend fun analyzeEvent(
        eventId: String,
        eventType: String,
        indicators: List<Int>
    ): NetworkResult<SecurityEvent> = withContext(Dispatchers.Default) {

        try {

            val severity =
                calculateSeverity(indicators)

            val securityEvent = SecurityEvent(
                eventId = eventId,
                eventType = eventType,
                severity = severity
            )

            monitoredEvents[eventId] = securityEvent

            NetworkResult.Success(securityEvent)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Realtime event analysis failed"
            )
        }
    }

    /**
     * Registers a security event.
     */
    fun registerEvent(
        event: SecurityEvent
    ) {
        monitoredEvents[event.eventId] = event
    }

    /**
     * Retrieves an event.
     */
    fun getEvent(
        eventId: String
    ): SecurityEvent? {
        return monitoredEvents[eventId]
    }

    /**
     * Returns all monitored events.
     */
    fun getAllEvents(): List<SecurityEvent> {
        return monitoredEvents.values.toList()
    }

    /**
     * Calculates event severity.
     */
    fun calculateSeverity(
        indicators: List<Int>
    ): Int {

        if (indicators.isEmpty()) {
            return 0
        }

        return indicators.average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Calculates overall protection score.
     */
    fun calculateProtectionScore(): Int {

        if (monitoredEvents.isEmpty()) {
            return 100
        }

        val averageSeverity =
            monitoredEvents.values
                .map { it.severity }
                .average()

        return (100 - averageSeverity)
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Detects suspicious activity.
     */
    fun isSuspiciousActivity(
        severity: Int,
        threshold: Int = 70
    ): Boolean {
        return severity >= threshold
    }

    /**
     * Determines protection status.
     */
    fun getProtectionStatus(
        score: Int
    ): String {
        return when {
            score >= 90 -> "FULLY_PROTECTED"
            score >= 75 -> "PROTECTED"
            score >= 50 -> "WARNING"
            score >= 25 -> "AT_RISK"
            else -> "COMPROMISED"
        }
    }

    /**
     * Generates automated response actions.
     */
    fun generateResponseActions(
        severity: Int
    ): List<String> {

        return when {
            severity >= 90 -> listOf(
                "Block process immediately",
                "Disconnect network access",
                "Trigger emergency incident response"
            )

            severity >= 75 -> listOf(
                "Quarantine suspicious activity",
                "Run advanced threat scan",
                "Notify security module"
            )

            severity >= 50 -> listOf(
                "Increase monitoring level",
                "Collect diagnostic information"
            )

            severity >= 25 -> listOf(
                "Log security event"
            )

            else -> listOf(
                "No action required"
            )
        }
    }

    /**
     * Removes an event.
     */
    fun removeEvent(
        eventId: String
    ) {
        monitoredEvents.remove(eventId)
    }

    /**
     * Clears all monitored events.
     */
    fun clearEvents() {
        monitoredEvents.clear()
    }

    /**
     * Returns total event count.
     */
    fun getEventCount(): Int {
        return monitoredEvents.size
    }

    /**
     * Returns critical events only.
     */
    fun getCriticalEvents(): List<SecurityEvent> {
        return monitoredEvents.values.filter {
            it.severity >= 90
        }
    }
}
