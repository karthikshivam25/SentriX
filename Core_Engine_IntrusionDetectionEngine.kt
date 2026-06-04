package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Intrusion Detection Engine
 *
 * Responsible for:
 * - Intrusion detection and monitoring
 * - Suspicious activity analysis
 * - Attack pattern recognition
 * - Risk assessment
 * - Security response recommendations
 */
class IntrusionDetectionEngine {

    private val intrusionEvents =
        ConcurrentHashMap<String, IntrusionEvent>()

    data class IntrusionEvent(
        val eventId: String,
        val source: String,
        val eventType: String,
        val severity: Int,
        val detectedAt: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes a security event for intrusion indicators.
     */
    suspend fun analyzeEvent(
        eventId: String,
        source: String,
        eventType: String,
        indicators: List<Int>
    ): NetworkResult<IntrusionEvent> = withContext(Dispatchers.Default) {

        try {

            val severity = calculateSeverity(indicators)

            val event = IntrusionEvent(
                eventId = eventId,
                source = source,
                eventType = eventType,
                severity = severity
            )

            intrusionEvents[eventId] = event

            NetworkResult.Success(event)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Intrusion analysis failed"
            )
        }
    }

    /**
     * Registers an intrusion event.
     */
    fun registerEvent(
        event: IntrusionEvent
    ) {
        intrusionEvents[event.eventId] = event
    }

    /**
     * Retrieves an intrusion event.
     */
    fun getEvent(
        eventId: String
    ): IntrusionEvent? {
        return intrusionEvents[eventId]
    }

    /**
     * Returns all intrusion events.
     */
    fun getEvents(): List<IntrusionEvent> {
        return intrusionEvents.values.toList()
    }

    /**
     * Calculates severity score.
     */
    fun calculateSeverity(
        indicators: List<Int>
    ): Int {

        if (indicators.isEmpty()) {
            return 0
        }

        return indicators
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Calculates overall intrusion risk score.
     */
    fun calculateOverallRiskScore(): Int {

        if (intrusionEvents.isEmpty()) {
            return 0
        }

        return intrusionEvents.values
            .map { it.severity }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Detects active intrusion attempts.
     */
    fun hasActiveIntrusions(
        threshold: Int = 75
    ): Boolean {

        return intrusionEvents.values.any {
            it.severity >= threshold
        }
    }

    /**
     * Returns critical intrusion events.
     */
    fun getCriticalEvents(): List<IntrusionEvent> {
        return intrusionEvents.values.filter {
            it.severity >= 90
        }
    }

    /**
     * Returns intrusion risk level.
     */
    fun getRiskLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Generates response recommendations.
     */
    fun generateRecommendations(
        riskScore: Int
    ): List<String> {

        return when {
            riskScore >= 90 -> listOf(
                "Block malicious source immediately.",
                "Isolate affected systems.",
                "Initiate incident response procedures."
            )

            riskScore >= 75 -> listOf(
                "Investigate intrusion indicators.",
                "Increase monitoring level.",
                "Review security logs."
            )

            riskScore >= 50 -> listOf(
                "Monitor suspicious activity.",
                "Validate access controls."
            )

            riskScore >= 25 -> listOf(
                "Continue security monitoring."
            )

            else -> listOf(
                "No intrusion indicators detected."
            )
        }
    }

    /**
     * Removes an intrusion event.
     */
    fun removeEvent(
        eventId: String
    ) {
        intrusionEvents.remove(eventId)
    }

    /**
     * Clears all intrusion events.
     */
    fun clearEvents() {
        intrusionEvents.clear()
    }

    /**
     * Returns total event count.
     */
    fun getEventCount(): Int {
        return intrusionEvents.size
    }

    /**
     * Returns events by source.
     */
    fun getEventsBySource(
        source: String
    ): List<IntrusionEvent> {
        return intrusionEvents.values.filter {
            it.source.equals(source, ignoreCase = true)
        }
    }
}
