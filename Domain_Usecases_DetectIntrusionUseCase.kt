package com.sentrix.domain.usecases

import com.sentrix.domain.models.IntrusionEvent
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.IntrusionDetectionRepository

/**
 * DetectIntrusionUseCase
 *
 * Responsible for detecting unauthorized access
 * attempts, suspicious system activities, policy
 * violations, and potential cyberattacks within
 * the SentriX cybersecurity platform.
 *
 * This use case analyzes intrusion indicators,
 * security events, network anomalies, behavioral
 * patterns, authentication failures, and threat
 * intelligence feeds to identify potential
 * intrusions and security incidents.
 *
 * Used by:
 * - IntrusionDetectionSystem
 * - RealtimeProtectionEngine
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - IncidentResponseManager
 * - SecurityOrchestrator
 * - ZeroTrustManager
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Detect intrusion attempts
 * - Correlate security events
 * - Identify attack patterns
 * - Calculate intrusion risk
 * - Classify intrusion severity
 * - Generate incident response actions
 */
class DetectIntrusionUseCase(
    private val repository: IntrusionDetectionRepository
) {

    /**
     * Executes intrusion detection analysis.
     *
     * @return IntrusionDetectionResult
     */
    suspend operator fun invoke():
        IntrusionDetectionResult {

        val intrusionEvents =
            repository.getIntrusionEvents()

        val activeEvents =
            intrusionEvents.filter {
                !it.isResolved
            }

        val criticalEvents =
            activeEvents.filter {
                it.threatLevel ==
                    ThreatLevel.CRITICAL
            }

        val intrusionStatus =
            determineIntrusionStatus(
                activeEvents.size,
                criticalEvents.size
            )

        val riskScore =
            calculateRiskScore(
                activeEvents.size,
                criticalEvents.size
            )

        return IntrusionDetectionResult(
            analyzedAt = System.currentTimeMillis(),
            intrusionDetected =
                activeEvents.isNotEmpty(),
            status = intrusionStatus,
            riskScore = riskScore,
            activeIntrusions =
                activeEvents.size,
            criticalIntrusions =
                criticalEvents.size,
            intrusionEvents =
                activeEvents,
            recommendations =
                generateRecommendations(
                    intrusionStatus
                )
        )
    }

    /**
     * Determines intrusion severity.
     */
    private fun determineIntrusionStatus(
        activeEvents: Int,
        criticalEvents: Int
    ): IntrusionStatus {

        return when {

            criticalEvents >= 3 ->
                IntrusionStatus.CRITICAL

            activeEvents >= 10 ->
                IntrusionStatus.HIGH

            activeEvents >= 5 ->
                IntrusionStatus.MEDIUM

            activeEvents >= 1 ->
                IntrusionStatus.LOW

            else ->
                IntrusionStatus.NONE
        }
    }

    /**
     * Calculates intrusion risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        activeEvents: Int,
        criticalEvents: Int
    ): Int {

        val score =
            (activeEvents * 5) +
            (criticalEvents * 25)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates incident response
     * recommendations.
     */
    private fun generateRecommendations(
        status: IntrusionStatus
    ): List<String> {

        return when (status) {

            IntrusionStatus.CRITICAL -> listOf(
                "Initiate incident response plan",
                "Isolate affected systems",
                "Block malicious activity",
                "Notify security team immediately"
            )

            IntrusionStatus.HIGH -> listOf(
                "Investigate intrusion events",
                "Increase monitoring sensitivity",
                "Review security logs"
            )

            IntrusionStatus.MEDIUM -> listOf(
                "Monitor suspicious activities",
                "Review access controls"
            )

            IntrusionStatus.LOW -> listOf(
                "Continue monitoring activities"
            )

            IntrusionStatus.NONE -> listOf(
                "No intrusion indicators detected"
            )
        }
    }
}

/**
 * IntrusionDetectionResult
 *
 * Represents the outcome of
 * intrusion detection analysis.
 */
data class IntrusionDetectionResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Indicates whether an intrusion
     * was detected.
     */
    val intrusionDetected: Boolean,

    /**
     * Current intrusion status.
     */
    val status: IntrusionStatus,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Number of active intrusion events.
     */
    val activeIntrusions: Int,

    /**
     * Number of critical intrusion events.
     */
    val criticalIntrusions: Int,

    /**
     * Detected intrusion events.
     */
    val intrusionEvents:
        List<IntrusionEvent>,

    /**
     * Recommended response actions.
     */
    val recommendations: List<String>
)

/**
 * Intrusion severity indicators.
 */
enum class IntrusionStatus {

    /**
     * No intrusion activity detected.
     */
    NONE,

    /**
     * Low severity intrusion activity.
     */
    LOW,

    /**
     * Moderate intrusion activity.
     */
    MEDIUM,

    /**
     * High severity intrusion activity.
     */
    HIGH,

    /**
     * Critical intrusion activity
     * requiring immediate response.
     */
    CRITICAL
}
