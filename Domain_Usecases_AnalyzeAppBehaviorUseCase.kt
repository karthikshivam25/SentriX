package com.sentrix.domain.usecases

import com.sentrix.domain.models.AppInfo
import com.sentrix.domain.repositories.AppBehaviorRepository

/**
 * AnalyzeAppBehaviorUseCase
 *
 * Responsible for analyzing application
 * behavior patterns and identifying
 * suspicious, malicious, or abnormal
 * activities within the SentriX platform.
 *
 * This use case evaluates application
 * runtime behavior, network activity,
 * resource consumption, permission usage,
 * process interactions, and behavioral
 * anomalies to determine security risks.
 *
 * Used by:
 * - BehavioralAnalysisEngine
 * - MalwareDetectionEngine
 * - RealtimeProtectionEngine
 * - ThreatAnalysisManager
 * - SecurityDashboard
 * - ApplicationScanner
 * - AIThreatDetectionEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze application behavior
 * - Detect behavioral anomalies
 * - Identify suspicious activities
 * - Calculate behavior risk scores
 * - Generate security recommendations
 * - Support automated threat response
 */
class AnalyzeAppBehaviorUseCase(
    private val repository: AppBehaviorRepository
) {

    /**
     * Executes behavioral analysis
     * for the specified application.
     *
     * @param appInfo Application to analyze
     *
     * @return AppBehaviorAnalysisResult
     */
    suspend operator fun invoke(
        appInfo: AppInfo
    ): AppBehaviorAnalysisResult {

        val behaviorEvents =
            repository.getBehaviorEvents(
                appInfo.packageName
            )

        val anomalyRules =
            repository.getAnomalyRules()

        val suspiciousEvents =
            behaviorEvents.filter { event ->
                event.isSuspicious
            }

        val detectedAnomalies =
            anomalyRules.filter { rule ->
                suspiciousEvents.count {
                    it.eventType == rule.eventType
                } >= rule.threshold
            }

        val riskLevel =
            determineRiskLevel(
                suspiciousEvents.size,
                detectedAnomalies.size
            )

        val riskScore =
            calculateRiskScore(
                suspiciousEvents.size,
                detectedAnomalies.size
            )

        return AppBehaviorAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            applicationId = appInfo.appId,
            packageName = appInfo.packageName,
            totalEvents = behaviorEvents.size,
            suspiciousEvents = suspiciousEvents,
            detectedAnomalies = detectedAnomalies,
            riskLevel = riskLevel,
            riskScore = riskScore,
            recommendations =
                generateRecommendations(
                    riskLevel
                )
        )
    }

    /**
     * Determines behavioral risk level.
     */
    private fun determineRiskLevel(
        suspiciousEventCount: Int,
        anomalyCount: Int
    ): BehaviorRiskLevel {

        return when {

            anomalyCount >= 5 ->
                BehaviorRiskLevel.CRITICAL

            anomalyCount >= 3 ->
                BehaviorRiskLevel.HIGH

            suspiciousEventCount >= 10 ->
                BehaviorRiskLevel.MEDIUM

            else ->
                BehaviorRiskLevel.LOW
        }
    }

    /**
     * Calculates behavior risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        suspiciousEventCount: Int,
        anomalyCount: Int
    ): Int {

        val score =
            (suspiciousEventCount * 4) +
            (anomalyCount * 15)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates behavior-based
     * security recommendations.
     */
    private fun generateRecommendations(
        riskLevel: BehaviorRiskLevel
    ): List<String> {

        return when (riskLevel) {

            BehaviorRiskLevel.CRITICAL -> listOf(
                "Isolate application immediately",
                "Block application network access",
                "Perform malware investigation",
                "Notify security administrators"
            )

            BehaviorRiskLevel.HIGH -> listOf(
                "Increase application monitoring",
                "Review suspicious behavior",
                "Perform advanced threat scan"
            )

            BehaviorRiskLevel.MEDIUM -> listOf(
                "Monitor behavioral changes",
                "Review application permissions"
            )

            BehaviorRiskLevel.LOW -> listOf(
                "No significant behavioral risks detected"
            )
        }
    }
}

/**
 * AppBehaviorAnalysisResult
 *
 * Represents the outcome of
 * application behavior analysis.
 */
data class AppBehaviorAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Application identifier.
     */
    val applicationId: String,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Total behavior events analyzed.
     */
    val totalEvents: Int,

    /**
     * Suspicious events detected.
     */
    val suspiciousEvents:
        List<AppBehaviorEvent>,

    /**
     * Detected behavioral anomalies.
     */
    val detectedAnomalies:
        List<BehaviorAnomalyRule>,

    /**
     * Calculated risk level.
     */
    val riskLevel: BehaviorRiskLevel,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Recommended actions.
     */
    val recommendations: List<String>
)

/**
 * AppBehaviorEvent
 *
 * Represents a runtime application
 * behavior event captured by SentriX.
 */
data class AppBehaviorEvent(

    /**
     * Event identifier.
     */
    val eventId: String,

    /**
     * Event type.
     */
    val eventType: BehaviorEventType,

    /**
     * Event description.
     */
    val description: String,

    /**
     * Event timestamp.
     */
    val timestamp: Long,

    /**
     * Indicates whether the event
     * is considered suspicious.
     */
    val isSuspicious: Boolean = false,

    /**
     * Additional event metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * BehaviorAnomalyRule
 *
 * Represents a behavioral anomaly
 * detection rule.
 */
data class BehaviorAnomalyRule(

    /**
     * Rule identifier.
     */
    val ruleId: String,

    /**
     * Rule name.
     */
    val ruleName: String,

    /**
     * Target event type.
     */
    val eventType: BehaviorEventType,

    /**
     * Trigger threshold.
     */
    val threshold: Int,

    /**
     * Risk description.
     */
    val description: String
)

/**
 * Application behavior event types.
 */
enum class BehaviorEventType {

    /**
     * File system activity.
     */
    FILE_ACCESS,

    /**
     * Network communication.
     */
    NETWORK_ACCESS,

    /**
     * Permission usage.
     */
    PERMISSION_USAGE,

    /**
     * Process execution.
     */
    PROCESS_EXECUTION,

    /**
     * Background service activity.
     */
    BACKGROUND_ACTIVITY,

    /**
     * Data exfiltration attempt.
     */
    DATA_TRANSFER,

    /**
     * Registry or configuration change.
     */
    SYSTEM_MODIFICATION
}

/**
 * Behavior risk indicators.
 */
enum class BehaviorRiskLevel {

    /**
     * Low behavioral risk.
     */
    LOW,

    /**
     * Moderate behavioral risk.
     */
    MEDIUM,

    /**
     * High behavioral risk.
     */
    HIGH,

    /**
     * Critical behavioral risk.
     */
    CRITICAL
}
