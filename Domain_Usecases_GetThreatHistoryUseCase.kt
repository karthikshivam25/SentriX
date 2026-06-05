package com.sentrix.domain.usecases

import com.sentrix.domain.models.ThreatIndicator
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.ThreatHistoryRepository

/**
 * GetThreatHistoryUseCase
 *
 * Responsible for retrieving and analyzing
 * historical threat information within the
 * SentriX cybersecurity platform.
 *
 * This use case provides access to previously
 * detected threats, threat trends, security
 * incidents, malware detections, intrusion
 * attempts, and threat intelligence records.
 *
 * Historical threat information is used for
 * security analytics, incident investigations,
 * threat hunting, compliance reporting, and
 * predictive threat modeling.
 *
 * Used by:
 * - SecurityDashboard
 * - ThreatAnalysisEngine
 * - SecurityAnalyticsPlatform
 * - ThreatHuntingService
 * - IncidentResponseManager
 * - ComplianceReportingService
 * - AIThreatPredictionEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Retrieve threat history
 * - Analyze historical trends
 * - Provide incident visibility
 * - Support threat investigations
 * - Generate threat summaries
 * - Enable predictive analytics
 */
class GetThreatHistoryUseCase(
    private val repository: ThreatHistoryRepository
) {

    /**
     * Retrieves threat history.
     *
     * @param filter Optional query filter.
     *
     * @return ThreatHistoryResult
     */
    suspend operator fun invoke(
        filter: ThreatHistoryFilter =
            ThreatHistoryFilter()
    ): ThreatHistoryResult {

        val threats =
            repository.getThreatHistory(
                filter
            )

        val criticalThreats =
            threats.count {
                it.threatLevel ==
                    ThreatLevel.CRITICAL
            }

        val highThreats =
            threats.count {
                it.threatLevel ==
                    ThreatLevel.HIGH
            }

        val resolvedThreats =
            threats.count {
                it.isResolved
            }

        return ThreatHistoryResult(
            generatedAt =
                System.currentTimeMillis(),

            totalThreats =
                threats.size,

            criticalThreats =
                criticalThreats,

            highSeverityThreats =
                highThreats,

            resolvedThreats =
                resolvedThreats,

            unresolvedThreats =
                threats.size - resolvedThreats,

            threatHistory =
                threats,

            summary =
                generateSummary(
                    threats.size,
                    criticalThreats,
                    resolvedThreats
                )
        )
    }

    /**
     * Generates historical
     * threat summary.
     */
    private fun generateSummary(
        totalThreats: Int,
        criticalThreats: Int,
        resolvedThreats: Int
    ): ThreatHistorySummary {

        val resolutionRate =
            if (totalThreats == 0) {
                0.0
            } else {
                (resolvedThreats.toDouble() /
                    totalThreats) * 100
            }

        return ThreatHistorySummary(
            totalThreats =
                totalThreats,

            criticalThreats =
                criticalThreats,

            resolutionRate =
                resolutionRate,

            overallThreatTrend =
                determineTrend(
                    totalThreats,
                    criticalThreats
                )
        )
    }

    /**
     * Determines threat trend.
     */
    private fun determineTrend(
        totalThreats: Int,
        criticalThreats: Int
    ): ThreatTrend {

        return when {

            criticalThreats >= 20 ->
                ThreatTrend.CRITICAL

            totalThreats >= 100 ->
                ThreatTrend.INCREASING

            totalThreats >= 25 ->
                ThreatTrend.STABLE

            else ->
                ThreatTrend.DECREASING
        }
    }
}

/**
 * ThreatHistoryResult
 *
 * Represents historical threat
 * information and analytics.
 */
data class ThreatHistoryResult(

    /**
     * Result generation timestamp.
     */
    val generatedAt: Long,

    /**
     * Total threats found.
     */
    val totalThreats: Int,

    /**
     * Critical threats detected.
     */
    val criticalThreats: Int,

    /**
     * High severity threats.
     */
    val highSeverityThreats: Int,

    /**
     * Resolved threats.
     */
    val resolvedThreats: Int,

    /**
     * Unresolved threats.
     */
    val unresolvedThreats: Int,

    /**
     * Historical threat records.
     */
    val threatHistory:
        List<ThreatHistoryRecord>,

    /**
     * Threat summary.
     */
    val summary:
        ThreatHistorySummary
)

/**
 * ThreatHistoryRecord
 *
 * Represents an individual
 * historical threat record.
 */
data class ThreatHistoryRecord(

    /**
     * Threat identifier.
     */
    val threatId: String,

    /**
     * Threat name.
     */
    val threatName: String,

    /**
     * Threat category.
     */
    val category:
        ThreatHistoryCategory,

    /**
     * Threat severity.
     */
    val threatLevel:
        ThreatLevel,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Resolution timestamp.
     */
    val resolvedAt: Long?,

    /**
     * Indicates whether the
     * threat has been resolved.
     */
    val isResolved: Boolean,

    /**
     * Threat description.
     */
    val description: String
)

/**
 * Threat history summary.
 */
data class ThreatHistorySummary(

    /**
     * Total threats.
     */
    val totalThreats: Int,

    /**
     * Critical threats.
     */
    val criticalThreats: Int,

    /**
     * Threat resolution rate.
     */
    val resolutionRate: Double,

    /**
     * Overall threat trend.
     */
    val overallThreatTrend:
        ThreatTrend
)

/**
 * Threat history query filter.
 */
data class ThreatHistoryFilter(

    /**
     * Start timestamp.
     */
    val startDate: Long? = null,

    /**
     * End timestamp.
     */
    val endDate: Long? = null,

    /**
     * Threat severity filter.
     */
    val threatLevel:
        ThreatLevel? = null,

    /**
     * Resolution status filter.
     */
    val resolvedOnly: Boolean? = null
)

/**
 * Historical threat categories.
 */
enum class ThreatHistoryCategory {

    /**
     * Malware threat.
     */
    MALWARE,

    /**
     * Phishing attack.
     */
    PHISHING,

    /**
     * Network intrusion.
     */
    INTRUSION,

    /**
     * Scam activity.
     */
    SCAM,

    /**
     * Device compromise.
     */
    DEVICE_COMPROMISE,

    /**
     * Data leakage.
     */
    DATA_EXPOSURE,

    /**
     * Privilege escalation.
     */
    PRIVILEGE_ESCALATION,

    /**
     * Suspicious activity.
     */
    SUSPICIOUS_ACTIVITY
}

/**
 * Threat trend indicators.
 */
enum class ThreatTrend {

    /**
     * Threat activity increasing.
     */
    INCREASING,

    /**
     * Threat activity stable.
     */
    STABLE,

    /**
     * Threat activity decreasing.
     */
    DECREASING,

    /**
     * Critical threat activity.
     */
    CRITICAL
}
