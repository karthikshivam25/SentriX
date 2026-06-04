package com.sentrix.core.wrappers

import com.sentrix.core.enums.AlertPriority
import com.sentrix.core.enums.ThreatSource

/**
 * Represents a detected threat and its analysis result.
 */
data class ThreatResultWrapper(
    val threatId: String,
    val threatName: String,
    val description: String,
    val source: ThreatSource,
    val severityScore: Int,
    val priority: AlertPriority,
    val affectedComponent: String? = null,
    val detectedAt: Long = System.currentTimeMillis(),
    val resolvedAt: Long? = null,
    val isResolved: Boolean = false,
    val recommendations: List<String> = emptyList(),
    val metadata: Map<String, Any> = emptyMap()
) {

    /**
     * Returns true if the threat is critical.
     */
    fun isCritical(): Boolean =
        severityScore >= 90

    /**
     * Returns true if the threat is high severity.
     */
    fun isHighRisk(): Boolean =
        severityScore in 70..89

    /**
     * Returns true if the threat is medium severity.
     */
    fun isMediumRisk(): Boolean =
        severityScore in 40..69

    /**
     * Returns true if the threat is low severity.
     */
    fun isLowRisk(): Boolean =
        severityScore in 0..39

    /**
     * Returns a readable severity label.
     */
    fun getSeverityLabel(): String {
        return when (severityScore) {
            in 0..39 -> "Low"
            in 40..69 -> "Medium"
            in 70..89 -> "High"
            else -> "Critical"
        }
    }

    /**
     * Returns true if recommendations are available.
     */
    fun hasRecommendations(): Boolean =
        recommendations.isNotEmpty()

    /**
     * Returns true if metadata exists.
     */
    fun hasMetadata(): Boolean =
        metadata.isNotEmpty()

    companion object {

        fun empty(): ThreatResultWrapper {
            return ThreatResultWrapper(
                threatId = "",
                threatName = "",
                description = "",
                source = ThreatSource.UNKNOWN,
                severityScore = 0,
                priority = AlertPriority.LOW
            )
        }
    }
}
