package com.sentrix.domain.services

import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.ThreatIndicator
import com.sentrix.domain.models.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for analytics and insights.
 *
 * This service analyzes security data,
 * generates trends and statistics,
 * and provides analytical insights for SentriX.
 */
class AnalyticsService {

    /**
     * Calculates threat distribution by severity.
     */
    suspend fun getThreatDistribution(
        indicators: List<ThreatIndicator>
    ): Map<String, Int> = withContext(Dispatchers.Default) {

        mapOf(
            "CRITICAL" to indicators.count {
                it.severity.equals("CRITICAL", true)
            },
            "HIGH" to indicators.count {
                it.severity.equals("HIGH", true)
            },
            "MEDIUM" to indicators.count {
                it.severity.equals("MEDIUM", true)
            },
            "LOW" to indicators.count {
                it.severity.equals("LOW", true)
            }
        )
    }

    /**
     * Calculates threat detection rate.
     *
     * Formula:
     * (Threats Detected / Total Scans) * 100
     */
    suspend fun calculateThreatDetectionRate(
        metrics: SecurityMetrics
    ): Double = withContext(Dispatchers.Default) {

        if (metrics.totalScans == 0) {
            return@withContext 0.0
        }

        (metrics.threatsDetected.toDouble() /
                metrics.totalScans) * 100
    }

    /**
     * Calculates average threats per scan.
     */
    suspend fun calculateAverageThreatsPerScan(
        metrics: SecurityMetrics
    ): Double = withContext(Dispatchers.Default) {

        if (metrics.totalScans == 0) {
            return@withContext 0.0
        }

        metrics.threatsDetected.toDouble() /
                metrics.totalScans
    }

    /**
     * Calculates scan completion rate.
     */
    suspend fun calculateScanCompletionRate(
        scanResults: List<ScanResult>
    ): Double = withContext(Dispatchers.Default) {

        if (scanResults.isEmpty()) {
            return@withContext 0.0
        }

        val completedScans = scanResults.count {
            it.scanCompleted
        }

        (completedScans.toDouble() /
                scanResults.size) * 100
    }

    /**
     * Returns the most common threat severity.
     */
    suspend fun getMostCommonThreatSeverity(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        getThreatDistribution(indicators)
            .maxByOrNull { it.value }
            ?.key ?: "NONE"
    }

    /**
     * Calculates overall security score.
     */
    suspend fun calculateSecurityScore(
        metrics: SecurityMetrics
    ): Int = withContext(Dispatchers.Default) {

        (100 - metrics.riskScore)
            .coerceIn(0, 100)
    }

    /**
     * Calculates threat growth trend.
     */
    suspend fun calculateThreatGrowth(
        previousThreatCount: Int,
        currentThreatCount: Int
    ): Double = withContext(Dispatchers.Default) {

        if (previousThreatCount == 0) {
            return@withContext 100.0
        }

        ((currentThreatCount - previousThreatCount)
                .toDouble() / previousThreatCount) * 100
    }

    /**
     * Generates analytics summary.
     */
    suspend fun generateAnalyticsSummary(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        val detectionRate =
            calculateThreatDetectionRate(metrics)

        val averageThreats =
            calculateAverageThreatsPerScan(metrics)

        val commonSeverity =
            getMostCommonThreatSeverity(indicators)

        buildString {

            appendLine("SentriX Analytics Summary")
            appendLine("=========================")
            appendLine("Security Score: ${calculateSecurityScore(metrics)}")
            appendLine(
                "Threat Detection Rate: ${
                    String.format("%.2f", detectionRate)
                }%"
            )
            appendLine(
                "Average Threats Per Scan: ${
                    String.format("%.2f", averageThreats)
                }"
            )
            appendLine("Most Common Severity: $commonSeverity")
            appendLine("Total Threats: ${indicators.size}")
        }
    }

    /**
     * Generates security trend analysis.
     */
    suspend fun generateTrendAnalysis(
        previousMetrics: SecurityMetrics,
        currentMetrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val riskDifference =
            currentMetrics.riskScore -
                    previousMetrics.riskScore

        val threatDifference =
            currentMetrics.threatsDetected -
                    previousMetrics.threatsDetected

        buildString {

            appendLine("SentriX Trend Analysis")
            appendLine("======================")
            appendLine("Risk Score Change: $riskDifference")
            appendLine("Threat Count Change: $threatDifference")

            appendLine(
                if (riskDifference > 0)
                    "Trend: Security posture deteriorating"
                else if (riskDifference < 0)
                    "Trend: Security posture improving"
                else
                    "Trend: Stable"
            )
        }
    }

    /**
     * Returns true if threat activity
     * is increasing.
     */
    suspend fun isThreatActivityIncreasing(
        previousThreatCount: Int,
        currentThreatCount: Int
    ): Boolean = withContext(Dispatchers.Default) {

        currentThreatCount > previousThreatCount
    }

    /**
     * Determines whether security posture
     * is improving.
     */
    suspend fun isSecurityImproving(
        previousMetrics: SecurityMetrics,
        currentMetrics: SecurityMetrics
    ): Boolean = withContext(Dispatchers.Default) {

        currentMetrics.riskScore <
                previousMetrics.riskScore
    }
}
