package com.sentrix.domain.repositories

import com.sentrix.domain.models.AnalyticsMetric
import com.sentrix.domain.models.AnalyticsReport
import com.sentrix.domain.models.AnalyticsTrend

/**
 * AnalyticsRepository
 *
 * Repository responsible for
 * managing security analytics
 * within the SentriX
 * cybersecurity platform.
 *
 * Used by:
 * - SecurityAnalyticsEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ThreatAnalysisEngine
 * - ReportingService
 *
 * Responsibilities:
 * - Store analytics data
 * - Generate reports
 * - Track security trends
 * - Provide metrics
 * - Support predictive analysis
 */
interface AnalyticsRepository {

    /**
     * Retrieves all
     * analytics metrics.
     *
     * @return Metrics list.
     */
    suspend fun getMetrics():
        List<AnalyticsMetric>

    /**
     * Retrieves metric
     * by identifier.
     *
     * @param metricId Metric ID.
     *
     * @return Analytics metric.
     */
    suspend fun getMetricById(
        metricId: String
    ): AnalyticsMetric?

    /**
     * Saves analytics metric.
     *
     * @param metric Analytics metric.
     */
    suspend fun saveMetric(
        metric: AnalyticsMetric
    )

    /**
     * Updates analytics metric.
     *
     * @param metric Analytics metric.
     */
    suspend fun updateMetric(
        metric: AnalyticsMetric
    )

    /**
     * Deletes analytics metric.
     *
     * @param metricId Metric ID.
     */
    suspend fun deleteMetric(
        metricId: String
    )

    /**
     * Retrieves analytics report.
     *
     * @return Analytics report.
     */
    suspend fun getLatestReport():
        AnalyticsReport?

    /**
     * Saves analytics report.
     *
     * @param report Analytics report.
     */
    suspend fun saveReport(
        report: AnalyticsReport
    )

    /**
     * Retrieves security trends.
     *
     * @return Trend list.
     */
    suspend fun getTrends():
        List<AnalyticsTrend>

    /**
     * Retrieves total
     * analytics count.
     *
     * @return Analytics count.
     */
    suspend fun getAnalyticsCount():
        Int
}

/**
 * AnalyticsMetric
 *
 * Represents a security
 * analytics metric.
 */
data class AnalyticsMetric(

    /**
     * Metric identifier.
     */
    val metricId: String,

    /**
     * Metric name.
     */
    val metricName: String,

    /**
     * Metric value.
     */
    val metricValue: Double,

    /**
     * Metric category.
     */
    val category:
        AnalyticsCategory,

    /**
     * Collection timestamp.
     */
    val collectedAt: Long
)

/**
 * AnalyticsReport
 *
 * Represents an analytics report.
 */
data class AnalyticsReport(

    /**
     * Report identifier.
     */
    val reportId: String,

    /**
     * Report title.
     */
    val title: String,

    /**
     * Report summary.
     */
    val summary: String,

    /**
     * Generated timestamp.
     */
    val generatedAt: Long,

    /**
     * Analytics metrics.
     */
    val metrics:
        List<AnalyticsMetric>
)

/**
 * AnalyticsTrend
 *
 * Represents a security trend.
 */
data class AnalyticsTrend(

    /**
     * Trend identifier.
     */
    val trendId: String,

    /**
     * Trend name.
     */
    val trendName: String,

    /**
     * Trend value.
     */
    val trendValue: Double,

    /**
     * Trend direction.
     */
    val direction:
        TrendDirection,

    /**
     * Recorded timestamp.
     */
    val recordedAt: Long
)

/**
 * Analytics categories.
 */
enum class AnalyticsCategory {

    /**
     * Threat analytics.
     */
    THREATS,

    /**
     * Malware analytics.
     */
    MALWARE,

    /**
     * Network analytics.
     */
    NETWORK,

    /**
     * Device analytics.
     */
    DEVICE,

    /**
     * Permission analytics.
     */
    PERMISSIONS,

    /**
     * Security analytics.
     */
    SECURITY,

    /**
     * Risk analytics.
     */
    RISK,

    /**
     * User behavior analytics.
     */
    USER_BEHAVIOR
}

/**
 * Trend direction.
 */
enum class TrendDirection {

    /**
     * Increasing trend.
     */
    UP,

    /**
     * Decreasing trend.
     */
    DOWN,

    /**
     * Stable trend.
     */
    STABLE
}
