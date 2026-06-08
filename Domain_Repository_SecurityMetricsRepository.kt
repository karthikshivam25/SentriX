package com.sentrix.domain.repositories

import com.sentrix.domain.models.SecurityMetric
import com.sentrix.domain.models.SecurityMetricCategory
import com.sentrix.domain.models.SecurityMetricTrend

/**
 * SecurityMetricsRepository
 *
 * Repository responsible for
 * managing security metrics
 * within the SentriX
 * cybersecurity platform.
 *
 * Used by:
 * - SecurityDashboard
 * - SecurityAnalyticsEngine
 * - CyberDefenseManager
 * - ReportingService
 * - ThreatAnalysisEngine
 *
 * Responsibilities:
 * - Store security metrics
 * - Retrieve security metrics
 * - Track security trends
 * - Generate metric reports
 * - Support analytics
 */
interface SecurityMetricsRepository {

    /**
     * Retrieves all
     * security metrics.
     *
     * @return Metric list.
     */
    suspend fun getMetrics():
        List<SecurityMetric>

    /**
     * Retrieves metric
     * by identifier.
     *
     * @param metricId Metric ID.
     *
     * @return Security metric.
     */
    suspend fun getMetricById(
        metricId: String
    ): SecurityMetric?

    /**
     * Saves security metric.
     *
     * @param metric Security metric.
     */
    suspend fun saveMetric(
        metric: SecurityMetric
    )

    /**
     * Updates security metric.
     *
     * @param metric Security metric.
     */
    suspend fun updateMetric(
        metric: SecurityMetric
    )

    /**
     * Deletes security metric.
     *
     * @param metricId Metric ID.
     */
    suspend fun deleteMetric(
        metricId: String
    )

    /**
     * Retrieves metrics
     * by category.
     *
     * @param category Metric category.
     *
     * @return Metric list.
     */
    suspend fun getMetricsByCategory(
        category: SecurityMetricCategory
    ): List<SecurityMetric>

    /**
     * Retrieves latest metrics.
     *
     * @return Metric list.
     */
    suspend fun getLatestMetrics():
        List<SecurityMetric>

    /**
     * Retrieves current
     * security score.
     *
     * @return Security score.
     */
    suspend fun getSecurityScore():
        Int

    /**
     * Retrieves total
     * metric count.
     *
     * @return Metric count.
     */
    suspend fun getMetricCount():
        Int
}

/**
 * SecurityMetric
 *
 * Represents a security metric.
 */
data class SecurityMetric(

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
        SecurityMetricCategory,

    /**
     * Metric trend.
     */
    val trend:
        SecurityMetricTrend,

    /**
     * Collection timestamp.
     */
    val collectedAt: Long
)

/**
 * Security metric categories.
 */
enum class SecurityMetricCategory {

    /**
     * Threat metrics.
     */
    THREATS,

    /**
     * Malware metrics.
     */
    MALWARE,

    /**
     * Network metrics.
     */
    NETWORK,

    /**
     * Device metrics.
     */
    DEVICE,

    /**
     * Permission metrics.
     */
    PERMISSIONS,

    /**
     * Firewall metrics.
     */
    FIREWALL,

    /**
     * VPN metrics.
     */
    VPN,

    /**
     * Overall security metrics.
     */
    SECURITY
}

/**
 * Security metric trends.
 */
enum class SecurityMetricTrend {

    /**
     * Increasing trend.
     */
    INCREASING,

    /**
     * Decreasing trend.
     */
    DECREASING,

    /**
     * Stable trend.
     */
    STABLE
}
