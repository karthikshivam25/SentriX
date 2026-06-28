package com.sentrix.data.remote.responses

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend after sending,
 * retrieving, or processing analytics information.
 *
 * This response is used by:
 * - Analytics Dashboard
 * - Security Insights Screen
 * - Usage Statistics Module
 * - Threat Analytics Engine
 *
 * Example API Endpoints:
 * POST /api/v1/analytics/events
 * GET  /api/v1/analytics/summary
 * GET  /api/v1/analytics/metrics
 */
@Serializable
data class AnalyticsResponse(

    // Indicates whether the analytics request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the backend
    //
    // Examples:
    // "Analytics event recorded successfully"
    // "Analytics data retrieved successfully"
    // "Unable to process analytics request"
    @SerialName("message")
    val message: String,

    // Unique identifier of the analytics event
    // Useful when tracking a specific event
    @SerialName("event_id")
    val eventId: String? = null,

    // Total number of analytics events processed
    @SerialName("total_events")
    val totalEvents: Int = 0,

    // Total number of scans performed
    @SerialName("total_scans")
    val totalScans: Int = 0,

    // Total number of threats detected
    @SerialName("total_threats")
    val totalThreats: Int = 0,

    // Total number of threats blocked
    @SerialName("blocked_threats")
    val blockedThreats: Int = 0,

    // Total number of phishing attempts blocked
    @SerialName("blocked_phishing_attempts")
    val blockedPhishingAttempts: Int = 0,

    // Average device security score
    // Range: 0 - 100
    @SerialName("average_security_score")
    val averageSecurityScore: Double = 100.0,

    // Security trend indicator
    //
    // Possible values:
    // IMPROVING
    // STABLE
    // DECLINING
    @SerialName("security_trend")
    val securityTrend: String = "STABLE",

    // Indicates whether the analytics data is synchronized
    // with the cloud backend
    @SerialName("cloud_sync_completed")
    val cloudSyncCompleted: Boolean = false,

    // Timestamp of the last analytics synchronization
    @SerialName("last_synced_at")
    val lastSyncedAt: Long? = null,

    // Time period covered by the analytics response
    //
    // Examples:
    // DAILY
    // WEEKLY
    // MONTHLY
    // CUSTOM
    @SerialName("report_period")
    val reportPeriod: String = "DAILY",

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional analytics information returned by the backend
    //
    // Example:
    // "most_common_threat" -> "Phishing"
    // "top_scan_type" -> "FULL"
    // "average_scan_duration" -> "180"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
