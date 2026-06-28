package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.ThreatHistoryDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend when retrieving
 * threat history information.
 *
 * This response is mainly used by:
 * - Threat History Screen
 * - Security Timeline
 * - Security Reports
 * - Analytics Dashboard
 *
 * Example API Endpoints:
 * GET /api/v1/threats/history
 * GET /api/v1/threats/history/{historyId}
 */
@Serializable
data class ThreatHistoryResponse(

    // Indicates whether the request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the backend
    //
    // Examples:
    // "Threat history retrieved successfully"
    // "No threat history found"
    @SerialName("message")
    val message: String,

    // Total number of threat history records available
    @SerialName("total_records")
    val totalRecords: Int = 0,

    // Current page number for paginated responses
    @SerialName("current_page")
    val currentPage: Int = 1,

    // Number of records returned per page
    @SerialName("page_size")
    val pageSize: Int = 20,

    // Total number of available pages
    @SerialName("total_pages")
    val totalPages: Int = 1,

    // Complete list of threat history records
    @SerialName("history")
    val history: List<ThreatHistoryDto> = emptyList(),

    // Most recent threat detected on the device
    @SerialName("latest_threat")
    val latestThreat: ThreatHistoryDto? = null,

    // Number of unresolved threats
    @SerialName("active_threat_count")
    val activeThreatCount: Int = 0,

    // Number of resolved threats
    @SerialName("resolved_threat_count")
    val resolvedThreatCount: Int = 0,

    // Overall risk score calculated from historical threats
    // Range: 0 - 100
    @SerialName("historical_risk_score")
    val historicalRiskScore: Int = 0,

    // Timestamp of the oldest record returned
    @SerialName("from_timestamp")
    val fromTimestamp: Long? = null,

    // Timestamp of the newest record returned
    @SerialName("to_timestamp")
    val toTimestamp: Long? = null,

    // Indicates whether more records are available
    @SerialName("has_more")
    val hasMore: Boolean = false,

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional backend information
    //
    // Example:
    // "threat_feed_version" -> "2026.06.28"
    // "analysis_engine_version" -> "v3.1.0"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
