package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.ThreatDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend when retrieving,
 * reporting, or updating threat information.
 *
 * This response is used by:
 * - Threat dashboard
 * - Real-time protection
 * - Threat history screen
 * - Threat intelligence module
 *
 * Example API Endpoints:
 * GET  /api/v1/threats
 * GET  /api/v1/threats/{id}
 * POST /api/v1/threats/report
 */
@Serializable
data class ThreatResponse(

    // Indicates whether the API request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the backend
    //
    // Examples:
    // "Threat retrieved successfully"
    // "Threat reported successfully"
    // "No threats found"
    @SerialName("message")
    val message: String,

    // Total number of threats returned
    @SerialName("total_threats")
    val totalThreats: Int = 0,

    // Number of active threats currently detected
    @SerialName("active_threats")
    val activeThreats: Int = 0,

    // Number of critical threats
    @SerialName("critical_threats")
    val criticalThreats: Int = 0,

    // List of detected threats
    @SerialName("threats")
    val threats: List<ThreatDto> = emptyList(),

    // Single threat object
    // Used when fetching a specific threat by ID
    @SerialName("threat")
    val threat: ThreatDto? = null,

    // Overall device risk score calculated from all threats
    // Range: 0 - 100
    @SerialName("risk_score")
    val riskScore: Int = 0,

    // Indicates whether immediate user action is required
    @SerialName("action_required")
    val actionRequired: Boolean = false,

    // Suggested action for the user
    //
    // Examples:
    // "Remove suspicious application"
    // "Disconnect from network"
    @SerialName("recommended_action")
    val recommendedAction: String? = null,

    // Timestamp of the last detected threat
    @SerialName("last_detected_at")
    val lastDetectedAt: Long? = null,

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional information returned by the backend
    //
    // Example:
    // "threat_feed_version" -> "2026.06.28"
    // "threat_intelligence_source" -> "SentriX Cloud"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
