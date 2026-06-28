package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.ScanResultDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend after initiating or completing
 * a security scan.
 *
 * This response contains:
 * - Scan status
 * - Scan progress information
 * - Scan results
 * - Threat statistics
 *
 * Example API Endpoints:
 * POST /api/v1/scans/start
 * GET  /api/v1/scans/{scanId}
 */
@Serializable
data class ScanResponse(

    // Indicates whether the scan request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the server
    //
    // Examples:
    // "Scan started successfully"
    // "Scan completed"
    // "Unable to start scan"
    @SerialName("message")
    val message: String,

    // Unique identifier of the scan session
    @SerialName("scan_id")
    val scanId: String? = null,

    // Current status of the scan
    //
    // Possible values:
    // PENDING
    // RUNNING
    // COMPLETED
    // FAILED
    // CANCELLED
    @SerialName("scan_status")
    val scanStatus: String = "PENDING",

    // Current scan progress percentage
    // Range: 0 - 100
    @SerialName("progress_percentage")
    val progressPercentage: Int = 0,

    // Type of scan currently running
    //
    // Examples:
    // QUICK
    // FULL
    // CUSTOM
    // REALTIME
    @SerialName("scan_type")
    val scanType: String? = null,

    // Estimated remaining scan time in seconds
    @SerialName("estimated_time_remaining")
    val estimatedTimeRemaining: Long = 0L,

    // Total number of items scanned so far
    @SerialName("items_scanned")
    val itemsScanned: Int = 0,

    // Number of threats detected during this scan
    @SerialName("threats_detected")
    val threatsDetected: Int = 0,

    // Detailed scan result returned after completion
    // Null while scan is still running
    @SerialName("scan_result")
    val scanResult: ScanResultDto? = null,

    // Indicates whether cloud threat analysis was performed
    @SerialName("cloud_analysis_enabled")
    val cloudAnalysisEnabled: Boolean = false,

    // Indicates whether behavioral analysis was performed
    @SerialName("behavior_analysis_enabled")
    val behaviorAnalysisEnabled: Boolean = false,

    // Timestamp when the scan started
    @SerialName("started_at")
    val startedAt: Long? = null,

    // Timestamp when the scan completed
    @SerialName("completed_at")
    val completedAt: Long? = null,

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional backend information
    //
    // Example:
    // "engine_version" -> "2.0.1"
    // "scan_node" -> "eu-west-1"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
