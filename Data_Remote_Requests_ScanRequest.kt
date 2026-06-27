package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used to initiate a security scan in SentriX.
 *
 * This request is sent from the mobile application to the backend
 * whenever the user starts a security scan.
 *
 * Example API Endpoint:
 * POST /api/v1/scans/start
 */
@Serializable
data class ScanRequest(

    // Unique identifier of the device requesting the scan
    @SerialName("device_id")
    val deviceId: String,

    // Unique identifier of the user initiating the scan
    @SerialName("user_id")
    val userId: String,

    // Type of scan to perform
    //
    // Possible values:
    // QUICK     -> Fast scan of critical areas
    // FULL      -> Complete device scan
    // CUSTOM    -> Scan selected locations/apps
    // REALTIME  -> Background continuous monitoring
    @SerialName("scan_type")
    val scanType: String,

    // Indicates whether installed applications should be scanned
    @SerialName("scan_apps")
    val scanApps: Boolean = true,

    // Indicates whether device files should be scanned
    @SerialName("scan_files")
    val scanFiles: Boolean = true,

    // Indicates whether URLs/web links should be analyzed
    @SerialName("scan_urls")
    val scanUrls: Boolean = true,

    // Indicates whether APK files should be scanned
    @SerialName("scan_apks")
    val scanApks: Boolean = true,

    // Indicates whether privacy analysis should be performed
    @SerialName("include_privacy_audit")
    val includePrivacyAudit: Boolean = true,

    // Indicates whether cloud-based threat intelligence should be used
    @SerialName("enable_cloud_analysis")
    val enableCloudAnalysis: Boolean = true,

    // Indicates whether AI-powered behavioral analysis should be enabled
    @SerialName("enable_behavior_analysis")
    val enableBehaviorAnalysis: Boolean = true,

    // Custom file paths selected by the user for scanning
    // Used only for CUSTOM scans
    @SerialName("custom_paths")
    val customPaths: List<String> = emptyList(),

    // Package names of applications selected for scanning
    // Used only for CUSTOM scans
    @SerialName("selected_packages")
    val selectedPackages: List<String> = emptyList(),

    // Maximum scan duration allowed in seconds
    // Example: 300 = 5 minutes
    @SerialName("max_scan_duration_seconds")
    val maxScanDurationSeconds: Int = 300,

    // Priority of the scan request
    //
    // Possible values:
    // LOW, NORMAL, HIGH, CRITICAL
    @SerialName("priority")
    val priority: String = "NORMAL",

    // Timestamp when the request was created
    // Stored as Epoch milliseconds
    @SerialName("requested_at")
    val requestedAt: Long = System.currentTimeMillis(),

    // Additional scan options or metadata
    //
    // Example:
    // "battery_optimization" -> "true"
    // "network_type" -> "WIFI"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
