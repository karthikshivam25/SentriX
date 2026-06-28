package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used to generate or retrieve a security report.
 *
 * Security reports provide a comprehensive overview of:
 * - Device security status
 * - Threat analysis
 * - Privacy audit results
 * - Security recommendations
 * - Historical security trends
 *
 * Example API Endpoints:
 * POST /api/v1/security/reports/generate
 * GET  /api/v1/security/reports/{reportId}
 */
@Serializable
data class SecurityReportRequest(

    // Unique identifier of the user requesting the report
    @SerialName("user_id")
    val userId: String,

    // Unique identifier of the device
    @SerialName("device_id")
    val deviceId: String,

    // Type of report to generate
    //
    // Possible values:
    // SUMMARY  -> Quick overview
    // DETAILED -> Full security analysis
    // WEEKLY   -> Weekly report
    // MONTHLY  -> Monthly report
    // CUSTOM   -> User-defined report
    @SerialName("report_type")
    val reportType: String = "DETAILED",

    // Report format requested by the user
    //
    // Possible values:
    // PDF, JSON, CSV
    @SerialName("report_format")
    val reportFormat: String = "PDF",

    // Include detected threats in the report
    @SerialName("include_threats")
    val includeThreats: Boolean = true,

    // Include privacy audit results
    @SerialName("include_privacy_audit")
    val includePrivacyAudit: Boolean = true,

    // Include device trust assessment
    @SerialName("include_device_trust")
    val includeDeviceTrust: Boolean = true,

    // Include VPN security information
    @SerialName("include_vpn_status")
    val includeVpnStatus: Boolean = true,

    // Include security recommendations
    @SerialName("include_recommendations")
    val includeRecommendations: Boolean = true,

    // Include analytics and historical trends
    @SerialName("include_analytics")
    val includeAnalytics: Boolean = true,

    // Start date for report generation
    // Epoch milliseconds
    // Mainly used for WEEKLY, MONTHLY, and CUSTOM reports
    @SerialName("from_date")
    val fromDate: Long? = null,

    // End date for report generation
    // Epoch milliseconds
    @SerialName("to_date")
    val toDate: Long? = null,

    // Report delivery method
    //
    // Possible values:
    // DOWNLOAD, EMAIL, CLOUD_STORAGE
    @SerialName("delivery_method")
    val deliveryMethod: String = "DOWNLOAD",

    // Email address to send the report to
    // Required only when deliveryMethod = EMAIL
    @SerialName("email")
    val email: String? = null,

    // Indicates whether the generated report should be archived
    @SerialName("archive_report")
    val archiveReport: Boolean = true,

    // Indicates whether sensitive information should be anonymized
    // before generating the report
    @SerialName("anonymize_sensitive_data")
    val anonymizeSensitiveData: Boolean = false,

    // Timestamp when the request was created
    @SerialName("requested_at")
    val requestedAt: Long = System.currentTimeMillis(),

    // Additional report generation settings
    //
    // Example:
    // "language" -> "en"
    // "timezone" -> "Asia/Kolkata"
    // "include_charts" -> "true"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
