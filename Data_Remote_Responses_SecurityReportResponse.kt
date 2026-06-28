package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.SecurityReportDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend when generating
 * or retrieving security reports.
 *
 * This response is used by:
 * - Security Reports Screen
 * - PDF Report Generation
 * - Weekly/Monthly Reports
 * - Security History Module
 *
 * Example API Endpoints:
 * GET  /api/v1/security/reports/{reportId}
 * POST /api/v1/security/reports/generate
 */
@Serializable
data class SecurityReportResponse(

    // Indicates whether the request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the backend
    //
    // Examples:
    // "Security report generated successfully"
    // "Security report retrieved successfully"
    // "Failed to generate report"
    @SerialName("message")
    val message: String,

    // Unique identifier of the generated report
    @SerialName("report_id")
    val reportId: String? = null,

    // Complete security report information
    @SerialName("report")
    val report: SecurityReportDto? = null,

    // List of reports
    // Useful when fetching report history
    @SerialName("reports")
    val reports: List<SecurityReportDto> = emptyList(),

    // Total number of reports available
    @SerialName("total_reports")
    val totalReports: Int = 0,

    // Current page number (for paginated report history)
    @SerialName("current_page")
    val currentPage: Int = 1,

    // Number of reports per page
    @SerialName("page_size")
    val pageSize: Int = 20,

    // Total number of pages available
    @SerialName("total_pages")
    val totalPages: Int = 1,

    // Download URL for generated report
    // Example:
    // https://api.sentrix.com/reports/report_123.pdf
    @SerialName("download_url")
    val downloadUrl: String? = null,

    // File format of the generated report
    //
    // Examples:
    // PDF
    // JSON
    // CSV
    @SerialName("report_format")
    val reportFormat: String? = null,

    // Timestamp when the report was generated
    @SerialName("generated_at")
    val generatedAt: Long? = null,

    // Indicates whether the report is archived
    @SerialName("is_archived")
    val isArchived: Boolean = false,

    // Indicates whether the report contains sensitive information
    @SerialName("contains_sensitive_data")
    val containsSensitiveData: Boolean = true,

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional information returned by the backend
    //
    // Example:
    // "report_version" -> "v2.0"
    // "storage_provider" -> "AWS_S3"
    // "expiry_date" -> "1753621000000"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
