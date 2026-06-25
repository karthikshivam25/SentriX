package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.report.GenerateReportRequestDto
import com.sentrix.data.remote.dto.report.ReportDownloadResponseDto
import com.sentrix.data.remote.dto.report.ReportHistoryResponseDto
import com.sentrix.data.remote.dto.report.SecurityReportSummaryDto
import com.sentrix.data.remote.dto.report.ShareReportRequestDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ReportApiService
 *
 * Retrofit API service responsible for generating,
 * retrieving, downloading, and sharing reports
 * within the SentriX ecosystem.
 *
 * Features:
 * - Security report generation
 * - Report history retrieval
 * - Report download
 * - Report sharing
 * - Compliance reporting
 * - PDF/CSV report export
 *
 * Used By:
 * - SecurityReportingService
 * - AnalyticsService
 * - ReportRepository
 * - ReportsViewModel
 * - DashboardViewModel
 *
 * Base URL Example:
 * https://reports-api.sentrix.com/
 */
interface ReportApiService {

    /**
     * Generate a new security report.
     *
     * Endpoint:
     * POST /reports/generate
     */
    @POST("reports/generate")
    suspend fun generateReport(
        @Body request: GenerateReportRequestDto
    ): Response<SecurityReportSummaryDto>

    /**
     * Retrieve report details.
     *
     * Endpoint:
     * GET /reports/{reportId}
     */
    @GET("reports/{reportId}")
    suspend fun getReportDetails(
        @Path("reportId")
        reportId: String
    ): Response<SecurityReportSummaryDto>

    /**
     * Retrieve report history.
     *
     * Endpoint:
     * GET /reports/history
     */
    @GET("reports/history")
    suspend fun getReportHistory(
        @Query("page")
        page: Int = 1,

        @Query("limit")
        limit: Int = 20
    ): Response<List<ReportHistoryResponseDto>>

    /**
     * Download a report.
     *
     * Endpoint:
     * GET /reports/download/{reportId}
     */
    @GET("reports/download/{reportId}")
    suspend fun downloadReport(
        @Path("reportId")
        reportId: String
    ): Response<ReportDownloadResponseDto>

    /**
     * Share report via email or other channels.
     *
     * Endpoint:
     * POST /reports/share
     */
    @POST("reports/share")
    suspend fun shareReport(
        @Body request: ShareReportRequestDto
    ): Response<Unit>

    /**
     * Retrieve latest generated reports.
     *
     * Endpoint:
     * GET /reports/recent
     */
    @GET("reports/recent")
    suspend fun getRecentReports():
            Response<List<ReportHistoryResponseDto>>
}
