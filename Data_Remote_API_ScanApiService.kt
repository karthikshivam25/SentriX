package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.scan.ScanRequestDto
import com.sentrix.data.remote.dto.scan.ScanResponseDto
import com.sentrix.data.remote.dto.scan.ScanHistoryResponseDto
import com.sentrix.data.remote.dto.scan.ScanStatusResponseDto
import com.sentrix.data.remote.dto.scan.ScanReportResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ScanApiService
 *
 * Retrofit API service responsible for all
 * security scanning operations in SentriX.
 *
 * Features:
 * - Start security scans
 * - Monitor scan progress
 * - Retrieve scan history
 * - Generate scan reports
 * - Fetch scan results
 * - Scan analytics integration
 *
 * Used By:
 * - ScanRepository
 * - ScanOptimizationService
 * - ThreatAnalysisService
 * - CyberDefenseService
 * - SecurityReportingService
 *
 * Base URL Example:
 * https://api.sentrix.com/
 */
interface ScanApiService {

    /**
     * Start a new security scan.
     *
     * Endpoint:
     * POST /scans/start
     */
    @POST("scans/start")
    suspend fun startScan(
        @Body request: ScanRequestDto
    ): Response<ScanResponseDto>

    /**
     * Get current scan status.
     *
     * Endpoint:
     * GET /scans/{scanId}/status
     */
    @GET("scans/{scanId}/status")
    suspend fun getScanStatus(
        @Path("scanId")
        scanId: String
    ): Response<ScanStatusResponseDto>

    /**
     * Retrieve scan results.
     *
     * Endpoint:
     * GET /scans/{scanId}/result
     */
    @GET("scans/{scanId}/result")
    suspend fun getScanResult(
        @Path("scanId")
        scanId: String
    ): Response<ScanResponseDto>

    /**
     * Retrieve scan history.
     *
     * Endpoint:
     * GET /scans/history
     */
    @GET("scans/history")
    suspend fun getScanHistory(
        @Query("page")
        page: Int = 1,

        @Query("limit")
        limit: Int = 20
    ): Response<List<ScanHistoryResponseDto>>

    /**
     * Generate scan report.
     *
     * Endpoint:
     * GET /scans/report/{scanId}
     */
    @GET("scans/report/{scanId}")
    suspend fun getScanReport(
        @Path("scanId")
        scanId: String
    ): Response<ScanReportResponseDto>

    /**
     * Cancel running scan.
     *
     * Endpoint:
     * POST /scans/{scanId}/cancel
     */
    @POST("scans/{scanId}/cancel")
    suspend fun cancelScan(
        @Path("scanId")
        scanId: String
    ): Response<Unit>

    /**
     * Get latest completed scans.
     *
     * Endpoint:
     * GET /scans/recent
     */
    @GET("scans/recent")
    suspend fun getRecentScans():
            Response<List<ScanHistoryResponseDto>>
}
