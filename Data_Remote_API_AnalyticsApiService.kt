package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.analytics.AnalyticsDashboardResponseDto
import com.sentrix.data.remote.dto.analytics.SecurityTrendResponseDto
import com.sentrix.data.remote.dto.analytics.ThreatAnalyticsResponseDto
import com.sentrix.data.remote.dto.analytics.ScanAnalyticsResponseDto
import com.sentrix.data.remote.dto.analytics.DeviceUsageAnalyticsResponseDto
import com.sentrix.data.remote.dto.analytics.AnalyticsEventRequestDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AnalyticsApiService
 *
 * Retrofit API service responsible for analytics,
 * telemetry, reporting, and security insights
 * within the SentriX platform.
 *
 * Features:
 * - Dashboard analytics
 * - Threat analytics
 * - Scan analytics
 * - Security trend analysis
 * - Device usage analytics
 * - Event tracking
 * - User behavior analytics
 *
 * Used By:
 * - AnalyticsRepository
 * - AnalyticsService
 * - DashboardViewModel
 * - ReportsViewModel
 * - CyberDefenseService
 *
 * Base URL Example:
 * https://api.sentrix.com/
 */
interface AnalyticsApiService {

    /**
     * Retrieve analytics dashboard summary.
     *
     * Endpoint:
     * GET /analytics/dashboard
     */
    @GET("analytics/dashboard")
    suspend fun getAnalyticsDashboard():
            Response<AnalyticsDashboardResponseDto>

    /**
     * Retrieve threat analytics.
     *
     * Endpoint:
     * GET /analytics/threats
     */
    @GET("analytics/threats")
    suspend fun getThreatAnalytics(
        @Query("period")
        period: String = "30D"
    ): Response<ThreatAnalyticsResponseDto>

    /**
     * Retrieve scan analytics.
     *
     * Endpoint:
     * GET /analytics/scans
     */
    @GET("analytics/scans")
    suspend fun getScanAnalytics(
        @Query("period")
        period: String = "30D"
    ): Response<ScanAnalyticsResponseDto>

    /**
     * Retrieve security score trends.
     *
     * Endpoint:
     * GET /analytics/security-trends
     */
    @GET("analytics/security-trends")
    suspend fun getSecurityTrends(
        @Query("period")
        period: String = "30D"
    ): Response<SecurityTrendResponseDto>

    /**
     * Retrieve device usage analytics.
     *
     * Endpoint:
     * GET /analytics/device-usage
     */
    @GET("analytics/device-usage")
    suspend fun getDeviceUsageAnalytics():
            Response<DeviceUsageAnalyticsResponseDto>

    /**
     * Send analytics event to backend.
     *
     * Endpoint:
     * POST /analytics/events
     */
    @POST("analytics/events")
    suspend fun trackEvent(
        @Body event: AnalyticsEventRequestDto
    ): Response<Unit>
}
