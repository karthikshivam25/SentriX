package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.security.SecurityDashboardResponseDto
import com.sentrix.data.remote.dto.security.SecurityReportResponseDto
import com.sentrix.data.remote.dto.security.SecurityStatusResponseDto
import com.sentrix.data.remote.dto.security.SecurityRecommendationResponseDto
import com.sentrix.data.remote.dto.security.SecurityEventResponseDto
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * SecurityApiService
 *
 * Retrofit API service responsible for security-related
 * operations within the SentriX platform.
 *
 * Features:
 * - Security dashboard data
 * - Security reports
 * - Security recommendations
 * - Security events
 * - Security posture monitoring
 * - Risk score retrieval
 * - Security analytics
 *
 * Used By:
 * - SecurityRepository
 * - SecurityReportingService
 * - CyberDefenseService
 * - RiskScoringService
 * - AnalyticsService
 * - DashboardViewModel
 *
 * Base URL Example:
 * https://api.sentrix.com/
 */
interface SecurityApiService {

    /**
     * Get current device security status.
     *
     * Endpoint:
     * GET /security/status
     */
    @GET("security/status")
    suspend fun getSecurityStatus():
            Response<SecurityStatusResponseDto>

    /**
     * Get dashboard security summary.
     *
     * Endpoint:
     * GET /security/dashboard
     */
    @GET("security/dashboard")
    suspend fun getSecurityDashboard():
            Response<SecurityDashboardResponseDto>

    /**
     * Get security recommendations.
     *
     * Endpoint:
     * GET /security/recommendations
     */
    @GET("security/recommendations")
    suspend fun getSecurityRecommendations():
            Response<List<SecurityRecommendationResponseDto>>

    /**
     * Get security events history.
     *
     * Endpoint:
     * GET /security/events
     */
    @GET("security/events")
    suspend fun getSecurityEvents(

        @Query("page")
        page: Int = 1,

        @Query("limit")
        limit: Int = 20

    ): Response<List<SecurityEventResponseDto>>

    /**
     * Get specific security event details.
     *
     * Endpoint:
     * GET /security/events/{eventId}
     */
    @GET("security/events/{eventId}")
    suspend fun getSecurityEventDetails(
        @Path("eventId")
        eventId: String
    ): Response<SecurityEventResponseDto>

    /**
     * Generate a complete security report.
     *
     * Endpoint:
     * GET /security/report
     */
    @GET("security/report")
    suspend fun getSecurityReport():
            Response<SecurityReportResponseDto>

    /**
     * Get security score trend analytics.
     *
     * Endpoint:
     * GET /security/score-history
     */
    @GET("security/score-history")
    suspend fun getSecurityScoreHistory():
            Response<List<Int>>
}
