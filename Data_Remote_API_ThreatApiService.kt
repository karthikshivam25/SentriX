package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.threat.ThreatAnalysisRequestDto
import com.sentrix.data.remote.dto.threat.ThreatAnalysisResponseDto
import com.sentrix.data.remote.dto.threat.ThreatDetailsResponseDto
import com.sentrix.data.remote.dto.threat.ThreatHistoryResponseDto
import com.sentrix.data.remote.dto.threat.ThreatReportResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ThreatApiService
 *
 * Retrofit API service responsible for all
 * threat intelligence and threat analysis operations.
 *
 * Features:
 * - Threat analysis
 * - Threat intelligence lookup
 * - Threat history retrieval
 * - Threat reporting
 * - Threat details lookup
 * - Risk assessment support
 *
 * Used By:
 * - ThreatRepository
 * - ThreatAnalysisService
 * - CyberDefenseService
 * - RiskScoringService
 * - SecurityReportingService
 *
 * Base URL Example:
 * https://api.sentrix.com/
 */
interface ThreatApiService {

    /**
     * Analyze a threat using SentriX
     * Threat Intelligence Engine.
     *
     * Endpoint:
     * POST /threats/analyze
     */
    @POST("threats/analyze")
    suspend fun analyzeThreat(
        @Body request: ThreatAnalysisRequestDto
    ): Response<ThreatAnalysisResponseDto>

    /**
     * Get threat details by threat ID.
     *
     * Endpoint:
     * GET /threats/{threatId}
     */
    @GET("threats/{threatId}")
    suspend fun getThreatDetails(
        @Path("threatId")
        threatId: String
    ): Response<ThreatDetailsResponseDto>

    /**
     * Retrieve threat history.
     *
     * Endpoint:
     * GET /threats/history
     */
    @GET("threats/history")
    suspend fun getThreatHistory(
        @Query("page")
        page: Int = 1,

        @Query("limit")
        limit: Int = 20
    ): Response<List<ThreatHistoryResponseDto>>

    /**
     * Generate threat report.
     *
     * Endpoint:
     * GET /threats/report
     */
    @GET("threats/report")
    suspend fun getThreatReport():
            Response<ThreatReportResponseDto>

    /**
     * Search threats by category.
     *
     * Examples:
     * MALWARE
     * PHISHING
     * SPYWARE
     * RANSOMWARE
     *
     * Endpoint:
     * GET /threats/category
     */
    @GET("threats/category")
    suspend fun getThreatsByCategory(
        @Query("category")
        category: String
    ): Response<List<ThreatDetailsResponseDto>>

    /**
     * Search threats by severity.
     *
     * Examples:
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     *
     * Endpoint:
     * GET /threats/severity
     */
    @GET("threats/severity")
    suspend fun getThreatsBySeverity(
        @Query("severity")
        severity: String
    ): Response<List<ThreatDetailsResponseDto>>

    /**
     * Get latest threat intelligence feed.
     *
     * Endpoint:
     * GET /threats/intelligence-feed
     */
    @GET("threats/intelligence-feed")
    suspend fun getThreatIntelligenceFeed():
            Response<List<ThreatDetailsResponseDto>>
}
