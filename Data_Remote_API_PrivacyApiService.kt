package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.privacy.PrivacyAuditRequestDto
import com.sentrix.data.remote.dto.privacy.PrivacyAuditResponseDto
import com.sentrix.data.remote.dto.privacy.PrivacyRiskResponseDto
import com.sentrix.data.remote.dto.privacy.PermissionAnalysisResponseDto
import com.sentrix.data.remote.dto.privacy.TrackerAnalysisResponseDto
import com.sentrix.data.remote.dto.privacy.PrivacyRecommendationResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * PrivacyApiService
 *
 * Retrofit API service responsible for privacy-related
 * operations within the SentriX ecosystem.
 *
 * Features:
 * - Privacy audits
 * - Permission analysis
 * - Tracker detection
 * - Privacy risk assessment
 * - Privacy recommendations
 * - App privacy intelligence
 *
 * Used By:
 * - PrivacyRepository
 * - PrivacyAuditService
 * - PrivacyMonitoringService
 * - CyberDefenseService
 * - PrivacyViewModel
 *
 * Base URL Example:
 * https://privacy-api.sentrix.com/
 */
interface PrivacyApiService {

    /**
     * Perform a privacy audit for an application.
     *
     * Endpoint:
     * POST /privacy/audit
     */
    @POST("privacy/audit")
    suspend fun performPrivacyAudit(
        @Body request: PrivacyAuditRequestDto
    ): Response<PrivacyAuditResponseDto>

    /**
     * Analyze application permissions.
     *
     * Endpoint:
     * GET /privacy/permissions/{packageName}
     */
    @GET("privacy/permissions/{packageName}")
    suspend fun analyzePermissions(
        @Path("packageName")
        packageName: String
    ): Response<PermissionAnalysisResponseDto>

    /**
     * Detect trackers inside an application.
     *
     * Endpoint:
     * GET /privacy/trackers/{packageName}
     */
    @GET("privacy/trackers/{packageName}")
    suspend fun analyzeTrackers(
        @Path("packageName")
        packageName: String
    ): Response<TrackerAnalysisResponseDto>

    /**
     * Retrieve privacy risk assessment.
     *
     * Endpoint:
     * GET /privacy/risk/{packageName}
     */
    @GET("privacy/risk/{packageName}")
    suspend fun getPrivacyRisk(
        @Path("packageName")
        packageName: String
    ): Response<PrivacyRiskResponseDto>

    /**
     * Retrieve privacy recommendations.
     *
     * Endpoint:
     * GET /privacy/recommendations
     */
    @GET("privacy/recommendations")
    suspend fun getPrivacyRecommendations():
            Response<List<PrivacyRecommendationResponseDto>>
}
