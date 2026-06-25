package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.devicetrust.DeviceTrustAssessmentRequestDto
import com.sentrix.data.remote.dto.devicetrust.DeviceTrustResponseDto
import com.sentrix.data.remote.dto.devicetrust.DeviceIntegrityResponseDto
import com.sentrix.data.remote.dto.devicetrust.DeviceComplianceResponseDto
import com.sentrix.data.remote.dto.devicetrust.DeviceRiskResponseDto
import com.sentrix.data.remote.dto.devicetrust.DeviceTrustHistoryResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * DeviceTrustApiService
 *
 * Retrofit API service responsible for device trust,
 * integrity verification, and compliance assessment
 * operations within the SentriX ecosystem.
 *
 * Features:
 * - Device trust assessment
 * - Device integrity verification
 * - Device compliance checks
 * - Risk assessment
 * - Trust history retrieval
 * - Root/jailbreak intelligence
 *
 * Used By:
 * - DeviceTrustRepository
 * - DeviceTrustService
 * - CyberDefenseService
 * - RiskScoringService
 * - SecurityReportingService
 *
 * Base URL Example:
 * https://device-api.sentrix.com/
 */
interface DeviceTrustApiService {

    /**
     * Perform complete device trust assessment.
     *
     * Endpoint:
     * POST /device-trust/assess
     */
    @POST("device-trust/assess")
    suspend fun assessDeviceTrust(
        @Body request: DeviceTrustAssessmentRequestDto
    ): Response<DeviceTrustResponseDto>

    /**
     * Verify device integrity.
     *
     * Endpoint:
     * GET /device-trust/integrity/{deviceId}
     */
    @GET("device-trust/integrity/{deviceId}")
    suspend fun verifyDeviceIntegrity(
        @Path("deviceId")
        deviceId: String
    ): Response<DeviceIntegrityResponseDto>

    /**
     * Check security compliance status.
     *
     * Endpoint:
     * GET /device-trust/compliance/{deviceId}
     */
    @GET("device-trust/compliance/{deviceId}")
    suspend fun getComplianceStatus(
        @Path("deviceId")
        deviceId: String
    ): Response<DeviceComplianceResponseDto>

    /**
     * Retrieve device risk assessment.
     *
     * Endpoint:
     * GET /device-trust/risk/{deviceId}
     */
    @GET("device-trust/risk/{deviceId}")
    suspend fun getDeviceRisk(
        @Path("deviceId")
        deviceId: String
    ): Response<DeviceRiskResponseDto>

    /**
     * Retrieve device trust history.
     *
     * Endpoint:
     * GET /device-trust/history/{deviceId}
     */
    @GET("device-trust/history/{deviceId}")
    suspend fun getDeviceTrustHistory(
        @Path("deviceId")
        deviceId: String
    ): Response<List<DeviceTrustHistoryResponseDto>>
}
