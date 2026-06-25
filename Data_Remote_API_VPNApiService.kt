package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.vpn.VPNConnectionRequestDto
import com.sentrix.data.remote.dto.vpn.VPNConnectionResponseDto
import com.sentrix.data.remote.dto.vpn.VPNServerResponseDto
import com.sentrix.data.remote.dto.vpn.VPNStatusResponseDto
import com.sentrix.data.remote.dto.vpn.VPNStatisticsResponseDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * VPNApiService
 *
 * Retrofit API service responsible for all VPN-related
 * communication between the SentriX application and
 * SentriX Cloud VPN infrastructure.
 *
 * Features:
 * - VPN server discovery
 * - VPN connection management
 * - VPN status monitoring
 * - VPN statistics retrieval
 * - VPN session management
 *
 * Used By:
 * - VPNRepository
 * - VPNService
 * - NetworkProtectionService
 * - CyberDefenseService
 * - VPNViewModel
 *
 * Base URL Example:
 * https://vpn-api.sentrix.com/
 */
interface VPNApiService {

    /**
     * Retrieve available VPN servers.
     *
     * Endpoint:
     * GET /vpn/servers
     */
    @GET("vpn/servers")
    suspend fun getAvailableServers():
            Response<List<VPNServerResponseDto>>

    /**
     * Establish a VPN connection.
     *
     * Endpoint:
     * POST /vpn/connect
     */
    @POST("vpn/connect")
    suspend fun connectVPN(
        @Body request: VPNConnectionRequestDto
    ): Response<VPNConnectionResponseDto>

    /**
     * Disconnect the current VPN session.
     *
     * Endpoint:
     * POST /vpn/disconnect
     */
    @POST("vpn/disconnect")
    suspend fun disconnectVPN():
            Response<Unit>

    /**
     * Retrieve current VPN connection status.
     *
     * Endpoint:
     * GET /vpn/status
     */
    @GET("vpn/status")
    suspend fun getVPNStatus():
            Response<VPNStatusResponseDto>

    /**
     * Retrieve VPN usage statistics.
     *
     * Endpoint:
     * GET /vpn/statistics
     */
    @GET("vpn/statistics")
    suspend fun getVPNStatistics():
            Response<VPNStatisticsResponseDto>

    /**
     * Retrieve details of a specific VPN server.
     *
     * Endpoint:
     * GET /vpn/servers/{serverId}
     */
    @GET("vpn/servers/{serverId}")
    suspend fun getServerDetails(
        @Path("serverId")
        serverId: String
    ): Response<VPNServerResponseDto>
}
