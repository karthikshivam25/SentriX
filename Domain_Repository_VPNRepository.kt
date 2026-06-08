package com.sentrix.domain.repositories

import com.sentrix.domain.models.VPNConnection
import com.sentrix.domain.models.VPNConnectionStatus
import com.sentrix.domain.models.VPNServer

/**
 * VPNRepository
 *
 * Repository responsible for
 * managing VPN services within
 * the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - EnableVPNProtectionUseCase
 * - DisableVPNProtectionUseCase
 * - VPNManager
 * - SecurityDashboard
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Manage VPN connections
 * - Retrieve VPN servers
 * - Monitor VPN status
 * - Store VPN sessions
 * - Support secure networking
 */
interface VPNRepository {

    /**
     * Connects to VPN server.
     *
     * @param server VPN server.
     *
     * @return VPN connection.
     */
    suspend fun connect(
        server: VPNServer
    ): VPNConnection

    /**
     * Disconnects VPN.
     *
     * @return Success status.
     */
    suspend fun disconnect():
        Boolean

    /**
     * Retrieves current
     * VPN connection.
     *
     * @return VPN connection.
     */
    suspend fun getCurrentConnection():
        VPNConnection?

    /**
     * Retrieves all
     * available VPN servers.
     *
     * @return Server list.
     */
    suspend fun getAvailableServers():
        List<VPNServer>

    /**
     * Retrieves VPN server
     * by identifier.
     *
     * @param serverId Server ID.
     *
     * @return VPN server.
     */
    suspend fun getServerById(
        serverId: String
    ): VPNServer?

    /**
     * Retrieves current
     * VPN status.
     *
     * @return Connection status.
     */
    suspend fun getConnectionStatus():
        VPNConnectionStatus

    /**
     * Checks whether VPN
     * is currently connected.
     *
     * @return Connection status.
     */
    suspend fun isConnected():
        Boolean

    /**
     * Retrieves VPN
     * connection history.
     *
     * @return Connection list.
     */
    suspend fun getConnectionHistory():
        List<VPNConnection>
}

/**
 * VPNConnection
 *
 * Represents an active or
 * historical VPN connection.
 */
data class VPNConnection(

    /**
     * Connection identifier.
     */
    val connectionId: String,

    /**
     * Connected server.
     */
    val server: VPNServer,

    /**
     * Connection status.
     */
    val status:
        VPNConnectionStatus,

    /**
     * Connection timestamp.
     */
    val connectedAt: Long,

    /**
     * Disconnection timestamp.
     */
    val disconnectedAt: Long?,

    /**
     * Data transferred.
     */
    val dataTransferred: Long
)

/**
 * VPNServer
 *
 * Represents a VPN server.
 */
data class VPNServer(

    /**
     * Server identifier.
     */
    val serverId: String,

    /**
     * Server name.
     */
    val serverName: String,

    /**
     * Server country.
     */
    val country: String,

    /**
     * Server city.
     */
    val city: String,

    /**
     * Server address.
     */
    val address: String,

    /**
     * Indicates whether
     * server is available.
     */
    val isAvailable: Boolean
)

/**
 * VPN connection status.
 */
enum class VPNConnectionStatus {

    /**
     * VPN connected.
     */
    CONNECTED,

    /**
     * VPN connecting.
     */
    CONNECTING,

    /**
     * VPN disconnected.
     */
    DISCONNECTED,

    /**
     * VPN connection failed.
     */
    FAILED
}
