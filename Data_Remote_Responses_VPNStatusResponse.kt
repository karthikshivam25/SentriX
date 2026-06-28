package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.VPNStatusDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend when requesting
 * VPN connection information or VPN status updates.
 *
 * This response is used by:
 * - VPN Dashboard
 * - Connection Status Screen
 * - Real-time VPN Monitoring
 * - Network Security Module
 *
 * Example API Endpoints:
 * GET  /api/v1/vpn/status
 * POST /api/v1/vpn/connect
 * POST /api/v1/vpn/disconnect
 */
@Serializable
data class VPNStatusResponse(

    // Indicates whether the VPN request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the backend
    //
    // Examples:
    // "VPN connected successfully"
    // "VPN disconnected"
    // "Unable to connect to server"
    @SerialName("message")
    val message: String,

    // Current VPN status information
    @SerialName("vpn_status")
    val vpnStatus: VPNStatusDto? = null,

    // Indicates whether the VPN is currently connected
    @SerialName("is_connected")
    val isConnected: Boolean = false,

    // Current connection state
    //
    // Possible values:
    // CONNECTING
    // CONNECTED
    // DISCONNECTED
    // RECONNECTING
    // FAILED
    @SerialName("connection_state")
    val connectionState: String = "DISCONNECTED",

    // Selected VPN server identifier
    @SerialName("server_id")
    val serverId: String? = null,

    // Name of the connected VPN server
    @SerialName("server_name")
    val serverName: String? = null,

    // Country of the connected VPN server
    @SerialName("server_country")
    val serverCountry: String? = null,

    // VPN protocol currently in use
    //
    // Examples:
    // WIREGUARD
    // OPENVPN
    // IKEV2
    @SerialName("protocol")
    val protocol: String? = null,

    // Timestamp when the VPN connection was established
    @SerialName("connected_since")
    val connectedSince: Long? = null,

    // Total session duration in seconds
    @SerialName("session_duration_seconds")
    val sessionDurationSeconds: Long = 0L,

    // Indicates whether Kill Switch is enabled
    @SerialName("kill_switch_enabled")
    val killSwitchEnabled: Boolean = false,

    // Indicates whether DNS leak protection is enabled
    @SerialName("dns_leak_protection_enabled")
    val dnsLeakProtectionEnabled: Boolean = false,

    // Current VPN security score
    // Range: 0 - 100
    @SerialName("security_score")
    val securityScore: Int = 100,

    // Server timestamp when this response was generated
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional information returned by the backend
    //
    // Example:
    // "latency_ms" -> "42"
    // "server_load" -> "35%"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
