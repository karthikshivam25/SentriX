package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used to establish a VPN connection in SentriX.
 *
 * This request is sent to the backend or VPN gateway whenever
 * the user attempts to connect to a secure VPN server.
 *
 * Example API Endpoint:
 * POST /api/v1/vpn/connect
 */
@Serializable
data class VPNConnectRequest(

    // Unique identifier of the user requesting the VPN connection
    @SerialName("user_id")
    val userId: String,

    // Unique identifier of the device initiating the connection
    @SerialName("device_id")
    val deviceId: String,

    // Unique identifier of the VPN server
    // Example: "IN_MUMBAI_01"
    @SerialName("server_id")
    val serverId: String,

    // Country where the selected VPN server is located
    // Example: "India", "United Kingdom", "Germany"
    @SerialName("server_country")
    val serverCountry: String,

    // VPN protocol to use for the connection
    //
    // Possible values:
    // WIREGUARD
    // OPENVPN
    // IKEV2
    @SerialName("protocol")
    val protocol: String = "WIREGUARD",

    // Indicates whether Kill Switch protection should be enabled
    // Kill Switch blocks internet access if VPN disconnects unexpectedly
    @SerialName("enable_kill_switch")
    val enableKillSwitch: Boolean = true,

    // Indicates whether DNS leak protection should be enabled
    @SerialName("enable_dns_leak_protection")
    val enableDnsLeakProtection: Boolean = true,

    // Indicates whether split tunneling is enabled
    // Split tunneling allows selected apps to bypass the VPN
    @SerialName("enable_split_tunneling")
    val enableSplitTunneling: Boolean = false,

    // List of package names excluded from VPN routing
    // Used only when split tunneling is enabled
    @SerialName("excluded_apps")
    val excludedApps: List<String> = emptyList(),

    // Whether automatic reconnect should be enabled
    // VPN will reconnect automatically if connection drops
    @SerialName("auto_reconnect")
    val autoReconnect: Boolean = true,

    // Network type from which the request originates
    // Example:
    // WIFI, MOBILE_DATA, ETHERNET
    @SerialName("network_type")
    val networkType: String = "WIFI",

    // Timestamp when the connection request was created
    @SerialName("requested_at")
    val requestedAt: Long = System.currentTimeMillis(),

    // Additional configuration options or metadata
    //
    // Example:
    // "preferred_dns" -> "1.1.1.1"
    // "battery_optimization" -> "disabled"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
