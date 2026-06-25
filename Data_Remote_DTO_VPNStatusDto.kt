package com.sentrix.data.remote.dto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * DTO representing the current VPN status received from the backend.
 *
 * This object is used by SentriX to display VPN connection information,
 * secure browsing status, and network protection details.
 */
@Serializable
data class VPNStatusDto(

    // Indicates whether the VPN service is currently enabled
    @SerialName("is_enabled")
    val isEnabled: Boolean = false,

    // Indicates whether the VPN is currently connected
    @SerialName("is_connected")
    val isConnected: Boolean = false,

    // Current VPN connection state
    // Example: CONNECTING, CONNECTED, DISCONNECTED, RECONNECTING
    @SerialName("connection_state")
    val connectionState: String = "DISCONNECTED",

    // Name of the VPN provider/server
    // Example: "SentriX Secure VPN"
    @SerialName("provider_name")
    val providerName: String = "",

    // Unique identifier of the connected server
    @SerialName("server_id")
    val serverId: String = "",

    // Friendly name of the connected server
    // Example: "Mumbai #01"
    @SerialName("server_name")
    val serverName: String = "",

    // Country where the VPN server is located
    @SerialName("server_country")
    val serverCountry: String = "",

    // City where the VPN server is located
    @SerialName("server_city")
    val serverCity: String = "",

    // IP address assigned by the VPN server
    @SerialName("vpn_ip_address")
    val vpnIpAddress: String = "",

    // Protocol currently being used
    // Example: WireGuard, OpenVPN, IKEv2
    @SerialName("protocol")
    val protocol: String = "",

    // Encryption algorithm used for the connection
    // Example: AES-256, ChaCha20
    @SerialName("encryption")
    val encryption: String = "",

    // VPN session start time (Epoch milliseconds)
    @SerialName("connected_since")
    val connectedSince: Long? = null,

    // Total duration of the active session in seconds
    @SerialName("session_duration_seconds")
    val sessionDurationSeconds: Long = 0L,

    // Downloaded data during this VPN session (in bytes)
    @SerialName("bytes_received")
    val bytesReceived: Long = 0L,

    // Uploaded data during this VPN session (in bytes)
    @SerialName("bytes_sent")
    val bytesSent: Long = 0L,

    // Current network type while VPN is active
    // Example: WIFI, MOBILE_DATA, ETHERNET
    @SerialName("network_type")
    val networkType: String = "",

    // Indicates whether Kill Switch protection is enabled
    @SerialName("kill_switch_enabled")
    val killSwitchEnabled: Boolean = false,

    // Indicates whether DNS leak protection is enabled
    @SerialName("dns_leak_protection_enabled")
    val dnsLeakProtectionEnabled: Boolean = false,

    // Indicates whether the VPN connection is considered secure
    @SerialName("is_secure")
    val isSecure: Boolean = true,

    // Current VPN risk score calculated by SentriX
    // Range: 0 - 100 (higher means safer)
    @SerialName("security_score")
    val securityScore: Int = 100,

    // Additional server or session information
    // Example:
    // "latency_ms" -> "45"
    // "load_percentage" -> "62"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
