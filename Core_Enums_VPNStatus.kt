package com.sentrix.core.enums

/**
 * Represents the current VPN connection status
 */
enum class VPNStatus(
    val displayName: String,
    val description: String
) {

    DISCONNECTED(
        displayName = "Disconnected",
        description = "VPN is currently disconnected"
    ),

    CONNECTING(
        displayName = "Connecting",
        description = "Establishing secure VPN connection"
    ),

    AUTHENTICATING(
        displayName = "Authenticating",
        description = "Verifying VPN credentials and certificates"
    ),

    CONNECTED(
        displayName = "Connected",
        description = "VPN connection established successfully"
    ),

    RECONNECTING(
        displayName = "Reconnecting",
        description = "Attempting to restore VPN connection"
    ),

    DISCONNECTING(
        displayName = "Disconnecting",
        description = "Closing VPN tunnel securely"
    ),

    PAUSED(
        displayName = "Paused",
        description = "VPN protection temporarily paused"
    ),

    BLOCKED(
        displayName = "Blocked",
        description = "VPN connection blocked by network or firewall"
    ),

    LIMITED(
        displayName = "Limited",
        description = "VPN connected with restricted functionality"
    ),

    NO_INTERNET(
        displayName = "No Internet",
        description = "Internet connection unavailable"
    ),

    SERVER_UNREACHABLE(
        displayName = "Server Unreachable",
        description = "Unable to contact VPN server"
    ),

    DNS_PROTECTION_ACTIVE(
        displayName = "DNS Protection Active",
        description = "Secure DNS protection is enabled"
    ),

    KILL_SWITCH_ACTIVE(
        displayName = "Kill Switch Active",
        description = "Internet blocked to prevent data leaks"
    ),

    ERROR(
        displayName = "Error",
        description = "Unexpected VPN error occurred"
    );

    /**
     * Returns true if VPN tunnel is active
     */
    fun isConnected(): Boolean {
        return this == CONNECTED ||
               this == DNS_PROTECTION_ACTIVE
    }

    /**
     * Returns true if VPN is attempting connection
     */
    fun isConnecting(): Boolean {
        return this == CONNECTING ||
               this == AUTHENTICATING ||
               this == RECONNECTING
    }

    /**
     * Returns true if VPN has issues
     */
    fun hasError(): Boolean {
        return this == ERROR ||
               this == SERVER_UNREACHABLE ||
               this == BLOCKED ||
               this == NO_INTERNET
    }

    /**
     * Returns true if protection is enabled
     */
    fun isProtectionActive(): Boolean {
        return isConnected() ||
               this == KILL_SWITCH_ACTIVE
    }
}
