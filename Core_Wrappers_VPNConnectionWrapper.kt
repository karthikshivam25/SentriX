package com.sentrix.core.wrappers

import com.sentrix.core.enums.VPNStatus

/**
 * Represents the current VPN connection state and metadata.
 */
data class VPNConnectionWrapper(
    val serverName: String = "",
    val serverLocation: String = "",
    val ipAddress: String = "",
    val protocol: String = "",
    val status: VPNStatus = VPNStatus.DISCONNECTED,
    val isSecureConnection: Boolean = false,
    val connectionDurationMillis: Long = 0L,
    val downloadSpeedMbps: Double = 0.0,
    val uploadSpeedMbps: Double = 0.0,
    val pingMs: Int = 0,
    val connectedAt: Long? = null,
    val disconnectedAt: Long? = null,
    val metadata: Map<String, Any> = emptyMap()
) {

    /**
     * Returns true if VPN is connected.
     */
    fun isConnected(): Boolean =
        status == VPNStatus.CONNECTED

    /**
     * Returns true if VPN is currently connecting.
     */
    fun isConnecting(): Boolean =
        status == VPNStatus.CONNECTING

    /**
     * Returns true if VPN is disconnected.
     */
    fun isDisconnected(): Boolean =
        status == VPNStatus.DISCONNECTED

    /**
     * Returns connection duration in seconds.
     */
    fun getConnectionDurationSeconds(): Long =
        connectionDurationMillis / 1000

    /**
     * Returns connection duration in minutes.
     */
    fun getConnectionDurationMinutes(): Long =
        connectionDurationMillis / 60000

    /**
     * Returns true if connection speeds are available.
     */
    fun hasSpeedMetrics(): Boolean =
        downloadSpeedMbps > 0.0 || uploadSpeedMbps > 0.0

    /**
     * Returns true if additional metadata exists.
     */
    fun hasMetadata(): Boolean =
        metadata.isNotEmpty()

    companion object {

        fun disconnected(): VPNConnectionWrapper {
            return VPNConnectionWrapper(
                status = VPNStatus.DISCONNECTED
            )
        }

        fun connecting(
            serverName: String,
            serverLocation: String
        ): VPNConnectionWrapper {
            return VPNConnectionWrapper(
                serverName = serverName,
                serverLocation = serverLocation,
                status = VPNStatus.CONNECTING
            )
        }
    }
}
