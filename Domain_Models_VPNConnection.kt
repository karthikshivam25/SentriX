package com.sentrix.domain.models

/**
 * VPNConnection
 *
 * Represents an active or historical
 * VPN connection monitored by the
 * SentriX platform.
 *
 * Used by:
 * - VPNDetectionManager
 * - NetworkSecurityEngine
 * - PrivacyMonitor
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - ComplianceMonitoring
 */
data class VPNConnection(

    /**
     * Unique connection identifier.
     */
    val connectionId: String,

    /**
     * VPN application name.
     */
    val vpnName: String,

    /**
     * VPN provider.
     */
    val provider: String,

    /**
     * VPN connection status.
     */
    val status: VPNStatus,

    /**
     * VPN protocol.
     */
    val protocol: VPNProtocol,

    /**
     * Assigned VPN IP address.
     */
    val ipAddress: String,

    /**
     * Connected server location.
     */
    val serverLocation: String,

    /**
     * Connection start timestamp.
     */
    val connectedAt: Long,

    /**
     * Connection duration in milliseconds.
     */
    val connectionDuration: Long,

    /**
     * Encryption type.
     */
    val encryptionType: String,

    /**
     * Whether kill switch is enabled.
     */
    val isKillSwitchEnabled: Boolean,

    /**
     * Whether traffic leak was detected.
     */
    val leakDetected: Boolean,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * VPN connection status.
 */
enum class VPNStatus {
    CONNECTED,
    DISCONNECTED,
    CONNECTING,
    RECONNECTING,
    FAILED
}

/**
 * Supported VPN protocols.
 */
enum class VPNProtocol {
    OPENVPN,
    WIREGUARD,
    IKEV2,
    L2TP,
    PPTP,
    SSTP,
    CUSTOM,
    UNKNOWN
}
