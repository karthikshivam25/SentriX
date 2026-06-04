package com.sentrix.domain.models

/**
 * NetworkConnection
 *
 * Represents a monitored network
 * connection within the SentriX platform.
 *
 * Used by:
 * - NetworkMonitoringEngine
 * - FirewallManager
 * - ThreatDetectionEngine
 * - VPNDetectionManager
 * - SecurityDashboard
 * - TrafficAnalysisEngine
 */
data class NetworkConnection(

    /**
     * Unique connection identifier.
     */
    val connectionId: String,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Application name.
     */
    val applicationName: String,

    /**
     * Connection protocol.
     */
    val protocol: NetworkProtocol,

    /**
     * Connection state.
     */
    val state: ConnectionState,

    /**
     * Source IP address.
     */
    val sourceIp: String,

    /**
     * Destination IP address.
     */
    val destinationIp: String,

    /**
     * Source port.
     */
    val sourcePort: Int,

    /**
     * Destination port.
     */
    val destinationPort: Int,

    /**
     * Host name or domain.
     */
    val hostName: String? = null,

    /**
     * Whether connection is encrypted.
     */
    val isEncrypted: Boolean,

    /**
     * Amount of uploaded data in bytes.
     */
    val uploadedBytes: Long,

    /**
     * Amount of downloaded data in bytes.
     */
    val downloadedBytes: Long,

    /**
     * Connection start timestamp.
     */
    val connectedAt: Long,

    /**
     * Last activity timestamp.
     */
    val lastActivityAt: Long,

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
 * Network connection states.
 */
enum class ConnectionState {
    CONNECTING,
    CONNECTED,
    IDLE,
    DISCONNECTED,
    BLOCKED,
    FAILED
}
