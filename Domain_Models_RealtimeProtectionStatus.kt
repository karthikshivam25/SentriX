package com.sentrix.domain.models

import java.util.UUID

/**
 * RealtimeProtectionStatus
 *
 * Represents the current state of SentriX
 * real-time protection services and
 * active security monitoring components.
 *
 * Used by:
 * - RealtimeProtectionEngine
 * - ThreatDetectionManager
 * - SecurityDashboard
 * - MalwareProtectionService
 * - IntrusionDetectionSystem
 * - DeviceSecurityMonitor
 */
data class RealtimeProtectionStatus(

    /**
     * Unique status identifier.
     */
    val statusId: String = UUID.randomUUID().toString(),

    /**
     * Indicates whether protection
     * services are currently active.
     */
    val isProtectionActive: Boolean = false,

    /**
     * Indicates whether monitoring
     * is currently enabled.
     */
    val isMonitoringEnabled: Boolean = false,

    /**
     * Indicates whether threat
     * detection is active.
     */
    val isThreatDetectionActive: Boolean = false,

    /**
     * Firewall protection status.
     */
    val isFirewallActive: Boolean = false,

    /**
     * VPN protection status.
     */
    val isVpnProtectionActive: Boolean = false,

    /**
     * Malware shield status.
     */
    val isMalwareShieldActive: Boolean = false,

    /**
     * Phishing protection status.
     */
    val isPhishingProtectionActive: Boolean = false,

    /**
     * Ransomware protection status.
     */
    val isRansomwareProtectionActive: Boolean = false,

    /**
     * Intrusion detection status.
     */
    val isIntrusionDetectionActive: Boolean = false,

    /**
     * Current threat level.
     */
    val currentThreatLevel: ThreatLevel = ThreatLevel.LOW,

    /**
     * Overall security score.
     */
    val securityScore: Int = 0,

    /**
     * Number of monitored processes.
     */
    val monitoredProcesses: Int = 0,

    /**
     * Number of monitored applications.
     */
    val monitoredApplications: Int = 0,

    /**
     * Number of monitored connections.
     */
    val monitoredConnections: Int = 0,

    /**
     * Number of monitored files.
     */
    val monitoredFiles: Int = 0,

    /**
     * Threats detected today.
     */
    val threatsDetectedToday: Int = 0,

    /**
     * Threats blocked today.
     */
    val threatsBlockedToday: Int = 0,

    /**
     * Suspicious activities detected.
     */
    val suspiciousActivitiesDetected: Int = 0,

    /**
     * Total active alerts.
     */
    val activeAlerts: Int = 0,

    /**
     * Total critical alerts.
     */
    val criticalAlerts: Int = 0,

    /**
     * Timestamp of the latest threat.
     */
    val lastThreatDetectedAt: Long? = null,

    /**
     * Last status update timestamp.
     */
    val lastProtectionUpdateAt: Long =
        System.currentTimeMillis(),

    /**
     * Current CPU usage percentage.
     */
    val cpuUsagePercentage: Float = 0f,

    /**
     * Current memory usage percentage.
     */
    val memoryUsagePercentage: Float = 0f,

    /**
     * Enabled protection modules.
     */
    val enabledProtectionModules: List<String> =
        emptyList(),

    /**
     * Disabled protection modules.
     */
    val disabledProtectionModules: List<String> =
        emptyList(),

    /**
     * Indicates whether automated
     * response actions are enabled.
     */
    val autoResponseEnabled: Boolean = false,

    /**
     * AI-powered protection status.
     */
    val aiProtectionEnabled: Boolean = false,

    /**
     * Zero Trust protection status.
     */
    val zeroTrustProtectionEnabled: Boolean = false,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)
