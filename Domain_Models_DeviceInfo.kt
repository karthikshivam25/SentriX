package com.sentrix.domain.models

/**
 * DeviceInfo
 *
 * Represents detailed information about a device
 * monitored, protected, or managed by the SentriX
 * cybersecurity platform.
 *
 * The model contains hardware details, operating
 * system information, security posture indicators,
 * device integrity status, and device identification
 * data used throughout the platform.
 *
 * Used by:
 * - DeviceManager
 * - DeviceIntegrityManager
 * - SecurityDashboard
 * - AuthenticationManager
 * - ThreatDetectionEngine
 * - RealtimeProtectionService
 * - EndpointProtectionManager
 * - AssetInventorySystem
 */
data class DeviceInfo(

    /**
     * Unique device identifier.
     */
    val deviceId: String,

    /**
     * Device name displayed to users.
     */
    val deviceName: String,

    /**
     * Device manufacturer.
     */
    val manufacturer: String,

    /**
     * Device model.
     */
    val model: String,

    /**
     * Device category.
     */
    val deviceType: DeviceType,

    /**
     * Operating system name.
     */
    val operatingSystem: String,

    /**
     * Operating system version.
     */
    val operatingSystemVersion: String,

    /**
     * Device SDK version.
     */
    val sdkVersion: Int? = null,

    /**
     * Device architecture.
     */
    val architecture: String? = null,

    /**
     * Serial number if available.
     */
    val serialNumber: String? = null,

    /**
     * Unique hardware identifier.
     */
    val hardwareId: String? = null,

    /**
     * Indicates whether the device
     * is currently active.
     */
    val isActive: Boolean = true,

    /**
     * Indicates whether the device
     * is managed by an organization.
     */
    val isManagedDevice: Boolean = false,

    /**
     * Indicates whether the device
     * is rooted or jailbroken.
     */
    val isCompromised: Boolean = false,

    /**
     * Indicates whether the device
     * passes integrity verification.
     */
    val isIntegrityVerified: Boolean = true,

    /**
     * Current security score.
     */
    val securityScore: Int = 0,

    /**
     * Current device risk level.
     */
    val riskLevel: DeviceRiskLevel =
        DeviceRiskLevel.LOW,

    /**
     * Last successful security scan.
     */
    val lastScanTimestamp: Long = 0L,

    /**
     * Last time the device was seen online.
     */
    val lastSeenTimestamp: Long = 0L,

    /**
     * Number of threats detected
     * on the device.
     */
    val detectedThreats: Int = 0,

    /**
     * Number of threats blocked.
     */
    val blockedThreats: Int = 0,

    /**
     * Installed security modules.
     */
    val enabledSecurityModules: List<String> =
        emptyList(),

    /**
     * Assigned compliance standards.
     */
    val complianceStandards: List<String> =
        emptyList(),

    /**
     * Device tags used for grouping
     * and asset management.
     */
    val tags: List<String> =
        emptyList(),

    /**
     * Additional device metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * Device type classifications.
 *
 * Represents the category of device
 * being protected or monitored.
 */
enum class DeviceType {

    /**
     * Android mobile device.
     */
    ANDROID,

    /**
     * Apple iPhone device.
     */
    IOS,

    /**
     * Windows desktop or laptop.
     */
    WINDOWS,

    /**
     * macOS desktop or laptop.
     */
    MACOS,

    /**
     * Linux-based device.
     */
    LINUX,

    /**
     * Cloud-hosted virtual machine.
     */
    CLOUD,

    /**
     * Internet of Things device.
     */
    IOT,

    /**
     * Server infrastructure.
     */
    SERVER,

    /**
     * Unknown device type.
     */
    UNKNOWN
}

/**
 * Device risk indicators.
 *
 * Represents the current security
 * risk associated with a device.
 */
enum class DeviceRiskLevel {

    /**
     * Low-risk device.
     */
    LOW,

    /**
     * Medium-risk device.
     */
    MEDIUM,

    /**
     * High-risk device.
     */
    HIGH,

    /**
     * Critical-risk device requiring
     * immediate remediation.
     */
    CRITICAL
}
