package com.sentrix.domain.models

/**
 * DeviceIntegrity
 *
 * Represents the overall integrity and
 * trust status of a device monitored
 * by the SentriX platform.
 *
 * Used by:
 * - DeviceIntegrityManager
 * - Root Detection Engine
 * - Emulator Detection Engine
 * - Security Dashboard
 * - Compliance Monitoring
 * - Risk Assessment Engine
 */
data class DeviceIntegrity(

    /**
     * Unique device identifier.
     */
    val deviceId: String,

    /**
     * Device name.
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
     * Android version.
     */
    val androidVersion: String,

    /**
     * Integrity status.
     */
    val integrityStatus: IntegrityStatus,

    /**
     * Overall integrity score (0 - 100).
     */
    val integrityScore: Int,

    /**
     * Root detection result.
     */
    val isRooted: Boolean,

    /**
     * Emulator detection result.
     */
    val isEmulator: Boolean,

    /**
     * Bootloader state.
     */
    val bootloaderState: BootloaderState,

    /**
     * Play Integrity verification result.
     */
    val playIntegrityStatus: PlayIntegrityStatus,

    /**
     * Last integrity scan timestamp.
     */
    val lastScannedAt: Long,

    /**
     * Integrity findings.
     */
    val findings: List<IntegrityFinding> = emptyList(),

    /**
     * Recommended actions.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Device integrity status.
 */
enum class IntegrityStatus {
    SECURE,
    WARNING,
    COMPROMISED,
    UNKNOWN
}

/**
 * Bootloader states.
 */
enum class BootloaderState {
    LOCKED,
    UNLOCKED,
    UNKNOWN
}

/**
 * Play Integrity verification status.
 */
enum class PlayIntegrityStatus {
    PASSED,
    FAILED,
    NOT_AVAILABLE,
    UNKNOWN
}

/**
 * Individual integrity finding.
 */
data class IntegrityFinding(

    /**
     * Finding title.
     */
    val title: String,

    /**
     * Finding description.
     */
    val description: String,

    /**
     * Severity level.
     */
    val severity: ThreatSeverity,

    /**
     * Whether issue can be remediated.
     */
    val isRemediable: Boolean
)
