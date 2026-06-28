package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used to submit device trust information to the backend.
 *
 * SentriX periodically sends this information to:
 * - Evaluate device integrity
 * - Detect rooted or compromised devices
 * - Enforce security policies
 * - Calculate device trust scores
 *
 * Example API Endpoint:
 * POST /api/v1/device/trust
 */
@Serializable
data class DeviceTrustRequest(

    // Unique identifier of the user
    @SerialName("user_id")
    val userId: String,

    // Unique identifier of the device
    @SerialName("device_id")
    val deviceId: String,

    // Device manufacturer
    // Example: Samsung, Xiaomi, Google
    @SerialName("manufacturer")
    val manufacturer: String,

    // Device model
    // Example: "Galaxy S24 Ultra"
    @SerialName("model")
    val model: String,

    // Device brand
    // Example: Samsung, Pixel, OnePlus
    @SerialName("brand")
    val brand: String,

    // Android OS version
    // Example: Android 15
    @SerialName("os_version")
    val osVersion: String,

    // Android SDK version
    // Example: 35
    @SerialName("sdk_version")
    val sdkVersion: Int,

    // Indicates whether the device is rooted
    @SerialName("is_rooted")
    val isRooted: Boolean = false,

    // Indicates whether USB debugging is enabled
    @SerialName("usb_debugging_enabled")
    val usbDebuggingEnabled: Boolean = false,

    // Indicates whether Developer Options are enabled
    @SerialName("developer_options_enabled")
    val developerOptionsEnabled: Boolean = false,

    // Indicates whether the bootloader is unlocked
    @SerialName("bootloader_unlocked")
    val bootloaderUnlocked: Boolean = false,

    // Indicates whether a custom ROM is installed
    @SerialName("custom_rom_detected")
    val customRomDetected: Boolean = false,

    // Indicates whether Google Play Protect is enabled
    @SerialName("play_protect_enabled")
    val playProtectEnabled: Boolean = true,

    // Indicates whether screen lock security is enabled
    @SerialName("screen_lock_enabled")
    val screenLockEnabled: Boolean = true,

    // Indicates whether biometric authentication is configured
    @SerialName("biometric_enabled")
    val biometricEnabled: Boolean = false,

    // Indicates whether device encryption is enabled
    @SerialName("device_encrypted")
    val deviceEncrypted: Boolean = true,

    // Indicates whether SafetyNet/Play Integrity passed
    @SerialName("integrity_check_passed")
    val integrityCheckPassed: Boolean = true,

    // Security patch level installed on the device
    // Example: "2026-06-05"
    @SerialName("security_patch_level")
    val securityPatchLevel: String,

    // Current application version
    @SerialName("app_version")
    val appVersion: String,

    // Timestamp when this trust information was collected
    @SerialName("collected_at")
    val collectedAt: Long = System.currentTimeMillis(),

    // Additional information collected by SentriX
    //
    // Example:
    // "verified_boot_state" -> "GREEN"
    // "selinux_status" -> "ENFORCING"
    // "play_integrity_verdict" -> "MEETS_DEVICE_INTEGRITY"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
