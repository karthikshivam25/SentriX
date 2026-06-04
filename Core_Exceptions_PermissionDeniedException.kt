package com.sentrix.core.exceptions

/**
 * PermissionDeniedException
 *
 * Base exception for all permission-related
 * failures within the SentriX platform.
 *
 * Used for:
 * - Android runtime permissions
 * - Security permissions
 * - Storage access
 * - Camera/Microphone access
 * - Location access
 * - Usage stats access
 * - Accessibility permissions
 * - VPN permissions
 */
open class PermissionDeniedException : SecurityException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic permission denial.
 */
class PermissionRequiredException(
    message: String = "Required permission not granted."
) : PermissionDeniedException(message)

/**
 * Camera permission denied.
 */
class CameraPermissionException(
    message: String = "Camera permission denied."
) : PermissionDeniedException(message)

/**
 * Microphone permission denied.
 */
class MicrophonePermissionException(
    message: String = "Microphone permission denied."
) : PermissionDeniedException(message)

/**
 * Location permission denied.
 */
class LocationPermissionException(
    message: String = "Location permission denied."
) : PermissionDeniedException(message)

/**
 * Background location permission denied.
 */
class BackgroundLocationPermissionException(
    message: String = "Background location permission denied."
) : PermissionDeniedException(message)

/**
 * Storage permission denied.
 */
class StoragePermissionException(
    message: String = "Storage permission denied."
) : PermissionDeniedException(message)

/**
 * External storage permission denied.
 */
class ExternalStoragePermissionException(
    message: String = "External storage access denied."
) : PermissionDeniedException(message)

/**
 * Notification permission denied.
 */
class NotificationPermissionException(
    message: String = "Notification permission denied."
) : PermissionDeniedException(message)

/**
 * Contacts permission denied.
 */
class ContactsPermissionException(
    message: String = "Contacts permission denied."
) : PermissionDeniedException(message)

/**
 * SMS permission denied.
 */
class SMSPermissionException(
    message: String = "SMS permission denied."
) : PermissionDeniedException(message)

/**
 * Phone permission denied.
 */
class PhonePermissionException(
    message: String = "Phone permission denied."
) : PermissionDeniedException(message)

/**
 * Bluetooth permission denied.
 */
class BluetoothPermissionException(
    message: String = "Bluetooth permission denied."
) : PermissionDeniedException(message)

/**
 * Nearby devices permission denied.
 */
class NearbyDevicesPermissionException(
    message: String = "Nearby devices permission denied."
) : PermissionDeniedException(message)

/**
 * Usage stats permission denied.
 */
class UsageStatsPermissionException(
    message: String = "Usage statistics permission denied."
) : PermissionDeniedException(message)

/**
 * Accessibility permission denied.
 */
class AccessibilityPermissionException(
    message: String = "Accessibility permission denied."
) : PermissionDeniedException(message)

/**
 * Overlay permission denied.
 */
class OverlayPermissionException(
    message: String = "Draw-over-apps permission denied."
) : PermissionDeniedException(message)

/**
 * VPN permission denied.
 */
class VPNPermissionException(
    message: String = "VPN permission denied."
) : PermissionDeniedException(message)

/**
 * Biometric permission unavailable.
 */
class BiometricPermissionException(
    message: String = "Biometric authentication unavailable."
) : PermissionDeniedException(message)

/**
 * Package usage permission denied.
 */
class PackageUsagePermissionException(
    message: String = "Package usage access denied."
) : PermissionDeniedException(message)

/**
 * Network permission denied.
 */
class NetworkPermissionException(
    message: String = "Network access denied."
) : PermissionDeniedException(message)

/**
 * File access permission denied.
 */
class FileAccessPermissionException(
    message: String = "File access denied."
) : PermissionDeniedException(message)

/**
 * Scan permission denied.
 */
class ScanPermissionException(
    message: String = "Scan operation permission denied."
) : PermissionDeniedException(message)

/**
 * Security-sensitive permission denied.
 */
class CriticalPermissionException(
    message: String =
        "Critical security permission denied."
) : PermissionDeniedException(message)

/**
 * Multiple permissions denied.
 */
class MultiplePermissionsDeniedException(
    val deniedPermissions: List<String>
) : PermissionDeniedException(
    "Multiple permissions denied: ${
        deniedPermissions.joinToString(", ")
    }"
)

/**
 * Permission permanently denied
 * (Don't Ask Again selected).
 */
class PermanentlyDeniedPermissionException(
    permission: String
) : PermissionDeniedException(
    "$permission permission permanently denied."
)
