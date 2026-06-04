package com.sentrix.core.exceptions

/**
 * RootDetectedException
 *
 * Base exception for root detection,
 * device integrity violations,
 * privilege escalation attempts,
 * and security posture failures.
 *
 * Used by:
 * - RootDetectionHelper
 * - SecurityManager
 * - DeviceManager
 * - MalwareManager
 * - AppLockManager
 * - Real-Time Protection Engine
 */
open class RootDetectedException : SecurityException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Root access detected.
 */
class DeviceRootedException(
    message: String = "Root access detected on device."
) : RootDetectedException(message)

/**
 * Superuser binary detected.
 */
class SuperuserBinaryDetectedException(
    message: String = "Superuser binary detected."
) : RootDetectedException(message)

/**
 * Magisk detected.
 */
class MagiskDetectedException(
    message: String = "Magisk framework detected."
) : RootDetectedException(message)

/**
 * Xposed Framework detected.
 */
class XposedDetectedException(
    message: String = "Xposed Framework detected."
) : RootDetectedException(message)

/**
 * BusyBox detected.
 */
class BusyBoxDetectedException(
    message: String = "BusyBox installation detected."
) : RootDetectedException(message)

/**
 * Dangerous system modification detected.
 */
class SystemModificationException(
    message: String = "Unauthorized system modification detected."
) : RootDetectedException(message)

/**
 * SELinux disabled or compromised.
 */
class SELinuxCompromisedException(
    message: String = "SELinux protection compromised."
) : RootDetectedException(message)

/**
 * System partition writable.
 */
class WritableSystemPartitionException(
    message: String = "System partition is writable."
) : RootDetectedException(message)

/**
 * Privilege escalation attempt detected.
 */
class PrivilegeEscalationException(
    message: String = "Privilege escalation attempt detected."
) : RootDetectedException(message)

/**
 * Suspicious root management application found.
 */
class RootManagementAppException(
    message: String = "Root management application detected."
) : RootDetectedException(message)

/**
 * SafetyNet validation failure.
 */
class SafetyNetValidationException(
    message: String = "SafetyNet integrity validation failed."
) : RootDetectedException(message)

/**
 * Play Integrity validation failure.
 */
class PlayIntegrityException(
    message: String = "Google Play Integrity validation failed."
) : RootDetectedException(message)

/**
 * Device integrity compromised.
 */
class DeviceIntegrityException(
    message: String = "Device integrity compromised."
) : RootDetectedException(message)

/**
 * Bootloader unlocked.
 */
class UnlockedBootloaderException(
    message: String = "Bootloader is unlocked."
) : RootDetectedException(message)

/**
 * Custom ROM detected.
 */
class CustomRomDetectedException(
    message: String = "Custom ROM detected."
) : RootDetectedException(message)

/**
 * Debuggable system detected.
 */
class DebuggableSystemException(
    message: String = "Debuggable system environment detected."
) : RootDetectedException(message)

/**
 * Runtime hooking framework detected.
 */
class RuntimeHookingException(
    message: String = "Runtime hooking framework detected."
) : RootDetectedException(message)

/**
 * Frida instrumentation detected.
 */
class FridaDetectedException(
    message: String = "Frida instrumentation detected."
) : RootDetectedException(message)

/**
 * Tampering attempt detected.
 */
class AppTamperingException(
    message: String = "Application tampering detected."
) : RootDetectedException(message)

/**
 * Security policy violation caused by root.
 */
class RootSecurityPolicyException(
    message: String =
        "Security policy violation due to rooted device."
) : RootDetectedException(message)

/**
 * Critical integrity violation.
 */
class CriticalIntegrityException(
    message: String =
        "Critical device integrity violation detected."
) : RootDetectedException(message)
