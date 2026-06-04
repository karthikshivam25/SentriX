package com.sentrix.core.exceptions

/**
 * SecurityException
 *
 * Base exception for all SentriX security-related failures.
 */
open class SecurityException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Thrown when malware is detected.
 */
class MalwareDetectedException(
    message: String = "Malware detected on device."
) : SecurityException(message)

/**
 * Thrown when a threat reaches a critical level.
 */
class CriticalThreatException(
    message: String = "Critical threat detected."
) : SecurityException(message)

/**
 * Thrown when an authentication operation fails.
 */
class AuthenticationException(
    message: String = "Authentication failed."
) : SecurityException(message)

/**
 * Thrown when a user session is invalid.
 */
class SessionExpiredException(
    message: String = "User session has expired."
) : SecurityException(message)

/**
 * Thrown when encryption fails.
 */
class EncryptionException(
    message: String = "Encryption operation failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when decryption fails.
 */
class DecryptionException(
    message: String = "Decryption operation failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when a network security issue occurs.
 */
class NetworkSecurityException(
    message: String = "Network security violation detected."
) : SecurityException(message)

/**
 * Thrown when VPN protection is unavailable.
 */
class VPNException(
    message: String = "VPN service unavailable."
) : SecurityException(message)

/**
 * Thrown when firewall enforcement fails.
 */
class FirewallException(
    message: String = "Firewall operation failed."
) : SecurityException(message)

/**
 * Thrown when an unauthorized app access attempt occurs.
 */
class AppLockException(
    message: String = "Application access denied."
) : SecurityException(message)

/**
 * Thrown when a permission-related issue occurs.
 */
class PermissionDeniedException(
    message: String = "Required permission denied."
) : SecurityException(message)

/**
 * Thrown when a scan operation fails.
 */
class ScanException(
    message: String = "Scan operation failed."
) : SecurityException(message)

/**
 * Thrown when a malware scan engine encounters an error.
 */
class MalwareScanException(
    message: String = "Malware scan failed."
) : SecurityException(message)

/**
 * Thrown when threat analysis fails.
 */
class ThreatAnalysisException(
    message: String = "Threat analysis failed."
) : SecurityException(message)

/**
 * Thrown when AI security analysis fails.
 */
class AIAnalysisException(
    message: String = "AI security analysis failed."
) : SecurityException(message)

/**
 * Thrown when cache operations fail.
 */
class CacheException(
    message: String = "Cache operation failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when preferences operations fail.
 */
class PreferencesException(
    message: String = "Preferences operation failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when update checking fails.
 */
class UpdateException(
    message: String = "Update check failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when logging operations fail.
 */
class LoggingException(
    message: String = "Logging operation failed.",
    cause: Throwable? = null
) : SecurityException(message, cause)

/**
 * Thrown when device integrity is compromised.
 */
class DeviceIntegrityException(
    message: String = "Device integrity check failed."
) : SecurityException(message)

/**
 * Thrown when root access is detected.
 */
class RootDetectedException(
    message: String = "Rooted device detected."
) : SecurityException(message)

/**
 * Thrown when emulator usage is detected.
 */
class EmulatorDetectedException(
    message: String = "Emulator environment detected."
) : SecurityException(message)

/**
 * Thrown when an operation is blocked by security policy.
 */
class SecurityPolicyViolationException(
    message: String = "Security policy violation."
) : SecurityException(message)

/**
 * Thrown when a file is considered unsafe.
 */
class UnsafeFileException(
    message: String = "Unsafe file detected."
) : SecurityException(message)

/**
 * Thrown when a URL is considered malicious.
 */
class MaliciousURLException(
    message: String = "Malicious URL detected."
) : SecurityException(message)
