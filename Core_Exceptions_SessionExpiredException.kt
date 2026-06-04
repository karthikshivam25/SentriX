package com.sentrix.core.exceptions

/**
 * SessionExpiredException
 *
 * Base exception for all session-related
 * failures within the SentriX platform.
 *
 * Used by:
 * - SessionManager
 * - AuthenticationManager
 * - API Layer
 * - SecurityManager
 * - AppLockManager
 * - Cloud Sync Services
 */
open class SessionExpiredException : AuthenticationException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * User session expired.
 */
class UserSessionExpiredException(
    message: String = "User session has expired."
) : SessionExpiredException(message)

/**
 * Session timeout reached.
 */
class SessionTimeoutException(
    message: String = "Session timeout exceeded."
) : SessionExpiredException(message)

/**
 * Invalid session token.
 */
class InvalidSessionTokenException(
    message: String = "Invalid session token."
) : SessionExpiredException(message)

/**
 * Missing session token.
 */
class MissingSessionTokenException(
    message: String = "Session token is missing."
) : SessionExpiredException(message)

/**
 * Session revoked remotely.
 */
class SessionRevokedException(
    message: String = "Session has been revoked."
) : SessionExpiredException(message)

/**
 * Session terminated by security policy.
 */
class SessionTerminatedException(
    message: String = "Session terminated by security policy."
) : SessionExpiredException(message)

/**
 * Concurrent login detected.
 */
class ConcurrentSessionException(
    message: String =
        "Another active session was detected."
) : SessionExpiredException(message)

/**
 * Device mismatch detected.
 */
class SessionDeviceMismatchException(
    message: String =
        "Session device verification failed."
) : SessionExpiredException(message)

/**
 * IP address mismatch detected.
 */
class SessionIPMismatchException(
    message: String =
        "Session IP verification failed."
) : SessionExpiredException(message)

/**
 * Session integrity validation failed.
 */
class SessionIntegrityException(
    message: String =
        "Session integrity validation failed."
) : SessionExpiredException(message)

/**
 * Refresh token expired.
 */
class RefreshTokenExpiredException(
    message: String =
        "Refresh token has expired."
) : SessionExpiredException(message)

/**
 * Refresh token invalid.
 */
class RefreshTokenInvalidException(
    message: String =
        "Refresh token is invalid."
) : SessionExpiredException(message)

/**
 * Authentication state lost.
 */
class AuthenticationStateException(
    message: String =
        "Authentication state is no longer valid."
) : SessionExpiredException(message)

/**
 * Session encryption validation failed.
 */
class SessionEncryptionException(
    message: String =
        "Session encryption validation failed."
) : SessionExpiredException(message)

/**
 * Security re-authentication required.
 */
class ReAuthenticationRequiredException(
    message: String =
        "Re-authentication is required."
) : SessionExpiredException(message)

/**
 * Biometric re-authentication required.
 */
class BiometricReAuthenticationException(
    message: String =
        "Biometric re-authentication required."
) : SessionExpiredException(message)

/**
 * Session suspended.
 */
class SessionSuspendedException(
    message: String =
        "Session has been temporarily suspended."
) : SessionExpiredException(message)

/**
 * Critical session security violation.
 */
class SessionSecurityViolationException(
    message: String =
        "Critical session security violation detected."
) : SessionExpiredException(message)
