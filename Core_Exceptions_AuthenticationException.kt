package com.sentrix.core.exceptions

/**
 * AuthenticationException
 *
 * Base exception for all authentication,
 * authorization, session, and identity
 * management related failures in SentriX.
 */
open class AuthenticationException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Invalid credentials provided.
 */
class InvalidCredentialsException(
    message: String = "Invalid username or password."
) : AuthenticationException(message)

/**
 * User account not found.
 */
class UserNotFoundException(
    message: String = "User account not found."
) : AuthenticationException(message)

/**
 * User account already exists.
 */
class UserAlreadyExistsException(
    message: String = "User account already exists."
) : AuthenticationException(message)

/**
 * Authentication token missing.
 */
class MissingTokenException(
    message: String = "Authentication token is missing."
) : AuthenticationException(message)

/**
 * Authentication token invalid.
 */
class InvalidTokenException(
    message: String = "Authentication token is invalid."
) : AuthenticationException(message)

/**
 * Authentication token expired.
 */
class TokenExpiredException(
    message: String = "Authentication token has expired."
) : AuthenticationException(message)

/**
 * Refresh token invalid.
 */
class InvalidRefreshTokenException(
    message: String = "Refresh token is invalid."
) : AuthenticationException(message)

/**
 * Session expired.
 */
class SessionExpiredException(
    message: String = "User session has expired."
) : AuthenticationException(message)

/**
 * Session invalid.
 */
class InvalidSessionException(
    message: String = "Invalid session detected."
) : AuthenticationException(message)

/**
 * User account locked.
 */
class AccountLockedException(
    message: String = "Account has been locked."
) : AuthenticationException(message)

/**
 * User account disabled.
 */
class AccountDisabledException(
    message: String = "Account has been disabled."
) : AuthenticationException(message)

/**
 * User account suspended.
 */
class AccountSuspendedException(
    message: String = "Account has been suspended."
) : AuthenticationException(message)

/**
 * Password validation failure.
 */
class WeakPasswordException(
    message: String =
        "Password does not meet security requirements."
) : AuthenticationException(message)

/**
 * Password expired.
 */
class PasswordExpiredException(
    message: String = "Password has expired."
) : AuthenticationException(message)

/**
 * Password reset failure.
 */
class PasswordResetException(
    message: String = "Password reset failed."
) : AuthenticationException(message)

/**
 * Multi-factor authentication required.
 */
class MFARequiredException(
    message: String =
        "Multi-factor authentication is required."
) : AuthenticationException(message)

/**
 * Multi-factor authentication failed.
 */
class MFAFailedException(
    message: String =
        "Multi-factor authentication failed."
) : AuthenticationException(message)

/**
 * Biometric authentication failed.
 */
class BiometricAuthenticationException(
    message: String =
        "Biometric authentication failed."
) : AuthenticationException(message)

/**
 * Email verification required.
 */
class EmailVerificationRequiredException(
    message: String =
        "Email verification is required."
) : AuthenticationException(message)

/**
 * Phone verification required.
 */
class PhoneVerificationRequiredException(
    message: String =
        "Phone verification is required."
) : AuthenticationException(message)

/**
 * Authorization failure.
 */
class AuthorizationException(
    message: String =
        "You do not have permission to perform this action."
) : AuthenticationException(message)

/**
 * Role validation failure.
 */
class InsufficientRoleException(
    message: String =
        "User role is insufficient for this operation."
) : AuthenticationException(message)

/**
 * Access denied.
 */
class AccessDeniedException(
    message: String = "Access denied."
) : AuthenticationException(message)

/**
 * Login attempt limit exceeded.
 */
class TooManyLoginAttemptsException(
    message: String =
        "Too many login attempts. Please try again later."
) : AuthenticationException(message)

/**
 * Device trust verification failed.
 */
class UntrustedDeviceException(
    message: String =
        "This device is not trusted."
) : AuthenticationException(message)

/**
 * Security challenge required.
 */
class SecurityChallengeException(
    message: String =
        "Additional security verification required."
) : AuthenticationException(message)

/**
 * Identity provider failure.
 */
class IdentityProviderException(
    message: String =
        "Identity provider authentication failed.",
    cause: Throwable? = null
) : AuthenticationException(message, cause)

/**
 * OAuth authentication failure.
 */
class OAuthException(
    message: String =
        "OAuth authentication failed.",
    cause: Throwable? = null
) : AuthenticationException(message, cause)

/**
 * SSO authentication failure.
 */
class SingleSignOnException(
    message: String =
        "Single Sign-On authentication failed.",
    cause: Throwable? = null
) : AuthenticationException(message, cause)
