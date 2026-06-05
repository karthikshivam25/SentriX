package com.sentrix.domain.models

/**
 * UserSession
 *
 * Represents an authenticated user session
 * within the SentriX platform.
 *
 * The session contains authentication details,
 * device information, security attributes,
 * session lifecycle information, and activity
 * tracking data used for access management and
 * threat detection.
 *
 * Used by:
 * - AuthenticationManager
 * - SessionManager
 * - SecurityMiddleware
 * - AccessControlService
 * - UserActivityTracker
 * - ThreatDetectionEngine
 * - AuditLoggingService
 * - TokenRefreshManager
 */
data class UserSession(

    /**
     * Unique session identifier.
     */
    val sessionId: String,

    /**
     * Unique user identifier.
     */
    val userId: String,

    /**
     * User email address.
     */
    val email: String,

    /**
     * Display name of the user.
     */
    val username: String,

    /**
     * Authentication access token.
     */
    val accessToken: String,

    /**
     * Refresh token used to
     * renew expired sessions.
     */
    val refreshToken: String? = null,

    /**
     * Session creation timestamp.
     */
    val createdAt: Long,

    /**
     * Session expiration timestamp.
     */
    val expiresAt: Long,

    /**
     * Last activity timestamp.
     */
    val lastActivityAt: Long,

    /**
     * Indicates whether the
     * session is currently active.
     */
    val isActive: Boolean = true,

    /**
     * Indicates whether the user
     * successfully completed MFA.
     */
    val isMultiFactorAuthenticated: Boolean = false,

    /**
     * Indicates whether the session
     * is trusted.
     */
    val isTrustedSession: Boolean = false,

    /**
     * Device information associated
     * with the session.
     */
    val deviceInfo: SessionDeviceInfo? = null,

    /**
     * IP address used during login.
     */
    val ipAddress: String? = null,

    /**
     * Geographic location associated
     * with the session.
     */
    val location: String? = null,

    /**
     * Authentication provider used.
     */
    val authProvider: AuthenticationProvider =
        AuthenticationProvider.LOCAL,

    /**
     * Current session risk level.
     */
    val riskLevel: SessionRiskLevel =
        SessionRiskLevel.LOW,

    /**
     * User roles assigned during
     * this session.
     */
    val roles: List<String> = emptyList(),

    /**
     * User permissions granted
     * within this session.
     */
    val permissions: List<String> = emptyList(),

    /**
     * Additional session metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * SessionDeviceInfo
 *
 * Represents device information
 * associated with an authenticated
 * user session.
 */
data class SessionDeviceInfo(

    /**
     * Unique device identifier.
     */
    val deviceId: String,

    /**
     * Device manufacturer.
     */
    val manufacturer: String,

    /**
     * Device model.
     */
    val model: String,

    /**
     * Operating system name.
     */
    val operatingSystem: String,

    /**
     * Operating system version.
     */
    val operatingSystemVersion: String,

    /**
     * Application version.
     */
    val appVersion: String
)

/**
 * Authentication provider types.
 */
enum class AuthenticationProvider {

    /**
     * Local authentication.
     */
    LOCAL,

    /**
     * Google authentication.
     */
    GOOGLE,

    /**
     * Microsoft authentication.
     */
    MICROSOFT,

    /**
     * Apple authentication.
     */
    APPLE,

    /**
     * GitHub authentication.
     */
    GITHUB,

    /**
     * Enterprise SSO authentication.
     */
    SSO
}

/**
 * Session risk indicators.
 */
enum class SessionRiskLevel {

    /**
     * Low-risk session.
     */
    LOW,

    /**
     * Moderate-risk session.
     */
    MEDIUM,

    /**
     * High-risk session.
     */
    HIGH,

    /**
     * Critical-risk session requiring
     * immediate action.
     */
    CRITICAL
}
