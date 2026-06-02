package com.sentrix.core.enums

/**
 * Represents authentication states inside SentriX
 */
enum class AuthenticationState(
    val displayName: String,
    val description: String
) {

    UNAUTHENTICATED(
        displayName = "Unauthenticated",
        description = "User is not authenticated"
    ),

    AUTHENTICATING(
        displayName = "Authenticating",
        description = "Authentication process is in progress"
    ),

    AUTHENTICATED(
        displayName = "Authenticated",
        description = "User successfully authenticated"
    ),

    SESSION_ACTIVE(
        displayName = "Session Active",
        description = "Authenticated session is currently active"
    ),

    SESSION_EXPIRED(
        displayName = "Session Expired",
        description = "Authentication session has expired"
    ),

    TOKEN_REFRESHING(
        displayName = "Token Refreshing",
        description = "Refreshing authentication token securely"
    ),

    BIOMETRIC_REQUIRED(
        displayName = "Biometric Required",
        description = "Biometric verification is required"
    ),

    BIOMETRIC_AUTHENTICATING(
        displayName = "Biometric Authenticating",
        description = "Performing biometric authentication"
    ),

    BIOMETRIC_SUCCESS(
        displayName = "Biometric Success",
        description = "Biometric verification successful"
    ),

    BIOMETRIC_FAILED(
        displayName = "Biometric Failed",
        description = "Biometric verification failed"
    ),

    MFA_REQUIRED(
        displayName = "Multi-Factor Authentication Required",
        description = "Additional verification step required"
    ),

    MFA_VERIFICATION(
        displayName = "MFA Verification",
        description = "Verifying multi-factor authentication code"
    ),

    LOCKED(
        displayName = "Locked",
        description = "Account temporarily locked due to security reasons"
    ),

    ACCESS_DENIED(
        displayName = "Access Denied",
        description = "Authentication failed or insufficient permissions"
    ),

    LOGGED_OUT(
        displayName = "Logged Out",
        description = "User has logged out successfully"
    ),

    ERROR(
        displayName = "Error",
        description = "Unexpected authentication error occurred"
    );

    /**
     * Returns true if user is fully authenticated
     */
    fun isAuthenticated(): Boolean {
        return this == AUTHENTICATED ||
               this == SESSION_ACTIVE ||
               this == BIOMETRIC_SUCCESS
    }

    /**
     * Returns true if authentication is ongoing
     */
    fun isInProgress(): Boolean {
        return this == AUTHENTICATING ||
               this == TOKEN_REFRESHING ||
               this == BIOMETRIC_AUTHENTICATING ||
               this == MFA_VERIFICATION
    }

    /**
     * Returns true if authentication failed
     */
    fun hasFailed(): Boolean {
        return this == BIOMETRIC_FAILED ||
               this == ACCESS_DENIED ||
               this == ERROR ||
               this == LOCKED
    }

    /**
     * Returns true if re-authentication is needed
     */
    fun requiresReauthentication(): Boolean {
        return this == SESSION_EXPIRED ||
               this == MFA_REQUIRED ||
               this == BIOMETRIC_REQUIRED
    }
}
