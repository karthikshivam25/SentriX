package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.DeviceTrustDto
import com.sentrix.data.remote.dto.UserDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend after a successful/failed login attempt.
 *
 * This response contains:
 * - Authentication tokens
 * - User profile information
 * - Device trust information
 * - Session details
 *
 * Example API Endpoint:
 * POST /api/v1/auth/login
 */
@Serializable
data class LoginResponse(

    // Indicates whether the login request was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the server
    // Example:
    // "Login successful"
    // "Invalid credentials"
    @SerialName("message")
    val message: String,

    // JWT access token used for authenticated API requests
    // Usually short-lived
    @SerialName("access_token")
    val accessToken: String? = null,

    // Refresh token used to obtain a new access token
    // when the current one expires
    @SerialName("refresh_token")
    val refreshToken: String? = null,

    // Token expiration time in seconds
    // Example: 3600 = 1 hour
    @SerialName("expires_in")
    val expiresIn: Long = 0L,

    // Type of token returned by the server
    // Example: "Bearer"
    @SerialName("token_type")
    val tokenType: String = "Bearer",

    // Authenticated user information
    @SerialName("user")
    val user: UserDto? = null,

    // Device trust information returned after authentication
    // Helps determine if the device is secure
    @SerialName("device_trust")
    val deviceTrust: DeviceTrustDto? = null,

    // Unique identifier for the current login session
    @SerialName("session_id")
    val sessionId: String? = null,

    // Indicates whether Multi-Factor Authentication is required
    @SerialName("mfa_required")
    val mfaRequired: Boolean = false,

    // Temporary MFA token used for OTP verification
    // Present only when mfaRequired = true
    @SerialName("mfa_token")
    val mfaToken: String? = null,

    // Indicates whether the account email is verified
    @SerialName("email_verified")
    val emailVerified: Boolean = false,

    // Indicates whether the user must change password
    // on next login
    @SerialName("password_reset_required")
    val passwordResetRequired: Boolean = false,

    // Server timestamp when login was processed
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional information returned by the backend
    //
    // Example:
    // "last_login_ip" -> "192.168.1.10"
    // "login_location" -> "Chennai, India"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
