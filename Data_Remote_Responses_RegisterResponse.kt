package com.sentrix.data.remote.responses

import com.sentrix.data.remote.dto.UserDto
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Response DTO returned by the backend after a user registration attempt.
 *
 * This response contains:
 * - Registration status
 * - Newly created user information
 * - Verification requirements
 * - Authentication tokens (optional)
 *
 * Example API Endpoint:
 * POST /api/v1/auth/register
 */
@Serializable
data class RegisterResponse(

    // Indicates whether registration was successful
    @SerialName("success")
    val success: Boolean,

    // Human-readable message returned by the server
    //
    // Examples:
    // "Account created successfully"
    // "Email already exists"
    @SerialName("message")
    val message: String,

    // Information about the newly registered user
    @SerialName("user")
    val user: UserDto? = null,

    // JWT access token returned after registration
    // Some systems automatically log users in after signup
    @SerialName("access_token")
    val accessToken: String? = null,

    // Refresh token for renewing authentication sessions
    @SerialName("refresh_token")
    val refreshToken: String? = null,

    // Token expiration time in seconds
    // Example: 3600 = 1 hour
    @SerialName("expires_in")
    val expiresIn: Long = 0L,

    // Authentication token type
    // Usually "Bearer"
    @SerialName("token_type")
    val tokenType: String = "Bearer",

    // Indicates whether email verification is required
    @SerialName("email_verification_required")
    val emailVerificationRequired: Boolean = true,

    // Indicates whether the user's email has already been verified
    @SerialName("email_verified")
    val emailVerified: Boolean = false,

    // Verification token sent by backend
    // Used for OTP/email verification flows
    @SerialName("verification_token")
    val verificationToken: String? = null,

    // Indicates whether MFA setup is recommended or required
    @SerialName("mfa_setup_required")
    val mfaSetupRequired: Boolean = false,

    // Unique session identifier created during registration
    @SerialName("session_id")
    val sessionId: String? = null,

    // Timestamp when registration was processed by the server
    @SerialName("server_timestamp")
    val serverTimestamp: Long = System.currentTimeMillis(),

    // Additional information returned by the backend
    //
    // Example:
    // "verification_method" -> "EMAIL"
    // "welcome_bonus" -> "PREMIUM_TRIAL"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
