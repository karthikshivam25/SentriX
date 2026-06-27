package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used when a user attempts to sign in to SentriX.
 *
 * This object is sent from the app to the backend authentication API.
 *
 * Example API Request:
 * POST /api/v1/auth/login
 */
@Serializable
data class LoginRequest(

    // User email address used for authentication
    // Example: "john.doe@example.com"
    @SerialName("email")
    val email: String,

    // User account password
    // NOTE:
    // - Always send over HTTPS/TLS.
    // - Never log passwords in production.
    // - Consider encrypting or hashing on the backend.
    @SerialName("password")
    val password: String,

    // Unique identifier of the device attempting login
    // Used for session management and device trust analysis
    @SerialName("device_id")
    val deviceId: String,

    // Human-readable device name
    // Example: "Samsung Galaxy S24"
    @SerialName("device_name")
    val deviceName: String,

    // Device operating system version
    // Example: "Android 15"
    @SerialName("os_version")
    val osVersion: String,

    // Application version currently installed
    // Example: "1.0.0"
    @SerialName("app_version")
    val appVersion: String,

    // Optional push notification token (FCM token)
    // Used for security alerts and notifications
    @SerialName("fcm_token")
    val fcmToken: String? = null,

    // Indicates whether the user wants to stay logged in
    @SerialName("remember_me")
    val rememberMe: Boolean = false
)
