package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used when a new user creates a SentriX account.
 *
 * This object is sent from the mobile application to the backend
 * during the registration/signup process.
 *
 * Example API Endpoint:
 * POST /api/v1/auth/register
 */
@Serializable
data class RegisterRequest(

    // User's full name
    // Example: "John Doe"
    @SerialName("full_name")
    val fullName: String,

    // User's email address
    // Must be unique within the system
    @SerialName("email")
    val email: String,

    // User's chosen password
    //
    // Password policy recommendation:
    // - Minimum 8 characters
    // - At least one uppercase letter
    // - At least one lowercase letter
    // - At least one digit
    // - At least one special character
    //
    // Never store raw passwords on the backend.
    @SerialName("password")
    val password: String,

    // Optional password confirmation
    // Used to validate that the user entered the same password twice
    @SerialName("confirm_password")
    val confirmPassword: String,

    // Unique device identifier
    // Helps SentriX establish device trust during registration
    @SerialName("device_id")
    val deviceId: String,

    // Human-readable device name
    // Example: "Google Pixel 9 Pro"
    @SerialName("device_name")
    val deviceName: String,

    // Device manufacturer
    // Example: Samsung, Xiaomi, OnePlus
    @SerialName("device_manufacturer")
    val deviceManufacturer: String,

    // Device model
    // Example: "SM-S928B"
    @SerialName("device_model")
    val deviceModel: String,

    // Operating system version
    // Example: "Android 15"
    @SerialName("os_version")
    val osVersion: String,

    // Currently installed application version
    @SerialName("app_version")
    val appVersion: String,

    // Country selected by the user
    // Example: "India"
    @SerialName("country")
    val country: String,

    // User's preferred language
    // Example: "en", "en-US"
    @SerialName("preferred_language")
    val preferredLanguage: String = "en",

    // Firebase Cloud Messaging token
    // Used for push notifications and security alerts
    @SerialName("fcm_token")
    val fcmToken: String? = null,

    // Indicates whether the user accepted Terms and Conditions
    // Registration should not proceed unless true
    @SerialName("accepted_terms")
    val acceptedTerms: Boolean,

    // Indicates whether the user accepted the Privacy Policy
    @SerialName("accepted_privacy_policy")
    val acceptedPrivacyPolicy: Boolean,

    // Whether the user has opted in to marketing emails
    @SerialName("marketing_opt_in")
    val marketingOptIn: Boolean = false
)
