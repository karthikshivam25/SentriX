package com.sentrix.data.remote.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Request DTO used to send analytics events and telemetry data
 * from the SentriX application to the backend.
 *
 * Analytics data helps SentriX:
 * - Understand feature usage
 * - Improve threat detection models
 * - Monitor application performance
 * - Generate security insights
 * - Analyze user engagement trends
 *
 * Example API Endpoint:
 * POST /api/v1/analytics/events
 */
@Serializable
data class AnalyticsRequest(

    // Unique identifier of the analytics event
    @SerialName("event_id")
    val eventId: String,

    // Unique identifier of the user
    @SerialName("user_id")
    val userId: String,

    // Unique identifier of the device
    @SerialName("device_id")
    val deviceId: String,

    // Name of the event being tracked
    //
    // Examples:
    // APP_OPENED
    // SCAN_STARTED
    // THREAT_DETECTED
    // VPN_CONNECTED
    // PERMISSION_REVOKED
    @SerialName("event_name")
    val eventName: String,

    // Category to which the event belongs
    //
    // Examples:
    // SECURITY
    // SCAN
    // VPN
    // AUTH
    // PERFORMANCE
    @SerialName("event_category")
    val eventCategory: String,

    // Optional action associated with the event
    //
    // Examples:
    // CLICKED
    // STARTED
    // COMPLETED
    // FAILED
    @SerialName("event_action")
    val eventAction: String? = null,

    // Optional label for additional event context
    //
    // Example:
    // "Full Scan"
    // "Mumbai VPN Server"
    @SerialName("event_label")
    val eventLabel: String? = null,

    // Numeric value associated with the event
    //
    // Example:
    // Scan duration in seconds
    // Threat count
    @SerialName("event_value")
    val eventValue: Long? = null,

    // Severity level for security-related events
    //
    // Examples:
    // INFO, LOW, MEDIUM, HIGH, CRITICAL
    @SerialName("severity")
    val severity: String = "INFO",

    // Current application version
    @SerialName("app_version")
    val appVersion: String,

    // Current operating system version
    @SerialName("os_version")
    val osVersion: String,

    // Device manufacturer
    @SerialName("device_manufacturer")
    val deviceManufacturer: String,

    // Device model
    @SerialName("device_model")
    val deviceModel: String,

    // Network type when the event occurred
    //
    // Examples:
    // WIFI, MOBILE_DATA, ETHERNET, OFFLINE
    @SerialName("network_type")
    val networkType: String = "UNKNOWN",

    // Indicates whether the device was online
    @SerialName("is_online")
    val isOnline: Boolean = true,

    // Timestamp when the event occurred
    @SerialName("timestamp")
    val timestamp: Long = System.currentTimeMillis(),

    // Additional event-specific information
    //
    // Example:
    // "scan_type" -> "FULL"
    // "threat_count" -> "5"
    // "vpn_server" -> "India-Mumbai"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
