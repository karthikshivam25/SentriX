package com.sentrix.data.remote.dto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * DTO representing a historical record of a detected threat.
 *
 * This object is received from the backend and is used to
 * display threat timelines, reports, analytics, and history screens.
 */
@Serializable
data class ThreatHistoryDto(

    // Unique identifier for this threat history record
    @SerialName("history_id")
    val historyId: String,

    // Unique identifier of the threat
    @SerialName("threat_id")
    val threatId: String,

    // Name of the detected threat
    // Example: "Banking Trojan", "Phishing Website"
    @SerialName("threat_name")
    val threatName: String,

    // Category of the threat
    // Example: MALWARE, PHISHING, SPYWARE, RANSOMWARE
    @SerialName("threat_type")
    val threatType: String,

    // Severity level assigned by SentriX
    // Example: LOW, MEDIUM, HIGH, CRITICAL
    @SerialName("severity")
    val severity: String,

    // Current status of the threat
    // Example: ACTIVE, QUARANTINED, REMOVED, IGNORED
    @SerialName("status")
    val status: String,

    // Package name if the threat originated from an app
    // Example: "com.fake.bank.app"
    @SerialName("package_name")
    val packageName: String? = null,

    // File path if the threat was found in a file
    @SerialName("file_path")
    val filePath: String? = null,

    // URL associated with the threat
    // Example: phishing or scam websites
    @SerialName("source_url")
    val sourceUrl: String? = null,

    // Detailed explanation of the threat
    @SerialName("description")
    val description: String = "",

    // Recommended action for the user
    // Example: "Uninstall immediately"
    @SerialName("recommended_action")
    val recommendedAction: String = "",

    // Risk score assigned by the AI engine
    // Range: 0 - 100
    @SerialName("risk_score")
    val riskScore: Int = 0,

    // Timestamp when the threat was first detected
    @SerialName("detected_at")
    val detectedAt: Long,

    // Timestamp when the threat was resolved
    // Null if still active
    @SerialName("resolved_at")
    val resolvedAt: Long? = null,

    // User action taken against the threat
    // Example: REMOVED, QUARANTINED, ALLOWED, IGNORED
    @SerialName("user_action")
    val userAction: String? = null,

    // Indicates whether the threat is currently active
    @SerialName("is_active")
    val isActive: Boolean = true,

    // Indicates whether this threat was automatically mitigated
    @SerialName("auto_mitigated")
    val autoMitigated: Boolean = false,

    // Threat source
    // Example: LOCAL_SCAN, CLOUD_ANALYSIS, REALTIME_MONITOR
    @SerialName("detection_source")
    val detectionSource: String = "",

    // Version of the threat intelligence database used
    @SerialName("signature_version")
    val signatureVersion: String = "",

    // Additional threat-related information
    // Example:
    // "country" -> "Unknown"
    // "confidence" -> "95%"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
