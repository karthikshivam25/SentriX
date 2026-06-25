package com.sentrix.data.remote.dto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * DTO representing overall security metrics collected from the device
 * and/or returned by the SentriX backend.
 *
 * These metrics are mainly used for:
 * - Dashboard statistics
 * - Analytics screens
 * - Security trend analysis
 * - Risk assessment
 * - Weekly/Monthly reports
 */
@Serializable
data class SecurityMetricsDto(

    // Unique identifier for this metrics record
    @SerialName("metrics_id")
    val metricsId: String,

    // Time at which these metrics were generated
    // Stored as Epoch milliseconds
    @SerialName("generated_at")
    val generatedAt: Long,

    // Overall device security score
    // Range: 0 - 100
    // Higher score = More secure device
    @SerialName("security_score")
    val securityScore: Int = 100,

    // Overall device risk score
    // Range: 0 - 100
    // Higher score = Higher risk
    @SerialName("risk_score")
    val riskScore: Int = 0,

    // Number of threats currently active on the device
    @SerialName("active_threat_count")
    val activeThreatCount: Int = 0,

    // Total threats detected since installation
    @SerialName("total_threat_count")
    val totalThreatCount: Int = 0,

    // Number of critical threats detected
    @SerialName("critical_threat_count")
    val criticalThreatCount: Int = 0,

    // Number of high severity threats detected
    @SerialName("high_threat_count")
    val highThreatCount: Int = 0,

    // Number of medium severity threats detected
    @SerialName("medium_threat_count")
    val mediumThreatCount: Int = 0,

    // Number of low severity threats detected
    @SerialName("low_threat_count")
    val lowThreatCount: Int = 0,

    // Number of threats successfully blocked
    @SerialName("blocked_threat_count")
    val blockedThreatCount: Int = 0,

    // Number of phishing attempts blocked
    @SerialName("blocked_phishing_count")
    val blockedPhishingCount: Int = 0,

    // Number of malicious URLs blocked
    @SerialName("blocked_url_count")
    val blockedUrlCount: Int = 0,

    // Number of malicious applications detected
    @SerialName("malicious_app_count")
    val maliciousAppCount: Int = 0,

    // Number of suspicious files detected
    @SerialName("suspicious_file_count")
    val suspiciousFileCount: Int = 0,

    // Number of scam SMS messages detected
    @SerialName("scam_sms_count")
    val scamSmsCount: Int = 0,

    // Number of privacy issues found on the device
    @SerialName("privacy_issue_count")
    val privacyIssueCount: Int = 0,

    // Number of installed applications analyzed
    @SerialName("apps_scanned")
    val appsScanned: Int = 0,

    // Number of files scanned
    @SerialName("files_scanned")
    val filesScanned: Int = 0,

    // Number of URLs analyzed
    @SerialName("urls_scanned")
    val urlsScanned: Int = 0,

    // Total number of scans performed by the user
    @SerialName("scan_count")
    val scanCount: Int = 0,

    // Timestamp of the most recent scan
    @SerialName("last_scan_time")
    val lastScanTime: Long? = null,

    // Whether real-time protection is currently active
    @SerialName("realtime_protection_enabled")
    val realtimeProtectionEnabled: Boolean = true,

    // Whether Safe Browsing is enabled
    @SerialName("safe_browsing_enabled")
    val safeBrowsingEnabled: Boolean = true,

    // Whether VPN protection is enabled
    @SerialName("vpn_enabled")
    val vpnEnabled: Boolean = false,

    // Whether firewall protection is enabled
    @SerialName("firewall_enabled")
    val firewallEnabled: Boolean = false,

    // Whether the device is currently considered secure
    @SerialName("device_secure")
    val deviceSecure: Boolean = true,

    // Percentage improvement in security compared to previous metrics
    @SerialName("security_improvement_percentage")
    val securityImprovementPercentage: Double = 0.0,

    // Additional analytics or custom backend data
    // Example:
    // "weekly_scan_average" -> "5"
    // "most_common_threat" -> "Phishing"
    @SerialName("metadata")
    val metadata: Map<String, String> = emptyMap()
)
