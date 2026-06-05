package com.sentrix.domain.models

import java.util.UUID

/**
 * CyberDefenseProfile
 *
 * Represents the overall cybersecurity posture,
 * protection configuration, and defense capabilities
 * assigned to a user, device, organization, or
 * managed environment within the SentriX platform.
 *
 * The profile serves as a centralized security
 * configuration model that defines active defense
 * mechanisms, risk posture, compliance requirements,
 * and protection policies.
 *
 * Used by:
 * - CyberDefenseManager
 * - SecurityDashboard
 * - ThreatAnalysisEngine
 * - DeviceProtectionService
 * - SecurityPolicyManager
 * - ComplianceMonitoringSystem
 * - EnterpriseSecurityCenter
 * - AIThreatResponseEngine
 */
data class CyberDefenseProfile(

    /**
     * Unique profile identifier.
     */
    val profileId: String = UUID.randomUUID().toString(),

    /**
     * Human-readable profile name.
     */
    val profileName: String,

    /**
     * Type of defense profile.
     */
    val profileType: ProfileType,

    /**
     * Overall security score.
     *
     * Range:
     * 0 - 100
     */
    val securityScore: Int = 0,

    /**
     * Overall calculated risk score.
     *
     * Higher values indicate
     * greater exposure to threats.
     */
    val riskScore: Int = 0,

    /**
     * Current threat level associated
     * with this profile.
     */
    val threatLevel: ThreatLevel =
        ThreatLevel.LOW,

    /**
     * Indicates whether firewall
     * protection is enabled.
     */
    val firewallEnabled: Boolean = false,

    /**
     * Indicates whether VPN
     * protection is enabled.
     */
    val vpnEnabled: Boolean = false,

    /**
     * Indicates whether malware
     * protection is enabled.
     */
    val malwareProtectionEnabled: Boolean = false,

    /**
     * Indicates whether intrusion
     * detection is enabled.
     */
    val intrusionDetectionEnabled: Boolean = false,

    /**
     * Indicates whether phishing
     * protection is enabled.
     */
    val phishingProtectionEnabled: Boolean = false,

    /**
     * Indicates whether ransomware
     * protection is enabled.
     */
    val ransomwareProtectionEnabled: Boolean = false,

    /**
     * Number of currently active threats.
     */
    val activeThreats: Int = 0,

    /**
     * Number of successfully blocked threats.
     */
    val blockedThreats: Int = 0,

    /**
     * Number of quarantined files.
     */
    val quarantinedFiles: Int = 0,

    /**
     * Number of protected devices.
     */
    val protectedDevices: Int = 1,

    /**
     * Number of monitored networks.
     */
    val monitoredNetworks: Int = 0,

    /**
     * Timestamp of the most recent
     * security scan.
     */
    val lastSecurityScan: Long = 0L,

    /**
     * Timestamp of the most recently
     * detected threat.
     */
    val lastThreatDetected: Long? = null,

    /**
     * Timestamp of the latest
     * profile update.
     */
    val lastUpdated: Long =
        System.currentTimeMillis(),

    /**
     * Security policies currently
     * assigned to the profile.
     */
    val securityPolicies: List<String> =
        emptyList(),

    /**
     * Security modules currently
     * enabled for this profile.
     */
    val enabledModules: List<String> =
        emptyList(),

    /**
     * Compliance frameworks and
     * standards associated with
     * this profile.
     */
    val complianceStandards: List<String> =
        emptyList(),

    /**
     * Indicates whether AI-powered
     * protection is enabled.
     */
    val aiProtectionEnabled: Boolean = false,

    /**
     * Indicates whether automatic
     * threat response actions
     * are enabled.
     */
    val autoResponseEnabled: Boolean = false,

    /**
     * Indicates whether Zero Trust
     * security architecture is enabled.
     */
    val zeroTrustEnabled: Boolean = false,

    /**
     * Additional profile metadata.
     */
    val customAttributes: Map<String, String> =
        emptyMap()
)

/**
 * Profile type classifications.
 *
 * Defines the scope and environment
 * for which the cyber defense profile
 * is intended.
 */
enum class ProfileType {

    /**
     * Individual user protection.
     */
    PERSONAL,

    /**
     * Enterprise-wide protection.
     */
    ENTERPRISE,

    /**
     * Government security environment.
     */
    GOVERNMENT,

    /**
     * Educational institution security.
     */
    EDUCATIONAL,

    /**
     * Small and medium business profile.
     */
    SMB,

    /**
     * Cloud-native security profile.
     */
    CLOUD,

    /**
     * Hybrid infrastructure profile.
     */
    HYBRID
}

/**
 * Threat level indicators.
 *
 * Represents the current severity
 * of detected risks and threats.
 */
enum class ThreatLevel {

    /**
     * Minimal security risk.
     */
    LOW,

    /**
     * Moderate security risk.
     */
    MEDIUM,

    /**
     * High security risk requiring
     * attention.
     */
    HIGH,

    /**
     * Critical threat level requiring
     * immediate response.
     */
    CRITICAL
}
