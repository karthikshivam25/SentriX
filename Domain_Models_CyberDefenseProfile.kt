package com.sentrix.domain.models

import java.util.UUID

/**
 * Represents the overall cyber defense posture and protection profile
 * of a user, device, or organization within SentriX.
 */
data class CyberDefenseProfile(
    val profileId: String = UUID.randomUUID().toString(),
    val profileName: String,
    val profileType: ProfileType,

    val securityScore: Int = 0,
    val riskScore: Int = 0,
    val threatLevel: ThreatLevel = ThreatLevel.LOW,

    val firewallEnabled: Boolean = false,
    val vpnEnabled: Boolean = false,
    val malwareProtectionEnabled: Boolean = false,
    val intrusionDetectionEnabled: Boolean = false,
    val phishingProtectionEnabled: Boolean = false,
    val ransomwareProtectionEnabled: Boolean = false,

    val activeThreats: Int = 0,
    val blockedThreats: Int = 0,
    val quarantinedFiles: Int = 0,

    val protectedDevices: Int = 1,
    val monitoredNetworks: Int = 0,

    val lastSecurityScan: Long = 0L,
    val lastThreatDetected: Long? = null,
    val lastUpdated: Long = System.currentTimeMillis(),

    val securityPolicies: List<String> = emptyList(),
    val enabledModules: List<String> = emptyList(),
    val complianceStandards: List<String> = emptyList(),

    val aiProtectionEnabled: Boolean = false,
    val autoResponseEnabled: Boolean = false,
    val zeroTrustEnabled: Boolean = false,

    val customAttributes: Map<String, String> = emptyMap()
)

enum class ProfileType {
    PERSONAL,
    ENTERPRISE,
    GOVERNMENT,
    EDUCATIONAL,
    SMB,
    CLOUD,
    HYBRID
}

enum class ThreatLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
