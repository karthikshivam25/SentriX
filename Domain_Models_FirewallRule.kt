package com.sentrix.domain.models

/**
 * FirewallRule
 *
 * Represents a network firewall rule
 * used by the SentriX platform to
 * control and monitor network traffic.
 *
 * Used by:
 * - FirewallManager
 * - NetworkProtectionEngine
 * - VPN Monitoring
 * - Threat Prevention Engine
 * - Security Dashboard
 * - Enterprise Security Policies
 */
data class FirewallRule(

    /**
     * Unique rule identifier.
     */
    val ruleId: String,

    /**
     * Rule name.
     */
    val name: String,

    /**
     * Rule description.
     */
    val description: String,

    /**
     * Rule action.
     */
    val action: FirewallAction,

    /**
     * Rule status.
     */
    val status: FirewallRuleStatus,

    /**
     * Network protocol.
     */
    val protocol: NetworkProtocol,

    /**
     * Source IP address.
     */
    val sourceIp: String? = null,

    /**
     * Destination IP address.
     */
    val destinationIp: String? = null,

    /**
     * Source port.
     */
    val sourcePort: Int? = null,

    /**
     * Destination port.
     */
    val destinationPort: Int? = null,

    /**
     * Application package name.
     */
    val packageName: String? = null,

    /**
     * Priority value.
     */
    val priority: Int,

    /**
     * Whether rule is enabled.
     */
    val isEnabled: Boolean = true,

    /**
     * Creation timestamp.
     */
    val createdAt: Long,

    /**
     * Last updated timestamp.
     */
    val updatedAt: Long,

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Firewall actions.
 */
enum class FirewallAction {
    ALLOW,
    BLOCK,
    MONITOR,
    RATE_LIMIT
}

/**
 * Firewall rule status.
 */
enum class FirewallRuleStatus {
    ACTIVE,
    DISABLED,
    PENDING,
    EXPIRED
}

/**
 * Supported network protocols.
 */
enum class NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    ALL
}
