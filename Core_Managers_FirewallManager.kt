package com.sentrix.core.managers

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.CopyOnWriteArrayList

/**
 * FirewallManager
 *
 * Responsibilities:
 * - Firewall rule management
 * - App network access tracking
 * - Domain blocking
 * - IP blocking
 * - Firewall statistics
 * - Security policy enforcement
 *
 * NOTE:
 * Android applications cannot implement a true
 * system-level firewall without VPNService,
 * root privileges, or device-owner permissions.
 *
 * This manager provides the policy layer that
 * can later be connected to a VPN-based firewall
 * engine for actual traffic filtering.
 */
class FirewallManager(
    private val context: Context
) {

    private val blockedDomains =
        CopyOnWriteArrayList<String>()

    private val blockedIps =
        CopyOnWriteArrayList<String>()

    private val firewallRules =
        CopyOnWriteArrayList<FirewallRule>()

    private val _firewallEnabled =
        MutableStateFlow(false)

    val firewallEnabled: StateFlow<Boolean> =
        _firewallEnabled.asStateFlow()

    /**
     * Enable firewall.
     */
    fun enableFirewall() {
        _firewallEnabled.value = true
    }

    /**
     * Disable firewall.
     */
    fun disableFirewall() {
        _firewallEnabled.value = false
    }

    /**
     * Check firewall status.
     */
    fun isFirewallEnabled(): Boolean {
        return _firewallEnabled.value
    }

    /**
     * Block a domain.
     */
    fun blockDomain(
        domain: String
    ) {
        if (!blockedDomains.contains(domain)) {
            blockedDomains.add(domain)
        }
    }

    /**
     * Unblock a domain.
     */
    fun unblockDomain(
        domain: String
    ) {
        blockedDomains.remove(domain)
    }

    /**
     * Check blocked domain.
     */
    fun isDomainBlocked(
        domain: String
    ): Boolean {

        return blockedDomains.any {
            domain.contains(
                it,
                ignoreCase = true
            )
        }
    }

    /**
     * Block an IP.
     */
    fun blockIp(
        ipAddress: String
    ) {
        if (!blockedIps.contains(ipAddress)) {
            blockedIps.add(ipAddress)
        }
    }

    /**
     * Unblock an IP.
     */
    fun unblockIp(
        ipAddress: String
    ) {
        blockedIps.remove(ipAddress)
    }

    /**
     * Check blocked IP.
     */
    fun isIpBlocked(
        ipAddress: String
    ): Boolean {
        return blockedIps.contains(ipAddress)
    }

    /**
     * Add firewall rule.
     */
    fun addRule(
        rule: FirewallRule
    ) {
        firewallRules.add(rule)
    }

    /**
     * Remove firewall rule.
     */
    fun removeRule(
        ruleId: String
    ) {
        firewallRules.removeAll {
            it.id == ruleId
        }
    }

    /**
     * Retrieve rules.
     */
    fun getRules(): List<FirewallRule> {
        return firewallRules.toList()
    }

    /**
     * Clear all rules.
     */
    fun clearRules() {
        firewallRules.clear()
    }

    /**
     * Get blocked domains.
     */
    fun getBlockedDomains(): List<String> {
        return blockedDomains.toList()
    }

    /**
     * Get blocked IPs.
     */
    fun getBlockedIps(): List<String> {
        return blockedIps.toList()
    }

    /**
     * Evaluate connection request.
     */
    fun evaluateConnection(
        host: String,
        ipAddress: String? = null
    ): FirewallDecision {

        if (!isFirewallEnabled()) {
            return FirewallDecision.ALLOW
        }

        if (isDomainBlocked(host)) {
            return FirewallDecision.BLOCK
        }

        if (
            ipAddress != null &&
            isIpBlocked(ipAddress)
        ) {
            return FirewallDecision.BLOCK
        }

        return FirewallDecision.ALLOW
    }

    /**
     * Generate firewall report.
     */
    fun generateReport(): String {

        return buildString {

            appendLine("Firewall Report")
            appendLine("--------------------------")
            appendLine("Enabled         : ${isFirewallEnabled()}")
            appendLine("Rules           : ${firewallRules.size}")
            appendLine("Blocked Domains : ${blockedDomains.size}")
            appendLine("Blocked IPs     : ${blockedIps.size}")
        }
    }

    /**
     * Firewall rule model.
     */
    data class FirewallRule(
        val id: String,
        val name: String,
        val target: String,
        val type: RuleType,
        val action: FirewallDecision,
        val enabled: Boolean = true
    )

    /**
     * Rule type.
     */
    enum class RuleType {
        DOMAIN,
        IP_ADDRESS,
        APPLICATION,
        PORT,
        NETWORK
    }

    /**
     * Firewall action.
     */
    enum class FirewallDecision {
        ALLOW,
        BLOCK,
        MONITOR
    }
}
