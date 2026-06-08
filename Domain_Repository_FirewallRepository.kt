package com.sentrix.domain.repositories

import com.sentrix.domain.models.FirewallRule
import com.sentrix.domain.models.FirewallRuleStatus
import com.sentrix.domain.models.FirewallStatus

/**
 * FirewallRepository
 *
 * Repository responsible for
 * managing firewall operations
 * within the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - ApplyFirewallRulesUseCase
 * - FirewallManager
 * - SecurityDashboard
 * - CyberDefenseManager
 * - NetworkProtectionEngine
 *
 * Responsibilities:
 * - Manage firewall rules
 * - Enable firewall protection
 * - Disable firewall protection
 * - Monitor firewall status
 * - Provide firewall analytics
 */
interface FirewallRepository {

    /**
     * Enables firewall.
     *
     * @return Success status.
     */
    suspend fun enableFirewall():
        Boolean

    /**
     * Disables firewall.
     *
     * @return Success status.
     */
    suspend fun disableFirewall():
        Boolean

    /**
     * Retrieves current
     * firewall status.
     *
     * @return Firewall status.
     */
    suspend fun getFirewallStatus():
        FirewallStatus

    /**
     * Retrieves all
     * firewall rules.
     *
     * @return Rule list.
     */
    suspend fun getRules():
        List<FirewallRule>

    /**
     * Retrieves firewall rule
     * by identifier.
     *
     * @param ruleId Rule ID.
     *
     * @return Firewall rule.
     */
    suspend fun getRuleById(
        ruleId: String
    ): FirewallRule?

    /**
     * Saves firewall rule.
     *
     * @param rule Firewall rule.
     */
    suspend fun saveRule(
        rule: FirewallRule
    )

    /**
     * Updates firewall rule.
     *
     * @param rule Firewall rule.
     */
    suspend fun updateRule(
        rule: FirewallRule
    )

    /**
     * Deletes firewall rule.
     *
     * @param ruleId Rule ID.
     */
    suspend fun deleteRule(
        ruleId: String
    )

    /**
     * Applies firewall rules.
     *
     * @param rules Firewall rules.
     *
     * @return Rule application status.
     */
    suspend fun applyRules(
        rules: List<FirewallRule>
    ): FirewallRuleStatus

    /**
     * Retrieves enabled rules.
     *
     * @return Enabled rule list.
     */
    suspend fun getEnabledRules():
        List<FirewallRule>
}

/**
 * FirewallRule
 *
 * Represents a firewall rule.
 */
data class FirewallRule(

    /**
     * Rule identifier.
     */
    val ruleId: String,

    /**
     * Rule name.
     */
    val ruleName: String,

    /**
     * Rule description.
     */
    val description: String,

    /**
     * Source address.
     */
    val sourceAddress: String,

    /**
     * Destination address.
     */
    val destinationAddress: String,

    /**
     * Port number.
     */
    val port: Int,

    /**
     * Rule enabled status.
     */
    val isEnabled: Boolean
)

/**
 * Firewall status.
 */
enum class FirewallStatus {

    /**
     * Firewall enabled.
     */
    ENABLED,

    /**
     * Firewall disabled.
     */
    DISABLED,

    /**
     * Firewall starting.
     */
    STARTING,

    /**
     * Firewall error.
     */
    ERROR
}

/**
 * Firewall rule status.
 */
enum class FirewallRuleStatus {

    /**
     * Rules applied successfully.
     */
    SUCCESS,

    /**
     * Rules partially applied.
     */
    PARTIAL_SUCCESS,

    /**
     * Failed to apply rules.
     */
    FAILED
}
