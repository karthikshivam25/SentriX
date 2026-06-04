package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Firewall Engine
 *
 * Responsible for:
 * - Firewall rule management
 * - Traffic filtering
 * - IP allow/block lists
 * - Connection validation
 * - Firewall security assessment
 */
class FirewallEngine {

    private val firewallRules =
        ConcurrentHashMap<String, FirewallRule>()

    data class FirewallRule(
        val ruleId: String,
        val ruleName: String,
        val target: String,
        val action: FirewallAction,
        val enabled: Boolean,
        val createdAt: Long = System.currentTimeMillis()
    )

    enum class FirewallAction {
        ALLOW,
        BLOCK,
        MONITOR
    }

    /**
     * Creates and registers a firewall rule.
     */
    suspend fun createRule(
        ruleId: String,
        ruleName: String,
        target: String,
        action: FirewallAction
    ): NetworkResult<FirewallRule> = withContext(Dispatchers.Default) {

        try {

            val rule = FirewallRule(
                ruleId = ruleId,
                ruleName = ruleName,
                target = target,
                action = action,
                enabled = true
            )

            firewallRules[ruleId] = rule

            NetworkResult.Success(rule)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Failed to create firewall rule"
            )
        }
    }

    /**
     * Registers an existing firewall rule.
     */
    fun registerRule(
        rule: FirewallRule
    ) {
        firewallRules[rule.ruleId] = rule
    }

    /**
     * Retrieves a firewall rule.
     */
    fun getRule(
        ruleId: String
    ): FirewallRule? {
        return firewallRules[ruleId]
    }

    /**
     * Returns all firewall rules.
     */
    fun getRules(): List<FirewallRule> {
        return firewallRules.values.toList()
    }

    /**
     * Enables or disables a firewall rule.
     */
    fun updateRuleStatus(
        ruleId: String,
        enabled: Boolean
    ): Boolean {

        val rule = firewallRules[ruleId] ?: return false

        firewallRules[ruleId] = rule.copy(
            enabled = enabled
        )

        return true
    }

    /**
     * Determines if traffic is allowed.
     */
    fun isTrafficAllowed(
        target: String
    ): Boolean {

        val matchingRule = firewallRules.values
            .firstOrNull {
                it.enabled &&
                it.target.equals(
                    target,
                    ignoreCase = true
                )
            }

        return when (matchingRule?.action) {
            FirewallAction.BLOCK -> false
            else -> true
        }
    }

    /**
     * Calculates firewall security score.
     */
    fun calculateSecurityScore(): Int {

        if (firewallRules.isEmpty()) {
            return 50
        }

        val enabledRules = firewallRules.values.count {
            it.enabled
        }

        val blockRules = firewallRules.values.count {
            it.enabled &&
            it.action == FirewallAction.BLOCK
        }

        return (
            (enabledRules * 5) +
            (blockRules * 10)
        ).coerceIn(0, 100)
    }

    /**
     * Returns firewall protection level.
     */
    fun getProtectionLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "MAXIMUM"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "MINIMAL"
        }
    }

    /**
     * Generates firewall recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Firewall protection is excellent."
            )

            score >= 75 -> listOf(
                "Firewall configuration is secure."
            )

            score >= 50 -> listOf(
                "Review firewall rules periodically.",
                "Add monitoring for suspicious traffic."
            )

            score >= 25 -> listOf(
                "Increase firewall coverage.",
                "Add more traffic filtering rules."
            )

            else -> listOf(
                "Firewall protection is insufficient.",
                "Configure essential security rules.",
                "Enable traffic filtering immediately."
            )
        }
    }

    /**
     * Removes a firewall rule.
     */
    fun removeRule(
        ruleId: String
    ) {
        firewallRules.remove(ruleId)
    }

    /**
     * Clears all firewall rules.
     */
    fun clearRules() {
        firewallRules.clear()
    }

    /**
     * Returns total rule count.
     */
    fun getRuleCount(): Int {
        return firewallRules.size
    }

    /**
     * Returns enabled firewall rules.
     */
    fun getEnabledRules(): List<FirewallRule> {
        return firewallRules.values.filter {
            it.enabled
        }
    }
}
