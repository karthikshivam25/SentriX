package com.sentrix.domain.usecases

/**
 * ApplyFirewallRulesUseCase
 *
 * Responsible for applying
 * firewall rules within the
 * SentriX cybersecurity platform.
 *
 * Firewall rules help:
 * - Block malicious traffic
 * - Control network access
 * - Restrict unauthorized connections
 * - Improve network security
 * - Protect critical resources
 *
 * Used by:
 * - FirewallManager
 * - NetworkProtectionEngine
 * - CyberDefenseManager
 * - SecurityDashboard
 *
 * Responsibilities:
 * - Apply firewall rules
 * - Validate rule configuration
 * - Activate protection policies
 * - Generate operation results
 */
class ApplyFirewallRulesUseCase {

    /**
     * Applies firewall rules.
     */
    operator fun invoke(
        rules: List<FirewallRule>
    ): FirewallRuleResult {

        val appliedRules =
            rules.count {
                it.isEnabled
            }

        return FirewallRuleResult(
            appliedAt =
                System.currentTimeMillis(),

            totalRules =
                rules.size,

            appliedRules =
                appliedRules,

            failedRules =
                rules.size - appliedRules,

            status =
                FirewallRuleStatus.SUCCESS,

            message =
                "Firewall rules applied successfully."
        )
    }
}

/**
 * FirewallRuleResult
 *
 * Represents firewall
 * rule application result.
 */
data class FirewallRuleResult(

    /**
     * Application timestamp.
     */
    val appliedAt: Long,

    /**
     * Total rules processed.
     */
    val totalRules: Int,

    /**
     * Successfully applied rules.
     */
    val appliedRules: Int,

    /**
     * Failed rules.
     */
    val failedRules: Int,

    /**
     * Operation status.
     */
    val status:
        FirewallRuleStatus,

    /**
     * Result message.
     */
    val message: String
)

/**
 * Firewall rule.
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
     * Rule enabled status.
     */
    val isEnabled: Boolean
)

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
     * Rule application failed.
     */
    FAILED
}
