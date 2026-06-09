package com.sentrix.domain.services

import com.sentrix.domain.models.FirewallRule
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for firewall security management.
 *
 * This service evaluates firewall rules,
 * identifies security weaknesses,
 * and generates firewall-related threat indicators.
 */
class FirewallService {

    /**
     * Analyzes firewall rules and generates threat indicators.
     *
     * Rules:
     * - Disabled firewall rule protection -> CRITICAL threat.
     * - Allow-all inbound rule -> HIGH threat.
     * - Suspicious port exposure -> MEDIUM threat.
     * - Unused firewall rule -> LOW threat.
     */
    suspend fun analyzeFirewallRules(
        firewallRules: List<FirewallRule>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        firewallRules.mapNotNull { rule ->

            when {

                // Firewall protection disabled
                !rule.isEnabled -> {
                    ThreatIndicator(
                        id = rule.ruleId,
                        threatName = "Firewall Rule Disabled",
                        severity = "CRITICAL",
                        description = "A firewall protection rule is currently disabled",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // All inbound traffic allowed
                rule.allowsAllInboundTraffic -> {
                    ThreatIndicator(
                        id = rule.ruleId,
                        threatName = "Open Inbound Access",
                        severity = "HIGH",
                        description = "Firewall rule allows unrestricted inbound traffic",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Sensitive port exposed
                rule.isSensitivePortExposed -> {
                    ThreatIndicator(
                        id = rule.ruleId,
                        threatName = "Sensitive Port Exposure",
                        severity = "MEDIUM",
                        description = "Potentially sensitive network port is exposed",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Rule exists but is not actively used
                rule.isUnused -> {
                    ThreatIndicator(
                        id = rule.ruleId,
                        threatName = "Unused Firewall Rule",
                        severity = "LOW",
                        description = "Firewall rule appears unused and should be reviewed",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns enabled firewall rules.
     */
    suspend fun getEnabledRules(
        firewallRules: List<FirewallRule>
    ): List<FirewallRule> = withContext(Dispatchers.Default) {

        firewallRules.filter {
            it.isEnabled
        }
    }

    /**
     * Returns disabled firewall rules.
     */
    suspend fun getDisabledRules(
        firewallRules: List<FirewallRule>
    ): List<FirewallRule> = withContext(Dispatchers.Default) {

        firewallRules.filter {
            !it.isEnabled
        }
    }

    /**
     * Returns rules exposing sensitive ports.
     */
    suspend fun getSensitivePortRules(
        firewallRules: List<FirewallRule>
    ): List<FirewallRule> = withContext(Dispatchers.Default) {

        firewallRules.filter {
            it.isSensitivePortExposed
        }
    }

    /**
     * Returns unused firewall rules.
     */
    suspend fun getUnusedRules(
        firewallRules: List<FirewallRule>
    ): List<FirewallRule> = withContext(Dispatchers.Default) {

        firewallRules.filter {
            it.isUnused
        }
    }

    /**
     * Calculates firewall security risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateFirewallRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Determines whether firewall-related threats exist.
     */
    suspend fun hasFirewallThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns only critical firewall threats.
     */
    suspend fun getCriticalFirewallThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority firewall threats.
     */
    suspend fun getHighPriorityFirewallThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Generates a firewall security summary.
     */
    suspend fun generateFirewallSummary(
        firewallRules: List<FirewallRule>
    ): String = withContext(Dispatchers.Default) {

        val totalRules = firewallRules.size

        val enabledRules = firewallRules.count {
            it.isEnabled
        }

        val disabledRules = firewallRules.count {
            !it.isEnabled
        }

        val exposedPorts = firewallRules.count {
            it.isSensitivePortExposed
        }

        buildString {
            appendLine("Firewall Security Summary")
            appendLine("-------------------------")
            appendLine("Total Rules: $totalRules")
            appendLine("Enabled Rules: $enabledRules")
            appendLine("Disabled Rules: $disabledRules")
            appendLine("Sensitive Port Exposures: $exposedPorts")
            appendLine(
                if (disabledRules > 0 || exposedPorts > 0)
                    "Status: Firewall Review Required"
                else
                    "Status: Firewall Secure"
            )
        }
    }

    /**
     * Checks whether all firewall rules are secure.
     */
    suspend fun areFirewallRulesSecure(
        firewallRules: List<FirewallRule>
    ): Boolean = withContext(Dispatchers.Default) {

        firewallRules.none {
            !it.isEnabled ||
            it.allowsAllInboundTraffic ||
            it.isSensitivePortExposed
        }
    }
}
