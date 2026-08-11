package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * FirewallManager
 *
 * Central lifecycle and orchestration manager for the SentriX
 * application-level firewall subsystem.
 *
 * Responsibilities:
 *
 * - Initialize the firewall subsystem.
 * - Start and stop firewall protection.
 * - Maintain firewall protection state.
 * - Add/remove firewall rules.
 * - Enable/disable individual rules.
 * - Evaluate network requests against firewall rules.
 * - Maintain runtime statistics.
 * - Provide firewall status information.
 * - Clear/reset firewall rules.
 * - Coordinate with firewall analyzers/evaluators.
 *
 * Important Android limitation:
 *
 * A normal Android application cannot implement a traditional
 * kernel-level firewall for the entire device without privileged
 * capabilities.
 *
 * SentriX should therefore treat this manager as an application/
 * VPN-based firewall orchestration layer.
 *
 * A production implementation can later connect this manager to:
 *
 * - Android VpnService
 * - FirewallRuleEvaluator
 * - NetworkMonitor
 * - ThreatIntelligenceService
 * - Domain/IP reputation services
 * - SentriX VPN tunnel
 *
 * Architecture:
 *
 *              FirewallManager
 *                     |
 *          ┌──────────┼──────────┐
 *          ▼          ▼          ▼
 *     Rule Store   Evaluator   Monitor
 *          |          |          |
 *          └──────────┼──────────┘
 *                     ▼
 *               Decision Engine
 *                     |
 *          ┌──────────┼──────────┐
 *          ▼          ▼          ▼
 *        ALLOW       BLOCK      LOG
 */
class FirewallManager(
    private val context: Context,
    private val ruleEvaluator: FirewallRuleEvaluator =
        FirewallRuleEvaluator()
) {

    companion object {

        private const val TAG = "FirewallManager"

        private const val MAX_RULES = 5_000

        private const val DEFAULT_RULE_PRIORITY = 100

        private const val MAX_STATISTICS_HISTORY = 10_000
    }

    /**
     * Application context.
     *
     * Holding applicationContext prevents accidental Activity
     * context leaks.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Firewall protection state.
     */
    private val protectionEnabled =
        AtomicBoolean(false)

    /**
     * Initialization state.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Runtime rules.
     *
     * A concurrent map is used because network evaluation may occur
     * from background threads while rules are being modified.
     */
    private val rules =
        java.util.concurrent.ConcurrentHashMap<
            String,
            FirewallRule
        >()

    /**
     * Runtime statistics.
     */
    private val statistics =
        FirewallStatisticsCounter()

    /**
     * Recent events.
     */
    private val eventHistory =
        java.util.concurrent.ConcurrentLinkedDeque<
            FirewallEvent
        >()

    /**
     * Indicates whether the manager has been initialized.
     */
    fun isInitialized(): Boolean {

        return initialized.get()
    }

    /**
     * Indicates whether firewall protection is enabled.
     */
    fun isProtectionEnabled(): Boolean {

        return protectionEnabled.get()
    }

    /**
     * Initializes the firewall manager.
     *
     * This method is idempotent.
     */
    suspend fun initialize(): FirewallOperationResult =
        withContext(Dispatchers.Default) {

            if (
                initialized.get()
            ) {

                return@withContext FirewallOperationResult.success(
                    message =
                        "Firewall manager is already initialized."
                )
            }

            try {

                checkCancellation()

                loadDefaultRules()

                initialized.set(true)

                logEvent(
                    FirewallEventType.INITIALIZED,
                    "Firewall manager initialized."
                )

                Log.i(
                    TAG,
                    "SentriX firewall manager initialized."
                )

                FirewallOperationResult.success(
                    message =
                        "Firewall manager initialized successfully."
                )

            } catch (exception: Exception) {

                Log.e(
                    TAG,
                    "Firewall initialization failed.",
                    exception
                )

                FirewallOperationResult.failure(
                    message =
                        "Firewall initialization failed.",
                    error =
                        exception.message
                )
            }
        }

    /**
     * Starts firewall protection.
     *
     * Initialization is automatically performed when necessary.
     */
    suspend fun startProtection():
            FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !initialized.get()
            ) {

                val initialization =
                    initialize()

                if (
                    !initialization.success
                ) {

                    return@withContext initialization
                }
            }

            if (
                protectionEnabled.get()
            ) {

                return@withContext FirewallOperationResult.success(
                    message =
                        "Firewall protection is already active."
                )
            }

            protectionEnabled.set(true)

            logEvent(
                FirewallEventType.PROTECTION_STARTED,
                "Firewall protection started."
            )

            Log.i(
                TAG,
                "Firewall protection started."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall protection started successfully."
            )
        }

    /**
     * Stops firewall protection.
     *
     * Rules are retained so protection can be restarted without
     * rebuilding the rule set.
     */
    suspend fun stopProtection():
            FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !protectionEnabled.get()
            ) {

                return@withContext FirewallOperationResult.success(
                    message =
                        "Firewall protection is already stopped."
                )
            }

            protectionEnabled.set(false)

            logEvent(
                FirewallEventType.PROTECTION_STOPPED,
                "Firewall protection stopped."
            )

            Log.i(
                TAG,
                "Firewall protection stopped."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall protection stopped successfully."
            )
        }

    /**
     * Adds a firewall rule.
     */
    suspend fun addRule(
        rule: FirewallRule
    ): FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !initialized.get()
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Firewall manager is not initialized."
                )
            }

            if (
                rules.size >= MAX_RULES &&
                !rules.containsKey(rule.id)
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Maximum firewall rule limit reached."
                )
            }

            if (
                rule.id.isBlank()
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Firewall rule ID cannot be blank."
                )
            }

            rules[rule.id] =
                rule

            logEvent(
                FirewallEventType.RULE_ADDED,
                "Firewall rule added: ${rule.id}."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall rule added successfully."
            )
        }

    /**
     * Adds multiple firewall rules.
     */
    suspend fun addRules(
        firewallRules: Collection<FirewallRule>
    ): FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                firewallRules.isEmpty()
            ) {

                return@withContext FirewallOperationResult.success(
                    message =
                        "No firewall rules were supplied."
                )
            }

            if (
                rules.size +
                firewallRules.count {
                    !rules.containsKey(it.id)
                } > MAX_RULES
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Adding these rules would exceed the maximum rule limit."
                )
            }

            firewallRules.forEach { rule ->

                if (
                    rule.id.isBlank()
                ) {

                    return@withContext FirewallOperationResult.failure(
                        message =
                            "Firewall rule ID cannot be blank."
                    )
                }

                rules[rule.id] =
                    rule
            }

            logEvent(
                FirewallEventType.RULES_ADDED,
                "${firewallRules.size} firewall rules added."
            )

            FirewallOperationResult.success(
                message =
                    "${firewallRules.size} firewall rules added successfully."
            )
        }

    /**
     * Removes a firewall rule.
     */
    suspend fun removeRule(
        ruleId: String
    ): FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                ruleId.isBlank()
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Rule ID cannot be blank."
                )
            }

            val removed =
                rules.remove(
                    ruleId
                )

            if (
                removed == null
            ) {

                return@withContext FirewallOperationResult.failure(
                    message =
                        "Firewall rule was not found."
                )
            }

            logEvent(
                FirewallEventType.RULE_REMOVED,
                "Firewall rule removed: $ruleId."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall rule removed successfully."
            )
        }

    /**
     * Enables an existing rule.
     */
    suspend fun enableRule(
        ruleId: String
    ): FirewallOperationResult =
        updateRuleState(
            ruleId = ruleId,
            enabled = true
        )

    /**
     * Disables an existing rule.
     */
    suspend fun disableRule(
        ruleId: String
    ): FirewallOperationResult =
        updateRuleState(
            ruleId = ruleId,
            enabled = false
        )

    /**
     * Updates rule state.
     */
    private suspend fun updateRuleState(
        ruleId: String,
        enabled: Boolean
    ): FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                rules[ruleId]
                    ?: return@withContext FirewallOperationResult.failure(
                        message =
                            "Firewall rule was not found."
                    )

            val updated =
                existing.copy(
                    enabled = enabled
                )

            rules[ruleId] =
                updated

            logEvent(
                if (enabled)
                    FirewallEventType.RULE_ENABLED
                else
                    FirewallEventType.RULE_DISABLED,

                "Firewall rule ${if (enabled) "enabled" else "disabled"}: $ruleId."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall rule state updated."
            )
        }

    /**
     * Retrieves a rule by ID.
     */
    fun getRule(
        ruleId: String
    ): FirewallRule? {

        return rules[ruleId]
    }

    /**
     * Returns an immutable snapshot of all rules.
     */
    fun getRules(): List<FirewallRule> {

        return rules.values
            .sortedWith(
                compareByDescending<FirewallRule> {
                    it.priority
                }.thenBy {
                    it.id
                }
            )
    }

    /**
     * Returns only enabled rules.
     */
    fun getEnabledRules():
            List<FirewallRule> {

        return getRules()
            .filter {
                it.enabled
            }
    }

    /**
     * Returns only disabled rules.
     */
    fun getDisabledRules():
            List<FirewallRule> {

        return getRules()
            .filter {
                !it.enabled
            }
    }

    /**
     * Evaluates a network request against the active firewall rules.
     *
     * This is the primary runtime entry point for the firewall
     * decision engine.
     */
    suspend fun evaluate(
        request: FirewallNetworkRequest
    ): FirewallEvaluationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !initialized.get()
            ) {

                return@withContext FirewallEvaluationResult(
                    decision =
                        FirewallDecision.ALLOW,
                    matchedRule = null,
                    reason =
                        "Firewall manager is not initialized.",
                    evaluatedRules = 0,
                    protectionActive = false
                )
            }

            if (
                !protectionEnabled.get()
            ) {

                return@withContext FirewallEvaluationResult(
                    decision =
                        FirewallDecision.ALLOW,
                    matchedRule = null,
                    reason =
                        "Firewall protection is disabled.",
                    evaluatedRules = 0,
                    protectionActive = false
                )
            }

            val activeRules =
                getEnabledRules()

            statistics.incrementEvaluatedRequests()

            val result =
                ruleEvaluator.evaluate(
                    request = request,
                    rules = activeRules
                )

            when (
                result.decision
            ) {

                FirewallDecision.ALLOW ->
                    statistics.incrementAllowedRequests()

                FirewallDecision.BLOCK ->
                    statistics.incrementBlockedRequests()

                FirewallDecision.MONITOR ->
                    statistics.incrementMonitoredRequests()

                FirewallDecision.WARN ->
                    statistics.incrementWarningRequests()
            }

            if (
                result.decision !=
                    FirewallDecision.ALLOW
            ) {

                logEvent(
                    FirewallEventType.NETWORK_DECISION,
                    "Firewall decision=${result.decision}, " +
                            "host=${request.host}, " +
                            "port=${request.port}."
                )
            }

            result.copy(
                evaluatedRules =
                    activeRules.size,
                protectionActive =
                    true
            )
        }

    /**
     * Convenience method for checking whether a connection should
     * be blocked.
     */
    suspend fun shouldBlock(
        request: FirewallNetworkRequest
    ): Boolean {

        return evaluate(
            request
        ).decision ==
                FirewallDecision.BLOCK
    }

    /**
     * Convenience method for checking whether a connection should
     * be allowed.
     */
    suspend fun shouldAllow(
        request: FirewallNetworkRequest
    ): Boolean {

        val result =
            evaluate(request)

        return result.decision ==
                FirewallDecision.ALLOW
    }

    /**
     * Clears all firewall rules.
     *
     * This is intentionally explicit and should normally be protected
     * by a higher-level administrative/security confirmation.
     */
    suspend fun clearRules():
            FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                rules.size

            rules.clear()

            logEvent(
                FirewallEventType.RULES_CLEARED,
                "All firewall rules cleared. count=$count."
            )

            FirewallOperationResult.success(
                message =
                    "$count firewall rules cleared."
            )
        }

    /**
     * Restores SentriX default firewall rules.
     */
    suspend fun resetToDefaults():
            FirewallOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            rules.clear()

            loadDefaultRules()

            logEvent(
                FirewallEventType.RULES_RESET,
                "Firewall rules reset to SentriX defaults."
            )

            FirewallOperationResult.success(
                message =
                    "Firewall rules reset to defaults."
            )
        }

    /**
     * Returns current firewall statistics.
     */
    fun getStatistics():
            FirewallStatistics {

        return statistics.snapshot()
    }

    /**
     * Resets runtime statistics.
     */
    fun resetStatistics() {

        statistics.reset()

        logEvent(
            FirewallEventType.STATISTICS_RESET,
            "Firewall statistics reset."
        )
    }

    /**
     * Returns current firewall status.
     */
    fun getStatus():
            FirewallStatus {

        return FirewallStatus(
            initialized =
                initialized.get(),

            protectionEnabled =
                protectionEnabled.get(),

            totalRules =
                rules.size,

            enabledRules =
                rules.values.count {
                    it.enabled
                },

            disabledRules =
                rules.values.count {
                    !it.enabled
                },

            statistics =
                statistics.snapshot()
        )
    }

    /**
     * Returns recent firewall events.
     */
    fun getEventHistory(
        limit: Int = 100
    ): List<FirewallEvent> {

        require(limit > 0) {
            "Limit must be greater than zero."
        }

        return eventHistory
            .take(limit)
    }

    /**
     * Removes old event history.
     */
    fun clearEventHistory() {

        eventHistory.clear()
    }

    /**
     * Loads safe/default rules.
     *
     * These defaults intentionally do not block arbitrary traffic.
     * High-confidence threat rules should normally come from the
     * SentriX threat intelligence/rule management layer.
     */
    private fun loadDefaultRules() {

        val defaults =
            listOf(

                FirewallRule(
                    id =
                        "SENTRIX_ALLOW_LOOPBACK",
                    name =
                        "Allow Loopback",
                    description =
                        "Allows local loopback communication.",
                    type =
                        FirewallRuleType.IP,
                    target =
                        "127.0.0.1",
                    action =
                        FirewallDecision.ALLOW,
                    priority =
                        1,
                    enabled =
                        true,
                    source =
                        FirewallRuleSource.SYSTEM
                ),

                FirewallRule(
                    id =
                        "SENTRIX_MONITOR_UNKNOWN",
                    name =
                        "Monitor Unknown Connections",
                    description =
                        "Monitors unknown network connections without blocking them.",
                    type =
                        FirewallRuleType.DEFAULT,
                    target =
                        "*",
                    action =
                        FirewallDecision.MONITOR,
                    priority =
                        DEFAULT_RULE_PRIORITY,
                    enabled =
                        true,
                    source =
                        FirewallRuleSource.SYSTEM
                )
            )

        defaults.forEach { rule ->

            rules.putIfAbsent(
                rule.id,
                rule
            )
        }
    }

    /**
     * Adds an event to the bounded event history.
     */
    private fun logEvent(
        type: FirewallEventType,
        message: String
    ) {

        eventHistory.addFirst(
            FirewallEvent(
                type =
                    type,
                message =
                    message
            )
        )

        while (
            eventHistory.size >
            MAX_STATISTICS_HISTORY
        ) {

            eventHistory.pollLast()
        }
    }

    /**
     * Checks coroutine cancellation.
     */
    private suspend fun checkCancellation() {

        if (
            !kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Firewall operation was cancelled."
            )
        }
    }
}

/**
 * Firewall rule.
 *
 * Rules are immutable and replaced rather than mutated.
 */
data class FirewallRule(

    /**
     * Stable unique rule identifier.
     */
    val id: String,

    /**
     * Human-readable rule name.
     */
    val name: String,

    /**
     * Description of the rule.
     */
    val description: String = "",

    /**
     * Target type.
     */
    val type: FirewallRuleType,

    /**
     * Target value.
     *
     * Examples:
     *
     * example.com
     * 192.168.1.10
     * 443
     * com.example.app
     * *
     */
    val target: String,

    /**
     * Firewall action.
     */
    val action: FirewallDecision,

    /**
     * Rule priority.
     *
     * Higher values are evaluated first.
     */
    val priority: Int = 100,

    /**
     * Whether the rule is active.
     */
    val enabled: Boolean = true,

    /**
     * Origin of the rule.
     */
    val source: FirewallRuleSource =
        FirewallRuleSource.USER,

    /**
     * Optional application package.
     */
    val packageName: String? = null,

    /**
     * Optional destination port.
     */
    val port: Int? = null,

    /**
     * Optional protocol.
     */
    val protocol: FirewallProtocol =
        FirewallProtocol.ANY,

    /**
     * Creation timestamp.
     */
    val createdAt: Long =
        System.currentTimeMillis(),

    /**
     * Last modification timestamp.
     */
    val updatedAt: Long =
        System.currentTimeMillis()
)

/**
 * Network request evaluated by the firewall.
 */
data class FirewallNetworkRequest(

    /**
     * Source IP address.
     */
    val sourceIp: String? = null,

    /**
     * Destination host/domain/IP.
     */
    val host: String,

    /**
     * Destination port.
     */
    val port: Int? = null,

    /**
     * Network protocol.
     */
    val protocol: FirewallProtocol =
        FirewallProtocol.ANY,

    /**
     * Android application package.
     */
    val packageName: String? = null,

    /**
     * Whether connection is encrypted.
     */
    val encrypted: Boolean = true,

    /**
     * Optional network interface.
     */
    val interfaceName: String? = null
)

/**
 * Firewall rule evaluator.
 *
 * This class performs deterministic local rule matching.
 *
 * A more advanced SentriX implementation can later delegate
 * reputation-based decisions to a separate threat intelligence
 * engine.
 */
class FirewallRuleEvaluator {

    /**
     * Evaluates the request against rules.
     */
    fun evaluate(
        request: FirewallNetworkRequest,
        rules: List<FirewallRule>
    ): FirewallEvaluationResult {

        val sortedRules =
            rules.sortedByDescending {
                it.priority
            }

        for (
            rule in sortedRules
        ) {

            if (
                !matches(
                    request,
                    rule
                )
            ) {
                continue
            }

            return FirewallEvaluationResult(
                decision =
                    rule.action,
                matchedRule =
                    rule,
                reason =
                    "Matched firewall rule: ${rule.name}.",
                evaluatedRules =
                    rules.size,
                protectionActive =
                    true
            )
        }

        return FirewallEvaluationResult(
            decision =
                FirewallDecision.ALLOW,
            matchedRule =
                null,
            reason =
                "No firewall rule matched the request.",
            evaluatedRules =
                rules.size,
            protectionActive =
                true
        )
    }

    /**
     * Checks whether a request matches a rule.
     */
    private fun matches(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): Boolean {

        if (
            rule.packageName != null &&
            rule.packageName !=
                request.packageName
        ) {

            return false
        }

        if (
            rule.port != null &&
            rule.port != request.port
        ) {

            return false
        }

        if (
            rule.protocol !=
                FirewallProtocol.ANY &&
            rule.protocol !=
                request.protocol
        ) {

            return false
        }

        return when (
            rule.type
        ) {

            FirewallRuleType.DEFAULT ->
                true

            FirewallRuleType.DOMAIN ->
                matchesTarget(
                    request.host,
                    rule.target
                )

            FirewallRuleType.IP ->
                matchesTarget(
                    request.host,
                    rule.target
                ) ||
                        request.sourceIp ==
                        rule.target

            FirewallRuleType.PORT ->
                request.port
                    ?.toString()
                    ?.let {
                        matchesTarget(
                            it,
                            rule.target
                        )
                    }
                    ?: false

            FirewallRuleType.APPLICATION ->
                request.packageName ==
                        rule.target

            FirewallRuleType.PROTOCOL ->
                request.protocol.name
                    .equals(
                        rule.target,
                        ignoreCase = true
                    )

            FirewallRuleType.NETWORK ->
                matchesTarget(
                    request.host,
                    rule.target
                )
        }
    }

    /**
     * Supports exact matching and simple wildcard suffix matching.
     */
    private fun matchesTarget(
        value: String?,
        target: String
    ): Boolean {

        if (
            value.isNullOrBlank()
        ) {
            return false
        }

        if (
            target == "*"
        ) {
            return true
        }

        val normalizedValue =
            value.lowercase()

        val normalizedTarget =
            target.lowercase()

        if (
            normalizedValue ==
            normalizedTarget
        ) {

            return true
        }

        if (
            normalizedTarget.startsWith(
                "*."
            )
        ) {

            val suffix =
                normalizedTarget
                    .removePrefix("*.")

            return normalizedValue ==
                    suffix ||
                    normalizedValue.endsWith(
                        ".$suffix"
                    )
        }

        return false
    }
}

/**
 * Result of firewall rule evaluation.
 */
data class FirewallEvaluationResult(

    val decision:
        FirewallDecision,

    val matchedRule:
        FirewallRule?,

    val reason:
        String,

    val evaluatedRules:
        Int,

    val protectionActive:
        Boolean
)

/**
 * Firewall operation result.
 */
data class FirewallOperationResult(

    val success:
        Boolean,

    val message:
        String,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message: String
        ): FirewallOperationResult {

            return FirewallOperationResult(
                success = true,
                message = message
            )
        }

        fun failure(
            message: String,
            error: String? = null
        ): FirewallOperationResult {

            return FirewallOperationResult(
                success = false,
                message = message,
                error = error
            )
        }
    }
}

/**
 * Firewall runtime status.
 */
data class FirewallStatus(

    val initialized:
        Boolean,

    val protectionEnabled:
        Boolean,

    val totalRules:
        Int,

    val enabledRules:
        Int,

    val disabledRules:
        Int,

    val statistics:
        FirewallStatistics
)

/**
 * Runtime firewall statistics.
 */
data class FirewallStatistics(

    val evaluatedRequests:
        Long,

    val allowedRequests:
        Long,

    val blockedRequests:
        Long,

    val monitoredRequests:
        Long,

    val warningRequests:
        Long
)

/**
 * Thread-safe statistics counter.
 */
private class FirewallStatisticsCounter {

    private val evaluated =
        AtomicLong(0)

    private val allowed =
        AtomicLong(0)

    private val blocked =
        AtomicLong(0)

    private val monitored =
        AtomicLong(0)

    private val warnings =
        AtomicLong(0)

    fun incrementEvaluatedRequests() {
        evaluated.incrementAndGet()
    }

    fun incrementAllowedRequests() {
        allowed.incrementAndGet()
    }

    fun incrementBlockedRequests() {
        blocked.incrementAndGet()
    }

    fun incrementMonitoredRequests() {
        monitored.incrementAndGet()
    }

    fun incrementWarningRequests() {
        warnings.incrementAndGet()
    }

    fun snapshot():
            FirewallStatistics {

        return FirewallStatistics(
            evaluatedRequests =
                evaluated.get(),
            allowedRequests =
                allowed.get(),
            blockedRequests =
                blocked.get(),
            monitoredRequests =
                monitored.get(),
            warningRequests =
                warnings.get()
        )
    }

    fun reset() {

        evaluated.set(0)
        allowed.set(0)
        blocked.set(0)
        monitored.set(0)
        warnings.set(0)
    }
}

/**
 * Firewall decision.
 */
enum class FirewallDecision {

    /**
     * Permit the connection.
     */
    ALLOW,

    /**
     * Prevent the connection.
     */
    BLOCK,

    /**
     * Allow while recording/monitoring it.
     */
    MONITOR,

    /**
     * Require higher-level user/security confirmation.
     */
    WARN
}

/**
 * Firewall rule types.
 */
enum class FirewallRuleType {

    /**
     * Match a domain.
     */
    DOMAIN,

    /**
     * Match an IP address.
     */
    IP,

    /**
     * Match a network port.
     */
    PORT,

    /**
     * Match an Android package.
     */
    APPLICATION,

    /**
     * Match a network protocol.
     */
    PROTOCOL,

    /**
     * Generic network target.
     */
    NETWORK,

    /**
     * Default/fallback rule.
     */
    DEFAULT
}

/**
 * Supported network protocols.
 */
enum class FirewallProtocol {

    TCP,

    UDP,

    ICMP,

    ANY
}

/**
 * Origin of firewall rule.
 */
enum class FirewallRuleSource {

    /**
     * SentriX built-in rule.
     */
    SYSTEM,

    /**
     * User-created rule.
     */
    USER,

    /**
     * Threat-intelligence rule.
     */
    THREAT_INTELLIGENCE,

    /**
     * Automatically generated by SentriX.
     */
    AUTOMATIC,

    /**
     * Enterprise policy.
     */
    ENTERPRISE,

    /**
     * Temporary runtime rule.
     */
    TEMPORARY
}

/**
 * Firewall event types.
 */
enum class FirewallEventType {

    INITIALIZED,

    PROTECTION_STARTED,

    PROTECTION_STOPPED,

    RULE_ADDED,

    RULES_ADDED,

    RULE_REMOVED,

    RULE_ENABLED,

    RULE_DISABLED,

    RULES_CLEARED,

    RULES_RESET,

    NETWORK_DECISION,

    STATISTICS_RESET
}

/**
 * Firewall event record.
 */
data class FirewallEvent(

    val type:
        FirewallEventType,

    val message:
        String,

    val timestamp:
        Long = System.currentTimeMillis()
)
