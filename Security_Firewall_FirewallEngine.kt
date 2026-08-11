package com.sentrix.security.firewall

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * FirewallEngine
 *
 * Core decision engine for the SentriX firewall subsystem.
 *
 * FirewallManager is responsible for lifecycle/orchestration,
 * while FirewallEngine is responsible for making firewall decisions.
 *
 * Responsibilities:
 *
 * - Evaluate network requests.
 * - Evaluate firewall rules.
 * - Apply rule priority.
 * - Apply application rules.
 * - Apply domain rules.
 * - Apply IP rules.
 * - Apply port rules.
 * - Apply protocol rules.
 * - Apply threat overrides.
 * - Apply default firewall policy.
 * - Maintain connection decision state.
 * - Maintain engine statistics.
 * - Explain why a decision was made.
 *
 * This class deliberately does NOT:
 *
 * - Capture packets.
 * - Create a VPN tunnel.
 * - Modify Android networking.
 * - Perform DNS interception.
 * - Perform external network requests.
 *
 * Those responsibilities belong to the appropriate Android
 * networking/VpnService and threat-intelligence layers.
 *
 * Architecture:
 *
 *                FirewallService
 *                       |
 *                       v
 *                FirewallManager
 *                       |
 *                       v
 *                 FirewallEngine
 *                       |
 *          ┌────────────┼────────────┐
 *          ▼            ▼            ▼
 *       Rules       Threats      Connection
 *          |            |            |
 *          └────────────┼────────────┘
 *                       ▼
 *                FirewallDecision
 */
class FirewallEngine(
    private val configuration:
        FirewallEngineConfiguration =
            FirewallEngineConfiguration()
) {

    companion object {

        private const val TAG =
            "FirewallEngine"

        private const val MAX_RULES =
            10_000

        private const val MAX_THREAT_OVERRIDES =
            10_000

        private const val MAX_CONNECTION_ENTRIES =
            50_000
    }

    /**
     * Runtime firewall rules.
     */
    private val rules =
        ConcurrentHashMap<
            String,
            FirewallRule
        >()

    /**
     * Threat overrides.
     */
    private val threatOverrides =
        ConcurrentHashMap<
            String,
            FirewallThreatOverride
        >()

    /**
     * Connection decision cache.
     *
     * This avoids repeatedly evaluating the exact same connection
     * metadata during a short-lived connection session.
     */
    private val connectionCache =
        ConcurrentHashMap<
            String,
            FirewallCachedDecision
        >()

    /**
     * Runtime statistics.
     */
    private val statistics =
        FirewallEngineStatisticsCounter()

    /**
     * Indicates whether the engine is active.
     */
    @Volatile
    private var active =
        false

    /**
     * Activates the engine.
     */
    suspend fun start():
            FirewallEngineOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                active
            ) {

                return@withContext
                    FirewallEngineOperationResult.success(
                        "Firewall engine is already active."
                    )
            }

            active = true

            Log.i(
                TAG,
                "Firewall engine started."
            )

            FirewallEngineOperationResult.success(
                "Firewall engine started successfully."
            )
        }

    /**
     * Deactivates the engine.
     *
     * Rules are retained.
     */
    suspend fun stop():
            FirewallEngineOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            active = false

            connectionCache.clear()

            Log.i(
                TAG,
                "Firewall engine stopped."
            )

            FirewallEngineOperationResult.success(
                "Firewall engine stopped successfully."
            )
        }

    /**
     * Indicates whether the engine is active.
     */
    fun isActive(): Boolean =
        active

    /**
     * Adds or replaces a firewall rule.
     */
    fun addRule(
        rule: FirewallRule
    ): FirewallEngineOperationResult {

        if (
            rule.id.isBlank()
        ) {

            return FirewallEngineOperationResult.failure(
                "Firewall rule ID cannot be blank."
            )
        }

        if (
            rules.size >= MAX_RULES &&
            !rules.containsKey(rule.id)
        ) {

            return FirewallEngineOperationResult.failure(
                "Maximum firewall rule count reached."
            )
        }

        rules[rule.id] =
            rule

        clearConnectionCache()

        return FirewallEngineOperationResult.success(
            "Firewall rule added."
        )
    }

    /**
     * Removes a firewall rule.
     */
    fun removeRule(
        ruleId: String
    ): FirewallEngineOperationResult {

        if (
            ruleId.isBlank()
        ) {

            return FirewallEngineOperationResult.failure(
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

            return FirewallEngineOperationResult.failure(
                "Firewall rule was not found."
            )
        }

        clearConnectionCache()

        return FirewallEngineOperationResult.success(
            "Firewall rule removed."
        )
    }

    /**
     * Replaces the complete rule set.
     */
    fun replaceRules(
        firewallRules:
            Collection<FirewallRule>
    ): FirewallEngineOperationResult {

        if (
            firewallRules.size >
            MAX_RULES
        ) {

            return FirewallEngineOperationResult.failure(
                "Rule collection exceeds the maximum supported size."
            )
        }

        val invalidRule =
            firewallRules.firstOrNull {
                it.id.isBlank()
            }

        if (
            invalidRule != null
        ) {

            return FirewallEngineOperationResult.failure(
                "Rule collection contains an invalid rule."
            )
        }

        rules.clear()

        firewallRules.forEach {
            rules[it.id] = it
        }

        clearConnectionCache()

        return FirewallEngineOperationResult.success(
            "Firewall rules replaced."
        )
    }

    /**
     * Returns all configured rules ordered by priority.
     */
    fun getRules():
            List<FirewallRule> {

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
     * Adds a threat override.
     *
     * Threat overrides represent higher-confidence security
     * decisions from SentriX threat intelligence or local detection.
     */
    fun addThreatOverride(
        override:
            FirewallThreatOverride
    ): FirewallEngineOperationResult {

        if (
            override.target.isBlank()
        ) {

            return FirewallEngineOperationResult.failure(
                "Threat override target cannot be blank."
            )
        }

        if (
            threatOverrides.size >=
            MAX_THREAT_OVERRIDES &&
            !threatOverrides.containsKey(
                override.target
            )
        ) {

            return FirewallEngineOperationResult.failure(
                "Maximum threat override count reached."
            )
        }

        threatOverrides[
            normalizeTarget(
                override.target
            )
        ] =
            override

        clearConnectionCache()

        return FirewallEngineOperationResult.success(
            "Threat override added."
        )
    }

    /**
     * Removes a threat override.
     */
    fun removeThreatOverride(
        target: String
    ): FirewallEngineOperationResult {

        val removed =
            threatOverrides.remove(
                normalizeTarget(target)
            )

        if (
            removed == null
        ) {

            return FirewallEngineOperationResult.failure(
                "Threat override was not found."
            )
        }

        clearConnectionCache()

        return FirewallEngineOperationResult.success(
            "Threat override removed."
        )
    }

    /**
     * Evaluates a network request.
     */
    suspend fun evaluate(
        request:
            FirewallNetworkRequest
    ): FirewallEngineResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            statistics.incrementEvaluations()

            /*
             * If the engine is disabled, the engine itself does not
             * enforce rules.
             */
            if (
                !active
            ) {

                statistics.incrementAllowed()

                return@withContext FirewallEngineResult(
                    decision =
                        FirewallDecision.ALLOW,
                    reason =
                        "Firewall engine is inactive.",
                    matchedRule =
                        null,
                    matchedThreat =
                        null,
                    evaluatedRuleCount =
                        0,
                    fromCache =
                        false
                )
            }

            validateRequest(
                request
            )

            /*
             * Check the short-lived connection cache first.
             */
            val cacheKey =
                buildConnectionKey(
                    request
                )

            val cached =
                connectionCache[
                    cacheKey
                ]

            if (
                cached != null &&
                !cached.isExpired()
            ) {

                statistics.incrementCacheHits()

                recordDecision(
                    cached.decision
                )

                return@withContext FirewallEngineResult(
                    decision =
                        cached.decision,
                    reason =
                        "Decision retrieved from connection cache.",
                    matchedRule =
                        cached.matchedRule,
                    matchedThreat =
                        cached.matchedThreat,
                    evaluatedRuleCount =
                        cached.evaluatedRuleCount,
                    fromCache =
                        true
                )
            }

            statistics.incrementCacheMisses()

            /*
             * Threat overrides have precedence over ordinary rules.
             */
            val threatMatch =
                findThreatOverride(
                    request
                )

            if (
                threatMatch != null
            ) {

                val decision =
                    threatMatch.action

                val result =
                    FirewallEngineResult(
                        decision =
                            decision,
                        reason =
                            threatMatch.reason,
                        matchedRule =
                            null,
                        matchedThreat =
                            threatMatch,
                        evaluatedRuleCount =
                            0,
                        fromCache =
                            false
                    )

                cacheDecision(
                    cacheKey,
                    result
                )

                recordDecision(
                    decision
                )

                return@withContext result
            }

            /*
             * Evaluate ordinary firewall rules.
             */
            val activeRules =
                getRules()
                    .filter {
                        it.enabled
                    }

            val matchedRule =
                findMatchingRule(
                    request,
                    activeRules
                )

            if (
                matchedRule != null
            ) {

                val result =
                    FirewallEngineResult(
                        decision =
                            matchedRule.action,
                        reason =
                            buildRuleReason(
                                matchedRule
                            ),
                        matchedRule =
                            matchedRule,
                        matchedThreat =
                            null,
                        evaluatedRuleCount =
                            activeRules.size,
                        fromCache =
                            false
                    )

                cacheDecision(
                    cacheKey,
                    result
                )

                recordDecision(
                    matchedRule.action
                )

                return@withContext result
            }

            /*
             * No explicit rule matched.
             *
             * Apply default policy.
             */
            val defaultDecision =
                determineDefaultDecision(
                    request
                )

            val result =
                FirewallEngineResult(
                    decision =
                        defaultDecision,
                    reason =
                        "No explicit firewall rule matched. " +
                                "Default policy applied.",
                    matchedRule =
                        null,
                    matchedThreat =
                        null,
                    evaluatedRuleCount =
                        activeRules.size,
                    fromCache =
                        false
                )

            cacheDecision(
                cacheKey,
                result
            )

            recordDecision(
                defaultDecision
            )

            result
        }

    /**
     * Evaluates several requests.
     */
    suspend fun evaluateBatch(
        requests:
            Collection<FirewallNetworkRequest>
    ): List<FirewallEngineResult> =
        withContext(Dispatchers.Default) {

            checkCancellation()

            requests.map { request ->

                evaluate(
                    request
                )
            }
        }

    /**
     * Checks whether the connection should be blocked.
     */
    suspend fun shouldBlock(
        request:
            FirewallNetworkRequest
    ): Boolean {

        return evaluate(
            request
        ).decision ==
                FirewallDecision.BLOCK
    }

    /**
     * Checks whether connection is permitted.
     */
    suspend fun shouldAllow(
        request:
            FirewallNetworkRequest
    ): Boolean {

        return evaluate(
            request
        ).decision ==
                FirewallDecision.ALLOW
    }

    /**
     * Finds the first matching rule.
     *
     * Rules are already sorted by priority.
     */
    private fun findMatchingRule(
        request:
            FirewallNetworkRequest,
        activeRules:
            List<FirewallRule>
    ): FirewallRule? {

        for (
            rule in activeRules
        ) {

            if (
                matchesRule(
                    request,
                    rule
                )
            ) {

                return rule
            }
        }

        return null
    }

    /**
     * Matches request against a firewall rule.
     */
    private fun matchesRule(
        request:
            FirewallNetworkRequest,
        rule:
            FirewallRule
    ): Boolean {

        /*
         * Application/package restriction.
         */
        if (
            rule.packageName != null &&
            !matchesExact(
                request.packageName,
                rule.packageName
            )
        ) {

            return false
        }

        /*
         * Protocol restriction.
         */
        if (
            rule.protocol !=
                FirewallProtocol.ANY &&
            request.protocol !=
                rule.protocol
        ) {

            return false
        }

        /*
         * Port restriction.
         */
        if (
            rule.port != null &&
            request.port !=
                rule.port
        ) {

            return false
        }

        return when (
            rule.type
        ) {

            FirewallRuleType.DOMAIN ->
                matchesDomain(
                    request.host,
                    rule.target
                )

            FirewallRuleType.IP ->
                matchesIp(
                    request,
                    rule.target
                )

            FirewallRuleType.PORT ->
                matchesPort(
                    request.port,
                    rule.target
                )

            FirewallRuleType.APPLICATION ->
                matchesExact(
                    request.packageName,
                    rule.target
                )

            FirewallRuleType.PROTOCOL ->
                request.protocol.name
                    .equals(
                        rule.target,
                        ignoreCase = true
                    )

            FirewallRuleType.NETWORK ->
                matchesDomainOrIp(
                    request,
                    rule.target
                )

            FirewallRuleType.DEFAULT ->
                true
        }
    }

    /**
     * Domain matching.
     *
     * Supports:
     *
     * example.com
     * *.example.com
     */
    private fun matchesDomain(
        host:
            String,
        target:
            String
    ): Boolean {

        val normalizedHost =
            normalizeTarget(
                host
            )

        val normalizedTarget =
            normalizeTarget(
                target
            )

        if (
            normalizedTarget == "*"
        ) {

            return true
        }

        if (
            normalizedHost ==
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

            return normalizedHost
                .endsWith(
                    ".$suffix"
                )
        }

        return false
    }

    /**
     * IP matching.
     */
    private fun matchesIp(
        request:
            FirewallNetworkRequest,
        target:
            String
    ): Boolean {

        val normalizedTarget =
            normalizeTarget(
                target
            )

        return normalizeTarget(
            request.host
        ) ==
                normalizedTarget ||

                normalizeTarget(
                    request.sourceIp
                ) ==
                normalizedTarget
    }

    /**
     * Port matching.
     */
    private fun matchesPort(
        port:
            Int?,
        target:
            String
    ): Boolean {

        if (
            port == null
        ) {

            return false
        }

        /*
         * Exact port.
         */
        target.toIntOrNull()?.let {

            return port == it
        }

        /*
         * Port range:
         *
         * 1000-2000
         */
        val range =
            target.split(
                "-"
            )

        if (
            range.size == 2
        ) {

            val start =
                range[0]
                    .trim()
                    .toIntOrNull()

            val end =
                range[1]
                    .trim()
                    .toIntOrNull()

            if (
                start != null &&
                end != null
            ) {

                return port in start..end
            }
        }

        return false
    }

    /**
     * Domain/IP generic matching.
     */
    private fun matchesDomainOrIp(
        request:
            FirewallNetworkRequest,
        target:
            String
    ): Boolean {

        return matchesDomain(
            request.host,
            target
        ) ||
                matchesIp(
                    request,
                    target
                )
    }

    /**
     * Finds a matching threat override.
     */
    private fun findThreatOverride(
        request:
            FirewallNetworkRequest
    ): FirewallThreatOverride? {

        val host =
            normalizeTarget(
                request.host
            )

        /*
         * Exact host match.
         */
        threatOverrides[
            host
        ]?.let {
            return it
        }

        /*
         * Parent-domain lookup.
         *
         * Example:
         *
         * login.bad.example.com
         *
         * can match:
         *
         * *.bad.example.com
         */
        val labels =
            host.split(
                "."
            )

        for (
            index in 0 until labels.size
        ) {

            val candidate =
                "*." +
                        labels
                            .drop(index)
                            .joinToString(".")

            threatOverrides[
                candidate
            ]?.let {
                return it
            }
        }

        return null
    }

    /**
     * Applies the default firewall policy.
     */
    private fun determineDefaultDecision(
        request:
            FirewallNetworkRequest
    ): FirewallDecision {

        return when (
            configuration.defaultPolicy
        ) {

            FirewallDefaultPolicy.ALLOW ->
                FirewallDecision.ALLOW

            FirewallDefaultPolicy.MONITOR ->
                FirewallDecision.MONITOR

            FirewallDefaultPolicy.WARN ->
                FirewallDecision.WARN

            FirewallDefaultPolicy.BLOCK ->
                FirewallDecision.BLOCK
        }
    }

    /**
     * Builds a readable reason for a matched rule.
     */
    private fun buildRuleReason(
        rule:
            FirewallRule
    ): String {

        return "Matched firewall rule " +
                "'${rule.name}' " +
                "(priority=${rule.priority}, " +
                "action=${rule.action})."
    }

    /**
     * Adds a result to the connection cache.
     */
    private fun cacheDecision(
        key:
            String,
        result:
            FirewallEngineResult
    ) {

        if (
            connectionCache.size >=
            MAX_CONNECTION_ENTRIES
        ) {

            /*
             * Simple bounded-cache strategy.
             *
             * A production implementation can replace this with
             * a dedicated LRU cache.
             */
            connectionCache.keys
                .firstOrNull()
                ?.let {
                    connectionCache.remove(
                        it
                    )
                }
        }

        connectionCache[
            key
        ] =
            FirewallCachedDecision(
                decision =
                    result.decision,
                matchedRule =
                    result.matchedRule,
                matchedThreat =
                    result.matchedThreat,
                evaluatedRuleCount =
                    result.evaluatedRuleCount,
                expiresAt =
                    System.currentTimeMillis() +
                            configuration
                                .connectionCacheTtlMs
            )
    }

    /**
     * Builds a stable connection key.
     */
    private fun buildConnectionKey(
        request:
            FirewallNetworkRequest
    ): String {

        return listOf(
            request.sourceIp.orEmpty(),
            request.host,
            request.port?.toString().orEmpty(),
            request.protocol.name,
            request.packageName.orEmpty()
        ).joinToString("|")
    }

    /**
     * Clears connection decisions.
     */
    fun clearConnectionCache() {

        connectionCache.clear()
    }

    /**
     * Returns current engine statistics.
     */
    fun getStatistics():
            FirewallEngineStatistics {

        return statistics.snapshot()
    }

    /**
     * Resets statistics.
     */
    fun resetStatistics() {

        statistics.reset()
    }

    /**
     * Returns number of rules.
     */
    fun getRuleCount():
            Int {

        return rules.size
    }

    /**
     * Returns number of threat overrides.
     */
    fun getThreatOverrideCount():
            Int {

        return threatOverrides.size
    }

    /**
     * Validates a network request.
     */
    private fun validateRequest(
        request:
            FirewallNetworkRequest
    ) {

        require(
            request.host.isNotBlank()
        ) {
            "Firewall request host cannot be blank."
        }

        request.port?.let {

            require(
                it in 1..65535
            ) {
                "Firewall request port must be between 1 and 65535."
            }
        }
    }

    /**
     * Normalizes matching targets.
     */
    private fun normalizeTarget(
        value:
            String?
    ): String {

        return value
            ?.trim()
            ?.lowercase()
            ?: ""
    }

    /**
     * Exact nullable string comparison.
     */
    private fun matchesExact(
        value:
            String?,
        target:
            String
    ): Boolean {

        if (
            value == null
        ) {
            return false
        }

        return value.equals(
            target,
            ignoreCase = true
        )
    }

    /**
     * Records decision statistics.
     */
    private fun recordDecision(
        decision:
            FirewallDecision
    ) {

        when (
            decision
        ) {

            FirewallDecision.ALLOW ->
                statistics.incrementAllowed()

            FirewallDecision.BLOCK ->
                statistics.incrementBlocked()

            FirewallDecision.MONITOR ->
                statistics.incrementMonitored()

            FirewallDecision.WARN ->
                statistics.incrementWarnings()
        }
    }

    /**
     * Coroutine cancellation support.
     */
    private suspend fun checkCancellation() {

        if (
            !kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Firewall engine operation was cancelled."
            )
        }
    }
}

/**
 * Threat override.
 *
 * Represents high-confidence intelligence that should take
 * precedence over normal firewall rules.
 */
data class FirewallThreatOverride(

    /**
     * Domain/IP target.
     */
    val target:
        String,

    /**
     * Threat classification.
     */
    val threatType:
        FirewallThreatType,

    /**
     * Recommended firewall action.
     */
    val action:
        FirewallDecision =
        FirewallDecision.BLOCK,

    /**
     * Confidence in the threat.
     */
    val confidence:
        Float = 1.0f,

    /**
     * Human-readable reason.
     */
    val reason:
        String,

    /**
     * Threat source.
     */
    val source:
        FirewallThreatSource =
        FirewallThreatSource.LOCAL_ENGINE,

    /**
     * Expiration time.
     */
    val expiresAt:
        Long? = null
) {

    /**
     * Whether this override is expired.
     */
    fun isExpired():
            Boolean {

        return expiresAt != null &&
                System.currentTimeMillis() >=
                expiresAt
    }
}

/**
 * Firewall threat types.
 */
enum class FirewallThreatType {

    MALWARE,

    PHISHING,

    BOTNET,

    COMMAND_AND_CONTROL,

    SPYWARE,

    RANSOMWARE,

    SCAM,

    SUSPICIOUS_DOMAIN,

    SUSPICIOUS_IP,

    DATA_EXFILTRATION,

    UNKNOWN
}

/**
 * Threat intelligence source.
 */
enum class FirewallThreatSource {

    LOCAL_ENGINE,

    THREAT_INTELLIGENCE,

    MALWARE_ANALYZER,

    PHISHING_ANALYZER,

    USER_REPORT,

    ENTERPRISE_POLICY,

    AUTOMATIC
}

/**
 * Final result generated by FirewallEngine.
 */
data class FirewallEngineResult(

    /**
     * Firewall decision.
     */
    val decision:
        FirewallDecision,

    /**
     * Explanation.
     */
    val reason:
        String,

    /**
     * Matching firewall rule.
     */
    val matchedRule:
        FirewallRule?,

    /**
     * Matching threat intelligence override.
     */
    val matchedThreat:
        FirewallThreatOverride?,

    /**
     * Number of rules evaluated.
     */
    val evaluatedRuleCount:
        Int,

    /**
     * Whether result came from connection cache.
     */
    val fromCache:
        Boolean
)

/**
 * Cached firewall decision.
 */
private data class FirewallCachedDecision(

    val decision:
        FirewallDecision,

    val matchedRule:
        FirewallRule?,

    val matchedThreat:
        FirewallThreatOverride?,

    val evaluatedRuleCount:
        Int,

    val expiresAt:
        Long
) {

    fun isExpired():
            Boolean {

        return System.currentTimeMillis() >=
                expiresAt
    }
}

/**
 * Default firewall policy.
 */
enum class FirewallDefaultPolicy {

    /**
     * Permit traffic when no rule matches.
     */
    ALLOW,

    /**
     * Permit but monitor traffic.
     */
    MONITOR,

    /**
     * Permit but require higher-level warning.
     */
    WARN,

    /**
     * Deny traffic when no rule matches.
     *
     * This should only be used when the user/enterprise policy
     * explicitly requires a default-deny configuration.
     */
    BLOCK
}

/**
 * Firewall engine configuration.
 */
data class FirewallEngineConfiguration(

    /**
     * Default behavior when no rule matches.
     */
    val defaultPolicy:
        FirewallDefaultPolicy =
        FirewallDefaultPolicy.ALLOW,

    /**
     * How long connection decisions may remain cached.
     */
    val connectionCacheTtlMs:
        Long = 30_000L
)

/**
 * Engine operation result.
 */
data class FirewallEngineOperationResult(

    val success:
        Boolean,

    val message:
        String,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String
        ):
                FirewallEngineOperationResult {

            return FirewallEngineOperationResult(
                success = true,
                message = message
            )
        }

        fun failure(
            message:
                String,
            error:
                String? = null
        ):
                FirewallEngineOperationResult {

            return FirewallEngineOperationResult(
                success = false,
                message = message,
                error = error
            )
        }
    }
}

/**
 * Firewall engine statistics.
 */
data class FirewallEngineStatistics(

    val evaluations:
        Long,

    val allowed:
        Long,

    val blocked:
        Long,

    val monitored:
        Long,

    val warnings:
        Long,

    val cacheHits:
        Long,

    val cacheMisses:
        Long
)

/**
 * Thread-safe statistics implementation.
 */
private class FirewallEngineStatisticsCounter {

    private val evaluations =
        AtomicLong(0)

    private val allowed =
        AtomicLong(0)

    private val blocked =
        AtomicLong(0)

    private val monitored =
        AtomicLong(0)

    private val warnings =
        AtomicLong(0)

    private val cacheHits =
        AtomicLong(0)

    private val cacheMisses =
        AtomicLong(0)

    fun incrementEvaluations() {
        evaluations.incrementAndGet()
    }

    fun incrementAllowed() {
        allowed.incrementAndGet()
    }

    fun incrementBlocked() {
        blocked.incrementAndGet()
    }

    fun incrementMonitored() {
        monitored.incrementAndGet()
    }

    fun incrementWarnings() {
        warnings.incrementAndGet()
    }

    fun incrementCacheHits() {
        cacheHits.incrementAndGet()
    }

    fun incrementCacheMisses() {
        cacheMisses.incrementAndGet()
    }

    fun snapshot():
            FirewallEngineStatistics {

        return FirewallEngineStatistics(
            evaluations =
                evaluations.get(),

            allowed =
                allowed.get(),

            blocked =
                blocked.get(),

            monitored =
                monitored.get(),

            warnings =
                warnings.get(),

            cacheHits =
                cacheHits.get(),

            cacheMisses =
                cacheMisses.get()
        )
    }

    fun reset() {

        evaluations.set(0)
        allowed.set(0)
        blocked.set(0)
        monitored.set(0)
        warnings.set(0)
        cacheHits.set(0)
        cacheMisses.set(0)
    }
}
