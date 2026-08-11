package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * FirewallSecurityLogger
 *
 * Enterprise-grade security audit logger for the SentriX firewall.
 *
 * Responsibilities:
 *
 * - Record firewall security events.
 * - Record connection decisions.
 * - Record blocked connections.
 * - Record suspicious traffic.
 * - Record firewall rule matches.
 * - Record policy matches.
 * - Record firewall configuration changes.
 * - Record firewall lifecycle events.
 * - Maintain bounded security-log history.
 * - Search and filter security logs.
 * - Track security-log statistics.
 * - Correlate logs with connections, applications, rules and policies.
 *
 * This class is an AUDIT component.
 *
 * It does not:
 *
 * - Make firewall decisions.
 * - Intercept traffic.
 * - Modify firewall rules.
 * - Start a VPN.
 * - Perform threat detection.
 *
 * Architecture:
 *
 * FirewallEventHandler
 *        |
 *        v
 * FirewallSecurityLogger
 *        |
 *        ├── Security audit history
 *        ├── Severity classification
 *        ├── Security statistics
 *        └── Audit queries
 *
 * Example:
 *
 * FirewallEngine
 *      |
 *      | BLOCK
 *      v
 * FirewallEventHandler
 *      |
 *      v
 * FirewallSecurityLogger
 *      |
 *      v
 * SecurityAuditLog
 */
class FirewallSecurityLogger(
    context: Context,
    private val configuration:
        FirewallSecurityLoggerConfiguration =
        FirewallSecurityLoggerConfiguration()
) {

    companion object {

        private const val TAG =
            "FirewallSecurityLogger"

        private const val ABSOLUTE_MAX_LOGS =
            50_000

        private const val DEFAULT_QUERY_LIMIT =
            100
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Security audit-log history.
     */
    private val logs =
        ConcurrentLinkedDeque<
            FirewallSecurityLog
        >()

    /**
     * Log index by ID.
     */
    private val logIndex =
        ConcurrentHashMap<
            String,
            FirewallSecurityLog
        >()

    /**
     * Logger statistics.
     */
    private val statistics =
        FirewallSecurityLogStatisticsCounter()

    /**
     * Initialization state.
     */
    @Volatile
    private var initialized =
        false

    /**
     * Initializes the security logger.
     */
    suspend fun initialize():
            FirewallSecurityLogOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized
            ) {

                return@withContext
                    FirewallSecurityLogOperationResult.success(
                        "Firewall security logger is already initialized."
                    )
            }

            initialized = true

            Log.i(
                TAG,
                "FirewallSecurityLogger initialized."
            )

            FirewallSecurityLogOperationResult.success(
                "Firewall security logger initialized successfully."
            )
        }

    /**
     * Returns initialization state.
     */
    fun isInitialized():
            Boolean {

        return initialized
    }

    /**
     * Records a generic firewall event.
     */
    suspend fun logEvent(
        event:
            FirewallEvent
    ):
            FirewallSecurityLogOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val securityLog =
                FirewallSecurityLog.fromFirewallEvent(
                    event
                )

            return@withContext recordLog(
                securityLog
            )
        }

    /**
     * Records a security audit entry directly.
     */
    suspend fun recordLog(
        log:
            FirewallSecurityLog
    ):
            FirewallSecurityLogOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validateLog(
                    log
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    FirewallSecurityLogOperationResult.failure(
                        validation.message
                    )
            }

            if (
                !shouldRecord(
                    log
                )
            ) {

                statistics.incrementFilteredLogs()

                return@withContext
                    FirewallSecurityLogOperationResult.success(
                        "Security log filtered by configuration."
                    )
            }

            /*
             * Protect against accidental duplicate IDs.
             */
            if (
                logIndex.containsKey(
                    log.id
                )
            ) {

                statistics.incrementDuplicates()

                return@withContext
                    FirewallSecurityLogOperationResult.failure(
                        "A security log with this ID already exists."
                    )
            }

            logs.addFirst(
                log
            )

            logIndex[
                log.id
            ] =
                log

            trimHistory()

            statistics.record(
                log
            )

            if (
                configuration
                    .writeToAndroidLog
            ) {

                writeToAndroidLog(
                    log
                )
            }

            FirewallSecurityLogOperationResult.success(
                "Firewall security log recorded successfully."
            )
        }

    /**
     * Records a firewall decision.
     */
    suspend fun logDecision(
        request:
            FirewallNetworkRequest,
        result:
            FirewallEvaluationResult
    ):
            FirewallSecurityLogOperationResult {

        val severity =
            when (
                result.decision
            ) {

                FirewallDecision.ALLOW ->
                    FirewallSecuritySeverity.INFO

                FirewallDecision.MONITOR ->
                    FirewallSecuritySeverity.LOW

                FirewallDecision.WARN ->
                    FirewallSecuritySeverity.MEDIUM

                FirewallDecision.BLOCK ->
                    FirewallSecuritySeverity.HIGH
            }

        val category =
            when (
                result.decision
            ) {

                FirewallDecision.ALLOW ->
                    FirewallSecurityLogCategory
                        .CONNECTION_ALLOWED

                FirewallDecision.MONITOR ->
                    FirewallSecurityLogCategory
                        .CONNECTION_MONITORED

                FirewallDecision.WARN ->
                    FirewallSecurityLogCategory
                        .CONNECTION_WARNING

                FirewallDecision.BLOCK ->
                    FirewallSecurityLogCategory
                        .CONNECTION_BLOCKED
            }

        val log =
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    category,

                severity =
                    severity,

                message =
                    "Firewall decision: " +
                            "${result.decision.name}. " +
                            result.reason,

                connectionId =
                    null,

                packageName =
                    request.packageName,

                host =
                    request.host,

                remoteIp =
                    request.host,

                remotePort =
                    request.port,

                protocol =
                    request.protocol,

                firewallDecision =
                    result.decision,

                ruleId =
                    result.matchedRule
                        ?.id,

                policyId =
                    null,

                metadata =
                    mapOf(
                        "decision" to
                                result.decision.name,

                        "reason" to
                                result.reason
                    )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a connection event.
     */
    suspend fun logConnection(
        connection:
            NetworkConnection,
        category:
            FirewallSecurityLogCategory,
        severity:
            FirewallSecuritySeverity,
        message:
            String
    ):
            FirewallSecurityLogOperationResult {

        val log =
            FirewallSecurityLog.fromConnection(
                connection =
                    connection,

                category =
                    category,

                severity =
                    severity,

                message =
                    message
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a blocked connection.
     */
    suspend fun logBlockedConnection(
        connection:
            NetworkConnection,
        reason:
            String
    ):
            FirewallSecurityLogOperationResult {

        return logConnection(
            connection =
                connection,

            category =
                FirewallSecurityLogCategory
                    .CONNECTION_BLOCKED,

            severity =
                FirewallSecuritySeverity.HIGH,

            message =
                "Network connection blocked: $reason"
        )
    }

    /**
     * Records an allowed connection.
     */
    suspend fun logAllowedConnection(
        connection:
            NetworkConnection,
        reason:
            String? = null
    ):
            FirewallSecurityLogOperationResult {

        return logConnection(
            connection =
                connection,

            category =
                FirewallSecurityLogCategory
                    .CONNECTION_ALLOWED,

            severity =
                FirewallSecuritySeverity.INFO,

            message =
                if (
                    reason.isNullOrBlank()
                ) {
                    "Network connection allowed."
                } else {
                    "Network connection allowed: $reason"
                }
        )
    }

    /**
     * Records suspicious traffic.
     */
    suspend fun logSuspiciousTraffic(
        connection:
            NetworkConnection,
        reason:
            String,
        indicators:
            List<String> =
            emptyList()
    ):
            FirewallSecurityLogOperationResult {

        val log =
            FirewallSecurityLog.fromConnection(
                connection =
                    connection,

                category =
                    FirewallSecurityLogCategory
                        .SUSPICIOUS_TRAFFIC,

                severity =
                    FirewallSecuritySeverity.HIGH,

                message =
                    "Suspicious network traffic detected: $reason",

                metadata =
                    mapOf(
                        "indicatorCount" to
                                indicators.size.toString(),

                        "indicators" to
                                indicators.joinToString(
                                    ","
                                )
                    )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a threat detection event.
     */
    suspend fun logThreatDetected(
        connection:
            NetworkConnection,
        threatName:
            String,
        threatLevel:
            NetworkThreatLevel,
        indicators:
            List<String> =
            emptyList()
    ):
            FirewallSecurityLogOperationResult {

        val severity =
            when (
                threatLevel
            ) {

                NetworkThreatLevel.UNKNOWN ->
                    FirewallSecuritySeverity.MEDIUM

                NetworkThreatLevel.SAFE ->
                    FirewallSecuritySeverity.INFO

                NetworkThreatLevel.LOW ->
                    FirewallSecuritySeverity.LOW

                NetworkThreatLevel.MEDIUM ->
                    FirewallSecuritySeverity.MEDIUM

                NetworkThreatLevel.HIGH ->
                    FirewallSecuritySeverity.HIGH

                NetworkThreatLevel.CRITICAL ->
                    FirewallSecuritySeverity.CRITICAL
            }

        val log =
            FirewallSecurityLog.fromConnection(
                connection =
                    connection,

                category =
                    FirewallSecurityLogCategory
                        .THREAT_DETECTED,

                severity =
                    severity,

                message =
                    "Network threat detected: $threatName",

                metadata =
                    mapOf(
                        "threatName" to
                                threatName,

                        "threatLevel" to
                                threatLevel.name,

                        "indicatorCount" to
                                indicators.size.toString(),

                        "indicators" to
                                indicators.joinToString(
                                    ","
                                )
                    )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a firewall-rule match.
     */
    suspend fun logRuleMatch(
        connection:
            NetworkConnection,
        ruleId:
            String,
        action:
            FirewallDecision,
        reason:
            String
    ):
            FirewallSecurityLogOperationResult {

        val severity =
            when (
                action
            ) {

                FirewallDecision.ALLOW ->
                    FirewallSecuritySeverity.INFO

                FirewallDecision.MONITOR ->
                    FirewallSecuritySeverity.LOW

                FirewallDecision.WARN ->
                    FirewallSecuritySeverity.MEDIUM

                FirewallDecision.BLOCK ->
                    FirewallSecuritySeverity.HIGH
            }

        val log =
            FirewallSecurityLog.fromConnection(
                connection =
                    connection,

                category =
                    FirewallSecurityLogCategory
                        .RULE_MATCHED,

                severity =
                    severity,

                message =
                    "Firewall rule matched: $reason",

                metadata =
                    mapOf(
                        "ruleId" to
                                ruleId,

                        "action" to
                                action.name
                    )
            ).copy(
                ruleId =
                    ruleId,

                firewallDecision =
                    action
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a connection-policy match.
     */
    suspend fun logPolicyMatch(
        connection:
            NetworkConnection,
        policyId:
            String,
        action:
            FirewallDecision,
        reason:
            String
    ):
            FirewallSecurityLogOperationResult {

        val severity =
            when (
                action
            ) {

                FirewallDecision.ALLOW ->
                    FirewallSecuritySeverity.INFO

                FirewallDecision.MONITOR ->
                    FirewallSecuritySeverity.LOW

                FirewallDecision.WARN ->
                    FirewallSecuritySeverity.MEDIUM

                FirewallDecision.BLOCK ->
                    FirewallSecuritySeverity.HIGH
            }

        val log =
            FirewallSecurityLog.fromConnection(
                connection =
                    connection,

                category =
                    FirewallSecurityLogCategory
                        .POLICY_MATCHED,

                severity =
                    severity,

                message =
                    "Connection policy matched: $reason",

                metadata =
                    mapOf(
                        "policyId" to
                                policyId,

                        "action" to
                                action.name
                    )
            ).copy(
                policyId =
                    policyId,

                firewallDecision =
                    action
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a firewall configuration change.
     */
    suspend fun logConfigurationChange(
        changedBy:
            String,
        change:
            String,
        metadata:
            Map<String, String> =
            emptyMap()
    ):
            FirewallSecurityLogOperationResult {

        val log =
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .CONFIGURATION_CHANGED,

                severity =
                    FirewallSecuritySeverity.MEDIUM,

                message =
                    "Firewall configuration changed: $change",

                metadata =
                    metadata +
                            mapOf(
                                "changedBy" to
                                        changedBy
                            )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a rule modification.
     */
    suspend fun logRuleChange(
        ruleId:
            String,
        action:
            String,
        changedBy:
            String
    ):
            FirewallSecurityLogOperationResult {

        val log =
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .RULE_CHANGED,

                severity =
                    FirewallSecuritySeverity.MEDIUM,

                message =
                    "Firewall rule changed: $action",

                ruleId =
                    ruleId,

                metadata =
                    mapOf(
                        "ruleId" to
                                ruleId,

                        "action" to
                                action,

                        "changedBy" to
                                changedBy
                    )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records a policy modification.
     */
    suspend fun logPolicyChange(
        policyId:
            String,
        action:
            String,
        changedBy:
            String
    ):
            FirewallSecurityLogOperationResult {

        val log =
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .POLICY_CHANGED,

                severity =
                    FirewallSecuritySeverity.MEDIUM,

                message =
                    "Connection policy changed: $action",

                policyId =
                    policyId,

                metadata =
                    mapOf(
                        "policyId" to
                                policyId,

                        "action" to
                                action,

                        "changedBy" to
                                changedBy
                    )
            )

        return recordLog(
            log
        )
    }

    /**
     * Records firewall startup.
     */
    suspend fun logFirewallStarted(
        version:
            String? = null
    ):
            FirewallSecurityLogOperationResult {

        return recordLog(
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .FIREWALL_STARTED,

                severity =
                    FirewallSecuritySeverity.INFO,

                message =
                    "SentriX firewall protection started.",

                metadata =
                    if (
                        version == null
                    ) {
                        emptyMap()
                    } else {
                        mapOf(
                            "version" to
                                    version
                        )
                    }
            )
        )
    }

    /**
     * Records firewall shutdown.
     */
    suspend fun logFirewallStopped(
        reason:
            String? = null
    ):
            FirewallSecurityLogOperationResult {

        return recordLog(
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .FIREWALL_STOPPED,

                severity =
                    FirewallSecuritySeverity.MEDIUM,

                message =
                    if (
                        reason.isNullOrBlank()
                    ) {
                        "SentriX firewall protection stopped."
                    } else {
                        "SentriX firewall protection stopped: $reason"
                    }
            )
        )
    }

    /**
     * Records an internal firewall error.
     */
    suspend fun logError(
        message:
            String,
        exception:
            Throwable? = null,
        metadata:
            Map<String, String> =
            emptyMap()
    ):
            FirewallSecurityLogOperationResult {

        val errorMetadata =
            buildMap {

                putAll(
                    metadata
                )

                exception?.let {
                    put(
                        "exceptionType",
                        it::class.java.name
                    )

                    it.message?.let { messageValue ->
                        put(
                            "exceptionMessage",
                            messageValue
                        )
                    }
                }
            }

        return recordLog(
            FirewallSecurityLog(

                id =
                    generateLogId(),

                category =
                    FirewallSecurityLogCategory
                        .ERROR,

                severity =
                    FirewallSecuritySeverity.HIGH,

                message =
                    message,

                metadata =
                    errorMetadata
            )
        )
    }

    /**
     * Returns a log by ID.
     */
    fun getLog(
        logId:
            String
    ):
            FirewallSecurityLog? {

        return logIndex[
            logId
        ]
    }

    /**
     * Returns all security logs.
     */
    fun getAllLogs():
            List<FirewallSecurityLog> {

        return logs.toList()
    }

    /**
     * Returns recent security logs.
     */
    fun getRecentLogs(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .take(
                limit
            )
    }

    /**
     * Returns logs by category.
     */
    fun getLogsByCategory(
        category:
            FirewallSecurityLogCategory,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.category == category
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs by severity.
     */
    fun getLogsBySeverity(
        severity:
            FirewallSecuritySeverity,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.severity == severity
            }
            .take(
                limit
            )
    }

    /**
     * Returns high-risk logs.
     */
    fun getHighRiskLogs(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {

                it.severity ==
                        FirewallSecuritySeverity.HIGH ||
                        it.severity ==
                        FirewallSecuritySeverity.CRITICAL
            }
            .take(
                limit
            )
    }

    /**
     * Returns blocked connection logs.
     */
    fun getBlockedLogs(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {

                it.category ==
                        FirewallSecurityLogCategory
                            .CONNECTION_BLOCKED ||

                        it.firewallDecision ==
                        FirewallDecision.BLOCK
            }
            .take(
                limit
            )
    }

    /**
     * Returns suspicious traffic logs.
     */
    fun getSuspiciousLogs(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {

                it.category ==
                        FirewallSecurityLogCategory
                            .SUSPICIOUS_TRAFFIC ||

                        it.category ==
                        FirewallSecurityLogCategory
                            .THREAT_DETECTED
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs for an application.
     */
    fun getLogsByPackage(
        packageName:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {

                it.packageName
                    ?.equals(
                        packageName,
                        ignoreCase = true
                    ) == true
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs for a connection.
     */
    fun getLogsByConnection(
        connectionId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.connectionId ==
                        connectionId
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs for a firewall rule.
     */
    fun getLogsByRule(
        ruleId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.ruleId ==
                        ruleId
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs for a policy.
     */
    fun getLogsByPolicy(
        policyId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.policyId ==
                        policyId
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs since a timestamp.
     */
    fun getLogsSince(
        timestamp:
            Long,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.timestamp >=
                        timestamp
            }
            .take(
                limit
            )
    }

    /**
     * Returns logs between two timestamps.
     */
    fun getLogsBetween(
        startTimestamp:
            Long,
        endTimestamp:
            Long,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        require(
            startTimestamp <=
                    endTimestamp
        ) {
            "Start timestamp cannot be greater than end timestamp."
        }

        validateLimit(
            limit
        )

        return logs
            .filter {
                it.timestamp >=
                        startTimestamp &&
                        it.timestamp <=
                        endTimestamp
            }
            .take(
                limit
            )
    }

    /**
     * Searches security logs.
     */
    fun searchLogs(
        query:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallSecurityLog> {

        validateLimit(
            limit
        )

        if (
            query.isBlank()
        ) {

            return getRecentLogs(
                limit
            )
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return logs
            .filter { log ->

                log.id
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        log.message
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        log.host
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        log.remoteIp
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        log.packageName
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        log.ruleId
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        log.policyId
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true
            }
            .take(
                limit
            )
    }

    /**
     * Returns security statistics.
     */
    fun getStatistics():
            FirewallSecurityLogStatistics {

        return statistics.snapshot(
            totalLogs =
                logs.size
        )
    }

    /**
     * Removes one log.
     */
    suspend fun removeLog(
        logId:
            String
    ):
            FirewallSecurityLogOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val log =
                logIndex.remove(
                    logId
                )

            if (
                log == null
            ) {

                return@withContext
                    FirewallSecurityLogOperationResult.failure(
                        "Security log was not found."
                    )
            }

            logs.remove(
                log
            )

            statistics.incrementRemoved()

            FirewallSecurityLogOperationResult.success(
                "Security log removed."
            )
        }

    /**
     * Clears all logs.
     */
    suspend fun clearLogs(
        includeCritical:
            Boolean = false
    ):
            FirewallSecurityLogOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !includeCritical
            ) {

                val removable =
                    logs.filter {
                        it.severity !=
                                FirewallSecuritySeverity
                                    .CRITICAL
                    }

                removable.forEach { log ->

                    logs.remove(
                        log
                    )

                    logIndex.remove(
                        log.id
                    )
                }

                statistics.incrementCleared(
                    removable.size
                )

            } else {

                val count =
                    logs.size

                logs.clear()
                logIndex.clear()

                statistics.incrementCleared(
                    count
                )
            }

            FirewallSecurityLogOperationResult.success(
                "Firewall security logs cleared."
            )
        }

    /**
     * Validates a security log.
     */
    fun validateLog(
        log:
            FirewallSecurityLog
    ):
            FirewallSecurityLogValidationResult {

        if (
            log.id.isBlank()
        ) {

            return FirewallSecurityLogValidationResult.invalid(
                "Security log ID cannot be blank."
            )
        }

        if (
            log.message.isBlank()
        ) {

            return FirewallSecurityLogValidationResult.invalid(
                "Security log message cannot be blank."
            )
        }

        if (
            log.timestamp <= 0
        ) {

            return FirewallSecurityLogValidationResult.invalid(
                "Security log timestamp is invalid."
            )
        }

        if (
            log.remotePort != null &&
            log.remotePort !in 1..65535
        ) {

            return FirewallSecurityLogValidationResult.invalid(
                "Remote port must be between 1 and 65535."
            )
        }

        return FirewallSecurityLogValidationResult.valid()
    }

    /**
     * Determines whether a log should be retained.
     */
    private fun shouldRecord(
        log:
            FirewallSecurityLog
    ):
            Boolean {

        if (
            log.severity ==
            FirewallSecuritySeverity.DEBUG &&
            !configuration
                .recordDebugLogs
        ) {

            return false
        }

        if (
            log.severity ==
            FirewallSecuritySeverity.INFO &&
            !configuration
                .recordInfoLogs
        ) {

            return false
        }

        return true
    }

    /**
     * Trims the audit history.
     */
    private fun trimHistory() {

        val maximum =
            configuration
                .maximumLogHistory
                .coerceIn(
                    1,
                    ABSOLUTE_MAX_LOGS
                )

        while (
            logs.size >
            maximum
        ) {

            val removed =
                logs.pollLast()

            removed?.let {
                logIndex.remove(
                    it.id
                )
            }
        }
    }

    /**
     * Writes selected events to Android Logcat.
     */
    private fun writeToAndroidLog(
        log:
            FirewallSecurityLog
    ) {

        when (
            log.severity
        ) {

            FirewallSecuritySeverity.DEBUG ->
                Log.d(
                    TAG,
                    log.message
                )

            FirewallSecuritySeverity.INFO,
            FirewallSecuritySeverity.LOW ->
                Log.i(
                    TAG,
                    log.message
                )

            FirewallSecuritySeverity.MEDIUM ->
                Log.w(
                    TAG,
                    log.message
                )

            FirewallSecuritySeverity.HIGH,
            FirewallSecuritySeverity.CRITICAL ->
                Log.e(
                    TAG,
                    log.message
                )
        }
    }

    /**
     * Generates unique security-log ID.
     */
    private fun generateLogId():
            String {

        return "FW_LOG_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(20)
                    .uppercase()
    }

    /**
     * Validates query limit.
     */
    private fun validateLimit(
        limit:
            Int
    ) {

        require(
            limit > 0
        ) {
            "Log query limit must be greater than zero."
        }
    }

    /**
     * Ensures logger initialization.
     */
    private fun ensureInitialized() {

        check(initialized) {
            "FirewallSecurityLogger has not been initialized."
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
                "Firewall security logging operation was cancelled."
            )
        }
    }

    /**
     * Closes the logger.
     */
    fun close() {

        initialized =
            false

        logs.clear()

        logIndex.clear()

        Log.i(
            TAG,
            "FirewallSecurityLogger closed."
        )
    }
}

/**
 * Structured firewall security audit record.
 */
data class FirewallSecurityLog(

    /**
     * Unique audit-log identifier.
     */
    val id:
        String,

    /**
     * Security-log category.
     */
    val category:
        FirewallSecurityLogCategory,

    /**
     * Security severity.
     */
    val severity:
        FirewallSecuritySeverity,

    /**
     * Human-readable security message.
     */
    val message:
        String,

    /**
     * Associated network connection.
     */
    val connectionId:
        String? = null,

    /**
     * Android package associated with the event.
     */
    val packageName:
        String? = null,

    /**
     * Destination host.
     */
    val host:
        String? = null,

    /**
     * Destination IP.
     */
    val remoteIp:
        String? = null,

    /**
     * Destination port.
     */
    val remotePort:
        Int? = null,

    /**
     * Network protocol.
     */
    val protocol:
        FirewallProtocol =
        FirewallProtocol.ANY,

    /**
     * Firewall decision.
     */
    val firewallDecision:
        FirewallDecision? = null,

    /**
     * Matched firewall rule.
     */
    val ruleId:
        String? = null,

    /**
     * Matched connection policy.
     */
    val policyId:
        String? = null,

    /**
     * Additional structured metadata.
     */
    val metadata:
        Map<String, String> =
        emptyMap(),

    /**
     * Timestamp.
     */
    val timestamp:
        Long =
        System.currentTimeMillis()
) {

    companion object {

        /**
         * Converts a FirewallEvent into a security audit record.
         */
        fun fromFirewallEvent(
            event:
                FirewallEvent
        ):
                FirewallSecurityLog {

            return FirewallSecurityLog(

                id =
                    "FW_LOG_" +
                            UUID.randomUUID()
                                .toString()
                                .replace(
                                    "-",
                                    ""
                                )
                                .take(20)
                                .uppercase(),

                category =
                    mapEventCategory(
                        event.type
                    ),

                severity =
                    mapSeverity(
                        event.severity
                    ),

                message =
                    event.message,

                connectionId =
                    event.connectionId,

                packageName =
                    event.packageName,

                host =
                    event.host,

                remoteIp =
                    event.remoteIp,

                remotePort =
                    event.remotePort,

                protocol =
                    event.protocol,

                firewallDecision =
                    event.firewallDecision,

                ruleId =
                    event.ruleId,

                policyId =
                    event.policyId,

                metadata =
                    event.metadata,

                timestamp =
                    event.timestamp
            )
        }

        /**
         * Creates a security log from a network connection.
         */
        fun fromConnection(
            connection:
                NetworkConnection,
            category:
                FirewallSecurityLogCategory,
            severity:
                FirewallSecuritySeverity,
            message:
                String,
            metadata:
                Map<String, String> =
                emptyMap()
        ):
                FirewallSecurityLog {

            return FirewallSecurityLog(

                id =
                    "FW_LOG_" +
                            UUID.randomUUID()
                                .toString()
                                .replace(
                                    "-",
                                    ""
                                )
                                .take(20)
                                .uppercase(),

                category =
                    category,

                severity =
                    severity,

                message =
                    message,

                connectionId =
                    connection.id,

                packageName =
                    connection.packageName,

                host =
                    connection.host,

                remoteIp =
                    connection.remoteIp,

                remotePort =
                    connection.remotePort,

                protocol =
                    connection.protocol,

                firewallDecision =
                    connection.firewallDecision,

                ruleId =
                    connection.matchedRuleId,

                policyId =
                    null,

                metadata =
                    metadata +
                            mapOf(
                                "transport" to
                                        connection.transport.name,

                                "connectionState" to
                                        connection.state.name,

                                "threatLevel" to
                                        connection.threatLevel.name,

                                "encrypted" to
                                        connection.encrypted.toString()
                            )
            )
        }

        private fun mapEventCategory(
            type:
                FirewallEventType
        ):
                FirewallSecurityLogCategory {

            return when (
                type
            ) {

                FirewallEventType.HANDLER_STARTED,
                FirewallEventType.FIREWALL_STARTED ->
                    FirewallSecurityLogCategory
                        .FIREWALL_STARTED

                FirewallEventType.HANDLER_STOPPED,
                FirewallEventType.FIREWALL_STOPPED ->
                    FirewallSecurityLogCategory
                        .FIREWALL_STOPPED

                FirewallEventType.CONNECTION_CREATED,
                FirewallEventType.CONNECTION_ESTABLISHED ->
                    FirewallSecurityLogCategory
                        .CONNECTION_CREATED

                FirewallEventType.CONNECTION_CLOSED ->
                    FirewallSecurityLogCategory
                        .CONNECTION_CLOSED

                FirewallEventType.CONNECTION_ALLOWED ->
                    FirewallSecurityLogCategory
                        .CONNECTION_ALLOWED

                FirewallEventType.CONNECTION_BLOCKED ->
                    FirewallSecurityLogCategory
                        .CONNECTION_BLOCKED

                FirewallEventType.CONNECTION_MONITORED ->
                    FirewallSecurityLogCategory
                        .CONNECTION_MONITORED

                FirewallEventType.CONNECTION_WARNING ->
                    FirewallSecurityLogCategory
                        .CONNECTION_WARNING

                FirewallEventType.RULE_MATCHED ->
                    FirewallSecurityLogCategory
                        .RULE_MATCHED

                FirewallEventType.POLICY_MATCHED ->
                    FirewallSecurityLogCategory
                        .POLICY_MATCHED

                FirewallEventType.NETWORK_STATE_CHANGED,
                FirewallEventType.NETWORK_AVAILABLE,
                FirewallEventType.NETWORK_LOST ->
                    FirewallSecurityLogCategory
                        .NETWORK_CHANGED

                FirewallEventType.TRAFFIC_OBSERVED ->
                    FirewallSecurityLogCategory
                        .TRAFFIC_OBSERVED

                FirewallEventType.SUSPICIOUS_TRAFFIC ->
                    FirewallSecurityLogCategory
                        .SUSPICIOUS_TRAFFIC

                FirewallEventType.THREAT_DETECTED ->
                    FirewallSecurityLogCategory
                        .THREAT_DETECTED

                FirewallEventType.REPEATED_ACTIVITY ->
                    FirewallSecurityLogCategory
                        .REPEATED_ACTIVITY

                FirewallEventType.RULE_UPDATED ->
                    FirewallSecurityLogCategory
                        .RULE_CHANGED

                FirewallEventType.POLICY_UPDATED ->
                    FirewallSecurityLogCategory
                        .POLICY_CHANGED

                FirewallEventType.CONFIGURATION_CHANGED ->
                    FirewallSecurityLogCategory
                        .CONFIGURATION_CHANGED

                FirewallEventType.ERROR ->
                    FirewallSecurityLogCategory
                        .ERROR

                FirewallEventType.SECURITY_ALERT ->
                    FirewallSecurityLogCategory
                        .SECURITY_ALERT
            }
        }

        private fun mapSeverity(
            severity:
                FirewallEventSeverity
        ):
                FirewallSecuritySeverity {

            return when (
                severity
            ) {

                FirewallEventSeverity.DEBUG ->
                    FirewallSecuritySeverity.DEBUG

                FirewallEventSeverity.INFO ->
                    FirewallSecuritySeverity.INFO

                FirewallEventSeverity.LOW ->
                    FirewallSecuritySeverity.LOW

                FirewallEventSeverity.MEDIUM ->
                    FirewallSecuritySeverity.MEDIUM

                FirewallEventSeverity.HIGH ->
                    FirewallSecuritySeverity.HIGH

                FirewallEventSeverity.CRITICAL ->
                    FirewallSecuritySeverity.CRITICAL
            }
        }
    }
}

/**
 * Security-log categories.
 */
enum class FirewallSecurityLogCategory {

    FIREWALL_STARTED,

    FIREWALL_STOPPED,

    CONNECTION_CREATED,

    CONNECTION_CLOSED,

    CONNECTION_ALLOWED,

    CONNECTION_BLOCKED,

    CONNECTION_MONITORED,

    CONNECTION_WARNING,

    RULE_MATCHED,

    RULE_CHANGED,

    POLICY_MATCHED,

    POLICY_CHANGED,

    NETWORK_CHANGED,

    TRAFFIC_OBSERVED,

    SUSPICIOUS_TRAFFIC,

    THREAT_DETECTED,

    REPEATED_ACTIVITY,

    CONFIGURATION_CHANGED,

    SECURITY_ALERT,

    ERROR
}

/**
 * Security-log severity.
 */
enum class FirewallSecuritySeverity {

    DEBUG,

    INFO,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Logger configuration.
 */
data class FirewallSecurityLoggerConfiguration(

    /**
     * Maximum retained logs.
     */
    val maximumLogHistory:
        Int = 10_000,

    /**
     * Whether DEBUG logs are retained.
     */
    val recordDebugLogs:
        Boolean = false,

    /**
     * Whether INFO logs are retained.
     */
    val recordInfoLogs:
        Boolean = true,

    /**
     * Whether logs are written to Logcat.
     */
    val writeToAndroidLog:
        Boolean = true
)

/**
 * Logger operation result.
 */
data class FirewallSecurityLogOperationResult(

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
                FirewallSecurityLogOperationResult {

            return FirewallSecurityLogOperationResult(
                success =
                    true,

                message =
                    message
            )
        }

        fun failure(
            message:
                String,
            error:
                String? = null
        ):
                FirewallSecurityLogOperationResult {

            return FirewallSecurityLogOperationResult(
                success =
                    false,

                message =
                    message,

                error =
                    error
            )
        }
    }
}

/**
 * Log validation result.
 */
data class FirewallSecurityLogValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                FirewallSecurityLogValidationResult {

            return FirewallSecurityLogValidationResult(
                valid =
                    true,

                message =
                    "Security log is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                FirewallSecurityLogValidationResult {

            return FirewallSecurityLogValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Security-log statistics.
 */
data class FirewallSecurityLogStatistics(

    val totalLogs:
        Int,

    val totalRecorded:
        Long,

    val allowed:
        Long,

    val blocked:
        Long,

    val monitored:
        Long,

    val warnings:
        Long,

    val suspicious:
        Long,

    val threats:
        Long,

    val critical:
        Long,

    val errors:
        Long,

    val removed:
        Long,

    val cleared:
        Long,

    val duplicates:
        Long,

    val filtered:
        Long,

    val validationFailures:
        Long
)

/**
 * Thread-safe statistics counter.
 */
private class FirewallSecurityLogStatisticsCounter {

    private val totalRecorded =
        AtomicLong(0)

    private val allowed =
        AtomicLong(0)

    private val blocked =
        AtomicLong(0)

    private val monitored =
        AtomicLong(0)

    private val warnings =
        AtomicLong(0)

    private val suspicious =
        AtomicLong(0)

    private val threats =
        AtomicLong(0)

    private val critical =
        AtomicLong(0)

    private val errors =
        AtomicLong(0)

    private val removed =
        AtomicLong(0)

    private val cleared =
        AtomicLong(0)

    private val duplicates =
        AtomicLong(0)

    private val filtered =
        AtomicLong(0)

    private val validationFailures =
        AtomicLong(0)

    fun record(
        log:
            FirewallSecurityLog
    ) {

        totalRecorded.incrementAndGet()

        when (
            log.firewallDecision
        ) {

            FirewallDecision.ALLOW ->
                allowed.incrementAndGet()

            FirewallDecision.BLOCK ->
                blocked.incrementAndGet()

            FirewallDecision.MONITOR ->
                monitored.incrementAndGet()

            FirewallDecision.WARN ->
                warnings.incrementAndGet()

            null -> Unit
        }

        if (
            log.category ==
            FirewallSecurityLogCategory
                .SUSPICIOUS_TRAFFIC
        ) {

            suspicious.incrementAndGet()
        }

        if (
            log.category ==
            FirewallSecurityLogCategory
                .THREAT_DETECTED
        ) {

            threats.incrementAndGet()
        }

        if (
            log.severity ==
            FirewallSecuritySeverity.CRITICAL
        ) {

            critical.incrementAndGet()
        }

        if (
            log.category ==
            FirewallSecurityLogCategory
                .ERROR
        ) {

            errors.incrementAndGet()
        }
    }

    fun incrementRemoved() {
        removed.incrementAndGet()
    }

    fun incrementCleared(
        count:
            Int
    ) {

        if (
            count > 0
        ) {

            cleared.addAndGet(
                count.toLong()
            )
        }
    }

    fun incrementDuplicates() {
        duplicates.incrementAndGet()
    }

    fun incrementFilteredLogs() {
        filtered.incrementAndGet()
    }

    fun incrementValidationFailures() {
        validationFailures.incrementAndGet()
    }

    fun snapshot(
        totalLogs:
            Int
    ):
            FirewallSecurityLogStatistics {

        return FirewallSecurityLogStatistics(

            totalLogs =
                totalLogs,

            totalRecorded =
                totalRecorded.get(),

            allowed =
                allowed.get(),

            blocked =
                blocked.get(),

            monitored =
                monitored.get(),

            warnings =
                warnings.get(),

            suspicious =
                suspicious.get(),

            threats =
                threats.get(),

            critical =
                critical.get(),

            errors =
                errors.get(),

            removed =
                removed.get(),

            cleared =
                cleared.get(),

            duplicates =
                duplicates.get(),

            filtered =
                filtered.get(),

            validationFailures =
                validationFailures.get()
        )
    }
}
