package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNThreatMonitor
 *
 * Enterprise-grade threat monitoring component for the
 * SentriX VPN security subsystem.
 *
 * Responsibilities:
 *
 * - Monitor threat signals observed through VPN traffic.
 * - Aggregate multiple threat indicators.
 * - Track suspicious endpoints.
 * - Track suspicious connections.
 * - Maintain active VPN threats.
 * - Calculate cumulative threat scores.
 * - Apply configurable threat thresholds.
 * - Detect repeated suspicious activity.
 * - Detect endpoint reputation concerns.
 * - Detect anomalous traffic indicators.
 * - Track blocked/allowed threat events.
 * - Publish reactive threat state.
 * - Maintain threat history.
 * - Provide threat statistics.
 *
 * This class does NOT:
 *
 * - Perform raw packet parsing.
 * - Implement the Android VpnService.
 * - Implement firewall rules.
 * - Perform complete malware analysis.
 * - Perform complete phishing analysis.
 * - Replace the SentriX threat intelligence engine.
 *
 * Those responsibilities belong to:
 *
 * VPNService
 * VPNEngine
 * FirewallEngine
 * MalwareAnalyzer
 * PhishingAnalyzer
 * ThreatAnalysisService
 *
 * Architecture:
 *
 *                  VPNEngine
 *                     |
 *                     v
 *               VPNThreatMonitor
 *                     |
 *          ┌──────────┼──────────┐
 *          ▼          ▼          ▼
 *       Signals    Threats    Statistics
 *          |
 *          ▼
 *    Threat Analysis
 *          |
 *          ▼
 *    Security Decision
 *
 * Example:
 *
 * DNS anomaly
 *      +
 * Suspicious domain
 *      +
 * Repeated connections
 *      +
 * Abnormal traffic
 *      |
 *      v
 * VPNThreatMonitor
 *      |
 *      v
 * Aggregated threat score
 *      |
 *      ├── LOW
 *      ├── MEDIUM
 *      ├── HIGH
 *      └── CRITICAL
 */
class VPNThreatMonitor(
    context: Context,
    private val configuration:
        VPNThreatMonitorConfiguration =
        VPNThreatMonitorConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNThreatMonitor"

        private const val MAX_ACTIVE_THREATS =
            10_000

        private const val MAX_HISTORY =
            25_000

        private const val MAX_SIGNALS_PER_THREAT =
            100
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Monitoring scope.
     */
    private val monitorScope =
        CoroutineScope(
            SupervisorJob() +
                    Dispatchers.Default
        )

    /**
     * Indicates whether monitoring is enabled.
     */
    private val monitoring =
        AtomicBoolean(false)

    /**
     * Indicates whether monitor has been initialized.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Active threat map.
     */
    private val activeThreats =
        ConcurrentHashMap<
            String,
            VPNThreat
        >()

    /**
     * Threat history.
     */
    private val threatHistory =
        ConcurrentLinkedDeque<
            VPNThreat
        >()

    /**
     * Suspicious endpoint counters.
     */
    private val endpointCounters =
        ConcurrentHashMap<
            String,
            EndpointThreatCounter
        >()

    /**
     * Current threat state.
     */
    private val _state =
        MutableStateFlow(
            VPNThreatMonitorState()
        )

    /**
     * Public immutable threat state.
     */
    val state:
        StateFlow<VPNThreatMonitorState> =
        _state.asStateFlow()

    /**
     * Latest threat event.
     */
    private val _latestEvent =
        MutableStateFlow<VPNThreatEvent?>(
            null
        )

    /**
     * Public latest threat event.
     */
    val latestEvent:
        StateFlow<VPNThreatEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Statistics counter.
     */
    private val statistics =
        VPNThreatMonitorStatisticsCounter()

    /**
     * Initializes the threat monitor.
     */
    suspend fun initialize():
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNThreatMonitorOperationResult.success(
                        "VPN threat monitor is already initialized."
                    )
            }

            initialized.set(
                true
            )

            updateState {
                it.copy(
                    initialized =
                        true,

                    monitoring =
                        false
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN threat monitor initialized."
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat monitor initialized successfully."
            )
        }

    /**
     * Enables threat monitoring.
     */
    suspend fun startMonitoring():
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                monitoring.get()
            ) {

                return@withContext
                    VPNThreatMonitorOperationResult.success(
                        "VPN threat monitoring is already active."
                    )
            }

            monitoring.set(
                true
            )

            updateState {
                it.copy(
                    monitoring =
                        true,

                    monitoringStartedAt =
                        System.currentTimeMillis()
                )
            }

            statistics.incrementMonitoringStarts()

            Log.i(
                TAG,
                "VPN threat monitoring started."
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat monitoring started."
            )
        }

    /**
     * Disables threat monitoring.
     */
    suspend fun stopMonitoring():
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            monitoring.set(
                false
            )

            updateState {
                it.copy(
                    monitoring =
                        false,

                    monitoringStoppedAt =
                        System.currentTimeMillis()
                )
            }

            statistics.incrementMonitoringStops()

            Log.i(
                TAG,
                "VPN threat monitoring stopped."
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat monitoring stopped."
            )
        }

    /**
     * Registers a threat signal originating from VPN traffic.
     *
     * This is the primary entry point for VPNEngine,
     * FirewallEngine and threat-analysis components.
     */
    suspend fun registerSignal(
        signal:
            VPNThreatSignal
    ):
            VPNThreatEvaluationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                !monitoring.get()
            ) {

                return@withContext
                    VPNThreatEvaluationResult.ignored(
                        "VPN threat monitoring is currently disabled."
                    )
            }

            val validation =
                validateSignal(
                    signal
                )

            if (
                !validation.valid
            ) {

                statistics
                    .incrementInvalidSignals()

                return@withContext
                    VPNThreatEvaluationResult.rejected(
                        validation.message
                    )
            }

            statistics.incrementSignals()

            val endpoint =
                normalizeEndpoint(
                    signal.endpoint
                )

            val counter =
                endpointCounters
                    .computeIfAbsent(
                        endpoint
                    ) {
                        EndpointThreatCounter()
                    }

            counter.record(
                signal
            )

            val existingThreat =
                findMatchingThreat(
                    signal
                )

            val threat =
                if (
                    existingThreat != null
                ) {

                    mergeSignalIntoThreat(
                        existingThreat,
                        signal
                    )

                } else {

                    createThreatFromSignal(
                        signal
                    )
                }

            val storedThreat =
                storeThreat(
                    threat
                )

            evaluateThreatAction(
                storedThreat
            )

            updateAggregateState()

            VPNThreatEvaluationResult.detected(
                storedThreat
            )
        }

    /**
     * Registers multiple signals in one operation.
     */
    suspend fun registerSignals(
        signals:
            List<VPNThreatSignal>
    ):
            VPNThreatBatchEvaluationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val results =
                mutableListOf<
                    VPNThreatEvaluationResult
                    >()

            signals.forEach { signal ->

                results.add(
                    registerSignal(
                        signal
                    )
                )
            }

            VPNThreatBatchEvaluationResult(
                total =
                    signals.size,

                detected =
                    results.count {
                        it.status ==
                                VPNThreatEvaluationStatus
                                    .DETECTED
                    },

                rejected =
                    results.count {
                        it.status ==
                                VPNThreatEvaluationStatus
                                    .REJECTED
                    },

                ignored =
                    results.count {
                        it.status ==
                                VPNThreatEvaluationStatus
                                    .IGNORED
                    },

                results =
                    results
            )
        }

    /**
     * Creates a threat from a new signal.
     */
    private fun createThreatFromSignal(
        signal:
            VPNThreatSignal
    ):
            VPNThreat {

        val score =
            calculateSignalScore(
                signal
            )

        val severity =
            calculateSeverity(
                score
            )

        val now =
            System.currentTimeMillis()

        return VPNThreat(

            id =
                generateThreatId(),

            connectionId =
                signal.connectionId,

            endpoint =
                signal.endpoint,

            protocol =
                signal.protocol,

            category =
                signal.category,

            severity =
                severity,

            score =
                score,

            confidence =
                signal.confidence,

            firstSeenAt =
                now,

            lastSeenAt =
                now,

            signalCount =
                1,

            signals =
                listOf(
                    signal
                ),

            status =
                VPNThreatStatus.ACTIVE,

            action =
                VPNThreatAction.MONITOR,

            description =
                signal.description,

            source =
                signal.source,

            resolvedAt =
                null
        )
    }

    /**
     * Merges a new signal into an existing threat.
     */
    private fun mergeSignalIntoThreat(
        existing:
            VPNThreat,
        signal:
            VPNThreatSignal
    ):
            VPNThreat {

        val newScore =
            calculateMergedScore(
                existing,
                signal
            )

        val severity =
            calculateSeverity(
                newScore
            )

        val signals =
            (
                existing.signals +
                        signal
                )
                .takeLast(
                    MAX_SIGNALS_PER_THREAT
                )

        return existing.copy(

            severity =
                severity,

            score =
                newScore,

            confidence =
                maxOf(
                    existing.confidence,
                    signal.confidence
                ),

            lastSeenAt =
                System.currentTimeMillis(),

            signalCount =
                existing.signalCount + 1,

            signals =
                signals,

            description =
                signal.description
                    .takeIf {
                        it.isNotBlank()
                    }
                    ?: existing.description
        )
    }

    /**
     * Stores a threat in the active threat collection.
     */
    private fun storeThreat(
        threat:
            VPNThreat
    ):
            VPNThreat {

        activeThreats[
            threat.id
        ] =
            threat

        while (
            activeThreats.size >
            MAX_ACTIVE_THREATS
        ) {

            val oldest =
                activeThreats.values
                    .minByOrNull {
                        it.lastSeenAt
                    }

            oldest?.let {
                resolveThreat(
                    it.id,
                    "Active threat capacity limit reached."
                )
            }
        }

        updateState {
            it.copy(
                activeThreatCount =
                    activeThreats.size
            )
        }

        return threat
    }

    /**
     * Determines the correct action for a threat.
     */
    private fun evaluateThreatAction(
        threat:
            VPNThreat
    ) {

        val action =
            when {

                threat.severity ==
                        VPNThreatSeverity.CRITICAL ->
                    VPNThreatAction.BLOCK

                threat.severity ==
                        VPNThreatSeverity.HIGH ->
                    if (
                        configuration
                            .blockHighSeverityThreats
                    ) {
                        VPNThreatAction.BLOCK
                    } else {
                        VPNThreatAction.ALERT
                    }

                threat.severity ==
                        VPNThreatSeverity.MEDIUM ->
                    VPNThreatAction.ALERT

                else ->
                    VPNThreatAction.MONITOR
            }

        val updated =
            threat.copy(
                action =
                    action
            )

        activeThreats[
            threat.id
        ] =
            updated

        when (
            action
        ) {

            VPNThreatAction.BLOCK -> {

                statistics.incrementBlockedThreats()

                publishEvent(
                    VPNThreatEvent.BlockRecommended(
                        timestamp =
                            System.currentTimeMillis(),

                        threat =
                            updated
                    )
                )
            }

            VPNThreatAction.ALERT -> {

                statistics.incrementAlerts()

                publishEvent(
                    VPNThreatEvent.Alert(
                        timestamp =
                            System.currentTimeMillis(),

                        threat =
                            updated
                    )
                )
            }

            VPNThreatAction.MONITOR -> {

                statistics.incrementMonitoredThreats()

                publishEvent(
                    VPNThreatEvent.Monitored(
                        timestamp =
                            System.currentTimeMillis(),

                        threat =
                            updated
                    )
                )
            }

            VPNThreatAction.ALLOW -> {

                statistics.incrementAllowedThreats()
            }
        }
    }

    /**
     * Calculates score for an individual signal.
     */
    private fun calculateSignalScore(
        signal:
            VPNThreatSignal
    ):
            Int {

        var score =
            signal.baseScore

        score +=
            when (
                signal.confidence
            ) {

                in 0.0..0.19 ->
                    0

                in 0.20..0.49 ->
                    5

                in 0.50..0.74 ->
                    10

                in 0.75..0.89 ->
                    15

                else ->
                    20
            }

        if (
            signal.repeatedActivity
        ) {

            score +=
                configuration
                    .repeatedActivityBonus
        }

        if (
            signal.knownMaliciousIndicator
        ) {

            score +=
                configuration
                    .maliciousIndicatorBonus
        }

        if (
            signal.suspiciousDomain
        ) {

            score +=
                configuration
                    .suspiciousDomainBonus
        }

        if (
            signal.anomalousTraffic
        ) {

            score +=
                configuration
                    .trafficAnomalyBonus
        }

        return score.coerceIn(
            0,
            100
        )
    }

    /**
     * Calculates score when merging a signal into
     * an existing threat.
     */
    private fun calculateMergedScore(
        existing:
            VPNThreat,
        signal:
            VPNThreatSignal
    ):
            Int {

        val signalScore =
            calculateSignalScore(
                signal
            )

        val repeatedBonus =
            if (
                existing.signalCount >=
                configuration
                    .repeatedSignalThreshold
            ) {

                configuration
                    .repeatedSignalBonus

            } else {

                0
            }

        return (
            maxOf(
                existing.score,
                signalScore
            ) +
                    repeatedBonus
            )
            .coerceIn(
                0,
                100
            )
    }

    /**
     * Converts score into threat severity.
     */
    private fun calculateSeverity(
        score:
            Int
    ):
            VPNThreatSeverity {

        return when {

            score >=
                    configuration
                        .criticalThreshold ->
                VPNThreatSeverity.CRITICAL

            score >=
                    configuration
                        .highThreshold ->
                VPNThreatSeverity.HIGH

            score >=
                    configuration
                        .mediumThreshold ->
                VPNThreatSeverity.MEDIUM

            else ->
                VPNThreatSeverity.LOW
        }
    }

    /**
     * Finds an existing matching threat.
     */
    private fun findMatchingThreat(
        signal:
            VPNThreatSignal
    ):
            VPNThreat? {

        return activeThreats.values
            .filter {
                it.status ==
                        VPNThreatStatus.ACTIVE
            }
            .firstOrNull {

                it.connectionId ==
                        signal.connectionId &&

                        normalizeEndpoint(
                            it.endpoint
                        ) ==
                        normalizeEndpoint(
                            signal.endpoint
                        ) &&

                        it.category ==
                        signal.category
            }
    }

    /**
     * Resolves an active threat.
     */
    suspend fun resolveThreat(
        threatId:
            String,
        reason:
            String =
            "Threat resolved."
    ):
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeThreats.remove(
                    threatId
                )
                    ?: return@withContext
                        VPNThreatMonitorOperationResult.failure(
                            "VPN threat not found."
                        )

            val resolved =
                existing.copy(

                    status =
                        VPNThreatStatus.RESOLVED,

                    resolvedAt =
                        System.currentTimeMillis(),

                    action =
                        VPNThreatAction.ALLOW,

                    description =
                        reason
                )

            addToHistory(
                resolved
            )

            updateAggregateState()

            statistics.incrementResolvedThreats()

            publishEvent(
                VPNThreatEvent.Resolved(
                    timestamp =
                        System.currentTimeMillis(),

                    threat =
                        resolved,

                    reason =
                        reason
                )
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat resolved successfully."
            )
        }

    /**
     * Marks a threat as blocked.
     *
     * This method records the monitoring decision.
     * Actual traffic blocking must be performed by
     * FirewallEngine/VPNEngine.
     */
    suspend fun markThreatBlocked(
        threatId:
            String,
        reason:
            String =
            "Threat blocked by security policy."
    ):
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val threat =
                activeThreats[
                    threatId
                ]
                    ?: return@withContext
                        VPNThreatMonitorOperationResult.failure(
                            "VPN threat not found."
                        )

            val updated =
                threat.copy(
                    action =
                        VPNThreatAction.BLOCK,

                    status =
                        VPNThreatStatus.BLOCKED,

                    description =
                        reason
                )

            activeThreats[
                threatId
            ] =
                updated

            addToHistory(
                updated
            )

            statistics.incrementBlockedThreats()

            publishEvent(
                VPNThreatEvent.Blocked(
                    timestamp =
                        System.currentTimeMillis(),

                    threat =
                        updated
                )
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat marked as blocked."
            )
        }

    /**
     * Returns an active threat.
     */
    fun getThreat(
        threatId:
            String
    ):
            VPNThreat? {

        return activeThreats[
            threatId
        ]
    }

    /**
     * Returns all active threats.
     */
    fun getActiveThreats():
            List<VPNThreat> {

        return activeThreats.values
            .sortedByDescending {
                it.score
            }
    }

    /**
     * Returns active threats by severity.
     */
    fun getThreatsBySeverity(
        severity:
            VPNThreatSeverity
    ):
            List<VPNThreat> {

        return activeThreats.values
            .filter {
                it.severity ==
                        severity
            }
            .sortedByDescending {
                it.score
            }
    }

    /**
     * Returns active threats by category.
     */
    fun getThreatsByCategory(
        category:
            VPNThreatCategory
    ):
            List<VPNThreat> {

        return activeThreats.values
            .filter {
                it.category ==
                        category
            }
            .sortedByDescending {
                it.score
            }
    }

    /**
     * Returns threats associated with a connection.
     */
    fun getThreatsByConnection(
        connectionId:
            String
    ):
            List<VPNThreat> {

        return activeThreats.values
            .filter {
                it.connectionId ==
                        connectionId
            }
            .sortedByDescending {
                it.lastSeenAt
            }
    }

    /**
     * Returns threats associated with an endpoint.
     */
    fun getThreatsByEndpoint(
        endpoint:
            String
    ):
            List<VPNThreat> {

        val normalized =
            normalizeEndpoint(
                endpoint
            )

        return activeThreats.values
            .filter {
                normalizeEndpoint(
                    it.endpoint
                ) ==
                        normalized
            }
            .sortedByDescending {
                it.score
            }
    }

    /**
     * Returns recent threat history.
     */
    fun getThreatHistory(
        limit:
            Int = 100
    ):
            List<VPNThreat> {

        require(
            limit > 0
        ) {
            "Threat history limit must be greater than zero."
        }

        return threatHistory
            .take(
                limit
            )
    }

    /**
     * Returns suspicious endpoint information.
     */
    fun getSuspiciousEndpoints(
        minimumScore:
            Int =
            configuration
                .suspiciousEndpointThreshold
    ):
            List<VPNEndpointThreatSummary> {

        return endpointCounters
            .map { (endpoint, counter) ->

                VPNEndpointThreatSummary(

                    endpoint =
                        endpoint,

                    signalCount =
                        counter.signalCount.get(),

                    threatCount =
                        counter.threatCount.get(),

                    blockedCount =
                        counter.blockedCount.get(),

                    maximumScore =
                        counter.maximumScore.get(),

                    lastSeenAt =
                        counter.lastSeenAt.get()
                )
            }
            .filter {
                it.maximumScore >=
                        minimumScore
            }
            .sortedByDescending {
                it.maximumScore
            }
    }

    /**
     * Returns whether an endpoint is currently suspicious.
     */
    fun isEndpointSuspicious(
        endpoint:
            String
    ):
            Boolean {

        val summary =
            getSuspiciousEndpoints()
                .firstOrNull {
                    normalizeEndpoint(
                        it.endpoint
                    ) ==
                            normalizeEndpoint(
                                endpoint
                            )
                }

        return summary != null
    }

    /**
     * Calculates the current aggregate threat score.
     */
    fun getAggregateThreatScore():
            Int {

        return activeThreats.values
            .maxOfOrNull {
                it.score
            }
            ?: 0
    }

    /**
     * Returns current aggregate severity.
     */
    fun getAggregateSeverity():
            VPNThreatSeverity {

        return calculateSeverity(
            getAggregateThreatScore()
        )
    }

    /**
     * Returns whether immediate attention is required.
     */
    fun requiresImmediateAttention():
            Boolean {

        return activeThreats.values.any {

            it.severity ==
                    VPNThreatSeverity.CRITICAL ||

                    it.action ==
                    VPNThreatAction.BLOCK
        }
    }

    /**
     * Clears all resolved threat history.
     */
    suspend fun clearHistory():
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                threatHistory.size

            threatHistory.clear()

            statistics.incrementHistoryCleared(
                count
            )

            VPNThreatMonitorOperationResult.success(
                "VPN threat history cleared."
            )
        }

    /**
     * Clears an endpoint's accumulated counters.
     */
    suspend fun clearEndpoint(
        endpoint:
            String
    ):
            VPNThreatMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val normalized =
                normalizeEndpoint(
                    endpoint
                )

            val removed =
                endpointCounters.remove(
                    normalized
                )

            if (
                removed == null
            ) {

                return@withContext
                    VPNThreatMonitorOperationResult.failure(
                        "Endpoint was not found."
                    )
            }

            VPNThreatMonitorOperationResult.success(
                "Endpoint threat counters cleared."
            )
        }

    /**
     * Updates aggregate monitor state.
     */
    private fun updateAggregateState() {

        val threats =
            activeThreats.values

        val aggregateScore =
            threats.maxOfOrNull {
                it.score
            }
                ?: 0

        val severity =
            calculateSeverity(
                aggregateScore
            )

        updateState {
            it.copy(

                activeThreatCount =
                    threats.size,

                criticalThreatCount =
                    threats.count {
                        it.severity ==
                                VPNThreatSeverity.CRITICAL
                    },

                highThreatCount =
                    threats.count {
                        it.severity ==
                                VPNThreatSeverity.HIGH
                    },

                mediumThreatCount =
                    threats.count {
                        it.severity ==
                                VPNThreatSeverity.MEDIUM
                    },

                lowThreatCount =
                    threats.count {
                        it.severity ==
                                VPNThreatSeverity.LOW
                    },

                aggregateScore =
                    aggregateScore,

                aggregateSeverity =
                    severity,

                lastUpdatedAt =
                    System.currentTimeMillis()
            )
        }
    }

    /**
     * Adds a threat to history.
     */
    private fun addToHistory(
        threat:
            VPNThreat
    ) {

        threatHistory.addFirst(
            threat
        )

        while (
            threatHistory.size >
            MAX_HISTORY
        ) {

            threatHistory.pollLast()
        }
    }

    /**
     * Validates a threat signal.
     */
    private fun validateSignal(
        signal:
            VPNThreatSignal
    ):
            VPNThreatSignalValidationResult {

        if (
            signal.endpoint.isBlank()
        ) {

            return VPNThreatSignalValidationResult.invalid(
                "Threat signal endpoint cannot be blank."
            )
        }

        if (
            signal.baseScore !in 0..100
        ) {

            return VPNThreatSignalValidationResult.invalid(
                "Threat signal score must be between 0 and 100."
            )
        }

        if (
            signal.confidence !in 0.0..1.0
        ) {

            return VPNThreatSignalValidationResult.invalid(
                "Threat signal confidence must be between 0 and 1."
            )
        }

        if (
            signal.description.isBlank()
        ) {

            return VPNThreatSignalValidationResult.invalid(
                "Threat signal description cannot be blank."
            )
        }

        return VPNThreatSignalValidationResult.valid()
    }

    /**
     * Normalizes an endpoint for comparison.
     */
    private fun normalizeEndpoint(
        endpoint:
            String
    ):
            String {

        return endpoint
            .trim()
            .lowercase()
            .removePrefix(
                "https://"
            )
            .removePrefix(
                "http://"
            )
            .removePrefix(
                "tcp://"
            )
            .removePrefix(
                "udp://"
            )
            .trimEnd(
                '/'
            )
    }

    /**
     * Generates threat ID.
     */
    private fun generateThreatId():
            String {

        return "VPN_THREAT_" +
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
     * Updates monitor state.
     */
    private fun updateState(
        transform:
            (VPNThreatMonitorState) ->
            VPNThreatMonitorState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Publishes a threat event.
     */
    private fun publishEvent(
        event:
            VPNThreatEvent
    ) {

        _latestEvent.value =
            event

        updateState {
            it.copy(
                latestEvent =
                    event
            )
        }
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized.get()
        ) {
            "VPNThreatMonitor has not been initialized."
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
                "VPN threat monitoring operation was cancelled."
            )
        }
    }

    /**
     * Releases monitor resources.
     */
    fun close() {

        monitoring.set(
            false
        )

        monitorScope.cancel()

        activeThreats.clear()

        threatHistory.clear()

        endpointCounters.clear()

        _state.value =
            VPNThreatMonitorState()

        _latestEvent.value =
            null

        initialized.set(
            false
        )

        Log.i(
            TAG,
            "VPNThreatMonitor closed."
        )
    }
}

/**
 * Threat signal received from VPN traffic/security
 * analysis components.
 */
data class VPNThreatSignal(

    /**
     * VPN connection that produced the signal.
     */
    val connectionId:
        String? = null,

    /**
     * Suspicious endpoint.
     */
    val endpoint:
        String,

    /**
     * Protocol involved.
     */
    val protocol:
        VPNTransportProtocol =
        VPNTransportProtocol.UNKNOWN,

    /**
     * Threat category.
     */
    val category:
        VPNThreatCategory,

    /**
     * Initial threat score.
     */
    val baseScore:
        Int,

    /**
     * Detection confidence.
     */
    val confidence:
        Double,

    /**
     * Human-readable explanation.
     */
    val description:
        String,

    /**
     * Component that generated the signal.
     */
    val source:
        VPNThreatSignalSource,

    /**
     * Whether the activity is repeated.
     */
    val repeatedActivity:
        Boolean = false,

    /**
     * Whether a known malicious indicator was detected.
     */
    val knownMaliciousIndicator:
        Boolean = false,

    /**
     * Whether the endpoint/domain appears suspicious.
     */
    val suspiciousDomain:
        Boolean = false,

    /**
     * Whether traffic behavior is anomalous.
     */
    val anomalousTraffic:
        Boolean = false,

    /**
     * Optional indicator value.
     */
    val indicator:
        String? = null,

    /**
     * Optional metadata.
     */
    val metadata:
        Map<String, String> =
        emptyMap()
)

/**
 * VPN threat categories.
 */
enum class VPNThreatCategory {

    MALICIOUS_DOMAIN,

    PHISHING,

    MALWARE,

    SPYWARE,

    COMMAND_AND_CONTROL,

    BOTNET,

    SCAM,

    SUSPICIOUS_DNS,

    SUSPICIOUS_IP,

    PORT_SCAN,

    NETWORK_ANOMALY,

    DATA_EXFILTRATION,

    CREDENTIAL_THEFT,

    MAN_IN_THE_MIDDLE,

    UNAUTHORIZED_CONNECTION,

    POLICY_VIOLATION,

    UNKNOWN
}

/**
 * Source of a VPN threat signal.
 */
enum class VPNThreatSignalSource {

    VPN_ENGINE,

    FIREWALL_ENGINE,

    PHISHING_ANALYZER,

    MALWARE_ANALYZER,

    THREAT_INTELLIGENCE,

    DNS_ANALYZER,

    TRAFFIC_ANALYZER,

    BEHAVIOR_ANALYZER,

    REPUTATION_ENGINE,

    USER_REPORT,

    UNKNOWN
}

/**
 * VPN threat severity.
 */
enum class VPNThreatSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Recommended action for a VPN threat.
 *
 * This represents the monitor's recommendation/state.
 * Actual enforcement should be performed by FirewallEngine
 * or the appropriate security enforcement component.
 */
enum class VPNThreatAction {

    MONITOR,

    ALERT,

    BLOCK,

    ALLOW
}

/**
 * Current VPN threat lifecycle state.
 */
enum class VPNThreatStatus {

    ACTIVE,

    BLOCKED,

    RESOLVED
}

/**
 * Aggregated VPN threat.
 */
data class VPNThreat(

    val id:
        String,

    val connectionId:
        String?,

    val endpoint:
        String,

    val protocol:
        VPNTransportProtocol,

    val category:
        VPNThreatCategory,

    val severity:
        VPNThreatSeverity,

    val score:
        Int,

    val confidence:
        Double,

    val firstSeenAt:
        Long,

    val lastSeenAt:
        Long,

    val signalCount:
        Int,

    val signals:
        List<VPNThreatSignal>,

    val status:
        VPNThreatStatus,

    val action:
        VPNThreatAction,

    val description:
        String,

    val source:
        VPNThreatSignalSource,

    val resolvedAt:
        Long?
)

/**
 * Endpoint-level threat summary.
 */
data class VPNEndpointThreatSummary(

    val endpoint:
        String,

    val signalCount:
        Long,

    val threatCount:
        Long,

    val blockedCount:
        Long,

    val maximumScore:
        Int,

    val lastSeenAt:
        Long
)

/**
 * Endpoint threat counter.
 */
private class EndpointThreatCounter {

    val signalCount =
        AtomicLong(0)

    val threatCount =
        AtomicLong(0)

    val blockedCount =
        AtomicLong(0)

    val maximumScore =
        AtomicLong(0)

    val lastSeenAt =
        AtomicLong(0)

    fun record(
        signal:
            VPNThreatSignal
    ) {

        signalCount.incrementAndGet()

        if (
            signal.knownMaliciousIndicator ||
            signal.suspiciousDomain ||
            signal.anomalousTraffic
        ) {

            threatCount.incrementAndGet()
        }

        val score =
            signal.baseScore

        maximumScore.updateAndGet {
            maxOf(
                it,
                score
            )
        }

        lastSeenAt.set(
            System.currentTimeMillis()
        )
    }
}

/**
 * VPN threat monitor state.
 */
data class VPNThreatMonitorState(

    val initialized:
        Boolean = false,

    val monitoring:
        Boolean = false,

    val monitoringStartedAt:
        Long? = null,

    val monitoringStoppedAt:
        Long? = null,

    val activeThreatCount:
        Int = 0,

    val criticalThreatCount:
        Int = 0,

    val highThreatCount:
        Int = 0,

    val mediumThreatCount:
        Int = 0,

    val lowThreatCount:
        Int = 0,

    val aggregateScore:
        Int = 0,

    val aggregateSeverity:
        VPNThreatSeverity =
        VPNThreatSeverity.LOW,

    val lastUpdatedAt:
        Long? = null,

    val latestEvent:
        VPNThreatEvent? = null
)

/**
 * Threat monitor configuration.
 */
data class VPNThreatMonitorConfiguration(

    /**
     * Critical score threshold.
     */
    val criticalThreshold:
        Int = 90,

    /**
     * High score threshold.
     */
    val highThreshold:
        Int = 70,

    /**
     * Medium score threshold.
     */
    val mediumThreshold:
        Int = 40,

    /**
     * Whether high severity threats should be
     * recommended for blocking.
     */
    val blockHighSeverityThreats:
        Boolean = true,

    /**
     * Bonus for repeated suspicious activity.
     */
    val repeatedActivityBonus:
        Int = 10,

    /**
     * Bonus for known malicious indicators.
     */
    val maliciousIndicatorBonus:
        Int = 25,

    /**
     * Bonus for suspicious domains.
     */
    val suspiciousDomainBonus:
        Int = 15,

    /**
     * Bonus for traffic anomalies.
     */
    val trafficAnomalyBonus:
        Int = 15,

    /**
     * Additional bonus after repeated signals.
     */
    val repeatedSignalBonus:
        Int = 5,

    /**
     * Number of signals required before applying
     * repeated-signal scoring.
     */
    val repeatedSignalThreshold:
        Int = 3,

    /**
     * Score at which an endpoint becomes suspicious.
     */
    val suspiciousEndpointThreshold:
        Int = 60
)

/**
 * Threat signal validation result.
 */
data class VPNThreatSignalValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                VPNThreatSignalValidationResult {

            return VPNThreatSignalValidationResult(
                valid =
                    true,

                message =
                    "VPN threat signal is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                VPNThreatSignalValidationResult {

            return VPNThreatSignalValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Threat evaluation status.
 */
enum class VPNThreatEvaluationStatus {

    DETECTED,

    REJECTED,

    IGNORED
}

/**
 * Result of evaluating one threat signal.
 */
data class VPNThreatEvaluationResult(

    val status:
        VPNThreatEvaluationStatus,

    val threat:
        VPNThreat?,

    val message:
        String
) {

    companion object {

        fun detected(
            threat:
                VPNThreat
        ):
                VPNThreatEvaluationResult {

            return VPNThreatEvaluationResult(
                status =
                    VPNThreatEvaluationStatus
                        .DETECTED,

                threat =
                    threat,

                message =
                    "VPN threat detected."
            )
        }

        fun rejected(
            message:
                String
        ):
                VPNThreatEvaluationResult {

            return VPNThreatEvaluationResult(
                status =
                    VPNThreatEvaluationStatus
                        .REJECTED,

                threat =
                    null,

                message =
                    message
            )
        }

        fun ignored(
            message:
                String
        ):
                VPNThreatEvaluationResult {

            return VPNThreatEvaluationResult(
                status =
                    VPNThreatEvaluationStatus
                        .IGNORED,

                threat =
                    null,

                message =
                    message
            )
        }
    }
}

/**
 * Batch threat evaluation result.
 */
data class VPNThreatBatchEvaluationResult(

    val total:
        Int,

    val detected:
        Int,

    val rejected:
        Int,

    val ignored:
        Int,

    val results:
        List<VPNThreatEvaluationResult>
)

/**
 * VPN threat monitor operation result.
 */
data class VPNThreatMonitorOperationResult(

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
                VPNThreatMonitorOperationResult {

            return VPNThreatMonitorOperationResult(
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
                VPNThreatMonitorOperationResult {

            return VPNThreatMonitorOperationResult(
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
 * VPN threat events.
 */
sealed class VPNThreatEvent {

    abstract val timestamp:
        Long

    /**
     * Threat should be blocked.
     */
    data class BlockRecommended(
        override val timestamp:
            Long,
        val threat:
            VPNThreat
    ) : VPNThreatEvent()

    /**
     * Threat generated an alert.
     */
    data class Alert(
        override val timestamp:
            Long,
        val threat:
            VPNThreat
    ) : VPNThreatEvent()

    /**
     * Threat is being monitored.
     */
    data class Monitored(
        override val timestamp:
            Long,
        val threat:
            VPNThreat
    ) : VPNThreatEvent()

    /**
     * Threat was actually marked blocked.
     */
    data class Blocked(
        override val timestamp:
            Long,
        val threat:
            VPNThreat
    ) : VPNThreatEvent()

    /**
     * Threat was resolved.
     */
    data class Resolved(
        override val timestamp:
            Long,
        val threat:
            VPNThreat,
        val reason:
            String
    ) : VPNThreatEvent()
}

/**
 * Threat monitor statistics.
 */
data class VPNThreatMonitorStatistics(

    val initializations:
        Long,

    val monitoringStarts:
        Long,

    val monitoringStops:
        Long,

    val signals:
        Long,

    val invalidSignals:
        Long,

    val blockedThreats:
        Long,

    val allowedThreats:
        Long,

    val monitoredThreats:
        Long,

    val alerts:
        Long,

    val resolvedThreats:
        Long,

    val historyCleared:
        Long,

    val totalMonitoringTimeMs:
        Long
)

/**
 * Thread-safe threat monitor statistics.
 */
private class VPNThreatMonitorStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val monitoringStarts =
        AtomicLong(0)

    private val monitoringStops =
        AtomicLong(0)

    private val signals =
        AtomicLong(0)

    private val invalidSignals =
        AtomicLong(0)

    private val blockedThreats =
        AtomicLong(0)

    private val allowedThreats =
        AtomicLong(0)

    private val monitoredThreats =
        AtomicLong(0)

    private val alerts =
        AtomicLong(0)

    private val resolvedThreats =
        AtomicLong(0)

    private val historyCleared =
        AtomicLong(0)

    private val monitoringStartedAt =
        AtomicLong(0)

    private val totalMonitoringTimeMs =
        AtomicLong(0)

    fun incrementInitializations() {
        initializations.incrementAndGet()
    }

    fun incrementMonitoringStarts() {

        monitoringStarts.incrementAndGet()

        monitoringStartedAt.set(
            System.currentTimeMillis()
        )
    }

    fun incrementMonitoringStops() {

        monitoringStops.incrementAndGet()

        val started =
            monitoringStartedAt.get()

        if (
            started > 0
        ) {

            val duration =
                System.currentTimeMillis() -
                        started

            if (
                duration > 0
            ) {

                totalMonitoringTimeMs
                    .addAndGet(
                        duration
                    )
            }
        }

        monitoringStartedAt.set(
            0
        )
    }

    fun incrementSignals() {
        signals.incrementAndGet()
    }

    fun incrementInvalidSignals() {
        invalidSignals.incrementAndGet()
    }

    fun incrementBlockedThreats() {
        blockedThreats.incrementAndGet()
    }

    fun incrementAllowedThreats() {
        allowedThreats.incrementAndGet()
    }

    fun incrementMonitoredThreats() {
        monitoredThreats.incrementAndGet()
    }

    fun incrementAlerts() {
        alerts.incrementAndGet()
    }

    fun incrementResolvedThreats() {
        resolvedThreats.incrementAndGet()
    }

    fun incrementHistoryCleared(
        count:
            Int
    ) {

        if (
            count > 0
        ) {

            historyCleared.addAndGet(
                count.toLong()
            )
        }
    }

    fun snapshot():
            VPNThreatMonitorStatistics {

        return VPNThreatMonitorStatistics(

            initializations =
                initializations.get(),

            monitoringStarts =
                monitoringStarts.get(),

            monitoringStops =
                monitoringStops.get(),

            signals =
                signals.get(),

            invalidSignals =
                invalidSignals.get(),

            blockedThreats =
                blockedThreats.get(),

            allowedThreats =
                allowedThreats.get(),

            monitoredThreats =
                monitoredThreats.get(),

            alerts =
                alerts.get(),

            resolvedThreats =
                resolvedThreats.get(),

            historyCleared =
                historyCleared.get(),

            totalMonitoringTimeMs =
                totalMonitoringTimeMs.get()
        )
    }
}
