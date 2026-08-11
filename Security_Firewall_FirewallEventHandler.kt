package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * FirewallEventHandler
 *
 * Central event-processing component for the SentriX firewall.
 *
 * Responsibilities:
 *
 * - Receive firewall events.
 * - Validate events.
 * - Publish events to observers.
 * - Maintain current firewall event state.
 * - Maintain event statistics.
 * - Maintain bounded event history.
 * - Detect repeated blocked activity.
 * - Detect repeated suspicious activity.
 * - Correlate connection/rule/policy information.
 * - Notify registered listeners.
 * - Provide filtered event queries.
 *
 * This component DOES NOT:
 *
 * - Intercept network packets.
 * - Make firewall decisions.
 * - Modify firewall rules.
 * - Start/stop VpnService.
 *
 * Decisions belong to:
 *
 *     FirewallEngine
 *
 * Rule management belongs to:
 *
 *     FirewallRuleManager
 *
 * Policy management belongs to:
 *
 *     ConnectionPolicyManager
 *
 * Network connection tracking belongs to:
 *
 *     NetworkConnectionManager
 *
 * Event flow:
 *
 * FirewallEngine
 *       |
 *       v
 * FirewallEventHandler
 *       |
 *       ├── Event validation
 *       ├── Event history
 *       ├── Event statistics
 *       ├── Suspicious activity detection
 *       └── Event streams
 *              |
 *              ├── UI
 *              ├── Security reports
 *              ├── Threat engine
 *              └── Audit subsystem
 */
class FirewallEventHandler(
    context: Context,
    private val configuration:
        FirewallEventHandlerConfiguration =
        FirewallEventHandlerConfiguration()
) {

    companion object {

        private const val TAG =
            "FirewallEventHandler"

        private const val MAX_EVENT_HISTORY =
            10_000

        private const val MAX_LISTENERS =
            1_000

        private const val DEFAULT_QUERY_LIMIT =
            100
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Event-processing scope.
     */
    private val eventScope =
        CoroutineScope(
            SupervisorJob() +
                    Dispatchers.Default
        )

    /**
     * Indicates whether handler is active.
     */
    private val active =
        AtomicBoolean(false)

    /**
     * Event history.
     */
    private val eventHistory =
        java.util.concurrent.ConcurrentLinkedDeque<
            FirewallEvent
        >()

    /**
     * Registered listeners.
     */
    private val listeners =
        ConcurrentHashMap<
            String,
            FirewallEventListener
        >()

    /**
     * Repeated activity tracker.
     */
    private val activityTracker =
        ConcurrentHashMap<
            String,
            ActivityCounter
        >()

    /**
     * Statistics.
     */
    private val statistics =
        FirewallEventStatisticsCounter()

    /**
     * Latest event.
     */
    private val _latestEvent =
        MutableStateFlow<FirewallEvent?>(
            null
        )

    /**
     * Public latest-event state.
     */
    val latestEvent:
        StateFlow<FirewallEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Shared event stream.
     */
    private val _events =
        MutableSharedFlow<FirewallEvent>(
            replay = 0,
            extraBufferCapacity =
                configuration
                    .eventBufferCapacity
        )

    /**
     * Public event stream.
     */
    val events:
        SharedFlow<FirewallEvent> =
        _events.asSharedFlow()

    /**
     * Initializes the event handler.
     */
    suspend fun initialize():
            FirewallEventOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                active.get()
            ) {

                return@withContext
                    FirewallEventOperationResult.success(
                        "Firewall event handler is already active."
                    )
            }

            active.set(
                true
            )

            publishInternalEvent(
                type =
                    FirewallEventType.HANDLER_STARTED,

                severity =
                    FirewallEventSeverity.INFO,

                message =
                    "SentriX firewall event handler started."
            )

            Log.i(
                TAG,
                "FirewallEventHandler initialized."
            )

            FirewallEventOperationResult.success(
                "Firewall event handler initialized successfully."
            )
        }

    /**
     * Returns whether handler is active.
     */
    fun isActive():
            Boolean {

        return active.get()
    }

    /**
     * Stops the event handler.
     */
    suspend fun stop():
            FirewallEventOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !active.get()
            ) {

                return@withContext
                    FirewallEventOperationResult.success(
                        "Firewall event handler is already stopped."
                    )
            }

            active.set(
                false
            )

            publishInternalEvent(
                type =
                    FirewallEventType.HANDLER_STOPPED,

                severity =
                    FirewallEventSeverity.INFO,

                message =
                    "SentriX firewall event handler stopped."
            )

            Log.i(
                TAG,
                "FirewallEventHandler stopped."
            )

            FirewallEventOperationResult.success(
                "Firewall event handler stopped successfully."
            )
        }

    /**
     * Handles an externally generated firewall event.
     *
     * This is the primary entry point for:
     *
     * FirewallEngine
     * FirewallManager
     * NetworkConnectionManager
     * NetworkTrafficMonitor
     * ConnectionPolicyManager
     */
    suspend fun handleEvent(
        event:
            FirewallEvent
    ):
            FirewallEventOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !active.get()
            ) {

                return@withContext
                    FirewallEventOperationResult.failure(
                        "Firewall event handler is not active."
                    )
            }

            val validation =
                validateEvent(
                    event
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    FirewallEventOperationResult.failure(
                        validation.message
                    )
            }

            processEvent(
                event
            )

            FirewallEventOperationResult.success(
                "Firewall event handled successfully."
            )
        }

    /**
     * Handles multiple events.
     */
    suspend fun handleEvents(
        events:
            Collection<FirewallEvent>
    ):
            FirewallEventBatchResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            var processed =
                0

            var rejected =
                0

            val errors =
                mutableListOf<FirewallEventError>()

            for (
                event in events
            ) {

                val validation =
                    validateEvent(
                        event
                    )

                if (
                    !validation.valid
                ) {

                    rejected++

                    errors.add(
                        FirewallEventError(
                            eventId =
                                event.id,

                            reason =
                                validation.message
                        )
                    )

                    continue
                }

                processEvent(
                    event
                )

                processed++
            }

            FirewallEventBatchResult(
                processed =
                    processed,

                rejected =
                    rejected,

                errors =
                    errors
            )
        }

    /**
     * Processes an event internally.
     */
    private suspend fun processEvent(
        event:
            FirewallEvent
    ) {

        /*
         * Add to history.
         */
        eventHistory.addFirst(
            event
        )

        trimHistory()

        /*
         * Update latest event.
         */
        _latestEvent.emit(
            event
        )

        /*
         * Update statistics.
         */
        statistics.record(
            event
        )

        /*
         * Track repeated activity.
         */
        updateActivityTracking(
            event
        )

        /*
         * Publish event.
         */
        _events.emit(
            event
        )

        /*
         * Notify registered listeners.
         */
        notifyListeners(
            event
        )

        Log.d(
            TAG,
            "Firewall event handled: " +
                    "${event.type}, " +
                    "${event.severity}, " +
                    "${event.message}"
        )
    }

    /**
     * Registers an event listener.
     */
    fun registerListener(
        listener:
            FirewallEventListener
    ):
            FirewallEventListenerRegistrationResult {

        if (
            listeners.size >=
            MAX_LISTENERS
        ) {

            return FirewallEventListenerRegistrationResult.failure(
                "Maximum listener count reached."
            )
        }

        val listenerId =
            "LISTENER_" +
                    UUID.randomUUID()
                        .toString()
                        .replace(
                            "-",
                            ""
                        )
                        .take(16)
                        .uppercase()

        listeners[
            listenerId
        ] =
            listener

        return FirewallEventListenerRegistrationResult.success(
            listenerId
        )
    }

    /**
     * Removes a listener.
     */
    fun unregisterListener(
        listenerId:
            String
    ):
            Boolean {

        return listeners.remove(
            listenerId
        ) != null
    }

    /**
     * Notifies listeners.
     */
    private fun notifyListeners(
        event:
            FirewallEvent
    ) {

        listeners.values
            .forEach { listener ->

                eventScope.launch {

                    try {

                        listener.onFirewallEvent(
                            event
                        )

                    } catch (
                        exception: Exception
                    ) {

                        Log.e(
                            TAG,
                            "Firewall event listener failed.",
                            exception
                        )
                    }
                }
            }
    }

    /**
     * Tracks repeated activity.
     */
    private fun updateActivityTracking(
        event:
            FirewallEvent
    ) {

        val key =
            buildActivityKey(
                event
            )
                ?: return

        val now =
            System.currentTimeMillis()

        val existing =
            activityTracker[
                key
            ]

        if (
            existing == null ||
            now -
            existing.windowStart >
            configuration
                .repetitionWindowMs
        ) {

            activityTracker[
                key
            ] =
                ActivityCounter(
                    count =
                        1,

                    windowStart =
                        now,

                    lastUpdated =
                        now
                )

            return
        }

        val updatedCount =
            existing.count +
                    1

        activityTracker[
            key
        ] =
            existing.copy(
                count =
                    updatedCount,

                lastUpdated =
                    now
            )

        /*
         * Detect repeated blocked/suspicious activity.
         */
        if (
            updatedCount >=
            configuration
                .repetitionThreshold
        ) {

            handleRepeatedActivity(
                event,
                updatedCount
            )

            activityTracker.remove(
                key
            )
        }
    }

    /**
     * Handles repeated suspicious activity.
     */
    private fun handleRepeatedActivity(
        event:
            FirewallEvent,
        count:
            Int
    ) {

        statistics.incrementRepeatedActivity()

        eventScope.launch {

            val repeatedEvent =
                FirewallEvent(

                    id =
                        generateEventId(),

                    type =
                        FirewallEventType
                            .REPEATED_ACTIVITY,

                    severity =
                        FirewallEventSeverity
                            .HIGH,

                    message =
                        "Repeated firewall activity detected " +
                                "(${count} events within the configured window).",

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
                        mapOf(
                            "repeatCount" to
                                    count.toString(),

                            "originalEventType" to
                                    event.type.name
                        )
                )

            /*
             * Prevent recursive repeated-activity detection.
             */
            eventHistory.addFirst(
                repeatedEvent
            )

            trimHistory()

            _latestEvent.emit(
                repeatedEvent
            )

            statistics.record(
                repeatedEvent
            )

            _events.emit(
                repeatedEvent
            )

            notifyListeners(
                repeatedEvent
            )
        }
    }

    /**
     * Builds an activity tracking key.
     */
    private fun buildActivityKey(
        event:
            FirewallEvent
    ): String? {

        val host =
            event.host
                ?.trim()
                ?.lowercase()

        val packageName =
            event.packageName
                ?.trim()
                ?.lowercase()

        if (
            host == null &&
            packageName == null
        ) {

            return null
        }

        return listOf(
            event.type.name,
            packageName ?: "",
            host ?: "",
            event.remoteIp ?: "",
            event.remotePort?.toString() ?: ""
        ).joinToString(
            "|"
        )
    }

    /**
     * Returns all event history.
     */
    fun getAllEvents():
            List<FirewallEvent> {

        return eventHistory.toList()
    }

    /**
     * Returns recent events.
     */
    fun getRecentEvents(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        require(
            limit > 0
        ) {
            "Event limit must be greater than zero."
        }

        return eventHistory
            .take(
                limit
            )
    }

    /**
     * Returns events of a specific type.
     */
    fun getEventsByType(
        type:
            FirewallEventType,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.type == type
            }
            .take(
                limit
            )
    }

    /**
     * Returns events with a specific severity.
     */
    fun getEventsBySeverity(
        severity:
            FirewallEventSeverity,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.severity == severity
            }
            .take(
                limit
            )
    }

    /**
     * Returns blocked events.
     */
    fun getBlockedEvents(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {

                it.firewallDecision ==
                        FirewallDecision.BLOCK ||
                        it.type ==
                        FirewallEventType
                            .CONNECTION_BLOCKED
            }
            .take(
                limit
            )
    }

    /**
     * Returns suspicious events.
     */
    fun getSuspiciousEvents(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {

                it.severity ==
                        FirewallEventSeverity.HIGH ||
                        it.severity ==
                        FirewallEventSeverity.CRITICAL ||
                        it.type ==
                        FirewallEventType
                            .SUSPICIOUS_TRAFFIC
            }
            .take(
                limit
            )
    }

    /**
     * Returns events associated with an application.
     */
    fun getEventsByPackage(
        packageName:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
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
     * Returns events associated with a connection.
     */
    fun getEventsByConnection(
        connectionId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.connectionId ==
                        connectionId
            }
            .take(
                limit
            )
    }

    /**
     * Returns events associated with a firewall rule.
     */
    fun getEventsByRule(
        ruleId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.ruleId ==
                        ruleId
            }
            .take(
                limit
            )
    }

    /**
     * Returns events associated with a policy.
     */
    fun getEventsByPolicy(
        policyId:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.policyId ==
                        policyId
            }
            .take(
                limit
            )
    }

    /**
     * Searches event messages and metadata.
     */
    fun searchEvents(
        query:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        if (
            query.isBlank()
        ) {

            return getRecentEvents(
                limit
            )
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return eventHistory
            .filter { event ->

                event.message
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        event.host
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        event.remoteIp
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        event.packageName
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        event.id
                            .lowercase()
                            .contains(
                                normalized
                            )
            }
            .take(
                limit
            )
    }

    /**
     * Returns events occurring after a timestamp.
     */
    fun getEventsSince(
        timestamp:
            Long,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<FirewallEvent> {

        return eventHistory
            .filter {
                it.timestamp >=
                        timestamp
            }
            .take(
                limit
            )
    }

    /**
     * Returns event statistics.
     */
    fun getStatistics():
            FirewallEventStatistics {

        return statistics.snapshot(
            historySize =
                eventHistory.size,

            listenerCount =
                listeners.size
        )
    }

    /**
     * Clears event history.
     */
    fun clearHistory() {

        eventHistory.clear()

        activityTracker.clear()

        statistics.incrementHistoryClear()
    }

    /**
     * Trims history to configured size.
     */
    private fun trimHistory() {

        val maximum =
            minOf(
                configuration
                    .maximumHistorySize,

                MAX_EVENT_HISTORY
            )

        while (
            eventHistory.size >
            maximum
        ) {

            eventHistory.pollLast()
        }
    }

    /**
     * Validates an event.
     */
    fun validateEvent(
        event:
            FirewallEvent
    ):
            FirewallEventValidationResult {

        if (
            event.id.isBlank()
        ) {

            return FirewallEventValidationResult.invalid(
                "Firewall event ID cannot be blank."
            )
        }

        if (
            event.message.isBlank()
        ) {

            return FirewallEventValidationResult.invalid(
                "Firewall event message cannot be blank."
            )
        }

        if (
            event.remotePort != null &&
            event.remotePort !in 1..65535
        ) {

            return FirewallEventValidationResult.invalid(
                "Remote port must be between 1 and 65535."
            )
        }

        if (
            event.timestamp <= 0
        ) {

            return FirewallEventValidationResult.invalid(
                "Firewall event timestamp is invalid."
            )
        }

        return FirewallEventValidationResult.valid()
    }

    /**
     * Creates and handles a connection event.
     */
    suspend fun handleConnectionEvent(
        type:
            FirewallEventType,
        connection:
            NetworkConnection,
        message:
            String,
        severity:
            FirewallEventSeverity =
            FirewallEventSeverity.INFO
    ):
            FirewallEventOperationResult {

        val event =
            FirewallEvent.fromConnection(
                type =
                    type,

                connection =
                    connection,

                message =
                    message,

                severity =
                    severity
            )

        return handleEvent(
            event
        )
    }

    /**
     * Creates and handles a firewall decision event.
     */
    suspend fun handleFirewallDecision(
        request:
            FirewallNetworkRequest,
        result:
            FirewallEvaluationResult
    ):
            FirewallEventOperationResult {

        val type =
            when (
                result.decision
            ) {

                FirewallDecision.ALLOW ->
                    FirewallEventType
                        .CONNECTION_ALLOWED

                FirewallDecision.BLOCK ->
                    FirewallEventType
                        .CONNECTION_BLOCKED

                FirewallDecision.MONITOR ->
                    FirewallEventType
                        .CONNECTION_MONITORED

                FirewallDecision.WARN ->
                    FirewallEventType
                        .CONNECTION_WARNING
            }

        val severity =
            when (
                result.decision
            ) {

                FirewallDecision.ALLOW ->
                    FirewallEventSeverity.INFO

                FirewallDecision.BLOCK ->
                    FirewallEventSeverity.MEDIUM

                FirewallDecision.MONITOR ->
                    FirewallEventSeverity.LOW

                FirewallDecision.WARN ->
                    FirewallEventSeverity.HIGH
            }

        val event =
            FirewallEvent(
                id =
                    generateEventId(),

                type =
                    type,

                severity =
                    severity,

                message =
                    result.reason,

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
                        ?.id
            )

        return handleEvent(
            event
        )
    }

    /**
     * Creates a network-change event.
     */
    suspend fun handleNetworkChange(
        state:
            NetworkEnvironmentState
    ):
            FirewallEventOperationResult {

        val event =
            FirewallEvent(
                id =
                    generateEventId(),

                type =
                    FirewallEventType
                        .NETWORK_STATE_CHANGED,

                severity =
                    if (
                        state.connected &&
                        state.internetAvailable
                    ) {
                        FirewallEventSeverity.INFO
                    } else {
                        FirewallEventSeverity.MEDIUM
                    },

                message =
                    "Network state changed: " +
                            "connected=${state.connected}, " +
                            "transport=${state.currentTransport}, " +
                            "validated=${state.validated}, " +
                            "vpn=${state.vpnActive}."
            )

        return handleEvent(
            event
        )
    }

    /**
     * Generates event ID.
     */
    private fun generateEventId():
            String {

        return "FW_EVENT_" +
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
     * Releases resources.
     */
    fun close() {

        active.set(
            false
        )

        eventHistory.clear()

        activityTracker.clear()

        listeners.clear()

        eventScope.cancel()

        Log.i(
            TAG,
            "FirewallEventHandler closed."
        )
    }

    /**
     * Creates an internal lifecycle event.
     */
    private suspend fun publishInternalEvent(
        type:
            FirewallEventType,
        severity:
            FirewallEventSeverity,
        message:
            String
    ) {

        val event =
            FirewallEvent(
                id =
                    generateEventId(),

                type =
                    type,

                severity =
                    severity,

                message =
                    message
            )

        eventHistory.addFirst(
            event
        )

        trimHistory()

        _latestEvent.emit(
            event
        )

        statistics.record(
            event
        )

        _events.emit(
            event
        )

        notifyListeners(
            event
        )
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
                "Firewall event operation was cancelled."
            )
        }
    }
}

/**
 * Firewall event.
 */
data class FirewallEvent(

    /**
     * Unique event identifier.
     */
    val id:
        String,

    /**
     * Event category.
     */
    val type:
        FirewallEventType,

    /**
     * Event severity.
     */
    val severity:
        FirewallEventSeverity,

    /**
     * Human-readable event description.
     */
    val message:
        String,

    /**
     * Associated network connection.
     */
    val connectionId:
        String? = null,

    /**
     * Associated Android package.
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
     * Additional metadata.
     */
    val metadata:
        Map<String, String> =
        emptyMap(),

    /**
     * Event timestamp.
     */
    val timestamp:
        Long =
        System.currentTimeMillis()
) {

    companion object {

        /**
         * Creates an event from a network connection.
         */
        fun fromConnection(
            type:
                FirewallEventType,
            connection:
                NetworkConnection,
            message:
                String,
            severity:
                FirewallEventSeverity
        ):
                FirewallEvent {

            return FirewallEvent(

                id =
                    "FW_EVENT_" +
                            UUID.randomUUID()
                                .toString()
                                .replace(
                                    "-",
                                    ""
                                )
                                .take(20)
                                .uppercase(),

                type =
                    type,

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

                metadata =
                    mapOf(
                        "transport" to
                                connection.transport.name,

                        "state" to
                                connection.state.name,

                        "threatLevel" to
                                connection.threatLevel.name
                    )
            )
        }
    }
}

/**
 * Firewall event categories.
 */
enum class FirewallEventType {

    HANDLER_STARTED,

    HANDLER_STOPPED,

    FIREWALL_STARTED,

    FIREWALL_STOPPED,

    CONNECTION_CREATED,

    CONNECTION_ESTABLISHED,

    CONNECTION_CLOSED,

    CONNECTION_ALLOWED,

    CONNECTION_BLOCKED,

    CONNECTION_MONITORED,

    CONNECTION_WARNING,

    RULE_MATCHED,

    POLICY_MATCHED,

    NETWORK_STATE_CHANGED,

    NETWORK_AVAILABLE,

    NETWORK_LOST,

    TRAFFIC_OBSERVED,

    SUSPICIOUS_TRAFFIC,

    THREAT_DETECTED,

    REPEATED_ACTIVITY,

    RULE_UPDATED,

    POLICY_UPDATED,

    CONFIGURATION_CHANGED,

    ERROR,

    SECURITY_ALERT
}

/**
 * Firewall event severity.
 */
enum class FirewallEventSeverity {

    DEBUG,

    INFO,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Event listener.
 */
fun interface FirewallEventListener {

    suspend fun onFirewallEvent(
        event:
            FirewallEvent
    )
}

/**
 * Listener registration result.
 */
data class FirewallEventListenerRegistrationResult(

    val success:
        Boolean,

    val listenerId:
        String?,

    val message:
        String
) {

    companion object {

        fun success(
            listenerId:
                String
        ):
                FirewallEventListenerRegistrationResult {

            return FirewallEventListenerRegistrationResult(
                success =
                    true,

                listenerId =
                    listenerId,

                message =
                    "Firewall event listener registered."
            )
        }

        fun failure(
            message:
                String
        ):
                FirewallEventListenerRegistrationResult {

            return FirewallEventListenerRegistrationResult(
                success =
                    false,

                listenerId =
                    null,

                message =
                    message
            )
        }
    }
}

/**
 * Event validation result.
 */
data class FirewallEventValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                FirewallEventValidationResult {

            return FirewallEventValidationResult(
                valid =
                    true,

                message =
                    "Firewall event is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                FirewallEventValidationResult {

            return FirewallEventValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Generic event operation result.
 */
data class FirewallEventOperationResult(

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
                FirewallEventOperationResult {

            return FirewallEventOperationResult(
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
                FirewallEventOperationResult {

            return FirewallEventOperationResult(
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
 * Batch event processing result.
 */
data class FirewallEventBatchResult(

    val processed:
        Int,

    val rejected:
        Int,

    val errors:
        List<FirewallEventError>
)

/**
 * Event processing error.
 */
data class FirewallEventError(

    val eventId:
        String,

    val reason:
        String
)

/**
 * Event-handler configuration.
 */
data class FirewallEventHandlerConfiguration(

    /**
     * Maximum event history.
     */
    val maximumHistorySize:
        Int = 5_000,

    /**
     * SharedFlow buffer.
     */
    val eventBufferCapacity:
        Int = 256,

    /**
     * Time window used for repeated activity detection.
     */
    val repetitionWindowMs:
        Long =
        60_000L,

    /**
     * Number of repeated events that triggers a
     * REPEATED_ACTIVITY event.
     */
    val repetitionThreshold:
        Int = 5
)

/**
 * Event statistics.
 */
data class FirewallEventStatistics(

    val historySize:
        Int,

    val listenerCount:
        Int,

    val totalEvents:
        Long,

    val allowedEvents:
        Long,

    val blockedEvents:
        Long,

    val monitoredEvents:
        Long,

    val warningEvents:
        Long,

    val suspiciousEvents:
        Long,

    val threatEvents:
        Long,

    val repeatedActivityEvents:
        Long,

    val errors:
        Long,

    val validationFailures:
        Long,

    val historyClears:
        Long
)

/**
 * Internal activity counter.
 */
private data class ActivityCounter(

    val count:
        Int,

    val windowStart:
        Long,

    val lastUpdated:
        Long
)

/**
 * Thread-safe event statistics counter.
 */
private class FirewallEventStatisticsCounter {

    private val totalEvents =
        AtomicLong(0)

    private val allowedEvents =
        AtomicLong(0)

    private val blockedEvents =
        AtomicLong(0)

    private val monitoredEvents =
        AtomicLong(0)

    private val warningEvents =
        AtomicLong(0)

    private val suspiciousEvents =
        AtomicLong(0)

    private val threatEvents =
        AtomicLong(0)

    private val repeatedActivityEvents =
        AtomicLong(0)

    private val errors =
        AtomicLong(0)

    private val validationFailures =
        AtomicLong(0)

    private val historyClears =
        AtomicLong(0)

    fun record(
        event:
            FirewallEvent
    ) {

        totalEvents.incrementAndGet()

        when (
            event.firewallDecision
        ) {

            FirewallDecision.ALLOW ->
                allowedEvents.incrementAndGet()

            FirewallDecision.BLOCK ->
                blockedEvents.incrementAndGet()

            FirewallDecision.MONITOR ->
                monitoredEvents.incrementAndGet()

            FirewallDecision.WARN ->
                warningEvents.incrementAndGet()

            null -> Unit
        }

        if (
            event.type ==
            FirewallEventType.SUSPICIOUS_TRAFFIC ||
            event.severity ==
            FirewallEventSeverity.HIGH ||
            event.severity ==
            FirewallEventSeverity.CRITICAL
        ) {

            suspiciousEvents.incrementAndGet()
        }

        if (
            event.type ==
            FirewallEventType.THREAT_DETECTED
        ) {

            threatEvents.incrementAndGet()
        }

        if (
            event.type ==
            FirewallEventType.REPEATED_ACTIVITY
        ) {

            repeatedActivityEvents.incrementAndGet()
        }

        if (
            event.type ==
            FirewallEventType.ERROR
        ) {

            errors.incrementAndGet()
        }
    }

    fun incrementValidationFailures() {
        validationFailures.incrementAndGet()
    }

    fun incrementHistoryClear() {
        historyClears.incrementAndGet()
    }

    fun incrementRepeatedActivity() {
        repeatedActivityEvents.incrementAndGet()
    }

    fun snapshot(
        historySize:
            Int,
        listenerCount:
            Int
    ):
            FirewallEventStatistics {

        return FirewallEventStatistics(

            historySize =
                historySize,

            listenerCount =
                listenerCount,

            totalEvents =
                totalEvents.get(),

            allowedEvents =
                allowedEvents.get(),

            blockedEvents =
                blockedEvents.get(),

            monitoredEvents =
                monitoredEvents.get(),

            warningEvents =
                warningEvents.get(),

            suspiciousEvents =
                suspiciousEvents.get(),

            threatEvents =
                threatEvents.get(),

            repeatedActivityEvents =
                repeatedActivityEvents.get(),

            errors =
                errors.get(),

            validationFailures =
                validationFailures.get(),

            historyClears =
                historyClears.get()
        )
    }
}
