package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNEventHandler
 *
 * Centralized event handling and normalization component
 * for the SentriX VPN security subsystem.
 *
 * Responsibilities:
 *
 * - Receive VPN events.
 * - Normalize events into a common event model.
 * - Classify event severity.
 * - Assign event priority.
 * - Maintain recent event history.
 * - Publish events reactively.
 * - Track event statistics.
 * - Detect repeated critical events.
 * - Provide event filtering.
 * - Provide event acknowledgement.
 * - Provide event history management.
 *
 * Supported event sources:
 *
 * - VPNManager
 * - VPNService
 * - VPNConnectionManager
 * - VPNConfigurationManager
 * - VPNStateMonitor
 * - VPNThreatMonitor
 * - VPNNetworkMonitor
 * - VPNLeakDetector
 * - VPNSecurityChecker
 *
 * This class DOES NOT:
 *
 * - Start or stop the VPN.
 * - Modify VPN routing.
 * - Block network traffic.
 * - Fix VPN leaks.
 * - Resolve threats.
 * - Change VPN configuration.
 *
 * It is an EVENT PROCESSING component.
 *
 * Architecture:
 *
 *       VPN Components
 *             |
 *             ▼
 *       VPNEventHandler
 *             |
 *      ┌──────┼────────┐
 *      ▼      ▼        ▼
 *   Normalize Classify History
 *      │      │        │
 *      └──────┼────────┘
 *             ▼
 *       Security Events
 *             |
 *       ┌─────┴─────┐
 *       ▼           ▼
 *    UI/Alert   Security Engine
 */
class VPNEventHandler(
    context: Context,
    private val configuration:
        VPNEventHandlerConfiguration =
        VPNEventHandlerConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNEventHandler"
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Initialization state.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Event history.
     *
     * New events are inserted at the beginning.
     */
    private val eventHistory =
        ConcurrentLinkedDeque<VPNSecurityEvent>()

    /**
     * Acknowledged event IDs.
     */
    private val acknowledgedEvents =
        ConcurrentLinkedDeque<String>()

    /**
     * Latest processed event.
     */
    private val _latestEvent =
        MutableStateFlow<VPNSecurityEvent?>(null)

    /**
     * Public latest event state.
     */
    val latestEvent:
        StateFlow<VPNSecurityEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Event stream.
     *
     * Consumers such as UI, notification,
     * analytics, and security-report layers
     * can subscribe to this stream.
     */
    private val _eventStream =
        MutableSharedFlow<VPNSecurityEvent>(
            replay = 0,
            extraBufferCapacity =
                configuration.eventBufferCapacity
        )

    /**
     * Public event stream.
     */
    val eventStream:
        SharedFlow<VPNSecurityEvent> =
        _eventStream.asSharedFlow()

    /**
     * Handler state.
     */
    private val _state =
        MutableStateFlow(
            VPNEventHandlerState()
        )

    /**
     * Public handler state.
     */
    val state:
        StateFlow<VPNEventHandlerState> =
        _state.asStateFlow()

    /**
     * Statistics.
     */
    private val statistics =
        VPNEventHandlerStatisticsCounter()

    /**
     * Initializes the event handler.
     */
    suspend fun initialize():
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNEventHandlerOperationResult.success(
                        "VPN event handler is already initialized."
                    )
            }

            initialized.set(
                true
            )

            updateState {
                it.copy(
                    initialized = true
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN event handler initialized."
            )

            VPNEventHandlerOperationResult.success(
                "VPN event handler initialized successfully."
            )
        }

    /**
     * Handles a generic VPN event.
     *
     * This is the primary entry point used by
     * the other VPN components.
     */
    suspend fun handleEvent(
        event:
            VPNRawEvent
    ):
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                !configuration.enabled
            ) {

                return@withContext
                    VPNEventHandlerOperationResult.success(
                        "VPN event handling is disabled."
                    )
            }

            val securityEvent =
                normalizeEvent(
                    event
                )

            processSecurityEvent(
                securityEvent
            )

            VPNEventHandlerOperationResult.success(
                "VPN event processed successfully."
            )
        }

    /**
     * Processes an already-normalized event.
     */
    suspend fun processSecurityEvent(
        event:
            VPNSecurityEvent
    ):
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                shouldIgnoreEvent(
                    event
                )
            ) {

                statistics
                    .incrementIgnoredEvents()

                return@withContext
                    VPNEventHandlerOperationResult.success(
                        "VPN event was filtered by configuration."
                    )
            }

            addToHistory(
                event
            )

            updateStateFromEvent(
                event
            )

            statistics
                .recordEvent(
                    event
                )

            publishEvent(
                event
            )

            VPNEventHandlerOperationResult.success(
                "VPN security event processed."
            )
        }

    /**
     * Normalizes raw events into a common model.
     */
    private fun normalizeEvent(
        event:
            VPNRawEvent
    ):
            VPNSecurityEvent {

        val timestamp =
            if (
                event.timestamp > 0
            ) {

                event.timestamp

            } else {

                System.currentTimeMillis()
            }

        val severity =
            determineSeverity(
                event
            )

        val priority =
            determinePriority(
                severity
            )

        return VPNSecurityEvent(

            id =
                generateEventId(),

            timestamp =
                timestamp,

            source =
                event.source,

            type =
                event.type,

            severity =
                severity,

            priority =
                priority,

            title =
                event.title,

            description =
                event.description,

            metadata =
                event.metadata,

            requiresAttention =
                severity >=
                        VPNEventSeverity.HIGH,

            acknowledged =
                false
        )
    }

    /**
     * Determines event severity.
     */
    private fun determineSeverity(
        event:
            VPNRawEvent
    ):
            VPNEventSeverity {

        if (
            event.severity !=
            VPNEventSeverity.AUTO
        ) {

            return event.severity
        }

        return when (
            event.type
        ) {

            VPNEventType.SECURITY_BREACH,
            VPNEventType.TRAFFIC_LEAK,
            VPNEventType.DNS_LEAK,
            VPNEventType.IPV6_LEAK,
            VPNEventType.ROUTE_LEAK,
            VPNEventType.CRITICAL_THREAT,
            VPNEventType.VPN_ERROR ->
                VPNEventSeverity.CRITICAL

            VPNEventType.THREAT_DETECTED,
            VPNEventType.PUBLIC_IP_EXPOSURE,
            VPNEventType.WEBRTC_EXPOSURE,
            VPNEventType.KILL_SWITCH_DISABLED,
            VPNEventType.ENCRYPTION_WEAK,
            VPNEventType.VPN_DISCONNECTED ->
                VPNEventSeverity.HIGH

            VPNEventType.NETWORK_DEGRADED,
            VPNEventType.CONNECTION_ANOMALY,
            VPNEventType.DNS_ANOMALY,
            VPNEventType.ENDPOINT_ANOMALY,
            VPNEventType.VPN_DEGRADED,
            VPNEventType.CONFIGURATION_WARNING ->
                VPNEventSeverity.MEDIUM

            VPNEventType.VPN_CONNECTED,
            VPNEventType.VPN_STARTED,
            VPNEventType.VPN_STOPPED,
            VPNEventType.CONNECTION_OPENED,
            VPNEventType.CONNECTION_CLOSED,
            VPNEventType.NETWORK_CHANGED,
            VPNEventType.SECURITY_CHECK_COMPLETED ->
                VPNEventSeverity.LOW

            VPNEventType.INFORMATION ->
                VPNEventSeverity.INFO

            VPNEventType.UNKNOWN ->
                VPNEventSeverity.INFO
        }
    }

    /**
     * Converts severity to event priority.
     */
    private fun determinePriority(
        severity:
            VPNEventSeverity
    ):
            VPNEventPriority {

        return when (
            severity
        ) {

            VPNEventSeverity.CRITICAL ->
                VPNEventPriority.IMMEDIATE

            VPNEventSeverity.HIGH ->
                VPNEventPriority.HIGH

            VPNEventSeverity.MEDIUM ->
                VPNEventPriority.NORMAL

            VPNEventSeverity.LOW ->
                VPNEventPriority.LOW

            VPNEventSeverity.INFO ->
                VPNEventPriority.BACKGROUND

            VPNEventSeverity.AUTO ->
                VPNEventPriority.BACKGROUND
        }
    }

    /**
     * Determines whether an event should be ignored.
     */
    private fun shouldIgnoreEvent(
        event:
            VPNSecurityEvent
    ):
            Boolean {

        if (
            !configuration.enabled
        ) {

            return true
        }

        if (
            event.severity ==
            VPNEventSeverity.INFO &&
            !configuration.captureInformationalEvents
        ) {

            return true
        }

        if (
            event.severity ==
            VPNEventSeverity.LOW &&
            !configuration.captureLowSeverityEvents
        ) {

            return true
        }

        return false
    }

    /**
     * Adds event to history.
     */
    private fun addToHistory(
        event:
            VPNSecurityEvent
    ) {

        eventHistory.addFirst(
            event
        )

        while (
            eventHistory.size >
            configuration.maxHistorySize
        ) {

            eventHistory.pollLast()
        }
    }

    /**
     * Publishes event to StateFlow and SharedFlow.
     */
    private fun publishEvent(
        event:
            VPNSecurityEvent
    ) {

        _latestEvent.value =
            event

        _eventStream.tryEmit(
            event
        )

        updateState {
            it.copy(
                latestEvent =
                    event,

                lastEventAt =
                    event.timestamp,

                totalEventsProcessed =
                    it.totalEventsProcessed + 1
            )
        }

        Log.d(
            TAG,
            "VPN event processed: " +
                    "${event.type} / " +
                    "${event.severity}"
        )
    }

    /**
     * Updates state based on incoming event.
     */
    private fun updateStateFromEvent(
        event:
            VPNSecurityEvent
    ) {

        updateState {

            var state =
                it

            when (
                event.severity
            ) {

                VPNEventSeverity.CRITICAL -> {

                    state =
                        state.copy(
                            criticalEventCount =
                                state
                                    .criticalEventCount + 1
                        )
                }

                VPNEventSeverity.HIGH -> {

                    state =
                        state.copy(
                            highEventCount =
                                state
                                    .highEventCount + 1
                        )
                }

                VPNEventSeverity.MEDIUM -> {

                    state =
                        state.copy(
                            mediumEventCount =
                                state
                                    .mediumEventCount + 1
                        )
                }

                VPNEventSeverity.LOW -> {

                    state =
                        state.copy(
                            lowEventCount =
                                state
                                    .lowEventCount + 1
                        )
                }

                VPNEventSeverity.INFO,
                VPNEventSeverity.AUTO -> Unit
            }

            if (
                event.requiresAttention
            ) {

                state =
                    state.copy(
                        attentionRequiredCount =
                            state
                                .attentionRequiredCount + 1
                    )
            }

            state
        }
    }

    /**
     * Returns complete event history.
     */
    fun getEventHistory():
            List<VPNSecurityEvent> {

        return eventHistory.toList()
    }

    /**
     * Returns recent events.
     */
    fun getRecentEvents(
        limit:
            Int = 50
    ):
            List<VPNSecurityEvent> {

        require(
            limit > 0
        ) {
            "Event history limit must be greater than zero."
        }

        return eventHistory
            .take(
                limit
            )
    }

    /**
     * Returns events filtered by severity.
     */
    fun getEventsBySeverity(
        severity:
            VPNEventSeverity
    ):
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.severity ==
                        severity
            }
    }

    /**
     * Returns events filtered by type.
     */
    fun getEventsByType(
        type:
            VPNEventType
    ):
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.type ==
                        type
            }
    }

    /**
     * Returns events filtered by source.
     */
    fun getEventsBySource(
        source:
            VPNEventSource
    ):
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.source ==
                        source
            }
    }

    /**
     * Returns events requiring attention.
     */
    fun getAttentionRequiredEvents():
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.requiresAttention &&
                        !it.acknowledged
            }
    }

    /**
     * Returns critical events.
     */
    fun getCriticalEvents():
            List<VPNSecurityEvent> {

        return getEventsBySeverity(
            VPNEventSeverity.CRITICAL
        )
    }

    /**
     * Returns high-risk events.
     */
    fun getHighRiskEvents():
            List<VPNSecurityEvent> {

        return getEventsBySeverity(
            VPNEventSeverity.HIGH
        )
    }

    /**
     * Acknowledges an event.
     */
    suspend fun acknowledgeEvent(
        eventId:
            String
    ):
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val event =
                eventHistory
                    .firstOrNull {
                        it.id ==
                                eventId
                    }
                    ?: return@withContext
                        VPNEventHandlerOperationResult.failure(
                            "VPN event not found."
                        )

            acknowledgedEvents.add(
                eventId
            )

            replaceEvent(
                event.copy(
                    acknowledged =
                        true
                )
            )

            statistics
                .incrementAcknowledgedEvents()

            VPNEventHandlerOperationResult.success(
                "VPN event acknowledged."
            )
        }

    /**
     * Acknowledges all events requiring attention.
     */
    suspend fun acknowledgeAllAttentionEvents():
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val events =
                eventHistory
                    .filter {
                        it.requiresAttention &&
                                !it.acknowledged
                    }

            events.forEach { event ->

                acknowledgedEvents.add(
                    event.id
                )

                replaceEvent(
                    event.copy(
                        acknowledged =
                            true
                    )
                )

                statistics
                    .incrementAcknowledgedEvents()
            }

            VPNEventHandlerOperationResult.success(
                "${events.size} VPN event(s) acknowledged."
            )
        }

    /**
     * Replaces an event in the history.
     */
    private fun replaceEvent(
        updated:
            VPNSecurityEvent
    ) {

        val existing =
            eventHistory
                .firstOrNull {
                    it.id ==
                            updated.id
                }
                ?: return

        eventHistory.remove(
            existing
        )

        eventHistory.addFirst(
            updated
        )
    }

    /**
     * Clears event history.
     */
    suspend fun clearHistory():
            VPNEventHandlerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                eventHistory.size

            eventHistory.clear()

            acknowledgedEvents.clear()

            statistics
                .incrementClearedEvents(
                    count
                )

            updateState {
                it.copy(
                    historySize =
                        0
                )
            }

            VPNEventHandlerOperationResult.success(
                "VPN event history cleared."
            )
        }

    /**
     * Returns event count.
     */
    fun getEventCount():
            Int {

        return eventHistory.size
    }

    /**
     * Returns unacknowledged event count.
     */
    fun getUnacknowledgedEventCount():
            Int {

        return eventHistory
            .count {
                !it.acknowledged
            }
    }

    /**
     * Returns critical unacknowledged events.
     */
    fun getCriticalUnacknowledgedEvents():
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.severity ==
                        VPNEventSeverity.CRITICAL &&
                        !it.acknowledged
            }
    }

    /**
     * Detects repeated event types.
     */
    fun detectRepeatedEvents(
        type:
            VPNEventType,
        threshold:
            Int =
            configuration
                .repeatedEventThreshold
    ):
            Boolean {

        if (
            threshold <= 0
        ) {

            return false
        }

        return eventHistory
            .count {
                it.type ==
                        type
            } >=
                threshold
    }

    /**
     * Returns events occurring within a time window.
     */
    fun getEventsSince(
        timestamp:
            Long
    ):
            List<VPNSecurityEvent> {

        return eventHistory
            .filter {
                it.timestamp >=
                        timestamp
            }
    }

    /**
     * Returns statistics.
     */
    fun getStatistics():
            VPNEventHandlerStatistics {

        return statistics.snapshot()
    }

    /**
     * Returns current handler state.
     */
    fun getState():
            VPNEventHandlerState {

        return _state.value
    }

    /**
     * Clears latest event.
     */
    fun clearLatestEvent() {

        _latestEvent.value =
            null

        updateState {
            it.copy(
                latestEvent =
                    null
            )
        }
    }

    /**
     * Updates handler state.
     */
    private fun updateState(
        transform:
            (VPNEventHandlerState) ->
            VPNEventHandlerState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized.get()
        ) {
            "VPNEventHandler has not been initialized."
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
                "VPN event handling operation was cancelled."
            )
        }
    }

    /**
     * Closes the event handler.
     */
    fun close() {

        initialized.set(
            false
        )

        eventHistory.clear()

        acknowledgedEvents.clear()

        _latestEvent.value =
            null

        _state.value =
            VPNEventHandlerState()

        Log.i(
            TAG,
            "VPNEventHandler closed."
        )
    }

    /**
     * Generates event ID.
     */
    private fun generateEventId():
            String {

        return "VPN_EVENT_" +
                UUID
                    .randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(20)
                    .uppercase()
    }
}

/**
 * Raw event received from VPN components.
 *
 * Components can submit events without depending
 * on the internal normalized event representation.
 */
data class VPNRawEvent(

    val timestamp:
        Long =
        System.currentTimeMillis(),

    val source:
        VPNEventSource,

    val type:
        VPNEventType,

    val title:
        String,

    val description:
        String,

    val severity:
        VPNEventSeverity =
        VPNEventSeverity.AUTO,

    val metadata:
        Map<String, String> =
        emptyMap()
)

/**
 * Normalized VPN security event.
 */
data class VPNSecurityEvent(

    val id:
        String,

    val timestamp:
        Long,

    val source:
        VPNEventSource,

    val type:
        VPNEventType,

    val severity:
        VPNEventSeverity,

    val priority:
        VPNEventPriority,

    val title:
        String,

    val description:
        String,

    val metadata:
        Map<String, String>,

    val requiresAttention:
        Boolean,

    val acknowledged:
        Boolean
)

/**
 * VPN event source.
 */
enum class VPNEventSource {

    VPN_MANAGER,

    VPN_SERVICE,

    VPN_CONNECTION_MANAGER,

    VPN_CONFIGURATION_MANAGER,

    VPN_STATE_MONITOR,

    VPN_THREAT_MONITOR,

    VPN_NETWORK_MONITOR,

    VPN_LEAK_DETECTOR,

    VPN_SECURITY_CHECKER,

    FIREWALL,

    SYSTEM,

    UNKNOWN
}

/**
 * VPN event type.
 */
enum class VPNEventType {

    VPN_STARTED,

    VPN_CONNECTED,

    VPN_DISCONNECTED,

    VPN_STOPPED,

    VPN_ERROR,

    VPN_DEGRADED,

    VPN_PERMISSION_REQUIRED,

    NETWORK_CHANGED,

    NETWORK_DEGRADED,

    CONNECTION_OPENED,

    CONNECTION_CLOSED,

    CONNECTION_ANOMALY,

    DNS_ANOMALY,

    DNS_LEAK,

    IPV6_LEAK,

    ROUTE_LEAK,

    TRAFFIC_LEAK,

    INTERFACE_LEAK,

    PUBLIC_IP_EXPOSURE,

    WEBRTC_EXPOSURE,

    ENDPOINT_ANOMALY,

    THREAT_DETECTED,

    CRITICAL_THREAT,

    SECURITY_BREACH,

    SECURITY_CHECK_COMPLETED,

    KILL_SWITCH_DISABLED,

    ENCRYPTION_WEAK,

    CONFIGURATION_WARNING,

    INFORMATION,

    UNKNOWN
}

/**
 * Event severity.
 */
enum class VPNEventSeverity {

    AUTO,

    INFO,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Event processing priority.
 */
enum class VPNEventPriority {

    BACKGROUND,

    LOW,

    NORMAL,

    HIGH,

    IMMEDIATE
}

/**
 * Event handler configuration.
 */
data class VPNEventHandlerConfiguration(

    /**
     * Enables event processing.
     */
    val enabled:
        Boolean = true,

    /**
     * Maximum number of events retained.
     */
    val maxHistorySize:
        Int = 10_000,

    /**
     * SharedFlow buffer capacity.
     */
    val eventBufferCapacity:
        Int = 256,

    /**
     * Capture informational events.
     */
    val captureInformationalEvents:
        Boolean = true,

    /**
     * Capture low-severity events.
     */
    val captureLowSeverityEvents:
        Boolean = true,

    /**
     * Number of repeated events considered anomalous.
     */
    val repeatedEventThreshold:
        Int = 5
)

/**
 * Current event handler state.
 */
data class VPNEventHandlerState(

    val initialized:
        Boolean = false,

    val latestEvent:
        VPNSecurityEvent? = null,

    val lastEventAt:
        Long? = null,

    val totalEventsProcessed:
        Long = 0,

    val criticalEventCount:
        Long = 0,

    val highEventCount:
        Long = 0,

    val mediumEventCount:
        Long = 0,

    val lowEventCount:
        Long = 0,

    val attentionRequiredCount:
        Long = 0,

    val historySize:
        Int = 0
)

/**
 * Generic operation result.
 */
data class VPNEventHandlerOperationResult(

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
                VPNEventHandlerOperationResult {

            return VPNEventHandlerOperationResult(
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
                VPNEventHandlerOperationResult {

            return VPNEventHandlerOperationResult(
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
 * Event processing statistics.
 */
data class VPNEventHandlerStatistics(

    val initializations:
        Long,

    val totalEvents:
        Long,

    val ignoredEvents:
        Long,

    val acknowledgedEvents:
        Long,

    val clearedEvents:
        Long,

    val informationalEvents:
        Long,

    val lowSeverityEvents:
        Long,

    val mediumSeverityEvents:
        Long,

    val highSeverityEvents:
        Long,

    val criticalEvents:
        Long
)

/**
 * Thread-safe event statistics.
 */
private class VPNEventHandlerStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val totalEvents =
        AtomicLong(0)

    private val ignoredEvents =
        AtomicLong(0)

    private val acknowledgedEvents =
        AtomicLong(0)

    private val clearedEvents =
        AtomicLong(0)

    private val informationalEvents =
        AtomicLong(0)

    private val lowSeverityEvents =
        AtomicLong(0)

    private val mediumSeverityEvents =
        AtomicLong(0)

    private val highSeverityEvents =
        AtomicLong(0)

    private val criticalEvents =
        AtomicLong(0)

    fun incrementInitializations() {

        initializations.incrementAndGet()
    }

    fun incrementIgnoredEvents() {

        ignoredEvents.incrementAndGet()
    }

    fun incrementAcknowledgedEvents() {

        acknowledgedEvents.incrementAndGet()
    }

    fun incrementClearedEvents(
        count:
            Int
    ) {

        if (
            count > 0
        ) {

            clearedEvents.addAndGet(
                count.toLong()
            )
        }
    }

    fun recordEvent(
        event:
            VPNSecurityEvent
    ) {

        totalEvents.incrementAndGet()

        when (
            event.severity
        ) {

            VPNEventSeverity.INFO ->
                informationalEvents
                    .incrementAndGet()

            VPNEventSeverity.LOW ->
                lowSeverityEvents
                    .incrementAndGet()

            VPNEventSeverity.MEDIUM ->
                mediumSeverityEvents
                    .incrementAndGet()

            VPNEventSeverity.HIGH ->
                highSeverityEvents
                    .incrementAndGet()

            VPNEventSeverity.CRITICAL ->
                criticalEvents
                    .incrementAndGet()

            VPNEventSeverity.AUTO ->
                Unit
        }
    }

    fun snapshot():
            VPNEventHandlerStatistics {

        return VPNEventHandlerStatistics(

            initializations =
                initializations.get(),

            totalEvents =
                totalEvents.get(),

            ignoredEvents =
                ignoredEvents.get(),

            acknowledgedEvents =
                acknowledgedEvents.get(),

            clearedEvents =
                clearedEvents.get(),

            informationalEvents =
                informationalEvents.get(),

            lowSeverityEvents =
                lowSeverityEvents.get(),

            mediumSeverityEvents =
                mediumSeverityEvents.get(),

            highSeverityEvents =
                highSeverityEvents.get(),

            criticalEvents =
                criticalEvents.get()
        )
    }
}
