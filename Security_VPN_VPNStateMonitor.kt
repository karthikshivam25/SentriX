package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNStateMonitor
 *
 * Enterprise-grade monitoring component for the SentriX VPN
 * subsystem.
 *
 * Responsibilities:
 *
 * - Monitor VPN lifecycle state.
 * - Detect state transitions.
 * - Detect unexpected disconnections.
 * - Detect stale connections.
 * - Detect prolonged CONNECTING states.
 * - Detect repeated failures.
 * - Track service restart events.
 * - Track reconnect conditions.
 * - Monitor traffic activity.
 * - Publish reactive VPN state.
 * - Generate VPN state events.
 * - Maintain monitoring statistics.
 *
 * This class does NOT:
 *
 * - Start the VPN.
 * - Stop the VPN.
 * - Establish the TUN interface.
 * - Process packets.
 * - Perform firewall decisions.
 * - Analyze threats.
 * - Modify VPN configuration.
 *
 * Those responsibilities belong to:
 *
 * VPNManager
 * VPNService
 * VPNEngine
 * FirewallEngine
 * VPNConfigurationManager
 *
 * Architecture:
 *
 *                     VPNStateMonitor
 *                           |
 *            ┌──────────────┼──────────────┐
 *            ▼              ▼              ▼
 *       State Changes    Health Check    Events
 *            |              |              |
 *            └──────────────┼──────────────┘
 *                           ▼
 *                    VPN Monitoring UI
 *
 * Typical monitored state:
 *
 * DISCONNECTED
 *      |
 *      v
 * CONNECTING
 *      |
 *      v
 * CONNECTED
 *      |
 *      ├── healthy
 *      |
 *      ├── stale
 *      |
 *      ├── service failure
 *      |
 *      └── unexpected disconnect
 *              |
 *              v
 *           RECONNECTING
 *              |
 *              v
 *           CONNECTED
 */
class VPNStateMonitor(
    context: Context,
    private val configuration:
        VPNStateMonitorConfiguration =
        VPNStateMonitorConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNStateMonitor"
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
     * Indicates whether monitoring is active.
     */
    private val monitoring =
        AtomicBoolean(false)

    /**
     * Indicates whether the monitor has been initialized.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Current monitored state.
     */
    private val _state =
        MutableStateFlow(
            VPNMonitorState()
        )

    /**
     * Public immutable monitored state.
     */
    val state:
        StateFlow<VPNMonitorState> =
        _state.asStateFlow()

    /**
     * State events.
     */
    private val _events =
        MutableStateFlow<VPNStateEvent?>(
            null
        )

    /**
     * Latest state event.
     */
    val events:
        StateFlow<VPNStateEvent?> =
        _events.asStateFlow()

    /**
     * Current monitoring job.
     */
    @Volatile
    private var monitoringJob:
        Job? =
        null

    /**
     * Previous VPN status.
     */
    @Volatile
    private var previousStatus:
        VPNStatus =
        VPNStatus.DISCONNECTED

    /**
     * Last observed VPN state.
     */
    @Volatile
    private var lastObservedState:
        VPNManagerState =
        VPNManagerState()

    /**
     * Last time traffic was observed.
     */
    private val lastTrafficTimestamp =
        AtomicLong(0)

    /**
     * Last bytes sent value.
     */
    private val lastBytesSent =
        AtomicLong(0)

    /**
     * Last bytes received value.
     */
    private val lastBytesReceived =
        AtomicLong(0)

    /**
     * Consecutive health-check failures.
     */
    private val consecutiveFailures =
        AtomicLong(0)

    /**
     * Monitor statistics.
     */
    private val statistics =
        VPNStateMonitorStatisticsCounter()

    /**
     * Initializes the state monitor.
     */
    suspend fun initialize():
            VPNStateMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNStateMonitorOperationResult.success(
                        "VPN state monitor is already initialized."
                    )
            }

            initialized.set(
                true
            )

            previousStatus =
                VPNStatus.DISCONNECTED

            lastObservedState =
                VPNManagerState()

            updateMonitorState {
                it.copy(
                    initialized =
                        true,

                    monitoring =
                        false,

                    health =
                        VPNHealthStatus.UNKNOWN
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN state monitor initialized."
            )

            VPNStateMonitorOperationResult.success(
                "VPN state monitor initialized successfully."
            )
        }

    /**
     * Starts continuous VPN monitoring.
     */
    suspend fun startMonitoring():
            VPNStateMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                monitoring.get()
            ) {

                return@withContext
                    VPNStateMonitorOperationResult.success(
                        "VPN state monitoring is already active."
                    )
            }

            monitoring.set(
                true
            )

            updateMonitorState {
                it.copy(
                    monitoring =
                        true,

                    monitoringStartedAt =
                        System.currentTimeMillis()
                )
            }

            statistics.incrementMonitoringStarts()

            monitoringJob =
                monitorScope.launch {

                    monitoringLoop()
                }

            Log.i(
                TAG,
                "VPN state monitoring started."
            )

            VPNStateMonitorOperationResult.success(
                "VPN state monitoring started."
            )
        }

    /**
     * Stops continuous VPN monitoring.
     */
    suspend fun stopMonitoring():
            VPNStateMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            monitoring.set(
                false
            )

            monitoringJob?.cancel()

            monitoringJob =
                null

            updateMonitorState {
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
                "VPN state monitoring stopped."
            )

            VPNStateMonitorOperationResult.success(
                "VPN state monitoring stopped."
            )
        }

    /**
     * Continuously checks VPN state.
     *
     * The actual state is obtained through the supplied
     * VPNManager instance.
     */
    private suspend fun monitoringLoop() {

        while (
            monitoring.get() &&
            monitorScope.isActive
        ) {

            try {

                checkCurrentState()

            } catch (
                exception:
                    CancellationException
            ) {

                throw exception

            } catch (
                exception:
                    Exception
            ) {

                statistics.incrementMonitorErrors()

                Log.e(
                    TAG,
                    "VPN state monitoring iteration failed.",
                    exception
                )

                registerHealthFailure(
                    exception.message
                        ?: "Unknown monitoring failure."
                )
            }

            delay(
                configuration
                    .monitoringIntervalMs
                    .coerceAtLeast(
                        250L
                    )
            )
        }
    }

    /**
     * Checks the current VPN manager state.
     */
    suspend fun checkCurrentState():
            VPNStateMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val managerState =
                configuration
                    .stateProvider()
                    .getState()

            processState(
                managerState
            )

            VPNStateMonitorOperationResult.success(
                "VPN state checked successfully."
            )
        }

    /**
     * Processes an externally supplied VPN state.
     *
     * This is useful when the application already observes
     * VPNManager.state and wants to push state changes here.
     */
    suspend fun processState(
        managerState:
            VPNManagerState
    ):
            VPNStateMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val currentStatus =
                managerState.status

            val previous =
                previousStatus

            if (
                currentStatus != previous
            ) {

                handleStateTransition(
                    previousStatus =
                        previous,

                    currentStatus =
                        currentStatus,

                    state =
                        managerState
                )
            }

            updateTrafficActivity(
                managerState
            )

            evaluateHealth(
                managerState
            )

            lastObservedState =
                managerState

            previousStatus =
                currentStatus

            statistics.incrementStateChecks()

            VPNStateMonitorOperationResult.success(
                "VPN state processed."
            )
        }

    /**
     * Handles VPN state transitions.
     */
    private fun handleStateTransition(
        previousStatus:
            VPNStatus,
        currentStatus:
            VPNStatus,
        state:
            VPNManagerState
    ) {

        statistics.incrementStateTransitions()

        updateMonitorState {
            it.copy(
                previousStatus =
                    previousStatus,

                currentStatus =
                    currentStatus,

                lastStateTransitionAt =
                    System.currentTimeMillis()
            )
        }

        val event =
            when {

                currentStatus ==
                        VPNStatus.CONNECTED -> {

                    VPNStateEvent.Connected(
                        timestamp =
                            System.currentTimeMillis(),

                        sessionId =
                            state.sessionId
                    )
                }

                currentStatus ==
                        VPNStatus.DISCONNECTED &&
                        previousStatus ==
                        VPNStatus.CONNECTED -> {

                    statistics
                        .incrementUnexpectedDisconnects()

                    VPNStateEvent.UnexpectedDisconnect(
                        timestamp =
                            System.currentTimeMillis(),

                        previousStatus =
                            previousStatus,

                        reason =
                            state.lastError
                    )
                }

                currentStatus ==
                        VPNStatus.PERMISSION_REQUIRED -> {

                    VPNStateEvent.PermissionRequired(
                        timestamp =
                            System.currentTimeMillis()
                    )
                }

                currentStatus ==
                        VPNStatus.ERROR -> {

                    statistics.incrementErrors()

                    VPNStateEvent.Error(
                        timestamp =
                            System.currentTimeMillis(),

                        message =
                            state.lastError
                                ?: "VPN entered error state."
                    )
                }

                currentStatus ==
                        VPNStatus.STARTING -> {

                    VPNStateEvent.Starting(
                        timestamp =
                            System.currentTimeMillis()
                    )
                }

                currentStatus ==
                        VPNStatus.STOPPING -> {

                    VPNStateEvent.Stopping(
                        timestamp =
                            System.currentTimeMillis()
                    )
                }

                else -> {

                    VPNStateEvent.StateChanged(
                        timestamp =
                            System.currentTimeMillis(),

                        previousStatus =
                            previousStatus,

                        currentStatus =
                            currentStatus
                    )
                }
            }

        publishEvent(
            event
        )

        Log.d(
            TAG,
            "VPN state changed: " +
                    "$previousStatus -> $currentStatus"
        )
    }

    /**
     * Tracks traffic activity.
     */
    private fun updateTrafficActivity(
        state:
            VPNManagerState
    ) {

        val currentSent =
            state.bytesSent

        val currentReceived =
            state.bytesReceived

        val previousSent =
            lastBytesSent.get()

        val previousReceived =
            lastBytesReceived.get()

        val trafficChanged =
            currentSent > previousSent ||
                    currentReceived > previousReceived

        if (
            trafficChanged
        ) {

            lastTrafficTimestamp.set(
                System.currentTimeMillis()
            )

            statistics.incrementTrafficActivity()

            updateMonitorState {
                it.copy(
                    lastTrafficAt =
                        System.currentTimeMillis(),

                    trafficActive =
                        true
                )
            }
        }

        lastBytesSent.set(
            currentSent
        )

        lastBytesReceived.set(
            currentReceived
        )
    }

    /**
     * Evaluates VPN health.
     */
    private fun evaluateHealth(
        state:
            VPNManagerState
    ) {

        when (
            state.status
        ) {

            VPNStatus.CONNECTED -> {

                evaluateConnectedHealth(
                    state
                )
            }

            VPNStatus.CONNECTING,
            VPNStatus.STARTING -> {

                evaluateStartingHealth(
                    state
                )
            }

            VPNStatus.ERROR -> {

                updateHealth(
                    VPNHealthStatus.UNHEALTHY,
                    "VPN is in an error state."
                )
            }

            VPNStatus.PERMISSION_REQUIRED -> {

                updateHealth(
                    VPNHealthStatus.PERMISSION_REQUIRED,
                    "VPN permission is required."
                )
            }

            VPNStatus.STOPPING -> {

                updateHealth(
                    VPNHealthStatus.STOPPING,
                    "VPN is stopping."
                )
            }

            VPNStatus.DISCONNECTED -> {

                updateHealth(
                    VPNHealthStatus.DISCONNECTED,
                    "VPN is disconnected."
                )
            }
        }
    }

    /**
     * Evaluates health while VPN is connected.
     */
    private fun evaluateConnectedHealth(
        state:
            VPNManagerState
    ) {

        consecutiveFailures.set(
            0
        )

        val now =
            System.currentTimeMillis()

        val connectedAt =
            state.connectedAt

        if (
            connectedAt != null
        ) {

            val connectionAge =
                now -
                        connectedAt

            if (
                connectionAge >
                configuration
                    .maximumConnectionAgeMs
            ) {

                updateHealth(
                    VPNHealthStatus.STALE,
                    "VPN connection has exceeded the configured age."
                )

                publishEvent(
                    VPNStateEvent.StaleConnection(
                        timestamp =
                            now,

                        connectionAgeMs =
                            connectionAge
                    )
                )

                return
            }
        }

        val lastTraffic =
            lastTrafficTimestamp.get()

        if (
            configuration
                .requireTrafficActivity &&
            lastTraffic > 0 &&
            now - lastTraffic >
            configuration
                .maximumTrafficInactivityMs
        ) {

            updateHealth(
                VPNHealthStatus.DEGRADED,
                "VPN has not observed traffic activity recently."
            )

            publishEvent(
                VPNStateEvent.TrafficInactivity(
                    timestamp =
                        now,

                    inactivityDurationMs =
                        now - lastTraffic
                )
            )

            return
        }

        updateHealth(
            VPNHealthStatus.HEALTHY,
            "VPN connection is healthy."
        )
    }

    /**
     * Evaluates VPN startup health.
     */
    private fun evaluateStartingHealth(
        state:
            VPNManagerState
    ) {

        val now =
            System.currentTimeMillis()

        val startTime =
            state.connectedAt
                ?: state.disconnectedAt
                ?: now

        /*
         * This is intentionally conservative because
         * VPNManagerState does not currently expose an
         * explicit "startingAt" timestamp.
         */
        if (
            now -
            startTime >
            configuration
                .maximumStartupDurationMs
        ) {

            updateHealth(
                VPNHealthStatus.DEGRADED,
                "VPN startup is taking longer than expected."
            )

            publishEvent(
                VPNStateEvent.StartupTimeout(
                    timestamp =
                        now
                )
            )

            return
        }

        updateHealth(
            VPNHealthStatus.STARTING,
            "VPN is starting."
        )
    }

    /**
     * Registers a health-check failure.
     */
    private fun registerHealthFailure(
        message:
            String
    ) {

        val failures =
            consecutiveFailures
                .incrementAndGet()

        updateMonitorState {
            it.copy(
                consecutiveHealthFailures =
                    failures
            )
        }

        if (
            failures >=
            configuration
                .maximumConsecutiveFailures
        ) {

            updateHealth(
                VPNHealthStatus.UNHEALTHY,
                message
            )

            publishEvent(
                VPNStateEvent.MonitorFailure(
                    timestamp =
                        System.currentTimeMillis(),

                    consecutiveFailures =
                        failures,

                    message =
                        message
                )
            )
        }
    }

    /**
     * Updates health status.
     */
    private fun updateHealth(
        health:
            VPNHealthStatus,
        reason:
            String
    ) {

        val previous =
            _state.value.health

        updateMonitorState {
            it.copy(
                health =
                    health,

                healthReason =
                    reason,

                lastHealthCheckAt =
                    System.currentTimeMillis()
            )
        }

        if (
            previous != health
        ) {

            statistics
                .incrementHealthTransitions()

            publishEvent(
                VPNStateEvent.HealthChanged(
                    timestamp =
                        System.currentTimeMillis(),

                    previousHealth =
                        previous,

                    currentHealth =
                        health,

                    reason =
                        reason
                )
            )
        }
    }

    /**
     * Publishes a state event.
     */
    private fun publishEvent(
        event:
            VPNStateEvent
    ) {

        _events.value =
            event

        updateMonitorState {
            it.copy(
                lastEvent =
                    event,

                lastEventAt =
                    event.timestamp
            )
        }
    }

    /**
     * Returns current health status.
     */
    fun getHealthStatus():
            VPNHealthStatus {

        return _state.value.health
    }

    /**
     * Returns current monitor state.
     */
    fun getMonitorState():
            VPNMonitorState {

        return _state.value
    }

    /**
     * Returns the last observed VPNManager state.
     */
    fun getLastObservedVpnState():
            VPNManagerState {

        return lastObservedState
    }

    /**
     * Returns whether VPN is considered healthy.
     */
    fun isHealthy():
            Boolean {

        return _state.value.health ==
                VPNHealthStatus.HEALTHY
    }

    /**
     * Returns whether VPN requires attention.
     */
    fun requiresAttention():
            Boolean {

        return when (
            _state.value.health
        ) {

            VPNHealthStatus.DEGRADED,
            VPNHealthStatus.UNHEALTHY,
            VPNHealthStatus.STALE,
            VPNHealthStatus.PERMISSION_REQUIRED ->
                true

            else ->
                false
        }
    }

    /**
     * Returns whether the VPN has active traffic.
     */
    fun hasActiveTraffic():
            Boolean {

        return _state.value.trafficActive
    }

    /**
     * Returns traffic inactivity duration.
     */
    fun getTrafficInactivityDuration(
        now:
            Long =
            System.currentTimeMillis()
    ):
            Long? {

        val last =
            lastTrafficTimestamp.get()

        if (
            last <= 0
        ) {

            return null
        }

        return (
            now - last
            ).coerceAtLeast(
                0L
            )
    }

    /**
     * Returns monitoring statistics.
     */
    fun getStatistics():
            VPNStateMonitorStatistics {

        return statistics.snapshot()
    }

    /**
     * Resets traffic activity state.
     */
    fun resetTrafficActivity() {

        lastTrafficTimestamp.set(
            0
        )

        lastBytesSent.set(
            0
        )

        lastBytesReceived.set(
            0
        )

        updateMonitorState {
            it.copy(
                trafficActive =
                    false,

                lastTrafficAt =
                    null
            )
        }
    }

    /**
     * Clears the latest event.
     */
    fun clearLatestEvent() {

        _events.value =
            null

        updateMonitorState {
            it.copy(
                lastEvent =
                    null,

                lastEventAt =
                    null
            )
        }
    }

    /**
     * Updates monitor state.
     */
    private fun updateMonitorState(
        transform:
            (VPNMonitorState) ->
            VPNMonitorState
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
            "VPNStateMonitor has not been initialized."
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
                "VPN state monitoring operation was cancelled."
            )
        }
    }

    /**
     * Closes the monitor.
     */
    fun close() {

        monitoring.set(
            false
        )

        monitoringJob?.cancel()

        monitoringJob =
            null

        monitorScope.cancel()

        initialized.set(
            false
        )

        _state.value =
            VPNMonitorState()

        _events.value =
            null

        Log.i(
            TAG,
            "VPNStateMonitor closed."
        )
    }
}

/**
 * Provider abstraction used by the state monitor.
 *
 * This prevents VPNStateMonitor from being tightly coupled
 * to one concrete VPNManager implementation.
 */
fun interface VPNStateProvider {

    /**
     * Returns the latest VPN manager state.
     */
    fun getState():
        VPNManagerState
}

/**
 * Configuration for VPN state monitoring.
 */
data class VPNStateMonitorConfiguration(

    /**
     * State-check interval.
     */
    val monitoringIntervalMs:
        Long = 5_000L,

    /**
     * Maximum allowed connection age before the connection
     * is considered stale.
     *
     * This does not forcibly disconnect the VPN.
     */
    val maximumConnectionAgeMs:
        Long =
        24L *
                60L *
                60L *
                1000L,

    /**
     * Maximum time without traffic before the connection
     * is considered degraded.
     */
    val maximumTrafficInactivityMs:
        Long =
        15L *
                60L *
                1000L,

    /**
     * Maximum expected startup duration.
     */
    val maximumStartupDurationMs:
        Long =
        60_000L,

    /**
     * Whether traffic inactivity should affect health.
     */
    val requireTrafficActivity:
        Boolean = false,

    /**
     * Maximum consecutive monitor failures.
     */
    val maximumConsecutiveFailures:
        Int = 3,

    /**
     * Provider used to retrieve VPNManager state.
     *
     * It defaults to a disconnected state and should be
     * replaced through dependency injection in production.
     */
    val stateProvider:
        VPNStateProvider =
        VPNStateProvider {
            VPNManagerState()
        }
)

/**
 * Complete monitor state.
 */
data class VPNMonitorState(

    val initialized:
        Boolean = false,

    val monitoring:
        Boolean = false,

    val health:
        VPNHealthStatus =
        VPNHealthStatus.UNKNOWN,

    val previousStatus:
        VPNStatus =
        VPNStatus.DISCONNECTED,

    val currentStatus:
        VPNStatus =
        VPNStatus.DISCONNECTED,

    val monitoringStartedAt:
        Long? = null,

    val monitoringStoppedAt:
        Long? = null,

    val lastStateTransitionAt:
        Long? = null,

    val lastHealthCheckAt:
        Long? = null,

    val lastTrafficAt:
        Long? = null,

    val trafficActive:
        Boolean = false,

    val consecutiveHealthFailures:
        Long = 0,

    val healthReason:
        String? = null,

    val lastEvent:
        VPNStateEvent? = null,

    val lastEventAt:
        Long? = null
)

/**
 * VPN health status.
 */
enum class VPNHealthStatus {

    UNKNOWN,

    STARTING,

    HEALTHY,

    DEGRADED,

    STALE,

    UNHEALTHY,

    PERMISSION_REQUIRED,

    STOPPING,

    DISCONNECTED
}

/**
 * Base VPN state event.
 */
sealed class VPNStateEvent {

    /**
     * Event timestamp.
     */
    abstract val timestamp:
        Long

    /**
     * VPN entered STARTING state.
     */
    data class Starting(
        override val timestamp:
            Long
    ) : VPNStateEvent()

    /**
     * VPN entered STOPPING state.
     */
    data class Stopping(
        override val timestamp:
            Long
    ) : VPNStateEvent()

    /**
     * VPN became connected.
     */
    data class Connected(
        override val timestamp:
            Long,
        val sessionId:
            String?
    ) : VPNStateEvent()

    /**
     * VPN disconnected unexpectedly.
     */
    data class UnexpectedDisconnect(
        override val timestamp:
            Long,
        val previousStatus:
            VPNStatus,
        val reason:
            String?
    ) : VPNStateEvent()

    /**
     * VPN permission is required.
     */
    data class PermissionRequired(
        override val timestamp:
            Long
    ) : VPNStateEvent()

    /**
     * VPN entered error state.
     */
    data class Error(
        override val timestamp:
            Long,
        val message:
            String
    ) : VPNStateEvent()

    /**
     * Generic state transition.
     */
    data class StateChanged(
        override val timestamp:
            Long,
        val previousStatus:
            VPNStatus,
        val currentStatus:
            VPNStatus
    ) : VPNStateEvent()

    /**
     * VPN health changed.
     */
    data class HealthChanged(
        override val timestamp:
            Long,
        val previousHealth:
            VPNHealthStatus,
        val currentHealth:
            VPNHealthStatus,
        val reason:
            String
    ) : VPNStateEvent()

    /**
     * VPN connection became stale.
     */
    data class StaleConnection(
        override val timestamp:
            Long,
        val connectionAgeMs:
            Long
    ) : VPNStateEvent()

    /**
     * VPN traffic became inactive.
     */
    data class TrafficInactivity(
        override val timestamp:
            Long,
        val inactivityDurationMs:
            Long
    ) : VPNStateEvent()

    /**
     * VPN startup exceeded expected duration.
     */
    data class StartupTimeout(
        override val timestamp:
            Long
    ) : VPNStateEvent()

    /**
     * State monitoring itself encountered repeated failures.
     */
    data class MonitorFailure(
        override val timestamp:
            Long,
        val consecutiveFailures:
            Long,
        val message:
            String
    ) : VPNStateEvent()
}

/**
 * Generic monitor operation result.
 */
data class VPNStateMonitorOperationResult(

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
                VPNStateMonitorOperationResult {

            return VPNStateMonitorOperationResult(
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
                VPNStateMonitorOperationResult {

            return VPNStateMonitorOperationResult(
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
 * State monitor statistics.
 */
data class VPNStateMonitorStatistics(

    val initializations:
        Long,

    val monitoringStarts:
        Long,

    val monitoringStops:
        Long,

    val stateChecks:
        Long,

    val stateTransitions:
        Long,

    val healthTransitions:
        Long,

    val unexpectedDisconnects:
        Long,

    val trafficActivityEvents:
        Long,

    val errors:
        Long,

    val monitorErrors:
        Long,

    val totalMonitoringTimeMs:
        Long
)

/**
 * Thread-safe VPN state monitor statistics.
 */
private class VPNStateMonitorStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val monitoringStarts =
        AtomicLong(0)

    private val monitoringStops =
        AtomicLong(0)

    private val stateChecks =
        AtomicLong(0)

    private val stateTransitions =
        AtomicLong(0)

    private val healthTransitions =
        AtomicLong(0)

    private val unexpectedDisconnects =
        AtomicLong(0)

    private val trafficActivityEvents =
        AtomicLong(0)

    private val errors =
        AtomicLong(0)

    private val monitorErrors =
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

    fun incrementStateChecks() {
        stateChecks.incrementAndGet()
    }

    fun incrementStateTransitions() {
        stateTransitions.incrementAndGet()
    }

    fun incrementHealthTransitions() {
        healthTransitions.incrementAndGet()
    }

    fun incrementUnexpectedDisconnects() {
        unexpectedDisconnects.incrementAndGet()
    }

    fun incrementTrafficActivity() {
        trafficActivityEvents.incrementAndGet()
    }

    fun incrementErrors() {
        errors.incrementAndGet()
    }

    fun incrementMonitorErrors() {
        monitorErrors.incrementAndGet()
    }

    fun snapshot():
            VPNStateMonitorStatistics {

        return VPNStateMonitorStatistics(

            initializations =
                initializations.get(),

            monitoringStarts =
                monitoringStarts.get(),

            monitoringStops =
                monitoringStops.get(),

            stateChecks =
                stateChecks.get(),

            stateTransitions =
                stateTransitions.get(),

            healthTransitions =
                healthTransitions.get(),

            unexpectedDisconnects =
                unexpectedDisconnects.get(),

            trafficActivityEvents =
                trafficActivityEvents.get(),

            errors =
                errors.get(),

            monitorErrors =
                monitorErrors.get(),

            totalMonitoringTimeMs =
                totalMonitoringTimeMs.get()
        )
    }
}
