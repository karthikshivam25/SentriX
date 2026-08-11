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
import kotlinx.coroutines.isActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNNetworkMonitor
 *
 * Enterprise-grade network monitoring component for SentriX.
 *
 * Responsibilities:
 *
 * - Monitor VPN network connections.
 * - Track active network connections.
 * - Track endpoints.
 * - Track protocols.
 * - Track bytes transmitted/received.
 * - Track packet counts.
 * - Track DNS activity.
 * - Detect network changes.
 * - Detect bandwidth spikes.
 * - Detect unusual connection counts.
 * - Detect repeated endpoint connections.
 * - Maintain network activity history.
 * - Publish network monitoring events.
 * - Expose reactive network statistics.
 *
 * This class does NOT:
 *
 * - Create the VPN tunnel.
 * - Modify Android routing.
 * - Block connections.
 * - Perform final threat classification.
 * - Replace FirewallEngine.
 * - Replace VPNThreatMonitor.
 *
 * Architecture:
 *
 *                       VPNService
 *                           |
 *                           v
 *                       VPNEngine
 *                           |
 *                           v
 *                    VPNNetworkMonitor
 *                           |
 *             ┌─────────────┼─────────────┐
 *             ▼             ▼             ▼
 *        Connections     Traffic       Network
 *          Tracking      Metrics       Events
 *             |             |             |
 *             └─────────────┼─────────────┘
 *                           ▼
 *                  VPNThreatMonitor
 *                           |
 *                           ▼
 *                     Security Engine
 */
class VPNNetworkMonitor(
    context: Context,
    private val configuration:
        VPNNetworkMonitorConfiguration =
        VPNNetworkMonitorConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNNetworkMonitor"

        private const val MAX_CONNECTIONS =
            20_000

        private const val MAX_HISTORY =
            50_000

        private const val MAX_ENDPOINTS =
            20_000
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
     * Indicates whether the monitor is active.
     */
    private val monitoring =
        AtomicBoolean(false)

    /**
     * Indicates initialization state.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Active network connections.
     */
    private val activeConnections =
        ConcurrentHashMap<
            String,
            VPNNetworkConnection
        >()

    /**
     * Endpoint statistics.
     */
    private val endpointStatistics =
        ConcurrentHashMap<
            String,
            VPNEndpointNetworkStatistics
        >()

    /**
     * Network activity history.
     */
    private val activityHistory =
        ConcurrentLinkedDeque<
            VPNNetworkActivity
        >()

    /**
     * Network events.
     */
    private val _latestEvent =
        MutableStateFlow<VPNNetworkEvent?>(
            null
        )

    /**
     * Public network events.
     */
    val latestEvent:
        StateFlow<VPNNetworkEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Current network state.
     */
    private val _state =
        MutableStateFlow(
            VPNNetworkMonitorState()
        )

    /**
     * Public network state.
     */
    val state:
        StateFlow<VPNNetworkMonitorState> =
        _state.asStateFlow()

    /**
     * Statistics.
     */
    private val statistics =
        VPNNetworkMonitorStatisticsCounter()

    /**
     * Monitoring job.
     */
    @Volatile
    private var monitoringJob:
        kotlinx.coroutines.Job? =
        null

    /**
     * Last total bytes sent.
     */
    private val previousBytesSent =
        AtomicLong(0)

    /**
     * Last total bytes received.
     */
    private val previousBytesReceived =
        AtomicLong(0)

    /**
     * Last monitoring timestamp.
     */
    private val lastMeasurementAt =
        AtomicLong(
            System.currentTimeMillis()
        )

    /**
     * Initializes the network monitor.
     */
    suspend fun initialize():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNNetworkMonitorOperationResult.success(
                        "VPN network monitor is already initialized."
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
                        false,

                    health =
                        VPNNetworkHealth.UNKNOWN
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN network monitor initialized."
            )

            VPNNetworkMonitorOperationResult.success(
                "VPN network monitor initialized successfully."
            )
        }

    /**
     * Starts continuous monitoring.
     */
    suspend fun startMonitoring():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                monitoring.get()
            ) {

                return@withContext
                    VPNNetworkMonitorOperationResult.success(
                        "VPN network monitoring is already active."
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

            monitoringJob =
                monitorScope.launch {

                    monitoringLoop()
                }

            Log.i(
                TAG,
                "VPN network monitoring started."
            )

            VPNNetworkMonitorOperationResult.success(
                "VPN network monitoring started."
            )
        }

    /**
     * Stops continuous monitoring.
     */
    suspend fun stopMonitoring():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            monitoring.set(
                false
            )

            monitoringJob?.cancel()

            monitoringJob =
                null

            updateState {
                it.copy(
                    monitoring =
                        false,

                    monitoringStoppedAt =
                        System.currentTimeMillis()
                )
            }

            statistics.incrementMonitoringStops()

            VPNNetworkMonitorOperationResult.success(
                "VPN network monitoring stopped."
            )
        }

    /**
     * Continuous monitoring loop.
     *
     * The provider is intentionally abstract so that
     * VPNEngine can provide real network measurements.
     */
    private suspend fun monitoringLoop() {

        while (
            monitoring.get() &&
            monitorScope.isActive
        ) {

            try {

                collectNetworkSnapshot()

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
                    "VPN network monitoring iteration failed.",
                    exception
                )

                publishEvent(
                    VPNNetworkEvent.MonitorError(
                        timestamp =
                            System.currentTimeMillis(),

                        message =
                            exception.message
                                ?: "Unknown network monitor error."
                    )
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
     * Collects a network snapshot.
     */
    suspend fun collectNetworkSnapshot():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val snapshot =
                configuration
                    .networkProvider
                    .getSnapshot()

            processSnapshot(
                snapshot
            )

            VPNNetworkMonitorOperationResult.success(
                "VPN network snapshot processed."
            )
        }

    /**
     * Processes an externally supplied network snapshot.
     */
    suspend fun processSnapshot(
        snapshot:
            VPNNetworkSnapshot
    ):
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            validateSnapshot(
                snapshot
            ).let {

                if (
                    !it.valid
                ) {

                    statistics
                        .incrementInvalidSnapshots()

                    return@withContext
                        VPNNetworkMonitorOperationResult.failure(
                            it.message
                        )
                }
            }

            updateTrafficMetrics(
                snapshot
            )

            updateConnectionMetrics(
                snapshot
            )

            detectNetworkAnomalies(
                snapshot
            )

            updateHealth(
                snapshot
            )

            statistics.incrementSnapshots()

            VPNNetworkMonitorOperationResult.success(
                "Network snapshot processed successfully."
            )
        }

    /**
     * Registers a new network connection.
     */
    suspend fun registerConnection(
        connection:
            VPNNetworkConnection
    ):
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                activeConnections.size >=
                MAX_CONNECTIONS
            ) {

                return@withContext
                    VPNNetworkMonitorOperationResult.failure(
                        "Maximum active VPN connection capacity reached."
                    )
            }

            val validation =
                validateConnection(
                    connection
                )

            if (
                !validation.valid
            ) {

                statistics
                    .incrementInvalidConnections()

                return@withContext
                    VPNNetworkMonitorOperationResult.failure(
                        validation.message
                    )
            }

            val existing =
                activeConnections[
                    connection.id
                ]

            if (
                existing != null
            ) {

                return@withContext
                    VPNNetworkMonitorOperationResult.success(
                        "VPN connection already exists."
                    )
            }

            activeConnections[
                connection.id
            ] =
                connection

            updateEndpointStatistics(
                connection
            )

            statistics.incrementConnectionsOpened()

            updateState {
                it.copy(
                    activeConnectionCount =
                        activeConnections.size,

                    lastConnectionChangeAt =
                        System.currentTimeMillis()
                )
            }

            publishEvent(
                VPNNetworkEvent.ConnectionOpened(
                    timestamp =
                        System.currentTimeMillis(),

                    connection =
                        connection
                )
            )

            VPNNetworkMonitorOperationResult.success(
                "VPN connection registered."
            )
        }

    /**
     * Updates an existing network connection.
     */
    suspend fun updateConnection(
        connection:
            VPNNetworkConnection
    ):
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connection.id
                ]
                    ?: return@withContext
                        VPNNetworkMonitorOperationResult.failure(
                            "VPN network connection not found."
                        )

            activeConnections[
                connection.id
            ] =
                connection

            updateEndpointStatistics(
                connection
            )

            if (
                existing.bytesSent !=
                connection.bytesSent ||
                existing.bytesReceived !=
                connection.bytesReceived
            ) {

                statistics
                    .incrementTrafficUpdates()
            }

            VPNNetworkMonitorOperationResult.success(
                "VPN network connection updated."
            )
        }

    /**
     * Removes a connection.
     */
    suspend fun unregisterConnection(
        connectionId:
            String,
        reason:
            String =
            "Connection closed."
    ):
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                activeConnections.remove(
                    connectionId
                )
                    ?: return@withContext
                        VPNNetworkMonitorOperationResult.failure(
                            "VPN network connection not found."
                        )

            val closed =
                connection.copy(
                    state =
                        VPNConnectionState.CLOSED,

                    closedAt =
                        System.currentTimeMillis()
                )

            addActivityHistory(
                VPNNetworkActivity.ConnectionClosed(
                    timestamp =
                        System.currentTimeMillis(),

                    connection =
                        closed,

                    reason =
                        reason
                )
            )

            statistics.incrementConnectionsClosed()

            updateState {
                it.copy(
                    activeConnectionCount =
                        activeConnections.size,

                    lastConnectionChangeAt =
                        System.currentTimeMillis()
                )
            }

            publishEvent(
                VPNNetworkEvent.ConnectionClosed(
                    timestamp =
                        System.currentTimeMillis(),

                    connection =
                        closed,

                    reason =
                        reason
                )
            )

            VPNNetworkMonitorOperationResult.success(
                "VPN network connection removed."
            )
        }

    /**
     * Updates traffic counters.
     */
    private fun updateTrafficMetrics(
        snapshot:
            VPNNetworkSnapshot
    ) {

        val previousSent =
            previousBytesSent.get()

        val previousReceived =
            previousBytesReceived.get()

        val sentDelta =
            (
                snapshot.totalBytesSent -
                        previousSent
                )
                .coerceAtLeast(
                    0L
                )

        val receivedDelta =
            (
                snapshot.totalBytesReceived -
                        previousReceived
                )
                .coerceAtLeast(
                    0L
                )

        val now =
            System.currentTimeMillis()

        val previousTimestamp =
            lastMeasurementAt.get()

        val elapsedMs =
            (
                now -
                        previousTimestamp
                )
                .coerceAtLeast(
                    1L
                )

        val sentRate =
            calculateRate(
                sentDelta,
                elapsedMs
            )

        val receivedRate =
            calculateRate(
                receivedDelta,
                elapsedMs
            )

        previousBytesSent.set(
            snapshot.totalBytesSent
        )

        previousBytesReceived.set(
            snapshot.totalBytesReceived
        )

        lastMeasurementAt.set(
            now
        )

        updateState {
            it.copy(

                totalBytesSent =
                    snapshot.totalBytesSent,

                totalBytesReceived =
                    snapshot.totalBytesReceived,

                totalPacketsSent =
                    snapshot.totalPacketsSent,

                totalPacketsReceived =
                    snapshot.totalPacketsReceived,

                bytesSentPerSecond =
                    sentRate,

                bytesReceivedPerSecond =
                    receivedRate,

                packetsSentPerSecond =
                    calculateRate(
                        snapshot.totalPacketsSent,
                        elapsedMs
                    ),

                packetsReceivedPerSecond =
                    calculateRate(
                        snapshot.totalPacketsReceived,
                        elapsedMs
                    ),

                lastTrafficAt =
                    now
            )
        }

        if (
            sentRate >=
            configuration
                .bandwidthSpikeBytesPerSecond ||
            receivedRate >=
            configuration
                .bandwidthSpikeBytesPerSecond
        ) {

            statistics
                .incrementBandwidthSpikes()

            publishEvent(
                VPNNetworkEvent.BandwidthSpike(
                    timestamp =
                        now,

                    bytesSentPerSecond =
                        sentRate,

                    bytesReceivedPerSecond =
                        receivedRate
                )
            )
        }
    }

    /**
     * Updates connection metrics.
     */
    private fun updateConnectionMetrics(
        snapshot:
            VPNNetworkSnapshot
    ) {

        val activeCount =
            snapshot.activeConnectionCount

        updateState {
            it.copy(
                activeConnectionCount =
                    activeCount,

                dnsQueryCount =
                    snapshot.dnsQueryCount,

                uniqueEndpointCount =
                    snapshot.uniqueEndpointCount,

                networkType =
                    snapshot.networkType,

                transportAvailable =
                    snapshot.transportAvailable
            )
        }

        if (
            activeCount >
            configuration
                .maximumConnectionCount
        ) {

            statistics
                .incrementConnectionCountAnomalies()

            publishEvent(
                VPNNetworkEvent.ConnectionCountAnomaly(
                    timestamp =
                        System.currentTimeMillis(),

                    connectionCount =
                        activeCount,

                    threshold =
                        configuration
                            .maximumConnectionCount
                )
            )
        }
    }

    /**
     * Detects network anomalies.
     */
    private fun detectNetworkAnomalies(
        snapshot:
            VPNNetworkSnapshot
    ) {

        if (
            snapshot.networkChanged
        ) {

            statistics
                .incrementNetworkChanges()

            publishEvent(
                VPNNetworkEvent.NetworkChanged(
                    timestamp =
                        System.currentTimeMillis(),

                    previousNetwork =
                        snapshot.previousNetworkType,

                    currentNetwork =
                        snapshot.networkType
                )
            )
        }

        if (
            snapshot.dnsFailures >
            configuration
                .maximumDnsFailures
        ) {

            statistics
                .incrementDnsAnomalies()

            publishEvent(
                VPNNetworkEvent.DnsAnomaly(
                    timestamp =
                        System.currentTimeMillis(),

                    failures =
                        snapshot.dnsFailures
                )
            )
        }

        if (
            snapshot.uniqueEndpointCount >
            configuration
                .maximumUniqueEndpoints
        ) {

            statistics
                .incrementEndpointAnomalies()

            publishEvent(
                VPNNetworkEvent.EndpointCountAnomaly(
                    timestamp =
                        System.currentTimeMillis(),

                    endpointCount =
                        snapshot.uniqueEndpointCount
                )
            )
        }
    }

    /**
     * Updates overall network health.
     */
    private fun updateHealth(
        snapshot:
            VPNNetworkSnapshot
    ) {

        val health =
            when {

                !snapshot.transportAvailable ->
                    VPNNetworkHealth.DISCONNECTED

                snapshot.dnsFailures >
                        configuration
                            .maximumDnsFailures ->
                    VPNNetworkHealth.DEGRADED

                snapshot.activeConnectionCount >
                        configuration
                            .maximumConnectionCount ->
                    VPNNetworkHealth.DEGRADED

                else ->
                    VPNNetworkHealth.HEALTHY
            }

        val previous =
            _state.value.health

        updateState {
            it.copy(
                health =
                    health,

                healthReason =
                    when (
                        health
                    ) {

                        VPNNetworkHealth.HEALTHY ->
                            "VPN network is healthy."

                        VPNNetworkHealth.DEGRADED ->
                            "VPN network activity requires attention."

                        VPNNetworkHealth.DISCONNECTED ->
                            "VPN network transport is unavailable."

                        VPNNetworkHealth.UNKNOWN ->
                            "VPN network health is unknown."
                    },

                lastHealthCheckAt =
                    System.currentTimeMillis()
            )
        }

        if (
            previous != health
        ) {

            publishEvent(
                VPNNetworkEvent.HealthChanged(
                    timestamp =
                        System.currentTimeMillis(),

                    previous =
                        previous,

                    current =
                        health
                )
            )
        }
    }

    /**
     * Updates endpoint statistics.
     */
    private fun updateEndpointStatistics(
        connection:
            VPNNetworkConnection
    ) {

        val endpoint =
            normalizeEndpoint(
                connection.remoteEndpoint
            )

        endpointStatistics
            .compute(
                endpoint
            ) { _, existing ->

                val current =
                    existing
                        ?: VPNEndpointNetworkStatistics(
                            endpoint =
                                endpoint,

                            connectionCount =
                                0,

                            totalBytesSent =
                                0,

                            totalBytesReceived =
                                0,

                            totalPacketsSent =
                                0,

                            totalPacketsReceived =
                                0,

                            firstSeenAt =
                                System.currentTimeMillis(),

                            lastSeenAt =
                                System.currentTimeMillis()
                        )

                current.copy(

                    connectionCount =
                        current.connectionCount + 1,

                    totalBytesSent =
                        current.totalBytesSent +
                                connection.bytesSent,

                    totalBytesReceived =
                        current.totalBytesReceived +
                                connection.bytesReceived,

                    totalPacketsSent =
                        current.totalPacketsSent +
                                connection.packetsSent,

                    totalPacketsReceived =
                        current.totalPacketsReceived +
                                connection.packetsReceived,

                    lastSeenAt =
                        System.currentTimeMillis()
                )
            }

        if (
            endpointStatistics.size >
            MAX_ENDPOINTS
        ) {

            val oldest =
                endpointStatistics.values
                    .minByOrNull {
                        it.lastSeenAt
                    }

            oldest?.let {
                endpointStatistics.remove(
                    it.endpoint
                )
            }
        }
    }

    /**
     * Adds network activity to history.
     */
    private fun addActivityHistory(
        activity:
            VPNNetworkActivity
    ) {

        activityHistory.addFirst(
            activity
        )

        while (
            activityHistory.size >
            MAX_HISTORY
        ) {

            activityHistory.pollLast()
        }
    }

    /**
     * Returns an active connection.
     */
    fun getConnection(
        connectionId:
            String
    ):
            VPNNetworkConnection? {

        return activeConnections[
            connectionId
        ]
    }

    /**
     * Returns all active connections.
     */
    fun getActiveConnections():
            List<VPNNetworkConnection> {

        return activeConnections.values
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Returns connections using a protocol.
     */
    fun getConnectionsByProtocol(
        protocol:
            VPNTransportProtocol
    ):
            List<VPNNetworkConnection> {

        return activeConnections.values
            .filter {
                it.protocol ==
                        protocol
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Returns connections for an endpoint.
     */
    fun getConnectionsByEndpoint(
        endpoint:
            String
    ):
            List<VPNNetworkConnection> {

        val normalized =
            normalizeEndpoint(
                endpoint
            )

        return activeConnections.values
            .filter {
                normalizeEndpoint(
                    it.remoteEndpoint
                ) ==
                        normalized
            }
    }

    /**
     * Returns endpoint statistics.
     */
    fun getEndpointStatistics(
        endpoint:
            String
    ):
            VPNEndpointNetworkStatistics? {

        return endpointStatistics[
            normalizeEndpoint(
                endpoint
            )
        ]
    }

    /**
     * Returns all endpoint statistics.
     */
    fun getAllEndpointStatistics():
            List<VPNEndpointNetworkStatistics> {

        return endpointStatistics.values
            .sortedByDescending {
                it.lastSeenAt
            }
    }

    /**
     * Returns network activity history.
     */
    fun getActivityHistory(
        limit:
            Int = 100
    ):
            List<VPNNetworkActivity> {

        require(
            limit > 0
        ) {
            "History limit must be greater than zero."
        }

        return activityHistory
            .take(
                limit
            )
    }

    /**
     * Returns network statistics.
     */
    fun getStatistics():
            VPNNetworkMonitorStatistics {

        return statistics.snapshot()
    }

    /**
     * Returns current network state.
     */
    fun getNetworkState():
            VPNNetworkMonitorState {

        return _state.value
    }

    /**
     * Returns whether the network is healthy.
     */
    fun isHealthy():
            Boolean {

        return _state.value.health ==
                VPNNetworkHealth.HEALTHY
    }

    /**
     * Returns whether traffic is currently active.
     */
    fun hasActiveTraffic():
            Boolean {

        return (
            _state.value.bytesSentPerSecond > 0 ||
                    _state.value.bytesReceivedPerSecond > 0
            )
    }

    /**
     * Returns current bandwidth.
     */
    fun getCurrentBandwidth():
            VPNBandwidthMetrics {

        val current =
            _state.value

        return VPNBandwidthMetrics(

            bytesSentPerSecond =
                current.bytesSentPerSecond,

            bytesReceivedPerSecond =
                current.bytesReceivedPerSecond,

            packetsSentPerSecond =
                current.packetsSentPerSecond,

            packetsReceivedPerSecond =
                current.packetsReceivedPerSecond
        )
    }

    /**
     * Clears activity history.
     */
    suspend fun clearHistory():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                activityHistory.size

            activityHistory.clear()

            statistics
                .incrementHistoryCleared(
                    count
                )

            VPNNetworkMonitorOperationResult.success(
                "VPN network activity history cleared."
            )
        }

    /**
     * Clears endpoint statistics.
     */
    suspend fun clearEndpointStatistics():
            VPNNetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            endpointStatistics.clear()

            VPNNetworkMonitorOperationResult.success(
                "VPN endpoint statistics cleared."
            )
        }

    /**
     * Validates network snapshot.
     */
    private fun validateSnapshot(
        snapshot:
            VPNNetworkSnapshot
    ):
            VPNNetworkSnapshotValidationResult {

        if (
            snapshot.totalBytesSent < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Total bytes sent cannot be negative."
            )
        }

        if (
            snapshot.totalBytesReceived < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Total bytes received cannot be negative."
            )
        }

        if (
            snapshot.totalPacketsSent < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Total packets sent cannot be negative."
            )
        }

        if (
            snapshot.totalPacketsReceived < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Total packets received cannot be negative."
            )
        }

        if (
            snapshot.activeConnectionCount < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Active connection count cannot be negative."
            )
        }

        if (
            snapshot.uniqueEndpointCount < 0
        ) {

            return VPNNetworkSnapshotValidationResult.invalid(
                "Unique endpoint count cannot be negative."
            )
        }

        return VPNNetworkSnapshotValidationResult.valid()
    }

    /**
     * Validates network connection.
     */
    private fun validateConnection(
        connection:
            VPNNetworkConnection
    ):
            VPNNetworkConnectionValidationResult {

        if (
            connection.id.isBlank()
        ) {

            return VPNNetworkConnectionValidationResult.invalid(
                "Connection ID cannot be blank."
            )
        }

        if (
            connection.remoteEndpoint.isBlank()
        ) {

            return VPNNetworkConnectionValidationResult.invalid(
                "Remote endpoint cannot be blank."
            )
        }

        if (
            connection.bytesSent < 0 ||
            connection.bytesReceived < 0
        ) {

            return VPNNetworkConnectionValidationResult.invalid(
                "Connection byte counters cannot be negative."
            )
        }

        if (
            connection.packetsSent < 0 ||
            connection.packetsReceived < 0
        ) {

            return VPNNetworkConnectionValidationResult.invalid(
                "Connection packet counters cannot be negative."
            )
        }

        return VPNNetworkConnectionValidationResult.valid()
    }

    /**
     * Calculates bytes/packets per second.
     */
    private fun calculateRate(
        delta:
            Long,
        elapsedMs:
            Long
    ):
            Long {

        if (
            delta <= 0 ||
            elapsedMs <= 0
        ) {

            return 0
        }

        return (
            delta * 1000L
            )
            .div(
                elapsedMs
            )
    }

    /**
     * Normalizes an endpoint.
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
     * Publishes a network event.
     */
    private fun publishEvent(
        event:
            VPNNetworkEvent
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
     * Updates state atomically through StateFlow.
     */
    private fun updateState(
        transform:
            (VPNNetworkMonitorState) ->
            VPNNetworkMonitorState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Ensures monitor initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized.get()
        ) {
            "VPNNetworkMonitor has not been initialized."
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
                "VPN network monitoring operation was cancelled."
            )
        }
    }

    /**
     * Releases resources.
     */
    fun close() {

        monitoring.set(
            false
        )

        monitoringJob?.cancel()

        monitorScope.cancel()

        activeConnections.clear()

        endpointStatistics.clear()

        activityHistory.clear()

        _state.value =
            VPNNetworkMonitorState()

        _latestEvent.value =
            null

        initialized.set(
            false
        )

        Log.i(
            TAG,
            "VPNNetworkMonitor closed."
        )
    }
}

/**
 * Provider abstraction for network measurements.
 *
 * VPNEngine or VPNService can provide the actual
 * implementation through dependency injection.
 */
fun interface VPNNetworkProvider {

    /**
     * Returns a current VPN network snapshot.
     */
    fun getSnapshot():
        VPNNetworkSnapshot
}

/**
 * VPN network monitor configuration.
 */
data class VPNNetworkMonitorConfiguration(

    /**
     * Network monitoring interval.
     */
    val monitoringIntervalMs:
        Long = 5_000L,

    /**
     * Maximum active connections considered normal.
     */
    val maximumConnectionCount:
        Int = 500,

    /**
     * Maximum unique endpoints considered normal.
     */
    val maximumUniqueEndpoints:
        Int = 250,

    /**
     * Maximum DNS failures considered normal.
     */
    val maximumDnsFailures:
        Int = 10,

    /**
     * Bandwidth spike threshold.
     */
    val bandwidthSpikeBytesPerSecond:
        Long =
        50L *
                1024L *
                1024L,

    /**
     * Provider of actual network metrics.
     */
    val networkProvider:
        VPNNetworkProvider =
        VPNNetworkProvider {
            VPNNetworkSnapshot()
        }
)

/**
 * Network snapshot.
 */
data class VPNNetworkSnapshot(

    /**
     * Total bytes sent through VPN.
     */
    val totalBytesSent:
        Long = 0,

    /**
     * Total bytes received through VPN.
     */
    val totalBytesReceived:
        Long = 0,

    /**
     * Total packets sent.
     */
    val totalPacketsSent:
        Long = 0,

    /**
     * Total packets received.
     */
    val totalPacketsReceived:
        Long = 0,

    /**
     * Current active connections.
     */
    val activeConnectionCount:
        Int = 0,

    /**
     * Current unique endpoints.
     */
    val uniqueEndpointCount:
        Int = 0,

    /**
     * DNS queries observed.
     */
    val dnsQueryCount:
        Long = 0,

    /**
     * DNS failures.
     */
    val dnsFailures:
        Int = 0,

    /**
     * Whether the underlying transport is available.
     */
    val transportAvailable:
        Boolean = true,

    /**
     * Current network type.
     */
    val networkType:
        VPNNetworkType =
        VPNNetworkType.UNKNOWN,

    /**
     * Previous network type.
     */
    val previousNetworkType:
        VPNNetworkType? =
        null,

    /**
     * Indicates a network transition.
     */
    val networkChanged:
        Boolean = false
)

/**
 * VPN network connection.
 */
data class VPNNetworkConnection(

    /**
     * Unique connection ID.
     */
    val id:
        String =
        generateVpnNetworkConnectionId(),

    /**
     * VPN connection/session ID.
     */
    val vpnSessionId:
        String? =
        null,

    /**
     * Remote endpoint.
     */
    val remoteEndpoint:
        String,

    /**
     * Remote port.
     */
    val remotePort:
        Int? =
        null,

    /**
     * Local port.
     */
    val localPort:
        Int? =
        null,

    /**
     * Transport protocol.
     */
    val protocol:
        VPNTransportProtocol =
        VPNTransportProtocol.UNKNOWN,

    /**
     * Connection state.
     */
    val state:
        VPNConnectionState =
        VPNConnectionState.CONNECTING,

    /**
     * Bytes sent.
     */
    val bytesSent:
        Long = 0,

    /**
     * Bytes received.
     */
    val bytesReceived:
        Long = 0,

    /**
     * Packets sent.
     */
    val packetsSent:
        Long = 0,

    /**
     * Packets received.
     */
    val packetsReceived:
        Long = 0,

    /**
     * Connection creation time.
     */
    val createdAt:
        Long =
        System.currentTimeMillis(),

    /**
     * Last activity.
     */
    val lastActivityAt:
        Long =
        System.currentTimeMillis(),

    /**
     * Closing timestamp.
     */
    val closedAt:
        Long? =
        null
)

/**
 * Endpoint network statistics.
 */
data class VPNEndpointNetworkStatistics(

    val endpoint:
        String,

    val connectionCount:
        Int,

    val totalBytesSent:
        Long,

    val totalBytesReceived:
        Long,

    val totalPacketsSent:
        Long,

    val totalPacketsReceived:
        Long,

    val firstSeenAt:
        Long,

    val lastSeenAt:
        Long
)

/**
 * VPN network activity.
 */
sealed class VPNNetworkActivity {

    abstract val timestamp:
        Long

    /**
     * Connection closed activity.
     */
    data class ConnectionClosed(
        override val timestamp:
            Long,
        val connection:
            VPNNetworkConnection,
        val reason:
            String
    ) : VPNNetworkActivity()
}

/**
 * VPN network events.
 */
sealed class VPNNetworkEvent {

    abstract val timestamp:
        Long

    /**
     * Connection opened.
     */
    data class ConnectionOpened(
        override val timestamp:
            Long,
        val connection:
            VPNNetworkConnection
    ) : VPNNetworkEvent()

    /**
     * Connection closed.
     */
    data class ConnectionClosed(
        override val timestamp:
            Long,
        val connection:
            VPNNetworkConnection,
        val reason:
            String
    ) : VPNNetworkEvent()

    /**
     * Bandwidth spike detected.
     */
    data class BandwidthSpike(
        override val timestamp:
            Long,
        val bytesSentPerSecond:
            Long,
        val bytesReceivedPerSecond:
            Long
    ) : VPNNetworkEvent()

    /**
     * Abnormally high connection count.
     */
    data class ConnectionCountAnomaly(
        override val timestamp:
            Long,
        val connectionCount:
            Int,
        val threshold:
            Int
    ) : VPNNetworkEvent()

    /**
     * Network changed.
     */
    data class NetworkChanged(
        override val timestamp:
            Long,
        val previousNetwork:
            VPNNetworkType?,
        val currentNetwork:
            VPNNetworkType
    ) : VPNNetworkEvent()

    /**
     * DNS anomaly.
     */
    data class DnsAnomaly(
        override val timestamp:
            Long,
        val failures:
            Int
    ) : VPNNetworkEvent()

    /**
     * Endpoint count anomaly.
     */
    data class EndpointCountAnomaly(
        override val timestamp:
            Long,
        val endpointCount:
            Int
    ) : VPNNetworkEvent()

    /**
     * Network health changed.
     */
    data class HealthChanged(
        override val timestamp:
            Long,
        val previous:
            VPNNetworkHealth,
        val current:
            VPNNetworkHealth
    ) : VPNNetworkEvent()

    /**
     * Internal monitor error.
     */
    data class MonitorError(
        override val timestamp:
            Long,
        val message:
            String
    ) : VPNNetworkEvent()
}

/**
 * VPN network health.
 */
enum class VPNNetworkHealth {

    UNKNOWN,

    HEALTHY,

    DEGRADED,

    DISCONNECTED
}

/**
 * VPN network type.
 */
enum class VPNNetworkType {

    WIFI,

    MOBILE,

    ETHERNET,

    VPN,

    UNKNOWN
}

/**
 * VPN transport protocol.
 */
enum class VPNTransportProtocol {

    TCP,

    UDP,

    ICMP,

    DNS,

    HTTP,

    HTTPS,

    QUIC,

    UNKNOWN
}

/**
 * VPN connection state.
 */
enum class VPNConnectionState {

    CONNECTING,

    CONNECTED,

    CLOSING,

    CLOSED,

    FAILED
)

/**
 * Network snapshot validation result.
 */
data class VPNNetworkSnapshotValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                VPNNetworkSnapshotValidationResult {

            return VPNNetworkSnapshotValidationResult(
                valid =
                    true,

                message =
                    "Network snapshot is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                VPNNetworkSnapshotValidationResult {

            return VPNNetworkSnapshotValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Network connection validation result.
 */
data class VPNNetworkConnectionValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                VPNNetworkConnectionValidationResult {

            return VPNNetworkConnectionValidationResult(
                valid =
                    true,

                message =
                    "Network connection is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                VPNNetworkConnectionValidationResult {

            return VPNNetworkConnectionValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Generic network monitor operation result.
 */
data class VPNNetworkMonitorOperationResult(

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
                VPNNetworkMonitorOperationResult {

            return VPNNetworkMonitorOperationResult(
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
                VPNNetworkMonitorOperationResult {

            return VPNNetworkMonitorOperationResult(
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
 * Current VPN network state.
 */
data class VPNNetworkMonitorState(

    val initialized:
        Boolean = false,

    val monitoring:
        Boolean = false,

    val monitoringStartedAt:
        Long? = null,

    val monitoringStoppedAt:
        Long? = null,

    val health:
        VPNNetworkHealth =
        VPNNetworkHealth.UNKNOWN,

    val healthReason:
        String? = null,

    val activeConnectionCount:
        Int = 0,

    val uniqueEndpointCount:
        Int = 0,

    val dnsQueryCount:
        Long = 0,

    val totalBytesSent:
        Long = 0,

    val totalBytesReceived:
        Long = 0,

    val totalPacketsSent:
        Long = 0,

    val totalPacketsReceived:
        Long = 0,

    val bytesSentPerSecond:
        Long = 0,

    val bytesReceivedPerSecond:
        Long = 0,

    val packetsSentPerSecond:
        Long = 0,

    val packetsReceivedPerSecond:
        Long = 0,

    val lastTrafficAt:
        Long? = null,

    val lastConnectionChangeAt:
        Long? = null,

    val lastHealthCheckAt:
        Long? = null,

    val networkType:
        VPNNetworkType =
        VPNNetworkType.UNKNOWN,

    val transportAvailable:
        Boolean = false,

    val latestEvent:
        VPNNetworkEvent? = null
)

/**
 * Bandwidth metrics.
 */
data class VPNBandwidthMetrics(

    val bytesSentPerSecond:
        Long,

    val bytesReceivedPerSecond:
        Long,

    val packetsSentPerSecond:
        Long,

    val packetsReceivedPerSecond:
        Long
)

/**
 * Network monitor statistics.
 */
data class VPNNetworkMonitorStatistics(

    val initializations:
        Long,

    val monitoringStarts:
        Long,

    val monitoringStops:
        Long,

    val snapshots:
        Long,

    val invalidSnapshots:
        Long,

    val connectionsOpened:
        Long,

    val connectionsClosed:
        Long,

    val invalidConnections:
        Long,

    val trafficUpdates:
        Long,

    val bandwidthSpikes:
        Long,

    val connectionCountAnomalies:
        Long,

    val networkChanges:
        Long,

    val dnsAnomalies:
        Long,

    val endpointAnomalies:
        Long,

    val monitorErrors:
        Long,

    val historyCleared:
        Long,

    val totalMonitoringTimeMs:
        Long
)

/**
 * Thread-safe network monitor statistics.
 */
private class VPNNetworkMonitorStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val monitoringStarts =
        AtomicLong(0)

    private val monitoringStops =
        AtomicLong(0)

    private val snapshots =
        AtomicLong(0)

    private val invalidSnapshots =
        AtomicLong(0)

    private val connectionsOpened =
        AtomicLong(0)

    private val connectionsClosed =
        AtomicLong(0)

    private val invalidConnections =
        AtomicLong(0)

    private val trafficUpdates =
        AtomicLong(0)

    private val bandwidthSpikes =
        AtomicLong(0)

    private val connectionCountAnomalies =
        AtomicLong(0)

    private val networkChanges =
        AtomicLong(0)

    private val dnsAnomalies =
        AtomicLong(0)

    private val endpointAnomalies =
        AtomicLong(0)

    private val monitorErrors =
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

    fun incrementSnapshots() {
        snapshots.incrementAndGet()
    }

    fun incrementInvalidSnapshots() {
        invalidSnapshots.incrementAndGet()
    }

    fun incrementConnectionsOpened() {
        connectionsOpened.incrementAndGet()
    }

    fun incrementConnectionsClosed() {
        connectionsClosed.incrementAndGet()
    }

    fun incrementInvalidConnections() {
        invalidConnections.incrementAndGet()
    }

    fun incrementTrafficUpdates() {
        trafficUpdates.incrementAndGet()
    }

    fun incrementBandwidthSpikes() {
        bandwidthSpikes.incrementAndGet()
    }

    fun incrementConnectionCountAnomalies() {
        connectionCountAnomalies.incrementAndGet()
    }

    fun incrementNetworkChanges() {
        networkChanges.incrementAndGet()
    }

    fun incrementDnsAnomalies() {
        dnsAnomalies.incrementAndGet()
    }

    fun incrementEndpointAnomalies() {
        endpointAnomalies.incrementAndGet()
    }

    fun incrementMonitorErrors() {
        monitorErrors.incrementAndGet()
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
            VPNNetworkMonitorStatistics {

        return VPNNetworkMonitorStatistics(

            initializations =
                initializations.get(),

            monitoringStarts =
                monitoringStarts.get(),

            monitoringStops =
                monitoringStops.get(),

            snapshots =
                snapshots.get(),

            invalidSnapshots =
                invalidSnapshots.get(),

            connectionsOpened =
                connectionsOpened.get(),

            connectionsClosed =
                connectionsClosed.get(),

            invalidConnections =
                invalidConnections.get(),

            trafficUpdates =
                trafficUpdates.get(),

            bandwidthSpikes =
                bandwidthSpikes.get(),

            connectionCountAnomalies =
                connectionCountAnomalies.get(),

            networkChanges =
                networkChanges.get(),

            dnsAnomalies =
                dnsAnomalies.get(),

            endpointAnomalies =
                endpointAnomalies.get(),

            monitorErrors =
                monitorErrors.get(),

            historyCleared =
                historyCleared.get(),

            totalMonitoringTimeMs =
                totalMonitoringTimeMs.get()
        )
    }
}

/**
 * Generates a VPN network connection identifier.
 */
private fun generateVpnNetworkConnectionId():
        String {

    return "VPN_CONN_" +
            UUID.randomUUID()
                .toString()
                .replace(
                    "-",
                    ""
                )
                .take(20)
                .uppercase()
}
