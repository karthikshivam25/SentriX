package com.sentrix.security.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * NetworkTrafficMonitor
 *
 * Monitors Android network connectivity and maintains a lightweight
 * application-level representation of network traffic state for the
 * SentriX firewall subsystem.
 *
 * Responsibilities:
 *
 * - Monitor network availability.
 * - Detect Wi-Fi/mobile/VPN/ethernet transport changes.
 * - Track active networks.
 * - Track network connection metadata.
 * - Maintain traffic counters supplied by the application layer.
 * - Notify firewall components about network changes.
 * - Detect network transitions.
 * - Maintain network health information.
 * - Provide traffic statistics.
 *
 * IMPORTANT ANDROID LIMITATION:
 *
 * Android does not expose arbitrary per-packet traffic to a normal
 * application through ConnectivityManager callbacks.
 *
 * Therefore this class should NOT be treated as a packet sniffer.
 *
 * For actual device-wide traffic interception, SentriX should use:
 *
 *     Android VpnService
 *
 * The VpnService layer can feed observed connection metadata into
 * this monitor.
 *
 * This class therefore provides the monitoring/aggregation layer
 * while keeping packet interception separate.
 *
 * Architecture:
 *
 *              Android ConnectivityManager
 *                           |
 *                           v
 *                NetworkTrafficMonitor
 *                           |
 *             ┌─────────────┼─────────────┐
 *             ▼             ▼             ▼
 *        Network State   Traffic Stats   Events
 *             |             |             |
 *             └─────────────┼─────────────┘
 *                           ▼
 *                    FirewallManager
 */
class NetworkTrafficMonitor(
    context: Context
) {

    companion object {

        private const val TAG =
            "NetworkTrafficMonitor"

        /**
         * Maximum number of tracked network records.
         */
        private const val MAX_NETWORK_RECORDS =
            256

        /**
         * Maximum number of traffic events retained.
         */
        private const val MAX_TRAFFIC_EVENTS =
            5_000

        /**
         * Unknown value used by Android TrafficStats APIs.
         */
        private const val UNKNOWN_TRAFFIC_VALUE =
            -1L
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Connectivity manager.
     */
    private val connectivityManager =
        applicationContext.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager

    /**
     * Coroutine scope owned by this monitor.
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
     * Active network records.
     */
    private val activeNetworks =
        ConcurrentHashMap<
            String,
            NetworkTrafficRecord
        >()

    /**
     * Traffic event history.
     */
    private val trafficEvents =
        java.util.concurrent.ConcurrentLinkedDeque<
            NetworkTrafficEvent
        >()

    /**
     * Traffic counters.
     */
    private val statistics =
        NetworkTrafficStatisticsCounter()

    /**
     * Current network state.
     */
    private val _networkState =
        MutableStateFlow(
            NetworkEnvironmentState()
        )

    /**
     * Public immutable network state stream.
     */
    val networkState:
        StateFlow<NetworkEnvironmentState> =
        _networkState.asStateFlow()

    /**
     * Current monitoring job.
     */
    @Volatile
    private var monitoringJob:
            Job? = null

    /**
     * Connectivity callback.
     */
    private val connectivityCallback =
        createConnectivityCallback()

    /**
     * Starts monitoring network state.
     */
    suspend fun start():
            NetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                monitoring.get()
            ) {

                return@withContext
                    NetworkMonitorOperationResult.success(
                        "Network traffic monitoring is already active."
                    )
            }

            try {

                registerNetworkCallback()

                refreshCurrentNetworkState()

                monitoring.set(true)

                monitoringJob =
                    monitorScope.launch {

                        while (
                            monitoring.get()
                        ) {

                            refreshTrafficStatistics()

                            kotlinx.coroutines
                                .delay(5_000L)
                        }
                    }

                logEvent(
                    NetworkTrafficEventType.MONITORING_STARTED,
                    "Network traffic monitoring started."
                )

                Log.i(
                    TAG,
                    "Network traffic monitoring started."
                )

                NetworkMonitorOperationResult.success(
                    "Network traffic monitoring started successfully."
                )

            } catch (
                exception: CancellationException
            ) {

                throw exception

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Unable to start network monitoring.",
                    exception
                )

                NetworkMonitorOperationResult.failure(
                    "Unable to start network monitoring.",
                    exception.message
                )
            }
        }

    /**
     * Stops monitoring.
     */
    suspend fun stop():
            NetworkMonitorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !monitoring.get()
            ) {

                return@withContext
                    NetworkMonitorOperationResult.success(
                        "Network traffic monitoring is already stopped."
                    )
            }

            monitoring.set(false)

            monitoringJob?.cancel()

            monitoringJob = null

            unregisterNetworkCallback()

            logEvent(
                NetworkTrafficEventType.MONITORING_STOPPED,
                "Network traffic monitoring stopped."
            )

            Log.i(
                TAG,
                "Network traffic monitoring stopped."
            )

            NetworkMonitorOperationResult.success(
                "Network traffic monitoring stopped successfully."
            )
        }

    /**
     * Returns whether monitoring is active.
     */
    fun isMonitoring():
            Boolean {

        return monitoring.get()
    }

    /**
     * Registers Android network callback.
     */
    private fun registerNetworkCallback() {

        val request =
            NetworkRequest.Builder()
                .addCapability(
                    NetworkCapabilities.NET_CAPABILITY_INTERNET
                )
                .build()

        connectivityManager
            .registerNetworkCallback(
                request,
                connectivityCallback
            )
    }

    /**
     * Unregisters Android network callback.
     */
    private fun unregisterNetworkCallback() {

        try {

            connectivityManager
                .unregisterNetworkCallback(
                    connectivityCallback
                )

        } catch (
            exception: Exception
        ) {

            Log.w(
                TAG,
                "Network callback was already unregistered.",
                exception
            )
        }
    }

    /**
     * Creates the Android ConnectivityManager callback.
     */
    private fun createConnectivityCallback():
            ConnectivityManager.NetworkCallback {

        return object :
            ConnectivityManager.NetworkCallback() {

            override fun onAvailable(
                network: Network
            ) {

                super.onAvailable(
                    network
                )

                handleNetworkAvailable(
                    network
                )
            }

            override fun onLost(
                network: Network
            ) {

                super.onLost(
                    network
                )

                handleNetworkLost(
                    network
                )
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities:
                    NetworkCapabilities
            ) {

                super.onCapabilitiesChanged(
                    network,
                    networkCapabilities
                )

                handleCapabilitiesChanged(
                    network,
                    networkCapabilities
                )
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties:
                    android.net.LinkProperties
            ) {

                super.onLinkPropertiesChanged(
                    network,
                    linkProperties
                )

                handleLinkPropertiesChanged(
                    network,
                    linkProperties
                )
            }

            override fun onUnavailable() {

                super.onUnavailable()

                handleNetworkUnavailable()
            }
        }
    }

    /**
     * Handles a network becoming available.
     */
    private fun handleNetworkAvailable(
        network: Network
    ) {

        monitorScope.launch {

            try {

                val capabilities =
                    connectivityManager
                        .getNetworkCapabilities(
                            network
                        )

                val record =
                    createNetworkRecord(
                        network,
                        capabilities
                    )

                if (
                    activeNetworks.size >=
                    MAX_NETWORK_RECORDS &&
                    !activeNetworks.containsKey(
                        record.networkId
                    )
                ) {

                    activeNetworks.keys
                        .firstOrNull()
                        ?.let {
                            activeNetworks.remove(
                                it
                            )
                        }
                }

                activeNetworks[
                    record.networkId
                ] =
                    record

                statistics.incrementNetworkAvailable()

                logEvent(
                    NetworkTrafficEventType.NETWORK_AVAILABLE,
                    "Network became available: ${record.networkId}."
                )

                refreshCurrentNetworkState()

            } catch (
                exception: CancellationException
            ) {

                throw exception

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Failed to process network availability.",
                    exception
                )
            }
        }
    }

    /**
     * Handles a network becoming unavailable.
     */
    private fun handleNetworkLost(
        network: Network
    ) {

        monitorScope.launch {

            val networkId =
                network.toString()

            activeNetworks.remove(
                networkId
            )

            statistics.incrementNetworkLost()

            logEvent(
                NetworkTrafficEventType.NETWORK_LOST,
                "Network lost: $networkId."
            )

            refreshCurrentNetworkState()
        }
    }

    /**
     * Handles network capability changes.
     */
    private fun handleCapabilitiesChanged(
        network: Network,
        capabilities:
            NetworkCapabilities
    ) {

        monitorScope.launch {

            val updatedRecord =
                createNetworkRecord(
                    network,
                    capabilities
                )

            activeNetworks[
                updatedRecord.networkId
            ] =
                updatedRecord

            statistics.incrementCapabilityChanges()

            logEvent(
                NetworkTrafficEventType.CAPABILITIES_CHANGED,
                "Network capabilities changed: " +
                        updatedRecord.networkId
            )

            refreshCurrentNetworkState()
        }
    }

    /**
     * Handles link-property changes.
     */
    private fun handleLinkPropertiesChanged(
        network: Network,
        linkProperties:
            android.net.LinkProperties
    ) {

        monitorScope.launch {

            val networkId =
                network.toString()

            val existing =
                activeNetworks[
                    networkId
                ]

            if (
                existing != null
            ) {

                activeNetworks[
                    networkId
                ] =
                    existing.copy(
                        interfaceName =
                            linkProperties
                                .interfaceName,

                        dnsServers =
                            linkProperties
                                .dnsServers
                                .map {
                                    it.hostAddress
                                        ?: ""
                                }
                                .filter {
                                    it.isNotBlank()
                                },

                        routes =
                            linkProperties
                                .routes
                                .map {
                                    it.toString()
                                },

                        lastUpdatedAt =
                            System.currentTimeMillis()
                    )
            }

            statistics.incrementLinkPropertyChanges()

            logEvent(
                NetworkTrafficEventType.LINK_PROPERTIES_CHANGED,
                "Network link properties changed: $networkId."
            )
        }
    }

    /**
     * Handles unavailable network callback.
     */
    private fun handleNetworkUnavailable() {

        statistics.incrementNetworkUnavailable()

        logEvent(
            NetworkTrafficEventType.NETWORK_UNAVAILABLE,
            "Requested network became unavailable."
        )

        monitorScope.launch {

            refreshCurrentNetworkState()
        }
    }

    /**
     * Creates a network record.
     */
    private fun createNetworkRecord(
        network: Network,
        capabilities:
            NetworkCapabilities?
    ): NetworkTrafficRecord {

        val networkId =
            network.toString()

        return NetworkTrafficRecord(

            networkId =
                networkId,

            transport =
                detectTransport(
                    capabilities
                ),

            metered =
                capabilities
                    ?.hasCapability(
                        NetworkCapabilities
                            .NET_CAPABILITY_NOT_METERED
                    )
                    ?.not()
                    ?: false,

            validated =
                capabilities
                    ?.hasCapability(
                        NetworkCapabilities
                            .NET_CAPABILITY_VALIDATED
                    )
                    ?: false,

            captivePortal =
                capabilities
                    ?.hasCapability(
                        NetworkCapabilities
                            .NET_CAPABILITY_CAPTIVE_PORTAL
                    )
                    ?: false,

            internetAvailable =
                capabilities
                    ?.hasCapability(
                        NetworkCapabilities
                            .NET_CAPABILITY_INTERNET
                    )
                    ?: false,

            downstreamKbps =
                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.M
                ) {
                    capabilities
                        ?.linkDownstreamBandwidthKbps
                } else {
                    null
                },

            upstreamKbps =
                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.M
                ) {
                    capabilities
                        ?.linkUpstreamBandwidthKbps
                } else {
                    null
                },

            lastUpdatedAt =
                System.currentTimeMillis()
        )
    }

    /**
     * Detects the network transport.
     */
    private fun detectTransport(
        capabilities:
            NetworkCapabilities?
    ): NetworkTransportType {

        if (
            capabilities == null
        ) {

            return NetworkTransportType.UNKNOWN
        }

        return when {

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_WIFI
            ) ->
                NetworkTransportType.WIFI

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_CELLULAR
            ) ->
                NetworkTransportType.CELLULAR

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_VPN
            ) ->
                NetworkTransportType.VPN

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_ETHERNET
            ) ->
                NetworkTransportType.ETHERNET

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_BLUETOOTH
            ) ->
                NetworkTransportType.BLUETOOTH

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_LOWPAN
            ) ->
                NetworkTransportType.LOWPAN

            else ->
                NetworkTransportType.UNKNOWN
        }
    }

    /**
     * Refreshes current network environment state.
     */
    private suspend fun refreshCurrentNetworkState() {

        checkCancellation()

        val networks =
            connectivityManager
                .allNetworks

        val records =
            networks
                .mapNotNull { network ->

                    val capabilities =
                        connectivityManager
                            .getNetworkCapabilities(
                                network
                            )

                    if (
                        capabilities == null
                    ) {

                        null

                    } else {

                        createNetworkRecord(
                            network,
                            capabilities
                        )
                    }
                }

        records.forEach { record ->

            activeNetworks[
                record.networkId
            ] =
                record
        }

        val currentNetwork =
            connectivityManager
                .activeNetwork

        val currentRecord =
            currentNetwork?.let {

                activeNetworks[
                    it.toString()
                ]
            }

        val environment =
            NetworkEnvironmentState(

                connected =
                    currentNetwork != null,

                currentTransport =
                    currentRecord
                        ?.transport
                        ?: NetworkTransportType.NONE,

                validated =
                    currentRecord
                        ?.validated
                        ?: false,

                metered =
                    currentRecord
                        ?.metered
                        ?: false,

                captivePortal =
                    currentRecord
                        ?.captivePortal
                        ?: false,

                internetAvailable =
                    currentRecord
                        ?.internetAvailable
                        ?: false,

                activeNetworkCount =
                    records.size,

                vpnActive =
                    records.any {
                        it.transport ==
                                NetworkTransportType.VPN
                    },

                lastUpdatedAt =
                    System.currentTimeMillis()
            )

        _networkState.emit(
            environment
        )
    }

    /**
     * Refreshes traffic statistics.
     *
     * TrafficStats provides device/interface level counters.
     * It does not provide arbitrary per-packet inspection.
     */
    private fun refreshTrafficStatistics() {

        val totalRx =
            android.net.TrafficStats
                .getTotalRxBytes()

        val totalTx =
            android.net.TrafficStats
                .getTotalTxBytes()

        if (
            totalRx !=
            UNKNOWN_TRAFFIC_VALUE
        ) {

            statistics.updateReceivedBytes(
                totalRx
            )
        }

        if (
            totalTx !=
            UNKNOWN_TRAFFIC_VALUE
        ) {

            statistics.updateTransmittedBytes(
                totalTx
            )
        }
    }

    /**
     * Records traffic observed by an upstream component.
     *
     * This is the method a future SentriX VpnService or application
     * networking interceptor can use to feed connection information
     * into this monitor.
     */
    fun recordTraffic(
        traffic:
            NetworkTrafficSample
    ) {

        if (
            traffic.bytesReceived < 0 ||
            traffic.bytesTransmitted < 0
        ) {

            return
        }

        statistics.incrementTrafficSamples()

        statistics.addReceivedBytes(
            traffic.bytesReceived
        )

        statistics.addTransmittedBytes(
            traffic.bytesTransmitted
        )

        when (
            traffic.direction
        ) {

            NetworkTrafficDirection.INBOUND ->
                statistics.incrementInboundConnections()

            NetworkTrafficDirection.OUTBOUND ->
                statistics.incrementOutboundConnections()

            NetworkTrafficDirection.BIDIRECTIONAL ->
                statistics.incrementBidirectionalConnections()
        }

        logEvent(
            NetworkTrafficEventType.TRAFFIC_OBSERVED,
            "Traffic observed: " +
                    "host=${traffic.host}, " +
                    "direction=${traffic.direction}, " +
                    "rx=${traffic.bytesReceived}, " +
                    "tx=${traffic.bytesTransmitted}."
        )
    }

    /**
     * Records a firewall network decision.
     *
     * This allows the monitor to correlate traffic with firewall
     * decisions.
     */
    fun recordFirewallDecision(
        request:
            FirewallNetworkRequest,
        result:
            FirewallEvaluationResult
    ) {

        statistics.incrementFirewallDecisions()

        when (
            result.decision
        ) {

            FirewallDecision.ALLOW ->
                statistics.incrementAllowedTraffic()

            FirewallDecision.BLOCK ->
                statistics.incrementBlockedTraffic()

            FirewallDecision.MONITOR ->
                statistics.incrementMonitoredTraffic()

            FirewallDecision.WARN ->
                statistics.incrementWarningTraffic()
        }

        logEvent(
            NetworkTrafficEventType.FIREWALL_DECISION,
            "Firewall decision=${result.decision}, " +
                    "host=${request.host}, " +
                    "reason=${result.reason}."
        )
    }

    /**
     * Returns current active networks.
     */
    fun getActiveNetworks():
            List<NetworkTrafficRecord> {

        return activeNetworks.values
            .sortedByDescending {
                it.lastUpdatedAt
            }
    }

    /**
     * Returns the current active network record.
     */
    fun getCurrentNetwork():
            NetworkTrafficRecord? {

        val activeNetwork =
            connectivityManager
                .activeNetwork
                ?: return null

        return activeNetworks[
            activeNetwork.toString()
        ]
    }

    /**
     * Returns whether an internet-capable network is available.
     */
    fun isInternetAvailable():
            Boolean {

        val network =
            connectivityManager
                .activeNetwork
                ?: return false

        val capabilities =
            connectivityManager
                .getNetworkCapabilities(
                    network
                )
                ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities
                .NET_CAPABILITY_INTERNET
        )
    }

    /**
     * Returns whether the active network is validated.
     */
    fun isNetworkValidated():
            Boolean {

        val network =
            connectivityManager
                .activeNetwork
                ?: return false

        val capabilities =
            connectivityManager
                .getNetworkCapabilities(
                    network
                )
                ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities
                .NET_CAPABILITY_VALIDATED
        )
    }

    /**
     * Returns whether VPN transport is currently present.
     */
    fun isVpnActive():
            Boolean {

        return activeNetworks.values.any {
            it.transport ==
                    NetworkTransportType.VPN
        }
    }

    /**
     * Returns current traffic statistics.
     */
    fun getStatistics():
            NetworkTrafficStatistics {

        return statistics.snapshot()
    }

    /**
     * Resets traffic counters.
     */
    fun resetStatistics() {

        statistics.reset()

        logEvent(
            NetworkTrafficEventType.STATISTICS_RESET,
            "Network traffic statistics reset."
        )
    }

    /**
     * Returns recent traffic events.
     */
    fun getEvents(
        limit: Int = 100
    ): List<NetworkTrafficEvent> {

        require(
            limit > 0
        ) {
            "Limit must be greater than zero."
        }

        return trafficEvents
            .take(
                limit
            )
    }

    /**
     * Clears event history.
     */
    fun clearEvents() {

        trafficEvents.clear()
    }

    /**
     * Adds an event to bounded history.
     */
    private fun logEvent(
        type:
            NetworkTrafficEventType,
        message:
            String
    ) {

        trafficEvents.addFirst(
            NetworkTrafficEvent(
                type =
                    type,

                message =
                    message
            )
        )

        while (
            trafficEvents.size >
            MAX_TRAFFIC_EVENTS
        ) {

            trafficEvents.pollLast()
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
                "Network monitoring operation was cancelled."
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

        monitoringJob?.cancel()

        monitoringJob = null

        try {

            connectivityManager
                .unregisterNetworkCallback(
                    connectivityCallback
                )

        } catch (
            _: Exception
        ) {
            // Callback may not be registered.
        }

        activeNetworks.clear()

        monitorScope.cancel()
    }
}

/**
 * Network record maintained by SentriX.
 */
data class NetworkTrafficRecord(

    /**
     * Android network identifier.
     */
    val networkId:
        String,

    /**
     * Detected transport type.
     */
    val transport:
        NetworkTransportType,

    /**
     * Whether network is metered.
     */
    val metered:
        Boolean,

    /**
     * Whether Android validated the network.
     */
    val validated:
        Boolean,

    /**
     * Whether a captive portal was detected.
     */
    val captivePortal:
        Boolean,

    /**
     * Whether the network advertises internet capability.
     */
    val internetAvailable:
        Boolean,

    /**
     * Estimated downstream bandwidth.
     */
    val downstreamKbps:
        Int? = null,

    /**
     * Estimated upstream bandwidth.
     */
    val upstreamKbps:
        Int? = null,

    /**
     * Network interface.
     */
    val interfaceName:
        String? = null,

    /**
     * DNS servers.
     */
    val dnsServers:
        List<String> = emptyList(),

    /**
     * Network routes.
     */
    val routes:
        List<String> = emptyList(),

    /**
     * Last update time.
     */
    val lastUpdatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Current network environment state.
 */
data class NetworkEnvironmentState(

    val connected:
        Boolean = false,

    val currentTransport:
        NetworkTransportType =
        NetworkTransportType.NONE,

    val validated:
        Boolean = false,

    val metered:
        Boolean = false,

    val captivePortal:
        Boolean = false,

    val internetAvailable:
        Boolean = false,

    val activeNetworkCount:
        Int = 0,

    val vpnActive:
        Boolean = false,

    val lastUpdatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Traffic sample supplied by an upstream traffic source.
 *
 * This can later be populated by:
 *
 * - SentriX VpnService
 * - OkHttp interceptor
 * - WebSocket layer
 * - application networking layer
 */
data class NetworkTrafficSample(

    val host:
        String,

    val port:
        Int? = null,

    val protocol:
        FirewallProtocol =
        FirewallProtocol.ANY,

    val packageName:
        String? = null,

    val direction:
        NetworkTrafficDirection,

    val bytesReceived:
        Long = 0L,

    val bytesTransmitted:
        Long = 0L,

    val encrypted:
        Boolean = true,

    val timestamp:
        Long =
        System.currentTimeMillis()
)

/**
 * Traffic direction.
 */
enum class NetworkTrafficDirection {

    INBOUND,

    OUTBOUND,

    BIDIRECTIONAL
}

/**
 * Network transport type.
 */
enum class NetworkTransportType {

    WIFI,

    CELLULAR,

    VPN,

    ETHERNET,

    BLUETOOTH,

    LOWPAN,

    UNKNOWN,

    NONE
}

/**
 * Network monitor operation result.
 */
data class NetworkMonitorOperationResult(

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
                NetworkMonitorOperationResult {

            return NetworkMonitorOperationResult(
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
                NetworkMonitorOperationResult {

            return NetworkMonitorOperationResult(
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
 * Network traffic statistics.
 */
data class NetworkTrafficStatistics(

    val trafficSamples:
        Long,

    val receivedBytes:
        Long,

    val transmittedBytes:
        Long,

    val inboundConnections:
        Long,

    val outboundConnections:
        Long,

    val bidirectionalConnections:
        Long,

    val networkAvailableEvents:
        Long,

    val networkLostEvents:
        Long,

    val networkUnavailableEvents:
        Long,

    val capabilityChanges:
        Long,

    val linkPropertyChanges:
        Long,

    val firewallDecisions:
        Long,

    val allowedTraffic:
        Long,

    val blockedTraffic:
        Long,

    val monitoredTraffic:
        Long,

    val warningTraffic:
        Long
)

/**
 * Thread-safe network statistics counter.
 */
private class NetworkTrafficStatisticsCounter {

    private val trafficSamples =
        AtomicLong(0)

    private val receivedBytes =
        AtomicLong(0)

    private val transmittedBytes =
        AtomicLong(0)

    private val inboundConnections =
        AtomicLong(0)

    private val outboundConnections =
        AtomicLong(0)

    private val bidirectionalConnections =
        AtomicLong(0)

    private val networkAvailableEvents =
        AtomicLong(0)

    private val networkLostEvents =
        AtomicLong(0)

    private val networkUnavailableEvents =
        AtomicLong(0)

    private val capabilityChanges =
        AtomicLong(0)

    private val linkPropertyChanges =
        AtomicLong(0)

    private val firewallDecisions =
        AtomicLong(0)

    private val allowedTraffic =
        AtomicLong(0)

    private val blockedTraffic =
        AtomicLong(0)

    private val monitoredTraffic =
        AtomicLong(0)

    private val warningTraffic =
        AtomicLong(0)

    private val totalReceivedSnapshot =
        AtomicLong(0)

    private val totalTransmittedSnapshot =
        AtomicLong(0)

    fun incrementTrafficSamples() {
        trafficSamples.incrementAndGet()
    }

    fun addReceivedBytes(
        bytes:
            Long
    ) {

        if (
            bytes > 0
        ) {

            receivedBytes.addAndGet(
                bytes
            )
        }
    }

    fun addTransmittedBytes(
        bytes:
            Long
    ) {

        if (
            bytes > 0
        ) {

            transmittedBytes.addAndGet(
                bytes
            )
        }
    }

    fun updateReceivedBytes(
        bytes:
            Long
    ) {

        if (
            bytes >= 0
        ) {

            totalReceivedSnapshot.set(
                bytes
            )
        }
    }

    fun updateTransmittedBytes(
        bytes:
            Long
    ) {

        if (
            bytes >= 0
        ) {

            totalTransmittedSnapshot.set(
                bytes
            )
        }
    }

    fun incrementInboundConnections() {
        inboundConnections.incrementAndGet()
    }

    fun incrementOutboundConnections() {
        outboundConnections.incrementAndGet()
    }

    fun incrementBidirectionalConnections() {
        bidirectionalConnections.incrementAndGet()
    }

    fun incrementNetworkAvailable() {
        networkAvailableEvents.incrementAndGet()
    }

    fun incrementNetworkLost() {
        networkLostEvents.incrementAndGet()
    }

    fun incrementNetworkUnavailable() {
        networkUnavailableEvents.incrementAndGet()
    }

    fun incrementCapabilityChanges() {
        capabilityChanges.incrementAndGet()
    }

    fun incrementLinkPropertyChanges() {
        linkPropertyChanges.incrementAndGet()
    }

    fun incrementFirewallDecisions() {
        firewallDecisions.incrementAndGet()
    }

    fun incrementAllowedTraffic() {
        allowedTraffic.incrementAndGet()
    }

    fun incrementBlockedTraffic() {
        blockedTraffic.incrementAndGet()
    }

    fun incrementMonitoredTraffic() {
        monitoredTraffic.incrementAndGet()
    }

    fun incrementWarningTraffic() {
        warningTraffic.incrementAndGet()
    }

    fun snapshot():
            NetworkTrafficStatistics {

        return NetworkTrafficStatistics(

            trafficSamples =
                trafficSamples.get(),

            receivedBytes =
                maxOf(
                    receivedBytes.get(),
                    totalReceivedSnapshot.get()
                ),

            transmittedBytes =
                maxOf(
                    transmittedBytes.get(),
                    totalTransmittedSnapshot.get()
                ),

            inboundConnections =
                inboundConnections.get(),

            outboundConnections =
                outboundConnections.get(),

            bidirectionalConnections =
                bidirectionalConnections.get(),

            networkAvailableEvents =
                networkAvailableEvents.get(),

            networkLostEvents =
                networkLostEvents.get(),

            networkUnavailableEvents =
                networkUnavailableEvents.get(),

            capabilityChanges =
                capabilityChanges.get(),

            linkPropertyChanges =
                linkPropertyChanges.get(),

            firewallDecisions =
                firewallDecisions.get(),

            allowedTraffic =
                allowedTraffic.get(),

            blockedTraffic =
                blockedTraffic.get(),

            monitoredTraffic =
                monitoredTraffic.get(),

            warningTraffic =
                warningTraffic.get()
        )
    }

    fun reset() {

        trafficSamples.set(0)
        receivedBytes.set(0)
        transmittedBytes.set(0)
        inboundConnections.set(0)
        outboundConnections.set(0)
        bidirectionalConnections.set(0)
        networkAvailableEvents.set(0)
        networkLostEvents.set(0)
        networkUnavailableEvents.set(0)
        capabilityChanges.set(0)
        linkPropertyChanges.set(0)
        firewallDecisions.set(0)
        allowedTraffic.set(0)
        blockedTraffic.set(0)
        monitoredTraffic.set(0)
        warningTraffic.set(0)
        totalReceivedSnapshot.set(0)
        totalTransmittedSnapshot.set(0)
    }
}

/**
 * Network traffic event.
 */
data class NetworkTrafficEvent(

    val type:
        NetworkTrafficEventType,

    val message:
        String,

    val timestamp:
        Long =
        System.currentTimeMillis()
)

/**
 * Network traffic event types.
 */
enum class NetworkTrafficEventType {

    MONITORING_STARTED,

    MONITORING_STOPPED,

    NETWORK_AVAILABLE,

    NETWORK_LOST,

    NETWORK_UNAVAILABLE,

    CAPABILITIES_CHANGED,

    LINK_PROPERTIES_CHANGED,

    TRAFFIC_OBSERVED,

    FIREWALL_DECISION,

    STATISTICS_RESET
}
