package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNConnectionManager
 *
 * Enterprise-grade VPN connection/session manager for SentriX.
 *
 * Responsibilities:
 *
 * - Create VPN connection sessions.
 * - Track active VPN connections.
 * - Track connection state transitions.
 * - Track connection start/end timestamps.
 * - Track VPN endpoints.
 * - Track DNS configuration.
 * - Track traffic statistics.
 * - Track reconnect attempts.
 * - Maintain connection history.
 * - Provide connection search/filter APIs.
 * - Expose reactive connection state.
 * - Calculate connection duration.
 *
 * This class does NOT:
 *
 * - Create Android VpnService tunnels.
 * - Read/write TUN packets.
 * - Make firewall decisions.
 * - Perform threat analysis.
 * - Modify VPN security policies.
 *
 * Those responsibilities belong to:
 *
 * VPNService
 * VPNEngine
 * FirewallEngine
 * VPNTrafficAnalyzer
 * VPNManager
 *
 * Architecture:
 *
 *                    VPNManager
 *                         |
 *                         v
 *                VPNConnectionManager
 *                         |
 *          ┌──────────────┼───────────────┐
 *          ▼              ▼               ▼
 *      Active Session   State Flow    History
 *          |
 *          ▼
 *     VPNConnection
 *
 * Typical lifecycle:
 *
 * DISCONNECTED
 *      |
 *      v
 * CONNECTING
 *      |
 *      ├──── failure ────> FAILED
 *      |
 *      v
 * CONNECTED
 *      |
 *      ├──── reconnect ──> RECONNECTING
 *      |
 *      └──── stop ───────> DISCONNECTING
 *                              |
 *                              v
 *                         DISCONNECTED
 */
class VPNConnectionManager(
    context: Context,
    private val configuration:
        VPNConnectionManagerConfiguration =
        VPNConnectionManagerConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNConnectionManager"

        private const val MAX_HISTORY =
            25_000

        private const val DEFAULT_QUERY_LIMIT =
            100
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Active connection map.
     */
    private val activeConnections =
        ConcurrentHashMap<
            String,
            VPNConnection
        >()

    /**
     * Connection history.
     *
     * Newest connection is placed first.
     */
    private val connectionHistory =
        ConcurrentLinkedDeque<
            VPNConnection
        >()

    /**
     * Current primary VPN connection.
     */
    private val _currentConnection =
        MutableStateFlow<VPNConnection?>(
            null
        )

    /**
     * Public current connection state.
     */
    val currentConnection:
        StateFlow<VPNConnection?> =
        _currentConnection.asStateFlow()

    /**
     * Number of active connections.
     */
    private val _activeConnectionCount =
        MutableStateFlow(0)

    /**
     * Public active connection count.
     */
    val activeConnectionCount:
        StateFlow<Int> =
        _activeConnectionCount.asStateFlow()

    /**
     * Connection statistics.
     */
    private val statistics =
        VPNConnectionStatisticsCounter()

    /**
     * Initializes the manager.
     */
    suspend fun initialize():
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            Log.i(
                TAG,
                "VPNConnectionManager initialized."
            )

            VPNConnectionOperationResult.success(
                "VPN connection manager initialized successfully."
            )
        }

    /**
     * Creates a new VPN connection.
     *
     * The connection initially enters CONNECTING state.
     */
    suspend fun createConnection(
        endpoint:
            VPNEndpoint,
        securityMode:
            VPNSecurityMode =
            VPNSecurityMode.BALANCED,
        configuration:
            VPNConfiguration =
            VPNConfiguration()
    ):
            VPNConnectionResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val validation =
                validateEndpoint(
                    endpoint
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    VPNConnectionResult.failure(
                        validation.message
                    )
            }

            val connectionId =
                generateConnectionId()

            val now =
                System.currentTimeMillis()

            val connection =
                VPNConnection(

                    id =
                        connectionId,

                    endpoint =
                        endpoint,

                    status =
                        VPNConnectionStatus.CONNECTING,

                    securityMode =
                        securityMode,

                    localAddress =
                        configuration.localAddress,

                    serverAddress =
                        endpoint.host,

                    dnsServers =
                        configuration.dnsServers,

                    mtu =
                        configuration.mtu,

                    createdAt =
                        now,

                    connectedAt =
                        null,

                    disconnectedAt =
                        null,

                    lastStateChangeAt =
                        now,

                    reconnectAttempts =
                        0,

                    bytesSent =
                        0,

                    bytesReceived =
                        0,

                    packetsSent =
                        0,

                    packetsReceived =
                        0,

                    errorMessage =
                        null
                )

            activeConnections[
                connectionId
            ] =
                connection

            _currentConnection.value =
                connection

            updateActiveCount()

            statistics.incrementCreated()

            Log.d(
                TAG,
                "VPN connection created: $connectionId"
            )

            VPNConnectionResult.success(
                connection
            )
        }

    /**
     * Marks a connection as connected.
     */
    suspend fun markConnected(
        connectionId:
            String,
        connectionInfo:
            VPNConnectionInfo? =
            null
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            if (
                existing.status ==
                VPNConnectionStatus.CONNECTED
            ) {

                return@withContext
                    VPNConnectionOperationResult.success(
                        "VPN connection is already connected."
                    )
            }

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.CONNECTED,

                    localAddress =
                        connectionInfo
                            ?.localAddress
                            ?: existing.localAddress,

                    serverAddress =
                        connectionInfo
                            ?.serverAddress
                            ?: existing.serverAddress,

                    dnsServers =
                        connectionInfo
                            ?.dnsServers
                            ?: existing.dnsServers,

                    mtu =
                        connectionInfo
                            ?.mtu
                            ?: existing.mtu,

                    connectedAt =
                        existing.connectedAt
                            ?: now,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        null
                )

            replaceActiveConnection(
                updated
            )

            statistics.incrementConnected()

            Log.i(
                TAG,
                "VPN connection connected: $connectionId"
            )

            VPNConnectionOperationResult.success(
                "VPN connection marked as connected."
            )
        }

    /**
     * Marks a connection as disconnecting.
     */
    suspend fun markDisconnecting(
        connectionId:
            String,
        reason:
            String? =
            null
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.DISCONNECTING,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        reason
                )

            replaceActiveConnection(
                updated
            )

            VPNConnectionOperationResult.success(
                "VPN connection marked as disconnecting."
            )
        }

    /**
     * Marks a connection as disconnected and moves it
     * to connection history.
     */
    suspend fun markDisconnected(
        connectionId:
            String,
        reason:
            String? =
            null
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections.remove(
                    connectionId
                )
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.DISCONNECTED,

                    disconnectedAt =
                        now,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        reason
                )

            addToHistory(
                updated
            )

            updateCurrentConnectionAfterRemoval(
                connectionId
            )

            updateActiveCount()

            statistics.incrementDisconnected()

            if (
                existing.connectedAt != null
            ) {

                statistics.recordDuration(
                    now -
                            existing.connectedAt
                )
            }

            Log.i(
                TAG,
                "VPN connection disconnected: $connectionId"
            )

            VPNConnectionOperationResult.success(
                "VPN connection disconnected."
            )
        }

    /**
     * Marks a connection as failed.
     */
    suspend fun markFailed(
        connectionId:
            String,
        error:
            String
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections.remove(
                    connectionId
                )
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.FAILED,

                    disconnectedAt =
                        now,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        error
                )

            addToHistory(
                updated
            )

            updateCurrentConnectionAfterRemoval(
                connectionId
            )

            updateActiveCount()

            statistics.incrementFailed()

            Log.e(
                TAG,
                "VPN connection failed: $connectionId - $error"
            )

            VPNConnectionOperationResult.success(
                "VPN connection marked as failed."
            )
        }

    /**
     * Starts a reconnect attempt.
     */
    suspend fun startReconnect(
        connectionId:
            String
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            if (
                existing.reconnectAttempts >=
                configuration
                    .maximumReconnectAttempts
            ) {

                return@withContext
                    VPNConnectionOperationResult.failure(
                        "Maximum VPN reconnect attempts reached."
                    )
            }

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.RECONNECTING,

                    reconnectAttempts =
                        existing.reconnectAttempts + 1,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        null
                )

            replaceActiveConnection(
                updated
            )

            statistics.incrementReconnectAttempts()

            Log.w(
                TAG,
                "VPN reconnect attempt " +
                        "${updated.reconnectAttempts} " +
                        "for $connectionId"
            )

            VPNConnectionOperationResult.success(
                "VPN reconnect attempt registered."
            )
        }

    /**
     * Marks a reconnect attempt as successful.
     */
    suspend fun markReconnectSuccessful(
        connectionId:
            String,
        connectionInfo:
            VPNConnectionInfo? =
            null
    ):
            VPNConnectionOperationResult {

        return markConnected(
            connectionId,
            connectionInfo
        )
    }

    /**
     * Records reconnect failure.
     */
    suspend fun markReconnectFailed(
        connectionId:
            String,
        error:
            String
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val now =
                System.currentTimeMillis()

            val updated =
                existing.copy(

                    status =
                        VPNConnectionStatus.RECONNECTING,

                    lastStateChangeAt =
                        now,

                    errorMessage =
                        error
                )

            replaceActiveConnection(
                updated
            )

            statistics.incrementReconnectFailures()

            VPNConnectionOperationResult.success(
                "VPN reconnect failure recorded."
            )
        }

    /**
     * Updates traffic counters.
     */
    suspend fun updateTraffic(
        connectionId:
            String,
        bytesSent:
            Long,
        bytesReceived:
            Long,
        packetsSent:
            Long,
        packetsReceived:
            Long
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                bytesSent < 0 ||
                bytesReceived < 0 ||
                packetsSent < 0 ||
                packetsReceived < 0
            ) {

                return@withContext
                    VPNConnectionOperationResult.failure(
                        "Traffic counters cannot be negative."
                    )
            }

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val updated =
                existing.copy(

                    bytesSent =
                        bytesSent,

                    bytesReceived =
                        bytesReceived,

                    packetsSent =
                        packetsSent,

                    packetsReceived =
                        packetsReceived
                )

            replaceActiveConnection(
                updated
            )

            statistics.updateTraffic(
                bytesSent =
                    bytesSent,

                bytesReceived =
                    bytesReceived,

                packetsSent =
                    packetsSent,

                packetsReceived =
                    packetsReceived
            )

            VPNConnectionOperationResult.success(
                "VPN traffic statistics updated."
            )
        }

    /**
     * Updates connection security mode.
     */
    suspend fun updateSecurityMode(
        connectionId:
            String,
        securityMode:
            VPNSecurityMode
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val updated =
                existing.copy(
                    securityMode =
                        securityMode,

                    lastStateChangeAt =
                        System.currentTimeMillis()
                )

            replaceActiveConnection(
                updated
            )

            VPNConnectionOperationResult.success(
                "VPN security mode updated."
            )
        }

    /**
     * Updates the endpoint of an active connection.
     */
    suspend fun updateEndpoint(
        connectionId:
            String,
        endpoint:
            VPNEndpoint
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val validation =
                validateEndpoint(
                    endpoint
                )

            if (
                !validation.valid
            ) {

                return@withContext
                    VPNConnectionOperationResult.failure(
                        validation.message
                    )
            }

            val existing =
                activeConnections[
                    connectionId
                ]
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "VPN connection not found."
                        )

            val updated =
                existing.copy(
                    endpoint =
                        endpoint,

                    serverAddress =
                        endpoint.host,

                    lastStateChangeAt =
                        System.currentTimeMillis()
                )

            replaceActiveConnection(
                updated
            )

            VPNConnectionOperationResult.success(
                "VPN endpoint updated."
            )
        }

    /**
     * Returns an active connection.
     */
    fun getConnection(
        connectionId:
            String
    ):
            VPNConnection? {

        return activeConnections[
            connectionId
        ]
    }

    /**
     * Returns all active connections.
     */
    fun getActiveConnections():
            List<VPNConnection> {

        return activeConnections.values
            .sortedByDescending {
                it.createdAt
            }
    }

    /**
     * Returns all connection history.
     */
    fun getConnectionHistory():
            List<VPNConnection> {

        return connectionHistory.toList()
    }

    /**
     * Returns recent connection history.
     */
    fun getRecentConnections(
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        validateLimit(
            limit
        )

        return connectionHistory
            .take(
                limit
            )
    }

    /**
     * Returns connections by status.
     */
    fun getConnectionsByStatus(
        status:
            VPNConnectionStatus,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        validateLimit(
            limit
        )

        val active =
            activeConnections.values
                .filter {
                    it.status == status
                }

        val history =
            connectionHistory
                .filter {
                    it.status == status
                }

        return (
                active + history
                )
            .distinctBy {
                it.id
            }
            .sortedByDescending {
                it.createdAt
            }
            .take(
                limit
            )
    }

    /**
     * Returns connections by endpoint.
     */
    fun getConnectionsByHost(
        host:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        validateLimit(
            limit
        )

        val normalized =
            host
                .trim()
                .lowercase()

        return getAllKnownConnections()
            .filter {
                it.endpoint.host
                    .lowercase() ==
                        normalized
            }
            .take(
                limit
            )
    }

    /**
     * Returns connections by port.
     */
    fun getConnectionsByPort(
        port:
            Int,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        require(
            port in 1..65535
        ) {
            "Port must be between 1 and 65535."
        }

        validateLimit(
            limit
        )

        return getAllKnownConnections()
            .filter {
                it.endpoint.port ==
                        port
            }
            .take(
                limit
            )
    }

    /**
     * Returns connections using a security mode.
     */
    fun getConnectionsBySecurityMode(
        mode:
            VPNSecurityMode,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        validateLimit(
            limit
        )

        return getAllKnownConnections()
            .filter {
                it.securityMode == mode
            }
            .take(
                limit
            )
    }

    /**
     * Searches connections.
     */
    fun searchConnections(
        query:
            String,
        limit:
            Int =
            DEFAULT_QUERY_LIMIT
    ):
            List<VPNConnection> {

        validateLimit(
            limit
        )

        if (
            query.isBlank()
        ) {

            return getRecentConnections(
                limit
            )
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return getAllKnownConnections()
            .filter {

                it.id
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        it.endpoint.host
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        it.endpoint.protocol
                            .name
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        it.status
                            .name
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        it.securityMode
                            .name
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        it.errorMessage
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
     * Returns currently connected connections.
     */
    fun getConnectedConnections():
            List<VPNConnection> {

        return activeConnections.values
            .filter {
                it.status ==
                        VPNConnectionStatus.CONNECTED
            }
            .sortedByDescending {
                it.connectedAt ?: 0L
            }
    }

    /**
     * Returns connection duration.
     */
    fun getConnectionDuration(
        connectionId:
            String,
        now:
            Long =
            System.currentTimeMillis()
    ):
            Long? {

        val connection =
            getConnection(
                connectionId
            )
                ?: connectionHistory
                    .firstOrNull {
                        it.id ==
                                connectionId
                    }
                ?: return null

        val start =
            connection.connectedAt
                ?: return null

        val end =
            connection.disconnectedAt
                ?: now

        return (
            end - start
            ).coerceAtLeast(
                0L
            )
    }

    /**
     * Returns aggregate statistics.
     */
    fun getStatistics():
            VPNConnectionStatistics {

        return statistics.snapshot(
            activeConnections =
                activeConnections.size,

            historySize =
                connectionHistory.size
        )
    }

    /**
     * Disconnects all active connections.
     *
     * This only updates connection-management state.
     * Actual VPN tunnel shutdown belongs to VPNService.
     */
    suspend fun disconnectAll(
        reason:
            String =
            "All VPN connections disconnected."
    ):
            VPNConnectionBatchResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val ids =
                activeConnections.keys.toList()

            var disconnected =
                0

            val failed =
                mutableListOf<String>()

            ids.forEach { id ->

                val result =
                    markDisconnected(
                        connectionId =
                            id,

                        reason =
                            reason
                    )

                if (
                    result.success
                ) {

                    disconnected++

                } else {

                    failed.add(
                        id
                    )
                }
            }

            VPNConnectionBatchResult(
                processed =
                    ids.size,

                disconnected =
                    disconnected,

                failed =
                    failed
            )
        }

    /**
     * Removes one historical connection.
     */
    suspend fun removeHistoryEntry(
        connectionId:
            String
    ):
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val entry =
                connectionHistory
                    .firstOrNull {
                        it.id ==
                                connectionId
                    }
                    ?: return@withContext
                        VPNConnectionOperationResult.failure(
                            "Connection history entry not found."
                        )

            connectionHistory.remove(
                entry
            )

            statistics.incrementHistoryRemoved()

            VPNConnectionOperationResult.success(
                "Connection history entry removed."
            )
        }

    /**
     * Clears connection history.
     */
    suspend fun clearHistory():
            VPNConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                connectionHistory.size

            connectionHistory.clear()

            statistics.incrementHistoryCleared(
                count
            )

            VPNConnectionOperationResult.success(
                "VPN connection history cleared."
            )
        }

    /**
     * Validates an endpoint.
     */
    fun validateEndpoint(
        endpoint:
            VPNEndpoint
    ):
            VPNEndpointValidationResult {

        if (
            endpoint.host.isBlank()
        ) {

            return VPNEndpointValidationResult.invalid(
                "VPN endpoint host cannot be blank."
            )
        }

        if (
            endpoint.port !in 1..65535
        ) {

            return VPNEndpointValidationResult.invalid(
                "VPN endpoint port must be between 1 and 65535."
            )
        }

        if (
            endpoint.protocol ==
            VPNTransportProtocol.UNKNOWN
        ) {

            return VPNEndpointValidationResult.invalid(
                "VPN endpoint protocol is unknown."
            )
        }

        return VPNEndpointValidationResult.valid()
    }

    /**
     * Replaces an active connection.
     */
    private fun replaceActiveConnection(
        connection:
            VPNConnection
    ) {

        activeConnections[
            connection.id
        ] =
            connection

        if (
            _currentConnection.value?.id ==
            connection.id
        ) {

            _currentConnection.value =
                connection

        } else if (
            _currentConnection.value == null
        ) {

            _currentConnection.value =
                connection
        }
    }

    /**
     * Updates current connection after it has been removed.
     */
    private fun updateCurrentConnectionAfterRemoval(
        removedConnectionId:
            String
    ) {

        if (
            _currentConnection.value?.id !=
            removedConnectionId
        ) {

            return
        }

        _currentConnection.value =
            activeConnections.values
                .maxByOrNull {
                    it.createdAt
                }
    }

    /**
     * Updates active-connection count.
     */
    private fun updateActiveCount() {

        _activeConnectionCount.value =
            activeConnections.size
    }

    /**
     * Adds connection to history.
     */
    private fun addToHistory(
        connection:
            VPNConnection
    ) {

        connectionHistory.addFirst(
            connection
        )

        while (
            connectionHistory.size >
            configuration
                .maximumHistorySize
                .coerceIn(
                    1,
                    MAX_HISTORY
                )
        ) {

            connectionHistory.pollLast()
        }
    }

    /**
     * Returns active + historical connections.
     */
    private fun getAllKnownConnections():
            List<VPNConnection> {

        return (
                activeConnections.values +
                        connectionHistory
                )
            .distinctBy {
                it.id
            }
            .sortedByDescending {
                it.createdAt
            }
    }

    /**
     * Generates connection ID.
     */
    private fun generateConnectionId():
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
            "Query limit must be greater than zero."
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
                "VPN connection operation was cancelled."
            )
        }
    }

    /**
     * Releases manager resources.
     *
     * Active connections are not silently marked as
     * disconnected here because actual tunnel shutdown
     * should be coordinated by VPNService.
     */
    fun close() {

        activeConnections.clear()

        connectionHistory.clear()

        _currentConnection.value =
            null

        _activeConnectionCount.value =
            0

        Log.i(
            TAG,
            "VPNConnectionManager closed."
        )
    }
}

/**
 * Represents a VPN endpoint.
 */
data class VPNEndpoint(

    /**
     * Remote VPN server hostname or IP.
     */
    val host:
        String,

    /**
     * Remote VPN server port.
     */
    val port:
        Int,

    /**
     * Transport protocol.
     */
    val protocol:
        VPNTransportProtocol =
        VPNTransportProtocol.UDP,

    /**
     * Optional endpoint identifier.
     */
    val id:
        String? = null,

    /**
     * Optional region.
     */
    val region:
        String? = null
)

/**
 * VPN transport protocols.
 */
enum class VPNTransportProtocol {

    UDP,

    TCP,

    QUIC,

    WIREGUARD,

    IPSEC,

    OPENVPN,

    UNKNOWN
}

/**
 * VPN connection lifecycle state.
 */
enum class VPNConnectionStatus {

    CONNECTING,

    CONNECTED,

    DISCONNECTING,

    DISCONNECTED,

    RECONNECTING,

    FAILED
}

/**
 * Represents one VPN connection/session.
 */
data class VPNConnection(

    /**
     * Unique connection identifier.
     */
    val id:
        String,

    /**
     * VPN endpoint.
     */
    val endpoint:
        VPNEndpoint,

    /**
     * Current connection state.
     */
    val status:
        VPNConnectionStatus,

    /**
     * VPN security mode.
     */
    val securityMode:
        VPNSecurityMode,

    /**
     * Local VPN address.
     */
    val localAddress:
        String,

    /**
     * VPN server address.
     */
    val serverAddress:
        String?,

    /**
     * DNS servers.
     */
    val dnsServers:
        List<String>,

    /**
     * VPN MTU.
     */
    val mtu:
        Int,

    /**
     * Connection creation time.
     */
    val createdAt:
        Long,

    /**
     * Actual successful connection time.
     */
    val connectedAt:
        Long?,

    /**
     * Disconnection/failure time.
     */
    val disconnectedAt:
        Long?,

    /**
     * Last state transition timestamp.
     */
    val lastStateChangeAt:
        Long,

    /**
     * Number of reconnect attempts.
     */
    val reconnectAttempts:
        Int,

    /**
     * Bytes sent.
     */
    val bytesSent:
        Long,

    /**
     * Bytes received.
     */
    val bytesReceived:
        Long,

    /**
     * Packets sent.
     */
    val packetsSent:
        Long,

    /**
     * Packets received.
     */
    val packetsReceived:
        Long,

    /**
     * Last error message.
     */
    val errorMessage:
        String?
)

/**
 * Connection manager configuration.
 */
data class VPNConnectionManagerConfiguration(

    /**
     * Maximum retained connection history.
     */
    val maximumHistorySize:
        Int = 10_000,

    /**
     * Maximum automatic reconnect attempts.
     */
    val maximumReconnectAttempts:
        Int = 5
)

/**
 * Connection operation result.
 */
data class VPNConnectionOperationResult(

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
                VPNConnectionOperationResult {

            return VPNConnectionOperationResult(
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
                VPNConnectionOperationResult {

            return VPNConnectionOperationResult(
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
 * Connection creation result.
 */
data class VPNConnectionResult(

    val success:
        Boolean,

    val connection:
        VPNConnection?,

    val message:
        String
) {

    companion object {

        fun success(
            connection:
                VPNConnection
        ):
                VPNConnectionResult {

            return VPNConnectionResult(
                success =
                    true,

                connection =
                    connection,

                message =
                    "VPN connection created successfully."
            )
        }

        fun failure(
            message:
                String
        ):
                VPNConnectionResult {

            return VPNConnectionResult(
                success =
                    false,

                connection =
                    null,

                message =
                    message
            )
        }
    }
}

/**
 * Endpoint validation result.
 */
data class VPNEndpointValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                VPNEndpointValidationResult {

            return VPNEndpointValidationResult(
                valid =
                    true,

                message =
                    "VPN endpoint is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                VPNEndpointValidationResult {

            return VPNEndpointValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Batch disconnect result.
 */
data class VPNConnectionBatchResult(

    val processed:
        Int,

    val disconnected:
        Int,

    val failed:
        List<String>
)

/**
 * VPN connection statistics.
 */
data class VPNConnectionStatistics(

    val activeConnections:
        Int,

    val historySize:
        Int,

    val created:
        Long,

    val connected:
        Long,

    val disconnected:
        Long,

    val failed:
        Long,

    val reconnectAttempts:
        Long,

    val reconnectFailures:
        Long,

    val totalBytesSent:
        Long,

    val totalBytesReceived:
        Long,

    val totalPacketsSent:
        Long,

    val totalPacketsReceived:
        Long,

    val totalConnectionDurationMs:
        Long,

    val historyRemoved:
        Long,

    val historyCleared:
        Long,

    val validationFailures:
        Long
)

/**
 * Thread-safe VPN connection statistics counter.
 */
private class VPNConnectionStatisticsCounter {

    private val created =
        AtomicLong(0)

    private val connected =
        AtomicLong(0)

    private val disconnected =
        AtomicLong(0)

    private val failed =
        AtomicLong(0)

    private val reconnectAttempts =
        AtomicLong(0)

    private val reconnectFailures =
        AtomicLong(0)

    private val totalBytesSent =
        AtomicLong(0)

    private val totalBytesReceived =
        AtomicLong(0)

    private val totalPacketsSent =
        AtomicLong(0)

    private val totalPacketsReceived =
        AtomicLong(0)

    private val totalConnectionDurationMs =
        AtomicLong(0)

    private val historyRemoved =
        AtomicLong(0)

    private val historyCleared =
        AtomicLong(0)

    private val validationFailures =
        AtomicLong(0)

    fun incrementCreated() {
        created.incrementAndGet()
    }

    fun incrementConnected() {
        connected.incrementAndGet()
    }

    fun incrementDisconnected() {
        disconnected.incrementAndGet()
    }

    fun incrementFailed() {
        failed.incrementAndGet()
    }

    fun incrementReconnectAttempts() {
        reconnectAttempts.incrementAndGet()
    }

    fun incrementReconnectFailures() {
        reconnectFailures.incrementAndGet()
    }

    fun updateTraffic(
        bytesSent:
            Long,
        bytesReceived:
            Long,
        packetsSent:
            Long,
        packetsReceived:
            Long
    ) {

        totalBytesSent.updateAndGet {
            maxOf(
                it,
                bytesSent
            )
        }

        totalBytesReceived.updateAndGet {
            maxOf(
                it,
                bytesReceived
            )
        }

        totalPacketsSent.updateAndGet {
            maxOf(
                it,
                packetsSent
            )
        }

        totalPacketsReceived.updateAndGet {
            maxOf(
                it,
                packetsReceived
            )
        }
    }

    fun recordDuration(
        duration:
            Long
    ) {

        if (
            duration > 0
        ) {

            totalConnectionDurationMs
                .addAndGet(
                    duration
                )
        }
    }

    fun incrementHistoryRemoved() {
        historyRemoved.incrementAndGet()
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

    fun incrementValidationFailures() {
        validationFailures.incrementAndGet()
    }

    fun snapshot(
        activeConnections:
            Int,
        historySize:
            Int
    ):
            VPNConnectionStatistics {

        return VPNConnectionStatistics(

            activeConnections =
                activeConnections,

            historySize =
                historySize,

            created =
                created.get(),

            connected =
                connected.get(),

            disconnected =
                disconnected.get(),

            failed =
                failed.get(),

            reconnectAttempts =
                reconnectAttempts.get(),

            reconnectFailures =
                reconnectFailures.get(),

            totalBytesSent =
                totalBytesSent.get(),

            totalBytesReceived =
                totalBytesReceived.get(),

            totalPacketsSent =
                totalPacketsSent.get(),

            totalPacketsReceived =
                totalPacketsReceived.get(),

            totalConnectionDurationMs =
                totalConnectionDurationMs.get(),

            historyRemoved =
                historyRemoved.get(),

            historyCleared =
                historyCleared.get(),

            validationFailures =
                validationFailures.get()
        )
    }
}
