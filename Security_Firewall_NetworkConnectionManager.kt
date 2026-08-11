package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * NetworkConnectionManager
 *
 * Manages the lifecycle and metadata of network connections observed
 * by the SentriX firewall subsystem.
 *
 * Responsibilities:
 *
 * - Register network connections.
 * - Track connection lifecycle.
 * - Update connection state.
 * - Associate connections with applications.
 * - Associate connections with domains/IPs/ports.
 * - Associate firewall decisions with connections.
 * - Track connection byte counters.
 * - Track connection duration.
 * - Search and filter connections.
 * - Maintain connection statistics.
 * - Remove expired/closed connections.
 *
 * IMPORTANT:
 *
 * This manager does not independently sniff packets or inspect all
 * device traffic.
 *
 * Connection records should be supplied by an authorized upstream
 * component such as:
 *
 * - SentriX VpnService
 * - Application networking layer
 * - Approved network interceptor
 *
 * Architecture:
 *
 *              VpnService / Network Layer
 *                         |
 *                         v
 *              NetworkConnectionManager
 *                         |
 *              ┌──────────┼──────────┐
 *              ▼          ▼          ▼
 *         Connection   Firewall    Statistics
 *           State      Decision
 *              │          │
 *              └────┬─────┘
 *                   ▼
 *             Security Events
 */
class NetworkConnectionManager(
    context: Context,
    private val configuration:
        NetworkConnectionManagerConfiguration =
        NetworkConnectionManagerConfiguration()
) {

    companion object {

        private const val TAG =
            "NetworkConnectionManager"

        /**
         * Maximum simultaneously tracked connections.
         */
        private const val MAX_CONNECTIONS =
            50_000

        /**
         * Maximum number of historical records retained.
         */
        private const val MAX_HISTORY =
            10_000
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Active connection store.
     */
    private val connections =
        ConcurrentHashMap<
            String,
            NetworkConnection
        >()

    /**
     * Historical connection records.
     */
    private val history =
        java.util.concurrent.ConcurrentLinkedDeque<
            NetworkConnection
        >()

    /**
     * Connection statistics.
     */
    private val statistics =
        NetworkConnectionStatisticsCounter()

    /**
     * Indicates whether manager is initialized.
     */
    @Volatile
    private var initialized =
        false

    /**
     * Initializes the connection manager.
     */
    suspend fun initialize():
            NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized
            ) {

                return@withContext
                    NetworkConnectionOperationResult.success(
                        "Network connection manager is already initialized."
                    )
            }

            initialized = true

            Log.i(
                TAG,
                "NetworkConnectionManager initialized."
            )

            NetworkConnectionOperationResult.success(
                "Network connection manager initialized successfully."
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
     * Registers a new network connection.
     */
    suspend fun registerConnection(
        request:
            RegisterNetworkConnectionRequest
    ): NetworkConnectionOperationResultWithConnection =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validateRequest(
                    request
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    NetworkConnectionOperationResultWithConnection.failure(
                        validation.message
                    )
            }

            if (
                connections.size >=
                MAX_CONNECTIONS
            ) {

                /*
                 * Try to clean closed connections before rejecting
                 * the new connection.
                 */
                cleanupClosedConnections()

                if (
                    connections.size >=
                    MAX_CONNECTIONS
                ) {

                    return@withContext
                        NetworkConnectionOperationResultWithConnection.failure(
                            "Maximum active network connection count reached."
                        )
                }
            }

            val connectionId =
                request.connectionId
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: generateConnectionId()

            if (
                connections.containsKey(
                    connectionId
                )
            ) {

                return@withContext
                    NetworkConnectionOperationResultWithConnection.failure(
                        "A network connection with this ID already exists."
                    )
            }

            val now =
                System.currentTimeMillis()

            val connection =
                NetworkConnection(
                    id =
                        connectionId,

                    host =
                        normalizeHost(
                            request.host
                        ),

                    remoteIp =
                        request.remoteIp
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            },

                    sourceIp =
                        request.sourceIp
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            },

                    remotePort =
                        request.remotePort,

                    localPort =
                        request.localPort,

                    protocol =
                        request.protocol,

                    packageName =
                        request.packageName
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            },

                    transport =
                        request.transport,

                    state =
                        NetworkConnectionState
                            .CONNECTING,

                    direction =
                        request.direction,

                    encrypted =
                        request.encrypted,

                    startedAt =
                        now,

                    lastActivityAt =
                        now,

                    bytesSent =
                        0L,

                    bytesReceived =
                        0L,

                    firewallDecision =
                        null,

                    firewallReason =
                        null,

                    matchedRuleId =
                        null,

                    threatLevel =
                        NetworkThreatLevel.UNKNOWN
                )

            connections[
                connectionId
            ] =
                connection

            statistics.incrementCreated()

            Log.d(
                TAG,
                "Network connection registered: $connectionId"
            )

            NetworkConnectionOperationResultWithConnection.success(
                message =
                    "Network connection registered successfully.",
                connection =
                    connection
            )
        }

    /**
     * Marks a connection as established.
     */
    suspend fun markEstablished(
        connectionId:
            String
    ): NetworkConnectionOperationResult =
        updateState(
            connectionId =
                connectionId,
            state =
                NetworkConnectionState.ESTABLISHED
        )

    /**
     * Marks a connection as connecting.
     */
    suspend fun markConnecting(
        connectionId:
            String
    ): NetworkConnectionOperationResult =
        updateState(
            connectionId =
                connectionId,
            state =
                NetworkConnectionState.CONNECTING
        )

    /**
     * Marks a connection as closing.
     */
    suspend fun markClosing(
        connectionId:
            String
    ): NetworkConnectionOperationResult =
        updateState(
            connectionId =
                connectionId,
            state =
                NetworkConnectionState.CLOSING
        )

    /**
     * Marks a connection as closed.
     */
    suspend fun markClosed(
        connectionId:
            String
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            val now =
                System.currentTimeMillis()

            val updated =
                connection.copy(
                    state =
                        NetworkConnectionState.CLOSED,

                    endedAt =
                        now,

                    lastActivityAt =
                        now
                )

            connections[
                connectionId
            ] =
                updated

            statistics.incrementClosed()

            moveToHistoryIfConfigured(
                updated
            )

            if (
                configuration
                    .removeClosedConnectionsImmediately
            ) {

                connections.remove(
                    connectionId
                )
            }

            NetworkConnectionOperationResult.success(
                "Network connection closed."
            )
        }

    /**
     * Marks a connection as blocked.
     */
    suspend fun markBlocked(
        connectionId:
            String,
        reason:
            String? = null
    ): NetworkConnectionOperationResult {

        return updateStateAndDecision(
            connectionId =
                connectionId,

            state =
                NetworkConnectionState.BLOCKED,

            decision =
                FirewallDecision.BLOCK,

            reason =
                reason
        )
    }

    /**
     * Marks a connection as allowed.
     */
    suspend fun markAllowed(
        connectionId:
            String,
        reason:
            String? = null
    ): NetworkConnectionOperationResult {

        return updateStateAndDecision(
            connectionId =
                connectionId,

            state =
                NetworkConnectionState.ESTABLISHED,

            decision =
                FirewallDecision.ALLOW,

            reason =
                reason
        )
    }

    /**
     * Marks a connection for monitoring.
     */
    suspend fun markMonitored(
        connectionId:
            String,
        reason:
            String? = null
    ): NetworkConnectionOperationResult {

        return updateStateAndDecision(
            connectionId =
                connectionId,

            state =
                NetworkConnectionState.MONITORED,

            decision =
                FirewallDecision.MONITOR,

            reason =
                reason
        )
    }

    /**
     * Marks a connection as warning state.
     */
    suspend fun markWarning(
        connectionId:
            String,
        reason:
            String? = null
    ): NetworkConnectionOperationResult {

        return updateStateAndDecision(
            connectionId =
                connectionId,

            state =
                NetworkConnectionState.WARNING,

            decision =
                FirewallDecision.WARN,

            reason =
                reason
        )
    }

    /**
     * Updates firewall decision for a connection.
     */
    suspend fun applyFirewallResult(
        connectionId:
            String,
        result:
            FirewallEvaluationResult
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            val newState =
                when (
                    result.decision
                ) {

                    FirewallDecision.ALLOW ->
                        NetworkConnectionState
                            .ESTABLISHED

                    FirewallDecision.BLOCK ->
                        NetworkConnectionState
                            .BLOCKED

                    FirewallDecision.MONITOR ->
                        NetworkConnectionState
                            .MONITORED

                    FirewallDecision.WARN ->
                        NetworkConnectionState
                            .WARNING
                }

            val updated =
                connection.copy(
                    state =
                        newState,

                    firewallDecision =
                        result.decision,

                    firewallReason =
                        result.reason,

                    matchedRuleId =
                        result.matchedRule
                            ?.id,

                    lastActivityAt =
                        System.currentTimeMillis()
                )

            connections[
                connectionId
            ] =
                updated

            statistics.incrementFirewallDecisions()

            when (
                result.decision
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

            NetworkConnectionOperationResult.success(
                "Firewall result applied to connection."
            )
        }

    /**
     * Updates connection byte counters.
     */
    suspend fun recordTraffic(
        connectionId:
            String,
        bytesSent:
            Long = 0L,
        bytesReceived:
            Long = 0L
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                bytesSent < 0 ||
                bytesReceived < 0
            ) {

                return@withContext
                    NetworkConnectionOperationResult.failure(
                        "Traffic byte counters cannot be negative."
                    )
            }

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            val updated =
                connection.copy(
                    bytesSent =
                        safeAdd(
                            connection.bytesSent,
                            bytesSent
                        ),

                    bytesReceived =
                        safeAdd(
                            connection.bytesReceived,
                            bytesReceived
                        ),

                    lastActivityAt =
                        System.currentTimeMillis()
                )

            connections[
                connectionId
            ] =
                updated

            statistics.addBytesSent(
                bytesSent
            )

            statistics.addBytesReceived(
                bytesReceived
            )

            statistics.incrementTrafficUpdates()

            NetworkConnectionOperationResult.success(
                "Connection traffic updated."
            )
        }

    /**
     * Updates threat information for a connection.
     */
    suspend fun updateThreatLevel(
        connectionId:
            String,
        threatLevel:
            NetworkThreatLevel
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            connections[
                connectionId
            ] =
                connection.copy(
                    threatLevel =
                        threatLevel,

                    lastActivityAt =
                        System.currentTimeMillis()
                )

            statistics.incrementThreatUpdates()

            NetworkConnectionOperationResult.success(
                "Connection threat level updated."
            )
        }

    /**
     * Updates connection state.
     */
    private suspend fun updateState(
        connectionId:
            String,
        state:
            NetworkConnectionState
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            connections[
                connectionId
            ] =
                connection.copy(
                    state =
                        state,

                    lastActivityAt =
                        System.currentTimeMillis()
                )

            statistics.incrementStateChanges()

            NetworkConnectionOperationResult.success(
                "Network connection state updated."
            )
        }

    /**
     * Updates connection state and firewall decision.
     */
    private suspend fun updateStateAndDecision(
        connectionId:
            String,
        state:
            NetworkConnectionState,
        decision:
            FirewallDecision,
        reason:
            String?
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val connection =
                connections[
                    connectionId
                ]
                    ?: return@withContext
                        NetworkConnectionOperationResult.failure(
                            "Network connection was not found."
                        )

            connections[
                connectionId
            ] =
                connection.copy(
                    state =
                        state,

                    firewallDecision =
                        decision,

                    firewallReason =
                        reason,

                    lastActivityAt =
                        System.currentTimeMillis()
                )

            statistics.incrementStateChanges()
            statistics.incrementFirewallDecisions()

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

            NetworkConnectionOperationResult.success(
                "Connection state and firewall decision updated."
            )
        }

    /**
     * Gets a connection by ID.
     */
    fun getConnection(
        connectionId:
            String
    ): NetworkConnection? {

        return connections[
            connectionId
        ]
    }

    /**
     * Returns all active connections.
     */
    fun getActiveConnections():
            List<NetworkConnection> {

        return connections.values
            .filter {
                it.state.isActive()
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Returns all tracked connections.
     */
    fun getAllConnections():
            List<NetworkConnection> {

        return connections.values
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Returns blocked connections.
     */
    fun getBlockedConnections():
            List<NetworkConnection> {

        return connections.values
            .filter {
                it.state ==
                        NetworkConnectionState.BLOCKED ||
                        it.firewallDecision ==
                        FirewallDecision.BLOCK
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Returns suspicious connections.
     */
    fun getSuspiciousConnections():
            List<NetworkConnection> {

        return connections.values
            .filter {
                it.threatLevel.isSuspicious()
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Finds connections associated with an application.
     */
    fun getConnectionsByPackage(
        packageName:
            String
    ): List<NetworkConnection> {

        return connections.values
            .filter {
                it.packageName.equals(
                    packageName,
                    ignoreCase = true
                )
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Finds connections by host.
     */
    fun getConnectionsByHost(
        host:
            String
    ): List<NetworkConnection> {

        val normalizedHost =
            normalizeHost(
                host
            )

        return connections.values
            .filter {
                normalizeHost(
                    it.host
                ) ==
                        normalizedHost
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Finds connections by remote port.
     */
    fun getConnectionsByPort(
        port:
            Int
    ): List<NetworkConnection> {

        return connections.values
            .filter {
                it.remotePort ==
                        port
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Searches connection records.
     */
    fun searchConnections(
        query:
            String
    ): List<NetworkConnection> {

        if (
            query.isBlank()
        ) {

            return getAllConnections()
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return connections.values
            .filter { connection ->

                connection.id
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        connection.host
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        connection.remoteIp
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        connection.packageName
                            ?.lowercase()
                            ?.contains(
                                normalized
                            ) == true ||

                        connection.protocol.name
                            .lowercase()
                            .contains(
                                normalized
                            )
            }
            .sortedByDescending {
                it.lastActivityAt
            }
    }

    /**
     * Cleans up inactive connections.
     */
    suspend fun cleanupInactiveConnections(
        olderThanMillis:
            Long =
            configuration
                .inactiveConnectionTimeoutMs
    ): Int =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val now =
                System.currentTimeMillis()

            val staleIds =
                connections.values
                    .filter {

                        it.state.isInactive() &&
                                now -
                                it.lastActivityAt >=
                                olderThanMillis
                    }
                    .map {
                        it.id
                    }

            staleIds.forEach { id ->

                val removed =
                    connections.remove(
                        id
                    )

                removed?.let {
                    moveToHistoryIfConfigured(
                        it
                    )
                }
            }

            statistics.incrementCleanups(
                staleIds.size
            )

            staleIds.size
        }

    /**
     * Removes closed connections.
     */
    private fun cleanupClosedConnections() {

        val closedIds =
            connections.values
                .filter {
                    it.state ==
                            NetworkConnectionState.CLOSED
                }
                .map {
                    it.id
                }

        closedIds.forEach {
            connections.remove(
                it
            )
        }
    }

    /**
     * Moves connection to history.
     */
    private fun moveToHistoryIfConfigured(
        connection:
            NetworkConnection
    ) {

        if (
            !configuration
                .retainHistory
        ) {
            return
        }

        history.addFirst(
            connection
        )

        while (
            history.size >
            MAX_HISTORY
        ) {

            history.pollLast()
        }
    }

    /**
     * Returns historical connections.
     */
    fun getHistory(
        limit:
            Int =
            100
    ): List<NetworkConnection> {

        require(
            limit > 0
        ) {
            "History limit must be greater than zero."
        }

        return history
            .take(
                limit
            )
    }

    /**
     * Clears historical connections.
     */
    fun clearHistory() {

        history.clear()
    }

    /**
     * Returns connection statistics.
     */
    fun getStatistics():
            NetworkConnectionStatistics {

        return statistics.snapshot(
            activeConnections =
                connections.values.count {
                    it.state.isActive()
                },

            totalConnections =
                connections.size,

            historicalConnections =
                history.size
        )
    }

    /**
     * Resets manager statistics.
     */
    fun resetStatistics() {

        statistics.reset()
    }

    /**
     * Removes a specific connection.
     */
    suspend fun removeConnection(
        connectionId:
            String
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val removed =
                connections.remove(
                    connectionId
                )

            if (
                removed == null
            ) {

                return@withContext
                    NetworkConnectionOperationResult.failure(
                        "Network connection was not found."
                    )
            }

            moveToHistoryIfConfigured(
                removed
            )

            statistics.incrementRemoved()

            NetworkConnectionOperationResult.success(
                "Network connection removed."
            )
        }

    /**
     * Clears all tracked connections.
     */
    suspend fun clearConnections(
        preserveActive:
            Boolean = true
    ): NetworkConnectionOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val toRemove =
                connections.values
                    .filter {
                        !preserveActive ||
                                !it.state.isActive()
                    }

            toRemove.forEach {
                connections.remove(
                    it.id
                )

                moveToHistoryIfConfigured(
                    it
                )
            }

            statistics.incrementRemoved(
                toRemove.size
            )

            NetworkConnectionOperationResult.success(
                "${toRemove.size} network connections removed."
            )
        }

    /**
     * Validates registration request.
     */
    private fun validateRequest(
        request:
            RegisterNetworkConnectionRequest
    ): NetworkConnectionValidationResult {

        if (
            request.host.isBlank()
        ) {

            return NetworkConnectionValidationResult.invalid(
                "Connection host cannot be blank."
            )
        }

        if (
            request.remotePort != null &&
            request.remotePort !in 1..65535
        ) {

            return NetworkConnectionValidationResult.invalid(
                "Remote port must be between 1 and 65535."
            )
        }

        if (
            request.localPort != null &&
            request.localPort !in 1..65535
        ) {

            return NetworkConnectionValidationResult.invalid(
                "Local port must be between 1 and 65535."
            )
        }

        return NetworkConnectionValidationResult.valid()
    }

    /**
     * Normalizes host values.
     */
    private fun normalizeHost(
        host:
            String
    ): String {

        return host
            .trim()
            .lowercase()
            .removePrefix(
                "https://"
            )
            .removePrefix(
                "http://"
            )
            .substringBefore(
                "/"
            )
            .substringBefore(
                "?"
            )
            .substringBefore(
                "#"
            )
            .trimEnd(
                '.'
            )
    }

    /**
     * Generates connection ID.
     */
    private fun generateConnectionId():
            String {

        return "CONN_" +
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
     * Safely adds byte counters without overflowing Long.
     */
    private fun safeAdd(
        current:
            Long,
        additional:
            Long
    ): Long {

        if (
            additional <= 0
        ) {

            return current
        }

        if (
            Long.MAX_VALUE -
            current <
            additional
        ) {

            return Long.MAX_VALUE
        }

        return current +
                additional
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(initialized) {
            "NetworkConnectionManager has not been initialized."
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
                "Network connection operation was cancelled."
            )
        }
    }

    /**
     * Releases manager resources.
     */
    fun close() {

        connections.clear()

        history.clear()

        initialized =
            false

        Log.i(
            TAG,
            "NetworkConnectionManager closed."
        )
    }
}

/**
 * Request used to register a network connection.
 */
data class RegisterNetworkConnectionRequest(

    val connectionId:
        String? = null,

    val host:
        String,

    val remoteIp:
        String? = null,

    val sourceIp:
        String? = null,

    val remotePort:
        Int? = null,

    val localPort:
        Int? = null,

    val protocol:
        FirewallProtocol =
        FirewallProtocol.ANY,

    val packageName:
        String? = null,

    val transport:
        NetworkTransportType =
        NetworkTransportType.UNKNOWN,

    val direction:
        NetworkTrafficDirection =
        NetworkTrafficDirection.OUTBOUND,

    val encrypted:
        Boolean = true
)

/**
 * Individual network connection record.
 */
data class NetworkConnection(

    /**
     * Unique connection ID.
     */
    val id:
        String,

    /**
     * Destination hostname.
     */
    val host:
        String,

    /**
     * Destination IP.
     */
    val remoteIp:
        String?,

    /**
     * Source IP.
     */
    val sourceIp:
        String?,

    /**
     * Destination port.
     */
    val remotePort:
        Int?,

    /**
     * Local source port.
     */
    val localPort:
        Int?,

    /**
     * Network protocol.
     */
    val protocol:
        FirewallProtocol,

    /**
     * Owning application package.
     */
    val packageName:
        String?,

    /**
     * Network transport.
     */
    val transport:
        NetworkTransportType,

    /**
     * Current connection state.
     */
    val state:
        NetworkConnectionState,

    /**
     * Traffic direction.
     */
    val direction:
        NetworkTrafficDirection,

    /**
     * Whether the connection is encrypted.
     */
    val encrypted:
        Boolean,

    /**
     * Connection start time.
     */
    val startedAt:
        Long,

    /**
     * Connection end time.
     */
    val endedAt:
        Long? = null,

    /**
     * Last traffic/activity timestamp.
     */
    val lastActivityAt:
        Long,

    /**
     * Number of bytes sent.
     */
    val bytesSent:
        Long,

    /**
     * Number of bytes received.
     */
    val bytesReceived:
        Long,

    /**
     * Firewall decision.
     */
    val firewallDecision:
        FirewallDecision?,

    /**
     * Firewall decision explanation.
     */
    val firewallReason:
        String?,

    /**
     * ID of the rule that produced the decision.
     */
    val matchedRuleId:
        String?,

    /**
     * Current threat classification.
     */
    val threatLevel:
        NetworkThreatLevel
) {

    /**
     * Connection duration.
     */
    fun durationMillis(
        now:
            Long =
            System.currentTimeMillis()
    ): Long {

        val end =
            endedAt ?: now

        return maxOf(
            0L,
            end - startedAt
        )
    }

    /**
     * Total bytes transferred.
     */
    fun totalBytes():
            Long {

        if (
            Long.MAX_VALUE -
            bytesSent <
            bytesReceived
        ) {

            return Long.MAX_VALUE
        }

        return bytesSent +
                bytesReceived
    }
}

/**
 * Network connection state.
 */
enum class NetworkConnectionState {

    CONNECTING,

    ESTABLISHED,

    MONITORED,

    WARNING,

    BLOCKED,

    CLOSING,

    CLOSED;

    fun isActive():
            Boolean {

        return when (
            this
        ) {

            CONNECTING,
            ESTABLISHED,
            MONITORED,
            WARNING ->
                true

            BLOCKED,
            CLOSING,
            CLOSED ->
                false
        }
    }

    fun isInactive():
            Boolean {

        return !isActive()
    }
}

/**
 * Threat level associated with a connection.
 */
enum class NetworkThreatLevel {

    UNKNOWN,

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL;

    fun isSuspicious():
            Boolean {

        return when (
            this
        ) {

            UNKNOWN,
            SAFE,
            LOW ->
                false

            MEDIUM,
            HIGH,
            CRITICAL ->
                true
        }
    }
}

/**
 * Validation result.
 */
data class NetworkConnectionValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                NetworkConnectionValidationResult {

            return NetworkConnectionValidationResult(
                valid =
                    true,
                message =
                    "Connection request is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                NetworkConnectionValidationResult {

            return NetworkConnectionValidationResult(
                valid =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Generic connection operation result.
 */
data class NetworkConnectionOperationResult(

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
                NetworkConnectionOperationResult {

            return NetworkConnectionOperationResult(
                success =
                    true,
                message =
                    message
            )
        }

        fun failure(
            message:
                String
        ):
                NetworkConnectionOperationResult {

            return NetworkConnectionOperationResult(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Connection operation result containing a connection.
 */
data class NetworkConnectionOperationResultWithConnection(

    val success:
        Boolean,

    val message:
        String,

    val connection:
        NetworkConnection? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            connection:
                NetworkConnection
        ):
                NetworkConnectionOperationResultWithConnection {

            return NetworkConnectionOperationResultWithConnection(
                success =
                    true,
                message =
                    message,
                connection =
                    connection
            )
        }

        fun failure(
            message:
                String
        ):
                NetworkConnectionOperationResultWithConnection {

            return NetworkConnectionOperationResultWithConnection(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Network connection manager configuration.
 */
data class NetworkConnectionManagerConfiguration(

    /**
     * Automatically move closed connections into history.
     */
    val retainHistory:
        Boolean = true,

    /**
     * Remove closed connections from active storage immediately.
     */
    val removeClosedConnectionsImmediately:
        Boolean = true,

    /**
     * Time after which inactive connections can be cleaned.
     */
    val inactiveConnectionTimeoutMs:
        Long =
        5 * 60 * 1_000L
)

/**
 * Network connection statistics.
 */
data class NetworkConnectionStatistics(

    val totalConnections:
        Int,

    val activeConnections:
        Int,

    val historicalConnections:
        Int,

    val created:
        Long,

    val closed:
        Long,

    val removed:
        Long,

    val stateChanges:
        Long,

    val trafficUpdates:
        Long,

    val bytesSent:
        Long,

    val bytesReceived:
        Long,

    val firewallDecisions:
        Long,

    val allowed:
        Long,

    val blocked:
        Long,

    val monitored:
        Long,

    val warnings:
        Long,

    val threatUpdates:
        Long,

    val cleanups:
        Long,

    val validationFailures:
        Long
)

/**
 * Thread-safe connection statistics.
 */
private class NetworkConnectionStatisticsCounter {

    private val created =
        AtomicLong(0)

    private val closed =
        AtomicLong(0)

    private val removed =
        AtomicLong(0)

    private val stateChanges =
        AtomicLong(0)

    private val trafficUpdates =
        AtomicLong(0)

    private val bytesSent =
        AtomicLong(0)

    private val bytesReceived =
        AtomicLong(0)

    private val firewallDecisions =
        AtomicLong(0)

    private val allowed =
        AtomicLong(0)

    private val blocked =
        AtomicLong(0)

    private val monitored =
        AtomicLong(0)

    private val warnings =
        AtomicLong(0)

    private val threatUpdates =
        AtomicLong(0)

    private val cleanups =
        AtomicLong(0)

    private val validationFailures =
        AtomicLong(0)

    fun incrementCreated() {
        created.incrementAndGet()
    }

    fun incrementClosed() {
        closed.incrementAndGet()
    }

    fun incrementRemoved(
        count:
            Int = 1
    ) {

        removed.addAndGet(
            count.toLong()
        )
    }

    fun incrementStateChanges() {
        stateChanges.incrementAndGet()
    }

    fun incrementTrafficUpdates() {
        trafficUpdates.incrementAndGet()
    }

    fun addBytesSent(
        value:
            Long
    ) {

        if (
            value > 0
        ) {

            bytesSent.addAndGet(
                value
            )
        }
    }

    fun addBytesReceived(
        value:
            Long
    ) {

        if (
            value > 0
        ) {

            bytesReceived.addAndGet(
                value
            )
        }
    }

    fun incrementFirewallDecisions() {
        firewallDecisions.incrementAndGet()
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

    fun incrementThreatUpdates() {
        threatUpdates.incrementAndGet()
    }

    fun incrementCleanups(
        count:
            Int
    ) {

        if (
            count > 0
        ) {

            cleanups.addAndGet(
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
        totalConnections:
            Int,
        historicalConnections:
            Int
    ):
            NetworkConnectionStatistics {

        return NetworkConnectionStatistics(

            totalConnections =
                totalConnections,

            activeConnections =
                activeConnections,

            historicalConnections =
                historicalConnections,

            created =
                created.get(),

            closed =
                closed.get(),

            removed =
                removed.get(),

            stateChanges =
                stateChanges.get(),

            trafficUpdates =
                trafficUpdates.get(),

            bytesSent =
                bytesSent.get(),

            bytesReceived =
                bytesReceived.get(),

            firewallDecisions =
                firewallDecisions.get(),

            allowed =
                allowed.get(),

            blocked =
                blocked.get(),

            monitored =
                monitored.get(),

            warnings =
                warnings.get(),

            threatUpdates =
                threatUpdates.get(),

            cleanups =
                cleanups.get(),

            validationFailures =
                validationFailures.get()
        )
    }

    fun reset() {

        created.set(0)
        closed.set(0)
        removed.set(0)
        stateChanges.set(0)
        trafficUpdates.set(0)
        bytesSent.set(0)
        bytesReceived.set(0)
        firewallDecisions.set(0)
        allowed.set(0)
        blocked.set(0)
        monitored.set(0)
        warnings.set(0)
        threatUpdates.set(0)
        cleanups.set(0)
        validationFailures.set(0)
    }
}
