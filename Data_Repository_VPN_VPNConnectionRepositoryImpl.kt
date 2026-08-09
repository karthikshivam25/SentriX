package com.sentrix.data.repository.vpn

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.VPNConnectionDao
import com.sentrix.data.local.entities.VPNConnectionEntity
import com.sentrix.data.remote.api.VPNApiService
import com.sentrix.data.remote.dto.VPNConnectionDto
import com.sentrix.domain.models.VPNConnection
import com.sentrix.domain.repository.VPNConnectionRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - VPN Connection Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.vpn
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * VPNConnectionRepository.
 *
 * This repository is responsible for individual VPN
 * connection records and their lifecycle information.
 *
 * It manages:
 *
 * - VPN connection creation.
 * - Connection state.
 * - Connection start time.
 * - Connection end time.
 * - Connection duration.
 * - VPN server information.
 * - VPN protocol.
 * - Upload statistics.
 * - Download statistics.
 * - Kill-switch state.
 * - DNS protection state.
 * - Threat-monitoring state.
 * - Connection failures.
 * - Connection history.
 * - Remote synchronization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT establish or terminate the actual
 * Android VPN tunnel.
 *
 * Actual VPN tunnel operations belong to:
 *
 * - Android VpnService.
 * - VPN Manager.
 * - VPN Connection Service.
 * - VPN Engine.
 *
 * This repository only stores and retrieves the state produced
 * by those components.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * VPNConnectionRepository
 *    │
 *    ▼
 * VPNConnectionRepositoryImpl
 *    │
 *    ├──────────────► VPNConnectionDao
 *    │                     │
 *    │                     ▼
 *    │              VPNConnectionEntity
 *    │
 *    └──────────────► VPNApiService
 *                          │
 *                          ▼
 *                    VPNConnectionDto
 */
@Singleton
class VPNConnectionRepositoryImpl @Inject constructor(
    private val vpnConnectionDao: VPNConnectionDao,
    private val vpnApiService: VPNApiService
) : VPNConnectionRepository {

    /**
     * Retrieves the currently active VPN connection.
     *
     * Returns null when no VPN connection is active.
     */
    override suspend fun getActiveConnection():
        Result<VPNConnection?> {

        return try {

            val entity =
                vpnConnectionDao.getActiveConnection()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves a VPN connection by its unique identifier.
     */
    override suspend fun getConnectionById(
        connectionId: String
    ): Result<VPNConnection?> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            val entity =
                vpnConnectionDao.getById(
                    connectionId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves recent VPN connection records.
     *
     * Useful for:
     *
     * - VPN history screen.
     * - Security reports.
     * - Analytics.
     * - Connection diagnostics.
     */
    override suspend fun getRecentConnections(
        limit: Int
    ): Result<List<VPNConnection>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection limit must be greater than zero."
                    )
                )
            }

            val entities =
                vpnConnectionDao.getRecentConnections(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves all stored VPN connections.
     */
    override suspend fun getAllConnections():
        Result<List<VPNConnection>> {

        return try {

            val entities =
                vpnConnectionDao.getAllConnections()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves VPN connections between two timestamps.
     */
    override suspend fun getConnectionsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<VPNConnection>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                vpnConnectionDao.getConnectionsBetween(
                    startTime = startTime,
                    endTime = endTime
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves VPN connections associated with a server.
     */
    override suspend fun getConnectionsByServer(
        serverId: String
    ): Result<List<VPNConnection>> {

        return try {

            if (serverId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN server ID cannot be blank."
                    )
                )
            }

            val entities =
                vpnConnectionDao.getConnectionsByServer(
                    serverId
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves connections using a specific VPN protocol.
     *
     * Examples:
     *
     * WireGuard
     * OpenVPN
     * IKEv2
     */
    override suspend fun getConnectionsByProtocol(
        protocol: String
    ): Result<List<VPNConnection>> {

        return try {

            if (protocol.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN protocol cannot be blank."
                    )
                )
            }

            val entities =
                vpnConnectionDao.getConnectionsByProtocol(
                    protocol
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Creates and stores a new VPN connection record.
     *
     * The repository does not actually establish the VPN
     * tunnel.
     */
    override suspend fun createConnection(
        connection: VPNConnection
    ): Result<Unit> {

        return try {

            vpnConnectionDao.insert(
                connection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Saves or updates an existing connection.
     */
    override suspend fun saveConnection(
        connection: VPNConnection
    ): Result<Unit> {

        return try {

            vpnConnectionDao.insertOrUpdate(
                connection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Saves multiple VPN connection records.
     */
    override suspend fun saveConnections(
        connections: List<VPNConnection>
    ): Result<Unit> {

        return try {

            if (connections.isEmpty()) {
                return Result.success(Unit)
            }

            vpnConnectionDao.insertOrUpdateAll(
                connections.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as CONNECTING.
     *
     * This only persists state. The actual connection process
     * is handled by the VPN service/manager.
     */
    override suspend fun markConnecting(
        connectionId: String
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.updateStatus(
                connectionId = connectionId,
                status = STATUS_CONNECTING
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as CONNECTED.
     */
    override suspend fun markConnected(
        connectionId: String,
        connectedAt: Long
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.markConnected(
                connectionId = connectionId,
                connectedAt = connectedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as RECONNECTING.
     */
    override suspend fun markReconnecting(
        connectionId: String
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.updateStatus(
                connectionId = connectionId,
                status = STATUS_RECONNECTING
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as DISCONNECTING.
     */
    override suspend fun markDisconnecting(
        connectionId: String
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.updateStatus(
                connectionId = connectionId,
                status = STATUS_DISCONNECTING
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as DISCONNECTED.
     */
    override suspend fun markDisconnected(
        connectionId: String,
        disconnectedAt: Long
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.markDisconnected(
                connectionId = connectionId,
                disconnectedAt = disconnectedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Marks a connection as FAILED.
     */
    override suspend fun markFailed(
        connectionId: String
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.updateStatus(
                connectionId = connectionId,
                status = STATUS_FAILED
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Updates the VPN connection traffic statistics.
     */
    override suspend fun updateTrafficStats(
        connectionId: String,
        uploadBytes: Long,
        downloadBytes: Long
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            if (uploadBytes < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Upload bytes cannot be negative."
                    )
                )
            }

            if (downloadBytes < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Download bytes cannot be negative."
                    )
                )
            }

            vpnConnectionDao.updateTrafficStats(
                connectionId = connectionId,
                uploadBytes = uploadBytes,
                downloadBytes = downloadBytes
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Updates connection duration.
     */
    override suspend fun updateConnectionDuration(
        connectionId: String,
        durationMs: Long
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            if (durationMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection duration cannot be negative."
                    )
                )
            }

            vpnConnectionDao.updateConnectionDuration(
                connectionId = connectionId,
                durationMs = durationMs
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves total VPN connection duration.
     */
    override suspend fun getTotalConnectionDuration():
        Result<Long> {

        return try {

            Result.success(
                vpnConnectionDao.getTotalConnectionDuration()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves total uploaded traffic.
     */
    override suspend fun getTotalUploadBytes():
        Result<Long> {

        return try {

            Result.success(
                vpnConnectionDao.getTotalUploadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves total downloaded traffic.
     */
    override suspend fun getTotalDownloadBytes():
        Result<Long> {

        return try {

            Result.success(
                vpnConnectionDao.getTotalDownloadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of successful connections.
     */
    override suspend fun getSuccessfulConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnConnectionDao.getSuccessfulConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of failed connections.
     */
    override suspend fun getFailedConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnConnectionDao.getFailedConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves the latest connection failure.
     */
    override suspend fun getLatestFailedConnection():
        Result<VPNConnection?> {

        return try {

            val entity =
                vpnConnectionDao.getLatestFailedConnection()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Refreshes the current VPN connection from the
     * SentriX backend.
     */
    override suspend fun refreshConnection():
        Result<VPNConnection?> {

        return try {

            val response =
                vpnApiService.getCurrentConnection()

            response?.let {

                vpnConnectionDao.insertOrUpdate(
                    it.toEntity()
                )
            }

            Result.success(
                response?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Synchronizes VPN connection history.
     */
    override suspend fun synchronizeConnections():
        Result<Unit> {

        return try {

            val response =
                vpnApiService.getConnectionHistory()

            if (response.isNotEmpty()) {

                vpnConnectionDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Retrieves connections created or updated after the
     * supplied timestamp.
     *
     * This supports incremental synchronization.
     */
    override suspend fun getConnectionsSince(
        timestamp: Long
    ): Result<List<VPNConnection>> {

        return try {

            val response =
                vpnApiService.getConnectionsSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                vpnConnectionDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Deletes one VPN connection.
     */
    override suspend fun deleteConnection(
        connectionId: String
    ): Result<Unit> {

        return try {

            validateConnectionId(
                connectionId
            )?.let {
                return Result.failure(it)
            }

            vpnConnectionDao.deleteById(
                connectionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Deletes connection records older than the supplied
     * timestamp.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            vpnConnectionDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Clears all locally stored VPN connection history.
     */
    override suspend fun clearConnections():
        Result<Unit> {

        return try {

            vpnConnectionDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Returns the total number of locally stored connections.
     */
    override suspend fun getConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnConnectionDao.getConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNConnectionException(exception)
            )
        }
    }

    /**
     * Validates the connection identifier.
     *
     * Returns an exception when invalid, otherwise null.
     */
    private fun validateConnectionId(
        connectionId: String
    ): Exception? {

        return if (connectionId.isBlank()) {
            IllegalArgumentException(
                "VPN connection ID cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Converts remote DTO into Domain model.
     *
     * DTO -> Domain
     */
    private fun VPNConnectionDto.toDomain():
        VPNConnection {

        return VPNConnection(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            serverCountry = serverCountry,
            serverRegion = serverRegion,
            serverAddress = serverAddress,
            protocol = protocol,
            status = status,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            uploadBytes = uploadBytes,
            downloadBytes = downloadBytes,
            connectionDurationMs = connectionDurationMs,
            killSwitchEnabled = killSwitchEnabled,
            dnsProtectionEnabled = dnsProtectionEnabled,
            threatMonitoringEnabled = threatMonitoringEnabled
        )
    }

    /**
     * Converts remote DTO into Room entity.
     *
     * DTO -> Entity
     */
    private fun VPNConnectionDto.toEntity():
        VPNConnectionEntity {

        return VPNConnectionEntity(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            serverCountry = serverCountry,
            serverRegion = serverRegion,
            serverAddress = serverAddress,
            protocol = protocol,
            status = status,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            uploadBytes = uploadBytes,
            downloadBytes = downloadBytes,
            connectionDurationMs = connectionDurationMs,
            killSwitchEnabled = killSwitchEnabled,
            dnsProtectionEnabled = dnsProtectionEnabled,
            threatMonitoringEnabled = threatMonitoringEnabled
        )
    }

    /**
     * Converts Domain model into Room entity.
     *
     * Domain -> Entity
     */
    private fun VPNConnection.toEntity():
        VPNConnectionEntity {

        return VPNConnectionEntity(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            serverCountry = serverCountry,
            serverRegion = serverRegion,
            serverAddress = serverAddress,
            protocol = protocol,
            status = status,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            uploadBytes = uploadBytes,
            downloadBytes = downloadBytes,
            connectionDurationMs = connectionDurationMs,
            killSwitchEnabled = killSwitchEnabled,
            dnsProtectionEnabled = dnsProtectionEnabled,
            threatMonitoringEnabled = threatMonitoringEnabled
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun VPNConnectionEntity.toDomain():
        VPNConnection {

        return VPNConnection(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            serverCountry = serverCountry,
            serverRegion = serverRegion,
            serverAddress = serverAddress,
            protocol = protocol,
            status = status,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            uploadBytes = uploadBytes,
            downloadBytes = downloadBytes,
            connectionDurationMs = connectionDurationMs,
            killSwitchEnabled = killSwitchEnabled,
            dnsProtectionEnabled = dnsProtectionEnabled,
            threatMonitoringEnabled = threatMonitoringEnabled
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapVPNConnectionException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX VPN connection service.",
                    cause = exception
                )
            }

            /**
             * HTTP/backend failure.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The VPN connection request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access VPN connections."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested VPN connection was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "VPN connection synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "VPN connection request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX VPN connection service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "VPN connection request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve already translated exceptions.
             */
            is NetworkException,
            is ServerException -> {
                exception
            }

            /**
             * Unexpected database/infrastructure failure.
             */
            else -> {
                UnknownException(
                    message = "An unexpected VPN connection repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * VPN connection lifecycle states.
         */
        private const val STATUS_CONNECTING = "CONNECTING"

        private const val STATUS_CONNECTED = "CONNECTED"

        private const val STATUS_RECONNECTING = "RECONNECTING"

        private const val STATUS_DISCONNECTING = "DISCONNECTING"

        private const val STATUS_DISCONNECTED = "DISCONNECTED"

        private const val STATUS_FAILED = "FAILED"
    }
}
