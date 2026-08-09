package com.sentrix.data.repository.vpn

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.VPNDao
import com.sentrix.data.local.entities.VPNConnectionEntity
import com.sentrix.data.remote.api.VPNApiService
import com.sentrix.data.remote.dto.VPNConnectionDto
import com.sentrix.domain.models.VPNConnection
import com.sentrix.domain.repository.VPNRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - VPN Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.vpn
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of VPNRepository.
 *
 * This repository manages:
 *
 * - Current VPN connection state.
 * - VPN connection history.
 * - VPN configuration persistence.
 * - VPN server information.
 * - Connection timestamps.
 * - Disconnection timestamps.
 * - VPN protocol information.
 * - VPN traffic statistics.
 * - VPN protection state.
 * - VPN synchronization.
 * - Local VPN cache.
 *
 * Supported VPN-related information may include:
 *
 * - Connection ID.
 * - Server ID.
 * - Server name.
 * - Server country.
 * - Server region.
 * - Server address.
 * - Protocol.
 * - Connection status.
 * - Connected timestamp.
 * - Disconnected timestamp.
 * - Upload bytes.
 * - Download bytes.
 * - Connection duration.
 * - Kill-switch state.
 * - DNS protection state.
 * - Threat monitoring state.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide:
 *
 * - Which VPN server should be selected.
 * - Whether VPN should be mandatory.
 * - Whether a network is dangerous.
 * - Whether traffic should be blocked.
 * - Which VPN protocol is optimal.
 *
 * Those responsibilities belong to Domain services/rules.
 *
 * The repository is responsible for DATA operations only.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * VPNRepository
 *    │
 *    ▼
 * VPNRepositoryImpl
 *    │
 *    ├──────────────► VPNDao
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
class VPNRepositoryImpl @Inject constructor(
    private val vpnDao: VPNDao,
    private val vpnApiService: VPNApiService
) : VPNRepository {

    /**
     * Retrieves the current VPN connection.
     *
     * Local state is used because VPN status must remain
     * available even when the backend is unreachable.
     */
    override suspend fun getCurrentConnection():
        Result<VPNConnection?> {

        return try {

            val entity =
                vpnDao.getCurrentConnection()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves a VPN connection using its unique ID.
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
                vpnDao.getConnectionById(
                    connectionId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves recent VPN connections.
     *
     * Useful for connection-history screens and analytics.
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
                vpnDao.getRecentConnections(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored VPN connections.
     */
    override suspend fun getAllConnections():
        Result<List<VPNConnection>> {

        return try {

            val entities =
                vpnDao.getAllConnections()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
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
                vpnDao.getConnectionsBetween(
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
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves connections associated with a particular
     * server.
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
                vpnDao.getConnectionsByServer(
                    serverId
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves currently active VPN connections.
     *
     * Normally SentriX should have at most one active VPN
     * tunnel per protected device profile.
     */
    override suspend fun getActiveConnections():
        Result<List<VPNConnection>> {

        return try {

            val entities =
                vpnDao.getActiveConnections()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Saves or updates a VPN connection.
     *
     * This method is used by the VPN manager/service when the
     * connection state changes.
     */
    override suspend fun saveConnection(
        connection: VPNConnection
    ): Result<Unit> {

        return try {

            vpnDao.insertOrUpdate(
                connection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Saves multiple VPN connection records.
     *
     * Useful during backend synchronization.
     */
    override suspend fun saveConnections(
        connections: List<VPNConnection>
    ): Result<Unit> {

        return try {

            if (connections.isEmpty()) {
                return Result.success(Unit)
            }

            vpnDao.insertOrUpdateAll(
                connections.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Updates VPN connection status.
     *
     * Example statuses:
     *
     * DISCONNECTED
     * CONNECTING
     * CONNECTED
     * RECONNECTING
     * DISCONNECTING
     * FAILED
     */
    override suspend fun updateConnectionStatus(
        connectionId: String,
        status: String
    ): Result<Unit> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection status cannot be blank."
                    )
                )
            }

            vpnDao.updateConnectionStatus(
                connectionId = connectionId,
                status = status
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Marks a VPN connection as connected.
     *
     * The actual tunnel establishment is handled outside the
     * repository.
     */
    override suspend fun markConnected(
        connectionId: String,
        connectedAt: Long
    ): Result<Unit> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            vpnDao.markConnected(
                connectionId = connectionId,
                connectedAt = connectedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Marks a VPN connection as disconnected.
     */
    override suspend fun markDisconnected(
        connectionId: String,
        disconnectedAt: Long
    ): Result<Unit> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            vpnDao.markDisconnected(
                connectionId = connectionId,
                disconnectedAt = disconnectedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Updates VPN traffic statistics.
     */
    override suspend fun updateTrafficStats(
        connectionId: String,
        uploadBytes: Long,
        downloadBytes: Long
    ): Result<Unit> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            if (uploadBytes < 0L || downloadBytes < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN traffic values cannot be negative."
                    )
                )
            }

            vpnDao.updateTrafficStats(
                connectionId = connectionId,
                uploadBytes = uploadBytes,
                downloadBytes = downloadBytes
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves total uploaded bytes.
     */
    override suspend fun getTotalUploadBytes():
        Result<Long> {

        return try {

            Result.success(
                vpnDao.getTotalUploadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves total downloaded bytes.
     */
    override suspend fun getTotalDownloadBytes():
        Result<Long> {

        return try {

            Result.success(
                vpnDao.getTotalDownloadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of VPN connections.
     */
    override suspend fun getConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnDao.getConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves the total connection duration.
     */
    override suspend fun getTotalConnectionDuration():
        Result<Long> {

        return try {

            Result.success(
                vpnDao.getTotalConnectionDuration()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves the latest VPN connection from the backend.
     *
     * The result is cached locally.
     */
    override suspend fun refreshCurrentConnection():
        Result<VPNConnection?> {

        return try {

            val response =
                vpnApiService.getCurrentConnection()

            response?.let {

                vpnDao.insertOrUpdate(
                    it.toEntity()
                )
            }

            Result.success(
                response?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Synchronizes VPN connection history with the backend.
     */
    override suspend fun synchronizeConnections():
        Result<Unit> {

        return try {

            val response =
                vpnApiService.getConnectionHistory()

            if (response.isNotEmpty()) {

                vpnDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Retrieves VPN records updated after the supplied
     * timestamp.
     *
     * Useful for incremental synchronization.
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

                vpnDao.insertOrUpdateAll(
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
                mapVPNException(exception)
            )
        }
    }

    /**
     * Deletes one VPN connection record.
     */
    override suspend fun deleteConnection(
        connectionId: String
    ): Result<Unit> {

        return try {

            if (connectionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN connection ID cannot be blank."
                    )
                )
            }

            vpnDao.deleteById(
                connectionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Deletes VPN connection records older than a specified
     * timestamp.
     *
     * This supports SentriX retention policies.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            vpnDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Clears locally stored VPN history.
     */
    override suspend fun clearConnectionHistory():
        Result<Unit> {

        return try {

            vpnDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNException(exception)
            )
        }
    }

    /**
     * Converts remote VPNConnectionDto into Domain model.
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
     * Converts Domain VPNConnection into Room entity.
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
    private fun mapVPNException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX VPN service.",
                    cause = exception
                )
            }

            /**
             * Backend HTTP failures.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The VPN request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access VPN information."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested VPN connection was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "VPN synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "VPN request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX VPN service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "VPN request failed with HTTP ${exception.code()}."
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
             * Unexpected database or infrastructure failure.
             */
            else -> {
                UnknownException(
                    message = "An unexpected VPN repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
