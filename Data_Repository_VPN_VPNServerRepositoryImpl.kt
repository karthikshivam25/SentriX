package com.sentrix.data.repository.vpn

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.VPNServerDao
import com.sentrix.data.local.entities.VPNServerEntity
import com.sentrix.data.remote.api.VPNApiService
import com.sentrix.data.remote.dto.VPNServerDto
import com.sentrix.domain.models.VPNServer
import com.sentrix.domain.repository.VPNServerRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - VPN Server Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.vpn
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of VPNServerRepository.
 *
 * This repository manages VPN server metadata and server
 * availability information.
 *
 * It is responsible for:
 *
 * - VPN server records.
 * - Server metadata.
 * - Server country.
 * - Server region.
 * - Server hostname/address.
 * - Server port.
 * - VPN protocols.
 * - Server status.
 * - Server health.
 * - Server load.
 * - Server latency.
 * - Server capacity.
 * - Server capabilities.
 * - Server synchronization.
 * - Local server caching.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide which VPN server the user
 * should connect to.
 *
 * Server selection belongs to Domain services/rules such as:
 *
 * - VPNServerSelectionService
 * - VPNOptimizationService
 * - VPNConnectionRules
 * - NetworkSecurityService
 *
 * The repository only provides server DATA.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * VPNServerRepository
 *    │
 *    ▼
 * VPNServerRepositoryImpl
 *    │
 *    ├──────────────► VPNServerDao
 *    │                     │
 *    │                     ▼
 *    │                VPNServerEntity
 *    │
 *    └──────────────► VPNApiService
 *                          │
 *                          ▼
 *                      VPNServerDto
 */
@Singleton
class VPNServerRepositoryImpl @Inject constructor(
    private val vpnServerDao: VPNServerDao,
    private val vpnApiService: VPNApiService
) : VPNServerRepository {

    /**
     * Retrieves all locally cached VPN servers.
     *
     * Local data allows the VPN server list to remain
     * available when the device is offline.
     */
    override suspend fun getAllServers():
        Result<List<VPNServer>> {

        return try {

            val entities =
                vpnServerDao.getAllServers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves a VPN server by its unique ID.
     */
    override suspend fun getServerById(
        serverId: String
    ): Result<VPNServer?> {

        return try {

            if (serverId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN server ID cannot be blank."
                    )
                )
            }

            val entity =
                vpnServerDao.getById(
                    serverId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers by country.
     */
    override suspend fun getServersByCountry(
        countryCode: String
    ): Result<List<VPNServer>> {

        return try {

            if (countryCode.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Country code cannot be blank."
                    )
                )
            }

            val entities =
                vpnServerDao.getByCountry(
                    countryCode.uppercase()
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers by region.
     */
    override suspend fun getServersByRegion(
        region: String
    ): Result<List<VPNServer>> {

        return try {

            if (region.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN server region cannot be blank."
                    )
                )
            }

            val entities =
                vpnServerDao.getByRegion(
                    region
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers supporting a specific VPN protocol.
     *
     * Examples:
     *
     * WireGuard
     * OpenVPN
     * IKEv2
     */
    override suspend fun getServersByProtocol(
        protocol: String
    ): Result<List<VPNServer>> {

        return try {

            if (protocol.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN protocol cannot be blank."
                    )
                )
            }

            val entities =
                vpnServerDao.getByProtocol(
                    protocol
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves currently available servers.
     *
     * This only reflects persisted server availability.
     * It does not perform a live connection test.
     */
    override suspend fun getAvailableServers():
        Result<List<VPNServer>> {

        return try {

            val entities =
                vpnServerDao.getAvailableServers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves healthy VPN servers.
     */
    override suspend fun getHealthyServers():
        Result<List<VPNServer>> {

        return try {

            val entities =
                vpnServerDao.getHealthyServers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers whose load is below a specified
     * percentage.
     */
    override suspend fun getServersBelowLoad(
        maximumLoad: Double
    ): Result<List<VPNServer>> {

        return try {

            if (maximumLoad !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server load must be between 0 and 100."
                    )
                )
            }

            val entities =
                vpnServerDao.getBelowLoad(
                    maximumLoad
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers whose latency is below the specified
     * threshold.
     */
    override suspend fun getServersBelowLatency(
        maximumLatencyMs: Long
    ): Result<List<VPNServer>> {

        return try {

            if (maximumLatencyMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Latency cannot be negative."
                    )
                )
            }

            val entities =
                vpnServerDao.getBelowLatency(
                    maximumLatencyMs
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves the nearest servers available for a given
     * geographical location.
     *
     * The actual server selection algorithm should remain in
     * the Domain layer. This repository simply queries the
     * persisted server metadata.
     */
    override suspend fun getServersNearLocation(
        latitude: Double,
        longitude: Double,
        limit: Int
    ): Result<List<VPNServer>> {

        return try {

            if (latitude !in -90.0..90.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Latitude must be between -90 and 90."
                    )
                )
            }

            if (longitude !in -180.0..180.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Longitude must be between -180 and 180."
                    )
                )
            }

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server limit must be greater than zero."
                    )
                )
            }

            val entities =
                vpnServerDao.getNearestServers(
                    latitude = latitude,
                    longitude = longitude,
                    limit = limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves servers supporting a particular capability.
     *
     * Examples:
     *
     * - KILL_SWITCH
     * - DNS_PROTECTION
     * - THREAT_MONITORING
     * - IPV6
     */
    override suspend fun getServersByCapability(
        capability: String
    ): Result<List<VPNServer>> {

        return try {

            if (capability.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN server capability cannot be blank."
                    )
                )
            }

            val entities =
                vpnServerDao.getByCapability(
                    capability
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves the current server count.
     */
    override suspend fun getServerCount():
        Result<Int> {

        return try {

            Result.success(
                vpnServerDao.getServerCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves the number of available servers.
     */
    override suspend fun getAvailableServerCount():
        Result<Int> {

        return try {

            Result.success(
                vpnServerDao.getAvailableServerCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Saves a single VPN server.
     */
    override suspend fun saveServer(
        server: VPNServer
    ): Result<Unit> {

        return try {

            vpnServerDao.insertOrUpdate(
                server.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Saves multiple VPN servers.
     *
     * Normally used when refreshing the server catalogue.
     */
    override suspend fun saveServers(
        servers: List<VPNServer>
    ): Result<Unit> {

        return try {

            if (servers.isEmpty()) {
                return Result.success(Unit)
            }

            vpnServerDao.insertOrUpdateAll(
                servers.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Updates server availability.
     */
    override suspend fun updateServerAvailability(
        serverId: String,
        available: Boolean
    ): Result<Unit> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            vpnServerDao.updateAvailability(
                serverId = serverId,
                available = available
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Updates server health.
     */
    override suspend fun updateServerHealth(
        serverId: String,
        healthStatus: String
    ): Result<Unit> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            if (healthStatus.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server health status cannot be blank."
                    )
                )
            }

            vpnServerDao.updateHealth(
                serverId = serverId,
                healthStatus = healthStatus
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Updates server load.
     */
    override suspend fun updateServerLoad(
        serverId: String,
        loadPercentage: Double
    ): Result<Unit> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            if (loadPercentage !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server load must be between 0 and 100."
                    )
                )
            }

            vpnServerDao.updateLoad(
                serverId = serverId,
                loadPercentage = loadPercentage
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Updates server latency.
     */
    override suspend fun updateServerLatency(
        serverId: String,
        latencyMs: Long
    ): Result<Unit> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            if (latencyMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server latency cannot be negative."
                    )
                )
            }

            vpnServerDao.updateLatency(
                serverId = serverId,
                latencyMs = latencyMs
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves the latest health information for a server.
     */
    override suspend fun getServerHealth(
        serverId: String
    ): Result<String?> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            Result.success(
                vpnServerDao.getHealth(
                    serverId
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Refreshes the complete VPN server catalogue from the
     * SentriX backend.
     */
    override suspend fun refreshServers():
        Result<List<VPNServer>> {

        return try {

            val response =
                vpnApiService.getServers()

            if (response.isNotEmpty()) {

                vpnServerDao.insertOrUpdateAll(
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
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Retrieves server information updated after a specified
     * timestamp.
     *
     * Used for incremental synchronization.
     */
    override suspend fun getServersSince(
        timestamp: Long
    ): Result<List<VPNServer>> {

        return try {

            val response =
                vpnApiService.getServersSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                vpnServerDao.insertOrUpdateAll(
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
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Synchronizes the complete VPN server catalogue.
     */
    override suspend fun synchronizeServers():
        Result<Unit> {

        return try {

            val response =
                vpnApiService.getServers()

            if (response.isNotEmpty()) {

                vpnServerDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Deletes one VPN server from local storage.
     */
    override suspend fun deleteServer(
        serverId: String
    ): Result<Unit> {

        return try {

            validateServerId(
                serverId
            )?.let {
                return Result.failure(it)
            }

            vpnServerDao.deleteById(
                serverId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Deletes VPN servers that have not been updated since
     * the supplied timestamp.
     *
     * Useful for local cache cleanup.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            vpnServerDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Clears the complete locally cached VPN server catalogue.
     */
    override suspend fun clearServers():
        Result<Unit> {

        return try {

            vpnServerDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNServerException(exception)
            )
        }
    }

    /**
     * Validates the server ID.
     */
    private fun validateServerId(
        serverId: String
    ): Exception? {

        return if (serverId.isBlank()) {
            IllegalArgumentException(
                "VPN server ID cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Converts VPNServerDto into Domain VPNServer.
     *
     * DTO -> Domain
     */
    private fun VPNServerDto.toDomain():
        VPNServer {

        return VPNServer(
            serverId = serverId,
            serverName = serverName,
            countryCode = countryCode,
            countryName = countryName,
            region = region,
            hostname = hostname,
            serverAddress = serverAddress,
            port = port,
            protocols = protocols,
            status = status,
            available = available,
            healthStatus = healthStatus,
            loadPercentage = loadPercentage,
            latencyMs = latencyMs,
            capacity = capacity,
            supportsKillSwitch =
                supportsKillSwitch,
            supportsDnsProtection =
                supportsDnsProtection,
            supportsThreatMonitoring =
                supportsThreatMonitoring,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    /**
     * Converts VPNServerDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun VPNServerDto.toEntity():
        VPNServerEntity {

        return VPNServerEntity(
            serverId = serverId,
            serverName = serverName,
            countryCode = countryCode,
            countryName = countryName,
            region = region,
            hostname = hostname,
            serverAddress = serverAddress,
            port = port,
            protocols = protocols,
            status = status,
            available = available,
            healthStatus = healthStatus,
            loadPercentage = loadPercentage,
            latencyMs = latencyMs,
            capacity = capacity,
            supportsKillSwitch =
                supportsKillSwitch,
            supportsDnsProtection =
                supportsDnsProtection,
            supportsThreatMonitoring =
                supportsThreatMonitoring,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    /**
     * Converts Domain VPNServer into Room entity.
     *
     * Domain -> Entity
     */
    private fun VPNServer.toEntity():
        VPNServerEntity {

        return VPNServerEntity(
            serverId = serverId,
            serverName = serverName,
            countryCode = countryCode,
            countryName = countryName,
            region = region,
            hostname = hostname,
            serverAddress = serverAddress,
            port = port,
            protocols = protocols,
            status = status,
            available = available,
            healthStatus = healthStatus,
            loadPercentage = loadPercentage,
            latencyMs = latencyMs,
            capacity = capacity,
            supportsKillSwitch =
                supportsKillSwitch,
            supportsDnsProtection =
                supportsDnsProtection,
            supportsThreatMonitoring =
                supportsThreatMonitoring,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    /**
     * Converts Room entity into Domain VPNServer.
     *
     * Entity -> Domain
     */
    private fun VPNServerEntity.toDomain():
        VPNServer {

        return VPNServer(
            serverId = serverId,
            serverName = serverName,
            countryCode = countryCode,
            countryName = countryName,
            region = region,
            hostname = hostname,
            serverAddress = serverAddress,
            port = port,
            protocols = protocols,
            status = status,
            available = available,
            healthStatus = healthStatus,
            loadPercentage = loadPercentage,
            latencyMs = latencyMs,
            capacity = capacity,
            supportsKillSwitch =
                supportsKillSwitch,
            supportsDnsProtection =
                supportsDnsProtection,
            supportsThreatMonitoring =
                supportsThreatMonitoring,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapVPNServerException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX VPN server service.",
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
                            "The VPN server request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access VPN servers."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested VPN server was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "VPN server synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "VPN server request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX VPN server service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "VPN server request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected VPN server repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
