package com.sentrix.data.repository.vpn

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.VPNStatisticsDao
import com.sentrix.data.local.entities.VPNStatisticsEntity
import com.sentrix.data.remote.api.VPNApiService
import com.sentrix.data.remote.dto.VPNStatisticsDto
import com.sentrix.domain.models.VPNStatistics
import com.sentrix.domain.repository.VPNStatisticsRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - VPN Statistics Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.vpn
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * VPNStatisticsRepository.
 *
 * This repository manages VPN-related statistical data.
 *
 * Statistics may include:
 *
 * - Total VPN connections.
 * - Successful connections.
 * - Failed connections.
 * - Reconnection count.
 * - Total connection duration.
 * - Average connection duration.
 * - Upload traffic.
 * - Download traffic.
 * - Total traffic.
 * - Blocked network requests.
 * - Prevented threats.
 * - DNS threats blocked.
 * - Malicious domains blocked.
 * - Phishing requests blocked.
 * - Server latency.
 * - Average server load.
 * - VPN uptime.
 * - Statistics timestamp.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT calculate security decisions.
 *
 * It only stores, retrieves and synchronizes statistics.
 *
 * Security decisions belong to:
 *
 * - CyberDefenseService.
 * - NetworkSecurityService.
 * - VPNConnectionRules.
 * - ThreatAnalysisService.
 * - RiskScoringService.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * VPNStatisticsRepository
 *    │
 *    ▼
 * VPNStatisticsRepositoryImpl
 *    │
 *    ├──────────────► VPNStatisticsDao
 *    │                     │
 *    │                     ▼
 *    │              VPNStatisticsEntity
 *    │
 *    └──────────────► VPNApiService
 *                          │
 *                          ▼
 *                    VPNStatisticsDto
 */
@Singleton
class VPNStatisticsRepositoryImpl @Inject constructor(
    private val vpnStatisticsDao: VPNStatisticsDao,
    private val vpnApiService: VPNApiService
) : VPNStatisticsRepository {

    /**
     * Retrieves the latest VPN statistics.
     *
     * Local statistics are preferred so the SentriX dashboard
     * can continue working without network connectivity.
     */
    override suspend fun getLatestStatistics():
        Result<VPNStatistics?> {

        return try {

            val entity =
                vpnStatisticsDao.getLatestStatistics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves VPN statistics by their unique identifier.
     */
    override suspend fun getStatisticsById(
        statisticsId: String
    ): Result<VPNStatistics?> {

        return try {

            if (statisticsId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN statistics ID cannot be blank."
                    )
                )
            }

            val entity =
                vpnStatisticsDao.getById(
                    statisticsId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves recent VPN statistics snapshots.
     *
     * Useful for:
     *
     * - Analytics charts.
     * - Dashboard graphs.
     * - Historical VPN reports.
     * - Usage monitoring.
     */
    override suspend fun getRecentStatistics(
        limit: Int
    ): Result<List<VPNStatistics>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Statistics limit must be greater than zero."
                    )
                )
            }

            val entities =
                vpnStatisticsDao.getRecentStatistics(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves statistics within a time range.
     */
    override suspend fun getStatisticsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<VPNStatistics>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                vpnStatisticsDao.getStatisticsBetween(
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
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves statistics for a specific VPN server.
     */
    override suspend fun getStatisticsByServer(
        serverId: String
    ): Result<List<VPNStatistics>> {

        return try {

            if (serverId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN server ID cannot be blank."
                    )
                )
            }

            val entities =
                vpnStatisticsDao.getStatisticsByServer(
                    serverId
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Saves a VPN statistics snapshot locally.
     */
    override suspend fun saveStatistics(
        statistics: VPNStatistics
    ): Result<Unit> {

        return try {

            vpnStatisticsDao.insertOrUpdate(
                statistics.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Saves multiple VPN statistics records.
     *
     * Normally used during synchronization.
     */
    override suspend fun saveStatisticsBatch(
        statistics: List<VPNStatistics>
    ): Result<Unit> {

        return try {

            if (statistics.isEmpty()) {
                return Result.success(Unit)
            }

            vpnStatisticsDao.insertOrUpdateAll(
                statistics.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Increments the VPN connection count.
     */
    override suspend fun incrementConnectionCount():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementConnectionCount()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Increments successful connection count.
     */
    override suspend fun incrementSuccessfulConnections():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementSuccessfulConnections()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Increments failed connection count.
     */
    override suspend fun incrementFailedConnections():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementFailedConnections()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Increments VPN reconnection count.
     */
    override suspend fun incrementReconnections():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementReconnections()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Adds connection duration to the current statistics.
     */
    override suspend fun addConnectionDuration(
        durationMs: Long
    ): Result<Unit> {

        return try {

            if (durationMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Connection duration cannot be negative."
                    )
                )
            }

            vpnStatisticsDao.addConnectionDuration(
                durationMs
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Adds uploaded traffic to the statistics.
     */
    override suspend fun addUploadBytes(
        bytes: Long
    ): Result<Unit> {

        return try {

            if (bytes < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Upload bytes cannot be negative."
                    )
                )
            }

            vpnStatisticsDao.addUploadBytes(
                bytes
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Adds downloaded traffic to the statistics.
     */
    override suspend fun addDownloadBytes(
        bytes: Long
    ): Result<Unit> {

        return try {

            if (bytes < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Download bytes cannot be negative."
                    )
                )
            }

            vpnStatisticsDao.addDownloadBytes(
                bytes
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Records a blocked network request.
     */
    override suspend fun recordBlockedRequest():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementBlockedRequests()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Records a blocked malicious domain.
     */
    override suspend fun recordBlockedMaliciousDomain():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementBlockedMaliciousDomains()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Records a blocked phishing request.
     */
    override suspend fun recordBlockedPhishingRequest():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementBlockedPhishingRequests()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Records a prevented network threat.
     */
    override suspend fun recordPreventedThreat():
        Result<Unit> {

        return try {

            vpnStatisticsDao.incrementPreventedThreats()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Updates the latest server latency.
     */
    override suspend fun updateServerLatency(
        latencyMs: Long
    ): Result<Unit> {

        return try {

            if (latencyMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server latency cannot be negative."
                    )
                )
            }

            vpnStatisticsDao.updateServerLatency(
                latencyMs
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Updates the average server load.
     */
    override suspend fun updateServerLoad(
        loadPercentage: Double
    ): Result<Unit> {

        return try {

            if (loadPercentage !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Server load must be between 0 and 100."
                    )
                )
            }

            vpnStatisticsDao.updateServerLoad(
                loadPercentage
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Updates VPN uptime.
     */
    override suspend fun updateUptime(
        uptimeMs: Long
    ): Result<Unit> {

        return try {

            if (uptimeMs < 0L) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN uptime cannot be negative."
                    )
                )
            }

            vpnStatisticsDao.updateUptime(
                uptimeMs
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
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
                vpnStatisticsDao.getTotalUploadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
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
                vpnStatisticsDao.getTotalDownloadBytes()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total VPN traffic.
     */
    override suspend fun getTotalTrafficBytes():
        Result<Long> {

        return try {

            val upload =
                vpnStatisticsDao.getTotalUploadBytes()

            val download =
                vpnStatisticsDao.getTotalDownloadBytes()

            Result.success(
                upload + download
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total connection duration.
     */
    override suspend fun getTotalConnectionDuration():
        Result<Long> {

        return try {

            Result.success(
                vpnStatisticsDao.getTotalConnectionDuration()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total successful connections.
     */
    override suspend fun getSuccessfulConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnStatisticsDao.getSuccessfulConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total failed connections.
     */
    override suspend fun getFailedConnectionCount():
        Result<Int> {

        return try {

            Result.success(
                vpnStatisticsDao.getFailedConnectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total blocked requests.
     */
    override suspend fun getBlockedRequestCount():
        Result<Long> {

        return try {

            Result.success(
                vpnStatisticsDao.getBlockedRequestCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total prevented threats.
     */
    override suspend fun getPreventedThreatCount():
        Result<Long> {

        return try {

            Result.success(
                vpnStatisticsDao.getPreventedThreatCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total blocked phishing requests.
     */
    override suspend fun getBlockedPhishingRequestCount():
        Result<Long> {

        return try {

            Result.success(
                vpnStatisticsDao.getBlockedPhishingRequestCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves total blocked malicious domains.
     */
    override suspend fun getBlockedMaliciousDomainCount():
        Result<Long> {

        return try {

            Result.success(
                vpnStatisticsDao.getBlockedMaliciousDomainCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Refreshes latest VPN statistics from the backend.
     */
    override suspend fun refreshStatistics():
        Result<VPNStatistics?> {

        return try {

            val response =
                vpnApiService.getStatistics()

            response?.let {

                vpnStatisticsDao.insertOrUpdate(
                    it.toEntity()
                )
            }

            Result.success(
                response?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Retrieves remote statistics since a timestamp.
     *
     * Supports incremental synchronization.
     */
    override suspend fun getStatisticsSince(
        timestamp: Long
    ): Result<List<VPNStatistics>> {

        return try {

            val response =
                vpnApiService.getStatisticsSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                vpnStatisticsDao.insertOrUpdateAll(
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
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Synchronizes VPN statistics with the backend.
     */
    override suspend fun synchronizeStatistics():
        Result<Unit> {

        return try {

            val response =
                vpnApiService.getStatisticsHistory()

            if (response.isNotEmpty()) {

                vpnStatisticsDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Deletes statistics older than the supplied timestamp.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            vpnStatisticsDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Deletes one statistics record.
     */
    override suspend fun deleteStatistics(
        statisticsId: String
    ): Result<Unit> {

        return try {

            if (statisticsId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "VPN statistics ID cannot be blank."
                    )
                )
            }

            vpnStatisticsDao.deleteById(
                statisticsId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Clears all locally stored VPN statistics.
     */
    override suspend fun clearStatistics():
        Result<Unit> {

        return try {

            vpnStatisticsDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapVPNStatisticsException(exception)
            )
        }
    }

    /**
     * Converts remote VPNStatisticsDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun VPNStatisticsDto.toDomain():
        VPNStatistics {

        return VPNStatistics(
            statisticsId = statisticsId,
            timestamp = timestamp,
            serverId = serverId,
            totalConnections = totalConnections,
            successfulConnections =
                successfulConnections,
            failedConnections =
                failedConnections,
            reconnections =
                reconnections,
            totalConnectionDurationMs =
                totalConnectionDurationMs,
            averageConnectionDurationMs =
                averageConnectionDurationMs,
            uploadBytes =
                uploadBytes,
            downloadBytes =
                downloadBytes,
            blockedRequests =
                blockedRequests,
            blockedMaliciousDomains =
                blockedMaliciousDomains,
            blockedPhishingRequests =
                blockedPhishingRequests,
            preventedThreats =
                preventedThreats,
            averageServerLatencyMs =
                averageServerLatencyMs,
            averageServerLoadPercentage =
                averageServerLoadPercentage,
            uptimeMs =
                uptimeMs
        )
    }

    /**
     * Converts remote DTO into Room entity.
     *
     * DTO -> Entity
     */
    private fun VPNStatisticsDto.toEntity():
        VPNStatisticsEntity {

        return VPNStatisticsEntity(
            statisticsId = statisticsId,
            timestamp = timestamp,
            serverId = serverId,
            totalConnections = totalConnections,
            successfulConnections =
                successfulConnections,
            failedConnections =
                failedConnections,
            reconnections =
                reconnections,
            totalConnectionDurationMs =
                totalConnectionDurationMs,
            averageConnectionDurationMs =
                averageConnectionDurationMs,
            uploadBytes =
                uploadBytes,
            downloadBytes =
                downloadBytes,
            blockedRequests =
                blockedRequests,
            blockedMaliciousDomains =
                blockedMaliciousDomains,
            blockedPhishingRequests =
                blockedPhishingRequests,
            preventedThreats =
                preventedThreats,
            averageServerLatencyMs =
                averageServerLatencyMs,
            averageServerLoadPercentage =
                averageServerLoadPercentage,
            uptimeMs =
                uptimeMs
        )
    }

    /**
     * Converts Domain VPNStatistics into Room entity.
     *
     * Domain -> Entity
     */
    private fun VPNStatistics.toEntity():
        VPNStatisticsEntity {

        return VPNStatisticsEntity(
            statisticsId = statisticsId,
            timestamp = timestamp,
            serverId = serverId,
            totalConnections = totalConnections,
            successfulConnections =
                successfulConnections,
            failedConnections =
                failedConnections,
            reconnections =
                reconnections,
            totalConnectionDurationMs =
                totalConnectionDurationMs,
            averageConnectionDurationMs =
                averageConnectionDurationMs,
            uploadBytes =
                uploadBytes,
            downloadBytes =
                downloadBytes,
            blockedRequests =
                blockedRequests,
            blockedMaliciousDomains =
                blockedMaliciousDomains,
            blockedPhishingRequests =
                blockedPhishingRequests,
            preventedThreats =
                preventedThreats,
            averageServerLatencyMs =
                averageServerLatencyMs,
            averageServerLoadPercentage =
                averageServerLoadPercentage,
            uptimeMs =
                uptimeMs
        )
    }

    /**
     * Converts Room entity into Domain VPNStatistics.
     *
     * Entity -> Domain
     */
    private fun VPNStatisticsEntity.toDomain():
        VPNStatistics {

        return VPNStatistics(
            statisticsId = statisticsId,
            timestamp = timestamp,
            serverId = serverId,
            totalConnections = totalConnections,
            successfulConnections =
                successfulConnections,
            failedConnections =
                failedConnections,
            reconnections =
                reconnections,
            totalConnectionDurationMs =
                totalConnectionDurationMs,
            averageConnectionDurationMs =
                averageConnectionDurationMs,
            uploadBytes =
                uploadBytes,
            downloadBytes =
                downloadBytes,
            blockedRequests =
                blockedRequests,
            blockedMaliciousDomains =
                blockedMaliciousDomains,
            blockedPhishingRequests =
                blockedPhishingRequests,
            preventedThreats =
                preventedThreats,
            averageServerLatencyMs =
                averageServerLatencyMs,
            averageServerLoadPercentage =
                averageServerLoadPercentage,
            uptimeMs =
                uptimeMs
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapVPNStatisticsException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX VPN statistics service.",
                    cause = exception
                )
            }

            /**
             * Backend HTTP failure.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The VPN statistics request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access VPN statistics."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested VPN statistics were not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "VPN statistics synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "VPN statistics request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX VPN statistics service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "VPN statistics request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected VPN statistics repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
