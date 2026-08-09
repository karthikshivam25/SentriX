package com.sentrix.data.repository.analytics

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.SecurityMetricsDao
import com.sentrix.data.local.entities.SecurityMetricsEntity
import com.sentrix.data.remote.api.AnalyticsApiService
import com.sentrix.data.remote.dto.SecurityMetricsDto
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.repository.SecurityMetricsRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Security Metrics Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.analytics
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * SecurityMetricsRepository.
 *
 * Security metrics represent measurable indicators of the
 * device's current and historical security posture.
 *
 * Examples:
 *
 * - Overall security score.
 * - Threat count.
 * - Critical threat count.
 * - High threat count.
 * - Medium threat count.
 * - Low threat count.
 * - Malware detections.
 * - Phishing detections.
 * - Scam detections.
 * - Blocked threats.
 * - Scan count.
 * - Successful scans.
 * - Failed scans.
 * - Average risk score.
 * - Network threats.
 * - Privacy events.
 * - Protection events.
 * - Security incidents.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT calculate the security score.
 *
 * Calculation and interpretation belong to Domain services:
 *
 * - RiskScoringService
 * - AnalyticsService
 * - SecurityHealthService
 * - SecurityMetricsService
 * - CyberDefenseService
 *
 * This repository only retrieves, persists and synchronizes
 * metric data.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * SecurityMetricsRepository
 *    │
 *    ▼
 * SecurityMetricsRepositoryImpl
 *    │
 *    ├──────────────► SecurityMetricsDao
 *    │                     │
 *    │                     ▼
 *    │               SecurityMetricsEntity
 *    │
 *    └──────────────► AnalyticsApiService
 *                          │
 *                          ▼
 *                    SecurityMetricsDto
 */
@Singleton
class SecurityMetricsRepositoryImpl @Inject constructor(
    private val securityMetricsDao: SecurityMetricsDao,
    private val analyticsApiService: AnalyticsApiService
) : SecurityMetricsRepository {

    /**
     * Retrieves the latest security metrics.
     *
     * Local storage is preferred so the security dashboard
     * remains functional when the device is offline.
     */
    override suspend fun getLatestMetrics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                securityMetricsDao.getLatestMetrics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves the current metrics from the remote backend
     * and stores them locally.
     */
    override suspend fun refreshMetrics():
        Result<SecurityMetrics> {

        return try {

            val response =
                analyticsApiService.getSecurityMetrics()

            /**
             * Update local metrics cache.
             */
            cacheMetrics(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics using their unique identifier.
     */
    override suspend fun getMetricsById(
        metricsId: String
    ): Result<SecurityMetrics?> {

        return try {

            if (metricsId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security metrics ID cannot be blank."
                    )
                )
            }

            val entity =
                securityMetricsDao.getById(metricsId)

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves historical security metrics.
     *
     * Useful for security-score and risk trend charts.
     */
    override suspend fun getMetricsHistory(
        limit: Int
    ): Result<List<SecurityMetrics>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Metrics history limit must be greater than zero."
                    )
                )
            }

            val entities =
                securityMetricsDao.getRecentMetrics(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves security metrics between two timestamps.
     */
    override suspend fun getMetricsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<SecurityMetrics>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                securityMetricsDao.getMetricsBetween(
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
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves the metrics associated with a particular day.
     */
    override suspend fun getMetricsForDay(
        dayTimestamp: Long
    ): Result<SecurityMetrics?> {

        return try {

            val entity =
                securityMetricsDao.getMetricsForDay(
                    dayTimestamp
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics with a security score greater than
     * or equal to the supplied threshold.
     */
    override suspend fun getMetricsAboveSecurityScore(
        minimumScore: Double
    ): Result<List<SecurityMetrics>> {

        return try {

            if (minimumScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security score must be between 0 and 100."
                    )
                )
            }

            val entities =
                securityMetricsDao.getAboveSecurityScore(
                    minimumScore
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics with risk scores at or above the
     * supplied threshold.
     */
    override suspend fun getMetricsAboveRiskScore(
        minimumRiskScore: Double
    ): Result<List<SecurityMetrics>> {

        return try {

            if (minimumRiskScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Risk score must be between 0 and 100."
                    )
                )
            }

            val entities =
                securityMetricsDao.getAboveRiskScore(
                    minimumRiskScore
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics containing critical threats.
     */
    override suspend fun getCriticalThreatMetrics():
        Result<List<SecurityMetrics>> {

        return try {

            val entities =
                securityMetricsDao.getWithCriticalThreats()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics containing malware detections.
     */
    override suspend fun getMalwareMetrics():
        Result<List<SecurityMetrics>> {

        return try {

            val entities =
                securityMetricsDao.getWithMalwareDetections()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics containing phishing detections.
     */
    override suspend fun getPhishingMetrics():
        Result<List<SecurityMetrics>> {

        return try {

            val entities =
                securityMetricsDao.getWithPhishingDetections()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics containing network threats.
     */
    override suspend fun getNetworkThreatMetrics():
        Result<List<SecurityMetrics>> {

        return try {

            val entities =
                securityMetricsDao.getWithNetworkThreats()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Saves locally generated security metrics.
     */
    override suspend fun saveMetrics(
        metrics: SecurityMetrics
    ): Result<Unit> {

        return try {

            securityMetricsDao.insertOrUpdate(
                metrics.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Saves multiple security metric records.
     */
    override suspend fun saveMetricsBatch(
        metrics: List<SecurityMetrics>
    ): Result<Unit> {

        return try {

            if (metrics.isEmpty()) {
                return Result.success(Unit)
            }

            securityMetricsDao.insertOrUpdateAll(
                metrics.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Retrieves metrics generated since the supplied
     * timestamp.
     *
     * Useful for incremental synchronization.
     */
    override suspend fun getMetricsSince(
        timestamp: Long
    ): Result<List<SecurityMetrics>> {

        return try {

            val response =
                analyticsApiService.getSecurityMetricsSince(
                    timestamp
                )

            cacheMetrics(response)

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Synchronizes security metrics with the remote backend.
     */
    override suspend fun synchronizeMetrics():
        Result<Unit> {

        return try {

            val response =
                analyticsApiService.getSecurityMetricsHistory()

            if (response.isNotEmpty()) {

                securityMetricsDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Deletes metrics older than the supplied timestamp.
     *
     * Retention policy should be controlled by SentriX
     * security/privacy configuration.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            securityMetricsDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Deletes one security-metrics record.
     */
    override suspend fun deleteMetrics(
        metricsId: String
    ): Result<Unit> {

        return try {

            if (metricsId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security metrics ID cannot be blank."
                    )
                )
            }

            securityMetricsDao.deleteById(
                metricsId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Clears the local security metrics cache.
     */
    override suspend fun clearMetrics():
        Result<Unit> {

        return try {

            securityMetricsDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored security metric
     * records.
     */
    override suspend fun getMetricsCount():
        Result<Int> {

        return try {

            Result.success(
                securityMetricsDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityMetricsException(exception)
            )
        }
    }

    /**
     * Converts remote SecurityMetricsDto into the Domain
     * SecurityMetrics model.
     *
     * DTO -> Domain
     */
    private fun SecurityMetricsDto.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts remote SecurityMetricsDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun SecurityMetricsDto.toEntity():
        SecurityMetricsEntity {

        return SecurityMetricsEntity(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts Domain SecurityMetrics into Room entity.
     *
     * Domain -> Entity
     */
    private fun SecurityMetrics.toEntity():
        SecurityMetricsEntity {

        return SecurityMetricsEntity(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts Room SecurityMetricsEntity into Domain model.
     *
     * Entity -> Domain
     */
    private fun SecurityMetricsEntity.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Caches one remote metrics response.
     */
    private suspend fun cacheMetrics(
        metrics: SecurityMetricsDto
    ) {

        securityMetricsDao.insertOrUpdate(
            metrics.toEntity()
        )
    }

    /**
     * Caches multiple remote metrics responses.
     */
    private suspend fun cacheMetrics(
        metrics: List<SecurityMetricsDto>
    ) {

        if (metrics.isEmpty()) {
            return
        }

        securityMetricsDao.insertOrUpdateAll(
            metrics.map {
                it.toEntity()
            }
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapSecurityMetricsException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Connectivity failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX security-metrics service.",
                    cause = exception
                )
            }

            /**
             * HTTP/backend failures.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The security-metrics request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access security metrics."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested security metrics were not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Security-metrics synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Security-metrics request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX security-metrics service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Security-metrics request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected security-metrics repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
