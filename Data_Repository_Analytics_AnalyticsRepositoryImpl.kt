package com.sentrix.data.repository.analytics

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.AnalyticsDao
import com.sentrix.data.local.entities.AnalyticsEntity
import com.sentrix.data.remote.api.AnalyticsApiService
import com.sentrix.data.remote.dto.AnalyticsDto
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.repository.AnalyticsRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Analytics Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.analytics
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of AnalyticsRepository.
 *
 * This repository provides security analytics data used by:
 *
 * - Security Dashboard
 * - Analytics screens
 * - Security Reports
 * - Risk monitoring
 * - Threat trend analysis
 * - Scan statistics
 * - Protection statistics
 * - Security health summaries
 *
 * Analytics may include:
 *
 * - Total scans.
 * - Completed scans.
 * - Failed scans.
 * - Threats detected.
 * - Critical threats.
 * - High threats.
 * - Medium threats.
 * - Low threats.
 * - Average risk score.
 * - Security score.
 * - Blocked threats.
 * - Malware detections.
 * - Phishing detections.
 * - Scam detections.
 * - Network threats.
 * - Privacy events.
 * - Protection events.
 * - Scan duration.
 * - Threat trends.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT calculate security policy or decide
 * whether a threat is malicious.
 *
 * Domain services remain responsible for:
 *
 * - Security metric interpretation.
 * - Risk calculations.
 * - Security scoring.
 * - Trend classification.
 * - Recommendations.
 *
 * This repository is responsible for:
 *
 * - Data retrieval.
 * - Local persistence.
 * - Remote synchronization.
 * - Historical queries.
 * - DTO <-> Domain mapping.
 * - Entity <-> Domain mapping.
 * - Exception translation.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * AnalyticsRepository
 *    │
 *    ▼
 * AnalyticsRepositoryImpl
 *    │
 *    ├──────────────► AnalyticsApiService
 *    │                     │
 *    │                     ▼
 *    │                AnalyticsDto
 *    │
 *    └──────────────► AnalyticsDao
 *                          │
 *                          ▼
 *                    AnalyticsEntity
 */
@Singleton
class AnalyticsRepositoryImpl @Inject constructor(
    private val analyticsApiService: AnalyticsApiService,
    private val analyticsDao: AnalyticsDao
) : AnalyticsRepository {

    /**
     * Retrieves the latest security analytics.
     *
     * Local cache is used first so dashboard analytics remain
     * available when the device is offline.
     */
    override suspend fun getLatestAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getLatestAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves the current analytics from the remote service
     * and updates the local cache.
     */
    override suspend fun refreshAnalytics():
        Result<SecurityMetrics> {

        return try {

            val response =
                analyticsApiService.getAnalytics()

            /**
             * Store the latest analytics locally.
             */
            cacheAnalytics(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves analytics for a specific time period.
     *
     * Timestamps are expected to be epoch milliseconds.
     */
    override suspend fun getAnalyticsBetween(
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
                analyticsDao.getAnalyticsBetween(
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
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves analytics for a specific date.
     *
     * The date is represented as an application-defined
     * timestamp/day identifier.
     */
    override suspend fun getAnalyticsForDay(
        dayTimestamp: Long
    ): Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getAnalyticsForDay(
                    dayTimestamp
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves recent analytics records.
     *
     * Useful for charts and dashboard trend visualization.
     */
    override suspend fun getRecentAnalytics(
        limit: Int
    ): Result<List<SecurityMetrics>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Analytics limit must be greater than zero."
                    )
                )
            }

            val entities =
                analyticsDao.getRecentAnalytics(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves scan-related analytics.
     */
    override suspend fun getScanAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getScanAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves threat-related analytics.
     */
    override suspend fun getThreatAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getThreatAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves malware-related analytics.
     */
    override suspend fun getMalwareAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getMalwareAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves privacy/security-event analytics.
     */
    override suspend fun getPrivacyAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getPrivacyAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves network-security analytics.
     */
    override suspend fun getNetworkAnalytics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                analyticsDao.getNetworkAnalytics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Saves locally generated analytics.
     *
     * This allows SentriX to record analytics even when the
     * device is offline.
     */
    override suspend fun saveAnalytics(
        metrics: SecurityMetrics
    ): Result<Unit> {

        return try {

            analyticsDao.insertOrUpdate(
                metrics.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Saves multiple analytics records.
     *
     * Useful for batch synchronization.
     */
    override suspend fun saveAnalyticsBatch(
        metrics: List<SecurityMetrics>
    ): Result<Unit> {

        return try {

            if (metrics.isEmpty()) {
                return Result.success(Unit)
            }

            analyticsDao.insertOrUpdateAll(
                metrics.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Synchronizes analytics with the remote backend.
     */
    override suspend fun synchronizeAnalytics():
        Result<Unit> {

        return try {

            val response =
                analyticsApiService.getAnalyticsHistory()

            if (response.isNotEmpty()) {

                analyticsDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Retrieves analytics updated since a specific timestamp.
     *
     * This enables incremental synchronization rather than
     * downloading the entire analytics dataset.
     */
    override suspend fun getAnalyticsSince(
        timestamp: Long
    ): Result<List<SecurityMetrics>> {

        return try {

            val response =
                analyticsApiService.getAnalyticsSince(
                    timestamp
                )

            cacheAnalytics(response)

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Deletes analytics records older than a specified
     * timestamp.
     *
     * Retention should be controlled by SentriX privacy and
     * storage policies.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            analyticsDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Deletes one analytics record.
     */
    override suspend fun deleteAnalytics(
        analyticsId: String
    ): Result<Unit> {

        return try {

            if (analyticsId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Analytics ID cannot be blank."
                    )
                )
            }

            analyticsDao.deleteById(
                analyticsId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Clears locally cached analytics.
     *
     * This should normally be invoked only during an explicit
     * data-reset or privacy operation.
     */
    override suspend fun clearAnalytics():
        Result<Unit> {

        return try {

            analyticsDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Returns the total number of analytics records.
     */
    override suspend fun getAnalyticsCount():
        Result<Int> {

        return try {

            Result.success(
                analyticsDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAnalyticsException(exception)
            )
        }
    }

    /**
     * Converts remote AnalyticsDto into the Domain
     * SecurityMetrics model.
     *
     * DTO -> Domain
     */
    private fun AnalyticsDto.toDomain():
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
     * Converts remote AnalyticsDto into a local Room entity.
     *
     * DTO -> Entity
     */
    private fun AnalyticsDto.toEntity():
        AnalyticsEntity {

        return AnalyticsEntity(
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
        AnalyticsEntity {

        return AnalyticsEntity(
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
     * Converts Room AnalyticsEntity into Domain model.
     *
     * Entity -> Domain
     */
    private fun AnalyticsEntity.toDomain():
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
     * Stores a remote analytics record locally.
     */
    private suspend fun cacheAnalytics(
        analytics: AnalyticsDto
    ) {

        analyticsDao.insertOrUpdate(
            analytics.toEntity()
        )
    }

    /**
     * Stores multiple remote analytics records locally.
     */
    private suspend fun cacheAnalytics(
        analytics: List<AnalyticsDto>
    ) {

        if (analytics.isEmpty()) {
            return
        }

        analyticsDao.insertOrUpdateAll(
            analytics.map {
                it.toEntity()
            }
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapAnalyticsException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX analytics service.",
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
                            "The analytics request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access analytics."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested analytics data was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Analytics synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Analytics request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX analytics service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Analytics request failed with HTTP ${exception.code()}."
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
             * Unexpected database or infrastructure error.
             */
            else -> {
                UnknownException(
                    message = "An unexpected analytics repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
