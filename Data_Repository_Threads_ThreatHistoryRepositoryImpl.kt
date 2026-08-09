package com.sentrix.data.repository.threads

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ThreatHistoryDao
import com.sentrix.data.local.entities.ThreatHistoryEntity
import com.sentrix.data.remote.api.ThreatApiService
import com.sentrix.data.remote.dto.ThreatHistoryDto
import com.sentrix.domain.models.ThreatHistory
import com.sentrix.domain.repository.ThreatHistoryRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat History Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.threads
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Manages historical threat detection and analysis records.
 *
 * ThreatRepository:
 * ------------------------------------------------------------
 * Represents current threat intelligence.
 *
 * ThreatHistoryRepository:
 * ------------------------------------------------------------
 * Represents what happened on the user's device over time.
 *
 * Examples:
 *
 * - Malware detected
 * - Phishing URL detected
 * - Suspicious APK detected
 * - Scam message detected
 * - Malicious download detected
 * - Suspicious network activity detected
 * - Threat resolved
 * - Threat ignored
 * - Threat quarantined
 * - Threat blocked
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *    │
 *    ▼
 * ThreatHistoryRepository
 *    │
 *    ▼
 * ThreatHistoryRepositoryImpl
 *    │
 *    ├──────────────► ThreatHistoryDao
 *    │
 *    └──────────────► ThreatApiService
 *                              │
 *                              ▼
 *                       ThreatHistoryDto
 *
 * Important:
 * ------------------------------------------------------------
 * Historical records are security/audit data.
 *
 * They should not be silently deleted as part of normal
 * threat-cache cleanup.
 *
 * Authentication/session cleanup and threat-history cleanup
 * should remain separate operations.
 */
@Singleton
class ThreatHistoryRepositoryImpl @Inject constructor(
    private val threatHistoryDao: ThreatHistoryDao,
    private val threatApiService: ThreatApiService
) : ThreatHistoryRepository {

    /**
     * Retrieves all locally stored threat-history records.
     *
     * This operation is local-first and does not require
     * network connectivity.
     */
    override suspend fun getThreatHistory(): Result<List<ThreatHistory>> {

        return try {

            val entities =
                threatHistoryDao.getAllThreatHistory()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves a single threat-history record by ID.
     */
    override suspend fun getThreatHistoryById(
        historyId: String
    ): Result<ThreatHistory?> {

        return try {

            if (historyId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat history ID cannot be blank."
                    )
                )
            }

            val entity =
                threatHistoryDao.getThreatHistoryById(historyId)

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves historical events associated with a specific
     * threat.
     *
     * This is useful when the same threat has been detected
     * multiple times.
     */
    override suspend fun getHistoryForThreat(
        threatId: String
    ): Result<List<ThreatHistory>> {

        return try {

            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            val entities =
                threatHistoryDao.getHistoryForThreat(threatId)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves historical records associated with a
     * particular security event type.
     *
     * Examples:
     *
     * MALWARE
     * PHISHING
     * SCAM
     * TROJAN
     * SPYWARE
     * NETWORK
     * APK
     * FILE
     * URL
     */
    override suspend fun getHistoryByCategory(
        category: String
    ): Result<List<ThreatHistory>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat category cannot be blank."
                    )
                )
            }

            val entities =
                threatHistoryDao.getHistoryByCategory(category)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves historical records for a specific severity.
     *
     * Examples:
     *
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     */
    override suspend fun getHistoryBySeverity(
        severity: String
    ): Result<List<ThreatHistory>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat severity cannot be blank."
                    )
                )
            }

            val entities =
                threatHistoryDao.getHistoryBySeverity(severity)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves threat history within a specific time range.
     *
     * Both timestamps are expected to use epoch milliseconds.
     *
     * Example:
     *
     * startTime = beginning of today
     * endTime   = current time
     */
    override suspend fun getHistoryBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<ThreatHistory>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                threatHistoryDao.getHistoryBetween(
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
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Retrieves the latest threat-history records.
     *
     * The limit is used to prevent loading an unnecessarily
     * large amount of historical security data into memory.
     */
    override suspend fun getRecentHistory(
        limit: Int
    ): Result<List<ThreatHistory>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "History limit must be greater than zero."
                    )
                )
            }

            val entities =
                threatHistoryDao.getRecentHistory(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Stores a newly detected threat event locally.
     *
     * This method is intended to be called by threat-analysis
     * and real-time protection components.
     */
    override suspend fun recordThreat(
        history: ThreatHistory
    ): Result<Unit> {

        return try {

            /**
             * Convert Domain object to database entity.
             */
            val entity =
                history.toEntity()

            /**
             * Persist the security event locally.
             */
            threatHistoryDao.insertOrUpdate(entity)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Stores multiple historical threat events.
     *
     * Bulk insertion is preferred when a scan produces
     * multiple findings.
     */
    override suspend fun recordThreats(
        history: List<ThreatHistory>
    ): Result<Unit> {

        return try {

            if (history.isEmpty()) {
                return Result.success(Unit)
            }

            threatHistoryDao.insertOrUpdateAll(
                history.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Updates the status of a previously detected threat.
     *
     * Examples:
     *
     * DETECTED
     * BLOCKED
     * QUARANTINED
     * RESOLVED
     * IGNORED
     */
    override suspend fun updateThreatStatus(
        historyId: String,
        status: String
    ): Result<Unit> {

        return try {

            if (historyId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat history ID cannot be blank."
                    )
                )
            }

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat status cannot be blank."
                    )
                )
            }

            threatHistoryDao.updateThreatStatus(
                historyId = historyId,
                status = status
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Marks a threat-history record as resolved.
     */
    override suspend fun markAsResolved(
        historyId: String
    ): Result<Unit> {

        return try {

            if (historyId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat history ID cannot be blank."
                    )
                )
            }

            threatHistoryDao.updateThreatStatus(
                historyId = historyId,
                status = THREAT_STATUS_RESOLVED
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Removes one historical record.
     *
     * This should generally be used only for explicit cleanup
     * or privacy-related deletion.
     */
    override suspend fun deleteThreatHistory(
        historyId: String
    ): Result<Unit> {

        return try {

            if (historyId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat history ID cannot be blank."
                    )
                )
            }

            threatHistoryDao.deleteThreatHistory(
                historyId = historyId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Deletes historical records older than the supplied
     * timestamp.
     *
     * Example:
     *
     * deleteHistoryOlderThan(
     *     System.currentTimeMillis() - 30.days
     * )
     *
     * The actual retention period should be controlled by
     * SentriX security/privacy policy rather than hard-coded
     * inside the repository.
     */
    override suspend fun deleteHistoryOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            threatHistoryDao.deleteHistoryOlderThan(
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Returns the total number of stored threat-history
     * records.
     */
    override suspend fun getThreatHistoryCount(): Result<Int> {

        return try {

            Result.success(
                threatHistoryDao.getThreatHistoryCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Synchronizes locally stored threat history with the
     * SentriX backend.
     *
     * The backend API is treated as the remote source of
     * security-history synchronization.
     */
    override suspend fun synchronizeThreatHistory(): Result<Unit> {

        return try {

            /**
             * Retrieve remote threat-history information.
             */
            val response =
                threatApiService.getThreatHistory()

            /**
             * Convert remote DTOs into local entities.
             */
            val entities =
                response.map {
                    it.toEntity()
                }

            /**
             * Merge the remote history into the local cache.
             */
            if (entities.isNotEmpty()) {
                threatHistoryDao.insertOrUpdateAll(
                    entities
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatHistoryException(exception)
            )
        }
    }

    /**
     * Converts a remote ThreatHistoryDto into a Domain model.
     */
    private fun ThreatHistoryDto.toDomain(): ThreatHistory {

        return ThreatHistory(
            id = id,
            threatId = threatId,
            category = category,
            severity = severity,
            status = status,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            confidenceScore = confidenceScore
        )
    }

    /**
     * Converts a remote ThreatHistoryDto into a local
     * Room entity.
     */
    private fun ThreatHistoryDto.toEntity(): ThreatHistoryEntity {

        return ThreatHistoryEntity(
            id = id,
            threatId = threatId,
            category = category,
            severity = severity,
            status = status,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            confidenceScore = confidenceScore
        )
    }

    /**
     * Converts a Domain ThreatHistory model into a Room
     * entity.
     */
    private fun ThreatHistory.toEntity(): ThreatHistoryEntity {

        return ThreatHistoryEntity(
            id = id,
            threatId = threatId,
            category = category,
            severity = severity,
            status = status,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            confidenceScore = confidenceScore
        )
    }

    /**
     * Converts a Room entity into a Domain ThreatHistory model.
     */
    private fun ThreatHistoryEntity.toDomain(): ThreatHistory {

        return ThreatHistory(
            id = id,
            threatId = threatId,
            category = category,
            severity = severity,
            status = status,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            confidenceScore = confidenceScore
        )
    }

    /**
     * Converts Data/infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapThreatHistoryException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network communication failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX threat-history service.",
                    cause = exception
                )
            }

            /**
             * HTTP errors returned by the backend.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The threat-history request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access threat history."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested threat-history resource was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Threat-history synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Threat-history request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX threat-history service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Threat-history request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Already translated application exceptions.
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
                    message = "An unexpected threat-history repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Standard SentriX threat-resolution status.
         */
        private const val THREAT_STATUS_RESOLVED = "RESOLVED"
    }
}
