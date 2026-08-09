package com.sentrix.data.repository.scanner

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ScanOptimizationDao
import com.sentrix.data.local.entities.ScanOptimizationEntity
import com.sentrix.data.remote.api.ScanApiService
import com.sentrix.data.remote.dto.ScanOptimizationRequestDto
import com.sentrix.data.remote.dto.ScanOptimizationResponseDto
import com.sentrix.domain.models.ScanOptimization
import com.sentrix.domain.repository.ScanOptimizationRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Scan Optimization Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.scanner
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * ScanOptimizationRepository.
 *
 * This repository manages information used by the SentriX
 * scanning subsystem to optimize security scans.
 *
 * Optimization information may include:
 *
 * - Recommended scan mode.
 * - Scan priority.
 * - Recommended scan targets.
 * - Previous scan information.
 * - Threat-risk priority.
 * - Resource constraints.
 * - Battery considerations.
 * - Network conditions.
 * - Scan frequency.
 * - Estimated scan duration.
 * - Optimization confidence.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT make security decisions.
 *
 * The following components remain responsible for actual
 * optimization logic:
 *
 * - ScanOptimizationService
 * - ScanOptimizationRules
 * - ScanOptimizationEngine
 * - RiskScoringService
 *
 * This class only provides persistence and remote-data
 * access.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *    │
 *    ▼
 * ScanOptimizationRepository
 *    │
 *    ▼
 * ScanOptimizationRepositoryImpl
 *    │
 *    ├──────────────► ScanApiService
 *    │                     │
 *    │                     ▼
 *    │            ScanOptimizationResponseDto
 *    │
 *    └──────────────► ScanOptimizationDao
 *                          │
 *                          ▼
 *                  ScanOptimizationEntity
 */
@Singleton
class ScanOptimizationRepositoryImpl @Inject constructor(
    private val scanApiService: ScanApiService,
    private val scanOptimizationDao: ScanOptimizationDao
) : ScanOptimizationRepository {

    /**
     * Retrieves the current optimization configuration.
     *
     * Local cache is checked first because scan optimization
     * must remain usable when the device is offline.
     */
    override suspend fun getCurrentOptimization():
        Result<ScanOptimization?> {

        return try {

            val entity =
                scanOptimizationDao.getCurrentOptimization()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Requests an optimized scan configuration from the
     * SentriX backend.
     *
     * The supplied information represents the current device
     * and security context.
     */
    override suspend fun requestOptimization(
        batteryLevel: Int,
        isCharging: Boolean,
        isMeteredNetwork: Boolean,
        availableStorageMb: Long,
        recentThreatCount: Int,
        lastScanTime: Long?,
        riskScore: Double
    ): Result<ScanOptimization> {

        return try {

            /**
             * Validate basic input before constructing the
             * network request.
             */
            if (batteryLevel !in 0..100) {
                return Result.failure(
                    IllegalArgumentException(
                        "Battery level must be between 0 and 100."
                    )
                )
            }

            if (availableStorageMb < 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Available storage cannot be negative."
                    )
                )
            }

            if (recentThreatCount < 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Recent threat count cannot be negative."
                    )
                )
            }

            if (riskScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Risk score must be between 0 and 100."
                    )
                )
            }

            /**
             * Build the Data-layer request DTO.
             */
            val request = ScanOptimizationRequestDto(
                batteryLevel = batteryLevel,
                isCharging = isCharging,
                isMeteredNetwork = isMeteredNetwork,
                availableStorageMb = availableStorageMb,
                recentThreatCount = recentThreatCount,
                lastScanTime = lastScanTime,
                riskScore = riskScore
            )

            /**
             * Request optimization information from the
             * backend.
             */
            val response =
                scanApiService.getScanOptimization(request)

            /**
             * Convert remote response to Domain model.
             */
            val optimization =
                response.toDomain()

            /**
             * Persist the latest optimization.
             */
            cacheOptimization(response)

            Result.success(optimization)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves optimization information by ID.
     */
    override suspend fun getOptimizationById(
        optimizationId: String
    ): Result<ScanOptimization?> {

        return try {

            if (optimizationId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Optimization ID cannot be blank."
                    )
                )
            }

            val cached =
                scanOptimizationDao.getById(
                    optimizationId
                )

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * Retrieve the optimization from the backend if it
             * is not available locally.
             */
            val response =
                scanApiService.getScanOptimizationById(
                    optimizationId
                )

            cacheOptimization(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves recent optimization decisions.
     *
     * This is useful for determining whether the scanning
     * engine has been repeatedly recommending the same scan
     * strategy.
     */
    override suspend fun getOptimizationHistory(
        limit: Int
    ): Result<List<ScanOptimization>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Optimization history limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanOptimizationDao.getRecentOptimizations(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves optimization decisions generated within a
     * specified time range.
     */
    override suspend fun getOptimizationsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<ScanOptimization>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                scanOptimizationDao.getOptimizationsBetween(
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
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves optimization configurations by recommended
     * scan mode.
     *
     * Examples:
     *
     * QUICK
     * SMART
     * DEEP
     * TARGETED
     * BACKGROUND
     */
    override suspend fun getByScanMode(
        scanMode: String
    ): Result<List<ScanOptimization>> {

        return try {

            if (scanMode.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan mode cannot be blank."
                    )
                )
            }

            val entities =
                scanOptimizationDao.getByScanMode(
                    scanMode
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves high-priority optimization decisions.
     *
     * Priority interpretation belongs to the Domain layer.
     */
    override suspend fun getHighPriorityOptimizations(
        minimumPriority: Int
    ): Result<List<ScanOptimization>> {

        return try {

            if (minimumPriority < 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Priority cannot be negative."
                    )
                )
            }

            val entities =
                scanOptimizationDao.getAbovePriority(
                    minimumPriority
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Retrieves optimization decisions above a specific
     * confidence threshold.
     */
    override suspend fun getHighConfidenceOptimizations(
        minimumConfidence: Double
    ): Result<List<ScanOptimization>> {

        return try {

            if (minimumConfidence !in 0.0..1.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Confidence must be between 0.0 and 1.0."
                    )
                )
            }

            val entities =
                scanOptimizationDao.getAboveConfidence(
                    minimumConfidence
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Saves an optimization result generated locally by
     * ScanOptimizationService/Engine.
     */
    override suspend fun saveOptimization(
        optimization: ScanOptimization
    ): Result<Unit> {

        return try {

            scanOptimizationDao.insertOrUpdate(
                optimization.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Saves multiple optimization results.
     */
    override suspend fun saveOptimizations(
        optimizations: List<ScanOptimization>
    ): Result<Unit> {

        return try {

            if (optimizations.isEmpty()) {
                return Result.success(Unit)
            }

            scanOptimizationDao.insertOrUpdateAll(
                optimizations.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Refreshes optimization information from the backend.
     */
    override suspend fun refreshOptimization():
        Result<ScanOptimization> {

        return try {

            val response =
                scanApiService.getCurrentScanOptimization()

            /**
             * Update local cache with the latest server result.
             */
            cacheOptimization(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Marks an optimization result as applied.
     *
     * This is useful for analytics and future optimization
     * feedback.
     */
    override suspend fun markOptimizationApplied(
        optimizationId: String
    ): Result<Unit> {

        return try {

            if (optimizationId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Optimization ID cannot be blank."
                    )
                )
            }

            scanOptimizationDao.markAsApplied(
                optimizationId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Records whether an optimization recommendation was
     * successful.
     *
     * This allows the Domain optimization engine to learn
     * from previous scan decisions.
     */
    override suspend fun recordOptimizationOutcome(
        optimizationId: String,
        successful: Boolean
    ): Result<Unit> {

        return try {

            if (optimizationId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Optimization ID cannot be blank."
                    )
                )
            }

            scanOptimizationDao.updateOutcome(
                optimizationId = optimizationId,
                successful = successful
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Deletes optimization records older than the specified
     * timestamp.
     *
     * Retention policy should be controlled by SentriX
     * configuration.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            scanOptimizationDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Deletes one optimization record.
     */
    override suspend fun deleteOptimization(
        optimizationId: String
    ): Result<Unit> {

        return try {

            if (optimizationId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Optimization ID cannot be blank."
                    )
                )
            }

            scanOptimizationDao.deleteById(
                optimizationId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Clears the local optimization cache.
     */
    override suspend fun clearOptimizationCache():
        Result<Unit> {

        return try {

            scanOptimizationDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored optimization
     * records.
     */
    override suspend fun getOptimizationCount():
        Result<Int> {

        return try {

            Result.success(
                scanOptimizationDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Synchronizes optimization records with the backend.
     */
    override suspend fun synchronizeOptimizations():
        Result<Unit> {

        return try {

            val response =
                scanApiService.getScanOptimizationHistory()

            if (response.isNotEmpty()) {

                scanOptimizationDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapOptimizationException(exception)
            )
        }
    }

    /**
     * Converts remote DTO into Domain model.
     */
    private fun ScanOptimizationResponseDto.toDomain():
        ScanOptimization {

        return ScanOptimization(
            id = id,
            scanMode = scanMode,
            priority = priority,
            recommendedTargets = recommendedTargets,
            estimatedDurationMs = estimatedDurationMs,
            confidenceScore = confidenceScore,
            batteryAware = batteryAware,
            networkAware = networkAware,
            reason = reason,
            createdAt = createdAt,
            expiresAt = expiresAt,
            applied = applied,
            successful = successful
        )
    }

    /**
     * Converts remote DTO into Room entity.
     */
    private fun ScanOptimizationResponseDto.toEntity():
        ScanOptimizationEntity {

        return ScanOptimizationEntity(
            id = id,
            scanMode = scanMode,
            priority = priority,
            recommendedTargets = recommendedTargets,
            estimatedDurationMs = estimatedDurationMs,
            confidenceScore = confidenceScore,
            batteryAware = batteryAware,
            networkAware = networkAware,
            reason = reason,
            createdAt = createdAt,
            expiresAt = expiresAt,
            applied = applied,
            successful = successful
        )
    }

    /**
     * Converts Domain model into Room entity.
     */
    private fun ScanOptimization.toEntity():
        ScanOptimizationEntity {

        return ScanOptimizationEntity(
            id = id,
            scanMode = scanMode,
            priority = priority,
            recommendedTargets = recommendedTargets,
            estimatedDurationMs = estimatedDurationMs,
            confidenceScore = confidenceScore,
            batteryAware = batteryAware,
            networkAware = networkAware,
            reason = reason,
            createdAt = createdAt,
            expiresAt = expiresAt,
            applied = applied,
            successful = successful
        )
    }

    /**
     * Converts Room entity into Domain model.
     */
    private fun ScanOptimizationEntity.toDomain():
        ScanOptimization {

        return ScanOptimization(
            id = id,
            scanMode = scanMode,
            priority = priority,
            recommendedTargets = recommendedTargets,
            estimatedDurationMs = estimatedDurationMs,
            confidenceScore = confidenceScore,
            batteryAware = batteryAware,
            networkAware = networkAware,
            reason = reason,
            createdAt = createdAt,
            expiresAt = expiresAt,
            applied = applied,
            successful = successful
        )
    }

    /**
     * Caches a remote optimization response.
     */
    private suspend fun cacheOptimization(
        optimization: ScanOptimizationResponseDto
    ) {

        scanOptimizationDao.insertOrUpdate(
            optimization.toEntity()
        )
    }

    /**
     * Maps infrastructure exceptions to SentriX application
     * exceptions.
     */
    private fun mapOptimizationException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Connectivity failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX scan-optimization service.",
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
                            "The scan-optimization request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access scan optimization."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested scan optimization was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Scan optimization synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Scan optimization request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX scan-optimization service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Scan optimization request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve previously translated exceptions.
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
                    message = "An unexpected scan-optimization repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
