package com.sentrix.data.repository.scanner

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.entities.ScanHistoryEntity
import com.sentrix.data.remote.api.ScanApiService
import com.sentrix.data.remote.dto.QuickScanRequestDto
import com.sentrix.data.remote.dto.QuickScanResponseDto
import com.sentrix.domain.models.ScanResult
import com.sentrix.domain.repository.QuickScanRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Quick Scan Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.scanner
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation for quick security scans.
 *
 * A Quick Scan is intended to perform a fast security
 * assessment without executing the complete deep/device scan.
 *
 * Typical Quick Scan targets:
 *
 * - Recently installed applications.
 * - Recently downloaded files.
 * - High-risk APKs.
 * - Suspicious URLs.
 * - Recent security events.
 * - Dangerous permissions.
 * - Recent threat indicators.
 * - Recent network activity.
 *
 * This repository is responsible for:
 *
 * - Starting remote quick-scan operations.
 * - Retrieving quick-scan results.
 * - Persisting scan results locally.
 * - Retrieving previous quick scans.
 * - Updating scan status.
 * - Cancelling an active remote scan.
 * - Synchronizing scan results.
 * - Mapping DTOs to Domain models.
 * - Mapping Domain models to local entities.
 * - Mapping local entities back to Domain models.
 * - Translating infrastructure exceptions.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * The repository does NOT perform the actual scan.
 *
 * Scanning logic belongs to:
 *
 * - QuickScanEngine
 * - ScanService
 * - MalwareAnalysisService
 * - ThreatAnalysisService
 * - PermissionAnalysisService
 * - RiskScoringService
 *
 * The repository is responsible for DATA access only.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *    │
 *    ▼
 * QuickScanRepository
 *    │
 *    ▼
 * QuickScanRepositoryImpl
 *    │
 *    ├──────────────► ScanApiService
 *    │                     │
 *    │                     ▼
 *    │              QuickScanResponseDto
 *    │
 *    └──────────────► ScanHistoryDao
 *                          │
 *                          ▼
 *                    ScanHistoryEntity
 */
@Singleton
class QuickScanRepositoryImpl @Inject constructor(
    private val scanApiService: ScanApiService,
    private val scanHistoryDao: ScanHistoryDao
) : QuickScanRepository {

    /**
     * Starts a new Quick Scan.
     *
     * The repository sends the scan configuration to the
     * backend and persists the resulting scan record.
     *
     * The actual security analysis is performed by the
     * appropriate SentriX scanning engine.
     */
    override suspend fun startQuickScan(
        scanType: String,
        includeApplications: Boolean,
        includeDownloads: Boolean,
        includeNetworkActivity: Boolean,
        includePermissions: Boolean
    ): Result<ScanResult> {

        return try {

            /**
             * Build the Data-layer request DTO.
             *
             * Domain models should not be sent directly to
             * Retrofit services.
             */
            val request = QuickScanRequestDto(
                scanType = scanType,
                includeApplications = includeApplications,
                includeDownloads = includeDownloads,
                includeNetworkActivity = includeNetworkActivity,
                includePermissions = includePermissions
            )

            /**
             * Start the remote quick scan.
             */
            val response =
                scanApiService.startQuickScan(request)

            /**
             * Convert remote response into Domain model.
             */
            val result =
                response.toDomain()

            /**
             * Persist scan history locally.
             */
            cacheScanResult(response)

            Result.success(result)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves a quick-scan result using its unique ID.
     *
     * Local cache is checked first.
     */
    override suspend fun getQuickScanResult(
        scanId: String
    ): Result<ScanResult?> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan ID cannot be blank."
                    )
                )
            }

            /**
             * Check local scan history.
             */
            val cached =
                scanHistoryDao.getScanById(scanId)

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * Request the result from the backend if it is
             * not available locally.
             */
            val response =
                scanApiService.getQuickScanResult(scanId)

            /**
             * Cache the remote result.
             */
            cacheScanResult(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves the latest Quick Scan result.
     */
    override suspend fun getLatestQuickScan(): Result<ScanResult?> {

        return try {

            val entity =
                scanHistoryDao.getLatestQuickScan()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves recent Quick Scan history.
     *
     * This operation is local-first and does not require
     * network connectivity.
     */
    override suspend fun getQuickScanHistory(
        limit: Int
    ): Result<List<ScanResult>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan history limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanHistoryDao.getRecentQuickScans(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves Quick Scan results between two timestamps.
     *
     * Timestamps are expected to be epoch milliseconds.
     */
    override suspend fun getQuickScansBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<ScanResult>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                scanHistoryDao.getScansBetween(
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
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves Quick Scans filtered by scan status.
     *
     * Example statuses:
     *
     * QUEUED
     * RUNNING
     * COMPLETED
     * FAILED
     * CANCELLED
     */
    override suspend fun getQuickScansByStatus(
        status: String
    ): Result<List<ScanResult>> {

        return try {

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan status cannot be blank."
                    )
                )
            }

            val entities =
                scanHistoryDao.getScansByStatus(status)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Retrieves Quick Scan results that detected threats.
     */
    override suspend fun getThreateningQuickScans(
        limit: Int
    ): Result<List<ScanResult>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanHistoryDao.getThreateningScans(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Saves a locally generated Quick Scan result.
     *
     * This is useful when the QuickScanEngine performs analysis
     * entirely on the device.
     */
    override suspend fun saveQuickScanResult(
        result: ScanResult
    ): Result<Unit> {

        return try {

            scanHistoryDao.insertOrUpdate(
                result.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Saves multiple Quick Scan results.
     */
    override suspend fun saveQuickScanResults(
        results: List<ScanResult>
    ): Result<Unit> {

        return try {

            if (results.isEmpty()) {
                return Result.success(Unit)
            }

            scanHistoryDao.insertOrUpdateAll(
                results.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Refreshes the status/result of an existing Quick Scan.
     *
     * Useful for scans that execute asynchronously on the
     * backend.
     */
    override suspend fun refreshQuickScan(
        scanId: String
    ): Result<ScanResult> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan ID cannot be blank."
                    )
                )
            }

            val response =
                scanApiService.getQuickScanResult(scanId)

            /**
             * Replace the locally cached scan with the latest
             * server representation.
             */
            cacheScanResult(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Cancels an active remote Quick Scan.
     *
     * Local status is updated after successful remote
     * cancellation.
     */
    override suspend fun cancelQuickScan(
        scanId: String
    ): Result<Unit> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan ID cannot be blank."
                    )
                )
            }

            /**
             * Request remote cancellation.
             */
            scanApiService.cancelQuickScan(scanId)

            /**
             * Update local scan state.
             */
            scanHistoryDao.updateScanStatus(
                scanId = scanId,
                status = SCAN_STATUS_CANCELLED
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Deletes one Quick Scan history entry.
     *
     * This only affects local history.
     */
    override suspend fun deleteQuickScan(
        scanId: String
    ): Result<Unit> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan ID cannot be blank."
                    )
                )
            }

            scanHistoryDao.deleteScanById(scanId)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Deletes scan history older than a specified timestamp.
     *
     * Retention policy should be defined by SentriX security
     * and privacy configuration.
     */
    override suspend fun deleteHistoryOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            scanHistoryDao.deleteScansOlderThan(timestamp)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Clears all locally stored Quick Scan history.
     */
    override suspend fun clearQuickScanHistory(): Result<Unit> {

        return try {

            scanHistoryDao.deleteAllQuickScans()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Returns the total number of Quick Scan records.
     */
    override suspend fun getQuickScanCount(): Result<Int> {

        return try {

            Result.success(
                scanHistoryDao.getQuickScanCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapQuickScanException(exception)
            )
        }
    }

    /**
     * Converts remote QuickScanResponseDto into the
     * SentriX Domain ScanResult model.
     */
    private fun QuickScanResponseDto.toDomain(): ScanResult {

        return ScanResult(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts remote response into a local Room entity.
     */
    private fun QuickScanResponseDto.toEntity(): ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts Domain ScanResult into Room entity.
     */
    private fun ScanResult.toEntity(): ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts Room ScanHistoryEntity into Domain ScanResult.
     */
    private fun ScanHistoryEntity.toDomain(): ScanResult {

        return ScanResult(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Caches a remote Quick Scan response.
     */
    private suspend fun cacheScanResult(
        response: QuickScanResponseDto
    ) {

        scanHistoryDao.insertOrUpdate(
            response.toEntity()
        )
    }

    /**
     * Maps infrastructure-level exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapQuickScanException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Connectivity-related errors.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX scan service.",
                    cause = exception
                )
            }

            /**
             * HTTP/backend errors.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The Quick Scan request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to perform a Quick Scan."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested Quick Scan was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "A Quick Scan operation conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Quick Scan request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX scan service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Quick Scan request failed with HTTP ${exception.code()}."
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
             * Unexpected database/infrastructure error.
             */
            else -> {
                UnknownException(
                    message = "An unexpected Quick Scan repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Standard local scan status used when a remote scan
         * has been successfully cancelled.
         */
        private const val SCAN_STATUS_CANCELLED = "CANCELLED"
    }
}
