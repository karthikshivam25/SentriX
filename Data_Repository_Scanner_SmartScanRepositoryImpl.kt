package com.sentrix.data.repository.scanner

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.entities.ScanHistoryEntity
import com.sentrix.data.remote.api.ScanApiService
import com.sentrix.data.remote.dto.SmartScanRequestDto
import com.sentrix.data.remote.dto.SmartScanResponseDto
import com.sentrix.domain.models.ScanResult
import com.sentrix.domain.repository.SmartScanRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Smart Scan Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.scanner
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of SmartScanRepository.
 *
 * Smart Scan is intended to provide an adaptive security scan
 * that focuses on the areas of the device most likely to
 * contain security risks.
 *
 * Compared with Quick Scan, Smart Scan may consider:
 *
 * - Recent application installations.
 * - Recently downloaded files.
 * - Application permissions.
 * - Recent threat detections.
 * - Behavioral indicators.
 * - Network activity.
 * - Threat intelligence.
 * - Previous scan history.
 * - Device security state.
 * - Risk score.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide what is malicious.
 *
 * Smart-scan decision logic belongs to:
 *
 * - SmartScanEngine
 * - ScanOptimizationService
 * - ThreatAnalysisService
 * - RiskScoringService
 * - MalwareAnalysisService
 * - PermissionAnalysisService
 * - ThreatPredictionService
 *
 * This repository is responsible for:
 *
 * - Remote Smart Scan communication.
 * - Local scan-result persistence.
 * - Retrieving Smart Scan history.
 * - Updating scan status.
 * - Synchronization.
 * - DTO <-> Domain mapping.
 * - Entity <-> Domain mapping.
 * - Exception translation.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *    │
 *    ▼
 * SmartScanRepository
 *    │
 *    ▼
 * SmartScanRepositoryImpl
 *    │
 *    ├──────────────► ScanApiService
 *    │                     │
 *    │                     ▼
 *    │              SmartScanResponseDto
 *    │
 *    └──────────────► ScanHistoryDao
 *                          │
 *                          ▼
 *                    ScanHistoryEntity
 */
@Singleton
class SmartScanRepositoryImpl @Inject constructor(
    private val scanApiService: ScanApiService,
    private val scanHistoryDao: ScanHistoryDao
) : SmartScanRepository {

    /**
     * Starts a new Smart Scan.
     *
     * The Smart Scan configuration determines which security
     * areas should be considered by the SentriX scanning engine.
     */
    override suspend fun startSmartScan(
        includeApplications: Boolean,
        includeDownloads: Boolean,
        includePermissions: Boolean,
        includeNetworkActivity: Boolean,
        includeThreatHistory: Boolean,
        includeBehaviorAnalysis: Boolean
    ): Result<ScanResult> {

        return try {

            /**
             * Construct the remote request.
             *
             * Request DTOs remain inside the Data layer.
             */
            val request = SmartScanRequestDto(
                includeApplications = includeApplications,
                includeDownloads = includeDownloads,
                includePermissions = includePermissions,
                includeNetworkActivity = includeNetworkActivity,
                includeThreatHistory = includeThreatHistory,
                includeBehaviorAnalysis = includeBehaviorAnalysis
            )

            /**
             * Start Smart Scan on the remote service.
             */
            val response =
                scanApiService.startSmartScan(request)

            /**
             * Convert remote response into a Domain model.
             */
            val result =
                response.toDomain()

            /**
             * Persist scan result locally.
             */
            cacheScanResult(response)

            Result.success(result)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves a Smart Scan by its unique identifier.
     *
     * Local cache is checked first.
     */
    override suspend fun getSmartScanResult(
        scanId: String
    ): Result<ScanResult?> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan ID cannot be blank."
                    )
                )
            }

            /**
             * Check local scan history first.
             */
            val cached =
                scanHistoryDao.getScanById(scanId)

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * Retrieve the latest result from the backend.
             */
            val response =
                scanApiService.getSmartScanResult(scanId)

            /**
             * Cache the result locally.
             */
            cacheScanResult(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves the most recent Smart Scan.
     */
    override suspend fun getLatestSmartScan(): Result<ScanResult?> {

        return try {

            val entity =
                scanHistoryDao.getLatestSmartScan()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves Smart Scan history.
     *
     * This operation is local-first and therefore works
     * without an active internet connection.
     */
    override suspend fun getSmartScanHistory(
        limit: Int
    ): Result<List<ScanResult>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan history limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanHistoryDao.getRecentSmartScans(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves Smart Scans between two timestamps.
     *
     * Both timestamps are expected to be epoch milliseconds.
     */
    override suspend fun getSmartScansBetween(
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
                scanHistoryDao.getSmartScansBetween(
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
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves Smart Scans by status.
     *
     * Supported examples:
     *
     * QUEUED
     * RUNNING
     * COMPLETED
     * FAILED
     * CANCELLED
     */
    override suspend fun getSmartScansByStatus(
        status: String
    ): Result<List<ScanResult>> {

        return try {

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan status cannot be blank."
                    )
                )
            }

            val entities =
                scanHistoryDao.getSmartScansByStatus(status)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Retrieves Smart Scans that discovered one or more
     * security threats.
     */
    override suspend fun getThreateningSmartScans(
        limit: Int
    ): Result<List<ScanResult>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanHistoryDao.getThreateningSmartScans(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Saves a Smart Scan result generated locally.
     *
     * This allows SmartScanEngine to operate offline and
     * persist its findings through the repository abstraction.
     */
    override suspend fun saveSmartScanResult(
        result: ScanResult
    ): Result<Unit> {

        return try {

            scanHistoryDao.insertOrUpdate(
                result.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Saves multiple Smart Scan results.
     */
    override suspend fun saveSmartScanResults(
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
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Refreshes the status of an asynchronous Smart Scan.
     *
     * This is useful when the backend performs the analysis
     * asynchronously.
     */
    override suspend fun refreshSmartScan(
        scanId: String
    ): Result<ScanResult> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan ID cannot be blank."
                    )
                )
            }

            val response =
                scanApiService.getSmartScanResult(scanId)

            /**
             * Replace the local representation with the
             * latest server state.
             */
            cacheScanResult(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Cancels an active Smart Scan.
     */
    override suspend fun cancelSmartScan(
        scanId: String
    ): Result<Unit> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan ID cannot be blank."
                    )
                )
            }

            /**
             * Request remote cancellation.
             */
            scanApiService.cancelSmartScan(scanId)

            /**
             * Update local state.
             */
            scanHistoryDao.updateScanStatus(
                scanId = scanId,
                status = SCAN_STATUS_CANCELLED
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Updates the local Smart Scan status.
     *
     * Useful for locally executed scans where the scanning
     * engine controls the state.
     */
    override suspend fun updateSmartScanStatus(
        scanId: String,
        status: String
    ): Result<Unit> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan ID cannot be blank."
                    )
                )
            }

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan status cannot be blank."
                    )
                )
            }

            scanHistoryDao.updateScanStatus(
                scanId = scanId,
                status = status
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Deletes one Smart Scan history record.
     *
     * This affects only local history.
     */
    override suspend fun deleteSmartScan(
        scanId: String
    ): Result<Unit> {

        return try {

            if (scanId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Smart Scan ID cannot be blank."
                    )
                )
            }

            scanHistoryDao.deleteScanById(scanId)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Removes Smart Scan history older than the supplied
     * timestamp.
     *
     * Retention rules should be controlled by SentriX
     * configuration.
     */
    override suspend fun deleteHistoryOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            scanHistoryDao.deleteSmartScansOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Clears locally stored Smart Scan history.
     */
    override suspend fun clearSmartScanHistory(): Result<Unit> {

        return try {

            scanHistoryDao.deleteAllSmartScans()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Returns the total number of Smart Scan records.
     */
    override suspend fun getSmartScanCount(): Result<Int> {

        return try {

            Result.success(
                scanHistoryDao.getSmartScanCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Synchronizes Smart Scan results with the remote
     * SentriX backend.
     */
    override suspend fun synchronizeSmartScans(): Result<Unit> {

        return try {

            val response =
                scanApiService.getSmartScanHistory()

            if (response.isNotEmpty()) {

                scanHistoryDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSmartScanException(exception)
            )
        }
    }

    /**
     * Converts remote SmartScanResponseDto into Domain
     * ScanResult.
     */
    private fun SmartScanResponseDto.toDomain(): ScanResult {

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
     * Converts remote SmartScanResponseDto into the local
     * Room ScanHistoryEntity.
     */
    private fun SmartScanResponseDto.toEntity(): ScanHistoryEntity {

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
     * Converts Domain ScanResult into a Room entity.
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
     * Converts Room entity into the Domain ScanResult.
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
     * Stores one remote Smart Scan response locally.
     */
    private suspend fun cacheScanResult(
        response: SmartScanResponseDto
    ) {

        scanHistoryDao.insertOrUpdate(
            response.toEntity()
        )
    }

    /**
     * Maps infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapSmartScanException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity errors.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX Smart Scan service.",
                    cause = exception
                )
            }

            /**
             * Backend HTTP errors.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The Smart Scan request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to perform a Smart Scan."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested Smart Scan was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "A Smart Scan operation conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Smart Scan request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX Smart Scan service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Smart Scan request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve previously mapped exceptions.
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
                    message = "An unexpected Smart Scan repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Standard SentriX cancellation status.
         */
        private const val SCAN_STATUS_CANCELLED = "CANCELLED"
    }
}
