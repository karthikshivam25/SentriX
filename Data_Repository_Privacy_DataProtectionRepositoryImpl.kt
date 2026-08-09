package com.sentrix.data.repository.privacy

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.DataProtectionDao
import com.sentrix.data.local.entities.DataProtectionEntity
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.dto.DataProtectionDto
import com.sentrix.domain.models.DataProtection
import com.sentrix.domain.repository.DataProtectionRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Data Protection Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.privacy
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * DataProtectionRepository.
 *
 * This repository manages DATA related to SentriX's
 * Data Protection / Data Leakage Prevention subsystem.
 *
 * Supported information includes:
 *
 * - Data protection records.
 * - Sensitive data detections.
 * - Data leakage events.
 * - Application/package activity.
 * - Data transfer observations.
 * - Blocked transfers.
 * - Allowed transfers.
 * - Sensitive-data categories.
 * - Protection rules.
 * - Protection state.
 * - Data protection statistics.
 * - Historical protection events.
 * - Remote synchronization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide whether data is sensitive,
 * malicious, or unsafe.
 *
 * Those decisions belong to the Domain layer.
 *
 * Examples:
 *
 * - DataProtectionRules.
 * - DataLeakagePreventionRules.
 * - SensitiveDataAnalysisService.
 * - PrivacyRiskScoringService.
 * - DataProtectionService.
 *
 * This repository is responsible only for:
 *
 * - Reading data.
 * - Writing data.
 * - Updating data.
 * - Querying history.
 * - Synchronizing data.
 * - DTO <-> Domain conversion.
 * - Domain <-> Entity conversion.
 * - Exception translation.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * DataProtectionRepository
 *    │
 *    ▼
 * DataProtectionRepositoryImpl
 *    │
 *    ├──────────────► DataProtectionDao
 *    │                     │
 *    │                     ▼
 *    │              DataProtectionEntity
 *    │
 *    └──────────────► PrivacyApiService
 *                          │
 *                          ▼
 *                    DataProtectionDto
 */
@Singleton
class DataProtectionRepositoryImpl @Inject constructor(
    private val dataProtectionDao: DataProtectionDao,
    private val privacyApiService: PrivacyApiService
) : DataProtectionRepository {

    /**
     * Retrieves a data-protection record by ID.
     */
    override suspend fun getProtectionById(
        protectionId: String
    ): Result<DataProtection?> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            val entity =
                dataProtectionDao.getById(
                    protectionId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the latest data-protection record.
     */
    override suspend fun getLatestProtection():
        Result<DataProtection?> {

        return try {

            val entity =
                dataProtectionDao.getLatestProtection()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored data-protection records.
     */
    override suspend fun getAllProtectionRecords():
        Result<List<DataProtection>> {

        return try {

            val entities =
                dataProtectionDao.getAllProtectionRecords()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves recent data-protection records.
     */
    override suspend fun getRecentProtectionRecords(
        limit: Int
    ): Result<List<DataProtection>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data protection record limit must be greater than zero."
                    )
                )
            }

            val entities =
                dataProtectionDao.getRecentProtectionRecords(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves records between two timestamps.
     */
    override suspend fun getProtectionRecordsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<DataProtection>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                dataProtectionDao.getProtectionRecordsBetween(
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
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves data-protection records associated with
     * an application.
     */
    override suspend fun getProtectionByPackage(
        packageName: String
    ): Result<List<DataProtection>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                dataProtectionDao.getByPackageName(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves records by sensitive-data category.
     *
     * Examples:
     *
     * - PERSONAL_DATA
     * - CREDENTIAL
     * - FINANCIAL
     * - CONTACT
     * - LOCATION
     * - HEALTH
     * - IDENTIFIER
     */
    override suspend fun getProtectionByDataCategory(
        category: String
    ): Result<List<DataProtection>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            val entities =
                dataProtectionDao.getByDataCategory(
                    category
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves records by event type.
     *
     * Examples:
     *
     * - DATA_DETECTED
     * - DATA_TRANSFER
     * - DATA_LEAK
     * - DATA_BLOCKED
     * - DATA_EXPORTED
     */
    override suspend fun getProtectionByEventType(
        eventType: String
    ): Result<List<DataProtection>> {

        return try {

            if (eventType.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data protection event type cannot be blank."
                    )
                )
            }

            val entities =
                dataProtectionDao.getByEventType(
                    eventType
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves records by severity.
     */
    override suspend fun getProtectionBySeverity(
        severity: String
    ): Result<List<DataProtection>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data protection severity cannot be blank."
                    )
                )
            }

            val entities =
                dataProtectionDao.getBySeverity(
                    severity
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves unresolved data-protection events.
     */
    override suspend fun getUnresolvedEvents():
        Result<List<DataProtection>> {

        return try {

            val entities =
                dataProtectionDao.getUnresolvedEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves critical unresolved data-protection events.
     */
    override suspend fun getCriticalUnresolvedEvents():
        Result<List<DataProtection>> {

        return try {

            val entities =
                dataProtectionDao.getCriticalUnresolvedEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Saves a data-protection record.
     */
    override suspend fun saveProtection(
        protection: DataProtection
    ): Result<Unit> {

        return try {

            dataProtectionDao.insertOrUpdate(
                protection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Saves multiple data-protection records.
     */
    override suspend fun saveProtectionBatch(
        protections: List<DataProtection>
    ): Result<Unit> {

        return try {

            if (protections.isEmpty()) {
                return Result.success(Unit)
            }

            dataProtectionDao.insertOrUpdateAll(
                protections.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Creates a new protection record.
     */
    override suspend fun createProtection(
        protection: DataProtection
    ): Result<Unit> {

        return try {

            dataProtectionDao.insert(
                protection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Updates an existing protection record.
     */
    override suspend fun updateProtection(
        protection: DataProtection
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protection.protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.update(
                protection.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Marks a data-protection event as reviewed.
     */
    override suspend fun markAsReviewed(
        protectionId: String
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.markReviewed(
                protectionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Marks a data-protection event as resolved.
     */
    override suspend fun markAsResolved(
        protectionId: String,
        resolvedAt: Long
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.markResolved(
                protectionId = protectionId,
                resolvedAt = resolvedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Marks a data-protection event as unresolved.
     */
    override suspend fun markAsUnresolved(
        protectionId: String
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.markUnresolved(
                protectionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Records a sensitive-data detection.
     *
     * The repository stores the observation.
     * The Domain layer determines its security significance.
     */
    override suspend fun recordSensitiveDataDetection(
        packageName: String,
        dataCategory: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (dataCategory.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            dataProtectionDao.recordDataEvent(
                packageName = packageName,
                eventType = EVENT_DATA_DETECTED,
                dataCategory = dataCategory,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Records a data-transfer observation.
     */
    override suspend fun recordDataTransfer(
        packageName: String,
        dataCategory: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (dataCategory.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            dataProtectionDao.recordDataEvent(
                packageName = packageName,
                eventType = EVENT_DATA_TRANSFER,
                dataCategory = dataCategory,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Records a data-leak event.
     */
    override suspend fun recordDataLeak(
        packageName: String,
        dataCategory: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (dataCategory.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            dataProtectionDao.recordDataEvent(
                packageName = packageName,
                eventType = EVENT_DATA_LEAK,
                dataCategory = dataCategory,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Records a blocked data transfer.
     */
    override suspend fun recordBlockedTransfer(
        packageName: String,
        dataCategory: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (dataCategory.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            dataProtectionDao.recordDataEvent(
                packageName = packageName,
                eventType = EVENT_DATA_BLOCKED,
                dataCategory = dataCategory,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Records an exported-data event.
     */
    override suspend fun recordDataExport(
        packageName: String,
        dataCategory: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (dataCategory.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            dataProtectionDao.recordDataEvent(
                packageName = packageName,
                eventType = EVENT_DATA_EXPORTED,
                dataCategory = dataCategory,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Updates the data-protection state.
     *
     * This persists state only. It does not perform enforcement.
     */
    override suspend fun updateProtectionState(
        protectionId: String,
        enabled: Boolean
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.updateProtectionState(
                protectionId = protectionId,
                enabled = enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Updates the risk score attached to a protection record.
     *
     * The risk score itself must be calculated by Domain logic.
     */
    override suspend fun updateRiskScore(
        protectionId: String,
        riskScore: Double
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            if (riskScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data protection risk score must be between 0 and 100."
                    )
                )
            }

            dataProtectionDao.updateRiskScore(
                protectionId = protectionId,
                riskScore = riskScore
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Updates protection severity.
     */
    override suspend fun updateSeverity(
        protectionId: String,
        severity: String
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data protection severity cannot be blank."
                    )
                )
            }

            dataProtectionDao.updateSeverity(
                protectionId = protectionId,
                severity = severity
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of protection records.
     */
    override suspend fun getProtectionRecordCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getProtectionRecordCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of unresolved protection events.
     */
    override suspend fun getUnresolvedEventCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getUnresolvedEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of critical protection events.
     */
    override suspend fun getCriticalEventCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getCriticalEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of detected sensitive-data events.
     */
    override suspend fun getSensitiveDataDetectionCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getEventCountByType(
                    EVENT_DATA_DETECTED
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of data transfers.
     */
    override suspend fun getDataTransferCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getEventCountByType(
                    EVENT_DATA_TRANSFER
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of detected data leaks.
     */
    override suspend fun getDataLeakCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getEventCountByType(
                    EVENT_DATA_LEAK
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of blocked transfers.
     */
    override suspend fun getBlockedTransferCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getEventCountByType(
                    EVENT_DATA_BLOCKED
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the number of data-export events.
     */
    override suspend fun getDataExportCount():
        Result<Long> {

        return try {

            Result.success(
                dataProtectionDao.getEventCountByType(
                    EVENT_DATA_EXPORTED
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves statistics for an application.
     */
    override suspend fun getStatisticsByPackage(
        packageName: String
    ): Result<List<DataProtection>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                dataProtectionDao.getStatisticsByPackage(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves statistics for a data category.
     */
    override suspend fun getStatisticsByCategory(
        category: String
    ): Result<List<DataProtection>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            val entities =
                dataProtectionDao.getStatisticsByCategory(
                    category
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the most recent data-protection event
     * associated with an application.
     */
    override suspend fun getLatestEventByPackage(
        packageName: String
    ): Result<DataProtection?> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entity =
                dataProtectionDao.getLatestEventByPackage(
                    packageName
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves the latest event for a data category.
     */
    override suspend fun getLatestEventByCategory(
        category: String
    ): Result<DataProtection?> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Data category cannot be blank."
                    )
                )
            }

            val entity =
                dataProtectionDao.getLatestEventByCategory(
                    category
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Refreshes data-protection information from the backend.
     */
    override suspend fun refreshProtectionData():
        Result<List<DataProtection>> {

        return try {

            val response =
                privacyApiService.getDataProtectionRecords()

            if (response.isNotEmpty()) {

                dataProtectionDao.insertOrUpdateAll(
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
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Retrieves remote data-protection records created or
     * modified since the specified timestamp.
     */
    override suspend fun getProtectionDataSince(
        timestamp: Long
    ): Result<List<DataProtection>> {

        return try {

            val response =
                privacyApiService.getDataProtectionRecordsSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                dataProtectionDao.insertOrUpdateAll(
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
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Synchronizes data-protection information.
     */
    override suspend fun synchronizeProtectionData():
        Result<Unit> {

        return try {

            val response =
                privacyApiService.getDataProtectionRecords()

            if (response.isNotEmpty()) {

                dataProtectionDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Deletes one data-protection record.
     */
    override suspend fun deleteProtection(
        protectionId: String
    ): Result<Unit> {

        return try {

            validateProtectionId(
                protectionId
            )?.let {
                return Result.failure(it)
            }

            dataProtectionDao.deleteById(
                protectionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Deletes records older than the supplied timestamp.
     *
     * Retention policy should be determined by the Domain/
     * application policy layer.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            dataProtectionDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Clears all locally stored data-protection records.
     */
    override suspend fun clearProtectionData():
        Result<Unit> {

        return try {

            dataProtectionDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDataProtectionException(exception)
            )
        }
    }

    /**
     * Converts remote DTO into Domain model.
     *
     * DTO -> Domain
     */
    private fun DataProtectionDto.toDomain():
        DataProtection {

        return DataProtection(
            protectionId = protectionId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            dataCategory = dataCategory,
            dataDescription = dataDescription,
            severity = severity,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            enabled = enabled,
            blocked = blocked,
            riskScore = riskScore
        )
    }

    /**
     * Converts remote DTO into Room entity.
     *
     * DTO -> Entity
     */
    private fun DataProtectionDto.toEntity():
        DataProtectionEntity {

        return DataProtectionEntity(
            protectionId = protectionId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            dataCategory = dataCategory,
            dataDescription = dataDescription,
            severity = severity,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            enabled = enabled,
            blocked = blocked,
            riskScore = riskScore
        )
    }

    /**
     * Converts Domain model into Room entity.
     *
     * Domain -> Entity
     */
    private fun DataProtection.toEntity():
        DataProtectionEntity {

        return DataProtectionEntity(
            protectionId = protectionId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            dataCategory = dataCategory,
            dataDescription = dataDescription,
            severity = severity,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            enabled = enabled,
            blocked = blocked,
            riskScore = riskScore
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun DataProtectionEntity.toDomain():
        DataProtection {

        return DataProtection(
            protectionId = protectionId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            dataCategory = dataCategory,
            dataDescription = dataDescription,
            severity = severity,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            enabled = enabled,
            blocked = blocked,
            riskScore = riskScore
        )
    }

    /**
     * Validates protection record ID.
     */
    private fun validateProtectionId(
        protectionId: String
    ): Exception? {

        return if (protectionId.isBlank()) {
            IllegalArgumentException(
                "Data protection ID cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Validates Android application package name.
     */
    private fun validatePackageName(
        packageName: String
    ): Exception? {

        return if (packageName.isBlank()) {
            IllegalArgumentException(
                "Application package name cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapDataProtectionException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX data protection service.",
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
                            "The data protection request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access data protection information."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested data protection record was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Data protection synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Data protection request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX data protection service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Data protection request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected data protection repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Data-protection event types.
         */
        private const val EVENT_DATA_DETECTED =
            "DATA_DETECTED"

        private const val EVENT_DATA_TRANSFER =
            "DATA_TRANSFER"

        private const val EVENT_DATA_LEAK =
            "DATA_LEAK"

        private const val EVENT_DATA_BLOCKED =
            "DATA_BLOCKED"

        private const val EVENT_DATA_EXPORTED =
            "DATA_EXPORTED"
    }
}
