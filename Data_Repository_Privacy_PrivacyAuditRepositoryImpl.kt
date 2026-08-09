package com.sentrix.data.repository.privacy

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.PrivacyAuditDao
import com.sentrix.data.local.entities.PrivacyAuditEntity
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.dto.PrivacyAuditDto
import com.sentrix.domain.models.PrivacyAudit
import com.sentrix.domain.repository.PrivacyAuditRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Privacy Audit Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.privacy
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of PrivacyAuditRepository.
 *
 * This repository manages individual privacy-audit records and
 * their complete lifecycle.
 *
 * Responsibilities include:
 *
 * - Creating privacy audit records.
 * - Retrieving audit records.
 * - Updating audit records.
 * - Marking audits as reviewed.
 * - Marking audits as resolved.
 * - Querying audits by application.
 * - Querying audits by event type.
 * - Querying audits by severity.
 * - Querying unresolved audits.
 * - Querying critical audits.
 * - Maintaining audit history.
 * - Synchronizing audits with the backend.
 * - Removing expired audit records.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT determine whether a privacy event
 * is dangerous.
 *
 * Risk calculation belongs to Domain components such as:
 *
 * - PrivacyRiskScoringService.
 * - PrivacyAuditRules.
 * - PrivacyProtectionService.
 *
 * This class is strictly responsible for DATA operations.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * PrivacyAuditRepository
 *    │
 *    ▼
 * PrivacyAuditRepositoryImpl
 *    │
 *    ├──────────────► PrivacyAuditDao
 *    │                     │
 *    │                     ▼
 *    │              PrivacyAuditEntity
 *    │
 *    └──────────────► PrivacyApiService
 *                          │
 *                          ▼
 *                    PrivacyAuditDto
 */
@Singleton
class PrivacyAuditRepositoryImpl @Inject constructor(
    private val privacyAuditDao: PrivacyAuditDao,
    private val privacyApiService: PrivacyApiService
) : PrivacyAuditRepository {

    /**
     * Retrieves a privacy audit by its ID.
     */
    override suspend fun getAuditById(
        auditId: String
    ): Result<PrivacyAudit?> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            val entity =
                privacyAuditDao.getById(
                    auditId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves the most recently created privacy audit.
     */
    override suspend fun getLatestAudit():
        Result<PrivacyAudit?> {

        return try {

            val entity =
                privacyAuditDao.getLatestAudit()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves recent privacy audits.
     */
    override suspend fun getRecentAudits(
        limit: Int
    ): Result<List<PrivacyAudit>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy audit limit must be greater than zero."
                    )
                )
            }

            val entities =
                privacyAuditDao.getRecentAudits(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored privacy audits.
     */
    override suspend fun getAllAudits():
        Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getAllAudits()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits within a time range.
     */
    override suspend fun getAuditsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<PrivacyAudit>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                privacyAuditDao.getAuditsBetween(
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
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits for a specific application package.
     */
    override suspend fun getAuditsByPackage(
        packageName: String
    ): Result<List<PrivacyAudit>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                privacyAuditDao.getByPackageName(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits by event type.
     *
     * Examples:
     *
     * CAMERA
     * MICROPHONE
     * LOCATION
     * CONTACTS
     * TRACKING
     * BACKGROUND_ACTIVITY
     */
    override suspend fun getAuditsByEventType(
        eventType: String
    ): Result<List<PrivacyAudit>> {

        return try {

            if (eventType.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy audit event type cannot be blank."
                    )
                )
            }

            val entities =
                privacyAuditDao.getByEventType(
                    eventType
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits by severity.
     */
    override suspend fun getAuditsBySeverity(
        severity: String
    ): Result<List<PrivacyAudit>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy audit severity cannot be blank."
                    )
                )
            }

            val entities =
                privacyAuditDao.getBySeverity(
                    severity
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits by resolution state.
     */
    override suspend fun getAuditsByResolutionState(
        resolved: Boolean
    ): Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getByResolutionState(
                    resolved
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits by review state.
     */
    override suspend fun getAuditsByReviewState(
        reviewed: Boolean
    ): Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getByReviewState(
                    reviewed
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves unresolved privacy audits.
     */
    override suspend fun getUnresolvedAudits():
        Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getUnresolvedEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves unresolved critical privacy audits.
     */
    override suspend fun getCriticalUnresolvedAudits():
        Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getCriticalUnresolvedEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Creates a new privacy audit.
     */
    override suspend fun createAudit(
        audit: PrivacyAudit
    ): Result<Unit> {

        return try {

            privacyAuditDao.insert(
                audit.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Saves or updates a privacy audit.
     */
    override suspend fun saveAudit(
        audit: PrivacyAudit
    ): Result<Unit> {

        return try {

            privacyAuditDao.insertOrUpdate(
                audit.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Saves multiple privacy audits.
     */
    override suspend fun saveAudits(
        audits: List<PrivacyAudit>
    ): Result<Unit> {

        return try {

            if (audits.isEmpty()) {
                return Result.success(Unit)
            }

            privacyAuditDao.insertOrUpdateAll(
                audits.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Updates an existing privacy audit.
     */
    override suspend fun updateAudit(
        audit: PrivacyAudit
    ): Result<Unit> {

        return try {

            validateAuditId(
                audit.auditId
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.update(
                audit.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Marks an audit as reviewed.
     */
    override suspend fun markAsReviewed(
        auditId: String
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.markReviewed(
                auditId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Marks an audit as unresolved.
     *
     * Useful when a previously resolved privacy issue becomes
     * active again.
     */
    override suspend fun markAsUnresolved(
        auditId: String
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.markUnresolved(
                auditId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Marks an audit as resolved.
     */
    override suspend fun markAsResolved(
        auditId: String,
        resolvedAt: Long
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.markResolved(
                auditId = auditId,
                resolvedAt = resolvedAt
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Updates the risk score attached to an audit.
     *
     * The actual risk calculation is performed by the Domain
     * layer. This method only persists the calculated value.
     */
    override suspend fun updateRiskScore(
        auditId: String,
        riskScore: Double
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            if (riskScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy risk score must be between 0 and 100."
                    )
                )
            }

            privacyAuditDao.updateRiskScore(
                auditId = auditId,
                riskScore = riskScore
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Updates audit severity.
     *
     * Severity determination belongs to Domain logic.
     */
    override suspend fun updateSeverity(
        auditId: String,
        severity: String
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy audit severity cannot be blank."
                    )
                )
            }

            privacyAuditDao.updateSeverity(
                auditId = auditId,
                severity = severity
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of privacy audits.
     */
    override suspend fun getAuditCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getAuditCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves unresolved audit count.
     */
    override suspend fun getUnresolvedAuditCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getUnresolvedEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves reviewed audit count.
     */
    override suspend fun getReviewedAuditCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getReviewedAuditCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves critical audit count.
     */
    override suspend fun getCriticalAuditCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getCriticalEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves the number of audits generated by a specific
     * application.
     */
    override suspend fun getAuditCountByPackage(
        packageName: String
    ): Result<Long> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            Result.success(
                privacyAuditDao.getAuditCountByPackage(
                    packageName
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves the latest audit for an application.
     */
    override suspend fun getLatestAuditByPackage(
        packageName: String
    ): Result<PrivacyAudit?> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entity =
                privacyAuditDao.getLatestEventForPackage(
                    packageName
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves the latest audit for a specific event type.
     */
    override suspend fun getLatestAuditByEventType(
        eventType: String
    ): Result<PrivacyAudit?> {

        return try {

            if (eventType.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy event type cannot be blank."
                    )
                )
            }

            val entity =
                privacyAuditDao.getLatestEventByType(
                    eventType
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves remote privacy audits.
     */
    override suspend fun refreshAudits():
        Result<List<PrivacyAudit>> {

        return try {

            val response =
                privacyApiService.getPrivacyAudits()

            if (response.isNotEmpty()) {

                privacyAuditDao.insertOrUpdateAll(
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
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Retrieves audits created or updated since the supplied
     * timestamp.
     */
    override suspend fun getAuditsSince(
        timestamp: Long
    ): Result<List<PrivacyAudit>> {

        return try {

            val response =
                privacyApiService.getPrivacyAuditsSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                privacyAuditDao.insertOrUpdateAll(
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
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Synchronizes local privacy audits with the backend.
     */
    override suspend fun synchronizeAudits():
        Result<Unit> {

        return try {

            val response =
                privacyApiService.getPrivacyAudits()

            if (response.isNotEmpty()) {

                privacyAuditDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Deletes one audit.
     */
    override suspend fun deleteAudit(
        auditId: String
    ): Result<Unit> {

        return try {

            validateAuditId(
                auditId
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.deleteById(
                auditId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Deletes audit records older than the supplied timestamp.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            privacyAuditDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Clears all local privacy audit records.
     */
    override suspend fun clearAudits():
        Result<Unit> {

        return try {

            privacyAuditDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyAuditException(exception)
            )
        }
    }

    /**
     * Converts PrivacyAuditDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun PrivacyAuditDto.toDomain():
        PrivacyAudit {

        return PrivacyAudit(
            auditId = auditId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            riskScore = riskScore
        )
    }

    /**
     * Converts PrivacyAuditDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun PrivacyAuditDto.toEntity():
        PrivacyAuditEntity {

        return PrivacyAuditEntity(
            auditId = auditId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            riskScore = riskScore
        )
    }

    /**
     * Converts Domain PrivacyAudit into Room entity.
     *
     * Domain -> Entity
     */
    private fun PrivacyAudit.toEntity():
        PrivacyAuditEntity {

        return PrivacyAuditEntity(
            auditId = auditId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            riskScore = riskScore
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun PrivacyAuditEntity.toDomain():
        PrivacyAudit {

        return PrivacyAudit(
            auditId = auditId,
            packageName = packageName,
            applicationName = applicationName,
            eventType = eventType,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            reviewed = reviewed,
            resolved = resolved,
            riskScore = riskScore
        )
    }

    /**
     * Validates audit ID.
     */
    private fun validateAuditId(
        auditId: String
    ): Exception? {

        return if (auditId.isBlank()) {
            IllegalArgumentException(
                "Privacy audit ID cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Validates application package name.
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
    private fun mapPrivacyAuditException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Device/network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX privacy audit service.",
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
                            "The privacy audit request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access privacy audits."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested privacy audit was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Privacy audit synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Privacy audit request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX privacy audit service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Privacy audit request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve translated exceptions.
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
                    message = "An unexpected privacy audit repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
