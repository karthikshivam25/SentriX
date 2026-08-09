package com.sentrix.data.repository.privacy

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.PrivacyAuditDao
import com.sentrix.data.local.entities.PrivacyAuditEntity
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.dto.PrivacyAuditDto
import com.sentrix.domain.models.PrivacyAudit
import com.sentrix.domain.repository.PrivacyRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Privacy Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.privacy
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of PrivacyRepository.
 *
 * This repository manages privacy-related information used by
 * the SentriX privacy protection subsystem.
 *
 * Supported privacy data includes:
 *
 * - Privacy audit records.
 * - Application privacy activity.
 * - Sensitive permission observations.
 * - Camera access events.
 * - Microphone access events.
 * - Location access events.
 * - Contact access events.
 * - Background activity.
 * - Tracking activity.
 * - Suspicious privacy events.
 * - Privacy risk observations.
 * - Privacy protection status.
 * - Privacy audit history.
 * - Remote privacy synchronization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide:
 *
 * - Whether an application is malicious.
 * - Whether an application should be uninstalled.
 * - Whether a privacy event is dangerous.
 * - What privacy risk score should be assigned.
 * - Which privacy policy should be enforced.
 *
 * Those responsibilities belong to the Domain layer.
 *
 * This repository is responsible for:
 *
 * - Reading privacy data.
 * - Persisting privacy data.
 * - Updating privacy records.
 * - Querying privacy history.
 * - Synchronizing privacy information.
 * - DTO -> Domain conversion.
 * - DTO -> Entity conversion.
 * - Domain -> Entity conversion.
 * - Entity -> Domain conversion.
 * - Infrastructure exception translation.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * PrivacyRepository
 *    │
 *    ▼
 * PrivacyRepositoryImpl
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
class PrivacyRepositoryImpl @Inject constructor(
    private val privacyAuditDao: PrivacyAuditDao,
    private val privacyApiService: PrivacyApiService
) : PrivacyRepository {

    /**
     * Retrieves the latest privacy audit.
     *
     * Local data is preferred so privacy information remains
     * available while the device is offline.
     */
    override suspend fun getLatestPrivacyAudit():
        Result<PrivacyAudit?> {

        return try {

            val entity =
                privacyAuditDao.getLatestAudit()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves a privacy audit by ID.
     */
    override suspend fun getPrivacyAuditById(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves recent privacy audits.
     *
     * Useful for:
     *
     * - Privacy dashboard.
     * - Privacy history.
     * - Security reports.
     * - Analytics.
     */
    override suspend fun getRecentPrivacyAudits(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored privacy audits.
     */
    override suspend fun getAllPrivacyAudits():
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy audits between two timestamps.
     */
    override suspend fun getPrivacyAuditsBetween(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy audits for a particular application.
     */
    override suspend fun getAuditsByPackage(
        packageName: String
    ): Result<List<PrivacyAudit>> {

        return try {

            if (packageName.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Application package name cannot be blank."
                    )
                )
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy audits by event type.
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
                        "Privacy event type cannot be blank."
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy audits by severity.
     */
    override suspend fun getAuditsBySeverity(
        severity: String
    ): Result<List<PrivacyAudit>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy severity cannot be blank."
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves unresolved privacy events.
     *
     * The repository only retrieves records. Whether an event
     * requires action is determined by the Domain layer.
     */
    override suspend fun getUnresolvedPrivacyEvents():
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves critical privacy events.
     */
    override suspend fun getCriticalPrivacyEvents():
        Result<List<PrivacyAudit>> {

        return try {

            val entities =
                privacyAuditDao.getCriticalEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Saves a privacy audit locally.
     */
    override suspend fun savePrivacyAudit(
        audit: PrivacyAudit
    ): Result<Unit> {

        return try {

            privacyAuditDao.insertOrUpdate(
                audit.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Saves multiple privacy audits.
     *
     * Useful during remote synchronization or bulk local
     * collection.
     */
    override suspend fun savePrivacyAudits(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Marks a privacy event as resolved.
     */
    override suspend fun markPrivacyEventResolved(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Marks a privacy event as reviewed.
     *
     * This represents user/system review state and does not
     * determine whether the event is safe or dangerous.
     */
    override suspend fun markPrivacyEventReviewed(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records camera access.
     */
    override suspend fun recordCameraAccess(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_CAMERA,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records microphone access.
     */
    override suspend fun recordMicrophoneAccess(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_MICROPHONE,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records location access.
     */
    override suspend fun recordLocationAccess(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_LOCATION,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records contact access.
     */
    override suspend fun recordContactAccess(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_CONTACTS,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records background activity.
     */
    override suspend fun recordBackgroundActivity(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_BACKGROUND_ACTIVITY,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Records tracking activity.
     */
    override suspend fun recordTrackingActivity(
        packageName: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            privacyAuditDao.recordPrivacyEvent(
                packageName = packageName,
                eventType = EVENT_TRACKING,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the number of privacy events.
     */
    override suspend fun getPrivacyEventCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the number of unresolved privacy events.
     */
    override suspend fun getUnresolvedEventCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getUnresolvedEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the number of critical privacy events.
     */
    override suspend fun getCriticalEventCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getCriticalEventCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves camera access count.
     */
    override suspend fun getCameraAccessCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCountByType(
                    EVENT_CAMERA
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves microphone access count.
     */
    override suspend fun getMicrophoneAccessCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCountByType(
                    EVENT_MICROPHONE
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves location access count.
     */
    override suspend fun getLocationAccessCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCountByType(
                    EVENT_LOCATION
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves contact access count.
     */
    override suspend fun getContactAccessCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCountByType(
                    EVENT_CONTACTS
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves tracking event count.
     */
    override suspend fun getTrackingEventCount():
        Result<Long> {

        return try {

            Result.success(
                privacyAuditDao.getEventCountByType(
                    EVENT_TRACKING
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the number of distinct applications that
     * generated privacy events.
     */
    override suspend fun getAffectedApplicationCount():
        Result<Int> {

        return try {

            Result.success(
                privacyAuditDao.getAffectedApplicationCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the latest privacy event for an application.
     */
    override suspend fun getLatestEventForPackage(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves the latest privacy event of a particular type.
     */
    override suspend fun getLatestEventByType(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy data from the remote backend.
     */
    override suspend fun refreshPrivacyAudits():
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Retrieves privacy records created or updated since
     * the supplied timestamp.
     *
     * Supports incremental synchronization.
     */
    override suspend fun getPrivacyAuditsSince(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Synchronizes privacy audit information.
     */
    override suspend fun synchronizePrivacyAudits():
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Deletes privacy audits older than the supplied
     * timestamp.
     *
     * Retention policy should be controlled by the appropriate
     * SentriX privacy/security policy.
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Deletes one privacy audit.
     */
    override suspend fun deletePrivacyAudit(
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
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Clears all locally stored privacy audit information.
     */
    override suspend fun clearPrivacyAudits():
        Result<Unit> {

        return try {

            privacyAuditDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyException(exception)
            )
        }
    }

    /**
     * Converts remote PrivacyAuditDto into Domain model.
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
     * Converts remote PrivacyAuditDto into Room entity.
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
     * Converts Room entity into Domain PrivacyAudit.
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
     * Validates privacy audit ID.
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
    private fun mapPrivacyException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX privacy service.",
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
                            "The privacy request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access privacy information."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested privacy information was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Privacy synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Privacy request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX privacy service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Privacy request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected privacy repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Privacy event types.
         */
        private const val EVENT_CAMERA =
            "CAMERA"

        private const val EVENT_MICROPHONE =
            "MICROPHONE"

        private const val EVENT_LOCATION =
            "LOCATION"

        private const val EVENT_CONTACTS =
            "CONTACTS"

        private const val EVENT_BACKGROUND_ACTIVITY =
            "BACKGROUND_ACTIVITY"

        private const val EVENT_TRACKING =
            "TRACKING"
    }
}
