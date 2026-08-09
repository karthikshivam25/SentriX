package com.sentrix.data.repository.privacy

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.TrackerBlockingDao
import com.sentrix.data.local.entities.TrackerBlockingEntity
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.dto.TrackerBlockingDto
import com.sentrix.domain.models.TrackerBlocking
import com.sentrix.domain.repository.TrackerBlockingRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Tracker Blocking Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.privacy
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * TrackerBlockingRepository.
 *
 * This repository manages tracker-blocking DATA.
 *
 * Supported information includes:
 *
 * - Tracker identifiers.
 * - Tracker domains.
 * - Tracker categories.
 * - Tracker providers.
 * - Tracker type.
 * - Blocked requests.
 * - Allowed requests.
 * - Blocking state.
 * - Application/package association.
 * - Tracker detection timestamps.
 * - Blocking timestamps.
 * - Tracker statistics.
 * - Tracker rules.
 * - Tracker database synchronization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT perform the actual blocking.
 *
 * Actual traffic interception/blocking belongs to components
 * such as:
 *
 * - VPN service.
 * - Network interceptor.
 * - TrackerBlockingEngine.
 * - PrivacyProtectionService.
 *
 * This repository only provides persistence and synchronization.
 *
 * The repository also does NOT determine whether a tracker
 * should be blocked.
 *
 * That decision belongs to Domain components such as:
 *
 * - TrackerBlockingRules.
 * - PrivacyProtectionRules.
 * - TrackerAnalysisService.
 * - PrivacyRiskScoringService.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * TrackerBlockingRepository
 *    │
 *    ▼
 * TrackerBlockingRepositoryImpl
 *    │
 *    ├──────────────► TrackerBlockingDao
 *    │                     │
 *    │                     ▼
 *    │              TrackerBlockingEntity
 *    │
 *    └──────────────► PrivacyApiService
 *                          │
 *                          ▼
 *                    TrackerBlockingDto
 */
@Singleton
class TrackerBlockingRepositoryImpl @Inject constructor(
    private val trackerBlockingDao: TrackerBlockingDao,
    private val privacyApiService: PrivacyApiService
) : TrackerBlockingRepository {

    /**
     * Retrieves a tracker record by ID.
     */
    override suspend fun getTrackerById(
        trackerId: String
    ): Result<TrackerBlocking?> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            val entity =
                trackerBlockingDao.getById(
                    trackerId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored tracker records.
     */
    override suspend fun getAllTrackers():
        Result<List<TrackerBlocking>> {

        return try {

            val entities =
                trackerBlockingDao.getAllTrackers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves recent tracker records.
     */
    override suspend fun getRecentTrackers(
        limit: Int
    ): Result<List<TrackerBlocking>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Tracker limit must be greater than zero."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getRecentTrackers(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves trackers by domain.
     */
    override suspend fun getTrackersByDomain(
        domain: String
    ): Result<List<TrackerBlocking>> {

        return try {

            validateDomain(
                domain
            )?.let {
                return Result.failure(it)
            }

            val entities =
                trackerBlockingDao.getByDomain(
                    domain
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves trackers associated with an application.
     */
    override suspend fun getTrackersByPackage(
        packageName: String
    ): Result<List<TrackerBlocking>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                trackerBlockingDao.getByPackageName(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves trackers by category.
     *
     * Examples:
     *
     * - ADVERTISING
     * - ANALYTICS
     * - SOCIAL
     * - FINGERPRINTING
     * - CROSS_SITE_TRACKING
     */
    override suspend fun getTrackersByCategory(
        category: String
    ): Result<List<TrackerBlocking>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Tracker category cannot be blank."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getByCategory(
                    category
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves trackers by provider.
     */
    override suspend fun getTrackersByProvider(
        provider: String
    ): Result<List<TrackerBlocking>> {

        return try {

            if (provider.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Tracker provider cannot be blank."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getByProvider(
                    provider
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves currently enabled tracker rules.
     */
    override suspend fun getEnabledTrackers():
        Result<List<TrackerBlocking>> {

        return try {

            val entities =
                trackerBlockingDao.getEnabledTrackers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves trackers marked as blocked.
     */
    override suspend fun getBlockedTrackers():
        Result<List<TrackerBlocking>> {

        return try {

            val entities =
                trackerBlockingDao.getBlockedTrackers()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves tracker records between two timestamps.
     */
    override suspend fun getTrackersBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<TrackerBlocking>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getTrackersBetween(
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
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Saves a tracker-blocking record.
     */
    override suspend fun saveTracker(
        tracker: TrackerBlocking
    ): Result<Unit> {

        return try {

            trackerBlockingDao.insertOrUpdate(
                tracker.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Saves multiple tracker records.
     */
    override suspend fun saveTrackers(
        trackers: List<TrackerBlocking>
    ): Result<Unit> {

        return try {

            if (trackers.isEmpty()) {
                return Result.success(Unit)
            }

            trackerBlockingDao.insertOrUpdateAll(
                trackers.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Creates a new tracker-blocking record.
     */
    override suspend fun createTracker(
        tracker: TrackerBlocking
    ): Result<Unit> {

        return try {

            trackerBlockingDao.insert(
                tracker.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Updates an existing tracker record.
     */
    override suspend fun updateTracker(
        tracker: TrackerBlocking
    ): Result<Unit> {

        return try {

            validateTrackerId(
                tracker.trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.update(
                tracker.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Updates tracker blocking state.
     *
     * This only persists the state.
     *
     * The actual network blocking operation is handled by
     * the SentriX blocking engine.
     */
    override suspend fun updateBlockingState(
        trackerId: String,
        blocked: Boolean
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.updateBlockingState(
                trackerId = trackerId,
                blocked = blocked
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Enables a tracker rule.
     */
    override suspend fun enableTracker(
        trackerId: String
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.updateEnabledState(
                trackerId = trackerId,
                enabled = true
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Disables a tracker rule.
     */
    override suspend fun disableTracker(
        trackerId: String
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.updateEnabledState(
                trackerId = trackerId,
                enabled = false
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Records one blocked tracker request.
     */
    override suspend fun recordBlockedRequest(
        trackerId: String
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.incrementBlockedRequests(
                trackerId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Records one allowed tracker request.
     */
    override suspend fun recordAllowedRequest(
        trackerId: String
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.incrementAllowedRequests(
                trackerId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Records a tracker detection event.
     */
    override suspend fun recordTrackerDetection(
        trackerId: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.recordDetection(
                trackerId = trackerId,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Records a blocked tracker event.
     */
    override suspend fun recordTrackerBlocked(
        trackerId: String,
        timestamp: Long
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.recordBlockedEvent(
                trackerId = trackerId,
                timestamp = timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of tracker records.
     */
    override suspend fun getTrackerCount():
        Result<Long> {

        return try {

            Result.success(
                trackerBlockingDao.getTrackerCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves total blocked tracker requests.
     */
    override suspend fun getBlockedRequestCount():
        Result<Long> {

        return try {

            Result.success(
                trackerBlockingDao.getBlockedRequestCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves total allowed tracker requests.
     */
    override suspend fun getAllowedRequestCount():
        Result<Long> {

        return try {

            Result.success(
                trackerBlockingDao.getAllowedRequestCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves total tracker detections.
     */
    override suspend fun getDetectionCount():
        Result<Long> {

        return try {

            Result.success(
                trackerBlockingDao.getDetectionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves tracker statistics for an application.
     */
    override suspend fun getStatisticsByPackage(
        packageName: String
    ): Result<List<TrackerBlocking>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                trackerBlockingDao.getStatisticsByPackage(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves tracker statistics by category.
     */
    override suspend fun getStatisticsByCategory(
        category: String
    ): Result<List<TrackerBlocking>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Tracker category cannot be blank."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getStatisticsByCategory(
                    category
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves the most frequently blocked trackers.
     */
    override suspend fun getMostBlockedTrackers(
        limit: Int
    ): Result<List<TrackerBlocking>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Tracker limit must be greater than zero."
                    )
                )
            }

            val entities =
                trackerBlockingDao.getMostBlockedTrackers(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves the latest tracker activity for an
     * application.
     */
    override suspend fun getLatestTrackerActivity(
        packageName: String
    ): Result<TrackerBlocking?> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entity =
                trackerBlockingDao.getLatestActivity(
                    packageName
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Refreshes the tracker database from the backend.
     */
    override suspend fun refreshTrackers():
        Result<List<TrackerBlocking>> {

        return try {

            val response =
                privacyApiService.getTrackerBlockingRules()

            if (response.isNotEmpty()) {

                trackerBlockingDao.insertOrUpdateAll(
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
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Retrieves tracker rules changed after the specified
     * timestamp.
     *
     * Supports incremental synchronization.
     */
    override suspend fun getTrackersSince(
        timestamp: Long
    ): Result<List<TrackerBlocking>> {

        return try {

            val response =
                privacyApiService.getTrackerBlockingRulesSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                trackerBlockingDao.insertOrUpdateAll(
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
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Synchronizes tracker-blocking rules with the backend.
     */
    override suspend fun synchronizeTrackers():
        Result<Unit> {

        return try {

            val response =
                privacyApiService.getTrackerBlockingRules()

            if (response.isNotEmpty()) {

                trackerBlockingDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Deletes a tracker record.
     */
    override suspend fun deleteTracker(
        trackerId: String
    ): Result<Unit> {

        return try {

            validateTrackerId(
                trackerId
            )?.let {
                return Result.failure(it)
            }

            trackerBlockingDao.deleteById(
                trackerId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Deletes tracker records older than the supplied
     * timestamp.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            trackerBlockingDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Clears all locally cached tracker records.
     */
    override suspend fun clearTrackers():
        Result<Unit> {

        return try {

            trackerBlockingDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapTrackerBlockingException(exception)
            )
        }
    }

    /**
     * Validates tracker ID.
     */
    private fun validateTrackerId(
        trackerId: String
    ): Exception? {

        return if (trackerId.isBlank()) {
            IllegalArgumentException(
                "Tracker ID cannot be blank."
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
     * Performs basic domain validation.
     *
     * This intentionally remains lightweight because complete
     * domain validation belongs to the Domain layer.
     */
    private fun validateDomain(
        domain: String
    ): Exception? {

        return if (domain.isBlank()) {
            IllegalArgumentException(
                "Tracker domain cannot be blank."
            )
        } else {
            null
        }
    }

    /**
     * Converts TrackerBlockingDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun TrackerBlockingDto.toDomain():
        TrackerBlocking {

        return TrackerBlocking(
            trackerId = trackerId,
            domain = domain,
            trackerName = trackerName,
            provider = provider,
            category = category,
            trackerType = trackerType,
            packageName = packageName,
            blocked = blocked,
            enabled = enabled,
            blockedRequests = blockedRequests,
            allowedRequests = allowedRequests,
            detectionCount = detectionCount,
            lastDetectedAt = lastDetectedAt,
            lastBlockedAt = lastBlockedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts TrackerBlockingDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun TrackerBlockingDto.toEntity():
        TrackerBlockingEntity {

        return TrackerBlockingEntity(
            trackerId = trackerId,
            domain = domain,
            trackerName = trackerName,
            provider = provider,
            category = category,
            trackerType = trackerType,
            packageName = packageName,
            blocked = blocked,
            enabled = enabled,
            blockedRequests = blockedRequests,
            allowedRequests = allowedRequests,
            detectionCount = detectionCount,
            lastDetectedAt = lastDetectedAt,
            lastBlockedAt = lastBlockedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts Domain TrackerBlocking into Room entity.
     *
     * Domain -> Entity
     */
    private fun TrackerBlocking.toEntity():
        TrackerBlockingEntity {

        return TrackerBlockingEntity(
            trackerId = trackerId,
            domain = domain,
            trackerName = trackerName,
            provider = provider,
            category = category,
            trackerType = trackerType,
            packageName = packageName,
            blocked = blocked,
            enabled = enabled,
            blockedRequests = blockedRequests,
            allowedRequests = allowedRequests,
            detectionCount = detectionCount,
            lastDetectedAt = lastDetectedAt,
            lastBlockedAt = lastBlockedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun TrackerBlockingEntity.toDomain():
        TrackerBlocking {

        return TrackerBlocking(
            trackerId = trackerId,
            domain = domain,
            trackerName = trackerName,
            provider = provider,
            category = category,
            trackerType = trackerType,
            packageName = packageName,
            blocked = blocked,
            enabled = enabled,
            blockedRequests = blockedRequests,
            allowedRequests = allowedRequests,
            detectionCount = detectionCount,
            lastDetectedAt = lastDetectedAt,
            lastBlockedAt = lastBlockedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapTrackerBlockingException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX tracker protection service.",
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
                            "The tracker-blocking request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access tracker-blocking data."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested tracker information was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Tracker database synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Tracker protection request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX tracker protection service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Tracker protection request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected tracker-blocking repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
