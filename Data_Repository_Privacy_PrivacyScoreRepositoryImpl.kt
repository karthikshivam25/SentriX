package com.sentrix.data.repository.privacy

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.PrivacyScoreDao
import com.sentrix.data.local.entities.PrivacyScoreEntity
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.dto.PrivacyScoreDto
import com.sentrix.domain.models.PrivacyScore
import com.sentrix.domain.repository.PrivacyScoreRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Privacy Score Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.privacy
 *
 * Responsibility
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of PrivacyScoreRepository.
 *
 * This repository manages privacy-score DATA used by SentriX.
 *
 * Supported information includes:
 *
 * - Overall privacy score.
 * - Application privacy score.
 * - Permission privacy score.
 * - Tracking privacy score.
 * - Data protection score.
 * - Sensitive-data exposure score.
 * - Background activity score.
 * - Privacy event score.
 * - Historical privacy scores.
 * - Privacy score timestamps.
 * - Privacy score synchronization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT calculate the privacy score.
 *
 * The actual scoring algorithm belongs to the Domain layer,
 * for example:
 *
 * - PrivacyRiskScoringService.
 * - PrivacyScoreRules.
 * - PrivacyAnalysisService.
 * - PrivacyProtectionService.
 *
 * The repository only persists and retrieves the score that
 * has already been calculated by the Domain layer.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * PrivacyScoreRepository
 *    │
 *    ▼
 * PrivacyScoreRepositoryImpl
 *    │
 *    ├──────────────► PrivacyScoreDao
 *    │                     │
 *    │                     ▼
 *    │              PrivacyScoreEntity
 *    │
 *    └──────────────► PrivacyApiService
 *                          │
 *                          ▼
 *                    PrivacyScoreDto
 */
@Singleton
class PrivacyScoreRepositoryImpl @Inject constructor(
    private val privacyScoreDao: PrivacyScoreDao,
    private val privacyApiService: PrivacyApiService
) : PrivacyScoreRepository {

    /**
     * Retrieves the latest overall privacy score.
     */
    override suspend fun getLatestScore():
        Result<PrivacyScore?> {

        return try {

            val entity =
                privacyScoreDao.getLatestScore()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves a privacy score by ID.
     */
    override suspend fun getScoreById(
        scoreId: String
    ): Result<PrivacyScore?> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            val entity =
                privacyScoreDao.getById(
                    scoreId
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored privacy scores.
     */
    override suspend fun getAllScores():
        Result<List<PrivacyScore>> {

        return try {

            val entities =
                privacyScoreDao.getAllScores()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves recent privacy scores.
     *
     * Useful for:
     *
     * - Privacy dashboard.
     * - Score history charts.
     * - Analytics.
     * - Security reports.
     */
    override suspend fun getRecentScores(
        limit: Int
    ): Result<List<PrivacyScore>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score limit must be greater than zero."
                    )
                )
            }

            val entities =
                privacyScoreDao.getRecentScores(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves privacy scores within a time range.
     */
    override suspend fun getScoresBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<PrivacyScore>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                privacyScoreDao.getScoresBetween(
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
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves privacy scores for a specific application.
     */
    override suspend fun getScoresByPackage(
        packageName: String
    ): Result<List<PrivacyScore>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entities =
                privacyScoreDao.getByPackageName(
                    packageName
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the latest privacy score for an application.
     */
    override suspend fun getLatestScoreByPackage(
        packageName: String
    ): Result<PrivacyScore?> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            val entity =
                privacyScoreDao.getLatestScoreByPackage(
                    packageName
                )

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves scores by privacy status.
     *
     * Examples:
     *
     * - EXCELLENT
     * - GOOD
     * - MODERATE
     * - POOR
     * - CRITICAL
     */
    override suspend fun getScoresByStatus(
        status: String
    ): Result<List<PrivacyScore>> {

        return try {

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score status cannot be blank."
                    )
                )
            }

            val entities =
                privacyScoreDao.getByStatus(
                    status
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves scores below a threshold.
     *
     * The threshold is supplied by the caller.
     * This repository does not determine what constitutes
     * a dangerous score.
     */
    override suspend fun getScoresBelow(
        threshold: Double
    ): Result<List<PrivacyScore>> {

        return try {

            if (threshold !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score threshold must be between 0 and 100."
                    )
                )
            }

            val entities =
                privacyScoreDao.getScoresBelow(
                    threshold
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Saves a privacy score.
     *
     * The score should already have been calculated by
     * the Domain layer.
     */
    override suspend fun saveScore(
        score: PrivacyScore
    ): Result<Unit> {

        return try {

            validateScore(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.insertOrUpdate(
                score.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Saves multiple privacy scores.
     */
    override suspend fun saveScores(
        scores: List<PrivacyScore>
    ): Result<Unit> {

        return try {

            if (scores.isEmpty()) {
                return Result.success(Unit)
            }

            scores.forEach { score ->

                validateScore(
                    score
                )?.let {
                    return Result.failure(it)
                }
            }

            privacyScoreDao.insertOrUpdateAll(
                scores.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Creates a new privacy score.
     */
    override suspend fun createScore(
        score: PrivacyScore
    ): Result<Unit> {

        return try {

            validateScore(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.insert(
                score.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates an existing privacy score.
     */
    override suspend fun updateScore(
        score: PrivacyScore
    ): Result<Unit> {

        return try {

            validateScoreId(
                score.scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScore(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.update(
                score.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the overall privacy score.
     *
     * The supplied score must already be calculated by
     * Domain logic.
     */
    override suspend fun updateOverallScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updateOverallScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the permission privacy score.
     */
    override suspend fun updatePermissionScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updatePermissionScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the tracker privacy score.
     */
    override suspend fun updateTrackerScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updateTrackerScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the data-protection score.
     */
    override suspend fun updateDataProtectionScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updateDataProtectionScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the sensitive-data exposure score.
     */
    override suspend fun updateSensitiveDataScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updateSensitiveDataScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the background-activity privacy score.
     */
    override suspend fun updateBackgroundActivityScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updateBackgroundActivityScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the privacy event score.
     */
    override suspend fun updatePrivacyEventScore(
        scoreId: String,
        score: Double
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            validateScoreValue(
                score
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.updatePrivacyEventScore(
                scoreId = scoreId,
                score = score
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Updates the score status.
     *
     * Status calculation belongs to Domain logic.
     */
    override suspend fun updateScoreStatus(
        scoreId: String,
        status: String
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score status cannot be blank."
                    )
                )
            }

            privacyScoreDao.updateScoreStatus(
                scoreId = scoreId,
                status = status
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current overall privacy score value.
     */
    override suspend fun getCurrentScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current permission score.
     */
    override suspend fun getCurrentPermissionScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentPermissionScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current tracker score.
     */
    override suspend fun getCurrentTrackerScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentTrackerScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current data-protection score.
     */
    override suspend fun getCurrentDataProtectionScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentDataProtectionScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current sensitive-data score.
     */
    override suspend fun getCurrentSensitiveDataScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentSensitiveDataScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current background activity score.
     */
    override suspend fun getCurrentBackgroundActivityScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentBackgroundActivityScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the current privacy-event score.
     */
    override suspend fun getCurrentPrivacyEventScore():
        Result<Double?> {

        return try {

            Result.success(
                privacyScoreDao.getCurrentPrivacyEventScore()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the average privacy score between two
     * timestamps.
     *
     * This method only performs data aggregation.
     */
    override suspend fun getAverageScore(
        startTime: Long,
        endTime: Long
    ): Result<Double?> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            Result.success(
                privacyScoreDao.getAverageScore(
                    startTime = startTime,
                    endTime = endTime
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the highest privacy score in a period.
     */
    override suspend fun getHighestScore(
        startTime: Long,
        endTime: Long
    ): Result<Double?> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            Result.success(
                privacyScoreDao.getHighestScore(
                    startTime = startTime,
                    endTime = endTime
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the lowest privacy score in a period.
     */
    override suspend fun getLowestScore(
        startTime: Long,
        endTime: Long
    ): Result<Double?> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            Result.success(
                privacyScoreDao.getLowestScore(
                    startTime = startTime,
                    endTime = endTime
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the latest score for a specific category.
     */
    override suspend fun getLatestCategoryScore(
        category: String
    ): Result<Double?> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score category cannot be blank."
                    )
                )
            }

            Result.success(
                privacyScoreDao.getLatestCategoryScore(
                    category
                )
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves privacy score history for an application.
     */
    override suspend fun getApplicationScoreHistory(
        packageName: String,
        limit: Int
    ): Result<List<PrivacyScore>> {

        return try {

            validatePackageName(
                packageName
            )?.let {
                return Result.failure(it)
            }

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Privacy score history limit must be greater than zero."
                    )
                )
            }

            val entities =
                privacyScoreDao.getApplicationScoreHistory(
                    packageName = packageName,
                    limit = limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves the number of stored privacy scores.
     */
    override suspend fun getScoreCount():
        Result<Long> {

        return try {

            Result.success(
                privacyScoreDao.getScoreCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Refreshes privacy scores from the backend.
     */
    override suspend fun refreshScores():
        Result<List<PrivacyScore>> {

        return try {

            val response =
                privacyApiService.getPrivacyScores()

            if (response.isNotEmpty()) {

                privacyScoreDao.insertOrUpdateAll(
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
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Retrieves remote privacy scores created or updated
     * since the supplied timestamp.
     *
     * Supports incremental synchronization.
     */
    override suspend fun getScoresSince(
        timestamp: Long
    ): Result<List<PrivacyScore>> {

        return try {

            val response =
                privacyApiService.getPrivacyScoresSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                privacyScoreDao.insertOrUpdateAll(
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
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Synchronizes local privacy scores with the backend.
     */
    override suspend fun synchronizeScores():
        Result<Unit> {

        return try {

            val response =
                privacyApiService.getPrivacyScores()

            if (response.isNotEmpty()) {

                privacyScoreDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Deletes a single privacy score.
     */
    override suspend fun deleteScore(
        scoreId: String
    ): Result<Unit> {

        return try {

            validateScoreId(
                scoreId
            )?.let {
                return Result.failure(it)
            }

            privacyScoreDao.deleteById(
                scoreId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Deletes scores older than the supplied timestamp.
     *
     * Retention policy should be determined by the application
     * or Domain policy layer.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            privacyScoreDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Clears all locally stored privacy scores.
     */
    override suspend fun clearScores():
        Result<Unit> {

        return try {

            privacyScoreDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPrivacyScoreException(exception)
            )
        }
    }

    /**
     * Converts remote PrivacyScoreDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun PrivacyScoreDto.toDomain():
        PrivacyScore {

        return PrivacyScore(
            scoreId = scoreId,
            packageName = packageName,
            overallScore = overallScore,
            permissionScore = permissionScore,
            trackerScore = trackerScore,
            dataProtectionScore = dataProtectionScore,
            sensitiveDataScore = sensitiveDataScore,
            backgroundActivityScore = backgroundActivityScore,
            privacyEventScore = privacyEventScore,
            status = status,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts remote PrivacyScoreDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun PrivacyScoreDto.toEntity():
        PrivacyScoreEntity {

        return PrivacyScoreEntity(
            scoreId = scoreId,
            packageName = packageName,
            overallScore = overallScore,
            permissionScore = permissionScore,
            trackerScore = trackerScore,
            dataProtectionScore = dataProtectionScore,
            sensitiveDataScore = sensitiveDataScore,
            backgroundActivityScore = backgroundActivityScore,
            privacyEventScore = privacyEventScore,
            status = status,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts Domain PrivacyScore into Room entity.
     *
     * Domain -> Entity
     */
    private fun PrivacyScore.toEntity():
        PrivacyScoreEntity {

        return PrivacyScoreEntity(
            scoreId = scoreId,
            packageName = packageName,
            overallScore = overallScore,
            permissionScore = permissionScore,
            trackerScore = trackerScore,
            dataProtectionScore = dataProtectionScore,
            sensitiveDataScore = sensitiveDataScore,
            backgroundActivityScore = backgroundActivityScore,
            privacyEventScore = privacyEventScore,
            status = status,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun PrivacyScoreEntity.toDomain():
        PrivacyScore {

        return PrivacyScore(
            scoreId = scoreId,
            packageName = packageName,
            overallScore = overallScore,
            permissionScore = permissionScore,
            trackerScore = trackerScore,
            dataProtectionScore = dataProtectionScore,
            sensitiveDataScore = sensitiveDataScore,
            backgroundActivityScore = backgroundActivityScore,
            privacyEventScore = privacyEventScore,
            status = status,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Validates privacy score ID.
     */
    private fun validateScoreId(
        scoreId: String
    ): Exception? {

        return if (scoreId.isBlank()) {
            IllegalArgumentException(
                "Privacy score ID cannot be blank."
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
     * Validates a privacy score value.
     *
     * SentriX uses a normalized 0-100 score.
     */
    private fun validateScoreValue(
        score: Double
    ): Exception? {

        return if (score !in 0.0..100.0) {
            IllegalArgumentException(
                "Privacy score must be between 0 and 100."
            )
        } else {
            null
        }
    }

    /**
     * Performs validation of a complete PrivacyScore model.
     */
    private fun validateScore(
        score: PrivacyScore
    ): Exception? {

        validateScoreId(
            score.scoreId
        )?.let {
            return it
        }

        validatePackageName(
            score.packageName
        )?.let {
            return it
        }

        validateScoreValue(
            score.overallScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.permissionScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.trackerScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.dataProtectionScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.sensitiveDataScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.backgroundActivityScore
        )?.let {
            return it
        }

        validateScoreValue(
            score.privacyEventScore
        )?.let {
            return it
        }

        if (score.status.isBlank()) {
            return IllegalArgumentException(
                "Privacy score status cannot be blank."
            )
        }

        return null
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapPrivacyScoreException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX privacy score service.",
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
                            "The privacy score request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access privacy scores."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested privacy score was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Privacy score synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Privacy score request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX privacy score service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Privacy score request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected privacy score repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
