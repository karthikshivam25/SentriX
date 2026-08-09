package com.sentrix.data.repository.threads

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ThreatPredictionDao
import com.sentrix.data.local.entities.ThreatPredictionEntity
import com.sentrix.data.remote.api.ThreatApiService
import com.sentrix.data.remote.dto.ThreatPredictionDto
import com.sentrix.domain.models.ThreatPrediction
import com.sentrix.domain.repository.ThreatPredictionRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat Prediction Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.threads
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Provides the concrete Data-layer implementation for
 * ThreatPredictionRepository.
 *
 * This repository manages threat-prediction information
 * produced by SentriX's prediction/analysis infrastructure.
 *
 * It is responsible for:
 *
 * - Retrieving predictions from the backend.
 * - Retrieving cached predictions.
 * - Saving prediction results.
 * - Updating prediction results.
 * - Retrieving predictions for a specific threat.
 * - Retrieving predictions for a specific device/event.
 * - Filtering predictions by confidence.
 * - Filtering predictions by severity.
 * - Maintaining local prediction history.
 * - Synchronizing predictions.
 * - Mapping DTOs <-> Domain <-> Entity.
 * - Translating infrastructure exceptions.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT perform the actual AI/ML prediction.
 *
 * Prediction logic belongs to components such as:
 *
 * - ThreatPredictionService
 * - ThreatPredictionEngine
 * - ThreatPredictionRules
 * - BehavioralAnalysisEngine
 *
 * The repository only persists and retrieves prediction data.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 *              DOMAIN
 *                 │
 *                 ▼
 *      ThreatPredictionRepository
 *                 │
 *                 ▼
 *              DATA
 *                 │
 *        ┌────────┴────────┐
 *        ▼                 ▼
 * ThreatApiService   ThreatPredictionDao
 *        │                 │
 *        ▼                 ▼
 * ThreatPredictionDto ThreatPredictionEntity
 *        │                 │
 *        └────────┬────────┘
 *                 ▼
 *          ThreatPrediction
 *
 * Security:
 * ------------------------------------------------------------
 * Prediction records may contain sensitive security context.
 *
 * Therefore this repository must NOT:
 *
 * - Log prediction payloads.
 * - Store raw passwords.
 * - Store authentication tokens.
 * - Store unnecessary personal information.
 * - Expose Retrofit DTOs outside Data.
 * - Expose Room entities outside Data.
 */
@Singleton
class ThreatPredictionRepositoryImpl @Inject constructor(
    private val threatApiService: ThreatApiService,
    private val threatPredictionDao: ThreatPredictionDao
) : ThreatPredictionRepository {

    /**
     * Retrieves the latest threat predictions from the
     * SentriX backend.
     *
     * After successful retrieval, predictions are cached
     * locally for offline access and historical analysis.
     */
    override suspend fun getPredictions(): Result<List<ThreatPrediction>> {

        return try {

            /**
             * Request current predictions from the backend.
             */
            val response =
                threatApiService.getThreatPredictions()

            /**
             * Convert remote DTOs into Domain models.
             */
            val predictions = response.map {
                it.toDomain()
            }

            /**
             * Cache the prediction results.
             */
            cachePredictions(response)

            Result.success(predictions)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves a specific prediction by its unique ID.
     */
    override suspend fun getPredictionById(
        predictionId: String
    ): Result<ThreatPrediction?> {

        return try {

            if (predictionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction ID cannot be blank."
                    )
                )
            }

            /**
             * Try local cache first.
             */
            val cached =
                threatPredictionDao.getPredictionById(
                    predictionId
                )

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * If the prediction is not cached, request it
             * from the backend.
             */
            val response =
                threatApiService.getThreatPredictionById(
                    predictionId
                )

            /**
             * Cache the newly retrieved prediction.
             */
            cachePrediction(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves predictions associated with a specific threat.
     */
    override suspend fun getPredictionsForThreat(
        threatId: String
    ): Result<List<ThreatPrediction>> {

        return try {

            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            /**
             * Query the local prediction history first.
             */
            val cached =
                threatPredictionDao.getPredictionsForThreat(
                    threatId
                )

            /**
             * If local predictions are available, return them.
             *
             * The synchronization layer can refresh them separately.
             */
            if (cached.isNotEmpty()) {
                return Result.success(
                    cached.map {
                        it.toDomain()
                    }
                )
            }

            /**
             * Fall back to the remote threat-prediction service.
             */
            val response =
                threatApiService.getPredictionsForThreat(
                    threatId
                )

            /**
             * Cache the remote results.
             */
            cachePredictions(response)

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves predictions associated with a specific
     * security event.
     *
     * This is useful when SentriX generates a prediction
     * from:
     *
     * - App behavior
     * - URL activity
     * - File analysis
     * - Network behavior
     * - SMS activity
     * - Permission changes
     */
    override suspend fun getPredictionsForEvent(
        eventId: String
    ): Result<List<ThreatPrediction>> {

        return try {

            if (eventId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Event ID cannot be blank."
                    )
                )
            }

            val entities =
                threatPredictionDao.getPredictionsForEvent(
                    eventId
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves predictions above a specified confidence
     * threshold.
     *
     * Example:
     *
     * confidence = 0.80
     *
     * returns predictions with confidence >= 80%.
     */
    override suspend fun getHighConfidencePredictions(
        confidence: Double
    ): Result<List<ThreatPrediction>> {

        return try {

            if (confidence !in 0.0..1.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Confidence must be between 0.0 and 1.0."
                    )
                )
            }

            val entities =
                threatPredictionDao.getPredictionsAboveConfidence(
                    confidence
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves predictions by predicted threat severity.
     */
    override suspend fun getPredictionsBySeverity(
        severity: String
    ): Result<List<ThreatPrediction>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction severity cannot be blank."
                    )
                )
            }

            val entities =
                threatPredictionDao.getPredictionsBySeverity(
                    severity
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves recent prediction history.
     */
    override suspend fun getRecentPredictions(
        limit: Int
    ): Result<List<ThreatPrediction>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction limit must be greater than zero."
                    )
                )
            }

            val entities =
                threatPredictionDao.getRecentPredictions(
                    limit
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Retrieves predictions generated within a specified
     * time range.
     */
    override suspend fun getPredictionsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<ThreatPrediction>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                threatPredictionDao.getPredictionsBetween(
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
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Stores a prediction generated locally by the SentriX
     * prediction engine.
     *
     * This is important because predictions can be generated
     * even when the device is offline.
     */
    override suspend fun savePrediction(
        prediction: ThreatPrediction
    ): Result<Unit> {

        return try {

            threatPredictionDao.insertOrUpdate(
                prediction.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Stores multiple predictions.
     *
     * Bulk insertion is useful after:
     *
     * - Full-device scan.
     * - Behavioral analysis.
     * - Threat intelligence synchronization.
     * - Batch ML inference.
     */
    override suspend fun savePredictions(
        predictions: List<ThreatPrediction>
    ): Result<Unit> {

        return try {

            if (predictions.isEmpty()) {
                return Result.success(Unit)
            }

            threatPredictionDao.insertOrUpdateAll(
                predictions.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Updates an existing prediction.
     *
     * This is useful when additional evidence changes the
     * prediction confidence or severity.
     */
    override suspend fun updatePrediction(
        prediction: ThreatPrediction
    ): Result<Unit> {

        return try {

            val existing =
                threatPredictionDao.getPredictionById(
                    prediction.id
                )

            if (existing == null) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction does not exist."
                    )
                )
            }

            threatPredictionDao.update(
                prediction.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Marks a prediction as reviewed.
     *
     * This can be used by the SentriX security engine or
     * user-facing threat-review workflows.
     */
    override suspend fun markPredictionReviewed(
        predictionId: String
    ): Result<Unit> {

        return try {

            if (predictionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction ID cannot be blank."
                    )
                )
            }

            threatPredictionDao.markAsReviewed(
                predictionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Deletes a single cached prediction.
     *
     * This does not delete the prediction from the remote
     * threat-intelligence service.
     */
    override suspend fun deletePrediction(
        predictionId: String
    ): Result<Unit> {

        return try {

            if (predictionId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Prediction ID cannot be blank."
                    )
                )
            }

            threatPredictionDao.deletePrediction(
                predictionId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Deletes predictions older than a supplied timestamp.
     *
     * Retention policy should be controlled by a higher-level
     * security/privacy configuration rather than hard-coded
     * here.
     */
    override suspend fun deletePredictionsOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            threatPredictionDao.deletePredictionsOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Clears all locally cached predictions.
     *
     * This operation should normally be used for explicit
     * security/privacy reset operations.
     */
    override suspend fun clearPredictionCache(): Result<Unit> {

        return try {

            threatPredictionDao.deleteAllPredictions()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Synchronizes locally stored predictions with the
     * SentriX backend.
     */
    override suspend fun synchronizePredictions(): Result<Unit> {

        return try {

            val response =
                threatApiService.getThreatPredictions()

            if (response.isNotEmpty()) {

                threatPredictionDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored predictions.
     */
    override suspend fun getPredictionCount(): Result<Int> {

        return try {

            Result.success(
                threatPredictionDao.getPredictionCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapPredictionException(exception)
            )
        }
    }

    /**
     * Converts remote ThreatPredictionDto into a Domain model.
     */
    private fun ThreatPredictionDto.toDomain(): ThreatPrediction {

        return ThreatPrediction(
            id = id,
            threatId = threatId,
            eventId = eventId,
            predictedThreatType = predictedThreatType,
            predictedSeverity = predictedSeverity,
            confidenceScore = confidenceScore,
            predictionSource = predictionSource,
            reasoning = reasoning,
            createdAt = createdAt,
            expiresAt = expiresAt,
            reviewed = reviewed
        )
    }

    /**
     * Converts remote DTO into a local Room entity.
     */
    private fun ThreatPredictionDto.toEntity(): ThreatPredictionEntity {

        return ThreatPredictionEntity(
            id = id,
            threatId = threatId,
            eventId = eventId,
            predictedThreatType = predictedThreatType,
            predictedSeverity = predictedSeverity,
            confidenceScore = confidenceScore,
            predictionSource = predictionSource,
            reasoning = reasoning,
            createdAt = createdAt,
            expiresAt = expiresAt,
            reviewed = reviewed
        )
    }

    /**
     * Converts Domain prediction into Room entity.
     */
    private fun ThreatPrediction.toEntity(): ThreatPredictionEntity {

        return ThreatPredictionEntity(
            id = id,
            threatId = threatId,
            eventId = eventId,
            predictedThreatType = predictedThreatType,
            predictedSeverity = predictedSeverity,
            confidenceScore = confidenceScore,
            predictionSource = predictionSource,
            reasoning = reasoning,
            createdAt = createdAt,
            expiresAt = expiresAt,
            reviewed = reviewed
        )
    }

    /**
     * Converts Room entity into Domain prediction.
     */
    private fun ThreatPredictionEntity.toDomain(): ThreatPrediction {

        return ThreatPrediction(
            id = id,
            threatId = threatId,
            eventId = eventId,
            predictedThreatType = predictedThreatType,
            predictedSeverity = predictedSeverity,
            confidenceScore = confidenceScore,
            predictionSource = predictionSource,
            reasoning = reasoning,
            createdAt = createdAt,
            expiresAt = expiresAt,
            reviewed = reviewed
        )
    }

    /**
     * Caches a single remote prediction.
     */
    private suspend fun cachePrediction(
        prediction: ThreatPredictionDto
    ) {

        threatPredictionDao.insertOrUpdate(
            prediction.toEntity()
        )
    }

    /**
     * Caches multiple remote predictions.
     */
    private suspend fun cachePredictions(
        predictions: List<ThreatPredictionDto>
    ) {

        if (predictions.isEmpty()) {
            return
        }

        threatPredictionDao.insertOrUpdateAll(
            predictions.map {
                it.toEntity()
            }
        )
    }

    /**
     * Converts infrastructure-level exceptions into
     * SentriX application exceptions.
     */
    private fun mapPredictionException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * DNS, timeout, socket and connectivity failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX threat-prediction service.",
                    cause = exception
                )
            }

            /**
             * HTTP-level backend failures.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The threat-prediction request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access threat predictions."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested threat prediction was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Threat prediction synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Threat prediction request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX threat-prediction service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Threat prediction request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Already translated exceptions.
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
                    message = "An unexpected threat-prediction repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
