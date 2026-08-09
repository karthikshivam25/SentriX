package com.sentrix.data.repository.threads

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ThreatIntelDao
import com.sentrix.data.local.entities.ThreatIntelEntity
import com.sentrix.data.remote.api.ThreatApiService
import com.sentrix.data.remote.dto.ThreatIntelDto
import com.sentrix.domain.models.ThreatIntel
import com.sentrix.domain.repository.ThreatIntelRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat Intelligence Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.threads
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Provides the concrete Data-layer implementation of the
 * ThreatIntelRepository.
 *
 * Threat intelligence represents externally sourced security
 * knowledge used by SentriX to identify potentially malicious
 * activity.
 *
 * Examples:
 *
 * - Malicious URLs
 * - Malicious domains
 * - Suspicious IP addresses
 * - File hashes
 * - Malware indicators
 * - Phishing indicators
 * - Scam indicators
 * - Threat actors
 * - Campaign information
 * - IOC (Indicator of Compromise) information
 * - Threat signatures
 * - Intelligence confidence
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *    │
 *    ▼
 * ThreatIntelRepository
 *    │
 *    ▼
 * ThreatIntelRepositoryImpl
 *    │
 *    ├──────────────► ThreatApiService
 *    │                     │
 *    │                     ▼
 *    │                ThreatIntelDto
 *    │
 *    └──────────────► ThreatIntelDao
 *                          │
 *                          ▼
 *                    ThreatIntelEntity
 *
 * Important:
 * ------------------------------------------------------------
 * This repository does NOT perform threat analysis.
 *
 * It only retrieves, stores and manages threat intelligence.
 *
 * Analysis belongs to components such as:
 *
 * - ThreatAnalysisService
 * - URLFilteringService
 * - MalwareAnalysisService
 * - ThreatPredictionService
 * - CyberDefenseService
 * - RiskScoringService
 *
 * Security:
 * ------------------------------------------------------------
 * Threat intelligence may contain externally supplied data.
 *
 * The repository must treat remote intelligence as untrusted
 * input and should not execute or interpret it as code.
 */
@Singleton
class ThreatIntelRepositoryImpl @Inject constructor(
    private val threatApiService: ThreatApiService,
    private val threatIntelDao: ThreatIntelDao
) : ThreatIntelRepository {

    /**
     * Retrieves the latest threat-intelligence feed.
     *
     * Successful remote results are stored locally so that
     * SentriX can continue performing security decisions when
     * the device temporarily loses connectivity.
     */
    override suspend fun getThreatIntelligence(): Result<List<ThreatIntel>> {

        return try {

            /**
             * Request the latest intelligence from the backend.
             */
            val response =
                threatApiService.getThreatIntelligence()

            /**
             * Convert DTOs into Domain models.
             */
            val intelligence = response.map {
                it.toDomain()
            }

            /**
             * Update local intelligence cache.
             */
            cacheIntelligence(response)

            Result.success(intelligence)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves a specific intelligence record.
     */
    override suspend fun getThreatIntelById(
        intelId: String
    ): Result<ThreatIntel?> {

        return try {

            if (intelId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat intelligence ID cannot be blank."
                    )
                )
            }

            /**
             * Local-first lookup.
             */
            val cached =
                threatIntelDao.getById(intelId)

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * Fall back to the remote intelligence service.
             */
            val response =
                threatApiService.getThreatIntelligenceById(
                    intelId
                )

            /**
             * Cache the result.
             */
            cacheIntelligence(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Searches threat intelligence using a generic query.
     *
     * Query examples:
     *
     * - Domain
     * - URL
     * - IP
     * - Hash
     * - Threat name
     * - Campaign
     * - Malware family
     */
    override suspend fun searchThreatIntelligence(
        query: String
    ): Result<List<ThreatIntel>> {

        return try {

            if (query.isBlank()) {
                return Result.success(emptyList())
            }

            val response =
                threatApiService.searchThreatIntelligence(
                    query
                )

            val intelligence =
                response.map {
                    it.toDomain()
                }

            cacheIntelligence(response)

            Result.success(intelligence)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Looks up an indicator of compromise.
     *
     * Indicator types may include:
     *
     * URL
     * DOMAIN
     * IP
     * FILE_HASH
     * CERTIFICATE
     * EMAIL
     *
     * The actual supported types are controlled by the
     * SentriX backend and Domain layer.
     */
    override suspend fun lookupIndicator(
        indicator: String
    ): Result<ThreatIntel?> {

        return try {

            if (indicator.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat indicator cannot be blank."
                    )
                )
            }

            /**
             * Search the local intelligence database first.
             */
            val cached =
                threatIntelDao.findByIndicator(
                    indicator
                )

            if (cached != null) {
                return Result.success(
                    cached.toDomain()
                )
            }

            /**
             * Perform remote lookup when no local result exists.
             */
            val response =
                threatApiService.lookupThreatIndicator(
                    indicator
                )

            if (response != null) {
                cacheIntelligence(response)
            }

            Result.success(
                response?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves intelligence associated with a specific
     * threat.
     */
    override suspend fun getIntelligenceForThreat(
        threatId: String
    ): Result<List<ThreatIntel>> {

        return try {

            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            val entities =
                threatIntelDao.getByThreatId(
                    threatId
                )

            /**
             * Local intelligence is sufficient for this
             * repository operation.
             */
            if (entities.isNotEmpty()) {
                return Result.success(
                    entities.map {
                        it.toDomain()
                    }
                )
            }

            /**
             * Fetch from backend if no cached intelligence
             * exists.
             */
            val response =
                threatApiService.getIntelligenceForThreat(
                    threatId
                )

            cacheIntelligence(response)

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves intelligence by indicator type.
     *
     * Examples:
     *
     * URL
     * DOMAIN
     * IP
     * HASH
     * EMAIL
     */
    override suspend fun getByIndicatorType(
        indicatorType: String
    ): Result<List<ThreatIntel>> {

        return try {

            if (indicatorType.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Indicator type cannot be blank."
                    )
                )
            }

            val entities =
                threatIntelDao.getByIndicatorType(
                    indicatorType
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves intelligence by confidence threshold.
     *
     * Example:
     *
     * 0.90 = 90% confidence
     */
    override suspend fun getHighConfidenceIntelligence(
        minimumConfidence: Double
    ): Result<List<ThreatIntel>> {

        return try {

            if (minimumConfidence !in 0.0..1.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Confidence must be between 0.0 and 1.0."
                    )
                )
            }

            val entities =
                threatIntelDao.getAboveConfidence(
                    minimumConfidence
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves intelligence belonging to a specific
     * threat category.
     *
     * Examples:
     *
     * MALWARE
     * PHISHING
     * SCAM
     * SPYWARE
     * RANSOMWARE
     * TROJAN
     * NETWORK
     */
    override suspend fun getByCategory(
        category: String
    ): Result<List<ThreatIntel>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat intelligence category cannot be blank."
                    )
                )
            }

            val entities =
                threatIntelDao.getByCategory(
                    category
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Retrieves intelligence generated or updated after
     * a specific timestamp.
     *
     * This is useful for incremental synchronization.
     */
    override suspend fun getUpdatedSince(
        timestamp: Long
    ): Result<List<ThreatIntel>> {

        return try {

            val response =
                threatApiService.getThreatIntelligenceUpdatedSince(
                    timestamp
                )

            cacheIntelligence(response)

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Saves a single intelligence record locally.
     *
     * Used when intelligence is generated or received by
     * another SentriX subsystem.
     */
    override suspend fun saveIntelligence(
        intelligence: ThreatIntel
    ): Result<Unit> {

        return try {

            threatIntelDao.insertOrUpdate(
                intelligence.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Saves multiple intelligence records.
     *
     * Bulk operations are preferred for large threat-feed
     * synchronization.
     */
    override suspend fun saveIntelligenceBatch(
        intelligence: List<ThreatIntel>
    ): Result<Unit> {

        return try {

            if (intelligence.isEmpty()) {
                return Result.success(Unit)
            }

            threatIntelDao.insertOrUpdateAll(
                intelligence.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Synchronizes the complete threat-intelligence feed.
     */
    override suspend fun synchronizeThreatIntelligence(): Result<Unit> {

        return try {

            val response =
                threatApiService.getThreatIntelligence()

            if (response.isNotEmpty()) {

                threatIntelDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Removes intelligence records older than the supplied
     * timestamp.
     *
     * Retention should be controlled by SentriX security
     * configuration.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            threatIntelDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Deletes a specific intelligence record.
     */
    override suspend fun deleteIntelligence(
        intelId: String
    ): Result<Unit> {

        return try {

            if (intelId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat intelligence ID cannot be blank."
                    )
                )
            }

            threatIntelDao.deleteById(
                intelId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Clears locally cached threat intelligence.
     *
     * This should be used only when a full intelligence reset
     * is explicitly required.
     */
    override suspend fun clearIntelligenceCache(): Result<Unit> {

        return try {

            threatIntelDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored intelligence
     * records.
     */
    override suspend fun getIntelligenceCount(): Result<Int> {

        return try {

            Result.success(
                threatIntelDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatIntelException(exception)
            )
        }
    }

    /**
     * Converts remote ThreatIntelDto into the Domain model.
     */
    private fun ThreatIntelDto.toDomain(): ThreatIntel {

        return ThreatIntel(
            id = id,
            threatId = threatId,
            indicator = indicator,
            indicatorType = indicatorType,
            category = category,
            severity = severity,
            confidenceScore = confidenceScore,
            source = source,
            description = description,
            firstSeenAt = firstSeenAt,
            lastSeenAt = lastSeenAt,
            expiresAt = expiresAt
        )
    }

    /**
     * Converts remote DTO into a Room entity.
     */
    private fun ThreatIntelDto.toEntity(): ThreatIntelEntity {

        return ThreatIntelEntity(
            id = id,
            threatId = threatId,
            indicator = indicator,
            indicatorType = indicatorType,
            category = category,
            severity = severity,
            confidenceScore = confidenceScore,
            source = source,
            description = description,
            firstSeenAt = firstSeenAt,
            lastSeenAt = lastSeenAt,
            expiresAt = expiresAt
        )
    }

    /**
     * Converts Domain model into Room entity.
     */
    private fun ThreatIntel.toEntity(): ThreatIntelEntity {

        return ThreatIntelEntity(
            id = id,
            threatId = threatId,
            indicator = indicator,
            indicatorType = indicatorType,
            category = category,
            severity = severity,
            confidenceScore = confidenceScore,
            source = source,
            description = description,
            firstSeenAt = firstSeenAt,
            lastSeenAt = lastSeenAt,
            expiresAt = expiresAt
        )
    }

    /**
     * Converts Room entity into Domain model.
     */
    private fun ThreatIntelEntity.toDomain(): ThreatIntel {

        return ThreatIntel(
            id = id,
            threatId = threatId,
            indicator = indicator,
            indicatorType = indicatorType,
            category = category,
            severity = severity,
            confidenceScore = confidenceScore,
            source = source,
            description = description,
            firstSeenAt = firstSeenAt,
            lastSeenAt = lastSeenAt,
            expiresAt = expiresAt
        )
    }

    /**
     * Stores a single remote intelligence DTO.
     */
    private suspend fun cacheIntelligence(
        intelligence: ThreatIntelDto
    ) {

        threatIntelDao.insertOrUpdate(
            intelligence.toEntity()
        )
    }

    /**
     * Stores multiple remote intelligence DTOs.
     */
    private suspend fun cacheIntelligence(
        intelligence: List<ThreatIntelDto>
    ) {

        if (intelligence.isEmpty()) {
            return
        }

        threatIntelDao.insertOrUpdateAll(
            intelligence.map {
                it.toEntity()
            }
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapThreatIntelException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * DNS, timeout, socket and connectivity errors.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX threat-intelligence service.",
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
                            "The threat-intelligence request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access threat intelligence."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested threat-intelligence record was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Threat-intelligence synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Threat-intelligence request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX threat-intelligence service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Threat-intelligence request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected threat-intelligence repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
