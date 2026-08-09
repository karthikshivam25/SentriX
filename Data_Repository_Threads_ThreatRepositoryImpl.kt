package com.sentrix.data.repository.threads

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.ThreatDao
import com.sentrix.data.local.entities.ThreatEntity
import com.sentrix.data.remote.api.ThreatApiService
import com.sentrix.data.remote.dto.ThreatDto
import com.sentrix.domain.models.Threat
import com.sentrix.domain.repository.ThreatRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.threads
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of ThreatRepository.
 *
 * This repository acts as the bridge between:
 *
 * Domain Layer
 *       │
 *       ▼
 * ThreatRepository
 *       │
 *       ▼
 * ThreatRepositoryImpl
 *       │
 *       ├──────────────► ThreatApiService
 *       │                     │
 *       │                     ▼
 *       │                 ThreatDto
 *       │
 *       └──────────────► ThreatDao
 *                             │
 *                             ▼
 *                         ThreatEntity
 *
 * Responsibilities:
 * ------------------------------------------------------------
 * - Retrieve threats from the backend.
 * - Retrieve a specific threat.
 * - Cache threats locally.
 * - Retrieve cached threats.
 * - Search cached/remote threats.
 * - Update threat information.
 * - Delete stale local threat information.
 * - Convert DTO -> Domain.
 * - Convert Entity -> Domain.
 * - Convert Domain -> Entity.
 * - Translate infrastructure exceptions.
 *
 * Security responsibilities:
 * ------------------------------------------------------------
 * This repository does NOT:
 *
 * - Perform authentication.
 * - Manage access tokens.
 * - Store passwords.
 * - Analyze malware directly.
 * - Calculate threat scores directly.
 * - Perform threat prediction directly.
 *
 * Those responsibilities belong to their respective
 * SentriX Domain services/use cases.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The repository implementation belongs to Data.
 *
 * Domain depends only on the repository interface.
 *
 * Retrofit and Room implementation details never leak into
 * the Domain layer.
 */
@Singleton
class ThreatRepositoryImpl @Inject constructor(
    private val threatApiService: ThreatApiService,
    private val threatDao: ThreatDao
) : ThreatRepository {

    /**
     * Retrieves all currently available threats from the
     * SentriX threat-intelligence backend.
     *
     * Remote data is also cached locally after a successful
     * response.
     */
    override suspend fun getThreats(): Result<List<Threat>> {

        return try {

            /**
             * Request current threat intelligence from the
             * SentriX backend.
             */
            val response = threatApiService.getThreats()

            /**
             * Convert every DTO into a Domain model.
             */
            val threats = response.map {
                it.toDomain()
            }

            /**
             * Update local cache.
             *
             * This allows SentriX to continue displaying threat
             * intelligence when the device temporarily loses
             * network connectivity.
             */
            cacheThreats(response)

            Result.success(threats)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Retrieves a specific threat using its unique identifier.
     */
    override suspend fun getThreatById(
        threatId: String
    ): Result<Threat?> {

        return try {

            /**
             * Reject invalid identifiers before making a
             * network/database operation.
             */
            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            val response =
                threatApiService.getThreatById(threatId)

            val threat = response.toDomain()

            /**
             * Cache the latest threat information.
             */
            cacheThreat(response)

            Result.success(threat)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Retrieves a threat from the local database.
     *
     * This operation does not require an internet connection.
     */
    override suspend fun getCachedThreatById(
        threatId: String
    ): Result<Threat?> {

        return try {

            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            val entity =
                threatDao.getThreatById(threatId)

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Retrieves all locally cached threats.
     *
     * Useful for:
     *
     * - Offline threat history.
     * - Dashboard summaries.
     * - Threat intelligence cache.
     * - Recently detected threats.
     */
    override suspend fun getCachedThreats(): Result<List<Threat>> {

        return try {

            val entities =
                threatDao.getAllThreats()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Searches the SentriX threat database.
     *
     * The actual search implementation remains inside the
     * remote API service.
     */
    override suspend fun searchThreats(
        query: String
    ): Result<List<Threat>> {

        return try {

            if (query.isBlank()) {
                return Result.success(emptyList())
            }

            val response =
                threatApiService.searchThreats(query)

            val threats = response.map {
                it.toDomain()
            }

            /**
             * Cache search results so recently discovered threat
             * information remains available locally.
             */
            cacheThreats(response)

            Result.success(threats)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Retrieves threats associated with a specific severity.
     *
     * Example severity values:
     *
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     */
    override suspend fun getThreatsBySeverity(
        severity: String
    ): Result<List<Threat>> {

        return try {

            if (severity.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat severity cannot be blank."
                    )
                )
            }

            val response =
                threatApiService.getThreatsBySeverity(
                    severity = severity
                )

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Retrieves threats belonging to a particular category.
     *
     * Examples:
     *
     * - PHISHING
     * - MALWARE
     * - RANSOMWARE
     * - SPYWARE
     * - TROJAN
     * - SCAM
     * - NETWORK
     */
    override suspend fun getThreatsByCategory(
        category: String
    ): Result<List<Threat>> {

        return try {

            if (category.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat category cannot be blank."
                    )
                )
            }

            val response =
                threatApiService.getThreatsByCategory(
                    category = category
                )

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Stores a single threat in the local cache.
     *
     * This method can be used by threat-analysis components
     * when they discover a new threat.
     */
    override suspend fun cacheThreat(
        threat: Threat
    ): Result<Unit> {

        return try {

            threatDao.insertOrUpdate(
                threat.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Stores multiple threats in the local database.
     *
     * A bulk operation is preferable when processing a large
     * threat-intelligence response because it minimizes
     * individual database transactions.
     */
    override suspend fun cacheThreats(
        threats: List<Threat>
    ): Result<Unit> {

        return try {

            if (threats.isEmpty()) {
                return Result.success(Unit)
            }

            threatDao.insertOrUpdateAll(
                threats.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Deletes a specific threat from the local cache.
     *
     * This does not delete the threat from the SentriX
     * backend.
     */
    override suspend fun deleteCachedThreat(
        threatId: String
    ): Result<Unit> {

        return try {

            if (threatId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat ID cannot be blank."
                    )
                )
            }

            threatDao.deleteThreatById(
                threatId = threatId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Removes all locally cached threat intelligence.
     *
     * Useful during:
     *
     * - Logout.
     * - Account reset.
     * - Security reset.
     * - Database cleanup.
     * - Cache invalidation.
     */
    override suspend fun clearThreatCache(): Result<Unit> {

        return try {

            threatDao.deleteAllThreats()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Returns the number of locally cached threats.
     */
    override suspend fun getCachedThreatCount(): Result<Int> {

        return try {

            Result.success(
                threatDao.getThreatCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapThreatException(exception)
            )
        }
    }

    /**
     * Converts a ThreatDto into the SentriX Domain Threat model.
     *
     * DTO -> Domain
     *
     * This mapping prevents Retrofit-specific objects from
     * reaching use cases or UI.
     */
    private fun ThreatDto.toDomain(): Threat {

        return Threat(
            id = id,
            name = name,
            description = description,
            severity = severity,
            category = category,
            source = source,
            confidenceScore = confidenceScore,
            detectedAt = detectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Domain Threat into a Room entity.
     *
     * Domain -> Entity
     *
     * This mapping keeps Room implementation details inside
     * the Data layer.
     */
    private fun Threat.toEntity(): ThreatEntity {

        return ThreatEntity(
            id = id,
            name = name,
            description = description,
            severity = severity,
            category = category,
            source = source,
            confidenceScore = confidenceScore,
            detectedAt = detectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Room entity into the Domain Threat model.
     *
     * Entity -> Domain
     */
    private fun ThreatEntity.toDomain(): Threat {

        return Threat(
            id = id,
            name = name,
            description = description,
            severity = severity,
            category = category,
            source = source,
            confidenceScore = confidenceScore,
            detectedAt = detectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a list of remote DTOs into Room entities and
     * updates the local cache.
     */
    private suspend fun cacheThreats(
        threats: List<ThreatDto>
    ) {

        if (threats.isEmpty()) {
            return
        }

        threatDao.insertOrUpdateAll(
            threats.map {
                it.toEntity()
            }
        )
    }

    /**
     * Converts one remote DTO into a local Room entity and
     * stores it.
     */
    private suspend fun cacheThreat(
        threat: ThreatDto
    ) {

        threatDao.insertOrUpdate(
            threat.toEntity()
        )
    }

    /**
     * Converts infrastructure-specific exceptions into
     * SentriX application exceptions.
     *
     * Retrofit, OkHttp and database exceptions must not leak
     * into the Domain layer.
     */
    private fun mapThreatException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * DNS, socket, timeout and other I/O failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX threat service.",
                    cause = exception
                )
            }

            /**
             * HTTP errors returned by the SentriX backend.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The threat request was invalid."
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
                            "The requested threat could not be found."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Threat intelligence request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX threat intelligence service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Threat request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve already translated infrastructure
             * exceptions.
             */
            is NetworkException,
            is ServerException -> {
                exception
            }

            /**
             * Unexpected database or infrastructure error.
             */
            else -> {
                UnknownException(
                    message = "An unexpected threat repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
