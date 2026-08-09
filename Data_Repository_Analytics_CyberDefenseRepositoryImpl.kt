package com.sentrix.data.repository.analytics

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.CyberDefenseDao
import com.sentrix.data.local.entities.CyberDefenseEntity
import com.sentrix.data.remote.api.SecurityApiService
import com.sentrix.data.remote.dto.CyberDefenseDto
import com.sentrix.domain.models.CyberDefenseProfile
import com.sentrix.domain.repository.CyberDefenseRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Cyber Defense Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.analytics
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * CyberDefenseRepository.
 *
 * This repository manages the persisted and remote state of
 * SentriX cyber-defense capabilities.
 *
 * Cyber-defense information may include:
 *
 * - Overall defense status.
 * - Real-time protection state.
 * - Web protection state.
 * - Download protection state.
 * - Network protection state.
 * - Phishing protection state.
 * - Malware protection state.
 * - Scam protection state.
 * - Privacy protection state.
 * - Threat blocking state.
 * - Number of blocked threats.
 * - Number of prevented attacks.
 * - Active defense events.
 * - Last defense action.
 * - Last threat blocked timestamp.
 * - Protection configuration state.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT decide:
 *
 * - Whether a threat should be blocked.
 * - Which defensive action should be executed.
 * - Whether a URL is malicious.
 * - Whether an application is dangerous.
 * - How a threat is scored.
 *
 * Those responsibilities belong to Domain-layer services,
 * rules and engines.
 *
 * This repository is responsible for:
 *
 * - Reading defense state.
 * - Persisting defense state.
 * - Updating defense state.
 * - Retrieving defense history.
 * - Synchronizing with backend.
 * - Mapping DTO <-> Domain.
 * - Mapping Entity <-> Domain.
 * - Translating infrastructure exceptions.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * CyberDefenseRepository
 *    │
 *    ▼
 * CyberDefenseRepositoryImpl
 *    │
 *    ├──────────────► CyberDefenseDao
 *    │                     │
 *    │                     ▼
 *    │              CyberDefenseEntity
 *    │
 *    └──────────────► SecurityApiService
 *                          │
 *                          ▼
 *                    CyberDefenseDto
 */
@Singleton
class CyberDefenseRepositoryImpl @Inject constructor(
    private val cyberDefenseDao: CyberDefenseDao,
    private val securityApiService: SecurityApiService
) : CyberDefenseRepository {

    /**
     * Retrieves the current cyber-defense profile.
     *
     * Local state is used so SentriX can display protection
     * status even when the device is offline.
     */
    override suspend fun getDefenseProfile():
        Result<CyberDefenseProfile?> {

        return try {

            val entity =
                cyberDefenseDao.getLatestProfile()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the latest cyber-defense profile from the
     * remote SentriX backend.
     *
     * The returned state is cached locally.
     */
    override suspend fun refreshDefenseProfile():
        Result<CyberDefenseProfile> {

        return try {

            val response =
                securityApiService.getCyberDefenseProfile()

            cyberDefenseDao.insertOrUpdate(
                response.toEntity()
            )

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves a cyber-defense profile by its unique ID.
     */
    override suspend fun getDefenseProfileById(
        profileId: String
    ): Result<CyberDefenseProfile?> {

        return try {

            if (profileId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Cyber-defense profile ID cannot be blank."
                    )
                )
            }

            val entity =
                cyberDefenseDao.getById(profileId)

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves historical cyber-defense states.
     *
     * Useful for protection-status history and security
     * reporting.
     */
    override suspend fun getDefenseHistory(
        limit: Int
    ): Result<List<CyberDefenseProfile>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Defense history limit must be greater than zero."
                    )
                )
            }

            val entities =
                cyberDefenseDao.getRecentProfiles(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves cyber-defense states within a time range.
     */
    override suspend fun getDefenseHistoryBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<CyberDefenseProfile>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                cyberDefenseDao.getProfilesBetween(
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
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current real-time protection state.
     */
    override suspend fun isRealTimeProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isRealTimeProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current web protection state.
     */
    override suspend fun isWebProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isWebProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current download protection state.
     */
    override suspend fun isDownloadProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isDownloadProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current network protection state.
     */
    override suspend fun isNetworkProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isNetworkProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current phishing protection state.
     */
    override suspend fun isPhishingProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isPhishingProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current malware protection state.
     */
    override suspend fun isMalwareProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isMalwareProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the current privacy protection state.
     */
    override suspend fun isPrivacyProtectionEnabled():
        Result<Boolean> {

        return try {

            Result.success(
                cyberDefenseDao.isPrivacyProtectionEnabled()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Saves a cyber-defense profile locally.
     *
     * Used when local protection configuration or defense
     * state changes.
     */
    override suspend fun saveDefenseProfile(
        profile: CyberDefenseProfile
    ): Result<Unit> {

        return try {

            cyberDefenseDao.insertOrUpdate(
                profile.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Saves multiple cyber-defense profiles.
     */
    override suspend fun saveDefenseProfiles(
        profiles: List<CyberDefenseProfile>
    ): Result<Unit> {

        return try {

            if (profiles.isEmpty()) {
                return Result.success(Unit)
            }

            cyberDefenseDao.insertOrUpdateAll(
                profiles.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates the real-time protection state.
     */
    override suspend fun updateRealTimeProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updateRealTimeProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates web protection state.
     */
    override suspend fun updateWebProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updateWebProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates download protection state.
     */
    override suspend fun updateDownloadProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updateDownloadProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates network protection state.
     */
    override suspend fun updateNetworkProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updateNetworkProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates phishing protection state.
     */
    override suspend fun updatePhishingProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updatePhishingProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates malware protection state.
     */
    override suspend fun updateMalwareProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updateMalwareProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Updates privacy protection state.
     */
    override suspend fun updatePrivacyProtection(
        enabled: Boolean
    ): Result<Unit> {

        return try {

            cyberDefenseDao.updatePrivacyProtection(
                enabled
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Records a blocked threat.
     *
     * The repository only records the defensive outcome.
     * The actual blocking decision belongs to the Domain/security
     * engine.
     */
    override suspend fun recordBlockedThreat():
        Result<Unit> {

        return try {

            cyberDefenseDao.incrementBlockedThreats()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Records a prevented attack.
     */
    override suspend fun recordPreventedAttack():
        Result<Unit> {

        return try {

            cyberDefenseDao.incrementPreventedAttacks()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of blocked threats.
     */
    override suspend fun getBlockedThreatCount():
        Result<Int> {

        return try {

            Result.success(
                cyberDefenseDao.getBlockedThreatCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the total number of prevented attacks.
     */
    override suspend fun getPreventedAttackCount():
        Result<Int> {

        return try {

            Result.success(
                cyberDefenseDao.getPreventedAttackCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the timestamp of the last blocked threat.
     */
    override suspend fun getLastDefenseEventTime():
        Result<Long?> {

        return try {

            Result.success(
                cyberDefenseDao.getLastDefenseEventTime()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves the latest cyber-defense profile from the
     * remote backend and stores it locally.
     */
    override suspend fun synchronizeDefenseProfile():
        Result<Unit> {

        return try {

            val response =
                securityApiService.getCyberDefenseProfile()

            cyberDefenseDao.insertOrUpdate(
                response.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Retrieves defense states generated since a specific
     * timestamp.
     *
     * This supports incremental synchronization.
     */
    override suspend fun getDefenseProfilesSince(
        timestamp: Long
    ): Result<List<CyberDefenseProfile>> {

        return try {

            val response =
                securityApiService.getCyberDefenseHistorySince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                cyberDefenseDao.insertOrUpdateAll(
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
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Synchronizes complete cyber-defense history.
     */
    override suspend fun synchronizeDefenseHistory():
        Result<Unit> {

        return try {

            val response =
                securityApiService.getCyberDefenseHistory()

            if (response.isNotEmpty()) {

                cyberDefenseDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Deletes old cyber-defense history.
     *
     * Retention policy should be controlled by the appropriate
     * SentriX privacy/security policy.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            cyberDefenseDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Deletes a specific cyber-defense profile.
     */
    override suspend fun deleteDefenseProfile(
        profileId: String
    ): Result<Unit> {

        return try {

            if (profileId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Cyber-defense profile ID cannot be blank."
                    )
                )
            }

            cyberDefenseDao.deleteById(
                profileId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Clears locally stored cyber-defense information.
     */
    override suspend fun clearDefenseData():
        Result<Unit> {

        return try {

            cyberDefenseDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored defense profiles.
     */
    override suspend fun getDefenseProfileCount():
        Result<Int> {

        return try {

            Result.success(
                cyberDefenseDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapCyberDefenseException(exception)
            )
        }
    }

    /**
     * Converts remote CyberDefenseDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun CyberDefenseDto.toDomain():
        CyberDefenseProfile {

        return CyberDefenseProfile(
            profileId = profileId,
            timestamp = timestamp,
            enabled = enabled,
            realTimeProtectionEnabled =
                realTimeProtectionEnabled,
            webProtectionEnabled =
                webProtectionEnabled,
            downloadProtectionEnabled =
                downloadProtectionEnabled,
            networkProtectionEnabled =
                networkProtectionEnabled,
            phishingProtectionEnabled =
                phishingProtectionEnabled,
            malwareProtectionEnabled =
                malwareProtectionEnabled,
            privacyProtectionEnabled =
                privacyProtectionEnabled,
            blockedThreats =
                blockedThreats,
            preventedAttacks =
                preventedAttacks,
            lastDefenseEventTime =
                lastDefenseEventTime
        )
    }

    /**
     * Converts remote CyberDefenseDto into Room entity.
     *
     * DTO -> Entity
     */
    private fun CyberDefenseDto.toEntity():
        CyberDefenseEntity {

        return CyberDefenseEntity(
            profileId = profileId,
            timestamp = timestamp,
            enabled = enabled,
            realTimeProtectionEnabled =
                realTimeProtectionEnabled,
            webProtectionEnabled =
                webProtectionEnabled,
            downloadProtectionEnabled =
                downloadProtectionEnabled,
            networkProtectionEnabled =
                networkProtectionEnabled,
            phishingProtectionEnabled =
                phishingProtectionEnabled,
            malwareProtectionEnabled =
                malwareProtectionEnabled,
            privacyProtectionEnabled =
                privacyProtectionEnabled,
            blockedThreats =
                blockedThreats,
            preventedAttacks =
                preventedAttacks,
            lastDefenseEventTime =
                lastDefenseEventTime
        )
    }

    /**
     * Converts Domain CyberDefenseProfile into Room entity.
     *
     * Domain -> Entity
     */
    private fun CyberDefenseProfile.toEntity():
        CyberDefenseEntity {

        return CyberDefenseEntity(
            profileId = profileId,
            timestamp = timestamp,
            enabled = enabled,
            realTimeProtectionEnabled =
                realTimeProtectionEnabled,
            webProtectionEnabled =
                webProtectionEnabled,
            downloadProtectionEnabled =
                downloadProtectionEnabled,
            networkProtectionEnabled =
                networkProtectionEnabled,
            phishingProtectionEnabled =
                phishingProtectionEnabled,
            malwareProtectionEnabled =
                malwareProtectionEnabled,
            privacyProtectionEnabled =
                privacyProtectionEnabled,
            blockedThreats =
                blockedThreats,
            preventedAttacks =
                preventedAttacks,
            lastDefenseEventTime =
                lastDefenseEventTime
        )
    }

    /**
     * Converts Room entity into Domain model.
     *
     * Entity -> Domain
     */
    private fun CyberDefenseEntity.toDomain():
        CyberDefenseProfile {

        return CyberDefenseProfile(
            profileId = profileId,
            timestamp = timestamp,
            enabled = enabled,
            realTimeProtectionEnabled =
                realTimeProtectionEnabled,
            webProtectionEnabled =
                webProtectionEnabled,
            downloadProtectionEnabled =
                downloadProtectionEnabled,
            networkProtectionEnabled =
                networkProtectionEnabled,
            phishingProtectionEnabled =
                phishingProtectionEnabled,
            malwareProtectionEnabled =
                malwareProtectionEnabled,
            privacyProtectionEnabled =
                privacyProtectionEnabled,
            blockedThreats =
                blockedThreats,
            preventedAttacks =
                preventedAttacks,
            lastDefenseEventTime =
                lastDefenseEventTime
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapCyberDefenseException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX cyber-defense service.",
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
                            "The cyber-defense request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access cyber-defense data."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested cyber-defense data was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Cyber-defense synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Cyber-defense request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX cyber-defense service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Cyber-defense request failed with HTTP ${exception.code()}."
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
                    message = "An unexpected cyber-defense repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
