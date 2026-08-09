package com.sentrix.data.mappers

import com.sentrix.data.dto.ScanResultDto
import com.sentrix.data.local.entities.ScanHistoryEntity
import com.sentrix.domain.models.ScanConfiguration
import com.sentrix.domain.models.ScanResult

/**
 * SentriX - Scan Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts scan-related objects between Domain and Data
 * representations.
 *
 * Main conversions:
 *
 * Remote:
 *
 * ScanResultDto
 *      │
 *      ▼
 * ScanResult
 *
 * Local:
 *
 * ScanHistoryEntity
 *      │
 *      ▼
 * ScanResult
 *
 * Domain:
 *
 * ScanResult
 *      ├──► ScanResultDto
 *      └──► ScanHistoryEntity
 *
 * ScanConfiguration is a Domain configuration model and is
 * also supported for generic Data-layer conversion when the
 * corresponding DTO/entity representations are introduced.
 *
 * Clean Architecture Rule:
 * ------------------------------------------------------------
 * Domain models must not depend on:
 *
 * - Retrofit.
 * - Room.
 * - JSON serialization.
 * - Network response structures.
 * - Database implementation details.
 *
 * This mapper keeps those concerns inside the Data layer.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Execute scans.
 * - Analyze files.
 * - Detect malware.
 * - Calculate threat severity.
 * - Optimize scans.
 * - Make security decisions.
 *
 * It only transforms data representations.
 */
object ScanMapper {

    // -------------------------------------------------------------------------
    // ScanResultDto -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote ScanResultDto into the Domain
     * ScanResult model.
     *
     * Used when a scan result is received from the backend.
     */
    fun ScanResultDto.toDomain(): ScanResult {

        return ScanResult(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> ScanResultDto
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain ScanResult into a remote DTO.
     *
     * Used when a scan result must be synchronized with the
     * SentriX backend.
     */
    fun ScanResult.toDto(): ScanResultDto {

        return ScanResultDto(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // ScanHistoryEntity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room ScanHistoryEntity into the
     * Domain ScanResult model.
     *
     * This is useful when ScanHistoryRepositoryImpl retrieves
     * persisted scan history.
     */
    fun ScanHistoryEntity.toDomain(): ScanResult {

        return ScanResult(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> ScanHistoryEntity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain ScanResult into a local Room
     * ScanHistoryEntity.
     *
     * Used before inserting scan history into the database.
     */
    fun ScanResult.toEntity(): ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote ScanResultDto directly into a local
     * ScanHistoryEntity.
     *
     * Useful when API scan history needs to be persisted
     * without requiring an intermediate Domain object.
     */
    fun ScanResultDto.toEntity(): ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local ScanHistoryEntity into a remote DTO.
     *
     * Useful when local scan history needs to be synchronized
     * with the SentriX backend.
     */
    fun ScanHistoryEntity.toDto(): ScanResultDto {

        return ScanResultDto(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of remote scan-result DTOs into
     * Domain ScanResult objects.
     */
    fun List<ScanResultDto>.toDomainList():
        List<ScanResult> {

        return map(
            ScanResultDto::toDomain
        )
    }

    /**
     * Converts a list of Domain ScanResult objects into
     * remote DTOs.
     */
    fun List<ScanResult>.toDtoList():
        List<ScanResultDto> {

        return map(
            ScanResult::toDto
        )
    }

    /**
     * Converts a list of local scan-history entities into
     * Domain ScanResult objects.
     */
    fun List<ScanHistoryEntity>.toDomainList():
        List<ScanResult> {

        return map(
            ScanHistoryEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain ScanResult objects into
     * Room entities.
     */
    fun List<ScanResult>.toEntityList():
        List<ScanHistoryEntity> {

        return map(
            ScanResult::toEntity
        )
    }

    /**
     * Converts a list of DTOs into Room entities.
     */
    fun List<ScanResultDto>.toEntityList():
        List<ScanHistoryEntity> {

        return map(
            ScanResultDto::toEntity
        )
    }

    /**
     * Converts a list of Room entities into DTOs.
     */
    fun List<ScanHistoryEntity>.toDtoList():
        List<ScanResultDto> {

        return map(
            ScanHistoryEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts a nullable ScanResultDto into a
     * Domain ScanResult.
     */
    fun ScanResultDto?.toDomainOrNull():
        ScanResult? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable ScanResult into a DTO.
     */
    fun ScanResult?.toDtoOrNull():
        ScanResultDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable ScanHistoryEntity into a
     * Domain ScanResult.
     */
    fun ScanHistoryEntity?.toDomainOrNull():
        ScanResult? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable ScanResult into a Room entity.
     */
    fun ScanResult?.toEntityOrNull():
        ScanHistoryEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Update Existing Entity
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Room scan-history entity using
     * values from a Domain ScanResult.
     *
     * Persistence-specific fields from the existing entity
     * are preserved by copy().
     */
    fun ScanResult.updateEntity(
        existingEntity: ScanHistoryEntity
    ): ScanHistoryEntity {

        return existingEntity.copy(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // Update Existing Domain Model
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Domain ScanResult using values
     * from a local ScanHistoryEntity.
     */
    fun ScanHistoryEntity.updateDomain(
        existingResult: ScanResult
    ): ScanResult {

        return existingResult.copy(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }

    // -------------------------------------------------------------------------
    // ScanConfiguration Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates a copy of the scan configuration.
     *
     * This method intentionally does not convert the
     * configuration into a DTO/entity because the existing
     * SentriX Data layer should only introduce those
     * representations when their corresponding models are
     * defined.
     *
     * Keeping this helper here allows repository/application
     * code to work with configuration without adding
     * persistence assumptions.
     */
    fun ScanConfiguration.copyForDataLayer():
        ScanConfiguration {

        return copy()
    }

    // -------------------------------------------------------------------------
    // Scan Result Synchronization
    // -------------------------------------------------------------------------

    /**
     * Creates a Domain ScanResult from a remote DTO while
     * allowing an existing Domain object to retain fields
     * that are not represented by the API response.
     */
    fun ScanResultDto.mergeInto(
        existingResult: ScanResult
    ): ScanResult {

        return existingResult.copy(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            detectedThreats = detectedThreats,
            riskScore = riskScore,
            isSuccessful = isSuccessful
        )
    }
}
