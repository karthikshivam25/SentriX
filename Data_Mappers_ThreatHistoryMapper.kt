package com.sentrix.data.mappers

import com.sentrix.data.dto.ThreatHistoryDto
import com.sentrix.data.local.entities.ThreatHistoryEntity
import com.sentrix.domain.models.ThreatHistory

/**
 * SentriX - Threat History Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts threat-history objects between:
 *
 * - Remote API DTOs.
 * - Domain models.
 * - Local Room entities.
 *
 * Supported conversions:
 *
 * ThreatHistoryDto
 *        │
 *        ▼
 * ThreatHistory
 *
 * ThreatHistoryEntity
 *        │
 *        ▼
 * ThreatHistory
 *
 * ThreatHistory
 *        ├──► ThreatHistoryDto
 *        └──► ThreatHistoryEntity
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The Domain layer must not depend on:
 *
 * - Retrofit DTOs.
 * - Room entities.
 * - JSON serialization.
 * - Database implementation details.
 * - API response structures.
 *
 * This mapper keeps those concerns inside the Data layer.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper does NOT:
 *
 * - Analyze threats.
 * - Calculate threat severity.
 * - Predict threats.
 * - Calculate risk.
 * - Modify threat intelligence.
 * - Access the database.
 * - Perform API calls.
 *
 * It only converts data representations.
 *
 * Security Principle:
 * ------------------------------------------------------------
 * Historical security information must be transferred
 * faithfully without silently changing its security meaning.
 */
object ThreatHistoryMapper {

    // -------------------------------------------------------------------------
    // DTO -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote ThreatHistoryDto into the Domain
     * ThreatHistory model.
     *
     * Used when threat-history information is received from
     * the SentriX backend.
     */
    fun ThreatHistoryDto.toDomain():
        ThreatHistory {

        return ThreatHistory(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain ThreatHistory model into a remote
     * ThreatHistoryDto.
     *
     * Used when threat-history data needs to be synchronized
     * with the SentriX backend.
     */
    fun ThreatHistory.toDto():
        ThreatHistoryDto {

        return ThreatHistoryDto(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room ThreatHistoryEntity into the
     * Domain ThreatHistory model.
     *
     * Used by ThreatHistoryRepositoryImpl when reading
     * historical threat information from Room.
     */
    fun ThreatHistoryEntity.toDomain():
        ThreatHistory {

        return ThreatHistory(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain ThreatHistory model into a local
     * Room ThreatHistoryEntity.
     *
     * Used before inserting or updating threat-history
     * information in the local database.
     */
    fun ThreatHistory.toEntity():
        ThreatHistoryEntity {

        return ThreatHistoryEntity(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote ThreatHistoryDto directly into a
     * local Room entity.
     *
     * Useful when synchronizing backend threat history into
     * the local database.
     */
    fun ThreatHistoryDto.toEntity():
        ThreatHistoryEntity {

        return ThreatHistoryEntity(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local ThreatHistoryEntity into a remote
     * ThreatHistoryDto.
     *
     * Useful when local threat-history information must be
     * synchronized with the backend.
     */
    fun ThreatHistoryEntity.toDto():
        ThreatHistoryDto {

        return ThreatHistoryDto(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of remote DTOs into Domain models.
     */
    fun List<ThreatHistoryDto>.toDomainList():
        List<ThreatHistory> {

        return map(
            ThreatHistoryDto::toDomain
        )
    }

    /**
     * Converts a list of Domain models into remote DTOs.
     */
    fun List<ThreatHistory>.toDtoList():
        List<ThreatHistoryDto> {

        return map(
            ThreatHistory::toDto
        )
    }

    /**
     * Converts a list of local entities into Domain models.
     */
    fun List<ThreatHistoryEntity>.toDomainList():
        List<ThreatHistory> {

        return map(
            ThreatHistoryEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain models into Room entities.
     */
    fun List<ThreatHistory>.toEntityList():
        List<ThreatHistoryEntity> {

        return map(
            ThreatHistory::toEntity
        )
    }

    /**
     * Converts a list of DTOs into Room entities.
     */
    fun List<ThreatHistoryDto>.toEntityList():
        List<ThreatHistoryEntity> {

        return map(
            ThreatHistoryDto::toEntity
        )
    }

    /**
     * Converts a list of Room entities into DTOs.
     */
    fun List<ThreatHistoryEntity>.toDtoList():
        List<ThreatHistoryDto> {

        return map(
            ThreatHistoryEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts a nullable DTO into a Domain model.
     */
    fun ThreatHistoryDto?.toDomainOrNull():
        ThreatHistory? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain model into a DTO.
     */
    fun ThreatHistory?.toDtoOrNull():
        ThreatHistoryDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable Entity into a Domain model.
     */
    fun ThreatHistoryEntity?.toDomainOrNull():
        ThreatHistory? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain model into an Entity.
     */
    fun ThreatHistory?.toEntityOrNull():
        ThreatHistoryEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Update Existing Entity
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Room entity using a Domain
     * ThreatHistory object.
     *
     * copy() preserves persistence-specific fields that may
     * exist on the Entity but are not part of the Domain model.
     */
    fun ThreatHistory.updateEntity(
        existingEntity: ThreatHistoryEntity
    ): ThreatHistoryEntity {

        return existingEntity.copy(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Update Existing Domain Model
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Domain ThreatHistory using values
     * from a local Room entity.
     */
    fun ThreatHistoryEntity.updateDomain(
        existingHistory: ThreatHistory
    ): ThreatHistory {

        return existingHistory.copy(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // DTO Merge
    // -------------------------------------------------------------------------

    /**
     * Merges a remote DTO into an existing Domain history
     * object.
     *
     * Useful during synchronization when the Domain object
     * may already contain information that is not represented
     * by the remote response.
     */
    fun ThreatHistoryDto.mergeInto(
        existingHistory: ThreatHistory
    ): ThreatHistory {

        return existingHistory.copy(
            id = id,
            threatId = threatId,
            threatName = threatName,
            threatType = threatType,
            severity = severity,
            status = status,
            action = action,
            description = description,
            source = source,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Threat-Specific History Helpers
    // -------------------------------------------------------------------------

    /**
     * Converts history records belonging to a particular
     * threat into Domain models.
     *
     * Filtering is intentionally kept simple. More complex
     * filtering rules should remain in the Repository or
     * Domain layer.
     */
    fun List<ThreatHistoryEntity>.toDomainForThreat(
        threatId: String
    ): List<ThreatHistory> {

        if (threatId.isBlank()) {
            return emptyList()
        }

        return filter {
            it.threatId == threatId
        }.map {
            it.toDomain()
        }
    }

    /**
     * Converts history records belonging to a particular
     * threat into DTOs.
     */
    fun List<ThreatHistory>.toDtoForThreat(
        threatId: String
    ): List<ThreatHistoryDto> {

        if (threatId.isBlank()) {
            return emptyList()
        }

        return filter {
            it.threatId == threatId
        }.map {
            it.toDto()
        }
    }
}
