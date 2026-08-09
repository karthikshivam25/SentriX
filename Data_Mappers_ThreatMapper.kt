package com.sentrix.data.mappers

import com.sentrix.data.dto.ThreatDto
import com.sentrix.data.local.entities.ThreatEntity
import com.sentrix.domain.models.Threat

/**
 * SentriX - Threat Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts Threat objects between the different architectural
 * layers of the SentriX Data layer.
 *
 * Supported conversions:
 *
 * Remote DTO
 *      │
 *      ▼
 * ThreatDto
 *      │
 *      ▼
 * Threat Domain Model
 *
 * Local Entity
 *      │
 *      ▼
 * Threat Domain Model
 *
 * Domain Model
 *      │
 *      ├──► ThreatDto
 *      │
 *      └──► ThreatEntity
 *
 * Clean Architecture Rule:
 * ------------------------------------------------------------
 * The Domain layer must NOT depend on:
 *
 * - Retrofit DTOs.
 * - Room entities.
 * - JSON models.
 * - Database implementation details.
 *
 * Therefore, all conversion logic is kept here.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper should NOT:
 *
 * - Perform network requests.
 * - Access Room.
 * - Apply business rules.
 * - Calculate threat severity.
 * - Determine whether a threat is malicious.
 * - Modify threat intelligence.
 *
 * It only transforms data representations.
 */
object ThreatMapper {

    // -------------------------------------------------------------------------
    // DTO -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote ThreatDto into the Domain Threat model.
     *
     * This is normally used by repositories after receiving
     * data from the SentriX backend.
     */
    fun ThreatDto.toDomain(): Threat {

        return Threat(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain Threat model into a remote DTO.
     *
     * This is useful when a Threat object needs to be sent
     * back to the SentriX backend.
     */
    fun Threat.toDto(): ThreatDto {

        return ThreatDto(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room ThreatEntity into the Domain
     * Threat model.
     *
     * This is normally used by repositories when reading
     * cached/persisted threat information.
     */
    fun ThreatEntity.toDomain(): Threat {

        return Threat(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain Threat model into a local Room
     * ThreatEntity.
     *
     * This is normally used before inserting or updating
     * threat data in the local database.
     */
    fun Threat.toEntity(): ThreatEntity {

        return ThreatEntity(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote DTO directly into a Room entity.
     *
     * This can be useful when repository code only needs to
     * persist API data locally without first exposing the
     * Domain model.
     */
    fun ThreatDto.toEntity(): ThreatEntity {

        return ThreatEntity(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room entity into the remote DTO.
     *
     * This can be useful when local information needs to be
     * synchronized with the backend.
     */
    fun ThreatEntity.toDto(): ThreatDto {

        return ThreatDto(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of ThreatDto objects into Domain
     * Threat objects.
     */
    fun List<ThreatDto>.toDomainList():
        List<Threat> {

        return map(
            ThreatDto::toDomain
        )
    }

    /**
     * Converts a list of Domain Threat objects into DTOs.
     */
    fun List<Threat>.toDtoList():
        List<ThreatDto> {

        return map(
            Threat::toDto
        )
    }

    /**
     * Converts a list of ThreatEntity objects into Domain
     * Threat objects.
     */
    fun List<ThreatEntity>.toDomainList():
        List<Threat> {

        return map(
            ThreatEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain Threat objects into Room
     * entities.
     */
    fun List<Threat>.toEntityList():
        List<ThreatEntity> {

        return map(
            Threat::toEntity
        )
    }

    /**
     * Converts a list of ThreatDto objects into Room entities.
     */
    fun List<ThreatDto>.toEntityList():
        List<ThreatEntity> {

        return map(
            ThreatDto::toEntity
        )
    }

    /**
     * Converts a list of ThreatEntity objects into DTOs.
     */
    fun List<ThreatEntity>.toDtoList():
        List<ThreatDto> {

        return map(
            ThreatEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts a nullable DTO into a Domain model.
     *
     * Useful for APIs where a threat object may be absent.
     */
    fun ThreatDto?.toDomainOrNull():
        Threat? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain object into a DTO.
     */
    fun Threat?.toDtoOrNull():
        ThreatDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable Entity into a Domain model.
     */
    fun ThreatEntity?.toDomainOrNull():
        Threat? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain object into an Entity.
     */
    fun Threat?.toEntityOrNull():
        ThreatEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Synchronization Helpers
    // -------------------------------------------------------------------------

    /**
     * Creates an updated Entity from a Domain Threat.
     *
     * This method makes the synchronization intent explicit
     * when updating an existing Room record.
     */
    fun Threat.updateEntity(
        existingEntity: ThreatEntity
    ): ThreatEntity {

        return existingEntity.copy(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }

    /**
     * Creates a Domain Threat from an existing Entity while
     * allowing the persisted entity to remain the source of
     * truth for database-specific fields.
     */
    fun ThreatEntity.updateDomain(
        existingThreat: Threat
    ): Threat {

        return existingThreat.copy(
            id = id,
            name = name,
            type = type,
            severity = severity,
            description = description,
            source = source,
            confidence = confidence,
            detectedAt = detectedAt,
            updatedAt = updatedAt,
            isActive = isActive
        )
    }
}
