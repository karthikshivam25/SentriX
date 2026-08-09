package com.sentrix.data.mappers

import com.sentrix.data.dto.SecurityMetricsDto
import com.sentrix.data.local.entities.SecurityMetricsEntity
import com.sentrix.domain.models.SecurityMetrics

/**
 * SentriX - Security Metrics Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts security-metrics objects between Data-layer
 * representations and the Domain SecurityMetrics model.
 *
 * Supported conversions:
 *
 * Remote:
 *
 * SecurityMetricsDto
 *        │
 *        ▼
 * SecurityMetrics
 *
 * Local:
 *
 * SecurityMetricsEntity
 *        │
 *        ▼
 * SecurityMetrics
 *
 * Domain:
 *
 * SecurityMetrics
 *        ├──► SecurityMetricsDto
 *        └──► SecurityMetricsEntity
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The Domain layer must remain independent from:
 *
 * - Retrofit DTOs.
 * - Room entities.
 * - JSON serialization.
 * - Database implementation details.
 * - API response structures.
 *
 * This mapper provides the Data-layer boundary.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper does NOT:
 *
 * - Calculate security metrics.
 * - Calculate risk scores.
 * - Calculate security scores.
 * - Analyze threats.
 * - Analyze malware.
 * - Generate recommendations.
 * - Access Room directly.
 * - Perform network requests.
 *
 * It only transforms data.
 *
 * Security Principle:
 * ------------------------------------------------------------
 * Metric values must be transferred exactly as supplied by
 * the source model. A mapper must never silently alter a
 * security-related metric.
 */
object SecurityMetricsMapper {

    // -------------------------------------------------------------------------
    // DTO -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote SecurityMetricsDto into the Domain
     * SecurityMetrics model.
     *
     * Used when security analytics are received from the
     * SentriX backend.
     */
    fun SecurityMetricsDto.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain SecurityMetrics object into a
     * remote SecurityMetricsDto.
     *
     * Used when metrics need to be synchronized with the
     * SentriX backend.
     */
    fun SecurityMetrics.toDto():
        SecurityMetricsDto {

        return SecurityMetricsDto(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room SecurityMetricsEntity into the
     * Domain SecurityMetrics model.
     *
     * Used when SecurityMetricsRepositoryImpl retrieves
     * persisted metrics from Room.
     */
    fun SecurityMetricsEntity.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain SecurityMetrics object into a
     * local Room SecurityMetricsEntity.
     *
     * Used before inserting or updating persisted metrics.
     */
    fun SecurityMetrics.toEntity():
        SecurityMetricsEntity {

        return SecurityMetricsEntity(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote SecurityMetricsDto directly into a
     * local Room SecurityMetricsEntity.
     *
     * Useful during API-to-local synchronization.
     */
    fun SecurityMetricsDto.toEntity():
        SecurityMetricsEntity {

        return SecurityMetricsEntity(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local SecurityMetricsEntity into a remote
     * SecurityMetricsDto.
     *
     * Useful when locally persisted metrics must be
     * synchronized with the backend.
     */
    fun SecurityMetricsEntity.toDto():
        SecurityMetricsDto {

        return SecurityMetricsDto(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of DTOs into Domain metrics.
     */
    fun List<SecurityMetricsDto>.toDomainList():
        List<SecurityMetrics> {

        return map(
            SecurityMetricsDto::toDomain
        )
    }

    /**
     * Converts a list of Domain metrics into DTOs.
     */
    fun List<SecurityMetrics>.toDtoList():
        List<SecurityMetricsDto> {

        return map(
            SecurityMetrics::toDto
        )
    }

    /**
     * Converts a list of local entities into Domain metrics.
     */
    fun List<SecurityMetricsEntity>.toDomainList():
        List<SecurityMetrics> {

        return map(
            SecurityMetricsEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain metrics into Room entities.
     */
    fun List<SecurityMetrics>.toEntityList():
        List<SecurityMetricsEntity> {

        return map(
            SecurityMetrics::toEntity
        )
    }

    /**
     * Converts a list of DTOs into Room entities.
     */
    fun List<SecurityMetricsDto>.toEntityList():
        List<SecurityMetricsEntity> {

        return map(
            SecurityMetricsDto::toEntity
        )
    }

    /**
     * Converts a list of Room entities into DTOs.
     */
    fun List<SecurityMetricsEntity>.toDtoList():
        List<SecurityMetricsDto> {

        return map(
            SecurityMetricsEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts nullable DTO metrics into Domain metrics.
     */
    fun SecurityMetricsDto?.toDomainOrNull():
        SecurityMetrics? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable Domain metrics into a DTO.
     */
    fun SecurityMetrics?.toDtoOrNull():
        SecurityMetricsDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable Entity metrics into Domain metrics.
     */
    fun SecurityMetricsEntity?.toDomainOrNull():
        SecurityMetrics? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable Domain metrics into an Entity.
     */
    fun SecurityMetrics?.toEntityOrNull():
        SecurityMetricsEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Update Existing Entity
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Room SecurityMetricsEntity using
     * values from the Domain model.
     *
     * Persistence-specific fields from the existing entity
     * are preserved by copy().
     */
    fun SecurityMetrics.updateEntity(
        existingEntity: SecurityMetricsEntity
    ): SecurityMetricsEntity {

        return existingEntity.copy(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Update Existing Domain Model
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Domain SecurityMetrics object
     * using values from a local Room entity.
     */
    fun SecurityMetricsEntity.updateDomain(
        existingMetrics: SecurityMetrics
    ): SecurityMetrics {

        return existingMetrics.copy(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // -------------------------------------------------------------------------
    // DTO Merge
    // -------------------------------------------------------------------------

    /**
     * Merges remote metric values into an existing Domain
     * SecurityMetrics object.
     *
     * Useful during incremental backend synchronization.
     */
    fun SecurityMetricsDto.mergeInto(
        existingMetrics: SecurityMetrics
    ): SecurityMetrics {

        return existingMetrics.copy(
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            cancelledScans = cancelledScans,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            resolvedThreats = resolvedThreats,
            activeThreats = activeThreats,
            blockedThreats = blockedThreats,
            detectedMalware = detectedMalware,
            phishingAttempts = phishingAttempts,
            scamAttempts = scamAttempts,
            suspiciousApps = suspiciousApps,
            privacyIncidents = privacyIncidents,
            networkThreats = networkThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            lastUpdatedAt = lastUpdatedAt
        )
    }
}
