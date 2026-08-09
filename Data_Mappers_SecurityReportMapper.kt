package com.sentrix.data.mappers

import com.sentrix.data.dto.SecurityReportDto
import com.sentrix.data.local.entities.SecurityReportEntity
import com.sentrix.domain.models.SecurityReport

/**
 * SentriX - Security Report Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts SecurityReport objects between the Domain layer
 * and Data-layer representations.
 *
 * Supported conversions:
 *
 * Remote:
 *
 * SecurityReportDto
 *        │
 *        ▼
 * SecurityReport
 *
 * Local:
 *
 * SecurityReportEntity
 *        │
 *        ▼
 * SecurityReport
 *
 * Domain:
 *
 * SecurityReport
 *        ├──► SecurityReportDto
 *        └──► SecurityReportEntity
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The Domain layer must remain independent from:
 *
 * - Retrofit.
 * - Room.
 * - JSON serialization.
 * - Database implementation details.
 * - Remote API contracts.
 *
 * This mapper keeps those concerns isolated inside the
 * Data layer.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper does NOT:
 *
 * - Generate security reports.
 * - Calculate risk scores.
 * - Calculate security scores.
 * - Determine threat severity.
 * - Analyze malware.
 * - Generate recommendations.
 * - Make security decisions.
 * - Access Room directly.
 * - Perform API calls.
 *
 * It only transforms data representations.
 */
object SecurityReportMapper {

    // -------------------------------------------------------------------------
    // DTO -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote SecurityReportDto into the Domain
     * SecurityReport model.
     *
     * Used when a security report is received from the
     * SentriX backend.
     */
    fun SecurityReportDto.toDomain():
        SecurityReport {

        return SecurityReport(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain SecurityReport into a remote DTO.
     *
     * Used when a report needs to be submitted or synchronized
     * with the SentriX backend.
     */
    fun SecurityReport.toDto():
        SecurityReportDto {

        return SecurityReportDto(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room SecurityReportEntity into the
     * Domain SecurityReport model.
     *
     * Used when retrieving reports from local persistence.
     */
    fun SecurityReportEntity.toDomain():
        SecurityReport {

        return SecurityReport(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain SecurityReport into a local Room
     * SecurityReportEntity.
     *
     * Used before inserting or updating a security report
     * in the local database.
     */
    fun SecurityReport.toEntity():
        SecurityReportEntity {

        return SecurityReportEntity(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote SecurityReportDto directly into a
     * local Room entity.
     *
     * Useful when synchronizing API report data into the
     * local database.
     */
    fun SecurityReportDto.toEntity():
        SecurityReportEntity {

        return SecurityReportEntity(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local SecurityReportEntity into a remote
     * SecurityReportDto.
     *
     * Useful when locally stored reports need to be
     * synchronized with the backend.
     */
    fun SecurityReportEntity.toDto():
        SecurityReportDto {

        return SecurityReportDto(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of remote report DTOs into Domain
     * SecurityReport objects.
     */
    fun List<SecurityReportDto>.toDomainList():
        List<SecurityReport> {

        return map(
            SecurityReportDto::toDomain
        )
    }

    /**
     * Converts a list of Domain reports into remote DTOs.
     */
    fun List<SecurityReport>.toDtoList():
        List<SecurityReportDto> {

        return map(
            SecurityReport::toDto
        )
    }

    /**
     * Converts a list of local report entities into Domain
     * SecurityReport objects.
     */
    fun List<SecurityReportEntity>.toDomainList():
        List<SecurityReport> {

        return map(
            SecurityReportEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain reports into Room entities.
     */
    fun List<SecurityReport>.toEntityList():
        List<SecurityReportEntity> {

        return map(
            SecurityReport::toEntity
        )
    }

    /**
     * Converts a list of remote DTOs into Room entities.
     */
    fun List<SecurityReportDto>.toEntityList():
        List<SecurityReportEntity> {

        return map(
            SecurityReportDto::toEntity
        )
    }

    /**
     * Converts a list of local entities into remote DTOs.
     */
    fun List<SecurityReportEntity>.toDtoList():
        List<SecurityReportDto> {

        return map(
            SecurityReportEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts a nullable DTO into a Domain report.
     */
    fun SecurityReportDto?.toDomainOrNull():
        SecurityReport? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain report into a DTO.
     */
    fun SecurityReport?.toDtoOrNull():
        SecurityReportDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable Entity into a Domain report.
     */
    fun SecurityReportEntity?.toDomainOrNull():
        SecurityReport? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain report into an Entity.
     */
    fun SecurityReport?.toEntityOrNull():
        SecurityReportEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Update Existing Entity
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Room SecurityReportEntity using
     * values from the Domain SecurityReport.
     *
     * copy() preserves any persistence-specific fields that
     * are not represented in the Domain model.
     */
    fun SecurityReport.updateEntity(
        existingEntity: SecurityReportEntity
    ): SecurityReportEntity {

        return existingEntity.copy(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // Update Existing Domain Model
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Domain SecurityReport using values
     * from a local database entity.
     */
    fun SecurityReportEntity.updateDomain(
        existingReport: SecurityReport
    ): SecurityReport {

        return existingReport.copy(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }

    // -------------------------------------------------------------------------
    // DTO Merge
    // -------------------------------------------------------------------------

    /**
     * Merges a remote DTO into an existing Domain report.
     *
     * Useful when the backend returns only the report fields
     * represented by SecurityReportDto.
     */
    fun SecurityReportDto.mergeInto(
        existingReport: SecurityReport
    ): SecurityReport {

        return existingReport.copy(
            reportId = reportId,
            title = title,
            summary = summary,
            generatedAt = generatedAt,
            updatedAt = updatedAt,
            securityScore = securityScore,
            riskScore = riskScore,
            totalThreats = totalThreats,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            scannedItems = scannedItems,
            recommendations = recommendations,
            status = status
        )
    }
}
