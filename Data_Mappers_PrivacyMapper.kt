package com.sentrix.data.mappers

import com.sentrix.data.dto.DataProtectionDto
import com.sentrix.data.dto.PrivacyAuditDto
import com.sentrix.data.dto.PrivacyDto
import com.sentrix.data.dto.PrivacyScoreDto
import com.sentrix.data.dto.TrackerBlockingDto
import com.sentrix.data.local.entities.DataProtectionEntity
import com.sentrix.data.local.entities.PrivacyAuditEntity
import com.sentrix.data.local.entities.PrivacyEntity
import com.sentrix.data.local.entities.PrivacyScoreEntity
import com.sentrix.data.local.entities.TrackerBlockingEntity
import com.sentrix.domain.models.DataProtection
import com.sentrix.domain.models.Privacy
import com.sentrix.domain.models.PrivacyAudit
import com.sentrix.domain.models.PrivacyScore
import com.sentrix.domain.models.TrackerBlocking

/**
 * SentriX - Privacy Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts privacy-related objects between:
 *
 * - Remote API DTOs.
 * - Domain models.
 * - Local Room entities.
 *
 * Supported privacy models:
 *
 * Privacy
 * PrivacyAudit
 * TrackerBlocking
 * DataProtection
 * PrivacyScore
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
 * This mapper acts as the boundary between those layers.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper does NOT:
 *
 * - Perform privacy audits.
 * - Detect trackers.
 * - Block trackers.
 * - Calculate privacy scores.
 * - Apply privacy policies.
 * - Modify application permissions.
 * - Access Room directly.
 * - Perform network requests.
 *
 * It only transforms data representations.
 *
 * SECURITY PRINCIPLE:
 * ------------------------------------------------------------
 * Privacy-related information can contain sensitive data.
 *
 * The mapper must not:
 *
 * - Log private values.
 * - Persist secrets unnecessarily.
 * - Add tracking identifiers.
 * - Modify user privacy settings.
 * - Expose authentication credentials.
 */
object PrivacyMapper {

    // ========================================================================
    // PRIVACY
    // ========================================================================

    /**
     * Converts a remote PrivacyDto into the Domain Privacy model.
     */
    fun PrivacyDto.toDomain():
        Privacy {

        return Privacy(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Domain Privacy model into a remote DTO.
     */
    fun Privacy.toDto():
        PrivacyDto {

        return PrivacyDto(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a local PrivacyEntity into the Domain Privacy model.
     */
    fun PrivacyEntity.toDomain():
        Privacy {

        return Privacy(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Domain Privacy model into a local Room entity.
     */
    fun Privacy.toEntity():
        PrivacyEntity {

        return PrivacyEntity(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a PrivacyDto directly into a local Room entity.
     */
    fun PrivacyDto.toEntity():
        PrivacyEntity {

        return PrivacyEntity(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a PrivacyEntity into a remote PrivacyDto.
     */
    fun PrivacyEntity.toDto():
        PrivacyDto {

        return PrivacyDto(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    // ========================================================================
    // PRIVACY AUDIT
    // ========================================================================

    /**
     * Converts a PrivacyAuditDto into the Domain PrivacyAudit model.
     */
    fun PrivacyAuditDto.toDomain():
        PrivacyAudit {

        return PrivacyAudit(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Converts a Domain PrivacyAudit into a remote DTO.
     */
    fun PrivacyAudit.toDto():
        PrivacyAuditDto {

        return PrivacyAuditDto(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Converts a local PrivacyAuditEntity into Domain PrivacyAudit.
     */
    fun PrivacyAuditEntity.toDomain():
        PrivacyAudit {

        return PrivacyAudit(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Converts a Domain PrivacyAudit into a Room entity.
     */
    fun PrivacyAudit.toEntity():
        PrivacyAuditEntity {

        return PrivacyAuditEntity(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Converts a PrivacyAuditDto directly into a Room entity.
     */
    fun PrivacyAuditDto.toEntity():
        PrivacyAuditEntity {

        return PrivacyAuditEntity(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Converts a PrivacyAuditEntity into a remote DTO.
     */
    fun PrivacyAuditEntity.toDto():
        PrivacyAuditDto {

        return PrivacyAuditDto(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    // ========================================================================
    // TRACKER BLOCKING
    // ========================================================================

    /**
     * Converts a TrackerBlockingDto into the Domain
     * TrackerBlocking model.
     */
    fun TrackerBlockingDto.toDomain():
        TrackerBlocking {

        return TrackerBlocking(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Domain TrackerBlocking into a remote DTO.
     */
    fun TrackerBlocking.toDto():
        TrackerBlockingDto {

        return TrackerBlockingDto(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a TrackerBlockingEntity into Domain
     * TrackerBlocking.
     */
    fun TrackerBlockingEntity.toDomain():
        TrackerBlocking {

        return TrackerBlocking(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a Domain TrackerBlocking into a Room entity.
     */
    fun TrackerBlocking.toEntity():
        TrackerBlockingEntity {

        return TrackerBlockingEntity(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a TrackerBlockingDto directly into a Room entity.
     */
    fun TrackerBlockingDto.toEntity():
        TrackerBlockingEntity {

        return TrackerBlockingEntity(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts a TrackerBlockingEntity into a remote DTO.
     */
    fun TrackerBlockingEntity.toDto():
        TrackerBlockingDto {

        return TrackerBlockingDto(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    // ========================================================================
    // DATA PROTECTION
    // ========================================================================

    /**
     * Converts DataProtectionDto into the Domain
     * DataProtection model.
     */
    fun DataProtectionDto.toDomain():
        DataProtection {

        return DataProtection(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts Domain DataProtection into a remote DTO.
     */
    fun DataProtection.toDto():
        DataProtectionDto {

        return DataProtectionDto(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts DataProtectionEntity into Domain DataProtection.
     */
    fun DataProtectionEntity.toDomain():
        DataProtection {

        return DataProtection(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts Domain DataProtection into a Room entity.
     */
    fun DataProtection.toEntity():
        DataProtectionEntity {

        return DataProtectionEntity(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts DataProtectionDto directly into a Room entity.
     */
    fun DataProtectionDto.toEntity():
        DataProtectionEntity {

        return DataProtectionEntity(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Converts DataProtectionEntity into a remote DTO.
     */
    fun DataProtectionEntity.toDto():
        DataProtectionDto {

        return DataProtectionDto(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    // ========================================================================
    // PRIVACY SCORE
    // ========================================================================

    /**
     * Converts PrivacyScoreDto into the Domain PrivacyScore model.
     */
    fun PrivacyScoreDto.toDomain():
        PrivacyScore {

        return PrivacyScore(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts Domain PrivacyScore into a remote DTO.
     */
    fun PrivacyScore.toDto():
        PrivacyScoreDto {

        return PrivacyScoreDto(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts PrivacyScoreEntity into Domain PrivacyScore.
     */
    fun PrivacyScoreEntity.toDomain():
        PrivacyScore {

        return PrivacyScore(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts Domain PrivacyScore into a Room entity.
     */
    fun PrivacyScore.toEntity():
        PrivacyScoreEntity {

        return PrivacyScoreEntity(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts PrivacyScoreDto directly into a Room entity.
     */
    fun PrivacyScoreDto.toEntity():
        PrivacyScoreEntity {

        return PrivacyScoreEntity(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    /**
     * Converts PrivacyScoreEntity into a remote DTO.
     */
    fun PrivacyScoreEntity.toDto():
        PrivacyScoreDto {

        return PrivacyScoreDto(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    // ========================================================================
    // COLLECTION MAPPERS
    // ========================================================================

    /**
     * Converts Privacy DTOs into Domain models.
     */
    fun List<PrivacyDto>.toPrivacyDomainList():
        List<Privacy> {

        return map(
            PrivacyDto::toDomain
        )
    }

    /**
     * Converts Domain Privacy models into DTOs.
     */
    fun List<Privacy>.toPrivacyDtoList():
        List<PrivacyDto> {

        return map(
            Privacy::toDto
        )
    }

    /**
     * Converts Privacy entities into Domain models.
     */
    fun List<PrivacyEntity>.toPrivacyDomainList():
        List<Privacy> {

        return map(
            PrivacyEntity::toDomain
        )
    }

    /**
     * Converts Domain Privacy models into Room entities.
     */
    fun List<Privacy>.toPrivacyEntityList():
        List<PrivacyEntity> {

        return map(
            Privacy::toEntity
        )
    }

    /**
     * Converts PrivacyAudit DTOs into Domain models.
     */
    fun List<PrivacyAuditDto>.toAuditDomainList():
        List<PrivacyAudit> {

        return map(
            PrivacyAuditDto::toDomain
        )
    }

    /**
     * Converts Domain PrivacyAudit models into DTOs.
     */
    fun List<PrivacyAudit>.toAuditDtoList():
        List<PrivacyAuditDto> {

        return map(
            PrivacyAudit::toDto
        )
    }

    /**
     * Converts PrivacyAudit entities into Domain models.
     */
    fun List<PrivacyAuditEntity>.toAuditDomainList():
        List<PrivacyAudit> {

        return map(
            PrivacyAuditEntity::toDomain
        )
    }

    /**
     * Converts Domain PrivacyAudit models into entities.
     */
    fun List<PrivacyAudit>.toAuditEntityList():
        List<PrivacyAuditEntity> {

        return map(
            PrivacyAudit::toEntity
        )
    }

    /**
     * Converts TrackerBlocking DTOs into Domain models.
     */
    fun List<TrackerBlockingDto>.toTrackerDomainList():
        List<TrackerBlocking> {

        return map(
            TrackerBlockingDto::toDomain
        )
    }

    /**
     * Converts Domain TrackerBlocking models into DTOs.
     */
    fun List<TrackerBlocking>.toTrackerDtoList():
        List<TrackerBlockingDto> {

        return map(
            TrackerBlocking::toDto
        )
    }

    /**
     * Converts TrackerBlocking entities into Domain models.
     */
    fun List<TrackerBlockingEntity>.toTrackerDomainList():
        List<TrackerBlocking> {

        return map(
            TrackerBlockingEntity::toDomain
        )
    }

    /**
     * Converts Domain TrackerBlocking models into Room entities.
     */
    fun List<TrackerBlocking>.toTrackerEntityList():
        List<TrackerBlockingEntity> {

        return map(
            TrackerBlocking::toEntity
        )
    }

    /**
     * Converts DataProtection DTOs into Domain models.
     */
    fun List<DataProtectionDto>.toProtectionDomainList():
        List<DataProtection> {

        return map(
            DataProtectionDto::toDomain
        )
    }

    /**
     * Converts Domain DataProtection models into DTOs.
     */
    fun List<DataProtection>.toProtectionDtoList():
        List<DataProtectionDto> {

        return map(
            DataProtection::toDto
        )
    }

    /**
     * Converts DataProtection entities into Domain models.
     */
    fun List<DataProtectionEntity>.toProtectionDomainList():
        List<DataProtection> {

        return map(
            DataProtectionEntity::toDomain
        )
    }

    /**
     * Converts Domain DataProtection models into Room entities.
     */
    fun List<DataProtection>.toProtectionEntityList():
        List<DataProtectionEntity> {

        return map(
            DataProtection::toEntity
        )
    }

    // ========================================================================
    // NULLABLE MAPPERS
    // ========================================================================

    /**
     * Safely converts nullable Privacy DTO.
     */
    fun PrivacyDto?.toPrivacyDomainOrNull():
        Privacy? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable Privacy model.
     */
    fun Privacy?.toPrivacyDtoOrNull():
        PrivacyDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable Privacy entity.
     */
    fun PrivacyEntity?.toPrivacyDomainOrNull():
        Privacy? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable PrivacyAudit DTO.
     */
    fun PrivacyAuditDto?.toAuditDomainOrNull():
        PrivacyAudit? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable PrivacyAudit model.
     */
    fun PrivacyAudit?.toAuditDtoOrNull():
        PrivacyAuditDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable PrivacyAudit entity.
     */
    fun PrivacyAuditEntity?.toAuditDomainOrNull():
        PrivacyAudit? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable TrackerBlocking DTO.
     */
    fun TrackerBlockingDto?.toTrackerDomainOrNull():
        TrackerBlocking? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable TrackerBlocking model.
     */
    fun TrackerBlocking?.toTrackerDtoOrNull():
        TrackerBlockingDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable TrackerBlocking entity.
     */
    fun TrackerBlockingEntity?.toTrackerDomainOrNull():
        TrackerBlocking? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable DataProtection DTO.
     */
    fun DataProtectionDto?.toProtectionDomainOrNull():
        DataProtection? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable DataProtection model.
     */
    fun DataProtection?.toProtectionDtoOrNull():
        DataProtectionDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable DataProtection entity.
     */
    fun DataProtectionEntity?.toProtectionDomainOrNull():
        DataProtection? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable PrivacyScore DTO.
     */
    fun PrivacyScoreDto?.toScoreDomainOrNull():
        PrivacyScore? {

        return this?.toDomain()
    }

    /**
     * Safely converts nullable PrivacyScore model.
     */
    fun PrivacyScore?.toScoreDtoOrNull():
        PrivacyScoreDto? {

        return this?.toDto()
    }

    /**
     * Safely converts nullable PrivacyScore entity.
     */
    fun PrivacyScoreEntity?.toScoreDomainOrNull():
        PrivacyScore? {

        return this?.toDomain()
    }

    // ========================================================================
    // ENTITY UPDATE HELPERS
    // ========================================================================

    /**
     * Updates an existing PrivacyEntity with Domain data.
     */
    fun Privacy.updateEntity(
        existingEntity: PrivacyEntity
    ): PrivacyEntity {

        return existingEntity.copy(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing PrivacyAuditEntity with Domain data.
     */
    fun PrivacyAudit.updateEntity(
        existingEntity: PrivacyAuditEntity
    ): PrivacyAuditEntity {

        return existingEntity.copy(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Updates an existing TrackerBlockingEntity with Domain
     * data.
     */
    fun TrackerBlocking.updateEntity(
        existingEntity: TrackerBlockingEntity
    ): TrackerBlockingEntity {

        return existingEntity.copy(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing DataProtectionEntity with Domain
     * data.
     */
    fun DataProtection.updateEntity(
        existingEntity: DataProtectionEntity
    ): DataProtectionEntity {

        return existingEntity.copy(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing PrivacyScoreEntity with Domain data.
     */
    fun PrivacyScore.updateEntity(
        existingEntity: PrivacyScoreEntity
    ): PrivacyScoreEntity {

        return existingEntity.copy(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    // ========================================================================
    // DOMAIN UPDATE HELPERS
    // ========================================================================

    /**
     * Updates an existing Domain Privacy model using local
     * persistence data.
     */
    fun PrivacyEntity.updateDomain(
        existingPrivacy: Privacy
    ): Privacy {

        return existingPrivacy.copy(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing Domain PrivacyAudit model using
     * local persistence data.
     */
    fun PrivacyAuditEntity.updateDomain(
        existingAudit: PrivacyAudit
    ): PrivacyAudit {

        return existingAudit.copy(
            auditId = auditId,
            userId = userId,
            auditType = auditType,
            title = title,
            description = description,
            status = status,
            severity = severity,
            affectedApp = affectedApp,
            affectedPermission = affectedPermission,
            recommendation = recommendation,
            detectedAt = detectedAt,
            resolvedAt = resolvedAt
        )
    }

    /**
     * Updates an existing Domain TrackerBlocking model using
     * local persistence data.
     */
    fun TrackerBlockingEntity.updateDomain(
        existingTracker: TrackerBlocking
    ): TrackerBlocking {

        return existingTracker.copy(
            trackerId = trackerId,
            trackerName = trackerName,
            trackerType = trackerType,
            packageName = packageName,
            domain = domain,
            isBlocked = isBlocked,
            blockedRequests = blockedRequests,
            detectedRequests = detectedRequests,
            lastDetectedAt = lastDetectedAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing Domain DataProtection model using
     * local persistence data.
     */
    fun DataProtectionEntity.updateDomain(
        existingProtection: DataProtection
    ): DataProtection {

        return existingProtection.copy(
            protectionId = protectionId,
            userId = userId,
            dataType = dataType,
            protectionLevel = protectionLevel,
            encryptionEnabled = encryptionEnabled,
            backupEnabled = backupEnabled,
            leakageDetectionEnabled =
                leakageDetectionEnabled,
            sensitiveDataDetected =
                sensitiveDataDetected,
            leakageEvents = leakageEvents,
            lastScanAt = lastScanAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Updates an existing Domain PrivacyScore model using
     * local persistence data.
     */
    fun PrivacyScoreEntity.updateDomain(
        existingScore: PrivacyScore
    ): PrivacyScore {

        return existingScore.copy(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }

    // ========================================================================
    // MERGE HELPERS
    // ========================================================================

    /**
     * Merges remote Privacy data into an existing Domain
     * Privacy model.
     */
    fun PrivacyDto.mergeInto(
        existingPrivacy: Privacy
    ): Privacy {

        return existingPrivacy.copy(
            privacyId = privacyId,
            userId = userId,
            privacyLevel = privacyLevel,
            trackingProtectionEnabled =
                trackingProtectionEnabled,
            locationProtectionEnabled =
                locationProtectionEnabled,
            cameraProtectionEnabled =
                cameraProtectionEnabled,
            microphoneProtectionEnabled =
                microphoneProtectionEnabled,
            contactProtectionEnabled =
                contactProtectionEnabled,
            notificationProtectionEnabled =
                notificationProtectionEnabled,
            dataLeakageProtectionEnabled =
                dataLeakageProtectionEnabled,
            vpnProtectionEnabled =
                vpnProtectionEnabled,
            lastAuditAt = lastAuditAt,
            updatedAt = updatedAt
        )
    }

    /**
     * Merges remote PrivacyScore data into an existing
     * Domain PrivacyScore model.
     */
    fun PrivacyScoreDto.mergeInto(
        existingScore: PrivacyScore
    ): PrivacyScore {

        return existingScore.copy(
            score = score,
            trackingScore = trackingScore,
            permissionScore = permissionScore,
            dataProtectionScore = dataProtectionScore,
            networkPrivacyScore = networkPrivacyScore,
            devicePrivacyScore = devicePrivacyScore,
            riskLevel = riskLevel,
            calculatedAt = calculatedAt
        )
    }
}
