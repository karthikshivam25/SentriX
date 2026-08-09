package com.sentrix.data.mappers

import com.sentrix.data.dto.VPNConnectionDto
import com.sentrix.data.dto.VPNServerDto
import com.sentrix.data.dto.VPNStatisticsDto
import com.sentrix.data.local.entities.VPNConnectionEntity
import com.sentrix.data.local.entities.VPNServerEntity
import com.sentrix.data.local.entities.VPNStatisticsEntity
import com.sentrix.domain.models.VPNConnection
import com.sentrix.domain.models.VPNServer
import com.sentrix.domain.models.VPNStatistics

/**
 * SentriX - VPN Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts VPN-related objects between:
 *
 * - Remote API DTOs.
 * - Domain models.
 * - Local Room entities.
 *
 * Supported VPN models:
 *
 * VPNConnection
 * VPNServer
 * VPNStatistics
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The Domain layer must not depend on:
 *
 * - Retrofit.
 * - Room.
 * - JSON serialization.
 * - API response structures.
 * - Database implementation details.
 *
 * This mapper provides the Data-layer boundary.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This mapper does NOT:
 *
 * - Establish VPN connections.
 * - Disconnect VPN connections.
 * - Select VPN servers.
 * - Calculate server health.
 * - Calculate network security.
 * - Apply VPN security policies.
 * - Access Room directly.
 * - Perform API calls.
 *
 * It only converts data representations.
 *
 * Security Principle:
 * ------------------------------------------------------------
 * VPN credentials, private keys, certificates, authentication
 * tokens, or other sensitive secrets must NOT be introduced
 * into ordinary VPN DTO/entity/domain mapping unless the
 * corresponding secure architecture explicitly requires them.
 */
object VPNMapper {

    // ========================================================================
    // VPN CONNECTION
    // ========================================================================

    // ------------------------------------------------------------------------
    // VPNConnectionDto -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts a remote VPNConnectionDto into the Domain
     * VPNConnection model.
     */
    fun VPNConnectionDto.toDomain():
        VPNConnection {

        return VPNConnection(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNConnectionDto
    // ------------------------------------------------------------------------

    /**
     * Converts a Domain VPNConnection into a remote DTO.
     */
    fun VPNConnection.toDto():
        VPNConnectionDto {

        return VPNConnectionDto(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ------------------------------------------------------------------------
    // VPNConnectionEntity -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts a local VPNConnectionEntity into the Domain
     * VPNConnection model.
     */
    fun VPNConnectionEntity.toDomain():
        VPNConnection {

        return VPNConnection(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNConnectionEntity
    // ------------------------------------------------------------------------

    /**
     * Converts a Domain VPNConnection into a local Room
     * VPNConnectionEntity.
     */
    fun VPNConnection.toEntity():
        VPNConnectionEntity {

        return VPNConnectionEntity(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ------------------------------------------------------------------------
    // VPNConnectionDto -> Entity
    // ------------------------------------------------------------------------

    /**
     * Converts a remote VPN connection DTO directly into a
     * local Room entity.
     */
    fun VPNConnectionDto.toEntity():
        VPNConnectionEntity {

        return VPNConnectionEntity(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ------------------------------------------------------------------------
    // VPNConnectionEntity -> DTO
    // ------------------------------------------------------------------------

    /**
     * Converts a local VPN connection entity into a remote
     * DTO.
     */
    fun VPNConnectionEntity.toDto():
        VPNConnectionDto {

        return VPNConnectionDto(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    // ========================================================================
    // VPN SERVER
    // ========================================================================

    // ------------------------------------------------------------------------
    // VPNServerDto -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts a remote VPNServerDto into the Domain VPNServer
     * model.
     */
    fun VPNServerDto.toDomain():
        VPNServer {

        return VPNServer(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNServerDto
    // ------------------------------------------------------------------------

    /**
     * Converts a Domain VPNServer into a remote DTO.
     */
    fun VPNServer.toDto():
        VPNServerDto {

        return VPNServerDto(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ------------------------------------------------------------------------
    // VPNServerEntity -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts a local VPNServerEntity into the Domain
     * VPNServer model.
     */
    fun VPNServerEntity.toDomain():
        VPNServer {

        return VPNServer(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNServerEntity
    // ------------------------------------------------------------------------

    /**
     * Converts a Domain VPNServer into a local Room entity.
     */
    fun VPNServer.toEntity():
        VPNServerEntity {

        return VPNServerEntity(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ------------------------------------------------------------------------
    // VPNServerDto -> Entity
    // ------------------------------------------------------------------------

    /**
     * Converts a remote VPN server DTO directly into a Room
     * entity.
     */
    fun VPNServerDto.toEntity():
        VPNServerEntity {

        return VPNServerEntity(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ------------------------------------------------------------------------
    // VPNServerEntity -> DTO
    // ------------------------------------------------------------------------

    /**
     * Converts a local VPN server entity into a remote DTO.
     */
    fun VPNServerEntity.toDto():
        VPNServerDto {

        return VPNServerDto(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    // ========================================================================
    // VPN STATISTICS
    // ========================================================================

    // ------------------------------------------------------------------------
    // VPNStatisticsDto -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts remote VPN statistics into the Domain model.
     */
    fun VPNStatisticsDto.toDomain():
        VPNStatistics {

        return VPNStatistics(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNStatisticsDto
    // ------------------------------------------------------------------------

    /**
     * Converts Domain VPN statistics into a remote DTO.
     */
    fun VPNStatistics.toDto():
        VPNStatisticsDto {

        return VPNStatisticsDto(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ------------------------------------------------------------------------
    // VPNStatisticsEntity -> Domain
    // ------------------------------------------------------------------------

    /**
     * Converts local VPN statistics into the Domain model.
     */
    fun VPNStatisticsEntity.toDomain():
        VPNStatistics {

        return VPNStatistics(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ------------------------------------------------------------------------
    // Domain -> VPNStatisticsEntity
    // ------------------------------------------------------------------------

    /**
     * Converts Domain VPN statistics into a local Room
     * entity.
     */
    fun VPNStatistics.toEntity():
        VPNStatisticsEntity {

        return VPNStatisticsEntity(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ------------------------------------------------------------------------
    // VPNStatisticsDto -> Entity
    // ------------------------------------------------------------------------

    /**
     * Converts remote VPN statistics directly into a Room
     * entity.
     */
    fun VPNStatisticsDto.toEntity():
        VPNStatisticsEntity {

        return VPNStatisticsEntity(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ------------------------------------------------------------------------
    // VPNStatisticsEntity -> DTO
    // ------------------------------------------------------------------------

    /**
     * Converts local VPN statistics into a remote DTO.
     */
    fun VPNStatisticsEntity.toDto():
        VPNStatisticsDto {

        return VPNStatisticsDto(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ========================================================================
    // COLLECTION MAPPERS
    // ========================================================================

    // ------------------------------------------------------------------------
    // VPN Connections
    // ------------------------------------------------------------------------

    /**
     * Converts a list of connection DTOs into Domain models.
     */
    fun List<VPNConnectionDto>.toConnectionDomainList():
        List<VPNConnection> {

        return map(
            VPNConnectionDto::toDomain
        )
    }

    /**
     * Converts a list of Domain connections into DTOs.
     */
    fun List<VPNConnection>.toConnectionDtoList():
        List<VPNConnectionDto> {

        return map(
            VPNConnection::toDto
        )
    }

    /**
     * Converts a list of connection entities into Domain
     * models.
     */
    fun List<VPNConnectionEntity>.toConnectionDomainList():
        List<VPNConnection> {

        return map(
            VPNConnectionEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain connections into Room entities.
     */
    fun List<VPNConnection>.toConnectionEntityList():
        List<VPNConnectionEntity> {

        return map(
            VPNConnection::toEntity
        )
    }

    /**
     * Converts connection DTOs directly into Room entities.
     */
    fun List<VPNConnectionDto>.toConnectionEntityList():
        List<VPNConnectionEntity> {

        return map(
            VPNConnectionDto::toEntity
        )
    }

    /**
     * Converts connection entities into remote DTOs.
     */
    fun List<VPNConnectionEntity>.toConnectionDtoList():
        List<VPNConnectionDto> {

        return map(
            VPNConnectionEntity::toDto
        )
    }

    // ------------------------------------------------------------------------
    // VPN Servers
    // ------------------------------------------------------------------------

    /**
     * Converts server DTOs into Domain models.
     */
    fun List<VPNServerDto>.toServerDomainList():
        List<VPNServer> {

        return map(
            VPNServerDto::toDomain
        )
    }

    /**
     * Converts Domain servers into DTOs.
     */
    fun List<VPNServer>.toServerDtoList():
        List<VPNServerDto> {

        return map(
            VPNServer::toDto
        )
    }

    /**
     * Converts server entities into Domain models.
     */
    fun List<VPNServerEntity>.toServerDomainList():
        List<VPNServer> {

        return map(
            VPNServerEntity::toDomain
        )
    }

    /**
     * Converts Domain servers into Room entities.
     */
    fun List<VPNServer>.toServerEntityList():
        List<VPNServerEntity> {

        return map(
            VPNServer::toEntity
        )
    }

    /**
     * Converts server DTOs directly into Room entities.
     */
    fun List<VPNServerDto>.toServerEntityList():
        List<VPNServerEntity> {

        return map(
            VPNServerDto::toEntity
        )
    }

    /**
     * Converts server entities into DTOs.
     */
    fun List<VPNServerEntity>.toServerDtoList():
        List<VPNServerDto> {

        return map(
            VPNServerEntity::toDto
        )
    }

    // ========================================================================
    // NULLABLE MAPPERS
    // ========================================================================

    /**
     * Safely converts a nullable VPN connection DTO.
     */
    fun VPNConnectionDto?.toConnectionDomainOrNull():
        VPNConnection? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable VPN connection.
     */
    fun VPNConnection?.toConnectionDtoOrNull():
        VPNConnectionDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable VPN connection entity.
     */
    fun VPNConnectionEntity?.toConnectionDomainOrNull():
        VPNConnection? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable VPN server DTO.
     */
    fun VPNServerDto?.toServerDomainOrNull():
        VPNServer? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable VPN server.
     */
    fun VPNServer?.toServerDtoOrNull():
        VPNServerDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable VPN server entity.
     */
    fun VPNServerEntity?.toServerDomainOrNull():
        VPNServer? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable VPN statistics DTO.
     */
    fun VPNStatisticsDto?.toStatisticsDomainOrNull():
        VPNStatistics? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable VPN statistics object.
     */
    fun VPNStatistics?.toStatisticsDtoOrNull():
        VPNStatisticsDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable VPN statistics entity.
     */
    fun VPNStatisticsEntity?.toStatisticsDomainOrNull():
        VPNStatistics? {

        return this?.toDomain()
    }

    // ========================================================================
    // UPDATE EXISTING ENTITIES
    // ========================================================================

    /**
     * Updates an existing VPN connection entity using
     * values from the Domain model.
     */
    fun VPNConnection.updateEntity(
        existingEntity: VPNConnectionEntity
    ): VPNConnectionEntity {

        return existingEntity.copy(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    /**
     * Updates an existing VPN server entity using values from
     * the Domain model.
     */
    fun VPNServer.updateEntity(
        existingEntity: VPNServerEntity
    ): VPNServerEntity {

        return existingEntity.copy(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    /**
     * Updates an existing VPN statistics entity using values
     * from the Domain model.
     */
    fun VPNStatistics.updateEntity(
        existingEntity: VPNStatisticsEntity
    ): VPNStatisticsEntity {

        return existingEntity.copy(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ========================================================================
    // DOMAIN UPDATE HELPERS
    // ========================================================================

    /**
     * Updates an existing Domain VPN connection using a
     * local Room entity.
     */
    fun VPNConnectionEntity.updateDomain(
        existingConnection: VPNConnection
    ): VPNConnection {

        return existingConnection.copy(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    /**
     * Updates an existing Domain VPN server using a local
     * Room entity.
     */
    fun VPNServerEntity.updateDomain(
        existingServer: VPNServer
    ): VPNServer {

        return existingServer.copy(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    /**
     * Updates an existing Domain VPN statistics object using
     * a local Room entity.
     */
    fun VPNStatisticsEntity.updateDomain(
        existingStatistics: VPNStatistics
    ): VPNStatistics {

        return existingStatistics.copy(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }

    // ========================================================================
    // MERGE HELPERS
    // ========================================================================

    /**
     * Merges remote connection data into an existing Domain
     * VPN connection.
     */
    fun VPNConnectionDto.mergeInto(
        existingConnection: VPNConnection
    ): VPNConnection {

        return existingConnection.copy(
            connectionId = connectionId,
            serverId = serverId,
            serverName = serverName,
            status = status,
            protocol = protocol,
            ipAddress = ipAddress,
            connectedAt = connectedAt,
            disconnectedAt = disconnectedAt,
            bytesUploaded = bytesUploaded,
            bytesDownloaded = bytesDownloaded,
            durationSeconds = durationSeconds,
            isSecure = isSecure
        )
    }

    /**
     * Merges remote server data into an existing Domain
     * VPN server.
     */
    fun VPNServerDto.mergeInto(
        existingServer: VPNServer
    ): VPNServer {

        return existingServer.copy(
            serverId = serverId,
            name = name,
            country = country,
            city = city,
            host = host,
            ipAddress = ipAddress,
            protocol = protocol,
            port = port,
            load = load,
            latencyMs = latencyMs,
            isAvailable = isAvailable,
            isRecommended = isRecommended
        )
    }

    /**
     * Merges remote statistics into an existing Domain
     * VPN statistics object.
     */
    fun VPNStatisticsDto.mergeInto(
        existingStatistics: VPNStatistics
    ): VPNStatistics {

        return existingStatistics.copy(
            totalConnections = totalConnections,
            successfulConnections = successfulConnections,
            failedConnections = failedConnections,
            totalBytesUploaded = totalBytesUploaded,
            totalBytesDownloaded = totalBytesDownloaded,
            averageLatencyMs = averageLatencyMs,
            averageConnectionDurationSeconds =
                averageConnectionDurationSeconds,
            blockedThreats = blockedThreats,
            protectedConnections = protectedConnections,
            lastUpdatedAt = lastUpdatedAt
        )
    }
}
