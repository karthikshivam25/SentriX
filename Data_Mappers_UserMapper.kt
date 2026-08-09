package com.sentrix.data.mappers

import com.sentrix.data.dto.UserDto
import com.sentrix.data.local.entities.UserEntity
import com.sentrix.domain.models.User

/**
 * SentriX - User Mapper
 *
 * Package:
 * com.sentrix.data.mappers
 *
 * Responsibility
 * ------------------------------------------------------------
 * Converts User objects between the Domain layer and the
 * Data layer representations.
 *
 * Supported conversions:
 *
 * Remote DTO
 *      │
 *      ▼
 *   UserDto
 *      │
 *      ▼
 * Domain User
 *
 * Local Entity
 *      │
 *      ▼
 *  UserEntity
 *      │
 *      ▼
 * Domain User
 *
 * Domain User
 *      │
 *      ├──► UserDto
 *      │
 *      └──► UserEntity
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * The Domain layer must not depend on:
 *
 * - Retrofit.
 * - Room.
 * - JSON serialization.
 * - Database implementation details.
 * - Remote API models.
 *
 * This mapper acts as the boundary between those models.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Authenticate users.
 * - Validate passwords.
 * - Store access tokens.
 * - Refresh tokens.
 * - Perform authorization.
 * - Make network requests.
 * - Access Room directly.
 *
 * It only transforms data representations.
 *
 * SECURITY:
 * ------------------------------------------------------------
 * Authentication credentials and secrets should not be copied
 * into UserEntity/UserDto unless explicitly required by the
 * corresponding authentication architecture.
 */
object UserMapper {

    // -------------------------------------------------------------------------
    // DTO -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a remote UserDto into the Domain User model.
     *
     * Used after receiving user information from the backend.
     */
    fun UserDto.toDomain(): User {

        return User(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain User into a remote UserDto.
     *
     * Used when user information needs to be sent to the
     * SentriX backend.
     */
    fun User.toDto(): UserDto {

        return UserDto(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> Domain
    // -------------------------------------------------------------------------

    /**
     * Converts a local Room UserEntity into the Domain User
     * model.
     *
     * Used when retrieving persisted user information from
     * the local database.
     */
    fun UserEntity.toDomain(): User {

        return User(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Domain -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a Domain User into a local Room UserEntity.
     *
     * Used before inserting or updating user information
     * inside the local database.
     */
    fun User.toEntity(): UserEntity {

        return UserEntity(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // DTO -> Entity
    // -------------------------------------------------------------------------

    /**
     * Converts a remote UserDto directly into a local
     * UserEntity.
     *
     * Useful when repository synchronization requires
     * persisting API data without exposing the Domain model
     * to the persistence operation.
     */
    fun UserDto.toEntity(): UserEntity {

        return UserEntity(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Entity -> DTO
    // -------------------------------------------------------------------------

    /**
     * Converts a local UserEntity into a remote UserDto.
     *
     * Useful for synchronization operations where locally
     * persisted user data must be sent to the backend.
     */
    fun UserEntity.toDto(): UserDto {

        return UserDto(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Collection Mappers
    // -------------------------------------------------------------------------

    /**
     * Converts a list of UserDto objects into Domain Users.
     */
    fun List<UserDto>.toDomainList():
        List<User> {

        return map(
            UserDto::toDomain
        )
    }

    /**
     * Converts a list of Domain Users into UserDto objects.
     */
    fun List<User>.toDtoList():
        List<UserDto> {

        return map(
            User::toDto
        )
    }

    /**
     * Converts a list of UserEntity objects into Domain Users.
     */
    fun List<UserEntity>.toDomainList():
        List<User> {

        return map(
            UserEntity::toDomain
        )
    }

    /**
     * Converts a list of Domain Users into UserEntity objects.
     */
    fun List<User>.toEntityList():
        List<UserEntity> {

        return map(
            User::toEntity
        )
    }

    /**
     * Converts a list of UserDto objects into UserEntity objects.
     */
    fun List<UserDto>.toEntityList():
        List<UserEntity> {

        return map(
            UserDto::toEntity
        )
    }

    /**
     * Converts a list of UserEntity objects into UserDto objects.
     */
    fun List<UserEntity>.toDtoList():
        List<UserDto> {

        return map(
            UserEntity::toDto
        )
    }

    // -------------------------------------------------------------------------
    // Nullable Mappers
    // -------------------------------------------------------------------------

    /**
     * Safely converts a nullable UserDto to Domain User.
     */
    fun UserDto?.toDomainOrNull():
        User? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain User to UserDto.
     */
    fun User?.toDtoOrNull():
        UserDto? {

        return this?.toDto()
    }

    /**
     * Safely converts a nullable UserEntity to Domain User.
     */
    fun UserEntity?.toDomainOrNull():
        User? {

        return this?.toDomain()
    }

    /**
     * Safely converts a nullable Domain User to UserEntity.
     */
    fun User?.toEntityOrNull():
        UserEntity? {

        return this?.toEntity()
    }

    // -------------------------------------------------------------------------
    // Update Existing Entity
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Room entity using values from the
     * Domain User.
     *
     * This is useful when the existing entity contains
     * persistence-specific information that should be
     * preserved.
     */
    fun User.updateEntity(
        existingEntity: UserEntity
    ): UserEntity {

        return existingEntity.copy(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }

    // -------------------------------------------------------------------------
    // Update Existing Domain Model
    // -------------------------------------------------------------------------

    /**
     * Updates an existing Domain User using values from a
     * local UserEntity.
     *
     * Useful when synchronization needs to preserve
     * Domain-level information that is not represented as
     * persistence-specific metadata.
     */
    fun UserEntity.updateDomain(
        existingUser: User
    ): User {

        return existingUser.copy(
            userId = userId,
            username = username,
            email = email,
            firstName = firstName,
            lastName = lastName,
            displayName = displayName,
            profileImageUrl = profileImageUrl,
            phoneNumber = phoneNumber,
            role = role,
            isActive = isActive,
            createdAt = createdAt,
            updatedAt = updatedAt
        )
    }
}
